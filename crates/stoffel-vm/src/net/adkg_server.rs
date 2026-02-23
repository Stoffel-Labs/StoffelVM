//! ADKG server with QUIC networking.
//!
//! This module provides the networking layer for ADKG (Asynchronous Distributed
//! Key Generation) nodes, handling connection management, ECDH public key exchange,
//! and AVSS message routing.
//!
//! QUIC/TLS (including ALPN and certificates) provides transport authentication
//! and peer identity. The AVSS ECDH keys exchanged here are used for payload
//! confidentiality inside ADKG protocol messages. These mechanisms are
//! complementary and intentionally both required.
//!
//! The server is generic over a `(F, G)` field/curve pair. Use the type aliases
//! `Bls12381AdkgServer` and `Bn254AdkgServer` for the supported configurations.

use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{FftField, PrimeField};
use ark_std::rand::SeedableRng;
use std::sync::Arc;
use std::time::Duration;
use stoffelmpc_mpc::avss_mpc::AvssSessionId;
use stoffelmpc_mpc::common::share::avss::AvssMessage;
use stoffelnet::network_utils::Network;
use stoffelnet::transports::quic::QuicNetworkManager;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use super::adkg_engine::AdkgMpcEngine;

// ============================================================================
// Type aliases for supported curve configurations
// ============================================================================

pub type Bls12381AdkgServer =
    AdkgQuicServer<ark_bls12_381::Fr, ark_bls12_381::G1Projective>;
pub type Bn254AdkgServer =
    AdkgQuicServer<ark_bn254::Fr, ark_bn254::G1Projective>;

/// Configuration for ADKG over QUIC
#[derive(Debug, Clone)]
pub struct AdkgQuicConfig {
    /// Timeout for public key exchange
    pub pk_exchange_timeout: Duration,
    /// Connection retry attempts
    pub max_connection_retries: u32,
    /// Delay between connection attempts
    pub connection_retry_delay: Duration,
}

impl Default for AdkgQuicConfig {
    fn default() -> Self {
        Self {
            pk_exchange_timeout: Duration::from_secs(30),
            max_connection_retries: 5,
            connection_retry_delay: Duration::from_millis(100),
        }
    }
}

/// An ADKG server node using QUIC networking.
///
/// Manages network setup, ECDH key exchange, and AVSS message routing
/// for distributed key generation. Parallel structure to `HoneyBadgerQuicServer`.
///
/// Generic over `(F, G)` where `F` is the scalar field and `G` is the curve group.
/// Use `Bls12381AdkgServer` or `Bn254AdkgServer` type aliases.
pub struct AdkgQuicServer<F, G>
where
    F: FftField + PrimeField,
    G: CurveGroup<ScalarField = F> + PrimeGroup,
{
    /// This party's ID
    pub node_id: usize,
    /// Total number of parties
    pub n: usize,
    /// Threshold (tolerates up to t malicious parties)
    pub t: usize,
    /// Instance ID for the ADKG session
    pub instance_id: u64,
    /// Network manager builder - used during setup before start() is called
    network_builder: Option<QuicNetworkManager>,
    /// Network manager Arc - created when start() is called
    pub network: Option<Arc<QuicNetworkManager>>,
    /// This party's AVSS ECDH secret key used for protocol payload encryption.
    /// Transport identity/authentication is handled separately by QUIC/TLS.
    sk_i: F,
    /// This party's AVSS ECDH public key.
    pk_i: G,
    /// Collected public keys of all parties (populated after exchange)
    pk_map: Option<Arc<Vec<G>>>,
    /// Configuration
    pub config: AdkgQuicConfig,
    /// Cancellation token for graceful shutdown
    shutdown_token: CancellationToken,
}

impl<F, G> AdkgQuicServer<F, G>
where
    F: FftField + PrimeField + Send + Sync + 'static,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    /// Creates a new ADKG QUIC server.
    ///
    /// Generates a fresh ECDH key pair for this party.
    pub fn new(
        node_id: usize,
        n: usize,
        t: usize,
        instance_id: u64,
        network: QuicNetworkManager,
        config: AdkgQuicConfig,
    ) -> Self {
        // Generate ECDH key pair: sk_i random, pk_i = g * sk_i
        let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
        let sk_i = F::rand(&mut rng);
        let pk_i = G::generator() * sk_i;

        Self {
            node_id,
            n,
            t,
            instance_id,
            network_builder: Some(network),
            network: None,
            sk_i,
            pk_i,
            pk_map: None,
            config,
            shutdown_token: CancellationToken::new(),
        }
    }

    /// Creates an ADKG server with a pre-existing key pair (for testing).
    pub fn with_keys(
        node_id: usize,
        n: usize,
        t: usize,
        instance_id: u64,
        network: QuicNetworkManager,
        config: AdkgQuicConfig,
        sk_i: F,
    ) -> Self {
        let pk_i = G::generator() * sk_i;
        Self {
            node_id,
            n,
            t,
            instance_id,
            network_builder: Some(network),
            network: None,
            sk_i,
            pk_i,
            pk_map: None,
            config,
            shutdown_token: CancellationToken::new(),
        }
    }

    /// Add a peer before starting.
    pub fn add_peer(&mut self, peer_id: usize, addr: std::net::SocketAddr) {
        if let Some(ref mut mgr) = self.network_builder {
            mgr.add_node_with_party_id(peer_id, addr);
        }
    }

    /// Start the server: convert builder to shared Arc.
    pub fn start(&mut self) -> Result<Arc<QuicNetworkManager>, String> {
        let mgr = self
            .network_builder
            .take()
            .ok_or("Server already started")?;
        let net = Arc::new(mgr);
        self.network = Some(net.clone());
        Ok(net)
    }

    /// Connect to all known peers.
    pub async fn connect_to_peers(&self) -> Result<(), String> {
        let net = self
            .network
            .as_ref()
            .ok_or("Server not started")?;

        let connections = net.get_all_server_connections();
        let peer_addrs: Vec<_> = connections
            .iter()
            .filter(|(id, _)| *id != self.node_id)
            .map(|(id, conn)| (*id, conn.clone()))
            .collect();

        info!(
            "[ADKG] Party {} connecting to {} peers",
            self.node_id,
            peer_addrs.len()
        );

        // Connections are already established through discovery/session setup
        // Just verify we have the right number of peers
        let connected = net.parties().len();
        if connected < self.n - 1 {
            warn!(
                "[ADKG] Party {} has {} connections, expected {}",
                self.node_id,
                connected,
                self.n - 1
            );
        }

        Ok(())
    }

    /// Exchange ECDH public keys with all peers.
    ///
    /// Each party broadcasts its `pk_i = g * sk_i` and collects all others.
    /// Returns the collected public key map indexed by party ID.
    pub async fn exchange_public_keys(&mut self) -> Result<Arc<Vec<G>>, String> {
        let net = self
            .network
            .as_ref()
            .ok_or("Server not started")?
            .clone();

        info!(
            "[ADKG] Party {} starting public key exchange (n={})",
            self.node_id, self.n
        );

        // Serialize our public key
        let mut pk_bytes = Vec::new();
        self.pk_i
            .serialize_compressed(&mut pk_bytes)
            .map_err(|e| format!("Failed to serialize public key: {:?}", e))?;

        // Create envelope: [party_id: u32][pk_bytes]
        let mut envelope = Vec::with_capacity(4 + pk_bytes.len());
        envelope.extend_from_slice(&(self.node_id as u32).to_le_bytes());
        envelope.extend_from_slice(&pk_bytes);

        // Send to all peers
        let connections = net.get_all_server_connections();
        for (peer_id, conn) in &connections {
            if *peer_id == self.node_id {
                continue;
            }
            if let Err(e) = conn.send(&envelope).await {
                error!(
                    "[ADKG] Party {} failed to send PK to peer {}: {}",
                    self.node_id, peer_id, e
                );
            }
        }

        // Collect public keys (initialize with our own)
        let mut pk_map = vec![G::default(); self.n];
        pk_map[self.node_id] = self.pk_i;

        let mut received = 1usize; // Count ourselves
        let deadline =
            std::time::Instant::now() + self.config.pk_exchange_timeout;

        // Create a channel for receiving PK exchange messages
        let (pk_tx, mut pk_rx) = mpsc::channel::<(usize, G)>(self.n);

        // Spawn receive tasks for each peer connection
        for (peer_id, conn) in &connections {
            if *peer_id == self.node_id {
                continue;
            }
            let peer_id = *peer_id;
            let tx = pk_tx.clone();
            let conn = conn.clone();
            tokio::spawn(async move {
                match conn.receive().await {
                    Ok(data) => {
                        if data.len() < 4 {
                            error!("[ADKG] Invalid PK message from peer {}", peer_id);
                            return;
                        }
                        let sender_id =
                            u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
                        match G::deserialize_compressed(&data[4..]) {
                            Ok(pk) => {
                                let _ = tx.send((sender_id, pk)).await;
                            }
                            Err(e) => {
                                error!(
                                    "[ADKG] Failed to deserialize PK from party {}: {:?}",
                                    sender_id, e
                                );
                            }
                        }
                    }
                    Err(e) => {
                        error!(
                            "[ADKG] Failed to receive PK from peer {}: {}",
                            peer_id, e
                        );
                    }
                }
            });
        }
        drop(pk_tx); // Drop our sender so the loop below terminates

        // Collect PKs with timeout
        while received < self.n {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(format!(
                    "Timeout during PK exchange: received {}/{} keys",
                    received, self.n
                ));
            }

            match tokio::time::timeout(remaining, pk_rx.recv()).await {
                Ok(Some((sender_id, pk))) => {
                    if sender_id < self.n {
                        pk_map[sender_id] = pk;
                        received += 1;
                        info!(
                            "[ADKG] Party {} received PK from party {} ({}/{})",
                            self.node_id, sender_id, received, self.n
                        );
                    }
                }
                Ok(None) => {
                    // Channel closed - all senders dropped
                    break;
                }
                Err(_) => {
                    return Err(format!(
                        "Timeout during PK exchange: received {}/{} keys",
                        received, self.n
                    ));
                }
            }
        }

        if received < self.n {
            return Err(format!(
                "PK exchange incomplete: received {}/{} keys",
                received, self.n
            ));
        }

        info!(
            "[ADKG] Party {} completed PK exchange with all {} parties",
            self.node_id, self.n
        );

        let pk_arc = Arc::new(pk_map);
        self.pk_map = Some(pk_arc.clone());
        Ok(pk_arc)
    }

    /// Create an ADKG engine using the collected public keys.
    ///
    /// Must be called after `exchange_public_keys()`.
    pub fn create_engine(&self) -> Result<Arc<AdkgMpcEngine<F, G>>, String> {
        let net = self
            .network
            .as_ref()
            .ok_or("Server not started")?
            .clone();
        let pk_map = self
            .pk_map
            .as_ref()
            .ok_or("Public keys not exchanged yet")?
            .clone();

        AdkgMpcEngine::new(
            self.instance_id,
            self.node_id,
            self.n,
            self.t,
            net,
            self.sk_i,
            pk_map,
        )
    }

    /// Spawn AVSS message receive/process loops for all peer connections.
    ///
    /// Incoming messages are deserialized as `AvssMessage` and routed to the engine.
    pub async fn spawn_message_loops(
        &self,
        engine: Arc<AdkgMpcEngine<F, G>>,
    ) -> Result<mpsc::Receiver<Vec<u8>>, String> {
        let net = self
            .network
            .as_ref()
            .ok_or("Server not started")?
            .clone();

        let (msg_tx, msg_rx) = mpsc::channel::<Vec<u8>>(1000);

        let connections = net.get_all_server_connections();
        for (peer_id, conn) in &connections {
            if *peer_id == self.node_id {
                continue;
            }
            let peer_id = *peer_id;
            let engine = engine.clone();
            let tx = msg_tx.clone();
            let conn = conn.clone();
            let shutdown_token = self.shutdown_token.clone();

            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown_token.cancelled() => {
                            info!("[ADKG] Message loop for peer {} shutting down", peer_id);
                            break;
                        }
                        result = conn.receive() => {
                            match result {
                                Ok(data) => {
                                    // Try to deserialize as AVSS message
                                    match bincode::deserialize::<AvssMessage<AvssSessionId>>(&data) {
                                        Ok(avss_msg) => {
                                            if let Err(e) = engine.process_message(avss_msg).await {
                                                error!(
                                                    "[ADKG] Party failed to process AVSS message from {}: {}",
                                                    peer_id, e
                                                );
                                            }
                                        }
                                        Err(_) => {
                                            // Not an AVSS message, forward as raw bytes
                                            let _ = tx.send(data).await;
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!(
                                        "[ADKG] Connection to peer {} closed: {}",
                                        peer_id, e
                                    );
                                    break;
                                }
                            }
                        }
                    }
                }
            });
        }

        Ok(msg_rx)
    }

    /// Gracefully shut down the server, cancelling all message loops.
    pub fn stop(&self) {
        info!("[ADKG] Shutting down server for party {}", self.node_id);
        self.shutdown_token.cancel();
    }
}
