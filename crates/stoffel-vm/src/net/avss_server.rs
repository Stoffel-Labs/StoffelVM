//! AVSS server with QUIC networking.
//!
//! This module provides the networking layer for AVSS (Asynchronous Verifiable
//! Secret Sharing) nodes, handling connection management, ECDH public key exchange,
//! and AVSS message routing.
//!
//! QUIC/TLS (including ALPN and certificates) provides transport authentication
//! and peer identity. The AVSS ECDH keys exchanged here are used for payload
//! confidentiality inside AVSS protocol messages. These mechanisms are
//! complementary and intentionally both required.
//!
//! The server is generic over a `(F, G)` field/curve pair. Use the type aliases
//! `Bls12381AvssServer`, `Bn254AvssServer`, `Curve25519AvssServer`, or
//! `Ed25519AvssServer` for the supported configurations.

use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{FftField, PrimeField};
use ark_std::rand::SeedableRng;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use stoffelnet::network_utils::{ClientId, Network, Node};
use stoffelnet::transports::quic::{NetworkManager, QuicNetworkManager};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use super::avss_engine::AvssMpcEngine;

// ============================================================================
// Type aliases for supported curve configurations
// ============================================================================

pub type Bls12381AvssServer = AvssQuicServer<ark_bls12_381::Fr, ark_bls12_381::G1Projective>;
pub type Bn254AvssServer = AvssQuicServer<ark_bn254::Fr, ark_bn254::G1Projective>;
pub type Curve25519AvssServer =
    AvssQuicServer<ark_curve25519::Fr, ark_curve25519::EdwardsProjective>;
pub type Ed25519AvssServer = AvssQuicServer<ark_ed25519::Fr, ark_ed25519::EdwardsProjective>;

/// Configuration for AVSS over QUIC
#[derive(Debug, Clone)]
pub struct AvssQuicConfig {
    /// Timeout for public key exchange
    pub pk_exchange_timeout: Duration,
    /// Connection retry attempts
    pub max_connection_retries: u32,
    /// Delay between connection attempts
    pub connection_retry_delay: Duration,
}

impl Default for AvssQuicConfig {
    fn default() -> Self {
        Self {
            pk_exchange_timeout: Duration::from_secs(30),
            max_connection_retries: 5,
            connection_retry_delay: Duration::from_millis(100),
        }
    }
}

/// An AVSS server node using QUIC networking.
///
/// Manages network setup, ECDH key exchange, and AVSS message routing
/// for the full AVSS MPC protocol (share generation, multiplication via Beaver
/// triples, random share generation, and preprocessing).
///
/// ECDH keys are needed because AVSS encrypts share payloads with ECDH between
/// parties (unlike HoneyBadger, which sends shares in plaintext over TLS).
/// Transport authentication is handled separately by QUIC/TLS.
///
/// Generic over `(F, G)` where `F` is the scalar field and `G` is the curve group.
/// Use the type aliases: `Bls12381AvssServer`, `Bn254AvssServer`,
/// `Curve25519AvssServer`, or `Ed25519AvssServer`.
pub struct AvssQuicServer<F, G>
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
    /// Instance ID for the AVSS session
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
    pub config: AvssQuicConfig,
    /// Router shared by this server's receive loops and AVSS engine.
    pub open_message_router: Arc<crate::net::open_registry::OpenMessageRouter>,
    /// Accept loop task handle
    accept_task: Option<JoinHandle<()>>,
    /// Cancellation token for graceful shutdown
    shutdown_token: CancellationToken,
}

impl<F, G> AvssQuicServer<F, G>
where
    F: FftField + PrimeField + Send + Sync + 'static,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    #[inline]
    fn decode_public_key_envelope(
        authenticated_peer_id: Option<usize>,
        payload: &[u8],
        n_parties: usize,
    ) -> Result<(usize, G), String> {
        if payload.len() < 4 {
            return Err(format!(
                "Invalid PK message from peer {:?}: too short",
                authenticated_peer_id
            ));
        }

        let declared_sender =
            u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
        if let Some(auth_id) = authenticated_peer_id {
            // Security model: TLS mutual authentication prevents unauthorized connections.
            // The `auth_id >= n_parties` bypass handles early setup before party-ID mapping
            // is established (e.g., bootstrap phase where stoffelnet assigns temporary IDs
            // outside the protocol range). Once the mapping is set (`auth_id < n_parties`),
            // we enforce that the declared sender matches the authenticated transport identity.
            if auth_id < n_parties && declared_sender != auth_id {
                return Err(format!(
                    "PK sender mismatch: authenticated peer {} declared {}",
                    auth_id, declared_sender
                ));
            }
        }

        if declared_sender >= n_parties {
            return Err(format!(
                "Invalid declared sender {} (n={})",
                declared_sender, n_parties
            ));
        }

        let pk = G::deserialize_compressed(&payload[4..]).map_err(|e| {
            format!(
                "Failed to deserialize PK from authenticated peer {:?}: {:?}",
                authenticated_peer_id, e
            )
        })?;
        Ok((declared_sender, pk))
    }

    #[inline]
    fn insert_public_key_once(
        sender_id: usize,
        pk: G,
        n_parties: usize,
        seen_senders: &mut HashSet<usize>,
        pk_map: &mut [G],
    ) -> bool {
        if sender_id >= n_parties {
            return false;
        }
        if !seen_senders.insert(sender_id) {
            return false;
        }
        pk_map[sender_id] = pk;
        true
    }

    /// Creates a new AVSS QUIC server.
    ///
    /// Generates a fresh ECDH key pair for this party.
    pub fn new(
        node_id: usize,
        n: usize,
        t: usize,
        instance_id: u64,
        network: QuicNetworkManager,
        config: AvssQuicConfig,
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
            open_message_router: Arc::new(crate::net::open_registry::OpenMessageRouter::new()),
            accept_task: None,
            shutdown_token: CancellationToken::new(),
        }
    }

    /// Creates an AVSS server with a pre-existing key pair (for testing).
    pub fn with_keys(
        node_id: usize,
        n: usize,
        t: usize,
        instance_id: u64,
        network: QuicNetworkManager,
        config: AvssQuicConfig,
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
            open_message_router: Arc::new(crate::net::open_registry::OpenMessageRouter::new()),
            accept_task: None,
            shutdown_token: CancellationToken::new(),
        }
    }

    /// Add a peer before starting.
    pub fn add_peer(&mut self, peer_id: usize, addr: std::net::SocketAddr) {
        if let Some(ref mut mgr) = self.network_builder {
            mgr.add_node_with_party_id(peer_id, addr);
        }
    }

    /// Start the server: convert builder to shared Arc and spawn accept loop.
    ///
    /// The accept loop handles incoming connections from peers that dial us.
    /// After calling `start()`, call `connect_to_peers()` to establish outgoing
    /// connections to all known peers.
    pub fn start(&mut self) -> Result<Arc<QuicNetworkManager>, String> {
        let mgr = self
            .network_builder
            .take()
            .ok_or("Server already started")?;
        let net = Arc::new(mgr);
        self.network = Some(net.clone());

        // Spawn accept loop to handle incoming connections
        let mut acceptor = (*net).clone();
        let node_id = self.node_id;
        let shutdown_token = self.shutdown_token.clone();

        let accept_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_token.cancelled() => {
                        info!("[AVSS] Accept loop for node {} shutting down", node_id);
                        break;
                    }
                    result = acceptor.accept() => {
                        match result {
                            Ok(connection) => {
                                info!(
                                    "[AVSS] Node {} accepted connection from {}",
                                    node_id,
                                    connection.remote_address()
                                );
                                // Connection is accepted; the peer's dialer will use
                                // its own connection handle for send/receive.
                            }
                            Err(e) => {
                                warn!(
                                    "[AVSS] Node {} failed to accept connection: {}",
                                    node_id, e
                                );
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                        }
                    }
                }
            }
        });

        self.accept_task = Some(accept_task);

        info!(
            "[AVSS] Server started for party {} (accept loop spawned)",
            self.node_id
        );

        Ok(net)
    }

    /// Connect to all known peers by dialing each one.
    ///
    /// Must be called after `start()`. Establishes outgoing QUIC connections
    /// to every registered peer. The accept loop (spawned in `start()`) handles
    /// the incoming side of these connections on the remote peers.
    pub async fn connect_to_peers(&self) -> Result<(), String> {
        let net = self.network.as_ref().ok_or("Server not started")?;

        let peers: Vec<(usize, SocketAddr)> = net
            .parties()
            .iter()
            .map(|p| (p.id(), p.address()))
            .collect();

        // Clone the network manager to get mutable access for dialing
        let mut dialer = (**net).clone();

        info!(
            "[AVSS] Party {} connecting to {} peers (including self)",
            self.node_id,
            peers.len()
        );

        for (peer_id, peer_addr) in peers {
            info!(
                "[AVSS] Node {} connecting to peer {} at {}",
                self.node_id, peer_id, peer_addr
            );

            let mut retry_count = 0u32;
            loop {
                match dialer.connect_as_server(peer_addr).await {
                    Ok(connection) => {
                        info!(
                            "[AVSS] Node {} connected to peer {} at {}",
                            self.node_id,
                            peer_id,
                            connection.remote_address()
                        );
                        break;
                    }
                    Err(e) => {
                        retry_count += 1;
                        if retry_count >= self.config.max_connection_retries {
                            let msg = format!(
                                "[AVSS] Node {} failed to connect to peer {} after {} attempts: {}",
                                self.node_id, peer_id, retry_count, e
                            );
                            error!("{}", msg);
                            return Err(msg);
                        }
                        info!(
                            "[AVSS] Node {} attempt {} to peer {} failed: {}",
                            self.node_id, retry_count, peer_id, e
                        );
                        tokio::time::sleep(self.config.connection_retry_delay).await;
                    }
                }
            }
        }

        Ok(())
    }

    /// Exchange ECDH public keys with all peers.
    ///
    /// Each party broadcasts its `pk_i = g * sk_i` and collects all others.
    /// Returns the collected public key map indexed by party ID.
    pub async fn exchange_public_keys(&mut self) -> Result<Arc<Vec<G>>, String> {
        let net = self.network.as_ref().ok_or("Server not started")?.clone();

        info!(
            "[AVSS] Party {} starting public key exchange (n={})",
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
                    "[AVSS] Party {} failed to send PK to peer {}: {}",
                    self.node_id, peer_id, e
                );
            }
        }

        // Collect public keys (initialize with our own)
        let mut pk_map = vec![G::default(); self.n];
        pk_map[self.node_id] = self.pk_i;

        let mut received = 1usize; // Count ourselves
        let mut seen_senders = HashSet::with_capacity(self.n);
        seen_senders.insert(self.node_id);
        let deadline = std::time::Instant::now() + self.config.pk_exchange_timeout;

        // Create a channel for receiving PK exchange messages
        let (pk_tx, mut pk_rx) = mpsc::channel::<(Option<usize>, Vec<u8>)>(self.n);

        // Spawn receive tasks for each peer connection
        for (peer_id, conn) in &connections {
            if *peer_id == self.node_id {
                continue;
            }
            let peer_id = *peer_id;
            let authenticated_peer_id = conn.remote_party_id();
            let tx = pk_tx.clone();
            let conn = conn.clone();
            tokio::spawn(async move {
                match conn.receive().await {
                    Ok(data) => {
                        let _ = tx.send((authenticated_peer_id, data)).await;
                    }
                    Err(e) => {
                        error!(
                            "[AVSS] Failed to receive PK from authenticated peer {}: {}",
                            authenticated_peer_id.unwrap_or(peer_id),
                            e
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
                Ok(Some((authenticated_peer_id, data))) => {
                    match Self::decode_public_key_envelope(authenticated_peer_id, &data, self.n) {
                        Ok((sender_id, pk)) => {
                            if !Self::insert_public_key_once(
                                sender_id,
                                pk,
                                self.n,
                                &mut seen_senders,
                                &mut pk_map,
                            ) {
                                warn!(
                                    "[AVSS] Party {} ignoring duplicate/out-of-range PK from party {}",
                                    self.node_id, sender_id
                                );
                                continue;
                            }

                            received += 1;
                            info!(
                                "[AVSS] Party {} received PK from party {} ({}/{})",
                                self.node_id, sender_id, received, self.n
                            );
                        }
                        Err(e) => {
                            warn!("[AVSS] Party {} rejecting PK message: {}", self.node_id, e);
                        }
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
            "[AVSS] Party {} completed PK exchange with all {} parties",
            self.node_id, self.n
        );

        let pk_arc = Arc::new(pk_map);
        self.pk_map = Some(pk_arc.clone());
        Ok(pk_arc)
    }

    /// Create an AVSS engine using the collected public keys.
    ///
    /// Must be called after `exchange_public_keys()`.
    ///
    /// `input_ids` are sequential client indices (0..num_clients) used by the
    /// AVSS InputServer protocol. Pass an empty vec if no clients will connect.
    pub async fn create_engine(
        &self,
        input_ids: Vec<ClientId>,
    ) -> Result<Arc<AvssMpcEngine<F, G>>, String> {
        let net = self.network.as_ref().ok_or("Server not started")?.clone();
        let pk_map = self
            .pk_map
            .as_ref()
            .ok_or("Public keys not exchanged yet")?
            .clone();

        AvssMpcEngine::new_with_router(
            self.open_message_router.clone(),
            self.instance_id,
            self.node_id,
            self.n,
            self.t,
            net,
            self.sk_i,
            pk_map,
            input_ids,
        )
        .await
    }

    /// Spawn AVSS message receive/process loops for all peer connections.
    ///
    /// Incoming messages are routed as raw bytes to the AVSS node via the engine.
    /// With ALPN-based routing, these per-peer loops may be superseded by
    /// per-protocol accept loops in the future.
    pub async fn spawn_message_loops(
        &self,
        engine: Arc<AvssMpcEngine<F, G>>,
    ) -> Result<mpsc::Receiver<Vec<u8>>, String> {
        let net = self.network.as_ref().ok_or("Server not started")?.clone();
        let router = engine.open_message_router();

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
            let net_clone = net.clone();
            let shutdown_token = self.shutdown_token.clone();
            let authenticated_sender_id = conn.remote_party_id().unwrap_or(peer_id);
            let router = router.clone();

            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown_token.cancelled() => {
                            info!("[AVSS] Message loop for peer {} shutting down", peer_id);
                            break;
                        }
                        result = conn.receive() => {
                            match result {
                                Ok(data) => {
                                    match router.try_handle_wire_message(authenticated_sender_id, &data) {
                                        Ok(true) => {
                                            continue;
                                        }
                                        Err(e) => {
                                            warn!(
                                                "[AVSS] Failed to handle open wire message from {}: {}",
                                                authenticated_sender_id, e
                                            );
                                            continue;
                                        }
                                        Ok(false) => {}
                                    }

                                    match router.try_handle_avss_open_exp_wire_message(authenticated_sender_id, &data) {
                                        Ok(true) => {
                                            continue;
                                        }
                                        Err(e) => {
                                            warn!(
                                                "[AVSS] Failed to handle open-exp wire message from {}: {}",
                                                authenticated_sender_id, e
                                            );
                                            continue;
                                        }
                                        Ok(false) => {}
                                    }

                                    match router.try_handle_avss_g2_exp_wire_message(authenticated_sender_id, &data) {
                                        Ok(true) => {
                                            continue;
                                        }
                                        Err(e) => {
                                            warn!(
                                                "[AVSS] Failed to handle G2 open-exp wire message from {}: {}",
                                                authenticated_sender_id, e
                                            );
                                            continue;
                                        }
                                        Ok(false) => {}
                                    }

                                    // Route raw bytes to the AVSS node with sender_id
                                    if let Err(e) = engine.process_wrapped_message_with_network(authenticated_sender_id, &data, net_clone.clone()).await {
                                        // May fail to process non-protocol messages; forward as raw bytes
                                        let _ = tx.send(data).await;
                                        if !e.contains("deserialize") && !e.contains("process failed") {
                                            error!(
                                                "[AVSS] Party failed to process message from {}: {}",
                                                authenticated_sender_id, e
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!(
                                        "[AVSS] Connection to peer {} closed: {}",
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

    /// Spawn receive loops for both server and client connections with separate channels.
    ///
    /// Returns `(server_rx, client_rx)` where:
    /// - `server_rx` receives `(party_id, raw_msg)` from peer parties
    /// - `client_rx` receives `(client_id, raw_msg)` from connected clients
    ///
    /// Server messages are routed through the engine's message processor.
    /// Client messages are forwarded raw for the caller to route through the
    /// AVSS node's `process()` with appropriate sender_id remapping.
    pub async fn spawn_message_loops_split(
        &self,
        engine: Arc<AvssMpcEngine<F, G>>,
    ) -> Result<
        (
            mpsc::Receiver<(usize, Vec<u8>)>,
            mpsc::Receiver<(usize, Vec<u8>)>,
        ),
        String,
    > {
        let net = self.network.as_ref().ok_or("Server not started")?.clone();
        let router = engine.open_message_router();

        let (server_tx, server_rx) = mpsc::channel::<(usize, Vec<u8>)>(65536);
        let (client_tx, client_rx) = mpsc::channel::<(usize, Vec<u8>)>(4096);

        // Server connection receive loops
        let connections = net.get_all_server_connections();
        for (peer_id, conn) in &connections {
            if *peer_id == self.node_id {
                continue;
            }
            let peer_id = *peer_id;
            let engine = engine.clone();
            let tx = server_tx.clone();
            let conn = conn.clone();
            let net_clone = net.clone();
            let shutdown_token = self.shutdown_token.clone();
            let authenticated_sender_id = conn.remote_party_id().unwrap_or(peer_id);
            let router = router.clone();

            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown_token.cancelled() => break,
                        result = conn.receive() => {
                            match result {
                                Ok(data) => {
                                    if let Ok(true) = router.try_handle_wire_message(authenticated_sender_id, &data) {
                                        continue;
                                    }
                                    if let Ok(true) = router.try_handle_avss_open_exp_wire_message(authenticated_sender_id, &data) {
                                        continue;
                                    }
                                    if let Ok(true) = router.try_handle_avss_g2_exp_wire_message(authenticated_sender_id, &data) {
                                        continue;
                                    }
                                    if let Err(e) = engine.process_wrapped_message_with_network(authenticated_sender_id, &data, net_clone.clone()).await {
                                        let _ = tx.send((authenticated_sender_id, data)).await;
                                        if !e.contains("deserialize") && !e.contains("process failed") {
                                            error!(
                                                "[AVSS] Party failed to process message from {}: {}",
                                                authenticated_sender_id, e
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!("[AVSS] Connection to peer {} closed: {}", peer_id, e);
                                    break;
                                }
                            }
                        }
                    }
                }
            });
        }

        // Client connection receive loops — poll for new client connections
        // and spawn a per-client receive task for each.
        let scan_net = net.clone();
        let shutdown_token = self.shutdown_token.clone();
        let node_id = self.node_id;
        tokio::spawn(async move {
            let mut spawned_client_ids = HashSet::new();
            loop {
                for (client_id, conn) in scan_net.get_all_client_connections() {
                    if !spawned_client_ids.insert(client_id) {
                        continue;
                    }
                    info!(
                        "[AVSS] Party {} spawning receive loop for client {}",
                        node_id, client_id
                    );
                    let txx = client_tx.clone();
                    let shutdown2 = shutdown_token.clone();
                    tokio::spawn(async move {
                        loop {
                            tokio::select! {
                                _ = shutdown2.cancelled() => break,
                                result = conn.receive() => {
                                    match result {
                                        Ok(data) => {
                                            if let Err(e) = txx.send((client_id, data)).await {
                                                warn!("[AVSS] Failed to forward client {} message: {}", client_id, e);
                                                break;
                                            }
                                        }
                                        Err(e) => {
                                            warn!("[AVSS] Client {} connection closed: {}", client_id, e);
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    });
                }
                tokio::select! {
                    _ = shutdown_token.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                }
            }
        });

        Ok((server_rx, client_rx))
    }

    /// Gracefully shut down the server, cancelling accept loop and message loops.
    pub fn stop(&self) {
        info!("[AVSS] Shutting down server for party {}", self.node_id);
        self.shutdown_token.cancel();
        if let Some(task) = &self.accept_task {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Projective as G1};
    use ark_ec::PrimeGroup;
    use ark_serialize::CanonicalSerialize;

    #[test]
    fn test_decode_public_key_envelope_rejects_sender_mismatch() {
        let pk = G1::generator();
        let mut pk_bytes = Vec::new();
        pk.serialize_compressed(&mut pk_bytes)
            .expect("serialize pk");

        let mut envelope = Vec::with_capacity(4 + pk_bytes.len());
        envelope.extend_from_slice(&(1u32).to_le_bytes());
        envelope.extend_from_slice(&pk_bytes);

        let err = AvssQuicServer::<Fr, G1>::decode_public_key_envelope(Some(2), &envelope, 4)
            .expect_err("mismatched sender must be rejected");
        assert!(
            err.contains("sender mismatch"),
            "expected sender mismatch error, got: {}",
            err
        );
    }

    #[test]
    fn test_decode_public_key_envelope_accepts_unassigned_transport_party_id() {
        let pk = G1::generator();
        let mut pk_bytes = Vec::new();
        pk.serialize_compressed(&mut pk_bytes)
            .expect("serialize pk");

        let mut envelope = Vec::with_capacity(4 + pk_bytes.len());
        envelope.extend_from_slice(&(1u32).to_le_bytes());
        envelope.extend_from_slice(&pk_bytes);

        let (sender, decoded) =
            AvssQuicServer::<Fr, G1>::decode_public_key_envelope(None, &envelope, 4)
                .expect("valid message should decode without remote_party_id assignment");
        assert_eq!(sender, 1);
        assert_eq!(decoded, pk);
    }

    #[test]
    fn test_insert_public_key_once_rejects_duplicates() {
        let n = 4usize;
        let mut seen = HashSet::new();
        seen.insert(0usize);
        let mut pk_map = vec![G1::default(); n];

        let pk_first = G1::generator();
        let accepted = AvssQuicServer::<Fr, G1>::insert_public_key_once(
            1,
            pk_first,
            n,
            &mut seen,
            &mut pk_map,
        );
        assert!(accepted, "first key for sender should be accepted");
        assert_eq!(pk_map[1], pk_first);

        let pk_duplicate = G1::generator() + G1::generator();
        let accepted_duplicate = AvssQuicServer::<Fr, G1>::insert_public_key_once(
            1,
            pk_duplicate,
            n,
            &mut seen,
            &mut pk_map,
        );
        assert!(!accepted_duplicate, "duplicate sender must not be accepted");
        assert_eq!(
            pk_map[1], pk_first,
            "duplicate must not overwrite stored PK"
        );
    }
}
