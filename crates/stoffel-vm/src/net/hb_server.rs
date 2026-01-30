//! HoneyBadger MPC server with QUIC networking and receive loops.
//!
//! This module provides the networking layer for HoneyBadger MPC nodes,
//! handling connection management and message routing.

use ark_bls12_381::Fr;
use ark_ff::{FftField, PrimeField};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::common::MPCProtocol;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::{HoneyBadgerError, HoneyBadgerMPCNode, HoneyBadgerMPCNodeOpts};
use stoffelnet::network_utils::{ClientId, Network, NetworkError, Node, PartyId};
use stoffelnet::transports::quic::{NetworkManager, QuicNetworkManager};
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;
use tracing::{error, info, warn};

/// Configuration for HoneyBadger MPC over QUIC
#[derive(Debug, Clone)]
pub struct HoneyBadgerQuicConfig {
    /// Timeout for MPC operations
    pub mpc_timeout: Duration,
    /// Connection retry attempts
    pub max_connection_retries: u32,
    /// Delay between connection attempts
    pub connection_retry_delay: Duration,
}

impl Default for HoneyBadgerQuicConfig {
    fn default() -> Self {
        Self {
            mpc_timeout: Duration::from_secs(30),
            max_connection_retries: 5,
            connection_retry_delay: Duration::from_millis(100),
        }
    }
}

/// A HoneyBadger MPC server node using QUIC networking.
///
/// This struct manages the networking layer for a HoneyBadger MPC node,
/// including connection acceptance, peer connections, and message routing
/// via receive loops.
pub struct HoneyBadgerQuicServer<F: FftField + PrimeField> {
    /// The underlying MPC node
    pub node: HoneyBadgerMPCNode<F, Avid>,
    /// Network manager builder - used during setup before start() is called
    network_builder: Option<QuicNetworkManager>,
    /// Network manager Arc - created when start() is called, shared with all tasks
    pub network: Option<Arc<QuicNetworkManager>>,
    /// Connection handling task handle
    connection_task: Option<tokio::task::JoinHandle<()>>,
    /// Configuration
    pub config: HoneyBadgerQuicConfig,
    /// Shutdown signal
    shutdown_tx: Option<mpsc::Sender<()>>,
    /// Node ID
    pub node_id: PartyId,
    /// Channel for routing received messages
    pub channels: Sender<Vec<u8>>,
}

impl<F: FftField + PrimeField + 'static> HoneyBadgerQuicServer<F> {
    /// Creates a new HoneyBadger QUIC server
    pub async fn new(
        node_id: PartyId,
        bind_address: SocketAddr,
        mpc_opts: HoneyBadgerMPCNodeOpts,
        config: HoneyBadgerQuicConfig,
        channels: Sender<Vec<u8>>,
        input_ids: Vec<ClientId>,
    ) -> Result<Self, HoneyBadgerError> {
        // Create the MPC node
        let mpc_node = <HoneyBadgerMPCNode<F, Avid> as MPCProtocol<
            F,
            RobustShare<F>,
            QuicNetworkManager,
        >>::setup(node_id, mpc_opts, input_ids)?;

        // Create network manager
        info!(
            "[HB-QUIC] Initializing network manager for node {} at {}",
            node_id, bind_address
        );
        let mut base_manager = QuicNetworkManager::with_node_id(node_id);
        info!(
            "[HB-QUIC] Node {} calling listen({})",
            node_id, bind_address
        );
        base_manager.listen(bind_address).await.map_err(|e| {
            error!(
                "[HB-QUIC] Node {} failed to bind to {}: {}",
                node_id, bind_address, e
            );
            HoneyBadgerError::NetworkError(NetworkError::Timeout)
        })?;
        info!(
            "[HB-QUIC] Node {} successfully bound to {}",
            node_id, bind_address
        );

        // Ensure the local party is registered in the party map
        base_manager.add_node_with_party_id(node_id, bind_address);

        let initial_parties = base_manager.parties().len();
        info!(
            "Created HoneyBadger QUIC server for node {} on {} (initial peers: {})",
            node_id, bind_address, initial_parties
        );

        Ok(Self {
            node: mpc_node,
            network_builder: Some(base_manager),
            network: None,
            connection_task: None,
            config,
            shutdown_tx: None,
            node_id,
            channels,
        })
    }

    /// Adds a peer node to connect to. Must be called before start().
    pub async fn add_peer(&mut self, peer_id: PartyId, address: SocketAddr) {
        if let Some(ref mut builder) = self.network_builder {
            builder.add_node_with_party_id(peer_id, address);
            info!(
                "Added peer {} at {} to node {}",
                peer_id, address, self.node_id
            );
        } else {
            panic!(
                "Cannot add peer after start() has been called on node {}",
                self.node_id
            );
        }
    }

    /// Starts the server and begins accepting connections.
    ///
    /// This spawns a background task that accepts incoming connections
    /// and routes received messages to the channel.
    pub async fn start(&mut self) -> Result<(), HoneyBadgerError> {
        if self.connection_task.is_some() {
            warn!("Server already started");
            return Ok(());
        }

        // Convert builder to Arc - this freezes the peer list
        let network = Arc::new(
            self.network_builder
                .take()
                .expect("start() called but network_builder is None"),
        );
        self.network = Some(network.clone());

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
        self.shutdown_tx = Some(shutdown_tx);

        info!("Starting HoneyBadger QUIC server on node {}", self.node_id);

        // Start connection acceptance task
        let mut acceptor = (*network).clone();
        let node_id = self.node_id;
        let tx = self.channels.clone();

        let connection_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        info!("Shutting down connection handler for node {}", node_id);
                        break;
                    }
                    result = async {
                        info!("[HB-QUIC] Node {} waiting to accept incoming connection...", node_id);
                        acceptor.accept().await
                    } => {
                        match result {
                            Ok(connection) => {
                                info!("Node {} accepted connection from {}", node_id, connection.remote_address());

                                // Spawn a task to handle this connection's messages
                                let txx = tx.clone();
                                let conn_node_id = node_id;

                                info!("[HB-QUIC] Node {} spawning message handler for connection {}", conn_node_id, connection.remote_address());
                                tokio::spawn(async move {
                                    loop {
                                        match connection.receive().await {
                                            Ok(data) => {
                                                info!("[HB-QUIC] Node {} received {} bytes from {}", conn_node_id, data.len(), connection.remote_address());
                                                if let Err(e) = txx.send(data).await {
                                                    error!("Node {} failed to handle message: {:?}", conn_node_id, e);
                                                }
                                            }
                                            Err(e) => {
                                                info!("Connection closed: {}", e);
                                                break;
                                            }
                                        }
                                    }
                                });
                            }
                            Err(e) => {
                                warn!("Node {} failed to accept connection: {}", node_id, e);
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                        }
                    }
                }
            }
        });

        self.connection_task = Some(connection_task);

        Ok(())
    }

    /// Connects to all configured peer nodes. Must be called after start().
    ///
    /// This establishes outgoing connections to all peers and spawns
    /// receive loops for each connection.
    pub async fn connect_to_peers(&self) -> Result<(), HoneyBadgerError> {
        let network = self
            .network
            .as_ref()
            .expect("connect_to_peers() called before start()");

        let peers: Vec<(PartyId, SocketAddr)> = network
            .parties()
            .iter()
            .map(|p| (p.id(), p.address()))
            .collect();

        let mut dialer = (**network).clone();
        info!(
            "[HB-QUIC] Node {} discovered {} peers (including self)",
            self.node_id,
            peers.len()
        );

        for (peer_id, peer_addr) in peers {
            info!(
                "Node {} connecting to peer {} at {}",
                self.node_id, peer_id, peer_addr
            );

            let mut retry_count = 0;
            loop {
                // Note: In new stoffelnet, server ID is derived from public key,
                // not passed as a parameter. Call assign_sender_ids() after all
                // connections are established.
                let connection_result = dialer.connect_as_server(peer_addr).await;

                match connection_result {
                    Ok(connection) => {
                        info!(
                            "Node {} successfully connected to peer {}",
                            self.node_id, peer_id
                        );

                        // Spawn message handler for this connection
                        let pid_for_task = peer_id;
                        let txx = self.channels.clone();
                        tokio::spawn(async move {
                            loop {
                                match connection.receive().await {
                                    Ok(data) => {
                                        if let Err(e) = txx.send(data).await {
                                            error!(
                                                "Failed to handle message from peer {}: {:?}",
                                                pid_for_task, e
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        info!("Connection to peer {} closed: {}", pid_for_task, e);
                                        break;
                                    }
                                }
                            }
                        });
                        break;
                    }
                    Err(e) => {
                        retry_count += 1;
                        if retry_count >= self.config.max_connection_retries {
                            warn!(
                                "Node {} failed to connect to peer {} after {} attempts: {}",
                                self.node_id, peer_id, retry_count, e
                            );
                            break;
                        }

                        info!(
                            "Node {} connection attempt {} to peer {} failed: {}",
                            self.node_id, retry_count, peer_id, e
                        );
                        tokio::time::sleep(self.config.connection_retry_delay).await;
                    }
                }
            }
        }

        // After all connections are established, assign sender IDs based on public key ordering.
        // This ensures all parties have consistent sender IDs for the MPC protocol.
        let assigned_count = dialer.assign_sender_ids();
        info!(
            "[HB-QUIC] Node {} assigned sender IDs to {} connections",
            self.node_id, assigned_count
        );

        Ok(())
    }

    /// Stops the server
    pub async fn stop(&mut self) {
        info!("Stopping HoneyBadger QUIC server for node {}", self.node_id);

        // Send shutdown signal
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }

        // Wait for tasks to complete
        if let Some(task) = self.connection_task.take() {
            let _ = task.await;
        }

        info!("Stopped HoneyBadger QUIC server for node {}", self.node_id);
    }
}

/// Type alias for the common Fr field server
pub type FrHoneyBadgerQuicServer = HoneyBadgerQuicServer<Fr>;

/// Spawns receive loops for all connections in a network manager.
///
/// This is useful when you have an existing network manager with established
/// connections and want to add message routing without using the full
/// `HoneyBadgerQuicServer`.
///
/// Returns a channel receiver that will receive all incoming messages.
pub async fn spawn_receive_loops(
    net: Arc<QuicNetworkManager>,
    node_id: PartyId,
    n_parties: usize,
) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel::<Vec<u8>>(1024);

    // Get all established connections
    let connections = net.get_all_connections().await;
    eprintln!(
        "[party {}] spawn_receive_loops: found {} connections",
        node_id,
        connections.len()
    );

    // Spawn a receive loop for each MPC peer connection (party IDs 0 to n_parties-1)
    // Skip bootnode and other non-MPC connections (which have large random UUIDs)
    for (peer_id, connection) in connections {
        // Only process connections to MPC peers (party IDs < n_parties)
        if peer_id >= n_parties {
            eprintln!(
                "[party {}] Skipping receive loop for non-MPC connection {} (bootnode/other)",
                node_id, peer_id
            );
            continue;
        }
        let txx = tx.clone();
        let conn_node_id = node_id;
        let pid = peer_id;
        eprintln!(
            "[party {}] Spawning receive loop for peer {}",
            conn_node_id, pid
        );

        tokio::spawn(async move {
            eprintln!(
                "[party {}] Receive loop started for peer {}",
                conn_node_id, pid
            );
            loop {
                match connection.receive().await {
                    Ok(data) => {
                        eprintln!(
                            "[party {}] Received {} bytes from peer {}",
                            conn_node_id,
                            data.len(),
                            pid
                        );
                        if let Err(e) = txx.send(data).await {
                            eprintln!(
                                "[party {}] Failed to forward message from peer {}: {:?}",
                                conn_node_id, pid, e
                            );
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "[party {}] Connection to peer {} closed: {}",
                            conn_node_id, pid, e
                        );
                        break;
                    }
                }
            }
        });
    }

    rx
}
