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
use stoffelmpc_mpc::honeybadger::SessionId as HbSessionId;
use stoffelmpc_mpc::honeybadger::{HoneyBadgerError, HoneyBadgerMPCNode, HoneyBadgerMPCNodeOpts};
use stoffelnet::network_utils::{ClientId, Network, NetworkError, Node, PartyId};
use stoffelnet::transports::quic::{NetworkManager, QuicNetworkConfig, QuicNetworkManager};
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
    pub node: HoneyBadgerMPCNode<F, Avid<HbSessionId>>,
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
        let mpc_node = <HoneyBadgerMPCNode<F, Avid<HbSessionId>> as MPCProtocol<
            F,
            RobustShare<F>,
            QuicNetworkManager,
        >>::setup(node_id, mpc_opts, input_ids)?;

        // Create network manager
        info!(
            "[HB-QUIC] Initializing network manager for node {} at {}",
            node_id, bind_address
        );
        let mut base_manager = QuicNetworkManager::with_config(QuicNetworkConfig {
            use_tls: false,
            ..Default::default()
        });
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
                                                let sender_id =
                                                    connection.remote_party_id().unwrap_or(crate::net::open_registry::UNKNOWN_SENDER_ID);
                                                match crate::net::open_registry::try_handle_wire_message(
                                                    sender_id, &data,
                                                ) {
                                                    Ok(true) => continue,
                                                    Err(e) => {
                                                        warn!(
                                                            "Node {} failed to handle open wire message from {}: {}",
                                                            conn_node_id, sender_id, e
                                                        );
                                                        continue;
                                                    }
                                                    Ok(false) => {}
                                                }
                                                match crate::net::hb_engine::try_handle_open_exp_wire_message(
                                                    sender_id, &data,
                                                ) {
                                                    Ok(true) => continue,
                                                    Err(e) => {
                                                        warn!(
                                                            "Node {} failed to handle open_exp wire message from {}: {}",
                                                            conn_node_id, sender_id, e
                                                        );
                                                        continue;
                                                    }
                                                    Ok(false) => {}
                                                }
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
                                        match crate::net::open_registry::try_handle_wire_message(
                                            pid_for_task,
                                            &data,
                                        ) {
                                            Ok(true) => continue,
                                            Err(e) => {
                                                warn!(
                                                    "Failed to handle open wire message from peer {}: {}",
                                                    pid_for_task, e
                                                );
                                                continue;
                                            }
                                            Ok(false) => {}
                                        }
                                        match crate::net::hb_engine::try_handle_open_exp_wire_message(
                                            pid_for_task,
                                            &data,
                                        ) {
                                            Ok(true) => continue,
                                            Err(e) => {
                                                warn!(
                                                    "Failed to handle open_exp wire message from peer {}: {}",
                                                    pid_for_task, e
                                                );
                                                continue;
                                            }
                                            Ok(false) => {}
                                        }

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
) -> mpsc::Receiver<(PartyId, Vec<u8>)> {
    let (tx, rx) = mpsc::channel::<(PartyId, Vec<u8>)>(65536);
    let scan_tx = tx.clone();
    // Note: client messages also go through this channel. If you need
    // separate client handling, use spawn_receive_loops_split instead.
    let scan_net = net.clone();
    tokio::spawn(async move {
        let mut spawned_server_ids = std::collections::HashSet::new();
        let mut spawned_client_ids = std::collections::HashSet::new();

        loop {
            // Server-to-server connections (MPC parties)
            for (derived_id, connection) in scan_net.get_all_server_connections() {
                let sender_id = connection.remote_party_id().unwrap_or(derived_id);
                if sender_id >= n_parties {
                    tracing::debug!(
                        party_id = node_id,
                        derived_id,
                        sender_id,
                        n_parties,
                        "Skipping non-party server connection"
                    );
                    continue;
                }

                if !spawned_server_ids.insert(sender_id) {
                    continue;
                }

                let txx = scan_tx.clone();
                let local_party_id = node_id;
                tracing::info!(
                    party_id = local_party_id,
                    derived_id,
                    sender_id,
                    "Spawning receive loop for server connection"
                );

                tokio::spawn(async move {
                    loop {
                        match connection.receive().await {
                            Ok(data) => {
                                match crate::net::open_registry::try_handle_wire_message(
                                    sender_id, &data,
                                ) {
                                    Ok(true) => continue,
                                    Err(e) => {
                                        tracing::warn!(
                                            party_id = local_party_id,
                                            sender_id,
                                            error = %e,
                                            "Failed to handle open wire message"
                                        );
                                        continue;
                                    }
                                    Ok(false) => {}
                                }

                                match crate::net::hb_engine::try_handle_open_exp_wire_message(
                                    sender_id, &data,
                                ) {
                                    Ok(true) => continue,
                                    Err(e) => {
                                        tracing::warn!(
                                            party_id = local_party_id,
                                            sender_id,
                                            error = %e,
                                            "Failed to handle open_exp wire message"
                                        );
                                        continue;
                                    }
                                    Ok(false) => {}
                                }

                                if let Err(e) = txx.send((sender_id, data)).await {
                                    tracing::warn!(
                                        party_id = local_party_id,
                                        sender_id,
                                        error = ?e,
                                        "Failed to forward server message"
                                    );
                                    break;
                                }
                            }
                            Err(e) => {
                                tracing::info!(
                                    party_id = local_party_id,
                                    sender_id,
                                    error = %e,
                                    "Server connection closed"
                                );
                                break;
                            }
                        }
                    }
                });
            }

            // Client-to-server connections (external input clients)
            for (client_id, connection) in scan_net.get_all_client_connections() {
                if !spawned_client_ids.insert(client_id) {
                    continue;
                }

                let txx = scan_tx.clone();
                let local_party_id = node_id;
                tracing::info!(
                    party_id = local_party_id,
                    client_id,
                    "Spawning receive loop for client connection"
                );

                tokio::spawn(async move {
                    loop {
                        match connection.receive().await {
                            Ok(data) => {
                                if let Err(e) = txx.send((client_id, data)).await {
                                    tracing::warn!(
                                        party_id = local_party_id,
                                        client_id,
                                        error = ?e,
                                        "Failed to forward client message"
                                    );
                                    break;
                                }
                            }
                            Err(e) => {
                                tracing::info!(
                                    party_id = local_party_id,
                                    client_id,
                                    error = %e,
                                    "Client connection closed"
                                );
                                break;
                            }
                        }
                    }
                });
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });

    rx
}

/// Like `spawn_receive_loops` but returns separate channels for server (party-to-party)
/// messages and client (input provider) messages. This prevents the preprocessing
/// message backlog from blocking client input delivery.
pub async fn spawn_receive_loops_split(
    net: Arc<QuicNetworkManager>,
    node_id: PartyId,
    n_parties: usize,
) -> (
    mpsc::Receiver<(PartyId, Vec<u8>)>,
    mpsc::Receiver<(PartyId, Vec<u8>)>,
) {
    let (server_tx, server_rx) = mpsc::channel::<(PartyId, Vec<u8>)>(65536);
    let (client_tx, client_rx) = mpsc::channel::<(PartyId, Vec<u8>)>(4096);
    let scan_net = net.clone();
    tokio::spawn(async move {
        let mut spawned_server_ids = std::collections::HashSet::new();
        let mut spawned_client_ids = std::collections::HashSet::new();

        loop {
            // Server-to-server connections (MPC parties)
            for (derived_id, connection) in scan_net.get_all_server_connections() {
                let sender_id = connection.remote_party_id().unwrap_or(derived_id);
                if sender_id >= n_parties {
                    continue;
                }
                if !spawned_server_ids.insert(sender_id) {
                    continue;
                }

                let txx = server_tx.clone();
                let local_party_id = node_id;
                tracing::info!(
                    party_id = local_party_id,
                    sender_id,
                    "Spawning server receive loop"
                );

                tokio::spawn(async move {
                    loop {
                        match connection.receive().await {
                            Ok(data) => {
                                match crate::net::open_registry::try_handle_wire_message(
                                    sender_id, &data,
                                ) {
                                    Ok(true) => continue,
                                    Err(_) => continue,
                                    Ok(false) => {}
                                }
                                match crate::net::hb_engine::try_handle_open_exp_wire_message(
                                    sender_id, &data,
                                ) {
                                    Ok(true) => continue,
                                    Err(_) => continue,
                                    Ok(false) => {}
                                }
                                if let Err(e) = txx.send((sender_id, data)).await {
                                    tracing::warn!(
                                        party_id = local_party_id,
                                        sender_id,
                                        error = ?e,
                                        "Failed to forward server message"
                                    );
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });
            }

            // Client-to-server connections — separate channel
            let all_clients = scan_net.get_all_client_connections();
            if !all_clients.is_empty() && spawned_client_ids.is_empty() {
                eprintln!(
                    "[party {}] Found {} client connections to monitor",
                    node_id,
                    all_clients.len()
                );
            }
            for (cid, connection) in all_clients {
                if !spawned_client_ids.insert(cid) {
                    continue;
                }

                let txx = client_tx.clone();
                let local_party_id = node_id;
                tracing::info!(
                    party_id = local_party_id,
                    client_id = cid,
                    "Spawning client receive loop (separate channel)"
                );

                tokio::spawn(async move {
                    loop {
                        match connection.receive().await {
                            Ok(data) => {
                                if let Err(e) = txx.send((cid, data)).await {
                                    tracing::warn!(
                                        party_id = local_party_id,
                                        client_id = cid,
                                        error = ?e,
                                        "Failed to forward client message"
                                    );
                                    break;
                                }
                            }
                            Err(e) => {
                                tracing::info!(
                                    party_id = local_party_id,
                                    client_id = cid,
                                    error = %e,
                                    "Client connection closed"
                                );
                                break;
                            }
                        }
                    }
                });
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });

    (server_rx, client_rx)
}
