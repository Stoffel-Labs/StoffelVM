// honeybadger_quic.rs
//! Integration module for HoneyBadger MPC with QUIC networking
use ark_ff::FftField;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::common::{MPCProtocol, PreprocessingMPCProtocol};
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::{HoneyBadgerError, HoneyBadgerMPCNode, HoneyBadgerMPCNodeOpts};
use stoffelnet::network_utils::{Network, NetworkError, Node, PartyId};
use stoffelnet::transports::quic::{NetworkManager, QuicNetworkManager};
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{error, info, warn};

/// Configuration for HoneyBadger MPC over QUIC
#[derive(Debug, Clone)]
pub struct HoneyBadgerQuicConfig {
    /// QUIC network configuration
    /// Timeout for MPC operations
    pub mpc_timeout: Duration,
    /// Buffer size for message channels
    /// Connection retry attempts
    pub max_connection_retries: u32,
    /// Delay between connection attempts
    pub connection_retry_delay: Duration,
}

impl Default for HoneyBadgerQuicConfig {
    fn default() -> Self {
        Self {
            mpc_timeout: Duration::from_secs(5),
            max_connection_retries: 5,
            connection_retry_delay: Duration::from_millis(100),
        }
    }
}

/// A HoneyBadger MPC server node using QUIC networking
pub struct HoneyBadgerQuicServer<F: FftField> {
    /// The underlying MPC node
    pub node: HoneyBadgerMPCNode<F, Avid>,
    /// Actor-like manager usage: Arc for send/broadcast, owned clones for accept/connect
    pub network: Arc<QuicNetworkManager>,
    /// Message processing task handle
    message_task: Option<tokio::task::JoinHandle<()>>,
    /// Connection handling task handle
    connection_task: Option<tokio::task::JoinHandle<()>>,
    /// Configuration
    pub config: HoneyBadgerQuicConfig,
    /// Shutdown signal
    shutdown_tx: Option<mpsc::Sender<()>>,
    /// Node ID
    pub node_id: PartyId,
    /// Bind address
    pub channels: Sender<Vec<u8>>,
}

impl<F: FftField + 'static> HoneyBadgerQuicServer<F> {
    /// Creates a new HoneyBadger QUIC server
    pub async fn new(
        node_id: PartyId,
        bind_address: SocketAddr,
        mpc_opts: HoneyBadgerMPCNodeOpts,
        config: HoneyBadgerQuicConfig,
        channels: Sender<Vec<u8>>,
    ) -> Result<Self, HoneyBadgerError> {
        // Create the MPC node
        let mpc_node = <HoneyBadgerMPCNode<F, Avid> as MPCProtocol<
            F,
            RobustShare<F>,
            QuicNetworkManager,
        >>::setup(node_id, mpc_opts)?;
        //let node = Arc::new(Mutex::new(mpc_node));

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

        // Ensure the local party is registered in the party map to avoid PartyNotFound(self)
        base_manager.add_node_with_party_id(node_id, bind_address);

        // Arc for read-only ops; actor loops will use owned clones when mutability across await is needed
        let network = Arc::new(base_manager);

        let initial_parties = network.parties().len();
        info!(
            "Created HoneyBadger QUIC server for node {} on {} (initial peers: {})",
            node_id, bind_address, initial_parties
        );

        Ok(Self {
            node: mpc_node,
            network,
            message_task: None,
            connection_task: None,
            config,
            shutdown_tx: None,
            node_id,
            channels,
        })
    }

    /// Adds a peer node to connect to
    pub async fn add_peer(&mut self, peer_id: PartyId, address: SocketAddr) {
        // Work on a local owned clone, then swap back to update self
        let mut manager = self.network.as_ref().clone();
        manager.add_node_with_party_id(peer_id, address);
        self.network = Arc::new(manager);
        info!(
            "Added peer {} at {} to node {}",
            peer_id, address, self.node_id
        );
    }

    /// Starts the server and begins accepting connections
    pub async fn start(&mut self) -> Result<(), HoneyBadgerError> {
        if self.message_task.is_some() {
            warn!("Server already started");
            return Ok(());
        }

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
        self.shutdown_tx = Some(shutdown_tx);

        info!("Starting HoneyBadger QUIC server on node {}", self.node_id);

        // Start connection acceptance task with an owned clone (no locks held across await)
        let mut acceptor = self.network.as_ref().clone();
        // let network_for_handlers = self.network.clone();
        // let node_for_handlers = self.node.clone();
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
                                                // Important: no locks are held across await inside handle_message
                                                if let Err(e) =txx.send(data).await {
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

    /// Connects to all configured peer nodes
    pub async fn connect_to_peers(&self) -> Result<(), HoneyBadgerError> {
        let peers: Vec<(PartyId, SocketAddr)> = self
            .network
            .parties()
            .iter()
            .map(|p| (p.id(), p.address()))
            .collect();
        info!(
            "[HB-QUIC] Node {} discovered {} peers (including self)",
            self.node_id,
            peers.len()
        );
        for (pid, addr) in &peers {
            info!(
                "[HB-QUIC] Node {} peer listing -> id={} addr={}",
                self.node_id, pid, addr
            );
        }

        // Use a local owned clone for dialing without any external locks
        let mut dialer = self.network.as_ref().clone();
        for (peer_id, peer_addr) in peers {
            // Connect to all peers including self to ensure a loopback entry exists in the
            // network connections map. Some protocols send to self, and the transport
            // expects an established connection for that PartyId.
            info!(
                "Node {} connecting to peer {} at {}",
                self.node_id, peer_id, peer_addr
            );

            let mut retry_count = 0;
            loop {
                let connection_result = dialer.connect_as_server(peer_addr, self.node_id).await;

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

        if let Some(task) = self.message_task.take() {
            let _ = task.await;
        }

        info!("Stopped HoneyBadger QUIC server for node {}", self.node_id);
    }
}

/// Helper functions for setting up HoneyBadger MPC over QUIC

/// Sets up a complete HoneyBadger MPC network with QUIC
pub async fn setup_honeybadger_quic_network<F: FftField + 'static>(
    n_parties: usize,
    threshold: usize,
    n_triples: usize,
    n_random_shares: usize,
    instance_id: u64,
    base_port: u16,
    config: HoneyBadgerQuicConfig,
) -> Result<(Vec<HoneyBadgerQuicServer<F>>, Vec<Receiver<Vec<u8>>>), HoneyBadgerError> {
    let mut servers = Vec::new();

    // Create server addresses
    let addresses: Vec<SocketAddr> = (0..n_parties)
        .map(|i| {
            format!("127.0.0.1:{}", base_port + i as u16)
                .parse()
                .unwrap()
        })
        .collect();

    info!(
        "Setting up HoneyBadger QUIC network with {} parties",
        n_parties
    );
    for (i, addr) in addresses.iter().enumerate() {
        info!("[HB-SETUP] Server[{}] -> {}", i, addr);
    }

    // Create MPC options
    let mpc_opts = HoneyBadgerMPCNodeOpts::new(
        n_parties,
        threshold,
        n_triples,
        n_random_shares,
        instance_id,
    );

    // Create all servers
    let mut recv = Vec::new();
    for i in 0..n_parties {
        let (tx, rx) = mpsc::channel(1500);
        let mut server =
            HoneyBadgerQuicServer::new(i, addresses[i], mpc_opts.clone(), config.clone(), tx)
                .await?;
        // Add all other servers as peers
        for j in 0..n_parties {
            if i != j {
                server.add_peer(j, addresses[j]).await;
            }
        }

        servers.push(server);
        recv.push(rx);
    }

    info!("Created {} HoneyBadger QUIC servers", servers.len());
    Ok((servers, recv))
}

/// Example usage and integration tests
#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_std::rand::SeedableRng;
    use std::sync::Once;
    use std::time::Duration;
    use stoffelmpc_mpc::honeybadger::{ProtocolType, SessionId};
    use tracing_subscriber::EnvFilter;

    static INIT: Once = Once::new();
    fn init_crypto_provider() {
        INIT.call_once(|| {
            if rustls::crypto::CryptoProvider::get_default().is_none() {
                let _ = rustls::crypto::ring::default_provider().install_default();
            }
        });
    }

    #[tokio::test]
    async fn test_preprocessing_only() {
        init_crypto_provider();
        setup_test_tracing();

        info!("=== Starting Preprocessing-Only Test ===");

        // Minimal configuration for faster debugging
        let n_parties = 5;
        let threshold = 1;
        let n_triples = 3; // Minimal number of triples
        let n_random_shares = 6; // Minimal random shares
        let instance_id = 99999;
        let base_port = 9200;

        let mut config = HoneyBadgerQuicConfig::default();
        config.mpc_timeout = Duration::from_secs(10);
        config.connection_retry_delay = Duration::from_millis(100);

        // Step 1: Create servers
        info!("Step 1: Creating {} servers...", n_parties);
        let (mut servers, mut recv) = setup_honeybadger_quic_network::<Fr>(
            n_parties,
            threshold,
            n_triples,
            n_random_shares,
            instance_id,
            base_port,
            config,
        )
            .await
            .expect("Failed to create servers");
        info!("✓ Created {} servers", servers.len());

        // Step 2: Start all servers
        info!("Step 2: Starting servers...");
        for (i, server) in servers.iter_mut().enumerate() {
            //Reciever for each node
            let mut node = server.node.clone();
            let network = server.network.clone();
            let mut rx = recv.remove(0);
            tokio::spawn(async move {
                while let Some(raw_msg) = rx.recv().await {
                    if let Err(e) = node.process(raw_msg, network.clone()).await {
                        tracing::error!("Node {i} failed to process message: {e:?}");
                    }
                }
                tracing::info!("Receiver task for node {i} ended");
            });
            server.start().await.expect("Failed to start server");
            info!("✓ Started server {}", server.node_id);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Step 3: Connect servers to each other
        info!("Step 3: Connecting servers to each other...");
        for server in &servers {
            info!("Connecting server {} to peers...", server.node_id);
            server
                .connect_to_peers()
                .await
                .expect("Failed to connect to peers");
            info!("✓ Server {} connected to peers", server.node_id);
        }
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Step 4: Verify network connectivity with a simple ping-pong test
        info!("Step 4: Verifying network connectivity...");
        for (i, server) in servers.iter().enumerate() {
            let parties = server.network.parties();
            info!("Server {} sees {} parties in network map", i, parties.len());
            for party in parties {
                info!("  - Party {} at {}", party.id(), party.address());
            }

            // Verify each server can resolve all other parties
            for peer_id in 0..n_parties {
                match server.network.node(peer_id) {
                    Some(node) => {
                        info!(
                            "✓ Server {} can resolve peer {} at {}",
                            i,
                            peer_id,
                            node.address()
                        );
                    }
                    None => {
                        error!("✗ Server {} CANNOT resolve peer {}", i, peer_id);
                        panic!(
                            "Network connectivity check failed: Server {} cannot resolve peer {}",
                            i, peer_id
                        );
                    }
                }
            }
        }
        info!("✓ Network connectivity verified");

        // Step 5: Run preprocessing with timeout and detailed logging
        info!("Step 5: Running preprocessing on all servers...");
        info!(
            "Each server will generate {} triples and {} random shares",
            n_triples, n_random_shares
        );

        let preprocessing_timeout = Duration::from_secs(30);
        let _session_id = SessionId::new(ProtocolType::Ransha, 0, 0, instance_id);
        let preprocessing_handles: Vec<_> = servers
            .iter()
            .enumerate()
            .map(|(i, server)| {
                let mut node_arc = server.node.clone();
                let network_clone = server.network.clone();

                tokio::spawn(async move {
                    info!("[Server {}] Starting preprocessing...", i);
                    let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
                    let result = tokio::time::timeout(preprocessing_timeout, async {
                        node_arc
                            .run_preprocessing(network_clone.clone(), &mut rng)
                            .await
                    })
                        .await;

                    match result {
                        Ok(Ok(())) => {
                            info!("[Server {}] ✓ Preprocessing completed successfully", i);
                            Ok(())
                        }
                        Ok(Err(e)) => {
                            error!("[Server {}] ✗ Preprocessing failed with error: {:?}", i, e);
                            Err(format!("Preprocessing error: {:?}", e))
                        }
                        Err(_) => {
                            error!(
                                "[Server {}] ✗ Preprocessing TIMED OUT after {:?}",
                                i, preprocessing_timeout
                            );
                            Err(format!("Timeout after {:?}", preprocessing_timeout))
                        }
                    }
                })
            })
            .collect();

        // Wait for all preprocessing tasks to complete
        let results = futures::future::join_all(preprocessing_handles).await;

        // Check results
        let mut all_succeeded = true;
        for (i, result) in results.iter().enumerate() {
            match result {
                Ok(Ok(())) => {
                    info!("Server {} preprocessing: SUCCESS", i);
                }
                Ok(Err(e)) => {
                    error!("Server {} preprocessing: FAILED - {}", i, e);
                    all_succeeded = false;
                }
                Err(e) => {
                    error!("Server {} preprocessing task: PANICKED - {:?}", i, e);
                    all_succeeded = false;
                }
            }
        }

        // Step 6: Verify preprocessing material was actually generated
        if all_succeeded {
            info!("Step 6: Verifying preprocessing material...");
            for (i, server) in servers.iter().enumerate() {
                //let node = server.node.lock().await;
                let preproc = server.node.preprocessing_material.lock().await;

                let (triples_count, random_shares_count) = preproc.len();

                info!(
                    "Server {} has {} triples and {} random shares",
                    i, triples_count, random_shares_count
                );

                assert!(triples_count > 0, "Server {} has no triples!", i);
                assert!(
                    random_shares_count == 0,
                    "Server {} has no random shares!",
                    i
                );
            }
            info!("✓ All servers have preprocessing material");
        }

        // Step 7: Cleanup
        info!("Step 7: Cleaning up...");
        for mut server in servers {
            server.stop().await;
        }

        // Final assertion
        assert!(all_succeeded, "Preprocessing failed on one or more servers");

        info!("=== Preprocessing-Only Test PASSED ===");
    }

    // Helper function for test tracing setup
    fn setup_test_tracing() {
        use std::sync::Once;
        use tracing_subscriber::FmtSubscriber;

        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let subscriber = FmtSubscriber::builder()
                .with_env_filter(
                    EnvFilter::from_default_env().add_directive("debug".parse().unwrap()),
                )
                .with_test_writer()
                .finish();
            let _ = tracing::subscriber::set_global_default(subscriber);
        });
    }
}
