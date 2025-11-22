// honeybadger_quic.rs
//! Integration module for HoneyBadger MPC with QUIC networking
use ark_ff::{FftField, PrimeField};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::common::{MPCProtocol, PreprocessingMPCProtocol};
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::{
    HoneyBadgerError, HoneyBadgerMPCClient, HoneyBadgerMPCNode, HoneyBadgerMPCNodeOpts,
    WrappedMessage,
};
use stoffelnet::network_utils::{ClientId, Network, NetworkError, Node, PartyId};
use stoffelnet::transports::quic::{NetworkManager, QuicNetworkManager};
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};
use crate::net::mpc::honeybadger_node_opts;

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
pub struct HoneyBadgerQuicServer<F: FftField + PrimeField> {
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

impl<F: FftField + PrimeField + 'static> HoneyBadgerQuicServer<F> {
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

/// Message types for the client actor
pub enum ClientActorMessage {
    /// Process incoming network data
    ProcessData(Vec<u8>),
    /// Shutdown the actor
    Shutdown,
}

// /// State that can be extracted from the client
// pub struct ClientState<F: FftField> {
//     pub client_id: ClientId,
//     // Add other state fields as needed
// }

/// A HoneyBadger MPC client using QUIC networking with actor model
pub struct HoneyBadgerQuicClient<F: FftField> {
    /// QUIC network manager
    pub network: Arc<tokio::sync::Mutex<QuicNetworkManager>>,
    /// Configuration
    pub config: HoneyBadgerQuicConfig,
    /// Server addresses to connect to
    server_addresses: Vec<SocketAddr>,
    /// Client ID
    pub client_id: ClientId,
    /// Connection tasks
    connection_tasks: Vec<JoinHandle<()>>,
    /// Channel to send messages to the actor
    actor_tx: mpsc::Sender<ClientActorMessage>,
    /// Actor task handle
    actor_task: Option<JoinHandle<HoneyBadgerMPCClient<F, Avid>>>,
}

impl<F: FftField + 'static> HoneyBadgerQuicClient<F> {
    /// Creates a new HoneyBadger QUIC client
    pub async fn new(
        client_id: ClientId,
        n_parties: usize,
        threshold: usize,
        instance_id: u64,
        inputs: Vec<F>,
        input_len: usize,
        config: HoneyBadgerQuicConfig,
    ) -> Result<Self, HoneyBadgerError> {
        // Create the MPC client
        let mpc_client = HoneyBadgerMPCClient::new(
            client_id,
            n_parties,
            threshold,
            instance_id,
            inputs,
            input_len,
        )?;

        // Create network manager with interior mutability
        let network = Arc::new(Mutex::new(QuicNetworkManager::new()));

        // Create actor channel
        let (actor_tx, actor_rx) = mpsc::channel(1000);

        // Spawn the actor task
        let network_clone = network.clone();
        let actor_task =
            tokio::spawn(async move { Self::run_actor(mpc_client, actor_rx, network_clone).await });

        info!("Created HoneyBadger QUIC client {}", client_id);

        Ok(Self {
            network,
            config,
            server_addresses: Vec::new(),
            client_id,
            connection_tasks: Vec::new(),
            actor_tx,
            actor_task: Some(actor_task),
        })
    }

    /// Actor loop that owns the MPC client
    async fn run_actor(
        mut client: HoneyBadgerMPCClient<F, Avid>,
        mut rx: mpsc::Receiver<ClientActorMessage>,
        network: Arc<Mutex<QuicNetworkManager>>,
    ) -> HoneyBadgerMPCClient<F, Avid> {
        let client_id = client.id;
        info!("Starting actor loop for client {}", client_id);

        while let Some(msg) = rx.recv().await {
            match msg {
                ClientActorMessage::ProcessData(data) => {
                    info!(
                        "[HB-QUIC] Client {} received {} bytes",
                        client_id,
                        data.len()
                    );
                    let preview_len = data.len().min(64);
                    let hex_preview: String = data[..preview_len]
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect();
                    debug!(
                        "[MSG:RECV] client {} handling {} bytes (hex[0..{}]={})",
                        client_id,
                        data.len(),
                        preview_len,
                        hex_preview
                    );

                    use crate::net::mpc::NetEnvelope;

                    // Ignore plaintext handshake lines (legacy)
                    if data.starts_with(b"ROLE:") {
                        debug!(
                            "[ENV] Client ignoring plaintext handshake line: {}",
                            String::from_utf8_lossy(&data)
                        );
                        continue;
                    }

                    let network_guard = network.lock().await;
                    if let Err(e) = client.process(data, Arc::new(network_guard.clone())).await {
                        error!("Client {} failed to process message: {:?}", client_id, e);
                    }

                    // // Try envelope first, fallback to raw HB bytes
                    // match NetEnvelope::try_deserialize(&data) {
                    //     Ok(NetEnvelope::Handshake { role, id }) => {
                    //         debug!(
                    //             "[ENV] Client received handshake envelope: role={}, id={}",
                    //             role, id
                    //         );
                    //     }
                    //     Ok(NetEnvelope::HoneyBadger(payload)) => {
                    //         if let Err(e) = client.process(payload, network.clone()).await {
                    //             error!(
                    //                 "Client {} failed to process message: {:?}",
                    //                 client_id, e
                    //             );
                    //         }
                    //     }
                    //     Err(_) => {
                    //         if let Err(e) = client.process(data, network.clone()).await {
                    //             error!(
                    //                 "Client {} failed to process message: {:?}",
                    //                 client_id, e
                    //             );
                    //         }
                    //     }
                    // }
                }
                ClientActorMessage::Shutdown => {
                    info!("Client {} actor received shutdown signal", client_id);
                    break;
                }
            }
        }

        info!("Actor loop for client {} terminated", client_id);
        client
    }

    /// Adds a server with a known PartyId and address to the client's party map.
    pub async fn add_server_with_id(&mut self, party_id: PartyId, address: SocketAddr) {
        self.server_addresses.push(address);
        let mut manager = self.network.lock().await;
        manager.add_node_with_party_id(party_id, address);
        info!(
            "Client {} registered server party_id={} at {}",
            self.client_id, party_id, address
        );
    }

    /// Adds a server address to connect to
    pub fn add_server(&mut self, address: SocketAddr) {
        self.server_addresses.push(address);
        info!("Client {} added server at {}", self.client_id, address);
    }

    /// Connects to all configured servers
    pub async fn connect_to_servers(&mut self) -> Result<(), HoneyBadgerError> {
        info!(
            "Client {} connecting to {} servers",
            self.client_id,
            self.server_addresses.len()
        );
        for (idx, addr) in self.server_addresses.iter().enumerate() {
            info!(
                "[HB-QUIC] Client {} will connect to [{}] {}",
                self.client_id, idx, addr
            );
        }

        let mut dialer = self.network.clone();
        for (i, &address) in self.server_addresses.iter().enumerate() {
            let mut retry_count = 0;

            loop {
                info!(
                    "[HB-QUIC] Client {} dial attempt {} to {}",
                    self.client_id,
                    retry_count + 1,
                    address
                );

                let connection_result = {
                    let mut dialer = self.network.lock().await;
                    dialer.connect_as_client(address, self.client_id).await
                };

                match connection_result {
                    Ok(connection) => {
                        info!(
                            "Client {} successfully connected to server {} at {}",
                            self.client_id, i, address
                        );

                        // Spawn message handler for this connection
                        let actor_tx = self.actor_tx.clone();
                        let client_id = self.client_id;

                        let task = tokio::spawn(async move {
                            loop {
                                match connection.receive().await {
                                    Ok(data) => {
                                        if let Err(e) = actor_tx
                                            .send(ClientActorMessage::ProcessData(data))
                                            .await
                                        {
                                            error!(
                                                "Client {} failed to send to actor: {:?}",
                                                client_id, e
                                            );
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        info!(
                                            "Client {} connection to server closed: {}",
                                            client_id, e
                                        );
                                        break;
                                    }
                                }
                            }
                        });

                        self.connection_tasks.push(task);
                        break;
                    }
                    Err(e) => {
                        retry_count += 1;
                        if retry_count >= self.config.max_connection_retries {
                            error!("Client {} failed to connect to server {} at {} after {} attempts: {}",
                                  self.client_id, i, address, retry_count, e);
                            return Err(HoneyBadgerError::NetworkError(NetworkError::Timeout));
                        }

                        info!(
                            "Client {} connection attempt {} to server {} failed: {}",
                            self.client_id, retry_count, i, e
                        );
                        tokio::time::sleep(self.config.connection_retry_delay).await;
                    }
                }
            }
        }

        Ok(())
    }

    /// Stops the client and closes all connections, returning the MPC client
    pub async fn stop(mut self) -> Result<HoneyBadgerMPCClient<F, Avid>, HoneyBadgerError> {
        info!("Stopping HoneyBadger QUIC client {}", self.client_id);

        // Send shutdown message to actor
        let _ = self.actor_tx.send(ClientActorMessage::Shutdown).await;

        // Wait for actor to complete and return client
        let client = if let Some(task) = self.actor_task.take() {
            task.await.map_err(|e| {
                error!("Failed to join actor task: {:?}", e);
                HoneyBadgerError::NetworkError(NetworkError::Timeout)
            })?
        } else {
            return Err(HoneyBadgerError::NetworkError(NetworkError::Timeout));
        };

        // Wait for all connection tasks to complete
        for task in self.connection_tasks.drain(..) {
            task.abort();
            let _ = task.await;
        }

        info!("Stopped HoneyBadger QUIC client {}", self.client_id);

        Ok(client)
    }
}

impl<F: FftField + 'static> Drop for HoneyBadgerQuicClient<F> {
    fn drop(&mut self) {
        // Abort all running tasks
        if let Some(task) = self.actor_task.take() {
            task.abort();
        }

        for task in self.connection_tasks.drain(..) {
            task.abort();
        }
    }
}

/// Helper functions for setting up HoneyBadger MPC over QUIC

/// Sets up HoneyBadger MPC clients to connect to a QUIC network
pub async fn setup_honeybadger_quic_clients<F: FftField + 'static>(
    client_ids: Vec<ClientId>,
    server_addresses: Vec<SocketAddr>,
    n_parties: usize,
    threshold: usize,
    instance_id: u64,
    inputs: Vec<Vec<F>>,
    input_len: usize,
    config: HoneyBadgerQuicConfig,
) -> Result<Vec<HoneyBadgerQuicClient<F>>, HoneyBadgerError> {
    let mut clients = Vec::new();

    info!("Setting up {} HoneyBadger QUIC clients", client_ids.len());

    for (i, &client_id) in client_ids.iter().enumerate() {
        let client_inputs = inputs
            .get(i)
            .cloned()
            .or_else(|| inputs.last().cloned())
            .unwrap_or_default();

        let mut client = HoneyBadgerQuicClient::new(
            client_id,
            n_parties,
            threshold,
            instance_id,
            client_inputs,
            input_len,
            config.clone(),
        )
        .await?;

        // Add all servers
        for &address in &server_addresses {
            client.add_server(address);
        }

        clients.push(client);
    }

    info!("Created {} HoneyBadger QUIC clients", clients.len());
    Ok(clients)
}

/// Helper functions for setting up HoneyBadger MPC over QUIC

/// Sets up a complete HoneyBadger MPC network with QUIC
pub async fn setup_honeybadger_quic_network<F: FftField + PrimeField + 'static>(
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
    let mpc_opts =
        honeybadger_node_opts(n_parties, threshold, n_triples, n_random_shares, instance_id);

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
    async fn test_preprocessing_client_mul() {
        init_crypto_provider();
        setup_test_tracing();

        info!("=== Starting Preprocessing-Only Test ===");

        // Minimal configuration for faster debugging
        let n_parties = 5;
        let threshold = 1;
        let n_triples = 2 * threshold + 1; // Minimal number of triples
        let n_random_shares = 2 + 2 * n_triples; // Minimal random shares
        let instance_id = 99999;
        let base_port = 9200;
        let session_id = SessionId::new(ProtocolType::Mul, 0, 0, instance_id);
        let clientid: Vec<ClientId> = vec![100, 200];
        let input_values: Vec<Fr> = vec![Fr::from(10), Fr::from(20)];
        let no_of_multiplications = input_values.len();

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
            config.clone(),
        )
        .await
        .expect("Failed to create servers");
        info!("✓ Created {} servers", servers.len());

        // Get server addresses
        let server_addresses: Vec<SocketAddr> = (0..n_parties)
            .map(|i| {
                format!("127.0.0.1:{}", base_port + i as u16)
                    .parse()
                    .unwrap()
            })
            .collect();

        info!("Server addresses:");
        for (i, addr) in server_addresses.iter().enumerate() {
            info!("Server {}: {}", i, addr);
        }

        let mut clients = setup_honeybadger_quic_clients::<Fr>(
            clientid.clone(),
            server_addresses,
            n_parties,
            threshold,
            instance_id,
            vec![input_values],
            2,
            config.clone(),
        )
        .await
        .expect("Failed to create clients");

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
        // tokio::time::sleep(Duration::from_millis(100)).await;

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

        // Step 4: Connect clients to servers
        info!("Step 4: Connecting clients to servers...");
        for client in &mut clients {
            info!("Connecting client {} to servers...", client.client_id);
            client
                .connect_to_servers()
                .await
                .expect("Failed to connect client to servers");
            info!("✓ Client {} connected to servers", client.client_id);
        }
        info!("✓ All clients connected to servers");

        tokio::time::sleep(Duration::from_millis(300)).await;

        // Step 5: Verify client connectivity
        info!("Step 5: Verifying client connectivity...");
        for (i, client) in clients.iter().enumerate() {
            let connected_servers = client.network.lock().await.parties().len();
            info!(
                "Client {} sees {} servers in network map",
                i, connected_servers
            );
            assert_eq!(
                connected_servers, n_parties,
                "Client {} only sees {} servers but expected {}",
                i, connected_servers, n_parties
            );
        }
        info!("✓ Client connectivity verified");

        // Step 5: Verify network connectivity with a simple ping-pong test
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
        tokio::time::sleep(Duration::from_millis(300)).await;

        for (_, server) in servers.iter_mut().enumerate() {
            let local_shares = server
                .node
                .preprocessing_material
                .lock()
                .await
                .take_random_shares(2)
                .unwrap();
            match server
                .node
                .preprocess
                .input
                .init(clientid[0], local_shares, 2, server.network.clone())
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    eprint!("{e}");
                }
            }
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
        //----------------------------------------RUN MULTIPLICATION----------------------------------------

        let mut handles = Vec::new();
        for pid in 0..n_parties {
            let mut node = servers[pid].node.clone();
            let net = servers[pid].network.clone();

            let (x_shares, y_shares) = {
                let input_store = node.preprocess.input.input_shares.lock().await;
                let inputs = input_store.get(&clientid[0]).unwrap();
                (
                    vec![inputs[0].clone(), inputs[1].clone()],
                    vec![inputs[0].clone(), inputs[1].clone()],
                )
            };

            let handle = tokio::spawn(async move {
                {
                    node.mul(x_shares.clone(), y_shares.clone(), net.clone())
                        .await
                        .expect("mul failed");
                }
            });
            handles.push(handle);
        }

        // Wait for all mul tasks to finish
        futures::future::join_all(handles).await;
        tokio::time::sleep(Duration::from_millis(300)).await;

        //----------------------------------------VALIDATE VALUES----------------------------------------

        let output_clientid: ClientId = 200;
        // Each server sends its output shares
        for (i, server) in servers.iter().enumerate() {
            let net = server.network.clone();
            let storage_map = server.node.operations.mul.mult_storage.lock().await;
            if let Some(storage_mutex) = storage_map.get(&session_id) {
                let storage = storage_mutex.lock().await;

                if storage.protocol_output.is_empty() {
                    panic!("protocol_output empty for node {}", i);
                }
                let shares_mult_for_node: Vec<RobustShare<Fr>> = storage.protocol_output.clone();
                assert_eq!(shares_mult_for_node.len(), no_of_multiplications);
                match server
                    .node
                    .output
                    .init(
                        output_clientid,
                        shares_mult_for_node,
                        no_of_multiplications,
                        net.clone(),
                    )
                    .await
                {
                    Ok(_) => {}
                    Err(e) => eprintln!("Server init error: {e}"),
                }
            } else {
                panic!(
                    "no mult_storage entry for session {:?} on node {}",
                    session_id, i
                );
            }
        }
    }

    #[tokio::test]
    async fn test_client_input_only() {
        init_crypto_provider();
        setup_test_tracing();

        info!("=== Starting Preprocessing-Only Test ===");

        // Minimal configuration for faster debugging
        let n_parties = 5;
        let threshold = 1;
        let n_triples = 2 * threshold + 1; // Minimal number of triples
        let n_random_shares = 2 + 2 * n_triples; // Minimal random shares
        let instance_id = 99999;
        let base_port = 9200;
        let clientid: Vec<ClientId> = vec![100, 200];
        let input_values: Vec<Fr> = vec![Fr::from(10), Fr::from(20)];

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
            config.clone(),
        )
        .await
        .expect("Failed to create servers");
        info!("✓ Created {} servers", servers.len());

        // Get server addresses
        let server_addresses: Vec<SocketAddr> = (0..n_parties)
            .map(|i| {
                format!("127.0.0.1:{}", base_port + i as u16)
                    .parse()
                    .unwrap()
            })
            .collect();

        info!("Server addresses:");
        for (i, addr) in server_addresses.iter().enumerate() {
            info!("Server {}: {}", i, addr);
        }

        let mut clients = setup_honeybadger_quic_clients::<Fr>(
            clientid.clone(),
            server_addresses,
            n_parties,
            threshold,
            instance_id,
            vec![input_values],
            2,
            config.clone(),
        )
        .await
        .expect("Failed to create clients");

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
        // tokio::time::sleep(Duration::from_millis(100)).await;

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

        // Step 4: Connect clients to servers
        info!("Step 4: Connecting clients to servers...");
        for client in &mut clients {
            info!("Connecting client {} to servers...", client.client_id);
            client
                .connect_to_servers()
                .await
                .expect("Failed to connect client to servers");
            info!("✓ Client {} connected to servers", client.client_id);
        }
        info!("✓ All clients connected to servers");

        tokio::time::sleep(Duration::from_millis(300)).await;

        // Step 5: Verify client connectivity
        info!("Step 5: Verifying client connectivity...");
        for (i, client) in clients.iter().enumerate() {
            let connected_servers = client.network.lock().await.parties().len();
            info!(
                "Client {} sees {} servers in network map",
                i, connected_servers
            );
            assert_eq!(
                connected_servers, n_parties,
                "Client {} only sees {} servers but expected {}",
                i, connected_servers, n_parties
            );
        }
        info!("✓ Client connectivity verified");

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

        for (_, server) in servers.iter_mut().enumerate() {
            let local_shares = server
                .node
                .preprocessing_material
                .lock()
                .await
                .take_random_shares(2)
                .unwrap();
            match server
                .node
                .preprocess
                .input
                .init(clientid[0], local_shares, 2, server.network.clone())
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    eprint!("{e}");
                }
            }
        }
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
        // tokio::time::sleep(Duration::from_millis(100)).await;

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
        // tokio::time::sleep(Duration::from_millis(300)).await;

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
        info!("✓ Server network connectivity verified");

        // Step 6: Run preprocessing with timeout and detailed logging
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

                let (triples_count, random_shares_count, _prandbit_count, _prandint_count) =
                    preproc.len();

                info!(
                    "Server {} has {} triples and {} random shares",
                    i, triples_count, random_shares_count
                );

                assert!(triples_count > 0, "Server {} has no triples!", i);
                assert!(
                    random_shares_count == 6,
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
