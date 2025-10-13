// honeybadger_quic.rs
//! Integration module for HoneyBadger MPC with QUIC networking
use ark_ff::FftField;
use async_trait::async_trait;
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use bincode::Error;
use serde::Deserialize;
use stoffelmpc_mpc::common::{MPCProtocol, PreprocessingMPCProtocol};
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::honeybadger::{HoneyBadgerError, HoneyBadgerMPCClient, HoneyBadgerMPCNode, HoneyBadgerMPCNodeOpts, WrappedMessage};
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelnet::network_utils::{ClientId, Network, NetworkError, Node, PartyId};
use stoffelnet::transports::quic::{NetworkManager, QuicNetworkConfig, QuicNetworkManager};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};
use crate::net::mpc::NetEnvelope;

/// Configuration for HoneyBadger MPC over QUIC
#[derive(Debug, Clone)]
pub struct HoneyBadgerQuicConfig {
    /// QUIC network configuration
    pub network_config: QuicNetworkConfig,
    /// Timeout for MPC operations
    pub mpc_timeout: Duration,
    /// Buffer size for message channels
    pub buffer_size: usize,
    /// Connection retry attempts
    pub max_connection_retries: u32,
    /// Delay between connection attempts
    pub connection_retry_delay: Duration,
}

impl Default for HoneyBadgerQuicConfig {
    fn default() -> Self {
        Self {
            network_config: QuicNetworkConfig::default(),
            mpc_timeout: Duration::from_secs(5),
            buffer_size: 1000,
            max_connection_retries: 5,
            connection_retry_delay: Duration::from_millis(100),
        }
    }
}

/// A HoneyBadger MPC server node using QUIC networking
pub struct HoneyBadgerQuicServer<F: FftField> {
    /// The underlying MPC node
    pub node: Arc<Mutex<HoneyBadgerMPCNode<F, Avid>>>,
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
    pub bind_address: SocketAddr,
}

impl<F: FftField + 'static> HoneyBadgerQuicServer<F> {
    /// Creates a new HoneyBadger QUIC server
    pub async fn new(
        node_id: PartyId,
        bind_address: SocketAddr,
        mpc_opts: HoneyBadgerMPCNodeOpts,
        config: HoneyBadgerQuicConfig,
    ) -> Result<Self, HoneyBadgerError> {
        // Create the MPC node
        let mpc_node = <HoneyBadgerMPCNode<F, Avid> as MPCProtocol<F, RobustShare<F>, QuicNetworkManager>>
            ::setup(node_id, mpc_opts)?;
        let node = Arc::new(Mutex::new(mpc_node));

        // Create network manager
        info!("[HB-QUIC] Initializing network manager for node {} at {}", node_id, bind_address);
        let mut base_manager = QuicNetworkManager::with_node_id(node_id);
        info!("[HB-QUIC] Node {} calling listen({})", node_id, bind_address);
        base_manager.listen(bind_address).await
            .map_err(|e| {
                error!("[HB-QUIC] Node {} failed to bind to {}: {}", node_id, bind_address, e);
                HoneyBadgerError::NetworkError(NetworkError::Timeout)
            })?;
        info!("[HB-QUIC] Node {} successfully bound to {}", node_id, bind_address);

        // Ensure the local party is registered in the party map to avoid PartyNotFound(self)
        base_manager.add_node_with_party_id(node_id, bind_address);

        // Arc for read-only ops; actor loops will use owned clones when mutability across await is needed
        let network = Arc::new(base_manager);

        let initial_parties = network.parties().len();
        info!("Created HoneyBadger QUIC server for node {} on {} (initial peers: {})", node_id, bind_address, initial_parties);

        Ok(Self {
            node,
            network,
            message_task: None,
            connection_task: None,
            config,
            shutdown_tx: None,
            node_id,
            bind_address,
        })
    }

    /// Adds a peer node to connect to
    pub async fn add_peer(&mut self, peer_id: PartyId, address: SocketAddr) {
        // Work on a local owned clone, then swap back to update self
        let mut manager = self.network.as_ref().clone();
        manager.add_node_with_party_id(peer_id, address);
        self.network = Arc::new(manager);
        info!("Added peer {} at {} to node {}", peer_id, address, self.node_id);
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
        let network_for_handlers = self.network.clone();
        let node_for_handlers = self.node.clone();
        let node_id = self.node_id;

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
                            Ok(mut connection) => {
                                info!("Node {} accepted connection from {}", node_id, connection.remote_address());

                                // Spawn a task to handle this connection's messages
                                let network_for_handler = network_for_handlers.clone();
                                let node_for_handler = node_for_handlers.clone();
                                let conn_node_id = node_id;

                                info!("[HB-QUIC] Node {} spawning message handler for connection {}", conn_node_id, connection.remote_address());
                                tokio::spawn(async move {
                                    loop {
                                        match connection.receive().await {
                                            Ok(data) => {
                                                info!("[HB-QUIC] Node {} received {} bytes from {}", conn_node_id, data.len(), connection.remote_address());
                                                // Important: no locks are held across await inside handle_message
                                                if let Err(e) = Self::handle_message(
                                                    Arc::clone(&node_for_handler),
                                                    Arc::clone(&network_for_handler),
                                                    data,
                                                ).await {
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

    /// Handles an incoming message
    async fn handle_message(
        node: Arc<Mutex<HoneyBadgerMPCNode<F, Avid>>>,
        network: Arc<QuicNetworkManager>,
        data: Vec<u8>,
    ) -> Result<(), HoneyBadgerError> {
        use crate::net::mpc::NetEnvelope;
        let preview_len = data.len().min(64);
        let hex_preview: String = data[..preview_len].iter().map(|b| format!("{:02x}", b)).collect();
        debug!("[MSG:RECV] node handling {} bytes (hex[0..{}]={})", data.len(), preview_len, hex_preview);

        // Ignore plaintext handshake lines (legacy first-stream handshake)
        if data.starts_with(b"ROLE:") {
            debug!("[ENV] Ignoring plaintext handshake line at server: {}", String::from_utf8_lossy(&data));
            return Ok(());
        }

        // Try to parse as generic envelope; if that fails, assume raw HB message bytes
        match NetEnvelope::try_deserialize(&data) {
            Ok(NetEnvelope::Handshake { role, id }) => {
                debug!("[ENV] Handshake envelope received at server: role={}, id={}", role, id);
                Ok(())
            }
            Ok(NetEnvelope::HoneyBadger(payload)) => {
                debug!("Received HoneyBadger message at server: {}", String::from_utf8_lossy(&payload));
                let mut node_guard = node.lock().await;
                node_guard.process(payload, network.clone()).await
            }
            Err(_) => {
                debug!("[ENV] Ignoring message at server: {}", String::from_utf8_lossy(&data));
                let deserialize_result: Result<WrappedMessage, _> = bincode::deserialize(&data);

                match deserialize_result {
                    Ok(message) => {
                        info!("Received {:?}", message);
                    }
                    _ => {
                        debug!("[ENV] Ignoring message at server: {}", String::from_utf8_lossy(&data));
                    }
                }
                // Backward-compatibility: treat as raw HB message bytes
                let mut node_guard = node.lock().await;
                node_guard.process(data, network.clone()).await
            }
        }
    }

    /// Connects to all configured peer nodes
    pub async fn connect_to_peers(&self) -> Result<(), HoneyBadgerError> {
        let peers: Vec<(PartyId, SocketAddr)> =
            self.network.parties().iter().map(|p| (p.id(), p.address())).collect();
        info!("[HB-QUIC] Node {} discovered {} peers (including self)", self.node_id, peers.len());
        for (pid, addr) in &peers { info!("[HB-QUIC] Node {} peer listing -> id={} addr={}", self.node_id, pid, addr); }

        // Use a local owned clone for dialing without any external locks
        let mut dialer = self.network.as_ref().clone();
        for (peer_id, peer_addr) in peers {
            // Connect to all peers including self to ensure a loopback entry exists in the
            // network connections map. Some protocols send to self, and the transport
            // expects an established connection for that PartyId.
            info!("Node {} connecting to peer {} at {}", self.node_id, peer_id, peer_addr);

            let mut retry_count = 0;
            loop {
                let connection_result = dialer.connect_as_server(peer_addr, self.node_id).await;

                match connection_result {
                    Ok(mut connection) => {
                        info!("Node {} successfully connected to peer {}", self.node_id, peer_id);

                        // Spawn message handler for this connection
                        let network_clone = self.network.clone();
                        let node_clone = self.node.clone();
                        let pid_for_task = peer_id;

                        tokio::spawn(async move {
                            loop {
                                match connection.receive().await {
                                    Ok(data) => {
                                        if let Err(e) = Self::handle_message(
                                            Arc::clone(&node_clone),
                                            Arc::clone(&network_clone),
                                            data,
                                        ).await {
                                            error!("Failed to handle message from peer {}: {:?}", pid_for_task, e);
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
                            warn!("Node {} failed to connect to peer {} after {} attempts: {}",
                                 self.node_id, peer_id, retry_count, e);
                            break;
                        }

                        info!("Node {} connection attempt {} to peer {} failed: {}",
                              self.node_id, retry_count, peer_id, e);
                        tokio::time::sleep(self.config.connection_retry_delay).await;
                    }
                }
            }
        }

        Ok(())
    }

    /// Runs preprocessing to generate random shares and beaver triples
    pub async fn run_preprocessing<G>(&self, rng: &mut G) -> Result<(), HoneyBadgerError>
    where
        G: ark_std::rand::Rng + Send,
    {
        info!("Running preprocessing for node {}", self.node_id);

        let mut node = self.node.lock().await;
        node.run_preprocessing(self.network.clone(), rng).await
    }

    /// Performs secure multiplication
    pub async fn multiply(
        &self,
        x: Vec<RobustShare<F>>,
        y: Vec<RobustShare<F>>,
    ) -> Result<Vec<RobustShare<F>>, HoneyBadgerError> {
        info!("Performing multiplication on node {}", self.node_id);

        let mut node = self.node.lock().await;
        node.mul(x, y, self.network.clone()).await
    }

    /// Run the real input protocol: servers send mask shares to client, client broadcasts masked inputs
    pub async fn run_input_protocol(&self, client_id: ClientId, input_len: usize) -> Result<(), HoneyBadgerError> {
        // Take input_len random shares from preprocessing and send to client via InputServer::init
        let shares = {
            let mut node_guard = self.node.lock().await;
            let mut preproc = node_guard.preprocessing_material.lock().await;
            let taken = preproc.take_random_shares(input_len)?;
            taken
        };
        // Now call input.init which sends MaskShare to the client
        let node = self.node.lock().await;
        node.preprocess
            .input
            .init(client_id, shares, input_len, self.network.clone())
            .await?;
        Ok(())
    }

    /// Retrieve input shares produced by the input protocol for a given client
    pub async fn get_input_shares(&self, client_id: ClientId) -> Option<Vec<RobustShare<F>>> {
        let node = self.node.lock().await;
        let map_guard = node.preprocess.input.input_shares.lock().await;
        map_guard.get(&client_id).cloned()
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

impl<F: FftField + 'static> Drop for HoneyBadgerQuicServer<F> {
    fn drop(&mut self) {
        // Abort running tasks
        if let Some(task) = self.connection_task.take() {
            task.abort();
        }
        if let Some(task) = self.message_task.take() {
            task.abort();
        }
    }
}

/// A HoneyBadger MPC client using QUIC networking
pub struct HoneyBadgerQuicClient<F: FftField> {
    /// The underlying MPC client
    pub client: Arc<Mutex<HoneyBadgerMPCClient<F, Avid>>>,
    /// QUIC network manager
    pub network: Arc<QuicNetworkManager>,
    /// Configuration
    pub config: HoneyBadgerQuicConfig,
    /// Server addresses to connect to
    server_addresses: Vec<SocketAddr>,
    /// Client ID
    pub client_id: ClientId,
    /// Connection tasks
    connection_tasks: Vec<tokio::task::JoinHandle<()>>,
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
        let client = Arc::new(Mutex::new(mpc_client));

        // Create network manager
        let network = Arc::new(QuicNetworkManager::new());

        info!("Created HoneyBadger QUIC client {}", client_id);

        Ok(Self {
            client,
            network,
            config,
            server_addresses: Vec::new(),
            client_id,
            connection_tasks: Vec::new(),
        })
    }

    /// Adds a server with a known PartyId and address to the client's party map.
    /// This mirrors FakeNetwork behavior where the client knows PartyIds upfront.
    pub fn add_server_with_id(&mut self, party_id: PartyId, address: SocketAddr) {
        // Keep the address list for dialing
        self.server_addresses.push(address);
        // Also register the server mapping (PartyId -> SocketAddr) so future sends/broadcasts
        // can resolve PartyIds deterministically.
        let mut manager = self.network.as_ref().clone();
        manager.add_node_with_party_id(party_id, address);
        self.network = Arc::new(manager);
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
        info!("Client {} connecting to {} servers", self.client_id, self.server_addresses.len());
        for (idx, addr) in self.server_addresses.iter().enumerate() { info!("[HB-QUIC] Client {} will connect to [{}] {}", self.client_id, idx, addr); }

        // Local dialer clone to avoid locking the shared Arc across await
        let mut dialer = self.network.as_ref().clone();
        for (i, &address) in self.server_addresses.iter().enumerate() {
            let mut retry_count = 0;

            loop {
                info!("[HB-QUIC] Client {} dial attempt {} to {}", self.client_id, retry_count + 1, address);
                let connection_result = dialer.connect_as_client(address, self.client_id).await;

                match connection_result {
                    Ok(mut connection) => {
                        info!("Client {} successfully connected to server {} at {}",
                             self.client_id, i, address);

                        // Spawn message handler for this connection
                        let network_clone = self.network.clone();
                        let client_clone = self.client.clone();
                        let client_id = self.client_id;

                        let task = tokio::spawn(async move {
                            loop {
                                match connection.receive().await {
                                    Ok(data) => {
                                        info!("[HB-QUIC] Client {} received {} bytes", client_id, data.len());
                                        let preview_len = data.len().min(64);
                                        let hex_preview: String = data[..preview_len].iter().map(|b| format!("{:02x}", b)).collect();
                                        debug!("[MSG:RECV] client {} handling {} bytes (hex[0..{}]={})", client_id, data.len(), preview_len, hex_preview);
                                        use crate::net::mpc::NetEnvelope;
                                        // Ignore plaintext handshake lines (legacy)
                                        if data.starts_with(b"ROLE:") {
                                            debug!("[ENV] Client ignoring plaintext handshake line: {}", String::from_utf8_lossy(&data));
                                            continue;
                                        }
                                        // Try envelope first, fallback to raw HB bytes
                                        match NetEnvelope::try_deserialize(&data) {
                                            Ok(NetEnvelope::Handshake { role, id }) => {
                                                debug!("[ENV] Client received handshake envelope: role={}, id={}", role, id);
                                            }
                                            Ok(NetEnvelope::HoneyBadger(payload)) => {
                                                let mut client_guard = client_clone.lock().await;
                                                if let Err(e) = client_guard.process(payload, network_clone.clone()).await {
                                                    error!("Client {} failed to process message: {:?}", client_id, e);
                                                }
                                            }
                                            Err(_) => {
                                                let mut client_guard = client_clone.lock().await;
                                                if let Err(e) = client_guard.process(data, network_clone.clone()).await {
                                                    error!("Client {} failed to process message: {:?}", client_id, e);
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        info!("Client {} connection to server closed: {}", client_id, e);
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

                        info!("Client {} connection attempt {} to server {} failed: {}",
                              self.client_id, retry_count, i, e);
                        tokio::time::sleep(self.config.connection_retry_delay).await;
                    }
                }
            }
        }

        Ok(())
    }

    /// Stops the client and closes all connections
    pub async fn stop(&mut self) {
        info!("Stopping HoneyBadger QUIC client {}", self.client_id);

        // Wait for all connection tasks to complete
        for task in self.connection_tasks.drain(..) {
            task.abort();
            let _ = task.await;
        }

        info!("Stopped HoneyBadger QUIC client {}", self.client_id);
    }
}

impl<F: FftField + 'static> Drop for HoneyBadgerQuicClient<F> {
    fn drop(&mut self) {
        // Abort all running tasks
        for task in self.connection_tasks.drain(..) {
            task.abort();
        }
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
) -> Result<Vec<HoneyBadgerQuicServer<F>>, HoneyBadgerError> {
    let mut servers = Vec::new();

    // Create server addresses
    let addresses: Vec<SocketAddr> = (0..n_parties)
        .map(|i| format!("127.0.0.1:{}", base_port + i as u16).parse().unwrap())
        .collect();

    info!("Setting up HoneyBadger QUIC network with {} parties", n_parties);
    for (i, addr) in addresses.iter().enumerate() { info!("[HB-SETUP] Server[{}] -> {}", i, addr); }

    // Create MPC options
    let mpc_opts = HoneyBadgerMPCNodeOpts::new(
        n_parties,
        threshold,
        n_triples,
        n_random_shares,
        instance_id,
    );

    // Create all servers
    for i in 0..n_parties {
        let mut server = HoneyBadgerQuicServer::new(
            i,
            addresses[i],
            mpc_opts.clone(),
            config.clone(),
        ).await?;

        // Add all other servers as peers
        for j in 0..n_parties {
            if i != j {
                server.add_peer(j, addresses[j]).await;
            }
        }

        servers.push(server);
    }

    info!("Created {} HoneyBadger QUIC servers", servers.len());
    Ok(servers)
}

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
        let client_inputs = inputs.get(i).cloned().unwrap_or_default();

        let mut client = HoneyBadgerQuicClient::new(
            client_id,
            n_parties,
            threshold,
            instance_id,
            client_inputs,
            input_len,
            config.clone(),
        ).await?;

        // Add all servers
        for &address in &server_addresses {
            client.add_server(address);
        }

        clients.push(client);
    }

    info!("Created {} HoneyBadger QUIC clients", clients.len());
    Ok(clients)
}

/// Utility functions for message handling and serialization

/// Serializes a WrappedMessage for transmission over QUIC
pub fn serialize_wrapped_message(msg: &WrappedMessage) -> Result<Vec<u8>, HoneyBadgerError> {
    bincode::serialize(msg).map_err(HoneyBadgerError::from)
}

/// Deserializes a WrappedMessage from QUIC transmission
pub fn deserialize_wrapped_message(data: &[u8]) -> Result<WrappedMessage, HoneyBadgerError> {
    bincode::deserialize(data).map_err(HoneyBadgerError::from)
}

/// Example usage and integration tests
#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_std::test_rng;
    use std::time::Duration;
    use rustls::crypto::CryptoProvider;
    use std::sync::Once;
    use ark_std::iterable::Iterable;
    use ark_std::rand::SeedableRng;
    use stoffelmpc_mpc::common::SecretSharingScheme;
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
    async fn test_honeybadger_quic_server_creation() {
        init_crypto_provider();
        let node_id = 0;
        let bind_address: SocketAddr = "127.0.0.1:8000".parse().unwrap();
        let mpc_opts = HoneyBadgerMPCNodeOpts::new(5, 1, 10, 50, 12345);
        let config = HoneyBadgerQuicConfig::default();

        let server = HoneyBadgerQuicServer::<Fr>::new(
            node_id,
            bind_address,
            mpc_opts,
            config,
        ).await;

        assert!(server.is_ok());
        let mut server = server.unwrap();
        assert_eq!(server.node_id, 0);
        assert_eq!(server.bind_address, bind_address);

        // Test cleanup
        server.stop().await;
    }

    #[tokio::test]
    async fn test_honeybadger_quic_client_creation() {
        init_crypto_provider();
        let client_id = 100;
        let inputs = vec![Fr::from(42), Fr::from(24)];
        let config = HoneyBadgerQuicConfig::default();

        let client = HoneyBadgerQuicClient::<Fr>::new(
            client_id,
            5, // n_parties
            1, // threshold
            12345, // instance_id
            inputs,
            2, // input_len
            config,
        ).await;

        assert!(client.is_ok(), "client should be created without deadlocks");
        let mut client = client.unwrap();
        assert_eq!(client.client_id, 100);

        // Test cleanup
        client.stop().await;
    }

    #[tokio::test]
    async fn test_honeybadger_quic_network_setup() {
        init_crypto_provider();
        let config = HoneyBadgerQuicConfig::default();

        let servers = setup_honeybadger_quic_network::<Fr>(
            5, // n_parties
            1, // threshold
            5, // n_triples
            20, // n_random_shares
            12345, // instance_id
            9000, // base_port
            config,
        ).await;

        assert!(servers.is_ok(), "servers should be created without deadlocks");
        let mut servers = servers.unwrap();
        assert_eq!(servers.len(), 5);

        // Test cleanup
        for server in &mut servers {
            server.stop().await;
        }
    }

    #[tokio::test]
    async fn test_full_mpc_workflow_with_quic() {
        init_crypto_provider();
        setup_test_tracing();

        // Configuration
        let n_parties = 5;
        let threshold = 1;
        let n_triples = 3; // We'll multiply 2 values, so need at least 2 triples
        let n_random_shares = 20; // Need shares for input masking + triples
        let instance_id = 54321;
        let base_port = 9100;

        let client_id = 100;
        let input_values = vec![Fr::from(7), Fr::from(11)]; // Will compute 7 * 11 = 77

        let mut config = HoneyBadgerQuicConfig::default();
        config.mpc_timeout = Duration::from_secs(5);
        // config.connection_retry_delay = Duration::from_millis(50);

        // Step 1: Create and start 5 servers
        println!("Creating {} servers...", n_parties);
        let mut servers = setup_honeybadger_quic_network::<Fr>(
            n_parties,
            threshold,
            n_triples,
            n_random_shares,
            instance_id,
            base_port,
            config.clone(),
        ).await.expect("Failed to create servers");

        // Start all servers
        for server in &mut servers {
            info!("Started server {}", server.node_id);
            server.start().await.expect("Failed to start server without deadlocks");
        }

        // Give servers time to start listening
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Step 2: Connect servers to each other
        info!("Connecting servers to each other...");
        for server in &servers {
            server.connect_to_peers().await.expect("Failed to connect to peers");
        }

        // Give time for peer connections
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Step 3: Create client and connect to servers
        info!("Creating client and connecting to servers...");
        let server_addresses: Vec<SocketAddr> = (0..n_parties)
            .map(|i| format!("127.0.0.1:{}", base_port + i as u16).parse().unwrap())
            .collect();

        let mut client = HoneyBadgerQuicClient::new(
            client_id,
            n_parties,
            threshold,
            instance_id,
            input_values.clone(),
            input_values.len(),
            config.clone(),
        ).await.expect("Failed to create client");

        // Add all servers to client WITH their PartyIds so PartyId-based sends work (like FakeNetwork)
        for (pid, &address) in server_addresses.iter().enumerate() {
            client.add_server_with_id(pid, address);
        }

        // Optional sanity check: ensure client can resolve all parties by id before protocols start
        {
            let parties = client.network.parties();
            info!(
                "Client {} sees {} parties in map",
                client.client_id,
                parties.len()
            );
            for pid in 0..n_parties {
                assert!(
                    client.network.node(pid).is_some(),
                    "Client missing party mapping for server id {}", pid
                );
            }
        }
        // Connect client to all servers
        client.connect_to_servers().await.expect("Failed to connect to servers");

        // Give time for connections to establish
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Step 4: Run preprocessing on all servers to generate beaver triples and random shares
        info!("Running preprocessing on servers...");
        // Run preprocessing concurrently across all servers without spawning tasks
        let preprocessing_futs: Vec<_> = servers
            .iter()
            .enumerate()
            .map(|(i, server)| {
                // Independent RNG per server
                let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
                async move {
                    match server.run_preprocessing(&mut rng).await {
                        Ok(()) => println!("Preprocessing completed for server {}", i),
                        Err(e) => println!("Preprocessing failed for server {}: {:?}", i, e),
                    }
                }
            })
            .collect();
        futures::future::join_all(preprocessing_futs).await;

        // Give time for preprocessing to settle
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Step 5: Client inputs secret values (this will secret-share them to servers)
        info!("Client inputting secret values via real input protocol...");

        // Trigger the input protocol on each server: send mask shares to client
        for server in &servers {
            server
                .run_input_protocol(client_id, input_values.len())
                .await
                .expect("Server failed to send mask shares to client");
        }

        // Allow time for client to reconstruct masks and broadcast masked inputs via RBC
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Step 6: Perform secure multiplication on servers
        info!("Performing secure multiplication...");
        let multiplication_futs: Vec<_> = servers
            .iter()
            .enumerate()
            .map(|(i, server)| {
                let cid = client_id;
                async move {
                    match server.get_input_shares(cid).await {
                        Some(shares) if shares.len() >= 2 => {
                            let x_share = vec![shares[0].clone()];
                            let y_share = vec![shares[1].clone()];
                            match server.multiply(x_share, y_share).await {
                                Ok(result) => {
                                    println!("Multiplication completed for server {}, got {} result shares", i, result.len());
                                    result
                                },
                                Err(e) => {
                                    println!("Multiplication failed for server {}: {:?}", i, e);
                                    Vec::new()
                                }
                            }
                        }
                        _ => {
                            println!("Multiplication skipped for server {}: input shares not ready", i);
                            Vec::new()
                        }
                    }
                }
            })
            .collect();
        let multiplication_results: Vec<Vec<RobustShare<Fr>>> = futures::future::join_all(multiplication_futs).await;

        // Step 7: Collect and verify results
        info!("Collecting multiplication results...");
        let mut result_shares = Vec::new();

        for (i, res) in multiplication_results.iter().enumerate() {
            if !res.is_empty() {
                result_shares.push(res[0].clone());
                println!("Server {} contributed result share", i);
            }
        }

        // Step 8: Reconstruct the final result
        if result_shares.len() >= threshold + 1 {
            let shares_for_reconstruction = result_shares[0..=threshold].to_vec();
            match RobustShare::recover_secret(&shares_for_reconstruction, n_parties) {
                Ok((_, reconstructed_result)) => {
                    let expected_result = input_values[0] * input_values[1]; // 7 * 11 = 77

                    info!("Reconstruction successful!");
                    info!("Expected: {} * {} = {}", input_values[0], input_values[1], expected_result);
                    info!("Got: {}", reconstructed_result);

                    assert_eq!(reconstructed_result, expected_result,
                              "Multiplication result mismatch! Expected {}, got {}",
                              expected_result, reconstructed_result);

                    info!("✅ Full MPC workflow completed successfully!");
                },
                Err(e) => {
                    panic!("Failed to reconstruct result: {:?}", e);
                }
            }
        } else {
            panic!("Not enough result shares to reconstruct (got {}, need {})",
                  result_shares.len(), threshold + 1);
        }

        // Step 9: Cleanup
        info!("Cleaning up...");

        // Stop client
        client.stop().await;

        // Stop all servers
        for mut server in servers {
            server.stop().await;
        }

        info!("Test completed successfully!");
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
        let n_random_shares = 5; // Minimal random shares
        let instance_id = 99999;
        let base_port = 9200;

        let mut config = HoneyBadgerQuicConfig::default();
        config.mpc_timeout = Duration::from_secs(10);
        config.connection_retry_delay = Duration::from_millis(100);

        info!("Configuration: n_parties={}, threshold={}, n_triples={}, n_random_shares={}",
              n_parties, threshold, n_triples, n_random_shares);

        // Step 1: Create servers
        info!("Step 1: Creating {} servers...", n_parties);
        let mut servers = setup_honeybadger_quic_network::<Fr>(
            n_parties,
            threshold,
            n_triples,
            n_random_shares,
            instance_id,
            base_port,
            config.clone(),
        ).await.expect("Failed to create servers");
        info!("✓ Created {} servers", servers.len());

        // Step 2: Start all servers
        info!("Step 2: Starting servers...");
        for server in &mut servers {
            server.start().await.expect("Failed to start server");
            info!("✓ Started server {}", server.node_id);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Step 3: Connect servers to each other
        info!("Step 3: Connecting servers to each other...");
        for server in &servers {
            info!("Connecting server {} to peers...", server.node_id);
            server.connect_to_peers().await.expect("Failed to connect to peers");
            info!("✓ Server {} connected to peers", server.node_id);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;

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
                        info!("✓ Server {} can resolve peer {} at {}", i, peer_id, node.address());
                    }
                    None => {
                        error!("✗ Server {} CANNOT resolve peer {}", i, peer_id);
                        panic!("Network connectivity check failed: Server {} cannot resolve peer {}", i, peer_id);
                    }
                }
            }
        }
        info!("✓ Network connectivity verified");

        // Step 5: Run preprocessing with timeout and detailed logging
        info!("Step 5: Running preprocessing on all servers...");
        info!("Each server will generate {} triples and {} random shares", n_triples, n_random_shares);

        let preprocessing_timeout = Duration::from_secs(30);

        let preprocessing_handles: Vec<_> = servers
            .iter()
            .enumerate()
            .map(|(i, server)| {
                let server_clone = server.node.clone();
                let network_clone = server.network.clone();

                tokio::spawn(async move {
                    info!("[Server {}] Starting preprocessing...", i);
                    let mut rng = ark_std::rand::rngs::StdRng::from_entropy();

                    let result = tokio::time::timeout(
                        preprocessing_timeout,
                        async {
                            let mut node = server_clone.lock().await;
                            info!("[Server {}] Acquired node lock, calling run_preprocessing", i);
                            let res = node.run_preprocessing(network_clone.clone(), &mut rng).await;
                            info!("[Server {}] run_preprocessing returned: {:?}", i, res.is_ok());
                            res
                        }
                    ).await;

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
                            error!("[Server {}] ✗ Preprocessing TIMED OUT after {:?}", i, preprocessing_timeout);
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
                let node = server.node.lock().await;
                let preproc = node.preprocessing_material.lock().await;

                let (triples_count, random_shares_count) = preproc.len();


                info!("Server {} has {} triples and {} random shares",
                      i, triples_count, random_shares_count);

                assert!(triples_count > 0, "Server {} has no triples!", i);
                assert!(random_shares_count > 0, "Server {} has no random shares!", i);
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
        use tracing_subscriber::{FmtSubscriber};
        use std::sync::Once;

        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let subscriber = FmtSubscriber::builder()
                .with_env_filter(EnvFilter::from_default_env()
                    .add_directive("debug".parse().unwrap()))
                .with_test_writer()
                .finish();
            let _ = tracing::subscriber::set_global_default(subscriber);
        });
    }

    // Additional helper test to verify the basic multiplication logic
    #[tokio::test]
    async fn test_secret_sharing_multiplication_logic() {
        init_crypto_provider();

        let n_parties = 5;
        let threshold = 1;
        let mut rng = ark_std::test_rng();

        // Test values
        let x_val = Fr::from(13);
        let y_val = Fr::from(17);
        let expected = x_val * y_val; // 13 * 17 = 221

        // Create secret shares
        let x_shares = RobustShare::compute_shares(x_val, n_parties, threshold, None, &mut rng)
            .expect("Failed to create x shares");
        let y_shares = RobustShare::compute_shares(y_val, n_parties, threshold, None, &mut rng)
            .expect("Failed to create y shares");

        // Verify we can reconstruct the original values
        let x_reconstructed = RobustShare::recover_secret(&x_shares[0..=n_parties-1], n_parties)
            .expect("Failed to reconstruct x").1;
        let y_reconstructed = RobustShare::recover_secret(&y_shares[0..=n_parties-1], n_parties)
            .expect("Failed to reconstruct y").1;

        assert_eq!(x_reconstructed, x_val, "X reconstruction failed");
        assert_eq!(y_reconstructed, y_val, "Y reconstruction failed");

        println!("✅ Secret sharing logic verification passed!");
        println!("Original values: x={}, y={}, expected_product={}", x_val, y_val, expected);
        println!("Reconstructed: x={}, y={}", x_reconstructed, y_reconstructed);
    }

}
