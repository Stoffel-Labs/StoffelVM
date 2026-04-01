// honeybadger_quic.rs
//! Integration module for HoneyBadger MPC with QUIC networking.
//!
//! Uses stoffelnet's `assign_party_ids()` / `compute_local_party_id()` for
//! deterministic public-key-based party ID assignment, and a thin `MpcNetwork`
//! wrapper that only overrides `broadcast()` (self-skip to prevent AVID RBC
//! amplification) and `send_to_client()` (logical-ID bridging).
use crate::net::mpc::honeybadger_node_opts;
use ark_ff::{FftField, PrimeField};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::common::{MPCProtocol, PreprocessingMPCProtocol};
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::SessionId as HbSessionId;
use stoffelmpc_mpc::honeybadger::{
    HoneyBadgerError, HoneyBadgerMPCClient, HoneyBadgerMPCNode, HoneyBadgerMPCNodeOpts,
};
use stoffelnet::network_utils::{ClientId, Network, NetworkError, Node, PartyId, VerifiedOrdering};
use stoffelnet::transports::quic::{
    NetworkManager, PeerConnection, QuicNetworkConfig, QuicNetworkManager,
};
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, trace, warn};

// ---------------------------------------------------------------------------
// MpcNetwork – thin wrapper over QuicNetworkManager
// ---------------------------------------------------------------------------

/// Thin `Network` wrapper over `QuicNetworkManager`.
///
/// Delegates `send()` to the underlying manager (which routes via
/// `assign_party_ids()` / sorted-public-key positions).  Overrides only:
///
/// * **`broadcast()`** – skips self to prevent AVID RBC store amplification.
/// * **`send_to_client()`** – bridges logical client IDs to QUIC-derived IDs.
#[derive(Clone)]
pub struct MpcNetwork {
    pub inner: Arc<QuicNetworkManager>,
    /// Logical client ID → connection.
    client_conns: Arc<std::sync::RwLock<HashMap<ClientId, Arc<dyn PeerConnection>>>>,
}

impl MpcNetwork {
    pub fn new(inner: Arc<QuicNetworkManager>) -> Self {
        Self {
            inner,
            client_conns: Arc::new(std::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Register a client connection under a logical client ID so that
    /// `send_to_client(logical_id, ..)` can find it.
    pub fn register_client(&self, logical_id: ClientId, conn: Arc<dyn PeerConnection>) {
        self.client_conns.write().unwrap().insert(logical_id, conn);
    }
}

#[async_trait::async_trait]
impl Network for MpcNetwork {
    type NodeType = <QuicNetworkManager as Network>::NodeType;
    type NetworkConfig = <QuicNetworkManager as Network>::NetworkConfig;

    async fn send(&self, recipient: PartyId, message: &[u8]) -> Result<usize, NetworkError> {
        self.inner.send(recipient, message).await
    }

    async fn broadcast(&self, message: &[u8]) -> Result<usize, NetworkError> {
        let local = self.inner.local_party_id();
        let n = self.inner.party_count();
        let mut total = 0;
        for i in 0..n {
            // Skip self – sending broadcast messages to ourselves via loopback
            // causes AVID RBC store amplification: after drain_rbc_output()
            // removes a completed session, late self-messages recreate the store
            // and trigger exponential re-processing cascades that starve later
            // protocol rounds.
            if i == local {
                continue;
            }
            if self.inner.send(i, message).await.is_ok() {
                total += message.len();
            }
        }
        Ok(total)
    }

    fn parties(&self) -> Vec<&Self::NodeType> {
        self.inner.parties()
    }
    fn parties_mut(&mut self) -> Vec<&mut Self::NodeType> {
        vec![]
    }
    fn config(&self) -> &Self::NetworkConfig {
        self.inner.config()
    }
    fn node(&self, id: PartyId) -> Option<&Self::NodeType> {
        self.inner.node(id)
    }
    fn node_mut(&mut self, _id: PartyId) -> Option<&mut Self::NodeType> {
        None
    }

    async fn send_to_client(
        &self,
        client: ClientId,
        message: &[u8],
    ) -> Result<usize, NetworkError> {
        // Check local logical-ID map first (clone Arc before await)
        let conn = self.client_conns.read().unwrap().get(&client).cloned();
        if let Some(conn) = conn {
            if conn.is_connected().await {
                return conn
                    .send(message)
                    .await
                    .map(|_| message.len())
                    .map_err(|_| NetworkError::SendError);
            }
        }
        self.inner.send_to_client(client, message).await
    }

    fn clients(&self) -> Vec<ClientId> {
        let mut ids = self.inner.clients();
        for id in self.client_conns.read().unwrap().keys() {
            if !ids.contains(id) {
                ids.push(*id);
            }
        }
        ids
    }
    fn is_client_connected(&self, client: ClientId) -> bool {
        if self.client_conns.read().unwrap().contains_key(&client) {
            return true;
        }
        self.inner.is_client_connected(client)
    }
    fn local_party_id(&self) -> PartyId {
        self.inner.local_party_id()
    }
    fn party_count(&self) -> usize {
        self.inner.party_count()
    }
    fn verified_ordering(&self) -> Option<VerifiedOrdering> {
        self.inner.verified_ordering()
    }
}

/// `MpcNetwork` variant for the client side.
///
/// The client cannot use `QuicNetworkManager::send()` directly because
/// `get_connection_by_party_id()` sorts ALL public keys (including the
/// client's own) which gives positions that don't match the server-only
/// sorted order.  Instead we keep an explicit connection vec indexed by
/// the servers' party IDs (built from the sorted server public keys).
#[derive(Clone)]
pub struct ClientMpcNetwork {
    inner: Arc<QuicNetworkManager>,
    /// Connections indexed by server party ID (sorted public key position).
    conns: Arc<Vec<Option<Arc<dyn PeerConnection>>>>,
    n: usize,
    local_id: ClientId,
}

#[async_trait::async_trait]
impl Network for ClientMpcNetwork {
    type NodeType = <QuicNetworkManager as Network>::NodeType;
    type NetworkConfig = <QuicNetworkManager as Network>::NetworkConfig;

    async fn send(&self, recipient: PartyId, message: &[u8]) -> Result<usize, NetworkError> {
        let conn = self
            .conns
            .get(recipient)
            .and_then(|c| c.as_ref())
            .ok_or(NetworkError::PartyNotFound(recipient))?;
        conn.send(message)
            .await
            .map(|_| message.len())
            .map_err(|_| NetworkError::SendError)
    }

    async fn broadcast(&self, message: &[u8]) -> Result<usize, NetworkError> {
        let mut total = 0;
        for i in 0..self.n {
            if let Some(Some(conn)) = self.conns.get(i) {
                if conn.send(message).await.is_ok() {
                    total += message.len();
                }
            }
        }
        Ok(total)
    }

    fn parties(&self) -> Vec<&Self::NodeType> {
        self.inner.parties()
    }
    fn parties_mut(&mut self) -> Vec<&mut Self::NodeType> {
        vec![]
    }
    fn config(&self) -> &Self::NetworkConfig {
        self.inner.config()
    }
    fn node(&self, id: PartyId) -> Option<&Self::NodeType> {
        self.inner.node(id)
    }
    fn node_mut(&mut self, _id: PartyId) -> Option<&mut Self::NodeType> {
        None
    }
    async fn send_to_client(
        &self,
        client: ClientId,
        message: &[u8],
    ) -> Result<usize, NetworkError> {
        self.inner.send_to_client(client, message).await
    }
    fn clients(&self) -> Vec<ClientId> {
        self.inner.clients()
    }
    fn is_client_connected(&self, client: ClientId) -> bool {
        self.inner.is_client_connected(client)
    }
    fn local_party_id(&self) -> PartyId {
        self.local_id
    }
    fn party_count(&self) -> usize {
        self.n
    }
    fn verified_ordering(&self) -> Option<VerifiedOrdering> {
        None
    }
}

// Keep RoutedNetwork as a type alias for backward-compat with vm_mpc_integration
pub type RoutedNetwork = MpcNetwork;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for HoneyBadger MPC over QUIC
#[derive(Debug, Clone)]
pub struct HoneyBadgerQuicConfig {
    pub mpc_timeout: Duration,
    pub max_connection_retries: u32,
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

// ---------------------------------------------------------------------------
// HoneyBadgerQuicServer
// ---------------------------------------------------------------------------

/// A HoneyBadger MPC server node using QUIC networking.
///
/// Setup order:
/// 1. `new()` – creates the QUIC listener and registers peers (no HB node yet)
/// 2. `start()` – spawns the accept loop
/// 3. `connect_to_peers()` – dials all peers
/// 4. `finalize_network()` – calls `assign_party_ids()`, creates the HB node
///    with the computed party ID, and builds the `MpcNetwork` wrapper
pub struct HoneyBadgerQuicServer<F: FftField + PrimeField> {
    /// The underlying MPC node.  Created eagerly in `new()` with `node_id`;
    /// recreated in `finalize_network()` with the proper sorted-key party ID.
    pub node: HoneyBadgerMPCNode<F, Avid<HbSessionId>>,
    /// Kept so `finalize_network()` can recreate the node with the correct ID.
    mpc_opts: Option<HoneyBadgerMPCNodeOpts>,
    /// Network manager builder – consumed by `start()`.
    network_builder: Option<QuicNetworkManager>,
    /// Network manager Arc – created by `start()`, shared with all tasks.
    pub network: Option<Arc<QuicNetworkManager>>,
    connection_task: Option<JoinHandle<()>>,
    pub config: HoneyBadgerQuicConfig,
    shutdown_tx: Option<mpsc::Sender<()>>,
    pub node_id: PartyId,
    /// Computed party ID from `assign_party_ids()`.
    pub party_id: Option<PartyId>,
    pub channels: Sender<(PartyId, Vec<u8>)>,
    /// Available after `finalize_network()`.
    pub routed_network: Option<Arc<MpcNetwork>>,
    pub expected_client_ids: Vec<ClientId>,
    pub open_message_router: Arc<crate::net::open_registry::OpenMessageRouter>,
}

impl<F: FftField + PrimeField + 'static> HoneyBadgerQuicServer<F> {
    /// Creates a new server.  The HB node is created eagerly with `node_id`.
    /// Call `finalize_network()` after connections to recreate with the proper
    /// sorted-key party ID and build the `MpcNetwork` wrapper.
    pub async fn new(
        node_id: PartyId,
        bind_address: SocketAddr,
        mpc_opts: HoneyBadgerMPCNodeOpts,
        config: HoneyBadgerQuicConfig,
        channels: Sender<(PartyId, Vec<u8>)>,
        input_ids: Vec<ClientId>,
    ) -> Result<Self, HoneyBadgerError> {
        // Create HB node eagerly (will be recreated in finalize_network
        // if the sorted-key party ID differs from node_id).
        let hb_node = <HoneyBadgerMPCNode<F, Avid<HbSessionId>> as MPCProtocol<
            F,
            RobustShare<F>,
            QuicNetworkManager,
        >>::setup(node_id, mpc_opts.clone(), input_ids.clone())?;

        info!(
            "[HB-QUIC] Initializing network manager for node {} at {}",
            node_id, bind_address
        );
        let mut mgr = QuicNetworkManager::new();
        info!("[HB-QUIC] Node {} calling listen({})", node_id, bind_address);
        mgr.listen(bind_address).await.map_err(|e| {
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

        // Register self so parties() includes us
        mgr.add_node_with_party_id(mgr.local_derived_id(), bind_address);

        let initial_parties = mgr.parties().len();
        info!(
            "Created HoneyBadger QUIC server for node {} on {} (initial peers: {})",
            node_id, bind_address, initial_parties
        );

        Ok(Self {
            node: hb_node,
            mpc_opts: Some(mpc_opts),
            network_builder: Some(mgr),
            network: None,
            connection_task: None,
            config,
            shutdown_tx: None,
            node_id,
            party_id: None,
            channels,
            routed_network: None,
            expected_client_ids: input_ids,
            open_message_router: Arc::new(crate::net::open_registry::OpenMessageRouter::new()),
        })
    }

    /// Returns the TLS-derived identity of this server's QUIC endpoint.
    /// Available before and after `start()`.
    pub fn local_derived_id(&self) -> PartyId {
        if let Some(ref net) = self.network {
            net.local_derived_id()
        } else if let Some(ref builder) = self.network_builder {
            builder.local_derived_id()
        } else {
            0
        }
    }

    /// Adds a peer node to connect to.  Must be called before `start()`.
    ///
    /// `peer_id` should be the peer's TLS-derived identity so that the
    /// QUIC accept-loop allowlist recognises inbound connections from it.
    pub async fn add_peer(&mut self, peer_id: PartyId, address: SocketAddr) {
        if let Some(ref mut builder) = self.network_builder {
            builder.add_node_with_party_id(peer_id, address);
            info!("Added peer {} at {} to node {}", peer_id, address, self.node_id);
        } else {
            panic!("Cannot add peer after start() on node {}", self.node_id);
        }
    }

    /// Starts the accept loop.
    pub async fn start(&mut self) -> Result<(), HoneyBadgerError> {
        let network = Arc::new(
            self.network_builder
                .take()
                .expect("start() called but network_builder is None"),
        );
        self.network = Some(network.clone());

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
        self.shutdown_tx = Some(shutdown_tx);

        info!("Starting HoneyBadger QUIC server on node {}", self.node_id);

        let mut acceptor = (*network).clone();
        let node_id = self.node_id;
        let tx = self.channels.clone();
        let expected_clients = self.expected_client_ids.clone();

        let connection_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        info!("Shutting down connection handler for node {}", node_id);
                        break;
                    }
                    result = acceptor.accept() => {
                        match result {
                            Ok(connection) => {
                                info!("Node {} accepted connection from {}", node_id, connection.remote_address());
                                // Don't spawn receive handlers here for server
                                // connections — they'll be spawned in
                                // spawn_server_receive_loops() after
                                // assign_party_ids() has run.
                                //
                                // For client connections (arriving later), only
                                // auto-bridge when there is exactly one logical
                                // client. Multi-client integration tests install
                                // explicit derived-id -> logical-id handlers after
                                // connect_to_servers(); guessing here would route
                                // every client through expected_clients[0].
                                let is_unknown = connection.remote_party_id().is_none()
                                    && acceptor.parties().iter().all(|n| {
                                        n.address() != connection.remote_address()
                                    });
                                if is_unknown && expected_clients.len() == 1 {
                                    let txx = tx.clone();
                                    let client_sid = expected_clients[0];
                                    tokio::spawn(async move {
                                        loop {
                                            match connection.receive().await {
                                                Ok(data) => {
                                                    if txx.send((client_sid, data)).await.is_err() {
                                                        break;
                                                    }
                                                }
                                                Err(_) => break,
                                            }
                                        }
                                    });
                                }
                                // Server connections: accept() already stored them
                                // in the shared DashMap; nothing else to do here.
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

    /// Dials all registered peers.
    pub async fn connect_to_peers(&mut self) -> Result<(), HoneyBadgerError> {
        let network = self
            .network
            .as_ref()
            .expect("connect_to_peers() called before start()")
            .clone();

        let peers: Vec<SocketAddr> = network
            .parties()
            .iter()
            .map(|p| p.address())
            .collect();

        let mut dialer = (*network).clone();

        let local_did = network.local_derived_id();

        for peer_addr in &peers {
            // Skip self (our own address is in the list)
            if Some(*peer_addr)
                == network
                    .parties()
                    .iter()
                    .find(|p| p.id() == local_did)
                    .map(|p| p.address())
            {
                continue;
            }

            let mut retry_count = 0u32;
            loop {
                match dialer.connect_as_server(*peer_addr).await {
                    Ok(conn) => {
                        info!(
                            "Node {} connected to peer at {}",
                            self.node_id, peer_addr
                        );
                        drop(conn);
                        break;
                    }
                    Err(e) => {
                        retry_count += 1;
                        if retry_count >= self.config.max_connection_retries {
                            warn!(
                                "Node {} failed to connect to {} after {} attempts: {}",
                                self.node_id, peer_addr, retry_count, e
                            );
                            break;
                        }
                        tokio::time::sleep(self.config.connection_retry_delay).await;
                    }
                }
            }
        }

        Ok(())
    }

    /// Finalize the network after all connections are established.
    ///
    /// 1. Calls `assign_party_ids()` to stamp sorted-key positions on connections.
    /// 2. Computes the local party ID via `compute_local_party_id()`.
    /// 3. Creates the HoneyBadger MPC node with the computed party ID.
    /// 4. Builds the `MpcNetwork` wrapper (broadcast self-skip + client bridge).
    pub fn finalize_network(&mut self) -> Result<PartyId, HoneyBadgerError> {
        let network = self
            .network
            .as_ref()
            .expect("finalize_network() called before start()")
            .clone();

        let assigned = network.assign_party_ids();
        let local_pid = network
            .compute_local_party_id()
            .expect("compute_local_party_id failed — no local public key?");

        info!(
            "Node {} (legacy id {}) finalized: party_id={}, assigned {} connections, party_count={}",
            local_pid, self.node_id, local_pid, assigned, network.party_count()
        );

        self.party_id = Some(local_pid);

        // Recreate HB node with the correct sorted-key party ID
        if let Some(opts) = self.mpc_opts.take() {
            let hb_node = <HoneyBadgerMPCNode<F, Avid<HbSessionId>> as MPCProtocol<
                F,
                RobustShare<F>,
                QuicNetworkManager,
            >>::setup(local_pid, opts, self.expected_client_ids.clone())
            .map_err(|e| {
                error!("Failed to create HB node: {:?}", e);
                e
            })?;
            self.node = hb_node;
        }

        // Build MpcNetwork wrapper
        let wrapper = MpcNetwork::new(network);
        self.routed_network = Some(Arc::new(wrapper));

        Ok(local_pid)
    }

    /// Spawns receive handlers for all server connections currently in the
    /// DashMap.  Must be called AFTER `finalize_network()` so that
    /// `remote_party_id()` is set on the canonical connections.
    pub fn spawn_server_receive_loops(&self) {
        let network = self
            .network
            .as_ref()
            .expect("spawn_server_receive_loops called before start()");
        let derived_to_party: std::collections::HashMap<PartyId, PartyId> = network
            .get_sorted_public_keys()
            .into_iter()
            .enumerate()
            .map(|(party_id, pk)| (pk.derive_id(), party_id))
            .collect();
        let all = network.get_all_server_connections();
        for (derived_id, conn) in all {
            let txx = self.channels.clone();
            let nid = self.node_id;
            let sender_id = conn
                .remote_party_id()
                .unwrap_or_else(|| *derived_to_party.get(&derived_id).unwrap_or(&derived_id));
            tokio::spawn(async move {
                loop {
                    match conn.receive().await {
                        Ok(data) => {
                            if txx.send((sender_id, data)).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                trace!("Node {} DashMap recv handler ended", nid);
            });
        }
    }

    pub async fn stop(&mut self) {
        info!("Stopping HoneyBadger QUIC server for node {}", self.node_id);
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }
        if let Some(task) = self.connection_task.take() {
            let _ = task.await;
        }
        info!("Stopped HoneyBadger QUIC server for node {}", self.node_id);
    }
}

// ---------------------------------------------------------------------------
// HoneyBadgerQuicClient
// ---------------------------------------------------------------------------

/// Message types for the client actor
pub enum ClientActorMessage {
    ProcessData(PartyId, Vec<u8>),
    SetConnections(Vec<Option<Arc<dyn PeerConnection>>>),
    Shutdown,
}

/// A HoneyBadger MPC client using QUIC networking with actor model
pub struct HoneyBadgerQuicClient<F: FftField> {
    pub network: Arc<Mutex<QuicNetworkManager>>,
    pub config: HoneyBadgerQuicConfig,
    server_addresses: Vec<SocketAddr>,
    pub client_id: ClientId,
    connection_tasks: Vec<JoinHandle<()>>,
    actor_tx: mpsc::Sender<ClientActorMessage>,
    actor_task: Option<JoinHandle<HoneyBadgerMPCClient<F, Avid<HbSessionId>>>>,
}

impl<F: FftField + 'static> HoneyBadgerQuicClient<F> {
    pub async fn new(
        client_id: ClientId,
        n_parties: usize,
        threshold: usize,
        instance_id: u64,
        inputs: Vec<F>,
        input_len: usize,
        config: HoneyBadgerQuicConfig,
    ) -> Result<Self, HoneyBadgerError> {
        let mpc_client = HoneyBadgerMPCClient::new(
            client_id,
            n_parties,
            threshold,
            instance_id as u32,
            inputs,
            input_len,
        )?;

        let network = Arc::new(Mutex::new(QuicNetworkManager::new()));
        let (actor_tx, actor_rx) = mpsc::channel(1000);

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

    /// Actor loop that owns the MPC client.
    ///
    /// Uses a `ClientMpcNetwork` built from `SetConnections` so that
    /// party-ID routing matches the servers' sorted-public-key order.
    async fn run_actor(
        mut client: HoneyBadgerMPCClient<F, Avid<HbSessionId>>,
        mut rx: mpsc::Receiver<ClientActorMessage>,
        network: Arc<Mutex<QuicNetworkManager>>,
    ) -> HoneyBadgerMPCClient<F, Avid<HbSessionId>> {
        let client_id = client.id;
        info!("Starting actor loop for client {}", client_id);

        // Placeholder until SetConnections arrives.
        let initial_net = {
            let guard = network.lock().await;
            Arc::new(guard.clone())
        };
        let mut net: Arc<ClientMpcNetwork> = Arc::new(ClientMpcNetwork {
            inner: initial_net,
            conns: Arc::new(Vec::new()),
            n: 0,
            local_id: client_id,
        });

        while let Some(msg) = rx.recv().await {
            match msg {
                ClientActorMessage::SetConnections(conns) => {
                    let n = conns.len();
                    let guard = network.lock().await;
                    net = Arc::new(ClientMpcNetwork {
                        inner: Arc::new(guard.clone()),
                        conns: Arc::new(conns),
                        n,
                        local_id: client_id,
                    });
                    info!(
                        "Client {} actor built ClientMpcNetwork ({} parties)",
                        client_id, n
                    );
                }
                ClientActorMessage::ProcessData(sender_id, data) => {
                    if data.starts_with(b"ROLE:") {
                        continue;
                    }
                    if let Err(e) = client.process(sender_id, data, net.clone()).await {
                        error!("Client {} failed to process message: {:?}", client_id, e);
                    }
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

    pub async fn add_server_with_id(&mut self, party_id: PartyId, address: SocketAddr) {
        self.server_addresses.push(address);
        let mut manager = self.network.lock().await;
        manager.add_node_with_party_id(party_id, address);
        info!(
            "Client {} registered server party_id={} at {}",
            self.client_id, party_id, address
        );
    }

    pub fn add_server(&mut self, address: SocketAddr) {
        self.server_addresses.push(address);
    }

    /// Connects to all configured servers and builds the sorted-key-ordered
    /// connection map for the actor's `ClientMpcNetwork`.
    pub async fn connect_to_servers(&mut self) -> Result<(), HoneyBadgerError> {
        let n = self.server_addresses.len();
        info!("Client {} connecting to {} servers", self.client_id, n);

        // 1. Dial all servers
        for (i, &address) in self.server_addresses.iter().enumerate() {
            let mut retry_count = 0u32;
            loop {
                let connection_result = {
                    let mut dialer = self.network.lock().await;
                    dialer.connect_as_client(address).await
                };
                match connection_result {
                    Ok(connection) => {
                        info!(
                            "Client {} successfully connected to server {} at {}",
                            self.client_id, i, address
                        );

                        // Spawn receive handler – sender_id will be set below
                        // once we build the sorted-key mapping.
                        let actor_tx = self.actor_tx.clone();
                        let cid = self.client_id;
                        // temporarily tag with address index; we'll re-tag below
                        let task = tokio::spawn(async move {
                            loop {
                                match connection.receive().await {
                                    Ok(data) => {
                                        // Use remote_party_id at receive time
                                        let sid = connection
                                            .remote_party_id()
                                            .unwrap_or(i);
                                        if let Err(e) = actor_tx
                                            .send(ClientActorMessage::ProcessData(sid, data))
                                            .await
                                        {
                                            error!("Client {} actor send error: {:?}", cid, e);
                                            break;
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                        });
                        self.connection_tasks.push(task);
                        break;
                    }
                    Err(e) => {
                        retry_count += 1;
                        if retry_count >= self.config.max_connection_retries {
                            error!(
                                "Client {} failed to connect to server {} after {} attempts: {}",
                                self.client_id, i, retry_count, e
                            );
                            return Err(HoneyBadgerError::NetworkError(NetworkError::Timeout));
                        }
                        tokio::time::sleep(self.config.connection_retry_delay).await;
                    }
                }
            }
        }

        // 2. Build sorted-key-ordered connection map.
        //    The servers sort ALL their public keys (no client key) to assign
        //    party IDs 0..n-1.  We must sort only the SERVER keys the same way
        //    so our shard routing matches.
        let mgr = self.network.lock().await;
        let mut server_keys = mgr.get_sorted_public_keys();
        // Remove client's own key (it's in the sort because connect_as_client
        // stores our local key).
        if let Some(local_pk) = mgr.get_public_key_for_party_id(mgr.local_party_id()) {
            server_keys.retain(|k| k != &local_pk);
        }
        // server_keys is now sorted with only server public keys, positions 0..n-1

        let mut indexed_conns: Vec<Option<Arc<dyn PeerConnection>>> = vec![None; server_keys.len()];
        for (party_id, pk) in server_keys.iter().enumerate() {
            let derived_id = pk.derive_id();
            let all = mgr.get_all_server_connections();
            for (did, conn) in &all {
                if *did == derived_id {
                    conn.set_remote_party_id(party_id);
                    indexed_conns[party_id] = Some(conn.clone());
                    break;
                }
            }
        }
        drop(mgr);

        // 3. Send to actor
        self.actor_tx
            .send(ClientActorMessage::SetConnections(indexed_conns))
            .await
            .map_err(|_| HoneyBadgerError::NetworkError(NetworkError::SendError))?;

        Ok(())
    }

    pub async fn stop(
        mut self,
    ) -> Result<HoneyBadgerMPCClient<F, Avid<HbSessionId>>, HoneyBadgerError> {
        info!("Stopping HoneyBadger QUIC client {}", self.client_id);
        let _ = self.actor_tx.send(ClientActorMessage::Shutdown).await;

        let client = if let Some(task) = self.actor_task.take() {
            task.await.map_err(|e| {
                error!("Failed to join actor task: {:?}", e);
                HoneyBadgerError::NetworkError(NetworkError::Timeout)
            })?
        } else {
            return Err(HoneyBadgerError::NetworkError(NetworkError::Timeout));
        };

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
        if let Some(task) = self.actor_task.take() {
            task.abort();
        }
        for task in self.connection_tasks.drain(..) {
            task.abort();
        }
    }
}

// ---------------------------------------------------------------------------
// Setup helpers
// ---------------------------------------------------------------------------

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

        for &address in &server_addresses {
            client.add_server(address);
        }

        clients.push(client);
    }

    Ok(clients)
}

/// Sets up a complete HoneyBadger MPC network with QUIC.
///
/// Returns servers with network managers ready but NO HB nodes yet.
/// The caller must:
/// 1. `start()` each server
/// 2. `connect_to_peers()` each server
/// 3. `finalize_network()` each server (creates HB node + MpcNetwork)
pub async fn setup_honeybadger_quic_network<F: FftField + PrimeField + 'static>(
    n_parties: usize,
    threshold: usize,
    n_triples: usize,
    n_random_shares: usize,
    instance_id: u64,
    base_port: u16,
    config: HoneyBadgerQuicConfig,
    input_ids: Option<Vec<ClientId>>,
) -> Result<
    (
        Vec<HoneyBadgerQuicServer<F>>,
        Vec<Receiver<(PartyId, Vec<u8>)>>,
    ),
    HoneyBadgerError,
> {
    let input_ids = input_ids.unwrap_or_default();
    let mut servers = Vec::new();

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

    let mpc_opts = honeybadger_node_opts(
        n_parties,
        threshold,
        n_triples,
        n_random_shares,
        instance_id,
    )
    .expect("Failed to create HoneyBadger node options");

    let mut recv = Vec::new();
    // First pass: create all servers so their TLS identities are available.
    for i in 0..n_parties {
        let (tx, rx) = mpsc::channel(1500);
        let server = HoneyBadgerQuicServer::new(
            i,
            addresses[i],
            mpc_opts.clone(),
            config.clone(),
            tx,
            input_ids.clone(),
        )
        .await?;
        servers.push(server);
        recv.push(rx);
    }

    // Collect each server's TLS-derived ID so peers can be registered with
    // the correct identity (required for the QUIC accept-loop allowlist).
    let derived_ids: Vec<PartyId> = servers.iter().map(|s| s.local_derived_id()).collect();

    // Second pass: cross-register peers using real derived IDs.
    for i in 0..n_parties {
        for j in 0..n_parties {
            if i != j {
                servers[i].add_peer(derived_ids[j], addresses[j]).await;
            }
        }
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
    use std::time::Duration;
    use stoffelmpc_mpc::common::ProtocolSessionId;
    use stoffelmpc_mpc::honeybadger::{ProtocolType, SessionId};

    use crate::tests::test_utils::{
        acquire_hb_itest_lock, init_crypto_provider, setup_test_tracing,
    };

    #[tokio::test]
    async fn test_preprocessing_client_mul() {
        init_crypto_provider();
        setup_test_tracing();
        let _hb_itest_lock = acquire_hb_itest_lock().await;

        info!("=== Starting Preprocessing-Only Test ===");

        // Minimal configuration for faster debugging
        let n_parties = 5;
        let threshold = 1;
        let n_triples = 2 * threshold + 1; // Minimal number of triples
        let n_random_shares = 2 + 2 * n_triples; // Minimal random shares
        let instance_id = 99999;
        let base_port = 9200;
        let _session_id = SessionId::new(
            ProtocolType::Mul,
            SessionId::pack_slot24(0, 0, 0),
            instance_id as u32,
        );
        // Define client IDs before network setup (client IDs must be registered at setup time)
        // Client 100 is for input, client 200 is for output only
        let input_client_id: ClientId = 100;
        let output_client_id: ClientId = 200;
        let clientid: Vec<ClientId> = vec![input_client_id]; // Only register input client
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
            Some(clientid.clone()),
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

        // Step 2: Start all servers (no receive handler spawn yet)
        info!("Step 2: Starting servers...");
        for server in servers.iter_mut() {
            server.start().await.expect("Failed to start server");
            info!("✓ Started server {}", server.node_id);
        }

        // Step 3: Connect servers to each other
        info!("Step 3: Connecting servers to each other...");
        for server in servers.iter_mut() {
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

        // Finalize network: assign party IDs and recreate HB nodes
        for server in servers.iter_mut() {
            let pid = server.finalize_network().expect("Failed to finalize network");
            server.spawn_server_receive_loops();
            info!("✓ Server {} finalized with party_id={}", server.node_id, pid);
        }

        // Register client connections under logical IDs in each server's RoutedNetwork
        for server in servers.iter() {
            if let Some(ref routed) = server.routed_network {
                let all_clients = server
                    .network
                    .as_ref()
                    .expect("network should be set")
                    .get_all_client_connections();
                for (_, conn) in &all_clients {
                    routed.register_client(input_client_id, conn.clone());
                }
                info!(
                    "Server {} registered {} client connection(s) under logical ID {}",
                    server.node_id,
                    all_clients.len(),
                    input_client_id
                );
            }
        }

        // Spawn receive-loop tasks with updated nodes and routed networks
        for (i, server) in servers.iter().enumerate() {
            let mut node = server.node.clone();
            let network: Arc<RoutedNetwork> = server
                .routed_network
                .clone()
                .expect("routed_network should be set after finalize_network()");
            let open_message_router = server.open_message_router.clone();
            let mut rx = recv.remove(0);
            tokio::spawn(async move {
                while let Some((sender_id, raw_msg)) = rx.recv().await {
                    match open_message_router.try_handle_wire_message(sender_id, &raw_msg) {
                        Ok(true) => continue,
                        Err(e) => {
                            tracing::warn!("Node {i} failed to handle open wire message: {e}");
                            continue;
                        }
                        Ok(false) => {}
                    }
                    match open_message_router
                        .try_handle_hb_open_exp_wire_message(sender_id, &raw_msg)
                    {
                        Ok(true) => continue,
                        Err(e) => {
                            tracing::warn!("Node {i} failed to handle open_exp wire message: {e}");
                            continue;
                        }
                        Ok(false) => {}
                    }
                    if let Err(e) = node.process(sender_id, raw_msg, network.clone()).await {
                        tracing::error!("Node {i} failed to process message: {e:?}");
                    }
                }
                tracing::info!("Receiver task for node {i} ended");
            });
        }

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

        // Verify network connectivity
        info!("Verifying network connectivity...");
        for (i, server) in servers.iter().enumerate() {
            let network = server.network.as_ref().expect("network should be set");
            let parties = network.parties();
            info!("Server {} sees {} parties in network map", i, parties.len());
            for party in parties {
                info!("  - Party {} at {}", party.id(), party.address());
            }

            // Verify each server can resolve all other parties via sorted public keys
            for peer_id in 0..n_parties {
                match network.get_connection_by_party_id(peer_id) {
                    Some(conn) => {
                        info!(
                            "✓ Server {} can resolve peer {} at {}",
                            i,
                            peer_id,
                            conn.remote_address()
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

        // Step 6: Run preprocessing with timeout and detailed logging
        info!("Step 6: Running preprocessing on all servers...");
        info!(
            "Each server will generate {} triples and {} random shares",
            n_triples, n_random_shares
        );

        let preprocessing_timeout = Duration::from_secs(30);
        let _session_id = SessionId::new(
            ProtocolType::Ransha,
            SessionId::pack_slot24(0, 0, 0),
            instance_id as u32,
        );
        let preprocessing_handles: Vec<_> = servers
            .iter()
            .enumerate()
            .map(|(i, server)| {
                let mut node_arc = server.node.clone();
                let network_clone: Arc<RoutedNetwork> = server
                    .routed_network
                    .clone()
                    .expect("routed_network should be set after finalize_network()");

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
                .init(
                    input_client_id,
                    local_shares,
                    2,
                    server.routed_network.clone().expect("routed_network should be set"),
                )
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
            let net: Arc<RoutedNetwork> = servers[pid].routed_network.clone().expect("routed_network should be set");

            let (x_shares, y_shares) = {
                let input_store = node
                    .preprocess
                    .input
                    .wait_for_all_inputs(std::time::Duration::from_secs(30))
                    .await
                    .expect("Failed to get client inputs");
                let inputs = input_store.get(&input_client_id).unwrap();
                (
                    vec![inputs[0].clone(), inputs[1].clone()],
                    vec![inputs[0].clone(), inputs[1].clone()],
                )
            };

            let handle = tokio::spawn(async move {
                // mul() returns the result directly (via internal wait_for_result)
                let result = node
                    .mul(x_shares.clone(), y_shares.clone(), net.clone())
                    .await
                    .expect("mul failed");
                (pid, result)
            });
            handles.push(handle);
        }

        // Wait for all mul tasks to finish and collect results
        let mul_results: Vec<_> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.expect("task panicked"))
            .collect();
        tokio::time::sleep(Duration::from_millis(300)).await;

        //----------------------------------------VALIDATE VALUES----------------------------------------
        // Use the output client ID we defined earlier
        // Each server sends its output shares using the results from mul()
        for (i, server) in servers.iter().enumerate() {
            let net: Arc<RoutedNetwork> = server.routed_network.clone().expect("routed_network should be set");

            // Find the result for this party from the collected mul results
            let shares_mult_for_node = mul_results
                .iter()
                .find(|(pid, _)| *pid == i)
                .map(|(_, shares)| shares.clone())
                .expect(&format!("Result for party {} not found", i));

            assert_eq!(shares_mult_for_node.len(), no_of_multiplications);
            match server
                .node
                .output
                .init(
                    output_client_id,
                    shares_mult_for_node,
                    no_of_multiplications,
                    net.clone(),
                )
                .await
            {
                Ok(_) => {}
                Err(e) => eprintln!("Server init error: {e}"),
            }
        }
    }

    #[tokio::test]
    async fn test_client_input_only() {
        init_crypto_provider();
        setup_test_tracing();
        let _hb_itest_lock = acquire_hb_itest_lock().await;

        info!("=== Starting Preprocessing-Only Test ===");

        // Minimal configuration for faster debugging
        let n_parties = 5;
        let threshold = 1;
        let n_triples = 2 * threshold + 1; // Minimal number of triples
        let n_random_shares = 2 + 2 * n_triples; // Minimal random shares
        let instance_id = 99997;
        let base_port = 9220; // Unique port range for test_client_input_only
                              // Define client IDs before network setup (client IDs must be registered at setup time)
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
            Some(clientid.clone()),
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

        // Step 2: Start all servers (no receive handler spawn yet)
        info!("Step 2: Starting servers...");
        for server in servers.iter_mut() {
            server.start().await.expect("Failed to start server");
            info!("✓ Started server {}", server.node_id);
        }

        // Step 3: Connect servers to each other
        info!("Step 3: Connecting servers to each other...");
        for server in servers.iter_mut() {
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

        // Finalize network: assign party IDs and recreate HB nodes
        for server in servers.iter_mut() {
            let pid = server.finalize_network().expect("Failed to finalize network");
            server.spawn_server_receive_loops();
            info!("✓ Server {} finalized with party_id={}", server.node_id, pid);
        }

        // Register client connections under logical IDs in each server's RoutedNetwork
        for server in servers.iter() {
            if let Some(ref routed) = server.routed_network {
                let all_clients = server
                    .network
                    .as_ref()
                    .expect("network should be set")
                    .get_all_client_connections();
                // Register each client connection under both logical client IDs
                for (_, conn) in &all_clients {
                    for &cid in &clientid {
                        routed.register_client(cid, conn.clone());
                    }
                }
                info!(
                    "Server {} registered {} client connection(s) under logical IDs {:?}",
                    server.node_id,
                    all_clients.len(),
                    clientid
                );
            }
        }

        // Spawn receive-loop tasks with updated nodes and routed networks
        for (i, server) in servers.iter().enumerate() {
            let mut node = server.node.clone();
            let network: Arc<RoutedNetwork> = server
                .routed_network
                .clone()
                .expect("routed_network should be set after finalize_network()");
            let open_message_router = server.open_message_router.clone();
            let mut rx = recv.remove(0);
            tokio::spawn(async move {
                while let Some((sender_id, raw_msg)) = rx.recv().await {
                    match open_message_router.try_handle_wire_message(sender_id, &raw_msg) {
                        Ok(true) => continue,
                        Err(e) => {
                            tracing::warn!("Node {i} failed to handle open wire message: {e}");
                            continue;
                        }
                        Ok(false) => {}
                    }
                    match open_message_router
                        .try_handle_hb_open_exp_wire_message(sender_id, &raw_msg)
                    {
                        Ok(true) => continue,
                        Err(e) => {
                            tracing::warn!("Node {i} failed to handle open_exp wire message: {e}");
                            continue;
                        }
                        Ok(false) => {}
                    }
                    if let Err(e) = node.process(sender_id, raw_msg, network.clone()).await {
                        tracing::error!("Node {i} failed to process message: {e:?}");
                    }
                }
                tracing::info!("Receiver task for node {i} ended");
            });
        }

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

        // Verify network connectivity
        info!("Verifying network connectivity...");
        for (i, server) in servers.iter().enumerate() {
            let network = server.network.as_ref().expect("network should be set");
            let parties = network.parties();
            info!("Server {} sees {} parties in network map", i, parties.len());
            for party in parties {
                info!("  - Party {} at {}", party.id(), party.address());
            }

            // Verify each server can resolve all other parties via sorted public keys
            for peer_id in 0..n_parties {
                match network.get_connection_by_party_id(peer_id) {
                    Some(conn) => {
                        info!(
                            "✓ Server {} can resolve peer {} at {}",
                            i,
                            peer_id,
                            conn.remote_address()
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

        // Step 6: Run preprocessing with timeout and detailed logging
        info!("Step 6: Running preprocessing on all servers...");
        info!(
            "Each server will generate {} triples and {} random shares",
            n_triples, n_random_shares
        );

        let preprocessing_timeout = Duration::from_secs(30);
        let _session_id = SessionId::new(
            ProtocolType::Ransha,
            SessionId::pack_slot24(0, 0, 0),
            instance_id as u32,
        );
        let preprocessing_handles: Vec<_> = servers
            .iter()
            .enumerate()
            .map(|(i, server)| {
                let mut node_arc = server.node.clone();
                let network_clone: Arc<RoutedNetwork> = server
                    .routed_network
                    .clone()
                    .expect("routed_network should be set after finalize_network()");

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
                .init(
                    clientid[0],
                    local_shares,
                    2,
                    server.routed_network.clone().expect("routed_network should be set"),
                )
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
        let _hb_itest_lock = acquire_hb_itest_lock().await;

        info!("=== Starting Preprocessing-Only Test ===");

        // Minimal configuration for faster debugging
        let n_parties = 5;
        let threshold = 1;
        let n_triples = 3; // Minimal number of triples
        let n_random_shares = 6; // Minimal random shares
        let instance_id = 99996;
        let base_port = 9230; // Unique port range for test_preprocessing_only

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
            None, // Client IDs will be registered later
        )
        .await
        .expect("Failed to create servers");
        info!("✓ Created {} servers", servers.len());

        // Step 2: Start all servers
        info!("Step 2: Starting servers...");
        for server in servers.iter_mut() {
            server.start().await.expect("Failed to start server");
            info!("✓ Started server {}", server.node_id);
        }

        // Step 3: Connect servers to each other
        info!("Step 3: Connecting servers to each other...");
        for server in servers.iter_mut() {
            server
                .connect_to_peers()
                .await
                .expect("Failed to connect to peers");
            info!("✓ Server {} connected to peers", server.node_id);
        }

        tokio::time::sleep(Duration::from_millis(300)).await;

        // Finalize network: assign party IDs and recreate HB nodes
        for server in servers.iter_mut() {
            let pid = server.finalize_network().expect("Failed to finalize network");
            server.spawn_server_receive_loops();
            info!("✓ Server {} finalized with party_id={}", server.node_id, pid);
        }

        // Spawn receive-loop tasks with updated nodes and routed networks
        for (i, server) in servers.iter().enumerate() {
            let mut node = server.node.clone();
            let network: Arc<RoutedNetwork> = server
                .routed_network
                .clone()
                .expect("routed_network should be set after finalize_network()");
            let open_message_router = server.open_message_router.clone();
            let mut rx = recv.remove(0);
            tokio::spawn(async move {
                while let Some((sender_id, raw_msg)) = rx.recv().await {
                    match open_message_router.try_handle_wire_message(sender_id, &raw_msg) {
                        Ok(true) => continue,
                        Err(e) => {
                            tracing::warn!("Node {i} failed to handle open wire message: {e}");
                            continue;
                        }
                        Ok(false) => {}
                    }
                    match open_message_router
                        .try_handle_hb_open_exp_wire_message(sender_id, &raw_msg)
                    {
                        Ok(true) => continue,
                        Err(e) => {
                            tracing::warn!("Node {i} failed to handle open_exp wire message: {e}");
                            continue;
                        }
                        Ok(false) => {}
                    }
                    if let Err(e) = node.process(sender_id, raw_msg, network.clone()).await {
                        tracing::error!("Node {i} failed to process message: {e:?}");
                    }
                }
                tracing::info!("Receiver task for node {i} ended");
            });
        }

        // Step 4: Verify network connectivity with a simple ping-pong test
        info!("Step 4: Verifying network connectivity...");
        for (i, server) in servers.iter().enumerate() {
            let network = server.network.as_ref().expect("network should be set");
            let parties = network.parties();
            info!("Server {} sees {} parties in network map", i, parties.len());
            for party in parties {
                info!("  - Party {} at {}", party.id(), party.address());
            }

            // Verify each server can resolve all other parties via sorted public keys
            for peer_id in 0..n_parties {
                match network.get_connection_by_party_id(peer_id) {
                    Some(conn) => {
                        info!(
                            "✓ Server {} can resolve peer {} at {}",
                            i,
                            peer_id,
                            conn.remote_address()
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
        let _session_id = SessionId::new(
            ProtocolType::Ransha,
            SessionId::pack_slot24(0, 0, 0),
            instance_id as u32,
        );
        let preprocessing_handles: Vec<_> = servers
            .iter()
            .enumerate()
            .map(|(i, server)| {
                let mut node_arc = server.node.clone();
                let network_clone: Arc<RoutedNetwork> = server
                    .routed_network
                    .clone()
                    .expect("routed_network should be set after finalize_network()");

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
}
