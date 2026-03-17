//! End-to-end integration tests for the AVSS backend.
//!
//! These tests exercise the full AVSS flow over real QUIC networking:
//! 1. Stand up N AVSS nodes with QUIC transport (channel-based message routing)
//! 2. Exchange ECDH public keys between all parties
//! 3. Create AVSS engines and route AVSS messages via channels
//! 4. Run distributed key generation (AVSS share generation)
//! 5. Verify all parties agree on the same public key
//! 6. Wire the AVSS shares into VMs and extract the public key via builtins
//!
//! Uses the actor/channel pattern (like HoneyBadger) where accept loops and
//! outgoing connections both feed a `(PartyId, Vec<u8>)` channel. A message
//! processor reads from the channel and dispatches to the engine.

use ark_bls12_381::{Fr, G1Projective as G1};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::SeedableRng;
use ark_std::UniformRand;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use stoffel_vm_types::core_types::Value;
use stoffel_vm_types::functions::VMFunction;
use stoffel_vm_types::instructions::Instruction;
use stoffelnet::network_utils::{Network, Node};
use stoffelnet::transports::quic::{
    NetworkManager, PeerConnection as QuicPeerConnection, QuicNetworkManager,
};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::core_vm::VirtualMachine;
use crate::mpc_builtins::avss_object;
use crate::net::avss_engine::AvssMpcEngine;
use crate::tests::test_utils::{init_crypto_provider, setup_test_tracing};

// ---------------------------------------------------------------------------
// SimplePartyNetwork — party-id-based Network adapter
// ---------------------------------------------------------------------------

/// A minimal `Network` implementation that routes `send(party_id, msg)`
/// directly by party index, avoiding the QuicNetworkManager's sorted-public-key
/// routing which doesn't match AVSS party indices.
///
/// Connections are stored in a vector indexed by party_id (0..N-1).
struct SimplePartyNetwork {
    node_id: usize,
    n: usize,
    /// party_id → connection (index = party_id)
    connections: Vec<Option<Arc<dyn QuicPeerConnection>>>,
    /// Channel for self-delivery (when sending to our own party_id)
    self_tx: mpsc::Sender<(usize, Vec<u8>)>,
}

/// A trivial `Node` type for `SimplePartyNetwork`.
struct SimpleNode {
    id: usize,
}

impl stoffelnet::network_utils::Node for SimpleNode {
    fn id(&self) -> usize {
        self.id
    }
    fn scalar_id<F: ark_ff::Field>(&self) -> F {
        F::from((self.id + 1) as u64)
    }
}

/// Empty config type.
struct SimpleNetworkConfig;

#[async_trait::async_trait]
impl stoffelnet::network_utils::Network for SimplePartyNetwork {
    type NodeType = SimpleNode;
    type NetworkConfig = SimpleNetworkConfig;

    async fn send(
        &self,
        recipient: usize,
        message: &[u8],
    ) -> Result<usize, stoffelnet::network_utils::NetworkError> {
        // Self-delivery: route through the channel so our message processor picks it up
        if recipient == self.node_id {
            self.self_tx
                .send((self.node_id, message.to_vec()))
                .await
                .map_err(|_| stoffelnet::network_utils::NetworkError::SendError)?;
            return Ok(message.len());
        }
        let conn = self
            .connections
            .get(recipient)
            .and_then(|c| c.as_ref())
            .ok_or(stoffelnet::network_utils::NetworkError::PartyNotFound(
                recipient,
            ))?;
        conn.send(message)
            .await
            .map_err(|_| stoffelnet::network_utils::NetworkError::SendError)?;
        Ok(message.len())
    }

    async fn broadcast(
        &self,
        message: &[u8],
    ) -> Result<usize, stoffelnet::network_utils::NetworkError> {
        let mut total = 0;
        // Self-delivery for broadcast
        if self
            .self_tx
            .send((self.node_id, message.to_vec()))
            .await
            .is_ok()
        {
            total += message.len();
        }
        for (i, conn_opt) in self.connections.iter().enumerate() {
            if i == self.node_id {
                continue;
            }
            if let Some(conn) = conn_opt {
                if conn.send(message).await.is_ok() {
                    total += message.len();
                }
            }
        }
        Ok(total)
    }

    fn parties(&self) -> Vec<&Self::NodeType> {
        vec![]
    }
    fn parties_mut(&mut self) -> Vec<&mut Self::NodeType> {
        vec![]
    }
    fn config(&self) -> &Self::NetworkConfig {
        &SimpleNetworkConfig
    }
    fn node(&self, _id: usize) -> Option<&Self::NodeType> {
        None
    }
    fn node_mut(&mut self, _id: usize) -> Option<&mut Self::NodeType> {
        None
    }
    async fn send_to_client(
        &self,
        _client: usize,
        _message: &[u8],
    ) -> Result<usize, stoffelnet::network_utils::NetworkError> {
        Err(stoffelnet::network_utils::NetworkError::SendError)
    }
    fn clients(&self) -> Vec<usize> {
        vec![]
    }
    fn is_client_connected(&self, _client: usize) -> bool {
        false
    }
    fn local_party_id(&self) -> usize {
        self.node_id
    }
    fn party_count(&self) -> usize {
        self.n
    }
}

/// Build a `SimplePartyNetwork` for a given node from its dialer connections.
///
/// `node_id`: this party's id; `n`: total parties; `connections`: (peer_party_id, conn) pairs
/// obtained from `connect_as_server()` calls to known addresses.
fn build_simple_network(
    node_id: usize,
    n: usize,
    peer_connections: Vec<(usize, Arc<dyn QuicPeerConnection>)>,
    self_tx: mpsc::Sender<(usize, Vec<u8>)>,
) -> Arc<SimplePartyNetwork> {
    let mut conns: Vec<Option<Arc<dyn QuicPeerConnection>>> = vec![None; n];
    for (pid, conn) in peer_connections {
        conns[pid] = Some(conn);
    }
    Arc::new(SimplePartyNetwork {
        node_id,
        n,
        connections: conns,
        self_tx,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A test AVSS node that owns a network manager, channel, and ECDH keypair.
struct AvssTestNode {
    node_id: usize,
    network: Option<Arc<QuicNetworkManager>>,
    network_builder: Option<QuicNetworkManager>,
    rx: Option<mpsc::Receiver<(usize, Vec<u8>)>>,
    tx: mpsc::Sender<(usize, Vec<u8>)>,
    /// Simple party-id-based network for AVSS protocol messages
    simple_net: Option<Arc<SimplePartyNetwork>>,
    /// ECDH secret key for AVSS payload confidentiality
    sk_i: Fr,
    /// ECDH public key
    pk_i: G1,
}

impl AvssTestNode {
    fn new(node_id: usize, bind_addr: SocketAddr) -> Self {
        let (tx, rx) = mpsc::channel(1500);

        let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
        let sk_i = Fr::rand(&mut rng);
        let pk_i = G1::generator() * sk_i;

        let mut mgr = QuicNetworkManager::with_node_id(node_id);
        // listen is async but we're in a sync constructor — caller must await listen separately
        // Instead, return builder and let setup do listen
        mgr.add_node_with_party_id(node_id, bind_addr);

        Self {
            node_id,
            network: None,
            network_builder: Some(mgr),
            rx: Some(rx),
            tx,
            simple_net: None,
            sk_i,
            pk_i,
        }
    }
}

/// Set up N AVSS test nodes with QUIC networking and channel-based message routing.
///
/// Returns the started nodes with connections established and accept loops running.
async fn setup_avss_test_network(n: usize, base_port: u16) -> Result<Vec<AvssTestNode>, String> {
    let addresses: Vec<SocketAddr> = (0..n)
        .map(|i| {
            format!("127.0.0.1:{}", base_port + i as u16)
                .parse()
                .unwrap()
        })
        .collect();

    info!(
        "[AVSS-E2E] Setting up {} nodes on ports {}..{}",
        n,
        base_port,
        base_port + n as u16 - 1
    );

    // Step 1: Create nodes with listening endpoints
    let mut nodes = Vec::with_capacity(n);
    for i in 0..n {
        let mut node = AvssTestNode::new(i, addresses[i]);
        let mgr = node.network_builder.as_mut().unwrap();
        mgr.listen(addresses[i])
            .await
            .map_err(|e| format!("Node {} listen failed: {}", i, e))?;
        // Register all peers
        for j in 0..n {
            if j != i {
                mgr.add_node_with_party_id(j, addresses[j]);
            }
        }
        nodes.push(node);
    }

    // Step 2: Start — convert builders to Arc and spawn accept loops
    for node in &mut nodes {
        let mgr = node.network_builder.take().unwrap();
        let net = Arc::new(mgr);
        node.network = Some(net.clone());

        // Spawn accept loop
        let mut acceptor = (*net).clone();
        let node_id = node.node_id;
        let tx = node.tx.clone();
        tokio::spawn(async move {
            loop {
                match acceptor.accept().await {
                    Ok(connection) => {
                        let sender_id = connection
                            .remote_party_id()
                            .unwrap_or(crate::net::open_registry::UNKNOWN_SENDER_ID);
                        info!(
                            "[AVSS] Node {} accepted connection from {}",
                            node_id,
                            connection.remote_address()
                        );
                        let txx = tx.clone();
                        tokio::spawn(async move {
                            loop {
                                match connection.receive().await {
                                    Ok(data) => {
                                        if let Err(e) = txx.send((sender_id, data)).await {
                                            error!(
                                                "[AVSS] Node {} channel send error: {:?}",
                                                node_id, e
                                            );
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                        });
                    }
                    Err(e) => {
                        warn!("[AVSS] Node {} accept error: {}", node_id, e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });
    }

    // Step 3: Connect to all peers (dial outgoing) and capture connections
    // for building SimplePartyNetwork instances
    let mut all_peer_connections: Vec<Vec<(usize, Arc<dyn QuicPeerConnection>)>> =
        (0..n).map(|_| Vec::new()).collect();

    for idx in 0..n {
        let net = nodes[idx].network.as_ref().unwrap();
        let peers: Vec<(usize, SocketAddr)> = net
            .parties()
            .iter()
            .map(|p| (p.id(), p.address()))
            .collect();

        let mut dialer = (**net).clone();
        let node_id = nodes[idx].node_id;
        let tx = nodes[idx].tx.clone();

        for (peer_id, peer_addr) in peers {
            if peer_id == node_id {
                continue; // skip self
            }
            let mut retry_count = 0u32;
            loop {
                match dialer.connect_as_server(peer_addr).await {
                    Ok(connection) => {
                        info!(
                            "[AVSS] Node {} connected to peer {} at {}",
                            node_id, peer_id, peer_addr
                        );
                        // Save connection for SimplePartyNetwork
                        all_peer_connections[idx].push((peer_id, connection.clone()));
                        // Spawn receive handler that feeds the channel
                        let txx = tx.clone();
                        let pid = peer_id;
                        tokio::spawn(async move {
                            loop {
                                match connection.receive().await {
                                    Ok(data) => {
                                        if let Err(e) = txx.send((pid, data)).await {
                                            error!("[AVSS] Node channel send error: {:?}", e);
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                        });
                        break;
                    }
                    Err(e) => {
                        retry_count += 1;
                        if retry_count >= 10 {
                            warn!(
                                "[AVSS] Node {} failed to connect to peer {} after {} attempts: {}",
                                node_id, peer_id, retry_count, e
                            );
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }

    // Step 4: Build SimplePartyNetwork for each node (with self-delivery via channel)
    for idx in 0..n {
        let peer_conns = std::mem::take(&mut all_peer_connections[idx]);
        let self_tx = nodes[idx].tx.clone();
        nodes[idx].simple_net = Some(build_simple_network(idx, n, peer_conns, self_tx));
    }

    // Let connections stabilize
    tokio::time::sleep(Duration::from_millis(300)).await;

    Ok(nodes)
}

/// Exchange ECDH public keys between all nodes using the QUIC connections.
///
/// Each node broadcasts `[party_id: u32][pk_bytes]` via the network and
/// collects all public keys through the channel.
async fn exchange_ecdh_keys(nodes: &mut [AvssTestNode]) -> Result<Vec<Arc<Vec<G1>>>, String> {
    let n = nodes.len();

    // Each node sends its PK to all peers
    for node in nodes.iter() {
        let net = node.network.as_ref().unwrap();

        let mut pk_bytes = Vec::new();
        node.pk_i
            .serialize_compressed(&mut pk_bytes)
            .map_err(|e| format!("serialize PK: {:?}", e))?;

        // Envelope: [party_id: u32][pk_bytes]
        let mut envelope = Vec::with_capacity(4 + pk_bytes.len());
        envelope.extend_from_slice(&(node.node_id as u32).to_le_bytes());
        envelope.extend_from_slice(&pk_bytes);

        let connections = net.get_all_server_connections();
        for (peer_id, conn) in &connections {
            if *peer_id == node.node_id {
                continue;
            }
            if let Err(e) = conn.send(&envelope).await {
                warn!(
                    "[AVSS] Node {} failed to send PK to peer {}: {}",
                    node.node_id, peer_id, e
                );
            }
        }
    }

    // Collect PKs from channels
    let mut all_pk_maps = Vec::with_capacity(n);

    for node in nodes.iter_mut() {
        let mut pk_map = vec![G1::default(); n];
        pk_map[node.node_id] = node.pk_i;
        let mut received = 1usize;

        let rx = node.rx.as_mut().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);

        while received < n {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(format!(
                    "Node {} PK exchange timeout: {}/{}",
                    node.node_id, received, n
                ));
            }

            match tokio::time::timeout(remaining, rx.recv()).await {
                Ok(Some((_sender, data))) => {
                    if data.len() < 4 {
                        continue;
                    }
                    let sender_id =
                        u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
                    if sender_id >= n {
                        continue;
                    }
                    match G1::deserialize_compressed(&data[4..]) {
                        Ok(pk) => {
                            pk_map[sender_id] = pk;
                            received += 1;
                            info!(
                                "[AVSS] Node {} got PK from party {} ({}/{})",
                                node.node_id, sender_id, received, n
                            );
                        }
                        Err(e) => {
                            warn!("[AVSS] Failed to deserialize PK: {:?}", e);
                        }
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    return Err(format!(
                        "Node {} PK exchange timeout: {}/{}",
                        node.node_id, received, n
                    ));
                }
            }
        }

        all_pk_maps.push(Arc::new(pk_map));
    }

    Ok(all_pk_maps)
}

/// Spawn AVSS message processors that read from each node's channel and
/// dispatch to the engine's `process_wrapped_message_with_network`.
///
/// Messages on the wire are `AvssWrappedMessage` enums (not raw `AvssMessage`).
/// The engine handles both RBC protocol messages (SEND/ECHO/READY) and final
/// AVSS payloads. We pass a `SimplePartyNetwork` so that RBC responses
/// (ECHO/READY broadcasts, self-delivery) route correctly by party_id.
fn spawn_avss_message_processors(
    nodes: &mut [AvssTestNode],
    engines: &[Arc<AvssMpcEngine<Fr, G1>>],
) {
    for (i, node) in nodes.iter_mut().enumerate() {
        let rx = node.rx.take().unwrap();
        let engine = engines[i].clone();
        let simple_net = node.simple_net.clone().unwrap();
        let node_id = node.node_id;

        tokio::spawn(async move {
            let mut rx = rx;
            while let Some((sender_id, data)) = rx.recv().await {
                match crate::net::open_registry::try_handle_wire_message(sender_id, &data) {
                    Ok(true) => continue,
                    Err(e) => {
                        error!(
                            "[AVSS] Node {} failed to handle open wire message from {}: {}",
                            node_id, sender_id, e
                        );
                        continue;
                    }
                    Ok(false) => {}
                }
                match engine
                    .process_wrapped_message_with_network(sender_id, &data, simple_net.clone())
                    .await
                {
                    Ok(()) => {}
                    Err(e) => {
                        // May fail to deserialize non-AVSS messages (e.g. leftover PK data)
                        if !e.contains("deserialize") {
                            error!("[AVSS] Node {} process error: {}", node_id, e);
                        }
                    }
                }
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Test 1: Full AVSS distributed key generation over QUIC
// ---------------------------------------------------------------------------

/// End-to-end test: 5 parties run AVSS over real QUIC connections.
///
/// Party 0 acts as the dealer, initiating AVSS to generate a distributed key.
/// After the protocol completes, all parties must hold consistent Feldman shares
/// and agree on the same public key (commitment[0] = g^secret).
#[tokio::test(flavor = "multi_thread")]
async fn test_avss_e2e_distributed_key_generation() {
    init_crypto_provider();
    setup_test_tracing();
    info!("=== AVSS E2E: Distributed Key Generation ===");

    let n = 5;
    let t = 1;
    let instance_id = 800_000;
    let base_port = 12500;

    // Step 1: Setup QUIC network with channel routing
    info!("Step 1: Creating {} AVSS nodes with QUIC networking", n);
    let mut nodes = setup_avss_test_network(n, base_port)
        .await
        .expect("Failed to create AVSS network");

    // Step 2: Exchange ECDH public keys
    info!("Step 2: Exchanging ECDH public keys");
    let pk_maps = exchange_ecdh_keys(&mut nodes)
        .await
        .expect("PK exchange failed");
    info!("All {} parties exchanged ECDH public keys", n);

    // Step 3: Create AVSS engines
    info!("Step 3: Creating AVSS engines");
    let mut engines: Vec<Arc<AvssMpcEngine<Fr, G1>>> = Vec::with_capacity(n);
    for (i, node) in nodes.iter().enumerate() {
        let engine = AvssMpcEngine::new(
            instance_id,
            i,
            n,
            t,
            node.network.clone().unwrap(),
            node.sk_i,
            pk_maps[i].clone(),
        )
        .await
        .expect("Failed to create engine");
        engine.start_async().await.expect("Failed to start engine");
        engines.push(engine);
    }

    // Step 4: Spawn message processors
    info!("Step 4: Spawning AVSS message processors");
    spawn_avss_message_processors(&mut nodes, &engines);

    // Step 5: Party 0 initiates AVSS (distributed key generation)
    let key_name = "signing_key";
    info!("Step 5: Party 0 initiating AVSS for key '{}'", key_name);

    let simple_net_0 = nodes[0].simple_net.clone().unwrap();
    let share = engines[0]
        .generate_random_share_with_network(key_name, simple_net_0)
        .await
        .expect("Party 0 AVSS failed");
    info!(
        "Party 0 generated share with {} commitments",
        share.commitments.len()
    );

    // The dealer's public key (commitment[0])
    let dealer_pk = share.commitments[0];
    let mut dealer_pk_bytes = Vec::new();
    dealer_pk
        .serialize_compressed(&mut dealer_pk_bytes)
        .expect("Failed to serialize dealer PK");

    // Step 6: Verify all parties received their shares
    info!("Step 6: Verifying all parties received shares");
    let mut all_pks: Vec<Vec<u8>> = vec![dealer_pk_bytes.clone()];

    for i in 1..n {
        let party_share = engines[i]
            .await_received_share(key_name)
            .await
            .unwrap_or_else(|e| panic!("Party {} share not received: {}", i, e));
        let pk = party_share.commitments[0];
        let mut pk_bytes = Vec::new();
        pk.serialize_compressed(&mut pk_bytes)
            .expect("Failed to serialize PK");
        all_pks.push(pk_bytes);
        info!(
            "Party {} received share with {} commitments",
            i,
            party_share.commitments.len()
        );
    }

    // Step 7: Verify public key consistency
    info!("Step 7: Verifying public key consistency");
    for i in 1..n {
        assert_eq!(
            all_pks[0], all_pks[i],
            "Party 0 and party {} disagree on public key",
            i
        );
    }
    info!(
        "All {} parties agree on the same public key ({} bytes)",
        n,
        all_pks[0].len()
    );

    // Verify PK is not the identity element
    let identity = G1::default();
    let mut identity_bytes = Vec::new();
    identity
        .into_affine()
        .serialize_compressed(&mut identity_bytes)
        .expect("Failed to serialize identity");
    assert_ne!(
        all_pks[0], identity_bytes,
        "Public key must not be the identity"
    );

    info!("=== AVSS E2E: Distributed Key Generation PASSED ===");
}

// ---------------------------------------------------------------------------
// Test 2: DKG + VM public key extraction
// ---------------------------------------------------------------------------

/// End-to-end test: run AVSS over QUIC, then wire shares into VMs and
/// extract the public key using `Avss.get_commitment` with index 0.
///
/// This validates the full pipeline: network -> engine -> share -> VM -> result.
#[tokio::test(flavor = "multi_thread")]
async fn test_avss_e2e_vm_public_key_extraction() {
    init_crypto_provider();
    setup_test_tracing();
    info!("=== AVSS E2E: VM Public Key Extraction ===");

    let n = 5;
    let t = 1;
    let instance_id = 800_001;
    let base_port = 12600;

    // Setup network
    let mut nodes = setup_avss_test_network(n, base_port)
        .await
        .expect("Failed to create AVSS network");

    let pk_maps = exchange_ecdh_keys(&mut nodes)
        .await
        .expect("PK exchange failed");

    // Create engines
    let mut engines: Vec<Arc<AvssMpcEngine<Fr, G1>>> = Vec::with_capacity(n);
    for (i, node) in nodes.iter().enumerate() {
        let engine = AvssMpcEngine::new(
            instance_id,
            i,
            n,
            t,
            node.network.clone().unwrap(),
            node.sk_i,
            pk_maps[i].clone(),
        )
        .await
        .expect("Failed to create engine");
        engine.start_async().await.expect("start engine");
        engines.push(engine);
    }

    spawn_avss_message_processors(&mut nodes, &engines);

    // Party 0 deals
    let key_name = "vm_test_key";
    let simple_net_0 = nodes[0].simple_net.clone().unwrap();
    let share_party0 = engines[0]
        .generate_random_share_with_network(key_name, simple_net_0)
        .await
        .expect("Party 0 AVSS failed");

    let expected_pk = share_party0.commitments[0];
    let mut expected_pk_bytes = Vec::new();
    expected_pk
        .serialize_compressed(&mut expected_pk_bytes)
        .expect("Failed to serialize expected PK");

    // Collect shares from all parties
    info!("Collecting shares from all parties");
    let mut party_shares = vec![share_party0];
    for i in 1..n {
        let s = engines[i]
            .await_received_share(key_name)
            .await
            .unwrap_or_else(|e| panic!("Party {} share not received: {}", i, e));
        party_shares.push(s);
    }

    // Create a VM for each party, load the AVSS share, and extract the public key
    info!("Creating VMs and extracting public keys");
    let mut vm_results: Vec<Vec<u8>> = Vec::new();

    for (party_id, share) in party_shares.iter().enumerate() {
        let mut vm = VirtualMachine::new();

        // Serialize share data for the AVSS share object
        let mut share_bytes = Vec::new();
        share
            .feldmanshare
            .share
            .serialize_compressed(&mut share_bytes)
            .expect("Failed to serialize share value");

        let commitment_bytes: Vec<Vec<u8>> = share
            .commitments
            .iter()
            .map(|c| {
                let mut bytes = Vec::new();
                c.into_affine()
                    .serialize_compressed(&mut bytes)
                    .expect("Failed to serialize commitment");
                bytes
            })
            .collect();

        // Create the AVSS share object in the VM's object store
        let obj_id = avss_object::create_avss_share_object(
            &mut vm.state.object_store,
            key_name,
            share_bytes,
            commitment_bytes,
            party_id,
        )
        .unwrap();

        // Build a VM program that extracts the public key
        let main_fn = VMFunction::new(
            "main".to_string(),
            vec![],
            Vec::new(),
            None,
            4,
            vec![
                Instruction::LDI(0, Value::Object(obj_id)),
                Instruction::LDI(1, Value::I64(0)), // commitment index 0 = public key
                Instruction::PUSHARG(0),
                Instruction::PUSHARG(1),
                Instruction::CALL("Avss.get_commitment".to_string()),
                Instruction::RET(0),
            ],
            HashMap::new(),
        );

        vm.register_function(main_fn);
        let result = vm.execute("main").expect("VM execution failed");

        // Extract byte array from the VM result
        let pk_bytes = match result {
            Value::Array(arr_id) => {
                let arr = vm.state.object_store.get_array(arr_id).unwrap();
                let mut bytes = Vec::with_capacity(arr.length());
                for i in 0..arr.length() {
                    if let Some(Value::U8(b)) = arr.get(&Value::I64(i as i64)) {
                        bytes.push(*b);
                    }
                }
                bytes
            }
            other => panic!("Party {} VM returned unexpected: {:?}", party_id, other),
        };

        info!(
            "Party {} VM extracted public key ({} bytes)",
            party_id,
            pk_bytes.len()
        );
        vm_results.push(pk_bytes);
    }

    // Verify all VMs produced the same public key
    for i in 1..n {
        assert_eq!(
            vm_results[0], vm_results[i],
            "Party 0 and party {} VMs returned different public keys",
            i
        );
    }

    // Verify it matches the expected public key from the Feldman commitments
    assert_eq!(
        vm_results[0], expected_pk_bytes,
        "VM-extracted public key doesn't match Feldman commitment[0]"
    );

    info!(
        "All {} VMs produced identical, correct public key ({} bytes)",
        n,
        vm_results[0].len()
    );

    info!("=== AVSS E2E: VM Public Key Extraction PASSED ===");
}

// ---------------------------------------------------------------------------
// Test 3: Multiple DKG sessions over the same network
// ---------------------------------------------------------------------------

/// End-to-end test: generate two independent distributed keys over the same
/// QUIC network and verify they produce different public keys.
#[tokio::test(flavor = "multi_thread")]
async fn test_avss_e2e_multiple_keys() {
    init_crypto_provider();
    setup_test_tracing();
    info!("=== AVSS E2E: Multiple Key Generation ===");

    let n = 4;
    let t = 1;
    let instance_id = 800_002;
    let base_port = 12700;

    let mut nodes = setup_avss_test_network(n, base_port)
        .await
        .expect("Failed to create AVSS network");

    let pk_maps = exchange_ecdh_keys(&mut nodes)
        .await
        .expect("PK exchange failed");

    let mut engines: Vec<Arc<AvssMpcEngine<Fr, G1>>> = Vec::with_capacity(n);
    for (i, node) in nodes.iter().enumerate() {
        let engine = AvssMpcEngine::new(
            instance_id,
            i,
            n,
            t,
            node.network.clone().unwrap(),
            node.sk_i,
            pk_maps[i].clone(),
        )
        .await
        .expect("Failed to create engine");
        engine.start_async().await.expect("start engine");
        engines.push(engine);
    }

    spawn_avss_message_processors(&mut nodes, &engines);

    // Generate first key
    let key1 = "key_alpha";
    let simple_net_0 = nodes[0].simple_net.clone().unwrap();
    let share1 = engines[0]
        .generate_random_share_with_network(key1, simple_net_0.clone())
        .await
        .expect("Key 1 AVSS failed");
    let mut pk1_bytes = Vec::new();
    share1.commitments[0]
        .serialize_compressed(&mut pk1_bytes)
        .expect("serialize pk1");

    // Wait for all parties to receive key1
    for i in 1..n {
        engines[i]
            .await_received_share(key1)
            .await
            .unwrap_or_else(|e| panic!("Party {} didn't receive key1: {}", i, e));
    }

    // Generate second key
    let key2 = "key_beta";
    let share2 = engines[0]
        .generate_random_share_with_network(key2, simple_net_0)
        .await
        .expect("Key 2 AVSS failed");
    let mut pk2_bytes = Vec::new();
    share2.commitments[0]
        .serialize_compressed(&mut pk2_bytes)
        .expect("serialize pk2");

    // Wait for all parties to receive key2
    for i in 1..n {
        engines[i]
            .await_received_share(key2)
            .await
            .unwrap_or_else(|e| panic!("Party {} didn't receive key2: {}", i, e));
    }

    // Verify the two keys are different
    assert_ne!(
        pk1_bytes, pk2_bytes,
        "Two independent DKG runs must produce different public keys"
    );

    // Verify all parties agree on each key
    for i in 1..n {
        let s1 = engines[i].get_share(key1).await.unwrap();
        let mut b1 = Vec::new();
        s1.commitments[0]
            .serialize_compressed(&mut b1)
            .expect("serialize");
        assert_eq!(pk1_bytes, b1, "Party {} disagrees on key1", i);

        let s2 = engines[i].get_share(key2).await.unwrap();
        let mut b2 = Vec::new();
        s2.commitments[0]
            .serialize_compressed(&mut b2)
            .expect("serialize");
        assert_eq!(pk2_bytes, b2, "Party {} disagrees on key2", i);
    }

    info!(
        "Generated 2 independent keys, all {} parties agree on both",
        n
    );

    info!("=== AVSS E2E: Multiple Key Generation PASSED ===");
}
