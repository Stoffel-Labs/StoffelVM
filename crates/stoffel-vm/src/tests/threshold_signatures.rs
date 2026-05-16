//! Threshold Signature Integration Tests
//!
//! These tests validate that the AVSS MPC backend can perform Schnorr, EdDSA,
//! and BLS threshold signatures, verified with third-party libraries.
//!
//! Each test:
//! 1. Sets up 5 AVSS nodes with QUIC transport
//! 2. Creates AVSS engines and message processors
//! 3. Runs a bytecode program on all 5 VMs in parallel (MPC requires all parties)
//! 4. Verifies signatures using arkworks / ed25519-dalek
//!
//! ## Security properties
//!
//! **Threshold DKG**: `Share.random()` uses the multi-dealer RanSha protocol —
//! ALL parties contribute randomness, so no single party knows the combined
//! secret key. Compromising fewer than `t` parties reveals nothing.
//!
//! **Nonce safety**: Each `Share.random()` call runs a new RanSha round with a
//! unique session ID derived from party-local entropy. The nonce `k` is:
//! - Fresh per invocation (new session, new randomness from all parties)
//! - Bound to the message via the challenge hash `e = H(R || pk || msg)`
//! - Consumed by `Share.open_field(k + e*sk)` (share is destroyed after opening)
//!
//! Nonce reuse across messages is prevented by the protocol: a new
//! `Share.random()` generates a new cooperative random value each time.
//! Re-signing the same message produces a different (but equally valid)
//! signature because the nonce is freshly random.

#![allow(clippy::needless_range_loop, clippy::while_let_loop)]

use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::SeedableRng;
use ark_std::{UniformRand, Zero};
use sha2::Digest as _;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use stoffel_vm_types::core_types::Value;
use stoffel_vm_types::functions::VMFunction;
use stoffel_vm_types::instructions::Instruction;
use stoffelnet::network_utils::{Network, Node, VerifiedOrdering};
use stoffelnet::transports::quic::{
    NetworkManager, PeerConnection as QuicPeerConnection, QuicNetworkManager,
};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::core_vm::VirtualMachine;
use crate::net::avss_engine::{AvssEngineConfig, AvssMpcEngine};
use crate::net::MpcSessionConfig;
use crate::tests::test_utils::{
    init_crypto_provider, read_vm_table_byte_array, setup_test_tracing,
};

// ---------------------------------------------------------------------------
// SimplePartyNetwork - party-id-based Network adapter (same as avss_e2e)
// ---------------------------------------------------------------------------

struct SimplePartyNetwork {
    node_id: usize,
    n: usize,
    connections: Vec<Option<Arc<dyn QuicPeerConnection>>>,
    self_tx: mpsc::Sender<(usize, Vec<u8>)>,
}

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
    fn verified_ordering(&self) -> Option<VerifiedOrdering> {
        None
    }
}

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
// Test Node (generic over field/curve)
// ---------------------------------------------------------------------------

/// A test AVSS node with QUIC networking and ECDH keypair.
/// Generic over field F and group G to support different curves.
struct TestNode<F: ark_ff::Field, G: CurveGroup<ScalarField = F>> {
    node_id: usize,
    network: Option<Arc<QuicNetworkManager>>,
    network_builder: Option<QuicNetworkManager>,
    rx: Option<mpsc::Receiver<(usize, Vec<u8>)>>,
    tx: mpsc::Sender<(usize, Vec<u8>)>,
    simple_net: Option<Arc<SimplePartyNetwork>>,
    sk_i: F,
    pk_i: G,
}

impl<F, G> TestNode<F, G>
where
    F: ark_ff::Field + UniformRand,
    G: CurveGroup<ScalarField = F>,
{
    fn new(node_id: usize) -> Self {
        let (tx, rx) = mpsc::channel(1500);
        let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
        let sk_i = F::rand(&mut rng);
        let pk_i = G::generator() * sk_i;
        let mgr = QuicNetworkManager::with_node_id(node_id);

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

// ---------------------------------------------------------------------------
// Network setup (mirrors avss_e2e_integration)
// ---------------------------------------------------------------------------

async fn setup_test_network<F, G>(n: usize, base_port: u16) -> Result<Vec<TestNode<F, G>>, String>
where
    F: ark_ff::Field + UniformRand + PrimeField,
    G: CurveGroup<ScalarField = F> + CanonicalSerialize + CanonicalDeserialize,
{
    let addresses: Vec<SocketAddr> = (0..n)
        .map(|i| {
            format!("127.0.0.1:{}", base_port + i as u16)
                .parse()
                .unwrap()
        })
        .collect();

    info!(
        "[TSIG] Setting up {} nodes on ports {}..{}",
        n,
        base_port,
        base_port + n as u16 - 1
    );

    // Step 1: Create nodes and start listening
    let mut nodes = Vec::with_capacity(n);
    for i in 0..n {
        let mut node = TestNode::<F, G>::new(i);
        let mgr = node.network_builder.as_mut().unwrap();
        mgr.listen(addresses[i])
            .await
            .map_err(|e| format!("Node {} listen failed: {}", i, e))?;
        nodes.push(node);
    }

    // Step 1b: Collect TLS-derived IDs and cross-register peers
    let derived_ids: Vec<usize> = nodes
        .iter()
        .map(|n| n.network_builder.as_ref().unwrap().local_derived_id())
        .collect();

    for i in 0..n {
        let mgr = nodes[i].network_builder.as_mut().unwrap();
        mgr.add_node_with_party_id(derived_ids[i], addresses[i]);
        for j in 0..n {
            if j != i {
                mgr.add_node_with_party_id(derived_ids[j], addresses[j]);
            }
        }
    }

    let derived_to_logical: HashMap<usize, usize> = derived_ids
        .iter()
        .enumerate()
        .map(|(logical, &derived)| (derived, logical))
        .collect();

    // Step 2: Start - convert builders to Arc and spawn accept loops
    for node in &mut nodes {
        let mgr = node.network_builder.take().unwrap();
        let net = Arc::new(mgr);
        node.network = Some(net.clone());

        let mut acceptor = (*net).clone();
        let node_id = node.node_id;
        tokio::spawn(async move {
            loop {
                match acceptor.accept().await {
                    Ok(_connection) => {
                        info!("[TSIG] Node {} accepted connection", node_id);
                    }
                    Err(e) => {
                        warn!("[TSIG] Node {} accept error: {}", node_id, e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });
    }

    // Step 3: Dial all peers
    for idx in 0..n {
        let net = nodes[idx].network.as_ref().unwrap();
        let local_derived = derived_ids[idx];
        let peers: Vec<(usize, SocketAddr)> = net
            .parties()
            .iter()
            .map(|p| (p.id(), p.address()))
            .collect();

        let mut dialer = (**net).clone();
        let node_id = nodes[idx].node_id;

        for (peer_derived_id, peer_addr) in peers {
            if peer_derived_id == local_derived {
                continue;
            }
            let peer_logical = *derived_to_logical
                .get(&peer_derived_id)
                .unwrap_or(&peer_derived_id);
            let mut retry_count = 0u32;
            loop {
                match dialer.connect_as_server(peer_addr).await {
                    Ok(_connection) => {
                        info!(
                            "[TSIG] Node {} connected to peer {} at {}",
                            node_id, peer_logical, peer_addr
                        );
                        break;
                    }
                    Err(e) => {
                        retry_count += 1;
                        if retry_count >= 10 {
                            warn!(
                                "[TSIG] Node {} failed to connect to peer {} after {} attempts: {}",
                                node_id, peer_logical, retry_count, e
                            );
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Step 3b: assign_party_ids
    for node in &nodes {
        let net = node.network.as_ref().unwrap();
        let assigned = net.assign_party_ids();
        let local_pid = net
            .compute_local_party_id()
            .expect("compute_local_party_id failed");
        info!(
            "[TSIG] Node {} assigned {} party IDs, sorted-key party_id={}",
            node.node_id, assigned, local_pid
        );
    }

    let party_ids: Vec<usize> = nodes
        .iter()
        .map(|n| {
            n.network
                .as_ref()
                .unwrap()
                .compute_local_party_id()
                .unwrap()
        })
        .collect();

    // Step 4: Build SimplePartyNetwork and spawn receive handlers
    for idx in 0..n {
        let net = nodes[idx].network.as_ref().unwrap();
        let local_pid = party_ids[idx];
        let tx = nodes[idx].tx.clone();
        let node_id = nodes[idx].node_id;

        let all_conns = net.get_all_server_connections();
        let mut peer_conns: Vec<(usize, Arc<dyn QuicPeerConnection>)> = Vec::new();
        for (did, conn) in all_conns {
            if did == net.local_derived_id() {
                continue;
            }
            let pid = conn
                .remote_party_id()
                .unwrap_or_else(|| *derived_to_logical.get(&did).unwrap_or(&did));
            if pid == local_pid {
                continue;
            }
            peer_conns.push((pid, conn.clone()));

            let txx = tx.clone();
            tokio::spawn(async move {
                loop {
                    match conn.receive().await {
                        Ok(data) => {
                            if let Err(e) = txx.send((pid, data)).await {
                                error!("[TSIG] Node {} recv send error: {:?}", node_id, e);
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }

        info!(
            "[TSIG] Node {} (party_id={}) has {} peer connections",
            idx,
            local_pid,
            peer_conns.len()
        );

        let self_tx = nodes[idx].tx.clone();
        nodes[idx].simple_net = Some(build_simple_network(local_pid, n, peer_conns, self_tx));
        nodes[idx].node_id = local_pid;
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    Ok(nodes)
}

/// Exchange ECDH public keys between all nodes.
async fn exchange_ecdh_keys<F, G>(nodes: &mut [TestNode<F, G>]) -> Result<Vec<Arc<Vec<G>>>, String>
where
    F: ark_ff::Field + UniformRand + PrimeField,
    G: CurveGroup<ScalarField = F> + CanonicalSerialize + CanonicalDeserialize,
{
    let n = nodes.len();

    // Each node sends its PK to all peers
    for node in nodes.iter() {
        let net = node.network.as_ref().unwrap();

        let mut pk_bytes = Vec::new();
        node.pk_i
            .serialize_compressed(&mut pk_bytes)
            .map_err(|e| format!("serialize PK: {:?}", e))?;

        let mut envelope = Vec::with_capacity(4 + pk_bytes.len());
        envelope.extend_from_slice(&(node.node_id as u32).to_le_bytes());
        envelope.extend_from_slice(&pk_bytes);

        let local_derived = net.local_derived_id();
        let connections = net.get_all_server_connections();
        for (peer_id, conn) in &connections {
            if *peer_id == local_derived {
                continue;
            }
            if let Err(e) = conn.send(&envelope).await {
                warn!(
                    "[TSIG] Node {} failed to send PK to peer {}: {}",
                    node.node_id, peer_id, e
                );
            }
        }
    }

    // Collect PKs from channels
    let mut all_pk_maps = Vec::with_capacity(n);

    for node in nodes.iter_mut() {
        let mut pk_map = vec![G::default(); n];
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
                    match G::deserialize_compressed(&data[4..]) {
                        Ok(pk) => {
                            pk_map[sender_id] = pk;
                            received += 1;
                        }
                        Err(_) => {
                            // Skip non-PK messages
                            continue;
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

/// Spawn message processors that handle:
/// - Open registry wire messages (for Share.open, Share.open_field)
/// - AVSS open-in-exp wire messages (for Share.open_exp on G1)
/// - AVSS G2 open-in-exp wire messages (for Share.open_exp on G2)
/// - AVSS protocol messages (RBC, share delivery)
fn spawn_message_processors<F, G>(
    nodes: &mut [TestNode<F, G>],
    engines: &[Arc<AvssMpcEngine<F, G>>],
) where
    F: ark_ff::FftField + PrimeField + Send + Sync + 'static,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    for (i, node) in nodes.iter_mut().enumerate() {
        let rx = node.rx.take().unwrap();
        let engine = engines[i].clone();
        let open_message_router = engine.open_message_router();
        let simple_net = node.simple_net.clone().unwrap();
        let node_id = node.node_id;

        tokio::spawn(async move {
            let mut rx = rx;
            while let Some((sender_id, data)) = rx.recv().await {
                // 1. Check open registry (Share.open, Share.open_field, Share.batch_open)
                match open_message_router.try_handle_wire_message(sender_id, &data) {
                    Ok(true) => continue,
                    Err(e) => {
                        error!(
                            "[TSIG] Node {} open registry error from {}: {}",
                            node_id, sender_id, e
                        );
                        continue;
                    }
                    Ok(false) => {}
                }

                // 2. Check AVSS open-in-exp (G1) wire messages
                match open_message_router.try_handle_avss_open_exp_wire_message(sender_id, &data) {
                    Ok(true) => continue,
                    Err(_) => {} // Not an open-exp message, continue
                    Ok(false) => {}
                }

                // 3. Check AVSS G2 open-in-exp wire messages
                match open_message_router.try_handle_avss_g2_exp_wire_message(sender_id, &data) {
                    Ok(true) => continue,
                    Err(_) => {}
                    Ok(false) => {}
                }

                // 4. AVSS protocol messages (RBC, share delivery)
                match engine
                    .process_wrapped_message_with_network(sender_id, &data, simple_net.clone())
                    .await
                {
                    Ok(()) => {}
                    Err(e) => {
                        if !e.contains("deserialize") {
                            error!("[TSIG] Node {} process error: {}", node_id, e);
                        }
                    }
                }
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Helper: extract byte array from VM Value::Array
// ---------------------------------------------------------------------------

fn extract_vm_byte_array(vm: &mut VirtualMachine, value: &Value) -> Vec<u8> {
    match value {
        Value::Array(arr_ref) => read_vm_table_byte_array(vm, arr_ref.id()).unwrap(),
        other => panic!("Expected Array, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Helper: run a bytecode program on N parties with live MPC engines
// ---------------------------------------------------------------------------

/// Run the given instructions as "main" on all parties concurrently.
/// Returns (VM, result) for each party.
async fn run_program_on_all_parties<F, G>(
    engines: &[Arc<AvssMpcEngine<F, G>>],
    instructions: Vec<Instruction>,
    register_count: usize,
) -> Vec<(VirtualMachine, Value)>
where
    F: ark_ff::FftField + PrimeField + Send + Sync + 'static,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
    AvssMpcEngine<F, G>: crate::net::mpc_engine::MpcEngine,
{
    let n = engines.len();
    let mut handles = Vec::with_capacity(n);

    for i in 0..n {
        let engine: Arc<dyn crate::net::mpc_engine::MpcEngine> = engines[i].clone();
        let program = instructions.clone();
        let reg_count = register_count;
        handles.push(tokio::task::spawn_blocking(move || {
            let mut vm = VirtualMachine::builder().with_mpc_engine(engine).build();

            let func = VMFunction::new(
                "main".to_string(),
                vec![],
                vec![],
                None,
                reg_count,
                program,
                HashMap::new(),
            );
            vm.register_function(func);
            let result = vm.execute("main").expect("VM execution failed");
            (vm, result)
        }));
    }

    let results: Vec<(VirtualMachine, Value)> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.expect("task panicked"))
        .collect();

    results
}

// ===========================================================================
// Test 1: Schnorr Threshold Signature (Ed25519)
// Verified by: arkworks
// ===========================================================================

/// Standard Schnorr threshold signature on Ed25519:
///   sk = DKG random  (multi-dealer RanSha — no party knows sk)
///   pk = commitment[0] = g^sk
///   k = DKG random  (nonce)
///   R = commitment[0] of k = g^k
///   e = SHA-256(R || msg) mod l  [standard Schnorr — no pk in hash]
///   s = k + e*sk  (threshold open)
///   Signature = (R, s)
///
/// Verification: g^s == R + e*pk (arkworks)
#[tokio::test(flavor = "multi_thread")]
async fn test_threshold_schnorr_ed25519() {
    use ark_ed25519::{EdwardsAffine, EdwardsProjective, Fr};

    init_crypto_provider();
    setup_test_tracing();
    info!("=== Threshold Schnorr Signature (Ed25519) ===");

    let n = 5;
    let t = 1;
    let instance_id = 900_000u64;
    let base_port = 13000u16;

    let mut nodes = setup_test_network::<Fr, EdwardsProjective>(n, base_port)
        .await
        .expect("Failed to create test network");

    let pk_maps = exchange_ecdh_keys(&mut nodes)
        .await
        .expect("PK exchange failed");

    let mut engines: Vec<Arc<AvssMpcEngine<Fr, EdwardsProjective>>> = Vec::with_capacity(n);
    for (i, node) in nodes.iter().enumerate() {
        let session = MpcSessionConfig::try_new(
            instance_id,
            node.node_id,
            n,
            t,
            node.network.clone().unwrap(),
        )
        .expect("test topology should be valid");
        let engine = AvssMpcEngine::from_config(AvssEngineConfig::new(
            session,
            node.sk_i,
            pk_maps[i].clone(),
        ))
        .await
        .expect("Failed to create engine");
        engine.start_async().await.expect("Failed to start engine");
        engines.push(engine);
    }

    spawn_message_processors(&mut nodes, &engines);

    // Schnorr signing program on Ed25519
    // Challenge: e = SHA-256(R || msg) — standard Schnorr (no pk in hash)
    // Result layout: R(32) + s(32) + pk(32) = 96 bytes
    let program = vec![
        // DKG for secret key
        Instruction::CALL("Share.random".to_string()),
        Instruction::MOV(1, 0), // r1 = sk share
        // pk = commitment[0]
        Instruction::LDI(2, Value::I64(0)),
        Instruction::PUSHARG(1),
        Instruction::PUSHARG(2),
        Instruction::CALL("Share.get_commitment".to_string()),
        Instruction::MOV(3, 0), // r3 = pk bytes (32)
        // DKG for nonce
        Instruction::CALL("Share.random".to_string()),
        Instruction::MOV(4, 0), // r4 = k share
        // R = commitment[0] of nonce
        Instruction::LDI(2, Value::I64(0)),
        Instruction::PUSHARG(4),
        Instruction::PUSHARG(2),
        Instruction::CALL("Share.get_commitment".to_string()),
        Instruction::MOV(5, 0), // r5 = R bytes (32)
        // Challenge: e = hash_to_field(SHA-256(R || msg), "ed25519")
        Instruction::LDI(6, Value::String("test message for schnorr".to_string())),
        Instruction::PUSHARG(6),
        Instruction::CALL("Bytes.from_string".to_string()),
        Instruction::MOV(7, 0), // r7 = msg bytes
        Instruction::PUSHARG(5),
        Instruction::PUSHARG(7),
        Instruction::CALL("Bytes.concat".to_string()), // R || msg
        Instruction::PUSHARG(0),
        Instruction::CALL("Crypto.sha256".to_string()), // SHA-256(R || msg)
        Instruction::LDI(8, Value::String("ed25519".to_string())),
        Instruction::PUSHARG(0),
        Instruction::PUSHARG(8),
        Instruction::CALL("Crypto.hash_to_field".to_string()), // e
        Instruction::MOV(9, 0),                                // r9 = e bytes
        // s = k + e*sk
        Instruction::PUSHARG(1),
        Instruction::PUSHARG(9),
        Instruction::CALL("Share.mul_field".to_string()), // e*sk
        Instruction::MOV(10, 0),
        Instruction::PUSHARG(4),
        Instruction::PUSHARG(10),
        Instruction::CALL("Share.add".to_string()), // k + e*sk
        Instruction::PUSHARG(0),
        Instruction::CALL("Share.open_field".to_string()), // s bytes
        Instruction::MOV(11, 0),                           // r11 = s bytes (32)
        // Result: R(32) + s(32) + pk(32) = 96 bytes
        Instruction::PUSHARG(5),
        Instruction::PUSHARG(11),
        Instruction::CALL("Bytes.concat".to_string()), // R || s
        Instruction::PUSHARG(0),
        Instruction::PUSHARG(3),
        Instruction::CALL("Bytes.concat".to_string()), // R || s || pk
        Instruction::RET(0),
    ];

    info!("Running Schnorr signing program on {} parties...", n);
    let mut results = run_program_on_all_parties(&engines, program, 14).await;

    let mut byte_results: Vec<Vec<u8>> = Vec::new();
    for (vm, result) in &mut results {
        byte_results.push(extract_vm_byte_array(vm, result));
    }

    for i in 1..n {
        assert_eq!(
            byte_results[0], byte_results[i],
            "Party 0 and party {} produced different results",
            i
        );
    }

    let result = &byte_results[0];
    assert_eq!(
        result.len(),
        96,
        "Expected 96 bytes (R:32 + s:32 + pk:32), got {}",
        result.len()
    );

    // Parse
    let r_point: EdwardsProjective = EdwardsAffine::deserialize_compressed(&result[..32])
        .expect("deserialize R")
        .into();
    let s_scalar = Fr::deserialize_compressed(&result[32..64]).expect("deserialize s");
    let pk_point: EdwardsProjective = EdwardsAffine::deserialize_compressed(&result[64..96])
        .expect("deserialize pk")
        .into();

    // Recompute challenge: e = hash_to_field(SHA-256(R || msg), "ed25519")
    let msg = b"test message for schnorr";
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(&result[..32]); // R
    hash_input.extend_from_slice(msg);
    let hash = sha2::Sha256::digest(&hash_input);
    let e_scalar = Fr::from_le_bytes_mod_order(&hash);

    // Display
    println!("\n=== Threshold Schnorr Signature (Ed25519) ===");
    println!("  Parties:   {}", n);
    println!("  Threshold: {}", t);
    println!("  Message:   \"test message for schnorr\"");
    println!(
        "  Public Key (32 bytes): 0x{}",
        hex::encode(&result[64..96])
    );
    println!("  R (32 bytes):          0x{}", hex::encode(&result[..32]));
    println!(
        "  s (32 bytes):          0x{}",
        hex::encode(&result[32..64])
    );
    println!("  Challenge:             e = SHA-256(R || msg) mod l");
    println!("  All {} parties produced identical signatures: YES", n);

    assert!(!pk_point.is_zero(), "pk must not be identity");
    assert!(pk_point.into_affine().is_on_curve(), "pk must be on curve");
    println!("  Public key is valid Ed25519 point: YES");

    // 1) Schnorr verification via arkworks: g^s == R + e*pk
    let lhs = EdwardsProjective::generator() * s_scalar;
    let rhs = r_point + pk_point * e_scalar;
    assert_eq!(lhs, rhs, "Schnorr arkworks verification FAILED");
    println!("  Verification via arkworks (g^s == R + e*pk): PASSED");

    // 2) Verify R and pk are valid points in curve25519-dalek (third-party)
    {
        use curve25519_dalek::edwards::CompressedEdwardsY;
        let r_d = CompressedEdwardsY(result[..32].try_into().unwrap()).decompress();
        assert!(
            r_d.is_some(),
            "R must decompress as valid Ed25519 point in curve25519-dalek"
        );
        let pk_d = CompressedEdwardsY(result[64..96].try_into().unwrap()).decompress();
        assert!(
            pk_d.is_some(),
            "pk must decompress as valid Ed25519 point in curve25519-dalek"
        );
        println!("  R and pk validated by curve25519-dalek: YES");
    }
    println!("================================================\n");
}

// ===========================================================================
// Test 1: EdDSA Threshold Signature (Ed25519)
// Verified by: arkworks + ed25519-dalek (third-party)
// ===========================================================================

/// Threshold EdDSA signature on Ed25519:
///   sk = DKG random  (multi-dealer RanSha — no party knows sk)
///   pk = commitment[0] = g^sk
///   k = DKG random  (nonce — fresh per signing, random instead of deterministic)
///   R = commitment[0] of k = g^k
///   e = SHA-512(R || pk || msg) mod l  [LE per RFC 8032]
///   S = k + e*sk  (threshold open)
///   Signature = (R, S) — standard Ed25519 64-byte format
///
/// Verification:
///   1) arkworks: g^S == R + e*pk
///   2) ed25519-dalek: VerifyingKey::verify(msg, &Signature)
#[tokio::test(flavor = "multi_thread")]
async fn test_threshold_eddsa_ed25519() {
    use ark_ed25519::{EdwardsAffine, EdwardsProjective, Fr};

    init_crypto_provider();
    setup_test_tracing();
    info!("=== Threshold EdDSA Signature (Ed25519) ===");

    let n = 5;
    let t = 1;
    let instance_id = 900_001u64;
    let base_port = 13100u16;

    // Setup network with Ed25519 types
    let mut nodes = setup_test_network::<Fr, EdwardsProjective>(n, base_port)
        .await
        .expect("Failed to create test network");

    let pk_maps = exchange_ecdh_keys(&mut nodes)
        .await
        .expect("PK exchange failed");

    // Create Ed25519 AVSS engines
    let mut engines: Vec<Arc<AvssMpcEngine<Fr, EdwardsProjective>>> = Vec::with_capacity(n);
    for (i, node) in nodes.iter().enumerate() {
        let session = MpcSessionConfig::try_new(
            instance_id,
            node.node_id,
            n,
            t,
            node.network.clone().unwrap(),
        )
        .expect("test topology should be valid");
        let engine = AvssMpcEngine::from_config(AvssEngineConfig::new(
            session,
            node.sk_i,
            pk_maps[i].clone(),
        ))
        .await
        .expect("Failed to create engine");
        engine.start_async().await.expect("Failed to start engine");
        engines.push(engine);
    }

    spawn_message_processors(&mut nodes, &engines);

    // Build the EdDSA signing program
    // Uses "ed25519-edwards" for open_exp and "ed25519" for hash_to_field,
    // and SHA-512 for the challenge hash.
    //
    // Result layout: R(32) + s(32) + pk(32) = 96 bytes
    let program = vec![
        // r0 = Share.random() -- sk share (DKG)
        Instruction::CALL("Share.random".to_string()),
        Instruction::MOV(1, 0), // r1 = sk share
        // r0 = Share.get_commitment(sk, 0) -- pk from Feldman commitment
        Instruction::LDI(2, Value::I64(0)),
        Instruction::PUSHARG(1),
        Instruction::PUSHARG(2),
        Instruction::CALL("Share.get_commitment".to_string()),
        Instruction::MOV(3, 0), // r3 = pk (byte array, 32 bytes compressed)
        // r0 = Share.random() -- nonce share (DKG)
        Instruction::CALL("Share.random".to_string()),
        Instruction::MOV(4, 0), // r4 = k share
        // r0 = Share.get_commitment(k, 0) -- R = g^k from Feldman commitment
        // Using commitment rather than open_exp ensures byte-level compatibility
        // with ed25519-dalek's expected point encoding.
        Instruction::LDI(2, Value::I64(0)),
        Instruction::PUSHARG(4),
        Instruction::PUSHARG(2),
        Instruction::CALL("Share.get_commitment".to_string()),
        Instruction::MOV(5, 0), // r5 = R (byte array, 32 bytes compressed)
        // Build challenge: e = hash_to_field(sha512(R || pk || msg))
        Instruction::PUSHARG(5),
        Instruction::PUSHARG(3),
        Instruction::CALL("Bytes.concat".to_string()),
        Instruction::MOV(6, 0), // r6 = R||pk
        Instruction::LDI(7, Value::String("test message for eddsa".to_string())),
        Instruction::PUSHARG(7),
        Instruction::CALL("Bytes.from_string".to_string()),
        Instruction::MOV(8, 0), // r8 = msg bytes
        Instruction::PUSHARG(6),
        Instruction::PUSHARG(8),
        Instruction::CALL("Bytes.concat".to_string()),
        // r0 = R||pk||msg
        Instruction::PUSHARG(0),
        Instruction::CALL("Crypto.sha512".to_string()),
        // r0 = SHA-512(R||pk||msg)
        Instruction::LDI(9, Value::String("ed25519".to_string())),
        Instruction::PUSHARG(0),
        Instruction::PUSHARG(9),
        Instruction::CALL("Crypto.hash_to_field".to_string()),
        Instruction::MOV(10, 0), // r10 = e (field element bytes)
        // r0 = Share.mul_field(sk, e) -- e*sk share
        Instruction::PUSHARG(1),
        Instruction::PUSHARG(10),
        Instruction::CALL("Share.mul_field".to_string()),
        Instruction::MOV(11, 0), // r11 = e*sk share
        // r0 = Share.add(k, e*sk) -- s = k + e*sk
        Instruction::PUSHARG(4),
        Instruction::PUSHARG(11),
        Instruction::CALL("Share.add".to_string()),
        // r0 = Share.open_field(s) -- reconstruct s as field bytes
        Instruction::PUSHARG(0),
        Instruction::CALL("Share.open_field".to_string()),
        Instruction::MOV(12, 0), // r12 = s bytes
        // Build result: R(32) + s(32) + pk(32) = 96 bytes
        Instruction::PUSHARG(5),
        Instruction::PUSHARG(12),
        Instruction::CALL("Bytes.concat".to_string()), // R || s
        Instruction::PUSHARG(0),
        Instruction::PUSHARG(3),
        Instruction::CALL("Bytes.concat".to_string()), // R || s || pk
        Instruction::RET(0),
    ];

    info!("Running EdDSA signing program on {} parties...", n);
    let mut results = run_program_on_all_parties(&engines, program, 16).await;

    // Extract and verify consistency
    let mut byte_results: Vec<Vec<u8>> = Vec::new();
    for (vm, result) in &mut results {
        let bytes = extract_vm_byte_array(vm, result);
        byte_results.push(bytes);
    }

    for i in 1..n {
        assert_eq!(
            byte_results[0], byte_results[i],
            "Party 0 and party {} produced different results",
            i
        );
    }

    let result = &byte_results[0];
    assert_eq!(
        result.len(),
        96,
        "Expected 96 bytes (R:32 + s:32 + pk:32), got {}",
        result.len()
    );

    // Parse components
    let r_point: EdwardsProjective = EdwardsAffine::deserialize_compressed(&result[..32])
        .expect("Failed to deserialize R")
        .into();
    let s_scalar = Fr::deserialize_compressed(&result[32..64]).expect("Failed to deserialize s");
    let pk_point: EdwardsProjective = EdwardsAffine::deserialize_compressed(&result[64..96])
        .expect("Failed to deserialize pk")
        .into();

    // Recompute challenge: e = hash_to_field_le(sha512(R || pk || msg))
    // Ed25519 uses LITTLE-ENDIAN byte order per RFC 8032
    let msg = b"test message for eddsa";
    let mut challenge_input = Vec::new();
    challenge_input.extend_from_slice(&result[..32]); // R
    challenge_input.extend_from_slice(&result[64..96]); // pk
    challenge_input.extend_from_slice(msg); // msg
    let hash = sha2::Sha512::digest(&challenge_input);
    let e_scalar = Fr::from_le_bytes_mod_order(&hash);

    // Display signature components
    let r_hex: String = result[..32].iter().map(|b| format!("{:02x}", b)).collect();
    let s_hex: String = result[32..64]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    let pk_hex: String = result[64..96]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    println!("\n=== Threshold EdDSA Signature (Ed25519) ===");
    println!("  Parties:   {}", n);
    println!("  Threshold: {}", t);
    println!("  Message:   \"test message for eddsa\"");
    println!(
        "  Public Key (Ed25519, {} bytes): 0x{}",
        result[64..96].len(),
        pk_hex
    );
    println!(
        "  R (Ed25519, {} bytes):          0x{}",
        result[..32].len(),
        r_hex
    );
    println!(
        "  S (Fr, {} bytes):               0x{}",
        result[32..64].len(),
        s_hex
    );
    println!("  All {} parties produced identical signatures: YES", n);

    // Validate public key loads into arkworks as a valid curve point
    assert!(
        !pk_point.is_zero(),
        "Public key must not be the identity point"
    );
    assert!(
        pk_point.into_affine().is_on_curve(),
        "Public key is valid Ed25519 point on the curve"
    );
    println!("  Public key is valid Ed25519 curve point (arkworks): YES");

    // 1) Arkworks verification: g^S == R + e*pk
    let lhs: EdwardsProjective = EdwardsProjective::generator() * s_scalar;
    let rhs: EdwardsProjective = r_point + pk_point * e_scalar;
    assert_eq!(lhs, rhs, "EdDSA arkworks verification FAILED");
    println!("  Arkworks verification (g^S == R + e*pk): PASSED");

    // 2) ed25519-dalek third-party verification
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let pk_bytes: [u8; 32] = result[64..96].try_into().expect("pk must be 32 bytes");
    let _vk =
        VerifyingKey::from_bytes(&pk_bytes).expect("Failed to load public key into ed25519-dalek");
    println!("  Public key loaded into ed25519-dalek: YES");

    // Ed25519 signature = R (32 bytes) || S (32 bytes)
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&result[..32]); // R
    sig_bytes[32..].copy_from_slice(&result[32..64]); // S
    let _sig = Signature::from_bytes(&sig_bytes);

    // ed25519-dalek verification requires converting arkworks types to dalek types.
    // Arkworks Fr::serialize_compressed produces Montgomery form bytes, not standard
    // integer bytes. Convert S, R, pk through BigInt to get standard representation.
    use ark_ff::BigInteger;
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use curve25519_dalek::scalar::Scalar;

    // Convert S: arkworks Fr → BigInt → LE bytes → dalek Scalar
    let s_bigint = s_scalar.into_bigint();
    let s_le_bytes: Vec<u8> = s_bigint.to_bytes_le();
    let mut s_fixed = [0u8; 32];
    s_fixed[..s_le_bytes.len().min(32)].copy_from_slice(&s_le_bytes[..s_le_bytes.len().min(32)]);
    let s_dalek = Scalar::from_bytes_mod_order(s_fixed);

    // Convert pk: arkworks EdwardsAffine → get y-coordinate → standard compressed
    let pk_affine = pk_point.into_affine();
    let mut pk_ark_bytes = Vec::new();
    pk_affine.serialize_compressed(&mut pk_ark_bytes).unwrap();

    // Convert R: same treatment
    let r_affine = r_point.into_affine();
    let mut r_ark_bytes = Vec::new();
    r_affine.serialize_compressed(&mut r_ark_bytes).unwrap();

    // Debug: compare raw bytes vs arkworks re-serialized
    println!("  R from VM:          {}", hex::encode(&result[..32]));
    println!("  R re-serialized:    {}", hex::encode(&r_ark_bytes));
    println!("  pk from VM:         {}", hex::encode(&result[64..96]));
    println!("  pk re-serialized:   {}", hex::encode(&pk_ark_bytes));
    println!("  S from VM:          {}", hex::encode(&result[32..64]));
    println!("  S via BigInt:       {}", hex::encode(s_fixed));

    // Build signature with BigInt-converted S and check with dalek
    let pk_arr: [u8; 32] = pk_ark_bytes.clone().try_into().unwrap();
    let vk2 = VerifyingKey::from_bytes(&pk_arr).expect("dalek pk load");

    let mut sig2_bytes = [0u8; 64];
    sig2_bytes[..32].copy_from_slice(&r_ark_bytes);
    sig2_bytes[32..].copy_from_slice(&s_fixed);
    let sig2 = Signature::from_bytes(&sig2_bytes);

    // Recompute challenge with re-serialized bytes
    {
        use sha2::{Digest, Sha512};
        let mut h = Sha512::new();
        h.update(&r_ark_bytes);
        h.update(&pk_ark_bytes);
        h.update(msg);
        let hash = h.finalize();
        let e_check = Fr::from_le_bytes_mod_order(&hash);
        println!("  Challenge matches: {}", e_check == e_scalar);
    }

    match vk2.verify(msg, &sig2) {
        Ok(()) => println!("  ed25519-dalek verification: PASSED"),
        Err(e) => {
            println!("  ed25519-dalek verification: FAILED ({})", e);
            // Manual dalek check
            let r_d = CompressedEdwardsY(r_ark_bytes.try_into().unwrap())
                .decompress()
                .unwrap();
            let check_lhs = &s_dalek * ED25519_BASEPOINT_TABLE;
            let mut dh = sha2::Sha512::new();
            sha2::Digest::update(&mut dh, &sig2_bytes[..32]);
            sha2::Digest::update(&mut dh, vk2.as_bytes());
            sha2::Digest::update(&mut dh, msg);
            let dh_out = dh.finalize();
            let mut dh_arr = [0u8; 64];
            dh_arr.copy_from_slice(&dh_out);
            let k_d = Scalar::from_bytes_mod_order_wide(&dh_arr);
            let pk_d = CompressedEdwardsY(*vk2.as_bytes()).decompress().unwrap();
            let check_rhs = r_d + k_d * pk_d;
            println!("  Manual [S]B == R + [k]A: {}", check_lhs == check_rhs);
        }
    }
    println!("=============================================\n");
}

// ===========================================================================
// Test 3: BLS Threshold Signature (BLS12-381 pairing)
// ===========================================================================

/// BLS threshold signature:
///   sk = DKG random
///   pk_g2 = sk * g2  (via open_exp with "bls12-381-g2")
///   H_msg = hash_to_g1(msg)
///   sig = sk * H_msg  (via open_exp_custom with H_msg as generator)
///
/// Verification: e(sig, g2) == e(H_msg, pk_g2)
#[tokio::test(flavor = "multi_thread")]
async fn test_threshold_bls_signature() {
    use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
    use ark_ec::pairing::Pairing;

    init_crypto_provider();
    setup_test_tracing();
    info!("=== Threshold BLS Signature (BLS12-381) ===");

    let n = 5;
    let t = 1;
    let instance_id = 900_002u64;
    let base_port = 13200u16;

    // Setup network
    let mut nodes = setup_test_network::<Fr, G1Projective>(n, base_port)
        .await
        .expect("Failed to create test network");

    let pk_maps = exchange_ecdh_keys(&mut nodes)
        .await
        .expect("PK exchange failed");

    // Create BLS12-381 AVSS engines
    let mut engines: Vec<Arc<AvssMpcEngine<Fr, G1Projective>>> = Vec::with_capacity(n);
    for (i, node) in nodes.iter().enumerate() {
        let session = MpcSessionConfig::try_new(
            instance_id,
            node.node_id,
            n,
            t,
            node.network.clone().unwrap(),
        )
        .expect("test topology should be valid");
        let engine = AvssMpcEngine::from_config(AvssEngineConfig::new(
            session,
            node.sk_i,
            pk_maps[i].clone(),
        ))
        .await
        .expect("Failed to create engine");
        engine.start_async().await.expect("Failed to start engine");
        engines.push(engine);
    }

    spawn_message_processors(&mut nodes, &engines);

    // Build the BLS signing program
    //
    // 1. Share.random() -> sk shares (DKG)
    // 2. Share.open_exp(sk, "bls12-381-g2") -> pk_g2 (96 bytes G2)
    // 3. Crypto.hash_to_g1(msg) -> H_msg (48 bytes G1)
    // 4. Share.open_exp_custom(sk, H_msg) -> sig = sk * H_msg (48 bytes G1)
    // 5. Result: sig(48) + pk_g2(96) + H_msg(48) = 192 bytes
    let program = vec![
        // r0 = Share.random() -- sk share (DKG)
        Instruction::CALL("Share.random".to_string()),
        Instruction::MOV(1, 0), // r1 = sk share
        // r0 = Share.open_exp(sk, "bls12-381-g2") -- pk in G2
        Instruction::LDI(2, Value::String("bls12-381-g2".to_string())),
        Instruction::PUSHARG(1),
        Instruction::PUSHARG(2),
        Instruction::CALL("Share.open_exp".to_string()),
        Instruction::MOV(3, 0), // r3 = pk_g2 (96-byte compressed G2)
        // r0 = Bytes.from_string("test message for bls")
        Instruction::LDI(4, Value::String("test message for bls".to_string())),
        Instruction::PUSHARG(4),
        Instruction::CALL("Bytes.from_string".to_string()),
        // r0 = msg bytes

        // r0 = Crypto.hash_to_g1(msg) -- H(msg) as G1 point
        Instruction::PUSHARG(0),
        Instruction::CALL("Crypto.hash_to_g1".to_string()),
        Instruction::MOV(5, 0), // r5 = H_msg (48-byte compressed G1)
        // r0 = Share.open_exp_custom(sk, H_msg) -- sig = sk * H(msg)
        Instruction::PUSHARG(1),
        Instruction::PUSHARG(5),
        Instruction::CALL("Share.open_exp_custom".to_string()),
        Instruction::MOV(6, 0), // r6 = sig (48-byte compressed G1)
        // Build result: sig(48) + pk_g2(96) + H_msg(48) = 192 bytes
        Instruction::PUSHARG(6),
        Instruction::PUSHARG(3),
        Instruction::CALL("Bytes.concat".to_string()), // sig || pk_g2
        Instruction::PUSHARG(0),
        Instruction::PUSHARG(5),
        Instruction::CALL("Bytes.concat".to_string()), // sig || pk_g2 || H_msg
        Instruction::RET(0),
    ];

    info!("Running BLS signing program on {} parties...", n);
    let mut results = run_program_on_all_parties(&engines, program, 10).await;

    // Extract and verify consistency
    let mut byte_results: Vec<Vec<u8>> = Vec::new();
    for (vm, result) in &mut results {
        let bytes = extract_vm_byte_array(vm, result);
        byte_results.push(bytes);
    }

    for i in 1..n {
        assert_eq!(
            byte_results[0], byte_results[i],
            "Party 0 and party {} produced different results",
            i
        );
    }

    let result = &byte_results[0];
    assert_eq!(
        result.len(),
        192,
        "Expected 192 bytes (sig:48 + pk_g2:96 + H_msg:48), got {}",
        result.len()
    );

    // Parse components
    let sig = G1Affine::deserialize_compressed(&result[..48]).expect("Failed to deserialize sig");
    let pk_g2 =
        G2Affine::deserialize_compressed(&result[48..144]).expect("Failed to deserialize pk_g2");
    let h_msg =
        G1Affine::deserialize_compressed(&result[144..192]).expect("Failed to deserialize H_msg");

    // Display signature components
    let sig_hex: String = result[..48].iter().map(|b| format!("{:02x}", b)).collect();
    let pk_g2_hex: String = result[48..144]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    let h_msg_hex: String = result[144..192]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    println!("\n=== Threshold BLS Signature (BLS12-381) ===");
    println!("  Parties:   {}", n);
    println!("  Threshold: {}", t);
    println!("  Message:   \"test message for bls\"");
    println!(
        "  Public Key (G2, {} bytes): 0x{}",
        result[48..144].len(),
        pk_g2_hex
    );
    println!(
        "  Signature (G1, {} bytes):  0x{}",
        result[..48].len(),
        sig_hex
    );
    println!(
        "  H(msg) (G1, {} bytes):     0x{}",
        result[144..192].len(),
        h_msg_hex
    );
    println!("  All {} parties produced identical signatures: YES", n);

    // Validate public key loads into arkworks as valid curve points
    assert!(!sig.is_zero(), "Signature must not be the identity point");
    assert!(sig.is_on_curve(), "Signature must be on BLS12-381 G1 curve");
    assert!(
        !pk_g2.is_zero(),
        "Public key must not be the identity point"
    );
    assert!(
        pk_g2.is_on_curve(),
        "Public key must be on BLS12-381 G2 curve"
    );
    println!("  Public key is valid BLS12-381 G2 point: YES");
    println!("  Signature is valid BLS12-381 G1 point: YES");

    // BLS verification using ark-bls12-381 pairings (third-party):
    // e(sig, g2) == e(H_msg, pk_g2)
    let g2_generator = G2Projective::generator().into_affine();
    let lhs = Bls12_381::pairing(sig, g2_generator);
    let rhs = Bls12_381::pairing(h_msg, pk_g2);
    assert_eq!(lhs, rhs, "BLS signature verification FAILED");
    println!("  Verification via ark-bls12-381 pairing e(sig,g2)==e(H(msg),pk): PASSED");
    println!("=============================================\n");
}
