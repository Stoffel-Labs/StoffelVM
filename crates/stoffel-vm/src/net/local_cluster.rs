//! In-process N-party AVSS cluster helpers for local tests, examples,
//! and fixture-driven demos.
//!
//! Extracts the setup pattern previously only available under
//! `crates/stoffel-vm/src/tests/avss_e2e_integration.rs` so that
//! downstream crates (notably `stoffel-adkg`'s `execute_local`) can
//! reuse it without duplicating ~300 lines of QUIC / ECDH plumbing.
//!
//! **Specialized for BLS12-381 in this revision.** Other curves go
//! through the same [`AvssMpcEngine`] generic but benefit from
//! per-curve witness helpers; generalizing this module to `(F, G)` is
//! a follow-up once a non-BLS consumer shows up.
//!
//! **Not for production.** No cert management, no multi-host
//! discovery, no graceful shutdown. Use the `AvssQuicServer` family
//! for real deployments.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ark_bls12_381::{Fr, G1Projective as G1};
use ark_ec::PrimeGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::SeedableRng;
use ark_std::UniformRand;
use stoffelnet::network_utils::{Network, Node, VerifiedOrdering};
use stoffelnet::transports::quic::{
    NetworkManager, PeerConnection as QuicPeerConnection, QuicNetworkManager,
};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::net::avss_engine::AvssMpcEngine;

// ---------------------------------------------------------------------------
// SimplePartyNetwork — party-id-based Network adapter
// ---------------------------------------------------------------------------

/// Party-id-keyed [`Network`] adapter used by AVSS message dispatch.
///
/// Backed by a flat `Vec<Option<Arc<dyn QuicPeerConnection>>>` indexed
/// by party_id, plus a self-delivery channel. Constructed by
/// [`LocalClusterNode::build_simple_network`]; handed to
/// [`AvssMpcEngine::process_wrapped_message_with_network`] and friends.
pub struct SimplePartyNetwork {
    node_id: usize,
    n: usize,
    connections: Vec<Option<Arc<dyn QuicPeerConnection>>>,
    self_tx: mpsc::Sender<(usize, Vec<u8>)>,
}

/// Minimal `Node` used by [`SimplePartyNetwork`]; `id()` returns the
/// party id directly, `scalar_id()` returns `Fr::from(id + 1)` for any
/// field.
pub struct SimpleNode {
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

/// Placeholder config expected by the `Network` trait.
pub struct SimpleNetworkConfig;

#[async_trait::async_trait]
impl Network for SimplePartyNetwork {
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

// ---------------------------------------------------------------------------
// LocalClusterNode — a single party's networking + ECDH state
// ---------------------------------------------------------------------------

/// One party's in-process state: QUIC manager, receive channel,
/// ECDH keypair, and (post-setup) the `SimplePartyNetwork` adapter.
pub struct LocalClusterNode {
    /// Sorted-key party id (populated after `assign_party_ids`).
    pub party_id: usize,
    /// Owned QUIC manager after [`build_local_cluster`] completes.
    pub network: Option<Arc<QuicNetworkManager>>,
    /// Builder-stage manager (consumed during setup).
    pub network_builder: Option<QuicNetworkManager>,
    /// Receive channel consumer half (taken by [`spawn_avss_message_processor`]).
    pub rx: Option<mpsc::Receiver<(usize, Vec<u8>)>>,
    /// Receive channel producer half — shared with accept / dial loops.
    pub tx: mpsc::Sender<(usize, Vec<u8>)>,
    /// Party-id-keyed network adapter populated in step 4 of setup.
    pub simple_net: Option<Arc<SimplePartyNetwork>>,
    /// AVSS ECDH secret.
    pub sk_i: Fr,
    /// AVSS ECDH public point (`g^{sk_i}`).
    pub pk_i: G1,
}

impl LocalClusterNode {
    /// Fresh node with a random ECDH keypair and a `QuicNetworkManager`
    /// pre-tagged with `node_id` (the logical index before sorted-key
    /// resolution).
    pub fn new(logical_id: usize) -> Self {
        let (tx, rx) = mpsc::channel(1500);
        let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
        let sk_i = Fr::rand(&mut rng);
        let pk_i = G1::generator() * sk_i;
        let mgr = QuicNetworkManager::with_node_id(logical_id);
        Self {
            party_id: logical_id,
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
// Setup
// ---------------------------------------------------------------------------

/// Build an N-party local cluster bound to `127.0.0.1:(base_port + i)`.
///
/// Mirrors the test setup from `crates/stoffel-vm/src/tests/
/// avss_e2e_integration.rs`: each node listens, dials every peer,
/// assigns sorted-key party IDs, and builds a `SimplePartyNetwork` for
/// downstream AVSS message dispatch. The returned nodes are ready for
/// [`exchange_ecdh_keys`] then [`AvssMpcEngine::new`].
pub async fn build_local_cluster(
    n: usize,
    base_port: u16,
) -> Result<Vec<LocalClusterNode>, String> {
    let addresses: Vec<SocketAddr> = (0..n)
        .map(|i| {
            format!("127.0.0.1:{}", base_port + i as u16)
                .parse()
                .unwrap()
        })
        .collect();

    info!(
        "[local-cluster] Setting up {n} nodes on ports {}..{}",
        base_port,
        base_port + n as u16 - 1
    );

    // Step 1: start listeners.
    let mut nodes: Vec<LocalClusterNode> = Vec::with_capacity(n);
    for i in 0..n {
        let mut node = LocalClusterNode::new(i);
        let mgr = node.network_builder.as_mut().unwrap();
        mgr.listen(addresses[i])
            .await
            .map_err(|e| format!("Node {i} listen failed: {e}"))?;
        nodes.push(node);
    }

    // Step 1b: TLS-derived ID peer registration.
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

    // Step 2: promote builders to Arc and spawn accept loops.
    for node in &mut nodes {
        let mgr = node.network_builder.take().unwrap();
        let net = Arc::new(mgr);
        node.network = Some(net.clone());
        let mut acceptor = (*net).clone();
        tokio::spawn(async move {
            loop {
                match acceptor.accept().await {
                    Ok(_) => {}
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });
    }

    // Step 3: dial peers.
    for idx in 0..n {
        let net = nodes[idx].network.as_ref().unwrap();
        let local_derived = derived_ids[idx];
        let peers: Vec<(usize, SocketAddr)> = net
            .parties()
            .iter()
            .map(|p| (p.id(), p.address()))
            .collect();
        let mut dialer = (**net).clone();
        for (peer_derived_id, peer_addr) in peers {
            if peer_derived_id == local_derived {
                continue;
            }
            let mut retry = 0u32;
            loop {
                match dialer.connect_as_server(peer_addr).await {
                    Ok(_) => break,
                    Err(e) => {
                        retry += 1;
                        if retry >= 10 {
                            warn!("[local-cluster] dial failed after {retry} retries: {e}");
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Step 3b: assign sorted-key party IDs.
    for node in &nodes {
        let net = node.network.as_ref().unwrap();
        let _ = net.assign_party_ids();
    }
    let party_ids: Vec<usize> = nodes
        .iter()
        .map(|n| {
            n.network
                .as_ref()
                .unwrap()
                .compute_local_party_id()
                .expect("compute_local_party_id")
        })
        .collect();

    // Step 4: build SimplePartyNetwork + spawn receive handlers on
    // canonical DashMap connections.
    for idx in 0..n {
        let net = nodes[idx].network.as_ref().unwrap();
        let local_pid = party_ids[idx];
        let tx = nodes[idx].tx.clone();
        let all_conns = net.get_all_server_connections();
        let mut peer_conns: Vec<(usize, Arc<dyn QuicPeerConnection>)> = Vec::new();
        for (did, conn) in all_conns {
            if did == net.local_derived_id() {
                continue;
            }
            let pid = conn
                .remote_party_id()
                .unwrap_or(*derived_to_logical.get(&did).unwrap_or(&did));
            if pid == local_pid {
                continue;
            }
            peer_conns.push((pid, conn.clone()));
            let txx = tx.clone();
            tokio::spawn(async move {
                loop {
                    match conn.receive().await {
                        Ok(data) => {
                            if txx.send((pid, data)).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
        let self_tx = nodes[idx].tx.clone();
        let mut conns: Vec<Option<Arc<dyn QuicPeerConnection>>> = vec![None; n];
        for (pid, conn) in peer_conns {
            conns[pid] = Some(conn);
        }
        nodes[idx].simple_net = Some(Arc::new(SimplePartyNetwork {
            node_id: local_pid,
            n,
            connections: conns,
            self_tx,
        }));
        nodes[idx].party_id = local_pid;
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    Ok(nodes)
}

/// Broadcast each party's AVSS ECDH public key and collect the full
/// `Arc<Vec<G1>>` pk-map per party (indexed by `party_id`).
pub async fn exchange_ecdh_keys(
    nodes: &mut [LocalClusterNode],
) -> Result<Vec<Arc<Vec<G1>>>, String> {
    let n = nodes.len();

    for node in nodes.iter() {
        let net = node.network.as_ref().unwrap();
        let mut pk_bytes = Vec::new();
        node.pk_i
            .serialize_compressed(&mut pk_bytes)
            .map_err(|e| format!("serialize pk: {e:?}"))?;
        let mut envelope = Vec::with_capacity(4 + pk_bytes.len());
        envelope.extend_from_slice(&(node.party_id as u32).to_le_bytes());
        envelope.extend_from_slice(&pk_bytes);

        let local_derived = net.local_derived_id();
        for (peer_did, conn) in &net.get_all_server_connections() {
            if *peer_did == local_derived {
                continue;
            }
            let _ = conn.send(&envelope).await;
        }
    }

    let mut all_pk_maps = Vec::with_capacity(n);
    for node in nodes.iter_mut() {
        let mut pk_map = vec![G1::default(); n];
        pk_map[node.party_id] = node.pk_i;
        let mut received = 1usize;

        let rx = node.rx.as_mut().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while received < n {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(format!(
                    "Node {} PK exchange timeout: {received}/{n}",
                    node.party_id
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
                    if let Ok(pk) = G1::deserialize_compressed(&data[4..]) {
                        pk_map[sender_id] = pk;
                        received += 1;
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    return Err(format!(
                        "Node {} PK exchange timeout: {received}/{n}",
                        node.party_id
                    ));
                }
            }
        }
        all_pk_maps.push(Arc::new(pk_map));
    }

    Ok(all_pk_maps)
}

/// Spawn one tokio task per node that drains `rx` and dispatches each
/// received `(sender_id, bytes)` pair through the party's
/// [`AvssMpcEngine`] + [`SimplePartyNetwork`].
pub fn spawn_avss_message_processors(
    nodes: &mut [LocalClusterNode],
    engines: &[Arc<AvssMpcEngine<Fr, G1>>],
) {
    for (i, node) in nodes.iter_mut().enumerate() {
        let rx = node.rx.take().expect("rx already taken");
        let engine = engines[i].clone();
        let simple_net = node.simple_net.clone().expect("simple_net unset");
        tokio::spawn(async move {
            let mut rx = rx;
            while let Some((sender_id, data)) = rx.recv().await {
                match crate::net::open_registry::try_handle_wire_message(sender_id, &data) {
                    Ok(true) => continue,
                    Err(_) => continue,
                    Ok(false) => {}
                }
                let _ = engine
                    .process_wrapped_message_with_network(sender_id, &data, simple_net.clone())
                    .await;
            }
        });
    }
}
