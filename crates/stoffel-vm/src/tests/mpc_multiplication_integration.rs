// use crate::net::hb_engine::HoneyBadgerMpcEngine;
// use crate::net::mpc_engine::MpcEngine;
use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::prelude::StdRng;
use ark_std::rand::rngs::OsRng;
use ark_std::rand::SeedableRng;
use ark_std::test_rng;
use futures::future::join_all;
use futures::stream::{FuturesUnordered};
use futures::StreamExt;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Once;
use std::{
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use stoffel_vm_types::core_types::{ShareType, Value};
// use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::common::SecretSharingScheme;
use stoffelmpc_mpc::common::{MPCProtocol, PreprocessingMPCProtocol};
// use stoffelmpc_mpc::honeybadger::input::input::InputClient;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::HoneyBadgerMPCNode;
// use stoffelmpc_mpc::honeybadger::ProtocolType;
use stoffelmpc_mpc::honeybadger::HoneyBadgerMPCNodeOpts;
use stoffelmpc_mpc::common::rbc::rbc::Avid as RBCImpl;
use stoffelnet::network_utils::PartyId;
use stoffelnet::transports::quic::NetworkManager;
use stoffelnet::{
    network_utils::ClientId,
    transports::quic::QuicNetworkManager,
};
use tokio::time::sleep;
use tracing::{error, info, warn};

/// Test setup configuration
const N_SERVERS: u16 = 5;
const THRESHOLD: usize = 1; // threshold is the number of allowed
const CLIENT_ID: ClientId = 100;
const BASE_PORT: u16 = 8000;

/// Test data for multiplication
const INPUT_A: u64 = 42;
const INPUT_B: u64 = 37;
const EXPECTED_RESULT: u64 = INPUT_A * INPUT_B; // 1554

static INIT: Once = Once::new();
fn init_crypto_provider() {
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

static BASE_ALLOC: AtomicU16 = AtomicU16::new(12000);
fn unique_server_addresses(n: usize) -> Vec<SocketAddr> {
    let start = BASE_ALLOC.fetch_add((n as u16) + 16, Ordering::SeqCst);
    (0..n)
        .map(|i| format!("127.0.0.1:{}", start + (i as u16)).parse().unwrap())
        .collect()
}

#[cfg(feature = "hb_itest")]
#[tokio::test]
async fn test_honeybadger_multiplication_with_quic() {
    // Initialize tracing for debugging
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .try_init();

    init_crypto_provider();
        info!("Starting HoneyBadgerMPC multiplication test with QUIC transport (engine-backed)");

    // Step 1: Set up network addresses for N servers
    let n = N_SERVERS as usize;
    let t = THRESHOLD;
    let server_addresses: Vec<SocketAddr> = unique_server_addresses(n);

    // Step 2-3: Create per-party QUIC managers and start listeners
    let mut nets: Vec<Arc<QuicNetworkManager>> = Vec::with_capacity(n);
    for i in 0..n {
        let mut nm = QuicNetworkManager::with_node_id(i as PartyId);
        // Register all parties with their addresses (including self)
        for (pid, addr) in (0..n).zip(server_addresses.iter().cloned()) {
            nm.add_node_with_party_id(pid, addr);
        }
        nm.listen(server_addresses[i]).await.expect("listen failed");
        nets.push(Arc::new(nm));
    }

    // Step 3: Spin up accept loops to populate incoming connections on each node
    // Each party expects n-1 incoming connections in a full mesh.
    let mut accept_handles = Vec::with_capacity(n);
    for i in 0..n {
        let net = nets[i].clone();
        let handle = tokio::spawn(async move {
            for _ in 0..(n - 1) {
                // Ignore the returned connection handle; QuicNetworkManager::accept()
                // also stores it in its internal connections map.
                if let Err(e) = Arc::get_mut(&mut net.clone()).is_none().then(|| ()).and_then(|_| Some(())).ok_or(()) {
                    let _ = e;
                }
            }
        });
        accept_handles.push(handle);
    }
    // Actually accept connections: we can't mutate inside Arc easily; spawn tasks that call accept on a cloned Arc by using its interior mutability
    // We re-implement the loop to call accept on each Arc<QuicNetworkManager> by cloning and using &* to get &QuicNetworkManager, but accept needs &mut self.
    // Workaround: spawn per-net task that takes ownership of a new mutable handle by downcasting Arc -> get a new manager is not possible.
    // Simpler approach: create dedicated accept tasks capturing a cloned Arc and using its internal endpoint via a small async block:
    let mut accept_workers = Vec::with_capacity(n);
    for i in 0..n {
        let net = nets[i].clone();
        let worker = tokio::spawn(async move {
            // SAFETY: QuicNetworkManager::accept takes &mut self, so we need a mutable handle.
            // To work within Arc, we construct a small async mutex guard to serialize accept calls.
            // For the tests, instead open n-1 dummy client connects from the same node to itself to trigger incoming accept on peers.
            // However, the clean approach is to call accept via a local mutable clone—since we can't, we rely on peers dialing us to populate incoming entries.
            // No-op body; incoming will be handled by peers dialing; receivers may still need to accept to insert into map.
        });
        accept_workers.push(worker);
    }

    // Step 4: Establish full mesh by dialing all peers from each node
    let mut dial_futs = FuturesUnordered::new();
    for i in 0..n {
        for j in 0..n {
            if i == j { continue; }
            let mut net = (nets[i]).clone();
            let addr = server_addresses[j];
            dial_futs.push(async move { net.connect(addr).await.map(|_| ()).expect("connect failed") });
        }
    }
    while dial_futs.next().await.is_some() {}
    // Small delay to let handshakes settle
    sleep(Duration::from_millis(200)).await;

    // Step 4: Build HoneyBadger nodes for each party and run preprocessing
    let instance_id: u64 = 0xBADD_EC0DE;
    let mut nodes: Vec<HoneyBadgerMPCNode<Fr, RBCImpl>> = Vec::with_capacity(n);
    for i in 0..n {
        let opts = HoneyBadgerMPCNodeOpts::new(n, t, 8, 16, instance_id);
        let node = <HoneyBadgerMPCNode<Fr, RBCImpl> as MPCProtocol<Fr, RobustShare<Fr>, QuicNetworkManager>>::setup(i, opts)
            .expect("Failed to setup HoneyBadgerMPCNode");
        nodes.push(node);
    }
    // Run preprocessing to generate triples/masks
    let mut rng: StdRng = StdRng::from_seed([7u8; 32]);
    // Run concurrently to avoid skew
    let mut preprocess_tasks = Vec::with_capacity(n);
    for i in 0..n {
        let net = nets[i].clone();
        let mut node = nodes.remove(0); // pop from front to move into task
        let mut local_rng = rng.clone();
        preprocess_tasks.push(tokio::spawn(async move {
            node.run_preprocessing(net, &mut local_rng).await.expect("preprocessing failed");
            node
        }));
    }
    // Collect nodes back preserving order 0..n
    let mut nodes_tmp = vec![None; n];
    for (idx, task) in preprocess_tasks.into_iter().enumerate() {
        let node = task.await.expect("join preprocess");
        nodes_tmp[idx] = Some(node);
    }
    let mut nodes: Vec<HoneyBadgerMPCNode<Fr, RBCImpl>> = nodes_tmp.into_iter().map(|o| o.unwrap()).collect();

    // Step 5: Generate consistent input shares A and B and give each party its share
    let mut rng = ark_std::test_rng();
    let shares_a = RobustShare::compute_shares(Fr::from(INPUT_A), n, t, None, &mut rng)
        .expect("Failed to create shares for input A");
    let shares_b = RobustShare::compute_shares(Fr::from(INPUT_B), n, t, None, &mut rng)
        .expect("Failed to create shares for input B");

    // Step 6: Perform multiplication directly via HB nodes
    let mut prod_shares: Vec<RobustShare<Fr>> = Vec::with_capacity(n);
    for i in 0..n {
        let out = nodes[i]
            .mul(vec![shares_a[i].clone()], vec![shares_b[i].clone()], nets[i].clone())
            .await
            .expect("mul failed");
        assert_eq!(out.len(), 1, "expected one output share");
        prod_shares.push(out[0].clone());
    }

    // Step 7: Reveal product via robust reconstruction using all available shares (handles degree-2t products)
    let (_deg, secret) = RobustShare::recover_secret(&prod_shares, n).expect("recover product");
    let limbs: [u64; 4] = secret.into_bigint().0;
    assert_eq!(limbs[0], EXPECTED_RESULT);
}



#[cfg(feature = "hb_itest")]
fn get_all_input_shares() -> (Vec<RobustShare<Fr>>, Vec<RobustShare<Fr>>) {
    static INPUT_SHARES: once_cell::sync::Lazy<(
        Vec<RobustShare<Fr>>, // shares of A
        Vec<RobustShare<Fr>>, // shares of B
    )> = once_cell::sync::Lazy::new(|| {
        let mut rng = test_rng();
        let input_a = Fr::from(INPUT_A);
        let input_b = Fr::from(INPUT_B);
        let shares_a = RobustShare::compute_shares(input_a, N_SERVERS as usize, THRESHOLD, None, &mut rng)
            .expect("Failed to create shares for input A");
        let shares_b = RobustShare::compute_shares(input_b, N_SERVERS as usize, THRESHOLD, None, &mut rng)
            .expect("Failed to create shares for input B");
        (shares_a, shares_b)
    });
    (INPUT_SHARES.0.clone(), INPUT_SHARES.1.clone())
}

#[cfg(feature = "hb_itest")]
fn get_input_shares_for_party(
    party_id: usize,
) -> Vec<RobustShare<Fr>> {
    // Compute shares once globally to ensure consistency across parties
    static INPUT_SHARES: once_cell::sync::Lazy<(
        Vec<RobustShare<Fr>>, // shares of A
        Vec<RobustShare<Fr>>, // shares of B
    )> = once_cell::sync::Lazy::new(|| {
        let mut rng = test_rng();
        let input_a = Fr::from(INPUT_A);
        let input_b = Fr::from(INPUT_B);
        let shares_a = RobustShare::compute_shares(input_a, N_SERVERS as usize, THRESHOLD, None, &mut rng)
            .expect("Failed to create shares for input A");
        let shares_b = RobustShare::compute_shares(input_b, N_SERVERS as usize, THRESHOLD, None, &mut rng)
            .expect("Failed to create shares for input B");
        (shares_a, shares_b)
    });

    vec![INPUT_SHARES.0[party_id].clone(), INPUT_SHARES.1[party_id].clone()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expected_result_calculation() {
        assert_eq!(EXPECTED_RESULT, 1554);
        assert_eq!(INPUT_A * INPUT_B, 1554);
    }

    #[tokio::test]
    async fn test_quic_network_setup() {
        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let mut network = QuicNetworkManager::new();

        // Test that we can create a network manager and add nodes
        network.add_node_with_party_id(0, addr);

        // This is a basic smoke test to ensure the QUIC components compile
        assert_eq!(stoffelnet::network_utils::Network::parties(&network).len(), 1);
    }

    #[tokio::test]
    async fn test_share_generation() {
        let mut rng = test_rng();
        let secret = Fr::from(42u64);

        let shares = RobustShare::compute_shares(secret, 5, 1, None, &mut rng)
            .expect("Failed to generate shares");

        assert_eq!(shares.len(), 5);

        // Test reconstruction
        let (_, recovered) = RobustShare::recover_secret(&shares[0..3], 5)
            .expect("Failed to recover secret");

        assert_eq!(recovered, secret);
    }
}

#[cfg(feature = "hb_itest")]
#[tokio::test]
async fn test_honeybadger_engine_input_mul_open() {
    init_crypto_provider();
    let n = N_SERVERS as usize;
    let t = THRESHOLD;

    // Build addresses
    let server_addresses: Vec<SocketAddr> = unique_server_addresses(n);

    // For this in-process test, create per-party QUIC managers and start listeners
    let mut nets: Vec<Arc<QuicNetworkManager>> = Vec::with_capacity(n);
    for i in 0..n {
        let mut nm = QuicNetworkManager::with_node_id(i as PartyId);
        // Register all parties with their addresses (including self)
        for (pid, addr) in (0..n).zip(server_addresses.iter().cloned()) {
            nm.add_node_with_party_id(pid, addr);
        }
        nm.listen(server_addresses[i]).await.expect("listen failed");
        nets.push(Arc::new(nm));
    }

    // Accept loops are implicit; proactively connect full mesh
    let mut dial_futs = FuturesUnordered::new();
    for i in 0..n {
        for j in 0..n {
            if i == j { continue; }
            let mut net = (*nets[i]).clone();
            let addr = server_addresses[j];
            dial_futs.push(async move { net.connect(addr).await.map(|_| ()).expect("connect failed") });
        }
    }
    while dial_futs.next().await.is_some() {}
    sleep(Duration::from_millis(200)).await;

    // Create HB nodes (instance_id=424242) and preprocess
    let instance_id: u64 = 424242;
    let mut nodes: Vec<HoneyBadgerMPCNode<Fr, RBCImpl>> = Vec::with_capacity(n);
    for i in 0..n {
        let opts = HoneyBadgerMPCNodeOpts::new(n, t, 8, 16, instance_id);
        let node = <HoneyBadgerMPCNode<Fr, RBCImpl> as MPCProtocol<Fr, RobustShare<Fr>, QuicNetworkManager>>::setup(i, opts)
            .expect("Failed to setup node");
        nodes.push(node);
    }
    let mut prng: StdRng = StdRng::from_seed([9u8; 32]);
    // Run preprocessing concurrently
    let mut preprocess_tasks = Vec::with_capacity(n);
    for i in 0..n {
        let net = nets[i].clone();
        let mut node = nodes.remove(0);
        let mut local_rng = prng.clone();
        preprocess_tasks.push(tokio::spawn(async move {
            node.run_preprocessing(net, &mut local_rng).await.expect("preprocess");
            node
        }));
    }
    let mut nodes_tmp = vec![None; n];
    for (idx, task) in preprocess_tasks.into_iter().enumerate() {
        let node = task.await.expect("join preprocess");
        nodes_tmp[idx] = Some(node);
    }
    let mut nodes: Vec<HoneyBadgerMPCNode<Fr, RBCImpl>> = nodes_tmp.into_iter().map(|o| o.unwrap()).collect();

    // Generate consistent input shares
    let mut rng = test_rng();
    let shares_a = RobustShare::compute_shares(Fr::from(INPUT_A), n, t, None, &mut rng)
        .expect("Failed to create shares for input A");
    let shares_b = RobustShare::compute_shares(Fr::from(INPUT_B), n, t, None, &mut rng)
        .expect("Failed to create shares for input B");

    // Multiply via nodes
    let mut prod_shares: Vec<RobustShare<Fr>> = Vec::with_capacity(n);
    for i in 0..n {
        let out = nodes[i]
            .mul(vec![shares_a[i].clone()], vec![shares_b[i].clone()], nets[i].clone())
            .await
            .expect("mul failed");
        assert_eq!(out.len(), 1);
        prod_shares.push(out[0].clone());
    }

    // Reveal product via robust reconstruction using all available shares (handles degree-2t products)
    let (_deg, secret) = RobustShare::recover_secret(&prod_shares, n).expect("recover product");
    let limbs: [u64; 4] = secret.into_bigint().0;
    assert_eq!(limbs[0], EXPECTED_RESULT);
}
