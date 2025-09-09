//! HoneyBadger MPC integration helpers for the Stoffel VM.
//! It provides constructors for nodes/clients and message pumps to drive the protocol.
//! Use the MpcEngine abstraction (net::mpc_engine) to attach an engine to VMState for VM usage.
use std::collections::HashMap;
use std::sync::Arc;
use ark_ff::FftField;
use tokio::sync::{mpsc::Receiver, Mutex};
use stoffelnet::network_utils::{ClientId, Network};
use stoffelmpc_mpc::honeybadger::{HoneyBadgerMPCClient, HoneyBadgerMPCNode, HoneyBadgerMPCNodeOpts};
use stoffelmpc_mpc::common::{MPCProtocol, RBC, SecretSharingScheme};
use stoffelnet::transports::quic::QuicNetworkManager;

const DEFAULT_MIN_PARTIES: usize = 5;
const DEFAULT_THRESHOLD: usize = 3;

/// Convenience for creating default node options for a 5-party, t=3 network.
/// Customize n_triples / n_random_shares / instance_id as needed at callsite.
pub fn default_node_opts(instance_id: u64, n_triples: usize, n_random_shares: usize) -> HoneyBadgerMPCNodeOpts {
    HoneyBadgerMPCNodeOpts::new(
        DEFAULT_MIN_PARTIES,
        DEFAULT_THRESHOLD,
        n_triples,
        n_random_shares,
        instance_id,
    )
}

/// Helper to construct a node with the above defaults.
/// If you need different n or t, call HoneyBadgerMPCNodeOpts::new(...) directly.
pub fn new_default_node<F: FftField, R: RBC, S: SecretSharingScheme<F>>(
    id: usize,
    instance_id: u64,
    n_triples: usize,
    n_random_shares: usize,
) -> HoneyBadgerMPCNode<F, R>
where
    HoneyBadgerMPCNode<F, R>: MPCProtocol<F, S, QuicNetworkManager, MPCOpts = HoneyBadgerMPCNodeOpts>,
{
    let opts = default_node_opts(instance_id, n_triples, n_random_shares);
    HoneyBadgerMPCNode::<F, R>::setup(id, opts).expect("Failed to setup HoneyBadgerMPCNode")
}


pub fn receive<F, R, S, N>(
    receivers: Vec<Receiver<Vec<u8>>>,
    nodes: Vec<HoneyBadgerMPCNode<F, R>>,
    net: Arc<N>,
) where
    F: FftField,
    R: RBC + 'static,
    N: Network + Send + Sync + 'static,
    S: SecretSharingScheme<F>,
    HoneyBadgerMPCNode<F, R>: MPCProtocol<F, S, N>,
{
    // One task per server node/receiver. Pair nodes with their corresponding receivers.
    for (i, (mut node, mut rx)) in nodes.into_iter().zip(receivers.into_iter()).enumerate() {
        let net_clone = net.clone();
        tokio::spawn(async move {
            while let Some(raw) = rx.recv().await {
                if let Err(e) = node.process(raw, net_clone.clone()).await {
                    eprintln!("Server node {} process error: {:?}", i, e);
                }
            }
        });
    }
}

pub fn create_global_nodes<F: FftField, R: RBC + 'static, S, N>(
    n_parties: usize,
    t: usize,
    n_triples: usize,
    n_random_shares: usize,
    instance_id: u64,
) -> Vec<HoneyBadgerMPCNode<F, R>>
where
    N: Network + Send + Sync + 'static,
    S: SecretSharingScheme<F>,
    HoneyBadgerMPCNode<F, R>: MPCProtocol<F, S, N, MPCOpts = HoneyBadgerMPCNodeOpts>,
{
    // If caller passed fewer than the default, still honor the stricter minimum of 5/3
    let n = n_parties.max(DEFAULT_MIN_PARTIES);
    let t_eff = t.max(DEFAULT_THRESHOLD);
    assert!(
        n >= DEFAULT_MIN_PARTIES && t_eff >= DEFAULT_THRESHOLD,
        "Minimum network is n >= 5, t >= 3"
    );

    (0..n)
        .map(|id| {
            // Use caller values if they exceed defaults; otherwise default to 5/3
            let opts = HoneyBadgerMPCNodeOpts::new(
                n,
                t_eff,
                n_triples,
                n_random_shares,
                instance_id,
            );
            HoneyBadgerMPCNode::<F, R>::setup(id, opts)
                .expect("Failed to setup HoneyBadgerMPCNode")
        })
        .collect()
}


pub fn create_clients<F: FftField, R: RBC + 'static>(
    client_ids: Vec<ClientId>,
    n_parties: usize,
    t: usize,
    instance_id: u64,
    inputs: Vec<F>,
    input_len: usize,
) -> HashMap<ClientId, Arc<tokio::sync::Mutex<HoneyBadgerMPCClient<F, R>>>> {
    let n = n_parties.max(DEFAULT_MIN_PARTIES);
    let t_eff = t.max(DEFAULT_THRESHOLD);
    assert!(
        n >= DEFAULT_MIN_PARTIES && t_eff >= DEFAULT_THRESHOLD,
        "Minimum network is n >= 5, t >= 3"
    );

    let mut map = HashMap::new();
    for cid in client_ids {
        let client = HoneyBadgerMPCClient::<F, R>::new(
            cid,
            n,
            t_eff,
            instance_id,
            inputs.clone(),
            input_len,
        )
        .expect("Failed to setup HoneyBadgerMPCClient");
        map.insert(cid, Arc::new(Mutex::new(client)));
    }
    map
}

pub fn receive_client<F, R, N>(
    mut receivers: HashMap<ClientId, Receiver<Vec<u8>>>,
    clients: HashMap<ClientId, Arc<Mutex<HoneyBadgerMPCClient<F, R>>>>,
    net: Arc<N>,
) where
    F: FftField + 'static,
    R: RBC + 'static,
    N: Network + Send + Sync + 'static,
{
    for (cid, client) in clients {
        let net_clone = net.clone();
        let mut rx = receivers
            .remove(&cid)
            .expect("Missing receiver for client");
        let client_arc = client.clone();
        tokio::spawn(async move {
            while let Some(raw) = rx.recv().await {
                if let Err(e) = client_arc.lock().await.process(raw, net_clone.clone()).await {
                    eprintln!("Client {} process error: {:?}", cid, e);
                }
            }
        });
    }
}
