use std::env;
use std::net::SocketAddr;
use std::process::exit;
use std::str::FromStr;

#[cfg(feature = "honeybadger")]
use ark_ec::{CurveGroup, PrimeGroup};
#[cfg(feature = "honeybadger")]
use ark_ff::PrimeField;
#[cfg(feature = "honeybadger")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "honeybadger")]
use std::collections::HashSet;
use std::fs::File;
use std::sync::Arc;
use std::time::Duration;
use stoffel_vm::core_vm::VirtualMachine;
#[cfg(feature = "avss")]
use stoffel_vm::net::avss_server::{
    AvssQuicConfig, Bls12381AvssServer, Bn254AvssServer, Curve25519AvssServer, Ed25519AvssServer,
};
#[cfg(feature = "honeybadger")]
use stoffel_vm::net::curve::SupportedMpcField;
#[cfg(feature = "honeybadger")]
use stoffel_vm::net::hb_engine::HoneyBadgerMpcEngine;
#[cfg(feature = "honeybadger")]
use stoffel_vm::net::{honeybadger_node_opts, spawn_receive_loops};
use stoffel_vm::net::{
    program_id_from_bytes, register_and_wait_for_session_with_program, run_bootnode_with_config,
};
use stoffel_vm::net::{MpcBackendKind, MpcCurveConfig};
use stoffel_vm::runtime_hooks::{HookContext, HookEvent};
use stoffel_vm_types::compiled_binary::CompiledBinary;
#[cfg(feature = "honeybadger")]
use stoffelmpc_mpc::common::rbc::rbc::Avid;
#[cfg(feature = "honeybadger")]
use stoffelmpc_mpc::common::MPCProtocol;
#[cfg(feature = "honeybadger")]
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
#[cfg(feature = "honeybadger")]
use stoffelmpc_mpc::honeybadger::SessionId as HbSessionId;
#[cfg(feature = "honeybadger")]
use stoffelmpc_mpc::honeybadger::{HoneyBadgerMPCClient, HoneyBadgerMPCNode};
#[cfg(feature = "honeybadger")]
use stoffelnet::network_utils::ClientId;
use stoffelnet::network_utils::Network;
use stoffelnet::transports::quic::{NetworkManager, QuicNetworkManager};
use tokio::sync::mpsc;

fn is_flag_present(raw_args: &[String], flag: &str) -> bool {
    raw_args
        .iter()
        .any(|arg| arg == flag || arg.starts_with(&format!("{flag}=")))
}

fn fail_removed_flag(raw_args: &[String], old_flag: &str, replacement_hint: &str) {
    if is_flag_present(raw_args, old_flag) {
        eprintln!("Error: `{}` was removed. {}", old_flag, replacement_hint);
        exit(2);
    }
}

#[cfg(feature = "honeybadger")]
fn parse_inputs_as_field<F: PrimeField>(inputs_str: &str) -> Vec<F> {
    inputs_str
        .split(',')
        .map(|s| {
            let s = s.trim();
            let val: i64 = s.parse().unwrap_or_else(|_| {
                eprintln!("Invalid input value: {}", s);
                exit(2);
            });
            stoffel_vm::net::field_from_i64::<F>(val)
        })
        .collect()
}

/// Connect to all MPC servers with retry logic, spawning a receive loop per connection.
#[cfg(feature = "honeybadger")]
async fn connect_to_all_servers(
    network: &Arc<tokio::sync::Mutex<QuicNetworkManager>>,
    server_addrs: &[SocketAddr],
    msg_tx: mpsc::Sender<(usize, Vec<u8>)>,
) {
    let max_retries = 10;
    let retry_delay = Duration::from_millis(500);
    let mut connected_servers = Vec::with_capacity(server_addrs.len());

    for (server_idx, &addr) in server_addrs.iter().enumerate() {
        let mut retry_count = 0;

        loop {
            eprintln!(
                "[client] Connecting to server {} at {} (attempt {}/{})",
                server_idx,
                addr,
                retry_count + 1,
                max_retries
            );

            let connection_result = {
                let mut net = network.lock().await;
                net.connect_as_client(addr).await
            };

            match connection_result {
                Ok(connection) => {
                    eprintln!("[client] Connected to server {} at {}", server_idx, addr);
                    connected_servers.push((addr, connection));
                    break;
                }
                Err(e) => {
                    retry_count += 1;
                    if retry_count >= max_retries {
                        eprintln!(
                            "[client] Failed to connect to server {} at {} after {} attempts: {}",
                            server_idx, addr, retry_count, e
                        );
                        exit(21);
                    }
                    eprintln!(
                        "[client] Connection attempt {} failed: {}, retrying...",
                        retry_count, e
                    );
                    tokio::time::sleep(retry_delay).await;
                }
            }
        }
    }

    let (assigned_party_ids, local_party_id) = {
        let net = network.lock().await;
        let assigned = net.assign_party_ids();
        let local = net.compute_local_party_id();
        (assigned, local)
    };
    eprintln!(
        "[client] Assigned authenticated party IDs for {} connections",
        assigned_party_ids
    );

    let mut seen_peers = HashSet::new();
    for (addr, connection) in connected_servers {
        let authenticated_peer = connection.remote_party_id().unwrap_or_else(|| {
            eprintln!(
                "[client] Connected server {} has no authenticated party identity",
                addr
            );
            exit(24);
        });
        let peer = local_party_id.map_or(authenticated_peer, |local_id| {
            if authenticated_peer == local_id {
                eprintln!(
                    "[client] Connected server {} resolved to local authenticated identity {}",
                    addr, authenticated_peer
                );
                exit(24);
            }
            if authenticated_peer > local_id {
                authenticated_peer - 1
            } else {
                authenticated_peer
            }
        });

        if !seen_peers.insert(peer) {
            eprintln!(
                "[client] Duplicate authenticated party identity {} detected for server {}",
                peer, addr
            );
            exit(24);
        }

        let tx = msg_tx.clone();
        tokio::spawn(async move {
            loop {
                match connection.receive().await {
                    Ok(data) => {
                        if let Err(e) = tx.send((peer, data)).await {
                            eprintln!("[client] Failed to forward message: {:?}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("[client] Connection to server {} closed: {}", peer, e);
                        break;
                    }
                }
            }
        });
    }
}

#[cfg(feature = "honeybadger")]
const CLIENT_SET_SYNC_PREFIX: &[u8; 4] = b"CSS1";

#[cfg(feature = "honeybadger")]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClientSetSyncMessage {
    sender_party_id: usize,
    client_ids: Vec<ClientId>,
}

#[cfg(feature = "honeybadger")]
fn normalize_client_ids(mut ids: Vec<ClientId>) -> Vec<ClientId> {
    ids.sort_unstable();
    ids.dedup();
    ids
}

#[cfg(feature = "honeybadger")]
fn encode_client_set_sync(msg: &ClientSetSyncMessage) -> Result<Vec<u8>, String> {
    let payload = bincode::serialize(msg)
        .map_err(|e| format!("Failed to serialize client-set sync payload: {}", e))?;
    let mut out = Vec::with_capacity(CLIENT_SET_SYNC_PREFIX.len() + payload.len());
    out.extend_from_slice(CLIENT_SET_SYNC_PREFIX);
    out.extend_from_slice(&payload);
    Ok(out)
}

#[cfg(feature = "honeybadger")]
fn decode_client_set_sync(bytes: &[u8]) -> Result<ClientSetSyncMessage, String> {
    if bytes.len() < CLIENT_SET_SYNC_PREFIX.len()
        || &bytes[..CLIENT_SET_SYNC_PREFIX.len()] != CLIENT_SET_SYNC_PREFIX
    {
        return Err("Unexpected message prefix while waiting for client-set sync".to_string());
    }

    bincode::deserialize(&bytes[CLIENT_SET_SYNC_PREFIX.len()..])
        .map_err(|e| format!("Failed to deserialize client-set sync payload: {}", e))
}

#[cfg(feature = "honeybadger")]
async fn sync_client_set_across_parties(
    net: Arc<QuicNetworkManager>,
    my_id: usize,
    n_parties: usize,
    local_client_ids: &[ClientId],
) -> Result<(), String> {
    if n_parties <= 1 {
        return Ok(());
    }

    let normalized_local = normalize_client_ids(local_client_ids.to_vec());
    let sync_payload = encode_client_set_sync(&ClientSetSyncMessage {
        sender_party_id: my_id,
        client_ids: normalized_local.clone(),
    })?;

    eprintln!(
        "[party {}] Broadcasting client-set sync payload: {:?}",
        my_id, normalized_local
    );

    for peer_id in 0..n_parties {
        if peer_id == my_id {
            continue;
        }
        net.send(peer_id, &sync_payload)
            .await
            .map_err(|e| format!("Failed to send client-set sync to party {}: {}", peer_id, e))?;
    }

    let mut confirmed_parties: HashSet<usize> = HashSet::new();
    let expected_confirmations = n_parties - 1;
    let receive_deadline = std::time::Instant::now() + Duration::from_secs(20);

    while confirmed_parties.len() < expected_confirmations {
        if std::time::Instant::now() >= receive_deadline {
            return Err(format!(
                "Timed out waiting for client-set sync confirmations ({}/{})",
                confirmed_parties.len(),
                expected_confirmations
            ));
        }

        let mut progressed = false;
        for (derived_id, connection) in net.get_all_server_connections() {
            let sender_id = connection.remote_party_id().unwrap_or(derived_id);
            if sender_id >= n_parties
                || sender_id == my_id
                || confirmed_parties.contains(&sender_id)
            {
                continue;
            }

            let remaining = receive_deadline.saturating_duration_since(std::time::Instant::now());
            let wait_for = remaining.min(Duration::from_millis(500));
            if wait_for.is_zero() {
                continue;
            }

            match tokio::time::timeout(wait_for, connection.receive()).await {
                Ok(Ok(data)) => {
                    let sync = decode_client_set_sync(&data).map_err(|e| {
                        format!(
                            "Failed to decode client-set sync from party {}: {}",
                            sender_id, e
                        )
                    })?;

                    if sync.sender_party_id != sender_id {
                        return Err(format!(
                            "Client-set sync sender mismatch: transport sender={} payload sender={}",
                            sender_id, sync.sender_party_id
                        ));
                    }

                    let normalized_remote = normalize_client_ids(sync.client_ids);
                    if normalized_remote != normalized_local {
                        return Err(format!(
                            "Client-set mismatch with party {}: local={:?}, remote={:?}",
                            sender_id, normalized_local, normalized_remote
                        ));
                    }

                    confirmed_parties.insert(sender_id);
                    progressed = true;
                    eprintln!(
                        "[party {}] Client-set sync confirmed with party {}",
                        my_id, sender_id
                    );
                }
                Ok(Err(e)) => {
                    return Err(format!(
                        "Failed to receive client-set sync from party {}: {}",
                        sender_id, e
                    ));
                }
                Err(_) => {}
            }
        }

        if !progressed {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    eprintln!(
        "[party {}] Client-set sync complete with {} peers",
        my_id, expected_confirmations
    );
    Ok(())
}

#[cfg(feature = "honeybadger")]
async fn run_hb_client_protocol_for_curve<F: PrimeField>(
    cid: ClientId,
    n: usize,
    t: usize,
    inputs_str: &str,
    input_len: usize,
    network_for_process: Arc<tokio::sync::Mutex<QuicNetworkManager>>,
    mut msg_rx: mpsc::Receiver<(usize, Vec<u8>)>,
) -> Result<(), String> {
    let instance_id = 0u32;
    let mut mpc_client = HoneyBadgerMPCClient::<F, Avid<HbSessionId>>::new(
        cid,
        n,
        t,
        instance_id,
        parse_inputs_as_field::<F>(inputs_str),
        input_len,
    )
    .map_err(|e| format!("Failed to create MPC client: {:?}", e))?;

    let mut messages_processed = 0usize;
    while let Some((sender_id, data)) = msg_rx.recv().await {
        let network_clone = {
            let guard = network_for_process.lock().await;
            (*guard).clone()
        };

        if let Err(e) = mpc_client
            .process(data, sender_id, Arc::new(network_clone))
            .await
        {
            eprintln!("[client {}] Failed to process message: {:?}", cid, e);
        }

        messages_processed += 1;
        if messages_processed >= n {
            tokio::time::sleep(Duration::from_secs(2)).await;
            break;
        }
    }

    eprintln!(
        "[client {}] Message processing complete ({} messages)",
        cid, messages_processed
    );
    Ok(())
}

#[cfg(feature = "honeybadger")]
async fn run_hb_client_for_curve(
    curve_config: MpcCurveConfig,
    cid: ClientId,
    n: usize,
    t: usize,
    inputs_str: &str,
    input_len: usize,
    network_for_process: Arc<tokio::sync::Mutex<QuicNetworkManager>>,
    msg_rx: mpsc::Receiver<(usize, Vec<u8>)>,
) -> Result<(), String> {
    match curve_config {
        MpcCurveConfig::Bls12_381 => {
            run_hb_client_protocol_for_curve::<ark_bls12_381::Fr>(
                cid,
                n,
                t,
                inputs_str,
                input_len,
                network_for_process,
                msg_rx,
            )
            .await
        }
        MpcCurveConfig::Bn254 => {
            run_hb_client_protocol_for_curve::<ark_bn254::Fr>(
                cid,
                n,
                t,
                inputs_str,
                input_len,
                network_for_process,
                msg_rx,
            )
            .await
        }
        MpcCurveConfig::Curve25519 => {
            run_hb_client_protocol_for_curve::<ark_curve25519::Fr>(
                cid,
                n,
                t,
                inputs_str,
                input_len,
                network_for_process,
                msg_rx,
            )
            .await
        }
        MpcCurveConfig::Ed25519 => {
            run_hb_client_protocol_for_curve::<ark_ed25519::Fr>(
                cid,
                n,
                t,
                inputs_str,
                input_len,
                network_for_process,
                msg_rx,
            )
            .await
        }
    }
}

#[cfg(feature = "honeybadger")]
async fn setup_hb_party_for_curve<F, G>(
    vm: &mut VirtualMachine,
    net: Arc<QuicNetworkManager>,
    my_id: usize,
    n: usize,
    t: usize,
    instance_id: u64,
    expected_client_count: Option<usize>,
) -> Result<(), String>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    let mut input_ids: Vec<ClientId> = Vec::new();

    if let Some(expected_count) = expected_client_count {
        if expected_count == 0 {
            return Err("--expected-client-count must be greater than 0".to_string());
        }

        eprintln!(
            "[party {}] Waiting for {} transport-derived clients...",
            my_id, expected_count
        );

        let mut accept_net = (*net).clone();
        let accept_party_id = my_id;
        tokio::spawn(async move {
            loop {
                match accept_net.accept().await {
                    Ok(_) => {
                        eprintln!("[party {}] Accepted client connection", accept_party_id);
                    }
                    Err(e) => {
                        eprintln!("[party {}] Accept error: {}", accept_party_id, e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });

        let connect_timeout = Duration::from_secs(60);
        let check_interval = Duration::from_millis(250);
        let start = std::time::Instant::now();

        loop {
            let mut connected_clients = net.clients();
            connected_clients.sort_unstable();
            connected_clients.dedup();

            eprintln!(
                "[party {}] {} of {} expected clients connected: {:?}",
                my_id,
                connected_clients.len(),
                expected_count,
                connected_clients
            );

            if connected_clients.len() > expected_count {
                return Err(format!(
                    "Expected exactly {} clients, but {} are connected: {:?}",
                    expected_count,
                    connected_clients.len(),
                    connected_clients
                ));
            }

            if connected_clients.len() == expected_count {
                input_ids = connected_clients;
                break;
            }

            if start.elapsed() > connect_timeout {
                return Err(format!(
                    "Timeout waiting for {} clients; connected so far: {:?}",
                    expected_count,
                    net.clients()
                ));
            }

            tokio::time::sleep(check_interval).await;
        }

        eprintln!(
            "[party {}] Using transport-derived input IDs: {:?}",
            my_id, input_ids
        );

        sync_client_set_across_parties(net.clone(), my_id, n, &input_ids).await?;
    }

    let n_triples = 8;
    let n_random = 16;
    let mpc_opts = honeybadger_node_opts(n, t, n_triples, n_random, instance_id);

    let mut mpc_node = <HoneyBadgerMPCNode<F, Avid<HbSessionId>> as MPCProtocol<
        F,
        RobustShare<F>,
        QuicNetworkManager,
    >>::setup(my_id, mpc_opts, input_ids.clone())
    .map_err(|e| format!("Failed to create MPC node: {:?}", e))?;

    let mut msg_rx = spawn_receive_loops(net.clone(), my_id, n).await;
    let mut processing_node = mpc_node.clone();
    let processing_net = net.clone();
    tokio::spawn(async move {
        while let Some((sender_id, raw_msg)) = msg_rx.recv().await {
            if let Err(e) = processing_node
                .process(raw_msg, sender_id, processing_net.clone())
                .await
            {
                eprintln!(
                    "[party {}] Failed to process message from {}: {:?}",
                    my_id, sender_id, e
                );
            }
        }
    });

    let engine = HoneyBadgerMpcEngine::<F, G>::from_existing_node(
        instance_id,
        my_id,
        n,
        t,
        net.clone(),
        mpc_node.clone(),
    );

    engine
        .preprocess()
        .await
        .map_err(|e| format!("MPC preprocessing failed: {}", e))?;

    if !input_ids.is_empty() {
        for &cid in &input_ids {
            let local_shares = mpc_node
                .preprocessing_material
                .lock()
                .await
                .take_random_shares(1)
                .map_err(|e| format!("Not enough random shares for client {}: {:?}", cid, e))?;

            mpc_node
                .preprocess
                .input
                .init(cid, local_shares, 1, net.clone())
                .await
                .map_err(|e| format!("Failed to init InputServer for client {}: {:?}", cid, e))?;
        }

        let client_inputs = mpc_node
            .preprocess
            .input
            .wait_for_all_inputs(Duration::from_secs(60))
            .await
            .map_err(|e| format!("Failed to receive client inputs: {:?}", e))?;

        for (cid, shares) in client_inputs {
            vm.state.client_store().store_client_input(cid, shares);
            eprintln!("[party {}] Stored inputs for client {}", my_id, cid);
        }
    }

    vm.state.set_mpc_engine(engine);
    Ok(())
}

// Use a Tokio runtime for async operations
#[tokio::main]
async fn main() {
    let raw_args = env::args().skip(1).collect::<Vec<_>>();

    if raw_args.is_empty() {
        // Allow bootnode-only mode without program path
        print_usage_and_exit();
    }

    let mut path_opt: Option<String> = None;
    let mut entry: String = "main".to_string();

    let mut trace_instr = false;
    let mut trace_regs = false;
    let mut trace_stack = false;
    let mut as_bootnode = false;
    let mut as_leader = false;
    let mut as_client = false;
    let mut bind_addr: Option<SocketAddr> = None;
    let mut party_id: Option<usize> = None;
    let mut bootstrap_addr: Option<SocketAddr> = None;
    let mut n_parties: Option<usize> = None;
    let mut threshold: Option<usize> = None;
    let mut client_inputs: Option<String> = None;
    let mut expected_client_count: Option<usize> = None;
    let mut enable_nat: bool = false;
    let mut stun_servers: Vec<SocketAddr> = Vec::new();
    let mut server_addrs: Vec<SocketAddr> = Vec::new();
    let mut mpc_backend: Option<String> = None;
    let mut mpc_curve: Option<String> = None;

    for arg in &raw_args {
        if arg == "-h" || arg == "--help" {
            print_usage_and_exit();
        } else if arg == "--trace-instr" {
            trace_instr = true;
        } else if arg == "--trace-regs" {
            trace_regs = true;
        } else if arg == "--trace-stack" {
            trace_stack = true;
        } else if arg == "--bootnode" {
            as_bootnode = true;
        } else if arg == "--leader" {
            as_leader = true;
        } else if arg == "--client" {
            as_client = true;
        } else if arg == "--nat" {
            enable_nat = true;
        } else if let Some(_rest) = arg.strip_prefix("--bind") {
            // support "--bind" and "--bind=.."
            // actual value parsed later from positional with key
        } else if let Some(_rest) = arg.strip_prefix("--party-id") {
        } else if let Some(_rest) = arg.strip_prefix("--bootstrap") {
        } else if let Some(_rest) = arg.strip_prefix("--n-parties") {
        } else if let Some(_rest) = arg.strip_prefix("--threshold") {
        } else if let Some(_rest) = arg.strip_prefix("--inputs") {
        } else if let Some(_rest) = arg.strip_prefix("--expected-client-count") {
        } else if let Some(_rest) = arg.strip_prefix("--stun-servers") {
        } else if let Some(_rest) = arg.strip_prefix("--servers") {
        } else if let Some(_rest) = arg.strip_prefix("--mpc-backend") {
        } else if let Some(_rest) = arg.strip_prefix("--mpc-curve") {
        }
    }

    fail_removed_flag(
        &raw_args,
        "--client-id",
        "Client IDs are now transport-derived. Remove `--client-id`.",
    );
    fail_removed_flag(
        &raw_args,
        "--expected-clients",
        "Use `--expected-client-count <n>` instead.",
    );
    fail_removed_flag(
        &raw_args,
        "--adkg-curve",
        "Use `--mpc-curve <name>` instead.",
    );

    // collect positional args (non-flags)
    let mut positional = raw_args
        .into_iter()
        .filter(|a| !a.starts_with("--"))
        .collect::<Vec<_>>();

    if positional.is_empty() {
        // Allow bootnode-only mode without program path
        if !as_bootnode {
            print_usage_and_exit();
        }
    }

    // Parse key-value style flags
    let mut args_iter = env::args().skip(1).peekable();
    while let Some(a) = args_iter.next() {
        match a.as_str() {
            "--bind" => {
                if let Some(v) = args_iter.next() {
                    bind_addr = Some(v.parse().expect("Invalid --bind addr"));
                }
            }
            "--party-id" => {
                if let Some(v) = args_iter.next() {
                    party_id = Some(v.parse().expect("Invalid --party-id"));
                }
            }
            "--bootstrap" => {
                if let Some(v) = args_iter.next() {
                    bootstrap_addr = Some(v.parse().expect("Invalid --bootstrap addr"));
                }
            }
            "--n-parties" => {
                if let Some(v) = args_iter.next() {
                    n_parties = Some(v.parse().expect("Invalid --n-parties"));
                }
            }
            "--threshold" => {
                if let Some(v) = args_iter.next() {
                    threshold = Some(v.parse().expect("Invalid --threshold"));
                }
            }
            "--inputs" => {
                if let Some(v) = args_iter.next() {
                    client_inputs = Some(v);
                }
            }
            "--expected-client-count" => {
                if let Some(v) = args_iter.next() {
                    expected_client_count =
                        Some(v.parse().expect("Invalid --expected-client-count"));
                }
            }
            "--stun-servers" => {
                if let Some(v) = args_iter.next() {
                    stun_servers = v
                        .split(',')
                        .filter_map(|s| {
                            let s = s.trim();
                            s.parse::<SocketAddr>().ok().or_else(|| {
                                eprintln!("Warning: Invalid STUN server address '{}', skipping", s);
                                None
                            })
                        })
                        .collect();
                }
            }
            "--servers" => {
                if let Some(v) = args_iter.next() {
                    server_addrs = v
                        .split(',')
                        .filter_map(|s| {
                            let s = s.trim();
                            s.parse::<SocketAddr>().ok().or_else(|| {
                                eprintln!("Warning: Invalid server address '{}', skipping", s);
                                None
                            })
                        })
                        .collect();
                }
            }
            "--mpc-backend" => {
                if let Some(v) = args_iter.next() {
                    mpc_backend = Some(v);
                }
            }
            "--mpc-curve" => {
                if let Some(v) = args_iter.next() {
                    mpc_curve = Some(v);
                }
            }
            _ => {}
        }
    }

    // Bootnode-only mode (no program execution)
    if as_bootnode && !as_leader {
        let bind = bind_addr.unwrap_or_else(|| "127.0.0.1:9000".parse().unwrap());
        eprintln!("Starting bootnode on {}", bind);
        // Install crypto provider for quinn/rustls
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("install rustls crypto");
        // Pass expected parties if specified, so bootnode waits for all before announcing session
        if let Err(e) = run_bootnode_with_config(bind, n_parties).await {
            eprintln!("Bootnode error: {}", e);
            exit(10);
        }
        return;
    }

    // Client mode: connect to MPC servers and provide inputs (HoneyBadger only)
    #[cfg(feature = "honeybadger")]
    if as_client {
        let n = n_parties.unwrap_or_else(|| {
            eprintln!("Error: --n-parties is required in client mode");
            exit(2);
        });
        let t = threshold.unwrap_or(1);

        if let Some(ref backend_name) = mpc_backend {
            let parsed_backend = MpcBackendKind::from_str(backend_name).unwrap_or_else(|e| {
                eprintln!("Error: {}", e);
                exit(2);
            });
            if !matches!(parsed_backend, MpcBackendKind::HoneyBadger) {
                eprintln!(
                    "Error: client mode only supports honeybadger backend (got {})",
                    parsed_backend.name()
                );
                exit(2);
            }
        }

        // Parse inputs (comma-separated integers or fixed-point values)
        let inputs_str = client_inputs.unwrap_or_else(|| {
            eprintln!("Error: --inputs is required in client mode (comma-separated values)");
            exit(2);
        });
        let input_len = inputs_str.split(',').count();

        // Server addresses are required
        if server_addrs.is_empty() {
            eprintln!("Error: --servers is required in client mode (comma-separated addresses)");
            eprintln!("Example: --servers 172.18.0.2:9000,172.18.0.3:9000,172.18.0.4:9000,172.18.0.5:9000,172.18.0.6:9000");
            exit(2);
        }

        if server_addrs.len() != n {
            eprintln!(
                "Warning: number of servers ({}) doesn't match n_parties ({})",
                server_addrs.len(),
                n
            );
        }

        let curve_config = if let Some(ref name) = mpc_curve {
            MpcCurveConfig::from_str(name).unwrap_or_else(|e| {
                eprintln!("Error: {}", e);
                exit(2);
            })
        } else {
            MpcCurveConfig::default()
        };

        eprintln!(
            "[client] Client mode (curve={}, n={}, t={}, {} inputs, {} servers)",
            curve_config.name(),
            n,
            t,
            input_len,
            server_addrs.len()
        );

        // Install crypto provider for quinn/rustls
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("install rustls crypto");

        // Create network manager for client connections
        let network = Arc::new(tokio::sync::Mutex::new(QuicNetworkManager::new()));

        // Add all server addresses as nodes (party IDs 0 to n-1)
        for (party_id, &addr) in server_addrs.iter().enumerate() {
            network.lock().await.add_node_with_party_id(party_id, addr);
            eprintln!("[client] Added server party {} at {}", party_id, addr);
        }

        // Create channel for receiving messages (sender_id, data)
        let (msg_tx, msg_rx) = mpsc::channel::<(usize, Vec<u8>)>(1000);

        // Connect to all servers as a client
        eprintln!("[client] Connecting to {} servers...", server_addrs.len());
        connect_to_all_servers(&network, &server_addrs, msg_tx.clone()).await;

        // Derive client identity from transport/TLS public key hash
        let cid = {
            let net = network.lock().await;
            net.local_derived_id()
        };
        eprintln!("[client {}] Derived transport client ID", cid);

        eprintln!(
            "[client {}] Connected to all servers, starting input protocol...",
            cid
        );

        // Spawn protocol processing with the selected field.
        let network_for_process = network.clone();
        let client_id_for_task = cid;
        let inputs_for_task = inputs_str.clone();
        let process_handle = tokio::spawn(async move {
            run_hb_client_for_curve(
                curve_config,
                client_id_for_task,
                n,
                t,
                &inputs_for_task,
                input_len,
                network_for_process,
                msg_rx,
            )
            .await
        });

        // Wait for input protocol to complete with timeout
        let timeout_duration = Duration::from_secs(120);
        match tokio::time::timeout(timeout_duration, process_handle).await {
            Ok(Ok(Ok(()))) => {
                eprintln!(
                    "[client {}] Successfully submitted inputs to MPC network",
                    cid
                );
            }
            Ok(Ok(Err(e))) => {
                eprintln!("[client {}] Input protocol failed: {}", cid, e);
                exit(22);
            }
            Ok(Err(e)) => {
                eprintln!("[client {}] Input task error: {:?}", cid, e);
                exit(22);
            }
            Err(_) => {
                eprintln!(
                    "[client {}] Timeout waiting for input protocol to complete",
                    cid
                );
                exit(23);
            }
        }

        return;
    }
    #[cfg(not(feature = "honeybadger"))]
    if as_client {
        eprintln!("Error: client mode requires the 'honeybadger' feature");
        exit(2);
    }

    // Resolve MPC backend kind
    let backend_kind = if let Some(ref name) = mpc_backend {
        match MpcBackendKind::from_str(name) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("Error: {}", e);
                exit(2);
            }
        }
    } else {
        MpcBackendKind::default_backend()
    };

    let curve_config = if let Some(ref name) = mpc_curve {
        match MpcCurveConfig::from_str(name) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error: {}", e);
                exit(2);
            }
        }
    } else {
        MpcCurveConfig::default()
    };

    if let Err(e) = curve_config.validate_for_backend(backend_kind) {
        eprintln!("Error: {}", e);
        exit(2);
    }

    // Validate incompatible flag combinations
    if !backend_kind.supports_client_input() {
        if as_client {
            eprintln!(
                "Error: {} backend does not support client mode",
                backend_kind.name()
            );
            exit(2);
        }
    }

    if expected_client_count.is_some() && !backend_kind.supports_client_input() {
        eprintln!(
            "Error: {} backend does not support --expected-client-count",
            backend_kind.name()
        );
        exit(2);
    }

    path_opt = if !positional.is_empty() {
        Some(positional.remove(0))
    } else {
        None
    };
    entry = if !positional.is_empty() {
        positional.remove(0)
    } else {
        entry
    };

    // Optional: bring up networking in party mode if bootstrap provided or if leader
    let mut net_opt: Option<Arc<QuicNetworkManager>> = None;
    let mut program_id: [u8; 32] = [0u8; 32];
    let mut agreed_entry = entry.clone();
    let mut session_instance_id: Option<u64> = None;
    let mut session_n_parties: Option<usize> = None;
    let mut session_threshold: Option<usize> = None;

    // Leader mode: this party also runs the bootnode
    if as_leader {
        let bind = bind_addr.unwrap_or_else(|| "127.0.0.1:9000".parse().unwrap());
        let my_id = party_id.unwrap_or(0usize);

        // Install crypto provider for quinn/rustls
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("install rustls crypto");

        // Must have program path
        if path_opt.is_none() {
            eprintln!("Error: leader mode requires a program path");
            exit(2);
        }
        let program_path = path_opt.as_ref().unwrap();
        let bytes = std::fs::read(program_path).expect("read program");
        program_id = program_id_from_bytes(&bytes);

        // Get MPC parameters (required for session)
        let n = n_parties.unwrap_or_else(|| {
            eprintln!("Error: --n-parties is required for leader mode");
            exit(2);
        });
        let t = threshold.unwrap_or(1);

        eprintln!(
            "[leader/party {}] Starting bootnode on {} and participating in session (n={}, t={})",
            my_id, bind, n, t
        );

        // Spawn bootnode in background
        let bootnode_bind = bind;
        let bootnode_n = n;
        tokio::spawn(async move {
            if let Err(e) = run_bootnode_with_config(bootnode_bind, Some(bootnode_n)).await {
                eprintln!("Bootnode error: {}", e);
            }
        });

        // Give bootnode a moment to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Now connect to ourselves as the bootnode
        // Use with_node_id so connections are indexed by party ID (0-4), not random UUIDs
        let mut mgr = QuicNetworkManager::with_node_id(my_id);
        // Listen on a different port for peer connections
        let party_bind: SocketAddr = format!("{}:{}", bind.ip(), bind.port() + 1000)
            .parse()
            .unwrap();
        if let Err(e) = mgr.listen(party_bind).await {
            eprintln!("Failed to listen on {}: {}", party_bind, e);
            exit(11);
        }

        eprintln!(
            "[leader/party {}] Party listening on {}, registering with bootnode {}",
            my_id, party_bind, bind
        );

        // Register with our own bootnode and wait for session
        // Leader uploads program bytes so other parties can fetch them
        let session_info = match register_and_wait_for_session_with_program(
            &mut mgr,
            bind, // bootnode is on our bind address
            my_id,
            party_bind,
            program_id,
            &entry,
            n,
            t,
            Duration::from_secs(120), // 2 minute timeout for all parties to join
            Some(bytes),              // Leader uploads program bytes
        )
        .await
        {
            Ok(info) => info,
            Err(e) => {
                eprintln!("Session registration failed: {}", e);
                exit(12);
            }
        };

        // Use session parameters
        agreed_entry = session_info.entry.clone();
        session_instance_id = Some(session_info.instance_id);
        session_n_parties = Some(session_info.n_parties);
        session_threshold = Some(session_info.threshold);

        eprintln!(
            "[leader/party {}] Session started: instance_id={}, n={}, t={}, entry={}",
            my_id,
            session_info.instance_id,
            session_info.n_parties,
            session_info.threshold,
            agreed_entry
        );

        let net = Arc::new(mgr);
        net_opt = Some(net.clone());
    } else if let Some(bootnode) = bootstrap_addr {
        // Regular party mode: connect to external bootnode
        let bind = bind_addr.unwrap_or_else(|| "127.0.0.1:0".parse().unwrap());
        let my_id = party_id.unwrap_or(0usize);
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("install rustls crypto");

        // Must have program path in party mode
        if path_opt.is_none() {
            eprintln!("Error: party mode requires a program path");
            exit(2);
        }
        let program_path = path_opt.as_ref().unwrap();
        let bytes = std::fs::read(program_path).expect("read program");
        program_id = program_id_from_bytes(&bytes);

        // Get MPC parameters (required for session)
        let n = n_parties.unwrap_or_else(|| {
            eprintln!("Error: --n-parties is required for party mode");
            exit(2);
        });
        let t = threshold.unwrap_or(1);

        // Prepare QUIC manager
        // Use with_node_id so connections are indexed by party ID (0-4), not random UUIDs
        let mut mgr = QuicNetworkManager::with_node_id(my_id);
        // Listen so peers can connect back directly
        if let Err(e) = mgr.listen(bind).await {
            eprintln!("Failed to listen on {}: {}", bind, e);
            exit(11);
        }

        // Note: if using port 0, the OS assigns a port. For now we use the bind address.
        // In a real deployment, you should use specific ports, not port 0.
        let actual_listen = bind;
        eprintln!(
            "[party {}] Listening on {}, connecting to bootnode {}",
            my_id, actual_listen, bootnode
        );

        // Register with bootnode and wait for session to be announced
        // This blocks until all n parties have registered
        // Upload program bytes so bootnode can distribute to parties that don't have it
        let session_info = match register_and_wait_for_session_with_program(
            &mut mgr,
            bootnode,
            my_id,
            actual_listen,
            program_id,
            &entry,
            n,
            t,
            Duration::from_secs(120), // 2 minute timeout for all parties to join
            Some(bytes),              // Upload program bytes
        )
        .await
        {
            Ok(info) => info,
            Err(e) => {
                eprintln!("Session registration failed: {}", e);
                exit(12);
            }
        };

        // Use session parameters
        agreed_entry = session_info.entry.clone();
        session_instance_id = Some(session_info.instance_id);
        session_n_parties = Some(session_info.n_parties);
        session_threshold = Some(session_info.threshold);

        eprintln!(
            "[party {}] Session started: instance_id={}, n={}, t={}, entry={}",
            my_id,
            session_info.instance_id,
            session_info.n_parties,
            session_info.threshold,
            agreed_entry
        );

        let net = Arc::new(mgr);
        net_opt = Some(net.clone());
    } else {
        // local run: must have path
        if let Some(p) = &path_opt {
            let bytes = std::fs::read(p).expect("read program");
            program_id = program_id_from_bytes(&bytes);
        } else {
            eprintln!("Error: local run requires a program path unless --bootnode or --leader");
            exit(2);
        }
    }

    // Load compiled binary from a file path
    let load_path: String = if let Some(p) = path_opt.clone() {
        p
    } else {
        // Use cached program path if we fetched it from bootnode
        let p = stoffel_vm::net::program_sync::program_path(&program_id);
        p.to_string_lossy().to_string()
    };
    let mut f = File::open(&load_path).expect("open binary file");
    let binary = CompiledBinary::deserialize(&mut f).expect("deserialize compiled binary");
    let functions = binary.to_vm_functions();
    if functions.is_empty() {
        eprintln!("Error: compiled program contains no functions");
        exit(3);
    }

    // Initialize VM
    let mut vm = VirtualMachine::new();
    // Register standard library in case the program uses builtins like `print`
    vm.register_standard_library();

    // Register all functions
    for f in functions {
        vm.register_function(f);
    }

    // Register debugging hooks based on flags
    if trace_instr {
        vm.register_hook(
            |event| {
                matches!(
                    event,
                    HookEvent::BeforeInstructionExecute(_) | HookEvent::AfterInstructionExecute(_)
                )
            },
            |event, ctx: &HookContext| match event {
                HookEvent::BeforeInstructionExecute(instr) => {
                    let fn_name = ctx
                        .get_function_name()
                        .unwrap_or_else(|| "<unknown>".to_string());
                    let pc = ctx.get_current_instruction();
                    eprintln!(
                        "[instr][depth {}][{}][pc {}] BEFORE {:?}",
                        ctx.get_call_depth(),
                        fn_name,
                        pc,
                        instr
                    );
                    Ok(())
                }
                HookEvent::AfterInstructionExecute(instr) => {
                    let fn_name = ctx
                        .get_function_name()
                        .unwrap_or_else(|| "<unknown>".to_string());
                    let pc = ctx.get_current_instruction();
                    eprintln!(
                        "[instr][depth {}][{}][pc {}] AFTER  {:?}",
                        ctx.get_call_depth(),
                        fn_name,
                        pc,
                        instr
                    );
                    Ok(())
                }
                _ => Ok(()),
            },
            0,
        );
    }

    if trace_regs {
        vm.register_hook(
            |event| {
                matches!(
                    event,
                    HookEvent::RegisterRead(_, _) | HookEvent::RegisterWrite(_, _, _)
                )
            },
            |event, ctx: &HookContext| match event {
                HookEvent::RegisterRead(idx, val) => {
                    let fn_name = ctx
                        .get_function_name()
                        .unwrap_or_else(|| "<unknown>".to_string());
                    eprintln!(
                        "[regs][depth {}][{}] R{} -> {:?}",
                        ctx.get_call_depth(),
                        fn_name,
                        idx,
                        val
                    );
                    Ok(())
                }
                HookEvent::RegisterWrite(idx, old, new) => {
                    let fn_name = ctx
                        .get_function_name()
                        .unwrap_or_else(|| "<unknown>".to_string());
                    eprintln!(
                        "[regs][depth {}][{}] R{}: {:?} -> {:?}",
                        ctx.get_call_depth(),
                        fn_name,
                        idx,
                        old,
                        new
                    );
                    Ok(())
                }
                _ => Ok(()),
            },
            0,
        );
    }

    if trace_stack {
        vm.register_hook(
            |event| {
                matches!(
                    event,
                    HookEvent::BeforeFunctionCall(_, _)
                        | HookEvent::AfterFunctionCall(_, _)
                        | HookEvent::StackPush(_)
                        | HookEvent::StackPop(_)
                )
            },
            |event, ctx: &HookContext| match event {
                HookEvent::BeforeFunctionCall(func, args) => {
                    eprintln!(
                        "[stack][depth {}] CALL {:?} with {:?}",
                        ctx.get_call_depth(),
                        func,
                        args
                    );
                    Ok(())
                }
                HookEvent::AfterFunctionCall(func, ret) => {
                    eprintln!(
                        "[stack][depth {}] RET  {:?} => {:?}",
                        ctx.get_call_depth(),
                        func,
                        ret
                    );
                    Ok(())
                }
                HookEvent::StackPush(v) => {
                    let fn_name = ctx
                        .get_function_name()
                        .unwrap_or_else(|| "<unknown>".to_string());
                    eprintln!(
                        "[stack][depth {}][{}] PUSH {:?}",
                        ctx.get_call_depth(),
                        fn_name,
                        v
                    );
                    Ok(())
                }
                HookEvent::StackPop(v) => {
                    let fn_name = ctx
                        .get_function_name()
                        .unwrap_or_else(|| "<unknown>".to_string());
                    eprintln!(
                        "[stack][depth {}][{}] POP  {:?}",
                        ctx.get_call_depth(),
                        fn_name,
                        v
                    );
                    Ok(())
                }
                _ => Ok(()),
            },
            0,
        );
    }

    // If in party mode, configure MPC engine based on selected backend
    if let Some(net) = net_opt.clone() {
        let my_id = party_id.unwrap_or(0usize);
        // Use session parameters (already agreed upon with bootnode)
        let n = session_n_parties.unwrap_or_else(|| net.parties().len());
        let t = session_threshold.unwrap_or(1);
        // Use the session instance_id (agreed with all parties via bootnode)
        let instance_id =
            session_instance_id.expect("session instance_id should be set in party mode");

        eprintln!(
            "[party {}] Creating MPC engine (backend={}): instance_id={}, n={}, t={}",
            my_id,
            backend_kind.name(),
            instance_id,
            n,
            t
        );

        // Debug: print established connections (server connections are to other MPC parties)
        let connections = net.get_all_server_connections();
        let conn_ids: Vec<_> = connections.iter().map(|(id, _)| *id).collect();
        eprintln!(
            "[party {}] Connections before MPC: {:?} ({} total)",
            my_id,
            conn_ids,
            connections.len()
        );

        match backend_kind {
            #[cfg(feature = "honeybadger")]
            MpcBackendKind::HoneyBadger => {
                let hb_setup_result = match curve_config {
                    MpcCurveConfig::Bls12_381 => {
                        setup_hb_party_for_curve::<ark_bls12_381::Fr, ark_bls12_381::G1Projective>(
                            &mut vm,
                            net.clone(),
                            my_id,
                            n,
                            t,
                            instance_id,
                            expected_client_count,
                        )
                        .await
                    }
                    MpcCurveConfig::Bn254 => {
                        setup_hb_party_for_curve::<ark_bn254::Fr, ark_bn254::G1Projective>(
                            &mut vm,
                            net.clone(),
                            my_id,
                            n,
                            t,
                            instance_id,
                            expected_client_count,
                        )
                        .await
                    }
                    MpcCurveConfig::Curve25519 => {
                        setup_hb_party_for_curve::<
                            ark_curve25519::Fr,
                            ark_curve25519::EdwardsProjective,
                        >(
                            &mut vm,
                            net.clone(),
                            my_id,
                            n,
                            t,
                            instance_id,
                            expected_client_count,
                        )
                        .await
                    }
                    MpcCurveConfig::Ed25519 => {
                        setup_hb_party_for_curve::<ark_ed25519::Fr, ark_ed25519::EdwardsProjective>(
                            &mut vm,
                            net.clone(),
                            my_id,
                            n,
                            t,
                            instance_id,
                            expected_client_count,
                        )
                        .await
                    }
                };

                if let Err(e) = hb_setup_result {
                    eprintln!("[party {}] HoneyBadger setup failed: {}", my_id, e);
                    exit(13);
                }

                eprintln!(
                    "[party {}] HoneyBadger MPC engine set, starting VM execution...",
                    my_id
                );
            }

            #[cfg(feature = "avss")]
            MpcBackendKind::Avss => {
                eprintln!(
                    "[party {}] Setting up AVSS backend (curve: {})...",
                    my_id,
                    curve_config.name()
                );

                // Macro to avoid duplicating AVSS setup for each curve
                macro_rules! setup_avss {
                    ($server_type:ty) => {{
                        let mut avss_server = <$server_type>::new(
                            my_id,
                            n,
                            t,
                            instance_id,
                            (*net).clone(),
                            AvssQuicConfig::default(),
                        );

                        // Start the server (converts network builder to Arc)
                        let _avss_net = match avss_server.start() {
                            Ok(n) => n,
                            Err(e) => {
                                eprintln!("[party {}] Failed to start AVSS server: {}", my_id, e);
                                exit(13);
                            }
                        };

                        // Ensure server lifecycle mirrors HoneyBadger setup.
                        if let Err(e) = avss_server.connect_to_peers().await {
                            eprintln!("[party {}] Failed to connect AVSS peers: {}", my_id, e);
                            exit(13);
                        }

                        // Exchange ECDH public keys
                        eprintln!("[party {}] Exchanging ECDH public keys...", my_id);
                        match avss_server.exchange_public_keys().await {
                            Ok(pk_map) => {
                                eprintln!(
                                    "[party {}] PK exchange complete ({} keys collected)",
                                    my_id,
                                    pk_map.len()
                                );
                            }
                            Err(e) => {
                                eprintln!("[party {}] PK exchange failed: {}", my_id, e);
                                exit(14);
                            }
                        }

                        // Create AVSS engine
                        let engine = match avss_server.create_engine().await {
                            Ok(e) => e,
                            Err(e) => {
                                eprintln!("[party {}] Failed to create AVSS engine: {}", my_id, e);
                                exit(14);
                            }
                        };

                        // Start the engine
                        if let Err(e) = engine.start_async().await {
                            eprintln!("[party {}] Failed to start AVSS engine: {}", my_id, e);
                            exit(14);
                        }

                        // Spawn AVSS message receive/process loops
                        if let Err(e) = avss_server.spawn_message_loops(engine.clone()).await {
                            eprintln!("[party {}] Failed to spawn message loops: {}", my_id, e);
                            exit(14);
                        }

                        vm.state.set_mpc_engine(engine);
                    }};
                }

                match curve_config {
                    MpcCurveConfig::Bls12_381 => setup_avss!(Bls12381AvssServer),
                    MpcCurveConfig::Bn254 => setup_avss!(Bn254AvssServer),
                    MpcCurveConfig::Curve25519 => setup_avss!(Curve25519AvssServer),
                    MpcCurveConfig::Ed25519 => setup_avss!(Ed25519AvssServer),
                }

                eprintln!(
                    "[party {}] AVSS engine set, starting VM execution...",
                    my_id
                );
            }
        }
    }

    eprintln!("Starting VM execution of '{}'...", agreed_entry);

    // Execute entry function
    match vm.execute(&agreed_entry) {
        Ok(result) => {
            println!("Program returned: {:?}", result);
        }
        Err(err) => {
            eprintln!("Execution error in '{}': {}", agreed_entry, err);
            exit(4);
        }
    }
}

fn print_usage_and_exit() -> ! {
    eprintln!(
        r#"Stoffel VM Runner

Usage:
  stoffel-run <path-to-compiled-binary> [entry_function] [flags]

Flags:
  --trace-instr           Trace instructions before/after execution
  --trace-regs            Trace register reads/writes
  --trace-stack           Trace function calls and stack push/pop
  --bootnode              Run as bootnode only (coordinates party discovery)
  --leader                Run as leader: bootnode + party 0 in one process
  --client                Run as client (provide inputs to MPC network)
  --bind <addr:port>      Bind address for bootnode or party listen
  --party-id <usize>      Party id (party mode, 0-indexed)
  --bootstrap <addr:port> Bootnode address (party mode or client mode)
  --n-parties <usize>     Number of parties for MPC (required in party/leader/client mode)
  --threshold <usize>     Threshold t (default: 1)
  --mpc-backend <name>    MPC backend: honeybadger (default) or avss
  --mpc-curve <name>      MPC curve: bls12-381 (default), bn254, curve25519, ed25519
  --inputs <values>       Comma-separated input values (client mode)
  --servers <addrs>       Comma-separated server addresses (client mode)
  --expected-client-count <n>
                          Number of client inputs to collect before starting computation
                          (HoneyBadger only; ALPN handles routing, this controls coordination)
  -h, --help              Show this help

Required environment:
  STOFFEL_AUTH_TOKEN      Shared secret required by bootnode and all parties for
                          authenticated discovery registration

Multi-Party Execution:
  In party mode, all parties register with the bootnode and wait until
  all n-parties have joined. The bootnode then broadcasts a session with
  a shared instance_id to all parties, ensuring they all use the same
  MPC configuration.

  Use --leader on one party to have it also run the bootnode. This reduces
  the number of processes needed by one.

Examples:
  # Local execution (no MPC)
  stoffel-run program.stfbin
  stoffel-run program.stfbin main --trace-instr

  # Multi-party execution (5 parties, threshold 1) - Leader mode (recommended)
  # Terminal 1: Leader (bootnode + party 0)
  STOFFEL_AUTH_TOKEN=replace-with-random-secret \
  stoffel-run program.stfbin main --leader --bind 127.0.0.1:9000 --n-parties 5 --threshold 1

  # Terminals 2-5: Other parties
  STOFFEL_AUTH_TOKEN=replace-with-random-secret \
  stoffel-run program.stfbin main --party-id 1 --bootstrap 127.0.0.1:9000 --bind 127.0.0.1:9002 --n-parties 5 --threshold 1
  STOFFEL_AUTH_TOKEN=replace-with-random-secret \
  stoffel-run program.stfbin main --party-id 2 --bootstrap 127.0.0.1:9000 --bind 127.0.0.1:9003 --n-parties 5 --threshold 1
  STOFFEL_AUTH_TOKEN=replace-with-random-secret \
  stoffel-run program.stfbin main --party-id 3 --bootstrap 127.0.0.1:9000 --bind 127.0.0.1:9004 --n-parties 5 --threshold 1
  STOFFEL_AUTH_TOKEN=replace-with-random-secret \
  stoffel-run program.stfbin main --party-id 4 --bootstrap 127.0.0.1:9000 --bind 127.0.0.1:9005 --n-parties 5 --threshold 1

  # Alternative: Separate bootnode (6 processes total)
  # Terminal 1: Bootnode only
  STOFFEL_AUTH_TOKEN=replace-with-random-secret \
  stoffel-run --bootnode --bind 127.0.0.1:9000 --n-parties 5

  # Terminals 2-6: All parties
  STOFFEL_AUTH_TOKEN=replace-with-random-secret \
  stoffel-run program.stfbin main --party-id 0 --bootstrap 127.0.0.1:9000 --bind 127.0.0.1:9001 --n-parties 5 --threshold 1
  STOFFEL_AUTH_TOKEN=replace-with-random-secret \
  stoffel-run program.stfbin main --party-id 1 --bootstrap 127.0.0.1:9000 --bind 127.0.0.1:9002 --n-parties 5 --threshold 1
  # ... etc

  # Multi-party execution with client inputs (transport-derived IDs)
  # Terminal 1: Leader with expected client count
  stoffel-run program.stfbin main --leader --bind 127.0.0.1:9000 --n-parties 5 --threshold 1 --expected-client-count 2

  # Terminals 2-5: Other parties (same expected-client-count)
  stoffel-run program.stfbin main --party-id 1 --bootstrap 127.0.0.1:9000 --bind 127.0.0.1:9002 --n-parties 5 --expected-client-count 2
  # ... etc

  # Client mode: provide inputs to the MPC network
  # Note: clients connect directly to party servers, not the bootnode
  stoffel-run --client --inputs 10,20 --servers 127.0.0.1:10000,127.0.0.1:9002,127.0.0.1:9003,127.0.0.1:9004,127.0.0.1:9005 --n-parties 5
  stoffel-run --client --inputs 30,40 --servers 127.0.0.1:10000,127.0.0.1:9002,127.0.0.1:9003,127.0.0.1:9004,127.0.0.1:9005 --n-parties 5

  # Docker example with client inputs:
  # Start parties with expected-client-count:
  # docker run ... -e STOFFEL_EXPECTED_CLIENT_COUNT=2 stoffelvm:latest
  # Then run clients connecting to the party servers:
  stoffel-run --client --inputs 42 --servers 172.18.0.2:9000,172.18.0.3:9000,172.18.0.4:9000,172.18.0.5:9000,172.18.0.6:9000 --n-parties 5
"#
    );
    exit(1);
}
