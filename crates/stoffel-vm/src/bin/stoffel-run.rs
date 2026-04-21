use std::env;
use std::fs;
use std::net::SocketAddr;
use std::process::exit;
use std::str::FromStr;

use alloy::signers::local::PrivateKeySigner;
use alloy_primitives::Address;
#[cfg(any(feature = "honeybadger", feature = "avss"))]
use ark_ec::{CurveGroup, PrimeGroup};
#[cfg(any(feature = "honeybadger", feature = "avss"))]
use ark_ff::PrimeField;
#[cfg(any(feature = "honeybadger", feature = "avss"))]
use serde::{Deserialize, Serialize};
#[cfg(any(feature = "honeybadger", feature = "avss"))]
use std::collections::HashSet;
use std::fs::File;
use std::sync::Arc;
use std::time::Duration;
use stoffel_mpc_coordinator::off_chain::node_rpc::{NodeRPCClient, NodeRPCServer};
use stoffel_mpc_coordinator::off_chain::OffChainCoordinator;
use stoffel_mpc_coordinator::on_chain;
use stoffel_mpc_coordinator::Coordinator;
use stoffel_vm::core_vm::VirtualMachine;
#[cfg(any(feature = "honeybadger", feature = "avss"))]
use stoffel_vm::net::curve::SupportedMpcField;
#[cfg(feature = "honeybadger")]
use stoffel_vm::net::hb_engine::HoneyBadgerMpcEngine;
#[cfg(feature = "honeybadger")]
use stoffel_vm::net::{honeybadger_node_opts, spawn_receive_loops_split};
use stoffel_vm::net::{
    program_id_from_bytes, register_and_wait_for_session_with_program, run_bootnode_with_config,
};
use stoffel_vm::net::{MpcBackendKind, MpcCurveConfig};
use stoffel_vm::runtime_hooks::{HookContext, HookEvent};
use stoffel_vm_types::compiled_binary::CompiledBinary;
use stoffel_vm_types::core_types::Value;
#[cfg(any(feature = "honeybadger", feature = "avss"))]
use stoffelmpc_mpc::common::rbc::rbc::Avid;
#[cfg(any(feature = "honeybadger", feature = "avss"))]
use stoffelmpc_mpc::common::MPCProtocol;
#[cfg(feature = "honeybadger")]
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
#[cfg(feature = "honeybadger")]
use stoffelmpc_mpc::honeybadger::SessionId as HbSessionId;
#[cfg(feature = "honeybadger")]
use stoffelmpc_mpc::honeybadger::{HoneyBadgerMPCClient, HoneyBadgerMPCNode};
#[cfg(any(feature = "honeybadger", feature = "avss"))]
use stoffelnet::network_utils::ClientId;
use stoffelnet::network_utils::Network;
use stoffelnet::transports::quic::{NetworkManager, QuicNetworkManager};
use tokio::sync::mpsc;
use x509_parser::prelude::*;

fn extract_pubkey_from_cert(cert_der: &[u8]) -> Vec<u8> {
    let (_, parsed) = X509Certificate::from_der(cert_der).expect("parse X.509 cert");
    parsed
        .public_key()
        .subject_public_key
        .data
        .as_ref()
        .to_vec()
}

/// Network adapter for MPC clients that remaps party IDs from 5-space (0..n-1)
/// to 6-space (0..n with client's position excluded).
///
/// The client's QuicNetworkManager includes the client's own public key in the
/// sorted key list, creating n+1 entries. The MPC protocol expects n parties.
/// This wrapper adjusts send() to skip the client's own position.
#[cfg(feature = "honeybadger")]
struct ClientNetworkAdapter {
    inner: QuicNetworkManager,
    /// The client's position in the (n+1)-key sorted list
    local_position: usize,
}

#[cfg(feature = "honeybadger")]
#[async_trait::async_trait]
impl Network for ClientNetworkAdapter {
    type NodeType = <QuicNetworkManager as Network>::NodeType;
    type NetworkConfig = <QuicNetworkManager as Network>::NetworkConfig;

    async fn send(
        &self,
        recipient: stoffelnet::network_utils::PartyId,
        message: &[u8],
    ) -> Result<usize, stoffelnet::network_utils::NetworkError> {
        // Remap: 5-space party_id → 6-space position (skip our own slot)
        let mapped = if recipient >= self.local_position {
            recipient + 1
        } else {
            recipient
        };
        self.inner.send(mapped, message).await
    }

    async fn broadcast(
        &self,
        message: &[u8],
    ) -> Result<usize, stoffelnet::network_utils::NetworkError> {
        // Must remap each party_id through our send() to skip the client's own
        // slot in the 6-key sorted list. Using inner.broadcast() directly would
        // iterate over 6 positions (including self) with wrong party mapping.
        let n = self.party_count();
        let mut total = 0usize;
        for party_id in 0..n {
            match self.send(party_id, message).await {
                Ok(bytes) => total += bytes,
                Err(e) => {
                    tracing::debug!("client broadcast to party {} failed: {:?}", party_id, e);
                }
            }
        }
        Ok(total)
    }

    fn parties(&self) -> Vec<&Self::NodeType> {
        self.inner.parties()
    }

    fn parties_mut(&mut self) -> Vec<&mut Self::NodeType> {
        self.inner.parties_mut()
    }

    fn config(&self) -> &Self::NetworkConfig {
        self.inner.config()
    }

    fn node(&self, id: stoffelnet::network_utils::PartyId) -> Option<&Self::NodeType> {
        self.inner.node(id)
    }

    fn node_mut(&mut self, id: stoffelnet::network_utils::PartyId) -> Option<&mut Self::NodeType> {
        self.inner.node_mut(id)
    }

    async fn send_to_client(
        &self,
        client: ClientId,
        message: &[u8],
    ) -> Result<usize, stoffelnet::network_utils::NetworkError> {
        self.inner.send_to_client(client, message).await
    }

    fn clients(&self) -> Vec<ClientId> {
        self.inner.clients()
    }

    fn is_client_connected(&self, client: ClientId) -> bool {
        self.inner.is_client_connected(client)
    }

    fn local_party_id(&self) -> stoffelnet::network_utils::PartyId {
        self.inner.local_party_id()
    }

    fn party_count(&self) -> usize {
        // Return n (not n+1) — exclude the client from the party count
        self.inner.party_count().saturating_sub(1)
    }

    fn verified_ordering(&self) -> Option<stoffelnet::network_utils::VerifiedOrdering> {
        self.inner.verified_ordering()
    }
}

/// Network adapter for MPC servers that remaps sequential client indices
/// (0, 1, ...) back to transport-derived client IDs for send_to_client().
/// The MPC protocol uses small indices (because session_id only has 8 bits),
/// but the network layer needs transport-derived IDs to route messages.
#[cfg(any(feature = "honeybadger", feature = "avss"))]
struct ServerClientAdapter {
    inner: Arc<QuicNetworkManager>,
    /// Maps sequential index → transport-derived client ID
    client_id_map: Vec<ClientId>,
}

#[cfg(any(feature = "honeybadger", feature = "avss"))]
#[async_trait::async_trait]
impl Network for ServerClientAdapter {
    type NodeType = <QuicNetworkManager as Network>::NodeType;
    type NetworkConfig = <QuicNetworkManager as Network>::NetworkConfig;

    async fn send(
        &self,
        recipient: stoffelnet::network_utils::PartyId,
        message: &[u8],
    ) -> Result<usize, stoffelnet::network_utils::NetworkError> {
        self.inner.send(recipient, message).await
    }

    async fn broadcast(
        &self,
        message: &[u8],
    ) -> Result<usize, stoffelnet::network_utils::NetworkError> {
        self.inner.broadcast(message).await
    }

    fn parties(&self) -> Vec<&Self::NodeType> {
        self.inner.parties()
    }

    fn parties_mut(&mut self) -> Vec<&mut Self::NodeType> {
        // Safety: we hold Arc, can't get &mut easily; the MPC protocol
        // never calls this on the server adapter.
        unimplemented!("parties_mut not needed for server client adapter")
    }

    fn config(&self) -> &Self::NetworkConfig {
        self.inner.config()
    }

    fn node(&self, id: stoffelnet::network_utils::PartyId) -> Option<&Self::NodeType> {
        self.inner.node(id)
    }

    fn node_mut(&mut self, _id: stoffelnet::network_utils::PartyId) -> Option<&mut Self::NodeType> {
        unimplemented!("node_mut not needed for server client adapter")
    }

    async fn send_to_client(
        &self,
        client: ClientId,
        message: &[u8],
    ) -> Result<usize, stoffelnet::network_utils::NetworkError> {
        // Remap sequential index → transport-derived client ID
        let transport_id = self.client_id_map.get(client).copied().unwrap_or(client);
        self.inner.send_to_client(transport_id, message).await
    }

    fn clients(&self) -> Vec<ClientId> {
        self.inner.clients()
    }

    fn is_client_connected(&self, client: ClientId) -> bool {
        let transport_id = self.client_id_map.get(client).copied().unwrap_or(client);
        self.inner.is_client_connected(transport_id)
    }

    fn local_party_id(&self) -> stoffelnet::network_utils::PartyId {
        self.inner.local_party_id()
    }

    fn party_count(&self) -> usize {
        self.inner.party_count()
    }

    fn verified_ordering(&self) -> Option<stoffelnet::network_utils::VerifiedOrdering> {
        self.inner.verified_ordering()
    }
}

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

#[cfg(any(feature = "honeybadger", feature = "avss"))]
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
#[cfg(any(feature = "honeybadger", feature = "avss"))]
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

#[cfg(any(feature = "honeybadger", feature = "avss"))]
const CLIENT_SET_SYNC_PREFIX: &[u8; 4] = b"CSS1";

#[cfg(any(feature = "honeybadger", feature = "avss"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClientSetSyncMessage {
    sender_party_id: usize,
    client_ids: Vec<ClientId>,
}

#[cfg(any(feature = "honeybadger", feature = "avss"))]
fn normalize_client_ids(mut ids: Vec<ClientId>) -> Vec<ClientId> {
    ids.sort_unstable();
    ids.dedup();
    ids
}

#[cfg(any(feature = "honeybadger", feature = "avss"))]
fn encode_client_set_sync(msg: &ClientSetSyncMessage) -> Result<Vec<u8>, String> {
    let payload = bincode::serialize(msg)
        .map_err(|e| format!("Failed to serialize client-set sync payload: {}", e))?;
    let mut out = Vec::with_capacity(CLIENT_SET_SYNC_PREFIX.len() + payload.len());
    out.extend_from_slice(CLIENT_SET_SYNC_PREFIX);
    out.extend_from_slice(&payload);
    Ok(out)
}

#[cfg(any(feature = "honeybadger", feature = "avss"))]
fn decode_client_set_sync(bytes: &[u8]) -> Result<ClientSetSyncMessage, String> {
    if bytes.len() < CLIENT_SET_SYNC_PREFIX.len()
        || &bytes[..CLIENT_SET_SYNC_PREFIX.len()] != CLIENT_SET_SYNC_PREFIX
    {
        return Err("Unexpected message prefix while waiting for client-set sync".to_string());
    }

    bincode::deserialize(&bytes[CLIENT_SET_SYNC_PREFIX.len()..])
        .map_err(|e| format!("Failed to deserialize client-set sync payload: {}", e))
}

#[cfg(any(feature = "honeybadger", feature = "avss"))]
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
    _cid: ClientId,
    n: usize,
    t: usize,
    inputs_str: &str,
    input_len: usize,
    instance_id: u64,
    client_index: u8,
    local_position: usize,
    network_for_process: Arc<tokio::sync::Mutex<QuicNetworkManager>>,
    mut msg_rx: mpsc::Receiver<(usize, Vec<u8>)>,
) -> Result<(), String> {
    let instance_id = instance_id as u32;
    // Use the sequential client_index (0, 1, ...) as the MPC identity,
    // not the transport-derived cid, because the session_id only has
    // 8 bits for the client_id field.
    let mpc_cid = client_index as usize;
    let mut mpc_client = HoneyBadgerMPCClient::<F, Avid<HbSessionId>>::new(
        mpc_cid,
        n,
        t,
        instance_id,
        parse_inputs_as_field::<F>(inputs_str),
        input_len,
    )
    .map_err(|e| format!("Failed to create MPC client: {:?}", e))?;

    let mut messages_processed = 0usize;
    while let Some((sender_id, data)) = msg_rx.recv().await {
        // Skip INST messages from other servers (already consumed the first one)
        if data.len() == 13 && data.starts_with(b"INST") {
            eprintln!(
                "[client {}] Skipping extra INST from sender {}",
                mpc_cid, sender_id
            );
            continue;
        }
        eprintln!(
            "[client {}] Received {} bytes from sender {} (raw)",
            mpc_cid,
            data.len(),
            sender_id
        );

        let adapter = {
            let guard = network_for_process.lock().await;
            ClientNetworkAdapter {
                inner: (*guard).clone(),
                local_position,
            }
        };

        match mpc_client.process(sender_id, data, Arc::new(adapter)).await {
            Ok(()) => {
                messages_processed += 1;
                eprintln!(
                    "[client {}] Successfully processed message #{} from server {}",
                    mpc_cid, messages_processed, sender_id
                );
            }
            Err(e) => {
                eprintln!(
                    "[client {}] Failed to process message from {}: {:?}",
                    mpc_cid, sender_id, e
                );
            }
        }

        if messages_processed >= n {
            // Keep connection alive long enough for servers to drain their
            // preprocessing backlog and process our input messages.
            eprintln!(
                "[client {}] Input protocol complete, holding connection for 300s...",
                mpc_cid
            );
            tokio::time::sleep(Duration::from_secs(300)).await;
            break;
        }
    }

    eprintln!(
        "[client {}] Message processing done ({} messages)",
        mpc_cid, messages_processed
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
    instance_id: u64,
    client_index: u8,
    local_position: usize,
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
                instance_id,
                client_index,
                local_position,
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
                instance_id,
                client_index,
                local_position,
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
                instance_id,
                client_index,
                local_position,
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
                instance_id,
                client_index,
                local_position,
                network_for_process,
                msg_rx,
            )
            .await
        }
    }
}

#[cfg(feature = "honeybadger")]
async fn run_as_client(
    n_parties: Option<usize>,
    threshold: Option<usize>,
    mpc_backend: Option<&str>,
    mpc_curve: Option<&str>,
    client_inputs: Option<String>,
    server_addrs: Vec<SocketAddr>,
) {
    let n = n_parties.unwrap_or_else(|| {
        eprintln!("Error: --n-parties is required in client mode");
        exit(2);
    });
    let t = threshold.unwrap_or(1);

    if let Some(backend_name) = mpc_backend {
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

    let inputs_str = client_inputs.unwrap_or_else(|| {
        eprintln!("Error: --inputs is required in client mode (comma-separated values)");
        exit(2);
    });
    let input_len = inputs_str.split(',').count();

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

    let curve_config = if let Some(name) = mpc_curve {
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

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install rustls crypto");

    let network = Arc::new(tokio::sync::Mutex::new(QuicNetworkManager::new()));

    for (party_id, &addr) in server_addrs.iter().enumerate() {
        network.lock().await.add_node_with_party_id(party_id, addr);
        eprintln!("[client] Added server party {} at {}", party_id, addr);
    }

    let (msg_tx, mut msg_rx) = mpsc::channel::<(usize, Vec<u8>)>(1000);

    eprintln!("[client] Connecting to {} servers...", server_addrs.len());
    connect_to_all_servers(&network, &server_addrs, msg_tx.clone()).await;

    let cid = {
        let net = network.lock().await;
        net.local_derived_id()
    };
    eprintln!("[client {}] Derived transport client ID", cid);

    // Read INST message from servers: [b"INST" | instance_id:u64 | client_index:u8]
    let (instance_id, client_index) = {
        let timeout_dur = Duration::from_secs(600);
        let mut result: Option<(u64, u8)> = None;
        let deadline = tokio::time::Instant::now() + timeout_dur;
        while result.is_none() {
            match tokio::time::timeout_at(deadline, msg_rx.recv()).await {
                Ok(Some((_sender, data))) => {
                    if data.len() == 13 && &data[0..4] == b"INST" {
                        let id_bytes: [u8; 8] = data[4..12].try_into().unwrap();
                        let inst_id = u64::from_le_bytes(id_bytes);
                        let idx = data[12];
                        result = Some((inst_id, idx));
                    }
                    // If not an INST message, discard
                }
                Ok(None) => {
                    eprintln!("[client {}] Channel closed before receiving INST", cid);
                    exit(25);
                }
                Err(_) => {
                    eprintln!("[client {}] Timeout waiting for INST from server", cid);
                    exit(25);
                }
            }
        }
        let (id, idx) = result.unwrap();
        eprintln!(
            "[client {}] Received INST: instance_id={}, client_index={}",
            cid, id, idx
        );
        (id, idx)
    };

    eprintln!(
        "[client {}] Connected to all servers, starting input protocol...",
        cid
    );

    // Get the client's position in the (n+1)-key sorted list so we can
    // remap party IDs when sending (skip our own slot).
    let local_position = {
        let net = network.lock().await;
        net.compute_local_party_id().unwrap_or(0)
    };
    eprintln!(
        "[client {}] Local position in sorted key list: {}",
        cid, local_position
    );

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
            instance_id,
            client_index,
            local_position,
            network_for_process,
            msg_rx,
        )
        .await
    });

    let timeout_duration = Duration::from_secs(600);
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
) -> Result<Arc<HoneyBadgerMpcEngine<F, G>>, String>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    // ---- Phase 1: Wait for clients ----
    let mut input_ids: Vec<ClientId> = Vec::new();

    if let Some(expected_count) = expected_client_count {
        if expected_count == 0 {
            return Err("--wait-for-clients count must be greater than 0".to_string());
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

        let connect_timeout = Duration::from_secs(600);
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

    // ---- Phase 2: Setup MPC node and preprocess ----
    //
    // CRITICAL: We use exactly TWO clones of the MPC node to avoid the
    // double-processing bug where init_ransha() is called multiple times:
    //   - Clone 1 (`processing_node`): handles incoming messages via process()
    //   - Clone 2 (inside `engine`): initiates preprocessing via run_preprocessing()
    // Both share the same Arc<Mutex> stores, but only ONE processes each message.
    let n_triples = 1;
    let n_random = 4;
    eprintln!(
        "[party {}] Creating MPC node opts (n_triples={}, n_random={}, timeout=600s)",
        my_id, n_triples, n_random
    );
    let mpc_opts =
        honeybadger_node_opts(n, t, n_triples, n_random, instance_id).unwrap_or_else(|e| {
            eprintln!("Failed to create MPC node options: {}", e);
            std::process::exit(2);
        });

    // Use sequential indices (0..n_clients) as client IDs for the MPC protocol
    // because the session_id only has 8 bits for the client_id field.
    let mpc_input_ids: Vec<ClientId> = (0..input_ids.len()).collect();
    let mpc_node = <HoneyBadgerMPCNode<F, Avid<HbSessionId>> as MPCProtocol<
        F,
        RobustShare<F>,
        QuicNetworkManager,
    >>::setup(my_id, mpc_opts, mpc_input_ids)
    .map_err(|e| format!("Failed to create MPC node: {:?}", e))?;
    eprintln!("[party {}] MPC node setup complete", my_id);

    // Clone 1: the processing node — MOVED into the processing loop task.
    // This is the ONLY clone that calls process() on incoming messages.
    let mut processing_node = mpc_node.clone();

    // Clone 2: the engine node — used for preprocessing initiation only.
    // Created via from_existing_node which wraps it in Arc<Mutex>.
    let open_message_router = Arc::new(stoffel_vm::net::OpenMessageRouter::new());
    let engine = HoneyBadgerMpcEngine::<F, G>::from_existing_node_with_router(
        open_message_router.clone(),
        instance_id,
        my_id,
        n,
        t,
        net.clone(),
        mpc_node, // moved, not cloned
    );

    eprintln!(
        "[party {}] Spawning receive loops (split channels)...",
        my_id
    );
    let (mut server_rx, mut client_rx) =
        spawn_receive_loops_split(net.clone(), my_id, n, open_message_router).await;

    // Remap transport-derived client IDs to sequential indices for the MPC protocol.
    let client_id_to_index: std::collections::HashMap<ClientId, usize> = input_ids
        .iter()
        .enumerate()
        .map(|(idx, &tid)| (tid, idx))
        .collect();

    // Single processing loop using tokio::select! for both server and client messages.
    // Only this task calls process() — no other task touches the processing_node.
    let processing_net = net.clone();
    let process_party_id = my_id;
    tokio::spawn(async move {
        let mut msg_count = 0u64;
        loop {
            tokio::select! {
                Some((sender_id, raw_msg)) = server_rx.recv() => {
                    msg_count += 1;
                    if msg_count <= 5 || msg_count % 1000 == 0 {
                        eprintln!(
                            "[party {}] Processing message #{} from sender {} ({} bytes)",
                            process_party_id, msg_count, sender_id, raw_msg.len()
                        );
                    }
                    if let Err(e) = processing_node
                        .process(sender_id, raw_msg, processing_net.clone())
                        .await
                    {
                        eprintln!(
                            "[party {}] Failed to process message from {}: {:?}",
                            process_party_id, sender_id, e
                        );
                    }
                }
                Some((client_id, raw_msg)) = client_rx.recv() => {
                    // Remap transport client ID → sequential index
                    let mpc_sender_id = client_id_to_index
                        .get(&client_id)
                        .copied()
                        .unwrap_or(client_id);
                    if let Err(e) = processing_node
                        .process(mpc_sender_id, raw_msg, processing_net.clone())
                        .await
                    {
                        eprintln!(
                            "[party {}] Failed to process client message from {} (idx {}): {:?}",
                            process_party_id, client_id, mpc_sender_id, e
                        );
                    }
                }
                else => break,
            }
        }
    });

    // Brief delay to let receive loops discover connections
    tokio::time::sleep(Duration::from_secs(2)).await;

    eprintln!("[party {}] Starting MPC preprocessing...", my_id);
    engine
        .preprocess()
        .await
        .map_err(|e| format!("MPC preprocessing failed: {}", e))?;
    eprintln!("[party {}] MPC preprocessing complete!", my_id);

    if !input_ids.is_empty() {
        let client_index_map: Vec<(usize, ClientId)> = input_ids
            .iter()
            .enumerate()
            .map(|(idx, &tid)| (idx, tid))
            .collect();

        // Create a server-side network adapter that remaps sequential client
        // indices to transport-derived client IDs for send_to_client().
        let server_adapter = Arc::new(ServerClientAdapter {
            inner: net.clone(),
            client_id_map: client_index_map.iter().map(|(_, tid)| *tid).collect(),
        });

        // Access the engine's node for InputServer init
        eprintln!(
            "[party {}] Initializing InputServer for {} clients...",
            my_id,
            client_index_map.len()
        );
        {
            let mut node = engine.node_handle().lock().await;
            for &(idx, _tid) in &client_index_map {
                let local_shares = node
                    .preprocessing_material
                    .lock()
                    .await
                    .take_random_shares(1)
                    .map_err(|e| format!("Not enough random shares for client {}: {:?}", idx, e))?;

                eprintln!(
                    "[party {}] Sending random shares to client index {} (server_id={})",
                    my_id, idx, node.id
                );
                node.preprocess
                    .input
                    .init(idx, local_shares, 1, server_adapter.clone())
                    .await
                    .map_err(|e| {
                        format!("Failed to init InputServer for client {}: {:?}", idx, e)
                    })?;
                eprintln!(
                    "[party {}] InputServer initialized for client index {}",
                    my_id, idx
                );
            }
        }

        // Signal readiness to clients
        eprintln!(
            "[party {}] Sending INST to {} clients...",
            my_id,
            client_index_map.len()
        );
        for &(idx, tid) in &client_index_map {
            let mut inst_msg = Vec::with_capacity(13);
            inst_msg.extend_from_slice(b"INST");
            inst_msg.extend_from_slice(&instance_id.to_le_bytes());
            inst_msg.push(idx as u8);
            if let Err(e) = net.send_to_client(tid, &inst_msg).await {
                eprintln!(
                    "[party {}] Failed to send INST to client {}: {:?}",
                    my_id, tid, e
                );
            }
        }

        eprintln!(
            "[party {}] Waiting for all client inputs (timeout=600s)...",
            my_id
        );
        let client_inputs = {
            let mut node = engine.node_handle().lock().await;
            node.preprocess
                .input
                .wait_for_all_inputs(Duration::from_secs(600))
                .await
                .map_err(|e| format!("Failed to receive client inputs: {:?}", e))?
        };

        for (idx, shares) in client_inputs {
            let transport_cid = client_index_map
                .iter()
                .find(|(i, _)| *i == idx)
                .map(|(_, tid)| *tid)
                .unwrap_or(idx);
            vm.state
                .client_store()
                .store_client_input(transport_cid, shares);
            eprintln!(
                "[party {}] Stored inputs for client {} (index {})",
                my_id, transport_cid, idx
            );
        }
    }

    Ok(engine)
}

#[cfg(feature = "avss")]
async fn setup_avss_party_for_curve<F, G>(
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
    // ---- Phase 1: Wait for clients ----
    let mut input_ids: Vec<ClientId> = Vec::new();

    if let Some(expected_count) = expected_client_count {
        if expected_count == 0 {
            return Err("--wait-for-clients count must be greater than 0".to_string());
        }

        eprintln!(
            "[party {}] Waiting for {} clients (AVSS)...",
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

        let connect_timeout = Duration::from_secs(600);
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

    // ---- Phase 2: ECDH key exchange over existing network ----
    let mpc_input_ids: Vec<ClientId> = (0..input_ids.len()).collect();

    // Generate ECDH key pair for AVSS payload confidentiality
    use ark_std::rand::SeedableRng as _;
    let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
    let sk_i = F::rand(&mut rng);
    let pk_i: G = G::generator() * sk_i;

    // Serialize our public key into an envelope: [party_id: u32][pk_bytes]
    let mut pk_bytes = Vec::new();
    pk_i.serialize_compressed(&mut pk_bytes)
        .map_err(|e| format!("Failed to serialize ECDH public key: {:?}", e))?;
    let mut envelope = Vec::with_capacity(4 + pk_bytes.len());
    envelope.extend_from_slice(&(my_id as u32).to_le_bytes());
    envelope.extend_from_slice(&pk_bytes);

    eprintln!(
        "[party {}] Exchanging ECDH public keys over existing network...",
        my_id
    );

    // Broadcast our PK to all peers via existing connections
    let connections = net.get_all_server_connections();
    for (peer_id, conn) in &connections {
        if *peer_id == my_id {
            continue;
        }
        if let Err(e) = conn.send(&envelope).await {
            eprintln!(
                "[party {}] Failed to send PK to peer {}: {}",
                my_id, peer_id, e
            );
        }
    }

    // Collect PKs from all peers
    let mut pk_map: Vec<G> = vec![G::default(); n];
    pk_map[my_id] = pk_i;
    let mut received = 1usize;
    let mut seen = std::collections::HashSet::new();
    seen.insert(my_id);

    let (pk_tx, mut pk_rx) = tokio::sync::mpsc::channel::<(usize, Vec<u8>)>(n);

    for (peer_id, conn) in &connections {
        if *peer_id == my_id {
            continue;
        }
        let peer_id = *peer_id;
        let tx = pk_tx.clone();
        let conn = conn.clone();
        tokio::spawn(async move {
            match conn.receive().await {
                Ok(data) => {
                    let _ = tx.send((peer_id, data)).await;
                }
                Err(e) => {
                    eprintln!("[AVSS] Failed to receive PK from peer {}: {}", peer_id, e);
                }
            }
        });
    }
    drop(pk_tx);

    let pk_deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    while received < n {
        let remaining = pk_deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, pk_rx.recv()).await {
            Ok(Some((_peer_id, data))) => {
                if data.len() < 4 {
                    continue;
                }
                let sender_id = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
                if sender_id >= n || !seen.insert(sender_id) {
                    continue;
                }
                match G::deserialize_compressed(&data[4..]) {
                    Ok(pk) => {
                        pk_map[sender_id] = pk;
                        received += 1;
                        eprintln!(
                            "[party {}] Received PK from party {} ({}/{})",
                            my_id, sender_id, received, n
                        );
                    }
                    Err(e) => {
                        eprintln!(
                            "[party {}] Failed to deserialize PK from party {}: {:?}",
                            my_id, sender_id, e
                        );
                    }
                }
            }
            Ok(None) => break,
            Err(_) => {
                return Err(format!(
                    "Timeout during PK exchange: received {}/{} keys",
                    received, n
                ));
            }
        }
    }

    if received < n {
        return Err(format!(
            "PK exchange incomplete: received {}/{} keys",
            received, n
        ));
    }
    eprintln!("[party {}] PK exchange complete ({} keys)", my_id, n);

    let pk_map = Arc::new(pk_map);

    // ---- Phase 3: Create engine directly with existing network ----
    use stoffel_vm::net::avss_engine::AvssMpcEngine;
    let engine = AvssMpcEngine::<F, G>::new(
        instance_id,
        my_id,
        n,
        t,
        net.clone(),
        sk_i,
        pk_map,
        mpc_input_ids,
    )
    .await
    .map_err(|e| format!("Failed to create AVSS engine: {}", e))?;

    engine
        .start_async()
        .await
        .map_err(|e| format!("Failed to start AVSS engine: {}", e))?;

    // ---- Phase 4: Spawn message loops on existing connections ----
    // Server message loops
    let (msg_tx, _server_rx) = tokio::sync::mpsc::channel::<(usize, Vec<u8>)>(65536);
    let (client_tx, mut client_rx) = tokio::sync::mpsc::channel::<(usize, Vec<u8>)>(4096);

    for (peer_id, conn) in &connections {
        if *peer_id == my_id {
            continue;
        }
        let peer_id = *peer_id;
        let engine = engine.clone();
        let open_message_router = engine.open_message_router();
        let tx = msg_tx.clone();
        let conn = conn.clone();
        let net_clone = net.clone();
        let authenticated_sender_id = conn.remote_party_id().unwrap_or(peer_id);
        tokio::spawn(async move {
            loop {
                match conn.receive().await {
                    Ok(data) => {
                        if let Ok(true) = open_message_router
                            .try_handle_wire_message(authenticated_sender_id, &data)
                        {
                            continue;
                        }
                        if let Ok(true) = open_message_router
                            .try_handle_avss_open_exp_wire_message(authenticated_sender_id, &data)
                        {
                            continue;
                        }
                        if let Ok(true) = open_message_router
                            .try_handle_avss_g2_exp_wire_message(authenticated_sender_id, &data)
                        {
                            continue;
                        }
                        if let Err(e) = engine
                            .process_wrapped_message_with_network(
                                authenticated_sender_id,
                                &data,
                                net_clone.clone(),
                            )
                            .await
                        {
                            let _ = tx.send((authenticated_sender_id, data)).await;
                            if !e.contains("deserialize") && !e.contains("process failed") {
                                eprintln!(
                                    "[AVSS] Party failed to process message from {}: {}",
                                    authenticated_sender_id, e
                                );
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    }

    // Client connection monitor
    let client_net = net.clone();
    tokio::spawn(async move {
        let mut spawned = std::collections::HashSet::new();
        loop {
            for (cid, conn) in client_net.get_all_client_connections() {
                if !spawned.insert(cid) {
                    continue;
                }
                let txx = client_tx.clone();
                tokio::spawn(async move {
                    loop {
                        match conn.receive().await {
                            Ok(data) => {
                                if txx.send((cid, data)).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    // Route client messages through the AVSS node's process()
    if !input_ids.is_empty() {
        let client_id_to_index: std::collections::HashMap<ClientId, usize> = input_ids
            .iter()
            .enumerate()
            .map(|(idx, &tid)| (tid, idx))
            .collect();

        let processing_engine = engine.clone();
        let processing_net = net.clone();
        tokio::spawn(async move {
            while let Some((client_id, raw_msg)) = client_rx.recv().await {
                let mpc_sender_id = client_id_to_index
                    .get(&client_id)
                    .copied()
                    .unwrap_or(client_id);
                if let Err(e) = processing_engine
                    .process_wrapped_message_with_network(
                        mpc_sender_id,
                        &raw_msg,
                        processing_net.clone(),
                    )
                    .await
                {
                    eprintln!(
                        "[party {}] Failed to process client message from {} (idx {}): {:?}",
                        processing_engine.party_id(),
                        client_id,
                        mpc_sender_id,
                        e
                    );
                }
            }
        });
    }

    // ---- Phase 5: Preprocessing ----
    tokio::time::sleep(Duration::from_secs(2)).await;
    eprintln!("[party {}] Starting AVSS preprocessing...", my_id);
    engine.preprocess().await?;
    eprintln!("[party {}] AVSS preprocessing complete!", my_id);

    // ---- Phase 6: Client input initialization ----
    if !input_ids.is_empty() {
        let client_index_map: Vec<(usize, ClientId)> = input_ids
            .iter()
            .enumerate()
            .map(|(idx, &tid)| (idx, tid))
            .collect();

        let server_adapter = Arc::new(ServerClientAdapter {
            inner: net.clone(),
            client_id_map: client_index_map.iter().map(|(_, tid)| *tid).collect(),
        });

        eprintln!(
            "[party {}] Initializing AVSS InputServer for {} clients...",
            my_id,
            client_index_map.len()
        );
        {
            let mut node = engine.node_handle().lock().await;
            for &(idx, _tid) in &client_index_map {
                let local_shares = node
                    .preprocessing_material
                    .lock()
                    .await
                    .take_v_random_shares(1)
                    .map_err(|e| format!("Not enough random shares for client {}: {:?}", idx, e))?;

                node.input_server
                    .init(idx, local_shares, 1, server_adapter.clone())
                    .await
                    .map_err(|e| {
                        format!("Failed to init InputServer for client {}: {:?}", idx, e)
                    })?;
                eprintln!(
                    "[party {}] InputServer initialized for client index {}",
                    my_id, idx
                );
            }
        }

        // Signal readiness to clients
        eprintln!(
            "[party {}] Sending INST to {} clients...",
            my_id,
            client_index_map.len()
        );
        for &(idx, tid) in &client_index_map {
            let mut inst_msg = Vec::with_capacity(13);
            inst_msg.extend_from_slice(b"INST");
            inst_msg.extend_from_slice(&instance_id.to_le_bytes());
            inst_msg.push(idx as u8);
            if let Err(e) = net.send_to_client(tid, &inst_msg).await {
                eprintln!(
                    "[party {}] Failed to send INST to client {}: {:?}",
                    my_id, tid, e
                );
            }
        }

        // Wait for all client inputs
        eprintln!(
            "[party {}] Waiting for all client inputs (timeout=600s)...",
            my_id
        );
        let client_inputs = {
            let mut node = engine.node_handle().lock().await;
            node.input_server
                .wait_for_all_inputs(Duration::from_secs(600))
                .await
                .map_err(|e| format!("Failed to receive client inputs: {:?}", e))?
        };

        for (idx, shares) in client_inputs {
            let transport_cid = client_index_map
                .iter()
                .find(|(i, _)| *i == idx)
                .map(|(_, tid)| *tid)
                .unwrap_or(idx);
            vm.state
                .client_store()
                .store_client_input_feldman(transport_cid, shares);
            eprintln!(
                "[party {}] Stored inputs for client {} (index {})",
                my_id, transport_cid, idx
            );
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

    let path_opt: Option<String>;
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
    let mut _enable_nat: bool = false;
    let mut _stun_servers: Vec<SocketAddr> = Vec::new();
    let mut server_addrs: Vec<SocketAddr> = Vec::new();
    let mut mpc_backend: Option<String> = None;
    let mut mpc_curve: Option<String> = None;
    let mut rpc_addr: Option<(String, u16)> = None;
    let mut coord_addr: Option<(String, u16)> = None;
    let mut key_der: Option<Vec<u8>> = None;
    let mut cert_der: Option<Vec<u8>> = None;
    let mut timestamp: Option<u64> = None;
    let mut expected_clients: Vec<String> = Vec::new();
    let mut eth_node_addr: Option<String> = None;
    let mut wallet_sk_str: Option<String> = None;
    let mut contract_addr: Option<Address> = None;
    let mut node_ids: Vec<Address> = Vec::new();

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
            _enable_nat = true;
        } else if let Some(_rest) = arg.strip_prefix("--bind") {
            // support "--bind" and "--bind=.."
            // actual value parsed later from positional with key
        } else if let Some(_rest) = arg.strip_prefix("--party-id") {
        } else if let Some(_rest) = arg.strip_prefix("--bootstrap") {
        } else if let Some(_rest) = arg.strip_prefix("--n-parties") {
        } else if let Some(_rest) = arg.strip_prefix("--threshold") {
        } else if let Some(_rest) = arg.strip_prefix("--inputs") {
        } else if let Some(_rest) = arg.strip_prefix("--wait-for-clients") {
        } else if let Some(_rest) = arg.strip_prefix("--stun-servers") {
        } else if let Some(_rest) = arg.strip_prefix("--servers") {
        } else if let Some(_rest) = arg.strip_prefix("--mpc-backend") {
        } else if let Some(_rest) = arg.strip_prefix("--mpc-curve") {
        } else if let Some(_rest) = arg.strip_prefix("--rpc-bind") {
        } else if let Some(_rest) = arg.strip_prefix("--off-chain-coord") {
        } else if let Some(_rest) = arg.strip_prefix("--on-chain-coord") {
        } else if let Some(_rest) = arg.strip_prefix("--eth-node") {
        } else if let Some(_rest) = arg.strip_prefix("--wallet-sk") {
        } else if let Some(_rest) = arg.strip_prefix("--key") {
        } else if let Some(_rest) = arg.strip_prefix("--cert") {
        } else if let Some(_rest) = arg.strip_prefix("--timestamp") {
        } else if let Some(_rest) = arg.strip_prefix("--expected-clients") {
        } else if let Some(_rest) = arg.strip_prefix("--node-ids") {
        }
    }

    fail_removed_flag(
        &raw_args,
        "--client-id",
        "Client IDs are now transport-derived. Remove `--client-id`.",
    );
    fail_removed_flag(
        &raw_args,
        "--expected-client-count",
        "Use `--expected-clients <cert-paths>` instead.",
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
            "--wait-for-clients" => {
                if let Some(v) = args_iter.next() {
                    expected_client_count = Some(v.parse().expect("Invalid --wait-for-clients"));
                }
            }
            "--stun-servers" => {
                if let Some(v) = args_iter.next() {
                    _stun_servers = v
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
            "--rpc-bind" => {
                if let Some(v) = args_iter.next() {
                    let parts: Vec<&str> = v.rsplitn(2, ':').collect();
                    let port: u16 = parts[0].parse().expect("Invalid --rpc-bind port");
                    let host = parts[1].to_string();
                    rpc_addr = Some((host, port));
                }
            }
            "--off-chain-coord" => {
                if let Some(v) = args_iter.next() {
                    let parts: Vec<&str> = v.rsplitn(2, ':').collect();
                    let port: u16 = parts[0].parse().expect("Invalid --off-chain-coord port");
                    let host = parts[1].to_string();
                    coord_addr = Some((host, port));
                }
            }
            "--on-chain-coord" => {
                if let Some(v) = args_iter.next() {
                    contract_addr =
                        Some(Address::from_str(&v).expect("invalid smart contract address"));
                }
            }
            "--node-ids" => {
                if let Some(v) = args_iter.next() {
                    node_ids = v
                        .split(',')
                        .map(|s| Address::from_str(s.trim()).expect("invalid node address"))
                        .collect();
                }
            }
            "--eth-node" => {
                if let Some(v) = args_iter.next() {
                    eth_node_addr = Some(v);
                }
            }
            "--wallet-sk" => {
                if let Some(v) = args_iter.next() {
                    wallet_sk_str = Some(v);
                }
            }
            "--key" => {
                if let Some(v) = args_iter.next() {
                    key_der = Some(std::fs::read(&v).expect("Failed to read --key file"));
                }
            }
            "--cert" => {
                if let Some(v) = args_iter.next() {
                    cert_der = Some(std::fs::read(&v).expect("Failed to read --cert file"));
                }
            }
            "--timestamp" => {
                if let Some(v) = args_iter.next() {
                    timestamp = Some(v.parse().expect("Invalid --timestamp"));
                }
            }
            "--expected-clients" => {
                if let Some(v) = args_iter.next() {
                    expected_clients = v.split(',').map(|s| s.trim().to_string()).collect();
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

    // Client mode: connect to MPC servers and provide inputs
    if as_client {
        // Coordinator-based client mode
        if contract_addr.is_some() || coord_addr.is_some() {
            rustls::crypto::ring::default_provider()
                .install_default()
                .expect("install rustls crypto");

            let t = threshold.unwrap_or(1);
            let input_str = client_inputs.expect("--inputs required in client mode");
            let input_values: Vec<i64> = input_str
                .split(',')
                .map(|s| s.trim().parse().expect("invalid input value"))
                .collect();

            if let Some(contract) = contract_addr {
                // On-chain client mode
                let eth_addr = eth_node_addr
                    .as_ref()
                    .expect("--eth-node required for on-chain client mode");
                let wallet = wallet_sk_str
                    .as_ref()
                    .expect("--wallet-sk required for on-chain client mode");
                let provider = on_chain::ws_connect(eth_addr, wallet).await;
                let mut coord =
                    on_chain::setup_coord(provider, contract, t as u64, 1, key_der.clone()).await;
                let signer = PrivateKeySigner::from_str(wallet).unwrap();
                let client_addr = signer.address();

                coord.wait_for_pp().await.unwrap();
                coord.wait_for_input_mask_init().await.unwrap();
                let mut indices = Vec::new();
                for i in 0..input_values.len() as u64 {
                    coord.reserve_mask_index(i).await.unwrap();
                    indices.push(i);
                }
                eprintln!("[on-chain client] obtained index {}", indices[0]);

                let base_nonce = coord.base_nonce().await;
                let sig = on_chain::generate_client_sig(base_nonce, indices[0], signer).await;

                let rpc_addrs: Vec<(String, u16)> = server_addrs
                    .iter()
                    .map(|a| (a.ip().to_string(), a.port()))
                    .collect();
                let node_rpc_client = on_chain::node_rpc::NodeRPCClient::start_rpc_client(
                    t,
                    rpc_addrs,
                    cert_der.unwrap(),
                    key_der.unwrap(),
                )
                .await;
                let mask = node_rpc_client
                    .receive_mask(sig.as_bytes().to_vec(), client_addr)
                    .await
                    .unwrap();

                coord.wait_for_input().await.unwrap();
                let masked = mask + ark_bls12_381::Fr::from(input_values[0] as u64);
                coord.send_masked_input(masked, indices[0]).await.unwrap();

                coord.wait_for_mpc().await.unwrap();
                coord.wait_for_outputs().await.unwrap();
                let outputs = coord.obtain_outputs().await.unwrap();
                println!("outputs: {:?}", outputs);
                return;
            } else {
                // Off-chain client mode
                let cert = cert_der.clone().expect("--cert required in client mode");
                let key = key_der.clone().expect("--key required in client mode");

                let ca = coord_addr.as_ref().unwrap();
                let mut coord: OffChainCoordinator<ark_bls12_381::Fr> =
                    OffChainCoordinator::start_rpc_client(
                        &ca.0,
                        ca.1,
                        timestamp.expect("--timestamp required in client mode"),
                        t as u64,
                        1,
                        cert,
                        key,
                    )
                    .await;

                coord.wait_for_pp().await.unwrap();
                coord.wait_for_input_mask_init().await.unwrap();
                let mut indices = Vec::new();
                for i in 0..input_values.len() as u64 {
                    coord.reserve_mask_index(i).await.unwrap();
                    indices.push(i);
                }

                let rpc_addrs: Vec<(String, u16)> = server_addrs
                    .iter()
                    .map(|a| (a.ip().to_string(), a.port()))
                    .collect();
                let node_rpc_client: NodeRPCClient<ark_bls12_381::Fr> =
                    NodeRPCClient::start_rpc_client(
                        t,
                        rpc_addrs,
                        cert_der.unwrap(),
                        key_der.unwrap(),
                    )
                    .await;
                let mask = node_rpc_client.receive_mask().await.unwrap();

                coord.wait_for_input().await.unwrap();
                let masked = mask + ark_bls12_381::Fr::from(input_values[0] as u64);
                coord.send_masked_input(masked, indices[0]).await.unwrap();

                coord.wait_for_mpc().await.unwrap();
                coord.wait_for_outputs().await.unwrap();
                let outputs = coord.obtain_outputs().await.unwrap();
                println!("outputs: {:?}", outputs);
                return;
            }
        }

        // Direct client mode (no coordinator)
        #[cfg(feature = "honeybadger")]
        run_as_client(
            n_parties,
            threshold,
            mpc_backend.as_deref(),
            mpc_curve.as_deref(),
            client_inputs,
            server_addrs,
        )
        .await;
        #[cfg(not(feature = "honeybadger"))]
        {
            eprintln!("Error: client mode requires the 'honeybadger' feature");
            exit(2);
        }
        return;
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
            "Error: {} backend does not support --wait-for-clients",
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
    let program_id: [u8; 32];
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
        let mut mgr = QuicNetworkManager::new();
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
        let mut mgr = QuicNetworkManager::new();
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

    // =====================================================================
    // ON-CHAIN COORDINATOR: Self-contained flow
    // =====================================================================
    if contract_addr.is_some() {
        if let Some(net) = net_opt.clone() {
            let my_id = net.local_party_id();
            let n = session_n_parties.unwrap_or_else(|| net.parties().len());
            let t = session_threshold.unwrap_or(1);
            let instance_id =
                session_instance_id.expect("session instance_id should be set in party mode");

            let contract = contract_addr.unwrap();
            let eth_addr = eth_node_addr
                .as_ref()
                .expect("--eth-node required for on-chain coordinator");
            let wallet = wallet_sk_str
                .as_ref()
                .expect("--wallet-sk required for on-chain coordinator");
            let provider = on_chain::ws_connect(eth_addr, wallet).await;
            let mut coord_instance =
                on_chain::setup_coord(provider, contract, t as u64, 1, None).await;
            let coord_for_rpc = coord_instance.coord();

            // Grant roles (leader only)
            if as_leader {
                coord_instance.grant_roles(node_ids.clone()).await.unwrap();
            }

            // Parse expected client addresses (on-chain uses Ethereum addresses)
            let input_addrs: Vec<Address> = expected_clients
                .iter()
                .map(|s| Address::from_str(s).expect("invalid client Ethereum address"))
                .collect();

            // Setup NodeRPC server
            let rpc = rpc_addr
                .as_ref()
                .expect("--rpc-bind required with on-chain coordinator");
            let mut node_rpc = on_chain::node_rpc::NodeRPCServer::start(
                &rpc.0,
                rpc.1,
                coord_for_rpc,
                cert_der.clone().expect("--cert required"),
                key_der.clone().expect("--key required"),
            )
            .await;

            // Coordinator preprocessing trigger
            if as_leader {
                coord_instance.trigger_pp().await.unwrap();
            }
            coord_instance.wait_for_pp().await.unwrap();

            // Setup HB engine (BLS12-381 only for on-chain coordinator)
            let engine =
                match setup_hb_party_for_curve::<ark_bls12_381::Fr, ark_bls12_381::G1Projective>(
                    &mut vm,
                    net.clone(),
                    my_id,
                    n,
                    t,
                    instance_id,
                    None, // coordinator handles clients
                )
                .await
                {
                    Ok(e) => e,
                    Err(e) => {
                        eprintln!("[party {}] HoneyBadger setup failed: {}", my_id, e);
                        exit(13);
                    }
                };

            // Mask distribution
            if !input_addrs.is_empty() {
                let mask_shares = engine
                    .node_handle()
                    .lock()
                    .await
                    .preprocessing_material
                    .lock()
                    .await
                    .take_random_shares(input_addrs.len())
                    .unwrap_or_else(|e| {
                        eprintln!("take_random_shares: {}", e);
                        exit(13);
                    });

                for (i, share) in mask_shares.iter().enumerate() {
                    node_rpc
                        .add_mask_share(i as u64, share.clone())
                        .await
                        .unwrap_or_else(|e| {
                            eprintln!("add_mask_share: {:?}", e);
                            exit(13);
                        });
                }

                if as_leader {
                    coord_instance.init_input_masks().await.unwrap();
                }
                coord_instance.wait_for_input_mask_init().await.unwrap();

                let client_to_index = coord_instance
                    .wait_for_indices(input_addrs.len() as u64)
                    .await
                    .unwrap();
                for (addr, idx) in &client_to_index {
                    node_rpc
                        .add_reserved_index(*addr, *idx)
                        .await
                        .unwrap_or_else(|e| {
                            eprintln!("add_reserved_index: {:?}", e);
                            exit(13);
                        });
                }

                // On-chain client auth
                for addr in &input_addrs {
                    if coord_instance.wait_for_client_auth(*addr).await.unwrap() {
                        node_rpc.add_auth_status(*addr).await.unwrap_or_else(|e| {
                            eprintln!("add_auth_status: {:?}", e);
                            exit(13);
                        });
                        eprintln!("[party {}] client {:?} authenticated", my_id, addr);
                    } else {
                        eprintln!("[party {}] client {:?} auth failed", my_id, addr);
                        exit(13);
                    }
                }

                if as_leader {
                    coord_instance.trigger_input().await.unwrap();
                }
                coord_instance.wait_for_input().await.unwrap();

                let client_inputs = coord_instance
                    .wait_for_inputs(input_addrs.len() as u64, mask_shares)
                    .await
                    .unwrap();
                for (client_idx, (_addr, shares)) in client_inputs.iter().enumerate() {
                    vm.state
                        .client_store()
                        .store_client_input(client_idx, shares.clone());
                }
            }

            vm.state.set_mpc_engine(engine);

            // MPC execution phase
            if as_leader {
                coord_instance.trigger_mpc().await.unwrap();
            }
            coord_instance.wait_for_mpc().await.unwrap();

            eprintln!("Starting VM execution of '{}'...", agreed_entry);

            // Execute entry function
            match vm.execute(&agreed_entry) {
                Ok(result) => {
                    let output_share = match &result {
                        Value::Share(_ty, share_data) => share_data.as_bytes().to_vec(),
                        _ => {
                            println!("Program returned: {:?}", result);
                            vec![]
                        }
                    };

                    if !output_share.is_empty() {
                        if as_leader {
                            coord_instance.trigger_outputs().await.unwrap();
                        }
                        coord_instance.wait_for_outputs().await.unwrap();

                        let ids_and_addrs = node_rpc.ids_and_addrs().await;
                        for client_addr in input_addrs.iter() {
                            let id = &ids_and_addrs
                                .iter()
                                .find(|(_, addr)| addr == client_addr)
                                .expect("client address not found in node RPC")
                                .0;
                            let share: RobustShare<ark_bls12_381::Fr> =
                                ark_serialize::CanonicalDeserialize::deserialize_compressed(
                                    output_share.as_slice(),
                                )
                                .expect("deserialize output share");
                            coord_instance
                                .send_output_shares(*client_addr, id.clone(), vec![share])
                                .await
                                .unwrap();
                        }
                        if as_leader {
                            coord_instance.finalize().await.unwrap();
                        }
                    }
                }
                Err(err) => {
                    eprintln!("Execution error in '{}': {}", agreed_entry, err);
                    exit(4);
                }
            }
            return;
        } else {
            eprintln!("Error: on-chain coordinator requires party mode (--leader or --bootstrap)");
            exit(2);
        }
    }

    // =====================================================================
    // OFF-CHAIN COORDINATOR (or no coordinator): existing flow
    // =====================================================================

    // Off-chain coordinator initialization (both leader and party modes)
    let mut coord_opt: Option<OffChainCoordinator<ark_bls12_381::Fr>> = None;
    let mut node_rpc_opt: Option<NodeRPCServer<ark_bls12_381::Fr>> = None;
    let mut input_ids: Vec<Vec<u8>> = Vec::new();

    if let Some(ref ca) = coord_addr {
        let coord = OffChainCoordinator::start_rpc_client(
            &ca.0,
            ca.1,
            timestamp.expect("--timestamp required"),
            session_threshold.unwrap_or(1) as u64,
            1,
            cert_der.clone().expect("--cert required"),
            key_der.clone().expect("--key required"),
        )
        .await;
        coord_opt = Some(coord);

        input_ids = expected_clients
            .iter()
            .map(|path| extract_pubkey_from_cert(&fs::read(path).expect("read client cert")))
            .collect();

        if let Some(ref rpc) = rpc_addr {
            let node_rpc = NodeRPCServer::start(
                &rpc.0,
                rpc.1,
                cert_der.clone().unwrap(),
                key_der.clone().unwrap(),
            )
            .await;
            node_rpc_opt = Some(node_rpc);
        }
    }

    // If in party mode, configure MPC engine based on selected backend
    if let Some(net) = net_opt.clone() {
        // Use the network-derived party ID (sorted public key index), not the
        // bootnode-assigned one, because send() routes via sorted public keys.
        let my_id = net.local_party_id();
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
                // Phase 1: Coordinator preprocessing trigger
                if let Some(ref mut coord) = coord_opt {
                    if as_leader {
                        coord.trigger_pp().await.unwrap();
                    }
                    coord.wait_for_pp().await.unwrap();
                }

                // Phase 2: Create MPC engine + preprocessing + coordinator input phases
                macro_rules! setup_hb {
                    ($F:ty, $G:ty) => {{
                        let engine = match setup_hb_party_for_curve::<$F, $G>(
                            &mut vm,
                            net.clone(),
                            my_id,
                            n,
                            t,
                            instance_id,
                            expected_client_count,
                        )
                        .await
                        {
                            Ok(e) => e,
                            Err(e) => {
                                eprintln!("[party {}] HoneyBadger setup failed: {}", my_id, e);
                                exit(13);
                            }
                        };
                        vm.state.set_mpc_engine(engine);
                    }};
                }

                // Bls12_381 path with coordinator support
                if coord_opt.is_some() && matches!(curve_config, MpcCurveConfig::Bls12_381) {
                    let engine = match setup_hb_party_for_curve::<
                        ark_bls12_381::Fr,
                        ark_bls12_381::G1Projective,
                    >(
                        &mut vm,
                        net.clone(),
                        my_id,
                        n,
                        t,
                        instance_id,
                        None, // coordinator handles clients
                    )
                    .await
                    {
                        Ok(e) => e,
                        Err(e) => {
                            eprintln!("[party {}] HoneyBadger setup failed: {}", my_id, e);
                            exit(13);
                        }
                    };

                    // Coordinator mask distribution + input collection
                    if let Some(ref mut coord) = coord_opt {
                        let node_rpc = node_rpc_opt
                            .as_mut()
                            .expect("--rpc-bind required with coordinator");

                        if !input_ids.is_empty() {
                            let mask_shares = engine
                                .node_handle()
                                .lock()
                                .await
                                .preprocessing_material
                                .lock()
                                .await
                                .take_random_shares(input_ids.len())
                                .unwrap_or_else(|e| {
                                    eprintln!("take_random_shares: {}", e);
                                    exit(13);
                                });

                            for (i, share) in mask_shares.iter().enumerate() {
                                node_rpc
                                    .add_mask_share(i as u64, share)
                                    .await
                                    .unwrap_or_else(|e| {
                                        eprintln!("add_mask_share: {:?}", e);
                                        exit(13);
                                    });
                            }

                            if as_leader {
                                coord.init_input_masks().await.unwrap();
                            }
                            coord.wait_for_input_mask_init().await.unwrap();

                            let client_to_index = coord
                                .wait_for_indices(input_ids.len() as u64)
                                .await
                                .unwrap();
                            for (cid, idx) in &client_to_index {
                                node_rpc
                                    .add_reserved_index(cid.clone(), *idx)
                                    .await
                                    .unwrap_or_else(|e| {
                                        eprintln!("add_reserved_index: {:?}", e);
                                        exit(13);
                                    });
                            }

                            if as_leader {
                                coord.trigger_input().await.unwrap();
                            }
                            coord.wait_for_input().await.unwrap();

                            let client_inputs = coord
                                .wait_for_inputs(input_ids.len() as u64, mask_shares)
                                .await
                                .unwrap();
                            for (client_idx, (_cid, shares)) in client_inputs.iter().enumerate() {
                                vm.state
                                    .client_store()
                                    .store_client_input(client_idx, shares.clone());
                            }
                        }
                    }

                    vm.state.set_mpc_engine(engine);
                } else {
                    // No coordinator or non-Bls12_381 curves
                    match curve_config {
                        MpcCurveConfig::Bls12_381 => {
                            setup_hb!(ark_bls12_381::Fr, ark_bls12_381::G1Projective)
                        }
                        MpcCurveConfig::Bn254 => {
                            setup_hb!(ark_bn254::Fr, ark_bn254::G1Projective)
                        }
                        MpcCurveConfig::Curve25519 => {
                            setup_hb!(ark_curve25519::Fr, ark_curve25519::EdwardsProjective)
                        }
                        MpcCurveConfig::Ed25519 => {
                            setup_hb!(ark_ed25519::Fr, ark_ed25519::EdwardsProjective)
                        }
                    }
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

                macro_rules! setup_avss {
                    ($F:ty, $G:ty) => {{
                        if let Err(e) = setup_avss_party_for_curve::<$F, $G>(
                            &mut vm,
                            net.clone(),
                            my_id,
                            n,
                            t,
                            instance_id,
                            expected_client_count,
                        )
                        .await
                        {
                            eprintln!("[party {}] AVSS setup failed: {}", my_id, e);
                            exit(13);
                        }
                    }};
                }

                match curve_config {
                    MpcCurveConfig::Bls12_381 => {
                        setup_avss!(ark_bls12_381::Fr, ark_bls12_381::G1Projective)
                    }
                    MpcCurveConfig::Bn254 => {
                        setup_avss!(ark_bn254::Fr, ark_bn254::G1Projective)
                    }
                    MpcCurveConfig::Curve25519 => {
                        setup_avss!(ark_curve25519::Fr, ark_curve25519::EdwardsProjective)
                    }
                    MpcCurveConfig::Ed25519 => {
                        setup_avss!(ark_ed25519::Fr, ark_ed25519::EdwardsProjective)
                    }
                }

                eprintln!(
                    "[party {}] AVSS engine set, starting VM execution...",
                    my_id
                );
            }
        }
    }

    // Coordinator: signal MPC execution phase
    if let Some(ref mut coord) = coord_opt {
        if as_leader {
            coord.trigger_mpc().await.unwrap();
        }
        coord.wait_for_mpc().await.unwrap();
    }

    eprintln!("Starting VM execution of '{}'...", agreed_entry);

    // Execute entry function
    match vm.execute(&agreed_entry) {
        Ok(result) => {
            if let Some(ref mut coord) = coord_opt {
                // Coordinator output delivery
                let output_share = match &result {
                    Value::Share(_ty, share_data) => share_data.as_bytes().to_vec(),
                    _ => {
                        println!("Program returned: {:?}", result);
                        vec![]
                    }
                };

                if !output_share.is_empty() {
                    if as_leader {
                        coord.trigger_outputs().await.unwrap();
                    }
                    coord.wait_for_outputs().await.unwrap();
                    for cid in input_ids.iter() {
                        let share: RobustShare<ark_bls12_381::Fr> =
                            ark_serialize::CanonicalDeserialize::deserialize_compressed(
                                output_share.as_slice(),
                            )
                            .expect("deserialize output share");
                        coord
                            .send_output_shares(cid.clone(), cid.clone(), vec![share])
                            .await
                            .unwrap();
                    }
                    if as_leader {
                        coord.finalize().await.unwrap();
                    }
                }
            } else {
                // No coordinator — auto-reveal as before
                let result = if let Value::Share(ty, ref sd) = result {
                    if let Some(engine) = vm.state.mpc_engine() {
                        eprintln!("Program returned a secret share, revealing...");
                        match engine.open_share(ty, sd.as_bytes()) {
                            Ok(revealed) => revealed,
                            Err(e) => {
                                eprintln!("Failed to reveal returned share: {}", e);
                                result
                            }
                        }
                    } else {
                        result
                    }
                } else {
                    result
                };
                // Pretty-print the result
                match &result {
                    Value::Array(arr_id) => {
                        if let Some(arr) = vm.state.object_store.get_array(*arr_id) {
                            let len = arr.length();
                            let mut bytes = Vec::with_capacity(len);
                            let mut is_byte_array = true;
                            for i in 0..len {
                                match arr.get(&Value::I64(i as i64)) {
                                    Some(Value::U8(b)) => bytes.push(*b),
                                    _ => {
                                        is_byte_array = false;
                                        break;
                                    }
                                }
                            }
                            if is_byte_array && !bytes.is_empty() {
                                let hex: String =
                                    bytes.iter().map(|b| format!("{:02x}", b)).collect();
                                println!("Program returned: byte[{}] 0x{}", bytes.len(), hex);
                            } else {
                                println!("Program returned: {:?}", result);
                            }
                        } else {
                            println!("Program returned: {:?}", result);
                        }
                    }
                    _ => println!("Program returned: {:?}", result),
                }
            }
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
  --wait-for-clients <n>
                          Number of client inputs to collect before starting computation
                          (HoneyBadger only; ALPN handles routing, this controls coordination)
  --off-chain-coord <addr:port>
                          Off-chain coordinator address
  --on-chain-coord <address>
                          On-chain coordinator smart contract address
  --node-ids <addrs>      Comma-separated Ethereum addresses of MPC nodes (on-chain, leader only)
  --eth-node <url>        Ethereum node WebSocket URL (on-chain coordinator)
  --wallet-sk <hex>       Wallet secret key hex (on-chain coordinator)
  --rpc-bind <addr:port>  Node RPC server bind address (for mask distribution)
  --cert <path>           Path to DER-encoded X.509 certificate
  --key <path>            Path to DER-encoded private key
  --timestamp <u64>       Coordinator session timestamp (off-chain)
  --expected-clients <cert-paths-or-addrs>
                          Comma-separated client cert paths (off-chain) or Ethereum addresses (on-chain)
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
  stoffel-run program.stfbin main --leader --bind 127.0.0.1:9000 --n-parties 5 --threshold 1 --wait-for-clients 2

  # Terminals 2-5: Other parties (same expected-client-count)
  stoffel-run program.stfbin main --party-id 1 --bootstrap 127.0.0.1:9000 --bind 127.0.0.1:9002 --n-parties 5 --wait-for-clients 2
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
