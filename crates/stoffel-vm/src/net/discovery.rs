//! Bootnode-assisted formation of one certificate-pinned MPC party mesh.
mod bootnode;

use super::session::{ExecutionId, SessionInfo, SessionMessage};
use bincode;
use bootnode::{spawn_connection_handler, BootnodeState};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    time::Duration,
};
use stoffelnet::network_utils::{Network, NodePublicKey, PartyId};
use stoffelnet::transports::quic::{
    NetworkManager, PeerConnection, QuicNetworkConfig, QuicNetworkManager,
};

fn registration_progress_interval() -> Option<Duration> {
    std::env::var("STOFFEL_SESSION_REGISTRATION_PROGRESS_INTERVAL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs)
}

// NAT traversal types - use real types when feature is enabled, stubs otherwise
#[cfg(feature = "nat")]
use stoffelnet::transports::ice::{CandidateType, IceCandidate};

#[cfg(not(feature = "nat"))]
#[allow(dead_code)]
mod nat_stubs {
    use serde::{Deserialize, Serialize};
    use std::net::SocketAddr;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum CandidateType {
        Host,
        ServerReflexive,
        PeerReflexive,
        Relay,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct IceCandidate {
        pub foundation: String,
        pub priority: u32,
        pub address: SocketAddr,
        pub candidate_type: CandidateType,
        pub related_address: Option<SocketAddr>,
        pub stun_server: Option<SocketAddr>,
    }

    pub struct LocalCandidates {
        pub candidates: Vec<IceCandidate>,
        pub ufrag: String,
        pub pwd: String,
    }

    impl LocalCandidates {
        pub fn len(&self) -> usize {
            self.candidates.len()
        }
    }
}

#[cfg(not(feature = "nat"))]
use nat_stubs::IceCandidate;
use tokio::sync::oneshot;
use tokio::time::sleep;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiscoveryMessage {
    /// Register one party in the bootnode's immutable physical mesh.
    RegisterWithSession {
        /// Coordinator-issued identity for this execution. Program IDs are not
        /// unique execution identities because the same program can overlap.
        execution_id: ExecutionId,
        party_id: PartyId,
        listen_addr: SocketAddr,
        program_id: [u8; 32],
        entry: String,
        n_parties: usize,
        threshold: usize,
        auth_token: String,
        /// TLS-derived identity (hash of certificate public key) so peers can
        /// pre-register this party in their allowlist before accept().
        tls_derived_id: Option<PartyId>,
        /// Complete DER-encoded SubjectPublicKeyInfo. This is the
        /// authorization identity; `tls_derived_id` is diagnostic compact
        /// bookkeeping only.
        tls_public_key: Option<Vec<u8>>,
    },
    /// ICE candidates for NAT traversal - sent via bootnode as signaling relay
    IceCandidates {
        execution_id: ExecutionId,
        from_party_id: PartyId,
        to_party_id: PartyId,
        ufrag: String,
        pwd: String,
        candidates: Vec<IceCandidate>,
    },
    /// Request ICE candidate exchange with a peer
    IceExchangeRequest {
        execution_id: ExecutionId,
        from_party_id: PartyId,
        to_party_id: PartyId,
    },
}

fn discovery_auth_token_from_env() -> Option<String> {
    std::env::var("STOFFEL_AUTH_TOKEN")
        .ok()
        .map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty())
}

fn required_discovery_auth_token(context: &str) -> Result<String, String> {
    discovery_auth_token_from_env()
        .ok_or_else(|| format!("STOFFEL_AUTH_TOKEN must be set for {}", context))
}

fn registration_token_is_valid(required_auth_token: &str, message_auth_token: &str) -> bool {
    constant_time_eq(
        required_auth_token.as_bytes(),
        message_auth_token.as_bytes(),
    )
}

/// Constant-time byte comparison to prevent timing attacks on auth tokens.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Run a bootnode for one immutable physical party mesh.
pub async fn run_bootnode_with_config(
    bind: SocketAddr,
    expected_parties: usize,
) -> Result<(), String> {
    run_bootnode_with_config_ready(bind, expected_parties, None).await
}

/// Run a bootnode and acknowledge once its UDP listener is bound.
///
/// The optional sender lets a supervisor wait for concrete listener readiness
/// before it starts registering followers.
pub async fn run_bootnode_with_config_ready(
    bind: SocketAddr,
    expected_parties: usize,
    ready: Option<oneshot::Sender<()>>,
) -> Result<(), String> {
    let required_auth_token = required_discovery_auth_token("bootnode discovery registration")?;
    eprintln!("[bootnode] Discovery registration authentication enabled");
    run_bootnode_with_config_and_auth(bind, expected_parties, required_auth_token, ready).await
}

async fn run_bootnode_with_config_and_auth(
    bind: SocketAddr,
    expected_parties: usize,
    required_auth_token: String,
    ready: Option<oneshot::Sender<()>>,
) -> Result<(), String> {
    let mut net = QuicNetworkManager::with_config(QuicNetworkConfig {
        use_tls: false,
        ..Default::default()
    });
    net.listen(bind).await?;
    let state = BootnodeState::new(expected_parties);
    if let Some(ready) = ready {
        let _ = ready.send(());
    }

    eprintln!("[bootnode] Listening on {}", bind);

    loop {
        let conn = net.accept().await?;
        spawn_connection_handler(conn, state.clone(), required_auth_token.clone());
    }
}

/// Connect to a session party using its complete provisioned TLS identity.
/// No node/key/connection state is inserted until the certificate matches.
async fn add_node_and_connect_pinned(
    net: &mut QuicNetworkManager,
    party_id: PartyId,
    addr: SocketAddr,
    expected_public_key: &NodePublicKey,
) -> Result<(), String> {
    let max_retries = 3;
    let base_timeout = Duration::from_secs(10);
    let transport_id = expected_public_key.derive_id();
    let mut last_error = "connection was not attempted".to_string();

    for attempt in 0..max_retries {
        let timeout_duration = base_timeout * (1 << attempt);
        eprintln!(
            "[peer-connect] Pinned connect to logical party {} (transport {}) at {} (attempt {}/{}, timeout {:?})",
            party_id,
            transport_id,
            addr,
            attempt + 1,
            max_retries,
            timeout_duration
        );
        match tokio::time::timeout(
            timeout_duration,
            net.connect_as_server_with_expected_public_key(addr, expected_public_key),
        )
        .await
        {
            Ok(Ok(_)) => return Ok(()),
            Ok(Err(error)) => last_error = error,
            Err(_) => last_error = format!("timed out after {timeout_duration:?}"),
        }
        if attempt + 1 < max_retries {
            sleep(Duration::from_millis(500 * (attempt as u64 + 1))).await;
        }
    }

    Err(format!(
        "failed pinned connection to logical party {party_id} (transport {transport_id}) at {addr} after {max_retries} attempts: {last_error}"
    ))
}

/// Connect to a peer using NAT traversal (ICE hole punching via bootnode signaling)
#[cfg(feature = "nat")]
async fn add_node_and_connect_nat(
    net: &mut QuicNetworkManager,
    execution_id: ExecutionId,
    my_party_id: PartyId,
    target_party_id: PartyId,
    target_addr: SocketAddr,
    expected_public_key: &NodePublicKey,
    bn_conn: &dyn PeerConnection,
) -> Result<(), String> {
    if !net.is_nat_traversal_enabled() {
        // Fall back to direct connection if NAT traversal is not enabled
        eprintln!(
            "[NAT] NAT traversal not enabled, using direct connection to party {}",
            target_party_id
        );
        return add_node_and_connect_pinned(net, target_party_id, target_addr, expected_public_key)
            .await;
    }

    eprintln!(
        "[NAT] Starting NAT traversal to party {} (gathering ICE candidates)",
        target_party_id
    );

    // Step 1: Gather local ICE candidates
    let local_candidates = match net.gather_ice_candidates().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[NAT] Failed to gather ICE candidates: {}", e);
            // Fall back to direct connection
            return add_node_and_connect_pinned(
                net,
                target_party_id,
                target_addr,
                expected_public_key,
            )
            .await;
        }
    };

    eprintln!(
        "[NAT] Gathered {} local candidates, sending to party {} via bootnode",
        local_candidates.len(),
        target_party_id
    );

    // Step 2: Send our ICE candidates to the target party via bootnode
    let ice_msg = DiscoveryMessage::IceCandidates {
        execution_id,
        from_party_id: my_party_id,
        to_party_id: target_party_id,
        ufrag: local_candidates.ufrag.clone(),
        pwd: local_candidates.pwd.clone(),
        candidates: local_candidates.candidates.clone(),
    };

    if let Err(e) = send_ctrl(bn_conn, &ice_msg).await {
        eprintln!("[NAT] Failed to send ICE candidates: {}", e);
        return add_node_and_connect_pinned(net, target_party_id, target_addr, expected_public_key)
            .await;
    }

    // Step 3: Wait for remote ICE candidates from the target party
    eprintln!(
        "[NAT] Waiting for ICE candidates from party {}...",
        target_party_id
    );

    let ice_timeout = Duration::from_secs(30);
    let start = tokio::time::Instant::now();

    loop {
        if start.elapsed() > ice_timeout {
            eprintln!(
                "[NAT] Timeout waiting for ICE candidates from party {}",
                target_party_id
            );
            return add_node_and_connect_pinned(
                net,
                target_party_id,
                target_addr,
                expected_public_key,
            )
            .await;
        }

        match tokio::time::timeout(Duration::from_millis(100), bn_conn.receive()).await {
            Ok(Ok(buf)) => {
                if let Ok(DiscoveryMessage::IceCandidates {
                    execution_id: message_execution_id,
                    from_party_id,
                    to_party_id: _,
                    ufrag: _,
                    pwd: _,
                    candidates: remote_candidates,
                }) = bincode::deserialize::<DiscoveryMessage>(&buf)
                {
                    if message_execution_id == execution_id && from_party_id == target_party_id {
                        eprintln!(
                            "[NAT] Received {} ICE candidates from party {}",
                            remote_candidates.len(),
                            target_party_id
                        );

                        // Step 4: Try to connect using remote candidate addresses
                        // Prefer server reflexive (STUN-discovered) addresses
                        let mut connected = false;

                        // Sort candidates: prefer ServerReflexive, then Host
                        let mut sorted_candidates = remote_candidates.clone();
                        sorted_candidates.sort_by_key(|c| match c.candidate_type {
                            CandidateType::ServerReflexive => 0,
                            CandidateType::Host => 1,
                            CandidateType::PeerReflexive => 2,
                            CandidateType::Relay => 3,
                        });

                        for candidate in &sorted_candidates {
                            eprintln!(
                                "[NAT] Trying {:?} candidate {} for party {}",
                                candidate.candidate_type, candidate.address, target_party_id
                            );

                            match tokio::time::timeout(
                                Duration::from_secs(5),
                                net.connect_as_server_with_expected_public_key(
                                    candidate.address,
                                    expected_public_key,
                                ),
                            )
                            .await
                            {
                                Ok(Ok(_)) => {
                                    eprintln!(
                                        "[NAT] Successfully connected to party {} via {:?} at {}",
                                        target_party_id,
                                        candidate.candidate_type,
                                        candidate.address
                                    );
                                    connected = true;
                                    break;
                                }
                                Ok(Err(e)) => {
                                    eprintln!(
                                        "[NAT] Connection to {} failed: {}",
                                        candidate.address, e
                                    );
                                }
                                Err(_) => {
                                    eprintln!(
                                        "[NAT] Connection to {} timed out",
                                        candidate.address
                                    );
                                }
                            }
                        }

                        if connected {
                            return Ok(());
                        }

                        eprintln!(
                            "[NAT] All ICE candidates failed for party {}, trying direct",
                            target_party_id
                        );
                        return add_node_and_connect_pinned(
                            net,
                            target_party_id,
                            target_addr,
                            expected_public_key,
                        )
                        .await;
                    }
                }
            }
            Ok(Err(e)) => {
                eprintln!("[NAT] Error receiving from bootnode: {}", e);
                break;
            }
            Err(_) => {
                // Timeout, continue waiting
                continue;
            }
        }
    }

    // Fall back to direct connection
    add_node_and_connect_pinned(net, target_party_id, target_addr, expected_public_key).await
}

async fn send_ctrl(conn: &dyn PeerConnection, msg: &DiscoveryMessage) -> Result<(), String> {
    let bytes = bincode::serialize(msg).map_err(|e| e.to_string())?;
    conn.send(bytes.as_slice()).await.map_err(|e| e.to_string())
}

async fn send_session_announce(
    conn: &dyn PeerConnection,
    info: &SessionInfo,
) -> Result<(), String> {
    let announce = SessionMessage::SessionAnnounce(info.clone());
    let bytes = bincode::serialize(&announce).map_err(|e| e.to_string())?;
    conn.send(&bytes).await.map_err(|e| e.to_string())
}

/// Configuration for joining a bootnode-announced MPC session.
#[derive(Debug, Clone)]
pub struct SessionRegistrationConfig {
    pub bootnode: SocketAddr,
    /// Coordinator-issued identity shared by all parties for one execution.
    pub execution_id: ExecutionId,
    pub my_party_id: PartyId,
    pub my_listen: SocketAddr,
    pub program_id: [u8; 32],
    pub entry: String,
    pub n_parties: usize,
    pub threshold: usize,
    pub timeout: Duration,
    /// Optional locally provisioned logical-party to full-SPKI roster. When
    /// present, discovery must announce this exact roster and the transport
    /// freezes it before establishing the party mesh.
    pub expected_party_public_keys: Option<Vec<(PartyId, NodePublicKey)>>,
}

fn full_party_public_key_map(
    entries: &[(PartyId, NodePublicKey)],
    expected_parties: usize,
    label: &str,
) -> Result<HashMap<PartyId, NodePublicKey>, String> {
    if entries.len() != expected_parties {
        return Err(format!(
            "{label} has {} TLS public keys, expected {expected_parties}",
            entries.len()
        ));
    }
    let mut by_party = HashMap::with_capacity(entries.len());
    let mut identities = HashSet::with_capacity(entries.len());
    for (party_id, public_key) in entries {
        if *party_id >= expected_parties {
            return Err(format!(
                "{label} contains out-of-range logical party {party_id}"
            ));
        }
        if by_party.insert(*party_id, public_key.clone()).is_some() {
            return Err(format!(
                "{label} contains duplicate logical party {party_id}"
            ));
        }
        if !identities.insert(public_key.clone()) {
            return Err(format!(
                "{label} assigns one TLS public key to multiple logical parties"
            ));
        }
    }
    Ok(by_party)
}

/// Register with bootnode for a specific session and wait for session to be announced.
/// This is the recommended way to join a multi-party session:
/// 1. Party connects to bootnode and sends RegisterWithSession (with optional program bytes)
/// 2. Bootnode waits until n_parties have registered
/// 3. Bootnode broadcasts SessionAnnounce to all parties
/// 4. This function returns with the agreed SessionInfo
///
/// All parties receive the same instance ID derived from the full execution ID.
///
pub async fn register_and_wait_for_session(
    net: &mut QuicNetworkManager,
    config: SessionRegistrationConfig,
) -> Result<SessionInfo, String> {
    let SessionRegistrationConfig {
        bootnode,
        execution_id,
        my_party_id,
        my_listen,
        program_id,
        entry,
        n_parties,
        threshold,
        timeout,
        expected_party_public_keys,
    } = config;
    if execution_id.is_zero() {
        return Err("the all-zero execution ID cannot identify a session".to_string());
    }
    if n_parties == 0 || my_party_id >= n_parties || threshold >= n_parties {
        return Err("invalid party count, local party ID, or threshold".to_string());
    }
    let local_public_key = net.get_public_key().cloned().ok_or_else(|| {
        "session registration requires an installed local certificate".to_string()
    })?;
    let expected_party_public_key_map = expected_party_public_keys
        .as_deref()
        .map(|entries| full_party_public_key_map(entries, n_parties, "configured party roster"))
        .transpose()?;
    if let Some(expected) = expected_party_public_key_map.as_ref() {
        match expected.get(&my_party_id) {
            Some(expected_local) if expected_local == &local_public_key => {}
            Some(_) => {
                return Err(format!(
                    "configured party roster certificate for logical party {my_party_id} does not match the local certificate"
                ));
            }
            None => {
                return Err(format!(
                    "configured party roster omits logical party {my_party_id}"
                ));
            }
        }
        net.install_expected_server_public_keys(expected.values().cloned())?;
    }
    // Use a separate temporary manager for the bootnode discovery connection
    // so that the bootnode's TLS public key doesn't pollute the party mesh
    // manager's peer_public_keys (which would give N+1 sorted party IDs).
    let mut bn_mgr = QuicNetworkManager::with_config(QuicNetworkConfig {
        use_tls: false,
        ..Default::default()
    });
    let bn_conn = bn_mgr.connect(bootnode).await?;
    let auth_token = required_discovery_auth_token("session discovery registration")?;

    eprintln!(
        "[party {}] Registering with bootnode for execution {} (program: {}, n={}, t={})",
        my_party_id,
        execution_id,
        hex::encode(&program_id[..8]),
        n_parties,
        threshold
    );

    // Send the full TLS identity. The compact ID remains useful in logs and
    // connection tables, but is deliberately not an authorization credential.
    let local_tls_id = local_public_key.derive_id();
    let reg_msg = DiscoveryMessage::RegisterWithSession {
        execution_id,
        party_id: my_party_id,
        listen_addr: my_listen,
        program_id,
        entry,
        n_parties,
        threshold,
        auth_token,
        tls_derived_id: Some(local_tls_id),
        tls_public_key: Some(local_public_key.0.clone()),
    };
    let send_start = tokio::time::Instant::now();
    send_ctrl(&*bn_conn, &reg_msg)
        .await
        .map_err(|err| format!("failed to send session registration: {err}"))?;
    eprintln!(
        "[party {}] Sent session registration to bootnode in {}ms",
        my_party_id,
        send_start.elapsed().as_millis()
    );

    // Wait for SessionAnnounce from bootnode
    let start = tokio::time::Instant::now();
    let progress_interval = registration_progress_interval();
    let mut last_progress_log = Duration::ZERO;
    loop {
        if start.elapsed() > timeout {
            return Err(format!(
                "Timeout waiting for session announcement after {:?}",
                timeout
            ));
        }

        if let Some(interval) = progress_interval {
            let elapsed = start.elapsed();
            if elapsed >= last_progress_log + interval {
                last_progress_log = elapsed;
                eprintln!(
                    "[party {}] Waiting for SessionAnnounce for {}s",
                    my_party_id,
                    elapsed.as_secs()
                );
            }
        }

        match tokio::time::timeout(Duration::from_millis(100), bn_conn.receive()).await {
            Ok(Ok(buf)) => {
                // Try to parse as SessionMessage
                if let Ok(SessionMessage::SessionAnnounce(info)) =
                    bincode::deserialize::<SessionMessage>(&buf)
                {
                    if info.execution_id != execution_id {
                        eprintln!(
                            "[party {}] Ignoring SessionAnnounce for unrelated execution {}",
                            my_party_id, info.execution_id
                        );
                        continue;
                    }
                    if info.program_id != program_id {
                        return Err(format!(
                            "bootnode announced program {} for execution {}, expected {}",
                            hex::encode(info.program_id),
                            execution_id,
                            hex::encode(program_id)
                        ));
                    }
                    eprintln!(
                        "[party {}] Received SessionAnnounce: instance_id={}, {} parties",
                        my_party_id,
                        info.instance_id,
                        info.parties.len()
                    );

                    if info.parties.len() != info.n_parties {
                        return Err(format!(
                            "bootnode announced {} party addresses for n_parties={}",
                            info.parties.len(),
                            info.n_parties
                        ));
                    }
                    let announced_party_ids: HashSet<PartyId> =
                        info.parties.iter().map(|(party_id, _)| *party_id).collect();
                    if announced_party_ids.len() != info.parties.len() {
                        return Err(
                            "bootnode announced duplicate logical party addresses".to_string()
                        );
                    }

                    let announced_entries = info
                        .tls_public_keys
                        .iter()
                        .map(|(party_id, bytes)| (*party_id, NodePublicKey(bytes.clone())))
                        .collect::<Vec<_>>();
                    let announced_public_keys = full_party_public_key_map(
                        &announced_entries,
                        info.n_parties,
                        "bootnode-announced party roster",
                    )?;
                    if announced_public_keys
                        .keys()
                        .copied()
                        .collect::<HashSet<_>>()
                        != announced_party_ids
                    {
                        return Err(
                            "bootnode TLS public-key roster does not match announced parties"
                                .to_string(),
                        );
                    }

                    let mut tls_id_map = HashMap::with_capacity(info.tls_ids.len());
                    for (party_id, compact_id) in &info.tls_ids {
                        if tls_id_map.insert(*party_id, *compact_id).is_some() {
                            return Err(format!(
                                "bootnode announced duplicate compact TLS ID for logical party {party_id}"
                            ));
                        }
                    }
                    if tls_id_map.len() != info.n_parties {
                        return Err(format!(
                            "bootnode announced {} compact TLS IDs, expected {}",
                            tls_id_map.len(),
                            info.n_parties
                        ));
                    }
                    for (party_id, public_key) in &announced_public_keys {
                        let announced_compact = tls_id_map.get(party_id).ok_or_else(|| {
                            format!(
                                "bootnode omitted compact TLS diagnostic for logical party {party_id}"
                            )
                        })?;
                        if *announced_compact != public_key.derive_id() {
                            return Err(format!(
                                "bootnode compact TLS diagnostic for logical party {party_id} does not match its full certificate identity"
                            ));
                        }
                    }

                    if let Some(expected) = expected_party_public_key_map.as_ref() {
                        if expected != &announced_public_keys {
                            return Err(
                                "bootnode-announced TLS public-key roster differs from the configured standing roster"
                                    .to_string(),
                            );
                        }
                    }
                    if announced_public_keys.get(&my_party_id) != Some(&local_public_key) {
                        return Err(format!(
                            "bootnode-announced TLS identity for logical party {my_party_id} does not match the local certificate"
                        ));
                    }

                    // Freeze admission before any accept or dial. The
                    // transport validates compact-ID collisions and compares
                    // full SPKIs on every physical party connection.
                    net.install_expected_server_public_keys(
                        announced_public_keys.values().cloned(),
                    )?;

                    // Peer connection strategy:
                    // - Lower-ID parties CONNECT to higher-ID parties
                    // - Higher-ID parties ACCEPT from lower-ID parties
                    // This avoids bidirectional connection races
                    let higher_peers: Vec<_> = info
                        .parties
                        .iter()
                        .filter(|(pid, _)| *pid > my_party_id)
                        .map(|(pid, addr)| {
                            announced_public_keys
                                .get(pid)
                                .cloned()
                                .map(|public_key| (*pid, *addr, public_key))
                                .ok_or_else(|| {
                                    format!(
                                        "bootnode omitted TLS public key for logical party {pid}"
                                    )
                                })
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let n_expected_incoming = info
                        .parties
                        .iter()
                        .filter(|(pid, _)| *pid < my_party_id)
                        .count();

                    eprintln!(
                        "[party {}] Connection plan: {} outgoing (to higher IDs), {} incoming (from lower IDs)",
                        my_party_id,
                        higher_peers.len(),
                        n_expected_incoming
                    );

                    // Spawn a background accept loop for incoming connections from lower-ID parties
                    let mut acceptor = net.clone();
                    let acceptor_party_id = my_party_id;

                    let accept_handle = tokio::spawn(async move {
                        if n_expected_incoming == 0 {
                            eprintln!(
                                "[party {}] No incoming connections expected (lowest ID party)",
                                acceptor_party_id
                            );
                            return 0;
                        }

                        let mut accepted = 0;
                        let accept_timeout = Duration::from_secs(60);
                        let accept_start = tokio::time::Instant::now();

                        eprintln!(
                            "[party {}] Accept loop started, expecting {} connections from lower-ID parties",
                            acceptor_party_id, n_expected_incoming
                        );

                        while accepted < n_expected_incoming
                            && accept_start.elapsed() < accept_timeout
                        {
                            match tokio::time::timeout(Duration::from_secs(10), acceptor.accept())
                                .await
                            {
                                Ok(Ok(conn)) => {
                                    eprintln!(
                                        "[party {}] Accepted connection from {} ({}/{})",
                                        acceptor_party_id,
                                        conn.remote_address(),
                                        accepted + 1,
                                        n_expected_incoming
                                    );
                                    accepted += 1;
                                }
                                Ok(Err(e)) => {
                                    eprintln!(
                                        "[party {}] Accept error (will retry): {}",
                                        acceptor_party_id, e
                                    );
                                    sleep(Duration::from_millis(100)).await;
                                }
                                Err(_) => {
                                    // Timeout, continue waiting
                                    eprintln!(
                                        "[party {}] Accept timeout, waiting for {} more ({}/{})",
                                        acceptor_party_id,
                                        n_expected_incoming - accepted,
                                        accepted,
                                        n_expected_incoming
                                    );
                                }
                            }
                        }

                        eprintln!(
                            "[party {}] Accept loop finished: accepted {} connections",
                            acceptor_party_id, accepted
                        );
                        accepted
                    });

                    // Connect to higher-ID peers only
                    #[cfg(feature = "nat")]
                    {
                        // Use NAT-aware connection if NAT traversal is enabled
                        let use_nat = net.is_nat_traversal_enabled();
                        if use_nat {
                            eprintln!(
                                "[party {}] Using NAT traversal for peer connections",
                                my_party_id
                            );
                        }

                        for (pid, addr, public_key) in &higher_peers {
                            if use_nat {
                                add_node_and_connect_nat(
                                    net,
                                    execution_id,
                                    my_party_id,
                                    *pid,
                                    *addr,
                                    public_key,
                                    &*bn_conn,
                                )
                                .await?;
                            } else {
                                add_node_and_connect_pinned(net, *pid, *addr, public_key).await?;
                            }
                        }
                    }

                    #[cfg(not(feature = "nat"))]
                    {
                        for (pid, addr, public_key) in higher_peers {
                            add_node_and_connect_pinned(net, pid, addr, &public_key).await?;
                        }
                    }

                    // Wait for accept loop to finish
                    match tokio::time::timeout(Duration::from_secs(90), accept_handle).await {
                        Ok(Ok(n)) => {
                            eprintln!(
                                "[party {}] Peer mesh established: {} outgoing, {} accepted",
                                my_party_id,
                                info.parties.len() - 1 - n_expected_incoming,
                                n
                            );
                        }
                        Ok(Err(e)) => {
                            eprintln!("[party {}] Accept task error: {:?}", my_party_id, e);
                        }
                        Err(_) => {
                            eprintln!("[party {}] Accept task timed out", my_party_id);
                        }
                    }

                    // Assign party IDs based on sorted public keys now that
                    // the mesh is fully formed. This sets remote_party_id on
                    // each connection so that spawn_receive_loops can map
                    // TLS-derived IDs back to 0..N-1 party indices.
                    let assigned = net.assign_party_ids();
                    let local_pid = net.local_party_id();
                    eprintln!(
                        "[party {}] Assigned {} party IDs (local party_id={})",
                        my_party_id, assigned, local_pid
                    );

                    // Send acknowledgment
                    let ack = SessionMessage::SessionAck {
                        execution_id,
                        party_id: my_party_id,
                        program_id: info.program_id,
                        instance_id: info.instance_id,
                    };
                    let ack_bytes = bincode::serialize(&ack).map_err(|e| e.to_string())?;
                    bn_conn.send(&ack_bytes).await?;

                    return Ok(info);
                }
                // Ignore other messages while waiting
            }
            Ok(Err(e)) => {
                // Connection error
                return Err(format!("Connection error while waiting for session: {}", e));
            }
            Err(_) => {
                // Timeout on receive, continue waiting
                continue;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::HashMap,
        net::{Ipv4Addr, SocketAddrV4, UdpSocket},
        sync::Once,
    };
    use tokio::time::timeout;

    static INIT: Once = Once::new();

    fn init_crypto_provider() {
        INIT.call_once(|| {
            rustls::crypto::ring::default_provider()
                .install_default()
                .expect("install rustls crypto provider");
        });
    }

    fn reserve_local_addr() -> SocketAddr {
        let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .expect("bind UDP socket on localhost");
        socket.local_addr().expect("get local socket address")
    }

    async fn recv_session_announce(conn: &dyn PeerConnection) -> SessionInfo {
        let buf = timeout(Duration::from_secs(3), conn.receive())
            .await
            .expect("timed out waiting for session announcement")
            .expect("receive session announcement");
        match bincode::deserialize::<SessionMessage>(&buf).expect("deserialize session message") {
            SessionMessage::SessionAnnounce(info) => info,
            other => panic!("expected SessionAnnounce, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn invalid_session_register_auth_token_cannot_poison_session_parties() {
        init_crypto_provider();
        let bootnode_addr = reserve_local_addr();
        let auth_token = "session-secret".to_string();
        let (ready_tx, ready_rx) = oneshot::channel();
        let bootnode = tokio::spawn(run_bootnode_with_config_and_auth(
            bootnode_addr,
            2,
            auth_token.clone(),
            Some(ready_tx),
        ));
        tokio::time::timeout(Duration::from_secs(5), ready_rx)
            .await
            .expect("bootnode readiness deadline")
            .expect("bootnode listener ready");

        let program_id = [9u8; 32];
        let execution_id = ExecutionId::from([7u8; 32]);
        let entry = "main".to_string();
        let honest_party0_addr = reserve_local_addr();
        let honest_party1_addr = reserve_local_addr();
        let attacker_addr = reserve_local_addr();

        let mut party0_net = QuicNetworkManager::new();
        let party0_conn = party0_net
            .connect(bootnode_addr)
            .await
            .expect("party0 connects to bootnode");
        let party0_public_key = party0_net
            .get_public_key()
            .cloned()
            .expect("party0 has TLS identity");
        send_ctrl(
            &*party0_conn,
            &DiscoveryMessage::RegisterWithSession {
                execution_id,
                party_id: 0,
                listen_addr: honest_party0_addr,
                program_id,
                entry: entry.clone(),
                n_parties: 2,
                threshold: 1,
                auth_token: auth_token.clone(),
                tls_derived_id: Some(party0_public_key.derive_id()),
                tls_public_key: Some(party0_public_key.0),
            },
        )
        .await
        .expect("party0 registration succeeds");

        let mut attacker_net = QuicNetworkManager::new();
        let attacker_conn = attacker_net
            .connect(bootnode_addr)
            .await
            .expect("attacker connects to bootnode");
        send_ctrl(
            &*attacker_conn,
            &DiscoveryMessage::RegisterWithSession {
                execution_id,
                party_id: 0,
                listen_addr: attacker_addr,
                program_id,
                entry: entry.clone(),
                n_parties: 2,
                threshold: 1,
                auth_token: "bad-token".to_string(),
                tls_derived_id: None,
                tls_public_key: None,
            },
        )
        .await
        .expect("attacker registration message is delivered");

        let mut party1_net = QuicNetworkManager::new();
        let party1_conn = party1_net
            .connect(bootnode_addr)
            .await
            .expect("party1 connects to bootnode");
        let party1_public_key = party1_net
            .get_public_key()
            .cloned()
            .expect("party1 has TLS identity");
        send_ctrl(
            &*party1_conn,
            &DiscoveryMessage::RegisterWithSession {
                execution_id,
                party_id: 1,
                listen_addr: honest_party1_addr,
                program_id,
                entry,
                n_parties: 2,
                threshold: 1,
                auth_token,
                tls_derived_id: Some(party1_public_key.derive_id()),
                tls_public_key: Some(party1_public_key.0),
            },
        )
        .await
        .expect("party1 registration succeeds");

        let party0_info = recv_session_announce(&*party0_conn).await;
        let party1_info = recv_session_announce(&*party1_conn).await;

        let party_map: HashMap<PartyId, SocketAddr> = party0_info.parties.iter().copied().collect();
        assert_eq!(
            party_map.get(&0),
            Some(&honest_party0_addr),
            "session should keep the authentic address for party 0"
        );
        assert_eq!(
            party_map.get(&1),
            Some(&honest_party1_addr),
            "session should include party 1's authentic address"
        );
        assert!(
            !party_map.values().any(|addr| *addr == attacker_addr),
            "session party list must exclude attacker-controlled address"
        );
        assert_eq!(
            party1_info.parties.len(),
            2,
            "all parties should observe the same two-party session"
        );

        bootnode.abort();
        let _ = bootnode.await;
    }
}
