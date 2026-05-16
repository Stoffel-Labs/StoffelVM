//! Bootnode-based discovery for StoffelVM over QUIC.
//! Supports both direct connections and NAT traversal via ICE hole punching.
mod bootnode;

use super::session::{SessionInfo, SessionMessage};
use bincode;
use bootnode::{spawn_connection_handler, BootnodeState};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr, time::Duration};
use stoffelnet::network_utils::{Network, PartyId};
use stoffelnet::transports::quic::{
    NetworkManager, PeerConnection, QuicNetworkConfig, QuicNetworkManager,
};

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
use tokio::time::sleep;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiscoveryMessage {
    Register {
        party_id: PartyId,
        listen_addr: SocketAddr,
        /// Optional shared secret for registration authentication
        auth_token: Option<String>,
    },
    /// Register with session info - used when party wants to join a specific session
    RegisterWithSession {
        party_id: PartyId,
        listen_addr: SocketAddr,
        program_id: [u8; 32],
        entry: String,
        n_parties: usize,
        threshold: usize,
        /// Optional program bytes - first party to provide these becomes the source
        program_bytes: Option<Vec<u8>>,
        /// Optional shared secret for registration authentication
        auth_token: Option<String>,
        /// TLS-derived identity (hash of certificate public key) so peers can
        /// pre-register this party in their allowlist before accept().
        tls_derived_id: Option<PartyId>,
    },
    /// Request to fetch program bytes from bootnode
    ProgramFetchRequest {
        program_id: [u8; 32],
    },
    /// Program bytes response from bootnode
    ProgramFetchResponse {
        program_id: [u8; 32],
        bytes: Vec<u8>,
    },
    RequestPeers,
    PeerList {
        peers: Vec<(PartyId, SocketAddr)>,
    },
    PeerJoined {
        party_id: PartyId,
        listen_addr: SocketAddr,
    },
    PeerLeft {
        party_id: PartyId,
    },
    Heartbeat,
    /// ICE candidates for NAT traversal - sent via bootnode as signaling relay
    IceCandidates {
        from_party_id: PartyId,
        to_party_id: PartyId,
        ufrag: String,
        pwd: String,
        candidates: Vec<IceCandidate>,
    },
    /// Request ICE candidate exchange with a peer
    IceExchangeRequest {
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

fn registration_token_is_valid(
    required_auth_token: Option<&str>,
    message_auth_token: Option<&str>,
) -> bool {
    match required_auth_token {
        Some(expected) => match message_auth_token {
            Some(provided) => constant_time_eq(expected.as_bytes(), provided.as_bytes()),
            None => false,
        },
        None => true,
    }
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

/// Bootnode: accepts party registrations and shares membership updates.
/// Supports session-aware registration where parties specify the program they want to run.
/// When enough parties register for the same session, bootnode broadcasts SessionAnnounce.
pub async fn run_bootnode(bind: SocketAddr) -> Result<(), String> {
    run_bootnode_with_config(bind, None).await
}

/// Run bootnode with optional expected party count for session management.
/// If n_parties is Some, bootnode will wait for exactly that many parties before
/// announcing the session. If None, uses the n_parties from first RegisterWithSession.
pub async fn run_bootnode_with_config(
    bind: SocketAddr,
    expected_parties: Option<usize>,
) -> Result<(), String> {
    let required_auth_token = required_discovery_auth_token("bootnode discovery registration")?;
    eprintln!("[bootnode] Discovery registration authentication enabled");
    run_bootnode_with_config_and_auth(bind, expected_parties, Some(required_auth_token)).await
}

async fn run_bootnode_with_config_and_auth(
    bind: SocketAddr,
    expected_parties: Option<usize>,
    required_auth_token: Option<String>,
) -> Result<(), String> {
    let mut net = QuicNetworkManager::with_config(QuicNetworkConfig {
        use_tls: false,
        ..Default::default()
    });
    net.listen(bind).await?;
    let state = BootnodeState::new(expected_parties);

    eprintln!("[bootnode] Listening on {}", bind);

    loop {
        let conn = net.accept().await?;
        spawn_connection_handler(conn, state.clone(), required_auth_token.clone());
    }
}

/// Party-side bootstrap: connect to bootnode, register, fetch peers, and connect to them.
pub async fn bootstrap_with_bootnode(
    net: &mut QuicNetworkManager,
    bootnode: SocketAddr,
    my_party_id: PartyId,
    my_listen: SocketAddr,
) -> Result<(), String> {
    let bn_conn = net.connect(bootnode).await?;
    let auth_token = required_discovery_auth_token("party discovery registration")?;

    // Register
    send_ctrl(
        &*bn_conn,
        &DiscoveryMessage::Register {
            party_id: my_party_id,
            listen_addr: my_listen,
            auth_token: Some(auth_token),
        },
    )
    .await?;

    // Request peers
    send_ctrl(&*bn_conn, &DiscoveryMessage::RequestPeers).await?;

    // Receive initial list and connect
    if let Ok(buf) = bn_conn.receive().await {
        if let Ok(DiscoveryMessage::PeerList { peers }) =
            bincode::deserialize::<DiscoveryMessage>(&buf)
        {
            for (pid, addr) in peers {
                if pid == my_party_id {
                    continue;
                }
                // Track node and connect best-effort
                add_node_and_connect(net, pid, addr).await;
            }
        }
    }

    Ok(())
}

/// Connect to a peer with timeout and retry logic (direct connection)
async fn add_node_and_connect(net: &mut QuicNetworkManager, party_id: PartyId, addr: SocketAddr) {
    net.add_node_with_party_id(party_id, addr);

    // Retry connection with exponential backoff
    let max_retries = 3;
    let base_timeout = Duration::from_secs(10);

    for attempt in 0..max_retries {
        let timeout_duration = base_timeout * (1 << attempt); // Exponential backoff: 10s, 20s, 40s

        eprintln!(
            "[peer-connect] Attempting to connect to party {} at {} (attempt {}/{}, timeout {:?})",
            party_id,
            addr,
            attempt + 1,
            max_retries,
            timeout_duration
        );

        match tokio::time::timeout(timeout_duration, net.connect(addr)).await {
            Ok(Ok(_conn)) => {
                eprintln!(
                    "[peer-connect] Successfully connected to party {} at {} (attempt {})",
                    party_id,
                    addr,
                    attempt + 1
                );
                return;
            }
            Ok(Err(e)) => {
                eprintln!(
                    "[peer-connect] Connection error to party {} at {}: {} (attempt {}/{})",
                    party_id,
                    addr,
                    e,
                    attempt + 1,
                    max_retries
                );
            }
            Err(_) => {
                eprintln!(
                    "[peer-connect] Timeout connecting to party {} at {} after {:?} (attempt {}/{})",
                    party_id,
                    addr,
                    timeout_duration,
                    attempt + 1,
                    max_retries
                );
            }
        }

        // Longer delay before retry to allow other parties to settle
        if attempt < max_retries - 1 {
            let delay = Duration::from_millis(500 * (attempt as u64 + 1));
            eprintln!("[peer-connect] Waiting {:?} before retry...", delay);
            sleep(delay).await;
        }
    }

    eprintln!(
        "[peer-connect] WARNING: Could not connect to party {} at {} after {} attempts",
        party_id, addr, max_retries
    );
}

/// Connect to a peer using NAT traversal (ICE hole punching via bootnode signaling)
#[cfg(feature = "nat")]
async fn add_node_and_connect_nat(
    net: &mut QuicNetworkManager,
    my_party_id: PartyId,
    target_party_id: PartyId,
    target_addr: SocketAddr,
    bn_conn: &dyn PeerConnection,
) {
    net.add_node_with_party_id(target_party_id, target_addr);

    if !net.is_nat_traversal_enabled() {
        // Fall back to direct connection if NAT traversal is not enabled
        eprintln!(
            "[NAT] NAT traversal not enabled, using direct connection to party {}",
            target_party_id
        );
        add_node_and_connect_direct(net, target_party_id, target_addr).await;
        return;
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
            add_node_and_connect_direct(net, target_party_id, target_addr).await;
            return;
        }
    };

    eprintln!(
        "[NAT] Gathered {} local candidates, sending to party {} via bootnode",
        local_candidates.len(),
        target_party_id
    );

    // Step 2: Send our ICE candidates to the target party via bootnode
    let ice_msg = DiscoveryMessage::IceCandidates {
        from_party_id: my_party_id,
        to_party_id: target_party_id,
        ufrag: local_candidates.ufrag.clone(),
        pwd: local_candidates.pwd.clone(),
        candidates: local_candidates.candidates.clone(),
    };

    if let Err(e) = send_ctrl(bn_conn, &ice_msg).await {
        eprintln!("[NAT] Failed to send ICE candidates: {}", e);
        add_node_and_connect_direct(net, target_party_id, target_addr).await;
        return;
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
            add_node_and_connect_direct(net, target_party_id, target_addr).await;
            return;
        }

        match tokio::time::timeout(Duration::from_millis(100), bn_conn.receive()).await {
            Ok(Ok(buf)) => {
                if let Ok(DiscoveryMessage::IceCandidates {
                    from_party_id,
                    to_party_id: _,
                    ufrag: _,
                    pwd: _,
                    candidates: remote_candidates,
                }) = bincode::deserialize::<DiscoveryMessage>(&buf)
                {
                    if from_party_id == target_party_id {
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
                                net.connect(candidate.address),
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
                            return;
                        }

                        eprintln!(
                            "[NAT] All ICE candidates failed for party {}, trying direct",
                            target_party_id
                        );
                        add_node_and_connect_direct(net, target_party_id, target_addr).await;
                        return;
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
    add_node_and_connect_direct(net, target_party_id, target_addr).await;
}

/// Direct connection helper (used when NAT traversal fails or is disabled)
#[allow(dead_code)]
async fn add_node_and_connect_direct(
    net: &mut QuicNetworkManager,
    party_id: PartyId,
    addr: SocketAddr,
) {
    // Retry connection with exponential backoff
    let max_retries = 3;
    let base_timeout = Duration::from_secs(10);

    for attempt in 0..max_retries {
        let timeout_duration = base_timeout * (1 << attempt);

        eprintln!(
            "[peer-connect] Direct connect to party {} at {} (attempt {}/{}, timeout {:?})",
            party_id,
            addr,
            attempt + 1,
            max_retries,
            timeout_duration
        );

        match tokio::time::timeout(timeout_duration, net.connect(addr)).await {
            Ok(Ok(_conn)) => {
                eprintln!(
                    "[peer-connect] Direct connection established to party {} (attempt {})",
                    party_id,
                    attempt + 1
                );
                return;
            }
            Ok(Err(e)) => {
                eprintln!(
                    "[peer-connect] Direct connection error to party {}: {} (attempt {}/{})",
                    party_id,
                    e,
                    attempt + 1,
                    max_retries
                );
            }
            Err(_) => {
                eprintln!(
                    "[peer-connect] Direct connection timeout to party {} (attempt {}/{})",
                    party_id,
                    attempt + 1,
                    max_retries
                );
            }
        }

        if attempt < max_retries - 1 {
            let delay = Duration::from_millis(500 * (attempt as u64 + 1));
            sleep(delay).await;
        }
    }

    eprintln!(
        "[peer-connect] WARNING: Could not connect to party {} after {} attempts",
        party_id, max_retries
    );
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

/// Wait until at least n parties are in the QuicNetworkManager.parties() view (including self).
pub async fn wait_until_min_parties(
    net: &QuicNetworkManager,
    n: usize,
    timeout: Duration,
) -> Result<(), String> {
    let start = tokio::time::Instant::now();
    loop {
        if net.parties().len() >= n {
            return Ok(());
        }
        if start.elapsed() > timeout {
            return Err(format!(
                "timeout waiting for {} parties, have {}",
                n,
                net.parties().len()
            ));
        }
        sleep(Duration::from_millis(50)).await;
    }
}

/// Re-export program sync functions for convenience
pub async fn agree_and_sync_program(
    bn_conn: &dyn PeerConnection,
    my_party: PartyId,
    entry: &str,
    maybe_program_bytes: Option<Vec<u8>>,
) -> Result<([u8; 32], usize, String), String> {
    super::program_sync::agree_and_sync_program(bn_conn, my_party, entry, maybe_program_bytes)
        .await
        .map_err(String::from)
}

/// Re-export program ID computation
pub fn program_id_from_bytes(bytes: &[u8]) -> [u8; 32] {
    super::program_sync::program_id_from_bytes(bytes)
}

/// Configuration for joining a bootnode-announced MPC session.
#[derive(Debug, Clone)]
pub struct SessionRegistrationConfig {
    pub bootnode: SocketAddr,
    pub my_party_id: PartyId,
    pub my_listen: SocketAddr,
    pub program_id: [u8; 32],
    pub entry: String,
    pub n_parties: usize,
    pub threshold: usize,
    pub timeout: Duration,
    pub program_bytes: Option<Vec<u8>>,
}

impl SessionRegistrationConfig {
    pub fn with_program_bytes(mut self, program_bytes: Vec<u8>) -> Self {
        self.program_bytes = Some(program_bytes);
        self
    }
}

/// Register with bootnode for a specific session and wait for session to be announced.
/// This is the recommended way to join a multi-party session:
/// 1. Party connects to bootnode and sends RegisterWithSession (with optional program bytes)
/// 2. Bootnode waits until n_parties have registered
/// 3. Bootnode broadcasts SessionAnnounce to all parties
/// 4. This function returns with the agreed SessionInfo
///
/// All parties will receive the same instance_id, which is derived deterministically
/// from the program_id and a session nonce.
///
/// If `config.program_bytes` is Some, this party will upload the program to the bootnode.
/// Parties that don't have the program locally can pass None and later fetch it.
pub async fn register_and_wait_for_session(
    net: &mut QuicNetworkManager,
    config: SessionRegistrationConfig,
) -> Result<SessionInfo, String> {
    let SessionRegistrationConfig {
        bootnode,
        my_party_id,
        my_listen,
        program_id,
        entry,
        n_parties,
        threshold,
        timeout,
        program_bytes,
    } = config;
    let uploading_program = program_bytes.is_some();

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
        "[party {}] Registering with bootnode for session (program: {}, n={}, t={}, uploading={})",
        my_party_id,
        hex::encode(&program_id[..8]),
        n_parties,
        threshold,
        uploading_program
    );

    // Send session-aware registration with optional program bytes.
    // Include our TLS-derived ID so peers can pre-register us in their
    // allowlist for accept() with use_tls=true.
    let local_tls_id = net.local_derived_id();
    let reg_msg = DiscoveryMessage::RegisterWithSession {
        party_id: my_party_id,
        listen_addr: my_listen,
        program_id,
        entry,
        n_parties,
        threshold,
        program_bytes,
        auth_token: Some(auth_token),
        tls_derived_id: Some(local_tls_id),
    };
    send_ctrl(&*bn_conn, &reg_msg).await?;

    // Wait for SessionAnnounce from bootnode
    let start = tokio::time::Instant::now();
    loop {
        if start.elapsed() > timeout {
            return Err(format!(
                "Timeout waiting for session announcement after {:?}",
                timeout
            ));
        }

        match tokio::time::timeout(Duration::from_millis(100), bn_conn.receive()).await {
            Ok(Ok(buf)) => {
                // Try to parse as SessionMessage
                if let Ok(SessionMessage::SessionAnnounce(info)) =
                    bincode::deserialize::<SessionMessage>(&buf)
                {
                    eprintln!(
                        "[party {}] Received SessionAnnounce: instance_id={}, {} parties",
                        my_party_id,
                        info.instance_id,
                        info.parties.len()
                    );

                    // Build TLS-ID lookup from session info
                    let tls_id_map: HashMap<PartyId, PartyId> =
                        info.tls_ids.iter().cloned().collect();

                    // Add ALL peers to the node list using their TLS-derived IDs
                    // so that accept() recognises them with use_tls=true.
                    for (pid, addr) in &info.parties {
                        if *pid != my_party_id {
                            let node_id = tls_id_map.get(pid).copied().unwrap_or(*pid);
                            net.add_node_with_party_id(node_id, *addr);
                        }
                    }

                    // Peer connection strategy:
                    // - Lower-ID parties CONNECT to higher-ID parties
                    // - Higher-ID parties ACCEPT from lower-ID parties
                    // This avoids bidirectional connection races
                    let higher_peers: Vec<_> = info
                        .parties
                        .iter()
                        .filter(|(pid, _)| *pid > my_party_id)
                        .collect();
                    let n_expected_incoming = info
                        .parties
                        .iter()
                        .filter(|(pid, _)| *pid < my_party_id)
                        .count();

                    eprintln!(
                        "[party {}] Connection plan: {} outgoing (to higher IDs), {} incoming (from lower IDs)",
                        my_party_id, higher_peers.len(), n_expected_incoming
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

                        for (pid, addr) in &higher_peers {
                            if use_nat {
                                add_node_and_connect_nat(net, my_party_id, *pid, *addr, &*bn_conn)
                                    .await;
                            } else {
                                add_node_and_connect(net, *pid, *addr).await;
                            }
                        }
                    }

                    #[cfg(not(feature = "nat"))]
                    {
                        for (pid, addr) in higher_peers {
                            add_node_and_connect(net, *pid, *addr).await;
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
    use tokio::time::{sleep, timeout};

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

    async fn recv_peer_list(conn: &dyn PeerConnection) -> Vec<(PartyId, SocketAddr)> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            let now = tokio::time::Instant::now();
            assert!(now < deadline, "timed out waiting for PeerList");
            let remaining = deadline.duration_since(now);
            let buf = timeout(remaining, conn.receive())
                .await
                .expect("timed out waiting for discovery response")
                .expect("receive discovery response");
            match bincode::deserialize::<DiscoveryMessage>(&buf)
                .expect("deserialize discovery response")
            {
                DiscoveryMessage::PeerList { peers } => return peers,
                _ => continue,
            }
        }
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
    async fn unauthenticated_register_can_overwrite_existing_party_entry() {
        init_crypto_provider();
        let bootnode_addr = reserve_local_addr();
        let bootnode = tokio::spawn(run_bootnode_with_config_and_auth(bootnode_addr, None, None));
        sleep(Duration::from_millis(100)).await;

        let party_id = 7usize;
        let honest_addr = reserve_local_addr();
        let attacker_addr = reserve_local_addr();

        let mut honest_net = QuicNetworkManager::new();
        let honest_conn = honest_net
            .connect(bootnode_addr)
            .await
            .expect("honest party connects to bootnode");
        send_ctrl(
            &*honest_conn,
            &DiscoveryMessage::Register {
                party_id,
                listen_addr: honest_addr,
                auth_token: None,
            },
        )
        .await
        .expect("honest registration succeeds");
        let _ = recv_peer_list(&*honest_conn).await;

        let mut attacker_net = QuicNetworkManager::new();
        let attacker_conn = attacker_net
            .connect(bootnode_addr)
            .await
            .expect("attacker connects to bootnode");
        send_ctrl(
            &*attacker_conn,
            &DiscoveryMessage::Register {
                party_id,
                listen_addr: attacker_addr,
                auth_token: None,
            },
        )
        .await
        .expect("attacker registration succeeds");
        let _ = recv_peer_list(&*attacker_conn).await;

        send_ctrl(&*honest_conn, &DiscoveryMessage::RequestPeers)
            .await
            .expect("request peers");
        let peers = recv_peer_list(&*honest_conn).await;

        let mapped_addr = peers
            .iter()
            .find(|(pid, _)| *pid == party_id)
            .map(|(_, addr)| *addr);
        assert_eq!(
            mapped_addr,
            Some(attacker_addr),
            "without authentication, a second registration can overwrite an existing party entry"
        );

        bootnode.abort();
        let _ = bootnode.await;
    }

    #[tokio::test]
    async fn invalid_register_auth_token_cannot_overwrite_party_entry() {
        init_crypto_provider();
        let bootnode_addr = reserve_local_addr();
        let auth_token = "shared-secret".to_string();
        let bootnode = tokio::spawn(run_bootnode_with_config_and_auth(
            bootnode_addr,
            None,
            Some(auth_token.clone()),
        ));
        sleep(Duration::from_millis(100)).await;

        let party_id = 11usize;
        let honest_addr = reserve_local_addr();
        let attacker_addr = reserve_local_addr();

        let mut honest_net = QuicNetworkManager::new();
        let honest_conn = honest_net
            .connect(bootnode_addr)
            .await
            .expect("honest party connects to bootnode");
        send_ctrl(
            &*honest_conn,
            &DiscoveryMessage::Register {
                party_id,
                listen_addr: honest_addr,
                auth_token: Some(auth_token.clone()),
            },
        )
        .await
        .expect("honest registration succeeds");
        let _ = recv_peer_list(&*honest_conn).await;

        let mut attacker_net = QuicNetworkManager::new();
        let attacker_conn = attacker_net
            .connect(bootnode_addr)
            .await
            .expect("attacker connects to bootnode");
        send_ctrl(
            &*attacker_conn,
            &DiscoveryMessage::Register {
                party_id,
                listen_addr: attacker_addr,
                auth_token: Some("bad-token".to_string()),
            },
        )
        .await
        .expect("attacker message is delivered");

        // Allow bootnode task to process and reject attacker registration.
        sleep(Duration::from_millis(100)).await;

        send_ctrl(&*honest_conn, &DiscoveryMessage::RequestPeers)
            .await
            .expect("request peers");
        let peers = recv_peer_list(&*honest_conn).await;

        let mapped_addr = peers
            .iter()
            .find(|(pid, _)| *pid == party_id)
            .map(|(_, addr)| *addr);
        assert_eq!(
            mapped_addr,
            Some(honest_addr),
            "invalid auth token must not overwrite existing party mapping"
        );

        bootnode.abort();
        let _ = bootnode.await;
    }

    #[tokio::test]
    async fn invalid_session_register_auth_token_cannot_poison_session_parties() {
        init_crypto_provider();
        let bootnode_addr = reserve_local_addr();
        let auth_token = "session-secret".to_string();
        let bootnode = tokio::spawn(run_bootnode_with_config_and_auth(
            bootnode_addr,
            Some(2),
            Some(auth_token.clone()),
        ));
        sleep(Duration::from_millis(100)).await;

        let program_id = [9u8; 32];
        let entry = "main".to_string();
        let honest_party0_addr = reserve_local_addr();
        let honest_party1_addr = reserve_local_addr();
        let attacker_addr = reserve_local_addr();

        let mut party0_net = QuicNetworkManager::new();
        let party0_conn = party0_net
            .connect(bootnode_addr)
            .await
            .expect("party0 connects to bootnode");
        send_ctrl(
            &*party0_conn,
            &DiscoveryMessage::RegisterWithSession {
                party_id: 0,
                listen_addr: honest_party0_addr,
                program_id,
                entry: entry.clone(),
                n_parties: 2,
                threshold: 1,
                program_bytes: None,
                auth_token: Some(auth_token.clone()),
                tls_derived_id: None,
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
                party_id: 0,
                listen_addr: attacker_addr,
                program_id,
                entry: entry.clone(),
                n_parties: 2,
                threshold: 1,
                program_bytes: None,
                auth_token: Some("bad-token".to_string()),
                tls_derived_id: None,
            },
        )
        .await
        .expect("attacker registration message is delivered");

        let mut party1_net = QuicNetworkManager::new();
        let party1_conn = party1_net
            .connect(bootnode_addr)
            .await
            .expect("party1 connects to bootnode");
        send_ctrl(
            &*party1_conn,
            &DiscoveryMessage::RegisterWithSession {
                party_id: 1,
                listen_addr: honest_party1_addr,
                program_id,
                entry,
                n_parties: 2,
                threshold: 1,
                program_bytes: None,
                auth_token: Some(auth_token),
                tls_derived_id: None,
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
