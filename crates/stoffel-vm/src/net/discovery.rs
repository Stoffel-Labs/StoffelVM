//! Simple bootnode-based discovery for StoffelVM over QUIC.
//! Assumes nodes are directly reachable (no NAT traversal).
use super::program_sync::{
    send_ctrl as send_prog_ctrl, send_program_bytes, ProgramSyncMessage,
};
use super::session::{derive_instance_id, SessionInfo, SessionMessage};
use bincode;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use stoffelnet::network_utils::{Network, PartyId};
use stoffelnet::transports::quic::{NetworkManager, PeerConnection, QuicNetworkManager};
use tokio::{
    sync::{watch, Mutex},
    time::sleep,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiscoveryMessage {
    Register {
        party_id: PartyId,
        listen_addr: SocketAddr,
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
}

/// Pending session state at bootnode
#[derive(Debug, Clone)]
struct PendingSession {
    program_id: [u8; 32],
    entry: String,
    n_parties: usize,
    threshold: usize,
    /// Parties that have registered for this session
    parties: HashMap<PartyId, SocketAddr>,
    /// Session nonce (timestamp-based for uniqueness)
    nonce: u64,
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
    let mut net = QuicNetworkManager::new();
    net.listen(bind).await?;
    let state: Arc<Mutex<HashMap<PartyId, SocketAddr>>> = Arc::new(Mutex::new(HashMap::new()));
    // Program/Session agreement state: single active session for simplicity
    let session_state: Arc<Mutex<Option<SessionInfo>>> = Arc::new(Mutex::new(None));
    let uploader_bytes: Arc<Mutex<Option<Arc<Vec<u8>>>>> = Arc::new(Mutex::new(None));
    // Pending session: parties waiting for session to start
    let pending_session: Arc<Mutex<Option<PendingSession>>> = Arc::new(Mutex::new(None));
    let expected_parties = Arc::new(Mutex::new(expected_parties));
    // Watch channel for session ready notification
    let (session_tx, _session_rx) = watch::channel::<Option<SessionInfo>>(None);
    let session_tx = Arc::new(session_tx);

    eprintln!("[bootnode] Listening on {}", bind);

    loop {
        let mut conn = net.accept().await?;
        let state = state.clone();
        let session_state = session_state.clone();
        let uploader_bytes = uploader_bytes.clone();
        let pending_session = pending_session.clone();
        let expected_parties = expected_parties.clone();
        let session_tx = session_tx.clone();
        let mut session_rx = session_tx.subscribe();

        tokio::spawn(async move {
            // Track if this connection registered for a session
            let mut waiting_for_session = false;

            loop {
                // If waiting for session, check if it's ready
                if waiting_for_session {
                    // Check if session is already available - clone to avoid holding borrow across await
                    let session_info = session_rx.borrow().clone();
                    if let Some(info) = session_info {
                        // Send session announce
                        let announce = SessionMessage::SessionAnnounce(info);
                        let announce_bytes = bincode::serialize(&announce).unwrap();
                        let _ = conn.send(&announce_bytes).await;
                        waiting_for_session = false;
                    }
                }

                // Use a short timeout to allow checking session state
                match tokio::time::timeout(Duration::from_millis(50), conn.receive()).await {
                    Ok(Ok(buf)) => {
                        if let Ok(msg) = bincode::deserialize::<DiscoveryMessage>(&buf) {
                            match msg {
                                DiscoveryMessage::Register {
                                    party_id,
                                    listen_addr,
                                } => {
                                    let mut st = state.lock().await;
                                    let is_new = !st.contains_key(&party_id);
                                    st.insert(party_id, listen_addr);

                                    // reply with full peer list (excluding self)
                                    let peers: Vec<(PartyId, SocketAddr)> = st
                                        .iter()
                                        .filter(|(pid, _)| **pid != party_id)
                                        .map(|(pid, addr)| (*pid, *addr))
                                        .collect();
                                    let reply = DiscoveryMessage::PeerList { peers };
                                    let _ = send_ctrl(&*conn, &reply).await;

                                    // notify others if new
                                    if is_new {
                                        let joined = DiscoveryMessage::PeerJoined {
                                            party_id,
                                            listen_addr,
                                        };
                                        let _ = send_ctrl(&*conn, &joined).await;
                                    }
                                }
                                DiscoveryMessage::RegisterWithSession {
                                    party_id,
                                    listen_addr,
                                    program_id,
                                    entry,
                                    n_parties,
                                    threshold,
                                    program_bytes,
                                } => {
                                    eprintln!(
                                        "[bootnode] Party {} registering for session (program: {}, n={}, t={}, has_bytes={})",
                                        party_id,
                                        hex::encode(&program_id[..8]),
                                        n_parties,
                                        threshold,
                                        program_bytes.is_some()
                                    );

                                    // Store program bytes if provided and we don't have them yet
                                    if let Some(bytes) = program_bytes {
                                        let mut ub = uploader_bytes.lock().await;
                                        if ub.is_none() {
                                            eprintln!(
                                                "[bootnode] Storing program bytes from party {} ({} bytes)",
                                                party_id,
                                                bytes.len()
                                            );
                                            *ub = Some(Arc::new(bytes));
                                        }
                                    }

                                    // Update peer state
                                    {
                                        let mut st = state.lock().await;
                                        st.insert(party_id, listen_addr);
                                    }

                                    // Mark this connection as waiting for session
                                    waiting_for_session = true;

                                    // Check/create pending session
                                    let mut pending = pending_session.lock().await;
                                    let expected = expected_parties.lock().await;
                                    let target_n = expected.unwrap_or(n_parties);

                                    if pending.is_none() {
                                        // Create new pending session
                                        let nonce = std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .map(|d| d.as_nanos() as u64)
                                            .unwrap_or(0);
                                        let mut parties = HashMap::new();
                                        parties.insert(party_id, listen_addr);
                                        *pending = Some(PendingSession {
                                            program_id,
                                            entry,
                                            n_parties: target_n,
                                            threshold,
                                            parties,
                                            nonce,
                                        });
                                        eprintln!(
                                            "[bootnode] Created pending session, waiting for {} parties (have 1)",
                                            target_n
                                        );
                                    } else {
                                        // Add to existing pending session
                                        let ps = pending.as_mut().unwrap();
                                        if ps.program_id != program_id {
                                            eprintln!(
                                                "[bootnode] Warning: party {} has different program_id",
                                                party_id
                                            );
                                            // For now, reject mismatched programs
                                            let _ = send_ctrl(&*conn, &DiscoveryMessage::PeerLeft {
                                                party_id,
                                            }).await;
                                            waiting_for_session = false;
                                            continue;
                                        }
                                        ps.parties.insert(party_id, listen_addr);
                                        eprintln!(
                                            "[bootnode] Party {} joined, have {}/{} parties",
                                            party_id,
                                            ps.parties.len(),
                                            ps.n_parties
                                        );
                                    }

                                    // Check if session is ready
                                    let session_ready = {
                                        let ps = pending.as_ref().unwrap();
                                        ps.parties.len() >= ps.n_parties
                                    };

                                    if session_ready {
                                        let ps = pending.take().unwrap();
                                        let instance_id = derive_instance_id(&ps.program_id, ps.nonce);
                                        let parties: Vec<(PartyId, SocketAddr)> =
                                            ps.parties.into_iter().collect();

                                        let session_info = SessionInfo {
                                            program_id: ps.program_id,
                                            instance_id,
                                            entry: ps.entry,
                                            parties: parties.clone(),
                                            n_parties: ps.n_parties,
                                            threshold: ps.threshold,
                                        };

                                        eprintln!(
                                            "[bootnode] Session ready! instance_id={}, n_parties={}",
                                            instance_id,
                                            session_info.n_parties
                                        );

                                        // Store active session and notify all waiting connections
                                        {
                                            let mut ss = session_state.lock().await;
                                            *ss = Some(session_info.clone());
                                        }

                                        // Broadcast via watch channel - all waiting handlers will see this
                                        let _ = session_tx.send(Some(session_info));
                                    }
                                }
                                DiscoveryMessage::RequestPeers => {
                                    let st = state.lock().await;
                                    let peers: Vec<(PartyId, SocketAddr)> =
                                        st.iter().map(|(pid, addr)| (*pid, *addr)).collect();
                                    let _ =
                                        send_ctrl(&*conn, &DiscoveryMessage::PeerList { peers })
                                            .await;
                                }
                                DiscoveryMessage::Heartbeat => {
                                    // Ignored in this minimal version
                                }
                                DiscoveryMessage::ProgramFetchRequest { program_id } => {
                                    // Send cached program bytes if available
                                    let bytes_opt = uploader_bytes.lock().await.clone();
                                    if let Some(bytes) = bytes_opt {
                                        eprintln!(
                                            "[bootnode] Sending program bytes ({} bytes) for {}",
                                            bytes.len(),
                                            hex::encode(&program_id[..8])
                                        );
                                        let resp = DiscoveryMessage::ProgramFetchResponse {
                                            program_id,
                                            bytes: bytes.to_vec(),
                                        };
                                        let _ = send_ctrl(&*conn, &resp).await;
                                    } else {
                                        eprintln!(
                                            "[bootnode] Program fetch request for {} but no bytes cached",
                                            hex::encode(&program_id[..8])
                                        );
                                    }
                                }
                                _ => {}
                            }
                        } else if let Ok(ps) = bincode::deserialize::<ProgramSyncMessage>(&buf) {
                            // Handle program sync messages
                            match ps {
                                ProgramSyncMessage::ProgramAnnounce { .. } => {
                                    // Respond with program sync logic if needed
                                    // For now, just echo back
                                    let _ = send_prog_ctrl(&*conn, &ps).await;
                                }
                                ProgramSyncMessage::ProgramFetchRequest { program_id } => {
                                    // Send cached program bytes if available
                                    let bytes_opt = uploader_bytes.lock().await.clone();
                                    if let Some(bytes) = bytes_opt {
                                        let _ = send_program_bytes(&*conn, program_id, bytes).await;
                                    }
                                }
                                _ => {}
                            }
                        } else if let Ok(sess) = bincode::deserialize::<SessionMessage>(&buf) {
                            match sess {
                                SessionMessage::SessionAnnounce(_) => { /* not expected from clients */
                                }
                                SessionMessage::SessionAck { party_id, instance_id, .. } => {
                                    eprintln!(
                                        "[bootnode] Received SessionAck from party {} for instance {}",
                                        party_id, instance_id
                                    );
                                }
                                _ => {}
                            }
                        }
                    }
                    Ok(Err(_)) => {
                        // Connection error, exit loop
                        break;
                    }
                    Err(_) => {
                        // Timeout, continue loop to check session state
                        continue;
                    }
                }
            }
        });
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

    // Register
    send_ctrl(
        &*bn_conn,
        &DiscoveryMessage::Register {
            party_id: my_party_id,
            listen_addr: my_listen,
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

/// Connect to a peer with timeout and retry logic
async fn add_node_and_connect(net: &mut QuicNetworkManager, party_id: PartyId, addr: SocketAddr) {
    net.add_node_with_party_id(party_id, addr);

    // Retry connection with exponential backoff
    let max_retries = 3;
    let base_timeout = Duration::from_secs(10);

    for attempt in 0..max_retries {
        let timeout_duration = base_timeout * (1 << attempt); // Exponential backoff: 10s, 20s, 40s

        eprintln!(
            "[peer-connect] Attempting to connect to party {} at {} (attempt {}/{}, timeout {:?})",
            party_id, addr, attempt + 1, max_retries, timeout_duration
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

async fn send_ctrl(conn: &dyn PeerConnection, msg: &DiscoveryMessage) -> Result<(), String> {
    let bytes = bincode::serialize(msg).map_err(|e| e.to_string())?;
    conn.send(bytes.as_slice()).await.map_err(|e| e.to_string())
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
    super::program_sync::agree_and_sync_program(bn_conn, my_party, entry, maybe_program_bytes).await
}

/// Re-export program ID computation
pub fn program_id_from_bytes(bytes: &[u8]) -> [u8; 32] {
    super::program_sync::program_id_from_bytes(bytes)
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
/// If `program_bytes` is Some, this party will upload the program to the bootnode.
/// Parties that don't have the program locally can pass None and later fetch it.
pub async fn register_and_wait_for_session(
    net: &mut QuicNetworkManager,
    bootnode: SocketAddr,
    my_party_id: PartyId,
    my_listen: SocketAddr,
    program_id: [u8; 32],
    entry: &str,
    n_parties: usize,
    threshold: usize,
    timeout: Duration,
) -> Result<SessionInfo, String> {
    register_and_wait_for_session_with_program(
        net,
        bootnode,
        my_party_id,
        my_listen,
        program_id,
        entry,
        n_parties,
        threshold,
        timeout,
        None,
    )
    .await
}

/// Same as `register_and_wait_for_session` but allows passing program bytes.
/// If `program_bytes` is Some, the bytes will be uploaded to the bootnode for other parties to fetch.
pub async fn register_and_wait_for_session_with_program(
    net: &mut QuicNetworkManager,
    bootnode: SocketAddr,
    my_party_id: PartyId,
    my_listen: SocketAddr,
    program_id: [u8; 32],
    entry: &str,
    n_parties: usize,
    threshold: usize,
    timeout: Duration,
    program_bytes: Option<Vec<u8>>,
) -> Result<SessionInfo, String> {
    let bn_conn = net.connect(bootnode).await?;

    eprintln!(
        "[party {}] Registering with bootnode for session (program: {}, n={}, t={}, uploading={})",
        my_party_id,
        hex::encode(&program_id[..8]),
        n_parties,
        threshold,
        program_bytes.is_some()
    );

    // Send session-aware registration with optional program bytes
    let reg_msg = DiscoveryMessage::RegisterWithSession {
        party_id: my_party_id,
        listen_addr: my_listen,
        program_id,
        entry: entry.to_string(),
        n_parties,
        threshold,
        program_bytes,
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

                    // Add ALL peers to the node list first
                    for (pid, addr) in &info.parties {
                        if *pid != my_party_id {
                            net.add_node_with_party_id(*pid, *addr);
                        }
                    }

                    // Peer connection strategy:
                    // - Lower-ID parties CONNECT to higher-ID parties
                    // - Higher-ID parties ACCEPT from lower-ID parties
                    // This avoids bidirectional connection races
                    let higher_peers: Vec<_> = info.parties.iter()
                        .filter(|(pid, _)| *pid > my_party_id)
                        .collect();
                    let n_expected_incoming = info.parties.iter()
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

                        while accepted < n_expected_incoming && accept_start.elapsed() < accept_timeout {
                            match tokio::time::timeout(Duration::from_secs(10), acceptor.accept()).await {
                                Ok(Ok(conn)) => {
                                    eprintln!(
                                        "[party {}] Accepted connection from {} ({}/{})",
                                        acceptor_party_id, conn.remote_address(), accepted + 1, n_expected_incoming
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
                                        acceptor_party_id, n_expected_incoming - accepted, accepted, n_expected_incoming
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
                    for (pid, addr) in higher_peers {
                        add_node_and_connect(net, *pid, *addr).await;
                    }

                    // Wait for accept loop to finish
                    match tokio::time::timeout(Duration::from_secs(90), accept_handle).await {
                        Ok(Ok(n)) => {
                            eprintln!(
                                "[party {}] Peer mesh established: {} outgoing, {} accepted",
                                my_party_id, info.parties.len() - 1 - n_expected_incoming, n
                            );
                        }
                        Ok(Err(e)) => {
                            eprintln!(
                                "[party {}] Accept task error: {:?}",
                                my_party_id, e
                            );
                        }
                        Err(_) => {
                            eprintln!(
                                "[party {}] Accept task timed out",
                                my_party_id
                            );
                        }
                    }

                    // Create loopback connection to self (required by MPC protocols)
                    // Some MPC operations send messages to self, requiring a connection entry
                    let my_addr = info.parties.iter()
                        .find(|(pid, _)| *pid == my_party_id)
                        .map(|(_, addr)| *addr);
                    if let Some(addr) = my_addr {
                        eprintln!("[party {}] Establishing loopback connection to self at {}", my_party_id, addr);
                        match tokio::time::timeout(Duration::from_secs(5), net.connect(addr)).await {
                            Ok(Ok(_)) => {
                                eprintln!("[party {}] Loopback connection established", my_party_id);
                            }
                            Ok(Err(e)) => {
                                eprintln!("[party {}] Loopback connection failed: {} (non-fatal)", my_party_id, e);
                            }
                            Err(_) => {
                                eprintln!("[party {}] Loopback connection timed out (non-fatal)", my_party_id);
                            }
                        }
                    }

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
