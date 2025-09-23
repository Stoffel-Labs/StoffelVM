//! Simple bootnode-based discovery for StoffelVM over QUIC.
//! Assumes nodes are directly reachable (no NAT traversal).
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use bincode;
use serde::{Deserialize, Serialize};
use tokio::{sync::Mutex, time::sleep};
use stoffelnet::network_utils::{Network, PartyId};
use crate::net::NetworkManager;
use super::p2p::QuicNetworkManager;
use super::program_sync::{ProgramSyncMessage, send_ctrl as send_prog_ctrl, recv_ctrl as recv_prog_ctrl, send_program_bytes};
use super::session::{SessionInfo, SessionMessage, random_instance_id, CONTROL_STREAM_ID, PROGRAM_STREAM_ID};

const BOOTNODE_STREAM_ID: u64 = CONTROL_STREAM_ID;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiscoveryMessage {
    Register { party_id: PartyId, listen_addr: SocketAddr },
    RequestPeers,
    PeerList { peers: Vec<(PartyId, SocketAddr)> },
    PeerJoined { party_id: PartyId, listen_addr: SocketAddr },
    PeerLeft { party_id: PartyId },
    Heartbeat,
}

/// Bootnode: accepts party registrations and shares membership updates.
pub async fn run_bootnode(bind: SocketAddr) -> Result<(), String> {
    let mut net = QuicNetworkManager::new();
    net.listen(bind).await?;
    let state: Arc<Mutex<HashMap<PartyId, SocketAddr>>> = Arc::new(Mutex::new(HashMap::new()));
    // Program/Session agreement state: single active session for simplicity
    let session_state: Arc<Mutex<Option<SessionInfo>>> = Arc::new(Mutex::new(None));
    let uploader_bytes: Arc<Mutex<Option<Arc<Vec<u8>>>>> = Arc::new(Mutex::new(None));
    let mut instance_id_opt: Option<u64> = None;

    loop {
        let mut conn = net.accept().await?;
        let state = state.clone();
        let session_state = session_state.clone();
        let uploader_bytes = uploader_bytes.clone();
        tokio::spawn(async move {
            // We only use CONTROL_STREAM_ID for control plane messages.
            loop {
                match conn.receive_from_stream(CONTROL_STREAM_ID).await {
                    Ok(buf) => {
                        if let Ok(msg) = bincode::deserialize::<DiscoveryMessage>(&buf) {
                            match msg {
                                DiscoveryMessage::Register { party_id, listen_addr } => {
                                    let mut st = state.lock().await;
                                    let is_new = !st.contains_key(&party_id);
                                    st.insert(party_id, listen_addr);

                                    // reply with full peer list (excluding self)
                                    let peers: Vec<(PartyId, SocketAddr)> = st.iter()
                                        .filter(|(pid, _)| **pid != party_id)
                                        .map(|(pid, addr)| (*pid, *addr))
                                        .collect();
                                    let reply = DiscoveryMessage::PeerList { peers };
                                    let _ = send_ctrl(&mut *conn, &reply).await;

                                    // notify others if new
                                    if is_new {
                                        let joined = DiscoveryMessage::PeerJoined { party_id, listen_addr };
                                        // Best-effort: we don't have their direct connections here,
                                        // parties are expected to maintain their bootnode stream and receive this.
                                        // No-op: the joined broadcast is handled here by just sending to this conn.
                                        // Other parties will get their updates from their own connections.
                                        let _ = send_ctrl(&mut *conn, &joined).await;
                                    }
                                }
                                DiscoveryMessage::RequestPeers => {
                                    let st = state.lock().await;
                                    let peers: Vec<(PartyId, SocketAddr)> = st.iter()
                                        .map(|(pid, addr)| (*pid, *addr)).collect();
                                    let _ = send_ctrl(&mut *conn, &DiscoveryMessage::PeerList { peers }).await;
                                }
                                DiscoveryMessage::Heartbeat => {
                                    // Ignored in this minimal version
                                }
                                _ => {}
                            }
                        } else if let Ok(ps) = bincode::deserialize::<ProgramSyncMessage>(&buf) {
                            match ps {
                                ProgramSyncMessage::ProgramAnnounce { party_id, program_id, size, entry } => {
                                    // If session does not exist, initialize it and instance id
                                    let mut sess_guard = session_state.lock().await;
                                    if sess_guard.is_none() {
                                        let parties: Vec<(PartyId, SocketAddr)> = state.lock().await.iter().map(|(p,a)| (*p,*a)).collect();
                                        let inst = instance_id_opt.get_or_insert(random_instance_id()).to_owned();
                                        let info = SessionInfo {
                                            program_id,
                                            instance_id: inst,
                                            entry: entry.clone(),
                                            parties,
                                        };
                                        *sess_guard = Some(info.clone());
                                    }
                                    // Echo authoritative announce back to this party
                                    let info = sess_guard.clone().unwrap();
                                    let back = ProgramSyncMessage::ProgramAnnounce {
                                        party_id,
                                        program_id: info.program_id,
                                        size,
                                        entry: info.entry.clone(),
                                    };
                                    let _ = send_prog_ctrl(&mut *conn, &back).await;
                                }
                                ProgramSyncMessage::ProgramAck { .. } => {
                                    // ignore
                                }
                                ProgramSyncMessage::ProgramFetchRequest { program_id, ranges: _ } => {
                                    // stream program bytes from stored uploader buffer if present
                                    if let Some(bytes_arc) = uploader_bytes.lock().await.clone() {
                                        let _ = send_program_bytes(&mut *conn, program_id, bytes_arc).await;
                                    } else {
                                        // If no cached program, we expect sender to push bytes on PROGRAM_STREAM_ID frames
                                        // We'll receive and cache them here.
                                        // For simplicity, skip server-side caching in this minimal version.
                                    }
                                }
                                ProgramSyncMessage::ProgramComplete { .. } => {}
                            }
                        } else if let Ok(sess) = bincode::deserialize::<SessionMessage>(&buf) {
                            match sess {
                                SessionMessage::SessionAnnounce(_) => { /* not expected from clients */ }
                                SessionMessage::SessionAck { .. } => { /* optional: track */ }
                            }
                        } else {
                            // Unknown control message
                        }
                    }
                    Err(_) => {
                        // Remote closed control stream; we cannot map connection to a party id here reliably.
                        // Minimal version: sleep and end handler.
                        sleep(Duration::from_millis(10)).await;
                        break;
                    }
                }
            }
        });
    }
}

/// Party-side bootstrap: connect to bootnode, register, fetch peers, and connect to them.
/// - net should already be listening on my_listen for inbound peer connects (optional but recommended).
pub async fn bootstrap_with_bootnode(
    net: &mut QuicNetworkManager,
    bootnode: SocketAddr,
    my_party_id: PartyId,
    my_listen: SocketAddr,
) -> Result<(), String> {
    let mut bn_conn = net.connect(bootnode).await?;
    // Register
    send_ctrl(&mut *bn_conn, &DiscoveryMessage::Register {
        party_id: my_party_id,
        listen_addr: my_listen,
    }).await?;

    // Request peers
    send_ctrl(&mut *bn_conn, &DiscoveryMessage::RequestPeers).await?;

    // Receive initial list and connect
    if let Ok(buf) = bn_conn.receive_from_stream(BOOTNODE_STREAM_ID).await {
        if let Ok(DiscoveryMessage::PeerList { peers }) = bincode::deserialize::<DiscoveryMessage>(&buf) {
            for (pid, addr) in peers {
                if pid == my_party_id { continue; }
                // Track node and connect best-effort
                add_node_and_connect(net, pid, addr).await;
            }
        }
    }

/*    // Background task: listen for updates on bootnode control stream
    let net_clone = net.clone();
    tokio::spawn(async move {
        let mut bn_conn = bn_conn;
        loop {
            match bn_conn.receive_from_stream(BOOTNODE_STREAM_ID).await {
                Ok(buf) => {
                    if let Ok((msg, _)) = decode_from_slice::<DiscoveryMessage, _>(&buf, standard()) {
                        match msg {
                            DiscoveryMessage::PeerJoined { party_id, listen_addr } => {
                                if party_id != my_party_id {
                                    let mut mgr = net_clone.clone();
                                    add_node_and_connect(&mut mgr, party_id, listen_addr).await;
                                }
                            }
                            DiscoveryMessage::PeerLeft { party_id: _ } => {
                                // Minimal version: ignore; connection drops will be observed by sender.
                            }
                            DiscoveryMessage::PeerList { peers } => {
                                for (pid, addr) in peers {
                                    if pid == my_party_id { continue; }
                                    let mut mgr = net_clone.clone();
                                    add_node_and_connect(&mut mgr, pid, addr).await;
                                }
                            }
                            DiscoveryMessage::Heartbeat | DiscoveryMessage::Register { .. } | DiscoveryMessage::RequestPeers => {}
                        }
                    }
                }
                Err(_) => break,
            }
        }
    });
*/

    Ok(())
}

async fn add_node_and_connect(net: &mut QuicNetworkManager, party_id: PartyId, addr: SocketAddr) {
    net.add_node_with_party_id(party_id, addr);
    let _ = net.connect(addr).await;
}

async fn send_ctrl(conn: &mut dyn super::p2p::PeerConnection, msg: &DiscoveryMessage) -> Result<(), String> {
    let bytes = bincode::serialize(msg).map_err(|e| e.to_string())?;
    conn.send_on_stream(BOOTNODE_STREAM_ID, &bytes).await
}

/// Wait until at least n parties are in the QuicNetworkManager.parties() view (including self).
pub async fn wait_until_min_parties(net: &QuicNetworkManager, n: usize, timeout: Duration) -> Result<(), String> {
    let start = tokio::time::Instant::now();
    loop {
        if net.parties().len() >= n {
            return Ok(());
        }
        if start.elapsed() > timeout {
            return Err(format!("timeout waiting for {} parties, have {}", n, net.parties().len()));
        }
        sleep(Duration::from_millis(50)).await;
    }
}
