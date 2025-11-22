//! Simple bootnode-based discovery for StoffelVM over QUIC.
//! Assumes nodes are directly reachable (no NAT traversal).
use super::program_sync::{
    recv_ctrl as recv_prog_ctrl, send_ctrl as send_prog_ctrl, send_program_bytes,
    ProgramSyncMessage,
};
use super::session::{SessionInfo, SessionMessage};
use bincode;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use stoffelnet::network_utils::{Network, PartyId};
use stoffelnet::transports::quic::{NetworkManager, PeerConnection, QuicNetworkManager};
use tokio::{sync::Mutex, time::sleep};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiscoveryMessage {
    Register {
        party_id: PartyId,
        listen_addr: SocketAddr,
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

/// Bootnode: accepts party registrations and shares membership updates.
pub async fn run_bootnode(bind: SocketAddr) -> Result<(), String> {
    let mut net = QuicNetworkManager::new();
    net.listen(bind).await?;
    let state: Arc<Mutex<HashMap<PartyId, SocketAddr>>> = Arc::new(Mutex::new(HashMap::new()));
    // Program/Session agreement state: single active session for simplicity
    let session_state: Arc<Mutex<Option<SessionInfo>>> = Arc::new(Mutex::new(None));
    let uploader_bytes: Arc<Mutex<Option<Arc<Vec<u8>>>>> = Arc::new(Mutex::new(None));

    loop {
        let conn = net.accept().await?;
        let state = state.clone();
        let session_state = session_state.clone();
        let uploader_bytes = uploader_bytes.clone();
        tokio::spawn(async move {
            loop {
                match conn.receive().await {
                    Ok(buf) => {
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
                                SessionMessage::SessionAck { .. } => { /* optional: track */ }
                            }
                        }
                    }
                    Err(_) => {
                        sleep(Duration::from_millis(10)).await;
                        break;
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

async fn add_node_and_connect(net: &mut QuicNetworkManager, party_id: PartyId, addr: SocketAddr) {
    net.add_node_with_party_id(party_id, addr);
    let _ = net.connect(addr).await;
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
