use crate::net::discovery::DiscoveryMessage;
use crate::net::p2p::PeerConnection;
use bincode;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;
use stoffelnet::network_utils::PartyId;

pub const CONTROL_STREAM_ID: u64 = 1;
pub const PROGRAM_STREAM_ID: u64 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub program_id: [u8; 32],
    pub instance_id: u64,
    pub entry: String,
    pub parties: Vec<(PartyId, SocketAddr)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionMessage {
    // Sent by leader/bootnode
    SessionAnnounce(SessionInfo),
    // Sent by parties
    SessionAck {
        party_id: PartyId,
        program_id: [u8; 32],
        instance_id: u64,
    },
}

pub fn random_instance_id() -> u64 {
    let mut b = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut b);
    u64::from_le_bytes(b)
}

pub async fn send_ctrl(conn: &mut dyn PeerConnection, msg: &impl Serialize) -> Result<(), String> {
    let bytes = bincode::serialize(msg).map_err(|e| e.to_string())?;
    conn.send_on_stream(CONTROL_STREAM_ID, &bytes).await
}

pub async fn recv_ctrl<T: for<'a> serde::Deserialize<'a>>(
    conn: &mut dyn PeerConnection,
    _timeout: Option<Duration>,
) -> Result<T, String> {
    // simple version: ignore timeout for now; QUIC reliable
    let buf = conn.receive_from_stream(CONTROL_STREAM_ID).await?;
    let val: T = bincode::deserialize(&buf).map_err(|e| e.to_string())?;
    Ok(val)
}

/// Parties learn agreed session info over an existing control connection (e.g., to bootnode).
/// The leader/bootnode is responsible for generating instance_id and announcing it.
pub async fn agree_session_with_bootnode(
    bn_conn: &mut dyn PeerConnection,
    my_party: PartyId,
    my_program_id: [u8; 32],
    entry: &str,
) -> Result<SessionInfo, String> {
    // Request peers and implicit session announce via discovery RequestPeers
    // Then wait for SessionAnnounce
    // For compatibility with existing discovery, we send a Heartbeat first.
    let _ = send_ctrl(bn_conn, &DiscoveryMessage::Heartbeat).await;

    // SessionAnnounce expected next
    let info: SessionInfo = recv_ctrl(bn_conn, None).await?;
    if info.program_id != my_program_id {
        return Err("Program mismatch between local and session".into());
    }
    // Ack
    let ack = SessionMessage::SessionAck {
        party_id: my_party,
        program_id: my_program_id,
        instance_id: info.instance_id,
    };
    send_ctrl(bn_conn, &ack).await?;
    Ok(info)
}
