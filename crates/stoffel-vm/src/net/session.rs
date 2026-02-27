use crate::net::discovery::DiscoveryMessage;
use crate::net::p2p::PeerConnection;
use bincode;
use blake3::Hasher;
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
    pub n_parties: usize,
    pub threshold: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionMessage {
    /// Sent by parties to request joining a session
    SessionRequest {
        party_id: PartyId,
        program_id: [u8; 32],
        entry: String,
        listen_addr: SocketAddr,
    },
    /// Sent by leader/bootnode when all parties are ready
    SessionAnnounce(SessionInfo),
    /// Sent by parties to acknowledge session
    SessionAck {
        party_id: PartyId,
        program_id: [u8; 32],
        instance_id: u64,
    },
    /// Sent by bootnode to indicate session is fully confirmed and ready to start
    SessionStart { instance_id: u64 },
}

pub fn random_instance_id() -> u64 {
    let mut b = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut b);
    u64::from_le_bytes(b)
}

/// Derive a deterministic instance_id from program_id and a session nonce.
/// This ensures all parties that agree on the same program and nonce get the same instance_id.
pub fn derive_instance_id(program_id: &[u8; 32], session_nonce: u64) -> u64 {
    let mut hasher = Hasher::new();
    hasher.update(b"stoffel-session-v1");
    hasher.update(program_id);
    hasher.update(&session_nonce.to_le_bytes());
    let hash = hasher.finalize();
    let bytes: [u8; 8] = hash.as_bytes()[0..8].try_into().unwrap();
    u64::from_le_bytes(bytes)
}

pub async fn send_ctrl(conn: &mut dyn PeerConnection, msg: &impl Serialize) -> Result<(), String> {
    let bytes = bincode::serialize(msg).map_err(|e| e.to_string())?;
    conn.send_on_stream(CONTROL_STREAM_ID, &bytes).await
}

pub async fn recv_ctrl<T: for<'a> serde::Deserialize<'a>>(
    conn: &mut dyn PeerConnection,
    timeout: Option<Duration>,
) -> Result<T, String> {
    let buf = if let Some(limit) = timeout {
        tokio::time::timeout(limit, conn.receive_from_stream(CONTROL_STREAM_ID))
            .await
            .map_err(|_| format!("Timed out waiting for control message after {:?}", limit))??
    } else {
        conn.receive_from_stream(CONTROL_STREAM_ID).await?
    };
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::pin::Pin;

    struct DelayedMockConnection {
        response: Vec<u8>,
        delay: Duration,
    }

    impl PeerConnection for DelayedMockConnection {
        fn send<'a>(
            &'a mut self,
            _data: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
            Box::pin(async { Ok(()) })
        }

        fn receive<'a>(
            &'a mut self,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
            let response = self.response.clone();
            let delay = self.delay;
            Box::pin(async move {
                tokio::time::sleep(delay).await;
                Ok(response)
            })
        }

        fn send_on_stream<'a>(
            &'a mut self,
            _stream_id: u64,
            _data: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
            Box::pin(async { Ok(()) })
        }

        fn receive_from_stream<'a>(
            &'a mut self,
            _stream_id: u64,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
            let response = self.response.clone();
            let delay = self.delay;
            Box::pin(async move {
                tokio::time::sleep(delay).await;
                Ok(response)
            })
        }

        fn remote_address(&self) -> SocketAddr {
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        }

        fn close<'a>(
            &'a mut self,
        ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn recv_ctrl_respects_timeout() {
        let msg = SessionMessage::SessionStart { instance_id: 42 };
        let bytes = bincode::serialize(&msg).expect("serialize session message");
        let mut conn = DelayedMockConnection {
            response: bytes,
            delay: Duration::from_millis(50),
        };

        let result: Result<SessionMessage, String> =
            recv_ctrl(&mut conn, Some(Duration::from_millis(5))).await;
        assert!(
            result.is_err(),
            "recv_ctrl should return timeout error when timeout elapses before data arrival"
        );
    }
}
