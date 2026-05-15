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

pub type SessionResult<T> = Result<T, SessionError>;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SessionError {
    #[error("failed to serialize session control message: {reason}")]
    Encode { reason: String },
    #[error("failed to deserialize session control message: {reason}")]
    Decode { reason: String },
    #[error("session control transport {operation} failed on stream {stream_id}: {reason}")]
    Transport {
        operation: &'static str,
        stream_id: u64,
        reason: String,
    },
    #[error(
        "timed out waiting for session control message on stream {stream_id} after {timeout:?}"
    )]
    Timeout { stream_id: u64, timeout: Duration },
    #[error("unexpected session message: expected {expected}, got {actual}")]
    UnexpectedMessage {
        expected: &'static str,
        actual: &'static str,
    },
    #[error("program mismatch between local and session: expected {expected}, got {actual}")]
    ProgramMismatch { expected: String, actual: String },
}

impl From<SessionError> for String {
    fn from(error: SessionError) -> Self {
        error.to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub program_id: [u8; 32],
    pub instance_id: u64,
    pub entry: String,
    pub parties: Vec<(PartyId, SocketAddr)>,
    pub n_parties: usize,
    pub threshold: usize,
    /// TLS-derived IDs for each party, parallel to `parties`.
    /// Used by peers to pre-register allowlist entries so that
    /// `accept()` succeeds with `use_tls: true`.
    #[serde(default)]
    pub tls_ids: Vec<(PartyId, PartyId)>,
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

fn session_message_kind(message: &SessionMessage) -> &'static str {
    match message {
        SessionMessage::SessionRequest { .. } => "SessionRequest",
        SessionMessage::SessionAnnounce(_) => "SessionAnnounce",
        SessionMessage::SessionAck { .. } => "SessionAck",
        SessionMessage::SessionStart { .. } => "SessionStart",
    }
}

fn program_id_hex(program_id: &[u8; 32]) -> String {
    hex::encode(program_id)
}

pub fn random_instance_id() -> u64 {
    let mut b = [0u8; 8];
    rand::rng().fill_bytes(&mut b);
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
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&hash.as_bytes()[..8]);
    u64::from_le_bytes(bytes)
}

pub async fn send_ctrl(conn: &mut dyn PeerConnection, msg: &impl Serialize) -> SessionResult<()> {
    let bytes = bincode::serialize(msg).map_err(|error| SessionError::Encode {
        reason: error.to_string(),
    })?;
    conn.send_on_stream(CONTROL_STREAM_ID, &bytes)
        .await
        .map_err(|reason| SessionError::Transport {
            operation: "send",
            stream_id: CONTROL_STREAM_ID,
            reason,
        })
}

pub async fn recv_ctrl<T: for<'a> serde::Deserialize<'a>>(
    conn: &mut dyn PeerConnection,
    timeout: Option<Duration>,
) -> SessionResult<T> {
    let buf = if let Some(limit) = timeout {
        tokio::time::timeout(limit, conn.receive_from_stream(CONTROL_STREAM_ID))
            .await
            .map_err(|_| SessionError::Timeout {
                stream_id: CONTROL_STREAM_ID,
                timeout: limit,
            })?
            .map_err(|reason| SessionError::Transport {
                operation: "receive",
                stream_id: CONTROL_STREAM_ID,
                reason,
            })?
    } else {
        conn.receive_from_stream(CONTROL_STREAM_ID)
            .await
            .map_err(|reason| SessionError::Transport {
                operation: "receive",
                stream_id: CONTROL_STREAM_ID,
                reason,
            })?
    };
    let val: T = bincode::deserialize(&buf).map_err(|error| SessionError::Decode {
        reason: error.to_string(),
    })?;
    Ok(val)
}

/// Parties learn agreed session info over an existing control connection (e.g., to bootnode).
/// The leader/bootnode is responsible for generating instance_id and announcing it.
pub async fn agree_session_with_bootnode(
    bn_conn: &mut dyn PeerConnection,
    my_party: PartyId,
    my_program_id: [u8; 32],
    _entry: &str,
) -> SessionResult<SessionInfo> {
    // Request peers and implicit session announce via discovery RequestPeers
    // Then wait for SessionAnnounce
    // For compatibility with existing discovery, we send a Heartbeat first.
    send_ctrl(bn_conn, &DiscoveryMessage::Heartbeat).await?;

    // SessionAnnounce expected next
    let message: SessionMessage = recv_ctrl(bn_conn, None).await?;
    let info = match message {
        SessionMessage::SessionAnnounce(info) => info,
        other => {
            return Err(SessionError::UnexpectedMessage {
                expected: "SessionAnnounce",
                actual: session_message_kind(&other),
            });
        }
    };
    if info.program_id != my_program_id {
        return Err(SessionError::ProgramMismatch {
            expected: program_id_hex(&my_program_id),
            actual: program_id_hex(&info.program_id),
        });
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

        let result: SessionResult<SessionMessage> =
            recv_ctrl(&mut conn, Some(Duration::from_millis(5))).await;
        assert_eq!(
            result.unwrap_err(),
            SessionError::Timeout {
                stream_id: CONTROL_STREAM_ID,
                timeout: Duration::from_millis(5),
            }
        );
    }

    #[tokio::test]
    async fn agree_session_accepts_announced_matching_program() {
        let program_id = [7u8; 32];
        let info = SessionInfo {
            program_id,
            instance_id: 42,
            entry: "main".to_owned(),
            parties: Vec::new(),
            n_parties: 1,
            threshold: 0,
            tls_ids: Vec::new(),
        };
        let bytes = bincode::serialize(&SessionMessage::SessionAnnounce(info.clone()))
            .expect("serialize session announce");
        let mut conn = DelayedMockConnection {
            response: bytes,
            delay: Duration::ZERO,
        };

        let agreed = agree_session_with_bootnode(&mut conn, 0, program_id, "main")
            .await
            .expect("matching session should be accepted");

        assert_eq!(agreed.instance_id, info.instance_id);
        assert_eq!(agreed.program_id, program_id);
    }

    #[tokio::test]
    async fn agree_session_rejects_unexpected_session_message() {
        let bytes = bincode::serialize(&SessionMessage::SessionStart { instance_id: 42 })
            .expect("serialize session start");
        let mut conn = DelayedMockConnection {
            response: bytes,
            delay: Duration::ZERO,
        };

        let err = agree_session_with_bootnode(&mut conn, 0, [7u8; 32], "main")
            .await
            .unwrap_err();

        assert_eq!(
            err,
            SessionError::UnexpectedMessage {
                expected: "SessionAnnounce",
                actual: "SessionStart",
            }
        );
    }

    #[tokio::test]
    async fn agree_session_rejects_program_mismatch_with_typed_error() {
        let info = SessionInfo {
            program_id: [8u8; 32],
            instance_id: 42,
            entry: "main".to_owned(),
            parties: Vec::new(),
            n_parties: 1,
            threshold: 0,
            tls_ids: Vec::new(),
        };
        let bytes = bincode::serialize(&SessionMessage::SessionAnnounce(info))
            .expect("serialize session announce");
        let mut conn = DelayedMockConnection {
            response: bytes,
            delay: Duration::ZERO,
        };

        let err = agree_session_with_bootnode(&mut conn, 0, [7u8; 32], "main")
            .await
            .unwrap_err();

        assert_eq!(
            err,
            SessionError::ProgramMismatch {
                expected: hex::encode([7u8; 32]),
                actual: hex::encode([8u8; 32]),
            }
        );
    }

    #[test]
    fn derive_instance_id_is_deterministic_and_domain_separated() {
        let program_id = [7u8; 32];

        let first = derive_instance_id(&program_id, 11);
        let second = derive_instance_id(&program_id, 11);
        let different_nonce = derive_instance_id(&program_id, 12);

        assert_eq!(first, second);
        assert_ne!(first, different_nonce);
    }
}
