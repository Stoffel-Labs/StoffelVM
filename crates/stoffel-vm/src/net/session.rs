use crate::net::p2p::PeerConnection;
use bincode;
use blake3::Hasher;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use stoffelnet::network_utils::PartyId;

pub const CONTROL_STREAM_ID: u64 = 1;

pub type SessionResult<T> = Result<T, SessionError>;

/// Coordinator-issued identity for one execution of a program.
///
/// A program may be executed more than once at the same time, so `program_id`
/// is not a session key.  The full 256-bit execution ID is carried through
/// discovery and retained in [`SessionInfo`]; the shorter `instance_id` exists
/// only for protocols that still require a `u64` routing value.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExecutionId(pub [u8; 32]);

impl ExecutionId {
    pub fn new() -> Self {
        loop {
            let mut bytes = [0u8; 32];
            rand::rng().fill_bytes(&mut bytes);
            let id = Self(bytes);
            if !id.is_zero() {
                return id;
            }
        }
    }

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    pub fn is_zero(self) -> bool {
        self.0 == [0; 32]
    }
}

impl Default for ExecutionId {
    fn default() -> Self {
        Self::new()
    }
}

impl From<[u8; 32]> for ExecutionId {
    fn from(value: [u8; 32]) -> Self {
        Self::from_bytes(value)
    }
}

impl From<ExecutionId> for [u8; 32] {
    fn from(value: ExecutionId) -> Self {
        value.into_bytes()
    }
}

impl fmt::Debug for ExecutionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ExecutionId({})", hex::encode(self.0))
    }
}

impl fmt::Display for ExecutionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl FromStr for ExecutionId {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64 {
            return Err(format!(
                "execution ID must contain exactly 64 hexadecimal characters, got {}",
                value.len()
            ));
        }
        let bytes = hex::decode(value).map_err(|error| format!("invalid execution ID: {error}"))?;
        Ok(Self(
            bytes.try_into().expect("validated execution ID length"),
        ))
    }
}

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
}

impl From<SessionError> for String {
    fn from(error: SessionError) -> Self {
        error.to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub execution_id: ExecutionId,
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
    /// Full DER-encoded SPKIs for all logical parties. These identities, not
    /// the compact `tls_ids`, authorize mesh admission and reconnects.
    #[serde(default)]
    pub tls_public_keys: Vec<(PartyId, Vec<u8>)>,
}

/// Immutable description of the one physical party mesh owned by a standing
/// node. Execution and program identity deliberately do not appear here:
/// concurrent programs share this exact, certificate-pinned mesh and carry
/// their own execution IDs inside transport envelopes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshInfo {
    pub parties: Vec<(PartyId, SocketAddr)>,
    pub n_parties: usize,
    pub threshold: usize,
    /// Complete DER-encoded SPKIs, indexed by logical party ID. These are the
    /// admission authority; compact transport IDs are an implementation detail
    /// of the networking layer and are intentionally absent here.
    pub tls_public_keys: Vec<(PartyId, Vec<u8>)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionMessage {
    /// Sent by parties to request joining a session
    SessionRequest {
        execution_id: ExecutionId,
        party_id: PartyId,
        program_id: [u8; 32],
        entry: String,
        listen_addr: SocketAddr,
    },
    /// Sent by leader/bootnode when all parties are ready
    SessionAnnounce(SessionInfo),
    /// Sent by parties to acknowledge session
    SessionAck {
        execution_id: ExecutionId,
        party_id: PartyId,
        program_id: [u8; 32],
        instance_id: u64,
    },
    /// Sent by bootnode to indicate session is fully confirmed and ready to start
    SessionStart {
        execution_id: ExecutionId,
        instance_id: u64,
    },
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

/// Derive the compact `u64` protocol routing ID for an execution.
///
/// The bootnode and node supervisor must continue to treat `execution_id` as
/// the authoritative identity and reject a live collision in this shortened
/// value.
pub fn derive_instance_id_for_execution(execution_id: &ExecutionId) -> u64 {
    let mut hasher = Hasher::new();
    hasher.update(b"stoffel-execution-instance-v1");
    hasher.update(execution_id.as_bytes());
    let hash = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&hash.as_bytes()[..8]);
    u64::from_le_bytes(bytes)
}

/// Derive the transport identity for a coordinator-free one-shot session.
///
/// One-shot callers already coordinate on a unique protocol instance ID. Keep
/// that compact API while ensuring their traffic uses the same mandatory wire
/// envelope as coordinator-issued executions.
pub fn derive_execution_id_for_instance(instance_id: u64) -> ExecutionId {
    let mut hasher = Hasher::new();
    hasher.update(b"stoffel-one-shot-execution-v1");
    hasher.update(&instance_id.to_le_bytes());
    ExecutionId::from_bytes(*hasher.finalize().as_bytes())
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
        let msg = SessionMessage::SessionStart {
            execution_id: ExecutionId::from([3u8; 32]),
            instance_id: 42,
        };
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

    #[test]
    fn derive_instance_id_is_deterministic_and_domain_separated() {
        let program_id = [7u8; 32];

        let first = derive_instance_id(&program_id, 11);
        let second = derive_instance_id(&program_id, 11);
        let different_nonce = derive_instance_id(&program_id, 12);

        assert_eq!(first, second);
        assert_ne!(first, different_nonce);
    }

    #[test]
    fn execution_instance_id_is_deterministic_and_execution_scoped() {
        let first_execution = ExecutionId::from([1u8; 32]);
        let second_execution = ExecutionId::from([2u8; 32]);

        assert_eq!(
            derive_instance_id_for_execution(&first_execution),
            derive_instance_id_for_execution(&first_execution)
        );
        assert_ne!(
            derive_instance_id_for_execution(&first_execution),
            derive_instance_id_for_execution(&second_execution)
        );
    }

    #[test]
    fn execution_id_hex_round_trip_matches_coordinator_contract() {
        let id = ExecutionId::from_bytes([0xab; 32]);
        let encoded = id.to_string();

        assert_eq!(encoded.len(), 64);
        assert_eq!(encoded.parse::<ExecutionId>().unwrap(), id);
        assert!("ab".parse::<ExecutionId>().is_err());
        assert!(format!("{}z", &encoded[..63])
            .parse::<ExecutionId>()
            .is_err());
    }
}
