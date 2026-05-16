// crates/stoffel-vm/src/net/program_sync.rs
//! # Program Synchronization
//!
//! This module handles the synchronization of compiled programs between VMs in a distributed network.
//! When multiple VMs need to run the same program, they use this module to:
//! 1. Agree on a common program ID and entry point
//! 2. Exchange program bytecode efficiently
//! 3. Cache programs locally to avoid redundant transfers
//!
//! The protocol uses a simple message-based approach over QUIC connections.

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use stoffelnet::network_utils::PartyId;
use stoffelnet::transports::quic::PeerConnection;

pub type ProgramSyncResult<T> = Result<T, ProgramSyncError>;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProgramSyncError {
    #[error("program size {size} exceeds u64::MAX")]
    ProgramSizeExceedsWire { size: usize },
    #[error("program size {size} is too large for this platform")]
    ProgramSizeExceedsHost { size: u64 },
    #[error("failed to {operation} program cache path {path}: {reason}")]
    CacheIo {
        operation: &'static str,
        path: PathBuf,
        reason: String,
    },
    #[error("failed to serialize program sync message: {reason}")]
    Encode { reason: String },
    #[error("failed to deserialize program sync message: {reason}")]
    Decode { reason: String },
    #[error("program sync transport {operation} failed: {reason}")]
    Transport {
        operation: &'static str,
        reason: String,
    },
    #[error("unexpected program sync message: expected {expected}, got {actual}")]
    UnexpectedMessage {
        expected: &'static str,
        actual: &'static str,
    },
    #[error("program_id mismatch: expected {expected}, got {actual}")]
    ProgramIdMismatch { expected: String, actual: String },
    #[error("downloaded program hash mismatch: expected {expected}, got {actual}")]
    DownloadedProgramHashMismatch { expected: String, actual: String },
}

impl From<ProgramSyncError> for String {
    fn from(error: ProgramSyncError) -> Self {
        error.to_string()
    }
}

/// Message types for program synchronization protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProgramSyncMessage {
    ProgramAnnounce {
        party_id: PartyId,
        program_id: [u8; 32],
        size: u64,
        entry: String,
    },
    ProgramAck {
        party_id: PartyId,
        program_id: [u8; 32],
    },
    ProgramFetchRequest {
        program_id: [u8; 32],
    },
    ProgramBytes {
        program_id: [u8; 32],
        bytes: Vec<u8>,
    },
    ProgramComplete {
        program_id: [u8; 32],
    },
}

fn message_kind(message: &ProgramSyncMessage) -> &'static str {
    match message {
        ProgramSyncMessage::ProgramAnnounce { .. } => "ProgramAnnounce",
        ProgramSyncMessage::ProgramAck { .. } => "ProgramAck",
        ProgramSyncMessage::ProgramFetchRequest { .. } => "ProgramFetchRequest",
        ProgramSyncMessage::ProgramBytes { .. } => "ProgramBytes",
        ProgramSyncMessage::ProgramComplete { .. } => "ProgramComplete",
    }
}

fn program_id_hex(program_id: &[u8; 32]) -> String {
    hex::encode(program_id)
}

fn cache_io_error(operation: &'static str, path: &Path, error: io::Error) -> ProgramSyncError {
    ProgramSyncError::CacheIo {
        operation,
        path: path.to_path_buf(),
        reason: error.to_string(),
    }
}

/// Returns the cache directory for storing synced programs
pub fn cache_dir() -> PathBuf {
    std::env::var("STOFFEL_CACHE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .unwrap_or_else(|| ".".into())
                .join(".stoffel")
                .join("programs")
        })
}

/// Returns the path where a program with the given ID should be cached
pub fn program_path(program_id: &[u8; 32]) -> PathBuf {
    let hex = hex::encode(program_id);
    cache_dir().join(hex)
}

/// Computes a BLAKE3 hash of the program bytes to use as its ID
pub fn program_id_from_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"stoffel-program-v1");
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn program_size_from_len(size: usize) -> ProgramSyncResult<u64> {
    u64::try_from(size).map_err(|_| ProgramSyncError::ProgramSizeExceedsWire { size })
}

fn program_size_to_usize(size: u64) -> ProgramSyncResult<usize> {
    usize::try_from(size).map_err(|_| ProgramSyncError::ProgramSizeExceedsHost { size })
}

/// Ensures the cache directory exists
pub fn ensure_cache_dir() -> ProgramSyncResult<()> {
    let dir = cache_dir();
    fs::create_dir_all(&dir).map_err(|error| cache_io_error("create", &dir, error))
}

/// Sends a control message to a peer using stoffelnet's simple send/receive
pub async fn send_ctrl(
    conn: &dyn PeerConnection,
    msg: &ProgramSyncMessage,
) -> ProgramSyncResult<()> {
    let bytes = bincode::serialize(msg).map_err(|error| ProgramSyncError::Encode {
        reason: error.to_string(),
    })?;
    conn.send(&bytes)
        .await
        .map_err(|reason| ProgramSyncError::Transport {
            operation: "send control message",
            reason,
        })
}

/// Receives a control message from a peer
pub async fn recv_ctrl(conn: &dyn PeerConnection) -> ProgramSyncResult<ProgramSyncMessage> {
    let buf = conn
        .receive()
        .await
        .map_err(|reason| ProgramSyncError::Transport {
            operation: "receive control message",
            reason,
        })?;
    let msg: ProgramSyncMessage =
        bincode::deserialize(&buf).map_err(|error| ProgramSyncError::Decode {
            reason: error.to_string(),
        })?;
    Ok(msg)
}

/// Sends program bytecode to a peer
pub async fn send_program_bytes(
    conn: &dyn PeerConnection,
    program_id: [u8; 32],
    bytes: Arc<Vec<u8>>,
) -> ProgramSyncResult<()> {
    let msg = ProgramSyncMessage::ProgramBytes {
        program_id,
        bytes: bytes.to_vec(),
    };
    send_ctrl(conn, &msg).await
}

fn program_bytes_from_message(
    message: ProgramSyncMessage,
    expected_id: [u8; 32],
) -> ProgramSyncResult<Vec<u8>> {
    match message {
        ProgramSyncMessage::ProgramBytes { program_id, bytes } => {
            if program_id != expected_id {
                return Err(ProgramSyncError::ProgramIdMismatch {
                    expected: program_id_hex(&expected_id),
                    actual: program_id_hex(&program_id),
                });
            }
            Ok(bytes)
        }
        other => Err(ProgramSyncError::UnexpectedMessage {
            expected: "ProgramBytes",
            actual: message_kind(&other),
        }),
    }
}

/// Receives program bytecode from a peer
pub async fn recv_program_bytes(
    conn: &dyn PeerConnection,
    expected_id: [u8; 32],
) -> ProgramSyncResult<Vec<u8>> {
    let msg = recv_ctrl(conn).await?;
    program_bytes_from_message(msg, expected_id)
}

fn verify_program_id(expected_id: &[u8; 32], bytes: &[u8]) -> ProgramSyncResult<()> {
    let actual_id = program_id_from_bytes(bytes);
    if actual_id == *expected_id {
        Ok(())
    } else {
        Err(ProgramSyncError::DownloadedProgramHashMismatch {
            expected: program_id_hex(expected_id),
            actual: program_id_hex(&actual_id),
        })
    }
}

/// High-level helper to ensure all parties agree on the program and those who don't have it fetch it.
pub async fn agree_and_sync_program(
    bn_conn: &dyn PeerConnection,
    my_party: PartyId,
    entry: &str,
    maybe_program_bytes: Option<Vec<u8>>,
) -> ProgramSyncResult<([u8; 32], usize, String)> {
    ensure_cache_dir()?;
    let (pid, size) = if let Some(bytes) = maybe_program_bytes {
        let pid = program_id_from_bytes(&bytes);
        let path = program_path(&pid);
        if !Path::new(&path).exists() {
            fs::write(&path, &bytes).map_err(|error| cache_io_error("write", &path, error))?;
        }
        (pid, bytes.len())
    } else {
        // we don't have it; we will learn it from announce below
        ([0u8; 32], 0usize)
    };

    // Announce what we have (or zero pid)
    let announce = ProgramSyncMessage::ProgramAnnounce {
        party_id: my_party,
        program_id: pid,
        size: program_size_from_len(size)?,
        entry: entry.to_string(),
    };
    send_ctrl(bn_conn, &announce).await?;

    // Receive leader's announce with canonical pid/size/entry
    let announce2 = recv_ctrl(bn_conn).await?;
    let (agreed_pid, agreed_size, agreed_entry) = match announce2 {
        ProgramSyncMessage::ProgramAnnounce {
            party_id: _,
            program_id,
            size,
            entry,
        } => (program_id, program_size_to_usize(size)?, entry),
        other => {
            return Err(ProgramSyncError::UnexpectedMessage {
                expected: "ProgramAnnounce",
                actual: message_kind(&other),
            });
        }
    };

    // Ack
    let ack = ProgramSyncMessage::ProgramAck {
        party_id: my_party,
        program_id: agreed_pid,
    };
    send_ctrl(bn_conn, &ack).await?;

    // If absent locally, fetch from bootnode
    let local_path = program_path(&agreed_pid);
    if !local_path.exists() {
        // request the program
        let req = ProgramSyncMessage::ProgramFetchRequest {
            program_id: agreed_pid,
        };
        send_ctrl(bn_conn, &req).await?;

        // receive the bytes
        let bytes = recv_program_bytes(bn_conn, agreed_pid).await?;

        // verify hash
        verify_program_id(&agreed_pid, &bytes)?;

        fs::write(&local_path, &bytes)
            .map_err(|error| cache_io_error("write", &local_path, error))?;

        // send completion acknowledgment
        let complete = ProgramSyncMessage::ProgramComplete {
            program_id: agreed_pid,
        };
        send_ctrl(bn_conn, &complete).await?;
    }

    Ok((agreed_pid, agreed_size, agreed_entry))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_size_conversion_round_trips_representable_lengths() {
        let size = 4096usize;

        let wire_size = program_size_from_len(size).unwrap();
        let host_size = program_size_to_usize(wire_size).unwrap();

        assert_eq!(host_size, size);
    }

    #[test]
    #[cfg(target_pointer_width = "32")]
    fn program_size_conversion_rejects_unrepresentable_wire_size() {
        let err = program_size_to_usize(u64::from(u32::MAX) + 1).unwrap_err();

        assert_eq!(
            err,
            ProgramSyncError::ProgramSizeExceedsHost {
                size: u64::from(u32::MAX) + 1
            }
        );
    }

    #[test]
    fn program_bytes_message_rejects_unexpected_message_type() {
        let err = program_bytes_from_message(
            ProgramSyncMessage::ProgramAck {
                party_id: 7,
                program_id: [1u8; 32],
            },
            [1u8; 32],
        )
        .unwrap_err();

        assert_eq!(
            err,
            ProgramSyncError::UnexpectedMessage {
                expected: "ProgramBytes",
                actual: "ProgramAck"
            }
        );
    }

    #[test]
    fn program_bytes_message_reports_program_id_mismatch() {
        let err = program_bytes_from_message(
            ProgramSyncMessage::ProgramBytes {
                program_id: [2u8; 32],
                bytes: vec![1, 2, 3],
            },
            [1u8; 32],
        )
        .unwrap_err();

        assert_eq!(
            err,
            ProgramSyncError::ProgramIdMismatch {
                expected: hex::encode([1u8; 32]),
                actual: hex::encode([2u8; 32]),
            }
        );
    }

    #[test]
    fn downloaded_program_hash_mismatch_is_typed() {
        let err = verify_program_id(&[9u8; 32], b"not the announced program").unwrap_err();

        assert!(matches!(
            err,
            ProgramSyncError::DownloadedProgramHashMismatch { .. }
        ));
    }
}
