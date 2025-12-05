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
use std::path::{Path, PathBuf};
use std::sync::Arc;
use stoffelnet::network_utils::PartyId;
use stoffelnet::transports::quic::PeerConnection;

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
    hasher.finalize().as_bytes().clone()
}

/// Ensures the cache directory exists
pub fn ensure_cache_dir() -> Result<(), String> {
    let dir = cache_dir();
    fs::create_dir_all(&dir).map_err(|e| e.to_string())
}

/// Sends a control message to a peer using stoffelnet's simple send/receive
pub async fn send_ctrl(conn: &dyn PeerConnection, msg: &ProgramSyncMessage) -> Result<(), String> {
    let bytes = bincode::serialize(msg).map_err(|e| e.to_string())?;
    conn.send(&bytes).await
}

/// Receives a control message from a peer
pub async fn recv_ctrl(conn: &dyn PeerConnection) -> Result<ProgramSyncMessage, String> {
    let buf = conn.receive().await?;
    let msg: ProgramSyncMessage = bincode::deserialize(&buf).map_err(|e| e.to_string())?;
    Ok(msg)
}

/// Sends program bytecode to a peer
pub async fn send_program_bytes(
    conn: &dyn PeerConnection,
    program_id: [u8; 32],
    bytes: Arc<Vec<u8>>,
) -> Result<(), String> {
    let msg = ProgramSyncMessage::ProgramBytes {
        program_id,
        bytes: bytes.to_vec(),
    };
    send_ctrl(conn, &msg).await
}

/// Receives program bytecode from a peer
pub async fn recv_program_bytes(
    conn: &dyn PeerConnection,
    expected_id: [u8; 32],
) -> Result<Vec<u8>, String> {
    let msg = recv_ctrl(conn).await?;
    match msg {
        ProgramSyncMessage::ProgramBytes { program_id, bytes } => {
            if program_id != expected_id {
                return Err("program_id mismatch".into());
            }
            Ok(bytes)
        }
        _ => Err("expected ProgramBytes message".into()),
    }
}

/// High-level helper to ensure all parties agree on the program and those who don't have it fetch it.
pub async fn agree_and_sync_program(
    bn_conn: &dyn PeerConnection,
    my_party: PartyId,
    entry: &str,
    maybe_program_bytes: Option<Vec<u8>>,
) -> Result<([u8; 32], usize, String), String> {
    ensure_cache_dir()?;
    let (pid, size) = if let Some(bytes) = maybe_program_bytes {
        let pid = program_id_from_bytes(&bytes);
        let path = program_path(&pid);
        if !Path::new(&path).exists() {
            fs::write(&path, &bytes).map_err(|e| e.to_string())?;
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
        size: size as u64,
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
        } => (program_id, size as usize, entry),
        _ => return Err("unexpected control message (expected ProgramAnnounce)".into()),
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
        let pid2 = program_id_from_bytes(&bytes);
        if pid2 != agreed_pid {
            return Err("downloaded program hash mismatch".into());
        }

        fs::write(&local_path, &bytes).map_err(|e| e.to_string())?;

        // send completion acknowledgment
        let complete = ProgramSyncMessage::ProgramComplete {
            program_id: agreed_pid,
        };
        send_ctrl(bn_conn, &complete).await?;
    }

    Ok((agreed_pid, agreed_size, agreed_entry))
}
