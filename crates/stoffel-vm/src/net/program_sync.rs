use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use bincode;
use crate::net::p2p::PeerConnection;
use crate::net::session::{PROGRAM_STREAM_ID, CONTROL_STREAM_ID};
use stoffelnet::network_utils::PartyId;
use blake3::Hasher;

const DEFAULT_CHUNK: usize = 64 * 1024;

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
        ranges: Vec<(u64, u64)>, // [start, end)
    },
    ProgramComplete {
        program_id: [u8; 32],
    },
}

pub fn cache_dir() -> PathBuf {
    std::env::var("STOFFEL_CACHE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| dirs::home_dir().unwrap_or_else(|| ".".into()).join(".stoffel").join("programs"))
}

pub fn program_path(program_id: &[u8; 32]) -> PathBuf {
    let hex = hex::encode(program_id);
    cache_dir().join(hex)
}

pub fn program_id_from_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"stoffel-program-v1");
    hasher.update(bytes);
    hasher.finalize().as_bytes().clone()
}

pub fn ensure_cache_dir() -> Result<(), String> {
    let dir = cache_dir();
    fs::create_dir_all(&dir).map_err(|e| e.to_string())
}

pub async fn send_ctrl(conn: &mut dyn PeerConnection, msg: &ProgramSyncMessage) -> Result<(), String> {
    let bytes = bincode::serialize(msg).map_err(|e| e.to_string())?;
    conn.send_on_stream(CONTROL_STREAM_ID, &bytes).await
}

pub async fn recv_ctrl(conn: &mut dyn PeerConnection) -> Result<ProgramSyncMessage, String> {
    let buf = conn.receive_from_stream(CONTROL_STREAM_ID).await?;
    let msg: ProgramSyncMessage = bincode::deserialize(&buf).map_err(|e| e.to_string())?;
    Ok(msg)
}

pub async fn send_program_bytes(conn: &mut dyn PeerConnection, program_id: [u8; 32], bytes: Arc<Vec<u8>>) -> Result<(), String> {
    // Stream bytes sequentially on PROGRAM_STREAM_ID
    let mut offset = 0usize;
    while offset < bytes.len() {
        let end = (offset + DEFAULT_CHUNK).min(bytes.len());
        let chunk = &bytes[offset..end];
        // frame: program_id(32) + offset(u64) + len(u32) + data
        let mut frame = Vec::with_capacity(32 + 8 + 4 + chunk.len());
        frame.extend_from_slice(&program_id);
        frame.extend_from_slice(&(offset as u64).to_le_bytes());
        frame.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
        frame.extend_from_slice(chunk);
        conn.send_on_stream(PROGRAM_STREAM_ID, &frame).await?;
        offset = end;
    }
    Ok(())
}

pub async fn recv_program_bytes(conn: &mut dyn PeerConnection, expected_id: [u8; 32], expected_size: usize) -> Result<Vec<u8>, String> {
    let mut out = vec![0u8; expected_size];
    let mut received: BTreeSet<(usize, usize)> = BTreeSet::new();
    let mut total = 0usize;
    while total < expected_size {
        let buf = conn.receive_from_stream(PROGRAM_STREAM_ID).await?;
        if buf.len() < 32 + 8 + 4 {
            return Err("short program frame".into());
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&buf[0..32]);
        if id != expected_id {
            return Err("program_id mismatch in stream".into());
        }
        let off = u64::from_le_bytes(buf[32..40].try_into().unwrap()) as usize;
        let len = u32::from_le_bytes(buf[40..44].try_into().unwrap()) as usize;
        let data = &buf[44..];
        if data.len() != len || off + len > expected_size {
            return Err("invalid frame bounds".into());
        }
        out[off..off + len].copy_from_slice(data);
        received.insert((off, off + len));
        total += len;
    }
    Ok(out)
}

/// High-level helper to ensure all parties agree on the program and those who don't have it fetch it.
pub async fn agree_and_sync_program(
    bn_conn: &mut dyn PeerConnection,
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
        ProgramSyncMessage::ProgramAnnounce { party_id: _, program_id, size, entry } => (program_id, size as usize, entry),
        _ => return Err("unexpected control message (expected ProgramAnnounce)".into()),
    };
    // Ack
    let ack = ProgramSyncMessage::ProgramAck { party_id: my_party, program_id: agreed_pid };
    send_ctrl(bn_conn, &ack).await?;

    // If absent locally, fetch over program stream from bootnode
    let local_path = program_path(&agreed_pid);
    if !local_path.exists() {
        // request ranges (entire file)
        let req = ProgramSyncMessage::ProgramFetchRequest { program_id: agreed_pid, ranges: vec![(0, agreed_size as u64)] };
        send_ctrl(bn_conn, &req).await?;
        let bytes = recv_program_bytes(bn_conn, agreed_pid, agreed_size).await?;
        // verify hash
        let pid2 = program_id_from_bytes(&bytes);
        if pid2 != agreed_pid {
            return Err("downloaded program hash mismatch".into());
        }
        fs::write(&local_path, &bytes).map_err(|e| e.to_string())?;
        // complete
        let _ = send_ctrl(bn_conn, &ProgramSyncMessage::ProgramComplete { program_id: agreed_pid }).await;
    }
    Ok((agreed_pid, agreed_size, agreed_entry))
}
