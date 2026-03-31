//! Shared accumulation registry for `open_share` and `batch_open_shares`.
//!
//! Both HoneyBadger and AVSS engines need the same pattern: collect share bytes
//! from every party in the same process, and reconstruct the secret once enough
//! contributions arrive. The registry handles sequence tracking (so distinct
//! `open` calls don't collide) and async notification via [`tokio::sync::Notify`].

use once_cell::sync::Lazy;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::Notify;

use stoffel_vm_types::core_types::Value;

/// Completed entries older than this are evicted on the next insertion.
const EVICTION_AGE: Duration = Duration::from_secs(60);

/// Maximum wire message payload size accepted from the network (1 MB).
/// Prevents oversized allocations from malicious peers.
const MAX_WIRE_MESSAGE_LEN: usize = 1_048_576;

/// Sentinel value indicating the sender's party identity is unknown (e.g. an
/// accepted inbound connection whose party ID has not been authenticated yet).
/// Messages from unknown senders are **rejected** — callers must authenticate
/// connections before routing share contributions through the registry.
pub const UNKNOWN_SENDER_ID: usize = usize::MAX;

// ---------------------------------------------------------------------------
// Single-value open
// ---------------------------------------------------------------------------

#[derive(Default, Clone)]
struct OpenAccumulator {
    shares: Vec<Vec<u8>>,
    party_ids: Vec<usize>,
    result: Option<Value>,
    /// Set when `result` is first cached; used for eviction.
    result_cached_at: Option<Instant>,
}

type OpenKey = (u64, usize, String);

static OPEN_REGISTRY: Lazy<Mutex<HashMap<OpenKey, OpenAccumulator>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Notified after every insertion into [`OPEN_REGISTRY`].
static OPEN_NOTIFY: Lazy<Notify> = Lazy::new(Notify::new);

const OPEN_REGISTRY_WIRE_PREFIX: &[u8; 4] = b"OPN1";
const OPEN_REGISTRY_WAIT_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Serialize, Deserialize)]
enum OpenRegistryWireMessage {
    Single {
        instance_id: u64,
        type_key: String,
        sender_party_id: usize,
        share: Vec<u8>,
    },
    Batch {
        instance_id: u64,
        type_key: String,
        sender_party_id: usize,
        shares: Vec<Vec<u8>>,
    },
}

/// Evict completed entries older than [`EVICTION_AGE`] from the single-value registry.
fn evict_stale_open_entries(reg: &mut HashMap<OpenKey, OpenAccumulator>) {
    let now = Instant::now();
    reg.retain(|_, acc| {
        acc.result_cached_at
            .is_none_or(|t| now.duration_since(t) < EVICTION_AGE)
    });
}

fn insert_remote_single_contribution(
    reg: &mut HashMap<OpenKey, OpenAccumulator>,
    instance_id: u64,
    type_key: &str,
    sender_party_id: usize,
    share: Vec<u8>,
) {
    let type_key = type_key.to_owned();
    let mut seq = 0usize;
    loop {
        let key = (instance_id, seq, type_key.clone());
        let entry = reg.entry(key).or_default();

        if !entry.party_ids.contains(&sender_party_id) {
            entry.shares.push(share);
            entry.party_ids.push(sender_party_id);
            break;
        }
        seq += 1;
    }
}

/// Async implementation of the single-value open wait loop.
async fn open_share_via_registry_async<R>(
    instance_id: u64,
    party_id: usize,
    type_key: String,
    share_bytes: Vec<u8>,
    required: usize,
    reconstruct: R,
) -> Result<Value, String>
where
    R: FnOnce(&[Vec<u8>]) -> Result<Value, String>,
{
    let mut my_sequence: Option<usize> = None;
    let deadline = tokio::time::Instant::now()
        + tokio::time::Duration::from_secs(OPEN_REGISTRY_WAIT_TIMEOUT.as_secs());

    loop {
        // Create the notified future *before* checking the registry (avoids races).
        let notified = OPEN_NOTIFY.notified();
        let mut inserted_local = false;

        {
            let mut reg = OPEN_REGISTRY.lock();

            if my_sequence.is_none() {
                let mut seq = 0;
                loop {
                    let key = (instance_id, seq, type_key.clone());
                    let entry = reg.entry(key).or_default();

                    if !entry.party_ids.contains(&party_id) {
                        entry.shares.push(share_bytes.clone());
                        entry.party_ids.push(party_id);
                        my_sequence = Some(seq);
                        inserted_local = true;
                        break;
                    }
                    seq += 1;
                }
            }

            let seq = my_sequence.expect("sequence must be set after insertion");
            let key = (instance_id, seq, type_key.clone());
            let entry = reg
                .get_mut(&key)
                .expect("registry entry must exist after insertion");

            if let Some(result) = entry.result.clone() {
                return Ok(result);
            }

            if entry.shares.len() >= required {
                let collected: Vec<_> = entry.shares.iter().take(required).cloned().collect();
                drop(reg);
                let value = reconstruct(&collected)?;
                let mut reg = OPEN_REGISTRY.lock();
                let entry = reg
                    .get_mut(&(instance_id, seq, type_key))
                    .expect("registry entry must exist after insertion");
                entry.result = Some(value.clone());
                entry.result_cached_at = Some(Instant::now());
                drop(reg);
                OPEN_NOTIFY.notify_waiters();
                return Ok(value);
            }

            let current_count = entry.party_ids.len();
            drop(reg);

            if tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "Timeout waiting for open_share contributions ({}/{})",
                    current_count, required
                ));
            }
        }

        if inserted_local {
            OPEN_NOTIFY.notify_waiters();
        }

        // Wait for a new insertion or timeout.
        tokio::select! {
            _ = notified => {}
            _ = tokio::time::sleep_until(deadline) => {}
        }
    }
}

/// Polling fallback for contexts without a multi-thread tokio runtime.
fn open_share_via_registry_poll<R>(
    instance_id: u64,
    party_id: usize,
    type_key: String,
    share_bytes: &[u8],
    required: usize,
    reconstruct: R,
) -> Result<Value, String>
where
    R: FnOnce(&[Vec<u8>]) -> Result<Value, String>,
{
    let mut my_sequence: Option<usize> = None;
    let deadline = Instant::now() + OPEN_REGISTRY_WAIT_TIMEOUT;

    loop {
        let mut reg = OPEN_REGISTRY.lock();

        if my_sequence.is_none() {
            let mut seq = 0;
            loop {
                let key = (instance_id, seq, type_key.clone());
                let entry = reg.entry(key).or_default();

                if !entry.party_ids.contains(&party_id) {
                    entry.shares.push(share_bytes.to_vec());
                    entry.party_ids.push(party_id);
                    my_sequence = Some(seq);
                    break;
                }
                seq += 1;
            }
        }

        let seq = my_sequence.expect("sequence must be set after insertion");
        let key = (instance_id, seq, type_key.clone());
        let entry = reg
            .get_mut(&key)
            .expect("registry entry must exist after insertion");

        if let Some(result) = entry.result.clone() {
            return Ok(result);
        }

        if entry.shares.len() >= required {
            let collected: Vec<_> = entry.shares.iter().take(required).cloned().collect();
            drop(reg);
            let value = reconstruct(&collected)?;
            let mut reg = OPEN_REGISTRY.lock();
            let entry = reg
                .get_mut(&(instance_id, seq, type_key))
                .expect("registry entry must exist after insertion");
            entry.result = Some(value.clone());
            entry.result_cached_at = Some(Instant::now());
            return Ok(value);
        }

        let current_count = entry.party_ids.len();
        drop(reg);
        if Instant::now() >= deadline {
            return Err(format!(
                "Timeout waiting for open_share contributions ({}/{})",
                current_count, required
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Contribute a single share and wait until `required` parties have contributed.
///
/// * `instance_id`  – unique per MPC session (prevents cross-session collisions).
/// * `party_id`     – this party's index.
/// * `type_key`     – a string discriminant such as `"hb-int-64"` or `"avss-int-64"`.
/// * `share_bytes`  – the serialised share from this party.
/// * `required`     – how many contributions are needed (e.g. `2t+1` or `t+1`).
/// * `reconstruct`  – closure that receives **exactly `required`** share-byte slices
///   and returns the reconstructed [`Value`].
pub fn open_share_via_registry<R>(
    instance_id: u64,
    party_id: usize,
    type_key: &str,
    share_bytes: &[u8],
    required: usize,
    reconstruct: R,
) -> Result<Value, String>
where
    R: FnOnce(&[Vec<u8>]) -> Result<Value, String>,
{
    // Prefer the async path when a multi-thread tokio runtime is available.
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
            return tokio::task::block_in_place(|| {
                handle.block_on(open_share_via_registry_async(
                    instance_id,
                    party_id,
                    type_key.to_owned(),
                    share_bytes.to_vec(),
                    required,
                    reconstruct,
                ))
            });
        }
    }
    // Fallback to polling for single-thread or no-runtime contexts.
    open_share_via_registry_poll(
        instance_id,
        party_id,
        type_key.to_owned(),
        share_bytes,
        required,
        reconstruct,
    )
}

// ---------------------------------------------------------------------------
// Batch open
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct BatchOpenAccumulator {
    shares_per_position: Vec<Vec<Vec<u8>>>,
    party_ids: Vec<usize>,
    results: Option<Vec<Value>>,
    /// Set when `results` is first cached; used for eviction.
    result_cached_at: Option<Instant>,
}

impl BatchOpenAccumulator {
    fn new(batch_size: usize) -> Self {
        Self {
            shares_per_position: vec![Vec::new(); batch_size],
            party_ids: Vec::new(),
            results: None,
            result_cached_at: None,
        }
    }
}

type BatchKey = (u64, usize, String, usize);

static BATCH_OPEN_REGISTRY: Lazy<Mutex<HashMap<BatchKey, BatchOpenAccumulator>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Notified after every insertion into [`BATCH_OPEN_REGISTRY`].
static BATCH_OPEN_NOTIFY: Lazy<Notify> = Lazy::new(Notify::new);

/// Evict completed entries older than [`EVICTION_AGE`] from the batch registry.
fn evict_stale_batch_entries(reg: &mut HashMap<BatchKey, BatchOpenAccumulator>) {
    let now = Instant::now();
    reg.retain(|_, acc| {
        acc.result_cached_at
            .is_none_or(|t| now.duration_since(t) < EVICTION_AGE)
    });
}

fn insert_remote_batch_contribution(
    reg: &mut HashMap<BatchKey, BatchOpenAccumulator>,
    instance_id: u64,
    type_key: &str,
    sender_party_id: usize,
    shares: Vec<Vec<u8>>,
) {
    if shares.is_empty() {
        return;
    }

    let batch_size = shares.len();
    let type_key = type_key.to_owned();
    let mut seq = 0usize;
    loop {
        let key = (instance_id, seq, type_key.clone(), batch_size);
        let entry = reg
            .entry(key)
            .or_insert_with(|| BatchOpenAccumulator::new(batch_size));

        if !entry.party_ids.contains(&sender_party_id) {
            for (pos, share_bytes) in shares.into_iter().enumerate() {
                entry.shares_per_position[pos].push(share_bytes);
            }
            entry.party_ids.push(sender_party_id);
            break;
        }
        seq += 1;
    }
}

/// Encode a single-share open contribution for transport.
pub fn encode_single_share_wire_message(
    instance_id: u64,
    type_key: &str,
    sender_party_id: usize,
    share_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    let payload = OpenRegistryWireMessage::Single {
        instance_id,
        type_key: type_key.to_string(),
        sender_party_id,
        share: share_bytes.to_vec(),
    };
    let encoded =
        bincode::serialize(&payload).map_err(|e| format!("serialize open wire payload: {}", e))?;

    let mut out = Vec::with_capacity(OPEN_REGISTRY_WIRE_PREFIX.len() + encoded.len());
    out.extend_from_slice(OPEN_REGISTRY_WIRE_PREFIX);
    out.extend_from_slice(&encoded);
    Ok(out)
}

/// Encode a batch-open contribution for transport.
pub fn encode_batch_share_wire_message(
    instance_id: u64,
    type_key: &str,
    sender_party_id: usize,
    shares: &[Vec<u8>],
) -> Result<Vec<u8>, String> {
    let payload = OpenRegistryWireMessage::Batch {
        instance_id,
        type_key: type_key.to_string(),
        sender_party_id,
        shares: shares.to_vec(),
    };
    let encoded =
        bincode::serialize(&payload).map_err(|e| format!("serialize open wire payload: {}", e))?;

    let mut out = Vec::with_capacity(OPEN_REGISTRY_WIRE_PREFIX.len() + encoded.len());
    out.extend_from_slice(OPEN_REGISTRY_WIRE_PREFIX);
    out.extend_from_slice(&encoded);
    Ok(out)
}

/// Attempt to consume an incoming transport payload as an open-registry wire message.
///
/// Returns `Ok(true)` when the payload is recognized and handled.
/// Returns `Ok(false)` when the payload is not an open-registry message.
pub fn try_handle_wire_message(
    authenticated_sender_id: usize,
    payload: &[u8],
) -> Result<bool, String> {
    if payload.len() < OPEN_REGISTRY_WIRE_PREFIX.len()
        || &payload[..OPEN_REGISTRY_WIRE_PREFIX.len()] != OPEN_REGISTRY_WIRE_PREFIX
    {
        return Ok(false);
    }

    let body = &payload[OPEN_REGISTRY_WIRE_PREFIX.len()..];
    if body.len() > MAX_WIRE_MESSAGE_LEN {
        return Err(format!(
            "open wire payload too large: {} bytes (max {})",
            body.len(),
            MAX_WIRE_MESSAGE_LEN
        ));
    }

    let decoded: OpenRegistryWireMessage =
        bincode::deserialize(body).map_err(|e| format!("deserialize open wire payload: {}", e))?;

    match decoded {
        OpenRegistryWireMessage::Single {
            instance_id,
            type_key,
            sender_party_id,
            share,
        } => {
            if authenticated_sender_id == UNKNOWN_SENDER_ID {
                tracing::warn!(
                    sender_party_id,
                    "Rejecting open wire message from unauthenticated connection"
                );
                return Err("open wire rejected: sender identity not authenticated".to_string());
            }
            if sender_party_id != authenticated_sender_id {
                return Err(format!(
                    "open wire sender mismatch: transport={} payload={}",
                    authenticated_sender_id, sender_party_id
                ));
            }
            let mut reg = OPEN_REGISTRY.lock();
            evict_stale_open_entries(&mut reg);
            insert_remote_single_contribution(
                &mut reg,
                instance_id,
                &type_key,
                sender_party_id,
                share,
            );
            drop(reg);
            OPEN_NOTIFY.notify_waiters();
            Ok(true)
        }
        OpenRegistryWireMessage::Batch {
            instance_id,
            type_key,
            sender_party_id,
            shares,
        } => {
            if authenticated_sender_id == UNKNOWN_SENDER_ID {
                tracing::warn!(
                    sender_party_id,
                    "Rejecting batch open wire message from unauthenticated connection"
                );
                return Err(
                    "batch open wire rejected: sender identity not authenticated".to_string(),
                );
            }
            if sender_party_id != authenticated_sender_id {
                return Err(format!(
                    "batch open wire sender mismatch: transport={} payload={}",
                    authenticated_sender_id, sender_party_id
                ));
            }
            let mut reg = BATCH_OPEN_REGISTRY.lock();
            evict_stale_batch_entries(&mut reg);
            insert_remote_batch_contribution(
                &mut reg,
                instance_id,
                &type_key,
                sender_party_id,
                shares,
            );
            drop(reg);
            BATCH_OPEN_NOTIFY.notify_waiters();
            Ok(true)
        }
    }
}

/// Async implementation of the batch-open wait loop.
async fn batch_open_via_registry_async<R>(
    instance_id: u64,
    party_id: usize,
    type_key: String,
    shares: Vec<Vec<u8>>,
    required: usize,
    reconstruct_one: R,
) -> Result<Vec<Value>, String>
where
    R: Fn(&[Vec<u8>], usize) -> Result<Value, String>,
{
    let batch_size = shares.len();
    let mut my_sequence: Option<usize> = None;
    let deadline = tokio::time::Instant::now()
        + tokio::time::Duration::from_secs(OPEN_REGISTRY_WAIT_TIMEOUT.as_secs());

    loop {
        let notified = BATCH_OPEN_NOTIFY.notified();
        let mut inserted_local = false;

        {
            let mut reg = BATCH_OPEN_REGISTRY.lock();

            if my_sequence.is_none() {
                let mut seq = 0;
                loop {
                    let key = (instance_id, seq, type_key.clone(), batch_size);
                    let entry = reg
                        .entry(key)
                        .or_insert_with(|| BatchOpenAccumulator::new(batch_size));

                    if !entry.party_ids.contains(&party_id) {
                        for (pos, share_bytes) in shares.iter().enumerate() {
                            entry.shares_per_position[pos].push(share_bytes.clone());
                        }
                        entry.party_ids.push(party_id);
                        my_sequence = Some(seq);
                        inserted_local = true;
                        break;
                    }
                    seq += 1;
                }
            }

            let seq = my_sequence.expect("sequence must be set after insertion");
            let key = (instance_id, seq, type_key.clone(), batch_size);
            let entry = reg
                .get_mut(&key)
                .expect("registry entry must exist after insertion");

            if let Some(results) = entry.results.clone() {
                return Ok(results);
            }

            if entry.party_ids.len() >= required {
                let snapshot: Vec<Vec<Vec<u8>>> = entry
                    .shares_per_position
                    .iter()
                    .map(|pos| pos.iter().take(required).cloned().collect())
                    .collect();
                drop(reg);

                let mut results = Vec::with_capacity(batch_size);
                for (pos, collected) in snapshot.iter().enumerate() {
                    results.push(reconstruct_one(collected, pos)?);
                }

                let mut reg = BATCH_OPEN_REGISTRY.lock();
                let entry = reg
                    .get_mut(&(instance_id, seq, type_key, batch_size))
                    .expect("batch registry entry must exist after insertion");
                entry.results = Some(results.clone());
                entry.result_cached_at = Some(Instant::now());
                drop(reg);
                BATCH_OPEN_NOTIFY.notify_waiters();
                return Ok(results);
            }

            let current_count = entry.party_ids.len();
            drop(reg);

            if tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "Timeout waiting for batch_open_shares contributions ({}/{})",
                    current_count, required
                ));
            }
        }

        if inserted_local {
            BATCH_OPEN_NOTIFY.notify_waiters();
        }

        tokio::select! {
            _ = notified => {}
            _ = tokio::time::sleep_until(deadline) => {}
        }
    }
}

/// Polling fallback for batch open.
fn batch_open_via_registry_poll<R>(
    instance_id: u64,
    party_id: usize,
    type_key: String,
    shares: &[Vec<u8>],
    required: usize,
    reconstruct_one: R,
) -> Result<Vec<Value>, String>
where
    R: Fn(&[Vec<u8>], usize) -> Result<Value, String>,
{
    let batch_size = shares.len();
    let mut my_sequence: Option<usize> = None;
    let deadline = Instant::now() + OPEN_REGISTRY_WAIT_TIMEOUT;

    loop {
        let mut reg = BATCH_OPEN_REGISTRY.lock();

        if my_sequence.is_none() {
            let mut seq = 0;
            loop {
                let key = (instance_id, seq, type_key.clone(), batch_size);
                let entry = reg
                    .entry(key)
                    .or_insert_with(|| BatchOpenAccumulator::new(batch_size));

                if !entry.party_ids.contains(&party_id) {
                    for (pos, share_bytes) in shares.iter().enumerate() {
                        entry.shares_per_position[pos].push(share_bytes.clone());
                    }
                    entry.party_ids.push(party_id);
                    my_sequence = Some(seq);
                    break;
                }
                seq += 1;
            }
        }

        let seq = my_sequence.expect("sequence must be set after insertion");
        let key = (instance_id, seq, type_key.clone(), batch_size);
        let entry = reg
            .get_mut(&key)
            .expect("registry entry must exist after insertion");

        if let Some(results) = entry.results.clone() {
            return Ok(results);
        }

        if entry.party_ids.len() >= required {
            let snapshot: Vec<Vec<Vec<u8>>> = entry
                .shares_per_position
                .iter()
                .map(|pos| pos.iter().take(required).cloned().collect())
                .collect();
            drop(reg);

            let mut results = Vec::with_capacity(batch_size);
            for (pos, collected) in snapshot.iter().enumerate() {
                results.push(reconstruct_one(collected, pos)?);
            }

            let mut reg = BATCH_OPEN_REGISTRY.lock();
            let entry = reg
                .get_mut(&(instance_id, seq, type_key, batch_size))
                .unwrap();
            entry.results = Some(results.clone());
            entry.result_cached_at = Some(Instant::now());
            return Ok(results);
        }

        let current_count = entry.party_ids.len();
        drop(reg);
        if Instant::now() >= deadline {
            return Err(format!(
                "Timeout waiting for batch_open_shares contributions ({}/{})",
                current_count, required
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Batch variant of [`open_share_via_registry`].
///
/// * `shares` – one byte-vec per position in the batch.
/// * `reconstruct_one` – called once for each position in the batch with the
///   collected share bytes for that position.
pub fn batch_open_via_registry<R>(
    instance_id: u64,
    party_id: usize,
    type_key: &str,
    shares: &[Vec<u8>],
    required: usize,
    reconstruct_one: R,
) -> Result<Vec<Value>, String>
where
    R: Fn(&[Vec<u8>], usize) -> Result<Value, String>,
{
    if shares.is_empty() {
        return Ok(vec![]);
    }

    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
            return tokio::task::block_in_place(|| {
                handle.block_on(batch_open_via_registry_async(
                    instance_id,
                    party_id,
                    type_key.to_owned(),
                    shares.to_vec(),
                    required,
                    reconstruct_one,
                ))
            });
        }
    }
    batch_open_via_registry_poll(
        instance_id,
        party_id,
        type_key.to_owned(),
        shares,
        required,
        reconstruct_one,
    )
}

/// Clear both open registries. Useful between test cases in long-running test processes.
pub fn clear_registries() {
    OPEN_REGISTRY.lock().clear();
    BATCH_OPEN_REGISTRY.lock().clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_sender_single_is_rejected() {
        let msg = encode_single_share_wire_message(1, "test-key", 0, b"share0").unwrap();
        let result = try_handle_wire_message(UNKNOWN_SENDER_ID, &msg);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not authenticated"));
    }

    #[test]
    fn unknown_sender_batch_is_rejected() {
        let msg =
            encode_batch_share_wire_message(1, "test-key", 0, &[b"s0".to_vec(), b"s1".to_vec()])
                .unwrap();
        let result = try_handle_wire_message(UNKNOWN_SENDER_ID, &msg);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not authenticated"));
    }

    #[test]
    fn sender_mismatch_single_is_rejected() {
        // Payload says sender_party_id=0, but transport says authenticated_sender_id=1
        let msg = encode_single_share_wire_message(1, "test-key", 0, b"share0").unwrap();
        let result = try_handle_wire_message(1, &msg);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("sender mismatch"));
    }

    #[test]
    fn sender_mismatch_batch_is_rejected() {
        let msg = encode_batch_share_wire_message(1, "test-key", 0, &[b"s0".to_vec()]).unwrap();
        let result = try_handle_wire_message(1, &msg);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("sender mismatch"));
    }

    #[test]
    fn valid_single_contribution_is_accepted() {
        let msg = encode_single_share_wire_message(1, "test-key", 3, b"share3").unwrap();
        let result = try_handle_wire_message(3, &msg);
        assert_eq!(result.unwrap(), true);

        let reg = OPEN_REGISTRY.lock();
        let key = (1u64, 0usize, "test-key".to_string());
        let entry = reg.get(&key).unwrap();
        assert_eq!(entry.shares.len(), 1);
        assert_eq!(entry.party_ids, vec![3]);
    }

    #[test]
    fn valid_batch_contribution_is_accepted() {
        let shares = vec![b"s0".to_vec(), b"s1".to_vec()];
        let instance_id = 9999u64; // Use unique instance_id to avoid collisions
        let msg =
            encode_batch_share_wire_message(instance_id, "test-batch-unique", 5, &shares).unwrap();
        let result = try_handle_wire_message(5, &msg);
        assert_eq!(result.unwrap(), true);

        let reg = BATCH_OPEN_REGISTRY.lock();
        let key = (instance_id, 0usize, "test-batch-unique".to_string(), 2usize);
        let entry = reg.get(&key).unwrap();
        assert_eq!(entry.party_ids, vec![5]);
        assert_eq!(entry.shares_per_position.len(), 2);
    }

    #[test]
    fn non_prefixed_message_returns_false() {
        let result = try_handle_wire_message(0, b"NOT_OPEN_MSG");
        assert_eq!(result.unwrap(), false);
    }

    #[test]
    fn oversized_payload_is_rejected() {
        let mut msg = Vec::new();
        msg.extend_from_slice(OPEN_REGISTRY_WIRE_PREFIX);
        msg.extend(vec![0u8; MAX_WIRE_MESSAGE_LEN + 1]);
        let result = try_handle_wire_message(0, &msg);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too large"));
    }

    #[test]
    fn wire_message_roundtrip_single() {
        let encoded = encode_single_share_wire_message(42, "rt-key", 7, b"test_share").unwrap();
        assert!(encoded.starts_with(OPEN_REGISTRY_WIRE_PREFIX));
        assert!(encoded.len() < MAX_WIRE_MESSAGE_LEN + OPEN_REGISTRY_WIRE_PREFIX.len());
    }

    #[test]
    fn wire_message_roundtrip_batch() {
        let shares = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
        let encoded = encode_batch_share_wire_message(99, "batch-rt", 2, &shares).unwrap();
        assert!(encoded.starts_with(OPEN_REGISTRY_WIRE_PREFIX));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn local_single_insert_wakes_waiters() {
        clear_registries();

        let waiter = tokio::spawn(async {
            open_share_via_registry_async(
                55,
                0,
                "single-notify".to_string(),
                b"s0".to_vec(),
                2,
                |shares| Ok(Value::I64(shares.len() as i64)),
            )
            .await
        });

        tokio::time::timeout(tokio::time::Duration::from_secs(1), async {
            loop {
                let ready = {
                    let reg = OPEN_REGISTRY.lock();
                    reg.get(&(55u64, 0usize, "single-notify".to_string()))
                        .is_some_and(|entry| entry.party_ids == vec![0])
                };
                if ready {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first single contribution should be registered");

        let finalizer = tokio::spawn(async {
            open_share_via_registry_async(
                55,
                1,
                "single-notify".to_string(),
                b"s1".to_vec(),
                2,
                |shares| Ok(Value::I64(shares.len() as i64)),
            )
            .await
        });

        let (waiter, finalizer) =
            tokio::time::timeout(tokio::time::Duration::from_secs(1), async {
                tokio::join!(waiter, finalizer)
            })
            .await
            .expect("single open waiters should be notified by local insertion");

        assert_eq!(
            waiter.expect("waiter task").expect("waiter result"),
            Value::I64(2)
        );
        assert_eq!(
            finalizer
                .expect("finalizer task")
                .expect("finalizer result"),
            Value::I64(2)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn local_batch_insert_wakes_waiters() {
        clear_registries();

        let waiter = tokio::spawn(async {
            batch_open_via_registry_async(
                77,
                0,
                "batch-notify".to_string(),
                vec![b"a0".to_vec(), b"b0".to_vec()],
                2,
                |shares, _pos| Ok(Value::I64(shares.len() as i64)),
            )
            .await
        });

        tokio::time::timeout(tokio::time::Duration::from_secs(1), async {
            loop {
                let ready = {
                    let reg = BATCH_OPEN_REGISTRY.lock();
                    reg.get(&(77u64, 0usize, "batch-notify".to_string(), 2usize))
                        .is_some_and(|entry| entry.party_ids == vec![0])
                };
                if ready {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first batch contribution should be registered");

        let finalizer = tokio::spawn(async {
            batch_open_via_registry_async(
                77,
                1,
                "batch-notify".to_string(),
                vec![b"a1".to_vec(), b"b1".to_vec()],
                2,
                |shares, _pos| Ok(Value::I64(shares.len() as i64)),
            )
            .await
        });

        let (waiter, finalizer) =
            tokio::time::timeout(tokio::time::Duration::from_secs(1), async {
                tokio::join!(waiter, finalizer)
            })
            .await
            .expect("batch open waiters should be notified by local insertion");

        assert_eq!(
            waiter.expect("waiter task").expect("waiter result"),
            vec![Value::I64(2), Value::I64(2)]
        );
        assert_eq!(
            finalizer
                .expect("finalizer task")
                .expect("finalizer result"),
            vec![Value::I64(2), Value::I64(2)]
        );
    }
}
