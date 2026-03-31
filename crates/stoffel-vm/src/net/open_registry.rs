//! Per-instance accumulation registry for `open_share` and `batch_open_shares`.
//!
//! Each MPC engine owns an [`InstanceRegistry`] that collects share bytes from
//! every party and reconstructs secrets once enough contributions arrive.
//! Registries are scoped per `instance_id` — no cross-session contamination.
//!
//! A global [`DashMap`] routes incoming wire messages to the correct instance
//! by extracting `instance_id` from the payload. The wire message format and
//! call sites in receive loops are unchanged.

use dashmap::DashMap;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Notify;

use stoffel_vm_types::core_types::Value;

/// Maximum wire message payload size accepted from the network (1 MB).
const MAX_WIRE_MESSAGE_LEN: usize = 1_048_576;

const OPEN_REGISTRY_WIRE_PREFIX: &[u8; 4] = b"OPN1";
const OPEN_REGISTRY_WAIT_TIMEOUT: Duration = Duration::from_secs(60);

/// Sentinel value indicating the sender's party identity is unknown.
pub const UNKNOWN_SENDER_ID: usize = usize::MAX;

/// Global router: `instance_id → InstanceRegistry`.
static REGISTRY_MAP: Lazy<DashMap<u64, Arc<InstanceRegistry>>> = Lazy::new(DashMap::new);

// ---------------------------------------------------------------------------
// Accumulators
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct OpenAccumulator {
    shares: Vec<Vec<u8>>,
    party_ids: Vec<usize>,
    result: Option<Value>,
}

/// Key: (sequence, type_key)
type SingleKey = (usize, String);

#[derive(Clone)]
struct BatchOpenAccumulator {
    shares_per_position: Vec<Vec<Vec<u8>>>,
    party_ids: Vec<usize>,
    results: Option<Vec<Value>>,
}

impl BatchOpenAccumulator {
    fn new(batch_size: usize) -> Self {
        Self {
            shares_per_position: vec![Vec::new(); batch_size],
            party_ids: Vec::new(),
            results: None,
        }
    }
}

/// Key: (sequence, type_key, batch_size)
type BatchKey = (usize, String, usize);

// ---------------------------------------------------------------------------
// EXP accumulator (shared by HB and AVSS open-in-exponent)
// ---------------------------------------------------------------------------

/// Key: sequence number (no instance_id needed — scoped per instance)
type ExpKey = usize;

#[derive(Default, Clone)]
pub struct ExpOpenAccumulator {
    pub partial_points: Vec<(usize, Vec<u8>)>, // (share_id, serialized affine point)
    pub party_ids: Vec<usize>,
    pub result: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// RBC / ABA state (HB consensus)
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct RbcState {
    /// Maps (session_id, from_party) → message bytes
    pub messages: HashMap<(u64, usize), Vec<u8>>,
    /// Tracks deliveries: (receiver_party, from_party, session_id)
    pub delivered: std::collections::HashSet<(usize, usize, u64)>,
}

#[derive(Default)]
pub struct AbaState {
    /// Maps (session_id, party_id) → proposed value
    pub proposals: HashMap<(u64, usize), bool>,
    /// Maps session_id → agreed result once consensus is reached
    pub results: HashMap<u64, bool>,
}

// ---------------------------------------------------------------------------
// InstanceRegistry
// ---------------------------------------------------------------------------

/// Per-instance registry for all share accumulation and consensus state.
///
/// Each MPC engine creates one via [`InstanceRegistry::register`] and holds
/// the returned `Arc`. Incoming wire messages are routed here by `instance_id`.
/// On drop (or explicit [`InstanceRegistry::deregister`]), all state for that
/// instance is removed from the global map.
pub struct InstanceRegistry {
    instance_id: u64,
    // open share accumulation
    single: Mutex<HashMap<SingleKey, OpenAccumulator>>,
    single_notify: Notify,
    batch: Mutex<HashMap<BatchKey, BatchOpenAccumulator>>,
    batch_notify: Notify,
    // open-in-exponent accumulation (used by HB and AVSS)
    pub exp: Mutex<HashMap<ExpKey, ExpOpenAccumulator>>,
    pub exp_notify: Notify,
    // second EXP registry for AVSS G2 operations
    pub exp_g2: Mutex<HashMap<ExpKey, ExpOpenAccumulator>>,
    pub exp_g2_notify: Notify,
    // HB consensus
    pub rbc: Mutex<RbcState>,
    pub rbc_notify: Notify,
    pub aba: Mutex<AbaState>,
    pub aba_notify: Notify,
}

impl InstanceRegistry {
    /// Get or create a registry for the given instance_id.
    ///
    /// Multiple engines sharing the same `instance_id` (e.g. 5 parties in one
    /// process) will share a single `InstanceRegistry`.
    pub fn register(instance_id: u64) -> Arc<Self> {
        if let Some(existing) = REGISTRY_MAP.get(&instance_id) {
            return existing.clone();
        }
        let reg = Arc::new(Self {
            instance_id,
            single: Mutex::new(HashMap::new()),
            single_notify: Notify::new(),
            batch: Mutex::new(HashMap::new()),
            batch_notify: Notify::new(),
            exp: Mutex::new(HashMap::new()),
            exp_notify: Notify::new(),
            exp_g2: Mutex::new(HashMap::new()),
            exp_g2_notify: Notify::new(),
            rbc: Mutex::new(RbcState::default()),
            rbc_notify: Notify::new(),
            aba: Mutex::new(AbaState::default()),
            aba_notify: Notify::new(),
        });
        REGISTRY_MAP.entry(instance_id).or_insert(reg).clone()
    }

    /// Remove this instance from the global map, dropping all accumulated state.
    pub fn deregister(instance_id: u64) {
        REGISTRY_MAP.remove(&instance_id);
    }

    // -- single open --------------------------------------------------------

    fn insert_single(&self, type_key: &str, sender_party_id: usize, share: Vec<u8>) {
        let mut reg = self.single.lock();
        let type_key = type_key.to_owned();
        let mut seq = 0usize;
        loop {
            let entry = reg.entry((seq, type_key.clone())).or_default();
            if !entry.party_ids.contains(&sender_party_id) {
                entry.shares.push(share);
                entry.party_ids.push(sender_party_id);
                break;
            }
            seq += 1;
        }
        drop(reg);
        self.single_notify.notify_waiters();
    }

    /// Contribute a single share and wait until `required` parties have contributed.
    pub fn open_share_wait<R>(
        &self,
        party_id: usize,
        type_key: &str,
        share_bytes: &[u8],
        required: usize,
        reconstruct: R,
    ) -> Result<Value, String>
    where
        R: FnOnce(&[Vec<u8>]) -> Result<Value, String>,
    {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
                return tokio::task::block_in_place(|| {
                    handle.block_on(self.open_share_async(
                        party_id,
                        type_key.to_owned(),
                        share_bytes.to_vec(),
                        required,
                        reconstruct,
                    ))
                });
            }
        }
        self.open_share_poll(party_id, type_key.to_owned(), share_bytes, required, reconstruct)
    }

    async fn open_share_async<R>(
        &self,
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
            let notified = self.single_notify.notified();
            let mut inserted_local = false;

            {
                let mut reg = self.single.lock();

                if my_sequence.is_none() {
                    let mut seq = 0;
                    loop {
                        let entry = reg.entry((seq, type_key.clone())).or_default();
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

                let seq = my_sequence.unwrap();
                let entry = reg.get_mut(&(seq, type_key.clone())).unwrap();

                if let Some(result) = entry.result.clone() {
                    return Ok(result);
                }

                if entry.shares.len() >= required {
                    let collected: Vec<_> = entry.shares.iter().take(required).cloned().collect();
                    drop(reg);
                    let value = reconstruct(&collected)?;
                    let mut reg = self.single.lock();
                    let entry = reg.get_mut(&(seq, type_key)).unwrap();
                    entry.result = Some(value.clone());
                    drop(reg);
                    self.single_notify.notify_waiters();
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
                self.single_notify.notify_waiters();
            }

            tokio::select! {
                _ = notified => {}
                _ = tokio::time::sleep_until(deadline) => {}
            }
        }
    }

    fn open_share_poll<R>(
        &self,
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
            let mut reg = self.single.lock();

            if my_sequence.is_none() {
                let mut seq = 0;
                loop {
                    let entry = reg.entry((seq, type_key.clone())).or_default();
                    if !entry.party_ids.contains(&party_id) {
                        entry.shares.push(share_bytes.to_vec());
                        entry.party_ids.push(party_id);
                        my_sequence = Some(seq);
                        break;
                    }
                    seq += 1;
                }
            }

            let seq = my_sequence.unwrap();
            let entry = reg.get_mut(&(seq, type_key.clone())).unwrap();

            if let Some(result) = entry.result.clone() {
                return Ok(result);
            }

            if entry.shares.len() >= required {
                let collected: Vec<_> = entry.shares.iter().take(required).cloned().collect();
                drop(reg);
                let value = reconstruct(&collected)?;
                let mut reg = self.single.lock();
                let entry = reg.get_mut(&(seq, type_key)).unwrap();
                entry.result = Some(value.clone());
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

    // -- exp open -----------------------------------------------------------

    /// Insert a partial point contribution for open-in-exponent.
    pub fn insert_exp(&self, sender_party_id: usize, share_id: usize, partial_point: Vec<u8>) {
        let mut reg = self.exp.lock();
        let mut seq = 0usize;
        loop {
            let entry = reg.entry(seq).or_default();
            if !entry.party_ids.contains(&sender_party_id) {
                entry.partial_points.push((share_id, partial_point));
                entry.party_ids.push(sender_party_id);
                break;
            }
            seq += 1;
        }
        drop(reg);
        self.exp_notify.notify_waiters();
    }

    /// Insert a partial point contribution for G2 open-in-exponent (AVSS).
    pub fn insert_exp_g2(&self, sender_party_id: usize, share_id: usize, partial_point: Vec<u8>) {
        let mut reg = self.exp_g2.lock();
        let mut seq = 0usize;
        loop {
            let entry = reg.entry(seq).or_default();
            if !entry.party_ids.contains(&sender_party_id) {
                entry.partial_points.push((share_id, partial_point));
                entry.party_ids.push(sender_party_id);
                break;
            }
            seq += 1;
        }
        drop(reg);
        self.exp_g2_notify.notify_waiters();
    }

    // -- batch open ---------------------------------------------------------

    fn insert_batch(&self, type_key: &str, sender_party_id: usize, shares: Vec<Vec<u8>>) {
        if shares.is_empty() {
            return;
        }
        let batch_size = shares.len();
        let mut reg = self.batch.lock();
        let type_key = type_key.to_owned();
        let mut seq = 0usize;
        loop {
            let entry = reg
                .entry((seq, type_key.clone(), batch_size))
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
        drop(reg);
        self.batch_notify.notify_waiters();
    }

    /// Batch variant of [`open_share_wait`].
    pub fn batch_open_wait<R>(
        &self,
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
                    handle.block_on(self.batch_open_async(
                        party_id,
                        type_key.to_owned(),
                        shares.to_vec(),
                        required,
                        reconstruct_one,
                    ))
                });
            }
        }
        self.batch_open_poll(party_id, type_key.to_owned(), shares, required, reconstruct_one)
    }

    async fn batch_open_async<R>(
        &self,
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
            let notified = self.batch_notify.notified();
            let mut inserted_local = false;

            {
                let mut reg = self.batch.lock();

                if my_sequence.is_none() {
                    let mut seq = 0;
                    loop {
                        let entry = reg
                            .entry((seq, type_key.clone(), batch_size))
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

                let seq = my_sequence.unwrap();
                let key = (seq, type_key.clone(), batch_size);
                let entry = reg.get_mut(&key).unwrap();

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

                    let mut reg = self.batch.lock();
                    let entry = reg.get_mut(&(seq, type_key, batch_size)).unwrap();
                    entry.results = Some(results.clone());
                    drop(reg);
                    self.batch_notify.notify_waiters();
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
                self.batch_notify.notify_waiters();
            }

            tokio::select! {
                _ = notified => {}
                _ = tokio::time::sleep_until(deadline) => {}
            }
        }
    }

    fn batch_open_poll<R>(
        &self,
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
            let mut reg = self.batch.lock();

            if my_sequence.is_none() {
                let mut seq = 0;
                loop {
                    let entry = reg
                        .entry((seq, type_key.clone(), batch_size))
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

            let seq = my_sequence.unwrap();
            let key = (seq, type_key.clone(), batch_size);
            let entry = reg.get_mut(&key).unwrap();

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

                let mut reg = self.batch.lock();
                let entry = reg.get_mut(&(seq, type_key, batch_size)).unwrap();
                entry.results = Some(results.clone());
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
}

// ---------------------------------------------------------------------------
// Wire message encoding (unchanged format)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Wire message handler (same signature, routes via REGISTRY_MAP)
// ---------------------------------------------------------------------------

/// Attempt to consume an incoming transport payload as an open-registry wire message.
///
/// Returns `Ok(true)` when the payload is recognized and handled.
/// Returns `Ok(false)` when the payload is not an open-registry message,
/// or when no registry is registered for the `instance_id`.
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

    // Extract instance_id and validate sender
    let (instance_id, sender_party_id) = match &decoded {
        OpenRegistryWireMessage::Single { instance_id, sender_party_id, .. } => (*instance_id, *sender_party_id),
        OpenRegistryWireMessage::Batch { instance_id, sender_party_id, .. } => (*instance_id, *sender_party_id),
    };

    if authenticated_sender_id == UNKNOWN_SENDER_ID {
        tracing::warn!(sender_party_id, "Rejecting open wire message from unauthenticated connection");
        return Err("open wire rejected: sender identity not authenticated".to_string());
    }
    if sender_party_id != authenticated_sender_id {
        return Err(format!(
            "open wire sender mismatch: transport={} payload={}",
            authenticated_sender_id, sender_party_id
        ));
    }

    // Route to the correct per-instance registry
    let registry = match REGISTRY_MAP.get(&instance_id) {
        Some(r) => r.clone(),
        None => return Ok(false),
    };

    match decoded {
        OpenRegistryWireMessage::Single { type_key, sender_party_id, share, .. } => {
            registry.insert_single(&type_key, sender_party_id, share);
        }
        OpenRegistryWireMessage::Batch { type_key, sender_party_id, shares, .. } => {
            registry.insert_batch(&type_key, sender_party_id, shares);
        }
    }
    Ok(true)
}

// ---------------------------------------------------------------------------
// Legacy compat (kept for backward-compatible public API during migration)
// ---------------------------------------------------------------------------

/// Contribute a single share via a temporary or looked-up instance registry.
///
/// Prefer using `registry.open_share_wait()` directly when the engine has a
/// handle to its `InstanceRegistry`.
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
    let registry = REGISTRY_MAP
        .get(&instance_id)
        .map(|r| r.clone())
        .ok_or_else(|| format!("no InstanceRegistry for instance_id {instance_id}"))?;
    registry.open_share_wait(party_id, type_key, share_bytes, required, reconstruct)
}

/// Batch variant of [`open_share_via_registry`].
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
    let registry = REGISTRY_MAP
        .get(&instance_id)
        .map(|r| r.clone())
        .ok_or_else(|| format!("no InstanceRegistry for instance_id {instance_id}"))?;
    registry.batch_open_wait(party_id, type_key, shares, required, reconstruct_one)
}

/// Look up the registry for a given instance_id.
pub fn get_instance_registry(instance_id: u64) -> Option<Arc<InstanceRegistry>> {
    REGISTRY_MAP.get(&instance_id).map(|r| r.clone())
}

/// Clear all instance registries. Useful between test cases.
pub fn clear_registries() {
    REGISTRY_MAP.clear();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
        let _reg = InstanceRegistry::register(10001);
        let msg = encode_single_share_wire_message(10001, "test-key", 3, b"share3").unwrap();
        let result = try_handle_wire_message(3, &msg);
        assert_eq!(result.unwrap(), true);
        InstanceRegistry::deregister(10001);
    }

    #[test]
    fn valid_batch_contribution_is_accepted() {
        let _reg = InstanceRegistry::register(10002);
        let shares = vec![b"s0".to_vec(), b"s1".to_vec()];
        let msg = encode_batch_share_wire_message(10002, "test-batch", 5, &shares).unwrap();
        let result = try_handle_wire_message(5, &msg);
        assert_eq!(result.unwrap(), true);
        InstanceRegistry::deregister(10002);
    }

    #[test]
    fn unregistered_instance_returns_false() {
        let msg = encode_single_share_wire_message(99999999, "test-key", 0, b"share").unwrap();
        let result = try_handle_wire_message(0, &msg);
        assert_eq!(result.unwrap(), false);
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
        let reg = InstanceRegistry::register(20001);

        let reg2 = reg.clone();
        let waiter = tokio::spawn(async move {
            reg2.open_share_async(0, "single-notify".to_string(), b"s0".to_vec(), 2, |shares| {
                Ok(Value::I64(shares.len() as i64))
            })
            .await
        });

        // Wait for first contribution to be registered
        tokio::time::timeout(tokio::time::Duration::from_secs(1), async {
            loop {
                let ready = {
                    let r = reg.single.lock();
                    r.get(&(0usize, "single-notify".to_string()))
                        .is_some_and(|entry| entry.party_ids == vec![0])
                };
                if ready { break; }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first single contribution should be registered");

        let reg3 = reg.clone();
        let finalizer = tokio::spawn(async move {
            reg3.open_share_async(1, "single-notify".to_string(), b"s1".to_vec(), 2, |shares| {
                Ok(Value::I64(shares.len() as i64))
            })
            .await
        });

        let (waiter, finalizer) =
            tokio::time::timeout(tokio::time::Duration::from_secs(1), async {
                tokio::join!(waiter, finalizer)
            })
            .await
            .expect("single open waiters should be notified by local insertion");

        assert_eq!(waiter.unwrap().unwrap(), Value::I64(2));
        assert_eq!(finalizer.unwrap().unwrap(), Value::I64(2));
        InstanceRegistry::deregister(20001);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn local_batch_insert_wakes_waiters() {
        let reg = InstanceRegistry::register(20002);

        let reg2 = reg.clone();
        let waiter = tokio::spawn(async move {
            reg2.batch_open_async(
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
                    let r = reg.batch.lock();
                    r.get(&(0usize, "batch-notify".to_string(), 2usize))
                        .is_some_and(|entry| entry.party_ids == vec![0])
                };
                if ready { break; }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first batch contribution should be registered");

        let reg3 = reg.clone();
        let finalizer = tokio::spawn(async move {
            reg3.batch_open_async(
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

        assert_eq!(waiter.unwrap().unwrap(), vec![Value::I64(2), Value::I64(2)]);
        assert_eq!(finalizer.unwrap().unwrap(), vec![Value::I64(2), Value::I64(2)]);
        InstanceRegistry::deregister(20002);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_instances_are_isolated() {
        let reg_a = InstanceRegistry::register(30001);
        let reg_b = InstanceRegistry::register(30002);

        // Insert into instance A
        reg_a.insert_single("key", 0, b"share_a".to_vec());
        // Insert into instance B
        reg_b.insert_single("key", 0, b"share_b".to_vec());

        // Verify isolation
        let a_count = reg_a.single.lock().get(&(0, "key".to_string())).unwrap().shares.len();
        let b_count = reg_b.single.lock().get(&(0, "key".to_string())).unwrap().shares.len();
        assert_eq!(a_count, 1);
        assert_eq!(b_count, 1);

        InstanceRegistry::deregister(30001);
        InstanceRegistry::deregister(30002);
    }
}
