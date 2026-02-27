//! Shared accumulation registry for `open_share` and `batch_open_shares`.
//!
//! Both HoneyBadger and AVSS engines need the same pattern: collect share bytes
//! from every party in the same process, and reconstruct the secret once enough
//! contributions arrive. The registry handles sequence tracking (so distinct
//! `open` calls don't collide) and spin-waiting.

use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::Duration;

use stoffel_vm_types::core_types::Value;

// ---------------------------------------------------------------------------
// Single-value open
// ---------------------------------------------------------------------------

#[derive(Default, Clone)]
struct OpenAccumulator {
    shares: Vec<Vec<u8>>,
    party_ids: Vec<usize>,
    result: Option<Value>,
}

type OpenKey = (u64, usize, String);

static OPEN_REGISTRY: Lazy<Mutex<HashMap<OpenKey, OpenAccumulator>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Contribute a single share and wait until `required` parties have contributed.
///
/// * `instance_id`  – unique per MPC session (prevents cross-session collisions).
/// * `party_id`     – this party's index.
/// * `type_key`     – a string discriminant such as `"hb-int-64"` or `"avss-int-64"`.
/// * `share_bytes`  – the serialised share from this party.
/// * `required`     – how many contributions are needed (e.g. `2t+1` or `t+1`).
/// * `reconstruct`  – closure that receives **exactly `required`** share-byte slices
///                     and returns the reconstructed [`Value`].
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
    let type_key = type_key.to_owned();
    let mut my_sequence: Option<usize> = None;

    loop {
        let mut reg = OPEN_REGISTRY.lock();

        // Register our contribution in the first accumulator this party hasn't touched.
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

        let seq = my_sequence.unwrap();
        let key = (instance_id, seq, type_key.clone());
        let entry = reg.get_mut(&key).unwrap();

        // Already reconstructed by another party?
        if let Some(result) = entry.result.clone() {
            return Ok(result);
        }

        // Enough contributions to reconstruct?
        if entry.shares.len() >= required {
            let collected: Vec<_> = entry.shares.iter().take(required).cloned().collect();
            // Drop the lock before the potentially-expensive reconstruction.
            drop(reg);
            let value = reconstruct(&collected)?;
            // Cache the result so the remaining parties skip reconstruction.
            let mut reg = OPEN_REGISTRY.lock();
            let entry = reg.get_mut(&(instance_id, seq, type_key)).unwrap();
            entry.result = Some(value.clone());
            return Ok(value);
        }

        drop(reg);
        std::thread::sleep(Duration::from_millis(5));
    }
}

// ---------------------------------------------------------------------------
// Batch open
// ---------------------------------------------------------------------------

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

type BatchKey = (u64, usize, String, usize);

static BATCH_OPEN_REGISTRY: Lazy<Mutex<HashMap<BatchKey, BatchOpenAccumulator>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

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

    let type_key = type_key.to_owned();
    let batch_size = shares.len();
    let mut my_sequence: Option<usize> = None;

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

        let seq = my_sequence.unwrap();
        let key = (instance_id, seq, type_key.clone(), batch_size);
        let entry = reg.get_mut(&key).unwrap();

        if let Some(results) = entry.results.clone() {
            return Ok(results);
        }

        if entry.party_ids.len() >= required {
            // Snapshot the accumulated data and drop the lock before reconstruction.
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
            return Ok(results);
        }

        drop(reg);
        std::thread::sleep(Duration::from_millis(5));
    }
}
