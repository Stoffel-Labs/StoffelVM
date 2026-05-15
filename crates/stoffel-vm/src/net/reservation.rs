//! Masked share reservation registry.
//!
//! Tracks which preprocessing indices are reserved by which clients for
//! the masked-input protocol. Mirrors the coordinator's allocation model:
//! sequential index allocation via an advancing cursor.

use crate::storage::preproc::{PreprocStore, PreprocStoreError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use stoffelnet::network_utils::ClientId;
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Per-index reservation state (only stored for non-Free indices).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SlotStatus {
    Reserved(ClientId),
    Consumed(ClientId),
}

/// Result of a successful reservation.
#[derive(Debug, Clone)]
pub struct ReservationGrant {
    pub start: u64,
    pub count: u64,
}

impl ReservationGrant {
    pub fn indices(&self) -> std::ops::Range<u64> {
        self.start..self.start + self.count
    }
}

/// Serializable snapshot of the full registry state.
///
/// Slots are stored sparsely: only Reserved/Consumed entries appear in `slots`.
/// Indices >= `next_index` are implicitly Free.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryState {
    pub program_hash: [u8; 32],
    pub party_id: usize,
    pub capacity: u64,
    pub next_index: u64,
    pub slots: BTreeMap<u64, SlotStatus>,
    pub masked_inputs: BTreeMap<u64, Vec<u8>>,
}

impl RegistryState {
    fn validate(&self) -> Result<(), ReservationError> {
        if self.next_index > self.capacity {
            return Err(ReservationError::InvalidState(format!(
                "next_index {} exceeds capacity {}",
                self.next_index, self.capacity
            )));
        }

        for index in self.slots.keys() {
            if *index >= self.capacity {
                return Err(ReservationError::InvalidState(format!(
                    "slot index {index} exceeds capacity {}",
                    self.capacity
                )));
            }
        }

        for index in self.masked_inputs.keys() {
            if *index >= self.capacity {
                return Err(ReservationError::InvalidState(format!(
                    "masked input index {index} exceeds capacity {}",
                    self.capacity
                )));
            }
            if !self.slots.contains_key(index) {
                return Err(ReservationError::InvalidState(format!(
                    "masked input index {index} has no reservation slot"
                )));
            }
        }

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ReservationError {
    #[error("insufficient material: need {need}, have {have}")]
    InsufficientMaterial { need: u64, have: u64 },
    #[error("reservation index range overflows u64: start {start}, count {count}")]
    IndexOverflow { start: u64, count: u64 },
    #[error("invalid reservation state: {0}")]
    InvalidState(String),
    #[error("index {0} not reserved by this client")]
    NotReservedByClient(u64),
    #[error("index {0} not reserved")]
    NotReserved(u64),
    #[error("index {0} already consumed")]
    AlreadyConsumed(u64),
    #[error("index {0} out of bounds")]
    OutOfBounds(u64),
    #[error("storage: {0}")]
    Storage(#[from] PreprocStoreError),
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Tracks masked share reservations for one (program, party) pair.
///
/// Slots are stored sparsely in a `BTreeMap`; indices below `next_index` that
/// are absent from the map were never individually reserved (impossible with
/// sequential allocation) or have been evicted.
pub struct ReservationRegistry {
    state: RwLock<RegistryState>,
}

const RESERVATION_NS: &[u8] = b"rsv:";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ReservationPersistenceKey {
    program_hash: [u8; 32],
    party_id: usize,
}

impl ReservationPersistenceKey {
    fn new(program_hash: [u8; 32], party_id: usize) -> Self {
        Self {
            program_hash,
            party_id,
        }
    }

    fn encode(self) -> Result<Vec<u8>, PreprocStoreError> {
        let error_value = u64::try_from(self.party_id).unwrap_or(u64::MAX);
        let party_id =
            u32::try_from(self.party_id).map_err(|_| PreprocStoreError::U32Overflow {
                field: "reservation key party_id",
                value: error_value,
            })?;
        let mut key = Vec::with_capacity(36);
        key.extend_from_slice(&self.program_hash);
        key.extend_from_slice(&party_id.to_le_bytes());
        Ok(key)
    }
}

impl ReservationRegistry {
    pub fn new(program_hash: [u8; 32], party_id: usize, capacity: u64) -> Self {
        Self {
            state: RwLock::new(RegistryState {
                program_hash,
                party_id,
                capacity,
                next_index: 0,
                slots: BTreeMap::new(),
                masked_inputs: BTreeMap::new(),
            }),
        }
    }

    pub fn try_from_state(state: RegistryState) -> Result<Self, ReservationError> {
        state.validate()?;
        Ok(Self {
            state: RwLock::new(state),
        })
    }

    pub fn from_state(state: RegistryState) -> Self {
        Self {
            state: RwLock::new(state),
        }
    }

    /// Reserve `n` consecutive preprocessing indices for `client_id`.
    pub async fn reserve(
        &self,
        client_id: ClientId,
        n: u64,
    ) -> Result<ReservationGrant, ReservationError> {
        let mut s = self.state.write().await;
        let avail = s.capacity.checked_sub(s.next_index).ok_or_else(|| {
            ReservationError::InvalidState(format!(
                "next_index {} exceeds capacity {}",
                s.next_index, s.capacity
            ))
        })?;
        if n > avail {
            return Err(ReservationError::InsufficientMaterial {
                need: n,
                have: avail,
            });
        }
        let start = s.next_index;
        let end = start
            .checked_add(n)
            .ok_or(ReservationError::IndexOverflow { start, count: n })?;
        for i in start..end {
            s.slots.insert(i, SlotStatus::Reserved(client_id));
        }
        s.next_index = end;
        Ok(ReservationGrant { start, count: n })
    }

    /// Submit a masked input at a previously reserved index.
    pub async fn submit_masked_input(
        &self,
        client_id: ClientId,
        index: u64,
        value: Vec<u8>,
    ) -> Result<(), ReservationError> {
        let mut s = self.state.write().await;
        if index >= s.capacity {
            return Err(ReservationError::OutOfBounds(index));
        }
        match s.slots.get(&index) {
            Some(SlotStatus::Reserved(id)) if *id == client_id => {}
            Some(SlotStatus::Consumed(_)) => return Err(ReservationError::AlreadyConsumed(index)),
            Some(_) => return Err(ReservationError::NotReservedByClient(index)),
            None => return Err(ReservationError::NotReserved(index)),
        }
        s.masked_inputs.insert(index, value);
        Ok(())
    }

    /// Mark indices as consumed during MPC execution.
    pub async fn consume(&self, indices: &[u64]) -> Result<(), ReservationError> {
        let mut s = self.state.write().await;
        for &i in indices {
            if i >= s.capacity {
                return Err(ReservationError::OutOfBounds(i));
            }
            let client_id = match s.slots.get(&i) {
                Some(SlotStatus::Reserved(id)) => *id,
                Some(SlotStatus::Consumed(_)) => return Err(ReservationError::AlreadyConsumed(i)),
                None => return Err(ReservationError::NotReserved(i)),
            };
            s.slots.insert(i, SlotStatus::Consumed(client_id));
        }
        Ok(())
    }

    pub async fn available(&self) -> u64 {
        let s = self.state.read().await;
        s.capacity.saturating_sub(s.next_index)
    }

    pub async fn get_masked_input(&self, index: u64) -> Option<Vec<u8>> {
        let s = self.state.read().await;
        s.masked_inputs.get(&index).cloned()
    }

    pub async fn snapshot(&self) -> RegistryState {
        self.state.read().await.clone()
    }

    // -----------------------------------------------------------------------
    // Persistence through PreprocStore
    // -----------------------------------------------------------------------

    pub async fn persist(&self, store: &dyn PreprocStore) -> Result<(), ReservationError> {
        let state = self.snapshot().await;
        state.validate()?;
        let key = ReservationPersistenceKey::new(state.program_hash, state.party_id).encode()?;
        let data = bincode::serialize(&state)
            .map_err(|e| PreprocStoreError::Serialization(e.to_string()))?;
        store.store_blob(RESERVATION_NS, &key, &data).await?;
        Ok(())
    }

    pub async fn load(
        store: &dyn PreprocStore,
        program_hash: &[u8; 32],
        party_id: usize,
    ) -> Result<Option<Self>, ReservationError> {
        let key = ReservationPersistenceKey::new(*program_hash, party_id).encode()?;
        let data = store.load_blob(RESERVATION_NS, &key).await?;
        match data {
            Some(bytes) => {
                let state: RegistryState = bincode::deserialize(&bytes)
                    .map_err(|e| PreprocStoreError::Deserialization(e.to_string()))?;
                Ok(Some(Self::try_from_state(state)?))
            }
            None => Ok(None),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::preproc::LmdbPreprocStore;

    #[tokio::test]
    async fn reserve_basic() {
        let reg = ReservationRegistry::new([0; 32], 0, 10);
        let grant = reg.reserve(1, 3).await.unwrap();
        assert_eq!(grant.start, 0);
        assert_eq!(grant.count, 3);
        assert_eq!(reg.available().await, 7);
    }

    #[tokio::test]
    async fn reserve_insufficient() {
        let reg = ReservationRegistry::new([0; 32], 0, 5);
        let err = reg.reserve(1, 6).await.unwrap_err();
        assert!(matches!(
            err,
            ReservationError::InsufficientMaterial { need: 6, have: 5 }
        ));
    }

    #[tokio::test]
    async fn submit_and_consume() {
        let reg = ReservationRegistry::new([0; 32], 0, 10);
        let grant = reg.reserve(1, 3).await.unwrap();

        reg.submit_masked_input(1, grant.start, vec![0xAA])
            .await
            .unwrap();
        assert_eq!(reg.get_masked_input(grant.start).await, Some(vec![0xAA]));

        let err = reg
            .submit_masked_input(99, grant.start + 1, vec![0xBB])
            .await
            .unwrap_err();
        assert!(matches!(err, ReservationError::NotReservedByClient(_)));

        let indices: Vec<u64> = grant.indices().collect();
        reg.consume(&indices).await.unwrap();

        let err = reg.consume(&indices).await.unwrap_err();
        assert!(matches!(err, ReservationError::AlreadyConsumed(_)));
    }

    #[tokio::test]
    async fn unreserved_index_errors() {
        let reg = ReservationRegistry::new([0; 32], 0, 10);
        let err = reg.submit_masked_input(1, 0, vec![0xFF]).await.unwrap_err();
        assert!(matches!(err, ReservationError::NotReserved(0)));

        let err = reg.consume(&[0]).await.unwrap_err();
        assert!(matches!(err, ReservationError::NotReserved(0)));
    }

    #[tokio::test]
    async fn persist_and_restore() {
        let dir = tempfile::tempdir().unwrap();
        let store = LmdbPreprocStore::open(dir.path()).unwrap();

        let reg = ReservationRegistry::new([0x42; 32], 1, 20);
        reg.reserve(5, 4).await.unwrap();
        reg.submit_masked_input(5, 0, vec![0xFF]).await.unwrap();

        reg.persist(&store).await.unwrap();

        let restored = ReservationRegistry::load(&store, &[0x42; 32], 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(restored.available().await, 16);
        assert_eq!(restored.get_masked_input(0).await, Some(vec![0xFF]));
    }

    #[tokio::test]
    async fn load_nonexistent() {
        let dir = tempfile::tempdir().unwrap();
        let store = LmdbPreprocStore::open(dir.path()).unwrap();
        let result = ReservationRegistry::load(&store, &[0x99; 32], 0)
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn reserve_rejects_invalid_cursor_without_underflow() {
        let reg = ReservationRegistry::from_state(RegistryState {
            program_hash: [0; 32],
            party_id: 0,
            capacity: 1,
            next_index: 2,
            slots: BTreeMap::new(),
            masked_inputs: BTreeMap::new(),
        });

        let err = reg.reserve(1, 1).await.unwrap_err();
        assert!(matches!(err, ReservationError::InvalidState(_)));
    }

    #[tokio::test]
    async fn load_rejects_invalid_persisted_state() {
        let dir = tempfile::tempdir().unwrap();
        let store = LmdbPreprocStore::open(dir.path()).unwrap();
        let program_hash = [0x5A; 32];
        let state = RegistryState {
            program_hash,
            party_id: 0,
            capacity: 1,
            next_index: 2,
            slots: BTreeMap::new(),
            masked_inputs: BTreeMap::new(),
        };
        let key = ReservationPersistenceKey::new(program_hash, 0)
            .encode()
            .unwrap();
        let data = bincode::serialize(&state).unwrap();
        store.store_blob(RESERVATION_NS, &key, &data).await.unwrap();

        let err = match ReservationRegistry::load(&store, &program_hash, 0).await {
            Ok(_) => panic!("invalid persisted state should be rejected"),
            Err(err) => err,
        };
        assert!(matches!(err, ReservationError::InvalidState(_)));
    }

    #[test]
    fn persistence_key_rejects_party_ids_outside_binary_key_domain() {
        if usize::BITS <= u32::BITS {
            return;
        }

        let oversized = usize::try_from(u64::from(u32::MAX) + 1).unwrap();
        let err = ReservationPersistenceKey::new([0; 32], oversized)
            .encode()
            .expect_err("oversized party ID should be rejected");
        assert!(matches!(
            err,
            PreprocStoreError::U32Overflow {
                field: "reservation key party_id",
                ..
            }
        ));
    }

    #[test]
    fn try_from_state_rejects_masked_input_without_slot() {
        let mut masked_inputs = BTreeMap::new();
        masked_inputs.insert(0, vec![0xAA]);
        let state = RegistryState {
            program_hash: [0; 32],
            party_id: 0,
            capacity: 1,
            next_index: 0,
            slots: BTreeMap::new(),
            masked_inputs,
        };

        let err = match ReservationRegistry::try_from_state(state) {
            Ok(_) => panic!("invalid registry state should be rejected"),
            Err(err) => err,
        };
        assert!(matches!(err, ReservationError::InvalidState(_)));
    }
}
