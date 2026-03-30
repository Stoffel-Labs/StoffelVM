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

#[derive(Debug, thiserror::Error)]
pub enum ReservationError {
    #[error("insufficient material: need {need}, have {have}")]
    InsufficientMaterial { need: u64, have: u64 },
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

    pub fn from_state(state: RegistryState) -> Self {
        Self { state: RwLock::new(state) }
    }

    /// Reserve `n` consecutive indices for `client_id`. O(1) allocation.
    pub async fn reserve(
        &self,
        client_id: ClientId,
        n: u64,
    ) -> Result<ReservationGrant, ReservationError> {
        let mut s = self.state.write().await;
        let avail = s.capacity - s.next_index;
        if n > avail {
            return Err(ReservationError::InsufficientMaterial { need: n, have: avail });
        }
        let start = s.next_index;
        for i in start..start + n {
            s.slots.insert(i, SlotStatus::Reserved(client_id));
        }
        s.next_index = start + n;
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
        s.capacity - s.next_index
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

    fn persistence_key(program_hash: &[u8; 32], party_id: usize) -> Vec<u8> {
        let mut k = Vec::with_capacity(36);
        k.extend_from_slice(program_hash);
        k.extend_from_slice(&(party_id as u32).to_le_bytes());
        k
    }

    pub async fn persist(&self, store: &dyn PreprocStore) -> Result<(), ReservationError> {
        let state = self.snapshot().await;
        let key = Self::persistence_key(&state.program_hash, state.party_id);
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
        let key = Self::persistence_key(program_hash, party_id);
        let data = store.load_blob(RESERVATION_NS, &key).await?;
        match data {
            Some(bytes) => {
                let state: RegistryState = bincode::deserialize(&bytes)
                    .map_err(|e| PreprocStoreError::Deserialization(e.to_string()))?;
                Ok(Some(Self::from_state(state)))
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
        assert!(matches!(err, ReservationError::InsufficientMaterial { need: 6, have: 5 }));
    }

    #[tokio::test]
    async fn submit_and_consume() {
        let reg = ReservationRegistry::new([0; 32], 0, 10);
        let grant = reg.reserve(1, 3).await.unwrap();

        reg.submit_masked_input(1, grant.start, vec![0xAA]).await.unwrap();
        assert_eq!(reg.get_masked_input(grant.start).await, Some(vec![0xAA]));

        let err = reg.submit_masked_input(99, grant.start + 1, vec![0xBB]).await.unwrap_err();
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
            .await.unwrap().unwrap();
        assert_eq!(restored.available().await, 16);
        assert_eq!(restored.get_masked_input(0).await, Some(vec![0xFF]));
    }

    #[tokio::test]
    async fn load_nonexistent() {
        let dir = tempfile::tempdir().unwrap();
        let store = LmdbPreprocStore::open(dir.path()).unwrap();
        let result = ReservationRegistry::load(&store, &[0x99; 32], 0).await.unwrap();
        assert!(result.is_none());
    }
}
