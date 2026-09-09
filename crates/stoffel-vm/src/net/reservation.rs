//! Masked share reservation registry.
//!
//! Tracks which preprocessing indices are reserved by which clients for
//! the masked-input protocol. Mirrors the coordinator's allocation model:
//! sequential index allocation via an advancing cursor.

use crate::net::mpc_engine::DurableIdentityDigest;
use crate::storage::preproc::{PoolAvailability, PreprocStore, PreprocStoreError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Per-index reservation state (only stored for non-Free indices).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SlotStatus {
    Reserved(DurableIdentityDigest),
    Consumed(DurableIdentityDigest),
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
    pub node_identity: DurableIdentityDigest,
    #[serde(default)]
    pub run_id: u64,
    #[serde(default)]
    pub preproc_offset: PoolAvailability,
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
    node_identity: DurableIdentityDigest,
    run_id: u64,
}

impl ReservationPersistenceKey {
    fn new(program_hash: [u8; 32], node_identity: DurableIdentityDigest, run_id: u64) -> Self {
        Self {
            program_hash,
            node_identity,
            run_id,
        }
    }

    fn encode(self) -> Vec<u8> {
        let mut key = Vec::with_capacity(72);
        key.extend_from_slice(&self.program_hash);
        key.extend_from_slice(&self.node_identity.as_bytes());
        key.extend_from_slice(&self.run_id.to_le_bytes());
        key
    }
}

impl ReservationRegistry {
    pub fn new(
        program_hash: [u8; 32],
        node_identity: DurableIdentityDigest,
        capacity: u64,
    ) -> Self {
        Self {
            state: RwLock::new(RegistryState {
                program_hash,
                node_identity,
                run_id: 0,
                preproc_offset: PoolAvailability::default(),
                capacity,
                next_index: 0,
                slots: BTreeMap::new(),
                masked_inputs: BTreeMap::new(),
            }),
        }
    }

    pub fn new_for_run(
        program_hash: [u8; 32],
        node_identity: DurableIdentityDigest,
        capacity: u64,
        run_id: u64,
        preproc_offset: PoolAvailability,
    ) -> Self {
        Self {
            state: RwLock::new(RegistryState {
                program_hash,
                node_identity,
                run_id,
                preproc_offset,
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

    /// Reserve `n` consecutive preprocessing indices for `client_identity`.
    pub async fn reserve(
        &self,
        client_identity: DurableIdentityDigest,
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
            s.slots.insert(i, SlotStatus::Reserved(client_identity));
        }
        s.next_index = end;
        Ok(ReservationGrant { start, count: n })
    }

    /// Submit a masked input at a previously reserved index.
    pub async fn submit_masked_input(
        &self,
        client_identity: DurableIdentityDigest,
        index: u64,
        value: Vec<u8>,
    ) -> Result<(), ReservationError> {
        let mut s = self.state.write().await;
        if index >= s.capacity {
            return Err(ReservationError::OutOfBounds(index));
        }
        match s.slots.get(&index) {
            Some(SlotStatus::Reserved(id)) if *id == client_identity => {}
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
        let mut consumed = Vec::with_capacity(indices.len());
        for &i in indices {
            if i >= s.capacity {
                return Err(ReservationError::OutOfBounds(i));
            }
            let client_id = match s.slots.get(&i) {
                Some(SlotStatus::Reserved(id)) => *id,
                Some(SlotStatus::Consumed(_)) => return Err(ReservationError::AlreadyConsumed(i)),
                None => return Err(ReservationError::NotReserved(i)),
            };
            consumed.push((i, client_id));
        }
        for (i, client_id) in consumed {
            s.slots.insert(i, SlotStatus::Consumed(client_id));
            s.masked_inputs.remove(&i);
        }
        Ok(())
    }

    pub async fn available(&self) -> u64 {
        let s = self.state.read().await;
        s.capacity.saturating_sub(s.next_index)
    }

    pub async fn run_id(&self) -> u64 {
        self.state.read().await.run_id
    }

    pub async fn preproc_offset(&self) -> PoolAvailability {
        self.state.read().await.preproc_offset
    }

    pub async fn all_reserved_slots_consumed(&self) -> bool {
        let s = self.state.read().await;
        !s.slots.is_empty()
            && s.slots
                .values()
                .all(|status| matches!(status, SlotStatus::Consumed(_)))
    }

    /// True only after the entire declared run capacity was allocated and
    /// consumed. A partially allocated crash must remain recoverable even when
    /// every slot allocated so far happened to be consumed.
    pub async fn is_fully_consumed(&self) -> bool {
        let s = self.state.read().await;
        s.next_index == s.capacity
            && usize::try_from(s.capacity).ok() == Some(s.slots.len())
            && s.slots
                .values()
                .all(|status| matches!(status, SlotStatus::Consumed(_)))
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
        let key =
            ReservationPersistenceKey::new(state.program_hash, state.node_identity, state.run_id)
                .encode();
        let data = bincode::serialize(&state)
            .map_err(|e| PreprocStoreError::Serialization(e.to_string()))?;
        store.store_blob(RESERVATION_NS, &key, &data).await?;
        Ok(())
    }

    pub async fn load(
        store: &dyn PreprocStore,
        program_hash: &[u8; 32],
        node_identity: DurableIdentityDigest,
    ) -> Result<Option<Self>, ReservationError> {
        Self::load_for_run(store, program_hash, node_identity, 0).await
    }

    pub async fn load_for_run(
        store: &dyn PreprocStore,
        program_hash: &[u8; 32],
        node_identity: DurableIdentityDigest,
        run_id: u64,
    ) -> Result<Option<Self>, ReservationError> {
        let key = ReservationPersistenceKey::new(*program_hash, node_identity, run_id).encode();
        let data = store.load_blob(RESERVATION_NS, &key).await?;
        match data {
            Some(bytes) => {
                let state: RegistryState = bincode::deserialize(&bytes)
                    .map_err(|error| PreprocStoreError::Deserialization(error.to_string()))?;
                if state.program_hash != *program_hash
                    || state.node_identity != node_identity
                    || state.run_id != run_id
                {
                    return Err(ReservationError::InvalidState(format!(
                        "persisted reservation identity does not match requested program, node, and run {run_id}"
                    )));
                }
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

    fn identity(seed: u8) -> DurableIdentityDigest {
        DurableIdentityDigest::from_public_key_bytes(&[seed; 32])
    }

    fn client(seed: u8) -> DurableIdentityDigest {
        DurableIdentityDigest::from_public_key_bytes(&[seed; 16])
    }

    #[tokio::test]
    async fn reserve_basic() {
        let reg = ReservationRegistry::new([0; 32], identity(0), 10);
        let grant = reg.reserve(client(1), 3).await.unwrap();
        assert_eq!(grant.start, 0);
        assert_eq!(grant.count, 3);
        assert_eq!(reg.available().await, 7);
    }

    #[tokio::test]
    async fn reserve_insufficient() {
        let reg = ReservationRegistry::new([0; 32], identity(0), 5);
        let err = reg.reserve(client(1), 6).await.unwrap_err();
        assert!(matches!(
            err,
            ReservationError::InsufficientMaterial { need: 6, have: 5 }
        ));
    }

    #[tokio::test]
    async fn submit_and_consume() {
        let reg = ReservationRegistry::new([0; 32], identity(0), 10);
        let grant = reg.reserve(client(1), 3).await.unwrap();

        reg.submit_masked_input(client(1), grant.start, vec![0xAA])
            .await
            .unwrap();
        assert_eq!(reg.get_masked_input(grant.start).await, Some(vec![0xAA]));

        let err = reg
            .submit_masked_input(client(99), grant.start + 1, vec![0xBB])
            .await
            .unwrap_err();
        assert!(matches!(err, ReservationError::NotReservedByClient(_)));

        let indices: Vec<u64> = grant.indices().collect();
        reg.consume(&indices).await.unwrap();
        assert_eq!(
            reg.get_masked_input(grant.start).await,
            None,
            "consumed masked input payload should be evicted"
        );
        assert!(reg.all_reserved_slots_consumed().await);
        assert!(
            !reg.is_fully_consumed().await,
            "consuming a partial allocation must remain crash-recoverable"
        );

        let err = reg.consume(&indices).await.unwrap_err();
        assert!(matches!(err, ReservationError::AlreadyConsumed(_)));
    }

    #[tokio::test]
    async fn unreserved_index_errors() {
        let reg = ReservationRegistry::new([0; 32], identity(0), 10);
        let err = reg
            .submit_masked_input(client(1), 0, vec![0xFF])
            .await
            .unwrap_err();
        assert!(matches!(err, ReservationError::NotReserved(0)));

        let err = reg.consume(&[0]).await.unwrap_err();
        assert!(matches!(err, ReservationError::NotReserved(0)));
    }

    #[tokio::test]
    async fn persist_and_restore() {
        let dir = tempfile::tempdir().unwrap();
        let store = LmdbPreprocStore::open(dir.path()).unwrap();

        let node_identity = identity(1);
        let reg = ReservationRegistry::new([0x42; 32], node_identity, 20);
        reg.reserve(client(5), 4).await.unwrap();
        reg.submit_masked_input(client(5), 0, vec![0xFF])
            .await
            .unwrap();

        reg.persist(&store).await.unwrap();

        let restored = ReservationRegistry::load(&store, &[0x42; 32], node_identity)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(restored.available().await, 16);
        assert_eq!(restored.get_masked_input(0).await, Some(vec![0xFF]));
    }

    #[tokio::test]
    async fn persistence_isolated_by_run_id() {
        let dir = tempfile::tempdir().unwrap();
        let store = LmdbPreprocStore::open(dir.path()).unwrap();
        let program_hash = [0x43; 32];
        let node_identity = identity(2);

        let first = ReservationRegistry::new_for_run(
            program_hash,
            node_identity,
            20,
            11,
            PoolAvailability::default(),
        );
        first.reserve(client(5), 2).await.unwrap();
        first
            .submit_masked_input(client(5), 0, vec![0x11])
            .await
            .unwrap();
        first.persist(&store).await.unwrap();

        let second = ReservationRegistry::new_for_run(
            program_hash,
            node_identity,
            20,
            12,
            PoolAvailability::default(),
        );
        second.reserve(client(6), 5).await.unwrap();
        second
            .submit_masked_input(client(6), 0, vec![0x12])
            .await
            .unwrap();
        second.persist(&store).await.unwrap();

        let restored_first =
            ReservationRegistry::load_for_run(&store, &program_hash, node_identity, 11)
                .await
                .unwrap()
                .unwrap();
        let restored_second =
            ReservationRegistry::load_for_run(&store, &program_hash, node_identity, 12)
                .await
                .unwrap()
                .unwrap();

        assert_eq!(restored_first.run_id().await, 11);
        assert_eq!(restored_first.available().await, 18);
        assert_eq!(restored_first.get_masked_input(0).await, Some(vec![0x11]));
        assert_eq!(restored_second.run_id().await, 12);
        assert_eq!(restored_second.available().await, 15);
        assert_eq!(restored_second.get_masked_input(0).await, Some(vec![0x12]));
    }

    #[tokio::test]
    async fn load_nonexistent() {
        let dir = tempfile::tempdir().unwrap();
        let store = LmdbPreprocStore::open(dir.path()).unwrap();
        let result = ReservationRegistry::load(&store, &[0x99; 32], identity(0))
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn reserve_rejects_invalid_cursor_without_underflow() {
        let reg = ReservationRegistry::from_state(RegistryState {
            program_hash: [0; 32],
            node_identity: identity(0),
            run_id: 0,
            preproc_offset: PoolAvailability::default(),
            capacity: 1,
            next_index: 2,
            slots: BTreeMap::new(),
            masked_inputs: BTreeMap::new(),
        });

        let err = reg.reserve(client(1), 1).await.unwrap_err();
        assert!(matches!(err, ReservationError::InvalidState(_)));
    }

    #[tokio::test]
    async fn load_rejects_invalid_persisted_state() {
        let dir = tempfile::tempdir().unwrap();
        let store = LmdbPreprocStore::open(dir.path()).unwrap();
        let program_hash = [0x5A; 32];
        let state = RegistryState {
            program_hash,
            node_identity: identity(0),
            run_id: 0,
            preproc_offset: PoolAvailability::default(),
            capacity: 1,
            next_index: 2,
            slots: BTreeMap::new(),
            masked_inputs: BTreeMap::new(),
        };
        let key = ReservationPersistenceKey::new(program_hash, identity(0), 0).encode();
        let data = bincode::serialize(&state).unwrap();
        store.store_blob(RESERVATION_NS, &key, &data).await.unwrap();

        let err = match ReservationRegistry::load(&store, &program_hash, identity(0)).await {
            Ok(_) => panic!("invalid persisted state should be rejected"),
            Err(err) => err,
        };
        assert!(matches!(err, ReservationError::InvalidState(_)));
    }

    #[test]
    fn try_from_state_rejects_masked_input_without_slot() {
        let mut masked_inputs = BTreeMap::new();
        masked_inputs.insert(0, vec![0xAA]);
        let state = RegistryState {
            program_hash: [0; 32],
            node_identity: identity(0),
            run_id: 0,
            preproc_offset: PoolAvailability::default(),
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
