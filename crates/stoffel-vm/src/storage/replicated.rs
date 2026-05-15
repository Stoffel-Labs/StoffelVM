//! Interface for storage that is replicated across multiple peers.

use std::future::Future;
use std::pin::Pin;

pub type ReplicatedStorageResult<T> = Result<T, ReplicatedStorageError>;
pub type ReplicatedStorageFuture<'a, T> =
    Pin<Box<dyn Future<Output = ReplicatedStorageResult<T>> + Send + 'a>>;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReplicatedStorageError {
    #[error("replicated storage lock for {resource} was poisoned")]
    LockPoisoned { resource: &'static str },
}

impl From<ReplicatedStorageError> for String {
    fn from(error: ReplicatedStorageError) -> Self {
        error.to_string()
    }
}

/// Trait defining operations for replicated data storage.
/// Implementation requires a consensus mechanism (e.g., Raft, Paxos) or
/// a specific replication strategy suitable for the MPC context.
pub trait ReplicatedStorage: Send + Sync {
    /// Proposes storing data associated with a key across replicas.
    /// This operation needs to achieve consensus before confirming success.
    fn store<'a>(&'a mut self, key: &'a [u8], value: &'a [u8]) -> ReplicatedStorageFuture<'a, ()>;

    /// Retrieves data associated with a key from the replicated state.
    /// May require reading from a quorum or the leader depending on consistency model.
    fn retrieve<'a>(&'a self, key: &'a [u8]) -> ReplicatedStorageFuture<'a, Option<Vec<u8>>>;

    /// Proposes deleting data associated with a key across replicas.
    fn delete<'a>(&'a mut self, key: &'a [u8]) -> ReplicatedStorageFuture<'a, bool>;

    /// Checks if a key exists in the replicated state.
    fn exists<'a>(&'a self, key: &'a [u8]) -> ReplicatedStorageFuture<'a, bool>;
}

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// In-memory implementation of [`ReplicatedStorage`].
///
/// This is intentionally local and deterministic. It is useful for tests and
/// single-process development, while production deployments should provide a
/// network-backed implementation that satisfies the trait's replication
/// contract.
#[derive(Default, Clone)]
pub struct BasicReplicatedStorage {
    data: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
}

impl ReplicatedStorage for BasicReplicatedStorage {
    fn store<'a>(&'a mut self, key: &'a [u8], value: &'a [u8]) -> ReplicatedStorageFuture<'a, ()> {
        let data_clone = Arc::clone(&self.data);
        let key_vec = key.to_vec();
        let value_vec = value.to_vec();

        Box::pin(async move {
            let mut data = data_clone
                .lock()
                .map_err(|_| ReplicatedStorageError::LockPoisoned {
                    resource: "replicated storage data",
                })?;
            data.insert(key_vec, value_vec);
            Ok(())
        })
    }

    fn retrieve<'a>(&'a self, key: &'a [u8]) -> ReplicatedStorageFuture<'a, Option<Vec<u8>>> {
        let data_clone = Arc::clone(&self.data);
        let key_vec = key.to_vec();

        Box::pin(async move {
            let data = data_clone
                .lock()
                .map_err(|_| ReplicatedStorageError::LockPoisoned {
                    resource: "replicated storage data",
                })?;
            Ok(data.get(&key_vec).cloned())
        })
    }

    fn delete<'a>(&'a mut self, key: &'a [u8]) -> ReplicatedStorageFuture<'a, bool> {
        let data_clone = Arc::clone(&self.data);
        let key_vec = key.to_vec();
        Box::pin(async move {
            let mut data = data_clone
                .lock()
                .map_err(|_| ReplicatedStorageError::LockPoisoned {
                    resource: "replicated storage data",
                })?;
            Ok(data.remove(&key_vec).is_some())
        })
    }

    fn exists<'a>(&'a self, key: &'a [u8]) -> ReplicatedStorageFuture<'a, bool> {
        let data_clone = Arc::clone(&self.data);
        let key_vec = key.to_vec();
        Box::pin(async move {
            let data = data_clone
                .lock()
                .map_err(|_| ReplicatedStorageError::LockPoisoned {
                    resource: "replicated storage data",
                })?;
            Ok(data.contains_key(&key_vec))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{BasicReplicatedStorage, ReplicatedStorage, ReplicatedStorageError};

    #[tokio::test]
    async fn in_memory_storage_round_trips_values() {
        let mut storage = BasicReplicatedStorage::default();

        assert!(!storage.exists(b"key").await.expect("exists"));
        assert_eq!(storage.retrieve(b"key").await.expect("retrieve"), None);

        storage.store(b"key", b"value").await.expect("store");

        assert!(storage.exists(b"key").await.expect("exists"));
        assert_eq!(
            storage.retrieve(b"key").await.expect("retrieve"),
            Some(b"value".to_vec())
        );
        assert!(storage.delete(b"key").await.expect("delete"));
        assert!(!storage.delete(b"key").await.expect("delete missing"));
        assert_eq!(storage.retrieve(b"key").await.expect("retrieve"), None);
    }

    #[tokio::test]
    async fn in_memory_storage_clones_share_state() {
        let mut first = BasicReplicatedStorage::default();
        let second = first.clone();

        first.store(b"shared", b"value").await.expect("store");

        assert_eq!(
            second.retrieve(b"shared").await.expect("retrieve"),
            Some(b"value".to_vec())
        );
    }

    #[tokio::test]
    async fn lock_poisoning_reports_typed_error() {
        let storage = BasicReplicatedStorage::default();
        let poisoned = storage.clone();

        let thread_result = std::thread::spawn(move || {
            let _guard = poisoned.data.lock().expect("lock storage");
            panic!("poison storage lock");
        })
        .join();
        assert!(thread_result.is_err());

        let err = storage.retrieve(b"key").await.unwrap_err();

        assert_eq!(
            err,
            ReplicatedStorageError::LockPoisoned {
                resource: "replicated storage data"
            }
        );
    }
}
