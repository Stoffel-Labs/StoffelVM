//! Interface for persistent storage local to a single server/peer using redb.

use super::value_codec::{
    decode_value, decode_value_with_context, encode_value, encode_value_with_context,
    PersistentValueContext, PersistentValueError,
};
use redb::{Database, TableDefinition};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use stoffel_vm_types::core_types::{TableMemory, Value};

pub type LocalStorageResult<T> = Result<T, LocalStorageError>;
pub type LocalStorageValueResult<T> = Result<T, LocalStorageValueError>;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LocalStorageError {
    #[error("failed to open redb database at {path}: {reason}")]
    Open { path: PathBuf, reason: String },
    #[error("redb transaction '{operation}' failed: {reason}")]
    Transaction {
        operation: &'static str,
        reason: String,
    },
    #[error("redb table '{operation}' failed: {reason}")]
    Table {
        operation: &'static str,
        reason: String,
    },
    #[error("redb operation '{operation}' failed: {reason}")]
    Operation {
        operation: &'static str,
        reason: String,
    },
}

impl From<LocalStorageError> for String {
    fn from(error: LocalStorageError) -> Self {
        error.to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LocalStorageValueError {
    #[error(transparent)]
    Storage(#[from] LocalStorageError),
    #[error(transparent)]
    Codec(#[from] PersistentValueError),
}

impl From<LocalStorageValueError> for String {
    fn from(error: LocalStorageValueError) -> Self {
        error.to_string()
    }
}

/// Trait defining operations for local data persistence.
pub trait LocalStorage: Send + Sync {
    /// Stores data associated with a key. Overwrites if the key exists.
    fn store(&mut self, key: &[u8], value: &[u8]) -> LocalStorageResult<()>;

    /// Retrieves data associated with a key.
    fn retrieve(&self, key: &[u8]) -> LocalStorageResult<Option<Vec<u8>>>;

    /// Deletes data associated with a key.
    fn delete(&mut self, key: &[u8]) -> LocalStorageResult<bool>;

    /// Checks if a key exists.
    fn exists(&self, key: &[u8]) -> LocalStorageResult<bool>;

    /// Removes all data from this storage namespace.
    fn clear(&mut self) -> LocalStorageResult<()>;
}

/// Value-oriented extension methods for [`LocalStorage`] implementations.
pub trait LocalStorageValues: LocalStorage {
    fn store_value(
        &mut self,
        key: &[u8],
        value: &Value,
        memory: &mut dyn TableMemory,
    ) -> LocalStorageValueResult<()> {
        self.store_value_with_context(key, value, memory, None)
    }

    fn store_value_with_context(
        &mut self,
        key: &[u8],
        value: &Value,
        memory: &mut dyn TableMemory,
        context: Option<&PersistentValueContext>,
    ) -> LocalStorageValueResult<()> {
        let encoded = match context {
            Some(context) => encode_value_with_context(value, memory, Some(context))?,
            None => encode_value(value, memory)?,
        };
        self.store(key, &encoded)?;
        Ok(())
    }

    fn retrieve_value(
        &self,
        key: &[u8],
        memory: &mut dyn TableMemory,
    ) -> LocalStorageValueResult<Option<Value>> {
        self.retrieve_value_with_context(key, memory, None)
    }

    fn retrieve_value_with_context(
        &self,
        key: &[u8],
        memory: &mut dyn TableMemory,
        context: Option<&PersistentValueContext>,
    ) -> LocalStorageValueResult<Option<Value>> {
        self.retrieve(key)?
            .map(|bytes| match context {
                Some(context) => decode_value_with_context(&bytes, memory, Some(context)),
                None => decode_value(&bytes, memory),
            })
            .transpose()
            .map_err(LocalStorageValueError::from)
    }
}

impl<T> LocalStorageValues for T where T: LocalStorage + ?Sized {}

// All views share one table. The scope prefix keeps one-shot and concurrent
// execution state disjoint without maintaining two storage implementations.
const DATA_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("data_kv_store");
const NAMESPACE_KEY_FORMAT_VERSION: u8 = 1;
const NAMESPACE_CLEAR_BATCH_KEYS: usize = 256;

/// Implementation of LocalStorage using the redb library.
#[derive(Clone)]
pub struct RedbLocalStorage {
    db: Arc<Database>,
    namespace: Option<[u8; 32]>,
}

impl RedbLocalStorage {
    /// Creates or opens a redb database at the specified path.
    pub fn new<P: AsRef<Path>>(path: P) -> LocalStorageResult<Self> {
        let path = path.as_ref().to_path_buf();
        let db = Database::create(&path).map_err(|error| LocalStorageError::Open {
            path,
            reason: error.to_string(),
        })?;

        let write_txn = db
            .begin_write()
            .map_err(|error| LocalStorageError::Transaction {
                operation: "begin initial write",
                reason: error.to_string(),
            })?;
        {
            let _ = write_txn
                .open_table(DATA_TABLE)
                .map_err(|error| LocalStorageError::Table {
                    operation: "open data table",
                    reason: error.to_string(),
                })?;
        }
        write_txn
            .commit()
            .map_err(|error| LocalStorageError::Transaction {
                operation: "commit initial write",
                reason: error.to_string(),
            })?;

        Ok(RedbLocalStorage {
            db: Arc::new(db),
            namespace: None,
        })
    }

    /// Returns a storage view isolated to one execution ID without reopening the database.
    #[must_use]
    pub fn with_namespace(&self, namespace: [u8; 32]) -> Self {
        Self {
            db: Arc::clone(&self.db),
            namespace: Some(namespace),
        }
    }

    fn scope_prefix(&self) -> Vec<u8> {
        match self.namespace {
            Some(namespace) => {
                let mut prefix = Vec::with_capacity(2 + namespace.len());
                prefix.extend_from_slice(&[NAMESPACE_KEY_FORMAT_VERSION, 1]);
                prefix.extend_from_slice(&namespace);
                prefix
            }
            None => vec![NAMESPACE_KEY_FORMAT_VERSION, 0],
        }
    }

    fn storage_key(&self, key: &[u8]) -> Vec<u8> {
        let mut storage_key = self.scope_prefix();
        storage_key.extend_from_slice(key);
        storage_key
    }

    fn clear_batch(&mut self, maximum_keys: usize) -> LocalStorageResult<usize> {
        let prefix = self.scope_prefix();
        let mut upper_bound = prefix.clone();
        let last_non_max = upper_bound
            .iter()
            .rposition(|byte| *byte != u8::MAX)
            .expect("versioned namespace prefix has a finite upper bound");
        upper_bound[last_non_max] += 1;
        upper_bound.truncate(last_non_max + 1);

        self.with_write_txn(|table| {
            let entries = table
                .extract_from_if(prefix.as_slice()..upper_bound.as_slice(), |_, _| true)
                .map_err(|error| LocalStorageError::Operation {
                    operation: "scan storage scope",
                    reason: error.to_string(),
                })?;
            let mut removed = 0;
            for entry in entries.take(maximum_keys) {
                entry.map_err(|error| LocalStorageError::Operation {
                    operation: "remove storage key",
                    reason: error.to_string(),
                })?;
                removed += 1;
            }
            Ok(removed)
        })
    }

    fn with_write_txn<F, R>(&mut self, operation: F) -> LocalStorageResult<R>
    where
        F: FnOnce(&mut redb::Table<&[u8], &[u8]>) -> LocalStorageResult<R>,
    {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|error| LocalStorageError::Transaction {
                operation: "begin write",
                reason: error.to_string(),
            })?;
        let result = {
            let mut table =
                write_txn
                    .open_table(DATA_TABLE)
                    .map_err(|error| LocalStorageError::Table {
                        operation: "open data table for write",
                        reason: error.to_string(),
                    })?;
            operation(&mut table)
        };

        if result.is_ok() {
            write_txn
                .commit()
                .map_err(|error| LocalStorageError::Transaction {
                    operation: "commit write",
                    reason: error.to_string(),
                })?;
        }
        result
    }
}

impl LocalStorage for RedbLocalStorage {
    fn store(&mut self, key: &[u8], value: &[u8]) -> LocalStorageResult<()> {
        let key = self.storage_key(key);
        self.with_write_txn(|table| {
            table
                .insert(key.as_slice(), value)
                .map_err(|error| LocalStorageError::Operation {
                    operation: "insert",
                    reason: error.to_string(),
                })?;
            Ok(())
        })
    }

    fn retrieve(&self, key: &[u8]) -> LocalStorageResult<Option<Vec<u8>>> {
        let key = self.storage_key(key);
        let read_txn = self
            .db
            .begin_read()
            .map_err(|error| LocalStorageError::Transaction {
                operation: "begin read",
                reason: error.to_string(),
            })?;
        let table = read_txn
            .open_table(DATA_TABLE)
            .map_err(|error| LocalStorageError::Table {
                operation: "open data table for read",
                reason: error.to_string(),
            })?;

        match table
            .get(key.as_slice())
            .map_err(|error| LocalStorageError::Operation {
                operation: "get",
                reason: error.to_string(),
            })? {
            Some(value) => Ok(Some(value.value().to_vec())),
            None => Ok(None),
        }
    }

    fn delete(&mut self, key: &[u8]) -> LocalStorageResult<bool> {
        let key = self.storage_key(key);
        self.with_write_txn(|table| {
            let existed = table
                .remove(key.as_slice())
                .map_err(|error| LocalStorageError::Operation {
                    operation: "remove",
                    reason: error.to_string(),
                })?
                .is_some();
            Ok(existed)
        })
    }

    fn exists(&self, key: &[u8]) -> LocalStorageResult<bool> {
        self.retrieve(key).map(|opt| opt.is_some())
    }

    fn clear(&mut self) -> LocalStorageResult<()> {
        loop {
            let removed = self.clear_batch(NAMESPACE_CLEAR_BATCH_KEYS)?;
            if removed < NAMESPACE_CLEAR_BATCH_KEYS {
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{LocalStorage, LocalStorageValues, RedbLocalStorage, DATA_TABLE};
    use crate::net::mpc_engine::DurableIdentityDigest;
    use crate::storage::PersistentShareContext;
    use crate::storage::PersistentValueContext;
    use std::sync::{Arc, Barrier};
    use stoffel_vm_types::core_types::{
        ObjectStore, ShareData, ShareType, TableMemory, TableRef, Value,
    };

    #[test]
    fn redb_storage_round_trips_values() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("local.redb");
        let mut storage = RedbLocalStorage::new(&path).expect("open storage");

        assert!(!storage.exists(b"key").expect("exists"));
        assert_eq!(storage.retrieve(b"key").expect("retrieve"), None);

        storage.store(b"key", b"value").expect("store");

        assert!(storage.exists(b"key").expect("exists"));
        assert_eq!(
            storage.retrieve(b"key").expect("retrieve"),
            Some(b"value".to_vec())
        );

        storage.store(b"key", b"replacement").expect("replace");
        assert_eq!(
            storage.retrieve(b"key").expect("retrieve"),
            Some(b"replacement".to_vec())
        );

        assert!(storage.delete(b"key").expect("delete"));
        assert!(!storage.delete(b"key").expect("delete missing"));
        assert_eq!(storage.retrieve(b"key").expect("retrieve"), None);
    }

    #[test]
    fn redb_storage_reopens_existing_database() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("local.redb");

        {
            let mut storage = RedbLocalStorage::new(&path).expect("open storage");
            storage.store(b"key", b"value").expect("store");
        }

        let storage = RedbLocalStorage::new(&path).expect("reopen storage");

        assert_eq!(
            storage.retrieve(b"key").expect("retrieve"),
            Some(b"value".to_vec())
        );

        let read_txn = storage.db.begin_read().expect("begin raw read");
        let table = read_txn.open_table(DATA_TABLE).expect("open data table");
        let storage_key = storage.storage_key(b"key");
        assert_eq!(
            table
                .get(storage_key.as_slice())
                .expect("read encoded key")
                .expect("encoded key exists")
                .value(),
            b"value"
        );
    }

    #[test]
    fn redb_storage_clear_removes_all_entries() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("local.redb");
        let mut storage = RedbLocalStorage::new(&path).expect("open storage");

        storage.store(b"a", b"1").expect("store a");
        storage.store(b"b", b"2").expect("store b");
        storage.clear().expect("clear storage");

        assert_eq!(storage.retrieve(b"a").expect("retrieve a"), None);
        assert_eq!(storage.retrieve(b"b").expect("retrieve b"), None);

        drop(storage);
        let storage = RedbLocalStorage::new(&path).expect("reopen storage");
        assert_eq!(storage.retrieve(b"a").expect("retrieve a"), None);
        assert_eq!(storage.retrieve(b"b").expect("retrieve b"), None);
    }

    #[test]
    fn redb_namespaces_isolate_the_same_key_from_unscoped_data() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("local.redb");
        let mut storage = RedbLocalStorage::new(&path).expect("open storage");
        let mut first = storage.with_namespace([0xA1; 32]);
        let mut second = storage.with_namespace([0xB2; 32]);

        assert!(Arc::ptr_eq(&storage.db, &first.db));
        assert!(Arc::ptr_eq(&storage.db, &second.db));

        storage
            .store(b"state", b"unscoped")
            .expect("store unscoped");
        first.store(b"state", b"first").expect("store first");
        second.store(b"state", b"second").expect("store second");

        assert_eq!(
            storage.retrieve(b"state").expect("retrieve unscoped"),
            Some(b"unscoped".to_vec())
        );
        assert_eq!(
            first.retrieve(b"state").expect("retrieve first"),
            Some(b"first".to_vec())
        );
        assert_eq!(
            second.retrieve(b"state").expect("retrieve second"),
            Some(b"second".to_vec())
        );
    }

    #[test]
    fn redb_namespace_delete_and_clear_are_scoped() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("local.redb");
        let mut storage = RedbLocalStorage::new(&path).expect("open storage");
        let mut first = storage.with_namespace([0xA1; 32]);
        let mut second = storage.with_namespace([0xB2; 32]);

        storage
            .store(b"state", b"unscoped")
            .expect("store unscoped");
        first.store(b"state", b"first").expect("store first state");
        first.store(b"other", b"first").expect("store first other");
        second
            .store(b"state", b"second")
            .expect("store second state");
        second
            .store(b"other", b"second")
            .expect("store second other");

        assert!(first.delete(b"state").expect("delete first state"));
        assert_eq!(first.retrieve(b"state").expect("retrieve first"), None);
        assert_eq!(
            second.retrieve(b"state").expect("retrieve second"),
            Some(b"second".to_vec())
        );

        first.clear().expect("clear first namespace");
        assert_eq!(first.retrieve(b"other").expect("retrieve first"), None);
        assert_eq!(
            second.retrieve(b"other").expect("retrieve second"),
            Some(b"second".to_vec())
        );
        assert_eq!(
            storage.retrieve(b"state").expect("retrieve unscoped"),
            Some(b"unscoped".to_vec())
        );

        storage.clear().expect("clear unscoped storage");
        assert_eq!(storage.retrieve(b"state").expect("retrieve unscoped"), None);
        assert_eq!(
            second.retrieve(b"state").expect("retrieve second"),
            Some(b"second".to_vec())
        );
    }

    #[test]
    fn redb_namespace_clear_spans_bounded_transactions() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("local.redb");
        let storage = RedbLocalStorage::new(&path).expect("open storage");
        let mut target = storage.with_namespace([0xA1; 32]);
        let mut sibling = storage.with_namespace([0xB2; 32]);

        for index in 0..(super::NAMESPACE_CLEAR_BATCH_KEYS * 2 + 17) {
            target
                .store(&index.to_be_bytes(), b"scratch")
                .expect("store target scratch state");
        }
        sibling
            .store(b"state", b"preserved")
            .expect("store sibling state");

        target.clear().expect("clear target in bounded batches");
        for index in 0..(super::NAMESPACE_CLEAR_BATCH_KEYS * 2 + 17) {
            assert_eq!(
                target
                    .retrieve(&index.to_be_bytes())
                    .expect("retrieve cleared target state"),
                None
            );
        }
        assert_eq!(
            sibling.retrieve(b"state").expect("retrieve sibling"),
            Some(b"preserved".to_vec())
        );
    }

    #[test]
    fn redb_namespace_views_support_concurrent_writers() {
        const EXECUTIONS: u8 = 4;
        const KEYS_PER_EXECUTION: u8 = 16;

        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("local.redb");
        let storage = RedbLocalStorage::new(&path).expect("open storage");
        let barrier = Arc::new(Barrier::new(EXECUTIONS.into()));
        let mut workers = Vec::new();

        for execution in 0..EXECUTIONS {
            let mut view = storage.with_namespace([execution; 32]);
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                for key in 0..KEYS_PER_EXECUTION {
                    view.store(&[key], &[execution, key])
                        .expect("concurrent store");
                }
            }));
        }

        for worker in workers {
            worker.join().expect("worker thread");
        }

        for execution in 0..EXECUTIONS {
            let view = storage.with_namespace([execution; 32]);
            for key in 0..KEYS_PER_EXECUTION {
                assert_eq!(
                    view.retrieve(&[key]).expect("retrieve concurrent value"),
                    Some(vec![execution, key])
                );
            }
        }
    }

    #[test]
    fn redb_storage_round_trips_vm_values() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("local.redb");
        let mut memory = ObjectStore::new();
        let object_ref = memory.create_object_ref().expect("object");
        memory
            .set_table_field(
                TableRef::from(object_ref),
                Value::String("secret".to_owned()),
                Value::Share(
                    ShareType::secret_int(64),
                    ShareData::Feldman {
                        data: vec![1, 2, 3].into(),
                        commitments: vec![vec![4], vec![5, 6]].into(),
                    },
                ),
            )
            .expect("object field");

        {
            let mut storage = RedbLocalStorage::new(&path).expect("open storage");
            let context = PersistentValueContext::with_share_context(PersistentShareContext::new(
                "avss-mpc",
                "bls12-381",
                "bls12-381-fr",
                DurableIdentityDigest::from_legacy_party_id(0),
                5,
                1,
                b"state",
            ));
            storage
                .store_value_with_context(
                    b"state",
                    &Value::from(object_ref),
                    &mut memory,
                    Some(&context),
                )
                .expect("store value");
        }

        let storage = RedbLocalStorage::new(&path).expect("reopen storage");
        let context = PersistentValueContext::with_share_context(PersistentShareContext::new(
            "avss-mpc",
            "bls12-381",
            "bls12-381-fr",
            DurableIdentityDigest::from_legacy_party_id(0),
            5,
            1,
            b"state",
        ));
        let stored_value = storage
            .retrieve_value_with_context(b"state", &mut memory, Some(&context))
            .expect("retrieve value")
            .expect("stored value");
        let stored_object_ref = match stored_value {
            Value::Object(object_ref) => object_ref,
            other => panic!("expected object, got {other:?}"),
        };

        assert_eq!(
            memory
                .read_table_field(
                    TableRef::from(stored_object_ref),
                    &Value::String("secret".to_owned())
                )
                .expect("read decoded field"),
            Some(Value::Share(
                ShareType::secret_int(64),
                ShareData::Feldman {
                    data: vec![1, 2, 3].into(),
                    commitments: vec![vec![4], vec![5, 6]].into(),
                },
            ))
        );
    }
}
