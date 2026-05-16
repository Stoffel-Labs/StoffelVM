//! Interface for persistent storage local to a single server/peer using redb.

use redb::{Database, TableDefinition};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub type LocalStorageResult<T> = Result<T, LocalStorageError>;

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
}

// Define the table for storing key-value pairs
const DATA_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("data_kv_store");

/// Implementation of LocalStorage using the redb library.
pub struct RedbLocalStorage {
    db: Arc<Database>,
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

        Ok(RedbLocalStorage { db: Arc::new(db) })
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
        self.with_write_txn(|table| {
            table
                .insert(key, value)
                .map_err(|error| LocalStorageError::Operation {
                    operation: "insert",
                    reason: error.to_string(),
                })?;
            Ok(())
        })
    }

    fn retrieve(&self, key: &[u8]) -> LocalStorageResult<Option<Vec<u8>>> {
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
            .get(key)
            .map_err(|error| LocalStorageError::Operation {
                operation: "get",
                reason: error.to_string(),
            })? {
            Some(value) => Ok(Some(value.value().to_vec())),
            None => Ok(None),
        }
    }

    fn delete(&mut self, key: &[u8]) -> LocalStorageResult<bool> {
        self.with_write_txn(|table| {
            let existed = table
                .remove(key)
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
}

#[cfg(test)]
mod tests {
    use super::{LocalStorage, RedbLocalStorage};

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
    }
}
