//! Interface for persistent storage local to a single server/peer using redb.

use redb::{Database, Error as RedbError, TableDefinition};
use std::path::Path;
use std::sync::Arc;

/// Trait defining operations for local data persistence.
pub trait LocalStorage: Send + Sync {
    /// Stores data associated with a key. Overwrites if the key exists.
    fn store(&mut self, key: &[u8], value: &[u8]) -> Result<(), String>;

    /// Retrieves data associated with a key.
    fn retrieve(&self, key: &[u8]) -> Result<Option<Vec<u8>>, String>;

    /// Deletes data associated with a key.
    fn delete(&mut self, key: &[u8]) -> Result<bool, String>; // Returns true if deleted

    /// Checks if a key exists.
    fn exists(&self, key: &[u8]) -> Result<bool, String>;
}

// Define the table for storing key-value pairs
const DATA_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("data_kv_store");

/// Implementation of LocalStorage using the redb library.
pub struct RedbLocalStorage {
    db: Arc<Database>, // Use Arc for potential sharing across threads if needed later
}

impl RedbLocalStorage {
    /// Creates or opens a redb database at the specified path.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let db = Database::create(path).map_err(|e| format!("Failed to create/open redb database: {}", e))?;

        // Ensure the table exists (optional, but good practice)
        let write_txn = db.begin_write().map_err(|e| format!("Failed to begin write transaction: {}", e))?;
        {
            // Scope for the open_table call
           let _ = write_txn.open_table(DATA_TABLE).map_err(|e| format!("Failed to open table: {}", e))?;
        } // table handle is dropped here
        write_txn.commit().map_err(|e| format!("Failed to commit initial transaction: {}", e))?;

        Ok(RedbLocalStorage { db: Arc::new(db) })
    }

    // Helper to handle transaction and table opening for writes
    fn with_write_txn<F, R>(&mut self, operation: F) -> Result<R, String>
    where
        F: FnOnce(&mut redb::Table<&[u8], &[u8]>) -> Result<R, RedbError>,
    {
        let write_txn = self.db.begin_write().map_err(|e| format!("Failed to begin write transaction: {}", e))?;
        let result = {
             let mut table = write_txn.open_table(DATA_TABLE).map_err(|e| format!("Failed to open table for write: {}", e))?;
             operation(&mut table).map_err(|e| format!("Operation failed: {}", e))
        }; // table handle dropped here

        if result.is_ok() {
            write_txn.commit().map_err(|e| format!("Failed to commit transaction: {}", e))?;
        } else {
             // No need to explicitly abort, dropping does it, but good for clarity
             // write_txn.abort().map_err(|e| format!("Failed to abort transaction: {}", e))?;
        }
        result
    }
}

impl LocalStorage for RedbLocalStorage {
    fn store(&mut self, key: &[u8], value: &[u8]) -> Result<(), String> {
        self.with_write_txn(|table| {
            table.insert(key, value)?;
            Ok(())
        })
    }

    fn retrieve(&self, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let read_txn = self.db.begin_read().map_err(|e| format!("Failed to begin read transaction: {}", e))?;
        let table = read_txn.open_table(DATA_TABLE).map_err(|e| format!("Failed to open table for read: {}", e))?;

        match table.get(key).map_err(|e| format!("Failed to retrieve key: {}", e))? {
            Some(value) => Ok(Some(value.value().to_vec())),
            None => Ok(None),
        }
    }

    fn delete(&mut self, key: &[u8]) -> Result<bool, String> {
        self.with_write_txn(|table| {
            let existed = table.remove(key)?.is_some();
            Ok(existed)
        })
    }

    fn exists(&self, key: &[u8]) -> Result<bool, String> {
        // exists can be implemented more efficiently by checking get result
        self.retrieve(key).map(|opt| opt.is_some())
    }
}

// Example default implementation using a fixed file name
// Note: In a real application, the path should be configurable.
impl Default for RedbLocalStorage {
    fn default() -> Self {
        // Using Mutex guard for the potentially fallible operation
        // This isn't ideal for a Default implementation, better to have a dedicated constructor.
        // For demonstration purposes:
        RedbLocalStorage::new("local_storage.redb").expect("Failed to create default redb storage")
    }
}
