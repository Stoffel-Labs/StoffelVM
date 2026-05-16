//! Storage interfaces for local and replicated data.

pub mod local;
pub mod preproc;
pub mod replicated;

// Re-export key traits/structs
pub use local::{LocalStorage, LocalStorageError, LocalStorageResult, RedbLocalStorage};
pub use preproc::{
    LmdbPreprocStore, MaterialKind, PreprocBlob, PreprocKey, PreprocMeta, PreprocStore,
    PreprocStoreError,
};
pub use replicated::{
    BasicReplicatedStorage, ReplicatedStorage, ReplicatedStorageError, ReplicatedStorageFuture,
    ReplicatedStorageResult,
};
