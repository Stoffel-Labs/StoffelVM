//! Storage interfaces for local and replicated data.

pub mod local;
pub mod replicated;

// Re-export key traits/structs
pub use local::LocalStorage;
pub use replicated::ReplicatedStorage;
