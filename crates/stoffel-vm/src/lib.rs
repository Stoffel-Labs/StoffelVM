pub mod core_vm;
pub mod foreign_functions;
pub mod mutex_helpers;
pub mod net;
pub mod runtime_hooks;
pub mod storage;
#[cfg(test)]
mod tests;
pub mod vm_function_helper;
pub mod vm_state;

// Re-export types from stoffel_vm_types for convenient API
pub use stoffel_vm_types::{core_types, functions, instructions};
