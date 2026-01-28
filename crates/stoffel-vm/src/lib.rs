//! StoffelVM - Virtual Machine for the Stoffel programming language
//!
//! ## Features
//!
//! - `mpc` (default) - Full MPC networking support with HoneyBadger protocol
//! - `wasm` - WebAssembly bindings for browser/Node.js usage (sync-only, no MPC)
//!
//! When building for WASM, use `--no-default-features --features wasm` to exclude
//! the networking dependencies.

pub mod core_vm;
pub mod foreign_functions;
pub mod mutex_helpers;
pub mod runtime_hooks;
pub mod storage;
pub mod vm_function_helper;
pub mod vm_state;

// MPC networking module - only available when 'mpc' feature is enabled
#[cfg(feature = "mpc")]
pub mod net;

// C FFI module - only available when 'mpc' feature is enabled (uses tokio runtime)
#[cfg(feature = "mpc")]
pub mod cffi;

// WASM bindings module - only available when 'wasm' feature is enabled
#[cfg(feature = "wasm")]
pub mod wasm;

// Tests require MPC feature
#[cfg(all(test, feature = "mpc"))]
mod tests;
