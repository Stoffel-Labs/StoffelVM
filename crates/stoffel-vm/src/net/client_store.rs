//! Global store for client secret shares.
//!
//! This module provides a thread-safe global store where MPC nodes can store
//! client input shares received from clients. VMs can then retrieve these
//! shares to execute programs that require secret inputs.

use parking_lot::RwLock;
use std::collections::BTreeMap;
use stoffelnet::network_utils::ClientId;

mod core;
mod error;
#[cfg(feature = "avss")]
mod feldman;
#[cfg(feature = "honeybadger")]
mod robust;
mod share;

pub use error::ClientInputStoreError;
pub use share::{
    ClientInputEntry, ClientInputHydrationCount, ClientInputIndex, ClientOutputShareCount,
    ClientOutputShareCountError, ClientShare, ClientShareIndex,
};

/// Global store for client secret shares.
///
/// This store is shared across all VM nodes in the same process and provides
/// thread-safe access to client input shares.
#[derive(Debug, Default)]
pub struct ClientInputStore {
    entries: RwLock<BTreeMap<ClientId, ClientInputEntry>>,
}

#[cfg(test)]
mod tests;
