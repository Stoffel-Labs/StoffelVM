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
mod feldman;
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
    state: RwLock<ClientInputState>,
}

/// One coherent view of the client roster and its hydrated inputs.
///
/// Keeping these together is important for execution: a VM lookup by client
/// slot must not observe a roster from one hydration and shares from another.
/// It also lets the hot slot-based lookup take a single read lock.
#[derive(Debug, Default)]
struct ClientInputState {
    entries: BTreeMap<ClientId, ClientInputEntry>,
    client_roster: Vec<ClientId>,
}

#[cfg(test)]
mod tests;
