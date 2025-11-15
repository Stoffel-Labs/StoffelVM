//! Global store for client secret shares
//!
//! This module provides a thread-safe global store where MPC nodes can store
//! client input shares received from clients. VMs can then retrieve these
//! shares to execute programs that require secret inputs.

use ark_bls12_381::Fr;
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelnet::network_utils::ClientId;

/// A single entry in the client store, representing all shares from one client
#[derive(Debug, Clone)]
pub struct ClientInputEntry {
    /// The client's ID
    pub client_id: ClientId,
    /// The shares provided by this client (indexed by input position)
    pub shares: Vec<RobustShare<Fr>>,
    /// Timestamp when the shares were stored
    pub timestamp: std::time::SystemTime,
}

/// Global store for client secret shares
///
/// This store is shared across all VM nodes in the same process and provides
/// thread-safe access to client input shares.
#[derive(Debug, Default)]
pub struct ClientInputStore {
    /// Map from client ID to their input shares
    entries: RwLock<HashMap<ClientId, ClientInputEntry>>,
}

impl ClientInputStore {
    /// Create a new empty client input store
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Store shares from a client
    ///
    /// # Arguments
    /// * `client_id` - The ID of the client providing inputs
    /// * `shares` - The secret shares from this client
    pub fn store_client_input(&self, client_id: ClientId, shares: Vec<RobustShare<Fr>>) {
        let entry = ClientInputEntry {
            client_id,
            shares,
            timestamp: std::time::SystemTime::now(),
        };

        let mut entries = self.entries.write();
        entries.insert(client_id, entry);
    }

    /// Retrieve shares for a specific client
    ///
    /// # Arguments
    /// * `client_id` - The ID of the client
    ///
    /// # Returns
    /// `Some(shares)` if the client has provided inputs, `None` otherwise
    pub fn get_client_input(&self, client_id: ClientId) -> Option<Vec<RobustShare<Fr>>> {
        let entries = self.entries.read();
        entries.get(&client_id).map(|entry| entry.shares.clone())
    }

    /// Retrieve a specific share for a client by index
    ///
    /// # Arguments
    /// * `client_id` - The ID of the client
    /// * `index` - The index of the share (0-based)
    ///
    /// # Returns
    /// `Some(share)` if found, `None` otherwise
    pub fn get_client_share(&self, client_id: ClientId, index: usize) -> Option<RobustShare<Fr>> {
        let entries = self.entries.read();
        entries
            .get(&client_id)
            .and_then(|entry| entry.shares.get(index).cloned())
    }

    /// Check if a client has provided inputs
    pub fn has_client_input(&self, client_id: ClientId) -> bool {
        let entries = self.entries.read();
        entries.contains_key(&client_id)
    }

    /// Get the number of shares a client has provided
    pub fn get_client_input_count(&self, client_id: ClientId) -> usize {
        let entries = self.entries.read();
        entries
            .get(&client_id)
            .map(|entry| entry.shares.len())
            .unwrap_or(0)
    }

    /// List all client IDs that have provided inputs
    pub fn list_clients(&self) -> Vec<ClientId> {
        let entries = self.entries.read();
        entries.keys().copied().collect()
    }

    /// Remove shares for a specific client
    pub fn remove_client_input(&self, client_id: ClientId) -> Option<ClientInputEntry> {
        let mut entries = self.entries.write();
        entries.remove(&client_id)
    }

    /// Clear all client inputs
    pub fn clear(&self) {
        let mut entries = self.entries.write();
        entries.clear();
    }

    /// Get the total number of clients in the store
    pub fn len(&self) -> usize {
        let entries = self.entries.read();
        entries.len()
    }

    /// Check if the store is empty
    pub fn is_empty(&self) -> bool {
        let entries = self.entries.read();
        entries.is_empty()
    }
}

/// Global singleton instance of the client input store
pub static GLOBAL_CLIENT_STORE: Lazy<Arc<ClientInputStore>> =
    Lazy::new(|| Arc::new(ClientInputStore::new()));

/// Get a reference to the global client input store
pub fn get_global_store() -> Arc<ClientInputStore> {
    GLOBAL_CLIENT_STORE.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::PrimeField;
    use stoffelmpc_mpc::common::SecretSharingScheme;

    #[test]
    fn test_store_and_retrieve() {
        let store = ClientInputStore::new();
        let client_id = 42;

        // Generate some test shares
        let secret = Fr::from(100u64);
        let mut rng = ark_std::test_rng();
        let shares = RobustShare::compute_shares(secret, 5, 1, None, &mut rng).unwrap();

        // Store the shares
        store.store_client_input(client_id, shares.clone());

        // Retrieve and verify
        assert!(store.has_client_input(client_id));
        assert_eq!(store.get_client_input_count(client_id), shares.len());

        let retrieved = store.get_client_input(client_id).unwrap();
        assert_eq!(retrieved.len(), shares.len());
    }

    #[test]
    fn test_get_specific_share() {
        let store = ClientInputStore::new();
        let client_id = 99;

        let secret = Fr::from(200u64);
        let mut rng = ark_std::test_rng();
        let shares = RobustShare::compute_shares(secret, 3, 1, None, &mut rng).unwrap();

        store.store_client_input(client_id, shares.clone());

        // Get specific share
        let share_1 = store.get_client_share(client_id, 1).unwrap();
        assert_eq!(share_1.share, shares[1].share);
    }

    #[test]
    fn test_list_and_clear() {
        let store = ClientInputStore::new();

        store.store_client_input(1, vec![]);
        store.store_client_input(2, vec![]);
        store.store_client_input(3, vec![]);

        assert_eq!(store.len(), 3);
        let clients = store.list_clients();
        assert!(clients.contains(&1));
        assert!(clients.contains(&2));
        assert!(clients.contains(&3));

        store.clear();
        assert_eq!(store.len(), 0);
        assert!(store.is_empty());
    }
}
