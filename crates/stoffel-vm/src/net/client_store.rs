//! Global store for client secret shares
//!
//! This module provides a thread-safe global store where MPC nodes can store
//! client input shares received from clients. VMs can then retrieve these
//! shares to execute programs that require secret inputs.

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use parking_lot::RwLock;
use std::collections::BTreeMap;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelnet::network_utils::ClientId;

/// A single entry in the client store, representing all shares from one client
#[derive(Debug, Clone)]
pub struct ClientInputEntry {
    /// The client's ID
    pub client_id: ClientId,
    /// Serialized RobustShare bytes provided by this client (indexed by input position)
    pub share_bytes: Vec<Vec<u8>>,
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
    entries: RwLock<BTreeMap<ClientId, ClientInputEntry>>,
}

impl ClientInputStore {
    /// Create a new empty client input store
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(BTreeMap::new()),
        }
    }

    /// Store serialized share bytes from a client.
    pub fn store_client_input_bytes(&self, client_id: ClientId, share_bytes: Vec<Vec<u8>>) {
        let entry = ClientInputEntry {
            client_id,
            share_bytes,
            timestamp: std::time::SystemTime::now(),
        };

        let mut entries = self.entries.write();
        entries.insert(client_id, entry);
    }

    /// Store typed robust shares from a client.
    pub fn store_client_input<F>(&self, client_id: ClientId, shares: Vec<RobustShare<F>>)
    where
        F: ark_ff::FftField,
    {
        let mut serialized = Vec::with_capacity(shares.len());
        for share in shares {
            let mut bytes = Vec::new();
            if share.serialize_compressed(&mut bytes).is_ok() {
                serialized.push(bytes);
            }
        }
        self.store_client_input_bytes(client_id, serialized);
    }

    /// Retrieve serialized shares for a specific client.
    pub fn get_client_input_bytes(&self, client_id: ClientId) -> Option<Vec<Vec<u8>>> {
        let entries = self.entries.read();
        entries.get(&client_id).map(|entry| entry.share_bytes.clone())
    }

    /// Retrieve a specific serialized share for a client by index.
    pub fn get_client_share_bytes(&self, client_id: ClientId, index: usize) -> Option<Vec<u8>> {
        let entries = self.entries.read();
        entries
            .get(&client_id)
            .and_then(|entry| entry.share_bytes.get(index).cloned())
    }

    /// Retrieve typed shares for a specific client.
    pub fn get_client_input<F>(&self, client_id: ClientId) -> Option<Vec<RobustShare<F>>>
    where
        F: ark_ff::FftField,
    {
        let share_bytes = self.get_client_input_bytes(client_id)?;
        let mut shares = Vec::with_capacity(share_bytes.len());
        for bytes in share_bytes {
            match RobustShare::<F>::deserialize_compressed(bytes.as_slice()) {
                Ok(share) => shares.push(share),
                Err(_) => return None,
            }
        }
        Some(shares)
    }

    /// Retrieve a specific typed share for a client by index.
    pub fn get_client_share<F>(&self, client_id: ClientId, index: usize) -> Option<RobustShare<F>>
    where
        F: ark_ff::FftField,
    {
        let bytes = self.get_client_share_bytes(client_id, index)?;
        RobustShare::<F>::deserialize_compressed(bytes.as_slice()).ok()
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
            .map(|entry| entry.share_bytes.len())
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

    /// Return the client ID at a given index (sorted order).
    pub fn client_id_at(&self, index: usize) -> Option<ClientId> {
        let entries = self.entries.read();
        entries.keys().nth(index).copied()
    }

    /// Return all client IDs in sorted order.
    pub fn client_ids(&self) -> Vec<ClientId> {
        let entries = self.entries.read();
        entries.keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
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

        let retrieved: Vec<RobustShare<Fr>> = store.get_client_input(client_id).unwrap();
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
        let share_1: RobustShare<Fr> = store.get_client_share(client_id, 1).unwrap();
        assert_eq!(share_1.share, shares[1].share);
    }

    #[test]
    fn test_list_and_clear() {
        let store = ClientInputStore::new();

        store.store_client_input_bytes(1, vec![]);
        store.store_client_input_bytes(2, vec![]);
        store.store_client_input_bytes(3, vec![]);

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
