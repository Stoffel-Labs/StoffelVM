use super::{ClientInputEntry, ClientInputIndex, ClientInputStore, ClientShare, ClientShareIndex};
use std::time::SystemTime;
use stoffelnet::network_utils::ClientId;

impl ClientInputStore {
    /// Create a new empty client input store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Store VM share payloads from a client.
    pub fn store_client_shares(&self, client_id: ClientId, shares: Vec<ClientShare>) {
        let entry = ClientInputEntry {
            client_id,
            shares,
            timestamp: SystemTime::now(),
        };

        let mut state = self.state.write();
        state.entries.insert(client_id, entry);
        match state.client_roster.binary_search(&client_id) {
            Ok(_) => {}
            Err(index) => state.client_roster.insert(index, client_id),
        }
    }

    /// Replace every stored client input with VM share payloads.
    ///
    /// The replacement happens while holding one write lock, so consumers never
    /// observe a partially cleared/repopulated store.
    pub fn replace_client_shares<I>(&self, inputs: I) -> usize
    where
        I: IntoIterator<Item = (ClientId, Vec<ClientShare>)>,
    {
        let mut total_shares = 0;
        let timestamp = SystemTime::now();
        let mut input_clients = Vec::new();
        let mut entries = std::collections::BTreeMap::new();

        for (client_id, shares) in inputs {
            total_shares += shares.len();
            input_clients.push(client_id);
            entries.insert(
                client_id,
                ClientInputEntry {
                    client_id,
                    shares,
                    timestamp,
                },
            );
        }
        let mut state = self.state.write();
        state.entries = entries;
        state.client_roster.extend(input_clients);
        state.client_roster.sort_unstable();
        state.client_roster.dedup();

        total_shares
    }

    /// Snapshot every stored client input as backend-neutral VM share payloads.
    pub fn snapshot_client_shares(&self) -> Vec<(ClientId, Vec<ClientShare>)> {
        let state = self.state.read();
        state
            .entries
            .iter()
            .map(|(&client_id, entry)| (client_id, entry.shares.clone()))
            .collect()
    }

    /// Snapshot the deterministic VM-facing client roster.
    pub fn snapshot_client_roster(&self) -> Vec<ClientId> {
        self.client_ids()
    }

    /// Store serialized share bytes from a client.
    pub fn store_client_input_bytes(&self, client_id: ClientId, share_bytes: Vec<Vec<u8>>) {
        self.store_client_shares(
            client_id,
            share_bytes
                .into_iter()
                .map(ClientShare::untyped_bytes)
                .collect(),
        );
    }

    /// Retrieve VM share payloads for a specific client.
    pub fn get_client_input_shares(&self, client_id: ClientId) -> Option<Vec<ClientShare>> {
        let state = self.state.read();
        state
            .entries
            .get(&client_id)
            .map(|entry| entry.shares.clone())
    }

    /// Retrieve a specific VM share payload for a client by index.
    pub fn get_client_share_data(
        &self,
        client_id: ClientId,
        index: ClientShareIndex,
    ) -> Option<ClientShare> {
        let state = self.state.read();
        state
            .entries
            .get(&client_id)
            .and_then(|entry| entry.shares.get(index.index()).cloned())
    }

    /// Retrieve a share by deterministic client slot and per-client share
    /// index while holding a single coherent snapshot lock.
    pub fn get_client_share_data_at(
        &self,
        client_index: ClientInputIndex,
        share_index: ClientShareIndex,
    ) -> Option<(ClientId, ClientShare)> {
        let state = self.state.read();
        let client_id = if state.client_roster.is_empty() {
            state.entries.keys().nth(client_index.index()).copied()
        } else {
            state.client_roster.get(client_index.index()).copied()
        }?;
        state
            .entries
            .get(&client_id)
            .and_then(|entry| entry.shares.get(share_index.index()).cloned())
            .map(|share| (client_id, share))
    }

    /// Snapshot one input column in deterministic client-slot order.
    ///
    /// This is the execution-oriented bulk read used by semantic share
    /// reductions. All returned payloads come from the same store snapshot.
    pub fn snapshot_share_column(
        &self,
        share_index: ClientShareIndex,
        client_count: usize,
    ) -> Option<Vec<ClientShare>> {
        let state = self.state.read();
        let ids = if state.client_roster.is_empty() {
            state.entries.keys().copied().collect::<Vec<_>>()
        } else {
            state.client_roster.clone()
        };
        let count = client_count.max(1);
        if count > ids.len() {
            return None;
        }

        ids.into_iter()
            .take(count)
            .map(|client_id| {
                state
                    .entries
                    .get(&client_id)
                    .and_then(|entry| entry.shares.get(share_index.index()).cloned())
            })
            .collect()
    }

    /// Retrieve serialized shares for a specific client.
    pub fn get_client_input_bytes(&self, client_id: ClientId) -> Option<Vec<Vec<u8>>> {
        let state = self.state.read();
        state.entries.get(&client_id).map(|entry| {
            entry
                .shares
                .iter()
                .map(|share| share.bytes().to_vec())
                .collect()
        })
    }

    /// Retrieve a specific serialized share for a client by index.
    pub fn get_client_share_bytes(
        &self,
        client_id: ClientId,
        index: ClientShareIndex,
    ) -> Option<Vec<u8>> {
        self.get_client_share_data(client_id, index)
            .map(|share| share.bytes().to_vec())
    }

    /// Check if a client has provided inputs.
    pub fn has_client_input(&self, client_id: ClientId) -> bool {
        self.state.read().entries.contains_key(&client_id)
    }

    /// Get the number of shares a client has provided.
    pub fn get_client_input_count(&self, client_id: ClientId) -> usize {
        let state = self.state.read();
        state
            .entries
            .get(&client_id)
            .map(|entry| entry.shares.len())
            .unwrap_or(0)
    }

    /// List all client IDs that have provided inputs.
    pub fn list_clients(&self) -> Vec<ClientId> {
        self.state.read().entries.keys().copied().collect()
    }

    /// Remove shares for a specific client.
    pub fn remove_client_input(&self, client_id: ClientId) -> Option<ClientInputEntry> {
        self.state.write().entries.remove(&client_id)
    }

    /// Clear all client inputs.
    pub fn clear(&self) {
        let mut state = self.state.write();
        state.entries.clear();
        state.client_roster.clear();
    }

    /// Get the total number of known clients in the store.
    pub fn len(&self) -> usize {
        let state = self.state.read();
        if state.client_roster.is_empty() {
            state.entries.len()
        } else {
            state.client_roster.len()
        }
    }

    /// Get the number of clients that have provided input material.
    pub fn input_client_count(&self) -> usize {
        self.state.read().entries.len()
    }

    /// Get the number of output-capable clients known to the VM.
    pub fn output_client_count(&self) -> usize {
        self.len()
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return the client ID at a given index in sorted order.
    pub fn client_id_at(&self, index: ClientInputIndex) -> Option<ClientId> {
        let state = self.state.read();
        if state.client_roster.is_empty() {
            state.entries.keys().nth(index.index()).copied()
        } else {
            state.client_roster.get(index.index()).copied()
        }
    }

    /// Return all client IDs in sorted order.
    pub fn client_ids(&self) -> Vec<ClientId> {
        let state = self.state.read();
        if state.client_roster.is_empty() {
            state.entries.keys().copied().collect()
        } else {
            state.client_roster.clone()
        }
    }

    /// Replace the VM-facing known client roster.
    pub fn set_client_roster<I>(&self, clients: I)
    where
        I: IntoIterator<Item = ClientId>,
    {
        let mut clients = clients.into_iter().collect::<Vec<_>>();
        clients.sort_unstable();
        clients.dedup();
        self.state.write().client_roster = clients;
    }

    /// Add one known client while preserving deterministic client-slot order.
    pub fn add_known_client(&self, client_id: ClientId) {
        let mut state = self.state.write();
        match state.client_roster.binary_search(&client_id) {
            Ok(_) => {}
            Err(index) => state.client_roster.insert(index, client_id),
        }
    }
}
