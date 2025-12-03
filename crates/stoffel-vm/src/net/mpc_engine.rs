// Abstraction for MPC engines used by the VM.
// Minimal trait needed by VMState and current HoneyBadger engine.

use crate::net::client_store::ClientInputStore;
use std::any::Any;
use stoffel_vm_types::core_types::{ShareType, Value};
use stoffelnet::network_utils::ClientId;

/// Core MPC engine trait for synchronous VM operations
///
/// This trait provides the synchronous interface used by the VM during execution.
/// Implementations handle the async/sync bridging internally (e.g., using block_in_place).
pub trait MpcEngine: Send + Sync {
    /// Get the protocol name (e.g., "honeybadger-mpc")
    fn protocol_name(&self) -> &'static str;

    /// Get the unique instance ID for this MPC session
    fn instance_id(&self) -> u64;

    /// Check if the engine is ready for MPC operations
    fn is_ready(&self) -> bool;

    /// Start the engine (may trigger preprocessing)
    fn start(&self) -> Result<(), String>;

    /// Create a secret share from a clear value
    fn input_share(&self, ty: ShareType, clear: &Value) -> Result<Vec<u8>, String>;

    /// Perform secure multiplication of two shares (requires MPC interaction)
    fn multiply_share(&self, ty: ShareType, left: &[u8], right: &[u8]) -> Result<Vec<u8>, String>;

    /// Reconstruct a secret from shares (requires collecting shares from other parties)
    /// This broadcasts to all parties - all parties learn the secret.
    fn open_share(&self, ty: ShareType, share_bytes: &[u8]) -> Result<Value, String>;

    /// Send output share(s) to a specific client for private reconstruction
    ///
    /// Unlike `open_share` which reveals to all parties, this sends this party's
    /// share to a designated client who can collect shares from all parties and
    /// reconstruct the secret privately.
    ///
    /// # Arguments
    /// * `client_id` - The ID of the client to receive the output
    /// * `shares` - The share bytes to send (serialized RobustShare(s))
    /// * `input_len` - Number of values being sent
    ///
    /// # Returns
    /// Ok(()) on success, or an error if the client is not connected or send fails
    fn send_output_to_client(
        &self,
        _client_id: ClientId,
        _shares: &[u8],
        _input_len: usize,
    ) -> Result<(), String> {
        Err("send_output_to_client not implemented for this engine".to_string())
    }

    /// Shutdown the engine
    fn shutdown(&self) {
        // Default no-op implementation
    }

    /// Get the party ID for this node
    fn party_id(&self) -> usize {
        0 // Default, implementations should override
    }

    /// Get the number of parties in the MPC network
    fn n_parties(&self) -> usize {
        1 // Default, implementations should override
    }

    /// Get the threshold parameter
    fn threshold(&self) -> usize {
        0 // Default, implementations should override
    }

    /// Support downcasting for concrete engine types
    ///
    /// This enables the VM to access implementation-specific features
    /// (like client input hydration) when available.
    fn as_any(&self) -> Option<&dyn Any> {
        None // Default: no downcasting support
    }
}

/// Async MPC engine trait for non-blocking VM execution
///
/// This trait provides async versions of the MPC operations that require
/// network communication. The VM can use these methods to avoid blocking
/// the async runtime during MPC operations.
#[async_trait::async_trait]
pub trait AsyncMpcEngine: MpcEngine {
    /// Perform secure multiplication of two shares asynchronously
    async fn multiply_share_async(
        &self,
        ty: ShareType,
        left: &[u8],
        right: &[u8],
    ) -> Result<Vec<u8>, String>;

    /// Reconstruct a secret from shares asynchronously
    async fn open_share_async(&self, ty: ShareType, share_bytes: &[u8]) -> Result<Value, String>;

    /// Send output share(s) to a specific client asynchronously
    ///
    /// This is the async version of `send_output_to_client`.
    async fn send_output_to_client_async(
        &self,
        client_id: ClientId,
        shares: &[u8],
        input_len: usize,
    ) -> Result<(), String> {
        // Default implementation uses the sync version
        self.send_output_to_client(client_id, shares, input_len)
    }
}

/// Extended MPC engine trait for client input management
///
/// This trait provides methods for managing client inputs in the MPC system.
/// Implementations that support client inputs should implement this trait.
pub trait MpcEngineClientOps: MpcEngine {
    /// Get all client IDs that have submitted inputs
    fn get_client_ids_sync(&self) -> Vec<ClientId>;

    /// Check if a specific client has submitted inputs
    fn has_client_input(&self, client_id: ClientId) -> bool {
        self.get_client_ids_sync().contains(&client_id)
    }

    /// Hydrate a ClientInputStore with all client inputs from the MPC node
    ///
    /// This synchronously copies client input shares from the MPC node's internal
    /// storage to the provided ClientInputStore.
    ///
    /// Returns the number of clients whose inputs were hydrated.
    fn hydrate_client_inputs_sync(&self, store: &ClientInputStore) -> Result<usize, String>;

    /// Hydrate a ClientInputStore with inputs from specific clients
    fn hydrate_client_inputs_for_sync(
        &self,
        store: &ClientInputStore,
        client_ids: &[ClientId],
    ) -> Result<usize, String>;
}
