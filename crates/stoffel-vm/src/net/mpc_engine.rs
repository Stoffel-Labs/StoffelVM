// Abstraction for MPC engines used by the VM.
// Minimal trait needed by VMState and current HoneyBadger engine.

use crate::net::client_store::ClientInputStore;
use crate::net::curve::{MpcCurveConfig, MpcFieldKind};
use crate::net::reservation::ReservationGrant;
use crate::storage::preproc::PreprocStore;
use std::any::Any;
use std::sync::Arc;
use stoffel_vm_types::core_types::{ShareData, ShareType, Value};
use stoffelnet::network_utils::ClientId;

bitflags::bitflags! {
    /// Capability flags advertised by an [`MpcEngine`] implementation.
    ///
    /// Engines return these from [`MpcEngine::capabilities()`]. The individual
    /// `supports_*()` convenience methods delegate to this bitfield.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MpcCapabilities: u32 {
        const MULTIPLICATION   = 0b0000_0001;
        const ELLIPTIC_CURVES  = 0b0000_0010;
        const CLIENT_INPUT     = 0b0000_0100;
        const CONSENSUS        = 0b0000_1000;
        const OPEN_IN_EXP      = 0b0001_0000;
        const RESERVATION      = 0b0010_0000;
    }
}

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
    fn input_share(&self, ty: ShareType, clear: &Value) -> Result<ShareData, String>;

    /// Perform secure multiplication of two shares (requires MPC interaction)
    fn multiply_share(&self, ty: ShareType, left: &[u8], right: &[u8]) -> Result<ShareData, String>;

    /// Reconstruct a secret from shares (requires collecting shares from other parties)
    /// This broadcasts to all parties - all parties learn the secret.
    fn open_share(&self, ty: ShareType, share_bytes: &[u8]) -> Result<Value, String>;

    /// Batch reconstruct multiple secrets at once (more efficient than individual open_share calls)
    ///
    /// This method reveals multiple secrets in batches, reducing network rounds.
    /// The batch size is typically `t+1` where `t` is the threshold parameter.
    ///
    /// # Arguments
    /// * `ty` - The share type (must be the same for all shares)
    /// * `shares` - Vector of serialized shares to reveal
    ///
    /// # Returns
    /// Vector of revealed values in the same order as input shares
    fn batch_open_shares(&self, ty: ShareType, shares: &[Vec<u8>]) -> Result<Vec<Value>, String> {
        // Default implementation: sequential fallback
        shares.iter().map(|s| self.open_share(ty, s)).collect()
    }

    /// Generate random bytes as a secret-shared value.
    ///
    /// The engine uses its preprocessing pool (e.g. RanSha protocol) to produce
    /// jointly-random shares that no single party knows.
    fn random_share(&self, _ty: ShareType) -> Result<ShareData, String> {
        Err("random_share not implemented for this engine".to_string())
    }

    /// Reveal a share in the exponent: reconstructs `[secret] * generator`
    /// via Lagrange interpolation in the group.
    ///
    /// Each party computes `share_i * generator`, then all parties exchange
    /// partial points and reconstruct the public point.
    fn open_share_in_exp(
        &self,
        _ty: ShareType,
        _share_bytes: &[u8],
        _generator_bytes: &[u8],
    ) -> Result<Vec<u8>, String> {
        Err("open_share_in_exp not implemented for this engine".to_string())
    }

    /// Reconstruct a secret from shares and return the raw field element bytes
    /// instead of converting to a VM `Value`.
    ///
    /// This is used by `Share.open_field` to get the serialized field element
    /// for cryptographic operations (e.g. threshold signatures).
    fn open_share_as_field(
        &self,
        _ty: ShareType,
        _share_bytes: &[u8],
    ) -> Result<Vec<u8>, String> {
        Err("open_share_as_field not implemented for this engine".to_string())
    }

    /// Whether this engine supports `open_share_in_exp`.
    fn supports_open_share_in_exp(&self) -> bool {
        self.capabilities().contains(MpcCapabilities::OPEN_IN_EXP)
    }

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
    fn party_id(&self) -> usize;

    /// Get the number of parties in the MPC network
    fn n_parties(&self) -> usize;

    /// Get the threshold parameter
    fn threshold(&self) -> usize;

    /// MPC curve in use by this engine.
    fn curve_config(&self) -> MpcCurveConfig {
        MpcCurveConfig::default()
    }

    /// Share field used by this engine.
    fn field_kind(&self) -> MpcFieldKind {
        self.curve_config().field_kind()
    }

    /// Advertise which optional operations this engine supports.
    ///
    /// The default is empty (no optional capabilities). Implementations should
    /// override this to set the appropriate flags.
    fn capabilities(&self) -> MpcCapabilities {
        MpcCapabilities::empty()
    }

    /// Whether this engine supports secure multiplication
    fn supports_multiplication(&self) -> bool {
        self.capabilities()
            .contains(MpcCapabilities::MULTIPLICATION)
    }

    /// Whether this engine supports elliptic curve operations
    fn supports_elliptic_curves(&self) -> bool {
        self.capabilities()
            .contains(MpcCapabilities::ELLIPTIC_CURVES)
    }

    /// Whether this engine supports client input operations
    fn supports_client_input(&self) -> bool {
        self.capabilities().contains(MpcCapabilities::CLIENT_INPUT)
    }

    /// Whether this engine supports consensus (RBC/ABA)
    fn supports_consensus(&self) -> bool {
        self.capabilities().contains(MpcCapabilities::CONSENSUS)
    }

    /// Try to obtain a reference to the consensus sub-trait, if supported.
    fn as_consensus(&self) -> Option<&dyn MpcEngineConsensus> {
        None
    }

    /// Try to obtain a reference to the client-ops sub-trait, if supported.
    fn as_client_ops(&self) -> Option<&dyn MpcEngineClientOps> {
        None
    }

    /// Try to obtain a reference to the reservation sub-trait, if supported.
    fn as_reservation(&self) -> Option<&dyn MpcEngineReservation> {
        None
    }

    /// Whether this engine supports preprocessing reservation
    fn supports_reservation(&self) -> bool {
        self.capabilities().contains(MpcCapabilities::RESERVATION)
    }

    /// Attach persistent storage for preprocessing material caching.
    /// Called before `start()`. Engines that support persistence will
    /// use this store to load/save preprocessing material.
    fn set_preproc_store(&self, _store: Arc<dyn PreprocStore>, _program_hash: [u8; 32]) {
        // Default: no-op
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
    ) -> Result<ShareData, String>;

    /// Reconstruct a secret from shares asynchronously
    async fn open_share_async(&self, ty: ShareType, share_bytes: &[u8]) -> Result<Value, String>;

    /// Batch reconstruct multiple secrets asynchronously
    ///
    /// This is the async version of `batch_open_shares`.
    async fn batch_open_shares_async(
        &self,
        ty: ShareType,
        shares: &[Vec<u8>],
    ) -> Result<Vec<Value>, String> {
        // Default implementation uses the sync version
        self.batch_open_shares(ty, shares)
    }

    /// Generate random bytes as a secret-shared value (async).
    async fn random_share_async(&self, ty: ShareType) -> Result<ShareData, String> {
        self.random_share(ty)
    }

    /// Reveal a share in the exponent asynchronously.
    async fn open_share_in_exp_async(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
        generator_bytes: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.open_share_in_exp(ty, share_bytes, generator_bytes)
    }

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

/// Extended MPC engine trait for consensus protocols (RBC and ABA)
///
/// This trait provides methods for Reliable Broadcast (RBC) and
/// Asynchronous Binary Agreement (ABA) primitives.
///
/// RBC (Reliable Broadcast) ensures that:
/// - If the broadcaster is honest, all honest parties deliver the same message
/// - If any honest party delivers a message, all honest parties eventually deliver it
///
/// ABA (Asynchronous Binary Agreement) ensures that:
/// - All honest parties eventually decide on the same binary value
/// - If all honest parties propose the same value, that value is decided
pub trait MpcEngineConsensus: MpcEngine {
    /// Broadcast a message reliably to all parties using RBC
    ///
    /// # Arguments
    /// * `message` - The message to broadcast
    ///
    /// # Returns
    /// A session ID that can be used to track this broadcast
    fn rbc_broadcast(&self, message: &[u8]) -> Result<u64, String>;

    /// Receive a reliable broadcast from a specific party
    ///
    /// # Arguments
    /// * `from_party` - The party ID of the sender
    /// * `timeout_ms` - Maximum time to wait in milliseconds
    ///
    /// # Returns
    /// The broadcasted message bytes
    fn rbc_receive(&self, from_party: usize, timeout_ms: u64) -> Result<Vec<u8>, String>;

    /// Receive a reliable broadcast from any party
    ///
    /// # Arguments
    /// * `timeout_ms` - Maximum time to wait in milliseconds
    ///
    /// # Returns
    /// A tuple of (party_id, message_bytes)
    fn rbc_receive_any(&self, timeout_ms: u64) -> Result<(usize, Vec<u8>), String>;

    /// Propose a binary value for Asynchronous Binary Agreement
    ///
    /// # Arguments
    /// * `value` - The binary value (true/false) to propose
    ///
    /// # Returns
    /// A session ID for this ABA instance
    fn aba_propose(&self, value: bool) -> Result<u64, String>;

    /// Get the agreed-upon result for an ABA session
    ///
    /// # Arguments
    /// * `session_id` - The session ID from aba_propose
    /// * `timeout_ms` - Maximum time to wait in milliseconds
    ///
    /// # Returns
    /// The agreed-upon binary value
    fn aba_result(&self, session_id: u64, timeout_ms: u64) -> Result<bool, String>;

    /// Propose a value and wait for agreement (convenience method)
    ///
    /// # Arguments
    /// * `value` - The binary value to propose
    /// * `timeout_ms` - Maximum time to wait in milliseconds
    ///
    /// # Returns
    /// The agreed-upon binary value
    fn aba_propose_and_wait(&self, value: bool, timeout_ms: u64) -> Result<bool, String> {
        let session_id = self.aba_propose(value)?;
        self.aba_result(session_id, timeout_ms)
    }
}

/// Async version of MpcEngineConsensus
#[async_trait::async_trait]
pub trait AsyncMpcEngineConsensus: MpcEngineConsensus {
    /// Broadcast a message reliably to all parties (async)
    async fn rbc_broadcast_async(&self, message: &[u8]) -> Result<u64, String>;

    /// Receive a reliable broadcast from a specific party (async)
    async fn rbc_receive_async(
        &self,
        from_party: usize,
        timeout_ms: u64,
    ) -> Result<Vec<u8>, String>;

    /// Receive a reliable broadcast from any party (async)
    async fn rbc_receive_any_async(&self, timeout_ms: u64) -> Result<(usize, Vec<u8>), String>;

    /// Propose a binary value for ABA (async)
    async fn aba_propose_async(&self, value: bool) -> Result<u64, String>;

    /// Get the agreed-upon result for an ABA session (async)
    async fn aba_result_async(&self, session_id: u64, timeout_ms: u64) -> Result<bool, String>;

    /// Propose and wait for agreement (async)
    async fn aba_propose_and_wait_async(
        &self,
        value: bool,
        timeout_ms: u64,
    ) -> Result<bool, String> {
        let session_id = self.aba_propose_async(value).await?;
        self.aba_result_async(session_id, timeout_ms).await
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

/// Extended MPC engine trait for preprocessing reservation.
///
/// Engines that support persistent preprocessing and the masked-input
/// protocol implement this trait. The reservation lifecycle:
///
/// 1. `init_reservations` — set up or restore reservation state
/// 2. `reserve_masks` — clients reserve index ranges
/// 3. `get_mask_share` — clients collect per-node mask shares
/// 4. `submit_masked_input` — clients submit `input + mask`
/// 5. `consume_masked_inputs` — nodes compute `masked_input − mask_share`
#[async_trait::async_trait]
pub trait MpcEngineReservation: MpcEngine {
    /// Initialize or restore reservation state for a program.
    async fn init_reservations(
        &self,
        program_hash: [u8; 32],
        capacity: u64,
    ) -> Result<(), String>;

    /// Reserve `n` consecutive mask indices for a client.
    async fn reserve_masks(
        &self,
        client_id: ClientId,
        n: u64,
    ) -> Result<ReservationGrant, String>;

    /// Get this node's mask share at a given index (serialized bytes).
    async fn get_mask_share(&self, index: u64) -> Result<Vec<u8>, String>;

    /// Accept a masked input at a reserved index.
    async fn submit_masked_input(
        &self,
        client_id: ClientId,
        index: u64,
        value: Vec<u8>,
    ) -> Result<(), String>;

    /// Compute `input_share = masked_input − mask_share` for each index.
    /// Marks the indices as consumed.
    async fn consume_masked_inputs(
        &self,
        indices: &[u64],
    ) -> Result<Vec<(u64, Vec<u8>)>, String>;

    /// Number of unreserved mask slots.
    async fn available_masks(&self) -> u64;

    /// Persist the current reservation state.
    async fn persist_reservations(&self) -> Result<(), String>;
}
