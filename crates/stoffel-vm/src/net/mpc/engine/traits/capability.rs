use super::super::{MpcEngineError, MpcEngineResult, MpcExponentGroup};
use super::core::MpcEngine;
use crate::net::client_store::{
    ClientInputHydrationCount, ClientInputStore, ClientOutputShareCount,
};
use crate::net::reservation::ReservationGrant;
use crate::storage::preproc::PreprocStore;
use std::sync::Arc;
use stoffel_vm_types::core_types::{ShareData, ShareType};
use stoffelnet::network_utils::ClientId;

/// Extended MPC engine trait for interactive share multiplication.
///
/// Multiplication consumes preprocessing material and/or network interaction in
/// most MPC protocols, so backends expose it as an explicit capability instead
/// of forcing field-only or input-only engines to carry placeholder methods.
pub trait MpcEngineMultiplication: MpcEngine {
    /// Perform secure multiplication of two shares.
    fn multiply_share(
        &self,
        ty: ShareType,
        left: &[u8],
        right: &[u8],
    ) -> MpcEngineResult<ShareData>;
}

/// Extended MPC engine trait for client input management.
pub trait MpcEngineClientOps: MpcEngine {
    /// Get all client IDs that have submitted inputs.
    fn get_client_ids_sync(&self) -> Vec<ClientId>;

    /// Check if a specific client has submitted inputs.
    fn has_client_input(&self, client_id: ClientId) -> bool {
        self.get_client_ids_sync().contains(&client_id)
    }

    /// Hydrate a `ClientInputStore` with all client inputs from the MPC node.
    ///
    /// Returns the number of clients whose inputs were hydrated.
    fn hydrate_client_inputs_sync(
        &self,
        store: &ClientInputStore,
    ) -> MpcEngineResult<ClientInputHydrationCount>;

    /// Hydrate a `ClientInputStore` with inputs from specific clients.
    fn hydrate_client_inputs_for_sync(
        &self,
        store: &ClientInputStore,
        client_ids: &[ClientId],
    ) -> MpcEngineResult<ClientInputHydrationCount>;
}

/// Extended MPC engine trait for opening shares in an exponent group.
///
/// Backends that implement this capability can expose public group elements
/// derived from secret shares without revealing the scalar itself. Keeping this
/// separate from [`MpcEngine`] lets field-only engines remain small while AVSS
/// or curve-aware backends provide richer threshold-crypto operations.
pub trait MpcEngineOpenInExponent: MpcEngine {
    /// Reveal a share in the exponent: reconstruct `[secret] * generator`.
    fn open_share_in_exp(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
        generator_bytes: &[u8],
    ) -> MpcEngineResult<Vec<u8>>;

    /// Native exponent group handled by [`MpcEngineOpenInExponent::open_share_in_exp`].
    fn native_exponent_group(&self) -> MpcExponentGroup {
        MpcExponentGroup::native_for_curve(self.curve_config())
    }

    /// Whether this engine can open shares into the requested exponent group.
    fn supports_exponent_group(&self, group: MpcExponentGroup) -> bool {
        self.native_exponent_group() == group
    }

    /// Reveal a share in the exponent for a named group.
    ///
    /// Most engines support exactly their native curve/group and can rely on
    /// this default. Engines that support additional groups can override
    /// [`MpcEngineOpenInExponent::supports_exponent_group`] and this method
    /// without requiring VM builtins to downcast to concrete engine types.
    fn open_share_in_exp_group(
        &self,
        group: MpcExponentGroup,
        ty: ShareType,
        share_bytes: &[u8],
        generator_bytes: &[u8],
    ) -> MpcEngineResult<Vec<u8>> {
        if !self.supports_exponent_group(group) {
            return Err(MpcEngineError::operation_failed(
                "open_share_in_exp_group",
                group.unsupported_error(self.protocol_name()),
            ));
        }

        self.open_share_in_exp(ty, share_bytes, generator_bytes)
    }
}

/// Extended MPC engine trait for jointly-random share generation.
///
/// This backs VM operations like `Share.random`, where the resulting secret is
/// shared among parties and no individual party knows the clear value.
pub trait MpcEngineRandomness: MpcEngine {
    /// Generate a secret-shared random value of the requested share type.
    fn random_share(&self, ty: ShareType) -> MpcEngineResult<ShareData>;
}

/// Extended MPC engine trait for opening shares as raw field elements.
///
/// This capability backs `Share.open_field`, which is used by threshold
/// cryptography code that needs the canonical field encoding rather than a VM
/// scalar conversion.
pub trait MpcEngineFieldOpen: MpcEngine {
    /// Reconstruct a secret from shares and return the raw field element bytes.
    fn open_share_as_field(&self, ty: ShareType, share_bytes: &[u8]) -> MpcEngineResult<Vec<u8>>;
}

/// Extended MPC engine trait for persistent preprocessing material.
///
/// Engines that implement this capability can load or save expensive
/// preprocessing artifacts under a program-specific hash before `start()` or
/// `preprocess()` is called. Unsupported engines fail explicitly instead of
/// accepting a store and silently ignoring it.
pub trait MpcEnginePreprocPersistence: MpcEngine {
    /// Attach persistent storage for preprocessing material caching.
    fn set_preproc_store(
        &self,
        store: Arc<dyn PreprocStore>,
        program_hash: [u8; 32],
    ) -> MpcEngineResult<()>;
}

/// Extended MPC engine trait for sending private outputs to clients.
///
/// This is separate from [`MpcEngineClientOps`] because some backends may be
/// able to ingest client input without exposing an output-delivery channel, or
/// vice versa. Keeping it as a capability trait prevents the core VM engine
/// abstraction from accumulating protocol-specific optional methods.
pub trait MpcEngineClientOutput: MpcEngine {
    /// Send output share(s) to a specific client for private reconstruction.
    ///
    /// Unlike `open_share`, which reveals to all parties, this sends this
    /// party's share to a designated client who can collect shares from all
    /// parties and reconstruct the secret privately.
    fn send_output_to_client(
        &self,
        client_id: ClientId,
        shares: &[u8],
        output_share_count: ClientOutputShareCount,
    ) -> MpcEngineResult<()>;
}

/// Extended MPC engine trait for preprocessing reservation.
///
/// Engines that support persistent preprocessing and the masked-input protocol
/// implement this trait. The reservation lifecycle:
///
/// 1. `init_reservations` — set up or restore reservation state
/// 2. `reserve_masks` — clients reserve index ranges
/// 3. `get_mask_share` — clients collect per-node mask shares
/// 4. `submit_masked_input` — clients submit `input + mask`
/// 5. `consume_masked_inputs` — nodes compute `masked_input − mask_share`
#[async_trait::async_trait]
pub trait MpcEngineReservation: MpcEngine {
    /// Initialize or restore reservation state for a program.
    async fn init_reservations(&self, program_hash: [u8; 32], capacity: u64)
        -> MpcEngineResult<()>;

    /// Reserve `n` consecutive mask indices for a client.
    async fn reserve_masks(&self, client_id: ClientId, n: u64)
        -> MpcEngineResult<ReservationGrant>;

    /// Get this node's mask share at a given index as serialized bytes.
    async fn get_mask_share(&self, index: u64) -> MpcEngineResult<Vec<u8>>;

    /// Accept a masked input at a reserved index.
    async fn submit_masked_input(
        &self,
        client_id: ClientId,
        index: u64,
        value: Vec<u8>,
    ) -> MpcEngineResult<()>;

    /// Compute `input_share = masked_input − mask_share` for each index.
    ///
    /// Marks the indices as consumed.
    async fn consume_masked_inputs(&self, indices: &[u64]) -> MpcEngineResult<Vec<(u64, Vec<u8>)>>;

    /// Number of unreserved mask slots.
    async fn available_masks(&self) -> u64;

    /// Persist the current reservation state.
    async fn persist_reservations(&self) -> MpcEngineResult<()>;
}
