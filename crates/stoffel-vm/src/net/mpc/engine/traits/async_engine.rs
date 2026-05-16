use super::super::{MpcCapability, MpcEngineError, MpcEngineResult, MpcExponentGroup};
use super::consensus::AsyncMpcEngineConsensus;
use super::core::MpcEngine;
use crate::net::client_store::{
    ClientInputHydrationCount, ClientInputStore, ClientOutputShareCount,
};
use stoffel_vm_types::core_types::{ClearShareInput, ClearShareValue, ShareData, ShareType};
use stoffelnet::network_utils::ClientId;

/// Async client-input capability for network-backed MPC engines.
///
/// Hydrating VM client inputs can wait on network input servers, so async VM
/// orchestration routes through this trait instead of the synchronous
/// `MpcEngineClientOps` bridge.
#[async_trait::async_trait]
pub trait AsyncMpcEngineClientOps: MpcEngine {
    /// Get all client IDs that have submitted inputs without blocking the async runtime.
    async fn get_client_ids_async(&self) -> Vec<ClientId>;

    /// Hydrate a VM client input store with all available client inputs.
    async fn hydrate_client_inputs_async(
        &self,
        store: &ClientInputStore,
    ) -> MpcEngineResult<ClientInputHydrationCount>;

    /// Hydrate a VM client input store with inputs from specific clients.
    async fn hydrate_client_inputs_for_async(
        &self,
        store: &ClientInputStore,
        client_ids: &[ClientId],
    ) -> MpcEngineResult<ClientInputHydrationCount>;
}

/// Async MPC engine trait for non-blocking VM execution.
///
/// This trait provides async versions of the MPC operations that require
/// network communication. The VM can use these methods to avoid blocking the
/// async runtime during MPC operations.
#[async_trait::async_trait]
pub trait AsyncMpcEngine: MpcEngine {
    /// Build an error for core async operations that must be explicitly
    /// provided by async VM backends.
    fn async_operation_unavailable(
        &self,
        operation: &'static str,
        async_method: &'static str,
    ) -> MpcEngineError {
        MpcEngineError::operation_failed(
            operation,
            format!(
                "MPC backend '{}' does not expose {}; async VM execution cannot use a synchronous bridge for this operation",
                self.protocol_name(),
                async_method,
            ),
        )
    }

    /// Build an error for advertised optional capabilities that lack an
    /// async implementation.
    fn async_capability_unavailable(
        &self,
        operation: &'static str,
        capability: MpcCapability,
        async_method: &'static str,
    ) -> MpcEngineError {
        if self.has_capability(capability) {
            MpcEngineError::operation_failed(
                operation,
                format!(
                    "MPC backend '{}' advertises {} but does not expose {}; async VM execution cannot use a synchronous bridge for this operation",
                    self.protocol_name(),
                    capability.as_str(),
                    async_method,
                ),
            )
        } else {
            self.capability_error(capability)
        }
    }

    /// Try to obtain async client-input operations, if supported.
    fn as_async_client_ops(&self) -> Option<&dyn AsyncMpcEngineClientOps> {
        None
    }

    /// Obtain async client-input operations or return a capability-aware error.
    fn async_client_ops(&self) -> MpcEngineResult<&dyn AsyncMpcEngineClientOps> {
        self.as_async_client_ops().ok_or_else(|| {
            if self.supports_client_input() {
                MpcEngineError::operation_failed(
                    "async_client_ops",
                    format!(
                        "MPC backend '{}' advertises client input but does not expose AsyncMpcEngineClientOps",
                        self.protocol_name()
                    ),
                )
            } else {
                self.capability_error(MpcCapability::ClientInput)
            }
        })
    }

    /// Try to obtain async consensus operations, if supported.
    fn as_async_consensus_ops(&self) -> Option<&dyn AsyncMpcEngineConsensus> {
        None
    }

    /// Obtain async consensus operations or return a capability-aware error.
    fn async_consensus_ops(&self) -> MpcEngineResult<&dyn AsyncMpcEngineConsensus> {
        self.as_async_consensus_ops().ok_or_else(|| {
            if self.supports_consensus() {
                MpcEngineError::operation_failed(
                    "async_consensus_ops",
                    format!(
                        "MPC backend '{}' advertises consensus but does not expose AsyncMpcEngineConsensus",
                        self.protocol_name()
                    ),
                )
            } else {
                self.capability_error(MpcCapability::Consensus)
            }
        })
    }

    /// Create a secret share from a canonical clear input asynchronously.
    async fn input_share_async(&self, _clear: ClearShareInput) -> MpcEngineResult<ShareData> {
        Err(self.async_operation_unavailable("async_input_share", "input_share_async"))
    }

    /// Perform secure multiplication of two shares asynchronously.
    async fn multiply_share_async(
        &self,
        ty: ShareType,
        left: &[u8],
        right: &[u8],
    ) -> MpcEngineResult<ShareData> {
        let _ = (ty, left, right);
        Err(self.async_capability_unavailable(
            "async_multiply_share",
            MpcCapability::Multiplication,
            "multiply_share_async",
        ))
    }

    /// Reconstruct a secret from shares asynchronously.
    async fn open_share_async(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
    ) -> MpcEngineResult<ClearShareValue>;

    /// Batch reconstruct multiple secrets asynchronously.
    ///
    /// This is the async version of `batch_open_shares`.
    async fn batch_open_shares_async(
        &self,
        ty: ShareType,
        shares: &[Vec<u8>],
    ) -> MpcEngineResult<Vec<ClearShareValue>> {
        let mut opened = Vec::with_capacity(shares.len());
        for share in shares {
            opened.push(self.open_share_async(ty, share).await?);
        }
        Ok(opened)
    }

    /// Generate random bytes as a secret-shared value asynchronously.
    async fn random_share_async(&self, _ty: ShareType) -> MpcEngineResult<ShareData> {
        Err(self.async_capability_unavailable(
            "async_random_share",
            MpcCapability::Randomness,
            "random_share_async",
        ))
    }

    /// Reconstruct a secret as raw field-element bytes asynchronously.
    async fn open_share_as_field_async(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
    ) -> MpcEngineResult<Vec<u8>> {
        let _ = (ty, share_bytes);
        Err(self.async_capability_unavailable(
            "async_open_share_as_field",
            MpcCapability::FieldOpen,
            "open_share_as_field_async",
        ))
    }

    /// Reveal a share in the exponent asynchronously.
    async fn open_share_in_exp_async(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
        generator_bytes: &[u8],
    ) -> MpcEngineResult<Vec<u8>> {
        let _ = (ty, share_bytes, generator_bytes);
        Err(self.async_capability_unavailable(
            "async_open_share_in_exp",
            MpcCapability::OpenInExponent,
            "open_share_in_exp_async",
        ))
    }

    /// Reveal a share in a named exponent group asynchronously.
    ///
    /// Engines that only support their native group inherit an async-native
    /// dispatch path. Engines that support additional groups should override
    /// this method so those protocol rounds can also avoid sync runtime bridges.
    async fn open_share_in_exp_group_async(
        &self,
        group: MpcExponentGroup,
        ty: ShareType,
        share_bytes: &[u8],
        generator_bytes: &[u8],
    ) -> MpcEngineResult<Vec<u8>> {
        let ops = self.open_in_exp_ops()?;
        if !ops.supports_exponent_group(group) {
            return Err(MpcEngineError::operation_failed(
                "async_open_share_in_exp_group",
                group.unsupported_error(self.protocol_name()),
            ));
        }

        if ops.native_exponent_group() == group {
            return self
                .open_share_in_exp_async(ty, share_bytes, generator_bytes)
                .await;
        }

        Err(self.async_capability_unavailable(
            "async_open_share_in_exp_group",
            MpcCapability::OpenInExponent,
            "open_share_in_exp_group_async",
        ))
    }

    /// Send output shares to a specific client asynchronously.
    async fn send_output_to_client_async(
        &self,
        client_id: ClientId,
        shares: &[u8],
        output_share_count: ClientOutputShareCount,
    ) -> MpcEngineResult<()> {
        let _ = (client_id, shares, output_share_count);
        Err(self.async_capability_unavailable(
            "async_send_output_to_client",
            MpcCapability::ClientOutput,
            "send_output_to_client_async",
        ))
    }
}
