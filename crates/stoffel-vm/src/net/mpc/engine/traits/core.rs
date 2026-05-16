use super::super::{
    MpcCapabilities, MpcCapability, MpcEngineError, MpcEngineIdentity, MpcEngineResult,
    MpcInstanceId, MpcPartyCount, MpcPartyId, MpcSessionTopology, MpcSessionTopologyError,
    MpcThreshold, ShareAlgebraResult,
};
use super::capability::{
    MpcEngineClientOps, MpcEngineClientOutput, MpcEngineFieldOpen, MpcEngineMultiplication,
    MpcEngineOpenInExponent, MpcEnginePreprocPersistence, MpcEngineRandomness,
    MpcEngineReservation,
};
use super::consensus::MpcEngineConsensus;
use crate::net::curve::{MpcCurveConfig, MpcFieldKind};
use stoffel_vm_types::core_types::{ClearShareInput, ClearShareValue, ShareData, ShareType, Value};

/// Core MPC engine trait for synchronous VM operations.
///
/// This trait provides the synchronous interface used by the VM during
/// execution. Implementations handle async/sync bridging internally.
pub trait MpcEngine: Send + Sync {
    /// Get the protocol name (e.g., "honeybadger-mpc").
    fn protocol_name(&self) -> &'static str;

    /// Validated topology for this engine's current MPC session.
    ///
    /// Engine implementations should validate raw session metadata at
    /// construction time and store this structured value.
    fn topology(&self) -> MpcSessionTopology;

    /// Fallible topology accessor kept for compatibility with callers that
    /// already model engine metadata as a checked operation. The current trait
    /// contract requires implementations to store a validated topology, so this
    /// default is infallible.
    fn try_topology(&self) -> Result<MpcSessionTopology, MpcSessionTopologyError> {
        Ok(self.topology())
    }

    /// Typed instance identity for this MPC session.
    fn instance(&self) -> MpcInstanceId {
        self.topology().instance()
    }

    /// Check if the engine is ready for MPC operations.
    fn is_ready(&self) -> bool;

    /// Start the engine, which may trigger preprocessing.
    fn start(&self) -> MpcEngineResult<()>;

    /// Create a secret share from a canonical clear input value.
    fn input_share(&self, clear: ClearShareInput) -> MpcEngineResult<ShareData>;

    /// Reconstruct a secret from shares.
    ///
    /// This broadcasts to all parties, so all parties learn the secret.
    fn open_share(&self, ty: ShareType, share_bytes: &[u8]) -> MpcEngineResult<ClearShareValue>;

    /// Batch reconstruct multiple secrets at once.
    ///
    /// This reduces network rounds compared with calling `open_share`
    /// repeatedly. Results are returned in the same order as the input shares.
    fn batch_open_shares(
        &self,
        ty: ShareType,
        shares: &[Vec<u8>],
    ) -> MpcEngineResult<Vec<ClearShareValue>> {
        shares
            .iter()
            .map(|share| self.open_share(ty, share))
            .collect()
    }

    /// Locally add two shares owned by this party.
    ///
    /// Backends may override these local share-algebra hooks when their share
    /// encoding is not one of the built-in wire formats.
    fn add_share_local(
        &self,
        ty: ShareType,
        lhs_bytes: &[u8],
        rhs_bytes: &[u8],
    ) -> ShareAlgebraResult<Vec<u8>> {
        crate::net::share_algebra::add_share_for_curve(
            self.curve_config(),
            ty,
            lhs_bytes,
            rhs_bytes,
        )
    }

    /// Locally subtract two shares owned by this party.
    fn sub_share_local(
        &self,
        ty: ShareType,
        lhs_bytes: &[u8],
        rhs_bytes: &[u8],
    ) -> ShareAlgebraResult<Vec<u8>> {
        crate::net::share_algebra::sub_share_for_curve(
            self.curve_config(),
            ty,
            lhs_bytes,
            rhs_bytes,
        )
    }

    /// Locally negate a share owned by this party.
    fn neg_share_local(&self, ty: ShareType, share_bytes: &[u8]) -> ShareAlgebraResult<Vec<u8>> {
        crate::net::share_algebra::neg_share_for_curve(self.curve_config(), ty, share_bytes)
    }

    /// Locally add a clear scalar to a share owned by this party.
    fn add_share_scalar_local(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
        scalar: i64,
    ) -> ShareAlgebraResult<Vec<u8>> {
        crate::net::share_algebra::add_share_scalar_for_curve(
            self.curve_config(),
            ty,
            share_bytes,
            scalar,
        )
    }

    /// Locally subtract a clear scalar from a share owned by this party.
    fn sub_share_scalar_local(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
        scalar: i64,
    ) -> ShareAlgebraResult<Vec<u8>> {
        crate::net::share_algebra::sub_share_scalar_for_curve(
            self.curve_config(),
            ty,
            share_bytes,
            scalar,
        )
    }

    /// Locally subtract a share from a clear scalar.
    fn scalar_sub_share_local(
        &self,
        ty: ShareType,
        scalar: i64,
        share_bytes: &[u8],
    ) -> ShareAlgebraResult<Vec<u8>> {
        crate::net::share_algebra::scalar_sub_share_for_curve(
            self.curve_config(),
            ty,
            scalar,
            share_bytes,
        )
    }

    /// Locally multiply a share by a clear scalar.
    fn mul_share_scalar_local(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
        scalar: i64,
    ) -> ShareAlgebraResult<Vec<u8>> {
        crate::net::share_algebra::mul_share_scalar_for_curve(
            self.curve_config(),
            ty,
            share_bytes,
            scalar,
        )
    }

    /// Locally divide a share by a clear scalar.
    fn div_share_scalar_local(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
        scalar: i64,
    ) -> ShareAlgebraResult<Vec<u8>> {
        crate::net::share_algebra::div_share_scalar_for_curve(
            self.curve_config(),
            ty,
            share_bytes,
            scalar,
        )
    }

    /// Locally multiply a share by a serialized field element.
    fn mul_share_field_local(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
        scalar_bytes: &[u8],
    ) -> ShareAlgebraResult<Vec<u8>> {
        crate::net::share_algebra::mul_share_field_for_curve(
            self.curve_config(),
            ty,
            share_bytes,
            scalar_bytes,
        )
    }

    /// Locally reconstruct a secret from explicit share bytes.
    fn interpolate_shares_local(
        &self,
        ty: ShareType,
        shares: &[Vec<u8>],
    ) -> ShareAlgebraResult<Value> {
        crate::net::share_algebra::interpolate_local_for_curve(
            self.curve_config(),
            ty,
            shares,
            self.party_count().count(),
            self.threshold_param().value(),
        )
    }

    /// Shutdown the engine.
    fn shutdown(&self) {}

    /// Typed party identity for this node.
    fn party(&self) -> MpcPartyId {
        self.topology().party()
    }

    /// Fallible typed party count for this MPC session.
    fn try_party_count(&self) -> Result<MpcPartyCount, MpcSessionTopologyError> {
        Ok(self.topology().party_count())
    }

    /// Typed party count for this MPC session.
    fn party_count(&self) -> MpcPartyCount {
        self.topology().party_count()
    }

    /// Typed threshold parameter for this MPC session.
    fn threshold_param(&self) -> MpcThreshold {
        self.topology().threshold_param()
    }

    /// Structured identity for this engine's current MPC session.
    fn identity(&self) -> MpcEngineIdentity {
        MpcEngineIdentity::from_engine(self)
    }

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
    /// The default is empty. Implementations should override this to set the
    /// appropriate capability flags.
    fn capabilities(&self) -> MpcCapabilities {
        MpcCapabilities::empty()
    }

    /// Whether this engine advertises a specific optional capability.
    fn has_capability(&self, capability: MpcCapability) -> bool {
        self.capabilities().contains(capability.flag())
    }

    /// Build the standard error for an unavailable advertised capability.
    fn capability_error(&self, capability: MpcCapability) -> MpcEngineError {
        MpcEngineError::capability_unavailable(
            self.protocol_name(),
            capability,
            self.has_capability(capability),
        )
    }

    /// Whether this engine supports secure multiplication.
    fn supports_multiplication(&self) -> bool {
        self.has_capability(MpcCapability::Multiplication)
    }

    /// Try to obtain secure multiplication operations, if supported.
    fn as_multiplication(&self) -> Option<&dyn MpcEngineMultiplication> {
        None
    }

    /// Obtain secure multiplication operations or return a capability-aware error.
    fn multiplication_ops(&self) -> MpcEngineResult<&dyn MpcEngineMultiplication> {
        self.as_multiplication()
            .ok_or_else(|| self.capability_error(MpcCapability::Multiplication))
    }

    /// Whether this engine supports elliptic curve operations.
    fn supports_elliptic_curves(&self) -> bool {
        self.has_capability(MpcCapability::EllipticCurves)
    }

    /// Whether this engine supports client input operations.
    fn supports_client_input(&self) -> bool {
        self.has_capability(MpcCapability::ClientInput)
    }

    /// Whether this engine can send output shares to external clients.
    fn supports_client_output(&self) -> bool {
        self.has_capability(MpcCapability::ClientOutput)
    }

    /// Whether this engine supports consensus.
    fn supports_consensus(&self) -> bool {
        self.has_capability(MpcCapability::Consensus)
    }

    /// Whether this engine supports `open_share_in_exp`.
    fn supports_open_share_in_exp(&self) -> bool {
        self.has_capability(MpcCapability::OpenInExponent)
    }

    /// Try to obtain open-in-exponent operations, if supported.
    fn as_open_in_exp(&self) -> Option<&dyn MpcEngineOpenInExponent> {
        None
    }

    /// Obtain open-in-exponent operations or return a capability-aware error.
    fn open_in_exp_ops(&self) -> MpcEngineResult<&dyn MpcEngineOpenInExponent> {
        self.as_open_in_exp()
            .ok_or_else(|| self.capability_error(MpcCapability::OpenInExponent))
    }

    /// Whether this engine can generate jointly-random secret shares.
    fn supports_randomness(&self) -> bool {
        self.has_capability(MpcCapability::Randomness)
    }

    /// Try to obtain randomness operations, if supported.
    fn as_randomness(&self) -> Option<&dyn MpcEngineRandomness> {
        None
    }

    /// Obtain randomness operations or return a capability-aware error.
    fn randomness_ops(&self) -> MpcEngineResult<&dyn MpcEngineRandomness> {
        self.as_randomness()
            .ok_or_else(|| self.capability_error(MpcCapability::Randomness))
    }

    /// Whether this engine can open shares as raw field elements.
    fn supports_field_open(&self) -> bool {
        self.has_capability(MpcCapability::FieldOpen)
    }

    /// Try to obtain raw-field opening operations, if supported.
    fn as_field_open(&self) -> Option<&dyn MpcEngineFieldOpen> {
        None
    }

    /// Obtain raw-field opening operations or return a capability-aware error.
    fn field_open_ops(&self) -> MpcEngineResult<&dyn MpcEngineFieldOpen> {
        self.as_field_open()
            .ok_or_else(|| self.capability_error(MpcCapability::FieldOpen))
    }

    /// Try to obtain a reference to the consensus subtrait, if supported.
    fn as_consensus(&self) -> Option<&dyn MpcEngineConsensus> {
        None
    }

    /// Obtain consensus operations or return a capability-aware error.
    fn consensus_ops(&self) -> MpcEngineResult<&dyn MpcEngineConsensus> {
        self.as_consensus()
            .ok_or_else(|| self.capability_error(MpcCapability::Consensus))
    }

    /// Try to obtain a reference to the client-ops subtrait, if supported.
    fn as_client_ops(&self) -> Option<&dyn MpcEngineClientOps> {
        None
    }

    /// Obtain client-input operations or return a capability-aware error.
    fn client_ops(&self) -> MpcEngineResult<&dyn MpcEngineClientOps> {
        self.as_client_ops()
            .ok_or_else(|| self.capability_error(MpcCapability::ClientInput))
    }

    /// Try to obtain output-delivery operations, if supported.
    fn as_client_output(&self) -> Option<&dyn MpcEngineClientOutput> {
        None
    }

    /// Obtain client-output operations or return a capability-aware error.
    fn client_output_ops(&self) -> MpcEngineResult<&dyn MpcEngineClientOutput> {
        self.as_client_output()
            .ok_or_else(|| self.capability_error(MpcCapability::ClientOutput))
    }

    /// Whether this engine supports preprocessing reservation.
    fn supports_reservation(&self) -> bool {
        self.has_capability(MpcCapability::Reservation)
    }

    /// Try to obtain a reference to the reservation subtrait, if supported.
    fn as_reservation(&self) -> Option<&dyn MpcEngineReservation> {
        None
    }

    /// Obtain preprocessing reservation operations or return a capability-aware error.
    fn reservation_ops(&self) -> MpcEngineResult<&dyn MpcEngineReservation> {
        self.as_reservation()
            .ok_or_else(|| self.capability_error(MpcCapability::Reservation))
    }

    /// Whether this engine can persist preprocessing material.
    fn supports_preproc_persistence(&self) -> bool {
        self.has_capability(MpcCapability::PreprocPersistence)
    }

    /// Try to obtain preprocessing persistence operations, if supported.
    fn as_preproc_persistence(&self) -> Option<&dyn MpcEnginePreprocPersistence> {
        None
    }

    /// Obtain preprocessing persistence operations or return a capability-aware error.
    fn preproc_persistence_ops(&self) -> MpcEngineResult<&dyn MpcEnginePreprocPersistence> {
        self.as_preproc_persistence()
            .ok_or_else(|| self.capability_error(MpcCapability::PreprocPersistence))
    }
}
