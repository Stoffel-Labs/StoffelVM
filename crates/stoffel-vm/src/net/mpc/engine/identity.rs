use super::traits::MpcEngine;
use super::{MpcCapabilities, MpcCapability};
use crate::net::curve::{MpcCurveConfig, MpcFieldKind};
use std::fmt;
use std::num::NonZeroUsize;

/// Stable identifier for one MPC protocol instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct MpcInstanceId(u64);

impl MpcInstanceId {
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    pub const fn id(self) -> u64 {
        self.0
    }
}

impl From<u64> for MpcInstanceId {
    fn from(id: u64) -> Self {
        Self::new(id)
    }
}

impl fmt::Display for MpcInstanceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Party identity within a configured MPC session.
///
/// Transport and protocol adapters often expose party IDs as integers, but the
/// VM should not pass them around as arbitrary counts or indexes. This handle
/// marks values that name a protocol participant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MpcPartyId(usize);

impl MpcPartyId {
    pub const fn new(id: usize) -> Self {
        Self(id)
    }

    pub const fn id(self) -> usize {
        self.0
    }
}

impl fmt::Display for MpcPartyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Non-zero number of parties participating in an MPC session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MpcPartyCount(NonZeroUsize);

impl MpcPartyCount {
    pub const ONE: Self = Self(NonZeroUsize::MIN);

    pub const fn new(count: NonZeroUsize) -> Self {
        Self(count)
    }

    pub fn try_new(count: usize) -> Result<Self, MpcSessionTopologyError> {
        NonZeroUsize::new(count)
            .map(Self)
            .ok_or(MpcSessionTopologyError::ZeroParties)
    }

    pub const fn one() -> Self {
        Self::ONE
    }

    pub const fn count(self) -> usize {
        self.0.get()
    }

    pub const fn as_nonzero(self) -> NonZeroUsize {
        self.0
    }
}

impl Default for MpcPartyCount {
    fn default() -> Self {
        Self::one()
    }
}

impl fmt::Display for MpcPartyCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Threshold parameter for an MPC session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct MpcThreshold(usize);

impl MpcThreshold {
    pub const fn new(threshold: usize) -> Self {
        Self(threshold)
    }

    pub const fn value(self) -> usize {
        self.0
    }
}

impl fmt::Display for MpcThreshold {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Validated topology shared by MPC engine/session construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MpcSessionTopology {
    instance_id: MpcInstanceId,
    party_id: MpcPartyId,
    party_count: MpcPartyCount,
    threshold: MpcThreshold,
}

impl MpcSessionTopology {
    pub fn try_new(
        instance_id: u64,
        party_id: usize,
        n_parties: usize,
        threshold: usize,
    ) -> Result<Self, MpcSessionTopologyError> {
        let party_count = MpcPartyCount::try_new(n_parties)?;
        if party_id >= party_count.count() {
            return Err(MpcSessionTopologyError::PartyOutOfRange {
                party_id,
                n_parties: party_count.count(),
            });
        }
        if threshold >= party_count.count() {
            return Err(MpcSessionTopologyError::ThresholdOutOfRange {
                threshold,
                n_parties: party_count.count(),
            });
        }

        Ok(Self {
            instance_id: MpcInstanceId::new(instance_id),
            party_id: MpcPartyId::new(party_id),
            party_count,
            threshold: MpcThreshold::new(threshold),
        })
    }

    pub fn try_from_typed(
        instance_id: MpcInstanceId,
        party_id: MpcPartyId,
        party_count: MpcPartyCount,
        threshold: MpcThreshold,
    ) -> Result<Self, MpcSessionTopologyError> {
        if party_id.id() >= party_count.count() {
            return Err(MpcSessionTopologyError::PartyOutOfRange {
                party_id: party_id.id(),
                n_parties: party_count.count(),
            });
        }
        if threshold.value() >= party_count.count() {
            return Err(MpcSessionTopologyError::ThresholdOutOfRange {
                threshold: threshold.value(),
                n_parties: party_count.count(),
            });
        }

        Ok(Self {
            instance_id,
            party_id,
            party_count,
            threshold,
        })
    }

    pub const fn instance(self) -> MpcInstanceId {
        self.instance_id
    }

    pub const fn instance_id(self) -> u64 {
        self.instance_id.id()
    }

    pub const fn party(self) -> MpcPartyId {
        self.party_id
    }

    pub const fn party_id(self) -> usize {
        self.party_id.id()
    }

    pub const fn party_count(self) -> MpcPartyCount {
        self.party_count
    }

    pub const fn n_parties(self) -> usize {
        self.party_count.count()
    }

    pub const fn threshold_param(self) -> MpcThreshold {
        self.threshold
    }

    pub const fn threshold(self) -> usize {
        self.threshold.value()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MpcSessionTopologyError {
    #[error("MPC session must contain at least one party")]
    ZeroParties,
    #[error("MPC party id {party_id} is out of range for {n_parties} parties")]
    PartyOutOfRange { party_id: usize, n_parties: usize },
    #[error("MPC threshold {threshold} must be less than party count {n_parties}")]
    ThresholdOutOfRange { threshold: usize, n_parties: usize },
}

/// Session handle returned by reliable broadcast.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RbcSessionId(u64);

impl RbcSessionId {
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    pub const fn id(self) -> u64 {
        self.0
    }
}

impl fmt::Display for RbcSessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Session handle returned by asynchronous binary agreement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AbaSessionId(u64);

impl AbaSessionId {
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    pub const fn id(self) -> u64 {
        self.0
    }
}

impl fmt::Display for AbaSessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Stable runtime identity for an MPC engine attached to a VM.
///
/// Async execution receives an engine reference separately from the VM state.
/// Comparing this structured identity prevents accidentally executing protocol
/// work against a different session, party, threshold, or field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MpcEngineIdentity {
    protocol_name: &'static str,
    topology: MpcSessionTopology,
    curve_config: MpcCurveConfig,
    field_kind: MpcFieldKind,
}

impl MpcEngineIdentity {
    pub fn from_engine<E: MpcEngine + ?Sized>(engine: &E) -> Self {
        Self {
            protocol_name: engine.protocol_name(),
            topology: engine.topology(),
            curve_config: engine.curve_config(),
            field_kind: engine.field_kind(),
        }
    }

    pub fn protocol_name(self) -> &'static str {
        self.protocol_name
    }

    pub const fn topology(self) -> MpcSessionTopology {
        self.topology
    }

    pub const fn instance(self) -> MpcInstanceId {
        self.topology.instance()
    }

    pub fn party(self) -> MpcPartyId {
        self.topology.party()
    }

    pub const fn party_count(self) -> MpcPartyCount {
        self.topology.party_count()
    }

    pub const fn threshold_param(self) -> MpcThreshold {
        self.topology.threshold_param()
    }

    pub fn curve_config(self) -> MpcCurveConfig {
        self.curve_config
    }

    pub fn field_kind(self) -> MpcFieldKind {
        self.field_kind
    }
}

impl fmt::Display for MpcEngineIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "'{}' (instance {}, party {}, parties {}, threshold {}, curve {}, field {})",
            self.protocol_name,
            self.topology.instance_id(),
            self.topology.party(),
            self.topology.n_parties(),
            self.topology.threshold(),
            self.curve_config.name(),
            self.field_kind.name()
        )
    }
}

/// VM-facing MPC runtime metadata.
///
/// This is intentionally a copied value, not an engine handle. VM builtins that
/// only need identity/readiness information should depend on this metadata
/// rather than receiving access to protocol operation traits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MpcRuntimeInfo {
    identity: MpcEngineIdentity,
    capabilities: MpcCapabilities,
    ready: bool,
}

impl MpcRuntimeInfo {
    pub fn from_engine<E: MpcEngine + ?Sized>(engine: &E) -> Self {
        Self {
            identity: MpcEngineIdentity::from_engine(engine),
            capabilities: engine.capabilities(),
            ready: engine.is_ready(),
        }
    }

    pub const fn identity(self) -> MpcEngineIdentity {
        self.identity
    }

    pub const fn capabilities(self) -> MpcCapabilities {
        self.capabilities
    }

    pub fn has_capability(self, capability: MpcCapability) -> bool {
        self.capabilities.supports(capability)
    }

    pub const fn is_ready(self) -> bool {
        self.ready
    }

    pub fn protocol_name(self) -> &'static str {
        self.identity.protocol_name()
    }

    pub const fn topology(self) -> MpcSessionTopology {
        self.identity.topology()
    }

    pub const fn instance(self) -> MpcInstanceId {
        self.identity.instance()
    }

    pub fn party(self) -> MpcPartyId {
        self.identity.party()
    }

    pub const fn party_count(self) -> MpcPartyCount {
        self.identity.party_count()
    }

    pub const fn threshold_param(self) -> MpcThreshold {
        self.identity.threshold_param()
    }

    pub fn curve_config(self) -> MpcCurveConfig {
        self.identity.curve_config()
    }

    pub fn field_kind(self) -> MpcFieldKind {
        self.identity.field_kind()
    }
}
