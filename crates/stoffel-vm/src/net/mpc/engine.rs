//! Abstraction for MPC engines used by the VM.
//!
//! The core trait stays focused on VM execution primitives. Optional protocol
//! surfaces are exposed through explicit capability sub-traits so field-only,
//! client-input-only, and richer threshold-crypto backends can evolve
//! independently.

mod capabilities;
mod error;
mod exponent;
mod identity;
mod traits;

pub use crate::net::share_algebra::{ShareAlgebraError, ShareAlgebraResult};
pub use capabilities::{MpcCapabilities, MpcCapability, MpcCapabilityError, MpcCapabilityResult};
#[cfg(any(feature = "honeybadger", feature = "avss"))]
pub(crate) use error::MpcEngineOperationResultExt;
pub use error::{MpcEngineError, MpcEngineResult};
pub use exponent::{MpcExponentError, MpcExponentGenerator, MpcExponentGroup, MpcExponentResult};
pub use identity::{
    AbaSessionId, MpcEngineIdentity, MpcInstanceId, MpcPartyCount, MpcPartyId, MpcRuntimeInfo,
    MpcSessionTopology, MpcSessionTopologyError, MpcThreshold, RbcSessionId,
};
pub use traits::{
    AsyncMpcEngine, AsyncMpcEngineClientOps, AsyncMpcEngineConsensus, MpcEngine,
    MpcEngineClientOps, MpcEngineClientOutput, MpcEngineConsensus, MpcEngineFieldOpen,
    MpcEngineMultiplication, MpcEngineOpenInExponent, MpcEnginePreprocPersistence,
    MpcEngineRandomness, MpcEngineReservation,
};

#[cfg(test)]
mod tests;
