//! MPC engine trait surface.
//!
//! The VM depends on a small synchronous core trait. Protocol-specific or
//! optional operations live in explicit subtraits so backends can implement only
//! the capabilities they actually provide.

mod async_engine;
mod capability;
mod consensus;
mod core;

pub use async_engine::{AsyncMpcEngine, AsyncMpcEngineClientOps};
pub use capability::{
    MpcEngineClientOps, MpcEngineClientOutput, MpcEngineFieldOpen, MpcEngineMultiplication,
    MpcEngineOpenInExponent, MpcEnginePreprocPersistence, MpcEngineRandomness,
    MpcEngineReservation,
};
pub use consensus::{AsyncMpcEngineConsensus, MpcEngineConsensus};
pub use core::MpcEngine;
