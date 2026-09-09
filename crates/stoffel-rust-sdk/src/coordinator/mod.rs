//! Coordinator surfaces and re-exports.
//!
//! Off-chain coordinator behavior is owned by `stoffel-mpc-coordinator`; the SDK
//! re-exports those types.

pub mod offchain;

pub use offchain::{
    ClientIdentity, OffChainCoordinator, OffChainCoordinatorClient, OffChainCoordinatorServer,
};
pub use stoffel_mpc_coordinator_shared::{
    Coordinator, CoordinatorError, ExecutionId, Round, ShareBound,
};
