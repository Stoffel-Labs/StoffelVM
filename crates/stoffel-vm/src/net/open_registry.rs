//! Per-instance accumulation registry for `open_share` and `batch_open_shares`.
//!
//! Each MPC engine/session owns an [`OpenMessageRouter`] that routes wire
//! messages to per-instance [`InstanceRegistry`] values owned by that runtime.
//! Registries are scoped per `instance_id` within one router, preventing
//! cross-session contamination inside the same process.

mod accumulators;
mod consensus;
mod instance;
mod router;
mod wire;

pub use accumulators::{
    AbaState, ExpOpenAccumulator, ExpOpenProgress, ExpOpenRegistryKind, ExpOpenRequest, RbcState,
};
pub use instance::InstanceRegistry;
pub use router::OpenMessageRouter;
pub use wire::{
    encode_avss_g2_open_exp_wire_message, encode_avss_open_exp_wire_message,
    encode_batch_share_wire_message, encode_hb_open_exp_wire_message,
    encode_single_share_wire_message, UNKNOWN_SENDER_ID,
};

#[cfg(test)]
mod tests;
