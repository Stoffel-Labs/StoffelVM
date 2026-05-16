//! MPC-specific networking and backend integration.
//!
//! This subtree keeps the VM-facing MPC engine traits, backend selection,
//! shared session configuration, and concrete protocol engines together. The
//! parent `net` module keeps compatibility shims for the old public paths.

#[cfg(feature = "avss")]
pub mod avss;
pub mod backend;
pub mod engine;
pub mod helpers;
#[cfg(feature = "honeybadger")]
pub mod honeybadger;
pub(crate) mod protocol_ids;
pub mod session_config;

pub use helpers::NetEnvelope;
#[cfg(feature = "honeybadger")]
pub use helpers::{default_node_opts, honeybadger_node_opts, honeybadger_protocol_instance_id};
