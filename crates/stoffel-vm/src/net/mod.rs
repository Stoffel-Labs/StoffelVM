// src/net/mod.rs
//! Networking module for peer-to-peer communication.

#[cfg(feature = "avss")]
pub mod avss_server;
#[cfg(any(feature = "honeybadger", feature = "avss"))]
pub(crate) mod broadcast;
pub mod client_store;
pub mod curve;
pub mod discovery;
#[cfg(any(feature = "honeybadger", feature = "avss"))]
pub(crate) mod group_interpolation;
#[cfg(feature = "honeybadger")]
pub mod hb_server;
pub mod mpc;
#[cfg(feature = "honeybadger")]
pub mod mpc_runner;
pub mod open_registry;
pub use open_registry::{InstanceRegistry, OpenMessageRouter, UNKNOWN_SENDER_ID};
pub mod p2p;
pub mod program_sync;
pub mod reservation;
pub(crate) mod reveal_batcher;
pub mod session;
pub(crate) mod share_algebra;
pub(crate) mod share_runtime;

#[cfg(feature = "avss")]
pub mod avss_engine {
    pub use super::mpc::avss::*;
}

pub mod backend {
    pub use super::mpc::backend::*;
}

pub mod engine_config {
    pub use super::mpc::session_config::*;
}

#[cfg(feature = "honeybadger")]
pub mod hb_engine {
    pub use super::mpc::honeybadger::*;
}

pub mod mpc_engine {
    pub use super::mpc::engine::*;
}

// ---------------------------------------------------------------------------
// Async/sync bridge
// ---------------------------------------------------------------------------

pub type BlockOnResult<T> = Result<T, BlockOnError>;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BlockOnError {
    #[error("{reason}")]
    Future { reason: String },
    #[error("operation requires a multi-thread Tokio runtime; current runtime is {flavor}")]
    IncompatibleRuntime { flavor: &'static str },
    #[error("failed to create Tokio runtime: {reason}")]
    RuntimeBuild { reason: String },
}

impl From<BlockOnError> for String {
    fn from(error: BlockOnError) -> Self {
        error.to_string()
    }
}

#[allow(deprecated)]
fn runtime_flavor_name(flavor: tokio::runtime::RuntimeFlavor) -> &'static str {
    match flavor {
        tokio::runtime::RuntimeFlavor::MultiThread => "multi-thread",
        tokio::runtime::RuntimeFlavor::CurrentThread => "current-thread",
        _ => "unknown",
    }
}

fn map_block_on_future_result<T>(result: Result<T, String>) -> BlockOnResult<T> {
    result.map_err(|reason| BlockOnError::Future { reason })
}

/// Execute a future synchronously, bridging from a sync context to async.
///
/// Dispatches based on the current Tokio runtime:
/// - **Multi-thread runtime**: uses `block_in_place` + `block_on` (no deadlock).
/// - **No runtime**: creates a temporary current-thread runtime.
/// - **Single-thread runtime**: returns `Err` (would deadlock).
///
/// The future does NOT need to be `Send` or `'static`.
pub fn try_block_on_current<T>(
    fut: impl std::future::Future<Output = Result<T, String>>,
) -> BlockOnResult<T> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) =>
        {
            #[allow(deprecated)]
            match handle.runtime_flavor() {
                tokio::runtime::RuntimeFlavor::MultiThread => {
                    tokio::task::block_in_place(|| map_block_on_future_result(handle.block_on(fut)))
                }
                flavor => Err(BlockOnError::IncompatibleRuntime {
                    flavor: runtime_flavor_name(flavor),
                }),
            }
        }
        Err(_) => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| BlockOnError::RuntimeBuild {
                    reason: error.to_string(),
                })?;
            map_block_on_future_result(rt.block_on(fut))
        }
    }
}

/// String-compatible wrapper for legacy backend code.
///
/// Prefer [`try_block_on_current`] when the caller can preserve typed runtime
/// bridge failures.
pub fn block_on_current<T>(
    fut: impl std::future::Future<Output = Result<T, String>>,
) -> Result<T, String> {
    try_block_on_current(fut).map_err(String::from)
}

// Re-export key components
pub use p2p::{
    NetworkManager, PeerConnection, QuicMessage, QuicNetworkConfig, QuicNetworkManager, QuicNode,
    QuicPeerConnection,
};

// Re-export backend selection
pub use backend::{MpcBackendError, MpcBackendKind, MpcBackendResult};
pub use curve::{
    field_from_i64, field_to_i64, MpcCurveConfig, MpcCurveError, MpcCurveResult, MpcFieldKind,
};
pub use engine_config::MpcSessionConfig;
pub use mpc_engine::{
    MpcInstanceId, MpcPartyCount, MpcPartyId, MpcSessionTopology, MpcSessionTopologyError,
    MpcThreshold,
};

// Re-export MPC helpers (HB-specific helpers gated)
#[cfg(feature = "honeybadger")]
pub use mpc::{default_node_opts, honeybadger_node_opts, honeybadger_protocol_instance_id};
// Re-export HoneyBadger QUIC server
#[cfg(feature = "honeybadger")]
pub use hb_server::{
    spawn_receive_loops, spawn_receive_loops_split, FrHoneyBadgerQuicServer, HoneyBadgerQuicConfig,
    HoneyBadgerQuicServer, HoneyBadgerQuicServerError,
};
// Re-export MpcRunner for convenient VM+MPC orchestration
#[cfg(feature = "honeybadger")]
pub use mpc_runner::{
    MpcRunner, MpcRunnerBuilder, MpcRunnerConfig, MpcRunnerError, MpcRunnerResult,
};
// Re-export AVSS QUIC server types
#[cfg(feature = "avss")]
pub use avss_server::{
    AvssPublicKeyEnvelopeError, AvssQuicConfig, AvssQuicServer, Bls12381AvssServer,
    Bn254AvssServer, Curve25519AvssServer, Ed25519AvssServer,
};
// Re-export discovery helpers
pub use discovery::{
    bootstrap_with_bootnode, register_and_wait_for_session, run_bootnode, run_bootnode_with_config,
    wait_until_min_parties, DiscoveryMessage, SessionRegistrationConfig,
};
// Re-export program sync + session helpers
pub use program_sync::{
    agree_and_sync_program, program_id_from_bytes, ProgramSyncError, ProgramSyncMessage,
    ProgramSyncResult,
};
pub use session::{
    agree_session_with_bootnode, derive_instance_id, SessionError, SessionInfo, SessionMessage,
    SessionResult, CONTROL_STREAM_ID, PROGRAM_STREAM_ID,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_block_on_current_runs_without_existing_runtime() {
        let result = try_block_on_current(async { Ok::<_, String>(42usize) })
            .expect("temporary runtime should execute future");

        assert_eq!(result, 42);
    }

    #[test]
    fn typed_block_on_current_preserves_future_error() {
        let err =
            try_block_on_current(async { Err::<(), _>("backend failed".to_owned()) }).unwrap_err();

        assert_eq!(
            err,
            BlockOnError::Future {
                reason: "backend failed".to_owned()
            }
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn typed_block_on_current_rejects_current_thread_runtime() {
        let err = try_block_on_current(async { Ok::<_, String>(()) }).unwrap_err();

        assert_eq!(
            err,
            BlockOnError::IncompatibleRuntime {
                flavor: "current-thread"
            }
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn typed_block_on_current_runs_inside_multi_thread_runtime() {
        let result = try_block_on_current(async { Ok::<_, String>(7usize) })
            .expect("multi-thread runtime should support blocking bridge");

        assert_eq!(result, 7);
    }
}
