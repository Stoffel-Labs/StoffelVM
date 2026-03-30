// src/net/mod.rs
//! Networking module for peer-to-peer communication.

#[cfg(feature = "avss")]
pub mod avss_engine;
#[cfg(feature = "avss")]
pub mod avss_server;
pub mod backend;
pub mod client_store;
pub mod curve;
pub mod discovery;
#[cfg(feature = "honeybadger")]
pub mod hb_engine;
#[cfg(feature = "honeybadger")]
pub mod hb_server;
pub mod mpc;
pub mod mpc_engine;
#[cfg(feature = "honeybadger")]
pub mod mpc_runner;
pub mod open_registry;
pub use open_registry::UNKNOWN_SENDER_ID;
pub mod p2p;
pub mod program_sync;
pub mod reservation;
pub mod session;

// ---------------------------------------------------------------------------
// Async/sync bridge
// ---------------------------------------------------------------------------

/// Execute a future synchronously, bridging from a sync context to async.
///
/// Dispatches based on the current Tokio runtime:
/// - **Multi-thread runtime**: uses `block_in_place` + `block_on` (no deadlock).
/// - **No runtime**: creates a temporary current-thread runtime.
/// - **Single-thread runtime**: returns `Err` (would deadlock).
///
/// The future does NOT need to be `Send` or `'static`.
pub fn block_on_current<T>(
    fut: impl std::future::Future<Output = Result<T, String>>,
) -> Result<T, String> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            #[allow(deprecated)]
            match handle.runtime_flavor() {
                tokio::runtime::RuntimeFlavor::MultiThread => {
                    tokio::task::block_in_place(|| handle.block_on(fut))
                }
                _ => Err("operation requires a multi-thread Tokio runtime".to_string()),
            }
        }
        Err(_) => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("failed to create Tokio runtime: {e}"))?;
            rt.block_on(fut)
        }
    }
}

// Re-export key components
pub use p2p::{
    NetworkManager, PeerConnection, QuicMessage, QuicNetworkConfig, QuicNetworkManager, QuicNode,
    QuicPeerConnection,
};

// Re-export backend selection
pub use backend::MpcBackendKind;
pub use curve::{field_from_i64, field_to_i64, MpcCurveConfig, MpcFieldKind};

// Re-export MPC helpers (HB-specific helpers gated)
#[cfg(feature = "honeybadger")]
pub use mpc::{default_node_opts, honeybadger_node_opts};
// Re-export HoneyBadger QUIC server
#[cfg(feature = "honeybadger")]
pub use hb_server::{
    spawn_receive_loops, spawn_receive_loops_split, FrHoneyBadgerQuicServer,
    HoneyBadgerQuicConfig, HoneyBadgerQuicServer,
};
// Re-export MpcRunner for convenient VM+MPC orchestration
#[cfg(feature = "honeybadger")]
pub use mpc_runner::{MpcRunner, MpcRunnerBuilder, MpcRunnerConfig};
// Re-export AVSS QUIC server types
#[cfg(feature = "avss")]
pub use avss_server::{
    AvssQuicConfig, AvssQuicServer, Bls12381AvssServer, Bn254AvssServer, Curve25519AvssServer,
    Ed25519AvssServer,
};
// Re-export discovery helpers
pub use discovery::{
    bootstrap_with_bootnode, register_and_wait_for_session,
    register_and_wait_for_session_with_program, run_bootnode, run_bootnode_with_config,
    wait_until_min_parties, DiscoveryMessage,
};
// Re-export program sync + session helpers
pub use program_sync::{agree_and_sync_program, program_id_from_bytes, ProgramSyncMessage};
pub use session::{
    agree_session_with_bootnode, derive_instance_id, SessionInfo, SessionMessage,
    CONTROL_STREAM_ID, PROGRAM_STREAM_ID,
};
