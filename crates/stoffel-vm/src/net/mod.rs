// src/net/mod.rs
//! Networking module for peer-to-peer communication.

#[cfg(feature = "adkg")]
pub mod adkg_engine;
#[cfg(feature = "adkg")]
pub mod adkg_server;
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
pub mod p2p;
pub mod program_sync;
pub mod session;

// Re-export key components
pub use p2p::{
    NetworkManager, PeerConnection, QuicMessage, QuicNetworkConfig, QuicNetworkManager, QuicNode,
    QuicPeerConnection,
};

// Re-export backend selection
pub use backend::MpcBackendKind;
pub use curve::{MpcCurveConfig, MpcFieldKind};

// Re-export MPC helpers (HB-specific helpers gated)
#[cfg(feature = "honeybadger")]
pub use mpc::{default_node_opts, honeybadger_node_opts};
// Re-export HoneyBadger QUIC server
#[cfg(feature = "honeybadger")]
pub use hb_server::{
    spawn_receive_loops, FrHoneyBadgerQuicServer, HoneyBadgerQuicConfig, HoneyBadgerQuicServer,
};
// Re-export MpcRunner for convenient VM+MPC orchestration
#[cfg(feature = "honeybadger")]
pub use mpc_runner::{MpcRunner, MpcRunnerBuilder, MpcRunnerConfig};
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
