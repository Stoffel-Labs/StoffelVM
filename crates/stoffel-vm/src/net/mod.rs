// src/net/mod.rs
//! Networking module for peer-to-peer communication.

pub mod client_store;
pub mod discovery;
pub mod hb_engine;
pub mod mpc;
pub mod mpc_engine;
pub mod mpc_runner;
pub mod p2p;
pub mod program_sync;
pub mod session;

// Re-export key components
pub use p2p::{
    NetworkManager, PeerConnection, QuicMessage, QuicNetworkConfig, QuicNetworkManager, QuicNode,
    QuicPeerConnection,
};

// Re-export MPC helpers and engine unconditionally
pub use mpc::{default_node_opts, honeybadger_node_opts};
// Re-export MpcRunner for convenient VM+MPC orchestration
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
