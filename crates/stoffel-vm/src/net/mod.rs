// src/net/mod.rs
//! Networking module for peer-to-peer communication.

pub mod p2p;
pub mod mpc;
pub mod mpc_engine;
pub mod hb_engine;
pub mod discovery;
pub mod program_sync;
pub mod session;
pub mod client_store;

// Re-export key components
pub use p2p::{
    NetworkManager, PeerConnection, QuicMessage, QuicNetworkConfig, QuicNetworkManager, QuicNode,
    QuicPeerConnection,
};

// Re-export MPC helpers and engine unconditionally
pub use mpc::default_node_opts;
// Re-export discovery helpers
pub use discovery::{
    bootstrap_with_bootnode, run_bootnode, wait_until_min_parties, DiscoveryMessage,
};
// Re-export program sync + session helpers
pub use program_sync::{ProgramSyncMessage, agree_and_sync_program, program_id_from_bytes};
pub use session::{SessionInfo, agree_session_with_bootnode, CONTROL_STREAM_ID, PROGRAM_STREAM_ID};
