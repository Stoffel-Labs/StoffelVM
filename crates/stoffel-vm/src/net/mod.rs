// src/net/mod.rs
//! Networking module for peer-to-peer communication.

pub mod p2p;
#[cfg(feature = "mpc")]
pub mod mpc;
#[cfg(feature = "mpc")]
pub mod mpc_engine;

// Re-export key components
pub use p2p::{
    NetworkManager, PeerConnection, QuicMessage, QuicNetworkConfig, QuicNetworkManager, QuicNode,
    QuicPeerConnection,
};

// Re-export MPC helpers and engine when the `mpc` feature is enabled
#[cfg(feature = "mpc")]
pub use mpc::{
    create_clients, create_global_nodes, default_node_opts, new_default_node, receive,
    receive_client,
};
#[cfg(feature = "mpc")]
pub use mpc_engine::{MpcEngine, NoopMpcEngine};
