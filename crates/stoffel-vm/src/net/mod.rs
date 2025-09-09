// src/net/mod.rs
//! Networking module for peer-to-peer communication.

pub mod p2p;
pub mod mpc;
pub mod mpc_engine;
pub mod hb_engine;

// Re-export key components
pub use p2p::{
    NetworkManager, PeerConnection, QuicMessage, QuicNetworkConfig, QuicNetworkManager, QuicNode,
    QuicPeerConnection,
};

// Re-export MPC helpers and engine unconditionally
pub use mpc::{
    create_clients, create_global_nodes, default_node_opts, new_default_node, receive,
    receive_client,
};
pub use mpc_engine::{MpcEngine, NoopMpcEngine};
pub use hb_engine::HoneyBadgerMpcEngine;
