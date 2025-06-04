// src/net/mod.rs
//! Networking module for peer-to-peer communication.

pub mod p2p;

// Re-export key components
pub use p2p::{QuicNetworkManager, QuicPeerConnection, PeerConnection, NetworkManager};
