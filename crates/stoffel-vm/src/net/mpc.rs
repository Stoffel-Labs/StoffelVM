//! HoneyBadger MPC integration helpers for the Stoffel VM.
//! Minimal public API kept to avoid cross-crate trait bound conflicts.
//! Use the MpcEngine abstraction (net::mpc_engine) to attach an engine to VMState for VM usage.

use serde::{Deserialize, Serialize};
use stoffelmpc_mpc::honeybadger::HoneyBadgerMPCNodeOpts;
use stoffel_vm_types::core_types::{
    DEFAULT_FIXED_POINT_FRACTIONAL_BITS, DEFAULT_FIXED_POINT_TOTAL_BITS,
};

const DEFAULT_MIN_PARTIES: usize = 5;
const DEFAULT_THRESHOLD: usize = 1;
const DEFAULT_SECURITY_PARAMETER_K: usize = 8;

fn derive_prandbit_count(n_random_shares: usize) -> usize {
    std::cmp::max(n_random_shares, DEFAULT_FIXED_POINT_FRACTIONAL_BITS)
}

fn derive_prandint_count(n_triples: usize, n_random_shares: usize) -> usize {
    std::cmp::max(n_triples.max(1), n_random_shares.max(1))
}

/// Convenience for creating default node options for a n-party network.
/// Customize n_triples / n_random_shares / instance_id as needed at callsite.
pub fn default_node_opts(
    instance_id: u64,
    n_triples: usize,
    n_random_shares: usize,
) -> HoneyBadgerMPCNodeOpts {
    honeybadger_node_opts(
        DEFAULT_MIN_PARTIES,
        DEFAULT_THRESHOLD,
        n_triples,
        n_random_shares,
        instance_id,
    )
}

/// Build HoneyBadger node options, deriving ancillary preprocessing counts from existing inputs.
pub fn honeybadger_node_opts(
    n_parties: usize,
    threshold: usize,
    n_triples: usize,
    n_random_shares: usize,
    instance_id: u64,
) -> HoneyBadgerMPCNodeOpts {
    let n_prandbit = derive_prandbit_count(n_random_shares);
    let n_prandint = derive_prandint_count(n_triples, n_random_shares);
    let l = DEFAULT_FIXED_POINT_TOTAL_BITS;
    let k = DEFAULT_SECURITY_PARAMETER_K;

    HoneyBadgerMPCNodeOpts::new(
        n_parties,
        threshold,
        n_triples,
        n_random_shares,
        instance_id,
        n_prandbit,
        n_prandint,
        l,
        k,
    )
}

/// Network envelope used on QUIC to distinguish control messages (like handshakes)
/// from protocol payloads. If deserialization of this wrapper fails on receive,
/// the consumer must treat the bytes as a raw HoneyBadger WrappedMessage payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetEnvelope {
    /// Binary encoded handshake used for future extensibility. Current QUIC impl
    /// still uses a text-line handshake on the first stream, but we support this
    /// for forward-compatibility.
    Handshake { role: String, id: usize },
    /// Raw HoneyBadger message bytes (bincode of WrappedMessage from mpc crate).
    HoneyBadger(Vec<u8>),
}

impl NetEnvelope {
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).expect("envelope serialization should not fail")
    }

    pub fn try_deserialize(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}
