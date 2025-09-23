//! HoneyBadger MPC integration helpers for the Stoffel VM.
//! Minimal public API kept to avoid cross-crate trait bound conflicts.
//! Use the MpcEngine abstraction (net::mpc_engine) to attach an engine to VMState for VM usage.

use stoffelmpc_mpc::honeybadger::HoneyBadgerMPCNodeOpts;

const DEFAULT_MIN_PARTIES: usize = 5;
const DEFAULT_THRESHOLD: usize = 1;

/// Convenience for creating default node options for a n-party network.
/// Customize n_triples / n_random_shares / instance_id as needed at callsite.
pub fn default_node_opts(instance_id: u64, n_triples: usize, n_random_shares: usize) -> HoneyBadgerMPCNodeOpts {
    HoneyBadgerMPCNodeOpts::new(
        DEFAULT_MIN_PARTIES,
        DEFAULT_THRESHOLD,
        n_triples,
        n_random_shares,
        instance_id,
    )
}
