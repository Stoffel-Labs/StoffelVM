//! MPC integration helpers for the Stoffel VM.
//! Minimal public API kept to avoid cross-crate trait bound conflicts.
//! Use the MpcEngine abstraction (net::mpc_engine) to attach an engine to VMState for VM usage.

use super::backend::MpcBackendKind;
use super::protocol_ids::derive_protocol_instance_id_u32;
use serde::{Deserialize, Serialize};
use stoffel_vm_types::core_types::DEFAULT_FIXED_POINT_FRACTIONAL_BITS;
use stoffel_vm_types::core_types::DEFAULT_FIXED_POINT_TOTAL_BITS;
use stoffelmpc_mpc::honeybadger::HoneyBadgerMPCNodeOpts;
const DEFAULT_MIN_PARTIES: usize = 5;
const DEFAULT_THRESHOLD: usize = 1;
const DEFAULT_SECURITY_PARAMETER_K: usize = 8;
const DEFAULT_PROTOCOL_TIMEOUT_SECONDS: u64 = 600;
const GOLDILOCKS_FIELD_CAPACITY_BITS: usize = 64;
const PRAND_PROTOCOL_MARGIN_BITS: usize = 2;
#[allow(dead_code)]
fn derive_prandbit_count(n_random_shares: usize) -> usize {
    std::cmp::max(n_random_shares, DEFAULT_FIXED_POINT_FRACTIONAL_BITS)
}
#[allow(dead_code)]
fn derive_prandint_count(n_triples: usize, n_random_shares: usize) -> usize {
    std::cmp::max(n_triples.max(1), n_random_shares.max(1))
}
pub fn honeybadger_protocol_instance_id(instance_id: u64) -> u32 {
    derive_protocol_instance_id_u32(b"honeybadger", instance_id)
}

pub fn honeybadger_protocol_timeout() -> std::time::Duration {
    let seconds = std::env::var("STOFFEL_MPC_PROTOCOL_TIMEOUT_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_PROTOCOL_TIMEOUT_SECONDS);
    std::time::Duration::from_secs(seconds)
}

/// Derive the AVSS protocol instance id from the VM session id.
pub fn avss_protocol_instance_id(instance_id: u64) -> u32 {
    derive_protocol_instance_id_u32(b"avss", instance_id)
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
    .expect("default_node_opts should never fail with valid defaults")
}

/// Build HoneyBadger node options, deriving ancillary preprocessing counts from existing inputs.
/// Requests no random bits / integers (use [`honeybadger_node_opts_with_truncation`] for
/// programs that need fixed-point truncation preprocessing).
pub fn honeybadger_node_opts(
    n_parties: usize,
    threshold: usize,
    n_triples: usize,
    n_random_shares: usize,
    instance_id: u64,
) -> Result<HoneyBadgerMPCNodeOpts, String> {
    honeybadger_node_opts_with_truncation(
        n_parties,
        threshold,
        n_triples,
        n_random_shares,
        0,
        0,
        instance_id,
    )
}

/// Build HoneyBadger node options with explicit truncation-preprocessing counts
/// (`n_prandbit` random bits, `n_prandint` random integers) for fixed-point
/// division/multiplication. Note: prandbit generation consumes one beaver triple
/// and one random share per bit, so callers should already have folded that cost
/// into `n_triples`/`n_random_shares`.
pub fn honeybadger_node_opts_with_truncation(
    n_parties: usize,
    threshold: usize,
    n_triples: usize,
    n_random_shares: usize,
    n_prandbit: usize,
    n_prandint: usize,
    instance_id: u64,
) -> Result<HoneyBadgerMPCNodeOpts, String> {
    validate_honeybadger_topology(n_parties, threshold)?;

    // Fixed-point division requires l >= 2 * total_bits - fractional_bits.
    let mut l = 2 * DEFAULT_FIXED_POINT_TOTAL_BITS - DEFAULT_FIXED_POINT_FRACTIONAL_BITS;
    let k = DEFAULT_SECURITY_PARAMETER_K;

    if n_prandint > 0 && n_prandbit == 0 {
        // FIXME(mpc-protocols): Remove this cap after the release that fixes PRandInt's
        // field-capacity validation. In 0.1.1, PRandInt incorrectly checks `l + k`
        // against the 64-bit Goldilocks field even though that path supplies no
        // small-field bits, so the normal fixed-point width always fails with
        // `PRandError::SurpassedFieldCapacity`.
        let party_margin = n_parties
            .checked_next_power_of_two()
            .map_or(usize::BITS as usize, |power| {
                power.trailing_zeros() as usize
            });
        let accepted_l = GOLDILOCKS_FIELD_CAPACITY_BITS
            .saturating_sub(k)
            .saturating_sub(PRAND_PROTOCOL_MARGIN_BITS)
            .saturating_sub(party_margin)
            .saturating_sub(1);
        l = l.min(accepted_l);
    }

    HoneyBadgerMPCNodeOpts::new(
        n_parties,
        threshold,
        n_triples,
        n_random_shares,
        honeybadger_protocol_instance_id(instance_id),
        n_prandbit,
        n_prandint,
        l,
        k,
        honeybadger_protocol_timeout(),
    )
    .map_err(|e| format!("Failed to create HoneyBadger node options: {:?}", e))
}

fn validate_honeybadger_topology(n_parties: usize, threshold: usize) -> Result<(), String> {
    MpcBackendKind::HoneyBadger
        .validate_party_count(n_parties)
        .map_err(|error| error.to_string())?;
    let required = threshold
        .checked_mul(3)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| format!("HoneyBadger threshold {threshold} is too large"))?;
    if n_parties < required {
        return Err(format!(
            "HoneyBadger requires n_parties ({n_parties}) >= 3 * threshold ({threshold}) + 1 ({required})"
        ));
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honeybadger_node_opts_accepts_full_width_vm_instance_ids() {
        honeybadger_node_opts(5, 1, 0, 0, u64::from(u32::MAX) + 1)
            .expect("full-width VM instance ids must be projected into the protocol domain");
    }

    #[test]
    fn honeybadger_node_opts_requires_bft_topology() {
        let err = honeybadger_node_opts(4, 1, 0, 0, 1)
            .expect_err("HoneyBadger must reject fewer than five parties");
        assert!(
            err.contains("HoneyBadger requires at least 5 parties (got 4)"),
            "unexpected error: {err}"
        );

        honeybadger_node_opts(5, 1, 0, 0, 1)
            .expect("five parties should be accepted for HoneyBadger at threshold one");
    }

    #[test]
    fn honeybadger_protocol_instance_id_is_stable() {
        let instance_id = u64::MAX - 9;

        assert_eq!(
            honeybadger_protocol_instance_id(instance_id),
            honeybadger_protocol_instance_id(instance_id)
        );
    }

    #[test]
    fn prandint_only_opts_temporarily_fit_upstream_goldilocks_check() {
        let opts = honeybadger_node_opts_with_truncation(5, 1, 0, 2, 0, 3, 1).unwrap();
        let party_margin = 3;

        assert!(
            opts.l + opts.k + PRAND_PROTOCOL_MARGIN_BITS + party_margin
                < GOLDILOCKS_FIELD_CAPACITY_BITS
        );
        assert_eq!(opts.l, 50);
    }

    #[test]
    fn prandbit_opts_keep_fixed_point_width() {
        let opts = honeybadger_node_opts_with_truncation(5, 1, 16, 18, 16, 1, 1).unwrap();

        assert_eq!(
            opts.l,
            2 * DEFAULT_FIXED_POINT_TOTAL_BITS - DEFAULT_FIXED_POINT_FRACTIONAL_BITS
        );
    }
}
