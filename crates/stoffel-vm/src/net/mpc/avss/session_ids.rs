use ark_ff::PrimeField;
use std::sync::atomic::{AtomicU64, Ordering};
use stoffelmpc_mpc::avss_mpc::{AvssSessionId, ProtocolType as AvssProtocolType};
use stoffelmpc_mpc::common::ProtocolSessionId;

pub(super) struct AvssSessionIds {
    instance_id: u64,
    party_id: usize,
    n_parties: usize,
    local_counter: AtomicU64,
    input_share_counter: AtomicU64,
}

impl AvssSessionIds {
    pub fn new(instance_id: u64, party_id: usize, n_parties: usize) -> Self {
        Self {
            instance_id,
            party_id,
            n_parties,
            local_counter: AtomicU64::new(0),
            input_share_counter: AtomicU64::new(0),
        }
    }

    pub fn next_dealer_session(&self) -> Result<AvssSessionId, String> {
        let counter = next_u16_domain_counter(&self.local_counter, "AVSS local session counter")?;
        let slot24 = derive_session_slot24(self.instance_id, self.party_id)?;
        allocate_local_avss_session(self.instance_id, slot24, counter)
    }

    pub fn next_input_share_session(&self) -> Result<(usize, AvssSessionId), String> {
        let round = next_u16_domain_counter(
            &self.input_share_counter,
            "AVSS input-share session counter",
        )?;
        let dealer_id = usize::try_from(round)
            .map_err(|_| format!("AVSS input share round {round} exceeds usize::MAX"))?
            % self.n_parties.max(1);
        let slot24 = derive_input_share_slot24(self.instance_id, dealer_id)?;
        Ok((
            dealer_id,
            allocate_local_avss_session(self.instance_id, slot24, round)?,
        ))
    }
}

pub(super) fn protocol_instance_id_u32(instance_id: u64) -> Result<u32, String> {
    u32::try_from(instance_id).map_err(|_| {
        format!("AVSS instance_id {instance_id} exceeds u32::MAX required by AvssSessionId")
    })
}

pub(super) fn usize_seed(value: usize, field: &'static str) -> Result<u64, String> {
    u64::try_from(value).map_err(|_| format!("{field} {value} exceeds u64::MAX"))
}

pub(super) fn field_from_usize<F: PrimeField>(
    value: usize,
    field: &'static str,
) -> Result<F, String> {
    Ok(F::from(usize_seed(value, field)?))
}

pub(super) fn derive_session_slot24(instance_id: u64, party_id: usize) -> Result<u32, String> {
    let seed = instance_id ^ usize_seed(party_id, "party_id")?.rotate_left(17);
    slot24_from_seed(seed)
}

fn derive_input_share_slot24(instance_id: u64, dealer_id: usize) -> Result<u32, String> {
    let seed =
        instance_id ^ usize_seed(dealer_id, "dealer_id")?.rotate_left(29) ^ 0x4953_4841_5245_5f53; // "ISHARE_S"
    slot24_from_seed(seed)
}

fn allocate_local_avss_session(
    instance_id: u64,
    slot24_seed: u32,
    counter: u64,
) -> Result<AvssSessionId, String> {
    let counter16 = u16::try_from(counter)
        .map_err(|_| "AVSS local session counter overflowed u16".to_string())?;
    let instance_id = protocol_instance_id_u32(instance_id)?;
    let slot24 = (slot24_seed & 0x00ff_0000) | u32::from(counter16);
    Ok(AvssSessionId::new(
        AvssProtocolType::Avss,
        slot24,
        instance_id,
    ))
}

fn next_u16_domain_counter(counter: &AtomicU64, context: &'static str) -> Result<u64, String> {
    counter
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
            if current <= u64::from(u16::MAX) {
                current.checked_add(1)
            } else {
                None
            }
        })
        .map_err(|_| format!("{context} exhausted u16 session slot domain"))
}

#[inline]
fn mix64(mut x: u64) -> u64 {
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    x ^= x >> 33;
    x
}

#[inline]
fn slot24_from_seed(seed: u64) -> Result<u32, String> {
    let slot = mix64(seed) & 0x00ff_ffff;
    u32::try_from(slot).map_err(|_| format!("derived AVSS slot {slot} exceeds u32::MAX"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_slot24_uses_full_instance_party_domains() {
        let base = derive_session_slot24(1, 2).expect("base slot");
        let high_bits_changed = derive_session_slot24(257, 258).expect("high-bit slot");
        let very_high_bits_changed =
            derive_session_slot24(1u64 << 40, 2).expect("very-high-bit slot");

        assert_ne!(
            base, high_bits_changed,
            "slot24 must not collapse instance/party IDs that differ outside low 8 bits"
        );
        assert_ne!(
            base, very_high_bits_changed,
            "slot24 must include high instance-id bits in domain separation"
        );
    }

    #[test]
    fn protocol_instance_id_rejects_values_outside_u32_domain() {
        let err = protocol_instance_id_u32(u64::from(u32::MAX) + 1)
            .expect_err("oversized instance ids must be rejected");
        assert!(
            err.contains("exceeds u32::MAX"),
            "expected u32 overflow error, got: {err}"
        );
    }

    #[test]
    fn input_share_session_allocation_is_consistent_across_parties() {
        let first = AvssSessionIds::new(77, 0, 4);
        let second = AvssSessionIds::new(77, 1, 4);

        let (dealer0, sid0) = first.next_input_share_session().expect("session0");
        let (dealer1, sid1) = second.next_input_share_session().expect("session1");
        assert_eq!(dealer0, dealer1, "dealer selection must be deterministic");
        assert_eq!(
            sid0.as_u64(),
            sid1.as_u64(),
            "session ids must match across parties for the same input_share round"
        );

        let (dealer0_next, sid0_next) = first.next_input_share_session().expect("session0-next");
        let (dealer1_next, sid1_next) = second.next_input_share_session().expect("session1-next");
        assert_eq!(
            dealer0_next, dealer1_next,
            "dealer selection must stay aligned across rounds"
        );
        assert_eq!(
            sid0_next.as_u64(),
            sid1_next.as_u64(),
            "session ids must stay aligned across rounds"
        );
    }
}
