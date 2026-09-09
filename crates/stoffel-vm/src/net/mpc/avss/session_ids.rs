use ark_ff::PrimeField;
use std::sync::atomic::{AtomicU64, Ordering};
use stoffelmpc_mpc::avss_mpc::{AvssSessionId, ProtocolType as AvssProtocolType};
use stoffelmpc_mpc::common::ProtocolSessionId;

use crate::net::mpc::protocol_ids::derive_protocol_instance_id_u32;

pub(super) struct AvssSessionIds {
    instance_id: AtomicU64,
    party_id: usize,
    local_counter: AtomicU64,
}

impl AvssSessionIds {
    pub fn new(instance_id: u64, party_id: usize, _n_parties: usize) -> Self {
        Self {
            instance_id: AtomicU64::new(instance_id),
            party_id,
            local_counter: AtomicU64::new(0),
        }
    }

    pub fn reset(&self, instance_id: u64) {
        self.instance_id.store(instance_id, Ordering::SeqCst);
        self.local_counter.store(0, Ordering::SeqCst);
    }

    pub fn next_dealer_session(&self) -> Result<AvssSessionId, String> {
        let counter = next_u16_domain_counter(&self.local_counter, "AVSS local session counter")?;
        allocate_local_avss_session(
            self.instance_id.load(Ordering::SeqCst),
            self.party_id,
            counter,
        )
    }
}

pub(super) fn protocol_instance_id_u32(instance_id: u64) -> u32 {
    derive_protocol_instance_id_u32(b"avss", instance_id)
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

fn allocate_local_avss_session(
    instance_id: u64,
    dealer_id: usize,
    counter: u64,
) -> Result<AvssSessionId, String> {
    let counter16 = u16::try_from(counter)
        .map_err(|_| "AVSS local session counter overflowed u16".to_string())?;
    let instance_id = protocol_instance_id_u32(instance_id);
    let dealer_id = u8_domain_value(dealer_id, "AVSS dealer id")?;
    let exec_id = u8::try_from(counter16 >> 8)
        .map_err(|_| "AVSS session exec counter exceeds u8::MAX".to_string())?;
    let round_id = u8::try_from(counter16 & 0x00ff)
        .map_err(|_| "AVSS session round counter exceeds u8::MAX".to_string())?;
    let slot = AvssSessionId::pack_slot(u64::from(exec_id), dealer_id, round_id);
    Ok(AvssSessionId::new(
        AvssProtocolType::Avss,
        slot,
        instance_id,
    ))
}

fn next_u16_domain_counter(counter: &AtomicU64, context: &'static str) -> Result<u64, String> {
    let mut current = counter.load(Ordering::SeqCst);
    loop {
        let next = current
            .checked_add(1)
            .filter(|_| current <= u64::from(u16::MAX))
            .ok_or_else(|| format!("{context} exhausted u16 session slot domain"))?;
        match counter.compare_exchange_weak(current, next, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(previous) => return Ok(previous),
            Err(observed) => current = observed,
        }
    }
}

fn u8_domain_value(value: usize, field: &'static str) -> Result<u8, String> {
    u8::try_from(value).map_err(|_| {
        format!(
            "{field} {value} exceeds u8::MAX required by AvssSessionId::sub_id dealer validation"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dealer_session_encodes_party_id_as_sub_id() {
        let sessions = AvssSessionIds::new(1, 2, 4);
        let sid = sessions.next_dealer_session().expect("dealer session");

        assert_eq!(sid.sub_id(), 2);
        assert_eq!(sid.exec_id(), 0);
        assert_eq!(sid.round_id(), 0);
    }

    #[test]
    fn session_identity_uses_full_instance_domain() {
        let low_instance = AvssSessionIds::new(1, 2, 4)
            .next_dealer_session()
            .expect("low instance session");
        let high_instance = AvssSessionIds::new(257, 2, 4)
            .next_dealer_session()
            .expect("high instance session");

        assert_ne!(
            low_instance.as_u128(),
            high_instance.as_u128(),
            "full session id must include instance ids that differ outside low slot bits"
        );
    }

    #[test]
    fn protocol_instance_id_accepts_full_width_values() {
        let instance_id = u64::from(u32::MAX) + 1;

        assert_eq!(
            protocol_instance_id_u32(instance_id),
            protocol_instance_id_u32(instance_id)
        );
    }

    #[test]
    fn reset_rotates_instance_and_restarts_local_counter() {
        let sessions = AvssSessionIds::new(1, 2, 4);
        let first = sessions.next_dealer_session().expect("first session");

        sessions.reset(9);
        let after_reset = sessions.next_dealer_session().expect("reset session");

        assert_ne!(first.as_u128(), after_reset.as_u128());
        assert_eq!(after_reset.exec_id(), 0);
        assert_eq!(after_reset.round_id(), 0);
        assert_eq!(after_reset.sub_id(), 2);
    }

    #[test]
    fn session_allocation_rejects_dealers_outside_protocol_sub_id_domain() {
        let sessions = AvssSessionIds::new(1, usize::from(u8::MAX) + 1, 300);

        let err = sessions
            .next_dealer_session()
            .expect_err("dealer ids outside u8 must be rejected");
        assert!(
            err.contains("exceeds u8::MAX"),
            "expected u8 dealer domain error, got: {err}"
        );
    }
}
