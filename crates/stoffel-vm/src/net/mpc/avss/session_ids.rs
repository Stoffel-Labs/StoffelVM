use ark_ff::PrimeField;
use std::sync::atomic::{AtomicU64, Ordering};
use stoffelmpc_mpc::avss_mpc::{AvssSessionId, ProtocolType as AvssProtocolType};
use stoffelmpc_mpc::common::ProtocolSessionId;

use crate::net::mpc::protocol_ids::derive_protocol_instance_id_u32;

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
        allocate_local_avss_session(self.instance_id, self.party_id, counter)
    }

    pub fn next_input_share_session(&self) -> Result<(usize, AvssSessionId), String> {
        if self.n_parties == 0 {
            return Err("AVSS input-share session allocation requires at least one party".into());
        }

        let round = next_u16_domain_counter(
            &self.input_share_counter,
            "AVSS input-share session counter",
        )?;
        let dealer_id = usize::try_from(round)
            .map_err(|_| format!("AVSS input share round {round} exceeds usize::MAX"))?
            % self.n_parties;
        Ok((
            dealer_id,
            allocate_local_avss_session(self.instance_id, dealer_id, round)?,
        ))
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
    let slot24 = AvssSessionId::pack_slot24(exec_id, dealer_id, round_id);
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
            low_instance.as_u64(),
            high_instance.as_u64(),
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
        assert_eq!(
            sid0.sub_id() as usize,
            dealer0,
            "session sub_id must identify the input-share dealer"
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
        assert_eq!(
            sid0_next.sub_id() as usize,
            dealer0_next,
            "session sub_id must track the input-share dealer each round"
        );
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
