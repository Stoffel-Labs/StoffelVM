use super::{HoneyBadgerEngineConfig, HoneyBadgerMpcEngine, HoneyBadgerPreprocessingConfig};
use crate::net::engine_config::MpcSessionConfig;
use crate::net::mpc_engine::{MpcEngineConsensus, MpcPartyId};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use stoffelnet::transports::quic::QuicNetworkManager;

fn next_instance_id() -> u64 {
    static NEXT_INSTANCE_ID: AtomicU64 = AtomicU64::new(1_000_000);
    NEXT_INSTANCE_ID.fetch_add(1, Ordering::Relaxed)
}

fn test_engine(
    open_message_router: Arc<crate::net::open_registry::OpenMessageRouter>,
    instance_id: u64,
    party_id: usize,
    n: usize,
    t: usize,
) -> Arc<HoneyBadgerMpcEngine<ark_bls12_381::Fr, ark_bls12_381::G1Projective>> {
    let session = MpcSessionConfig::try_new(
        instance_id,
        party_id,
        n,
        t,
        Arc::new(QuicNetworkManager::new()),
    )
    .expect("test topology should be valid")
    .with_open_message_router(open_message_router);
    let config = HoneyBadgerEngineConfig::new(session, HoneyBadgerPreprocessingConfig::new(1, 1));
    HoneyBadgerMpcEngine::<ark_bls12_381::Fr, ark_bls12_381::G1Projective>::from_config(config)
        .expect("engine construction should succeed")
}

fn open_exp_test_payload(
    instance_id: u64,
    sender_party_id: usize,
    share_id: usize,
    partial_point: Vec<u8>,
) -> Vec<u8> {
    crate::net::open_registry::encode_hb_open_exp_wire_message(
        instance_id,
        sender_party_id,
        share_id,
        &partial_point,
    )
    .expect("serialize test payload")
}

#[test]
fn aba_same_round_uses_shared_session_and_converges() {
    let instance_id = next_instance_id();
    let n = 4;
    let t = 1;
    let router = Arc::new(crate::net::open_registry::OpenMessageRouter::new());
    let e0 = test_engine(router.clone(), instance_id, 0, n, t);
    let e1 = test_engine(router.clone(), instance_id, 1, n, t);
    let e2 = test_engine(router.clone(), instance_id, 2, n, t);
    let e3 = test_engine(router, instance_id, 3, n, t);

    let s0 = e0.aba_propose(true).expect("party 0 propose");
    let s1 = e1.aba_propose(true).expect("party 1 propose");
    let s2 = e2.aba_propose(true).expect("party 2 propose");
    let s3 = e3.aba_propose(true).expect("party 3 propose");

    assert_eq!(s0, s1, "same ABA round must share one session id");
    assert_eq!(s1, s2, "same ABA round must share one session id");
    assert_eq!(s2, s3, "same ABA round must share one session id");

    let r0 = e0.aba_result(s0, 50).expect("party 0 agreement");
    let r1 = e1.aba_result(s1, 50).expect("party 1 agreement");
    let r2 = e2.aba_result(s2, 50).expect("party 2 agreement");
    let r3 = e3.aba_result(s3, 50).expect("party 3 agreement");

    assert!(r0 && r1 && r2 && r3, "all parties should decide true");
}

#[test]
fn rbc_receive_delivers_new_broadcast_each_call_in_order() {
    let instance_id = next_instance_id();
    let n = 4;
    let t = 1;
    let router = Arc::new(crate::net::open_registry::OpenMessageRouter::new());
    let sender = test_engine(router.clone(), instance_id, 0, n, t);
    let receiver = test_engine(router, instance_id, 1, n, t);

    sender.rbc_broadcast(b"first").expect("broadcast first");
    sender.rbc_broadcast(b"second").expect("broadcast second");

    let first = receiver
        .rbc_receive(MpcPartyId::new(0), 50)
        .expect("receive first");
    let second = receiver
        .rbc_receive(MpcPartyId::new(0), 50)
        .expect("receive second");

    assert_eq!(
        first, b"first",
        "first receive should return first broadcast"
    );
    assert_eq!(
        second, b"second",
        "second receive should return second broadcast"
    );
}

#[test]
fn open_exp_wire_rejects_mismatched_share_id() {
    let instance_id = next_instance_id();
    let router = crate::net::open_registry::OpenMessageRouter::new();
    let registry = router.register_instance(instance_id);
    let payload = open_exp_test_payload(instance_id, 1, 0, vec![1, 2, 3, 4]);

    let err = router
        .try_handle_hb_open_exp_wire_message(1, &payload)
        .expect_err("mismatched share_id must be rejected");
    assert!(
        err.contains("open-exp share_id mismatch"),
        "unexpected error: {}",
        err
    );
    assert!(
        !registry.exp.lock().contains_key(&0),
        "rejected payload must not be inserted into the registry"
    );
}

#[test]
fn open_exp_wire_accepts_matching_share_id() {
    let instance_id = next_instance_id();
    let router = crate::net::open_registry::OpenMessageRouter::new();
    let registry = router.register_instance(instance_id);
    let payload = open_exp_test_payload(instance_id, 1, 1, vec![9, 8, 7, 6]);

    let handled = router
        .try_handle_hb_open_exp_wire_message(1, &payload)
        .expect("matching sender/share is valid");
    assert!(handled, "open-exp prefix payload must be handled");

    let reg = registry.exp.lock();
    let entry = reg
        .get(&0)
        .expect("entry should be inserted for valid payload");
    assert_eq!(entry.party_ids, vec![1]);
    assert_eq!(entry.partial_points, vec![(1, vec![9, 8, 7, 6])]);
}
