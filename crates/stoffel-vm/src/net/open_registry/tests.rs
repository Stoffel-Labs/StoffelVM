use std::sync::Arc;

use stoffel_vm_types::core_types::ClearShareValue;

use super::wire::{MAX_WIRE_MESSAGE_LEN, OPEN_REGISTRY_WIRE_PREFIX};
use super::*;

#[test]
fn unknown_sender_single_is_rejected() {
    let router = OpenMessageRouter::new();
    let msg = encode_single_share_wire_message(1, "test-key", 0, b"share0").unwrap();
    let result = router.try_handle_wire_message(UNKNOWN_SENDER_ID, &msg);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not authenticated"));
}

#[test]
fn unknown_sender_batch_is_rejected() {
    let router = OpenMessageRouter::new();
    let msg = encode_batch_share_wire_message(1, "test-key", 0, &[b"s0".to_vec(), b"s1".to_vec()])
        .unwrap();
    let result = router.try_handle_wire_message(UNKNOWN_SENDER_ID, &msg);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not authenticated"));
}

#[test]
fn sender_mismatch_single_is_rejected() {
    let router = OpenMessageRouter::new();
    let msg = encode_single_share_wire_message(1, "test-key", 0, b"share0").unwrap();
    let result = router.try_handle_wire_message(1, &msg);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("sender mismatch"));
}

#[test]
fn sender_mismatch_batch_is_rejected() {
    let router = OpenMessageRouter::new();
    let msg = encode_batch_share_wire_message(1, "test-key", 0, &[b"s0".to_vec()]).unwrap();
    let result = router.try_handle_wire_message(1, &msg);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("sender mismatch"));
}

#[test]
fn valid_single_contribution_is_accepted() {
    let router = OpenMessageRouter::new();
    let _reg = router.register_instance(10001);
    let msg = encode_single_share_wire_message(10001, "test-key", 3, b"share3").unwrap();
    let result = router.try_handle_wire_message(3, &msg);
    assert!(result.unwrap());
}

#[test]
fn valid_batch_contribution_is_accepted() {
    let router = OpenMessageRouter::new();
    let _reg = router.register_instance(10002);
    let shares = vec![b"s0".to_vec(), b"s1".to_vec()];
    let msg = encode_batch_share_wire_message(10002, "test-batch", 5, &shares).unwrap();
    let result = router.try_handle_wire_message(5, &msg);
    assert!(result.unwrap());
}

#[test]
fn unregistered_instance_returns_false() {
    let router = OpenMessageRouter::new();
    let msg = encode_single_share_wire_message(99999999, "test-key", 0, b"share").unwrap();
    let result = router.try_handle_wire_message(0, &msg);
    assert!(!result.unwrap());
}

#[test]
fn non_prefixed_message_returns_false() {
    let router = OpenMessageRouter::new();
    let result = router.try_handle_wire_message(0, b"NOT_OPEN_MSG");
    assert!(!result.unwrap());
}

#[test]
fn oversized_payload_is_rejected() {
    let router = OpenMessageRouter::new();
    let mut msg = Vec::new();
    msg.extend_from_slice(OPEN_REGISTRY_WIRE_PREFIX);
    msg.extend(vec![0u8; MAX_WIRE_MESSAGE_LEN + 1]);
    let result = router.try_handle_wire_message(0, &msg);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("too large"));
}

#[test]
fn wire_message_roundtrip_single() {
    let encoded = encode_single_share_wire_message(42, "rt-key", 7, b"test_share").unwrap();
    assert!(encoded.starts_with(OPEN_REGISTRY_WIRE_PREFIX));
    assert!(encoded.len() < MAX_WIRE_MESSAGE_LEN + OPEN_REGISTRY_WIRE_PREFIX.len());
}

#[test]
fn wire_message_roundtrip_batch() {
    let shares = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
    let encoded = encode_batch_share_wire_message(99, "batch-rt", 2, &shares).unwrap();
    assert!(encoded.starts_with(OPEN_REGISTRY_WIRE_PREFIX));
}

#[test]
fn open_share_wait_rejects_zero_required_contributions() {
    let router = OpenMessageRouter::new();
    let reg = router.register_instance(20003);

    let err = reg
        .open_share_wait(0, "zero-required", b"s0", 0, |_| {
            Ok(ClearShareValue::Integer(0))
        })
        .unwrap_err();

    assert!(
        err.contains("requires at least one contribution"),
        "unexpected error: {err}"
    );
    assert!(reg.single.lock().is_empty());
}

#[test]
fn batch_open_wait_rejects_zero_required_contributions() {
    let router = OpenMessageRouter::new();
    let reg = router.register_instance(20004);

    let err = reg
        .batch_open_wait(0, "zero-required-batch", &[b"s0".to_vec()], 0, |_, _| {
            Ok(ClearShareValue::Integer(0))
        })
        .unwrap_err();

    assert!(
        err.contains("requires at least one contribution"),
        "unexpected error: {err}"
    );
    assert!(reg.batch.lock().is_empty());
}

#[test]
fn open_bytes_wait_returns_raw_reconstruction_result() {
    let router = OpenMessageRouter::new();
    let reg = router.register_instance(20008);

    let result = reg
        .open_bytes_wait(0, "field-open", b"raw-share", 1, |shares| {
            Ok(shares[0].clone())
        })
        .expect("field opening bytes should reconstruct");

    assert_eq!(result, b"raw-share".to_vec());
}

#[test]
fn open_share_wait_reports_missing_registry_entry_without_panicking() {
    let router = OpenMessageRouter::new();
    let reg = router.register_instance(20005);
    let reg_for_reconstruct = Arc::clone(&reg);

    let err = reg
        .open_share_wait(0, "missing-single", b"s0", 1, move |_| {
            reg_for_reconstruct.single.lock().clear();
            Ok(ClearShareValue::Integer(1))
        })
        .unwrap_err();

    assert!(
        err.contains("open_share registry entry disappeared"),
        "unexpected error: {err}"
    );
}

#[test]
fn batch_open_wait_reports_missing_registry_entry_without_panicking() {
    let router = OpenMessageRouter::new();
    let reg = router.register_instance(20006);
    let reg_for_reconstruct = Arc::clone(&reg);

    let err = reg
        .batch_open_wait(0, "missing-batch", &[b"s0".to_vec()], 1, move |_, _| {
            reg_for_reconstruct.batch.lock().clear();
            Ok(ClearShareValue::Integer(1))
        })
        .unwrap_err();

    assert!(
        err.contains("batch_open_shares registry entry disappeared"),
        "unexpected error: {err}"
    );
}

#[test]
fn exp_open_contribution_collects_and_reuses_completed_result() {
    let router = OpenMessageRouter::new();
    let reg = router.register_instance(20007);
    let mut sequence = None;

    let progress = reg
        .contribute_exp_open(ExpOpenRegistryKind::G1, &mut sequence, 0, 3, b"p0", 1)
        .unwrap();
    let ExpOpenProgress::Collected {
        sequence: seq,
        partial_points,
    } = progress
    else {
        panic!("expected collected contribution, got {progress:?}");
    };
    assert_eq!(sequence, Some(seq));
    assert_eq!(partial_points, vec![(3, b"p0".to_vec())]);

    reg.complete_exp_open(ExpOpenRegistryKind::G1, seq, b"result".to_vec())
        .unwrap();

    let ready = reg
        .contribute_exp_open(ExpOpenRegistryKind::G1, &mut sequence, 0, 3, b"ignored", 1)
        .unwrap();
    assert_eq!(ready, ExpOpenProgress::Ready(b"result".to_vec()));
}

#[test]
fn exp_open_contribution_reports_missing_registry_entry_without_panicking() {
    let router = OpenMessageRouter::new();
    let reg = router.register_instance(20008);
    let mut sequence = Some(0);

    let err = reg
        .contribute_exp_open(ExpOpenRegistryKind::G2, &mut sequence, 0, 3, b"p0", 1)
        .unwrap_err();

    assert!(
        err.contains("open-in-exponent registry entry disappeared"),
        "unexpected error: {err}"
    );
}

#[test]
fn exp_open_wait_reconstructs_and_completes_result() {
    let router = OpenMessageRouter::new();
    let reg = router.register_instance(20009);

    let result = reg
        .exp_open_wait(
            ExpOpenRequest {
                kind: ExpOpenRegistryKind::G1,
                party_id: 0,
                share_id: 3,
                partial_point: b"p0",
                required: 1,
                timeout_message: "timeout waiting for test exp open",
            },
            |partial_points| {
                assert_eq!(partial_points, &[(3, b"p0".to_vec())]);
                Ok(b"result".to_vec())
            },
        )
        .expect("single contribution should reconstruct");

    assert_eq!(result, b"result".to_vec());
    assert_eq!(
        reg.exp
            .lock()
            .get(&0)
            .and_then(|entry| entry.result.clone()),
        Some(b"result".to_vec())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_exp_insert_wakes_waiters() {
    let router = OpenMessageRouter::new();
    let reg = router.register_instance(20010);

    let reg2 = reg.clone();
    let waiter = tokio::spawn(async move {
        reg2.exp_open_async(
            ExpOpenRequest {
                kind: ExpOpenRegistryKind::G1,
                party_id: 0,
                share_id: 3,
                partial_point: b"p0",
                required: 2,
                timeout_message: "timeout waiting for test exp open",
            },
            |partial_points| {
                Ok(partial_points
                    .iter()
                    .flat_map(|(_, point)| point.clone())
                    .collect())
            },
        )
        .await
    });

    tokio::time::timeout(tokio::time::Duration::from_secs(1), async {
        loop {
            let ready = {
                let r = reg.exp.lock();
                r.get(&0).is_some_and(|entry| entry.party_ids == vec![0])
            };
            if ready {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first exp contribution should be registered");

    let reg3 = reg.clone();
    let finalizer = tokio::spawn(async move {
        reg3.exp_open_async(
            ExpOpenRequest {
                kind: ExpOpenRegistryKind::G1,
                party_id: 1,
                share_id: 4,
                partial_point: b"p1",
                required: 2,
                timeout_message: "timeout waiting for test exp open",
            },
            |partial_points| {
                Ok(partial_points
                    .iter()
                    .flat_map(|(_, point)| point.clone())
                    .collect())
            },
        )
        .await
    });

    let (waiter, finalizer) = tokio::time::timeout(tokio::time::Duration::from_secs(1), async {
        tokio::join!(waiter, finalizer)
    })
    .await
    .expect("exp open waiters should be notified by local insertion");

    assert_eq!(waiter.unwrap().unwrap(), b"p0p1".to_vec());
    assert_eq!(finalizer.unwrap().unwrap(), b"p0p1".to_vec());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_single_insert_wakes_waiters() {
    let router = OpenMessageRouter::new();
    let reg = router.register_instance(20001);

    let reg2 = reg.clone();
    let waiter = tokio::spawn(async move {
        reg2.open_share_async(
            0,
            "single-notify".to_string(),
            b"s0".to_vec(),
            2,
            |shares| Ok(ClearShareValue::Integer(shares.len() as i64)),
        )
        .await
    });

    // Wait for first contribution to be registered
    tokio::time::timeout(tokio::time::Duration::from_secs(1), async {
        loop {
            let ready = {
                let r = reg.single.lock();
                r.get(&(0usize, "single-notify".to_string()))
                    .is_some_and(|entry| entry.party_ids == vec![0])
            };
            if ready {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first single contribution should be registered");

    let reg3 = reg.clone();
    let finalizer = tokio::spawn(async move {
        reg3.open_share_async(
            1,
            "single-notify".to_string(),
            b"s1".to_vec(),
            2,
            |shares| Ok(ClearShareValue::Integer(shares.len() as i64)),
        )
        .await
    });

    let (waiter, finalizer) = tokio::time::timeout(tokio::time::Duration::from_secs(1), async {
        tokio::join!(waiter, finalizer)
    })
    .await
    .expect("single open waiters should be notified by local insertion");

    assert_eq!(waiter.unwrap().unwrap(), ClearShareValue::Integer(2));
    assert_eq!(finalizer.unwrap().unwrap(), ClearShareValue::Integer(2));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_batch_insert_wakes_waiters() {
    let router = OpenMessageRouter::new();
    let reg = router.register_instance(20002);

    let reg2 = reg.clone();
    let waiter = tokio::spawn(async move {
        reg2.batch_open_async(
            0,
            "batch-notify".to_string(),
            vec![b"a0".to_vec(), b"b0".to_vec()],
            2,
            |shares, _pos| Ok(ClearShareValue::Integer(shares.len() as i64)),
        )
        .await
    });

    tokio::time::timeout(tokio::time::Duration::from_secs(1), async {
        loop {
            let ready = {
                let r = reg.batch.lock();
                r.get(&(0usize, "batch-notify".to_string(), 2usize))
                    .is_some_and(|entry| entry.party_ids == vec![0])
            };
            if ready {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first batch contribution should be registered");

    let reg3 = reg.clone();
    let finalizer = tokio::spawn(async move {
        reg3.batch_open_async(
            1,
            "batch-notify".to_string(),
            vec![b"a1".to_vec(), b"b1".to_vec()],
            2,
            |shares, _pos| Ok(ClearShareValue::Integer(shares.len() as i64)),
        )
        .await
    });

    let (waiter, finalizer) = tokio::time::timeout(tokio::time::Duration::from_secs(1), async {
        tokio::join!(waiter, finalizer)
    })
    .await
    .expect("batch open waiters should be notified by local insertion");

    assert_eq!(
        waiter.unwrap().unwrap(),
        vec![ClearShareValue::Integer(2), ClearShareValue::Integer(2)]
    );
    assert_eq!(
        finalizer.unwrap().unwrap(),
        vec![ClearShareValue::Integer(2), ClearShareValue::Integer(2)]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_instances_are_isolated() {
    let router = OpenMessageRouter::new();
    let reg_a = router.register_instance(30001);
    let reg_b = router.register_instance(30002);

    // Insert into instance A
    reg_a.insert_single("key", 0, b"share_a".to_vec());
    // Insert into instance B
    reg_b.insert_single("key", 0, b"share_b".to_vec());

    // Verify isolation
    let a_count = reg_a
        .single
        .lock()
        .get(&(0, "key".to_string()))
        .unwrap()
        .shares
        .len();
    let b_count = reg_b
        .single
        .lock()
        .get(&(0, "key".to_string()))
        .unwrap()
        .shares
        .len();
    assert_eq!(a_count, 1);
    assert_eq!(b_count, 1);
}
