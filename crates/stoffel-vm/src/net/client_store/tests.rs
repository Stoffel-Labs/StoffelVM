use super::*;
#[cfg(any(feature = "honeybadger", feature = "avss"))]
use ark_bls12_381::Fr;
#[cfg(feature = "avss")]
use ark_bls12_381::G1Projective as G1;
use std::num::NonZeroUsize;
use stoffel_vm_types::core_types::{ShareData, ShareType};
#[cfg(feature = "avss")]
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
#[cfg(any(feature = "honeybadger", feature = "avss"))]
use stoffelmpc_mpc::common::SecretSharingScheme;
#[cfg(feature = "honeybadger")]
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;

#[test]
fn client_input_hydration_count_is_zero_allowing_domain_count() {
    let zero = ClientInputHydrationCount::zero();
    let two = ClientInputHydrationCount::new(2);

    assert_eq!(zero.count(), 0);
    assert!(zero.is_zero());
    assert_eq!(two.count(), 2);
    assert_eq!(usize::from(two), 2);
    assert_eq!(ClientInputHydrationCount::from(3).to_string(), "3");
}

#[test]
fn client_output_share_count_rejects_zero() {
    assert_eq!(ClientOutputShareCount::one().count(), 1);
    assert_eq!(
        ClientOutputShareCount::new(NonZeroUsize::new(2).unwrap()).count(),
        2
    );
    assert!(ClientOutputShareCount::try_new(0).is_err());
}

#[test]
#[cfg(feature = "honeybadger")]
fn test_store_and_retrieve() {
    let store = ClientInputStore::new();
    let client_id = 42;

    let secret = Fr::from(100u64);
    let mut rng = ark_std::test_rng();
    let shares = RobustShare::compute_shares(secret, 5, 1, None, &mut rng).unwrap();

    let stored_count = store
        .try_store_client_input(client_id, shares.clone())
        .expect("robust shares should serialize");
    assert_eq!(stored_count, shares.len());

    assert!(store.has_client_input(client_id));
    assert_eq!(store.get_client_input_count(client_id), shares.len());

    let retrieved: Vec<RobustShare<Fr>> = store.get_client_input(client_id).unwrap();
    assert_eq!(retrieved.len(), shares.len());
}

#[test]
#[cfg(feature = "honeybadger")]
fn replace_client_input_replaces_existing_entries() {
    let store = ClientInputStore::new();
    let mut rng = ark_std::test_rng();
    let old_shares = RobustShare::compute_shares(Fr::from(100u64), 3, 1, None, &mut rng)
        .expect("old robust shares");
    let new_shares = RobustShare::compute_shares(Fr::from(200u64), 3, 1, None, &mut rng)
        .expect("new robust shares");

    store
        .try_store_client_input(1, old_shares)
        .expect("store old client inputs");
    let stored_count = store
        .try_replace_client_input([(2, new_shares.clone())])
        .expect("replace client inputs");

    assert_eq!(stored_count, new_shares.len());
    assert!(!store.has_client_input(1));
    assert!(store.has_client_input(2));
    let retrieved: Vec<RobustShare<Fr>> = store.get_client_input(2).expect("new client shares");
    assert_eq!(retrieved.len(), new_shares.len());
}

#[test]
#[cfg(feature = "honeybadger")]
fn test_get_specific_share() {
    let store = ClientInputStore::new();
    let client_id = 99;

    let secret = Fr::from(200u64);
    let mut rng = ark_std::test_rng();
    let shares = RobustShare::compute_shares(secret, 3, 1, None, &mut rng).unwrap();

    store.store_client_input(client_id, shares.clone());

    let share_1: RobustShare<Fr> = store
        .get_client_share(client_id, ClientShareIndex::new(1))
        .unwrap();
    assert_eq!(share_1.share, shares[1].share);
}

#[test]
#[cfg(feature = "avss")]
fn test_store_and_retrieve_feldman() {
    let store = ClientInputStore::new();
    let client_id = 55;

    let secret = Fr::from(42u64);
    let mut rng = ark_std::test_rng();
    let ids: Vec<usize> = (1..=5).collect();
    let shares =
        FeldmanShamirShare::<Fr, G1>::compute_shares(secret, 5, 1, Some(&ids), &mut rng).unwrap();

    let stored_count = store
        .try_store_client_input_feldman(client_id, shares.clone())
        .expect("Feldman shares should serialize");
    assert_eq!(stored_count, shares.len());

    assert!(store.has_client_input(client_id));
    assert_eq!(store.get_client_input_count(client_id), shares.len());
    let stored_payload = store
        .get_client_share_data(client_id, ClientShareIndex::new(0))
        .expect("stored Feldman share");
    match stored_payload.data() {
        ShareData::Feldman { commitments, .. } => {
            assert!(!commitments.is_empty(), "commitments must be preserved");
        }
        other => panic!("expected Feldman share data, got {other:?}"),
    }

    let retrieved: Vec<FeldmanShamirShare<Fr, G1>> =
        store.get_client_input_feldman(client_id).unwrap();
    assert_eq!(retrieved.len(), shares.len());

    let single: FeldmanShamirShare<Fr, G1> = store
        .get_client_share_feldman(client_id, ClientShareIndex::new(0))
        .unwrap();
    assert_eq!(single.feldmanshare.share, shares[0].feldmanshare.share);
}

#[test]
fn test_list_and_clear() {
    let store = ClientInputStore::new();

    store.store_client_input_bytes(1, vec![]);
    store.store_client_input_bytes(2, vec![]);
    store.store_client_input_bytes(3, vec![]);

    assert_eq!(store.len(), 3);
    assert_eq!(store.client_id_at(ClientInputIndex::new(0)), Some(1));
    assert_eq!(store.client_id_at(ClientInputIndex::new(1)), Some(2));
    let clients = store.list_clients();
    assert!(clients.contains(&1));
    assert!(clients.contains(&2));
    assert!(clients.contains(&3));

    store.clear();
    assert_eq!(store.len(), 0);
    assert!(store.is_empty());
}

#[test]
fn client_share_metadata_round_trips_without_flattening_to_bytes() {
    let store = ClientInputStore::new();
    let share_type = ShareType::default_secret_fixed_point();
    let share_data = ShareData::Feldman {
        data: vec![1, 2, 3],
        commitments: vec![vec![9, 8], vec![7, 6]],
    };

    store.store_client_shares(7, vec![ClientShare::typed(share_type, share_data.clone())]);

    let stored = store
        .get_client_share_data(7, ClientShareIndex::new(0))
        .expect("stored share");
    assert_eq!(stored.share_type(), Some(share_type));
    assert_eq!(stored.data(), &share_data);
    assert_eq!(
        store.get_client_share_bytes(7, ClientShareIndex::new(0)),
        Some(vec![1, 2, 3])
    );
    assert_eq!(
        store
            .get_client_share_data(7, ClientShareIndex::new(0))
            .expect("typed-index share")
            .data(),
        &share_data
    );
}
