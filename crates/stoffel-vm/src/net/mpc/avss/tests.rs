use super::*;
use crate::net::curve::SupportedMpcField;
use crate::net::mpc_engine::{DurableIdentityDigest, MpcEngine};
use crate::net::session::ExecutionId;
use crate::storage::preproc::{
    self, LmdbPreprocStore, OwnedPreprocBundle, PreprocBlob, PreprocKeyScope, PreprocStore,
    TakenPreproc,
};
use ark_bls12_381::{Fr, G1Projective as G1, G2Projective as G2};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{FftField, PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::test_rng;
use std::sync::Arc;
use stoffel_vm_types::core_types::{ClearShareValue, ShareType, F64};
use stoffelmpc_mpc::avss_mpc::triple_gen::BeaverTriple;
use stoffelmpc_mpc::common::share::avss::verify_feldman;
use stoffelmpc_mpc::common::ProtocolSessionId;
use stoffelnet::transports::quic::QuicNetworkManager;

#[tokio::test]
async fn avss_named_config_installs_execution_scoped_protocol_network() {
    let n = 4;
    let t = 1;
    let execution_id = ExecutionId::from_bytes([0xA5; 32]);
    let session =
        MpcSessionConfig::try_new(0x1122_3344, 0, n, t, Arc::new(QuicNetworkManager::new()))
            .unwrap()
            .try_with_execution_id(execution_id)
            .unwrap();
    let engine = AvssMpcEngine::<Fr, G1>::from_config(AvssEngineConfig::new(
        session,
        Fr::from(9u64),
        Arc::new(vec![G1::generator(); n]),
    ))
    .await
    .unwrap();

    assert_eq!(engine.protocol_net().execution_id(), execution_id);
}

#[tokio::test]
async fn await_received_share_selects_the_exact_session_from_the_same_dealer() {
    let n = 4;
    let t = 1;
    let instance_id = 0x1122_4455;
    let session =
        MpcSessionConfig::try_new(instance_id, 3, n, t, Arc::new(QuicNetworkManager::new()))
            .unwrap();
    let engine = AvssMpcEngine::<Fr, G1>::from_config(AvssEngineConfig::new(
        session,
        Fr::from(9u64),
        Arc::new(vec![G1::generator(); n]),
    ))
    .await
    .unwrap();

    let wrong_dealer_share = generate_feldman_shares(Fr::from(111u64), n, t)[3].clone();
    let expected_dealer_share = generate_feldman_shares(Fr::from(222u64), n, t)[3].clone();
    let dealer_sessions = AvssSessionIds::new(instance_id, 2, n);
    let wrong_session = dealer_sessions.next_dealer_session().unwrap();
    let expected_session = dealer_sessions.next_dealer_session().unwrap();
    let node = engine.clone_avss_node().await;
    let mut received = node.share_gen_avss.avss.shares.lock().await;
    received.insert(
        wrong_session,
        (std::time::Instant::now(), Some(vec![wrong_dealer_share])),
    );
    received.insert(
        expected_session,
        (
            std::time::Instant::now(),
            Some(vec![expected_dealer_share.clone()]),
        ),
    );
    drop(received);

    let selected = engine
        .await_received_share("expected-key", expected_session.as_u128())
        .await
        .expect("the requested dealer share is already available");
    assert_eq!(
        selected.feldmanshare.share,
        expected_dealer_share.feldmanshare.share
    );
}

#[test]
fn upstream_ransha_commitment_transform_produces_verifiable_ed25519_shares() {
    use ark_ed25519::{EdwardsProjective, Fr as EdFr};
    use ark_ff::Zero;
    use stoffelmpc_mpc::common::share::{apply_vandermonde, make_vandermonde};
    use stoffelmpc_mpc::common::SecretSharingScheme;

    let n = 5;
    let t = 1;
    let receiver_index = 0;
    let ids: Vec<_> = (1..=n).collect();
    let mut rng = test_rng();

    let mut shares_deg_t = Vec::with_capacity(n);
    for _ in 0..n {
        let secret = EdFr::rand(&mut rng);
        let shares = FeldmanShamirShare::<EdFr, EdwardsProjective>::compute_shares(
            secret,
            n,
            t,
            Some(&ids),
            &mut rng,
        )
        .expect("compute Feldman shares");
        shares_deg_t.push(shares[receiver_index].clone());
    }

    let shares = shares_deg_t
        .iter()
        .map(|share| share.feldmanshare.clone())
        .collect::<Vec<_>>();
    let vandermonde_matrix = make_vandermonde::<EdFr>(n, n - 1).expect("make Vandermonde matrix");
    let r_deg_t = apply_vandermonde(&vandermonde_matrix, &shares).expect("apply Vandermonde");

    let mut computed = Vec::with_capacity(n);
    for k in 0..n {
        let mut commitments = vec![EdwardsProjective::zero(); t + 1];
        for i in 0..n {
            let factor = vandermonde_matrix[k][i];
            for (dst, src) in commitments
                .iter_mut()
                .zip(shares_deg_t[i].commitments.iter())
            {
                *dst += *src * factor;
            }
        }
        computed.push(FeldmanShamirShare {
            feldmanshare: r_deg_t[k].clone(),
            commitments,
        });
    }

    for share in &computed[2 * t..] {
        assert!(verify_feldman(share.clone(), share.feldmanshare.id));
    }
}

#[test]
fn test_feldman_share_serialization() {
    let mut rng = test_rng();

    // Create a Feldman share manually for testing
    let share_value = Fr::rand(&mut rng);
    let degree = 2;
    let commitments: Vec<G1> = (0..=degree)
        .map(|_| G1::generator() * Fr::rand(&mut rng))
        .collect();

    let share = FeldmanShamirShare::new(share_value, 1, degree, commitments.clone())
        .expect("Failed to create FeldmanShamirShare");

    // Test serialization roundtrip
    let bytes = Bls12381AvssMpcEngine::encode_feldman_share(&share).expect("Serialization failed");
    assert!(!bytes.is_empty());

    let restored =
        Bls12381AvssMpcEngine::decode_feldman_share(&bytes).expect("Deserialization failed");
    assert_eq!(restored.commitments.len(), share.commitments.len());
    assert_eq!(restored.feldmanshare.id, share.feldmanshare.id);
    assert_eq!(restored.feldmanshare.share, share.feldmanshare.share);
}

#[test]
fn test_bn254_feldman_share_serialization() {
    use ark_bn254::{Fr as BnFr, G1Projective as BnG1};

    let mut rng = test_rng();
    let share_value = BnFr::rand(&mut rng);
    let degree = 2;
    let commitments: Vec<BnG1> = (0..=degree)
        .map(|_| <BnG1 as PrimeGroup>::generator() * BnFr::rand(&mut rng))
        .collect();

    let share = FeldmanShamirShare::new(share_value, 1, degree, commitments.clone())
        .expect("Failed to create FeldmanShamirShare");

    let bytes = Bn254AvssMpcEngine::encode_feldman_share(&share).expect("Serialization failed");
    assert!(!bytes.is_empty());

    let restored =
        Bn254AvssMpcEngine::decode_feldman_share(&bytes).expect("Deserialization failed");
    assert_eq!(restored.commitments.len(), share.commitments.len());
    assert_eq!(restored.feldmanshare.id, share.feldmanshare.id);
    assert_eq!(restored.feldmanshare.share, share.feldmanshare.share);
}

#[test]
fn test_public_key_extraction() {
    let mut rng = test_rng();

    // The secret
    let secret = Fr::rand(&mut rng);

    // commitment[0] = g^secret = the public key
    let public_key = G1::generator() * secret;

    // Create Feldman share with this commitment
    let share_value = Fr::rand(&mut rng);
    let degree = 2;
    let mut commitments = vec![public_key]; // commitment[0] = g^secret
    for _ in 1..=degree {
        commitments.push(G1::generator() * Fr::rand(&mut rng));
    }

    let share = FeldmanShamirShare::new(share_value, 1, degree, commitments)
        .expect("Failed to create FeldmanShamirShare");

    // Verify public key extraction from commitment[0]
    assert_eq!(share.commitments[0], public_key);
}

#[test]
fn test_feldman_verification() {
    let mut rng = test_rng();
    let n = 4;
    let t = 1;
    let secret = Fr::from(12345u64);

    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
    let mut poly = DensePolynomial::rand(t, &mut rng);
    poly[0] = secret;

    let commitments: Vec<G1> = poly.coeffs.iter().map(|c| G1::generator() * c).collect();

    for i in 1..=n {
        let x = Fr::from(i as u64);
        let y = poly.evaluate(&x);

        let share =
            FeldmanShamirShare::new(y, i, t, commitments.clone()).expect("Failed to create share");

        assert!(
            verify_feldman(share.clone(), share.feldmanshare.id),
            "Feldman verification failed for party {}",
            i
        );
    }

    assert_eq!(commitments[0], G1::generator() * secret);
}

/// Helper to generate Feldman shares for testing.
fn generate_feldman_shares(secret: Fr, n: usize, t: usize) -> Vec<FeldmanShamirShare<Fr, G1>> {
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
    let mut rng = test_rng();
    let mut poly = DensePolynomial::<Fr>::rand(t, &mut rng);
    poly[0] = secret;
    let generator = G1::generator();
    let commitments: Vec<G1> = poly.coeffs.iter().map(|c| generator * c).collect();

    (1..=n)
        .map(|i| {
            let x = Fr::from(i as u64);
            let share_value = poly.evaluate(&x);
            FeldmanShamirShare::new(share_value, i, t, commitments.clone()).unwrap()
        })
        .collect()
}

fn compressed_g1(point: G1) -> Vec<u8> {
    let mut bytes = Vec::new();
    point
        .into_affine()
        .serialize_compressed(&mut bytes)
        .expect("serialize G1 point");
    bytes
}

fn compressed_g2(point: G2) -> Vec<u8> {
    let mut bytes = Vec::new();
    point
        .into_affine()
        .serialize_compressed(&mut bytes)
        .expect("serialize G2 point");
    bytes
}

fn compressed_group_point<G>(point: G) -> Vec<u8>
where
    G: CurveGroup,
{
    let mut bytes = Vec::new();
    point
        .into_affine()
        .serialize_compressed(&mut bytes)
        .expect("serialize group point");
    bytes
}

fn generate_feldman_shares_for_curve<F, G>(
    secret: F,
    n: usize,
    t: usize,
) -> Vec<FeldmanShamirShare<F, G>>
where
    F: FftField + PrimeField + UniformRand,
    G: CurveGroup<ScalarField = F> + PrimeGroup,
{
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};

    let mut rng = test_rng();
    let mut poly = DensePolynomial::<F>::rand(t, &mut rng);
    poly[0] = secret;
    let generator = G::generator();
    let commitments: Vec<G> = poly.coeffs.iter().map(|c| generator * c).collect();

    (1..=n)
        .map(|i| {
            let x = F::from(i as u64);
            let share_value = poly.evaluate(&x);
            FeldmanShamirShare::<F, G>::new(share_value, i, t, commitments.clone()).unwrap()
        })
        .collect()
}

fn assert_open_in_exponent_filter_is_curve_agnostic<F, G>()
where
    F: SupportedMpcField + UniformRand,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    let n = 4;
    let t = 1;
    let secret = F::from(12345u64);
    let shares = generate_feldman_shares_for_curve::<F, G>(secret, n, t);
    let generator = G::generator() * F::from(7u64);
    let expected = generator * secret;

    let honest_point_1 = generator * shares[0].feldmanshare.share[0];
    let forged_point_2 = generator * F::from(99999u64);
    let old_raw_points = vec![
        (
            shares[0].feldmanshare.id,
            compressed_group_point(honest_point_1),
        ),
        (
            shares[1].feldmanshare.id,
            compressed_group_point(forged_point_2),
        ),
    ];

    let poisoned = crate::net::group_interpolation::interpolate_compressed_group_points::<F, G, _>(
        &old_raw_points,
        |id| field_from_usize::<F>(id, "AVSS evaluation point"),
        "deserialize partial point",
        "zero denominator",
        "serialize result",
    )
    .expect("raw interpolation should complete with forged input");
    assert_ne!(
        G::deserialize_compressed(&poisoned[..]).expect("deserialize poisoned"),
        expected,
        "raw open-in-exponent interpolation must be poisonable for this regression to reproduce"
    );

    let local_share =
        AvssMpcEngine::<F, G>::encode_feldman_share(&shares[0]).expect("encode local share");
    let valid_contribution_1 = AvssMpcEngine::<F, G>::encode_verified_exp_contribution(
        &shares[0],
        generator,
        honest_point_1,
    )
    .expect("encode valid contribution 1");
    let valid_contribution_3 = AvssMpcEngine::<F, G>::encode_verified_exp_contribution(
        &shares[2],
        generator,
        generator * shares[2].feldmanshare.share[0],
    )
    .expect("encode valid contribution 3");
    let collected = vec![
        (shares[0].feldmanshare.id, valid_contribution_1),
        (shares[1].feldmanshare.id, old_raw_points[1].1.clone()),
        (shares[2].feldmanshare.id, valid_contribution_3),
    ];

    let verified = AvssMpcEngine::<F, G>::filter_verified_exp_points(
        &local_share,
        generator,
        &collected,
        t + 1,
        "test curve-agnostic open-in-exp",
    )
    .expect("forged contribution should be ignored once enough valid proofs are present");
    assert_eq!(
        verified
            .iter()
            .map(|(share_id, _)| *share_id)
            .collect::<Vec<_>>(),
        vec![1, 3]
    );

    let reconstructed =
        crate::net::group_interpolation::interpolate_compressed_group_points::<F, G, _>(
            &verified,
            |id| field_from_usize::<F>(id, "AVSS evaluation point"),
            "deserialize partial point",
            "zero denominator",
            "serialize result",
        )
        .expect("verified interpolation should reconstruct");
    assert_eq!(
        G::deserialize_compressed(&reconstructed[..]).expect("deserialize reconstructed"),
        expected
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preprocess_reserves_persistent_avss_random_shares_when_loaded() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LmdbPreprocStore::open(dir.path()).unwrap());
    let program_hash = [0xC3; 32];
    let party_id = 0;
    let n = 4;
    let t = 1;
    let scope = PreprocKeyScope::new(
        program_hash,
        crate::net::curve::MpcFieldKind::Bls12_381Fr,
        n,
        t,
        DurableIdentityDigest::from_legacy_party_id(party_id),
    );
    let key = scope.random_share();
    let shares = generate_feldman_shares(Fr::from(77u64), 3, t);
    let (data, item_size) = preproc::serialize_feldman_shares::<Fr, G1>(&shares).unwrap();
    store
        .store(
            &key,
            &PreprocBlob::try_new(data, item_size, shares.len()).unwrap(),
        )
        .await
        .unwrap();

    let net = Arc::new(QuicNetworkManager::new());
    let public_keys = Arc::new(vec![G1::generator(); n]);
    let session = MpcSessionConfig::try_new(9_000_000, party_id, n, t, net).unwrap();
    let engine = AvssMpcEngine::<Fr, G1>::from_config(AvssEngineConfig::new(
        session,
        Fr::from(5u64),
        public_keys,
    ))
    .await
    .unwrap();
    engine
        .preproc_persistence_ops()
        .unwrap()
        .set_preproc_store(store.clone(), program_hash)
        .unwrap();

    engine.preprocess().await.unwrap();

    assert_eq!(
        store.available(&key).await.unwrap(),
        0,
        "persistent AVSS random shares loaded into the runtime pool must be consumed"
    );
    assert!(
        store.load(&key).await.unwrap().is_none(),
        "consumed persistent AVSS random shares should be evicted after preload"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn standing_avss_consumption_uses_owned_bundle_without_touching_reservoir() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LmdbPreprocStore::open(dir.path()).unwrap());
    let program_hash = [0xD4; 32];
    let execution_a = ExecutionId::from_bytes([0xA4; 32]);
    let party_id = 0;
    let n = 4;
    let t = 1;
    let identity = DurableIdentityDigest::from_legacy_party_id(party_id);
    let reservoir = PreprocKeyScope::new(
        program_hash,
        crate::net::curve::MpcFieldKind::Bls12_381Fr,
        n,
        t,
        identity,
    );
    let shares_a = generate_feldman_shares(Fr::from(17u64), 1, t);
    let shares_b = generate_feldman_shares(Fr::from(29u64), 1, t);
    let (reservoir_data, reservoir_item_size) =
        preproc::serialize_feldman_shares::<Fr, G1>(&shares_b).unwrap();
    store
        .store(
            &reservoir.random_share(),
            &PreprocBlob::try_new(reservoir_data, reservoir_item_size, shares_b.len()).unwrap(),
        )
        .await
        .unwrap();

    let session = MpcSessionConfig::try_new(
        9_000_001,
        party_id,
        n,
        t,
        Arc::new(QuicNetworkManager::new()),
    )
    .unwrap()
    .try_with_execution_id(execution_a)
    .unwrap();
    let engine = AvssMpcEngine::<Fr, G1>::from_config(
        AvssEngineConfig::new(session, Fr::from(5u64), Arc::new(vec![G1::generator(); n]))
            .with_deployment_mode(crate::net::engine_config::DeploymentMode::Standing)
            .with_preprocessing_counts(1, 0),
    )
    .await
    .unwrap();
    engine
        .preproc_persistence_ops()
        .unwrap()
        .set_preproc_store(store.clone(), program_hash)
        .unwrap();

    let (data, item_size) = preproc::serialize_feldman_shares::<Fr, G1>(&shares_a).unwrap();
    let bundle = OwnedPreprocBundle {
        random: Some(TakenPreproc {
            count: shares_a.len() as u32,
            item_size,
            data,
        }),
        ..Default::default()
    };
    engine.activate_preallocated_standing(bundle).await.unwrap();

    let taken = engine.reserve_random_shares(1).await.unwrap();
    assert_eq!(taken[0].feldmanshare.share, shares_a[0].feldmanshare.share);
    assert!(
        store
            .load(&reservoir.random_share())
            .await
            .unwrap()
            .is_some(),
        "online execution must consume only its already-owned bundle"
    );
    assert_eq!(store.available(&reservoir.random_share()).await.unwrap(), 1);
}

#[tokio::test]
async fn standing_avss_activation_normalizes_every_triple_without_reordering() {
    let party_id = 0;
    let n = 4;
    let t = 1;
    let execution_id = ExecutionId::from_bytes([0xC4; 32]);
    let mut triples = Vec::new();
    for offset in 0..2u64 {
        let a = generate_feldman_shares(Fr::from(11 + offset), n, t)[party_id].clone();
        let b = generate_feldman_shares(Fr::from(21 + offset), n, t)[party_id].clone();
        let mut c = generate_feldman_shares(Fr::from((11 + offset) * (21 + offset)), n, t)
            [party_id]
            .clone();
        // Upstream AVSS triple generation uses the zero-based party index for
        // c, while Feldman a/b and online shares use one-based identifiers.
        c.feldmanshare.id = party_id;
        triples.push(BeaverTriple { a, b, c });
    }
    let expected_a = triples
        .iter()
        .map(|triple| triple.a.feldmanshare.share)
        .collect::<Vec<_>>();
    let (data, item_size) = preproc::serialize_avss_triples::<Fr, G1>(&triples).unwrap();

    let session = MpcSessionConfig::try_new(
        9_000_002,
        party_id,
        n,
        t,
        Arc::new(QuicNetworkManager::new()),
    )
    .unwrap()
    .try_with_execution_id(execution_id)
    .unwrap();
    let engine = AvssMpcEngine::<Fr, G1>::from_config(
        AvssEngineConfig::new(session, Fr::from(5u64), Arc::new(vec![G1::generator(); n]))
            .with_deployment_mode(crate::net::engine_config::DeploymentMode::Standing)
            .with_preprocessing_counts(0, triples.len()),
    )
    .await
    .unwrap();
    engine
        .activate_preallocated_standing(OwnedPreprocBundle {
            beaver: Some(TakenPreproc {
                count: triples.len() as u32,
                item_size,
                data,
            }),
            ..Default::default()
        })
        .await
        .unwrap();

    let node = engine.clone_avss_node().await;
    let installed = node
        .preprocessing_material
        .lock()
        .await
        .take_triples(triples.len())
        .unwrap();
    assert_eq!(installed.len(), 2);
    assert_eq!(
        installed
            .iter()
            .map(|triple| triple.a.feldmanshare.share)
            .collect::<Vec<_>>(),
        expected_a,
        "activation must preserve the correlated triple order"
    );
    assert!(installed.iter().all(|triple| {
        triple.c.feldmanshare.id == triple.a.feldmanshare.id
            && triple.c.feldmanshare.id == triple.b.feldmanshare.id
    }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn standing_avss_reservoir_uses_stable_program_scope_despite_execution_transport() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LmdbPreprocStore::open(dir.path()).unwrap());
    let execution_id = ExecutionId::from_bytes([0xE2; 32]);
    let program_a = [0xA2; 32];
    let program_b = [0xB2; 32];
    let party_id = 0;
    let n = 4;
    let t = 1;
    let identity = DurableIdentityDigest::from_legacy_party_id(party_id);
    let stable_a = PreprocKeyScope::new(
        program_a,
        crate::net::curve::MpcFieldKind::Bls12_381Fr,
        n,
        t,
        identity,
    );
    let stable_b = PreprocKeyScope::new(
        program_b,
        crate::net::curve::MpcFieldKind::Bls12_381Fr,
        n,
        t,
        identity,
    );
    for (key, count, fill) in [
        (stable_a.random_share(), 2, 0xA2),
        (stable_b.random_share(), 3, 0xB2),
    ] {
        store
            .store(
                &key,
                &PreprocBlob::try_new(vec![fill; count], 1, count).unwrap(),
            )
            .await
            .unwrap();
    }

    async fn make_reservoir(
        store: Arc<LmdbPreprocStore>,
        program_hash: [u8; 32],
        execution_id: ExecutionId,
        instance_id: u64,
        n: usize,
        t: usize,
    ) -> Arc<AvssMpcEngine<Fr, G1>> {
        let session =
            MpcSessionConfig::try_new(instance_id, 0, n, t, Arc::new(QuicNetworkManager::new()))
                .unwrap()
                .try_with_execution_id(execution_id)
                .unwrap();
        let engine = AvssMpcEngine::<Fr, G1>::from_config(
            AvssEngineConfig::new(session, Fr::from(5u64), Arc::new(vec![G1::generator(); n]))
                .with_preprocessing_counts(1, 1)
                .with_deployment_mode(crate::net::engine_config::DeploymentMode::Standing),
        )
        .await
        .unwrap();
        engine
            .preproc_persistence_ops()
            .unwrap()
            .set_preproc_store(store, program_hash)
            .unwrap();
        engine.use_program_preproc_reservoir();
        engine
    }

    let reservoir_a = make_reservoir(store.clone(), program_a, execution_id, 9_000_101, n, t).await;
    let snapshot_a = reservoir_a.standing_preproc_snapshot().await.unwrap();
    let snapshot_b = make_reservoir(store.clone(), program_b, execution_id, 9_000_102, n, t)
        .await
        .standing_preproc_snapshot()
        .await
        .unwrap();

    assert_eq!(snapshot_a.random.count, 2);
    assert_eq!(snapshot_b.random.count, 3);
    let error = reservoir_a
        .activate_preallocated_standing(OwnedPreprocBundle::default())
        .await
        .unwrap_err();
    assert!(
        error.contains("program reservoir cannot be activated"),
        "unexpected error: {error}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn standing_avss_activation_requires_complete_owned_bundle_without_top_up() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LmdbPreprocStore::open(dir.path()).unwrap());
    let program_hash = [0xC2; 32];
    let execution_id = ExecutionId::from_bytes([0xD2; 32]);
    let party_id = 0;
    let n = 4;
    let t = 1;
    let identity = DurableIdentityDigest::from_legacy_party_id(party_id);
    let stable = PreprocKeyScope::new(
        program_hash,
        crate::net::curve::MpcFieldKind::Bls12_381Fr,
        n,
        t,
        identity,
    );
    let stable_random = generate_feldman_shares(Fr::from(41u64), 1, t);
    let execution_random = generate_feldman_shares(Fr::from(43u64), 1, t);
    let (data, item_size) = preproc::serialize_feldman_shares::<Fr, G1>(&stable_random).unwrap();
    store
        .store(
            &stable.random_share(),
            &PreprocBlob::try_new(data, item_size, 1).unwrap(),
        )
        .await
        .unwrap();

    let session = MpcSessionConfig::try_new(
        9_000_103,
        party_id,
        n,
        t,
        Arc::new(QuicNetworkManager::new()),
    )
    .unwrap()
    .try_with_execution_id(execution_id)
    .unwrap();
    let engine = AvssMpcEngine::<Fr, G1>::from_config(
        AvssEngineConfig::new(session, Fr::from(5u64), Arc::new(vec![G1::generator(); n]))
            .with_preprocessing_counts(1, 0)
            .with_deployment_mode(crate::net::engine_config::DeploymentMode::Standing),
    )
    .await
    .unwrap();
    engine
        .preproc_persistence_ops()
        .unwrap()
        .set_preproc_store(store.clone(), program_hash)
        .unwrap();

    let before_stable = store.scope_availability(&stable).await.unwrap();
    let error = engine
        .activate_preallocated_standing(OwnedPreprocBundle::default())
        .await
        .unwrap_err();
    assert!(
        error.contains("does not match target"),
        "unexpected error: {error}"
    );
    assert!(!engine.is_ready());
    assert_eq!(
        store.scope_availability(&stable).await.unwrap(),
        before_stable
    );
    let (data, item_size) = preproc::serialize_feldman_shares::<Fr, G1>(&execution_random).unwrap();
    let bundle = OwnedPreprocBundle {
        random: Some(TakenPreproc {
            count: 1,
            item_size,
            data,
        }),
        ..Default::default()
    };
    engine.activate_preallocated_standing(bundle).await.unwrap();
    assert!(engine.is_ready());
    let taken = engine.reserve_random_shares(1).await.unwrap();
    assert_eq!(
        taken[0].feldmanshare.share,
        execution_random[0].feldmanshare.share
    );
    assert_eq!(
        store.available(&stable.random_share()).await.unwrap(),
        1,
        "execution consumption must not touch the program reservoir"
    );
}

#[test]
fn standing_avss_inventory_agreement_rebuilds_every_party_on_divergence() {
    let targets = preproc::PoolAvailability {
        beaver: 8,
        random: 16,
        prand_bit: 0,
        prand_int: 0,
    };
    let generation = [0x31; 32];
    let fresh = [0x52; 32];
    let full = StandingPreprocSnapshot {
        generation_id: Some(generation),
        beaver: preproc::PreprocMeta {
            count: 8,
            consumed: 0,
            item_size: 96,
        },
        random: preproc::PreprocMeta {
            count: 16,
            consumed: 0,
            item_size: 64,
        },
        ..Default::default()
    };

    let reuse = agree_standing_preproc_plan(targets, &[full; 4], fresh).unwrap();
    assert_eq!(reuse.action, StandingPreprocAction::Reuse);
    assert_eq!(reuse.generation_id, generation);

    let mut short = full;
    short.random.count = 7;
    let top_up = agree_standing_preproc_plan(targets, &[short; 4], fresh).unwrap();
    assert_eq!(top_up.action, StandingPreprocAction::TopUp);
    assert_eq!(top_up.generation_id, fresh);

    let mut divergent = [full; 4];
    divergent[2].random.count = 15;
    let rebuild = agree_standing_preproc_plan(targets, &divergent, fresh).unwrap();
    assert_eq!(rebuild.action, StandingPreprocAction::Rebuild);
    assert_eq!(rebuild.generation_id, fresh);

    let mut missing = [full; 4];
    missing[2] = StandingPreprocSnapshot::default();
    assert_eq!(
        agree_standing_preproc_plan(targets, &missing, fresh)
            .unwrap()
            .action,
        StandingPreprocAction::Rebuild
    );
}

#[test]
fn test_feldman_share_serialization_roundtrip() {
    let n = 4;
    let t = 1;
    let secret = Fr::from(42u64);

    let shares = generate_feldman_shares(secret, n, t);

    for share in &shares {
        let bytes = Bls12381AvssMpcEngine::encode_feldman_share(share).expect("encode failed");
        let decoded = Bls12381AvssMpcEngine::decode_feldman_share(&bytes).expect("decode failed");
        assert_eq!(share.feldmanshare.id, decoded.feldmanshare.id);
        assert_eq!(share.feldmanshare.degree, decoded.feldmanshare.degree);
        assert_eq!(share.feldmanshare.share, decoded.feldmanshare.share);
    }

    // Verify reconstruction works after round-tripping through bytes
    let required = t + 1;
    let subset: Vec<_> = shares.iter().take(required).cloned().collect();
    let recovered = Bls12381AvssMpcEngine::reconstruct_secret(&subset, n, t)
        .expect("reconstruct_secret failed");
    assert_eq!(recovered, secret);
}

#[test]
fn test_bn254_feldman_share_roundtrip() {
    use ark_bn254::{Fr as BnFr, G1Projective as BnG1};
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};

    let mut rng = test_rng();
    let n = 4;
    let t = 1;
    let secret = BnFr::from(42u64);

    let mut poly = DensePolynomial::<BnFr>::rand(t, &mut rng);
    poly[0] = secret;
    let generator = <BnG1 as PrimeGroup>::generator();
    let commitments: Vec<BnG1> = poly.coeffs.iter().map(|c| generator * c).collect();

    let shares: Vec<_> = (1..=n)
        .map(|i| {
            let x = BnFr::from(i as u64);
            let y = poly.evaluate(&x);
            FeldmanShamirShare::<BnFr, BnG1>::new(y, i, t, commitments.clone()).unwrap()
        })
        .collect();

    for share in &shares {
        let bytes = Bn254AvssMpcEngine::encode_feldman_share(share).expect("encode failed");
        let decoded = Bn254AvssMpcEngine::decode_feldman_share(&bytes).expect("decode failed");
        assert_eq!(share.feldmanshare.id, decoded.feldmanshare.id);
        assert_eq!(share.feldmanshare.degree, decoded.feldmanshare.degree);
        assert_eq!(share.feldmanshare.share, decoded.feldmanshare.share);
    }

    let required = t + 1;
    let subset: Vec<_> = shares.iter().take(required).cloned().collect();
    let recovered =
        Bn254AvssMpcEngine::reconstruct_secret(&subset, n, t).expect("reconstruct_secret failed");
    assert_eq!(recovered, secret);
}

fn assert_feldman_share_roundtrip_for_curve<F, G>()
where
    F: FftField + PrimeField + UniformRand + Send + Sync + 'static,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};

    let mut rng = test_rng();
    let n = 4;
    let t = 1;
    let secret = F::from(42u64);

    let mut poly = DensePolynomial::<F>::rand(t, &mut rng);
    poly[0] = secret;
    let generator = G::generator();
    let commitments: Vec<G> = poly.coeffs.iter().map(|c| generator * c).collect();

    let shares: Vec<_> = (1..=n)
        .map(|i| {
            let x = F::from(i as u64);
            let y = poly.evaluate(&x);
            FeldmanShamirShare::<F, G>::new(y, i, t, commitments.clone()).unwrap()
        })
        .collect();

    for share in &shares {
        let bytes = AvssMpcEngine::<F, G>::encode_feldman_share(share).expect("encode failed");
        let decoded = AvssMpcEngine::<F, G>::decode_feldman_share(&bytes).expect("decode failed");
        assert_eq!(share.feldmanshare.id, decoded.feldmanshare.id);
        assert_eq!(share.feldmanshare.degree, decoded.feldmanshare.degree);
        assert_eq!(share.feldmanshare.share, decoded.feldmanshare.share);
        assert!(verify_feldman(decoded.clone(), decoded.feldmanshare.id));
    }

    let required = t + 1;
    let subset: Vec<_> = shares.iter().take(required).cloned().collect();
    let recovered = AvssMpcEngine::<F, G>::reconstruct_secret(&subset, n, t)
        .expect("reconstruct_secret failed");
    assert_eq!(recovered, secret);
}

#[test]
fn test_secp256k1_feldman_share_roundtrip() {
    assert_feldman_share_roundtrip_for_curve::<ark_secp256k1::Fr, ark_secp256k1::Projective>();
}

#[test]
fn test_p256_feldman_share_roundtrip() {
    assert_feldman_share_roundtrip_for_curve::<ark_secp256r1::Fr, ark_secp256r1::Projective>();
}

#[test]
fn test_avss_input_share_i64() {
    let n = 4;
    let t = 1;
    let party_id = 0;
    let secret = Fr::from(42u64);

    let shares = generate_feldman_shares(secret, n, t);
    let bytes =
        Bls12381AvssMpcEngine::encode_feldman_share(&shares[party_id]).expect("encode failed");
    assert!(!bytes.is_empty());

    let decoded = Bls12381AvssMpcEngine::decode_feldman_share(&bytes).expect("decode failed");
    assert_eq!(decoded.feldmanshare.id, shares[party_id].feldmanshare.id);
    assert_eq!(
        decoded.feldmanshare.share,
        shares[party_id].feldmanshare.share
    );
}

#[test]
fn test_avss_input_share_bool() {
    let n = 4;
    let t = 1;
    let party_id = 1;
    let secret = Fr::from(1u64); // true

    let shares = generate_feldman_shares(secret, n, t);
    let bytes =
        Bls12381AvssMpcEngine::encode_feldman_share(&shares[party_id]).expect("encode failed");
    let decoded = Bls12381AvssMpcEngine::decode_feldman_share(&bytes).expect("decode failed");
    assert_eq!(decoded.feldmanshare.id, shares[party_id].feldmanshare.id);
}

#[test]
fn test_avss_input_share_float() {
    let n = 4;
    let t = 1;
    let party_id = 2;

    let ty = ShareType::default_secret_fixed_point();
    let precision = ty.precision().expect("fixed-point precision");
    let scaled_value = crate::net::curve::fixed_point_float_to_i64(precision, F64(3.125))
        .expect("encode fixed-point value");
    let secret = Bls12381AvssMpcEngine::field_from_i64(scaled_value);

    let shares = generate_feldman_shares(secret, n, t);
    let bytes =
        Bls12381AvssMpcEngine::encode_feldman_share(&shares[party_id]).expect("encode failed");
    let decoded = Bls12381AvssMpcEngine::decode_feldman_share(&bytes).expect("decode failed");
    assert_eq!(decoded.feldmanshare.id, shares[party_id].feldmanshare.id);
}

#[test]
fn test_avss_fixed_point_negative_encoding_roundtrip() {
    let ty = ShareType::default_secret_fixed_point();
    let precision = match ty {
        ShareType::SecretFixedPoint { precision } => precision,
        _ => unreachable!(),
    };

    // Choose a power-of-two denominator so this is exactly representable.
    let clear = -3.25f64;
    let scaled = crate::net::curve::fixed_point_float_to_i64(precision, F64(clear))
        .expect("encode fixed-point value");
    let encoded = Bls12381AvssMpcEngine::field_from_i64(scaled);
    let decoded =
        Bls12381AvssMpcEngine::field_to_clear_share_value(ty, encoded).expect("decode value");

    match decoded {
        ClearShareValue::FixedPoint(v) => assert!(
            (v.0 - clear).abs() < 1e-12,
            "expected {}, got {}",
            clear,
            v.0
        ),
        other => panic!("expected ClearShareValue::FixedPoint, got {:?}", other),
    }
}

/// Verify that negative fixed-point values survive the full
/// encode -> share -> reconstruct -> decode pipeline.
/// Regression test for the mismatch demonstrated in PR #31.
#[test]
fn test_avss_negative_fixed_point_share_reconstruct_roundtrip() {
    let n = 4;
    let t = 1;
    let ty = ShareType::default_secret_fixed_point();
    let precision = match ty {
        ShareType::SecretFixedPoint { precision } => precision,
        _ => unreachable!(),
    };

    let clear_value = -3.25_f64;
    let scaled_value = crate::net::curve::fixed_point_float_to_i64(precision, F64(clear_value))
        .expect("encode fixed-point value");

    // Encode using the AVSS engine's field_from_i64 (now delegates to curve::field_from_i64).
    let secret = Bls12381AvssMpcEngine::field_from_i64(scaled_value);

    // Share and reconstruct.
    let shares = generate_feldman_shares(secret, n, t);
    let subset: Vec<_> = shares.iter().take(t + 1).cloned().collect();
    let recovered = Bls12381AvssMpcEngine::reconstruct_secret(&subset, n, t)
        .expect("reconstruct_secret failed");

    // Decode using field_to_clear_share_value (now delegates to curve::field_to_i64).
    let decoded =
        Bls12381AvssMpcEngine::field_to_clear_share_value(ty, recovered).expect("decode value");

    match decoded {
        ClearShareValue::FixedPoint(v) => assert!(
            (v.0 - clear_value).abs() < 1e-12,
            "negative fixed-point round-trip failed: expected {}, got {}",
            clear_value,
            v.0
        ),
        other => panic!("expected ClearShareValue::FixedPoint, got {:?}", other),
    }
}

#[test]
fn test_avss_input_share_reconstruction() {
    let n = 4;
    let t = 1;
    let secret_val = 12345u64;
    let secret = Fr::from(secret_val);

    let shares = generate_feldman_shares(secret, n, t);

    let mut decoded_shares = Vec::new();
    for share in &shares {
        let bytes = Bls12381AvssMpcEngine::encode_feldman_share(share).expect("encode failed");
        let decoded = Bls12381AvssMpcEngine::decode_feldman_share(&bytes).expect("decode failed");
        decoded_shares.push(decoded);
    }

    let required = t + 1;
    let subset: Vec<_> = decoded_shares.iter().take(required).cloned().collect();
    let recovered = Bls12381AvssMpcEngine::reconstruct_secret(&subset, n, t)
        .expect("reconstruct_secret failed");
    assert_eq!(
        recovered, secret,
        "Reconstructed secret should match original"
    );
}

#[test]
fn avss_open_reconstruction_filters_byzantine_feldman_contributions() {
    let n = 4;
    let t = 1;
    let secret = Fr::from(12345u64);
    let honest_shares = generate_feldman_shares(secret, n, t);
    let byzantine_shares = generate_feldman_shares(Fr::from(99999u64), n, t);

    let local_share =
        Bls12381AvssMpcEngine::encode_feldman_share(&honest_shares[0]).expect("encode local");
    let malformed_share = vec![0xde, 0xad, 0xbe, 0xef];
    let mismatched_commitments =
        Bls12381AvssMpcEngine::encode_feldman_share(&byzantine_shares[1]).expect("encode bad");
    let second_valid =
        Bls12381AvssMpcEngine::encode_feldman_share(&honest_shares[1]).expect("encode valid");

    let collected = vec![
        local_share.clone(),
        malformed_share.clone(),
        mismatched_commitments.clone(),
        second_valid,
    ];
    let recovered = Bls12381AvssMpcEngine::reconstruct_verified_secret(
        &local_share,
        &collected,
        n,
        t,
        "test open",
    )
    .expect("one malformed and one mismatched share should be ignored");
    assert_eq!(recovered, secret);

    let insufficient = vec![local_share.clone(), malformed_share, mismatched_commitments];
    let err = Bls12381AvssMpcEngine::reconstruct_verified_secret(
        &local_share,
        &insufficient,
        n,
        t,
        "test open",
    )
    .expect_err("one valid share is not enough for t=1 reconstruction");
    assert!(
        err.contains("only 1 valid Feldman shares") && err.contains("need 2"),
        "unexpected error: {err}"
    );
}

#[test]
fn avss_open_reconstruction_skips_replayed_feldman_ids() {
    let n = 4;
    let t = 1;
    let secret = Fr::from(12345u64);
    let honest_shares = generate_feldman_shares(secret, n, t);

    let local_share =
        Bls12381AvssMpcEngine::encode_feldman_share(&honest_shares[0]).expect("encode local");
    let replayed = local_share.clone();
    let second_valid =
        Bls12381AvssMpcEngine::encode_feldman_share(&honest_shares[1]).expect("encode valid");

    let recovered = Bls12381AvssMpcEngine::reconstruct_verified_secret(
        &local_share,
        &[local_share.clone(), replayed, second_valid],
        n,
        t,
        "replayed AVSS open",
    )
    .expect("a replayed ID must not prevent later unique honest shares from reconstructing");

    assert_eq!(recovered, secret);
}

#[test]
fn avss_open_reconstruction_rejects_non_verifiable_local_feldman_share() {
    let n = 4;
    let t = 1;
    let secret = Fr::from(12345u64);
    let honest_shares = generate_feldman_shares(secret, n, t);
    let mut corrupted_local = honest_shares[0].clone();
    corrupted_local.commitments = vec![G1::generator(); t + 1];

    assert!(
        !verify_feldman(corrupted_local.clone(), corrupted_local.feldmanshare.id),
        "test setup should model a local Feldman share with invalid commitments"
    );

    let local_share =
        Bls12381AvssMpcEngine::encode_feldman_share(&corrupted_local).expect("encode local");
    let second_valid =
        Bls12381AvssMpcEngine::encode_feldman_share(&honest_shares[1]).expect("encode valid");
    let collected = vec![local_share.clone(), second_valid];

    let err = Bls12381AvssMpcEngine::reconstruct_verified_secret(
        &local_share,
        &collected,
        n,
        t,
        "test open",
    )
    .expect_err("invalid local Feldman commitment should be rejected");
    assert!(
        err.contains("local Feldman share failed commitment verification"),
        "unexpected error: {err}"
    );
}

#[test]
fn avss_open_in_exponent_filters_forged_partial_points() {
    let n = 4;
    let t = 1;
    let secret = Fr::from(12345u64);
    let shares = generate_feldman_shares(secret, n, t);
    let generator = G1::generator() * Fr::from(7u64);
    let expected = generator * secret;

    let honest_point_1 = generator * shares[0].feldmanshare.share[0];
    let forged_point_2 = generator * Fr::from(99999u64);
    let old_raw_points = vec![
        (shares[0].feldmanshare.id, compressed_g1(honest_point_1)),
        (shares[1].feldmanshare.id, compressed_g1(forged_point_2)),
    ];

    let poisoned =
        crate::net::group_interpolation::interpolate_compressed_group_points::<Fr, G1, _>(
            &old_raw_points,
            |id| field_from_usize::<Fr>(id, "AVSS evaluation point"),
            "deserialize partial point",
            "zero denominator",
            "serialize result",
        )
        .expect("raw interpolation should complete with forged input");
    assert_ne!(
        G1::deserialize_compressed(&poisoned[..]).expect("deserialize poisoned"),
        expected,
        "raw open-in-exponent interpolation must be poisonable for this regression to reproduce"
    );

    let local_share =
        Bls12381AvssMpcEngine::encode_feldman_share(&shares[0]).expect("encode local share");
    let valid_contribution_1 = Bls12381AvssMpcEngine::encode_verified_exp_contribution(
        &shares[0],
        generator,
        honest_point_1,
    )
    .expect("encode valid contribution 1");
    let valid_contribution_3 = Bls12381AvssMpcEngine::encode_verified_exp_contribution(
        &shares[2],
        generator,
        generator * shares[2].feldmanshare.share[0],
    )
    .expect("encode valid contribution 3");
    let collected = vec![
        (shares[0].feldmanshare.id, valid_contribution_1),
        (shares[1].feldmanshare.id, old_raw_points[1].1.clone()),
        (shares[2].feldmanshare.id, valid_contribution_3),
    ];

    let verified = Bls12381AvssMpcEngine::filter_verified_exp_points(
        &local_share,
        generator,
        &collected,
        t + 1,
        "test open-in-exp",
    )
    .expect("forged contribution should be ignored once enough valid proofs are present");
    assert_eq!(
        verified
            .iter()
            .map(|(share_id, _)| *share_id)
            .collect::<Vec<_>>(),
        vec![1, 3]
    );

    let reconstructed =
        crate::net::group_interpolation::interpolate_compressed_group_points::<Fr, G1, _>(
            &verified,
            |id| field_from_usize::<Fr>(id, "AVSS evaluation point"),
            "deserialize partial point",
            "zero denominator",
            "serialize result",
        )
        .expect("verified interpolation should reconstruct");
    assert_eq!(
        G1::deserialize_compressed(&reconstructed[..]).expect("deserialize reconstructed"),
        expected
    );
}

#[test]
fn avss_g2_open_in_exponent_filters_forged_partial_points() {
    let n = 4;
    let t = 1;
    let secret = Fr::from(12345u64);
    let shares = generate_feldman_shares(secret, n, t);
    let generator = G2::generator() * Fr::from(11u64);
    let expected = generator * secret;

    let honest_point_1 = generator * shares[0].feldmanshare.share[0];
    let forged_point_2 = generator * Fr::from(99999u64);
    let old_raw_points = vec![
        (shares[0].feldmanshare.id, compressed_g2(honest_point_1)),
        (shares[1].feldmanshare.id, compressed_g2(forged_point_2)),
    ];

    let poisoned =
        crate::net::group_interpolation::interpolate_compressed_group_points::<Fr, G2, _>(
            &old_raw_points,
            |id| usize_seed(id, "AVSS G2 evaluation point").map(Fr::from),
            "deserialize G2 partial point",
            "zero denominator",
            "serialize result",
        )
        .expect("raw G2 interpolation should complete with forged input");
    assert_ne!(
        G2::deserialize_compressed(&poisoned[..]).expect("deserialize poisoned"),
        expected,
        "raw G2 open-in-exponent interpolation must be poisonable for this regression to reproduce"
    );

    let local_share =
        Bls12381AvssMpcEngine::encode_feldman_share(&shares[0]).expect("encode local share");
    let valid_contribution_1 =
        Bls12381AvssMpcEngine::encode_verified_g2_exp_contribution(honest_point_1)
            .expect("encode valid contribution 1");
    let valid_contribution_3 = Bls12381AvssMpcEngine::encode_verified_g2_exp_contribution(
        generator * shares[2].feldmanshare.share[0],
    )
    .expect("encode valid contribution 3");
    let collected = vec![
        (shares[0].feldmanshare.id, valid_contribution_1),
        (shares[1].feldmanshare.id, old_raw_points[1].1.clone()),
        (shares[2].feldmanshare.id, valid_contribution_3),
    ];

    let verified = Bls12381AvssMpcEngine::filter_verified_bls12381_g2_exp_points(
        &local_share,
        generator,
        &collected,
        t + 1,
        "test G2 open-in-exp",
    )
    .expect("forged G2 contribution should be ignored once enough valid points are present");
    assert_eq!(
        verified
            .iter()
            .map(|(share_id, _)| *share_id)
            .collect::<Vec<_>>(),
        vec![1, 3]
    );

    let reconstructed =
        crate::net::group_interpolation::interpolate_compressed_group_points::<Fr, G2, _>(
            &verified,
            |id| usize_seed(id, "AVSS G2 evaluation point").map(Fr::from),
            "deserialize G2 partial point",
            "zero denominator",
            "serialize result",
        )
        .expect("verified G2 interpolation should reconstruct");
    assert_eq!(
        G2::deserialize_compressed(&reconstructed[..]).expect("deserialize reconstructed"),
        expected
    );
}

#[test]
fn avss_open_in_exponent_filter_covers_configurable_native_curves() {
    assert_open_in_exponent_filter_is_curve_agnostic::<
        ark_bls12_381::Fr,
        ark_bls12_381::G1Projective,
    >();
    assert_open_in_exponent_filter_is_curve_agnostic::<ark_bn254::Fr, ark_bn254::G1Projective>();
    assert_open_in_exponent_filter_is_curve_agnostic::<
        ark_curve25519::Fr,
        ark_curve25519::EdwardsProjective,
    >();
    assert_open_in_exponent_filter_is_curve_agnostic::<
        ark_ed25519::Fr,
        ark_ed25519::EdwardsProjective,
    >();
    assert_open_in_exponent_filter_is_curve_agnostic::<ark_secp256k1::Fr, ark_secp256k1::Projective>(
    );
    assert_open_in_exponent_filter_is_curve_agnostic::<ark_secp256r1::Fr, ark_secp256r1::Projective>(
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn avss_open_registry_waits_for_n_minus_t_and_tolerates_one_bad_share() {
    let n = 4;
    let t = 1;
    let instance_id = 98001;
    let type_key = "avss-int-64";
    let secret = Fr::from(12345u64);
    let honest_shares = generate_feldman_shares(secret, n, t);
    let byzantine_shares = generate_feldman_shares(Fr::from(99999u64), n, t);

    let local_share =
        Bls12381AvssMpcEngine::encode_feldman_share(&honest_shares[0]).expect("encode local");
    let bad_share =
        Bls12381AvssMpcEngine::encode_feldman_share(&byzantine_shares[1]).expect("encode bad");
    let valid_share =
        Bls12381AvssMpcEngine::encode_feldman_share(&honest_shares[1]).expect("encode valid");

    let router = Arc::new(crate::net::open_registry::OpenMessageRouter::new());
    let registry = router.register_instance(instance_id);
    let required = Bls12381AvssMpcEngine::byzantine_open_contribution_count(n, t)
        .expect("valid byzantine topology");

    let expected_share = local_share.clone();
    let waiter = tokio::spawn(async move {
        registry
            .open_share_at_async(
                0,
                type_key.to_string(),
                0,
                expected_share.clone(),
                required,
                move |collected| {
                    let secret = Bls12381AvssMpcEngine::reconstruct_verified_secret(
                        &expected_share,
                        collected,
                        n,
                        t,
                        "registry open",
                    )?;
                    Bls12381AvssMpcEngine::field_to_clear_share_value(
                        ShareType::default_secret_int(),
                        secret,
                    )
                },
            )
            .await
    });

    let bad_message = crate::net::open_registry::encode_single_share_wire_message(
        instance_id,
        0,
        type_key,
        1,
        &bad_share,
    )
    .expect("encode bad wire message");
    assert!(router
        .try_handle_wire_message(1, &bad_message)
        .expect("route bad wire message"));

    tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;
    assert!(
        !waiter.is_finished(),
        "open should wait for n - t contributions instead of reconstructing from one honest and one bad share"
    );

    let valid_message = crate::net::open_registry::encode_single_share_wire_message(
        instance_id,
        0,
        type_key,
        2,
        &valid_share,
    )
    .expect("encode valid wire message");
    assert!(router
        .try_handle_wire_message(2, &valid_message)
        .expect("route valid wire message"));

    let opened = tokio::time::timeout(tokio::time::Duration::from_secs(1), waiter)
        .await
        .expect("open should complete after n - t contributions")
        .expect("open task should not panic")
        .expect("open should reconstruct from valid Feldman shares");
    assert_eq!(opened, ClearShareValue::Integer(12345));
}

#[test]
fn test_bn254_input_share_reconstruction() {
    use ark_bn254::{Fr as BnFr, G1Projective as BnG1};
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};

    let mut rng = test_rng();
    let n = 4;
    let t = 1;
    let secret_val = 12345u64;
    let secret = BnFr::from(secret_val);

    let mut poly = DensePolynomial::<BnFr>::rand(t, &mut rng);
    poly[0] = secret;
    let generator = <BnG1 as PrimeGroup>::generator();
    let commitments: Vec<BnG1> = poly.coeffs.iter().map(|c| generator * c).collect();

    let shares: Vec<_> = (1..=n)
        .map(|i| {
            let x = BnFr::from(i as u64);
            let y = poly.evaluate(&x);
            FeldmanShamirShare::<BnFr, BnG1>::new(y, i, t, commitments.clone()).unwrap()
        })
        .collect();

    let mut decoded_shares = Vec::new();
    for share in &shares {
        let bytes = Bn254AvssMpcEngine::encode_feldman_share(share).expect("encode failed");
        let decoded = Bn254AvssMpcEngine::decode_feldman_share(&bytes).expect("decode failed");
        decoded_shares.push(decoded);
    }

    let required = t + 1;
    let subset: Vec<_> = decoded_shares.iter().take(required).cloned().collect();
    let recovered =
        Bn254AvssMpcEngine::reconstruct_secret(&subset, n, t).expect("reconstruct_secret failed");
    assert_eq!(
        recovered, secret,
        "Reconstructed secret should match original"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_avss_input_share_is_local_constant_sharing() {
    // A clear input must NOT run a network AVSS dealing (runtime dealings
    // collide with preprocessing session slots and hang); it is a local
    // degree-t constant sharing that reconstructs to the constant.
    let n = 4usize;
    let t = 1usize;
    let instance_id = 77u64;

    let net = Arc::new(QuicNetworkManager::new());
    let pk_map = Arc::new(vec![G1::generator(); n]);

    let e0_session =
        MpcSessionConfig::try_new(instance_id, 0, n, t, net.clone()).expect("valid topology");
    let e0 = AvssMpcEngine::<Fr, G1>::from_config(AvssEngineConfig::new(
        e0_session,
        Fr::from(11u64),
        pk_map.clone(),
    ))
    .await
    .expect("engine0");
    let e1_session = MpcSessionConfig::try_new(instance_id, 1, n, t, net).expect("valid topology");
    let e1 = AvssMpcEngine::<Fr, G1>::from_config(AvssEngineConfig::new(
        e1_session,
        Fr::from(13u64),
        pk_map,
    ))
    .await
    .expect("engine1");

    let value = Fr::from(123459u64);
    let s0 = e0
        .local_constant_share(value)
        .await
        .expect("constant share party 0");
    let s1 = e1
        .local_constant_share(value)
        .await
        .expect("constant share party 1");

    assert_eq!(s0.feldmanshare.share[0], value);
    assert_eq!(s1.feldmanshare.share[0], value);
    assert_ne!(
        s0.feldmanshare.id, s1.feldmanshare.id,
        "parties evaluate at distinct share ids"
    );
    assert!(
        stoffelmpc_mpc::common::share::avss::verify_feldman(s0.clone(), s0.feldmanshare.id),
        "constant share must pass Feldman verification"
    );
    assert!(
        stoffelmpc_mpc::common::share::avss::verify_feldman(s1.clone(), s1.feldmanshare.id),
        "constant share must pass Feldman verification"
    );

    let recovered = AvssMpcEngine::<Fr, G1>::reconstruct_secret(&[s0, s1], n, t)
        .expect("reconstruct constant sharing");
    assert_eq!(
        recovered, value,
        "constant sharing reconstructs to the constant"
    );
}
