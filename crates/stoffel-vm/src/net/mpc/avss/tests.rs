use super::*;
use ark_bls12_381::{Fr, G1Projective as G1};
use ark_ec::PrimeGroup;
use ark_ff::UniformRand;
use ark_std::test_rng;
use std::sync::Arc;
use stoffel_vm_types::core_types::{ClearShareValue, ShareType, F64};
use stoffelmpc_mpc::common::share::avss::verify_feldman;
use stoffelmpc_mpc::common::ProtocolSessionId;
use stoffelnet::transports::quic::QuicNetworkManager;

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
            verify_feldman(share.clone()),
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
async fn test_avss_input_share_session_allocation_is_consistent_across_parties() {
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

    let (dealer0, sid0) = e0.allocate_input_share_session().expect("session0");
    let (dealer1, sid1) = e1.allocate_input_share_session().expect("session1");
    assert_eq!(dealer0, dealer1, "dealer selection must be deterministic");
    assert_eq!(
        sid0.as_u64(),
        sid1.as_u64(),
        "session ids must match across parties for the same input_share round"
    );

    let (dealer0_next, sid0_next) = e0.allocate_input_share_session().expect("session0-next");
    let (dealer1_next, sid1_next) = e1.allocate_input_share_session().expect("session1-next");
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
