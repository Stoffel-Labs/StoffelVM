use super::{
    add_share_for_curve, add_share_scalar_for_curve, mul_share_field_for_curve,
    mul_share_scalar_for_curve, scale_fixed_point_scalar, sub_share_for_curve, ShareAlgebraError,
};
use crate::net::curve::MpcCurveConfig;
use ark_bls12_381::{Fr, G1Projective};
use ark_ec::PrimeGroup;
use ark_ed25519::{EdwardsProjective, Fr as EdFr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use stoffel_vm_types::core_types::ShareType;
use stoffelmpc_mpc::common::share::avss::verify_feldman;
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;

#[test]
fn scale_fixed_point_scalar_rejects_unrepresentable_shift() {
    let err = scale_fixed_point_scalar(usize::MAX, 1).unwrap_err();

    assert_eq!(err, ShareAlgebraError::FixedPointScaleOverflow);
    assert_eq!(err.to_string(), "Fixed-point scale overflow");
}

#[test]
fn scale_fixed_point_scalar_rejects_i64_overflow() {
    let range_err = scale_fixed_point_scalar(63, 1).unwrap_err();
    let overflow_err = scale_fixed_point_scalar(126, 3).unwrap_err();

    assert_eq!(range_err, ShareAlgebraError::FixedPointScalarOutOfRange);
    assert_eq!(overflow_err, ShareAlgebraError::FixedPointScalarOverflow);
    assert_eq!(
        range_err.to_string(),
        "Fixed-point scalar exceeds i64 range"
    );
    assert_eq!(overflow_err.to_string(), "Fixed-point scalar overflow");
}

fn test_feldman_share(secret: u64, slope: u64, id: usize) -> FeldmanShamirShare<Fr, G1Projective> {
    let x = Fr::from(id as u64);
    let secret = Fr::from(secret);
    let slope = Fr::from(slope);
    let share_value = secret + slope * x;
    let generator = G1Projective::generator();
    let commitments = vec![generator * secret, generator * slope];

    FeldmanShamirShare::new(share_value, id, 1, commitments).expect("create test Feldman share")
}

fn encode_feldman_share(share: &FeldmanShamirShare<Fr, G1Projective>) -> Vec<u8> {
    let mut out = Vec::new();
    share
        .serialize_compressed(&mut out)
        .expect("serialize test Feldman share");
    out
}

fn decode_feldman_share(bytes: &[u8]) -> FeldmanShamirShare<Fr, G1Projective> {
    FeldmanShamirShare::<Fr, G1Projective>::deserialize_compressed(bytes)
        .expect("decode test Feldman share")
}

fn test_ed25519_feldman_share(
    secret: u64,
    slope: u64,
    id: usize,
) -> FeldmanShamirShare<EdFr, EdwardsProjective> {
    let x = EdFr::from(id as u64);
    let secret = EdFr::from(secret);
    let slope = EdFr::from(slope);
    let share_value = secret + slope * x;
    let generator = EdwardsProjective::generator();
    let commitments = vec![generator * secret, generator * slope];

    FeldmanShamirShare::new(share_value, id, 1, commitments)
        .expect("create test Ed25519 Feldman share")
}

fn encode_ed25519_feldman_share(share: &FeldmanShamirShare<EdFr, EdwardsProjective>) -> Vec<u8> {
    let mut out = Vec::new();
    share
        .serialize_compressed(&mut out)
        .expect("serialize test Ed25519 Feldman share");
    out
}

fn decode_ed25519_feldman_share(bytes: &[u8]) -> FeldmanShamirShare<EdFr, EdwardsProjective> {
    FeldmanShamirShare::<EdFr, EdwardsProjective>::deserialize_compressed(bytes)
        .expect("decode test Ed25519 Feldman share")
}

#[test]
fn feldman_linear_local_ops_preserve_verifiable_commitments() {
    let ty = ShareType::secret_int(64);
    let lhs = test_feldman_share(11, 3, 1);
    let rhs = test_feldman_share(7, 5, 1);
    let lhs_bytes = encode_feldman_share(&lhs);
    let rhs_bytes = encode_feldman_share(&rhs);

    let added = decode_feldman_share(
        &add_share_for_curve(MpcCurveConfig::Bls12_381, ty, &lhs_bytes, &rhs_bytes)
            .expect("add Feldman shares"),
    );
    assert!(verify_feldman(added.clone()));
    assert_eq!(
        added.commitments[0],
        lhs.commitments[0] + rhs.commitments[0]
    );
    assert_eq!(
        added.commitments[1],
        lhs.commitments[1] + rhs.commitments[1]
    );

    let subtracted = decode_feldman_share(
        &sub_share_for_curve(MpcCurveConfig::Bls12_381, ty, &lhs_bytes, &rhs_bytes)
            .expect("subtract Feldman shares"),
    );
    assert!(verify_feldman(subtracted.clone()));
    assert_eq!(
        subtracted.commitments[0],
        lhs.commitments[0] - rhs.commitments[0]
    );
    assert_eq!(
        subtracted.commitments[1],
        lhs.commitments[1] - rhs.commitments[1]
    );

    let scaled = decode_feldman_share(
        &mul_share_scalar_for_curve(MpcCurveConfig::Bls12_381, ty, &lhs_bytes, 4)
            .expect("scale Feldman share"),
    );
    assert!(verify_feldman(scaled.clone()));
    assert_eq!(scaled.commitments[0], lhs.commitments[0] * Fr::from(4u64));
    assert_eq!(scaled.commitments[1], lhs.commitments[1] * Fr::from(4u64));

    let shifted = decode_feldman_share(
        &add_share_scalar_for_curve(MpcCurveConfig::Bls12_381, ty, &lhs_bytes, 9)
            .expect("add scalar to Feldman share"),
    );
    assert!(verify_feldman(shifted.clone()));
    assert_eq!(
        shifted.commitments[0],
        lhs.commitments[0] + G1Projective::generator() * Fr::from(9u64)
    );
    assert_eq!(shifted.commitments[1], lhs.commitments[1]);
}

#[test]
fn ed25519_feldman_local_ops_preserve_ed25519_commitments() {
    let ty = ShareType::secret_int(64);
    let sk = test_ed25519_feldman_share(11, 3, 1);
    let nonce = test_ed25519_feldman_share(7, 5, 1);
    let sk_bytes = encode_ed25519_feldman_share(&sk);
    let nonce_bytes = encode_ed25519_feldman_share(&nonce);

    let scalar = EdFr::from(13u64);
    let mut scalar_bytes = Vec::new();
    scalar
        .serialize_compressed(&mut scalar_bytes)
        .expect("serialize scalar");

    let scaled_bytes =
        mul_share_field_for_curve(MpcCurveConfig::Ed25519, ty, &sk_bytes, &scalar_bytes)
            .expect("multiply Ed25519 Feldman share by field element");
    let scaled = decode_ed25519_feldman_share(&scaled_bytes);
    assert!(verify_feldman(scaled.clone()));
    assert_eq!(scaled.commitments[0], sk.commitments[0] * scalar);
    assert_eq!(scaled.commitments[1], sk.commitments[1] * scalar);

    let added_bytes = add_share_for_curve(MpcCurveConfig::Ed25519, ty, &nonce_bytes, &scaled_bytes)
        .expect("add Ed25519 Feldman shares");
    let added = decode_ed25519_feldman_share(&added_bytes);
    assert!(verify_feldman(added.clone()));
    assert_eq!(
        added.commitments[0],
        nonce.commitments[0] + scaled.commitments[0]
    );
    assert_eq!(
        added.commitments[1],
        nonce.commitments[1] + scaled.commitments[1]
    );
}
