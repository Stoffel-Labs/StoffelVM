//! End-to-end client for the production-shaped threshold DH-PSI example.

use std::collections::HashSet;
use std::error::Error;
use std::path::PathBuf;
use std::time::Duration;

use ark_bls12_381::{g1::Config as G1Config, Fr, G1Affine, G1Projective};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    AffineRepr, CurveGroup,
};
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_ff::{BigInteger, Field, PrimeField, UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::thread_rng;
use sha2::Sha256;
use stoffel::prelude::*;

const FIELD_BYTES: usize = 32;
const POINT_BYTES: usize = 48;
const LIMB_BYTES: usize = 24;
const DOMAIN: &[u8] = b"STOFFEL-DH-PSI_BLS12381G1_XMD:SHA-256_SSWU_RO_V1";
const SET_SIZE: usize = 1_000;
const INTERSECTION_SIZE: usize = 500;
type AppResult<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Clone)]
struct BlindedInput {
    encoded_limbs: [Value; 2],
    inverse_blind: Fr,
}

type G1Hasher =
    MapToCurveBasedHasher<G1Projective, DefaultFieldHasher<Sha256, 128>, WBMap<G1Config>>;

fn canonical_be_bytes(value: Fr) -> Vec<u8> {
    let encoded = value.into_bigint().to_bytes_be();
    let mut out = vec![0u8; FIELD_BYTES];
    out[FIELD_BYTES - encoded.len()..].copy_from_slice(&encoded);
    out
}

fn pack_point(point: G1Affine) -> AppResult<[Value; 2]> {
    let mut encoded = Vec::with_capacity(POINT_BYTES);
    point.serialize_compressed(&mut encoded)?;
    let limbs = encoded
        .as_chunks::<LIMB_BYTES>()
        .0
        .iter()
        .map(|chunk| {
            let scalar = Fr::from_le_bytes_mod_order(chunk);
            Value::Bytes(canonical_be_bytes(scalar))
        })
        .collect::<Vec<_>>();
    Ok([limbs[0].clone(), limbs[1].clone()])
}

fn blind_set(elements: &[Vec<u8>]) -> AppResult<Vec<BlindedInput>> {
    let mut rng = thread_rng();
    let hasher = G1Hasher::new(DOMAIN)?;
    elements
        .iter()
        .map(|element| {
            let blind = loop {
                let candidate = Fr::rand(&mut rng);
                if !candidate.is_zero() {
                    break candidate;
                }
            };
            let inverse_blind = blind.inverse().expect("non-zero blind has an inverse");
            let hashed = hasher.hash(element)?;
            let blinded = hashed.mul_bigint(blind.into_bigint()).into_affine();
            Ok(BlindedInput {
                encoded_limbs: pack_point(blinded)?,
                inverse_blind,
            })
        })
        .collect()
}

fn unblind(point: &[u8], inverse_blind: Fr) -> AppResult<Vec<u8>> {
    let evaluated = G1Affine::deserialize_compressed(point)?;
    let tag = evaluated
        .mul_bigint(inverse_blind.into_bigint())
        .into_affine();
    let mut encoded = Vec::with_capacity(POINT_BYTES);
    tag.serialize_compressed(&mut encoded)?;
    Ok(encoded)
}

fn artifact_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../stoffel-lang/examples/mpc_dh_psi/target/release/mpc-dh-psi.stflb")
}

#[tokio::main]
async fn main() -> AppResult<()> {
    let set_a = (0..SET_SIZE)
        .map(|index| format!("item-{index:08}").into_bytes())
        .collect::<Vec<_>>();
    let set_b = (SET_SIZE - INTERSECTION_SIZE..2 * SET_SIZE - INTERSECTION_SIZE)
        .map(|index| format!("item-{index:08}").into_bytes())
        .collect::<Vec<_>>();
    let a = blind_set(&set_a)?;
    let b = blind_set(&set_b)?;

    let a_inputs = a
        .iter()
        .flat_map(|item| item.encoded_limbs.iter().cloned())
        .collect::<Vec<_>>();
    let b_inputs = b
        .iter()
        .flat_map(|item| item.encoded_limbs.iter().cloned())
        .collect::<Vec<_>>();

    let returned = Stoffel::load_file(artifact_path())?
        .with_client_input(0, &a_inputs)
        .with_client_input(1, &b_inputs)
        .execute_local_with_timeout(Duration::from_secs(600))
        .await?;
    let response = returned
        .first()
        .and_then(Value::as_bytes)
        .ok_or("DH-PSI program did not return its byte response")?;
    let expected_len = (a.len() + b.len()) * POINT_BYTES;
    if response.len() != expected_len {
        return Err(format!(
            "DH-PSI response is {} bytes, expected {expected_len}",
            response.len()
        )
        .into());
    }

    let tags_a = response[..a.len() * POINT_BYTES]
        .as_chunks::<POINT_BYTES>()
        .0
        .iter()
        .zip(&a)
        .map(|(point, input)| unblind(point, input.inverse_blind))
        .collect::<AppResult<HashSet<_>>>()?;
    let tags_b = response[a.len() * POINT_BYTES..]
        .as_chunks::<POINT_BYTES>()
        .0
        .iter()
        .zip(&b)
        .map(|(point, input)| unblind(point, input.inverse_blind))
        .collect::<AppResult<HashSet<_>>>()?;
    let intersection = tags_a.intersection(&tags_b).count();
    if intersection != INTERSECTION_SIZE {
        return Err(format!(
            "DH-PSI returned intersection size {intersection}, expected {INTERSECTION_SIZE}"
        )
        .into());
    }

    println!("DH-PSI verified: |A|={SET_SIZE} |B|={SET_SIZE} |intersection|={intersection}");
    Ok(())
}
