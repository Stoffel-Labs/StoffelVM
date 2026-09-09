//! End-to-end client for the client-blinded threshold OPRF example.

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
use sha2::{Digest, Sha256};
use stoffel::prelude::*;

const FIELD_BYTES: usize = 32;
const POINT_BYTES: usize = 48;
const LIMB_BYTES: usize = 24;
const REQUEST_COUNT: usize = 3;
const DOMAIN: &[u8] = b"STOFFEL-OPRF_BLS12381G1_XMD:SHA-256_SSWU_RO_V1";
type AppResult<T> = std::result::Result<T, Box<dyn Error>>;
type G1Hasher =
    MapToCurveBasedHasher<G1Projective, DefaultFieldHasher<Sha256, 128>, WBMap<G1Config>>;

struct BlindedInput {
    encoded_limbs: [Value; 2],
    inverse_blind: Fr,
}

fn canonical_be_bytes(value: Fr) -> Vec<u8> {
    let encoded = value.into_bigint().to_bytes_be();
    let mut out = vec![0u8; FIELD_BYTES];
    out[FIELD_BYTES - encoded.len()..].copy_from_slice(&encoded);
    out
}

fn pack_point(point: G1Affine) -> AppResult<[Value; 2]> {
    let mut encoded = Vec::with_capacity(POINT_BYTES);
    point.serialize_compressed(&mut encoded)?;
    let (chunks, remainder) = encoded.as_chunks::<LIMB_BYTES>();
    if !remainder.is_empty() {
        return Err("unexpected compressed BLS12-381 G1 length".into());
    }
    let [first, second] = chunks else {
        return Err("unexpected compressed BLS12-381 G1 length".into());
    };
    Ok([first, second]
        .map(|chunk| Value::Bytes(canonical_be_bytes(Fr::from_le_bytes_mod_order(chunk)))))
}

fn blind(hasher: &G1Hasher, message: &[u8]) -> AppResult<BlindedInput> {
    let mut rng = thread_rng();
    let blind = loop {
        let candidate = Fr::rand(&mut rng);
        if !candidate.is_zero() {
            break candidate;
        }
    };
    let inverse_blind = blind.inverse().expect("non-zero blind has an inverse");
    let blinded = hasher
        .hash(message)?
        .mul_bigint(blind.into_bigint())
        .into_affine();
    if blinded.is_zero() {
        return Err("hash-to-curve produced the identity point".into());
    }
    Ok(BlindedInput {
        encoded_limbs: pack_point(blinded)?,
        inverse_blind,
    })
}

fn finalize(message: &[u8], element: &[u8]) -> AppResult<Vec<u8>> {
    let message_len = u16::try_from(message.len()).map_err(|_| "OPRF input exceeds 65535 bytes")?;
    let element_len = u16::try_from(element.len()).map_err(|_| "OPRF element is too large")?;
    let mut hash = Sha256::new();
    hash.update(message_len.to_be_bytes());
    hash.update(message);
    hash.update(element_len.to_be_bytes());
    hash.update(element);
    hash.update(b"Finalize");
    Ok(hash.finalize().to_vec())
}

fn unblind_and_finalize(message: &[u8], point: &[u8], inverse_blind: Fr) -> AppResult<Vec<u8>> {
    let evaluated = G1Affine::deserialize_compressed(point)?;
    if evaluated.is_zero() {
        return Err("OPRF service returned the identity point".into());
    }
    let tag = evaluated
        .mul_bigint(inverse_blind.into_bigint())
        .into_affine();
    let mut encoded = Vec::with_capacity(POINT_BYTES);
    tag.serialize_compressed(&mut encoded)?;
    finalize(message, &encoded)
}

fn artifact_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../stoffel-lang/examples/mpc_oprf/target/release/mpc-oprf.stflb")
}

#[tokio::main]
async fn main() -> AppResult<()> {
    let hasher = G1Hasher::new(DOMAIN)?;
    let messages: [&[u8]; REQUEST_COUNT] = [
        b"alice@example.com",
        b"alice@example.com",
        b"bob@example.com",
    ];
    let blinded = messages
        .iter()
        .map(|message| blind(&hasher, message))
        .collect::<AppResult<Vec<_>>>()?;
    let inputs = blinded
        .iter()
        .flat_map(|input| input.encoded_limbs.iter().cloned())
        .collect::<Vec<_>>();

    let returned = Stoffel::load_file(artifact_path())?
        .with_client_input(0, &inputs)
        .execute_local_with_timeout(Duration::from_secs(600))
        .await?;
    let response = returned
        .first()
        .and_then(Value::as_bytes)
        .ok_or("OPRF program did not return its byte response")?;
    if response.len() != REQUEST_COUNT * POINT_BYTES {
        return Err(format!(
            "OPRF response is {} bytes, expected {}",
            response.len(),
            REQUEST_COUNT * POINT_BYTES
        )
        .into());
    }

    let tags = response
        .as_chunks::<POINT_BYTES>()
        .0
        .iter()
        .zip(messages.iter().zip(&blinded))
        .map(|(point, (message, input))| unblind_and_finalize(message, point, input.inverse_blind))
        .collect::<AppResult<Vec<_>>>()?;
    if tags[0] != tags[1] {
        return Err("equal OPRF inputs produced different unblinded tags".into());
    }
    if tags[0] == tags[2] {
        return Err("distinct OPRF inputs produced the same unblinded tag".into());
    }

    println!("OPRF verified: equal inputs match; distinct input differs; key remained shared");
    Ok(())
}
