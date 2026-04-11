//! Debug test for arkworks ↔ ed25519-dalek serialization compatibility

use ark_ec::{CurveGroup, PrimeGroup};
use ark_ed25519::{EdwardsProjective, Fr};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha512};

/// Test that a non-threshold Ed25519 Schnorr signature produced entirely
/// with arkworks math can be verified by ed25519-dalek.
#[test]
fn test_ark_eddsa_verified_by_dalek() {
    use ark_std::rand::SeedableRng;
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42);

    // Key generation
    let sk = Fr::rand(&mut rng);
    let pk = (EdwardsProjective::generator() * sk).into_affine();

    let mut pk_bytes = Vec::new();
    pk.serialize_compressed(&mut pk_bytes).unwrap();

    // Nonce
    let k = Fr::rand(&mut rng);
    let r = (EdwardsProjective::generator() * k).into_affine();

    let mut r_bytes = Vec::new();
    r.serialize_compressed(&mut r_bytes).unwrap();

    // Challenge: SHA-512(R || pk || msg) reduced LE mod l (per RFC 8032)
    let msg = b"test message";
    let mut hasher = Sha512::new();
    hasher.update(&r_bytes);
    hasher.update(&pk_bytes);
    hasher.update(msg);
    let hash = hasher.finalize();
    let e = Fr::from_le_bytes_mod_order(&hash);

    // Response: s = k + e * sk
    let s = k + e * sk;

    let mut s_bytes = Vec::new();
    s.serialize_compressed(&mut s_bytes).unwrap();

    // === Arkworks verification ===
    let lhs = EdwardsProjective::generator() * s;
    let rhs = EdwardsProjective::from(r) + EdwardsProjective::from(pk) * e;
    assert_eq!(lhs, rhs, "Arkworks verification failed");
    println!("Arkworks verification: PASSED");

    // === Debug: compare scalar representations ===
    // Arkworks Fr is serialized as 32 LE bytes in [0, l)
    // Dalek Scalar is also 32 LE bytes in [0, l)
    // But their internal representations might encode differently
    use curve25519_dalek::Scalar;
    let s_arr: [u8; 32] = s_bytes.clone().try_into().unwrap();
    let s_canonical = Scalar::from_canonical_bytes(s_arr);
    let is_canonical: bool = s_canonical.is_some().into();
    println!("S is canonical dalek scalar: {}", is_canonical);

    if !is_canonical {
        // Arkworks Fr canonical form may exceed l because arkworks uses
        // Montgomery form internally. Let's try reducing explicitly.
        let s_reduced = Scalar::from_bytes_mod_order(s_arr);
        println!("S bytes (arkworks): {}", hex::encode(&s_arr));
        println!("S bytes (reduced):  {}", hex::encode(s_reduced.as_bytes()));

        // The issue: arkworks serialize_compressed for Fr produces
        // the Montgomery form canonical bytes, which may not be in [0, l).
        // We need to convert: serialize Fr as a big integer, then create
        // a dalek Scalar from those bytes.
    }

    // === ed25519-dalek verification ===
    let pk_arr: [u8; 32] = pk_bytes.clone().try_into().unwrap();
    let vk = VerifyingKey::from_bytes(&pk_arr).expect("dalek: invalid public key");

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&r_bytes);
    sig_bytes[32..].copy_from_slice(&s_bytes);
    let sig = Signature::from_bytes(&sig_bytes);

    match vk.verify(msg, &sig) {
        Ok(()) => println!("ed25519-dalek verification: PASSED"),
        Err(e) => {
            println!("ed25519-dalek verification: FAILED ({})", e);

            // Debug: compute what dalek would get if S is not canonical
            let s_as_dalek = Scalar::from_bytes_mod_order(s_arr);
            let mut s_canonical_bytes = [0u8; 32];
            s_canonical_bytes.copy_from_slice(s_as_dalek.as_bytes());
            println!(
                "S bytes match after dalek reduce: {}",
                s_canonical_bytes == s_arr
            );

            if s_canonical_bytes != s_arr {
                println!("FIX: arkworks Fr serialization is NOT canonical for dalek");
                println!("  arkworks: {}", hex::encode(s_arr));
                println!("  dalek:    {}", hex::encode(s_canonical_bytes));

                // Retry with the dalek-canonical S
                sig_bytes[32..].copy_from_slice(&s_canonical_bytes);
                let sig2 = Signature::from_bytes(&sig_bytes);
                match vk.verify(msg, &sig2) {
                    Ok(()) => println!("  ed25519-dalek with reduced S: PASSED"),
                    Err(e2) => println!("  ed25519-dalek with reduced S: FAILED ({})", e2),
                }
            }

            panic!("ed25519-dalek verification failed");
        }
    }
}
