#[allow(dead_code, unused_mut, unused_variables)]
mod stoffel_bindings {
    include!(concat!(env!("OUT_DIR"), "/stoffel_bindings.rs"));
}

use std::time::Instant;

use sha2::{Digest, Sha256};
use stoffel_bindings::ProgramClient;

const PROGRAM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/main.stfl");

struct TestVector {
    name: &'static str,
    message: [u8; 32],
    digest: &'static str,
}

const TEST_VECTORS: [TestVector; 4] = [
    TestVector {
        name: "all zeroes",
        message: [0; 32],
        digest: "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925",
    },
    TestVector {
        name: "incrementing bytes",
        message: [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ],
        digest: "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd",
    },
    TestVector {
        name: "all ones",
        message: [0xff; 32],
        digest: "af9613760f72635fbdb44a5a0a63c39f12af30f950a6ee5c971be188e89c4051",
    },
    TestVector {
        name: "ASCII",
        message: *b"abcdefghijklmnopqrstuvwxyz012345",
        digest: "653bb1245e828fcda4fa53fcd5a3def5bd7654e651f54b4132b73d74e64435c4",
    },
];

#[tokio::main(flavor = "multi_thread")]
async fn main() -> stoffel::Result<()> {
    let client = ProgramClient::new(PROGRAM)
        .local_runner_path_from_env("STOFFEL_RUN_BIN")
        .optimization_level(3)
        .timeout(std::time::Duration::from_secs(1200));

    let requested = std::env::var("SHA256_TEST_VECTOR").ok();
    let vectors = TEST_VECTORS
        .iter()
        .filter(|vector| requested.as_deref().is_none_or(|name| vector.name == name))
        .collect::<Vec<_>>();
    assert!(!vectors.is_empty(), "unknown SHA256_TEST_VECTOR");

    let suite_started = Instant::now();
    for vector in &vectors {
        assert_eq!(
            hex::encode(Sha256::digest(vector.message)),
            vector.digest,
            "bad reference digest for {}",
            vector.name
        );

        let started = Instant::now();
        let digest = client.hash_32_bytes(hex::encode(vector.message)).await?;
        let actual = digest
            .into_array()
            .into_iter()
            .map(|word| format!("{:08x}", word as u32))
            .collect::<String>();

        assert_eq!(
            actual, vector.digest,
            "MPC SHA-256 failed for {}",
            vector.name
        );
        println!(
            "PASS {:>18}: {} ({:.2?})",
            vector.name,
            vector.digest,
            started.elapsed()
        );
    }
    println!(
        "PASS: {} secret-input vectors, MPC computation, and client-only reveals ({:.2?} total)",
        vectors.len(),
        suite_started.elapsed()
    );
    Ok(())
}

#[test]
fn reference_vectors_are_valid() {
    for vector in &TEST_VECTORS {
        assert_eq!(hex::encode(Sha256::digest(vector.message)), vector.digest);
    }
}
