use std::time::Duration;

use stoffel_vm::net::{MpcBackendKind, MpcCurveConfig};
use stoffel_vm_runner::{LocalCoordinatorRunOutput, LocalCoordinatorRunner};
use stoffel_vm_types::compiled_binary::{CompiledBinary, MpcBackend};
use stoffel_vm_types::core_types::{ShareDataFormat, ShareType};

const RETURNED_SECRET: i64 = 42;

fn compile_returned_share_program(backend: MpcBackend) -> CompiledBinary {
    let source =
        format!("def main() -> Share:\n  return Share.from_clear_int({RETURNED_SECRET}, 64)\n");
    let options = stoffellang::CompilerOptions {
        mpc_backend: backend,
        ..Default::default()
    };
    let compiled = stoffellang::compile(&source, "<opaque-share-e2e>", &options)
        .expect("compile returned-share program");
    stoffellang::convert_to_binary(&compiled)
}

fn assert_unrevealed_return_shares(
    output: &LocalCoordinatorRunOutput,
    expected_format: ShareDataFormat,
) {
    assert_eq!(output.party_outputs.len(), 5);
    assert_eq!(output.returned_values().len(), 5);
    assert!(
        !output
            .combined_output
            .contains("Program returned a secret share, revealing"),
        "runner attempted to auto-reveal a returned share:\n{}",
        output.combined_output
    );

    let shares = output.returned_shares().expect("decode returned shares");
    assert_eq!(
        shares.len(),
        output.party_outputs.len(),
        "expected each party to return a sealed share:\n{}",
        output.combined_output
    );
    for share in &shares {
        assert_eq!(share.share_type, ShareType::secret_int(64));
        assert_eq!(share.format, expected_format);
        assert!(!share.as_bytes().is_empty());

        // A party-local consumer can seal or hash the exact serialized share
        // without asking the VM to reconstruct the underlying secret.
        let sealed = blake3::hash(share.as_bytes());
        assert_ne!(sealed.as_bytes(), &[0_u8; 32]);
    }
    for party in &output.party_outputs {
        assert_eq!(party.returned_shares().unwrap().len(), 1);
    }

    let error = output.consistent_returned_values().unwrap_err();
    assert!(error.contains("party-local"), "unexpected error: {error}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator and HoneyBadger MPC party mesh"]
async fn honeybadger_returns_an_opaque_share_without_auto_reveal() {
    let binary = compile_returned_share_program(MpcBackend::HoneyBadger);
    let output = LocalCoordinatorRunner::builder(env!("CARGO_BIN_EXE_stoffel-run"), binary)
        .backend(MpcBackendKind::HoneyBadger)
        .parties(5)
        .threshold(1)
        .timeout(Duration::from_secs(180))
        .build()
        .expect("local HoneyBadger runner config")
        .run()
        .await
        .expect("local HoneyBadger returned-share run");

    assert_unrevealed_return_shares(&output, ShareDataFormat::Opaque);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator and AVSS MPC party mesh"]
async fn avss_returns_a_feldman_share_without_auto_reveal() {
    let binary = compile_returned_share_program(MpcBackend::Avss);
    let output = LocalCoordinatorRunner::builder(env!("CARGO_BIN_EXE_stoffel-run"), binary)
        .backend(MpcBackendKind::Avss)
        .curve(MpcCurveConfig::Bls12_381)
        .parties(5)
        .threshold(1)
        .timeout(Duration::from_secs(180))
        .build()
        .expect("local AVSS runner config")
        .run()
        .await
        .expect("local AVSS returned-share run");

    assert_unrevealed_return_shares(&output, ShareDataFormat::Feldman);
}
