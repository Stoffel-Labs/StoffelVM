use std::collections::HashMap;
use std::time::Duration;

use stoffel_vm::net::{MpcBackendKind, MpcCurveConfig};
use stoffel_vm_runner::{
    LocalClientInput, LocalCoordinatorRunOutput, LocalCoordinatorRunner, LocalPartyOutput,
};
use stoffel_vm_types::compiled_binary::{ClientIoManifest, ClientIoSchema, CompiledBinary};
use stoffel_vm_types::core_types::{ShareDataFormat, ShareType, Value};
use stoffel_vm_types::functions::VMFunction;
use stoffel_vm_types::instructions::Instruction;

fn assert_all_parties_proposed(output: &LocalCoordinatorRunOutput, round: &str) {
    let needle = format!("proposing {round}");
    let proposals = output.combined_output.matches(&needle).count();
    let expected = output.party_outputs.len();
    assert!(
        proposals >= expected,
        "expected all {expected} parties to propose {round}, saw {proposals}; output:\n{}",
        output.combined_output
    );
}

fn assert_round_skipped(output: &LocalCoordinatorRunOutput, round: &str) {
    assert!(
        !output
            .combined_output
            .contains(&format!("proposing {round}")),
        "expected {round} to be skipped; output:\n{}",
        output.combined_output
    );
}

fn assert_all_parties_acknowledged_completion(output: &LocalCoordinatorRunOutput) {
    let acknowledgements = output
        .combined_output
        .matches("local runner acknowledged coordinated execution completion")
        .count();
    assert_eq!(
        acknowledgements,
        output.party_outputs.len(),
        "every successful party must acknowledge lifecycle completion; output:\n{}",
        output.combined_output
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator and MPC party mesh"]
async fn local_offchain_coordinator_runs_networked_vm_without_docker_compose() {
    let function = VMFunction::new(
        "main".to_owned(),
        Vec::new(),
        Vec::new(),
        None,
        1,
        vec![Instruction::LDI(0, Value::I64(7)), Instruction::RET(0)],
        HashMap::new(),
    );
    let binary = CompiledBinary::from_vm_functions(&[function]);

    let output = LocalCoordinatorRunner::builder(env!("CARGO_BIN_EXE_stoffel-run"), binary)
        .parties(5)
        .threshold(1)
        .timeout(Duration::from_secs(180))
        .build()
        .expect("local runner config")
        .run()
        .await
        .expect("local coordinator run");

    assert_eq!(output.returned_values(), vec!["7", "7", "7", "7", "7"]);
    assert_eq!(output.consistent_returned_values().unwrap(), vec!["7"]);
    assert_all_parties_proposed(&output, "Preprocessing");
    assert_round_skipped(&output, "InputMaskReservation");
    assert_round_skipped(&output, "InputCollection");
    assert_all_parties_proposed(&output, "MPCExecution");
    assert_round_skipped(&output, "OutputDistribution");
    assert_all_parties_proposed(&output, "ProgramFinished");
    assert_all_parties_acknowledged_completion(&output);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator and AVSS MPC party mesh"]
async fn local_offchain_coordinator_runs_avss_networked_vm_without_docker_compose() {
    let function = VMFunction::new(
        "main".to_owned(),
        Vec::new(),
        Vec::new(),
        None,
        1,
        vec![Instruction::LDI(0, Value::I64(7)), Instruction::RET(0)],
        HashMap::new(),
    );
    let mut binary = CompiledBinary::from_vm_functions(&[function]);
    binary.client_io_manifest.mpc_backend = stoffel_vm_types::compiled_binary::MpcBackend::Avss;

    let output = LocalCoordinatorRunner::builder(env!("CARGO_BIN_EXE_stoffel-run"), binary)
        .backend(MpcBackendKind::Avss)
        .curve(MpcCurveConfig::Bls12_381)
        .parties(5)
        .threshold(1)
        .timeout(Duration::from_secs(180))
        .build()
        .expect("local runner config")
        .run()
        .await
        .expect("local AVSS coordinator run");

    assert_eq!(output.returned_values(), vec!["7", "7", "7", "7", "7"]);
    assert_eq!(output.consistent_returned_values().unwrap(), vec!["7"]);
    assert_all_parties_proposed(&output, "Preprocessing");
    assert_round_skipped(&output, "InputMaskReservation");
    assert_round_skipped(&output, "InputCollection");
    assert_all_parties_proposed(&output, "MPCExecution");
    assert_round_skipped(&output, "OutputDistribution");
    assert_all_parties_proposed(&output, "ProgramFinished");
    assert_all_parties_acknowledged_completion(&output);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator and AVSS MPC party mesh"]
async fn local_offchain_coordinator_runs_compiled_avss_networked_vm_without_docker_compose() {
    let options = stoffellang::CompilerOptions {
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::Avss,
        ..Default::default()
    };
    let compiled = stoffellang::compile(
        "def main() -> int64:\n  return 7",
        "<local-avss-runner-e2e>",
        &options,
    )
    .expect("compile AVSS no-input program");
    let binary = stoffellang::convert_to_binary(&compiled);
    assert_eq!(
        binary.client_io_manifest.mpc_backend,
        stoffel_vm_types::compiled_binary::MpcBackend::Avss
    );

    let output = LocalCoordinatorRunner::builder(env!("CARGO_BIN_EXE_stoffel-run"), binary)
        .backend(MpcBackendKind::Avss)
        .curve(MpcCurveConfig::Bls12_381)
        .parties(5)
        .threshold(1)
        .timeout(Duration::from_secs(180))
        .build()
        .expect("local runner config")
        .run()
        .await
        .expect("local compiled AVSS coordinator run");

    assert_eq!(output.returned_values(), vec!["7", "7", "7", "7", "7"]);
    assert_eq!(output.consistent_returned_values().unwrap(), vec!["7"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator, AVSS MPC party mesh, and coordinator client"]
async fn local_offchain_coordinator_submits_multiple_avss_clientstore_inputs_without_docker_compose(
) {
    let source = r#"
def main() -> int64:
  var first = ClientStore.take_share(0, 0)
  var second = ClientStore.take_share(0, 1)
  var third = ClientStore.take_share(0, 2)
  return first.open() + second.open() + third.open()
"#;
    let options = stoffellang::CompilerOptions {
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::Avss,
        ..Default::default()
    };
    let compiled = stoffellang::compile(source, "<local-avss-runner-client-e2e>", &options)
        .expect("compile AVSS client input program");
    let binary = stoffellang::convert_to_binary(&compiled);

    let output = LocalCoordinatorRunner::builder(env!("CARGO_BIN_EXE_stoffel-run"), binary)
        .backend(MpcBackendKind::Avss)
        .curve(MpcCurveConfig::Bls12_381)
        .parties(5)
        .threshold(1)
        .timeout(Duration::from_secs(180))
        .client_inputs([LocalClientInput::raw(0, ["42", "11", "7"])])
        .build()
        .expect("local runner config")
        .run()
        .await
        .expect("local AVSS coordinator client input run");

    assert_eq!(output.returned_values(), vec!["60", "60", "60", "60", "60"]);
    assert_eq!(output.consistent_returned_values().unwrap(), vec!["60"]);
    assert_round_skipped(&output, "OutputDistribution");
    assert_all_parties_proposed(&output, "InputMaskReservation");
    assert_all_parties_proposed(&output, "InputCollection");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator, MPC party mesh, and coordinator client"]
async fn local_offchain_coordinator_submits_clientstore_inputs_without_docker_compose() {
    let source = r#"
def main() -> int64:
  var share = ClientStore.take_share(0, 0)
  var opened: int64 = share.open()
  return opened + 5
"#;
    let options = stoffellang::CompilerOptions {
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
        ..Default::default()
    };
    let compiled = stoffellang::compile(source, "<local-runner-e2e>", &options)
        .expect("compile client input program");
    let binary = stoffellang::convert_to_binary(&compiled);

    let output = LocalCoordinatorRunner::builder(env!("CARGO_BIN_EXE_stoffel-run"), binary)
        .parties(5)
        .threshold(1)
        .timeout(Duration::from_secs(180))
        .client_inputs([LocalClientInput::raw(0, ["42"])])
        .build()
        .expect("local runner config")
        .run()
        .await
        .expect("local coordinator run");

    assert_eq!(output.returned_values(), vec!["47", "47", "47", "47", "47"]);
    assert_eq!(output.consistent_returned_values().unwrap(), vec!["47"]);
    assert_all_parties_proposed(&output, "InputMaskReservation");
    assert_all_parties_proposed(&output, "InputCollection");
    assert_all_parties_proposed(&output, "MPCExecution");
    assert_round_skipped(&output, "OutputDistribution");
    assert_all_parties_proposed(&output, "ProgramFinished");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator and long-running MPC AES party mesh"]
async fn local_offchain_coordinator_runs_optimized_aes_circuit_without_docker_compose() {
    // Compiling the optimized AES circuit recurses deeply (the inlined S-box
    // network) and overflows the default test-thread stack, so do it on a
    // dedicated large-stack thread. `CompiledBinary` is `Send`, so the result
    // crosses back to this async context.
    let binary = std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(|| {
            let source = include_str!("../../stoffel-lang/examples/mpc_aes128_circuit/main.stfl");
            let options = stoffellang::CompilerOptions {
                optimize: true,
                mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
                ..Default::default()
            };
            let compiled = stoffellang::compile(source, "<local-runner-aes-e2e>", &options)
                .expect("compile AES");
            stoffellang::convert_to_binary(&compiled)
        })
        .expect("spawn AES compile thread")
        .join()
        .expect("AES compile thread panicked");

    let output = LocalCoordinatorRunner::builder(env!("CARGO_BIN_EXE_stoffel-run"), binary)
        .parties(5)
        .threshold(1)
        .timeout(Duration::from_secs(1800))
        .build()
        .expect("local runner config")
        .run()
        .await
        .expect("local AES coordinator run");

    assert_eq!(output.consistent_returned_values().unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator and MPC party mesh"]
async fn local_offchain_coordinator_runs_honeybadger_batch_mul_40_without_docker_compose() {
    let source = r#"
def main() -> int64:
  var lefts: list[Share] = []
  var rights: list[Share] = []
  for i in 0..40:
    lefts.append(Share.from_clear_int(i % 2, 1))
    rights.append(Share.from_clear_int(1, 1))
  var products = Share.batch_mul(lefts, rights)
  return products[39].open()
"#;
    let options = stoffellang::CompilerOptions {
        optimize: true,
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
        ..Default::default()
    };
    let compiled = stoffellang::compile(source, "<local-runner-batch-mul-40-e2e>", &options)
        .expect("compile batch mul 40");
    let binary = stoffellang::convert_to_binary(&compiled);

    let output = LocalCoordinatorRunner::builder(env!("CARGO_BIN_EXE_stoffel-run"), binary)
        .parties(5)
        .threshold(1)
        .timeout(Duration::from_secs(900))
        .build()
        .expect("local runner config")
        .run()
        .await
        .expect("local batch mul coordinator run");

    assert_eq!(output.consistent_returned_values().unwrap(), vec!["true"]);
}

#[test]
fn local_run_output_reports_consistent_party_return_values() {
    let output = LocalCoordinatorRunOutput {
        combined_output: "Program returned: 5\nProgram returned: 5\n".to_owned(),
        party_outputs: vec![
            party_output("party0", "Program returned: 5\n"),
            party_output("party1", "Program returned: 5\n"),
        ],
        client_outputs: Vec::new(),
    };

    assert_eq!(output.returned_values(), vec!["5", "5"]);
    assert_eq!(output.consistent_returned_values().unwrap(), vec!["5"]);
}

#[test]
fn local_run_output_rejects_inconsistent_party_return_values() {
    let output = LocalCoordinatorRunOutput {
        combined_output: "Program returned: 5\nProgram returned: 6\n".to_owned(),
        party_outputs: vec![
            party_output("party0", "Program returned: 5\n"),
            party_output("party1", "Program returned: 6\n"),
        ],
        client_outputs: Vec::new(),
    };

    let err = output.consistent_returned_values().unwrap_err();
    assert!(
        err.contains("returned"),
        "expected consistency error, got: {err}"
    );
}

#[test]
fn local_run_output_exposes_each_party_share_without_requiring_consistency() {
    let party0 = "Program returned: share:v1[secret-int:64;opaque;3] 0x000102\n";
    let party1 = "Program returned: share:v1[secret-int:64;opaque;3] 0x030405\n";
    let output = LocalCoordinatorRunOutput {
        combined_output: format!("{party0}{party1}"),
        party_outputs: vec![
            party_output("party0", party0),
            party_output("party1", party1),
        ],
        client_outputs: Vec::new(),
    };

    let shares = output.returned_shares().unwrap();
    assert_eq!(shares.len(), 2);
    assert_eq!(shares[0].share_type, ShareType::secret_int(64));
    assert_eq!(shares[0].format, ShareDataFormat::Opaque);
    assert_eq!(shares[0].as_bytes(), &[0x00, 0x01, 0x02]);
    assert_eq!(shares[1].as_bytes(), &[0x03, 0x04, 0x05]);

    assert_eq!(
        output.party_outputs[0].returned_shares().unwrap()[0].as_bytes(),
        &[0x00, 0x01, 0x02]
    );
    let error = output.consistent_returned_values().unwrap_err();
    assert!(error.contains("party-local"), "unexpected error: {error}");
}

fn party_output(name: &str, combined: &str) -> LocalPartyOutput {
    LocalPartyOutput {
        name: name.to_owned(),
        stdout: combined.to_owned(),
        stderr: String::new(),
        combined: combined.to_owned(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a local coordinator, five parties, and asymmetric clients"]
async fn local_indexed_masks_cover_one_two_four_inputs_and_client_outputs() {
    run_indexed_mask_and_client_output_case(
        stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a local coordinator, five AVSS parties, and asymmetric clients"]
async fn local_avss_indexed_masks_cover_one_two_four_inputs_and_client_outputs() {
    run_indexed_mask_and_client_output_case(stoffel_vm_types::compiled_binary::MpcBackend::Avss)
        .await;
}

async fn run_indexed_mask_and_client_output_case(
    backend: stoffel_vm_types::compiled_binary::MpcBackend,
) {
    let source = r#"
def main() -> int64:
  var a = ClientStore.take_share(0, 0)
  var b = ClientStore.take_share(1, 0)
  var c = ClientStore.take_share(1, 1)
  var d = ClientStore.take_share(2, 0)
  var e = ClientStore.take_share(2, 1)
  var f = ClientStore.take_share(2, 2)
  var g = ClientStore.take_share(2, 3)
  var sum = a.add(b).add(c).add(d).add(e).add(f).add(g)
  sum.send_to_client(0)
  sum.send_to_client(3)
  return sum.open()
"#;
    let options = stoffellang::CompilerOptions {
        mpc_backend: backend,
        ..Default::default()
    };
    let compiled = stoffellang::compile(source, "<indexed-local-inputs>", &options)
        .expect("compile asymmetric client inputs");
    let output = LocalCoordinatorRunner::builder(
        env!("CARGO_BIN_EXE_stoffel-run"),
        stoffellang::convert_to_binary(&compiled),
    )
    .client_inputs([
        LocalClientInput::new(0, [1]),
        LocalClientInput::new(1, [2, 3]),
        LocalClientInput::new(2, [4, 5, 6, 7]),
    ])
    .timeout(Duration::from_secs(120))
    .build()
    .unwrap()
    .run()
    .await
    .expect("indexed asymmetric local run");
    assert_eq!(output.consistent_returned_values().unwrap(), vec!["28"]);
    assert_eq!(output.client_outputs.len(), 2);
    assert_eq!(output.client_outputs[0].values, vec![28]);
    assert_eq!(output.client_outputs[1].client_slot, 3);
    assert_eq!(output.client_outputs[1].values, vec![28]);
    assert_all_parties_acknowledged_completion(&output);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts local coordinator meshes with output-only clients on both backends"]
async fn local_output_only_runs_finalize_without_client_inputs() {
    use stoffel_vm_types::compiled_binary::MpcBackend;
    for backend in [MpcBackend::HoneyBadger, MpcBackend::Avss] {
        let options = stoffellang::CompilerOptions {
            mpc_backend: backend,
            ..Default::default()
        };
        let compiled = stoffellang::compile(
            "def main() -> int64:\n  var share = Share.from_clear_int(7, 64)\n  MpcOutput.send_to_client(0, [share])\n  return 7",
            "<output-only-local-run>",
            &options,
        )
        .unwrap();
        let output = LocalCoordinatorRunner::builder(
            env!("CARGO_BIN_EXE_stoffel-run"),
            stoffellang::convert_to_binary(&compiled),
        )
        .timeout(Duration::from_secs(120))
        .build()
        .unwrap()
        .run()
        .await
        .expect("output-only run should not require any mask or party RPC connection");
        assert_eq!(output.consistent_returned_values().unwrap(), vec!["7"]);
        assert_eq!(output.client_outputs.len(), 1);
        assert_eq!(output.client_outputs[0].values, vec![7]);
        assert_round_skipped(&output, "InputMaskReservation");
        assert_round_skipped(&output, "InputCollection");
        assert_all_parties_proposed(&output, "OutputDistribution");
        assert_all_parties_acknowledged_completion(&output);
    }
}

#[test]
fn local_runner_rejects_missing_clientstore_inputs_before_spawning_parties() {
    let mut binary = CompiledBinary::from_vm_functions(&[VMFunction::new(
        "main".to_owned(),
        Vec::new(),
        Vec::new(),
        None,
        1,
        vec![Instruction::LDI(0, Value::I64(7)), Instruction::RET(0)],
        HashMap::new(),
    )]);
    binary.client_io_manifest = ClientIoManifest {
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
        mpc_curve: stoffel_vm_types::compiled_binary::MpcCurve::Bls12_381,
        clients: vec![ClientIoSchema {
            client_slot: 0,
            inputs: vec![ShareType::default_secret_int()],
            outputs: Vec::new(),
        }],
        preprocessing_demand: stoffel_vm_types::compiled_binary::PreprocessingDemand::default(),
        dynamic_client_inputs: Vec::new(),
    };

    let err = LocalCoordinatorRunner::builder(env!("CARGO_BIN_EXE_stoffel-run"), binary)
        .build()
        .unwrap_err();

    assert!(
        err.to_string().contains("provide local client inputs"),
        "unexpected error: {err}"
    );
}

#[test]
fn local_runner_accepts_static_output_only_clients_without_inputs() {
    let mut binary = CompiledBinary::from_vm_functions(&[VMFunction::new(
        "main".to_owned(),
        Vec::new(),
        Vec::new(),
        None,
        1,
        vec![Instruction::LDI(0, Value::I64(7)), Instruction::RET(0)],
        HashMap::new(),
    )]);
    binary.client_io_manifest = ClientIoManifest {
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
        mpc_curve: stoffel_vm_types::compiled_binary::MpcCurve::Bls12_381,
        clients: vec![ClientIoSchema {
            client_slot: 0,
            inputs: Vec::new(),
            outputs: vec![ShareType::default_secret_int()],
        }],
        preprocessing_demand: stoffel_vm_types::compiled_binary::PreprocessingDemand::default(),
        dynamic_client_inputs: Vec::new(),
    };

    LocalCoordinatorRunner::builder(env!("CARGO_BIN_EXE_stoffel-run"), binary)
        .build()
        .expect("output-only client manifests should not require client input");
}

#[test]
fn local_runner_rejects_expected_output_clients_below_static_manifest_slots() {
    let mut binary = CompiledBinary::from_vm_functions(&[VMFunction::new(
        "main".to_owned(),
        Vec::new(),
        Vec::new(),
        None,
        1,
        vec![Instruction::LDI(0, Value::I64(7)), Instruction::RET(0)],
        HashMap::new(),
    )]);
    binary.client_io_manifest = ClientIoManifest {
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
        mpc_curve: stoffel_vm_types::compiled_binary::MpcCurve::Bls12_381,
        clients: vec![ClientIoSchema {
            client_slot: 2,
            inputs: Vec::new(),
            outputs: vec![ShareType::default_secret_int()],
        }],
        preprocessing_demand: stoffel_vm_types::compiled_binary::PreprocessingDemand::default(),
        dynamic_client_inputs: Vec::new(),
    };

    let err = LocalCoordinatorRunner::builder(env!("CARGO_BIN_EXE_stoffel-run"), binary)
        .expected_output_clients(2)
        .build()
        .unwrap_err();

    assert!(
        err.to_string().contains("expected_clients >= 3"),
        "unexpected error: {err}"
    );
}

#[test]
fn local_runner_rejects_duplicate_client_input_slots() {
    let mut binary = CompiledBinary::from_vm_functions(&[VMFunction::new(
        "main".to_owned(),
        Vec::new(),
        Vec::new(),
        None,
        1,
        vec![Instruction::LDI(0, Value::I64(7)), Instruction::RET(0)],
        HashMap::new(),
    )]);
    binary.client_io_manifest = ClientIoManifest {
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
        mpc_curve: stoffel_vm_types::compiled_binary::MpcCurve::Bls12_381,
        clients: vec![ClientIoSchema {
            client_slot: 0,
            inputs: vec![ShareType::default_secret_int()],
            outputs: Vec::new(),
        }],
        preprocessing_demand: stoffel_vm_types::compiled_binary::PreprocessingDemand::default(),
        dynamic_client_inputs: Vec::new(),
    };

    let err = LocalCoordinatorRunner::builder(env!("CARGO_BIN_EXE_stoffel-run"), binary)
        .client_inputs([LocalClientInput::new(0, [1]), LocalClientInput::new(0, [2])])
        .build()
        .unwrap_err();

    assert!(
        err.to_string().contains("provided more than once"),
        "unexpected error: {err}"
    );
}
