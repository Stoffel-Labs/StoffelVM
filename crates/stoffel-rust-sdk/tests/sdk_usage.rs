use std::collections::BTreeMap;
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

use stoffel::prelude::*;
use stoffel_bindgen::{generate_bindings, BindingsConfig};
use stoffel_vm_types::compiled_binary::{ClientIoManifest, ClientIoSchema, CompiledBinary};
use stoffel_vm_types::core_types::ShareType;
use tempfile::tempdir;
use tracing::Level;

const ADD_SOURCE: &str = r#"
def main(a: secret int64, b: secret int64) -> secret int64:
  return a + b
"#;

const CLEAR_ADD_SOURCE: &str = r#"
def main(a: int64, b: int64) -> int64:
  return a + b
"#;

fn offchain_config_builder() -> OffChainClientConfigBuilder {
    OffChainClientConfig::builder().execution_id(ExecutionId::from_bytes([0x51; 32]))
}

mod federated_average_bindings {
    include!("fixtures/mpc_client_federated_average_bindings.rs");
}

#[test]
fn public_sdk_types_are_send_and_sync_where_expected() {
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<Stoffel>();
    assert_send_sync::<StoffelRuntime>();
    assert_send_sync::<stoffel::LocalNetworkBuilder<'static>>();
    assert_send_sync::<LocalShareExecutionOutput>();
    assert_send_sync::<LocalPartyShareOutput>();
    assert_send_sync::<OpaqueShare>();
    assert_send_sync::<Program>();
    assert_send_sync::<ProgramSummary>();
    assert_send_sync::<BytecodeSummary>();
    assert_send_sync::<FunctionSummary>();
    assert_send_sync::<ClientMetadataSummary>();
    assert_send_sync::<FunctionMetadata<'static>>();
    assert_send_sync::<ClientMetadata<'static>>();
    assert_send_sync::<BindingsConfig>();

    assert_send_sync::<MpcConfig>();
    assert_send_sync::<MpcConfigBuilder>();
    assert_send_sync::<NetworkConfig>();
    assert_send_sync::<NetworkConfigBuilder>();
    assert_send_sync::<NetworkDeployment>();
    assert_send_sync::<NetworkDeploymentBuilder>();
    assert_send_sync::<NetworkSection>();
    assert_send_sync::<MpcSection>();
    assert_send_sync::<PreprocessingConfig>();
    assert_send_sync::<Curve>();
    assert_send_sync::<MpcBackend>();

    assert_send_sync::<ClientBuilder>();
    assert_send_sync::<OffChainClientConfig>();
    assert_send_sync::<OffChainClientConfigBuilder>();
    assert_send_sync::<StoffelClient>();
    assert_send_sync::<ComputationHandle>();
    assert_send_sync::<ClientState>();
    assert_send_sync::<ComputationStatus>();

    assert_send_sync::<ServerBuilder>();
    assert_send_sync::<OffChainServerConfig>();
    assert_send_sync::<OffChainServerConfigBuilder>();
    assert_send_sync::<StoffelServer>();
    assert_send_sync::<ServerState>();
    assert_send_sync::<ServerMetrics>();
    assert_send_sync::<ServerMetricsSnapshot>();
    assert_send_sync::<HealthStatus>();
    assert_send_sync::<ConsensusGate>();
    assert_send_sync::<VerifiedOrdering>();
    assert_send_sync::<NodePublicKey>();

    assert_send_sync::<Value>();
    assert_send_sync::<ClientValueType>();
    assert_send_sync::<Share>();
    assert_send_sync::<PublicKey>();
    assert_send_sync::<FieldElement>();
    assert_send_sync::<GroupElement>();

    assert_send_sync::<HoneyBadgerBackend>();
    assert_send_sync::<AvssBackend>();
    assert_send_sync::<AvssEngine>();
    assert_send_sync::<stoffel::AvssEngine>();

    assert_send_sync::<TracingConfig>();
    assert_send_sync::<TracingConfigBuilder>();
    assert_send_sync::<TracingConfigSummary>();
    assert_send_sync::<OpenTelemetryGuard>();
}

#[test]
fn crate_root_reexports_common_reference_sdk_types() {
    fn type_name<T>() -> &'static str {
        std::any::type_name::<T>()
    }

    assert!(type_name::<stoffel::MpcConfigBuilder>().contains("MpcConfigBuilder"));
    assert!(type_name::<stoffel::NetworkConfigBuilder>().contains("NetworkConfigBuilder"));
    assert!(type_name::<stoffel::NetworkDeployment>().contains("NetworkDeployment"));
    assert!(type_name::<stoffel::NetworkDeploymentBuilder>().contains("NetworkDeploymentBuilder"));
    assert!(type_name::<stoffel::ProgramSummary>().contains("ProgramSummary"));
    assert!(type_name::<stoffel::BytecodeSummary>().contains("BytecodeSummary"));
    assert!(type_name::<stoffel::FunctionSummary>().contains("FunctionSummary"));
    assert!(type_name::<stoffel::ClientMetadataSummary>().contains("ClientMetadataSummary"));
    assert!(type_name::<stoffel::NetworkSection>().contains("NetworkSection"));
    assert!(type_name::<stoffel::MpcSection>().contains("MpcSection"));
    assert!(type_name::<stoffel::PreprocessingConfig>().contains("PreprocessingConfig"));
    assert!(type_name::<stoffel::ClientState>().contains("ClientState"));
    assert!(type_name::<BindingsConfig>().contains("BindingsConfig"));
    assert!(type_name::<stoffel::ClientValueType>().contains("ClientValueType"));
    assert!(type_name::<stoffel::ServerState>().contains("ServerState"));
    assert!(type_name::<stoffel::HealthStatus>().contains("HealthStatus"));
    assert!(type_name::<stoffel::ServerMetrics>().contains("ServerMetrics"));
    assert!(type_name::<stoffel::ServerMetricsSnapshot>().contains("ServerMetricsSnapshot"));
    assert!(type_name::<stoffel::TracingConfigSummary>().contains("TracingConfigSummary"));
    assert!(type_name::<stoffel::QuicNetworkConfig>().contains("QuicNetworkConfig"));
    assert!(type_name::<stoffel::AvssEngine>().contains("AvssEngine"));
    assert!(type_name::<stoffel::LocalNetworkBuilder<'static>>().contains("LocalNetworkBuilder"));

    let _party_id: stoffel::PartyId = 0;
    let _client_id: stoffel::ClientId = 0;
    let _round: stoffel::Round = stoffel::coordinator::Round::Preprocessing;
    let _mask_index: stoffel::MaskIndex = 0;
    let _share = stoffel::Share::new("root-share");
    let _public_key = stoffel::PublicKey::new("root-key", [1_u8, 2, 3]);
    let _field = stoffel::FieldElement::from_bytes([4_u8, 5, 6]);
    let _group = stoffel::GroupElement::from_bytes([7_u8, 8, 9]);
}

#[test]
fn load_program_executes_loaded_bytecode_with_positional_args() -> stoffel::Result<()> {
    let runtime = Stoffel::compile(CLEAR_ADD_SOURCE)?.build()?;
    let bytecode = runtime.to_bytecode()?;

    let program = Stoffel::load_program(bytecode)?;
    let result = program.execute("main", (40_i64, 2_i64))?;

    assert_eq!(result, vec![Value::I64(42)]);
    Ok(())
}

#[test]
fn load_program_accepts_compiled_program_and_path() -> stoffel::Result<()> {
    let runtime = Stoffel::compile(CLEAR_ADD_SOURCE)?.build()?;
    let program = runtime.program().clone();

    let loaded = Stoffel::load_program(program)?;
    assert_eq!(
        loaded.execute("main", (5_i64, 7_i64))?,
        vec![Value::I64(12)]
    );

    let temp = tempdir()?;
    let bytecode_path = temp.path().join("program.stflb");
    runtime.save_bytecode(&bytecode_path)?;
    let loaded_from_path = Stoffel::load_program(bytecode_path.as_path())?;
    assert_eq!(
        loaded_from_path.execute("main", (3_i64, 4_i64))?,
        vec![Value::I64(7)]
    );
    Ok(())
}

#[test]
fn execute_supports_zero_and_single_argument_calls() -> stoffel::Result<()> {
    let no_args = Stoffel::compile("def main() -> int64:\n  return 42")?.build()?;
    assert_eq!(no_args.execute("main", ())?, vec![Value::I64(42)]);

    let single_arg =
        Stoffel::compile("def main(value: int64) -> int64:\n  return value + 1")?.build()?;
    assert_eq!(single_arg.execute("main", 41_i64)?, vec![Value::I64(42)]);
    Ok(())
}

#[test]
fn execute_validates_positional_argument_shape_against_binary_metadata() -> stoffel::Result<()> {
    let program = Stoffel::compile(CLEAR_ADD_SOURCE)?.build()?;

    let missing = program.execute("main", 40_i64).unwrap_err().to_string();
    assert!(missing.contains("expects 2 argument(s), got 1"));

    let wrong_type = program
        .execute("main", ("forty", 2_i64))
        .unwrap_err()
        .to_string();
    assert!(wrong_type.contains("input 'a' expects"));
    assert!(wrong_type.contains("got string"));
    Ok(())
}

#[test]
fn generate_bindings_emits_typed_client_io_from_stflb_manifest() -> stoffel::Result<()> {
    let runtime = Stoffel::compile(
        r#"
def main() -> int64:
  var left = ClientStore.take_share(0, 0)
  var right = ClientStore.take_share_fixed(0, 1)
  MpcOutput.send_to_client(0, [left, right])
  return 0
"#,
    )?
    .build()?;
    let temp = tempdir()?;
    let bytecode_path = temp.path().join("program.stflb");
    let bindings_path = temp.path().join("stoffel_bindings.rs");
    runtime.program().save_bytecode(&bytecode_path)?;

    generate_bindings(&bytecode_path, &bindings_path).expect("bindings should generate");
    let generated = std::fs::read_to_string(bindings_path)?;

    assert!(generated.contains("pub struct Client0Inputs"));
    assert!(generated.contains("pub struct ProgramManifest"));
    assert!(generated.contains("impl stoffel::GeneratedProgramManifest for ProgramManifest"));
    assert!(
        generated.contains("const BACKEND: stoffel::MpcBackend = stoffel::MpcBackend::HoneyBadger")
    );
    assert!(generated.contains("pub input_0: i64"));
    assert!(generated.contains("pub input_1: f64"));
    assert!(generated.contains("impl stoffel::TypedClientInputs for Client0Inputs"));
    assert!(generated.contains("pub struct Client0Outputs"));
    assert!(generated.contains("pub output_0: i64"));
    assert!(generated.contains("pub output_1: f64"));
    assert!(generated.contains("impl stoffel::TypedClientOutputs for Client0Outputs"));
    Ok(())
}

#[test]
fn generate_bindings_preserves_secret_integer_widths() -> stoffel::Result<()> {
    let mut binary = CompiledBinary::new();
    binary.client_io_manifest = ClientIoManifest {
        clients: vec![ClientIoSchema {
            client_slot: 0,
            inputs: vec![
                ShareType::secret_int(8),
                ShareType::secret_int(16),
                ShareType::secret_int(32),
                ShareType::secret_int(64),
                ShareType::secret_uint(8),
                ShareType::secret_uint(16),
                ShareType::secret_uint(32),
                ShareType::secret_uint(64),
            ],
            outputs: vec![
                ShareType::secret_int(8),
                ShareType::secret_int(16),
                ShareType::secret_int(32),
                ShareType::secret_int(64),
                ShareType::secret_uint(8),
                ShareType::secret_uint(16),
                ShareType::secret_uint(32),
                ShareType::secret_uint(64),
            ],
        }],
        ..Default::default()
    };
    let program = Program::new(binary);
    let temp = tempdir()?;
    let bytecode_path = temp.path().join("unsigned.stflb");
    let bindings_path = temp.path().join("stoffel_bindings.rs");
    program.save_bytecode(&bytecode_path)?;

    generate_bindings(&bytecode_path, &bindings_path).expect("bindings should generate");
    let generated = std::fs::read_to_string(bindings_path)?;

    for (ordinal, rust_type) in ["i8", "i16", "i32", "i64", "u8", "u16", "u32", "u64"]
        .into_iter()
        .enumerate()
    {
        assert!(generated.contains(&format!("pub input_{ordinal}: {rust_type}")));
        assert!(generated.contains(&format!("pub output_{ordinal}: {rust_type}")));
    }
    assert!(generated.contains("stoffel::ClientValueType::Integer"));
    Ok(())
}

#[test]
fn generated_bindings_type_check_federated_average_example() -> stoffel::Result<()> {
    let sdk_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_dir = sdk_dir
        .parent()
        .and_then(Path::parent)
        .expect("SDK crate lives under crates/");
    let example_path =
        workspace_dir.join("crates/stoffel-lang/examples/mpc_client_federated_average/main.stfl");
    let runtime = Stoffel::compile_file(&example_path)?
        .parties(5)
        .threshold(1)
        .build()?;
    let client = runtime
        .program()
        .client(0)
        .expect("federated average example declares client slot 0 IO");
    assert_eq!(client.input_count(), 6);
    assert_eq!(client.output_count(), 6);

    let temp = tempdir()?;
    let bytecode_path = temp.path().join("mpc_client_federated_average.stflb");
    let bindings_path = temp.path().join("stoffel_bindings.rs");
    runtime.program().save_bytecode(&bytecode_path)?;
    generate_bindings(&bytecode_path, &bindings_path).expect("bindings should generate");
    let generated = std::fs::read_to_string(&bindings_path)?;
    assert!(generated.contains("pub struct Client0Inputs"));
    assert!(generated.contains("pub struct ProgramManifest"));
    assert!(generated.contains("impl stoffel::GeneratedProgramManifest for ProgramManifest"));
    assert!(generated.contains("impl stoffel::TypedClientInputs for Client0Inputs"));
    assert!(generated.contains("pub struct Client0Outputs"));
    assert!(generated.contains("impl stoffel::TypedClientOutputs for Client0Outputs"));
    for ordinal in 0..6 {
        assert!(generated.contains(&format!("pub input_{ordinal}: f64")));
        assert!(generated.contains(&format!("pub output_{ordinal}: f64")));
    }

    use federated_average_bindings::{Client0Inputs, Client0Outputs, ProgramManifest};
    let typed_client = StoffelClient::builder()
        .server("127.0.0.1:1")
        .client_id(0)
        .with_program(runtime.program().clone())
        .build()?;
    let typed_call = typed_client
        .run_typed_with_manifest::<ProgramManifest, Client0Inputs, Client0Outputs>(Client0Inputs {
            input_0: 1.0,
            input_1: 2.0,
            input_2: 3.0,
            input_3: 4.0,
            input_4: 5.0,
            input_5: 6.0,
        });
    drop(typed_call);
    let output = Client0Outputs {
        output_0: 8.0,
        output_1: 10.0,
        output_2: 12.0,
        output_3: 14.0,
        output_4: 16.0,
        output_5: 18.0,
    };
    assert_eq!(output.output_0, 8.0);
    Ok(())
}

#[test]
fn generated_manifest_marker_selects_backend_and_curve() -> stoffel::Result<()> {
    use federated_average_bindings::ProgramManifest;

    let mpc = MpcConfig::builder().manifest::<ProgramManifest>().build()?;
    assert_eq!(mpc.backend, MpcBackend::HoneyBadger);

    let runtime = Stoffel::compile("def main() -> int64:\n  return 0")?
        .manifest::<ProgramManifest>()
        .build()?;
    assert_eq!(
        runtime.mpc_config().unwrap().backend,
        MpcBackend::HoneyBadger
    );

    let network = NetworkConfig::builder()
        .party_id(0)
        .bind_address("127.0.0.1:19800")
        .expected_parties(5)
        .threshold(1)
        .manifest::<ProgramManifest>()
        .build()?;
    assert_eq!(network.mpc_backend()?, MpcBackend::HoneyBadger);
    Ok(())
}

#[tokio::test]
async fn typed_client_run_validates_manifest_types_before_network_submission() -> stoffel::Result<()>
{
    let program = Stoffel::compile(
        r#"
def main() -> int64:
  var share = ClientStore.take_share(0, 0)
  MpcOutput.send_to_client(0, [share])
  return 0
"#,
    )?
    .build()?
    .program()
    .clone();
    let client = StoffelClient::builder()
        .server("127.0.0.1:1")
        .client_id(0)
        .with_program(program)
        .build()?;

    let mismatch = client.run_typed::<i64, bool>(55_i64).await.unwrap_err();
    assert!(matches!(
        mismatch,
        stoffel::Error::InvalidInput(message)
            if message.contains("output 0 expects SecretInt") && message.contains("Boolean")
    ));

    let missing_config = client.run_typed::<i64, i64>(55_i64).await.unwrap_err();
    assert!(matches!(
        missing_config,
        stoffel::Error::Configuration(message)
            if message.contains("off-chain client IO configuration")
    ));
    Ok(())
}

#[test]
fn sdk_source_tree_does_not_reintroduce_legacy_modules() {
    let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for module in [
        "advanced",
        "secret_sharing",
        "network_helpers",
        "mpc_local",
        "network_config",
        "session",
        "stoffel_mpc",
        "mpc_network",
    ] {
        assert!(
            !src_dir.join(format!("{module}.rs")).exists(),
            "legacy module {module}.rs must not be present"
        );
        assert!(
            !src_dir.join(module).exists(),
            "legacy module directory {module}/ must not be present"
        );
    }
}

#[test]
fn compiles_source_and_exposes_program_metadata() -> stoffel::Result<()> {
    let runtime = Stoffel::compile(ADD_SOURCE)?
        .parties(5)
        .threshold(1)
        .backend(MpcBackend::HoneyBadger)
        .build()?;

    let main = runtime.program().main().unwrap();
    assert_eq!(main.name(), "main");
    assert_eq!(main.to_string(), "main(a, b)");
    assert_eq!(main.arg_count(), 2);
    assert_eq!(main.parameters(), &["a".to_string(), "b".to_string()]);
    assert_eq!(main.parameter_names().collect::<Vec<_>>(), ["a", "b"]);
    assert!(main.register_count() >= 2);
    assert!(main.instruction_count() > 0);
    assert_eq!(main.upvalue_count(), 0);
    assert_eq!(main.parent(), None);
    let main_summary = main.summary();
    assert_eq!(main_summary.name, "main");
    assert_eq!(main_summary.arg_count, 2);
    assert_eq!(
        main_summary.parameters,
        vec!["a".to_owned(), "b".to_owned()]
    );
    assert_eq!(main_summary.instruction_count, main.instruction_count());
    assert_eq!(main_summary.parent, None);
    assert_eq!(runtime.program().function_count(), 1);
    let functions = runtime.program().functions().collect::<Vec<_>>();
    assert_eq!(functions.len(), 1);
    assert_eq!(functions[0].name(), "main");
    assert_eq!(
        runtime.program().function_names().collect::<Vec<_>>(),
        ["main"]
    );
    assert_eq!(
        runtime.program().total_instruction_count(),
        main.instruction_count()
    );
    assert!(runtime.program().total_register_count() >= main.register_count());
    let summary = runtime.program().summary();
    assert_eq!(summary.function_count, 1);
    assert_eq!(summary.function_names, vec!["main".to_owned()]);
    assert_eq!(summary.functions, vec![main_summary]);
    assert_eq!(summary.bytecode_backend, "honeybadger");
    assert_eq!(summary.bytecode_curve, "bls12_381");
    assert_eq!(summary.client_count, 0);
    assert!(summary.clients.is_empty());
    assert_eq!(summary.minimum_expected_clients, 0);
    assert!(toml::to_string(&summary)?.contains("bytecode_backend = \"honeybadger\""));
    assert!(toml::to_string(&summary)?.contains("bytecode_curve = \"bls12_381\""));
    assert!(toml::to_string(&summary)?.contains("[[functions]]"));
    assert_eq!(runtime.mpc_config().unwrap().parties, 5);
    Ok(())
}

#[test]
fn clientstore_program_exposes_client_input_metadata() -> stoffel::Result<()> {
    let runtime = Stoffel::compile(
        r#"
def main() -> int64:
  var share = ClientStore.take_share(0, 0)
  var opened: int64 = share.open()
  return opened
"#,
    )?
    .parties(5)
    .threshold(1)
    .build()?;

    let program = runtime.program();
    assert!(program.has_client_io());
    assert_eq!(program.client_count(), 1);
    assert_eq!(program.client_slots().collect::<Vec<_>>(), vec![0]);
    assert_eq!(program.total_client_input_count(), 1);
    assert_eq!(program.total_client_output_count(), 0);
    assert_eq!(program.minimum_expected_clients(), 1);
    let summary = program.summary();
    assert_eq!(summary.client_count, 1);
    assert_eq!(summary.client_slots, vec![0]);
    assert_eq!(summary.clients.len(), 1);
    assert_eq!(summary.total_client_input_count, 1);
    assert_eq!(summary.minimum_expected_clients, 1);
    let client_values = [Value::I64(42)];
    program.validate_client_inputs(&[(0, client_values.as_slice())])?;

    let client = program.client(0).expect("client slot 0 metadata");
    assert_eq!(client.client_slot(), 0);
    assert_eq!(client.to_string(), "client 0: 1 input(s), 0 output(s)");
    assert_eq!(client.input_count(), 1);
    assert_eq!(client.output_count(), 0);
    assert_eq!(
        client.inputs(),
        &[stoffel_vm_types::core_types::ShareType::default_secret_int()]
    );
    let client_summary = client.summary();
    assert_eq!(client_summary.client_slot, 0);
    assert_eq!(client_summary.input_count, 1);
    assert_eq!(client_summary.output_count, 0);
    assert_eq!(
        client_summary.inputs,
        vec![stoffel_vm_types::core_types::ShareType::default_secret_int()]
    );
    assert_eq!(summary.clients, vec![client_summary]);
    assert!(program.client(1).is_none());
    let client_slots = program
        .clients()
        .map(|client| client.client_slot())
        .collect::<Vec<_>>();
    assert_eq!(client_slots, vec![0]);
    Ok(())
}

#[test]
fn bytecode_round_trip_supports_cli_compatible_load_path() -> stoffel::Result<()> {
    let dir = tempdir()?;
    let bytecode_path = dir.path().join("program.stflb");
    let runtime = Stoffel::compile(ADD_SOURCE)?.build()?;
    let bytecode = runtime.to_bytecode()?;
    runtime.save_bytecode(&bytecode_path)?;
    let summary = runtime.bytecode_summary()?;
    assert_eq!(summary.byte_len, bytecode.len());
    assert_eq!(summary.program.function_names, vec!["main".to_owned()]);
    assert_eq!(summary.program.bytecode_backend, "honeybadger");
    assert_eq!(summary.program.bytecode_curve, "bls12_381");
    let summary_toml = toml::to_string(&summary)?;
    assert!(summary_toml.contains("byte_len"));
    assert!(summary_toml.contains("[program]"));
    let reparsed_summary: BytecodeSummary = toml::from_str(&summary_toml)?;
    assert_eq!(reparsed_summary, summary);

    let loaded = Stoffel::load(&bytecode)?.build()?;
    assert!(loaded.program().function("main").is_some());
    assert_eq!(loaded.program().bytecode_summary()?, summary);

    let loaded_from_file = Stoffel::load_file(&bytecode_path)?.build()?;
    assert!(loaded_from_file.program().function("main").is_some());

    let program_from_file = stoffel::Program::from_bytecode_file(&bytecode_path)?;
    assert_eq!(
        program_from_file.function_count(),
        runtime.program().function_count()
    );
    assert_eq!(
        program_from_file.bytecode_backend(),
        stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger
    );
    Ok(())
}

#[test]
fn bytecode_load_rejects_trailing_data() -> stoffel::Result<()> {
    let dir = tempdir()?;
    let bytecode_path = dir.path().join("corrupt.stflb");
    let runtime = Stoffel::compile(ADD_SOURCE)?.build()?;
    let mut bytecode = runtime.program().to_bytecode()?;
    bytecode.extend_from_slice(b"trailing");
    std::fs::write(&bytecode_path, &bytecode)?;

    let err = Stoffel::load(&bytecode)?.build().unwrap_err();
    assert!(matches!(err, stoffel::Error::Bytecode(_)));

    let err = stoffel::Program::from_bytecode(&bytecode).unwrap_err();
    assert!(matches!(err, stoffel::Error::Bytecode(_)));

    let err = stoffel::Program::from_bytecode_file(&bytecode_path).unwrap_err();
    assert!(matches!(err, stoffel::Error::Bytecode(_)));
    Ok(())
}

#[test]
fn empty_bytecode_is_rejected_at_runtime_build() -> stoffel::Result<()> {
    let program = stoffel::Program::new(CompiledBinary::new());
    assert!(program.is_empty());
    assert!(program.main().is_none());

    let bytecode = program.to_bytecode()?;
    let err = Stoffel::load(&bytecode)?.build().unwrap_err();
    assert!(matches!(err, stoffel::Error::Configuration(_)));
    Ok(())
}

#[test]
fn loaded_bytecode_backend_metadata_is_validated() -> stoffel::Result<()> {
    let avss_runtime = Stoffel::compile(ADD_SOURCE)?.avss(Curve::Ed25519).build()?;
    let bytecode = avss_runtime.program().to_bytecode()?;

    let inferred = Stoffel::load(&bytecode)?.build()?;
    assert_eq!(
        inferred.mpc_config().unwrap().backend,
        MpcBackend::Avss {
            curve: Curve::Ed25519
        }
    );
    assert_eq!(
        inferred.program().bytecode_curve(),
        stoffel_vm_types::compiled_binary::MpcCurve::Ed25519
    );

    let explicit = Stoffel::load(&bytecode)?.avss(Curve::Ed25519).build()?;
    assert_eq!(
        explicit.program().bytecode_backend(),
        stoffel_vm_types::compiled_binary::MpcBackend::Avss
    );
    assert_eq!(explicit.program().summary().bytecode_curve, "ed25519");

    let honeybadger_network = NetworkConfig::builder()
        .party_id(0)
        .bind_address("127.0.0.1:19620")
        .expected_parties(5)
        .threshold(1)
        .honeybadger()
        .build()?;
    let err = Stoffel::load(&bytecode)?
        .network_config(honeybadger_network)
        .build()
        .unwrap_err();
    assert!(matches!(err, stoffel::Error::Configuration(_)));
    Ok(())
}

#[test]
fn compiles_from_file_and_loads_network_config_file() -> stoffel::Result<()> {
    let dir = tempdir()?;
    let source_path = dir.path().join("program.stfl");
    let config_path = dir.path().join("network.toml");

    std::fs::write(&source_path, CLEAR_ADD_SOURCE)?;
    std::fs::write(
        &config_path,
        r#"
[network]
party_id = 2
bind_address = "127.0.0.1:19602"
expected_parties = 5
expected_clients = 1
consensus_timeout_ms = 1000

[network.peers]
0 = "127.0.0.1:19600"
1 = "127.0.0.1:19601"
3 = "127.0.0.1:19603"
4 = "127.0.0.1:19604"

[mpc]
threshold = 1
protocol = "honeybadger"

[preprocessing]
triples = 4
random_shares = 2
"#,
    )?;

    let runtime = Stoffel::compile_file(&source_path)?
        .network_config_file(&config_path)
        .with_inputs(&[("a", 1_i64), ("b", 2_i64)])
        .build()?;

    assert_eq!(runtime.execute_clear()?, vec![Value::I64(3)]);
    let network = runtime.network_config().unwrap();
    assert_eq!(network.network.party_id, 2);
    assert_eq!(network.network.peers.len(), 4);
    assert_eq!(network.preprocessing.random_shares, 2);
    let mpc = runtime.mpc_config().unwrap();
    assert_eq!(mpc.parties, 5);
    assert_eq!(mpc.threshold, 1);
    assert_eq!(mpc.backend, MpcBackend::HoneyBadger);

    let server = runtime.server(2).build()?;
    assert_eq!(server.party_id(), 2);
    assert_eq!(server.bind_addr(), "127.0.0.1:19602");
    assert_eq!(server.peers().len(), 4);
    assert_eq!(server.preprocessing(), (4, 2));

    let mismatched_server = runtime.server(1).build().unwrap_err();
    let stoffel::Error::Configuration(message) = mismatched_server else {
        panic!("expected network config party_id mismatch");
    };
    assert!(message.contains("network config party_id 2"));
    assert!(message.contains("requested server party_id 1"));

    let client = runtime.client().build()?;
    assert_eq!(
        client.servers(),
        &[
            "127.0.0.1:19600".to_owned(),
            "127.0.0.1:19601".to_owned(),
            "127.0.0.1:19602".to_owned(),
            "127.0.0.1:19603".to_owned(),
            "127.0.0.1:19604".to_owned(),
        ]
    );
    Ok(())
}

#[test]
fn stoffel_network_config_file_errors_are_reported_by_build() -> stoffel::Result<()> {
    let dir = tempdir()?;
    let missing_path = dir.path().join("missing-network.toml");

    let err = Stoffel::compile(CLEAR_ADD_SOURCE)?
        .network_config_file(&missing_path)
        .build()
        .unwrap_err();

    assert!(matches!(err, stoffel::Error::Configuration(_)));
    Ok(())
}

#[test]
fn network_config_is_authoritative_for_runtime_mpc_settings() -> stoffel::Result<()> {
    let network = NetworkConfig::builder()
        .party_id(0)
        .bind_address("127.0.0.1:19610")
        .expected_parties(9)
        .peers([
            (1, "127.0.0.1:19611"),
            (2, "127.0.0.1:19612"),
            (3, "127.0.0.1:19613"),
            (4, "127.0.0.1:19614"),
            (5, "127.0.0.1:19615"),
            (6, "127.0.0.1:19616"),
            (7, "127.0.0.1:19617"),
            (8, "127.0.0.1:19618"),
        ])
        .threshold(2)
        .backend(MpcBackend::Avss {
            curve: Curve::Ed25519,
        })
        .build()?;

    let config_mpc = network.to_mpc_config(123)?;
    assert_eq!(config_mpc.parties, 9);
    assert_eq!(config_mpc.threshold, 2);
    assert_eq!(config_mpc.instance_id, 123);
    assert_eq!(
        config_mpc.backend,
        MpcBackend::Avss {
            curve: Curve::Ed25519
        }
    );

    let runtime = Stoffel::compile(ADD_SOURCE)?
        .parties(5)
        .threshold(1)
        .backend(MpcBackend::HoneyBadger)
        .network_config(network)
        .build()?;

    let mpc = runtime.mpc_config().unwrap();
    assert_eq!(mpc.parties, 9);
    assert_eq!(mpc.threshold, 2);
    assert_eq!(
        mpc.backend,
        MpcBackend::Avss {
            curve: Curve::Ed25519
        }
    );
    let mpc_summary = runtime.mpc_summary()?.expect("mpc summary");
    assert_eq!(mpc_summary.parties, 9);
    assert_eq!(mpc_summary.maximum_threshold, 2);
    assert_eq!(mpc_summary.minimum_reconstruction_shares, 3);
    let network_summary = runtime.network_summary()?.expect("network summary");
    assert_eq!(network_summary.expected_parties, 9);
    assert_eq!(network_summary.threshold, 2);
    assert_eq!(
        network_summary.backend,
        MpcBackend::Avss {
            curve: Curve::Ed25519
        }
    );
    let runtime_summary = runtime.summary()?;
    assert_eq!(runtime_summary.program.function_count, 1);
    assert_eq!(runtime_summary.mpc.as_ref().unwrap().parties, 9);
    assert_eq!(
        runtime_summary.network.as_ref().unwrap().backend,
        MpcBackend::Avss {
            curve: Curve::Ed25519
        }
    );
    assert_eq!(runtime_summary.named_input_count, 0);
    assert_eq!(runtime_summary.client_input_count, 0);
    assert!(!runtime_summary.local_runner_configured);
    assert!(toml::to_string(&runtime_summary)?.contains("[program]"));
    assert_eq!(
        runtime.program().client_io_manifest().mpc_backend,
        stoffel_vm_types::compiled_binary::MpcBackend::Avss
    );

    let server = runtime.server(0).build()?;
    assert_eq!(
        server.backend(),
        MpcBackend::Avss {
            curve: Curve::Ed25519
        }
    );
    let server_mpc = server.mpc_config().expect("server mpc config");
    assert_eq!(server_mpc.parties, 9);
    assert_eq!(server_mpc.threshold, 2);
    assert_eq!(
        server_mpc.instance_id,
        runtime.mpc_config().unwrap().instance_id
    );
    assert_eq!(
        server_mpc.backend,
        MpcBackend::Avss {
            curve: Curve::Ed25519
        }
    );
    let server_summary = server.summary();
    assert_eq!(server_summary.mpc_parties, Some(9));
    assert_eq!(server_summary.mpc_threshold, Some(2));
    assert_eq!(server.preprocessing(), (1000, 500));
    Ok(())
}

#[test]
fn network_config_expected_clients_must_cover_program_client_io() -> stoffel::Result<()> {
    let source = r#"
def main() -> int64:
  var left = ClientStore.take_share(0, 0)
  var right = ClientStore.take_share(1, 0)
  return Share.add(left, right).open()
"#;

    let too_few_clients = NetworkConfig::builder()
        .party_id(0)
        .bind_address("127.0.0.1:19630")
        .expected_parties(5)
        .peers([
            (1, "127.0.0.1:19631"),
            (2, "127.0.0.1:19632"),
            (3, "127.0.0.1:19633"),
            (4, "127.0.0.1:19634"),
        ])
        .expected_clients(1)
        .threshold(1)
        .build()?;
    let err = Stoffel::compile(source)?
        .network_config(too_few_clients)
        .build()
        .unwrap_err();
    assert!(matches!(err, stoffel::Error::Configuration(_)));

    let enough_clients = NetworkConfig::builder()
        .party_id(0)
        .bind_address("127.0.0.1:19640")
        .expected_parties(5)
        .peers([
            (1, "127.0.0.1:19641"),
            (2, "127.0.0.1:19642"),
            (3, "127.0.0.1:19643"),
            (4, "127.0.0.1:19644"),
        ])
        .expected_clients(2)
        .threshold(1)
        .build()?;
    let runtime = Stoffel::compile(source)?
        .network_config(enough_clients)
        .build()?;
    assert_eq!(runtime.program().client_count(), 2);
    Ok(())
}

#[test]
fn network_config_expected_clients_rejects_sparse_client_slots() -> stoffel::Result<()> {
    let source = r#"
def main() -> int64:
  var share = ClientStore.take_share(3, 0)
  return share.open()
"#;

    let sparse_slot_config = NetworkConfig::builder()
        .party_id(0)
        .bind_address("127.0.0.1:19650")
        .expected_parties(5)
        .peers([
            (1, "127.0.0.1:19651"),
            (2, "127.0.0.1:19652"),
            (3, "127.0.0.1:19653"),
            (4, "127.0.0.1:19654"),
        ])
        .expected_clients(2)
        .threshold(1)
        .build()?;
    let err = Stoffel::compile(source)?
        .network_config(sparse_slot_config)
        .build()
        .unwrap_err();
    assert!(matches!(err, stoffel::Error::Configuration(_)));

    let covering_config = NetworkConfig::builder()
        .party_id(0)
        .bind_address("127.0.0.1:19660")
        .expected_parties(5)
        .peers([
            (1, "127.0.0.1:19661"),
            (2, "127.0.0.1:19662"),
            (3, "127.0.0.1:19663"),
            (4, "127.0.0.1:19664"),
        ])
        .expected_clients(4)
        .threshold(1)
        .build()?;
    let runtime = Stoffel::compile(source)?
        .network_config(covering_config)
        .build()?;
    assert_eq!(runtime.program().minimum_expected_clients(), 4);
    assert_eq!(
        runtime
            .program()
            .clients()
            .map(|client| client.client_slot())
            .collect::<Vec<_>>(),
        vec![3]
    );
    Ok(())
}

#[test]
fn network_config_can_be_loaded_and_serialized_directly() -> stoffel::Result<()> {
    let config = NetworkConfig::from_toml_str(
        r#"
[network]
party_id = 1
bind_address = "127.0.0.1:19601"
expected_parties = 5
expected_clients = 2
consensus_timeout_ms = 2500

[network.peers]
0 = "127.0.0.1:19600"
2 = "127.0.0.1:19602"
3 = "127.0.0.1:19603"
4 = "127.0.0.1:19604"

[mpc]
threshold = 1
protocol = "avss:ed25519"

[preprocessing]
triples = 8
random_shares = 4
"#,
    )?;

    assert_eq!(config.party_id(), 1);
    assert_eq!(config.bind_address(), "127.0.0.1:19601");
    assert_eq!(config.expected_parties(), 5);
    assert_eq!(config.expected_clients(), 2);
    assert_eq!(config.consensus_timeout_ms(), 2500);
    assert_eq!(config.threshold(), 1);
    assert_eq!(config.protocol(), "avss:ed25519");
    assert_eq!(config.preprocessing().triples, 8);
    assert_eq!(config.preprocessing().random_shares, 4);
    assert_eq!(
        config.peer_addresses().get(&0).map(String::as_str),
        Some("127.0.0.1:19600")
    );
    assert_eq!(
        MpcBackend::try_from(&config)?,
        MpcBackend::Avss {
            curve: Curve::Ed25519
        }
    );
    let summary = config.summary()?;
    assert_eq!(summary.party_id, 1);
    assert_eq!(summary.expected_parties, 5);
    assert_eq!(summary.expected_clients, 2);
    assert_eq!(summary.peer_count, 4);
    assert_eq!(
        summary.backend,
        MpcBackend::Avss {
            curve: Curve::Ed25519
        }
    );
    assert_eq!(summary.minimum_reconstruction_shares, 2);
    assert_eq!(summary.preprocessing_triples, 8);
    assert!(toml::to_string(&summary)?.contains("backend = \"avss:ed25519\""));

    let serialized = config.to_toml_string()?;
    assert!(serialized.contains("[network.peers]"));
    assert!(serialized.contains("0 = \"127.0.0.1:19600\""));

    let reparsed = NetworkConfig::from_toml_str(&serialized)?;
    assert_eq!(reparsed, config);

    let dir = tempfile::tempdir()?;
    let path = dir.path().join("network.toml");
    config.save_toml_file(&path)?;
    let reparsed_file = NetworkConfig::from_toml_file(&path)?;
    assert_eq!(reparsed_file, config);
    Ok(())
}

#[test]
fn network_deployment_builds_one_valid_config_per_party() -> stoffel::Result<()> {
    let deployment = NetworkDeployment::builder([
        "127.0.0.1:20100",
        "127.0.0.1:20101",
        "127.0.0.1:20102",
        "127.0.0.1:20103",
        "127.0.0.1:20104",
    ])
    .expected_clients(2)
    .threshold(1)
    .honeybadger()
    .consensus_timeout(Duration::from_secs(3))
    .preprocessing(12, 6)
    .build()?;

    assert_eq!(deployment.len(), 5);
    assert!(!deployment.is_empty());
    assert_eq!(
        deployment.server_addresses(),
        vec![
            "127.0.0.1:20100".to_owned(),
            "127.0.0.1:20101".to_owned(),
            "127.0.0.1:20102".to_owned(),
            "127.0.0.1:20103".to_owned(),
            "127.0.0.1:20104".to_owned(),
        ]
    );

    let party_two = deployment.config(2).expect("party 2 config");
    assert_eq!(party_two.party_id(), 2);
    assert_eq!(party_two.bind_address(), "127.0.0.1:20102");
    assert_eq!(party_two.expected_parties(), 5);
    assert_eq!(party_two.expected_clients(), 2);
    assert_eq!(party_two.consensus_timeout_ms(), 3_000);
    assert_eq!(
        party_two.preprocessing(),
        &PreprocessingConfig {
            triples: 12,
            random_shares: 6,
        }
    );
    assert_eq!(
        party_two.server_addresses()?,
        vec![
            "127.0.0.1:20100".to_owned(),
            "127.0.0.1:20101".to_owned(),
            "127.0.0.1:20102".to_owned(),
            "127.0.0.1:20103".to_owned(),
            "127.0.0.1:20104".to_owned(),
        ]
    );
    assert_eq!(
        party_two
            .peer_addresses()
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        vec![0, 1, 3, 4]
    );

    let summaries = deployment.summaries()?;
    assert_eq!(summaries.len(), 5);
    assert_eq!(summaries[2].peer_count, 4);
    assert_eq!(summaries[2].minimum_reconstruction_shares, 3);

    let toml_configs = deployment.to_toml_strings()?;
    assert_eq!(toml_configs.len(), 5);
    assert!(toml_configs[2].contains("party_id = 2"));
    assert!(toml_configs[2].contains("bind_address = \"127.0.0.1:20102\""));

    let dir = tempfile::tempdir()?;
    let paths = deployment.save_toml_files(dir.path())?;
    assert_eq!(paths.len(), 5);
    assert_eq!(
        paths
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().to_string())
            .collect::<Vec<_>>(),
        vec![
            "party-0.toml".to_owned(),
            "party-1.toml".to_owned(),
            "party-2.toml".to_owned(),
            "party-3.toml".to_owned(),
            "party-4.toml".to_owned(),
        ]
    );
    let saved_party_two = NetworkConfig::from_toml_file(&paths[2])?;
    assert_eq!(&saved_party_two, party_two);

    let custom_dir = tempfile::tempdir()?;
    let custom_paths = deployment.save_toml_files_with_prefix(custom_dir.path(), "node")?;
    assert_eq!(
        custom_paths[2].file_name().unwrap().to_string_lossy(),
        "node-2.toml"
    );

    let client = StoffelClient::builder()
        .network_config(party_two)
        .client_id(7)
        .build()?;
    assert_eq!(client.servers(), &deployment.server_addresses());

    let deployment_client = StoffelClient::builder()
        .network_deployment(&deployment)
        .client_id(8)
        .build()?;
    assert_eq!(deployment_client.servers(), &deployment.server_addresses());

    let server = StoffelServer::builder(2)
        .network_config(party_two)
        .build()?;
    assert_eq!(server.party_id(), 2);
    assert_eq!(server.bind_addr(), "127.0.0.1:20102");
    assert_eq!(server.peers().len(), 4);

    let deployment_server = StoffelServer::builder(2)
        .network_deployment(&deployment)
        .build()?;
    assert_eq!(deployment_server.party_id(), 2);
    assert_eq!(deployment_server.bind_addr(), "127.0.0.1:20102");
    assert_eq!(deployment_server.peers().len(), 4);

    let runtime = Stoffel::compile(CLEAR_ADD_SOURCE)?
        .parties(5)
        .threshold(1)
        .build()?;
    let runtime_client = runtime.client_for_deployment(&deployment).build()?;
    assert!(runtime_client.has_program());
    assert_eq!(runtime_client.servers(), &deployment.server_addresses());

    let runtime_servers = runtime.servers_for_deployment(&deployment);
    assert_eq!(runtime_servers.len(), 5);
    assert!(runtime_servers[2].has_configured_program());
    let runtime_party_two = runtime_servers[2].clone().build()?;
    assert_eq!(runtime_party_two.party_id(), 2);
    assert_eq!(runtime_party_two.bind_addr(), "127.0.0.1:20102");
    assert!(runtime_party_two.program().is_some());
    Ok(())
}

#[test]
fn network_deployment_rejects_invalid_address_sets() {
    let too_few =
        NetworkDeployment::builder(["127.0.0.1:20200", "127.0.0.1:20201", "127.0.0.1:20202"])
            .build()
            .unwrap_err();
    assert!(matches!(too_few, stoffel::Error::Configuration(_)));

    let four_parties = NetworkDeployment::builder([
        "127.0.0.1:20200",
        "127.0.0.1:20201",
        "127.0.0.1:20202",
        "127.0.0.1:20203",
    ])
    .build()
    .unwrap_err();
    assert!(matches!(
        four_parties,
        stoffel::Error::Configuration(message) if message.contains("at least 5")
    ));

    let duplicate = NetworkDeployment::builder([
        "127.0.0.1:20200",
        "127.0.0.1:20201",
        "127.0.0.1:20202",
        "127.0.0.1:20200",
        "127.0.0.1:20204",
    ])
    .build()
    .unwrap_err();
    assert!(matches!(
        duplicate,
        stoffel::Error::Configuration(message) if message.contains("duplicate deployment address")
    ));

    let invalid_threshold = NetworkDeployment::builder([
        "127.0.0.1:20200",
        "127.0.0.1:20201",
        "127.0.0.1:20202",
        "127.0.0.1:20203",
        "127.0.0.1:20204",
    ])
    .threshold(2)
    .build()
    .unwrap_err();
    assert!(matches!(
        invalid_threshold,
        stoffel::Error::Configuration(_)
    ));

    let deployment = NetworkDeployment::builder([
        "127.0.0.1:20300",
        "127.0.0.1:20301",
        "127.0.0.1:20302",
        "127.0.0.1:20303",
        "127.0.0.1:20304",
    ])
    .build()
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let invalid_prefix = deployment
        .save_toml_files_with_prefix(dir.path(), " ")
        .unwrap_err();
    assert!(matches!(invalid_prefix, stoffel::Error::Configuration(_)));
}

#[test]
fn executes_clear_programs_with_embedded_vm() -> stoffel::Result<()> {
    let result = Stoffel::compile(CLEAR_ADD_SOURCE)?
        .with_inputs(&[("b", 58_i64), ("a", 42_i64)])
        .execute_clear()?;

    assert_eq!(result, vec![Value::I64(100)]);
    Ok(())
}

#[test]
fn clear_vm_array_outputs_are_returned_as_sdk_values() -> stoffel::Result<()> {
    let result =
        Stoffel::compile("def main() -> list[int64]:\n  return [2, 3, 5]")?.execute_clear()?;

    assert_eq!(result, vec![Value::I64(2), Value::I64(3), Value::I64(5)]);
    Ok(())
}

#[test]
fn clear_vm_nested_array_outputs_are_preserved_as_lists() -> stoffel::Result<()> {
    let result = Stoffel::compile("def main() -> list[list[int64]]:\n  return [[1, 2], [3, 4]]")?
        .execute_clear()?;

    assert_eq!(
        result,
        vec![
            Value::List(vec![Value::I64(1), Value::I64(2)]),
            Value::List(vec![Value::I64(3), Value::I64(4)]),
        ]
    );
    Ok(())
}

#[test]
fn nested_list_index_concat_executes_as_python_style_list_concat() -> stoffel::Result<()> {
    let result = Stoffel::compile(
        r#"
def main(a: list[list[int64]], a_rows: int64, a_cols: int64) -> list[int64]:
  var nested_list: list[list[int64]] = a
  var result: list[int64] = []
  for i in 0..a_rows:
    result = nested_list[i] + nested_list[i]
  return result
"#,
    )?
    .with_input(
        "a",
        Value::List(vec![
            Value::List(vec![Value::I64(1), Value::I64(2)]),
            Value::List(vec![Value::I64(3), Value::I64(4)]),
        ]),
    )
    .with_input("a_rows", 2_i64)
    .with_input("a_cols", 2_i64)
    .execute_clear()?;

    assert_eq!(
        result,
        vec![Value::I64(3), Value::I64(4), Value::I64(3), Value::I64(4)]
    );
    Ok(())
}

#[test]
fn function_type_metadata_survives_bytecode_round_trip() -> stoffel::Result<()> {
    let runtime = Stoffel::compile(
        r#"
def main(a: list[list[int64]], n: uint64) -> list[int64]:
  return a[0]
"#,
    )?
    .build()?;
    let bytecode = runtime.to_bytecode()?;
    let loaded = Stoffel::load(&bytecode)?.build()?;
    let main = loaded.program().main().expect("main metadata should exist");

    assert_eq!(
        main.parameter_types(),
        &[
            FunctionType::List(Box::new(FunctionType::List(
                Box::new(FunctionType::int64())
            ))),
            FunctionType::uint64()
        ]
    );
    assert_eq!(
        main.return_type(),
        &FunctionType::List(Box::new(FunctionType::int64()))
    );
    Ok(())
}

#[test]
fn loaded_bytecode_rejects_flat_list_for_nested_list_input() -> stoffel::Result<()> {
    let runtime = Stoffel::compile(
        r#"
def main(a: list[list[int64]], a_rows: int64, a_cols: int64) -> int64:
  return a[0][0]
"#,
    )?
    .build()?;
    let bytecode = runtime.to_bytecode()?;
    let err = Stoffel::load(&bytecode)?
        .with_input(
            "a",
            Value::List(vec![
                Value::I64(1),
                Value::I64(2),
                Value::I64(3),
                Value::I64(4),
            ]),
        )
        .with_input("a_rows", 1_i64)
        .with_input("a_cols", 4_i64)
        .execute_clear()
        .unwrap_err();

    assert!(
        err.to_string()
            .contains("input 'a[0]' expects list[int64], got i64"),
        "unexpected error: {err}"
    );
    Ok(())
}

#[test]
fn clear_list_methods_follow_python_style_mutation_semantics() -> stoffel::Result<()> {
    let result = Stoffel::compile(
        r#"
def main() -> list[int64]:
  var items: list[int64] = [3, 1, 2]
  items.insert(1, 9)
  var popped: int64 = items.pop(-2)
  items.remove(9)
  items.extend([5, 5])
  var five_count: int64 = items.count(5)
  var two_index: int64 = items.index(2)
  items.reverse()
  items.sort()
  items.append(popped)
  items.append(five_count)
  items.append(two_index)
  return items
"#,
    )?
    .execute_clear()?;

    assert_eq!(
        result,
        vec![
            Value::I64(2),
            Value::I64(3),
            Value::I64(5),
            Value::I64(5),
            Value::I64(1),
            Value::I64(2),
            Value::I64(1),
        ]
    );
    Ok(())
}

#[test]
fn clear_list_copy_clear_and_repeat_follow_python_style_semantics() -> stoffel::Result<()> {
    let result = Stoffel::compile(
        r#"
def main() -> list[int64]:
  var items: list[int64] = [4, 6]
  var copied: list[int64] = items.copy()
  items.clear()
  return copied + ([7] * 2) + (2 * [8]) + [len(items)]
"#,
    )?
    .execute_clear()?;

    assert_eq!(
        result,
        vec![
            Value::I64(4),
            Value::I64(6),
            Value::I64(7),
            Value::I64(7),
            Value::I64(8),
            Value::I64(8),
            Value::I64(0),
        ]
    );
    Ok(())
}

#[test]
fn list_inputs_execute_as_clear_vm_arrays() -> stoffel::Result<()> {
    let result = Stoffel::compile("def main(values: list[int64]) -> int64:\n  return values[0]")?
        .with_input("values", Value::List(vec![Value::I64(7)]))
        .execute_clear()?;

    assert_eq!(result, vec![Value::I64(7)]);
    Ok(())
}

#[test]
fn object_inputs_execute_as_clear_vm_objects() -> stoffel::Result<()> {
    let mut point = BTreeMap::new();
    point.insert("x".to_owned(), Value::I64(7));
    point.insert("y".to_owned(), Value::I64(5));

    let result = Stoffel::compile(
        r#"
object point:
  x: int64
  y: int64

def main(value: point) -> int64:
  return value.x
"#,
    )?
    .with_input("value", Value::Object(point))
    .execute_clear()?;

    assert_eq!(result, vec![Value::I64(7)]);
    Ok(())
}

#[test]
fn object_locals_default_construct_and_preserve_parameters_across_calls() -> stoffel::Result<()> {
    let result = Stoffel::compile(
        r#"
object polynomial:
  n: int64
  coeffs: list[int64]

def main(n: int64, coeffs: list[int64]) -> int64:
  var p: polynomial
  p.n = n
  p.coeffs = coeffs

  var q: polynomial
  q.n = n

  var r: polynomial
  r.n = q.n
  r.coeffs.append(p.coeffs[0] + p.coeffs[1])
  return r.n + r.coeffs[0]
"#,
    )?
    .with_input("n", 1_i64)
    .with_input("coeffs", Value::List(vec![Value::I64(10), Value::I64(90)]))
    .execute_clear()?;

    assert_eq!(result, vec![Value::I64(101)]);
    Ok(())
}

#[test]
fn byte_inputs_fail_explicitly_before_clear_vm_execution() -> stoffel::Result<()> {
    let err = Stoffel::compile("def main(value: string) -> string:\n  return value")?
        .with_input("value", Value::Bytes(vec![0xff, 0x00]))
        .execute_clear()
        .unwrap_err();

    assert!(matches!(err, stoffel::Error::InvalidInput(_)));
    Ok(())
}

#[test]
fn clear_array_inputs_and_outputs_round_trip_without_recursing_forever() -> stoffel::Result<()> {
    let result =
        Stoffel::compile("def main(a: int64, b: int64) -> list[int64]:\n  return [a, b, a + b]")?
            .with_inputs(&[("a", 2_i64), ("b", 3_i64)])
            .execute_clear()?;

    assert_eq!(result, vec![Value::I64(2), Value::I64(3), Value::I64(5)]);
    Ok(())
}

#[test]
fn named_input_builder_orders_values_by_function_parameters() -> stoffel::Result<()> {
    let result = Stoffel::compile("def main(a: int64, b: int64) -> int64:\n  return a - b")?
        .with_input("b", 3_i64)
        .with_input("a", 10_i64)
        .execute_clear()?;

    assert_eq!(result, vec![Value::I64(7)]);
    Ok(())
}

#[test]
fn missing_named_inputs_are_reported_before_vm_execution() -> stoffel::Result<()> {
    let err = Stoffel::compile(CLEAR_ADD_SOURCE)?
        .with_input("a", 1_i64)
        .execute_clear()
        .unwrap_err();

    assert!(matches!(err, stoffel::Error::InvalidInput(_)));
    Ok(())
}

#[test]
fn duplicate_and_unexpected_named_inputs_are_reported() -> stoffel::Result<()> {
    let duplicate = Stoffel::compile(CLEAR_ADD_SOURCE)?
        .with_input("a", 1_i64)
        .with_input("a", 2_i64)
        .with_input("b", 3_i64)
        .execute_clear()
        .unwrap_err();
    assert!(matches!(duplicate, stoffel::Error::InvalidInput(_)));

    let unexpected = Stoffel::compile(CLEAR_ADD_SOURCE)?
        .with_input("a", 1_i64)
        .with_input("b", 2_i64)
        .with_input("c", 3_i64)
        .execute_clear()
        .unwrap_err();
    assert!(matches!(unexpected, stoffel::Error::InvalidInput(_)));
    Ok(())
}

#[test]
fn runtime_can_execute_named_clear_functions() -> stoffel::Result<()> {
    let runtime = Stoffel::compile(CLEAR_ADD_SOURCE)?
        .with_inputs(&[("a", 7_i64), ("b", 9_i64)])
        .build()?;

    assert_eq!(
        runtime.execute_clear_function("main")?,
        vec![Value::I64(16)]
    );
    Ok(())
}

#[test]
fn runtime_can_be_reused_with_new_inputs() -> stoffel::Result<()> {
    let runtime = Stoffel::compile(CLEAR_ADD_SOURCE)?.build()?;

    let first = runtime.clone().with_inputs(&[("a", 7_i64), ("b", 9_i64)]);
    assert_eq!(first.execute_clear()?, vec![Value::I64(16)]);

    let second = runtime.with_input("a", 40_i64).with_input("b", 2_i64);
    assert_eq!(second.inputs().len(), 2);
    assert_eq!(second.execute_clear()?, vec![Value::I64(42)]);
    Ok(())
}

#[test]
fn runtime_can_attach_local_client_inputs_after_build() -> stoffel::Result<()> {
    let runtime = Stoffel::compile(
        r#"
def main() -> int64:
  var share = ClientStore.take_share(0, 0)
  return share.open()
"#,
    )?
    .parties(5)
    .threshold(1)
    .build()?
    .with_client_input(0, &[42_i64]);

    assert_eq!(runtime.client_inputs().len(), 1);
    assert_eq!(runtime.client_inputs()[0].0, 0);
    assert_eq!(runtime.client_inputs()[0].1, vec![Value::I64(42)]);
    runtime.validate_client_inputs()?;
    Ok(())
}

#[test]
fn runtime_can_validate_local_client_inputs_before_execution() -> stoffel::Result<()> {
    let runtime = Stoffel::compile(
        r#"
def main() -> int64:
  var share = ClientStore.take_share(0, 0)
  return share.open()
"#,
    )?
    .parties(5)
    .threshold(1)
    .build()?;

    let missing = runtime.validate_client_inputs().unwrap_err();
    assert!(matches!(
        missing,
        stoffel::Error::Configuration(message)
            if message.contains("provide local client inputs")
    ));

    let valid = runtime.with_client_input(0, &[42_i64]);
    valid.validate_client_inputs()?;
    Ok(())
}

#[test]
fn runtime_allows_static_output_only_clients_without_inputs() -> stoffel::Result<()> {
    let runtime = Stoffel::compile(
        r#"
def main() -> int64:
  var share = Share.from_clear_int(7, 64)
  MpcOutput.send_to_client(0, [share])
  return ClientStore.get_number_clients()
"#,
    )?
    .parties(5)
    .threshold(1)
    .build()?;

    assert_eq!(runtime.program().minimum_expected_clients(), 1);
    runtime.validate_client_inputs()?;
    Ok(())
}

#[test]
fn runtime_rejects_expected_output_clients_below_static_manifest_slots() -> stoffel::Result<()> {
    let error = Stoffel::compile(
        r#"
def main() -> int64:
  var share = Share.from_clear_int(7, 64)
  MpcOutput.send_to_client(1, [share])
  return ClientStore.get_number_clients()
"#,
    )?
    .parties(5)
    .threshold(1)
    .expected_output_clients(1)
    .build()
    .unwrap_err();

    assert!(matches!(
        error,
        stoffel::Error::Configuration(message)
            if message.contains("expected_clients >= 2")
    ));
    Ok(())
}

#[test]
fn runtime_accepts_explicit_expected_output_clients_for_dynamic_outputs() -> stoffel::Result<()> {
    let runtime = Stoffel::compile(
        r#"
def main() -> int64:
  var count = ClientStore.get_number_clients()
  var i = 0
  while i < count:
    var share = Share.from_clear_int(i, 64)
    MpcOutput.send_to_client(i, [share])
    i = i + 1
  return count
"#,
    )?
    .parties(5)
    .threshold(1)
    .expected_output_clients(2)
    .build()?;

    // The output client slot `i` is a runtime `while`-loop counter spanning
    // `0..count`, so it is NOT statically resolvable and contributes no client
    // to the manifest — the static minimum is 0. This is precisely why the
    // developer must declare `expected_output_clients` explicitly for dynamic
    // outputs (a counter's initial value is not a meaningful static slot).
    assert_eq!(runtime.program().minimum_expected_clients(), 0);
    assert_eq!(runtime.configured_expected_clients(), Some(2));
    runtime.validate_client_inputs()?;
    Ok(())
}

#[test]
fn stoffel_builder_can_validate_local_client_inputs_before_execution() -> stoffel::Result<()> {
    let source = r#"
def main() -> int64:
  var share = ClientStore.take_share(0, 0)
  return share.open()
"#;

    let missing = Stoffel::compile(source)?
        .parties(5)
        .threshold(1)
        .validate_client_inputs()
        .unwrap_err();
    assert!(matches!(
        missing,
        stoffel::Error::Configuration(message)
            if message.contains("provide local client inputs")
    ));

    Stoffel::compile(source)?
        .parties(5)
        .threshold(1)
        .with_client_input(0, &[42_i64])
        .validate_client_inputs()?;
    Ok(())
}

#[test]
fn client_input_batch_builders_replace_existing_sets() -> stoffel::Result<()> {
    let first = [40_i64];
    let second = [2_i64];
    let replacement = [42_i64];

    let runtime = Stoffel::compile(
        r#"
def main() -> int64:
  var share = ClientStore.take_share(0, 0)
  return share.open()
"#,
    )?
    .parties(5)
    .threshold(1)
    .with_client_input(0, &first)
    .with_client_input(1, &second)
    .with_client_inputs(&[(0, replacement.as_slice())])
    .build()?;

    assert_eq!(runtime.client_inputs().len(), 1);
    assert_eq!(runtime.client_inputs()[0].0, 0);
    assert_eq!(runtime.client_inputs()[0].1, vec![Value::I64(42)]);

    let runtime = runtime
        .with_client_input(1, &second)
        .with_client_inputs(&[(0, first.as_slice())]);

    assert_eq!(runtime.client_inputs().len(), 1);
    assert_eq!(runtime.client_inputs()[0].0, 0);
    assert_eq!(runtime.client_inputs()[0].1, vec![Value::I64(40)]);
    Ok(())
}

#[test]
fn runtime_preserves_local_runner_path_override() -> stoffel::Result<()> {
    let dir = tempdir()?;
    let runner_path = dir.path().join("stoffel-run");

    let runtime = Stoffel::compile("def main() -> int64:\n  return 7")?
        .parties(5)
        .threshold(1)
        .local_runner_path(&runner_path)
        .build()?;

    assert_eq!(
        runtime.local_runner_binary_path(),
        Some(runner_path.as_path())
    );

    let other_path = dir.path().join("other-stoffel-run");
    let runtime = runtime.local_runner_path(&other_path);
    assert_eq!(
        runtime.local_runner_binary_path(),
        Some(other_path.as_path())
    );
    Ok(())
}

#[tokio::test]
async fn local_runner_path_override_is_validated_before_spawning() -> stoffel::Result<()> {
    let dir = tempdir()?;
    let runner_path = dir.path().join("missing-stoffel-run");

    let err = Stoffel::compile("def main() -> int64:\n  return 7")?
        .parties(5)
        .threshold(1)
        .local_runner_path(&runner_path)
        .execute_local()
        .await
        .unwrap_err();

    let stoffel::Error::Unsupported(message) = err else {
        panic!("expected unsupported error for missing local runner path");
    };
    assert!(message.contains("configured path does not exist"));
    assert!(message.contains(&runner_path.display().to_string()));
    Ok(())
}

#[tokio::test]
async fn local_network_builder_runner_path_is_validated_before_spawning() -> stoffel::Result<()> {
    let dir = tempdir()?;
    let runner_path = dir.path().join("missing-stoffel-run");
    let runtime = Stoffel::compile("def main() -> int64:\n  return 7")?
        .parties(5)
        .threshold(1)
        .build()?;

    let builder = runtime
        .local_network()
        .runner_path(&runner_path)
        .timeout(Duration::from_secs(1));
    assert_eq!(builder.configured_entry(), "main");
    assert_eq!(
        builder.configured_runner_path(),
        Some(runner_path.as_path())
    );
    assert_eq!(builder.configured_timeout(), Some(Duration::from_secs(1)));

    let err = builder.run().await.unwrap_err();

    let stoffel::Error::Unsupported(message) = err else {
        panic!("expected unsupported error for missing local runner path");
    };
    assert!(message.contains("configured path does not exist"));
    assert!(message.contains(&runner_path.display().to_string()));
    Ok(())
}

#[tokio::test]
async fn local_network_builder_rejects_zero_timeout_before_runner_lookup() -> stoffel::Result<()> {
    let runtime = Stoffel::compile("def main() -> int64:\n  return 7")?
        .parties(5)
        .threshold(1)
        .build()?;

    let builder = runtime
        .local_network()
        .entry("main")
        .timeout(Duration::ZERO);
    assert_eq!(builder.configured_entry(), "main");
    assert_eq!(builder.configured_timeout(), Some(Duration::ZERO));
    let err = builder.run().await.unwrap_err();
    assert!(matches!(
        err,
        stoffel::Error::Configuration(message) if message.contains("timeout")
    ));
    Ok(())
}

#[test]
fn local_execution_preserves_non_bls_avss_client_input_configuration() -> stoffel::Result<()> {
    let runtime = Stoffel::compile(
        r#"
def main() -> int64:
  var share = ClientStore.take_share(0, 0)
  return share.open()
"#,
    )?
    .parties(5)
    .threshold(1)
    .backend(MpcBackend::Avss {
        curve: Curve::Ed25519,
    })
    .with_client_input(0, &[42_i64])
    .build()?;

    assert_eq!(
        runtime.mpc_config().unwrap().backend,
        MpcBackend::Avss {
            curve: Curve::Ed25519
        }
    );
    runtime.validate_client_inputs()?;
    Ok(())
}

#[tokio::test]
async fn local_client_inputs_are_validated_before_runner_lookup() -> stoffel::Result<()> {
    let source = r#"
def main() -> int64:
  var share = ClientStore.take_share(0, 0)
  return share.open()
"#;

    let missing_inputs = Stoffel::compile(source)?
        .parties(5)
        .threshold(1)
        .execute_local()
        .await
        .unwrap_err();
    assert!(matches!(
        missing_inputs,
        stoffel::Error::Configuration(message)
            if message.contains("provide local client inputs")
    ));

    let unexpected_slot = Stoffel::compile(source)?
        .parties(5)
        .threshold(1)
        .with_client_input(1, &[42_i64])
        .execute_local()
        .await
        .unwrap_err();
    assert!(matches!(
        unexpected_slot,
        stoffel::Error::Configuration(message)
            if message.contains("client slot 1 is not declared")
    ));

    let duplicate_slot = Stoffel::compile(source)?
        .parties(5)
        .threshold(1)
        .with_client_input(0, &[42_i64])
        .with_client_input(0, &[58_i64])
        .execute_local()
        .await
        .unwrap_err();
    assert!(matches!(
        duplicate_slot,
        stoffel::Error::Configuration(message)
            if message.contains("client slot 0 was provided more than once")
    ));

    let wrong_count = Stoffel::compile(source)?
        .parties(5)
        .threshold(1)
        .with_client_input(0, &[42_i64, 58_i64])
        .execute_local()
        .await
        .unwrap_err();
    assert!(matches!(
        wrong_count,
        stoffel::Error::Configuration(message)
            if message.contains("client slot 0 expects 1 inputs, got 2")
    ));

    let duplicate_dynamic_slot = Stoffel::compile("def main() -> int64:\n  return 7")?
        .parties(5)
        .threshold(1)
        .with_client_input(0, &[42_i64])
        .with_client_input(0, &[58_i64])
        .execute_local()
        .await
        .unwrap_err();
    assert!(matches!(
        duplicate_dynamic_slot,
        stoffel::Error::Configuration(message)
            if message.contains("client slot 0 was provided more than once")
    ));

    let unsupported_value = Stoffel::compile(source)?
        .parties(5)
        .threshold(1)
        .with_client_input(0, &[Value::String("not a field element".to_owned())])
        .execute_local()
        .await
        .unwrap_err();
    assert!(matches!(unsupported_value, stoffel::Error::InvalidInput(_)));

    Ok(())
}

#[tokio::test]
async fn runtime_local_execution_rejects_direct_parameters_before_spawning() -> stoffel::Result<()>
{
    let runtime = Stoffel::compile(ADD_SOURCE)?
        .parties(5)
        .threshold(1)
        .with_inputs(&[("a", 7_i64), ("b", 9_i64)])
        .build()?;

    let err = runtime.execute_local().await.unwrap_err();
    assert!(matches!(err, stoffel::Error::Unsupported(_)));
    Ok(())
}

#[tokio::test]
async fn computation_handle_exposes_state_without_faking_network_results() -> stoffel::Result<()> {
    let pending = ComputationHandle::pending();
    assert_eq!(pending.status(), ComputationStatus::Pending);
    assert_eq!(pending.status().to_string(), "pending");
    assert!(pending.is_pending());
    assert!(!pending.is_completed());
    assert!(!pending.is_cancelled());
    let pending_summary = pending.summary();
    assert_eq!(pending_summary.status, ComputationStatus::Pending);
    assert!(!pending_summary.has_result);
    assert_eq!(pending_summary.result_count, 0);

    let pending_err = pending.clone().await_result().await.unwrap_err();
    assert!(matches!(pending_err, stoffel::Error::Unsupported(_)));

    pending.cancel();
    assert_eq!(pending.status(), ComputationStatus::Cancelled);
    assert_eq!(pending.status().to_string(), "cancelled");
    assert!(!pending.is_pending());
    assert!(!pending.is_completed());
    assert!(pending.is_cancelled());
    assert_eq!(pending.clone().status(), ComputationStatus::Cancelled);
    let cancelled_err = pending.await_result().await.unwrap_err();
    assert!(matches!(cancelled_err, stoffel::Error::Computation(_)));

    let completed = ComputationHandle::completed(vec![Value::I64(100)]);
    assert_eq!(completed.status(), ComputationStatus::Completed);
    assert_eq!(completed.status().to_string(), "completed");
    assert!(!completed.is_pending());
    assert!(completed.is_completed());
    assert!(!completed.is_cancelled());
    let completed_summary = completed.summary();
    assert_eq!(completed_summary.status, ComputationStatus::Completed);
    assert!(completed_summary.has_result);
    assert_eq!(completed_summary.result_count, 1);
    assert!(toml::to_string(&completed_summary)?.contains("status = \"completed\""));
    assert_eq!(completed.await_result().await?, vec![Value::I64(100)]);
    Ok(())
}

#[test]
fn lifecycle_states_round_trip_as_readable_payloads() -> stoffel::Result<()> {
    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct LifecyclePayload {
        client: ClientState,
        server: ServerState,
        computation: ComputationStatus,
    }

    let payload = LifecyclePayload {
        client: ClientState::Disconnected,
        server: ServerState::Shutdown,
        computation: ComputationStatus::Cancelled,
    };

    assert_eq!(payload.client.to_string(), "disconnected");
    assert_eq!(payload.server.to_string(), "shutdown");
    assert_eq!(payload.computation.to_string(), "cancelled");
    assert_eq!(
        "disconnected".parse::<ClientState>()?,
        ClientState::Disconnected
    );
    assert_eq!("shutdown".parse::<ServerState>()?, ServerState::Shutdown);
    assert_eq!(
        "cancelled".parse::<ComputationStatus>()?,
        ComputationStatus::Cancelled
    );

    let serialized = toml::to_string(&payload)?;
    assert!(serialized.contains("client = \"disconnected\""));
    assert!(serialized.contains("server = \"shutdown\""));
    assert!(serialized.contains("computation = \"cancelled\""));

    let reparsed: LifecyclePayload = toml::from_str(&serialized)?;
    assert_eq!(reparsed, payload);

    let err = "unknown".parse::<ComputationStatus>().unwrap_err();
    assert!(matches!(
        err,
        stoffel::Error::Configuration(message)
            if message.contains("unsupported computation status")
    ));
    Ok(())
}

#[test]
fn validates_byzantine_threshold_configuration() {
    let err = Stoffel::compile(ADD_SOURCE)
        .unwrap()
        .parties(3)
        .threshold(1)
        .build()
        .unwrap_err();

    assert!(matches!(err, stoffel::Error::Configuration(_)));
}

#[test]
fn backend_specific_reconstruction_share_counts_are_explicit() -> stoffel::Result<()> {
    assert_eq!(MpcConfig::minimum_parties_for_threshold(2)?, 9);
    assert_eq!(MpcConfig::maximum_threshold_for_parties(5)?, 1);
    assert_eq!(MpcConfig::maximum_threshold_for_parties(9)?, 2);
    assert!(matches!(
        MpcConfig::maximum_threshold_for_parties(3),
        Err(stoffel::Error::Configuration(_))
    ));

    assert_eq!(MpcBackend::HoneyBadger.minimum_reconstruction_shares(2)?, 5);
    assert_eq!(
        MpcBackend::Avss {
            curve: Curve::Bls12_381
        }
        .minimum_reconstruction_shares(2)?,
        3
    );

    let honeybadger = MpcConfig::builder()
        .parties(9)
        .threshold(2)
        .backend(MpcBackend::HoneyBadger)
        .build()?;
    assert_eq!(honeybadger.minimum_parties()?, 9);
    assert_eq!(honeybadger.maximum_threshold()?, 2);
    assert_eq!(honeybadger.minimum_reconstruction_shares()?, 5);

    let avss = NetworkConfig::builder()
        .expected_parties(9)
        .threshold(2)
        .backend(MpcBackend::Avss {
            curve: Curve::Ed25519,
        })
        .build()?;
    assert_eq!(avss.minimum_reconstruction_shares()?, 3);

    let topology_overflow = MpcConfig::minimum_parties_for_threshold(usize::MAX).unwrap_err();
    assert!(matches!(
        topology_overflow,
        stoffel::Error::Configuration(_)
    ));

    let overflow = MpcBackend::HoneyBadger
        .minimum_reconstruction_shares(usize::MAX)
        .unwrap_err();
    assert!(matches!(overflow, stoffel::Error::Configuration(_)));
    Ok(())
}

#[test]
fn backend_trait_exposes_protocol_identity_without_protocol_logic() {
    fn backend_names(backend: &dyn Backend) -> (&'static str, MpcBackend) {
        (backend.name(), backend.kind())
    }

    let honeybadger = HoneyBadgerBackend::new();
    assert_eq!(
        backend_names(&honeybadger),
        ("honeybadger", MpcBackend::HoneyBadger)
    );
    assert!(MpcBackend::HoneyBadger.is_honeybadger());
    assert!(!MpcBackend::HoneyBadger.is_avss());
    assert_eq!(MpcBackend::HoneyBadger.curve(), None);

    let avss = AvssBackend::new(Curve::Ed25519);
    assert_eq!(avss.curve(), Curve::Ed25519);
    assert_eq!(
        backend_names(&avss),
        (
            "avss",
            MpcBackend::Avss {
                curve: Curve::Ed25519
            }
        )
    );

    let selected = MpcBackend::Avss {
        curve: Curve::Bls12_381,
    };
    assert_eq!(backend_names(&selected), ("avss", selected));
    assert!(!selected.is_honeybadger());
    assert!(selected.is_avss());
    assert_eq!(selected.curve(), Some(Curve::Bls12_381));
}

#[test]
fn network_config_server_addresses_require_all_parties() -> stoffel::Result<()> {
    let complete = NetworkConfig::builder()
        .party_id(1)
        .bind_address("127.0.0.1:19301")
        .expected_parties(5)
        .peer(0, "127.0.0.1:19300")
        .peer(2, "127.0.0.1:19302")
        .peer(3, "127.0.0.1:19303")
        .peer(4, "127.0.0.1:19304")
        .build()?;
    complete.validate_server_addresses()?;
    assert_eq!(
        complete.server_addresses()?,
        vec![
            "127.0.0.1:19300".to_owned(),
            "127.0.0.1:19301".to_owned(),
            "127.0.0.1:19302".to_owned(),
            "127.0.0.1:19303".to_owned(),
            "127.0.0.1:19304".to_owned(),
        ]
    );
    assert_eq!(
        complete
            .server_address_map()?
            .into_iter()
            .collect::<Vec<_>>(),
        vec![
            (0, "127.0.0.1:19300".to_owned()),
            (1, "127.0.0.1:19301".to_owned()),
            (2, "127.0.0.1:19302".to_owned()),
            (3, "127.0.0.1:19303".to_owned()),
            (4, "127.0.0.1:19304".to_owned()),
        ]
    );
    assert_eq!(
        complete.server_address(1)?,
        Some("127.0.0.1:19301".to_owned())
    );
    assert_eq!(
        complete.server_address(3)?,
        Some("127.0.0.1:19303".to_owned())
    );
    let out_of_range = complete.server_address(5).unwrap_err();
    assert!(matches!(out_of_range, stoffel::Error::Configuration(_)));

    let incomplete = NetworkConfig::builder()
        .party_id(0)
        .bind_address("127.0.0.1:19310")
        .expected_parties(5)
        .peer(1, "127.0.0.1:19311")
        .build()?;
    assert_eq!(incomplete.server_address(2)?, None);
    let validation_err = incomplete.validate_server_addresses().unwrap_err();
    assert!(matches!(validation_err, stoffel::Error::Configuration(_)));
    let err = incomplete.server_addresses().unwrap_err();
    assert!(matches!(err, stoffel::Error::Configuration(_)));

    let runtime_err = Stoffel::compile(ADD_SOURCE)?
        .network_config(incomplete)
        .build()
        .unwrap_err();
    assert!(matches!(
        runtime_err,
        stoffel::Error::Configuration(message)
            if message.contains("missing server address for party_id 2")
    ));
    Ok(())
}

#[test]
fn server_builder_captures_operational_configuration() -> stoffel::Result<()> {
    let dir = tempdir()?;
    let runner_path = dir.path().join("stoffel-run");
    let party_cert = dir.path().join("party.pem");
    let party_key = dir.path().join("party.key");
    let client_zero_cert = dir.path().join("client-0.pem");
    let client_one_cert = dir.path().join("client-1.pem");
    std::fs::write(&party_cert, "party cert")?;
    std::fs::write(&party_key, "party key")?;
    std::fs::write(&client_zero_cert, "client zero cert")?;
    std::fs::write(&client_one_cert, "client one cert")?;
    let offchain_coordinator = OffChainServerConfig::builder()
        .coordinator("127.0.0.1:19300")
        .rpc_bind("127.0.0.1:19310")
        .identity_files(&party_cert, &party_key)
        .timestamp(42)
        .expected_client_certs([&client_zero_cert, &client_one_cert])
        .build()?;
    let runtime = Stoffel::compile(ADD_SOURCE)?
        .parties(5)
        .backend(MpcBackend::Avss {
            curve: Curve::Bls12_381,
        })
        .build()?;

    let builder = runtime
        .server(0)
        .bind("127.0.0.1:19200")
        .peers([
            (1, "127.0.0.1:19201"),
            (2, "127.0.0.1:19202"),
            (3, "127.0.0.1:19203"),
            (4, "127.0.0.1:19204"),
        ])
        .with_preprocessing(16, 8)
        .expected_clients(2)
        .consensus_timeout(Duration::from_secs(5))
        .runner_path(&runner_path)
        .entry("main")
        .bootstrap("127.0.0.1:19000")
        .offchain_coordinator(offchain_coordinator.clone());

    assert_eq!(builder.configured_party_id(), 0);
    assert_eq!(builder.configured_bind_addr(), Some("127.0.0.1:19200"));
    assert_eq!(
        builder.configured_peers(),
        &[
            (1, "127.0.0.1:19201".to_owned()),
            (2, "127.0.0.1:19202".to_owned()),
            (3, "127.0.0.1:19203".to_owned()),
            (4, "127.0.0.1:19204".to_owned())
        ]
    );
    assert_eq!(builder.configured_preprocessing(), (16, 8));
    assert_eq!(builder.configured_expected_clients(), 2);
    assert_eq!(
        builder.configured_consensus_timeout(),
        Duration::from_secs(5)
    );
    assert_eq!(
        builder.configured_runner_path(),
        Some(runner_path.as_path())
    );
    assert_eq!(builder.configured_entry(), "main");
    assert_eq!(builder.configured_bootstrap(), Some("127.0.0.1:19000"));
    assert_eq!(
        builder.configured_offchain_coordinator(),
        Some(&offchain_coordinator)
    );
    assert_eq!(
        builder.configured_backend(),
        MpcBackend::Avss {
            curve: Curve::Bls12_381
        }
    );
    let configured_mpc = builder.configured_mpc_config().expect("configured mpc");
    assert_eq!(
        configured_mpc.parties,
        runtime.mpc_config().unwrap().parties
    );
    assert_eq!(
        configured_mpc.threshold,
        runtime.mpc_config().unwrap().threshold
    );
    assert_eq!(
        configured_mpc.backend,
        MpcBackend::Avss {
            curve: Curve::Bls12_381
        }
    );
    assert!(builder.has_configured_program());
    assert_eq!(
        builder.configured_program().unwrap().function_count(),
        runtime.program().function_count()
    );

    let server = builder.build()?;

    assert_eq!(server.party_id(), 0);
    assert_eq!(
        server.backend(),
        MpcBackend::Avss {
            curve: Curve::Bls12_381
        }
    );
    assert_eq!(server.preprocessing(), (16, 8));
    assert_eq!(server.expected_clients(), 2);
    assert!(server.program().is_some());
    assert_eq!(server.runner_path(), Some(runner_path.as_path()));
    assert_eq!(server.entry(), "main");
    assert_eq!(server.bootstrap_addr(), Some("127.0.0.1:19000"));
    assert_eq!(server.offchain_coordinator(), Some(&offchain_coordinator));
    assert_eq!(
        server.mpc_config().expect("server mpc config"),
        runtime.mpc_config().unwrap()
    );
    let summary = server.summary();
    assert_eq!(summary.party_id, 0);
    assert_eq!(summary.bind_addr, "127.0.0.1:19200");
    assert_eq!(summary.peer_count, 4);
    assert_eq!(summary.expected_clients, 2);
    assert_eq!(summary.preprocessing_triples, 16);
    assert_eq!(summary.preprocessing_random_shares, 8);
    assert_eq!(summary.consensus_timeout_ms, 5_000);
    assert_eq!(
        summary.backend,
        MpcBackend::Avss {
            curve: Curve::Bls12_381
        }
    );
    assert_eq!(
        summary.mpc_parties,
        Some(runtime.mpc_config().unwrap().parties)
    );
    assert_eq!(
        summary.mpc_threshold,
        Some(runtime.mpc_config().unwrap().threshold)
    );
    assert_eq!(
        summary.mpc_instance_id,
        Some(runtime.mpc_config().unwrap().instance_id)
    );
    assert!(!summary.has_verified_ordering);
    assert_eq!(summary.state, ServerState::Created);
    assert!(!summary.ready);
    assert!(summary.health.is_degraded());
    assert!(toml::to_string(&summary)?.contains("state = \"created\""));
    Ok(())
}

#[test]
fn topology_aware_server_builder_requires_all_peer_addresses() -> stoffel::Result<()> {
    let runtime = Stoffel::compile(ADD_SOURCE)?.parties(5).build()?;

    let missing_peer = runtime
        .server(0)
        .bind("127.0.0.1:19200")
        .with_peers(&[(1, "127.0.0.1:19201"), (2, "127.0.0.1:19202")])
        .build()
        .unwrap_err();
    assert!(matches!(missing_peer, stoffel::Error::Configuration(_)));

    let out_of_range_peer = runtime
        .server(0)
        .bind("127.0.0.1:19200")
        .with_peers(&[
            (1, "127.0.0.1:19201"),
            (2, "127.0.0.1:19202"),
            (4, "127.0.0.1:19204"),
        ])
        .build()
        .unwrap_err();
    assert!(matches!(
        out_of_range_peer,
        stoffel::Error::Configuration(_)
    ));
    Ok(())
}

#[test]
fn stoffel_direct_participant_builders_do_not_require_compilation() -> stoffel::Result<()> {
    let server_builder = Stoffel::server(0)
        .bind("127.0.0.1:19200")
        .peer(1, "127.0.0.1:19201")
        .honeybadger();
    assert_eq!(server_builder.configured_party_id(), 0);
    assert_eq!(
        server_builder.configured_bind_addr(),
        Some("127.0.0.1:19200")
    );
    assert!(!server_builder.has_configured_program());
    let server = server_builder.build()?;
    assert_eq!(server.party_id(), 0);
    assert_eq!(server.backend(), MpcBackend::HoneyBadger);
    assert!(server.program().is_none());

    let client_builder = Stoffel::client()
        .server("127.0.0.1:19199")
        .with_servers(&["127.0.0.1:19200"])
        .client_id(7);
    assert_eq!(client_builder.configured_client_id(), 7);
    assert_eq!(
        client_builder.configured_servers(),
        &["127.0.0.1:19200".to_owned()]
    );
    assert!(!client_builder.has_configured_program());
    let client = client_builder.build()?;
    assert_eq!(client.client_id(), 7);
    assert_eq!(client.servers(), &["127.0.0.1:19200".to_owned()]);
    assert!(!client.has_program());
    let summary = client.summary();
    assert_eq!(summary.client_id, 7);
    assert_eq!(summary.server_count, 1);
    assert!(!summary.has_program);
    assert!(!summary.has_verified_ordering);
    assert!(!summary.has_offchain_io);
    assert_eq!(summary.state, ClientState::Disconnected);
    assert!(toml::to_string(&summary)?.contains("state = \"disconnected\""));
    Ok(())
}

#[test]
fn offchain_client_config_defaults_to_five_party_topology() -> stoffel::Result<()> {
    let config = offchain_config_builder()
        .coordinator("127.0.0.1", 19000)
        .timestamp(1)
        .node_rpc_addresses(["127.0.0.1:19100"])
        .identity_der(vec![1], vec![2])
        .build()?;
    assert_eq!(config.parties, 5);
    assert_eq!(config.threshold, 1);
    assert_eq!(config.backend, MpcBackend::HoneyBadger);

    let invalid_topology = offchain_config_builder()
        .coordinator("127.0.0.1", 19000)
        .timestamp(1)
        .parties(4)
        .threshold(1)
        .node_rpc_addresses(["127.0.0.1:19100"])
        .identity_der(vec![1], vec![2])
        .build()
        .unwrap_err();
    assert!(matches!(
        invalid_topology,
        stoffel::Error::Configuration(message) if message.contains("at least 5")
    ));

    let zero_threshold = offchain_config_builder()
        .coordinator("127.0.0.1", 19000)
        .timestamp(1)
        .threshold(0)
        .node_rpc_addresses(["127.0.0.1:19100"])
        .identity_der(vec![1], vec![2])
        .build()
        .unwrap_err();
    assert!(matches!(
        zero_threshold,
        stoffel::Error::Configuration(message)
            if message.contains("threshold must be greater than zero")
    ));
    Ok(())
}

#[test]
fn offchain_client_config_reports_actionable_validation_errors() {
    let missing_execution_id = OffChainClientConfig::builder().build().unwrap_err();
    assert!(matches!(
        missing_execution_id,
        stoffel::Error::Configuration(message) if message.contains("execution ID")
    ));

    let missing_port = offchain_config_builder()
        .timestamp(1)
        .node_rpc_address("127.0.0.1:19100")
        .identity_der(vec![1], vec![2])
        .build()
        .unwrap_err();
    assert!(matches!(
        missing_port,
        stoffel::Error::Configuration(message) if message.contains("coordinator port")
    ));

    let missing_timestamp = offchain_config_builder()
        .coordinator("127.0.0.1", 19000)
        .node_rpc_address("127.0.0.1:19100")
        .identity_der(vec![1], vec![2])
        .build()
        .unwrap_err();
    assert!(matches!(
        missing_timestamp,
        stoffel::Error::Configuration(message) if message.contains("timestamp")
    ));

    let missing_cert = offchain_config_builder()
        .coordinator("127.0.0.1", 19000)
        .timestamp(1)
        .node_rpc_address("127.0.0.1:19100")
        .build()
        .unwrap_err();
    assert!(matches!(
        missing_cert,
        stoffel::Error::Configuration(message) if message.contains("certificate")
    ));

    let empty_host = offchain_config_builder()
        .coordinator(" ", 19000)
        .timestamp(1)
        .node_rpc_address("127.0.0.1:19100")
        .identity_der(vec![1], vec![2])
        .build()
        .unwrap_err();
    assert!(matches!(
        empty_host,
        stoffel::Error::Configuration(message) if message.contains("host")
    ));

    let non_bls_curve = offchain_config_builder()
        .coordinator("127.0.0.1", 19000)
        .timestamp(1)
        .avss(Curve::Bn254)
        .node_rpc_address("127.0.0.1:19100")
        .identity_der(vec![1], vec![2])
        .build()
        .expect("BN254 AVSS client config");
    assert_eq!(
        non_bls_curve.backend,
        MpcBackend::Avss {
            curve: Curve::Bn254
        }
    );

    let invalid_threshold = offchain_config_builder()
        .coordinator("127.0.0.1", 19000)
        .timestamp(1)
        .parties(5)
        .threshold(2)
        .honeybadger()
        .node_rpc_address("127.0.0.1:19100")
        .identity_der(vec![1], vec![2])
        .build()
        .unwrap_err();
    assert!(matches!(invalid_threshold, stoffel::Error::Unsupported(_)));

    let missing_rpc = offchain_config_builder()
        .coordinator("127.0.0.1", 19000)
        .timestamp(1)
        .identity_der(vec![1], vec![2])
        .build()
        .unwrap_err();
    assert!(matches!(
        missing_rpc,
        stoffel::Error::Configuration(message) if message.contains("node RPC")
    ));

    let invalid_rpc = offchain_config_builder()
        .coordinator("127.0.0.1", 19000)
        .timestamp(1)
        .node_rpc_address("not-a-socket")
        .identity_der(vec![1], vec![2])
        .build()
        .unwrap_err();
    assert!(matches!(invalid_rpc, stoffel::Error::Configuration(_)));

    let zero_timeout = offchain_config_builder()
        .coordinator("127.0.0.1", 19000)
        .timestamp(1)
        .node_rpc_address("127.0.0.1:19100")
        .identity_der(vec![1], vec![2])
        .timeout(Duration::ZERO)
        .build()
        .unwrap_err();
    assert!(matches!(
        zero_timeout,
        stoffel::Error::Configuration(message) if message.contains("timeout")
    ));
}

#[test]
fn offchain_client_config_accepts_every_avss_curve() {
    let curves = [
        Curve::Bls12_381,
        Curve::Bn254,
        Curve::Curve25519,
        Curve::Ed25519,
        Curve::Secp256k1,
        Curve::Secp256r1,
    ];

    for curve in curves {
        let config = offchain_config_builder()
            .coordinator("127.0.0.1", 19000)
            .timestamp(1)
            .avss(curve)
            .node_rpc_address("127.0.0.1:19100")
            .identity_der(vec![1], vec![2])
            .build()
            .unwrap_or_else(|error| panic!("{curve:?} AVSS client config failed: {error}"));
        assert_eq!(config.backend, MpcBackend::Avss { curve });
    }
}

#[test]
fn offchain_client_config_round_trips_toml_and_identity_files() -> stoffel::Result<()> {
    let dir = tempdir()?;
    let cert_path = dir.path().join("client.cert.der");
    let key_path = dir.path().join("client.key.der");
    std::fs::write(&cert_path, [1_u8, 2, 3])?;
    std::fs::write(&key_path, [4_u8, 5, 6])?;

    let config = offchain_config_builder()
        .coordinator("localhost", 19000)
        .timestamp(42)
        .parties(5)
        .threshold(1)
        .backend(MpcBackend::HoneyBadger)
        .node_rpc_addresses(["127.0.0.1:19100", "127.0.0.1:19101"])
        .identity_files(&cert_path, &key_path)
        .output_count(2)
        .timeout(Duration::from_millis(1_250))
        .build()?;
    assert_eq!(config.cert_der, vec![1, 2, 3]);
    assert_eq!(config.key_der, vec![4, 5, 6]);
    assert_eq!(config.timeout, Duration::from_millis(1_250));

    let serialized = toml::to_string(&config)?;
    assert!(serialized.contains("timeout = 1250"));
    let reparsed: OffChainClientConfig = toml::from_str(&serialized)?;
    reparsed.validate()?;
    assert_eq!(reparsed, config);

    let missing_identity = offchain_config_builder()
        .coordinator("localhost", 19000)
        .timestamp(42)
        .node_rpc_address("127.0.0.1:19100")
        .identity_files(dir.path().join("missing.cert.der"), &key_path)
        .build()
        .unwrap_err();
    assert!(matches!(missing_identity, stoffel::Error::Io(_)));
    Ok(())
}

#[tokio::test]
async fn computation_handle_reports_completion_cancellation_and_unsubmitted_state(
) -> stoffel::Result<()> {
    assert_eq!(
        "pending".parse::<ComputationStatus>()?,
        ComputationStatus::Pending
    );
    assert_eq!(
        "completed".parse::<ComputationStatus>()?,
        ComputationStatus::Completed
    );
    assert_eq!(
        "cancelled".parse::<ComputationStatus>()?,
        ComputationStatus::Cancelled
    );
    assert!(matches!(
        "unknown".parse::<ComputationStatus>(),
        Err(stoffel::Error::Configuration(_))
    ));

    let pending = ComputationHandle::pending();
    assert_eq!(pending.status().to_string(), "pending");
    assert!(pending.is_pending());
    assert!(!pending.is_completed());
    assert!(!pending.is_cancelled());
    let pending_summary = pending.summary();
    assert_eq!(pending_summary.status, ComputationStatus::Pending);
    assert!(!pending_summary.has_result);
    assert_eq!(pending_summary.result_count, 0);
    assert!(matches!(
        pending.await_result().await,
        Err(stoffel::Error::Unsupported(message))
            if message.contains("not been submitted")
    ));

    let completed = ComputationHandle::completed(vec![Value::I64(7), Value::Bool(true)]);
    assert!(completed.is_completed());
    let completed_summary = completed.summary();
    assert_eq!(completed_summary.status, ComputationStatus::Completed);
    assert!(completed_summary.has_result);
    assert_eq!(completed_summary.result_count, 2);
    assert_eq!(
        completed.await_result().await?,
        vec![Value::I64(7), Value::Bool(true)]
    );

    let cancelled = ComputationHandle::pending();
    cancelled.cancel();
    assert!(cancelled.is_cancelled());
    assert!(matches!(
        cancelled.await_result().await,
        Err(stoffel::Error::Computation(message)) if message.contains("cancelled")
    ));
    Ok(())
}

#[tokio::test]
async fn submit_returns_pending_handle_for_live_offchain_submission() -> stoffel::Result<()> {
    let runtime = Stoffel::compile(
        r#"
def main() -> int64:
  var share = ClientStore.take_share(0, 0)
  return share.open()
"#,
    )?
    .parties(5)
    .threshold(1)
    .build()?;
    let config = runtime
        .offchain_client_config(0)?
        .execution_id(ExecutionId::from_bytes([0x52; 32]))
        .coordinator("127.0.0.1", 9)
        .timestamp(1)
        .node_rpc_addresses(["127.0.0.1:19100"])
        .identity_der(vec![1], vec![2])
        .timeout(Duration::from_millis(1))
        .build()?;
    let client = runtime
        .client()
        .client_id(0)
        .server("127.0.0.1:19500")
        .offchain_io(config)
        .build()?;

    let handle = client.submit(&[42_i64]).await?;
    assert_eq!(handle.status(), ComputationStatus::Pending);
    assert!(handle.is_pending());
    handle.cancel();
    assert!(handle.is_cancelled());
    Ok(())
}

#[test]
fn runtime_derives_offchain_client_config_from_typed_program_metadata() -> stoffel::Result<()> {
    let runtime = Stoffel::compile(
        r#"
def main() -> int64:
  var share = ClientStore.take_share(0, 0)
  return share.open()
"#,
    )?
    .parties(5)
    .threshold(1)
    .avss(Curve::Bls12_381)
    .build()?;

    let config = runtime
        .offchain_client_config(0)?
        .execution_id(ExecutionId::from_bytes([0x53; 32]))
        .coordinator("127.0.0.1", 19000)
        .timestamp(1)
        .node_rpc_addresses(["127.0.0.1:19100"])
        .identity_der(vec![1], vec![2])
        .build()?;
    assert_eq!(config.parties, 5);
    assert_eq!(config.threshold, 1);
    assert_eq!(
        config.backend,
        MpcBackend::Avss {
            curve: Curve::Bls12_381
        }
    );
    assert_eq!(config.output_count, 0);

    let missing_slot = runtime.offchain_client_config(1).unwrap_err();
    assert!(matches!(missing_slot, stoffel::Error::Configuration(_)));
    Ok(())
}

#[test]
fn server_builder_expected_clients_must_cover_program_client_io() -> stoffel::Result<()> {
    let program = Stoffel::compile(
        r#"
def main() -> int64:
  var left = ClientStore.take_share(0, 0)
  var right = ClientStore.take_share(1, 0)
  return left.open() + right.open()
"#,
    )?
    .parties(5)
    .threshold(1)
    .build()?
    .program()
    .clone();

    assert!(matches!(
        program.validate_expected_clients(1),
        Err(stoffel::Error::Configuration(_))
    ));

    let too_few_clients = StoffelServer::builder(0)
        .bind("127.0.0.1:19200")
        .with_program(program.clone())
        .expected_clients(1)
        .build()
        .unwrap_err();
    assert!(matches!(too_few_clients, stoffel::Error::Configuration(_)));

    let server = StoffelServer::builder(0)
        .bind("127.0.0.1:19200")
        .with_program(program)
        .expected_clients(2)
        .build()?;
    assert_eq!(server.expected_clients(), 2);
    Ok(())
}

#[test]
fn server_builder_rejects_sparse_client_slots_beyond_expected_clients() -> stoffel::Result<()> {
    let program = Stoffel::compile(
        r#"
def main() -> int64:
  var share = ClientStore.take_share(3, 0)
  return share.open()
"#,
    )?
    .parties(5)
    .threshold(1)
    .build()?
    .program()
    .clone();

    let sparse_slot = StoffelServer::builder(0)
        .bind("127.0.0.1:19200")
        .with_program(program.clone())
        .expected_clients(2)
        .build()
        .unwrap_err();
    assert!(matches!(sparse_slot, stoffel::Error::Configuration(_)));

    let server = StoffelServer::builder(0)
        .bind("127.0.0.1:19200")
        .with_program(program)
        .expected_clients(4)
        .build()?;
    assert_eq!(server.expected_clients(), 4);
    Ok(())
}

#[test]
fn config_builders_make_advanced_configuration_explicit() -> stoffel::Result<()> {
    let mpc = MpcConfig::builder()
        .parties(9)
        .threshold(2)
        .instance_id(99)
        .avss(Curve::Ed25519)
        .build()?;

    let network = NetworkConfig::builder()
        .party_id(1)
        .bind_address("127.0.0.1:19301")
        .expected_parties(9)
        .expected_clients(3)
        .consensus_timeout(Duration::from_secs(2))
        .peer(6, "127.0.0.1:19306")
        .peers([(0, "127.0.0.1:19300"), (2, "127.0.0.1:19302")])
        .threshold(2)
        .avss(Curve::Bls12_381)
        .preprocessing(32, 16)
        .build()?;

    assert_eq!(mpc.parties, 9);
    assert_eq!(network.network.party_id, 1);
    assert_eq!(
        network.to_mpc_config(100)?.backend,
        MpcBackend::Avss {
            curve: Curve::Bls12_381
        }
    );
    assert_eq!(network.consensus_timeout(), Duration::from_secs(2));
    assert_eq!(network.peer_addresses().len(), 2);
    assert_eq!(
        network.server_address(2)?.as_deref(),
        Some("127.0.0.1:19302")
    );
    assert_eq!(
        network.mpc_backend()?,
        MpcBackend::Avss {
            curve: Curve::Bls12_381
        }
    );
    assert_eq!(network.preprocessing.triples, 32);

    let quic: QuicNetworkConfig = (&network).try_into()?;
    assert_eq!(quic.expected_parties, Some(9));
    assert_eq!(quic.expected_clients, Some(3));
    assert_eq!(quic.consensus_timeout_ms, 2_000);
    let _manager = network.to_quic_manager()?;

    let topology = mpc.to_vm_topology(3)?;
    assert_eq!(topology.instance_id(), 99);
    assert_eq!(topology.party_id(), 3);
    assert_eq!(topology.n_parties(), 9);
    assert_eq!(topology.threshold(), 2);
    Ok(())
}

#[test]
fn backend_and_curve_strings_parse_to_sdk_config_types() -> stoffel::Result<()> {
    assert_eq!("bls12-381".parse::<Curve>()?, Curve::Bls12_381);
    assert_eq!("BN_254".parse::<Curve>()?, Curve::Bn254);
    assert_eq!(Curve::Ed25519.to_string(), "ed25519");

    assert_eq!(
        "honey_badger".parse::<MpcBackend>()?,
        MpcBackend::HoneyBadger
    );
    assert!(matches!(
        "honeybadger:ed25519".parse::<MpcBackend>(),
        Err(stoffel::Error::Configuration(_))
    ));
    assert_eq!(
        "avss:ed25519".parse::<MpcBackend>()?,
        MpcBackend::Avss {
            curve: Curve::Ed25519
        }
    );
    assert_eq!(
        "avss:ed25519".parse::<MpcBackend>()?.curve(),
        Some(Curve::Ed25519)
    );
    assert_eq!(
        MpcBackend::Avss {
            curve: Curve::Curve25519
        }
        .to_string(),
        "avss:curve25519"
    );

    let network = NetworkConfig::builder().protocol("avss:bn254").build()?;
    assert_eq!(
        MpcBackend::try_from(&network)?,
        MpcBackend::Avss {
            curve: Curve::Bn254
        }
    );
    Ok(())
}

#[test]
fn mpc_config_and_backend_round_trip_as_readable_config() -> stoffel::Result<()> {
    #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct BackendSelection {
        backend: MpcBackend,
    }

    let config = MpcConfig::builder()
        .parties(9)
        .threshold(2)
        .instance_id(42)
        .avss(Curve::Ed25519)
        .build()?;

    let serialized = toml::to_string(&config)?;
    assert!(serialized.contains("backend = \"avss:ed25519\""));

    let reparsed: MpcConfig = toml::from_str(&serialized)?;
    assert_eq!(reparsed, config);
    assert_eq!(reparsed.backend.minimum_reconstruction_shares(2)?, 3);
    let summary = reparsed.summary()?;
    assert_eq!(summary.parties, 9);
    assert_eq!(summary.threshold, 2);
    assert_eq!(summary.minimum_parties, 9);
    assert_eq!(summary.maximum_threshold, 2);
    assert_eq!(summary.minimum_reconstruction_shares, 3);
    assert!(toml::to_string(&summary)?.contains("backend = \"avss:ed25519\""));

    let backend = BackendSelection {
        backend: MpcBackend::HoneyBadger,
    };
    let serialized_backend = toml::to_string(&backend)?;
    assert_eq!(serialized_backend.trim(), "backend = \"honeybadger\"");
    assert_eq!(
        toml::from_str::<BackendSelection>("backend = \"avss:bls12_381\"")?,
        BackendSelection {
            backend: MpcBackend::Avss {
                curve: Curve::Bls12_381
            }
        }
    );
    Ok(())
}

#[test]
fn network_config_rejects_invalid_protocol_and_party_id() {
    let invalid_protocol = NetworkConfig::builder().protocol("unsupported").build();
    assert!(matches!(
        invalid_protocol,
        Err(stoffel::Error::Configuration(_))
    ));

    let invalid_honeybadger_curve = NetworkConfig::builder()
        .protocol("honeybadger:ed25519")
        .build();
    assert!(matches!(
        invalid_honeybadger_curve,
        Err(stoffel::Error::Configuration(_))
    ));

    let invalid_party = NetworkConfig::builder()
        .party_id(5)
        .expected_parties(5)
        .build();
    assert!(matches!(
        invalid_party,
        Err(stoffel::Error::Configuration(_))
    ));

    let too_few_parties = NetworkConfig::builder()
        .party_id(0)
        .expected_parties(3)
        .threshold(1)
        .build();
    assert!(matches!(
        too_few_parties,
        Err(stoffel::Error::Configuration(_))
    ));

    let invalid_threshold = NetworkConfig::builder()
        .party_id(0)
        .expected_parties(5)
        .threshold(2)
        .build();
    assert!(matches!(
        invalid_threshold,
        Err(stoffel::Error::Configuration(_))
    ));

    let out_of_range_peer = NetworkConfig::builder()
        .party_id(0)
        .expected_parties(5)
        .peer(5, "127.0.0.1:19605")
        .build();
    assert!(matches!(
        out_of_range_peer,
        Err(stoffel::Error::Configuration(_))
    ));

    let self_peer = NetworkConfig::builder()
        .party_id(2)
        .expected_parties(5)
        .peer(2, "127.0.0.1:19602")
        .build();
    assert!(matches!(self_peer, Err(stoffel::Error::Configuration(_))));

    let empty_peer_address = NetworkConfig::builder()
        .party_id(0)
        .expected_parties(5)
        .peer(1, " ")
        .build();
    assert!(matches!(
        empty_peer_address,
        Err(stoffel::Error::Configuration(_))
    ));

    let invalid_bind_address = NetworkConfig::builder()
        .bind_address("not a socket address")
        .build();
    assert!(matches!(
        invalid_bind_address,
        Err(stoffel::Error::Configuration(_))
    ));

    let invalid_peer_address = NetworkConfig::builder()
        .party_id(0)
        .expected_parties(5)
        .peer(1, "not a socket address")
        .build();
    assert!(matches!(
        invalid_peer_address,
        Err(stoffel::Error::Configuration(_))
    ));

    let zero_triples = NetworkConfig::builder().preprocessing(0, 1).build();
    assert!(matches!(
        zero_triples,
        Err(stoffel::Error::Configuration(_))
    ));

    let zero_random_shares = NetworkConfig::builder().preprocessing(1, 0).build();
    assert!(matches!(
        zero_random_shares,
        Err(stoffel::Error::Configuration(_))
    ));
}

#[test]
fn network_config_file_and_server_builder_validate_config() -> stoffel::Result<()> {
    let dir = tempdir()?;
    let source_path = dir.path().join("program.stfl");
    let config_path = dir.path().join("network.toml");

    std::fs::write(&source_path, CLEAR_ADD_SOURCE)?;
    std::fs::write(
        &config_path,
        r#"
[network]
party_id = 3
bind_address = "127.0.0.1:19803"
expected_parties = 3
expected_clients = 0
consensus_timeout_ms = 1000

[mpc]
threshold = 1
protocol = "honeybadger"

[preprocessing]
triples = 1
random_shares = 1
"#,
    )?;

    let err = Stoffel::compile_file(&source_path)?
        .network_config_file(&config_path)
        .build()
        .unwrap_err();
    assert!(matches!(err, stoffel::Error::Configuration(_)));

    let config = NetworkConfig {
        network: stoffel::NetworkSection {
            party_id: 3,
            expected_parties: 3,
            ..Default::default()
        },
        ..Default::default()
    };
    let server_err = StoffelServer::builder(0)
        .network_config(&config)
        .build()
        .unwrap_err();
    assert!(matches!(server_err, stoffel::Error::Configuration(_)));

    let valid_config = NetworkConfig::builder()
        .party_id(2)
        .bind_address("127.0.0.1:19812")
        .expected_parties(5)
        .peer(0, "127.0.0.1:19810")
        .peer(1, "127.0.0.1:19811")
        .peer(3, "127.0.0.1:19813")
        .peer(4, "127.0.0.1:19814")
        .build()?;
    let mismatch = StoffelServer::builder(1)
        .network_config(&valid_config)
        .build()
        .unwrap_err();
    assert!(matches!(mismatch, stoffel::Error::Configuration(_)));

    let matching = StoffelServer::builder(2)
        .network_config(&valid_config)
        .build()?;
    assert_eq!(matching.party_id(), 2);
    assert_eq!(matching.bind_addr(), "127.0.0.1:19812");
    let matching_mpc = matching.mpc_config().expect("network-derived mpc config");
    assert_eq!(matching_mpc.parties, 5);
    assert_eq!(matching_mpc.threshold, valid_config.mpc.threshold);
    assert_eq!(matching.summary().mpc_parties, Some(5));

    let self_peer = StoffelServer::builder(1)
        .bind("127.0.0.1:19801")
        .with_peers(&[(1, "127.0.0.1:19801")])
        .build()
        .unwrap_err();
    assert!(matches!(self_peer, stoffel::Error::Configuration(_)));

    let empty_peer_address = StoffelServer::builder(1)
        .bind("127.0.0.1:19801")
        .with_peers(&[(2, " ")])
        .build()
        .unwrap_err();
    assert!(matches!(
        empty_peer_address,
        stoffel::Error::Configuration(_)
    ));

    let invalid_peer_address = StoffelServer::builder(1)
        .bind("127.0.0.1:19801")
        .with_peers(&[(2, "not a socket address")])
        .build()
        .unwrap_err();
    assert!(matches!(
        invalid_peer_address,
        stoffel::Error::Configuration(_)
    ));

    let duplicate_peer = StoffelServer::builder(1)
        .bind("127.0.0.1:19801")
        .with_peers(&[(2, "127.0.0.1:19802"), (2, "127.0.0.1:19812")])
        .build()
        .unwrap_err();
    assert!(matches!(duplicate_peer, stoffel::Error::Configuration(_)));

    let invalid_preprocessing = StoffelServer::builder(1)
        .bind("127.0.0.1:19801")
        .with_preprocessing(0, 1)
        .build()
        .unwrap_err();
    assert!(matches!(
        invalid_preprocessing,
        stoffel::Error::Configuration(_)
    ));

    let zero_consensus_timeout = StoffelServer::builder(1)
        .bind("127.0.0.1:19801")
        .consensus_timeout(Duration::ZERO)
        .build()
        .unwrap_err();
    assert!(matches!(
        zero_consensus_timeout,
        stoffel::Error::Configuration(message) if message.contains("consensus timeout")
    ));
    Ok(())
}

#[test]
fn client_and_server_builders_can_load_network_config_files() -> stoffel::Result<()> {
    let dir = tempdir()?;
    let config_path = dir.path().join("network.toml");
    std::fs::write(
        &config_path,
        r#"
[network]
party_id = 1
bind_address = "127.0.0.1:19901"
expected_parties = 5
expected_clients = 2
consensus_timeout_ms = 1500

[network.peers]
0 = "127.0.0.1:19900"
2 = "127.0.0.1:19902"
3 = "127.0.0.1:19903"
4 = "127.0.0.1:19904"

[mpc]
threshold = 1
protocol = "honeybadger"

[preprocessing]
triples = 12
random_shares = 6
"#,
    )?;

    let client = StoffelClient::builder()
        .network_config_file(&config_path)
        .build()?;
    assert_eq!(
        client.servers(),
        &[
            "127.0.0.1:19900".to_owned(),
            "127.0.0.1:19901".to_owned(),
            "127.0.0.1:19902".to_owned(),
            "127.0.0.1:19903".to_owned(),
            "127.0.0.1:19904".to_owned(),
        ]
    );

    let server = StoffelServer::builder(1)
        .network_config_file(&config_path)
        .build()?;
    assert_eq!(server.bind_addr(), "127.0.0.1:19901");
    assert_eq!(server.peers().len(), 4);
    assert_eq!(server.preprocessing(), (12, 6));
    assert_eq!(server.expected_clients(), 2);
    assert_eq!(server.consensus_timeout(), Duration::from_millis(1500));

    let mismatch = StoffelServer::builder(2)
        .network_config_file(&config_path)
        .build()
        .unwrap_err();
    assert!(matches!(mismatch, stoffel::Error::Configuration(_)));
    Ok(())
}

#[tokio::test]
async fn loaded_bytecode_named_inputs_are_adapted_before_runner_lookup() -> stoffel::Result<()> {
    let dir = tempfile::tempdir()?;
    let runner_path = dir.path().join("missing-stoffel-run");
    let bytecode = Stoffel::compile(ADD_SOURCE)?
        .build()?
        .program()
        .to_bytecode()?;
    let err = Stoffel::load(&bytecode)?
        .local_runner_path(&runner_path)
        .with_inputs(&[("a", 42_i64), ("b", 58_i64)])
        .execute_local()
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        stoffel::Error::Unsupported(message) if message.contains("stoffel-run")
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator and MPC party mesh; requires stoffel-run"]
async fn execute_local_uses_real_local_coordinator_runner() -> stoffel::Result<()> {
    let result = Stoffel::compile("def main() -> int64:\n  return 7")?
        .parties(5)
        .threshold(1)
        .execute_local()
        .await?;

    assert_eq!(result, vec![Value::I64(7)]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator and MPC party mesh; requires target/debug/stoffel-run"]
async fn execute_local_accepts_workspace_relative_runner_path() -> stoffel::Result<()> {
    let result = Stoffel::compile("def main() -> int64:\n  return 7")?
        .parties(5)
        .threshold(1)
        .local_runner_path("target/debug/stoffel-run")
        .execute_local()
        .await?;

    assert_eq!(result, vec![Value::I64(7)]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator and AVSS MPC party mesh; requires target/debug/stoffel-run"]
async fn execute_local_uses_real_local_avss_coordinator_runner_for_no_input_program(
) -> stoffel::Result<()> {
    let result = Stoffel::compile("def main() -> int64:\n  return 7")?
        .parties(5)
        .threshold(1)
        .avss(Curve::Bls12_381)
        .local_runner_path("target/debug/stoffel-run")
        .execute_local()
        .await?;

    assert_eq!(result, vec![Value::I64(7)]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator and AVSS MPC party mesh; requires target/debug/stoffel-run"]
async fn execute_local_preserves_party_local_opaque_return_shares() -> stoffel::Result<()> {
    let result = Stoffel::compile(
        "def main() -> secret int64:\n  var share: secret int64 = Share.random()\n  return share",
    )?
    .parties(5)
    .threshold(1)
    .avss(Curve::Bls12_381)
    .local_runner_path("target/debug/stoffel-run")
    .execute_local_returning_party_shares()
    .await?;

    assert!(result.client_outputs.is_empty());
    assert_eq!(result.shares().len(), 5);
    assert_eq!(result.party_outputs.len(), 5);

    let mut payloads = std::collections::HashSet::new();
    for party in &result.party_outputs {
        let share = &party.returned_share;
        assert_eq!(share.share_type, ShareType::secret_int(64));
        assert_eq!(share.backend_format, ShareDataFormat::Feldman);
        assert!(!share.as_bytes().is_empty());
        payloads.insert(share.as_bytes().to_vec());
    }
    assert_eq!(payloads.len(), 5, "each party must retain its own share");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator, AVSS MPC party mesh, and coordinator client"]
async fn execute_local_submits_avss_clientstore_inputs_through_coordinator() -> stoffel::Result<()>
{
    let result = Stoffel::compile(
        r#"
def main() -> int64:
  var share = ClientStore.take_share(0, 0)
  var opened: int64 = share.open()
  return opened + 5
"#,
    )?
    .parties(5)
    .threshold(1)
    .avss(Curve::Bls12_381)
    .with_client_input(0, &[42_i64])
    .local_runner_path("target/debug/stoffel-run")
    .execute_local()
    .await?;

    assert_eq!(result, vec![Value::I64(47)]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator, BN254 AVSS party mesh, and coordinator client"]
async fn execute_local_submits_bn254_avss_clientstore_inputs_through_coordinator(
) -> stoffel::Result<()> {
    let result = Stoffel::compile(
        r#"
def main() -> int64:
  var share = ClientStore.take_share(0, 0)
  var opened: int64 = share.open()
  return opened + 5
"#,
    )?
    .parties(5)
    .threshold(1)
    .avss(Curve::Bn254)
    .with_client_input(0, &[42_i64])
    .local_runner_path("target/debug/stoffel-run")
    .execute_local()
    .await?;

    assert_eq!(result, vec![Value::I64(47)]);
    Ok(())
}

#[tokio::test]
async fn secret_parameter_named_inputs_are_adapted_before_runner_lookup() -> stoffel::Result<()> {
    let dir = tempfile::tempdir()?;
    let runner_path = dir.path().join("missing-stoffel-run");

    let err = Stoffel::compile(ADD_SOURCE)?
        .parties(5)
        .threshold(1)
        .local_runner_path(&runner_path)
        .with_inputs(&[("a", 42_i64), ("b", 58_i64)])
        .execute_local()
        .await
        .unwrap_err();

    assert!(
        matches!(
        err,
            stoffel::Error::Unsupported(ref message) if message.contains("stoffel-run")
        ),
        "unexpected error: {err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn secret_list_named_inputs_are_adapted_before_runner_lookup() -> stoffel::Result<()> {
    let dir = tempfile::tempdir()?;
    let runner_path = dir.path().join("missing-stoffel-run");

    let err = Stoffel::compile(
        r#"
def main(values: list[Share]) -> int64:
  return values[0].open()
"#,
    )?
    .parties(5)
    .threshold(1)
    .local_runner_path(&runner_path)
    .with_input("values", Value::List(vec![Value::I64(42), Value::I64(58)]))
    .execute_local()
    .await
    .unwrap_err();

    assert!(
        matches!(
        err,
            stoffel::Error::Unsupported(ref message) if message.contains("stoffel-run")
        ),
        "unexpected error: {err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn mixed_clear_and_secret_list_named_inputs_are_adapted_before_runner_lookup(
) -> stoffel::Result<()> {
    let dir = tempfile::tempdir()?;
    let runner_path = dir.path().join("missing-stoffel-run");

    let err = Stoffel::compile(
        r#"
def main(n: int64, values: list[Share]) -> int64:
  return n
"#,
    )?
    .parties(5)
    .threshold(1)
    .local_runner_path(&runner_path)
    .with_input("n", 2_i64)
    .with_input("values", Value::List(vec![Value::I64(42), Value::I64(58)]))
    .execute_local()
    .await
    .unwrap_err();

    assert!(
        matches!(
        err,
            stoffel::Error::Unsupported(ref message) if message.contains("stoffel-run")
        ),
        "unexpected error: {err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn file_secret_parameter_named_inputs_are_adapted_before_runner_lookup() -> stoffel::Result<()>
{
    let dir = tempfile::tempdir()?;
    let source_path = dir.path().join("private_add.stfl");
    std::fs::write(&source_path, ADD_SOURCE)?;
    let runner_path = dir.path().join("missing-stoffel-run");

    let err = Stoffel::compile_file(&source_path)?
        .parties(5)
        .threshold(1)
        .local_runner_path(&runner_path)
        .with_inputs(&[("a", 42_i64), ("b", 58_i64)])
        .execute_local()
        .await
        .unwrap_err();

    assert!(
        matches!(
        err,
            stoffel::Error::Unsupported(ref message) if message.contains("stoffel-run")
        ),
        "unexpected error: {err:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator, MPC party mesh, and coordinator client"]
async fn execute_local_adapts_prd_secret_int_quickstart() -> stoffel::Result<()> {
    let result = Stoffel::compile(ADD_SOURCE)?
        .parties(5)
        .threshold(1)
        .with_inputs(&[("a", 42_i64), ("b", 58_i64)])
        .execute_local_returning_party_shares()
        .await?;

    assert!(result.client_outputs.is_empty());
    assert_eq!(result.shares().len(), 5);
    assert!(result.shares().all(|share| {
        share.share_type == ShareType::secret_int(64)
            && share.backend_format == ShareDataFormat::Opaque
            && !share.as_bytes().is_empty()
    }));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator, MPC party mesh, and coordinator client"]
async fn execute_local_adapts_loaded_secret_int_bytecode() -> stoffel::Result<()> {
    let bytecode = Stoffel::compile(ADD_SOURCE)?
        .build()?
        .program()
        .to_bytecode()?;

    let result = Stoffel::load(&bytecode)?
        .parties(5)
        .threshold(1)
        .with_inputs(&[("a", 42_i64), ("b", 58_i64)])
        .execute_local_returning_party_shares()
        .await?;

    assert!(result.client_outputs.is_empty());
    assert_eq!(result.shares().len(), 5);
    assert!(result.shares().all(|share| {
        share.share_type == ShareType::secret_int(64)
            && share.backend_format == ShareDataFormat::Opaque
            && !share.as_bytes().is_empty()
    }));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator, MPC party mesh, and coordinator client"]
async fn execute_local_maps_share_parameters_through_coordinator_client() -> stoffel::Result<()> {
    let result = Stoffel::compile(
        r#"
def add_client_values(a: Share, b: Share) -> int64:
  var sum = Share.add(a, b)
  return sum.open()
"#,
    )?
    .parties(5)
    .threshold(1)
    .with_inputs(&[("a", 42_i64), ("b", 58_i64)])
    .execute_local_function("add_client_values")
    .await?;

    assert_eq!(result, vec![Value::I64(100)]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator, MPC party mesh, and coordinator client"]
async fn execute_local_submits_clientstore_inputs_through_coordinator() -> stoffel::Result<()> {
    let result = Stoffel::compile(
        r#"
def main() -> int64:
  var share = ClientStore.take_share(0, 0)
  var opened: int64 = share.open()
  return opened + 5
"#,
    )?
    .parties(5)
    .threshold(1)
    .with_client_input(0, &[42_i64])
    .execute_local()
    .await?;

    assert_eq!(result, vec![Value::I64(47)]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator, MPC party mesh, and coordinator client"]
async fn runtime_execute_local_uses_real_local_coordinator_runner() -> stoffel::Result<()> {
    let runtime = Stoffel::compile(
        r#"
def main() -> int64:
  var share = ClientStore.take_share(0, 0)
  return share.open()
"#,
    )?
    .parties(5)
    .threshold(1)
    .with_client_input(0, &[55_i64])
    .build()?;

    assert_eq!(runtime.execute_local().await?, vec![Value::I64(55)]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator, MPC party mesh, and coordinator client"]
async fn local_network_builder_uses_real_local_coordinator_runner() -> stoffel::Result<()> {
    let runtime = Stoffel::compile(
        r#"
def reveal_client_value() -> int64:
  var share = ClientStore.take_share(0, 0)
  return share.open()
"#,
    )?
    .parties(5)
    .threshold(1)
    .with_client_input(0, &[61_i64])
    .build()?;

    let result = runtime
        .local_network()
        .entry("reveal_client_value")
        .runner_path("target/debug/stoffel-run")
        .timeout(Duration::from_secs(180))
        .run()
        .await?;

    assert_eq!(result, vec![Value::I64(61)]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a real localhost coordinator, MPC party mesh, and two coordinator clients"]
async fn execute_local_submits_multiple_clientstore_inputs() -> stoffel::Result<()> {
    let result = Stoffel::compile(
        r#"
def main() -> int64:
  var left_share = ClientStore.take_share(0, 0)
  var right_share = ClientStore.take_share(1, 0)
  var left: int64 = left_share.open()
  var right: int64 = right_share.open()
  return left + right + 5
"#,
    )?
    .parties(5)
    .threshold(1)
    .with_client_input(0, &[40_i64])
    .with_client_input(1, &[2_i64])
    .execute_local()
    .await?;

    assert_eq!(result, vec![Value::I64(47)]);
    Ok(())
}

#[test]
fn consensus_types_are_reexported_from_networking() {
    let ordering = VerifiedOrdering::new(vec![], vec![]);
    assert_eq!(ordering.node_count(), 0);
    assert_eq!(ordering.client_count(), 0);

    let root_ordering = stoffel::VerifiedOrdering::new(vec![], vec![]);
    assert_eq!(root_ordering.node_count(), 0);

    assert_eq!(ConsensusGate::Ready, stoffel::ConsensusGate::Ready);
    assert!(matches!(
        stoffel::ConsensusGate::Failed("digest mismatch".to_owned()),
        ConsensusGate::Failed(message) if message == "digest mismatch"
    ));

    let network_error = stoffel::Error::from(stoffel::NetworkError::Timeout);
    assert!(matches!(network_error, stoffel::Error::Network(_)));

    let status = ComputationStatus::Pending;
    assert_eq!(status, ComputationStatus::Pending);
}

#[tokio::test]
async fn participants_can_carry_verified_ordering_from_networking() -> stoffel::Result<()> {
    let ordering = VerifiedOrdering::new(
        vec![NodePublicKey(vec![1]), NodePublicKey(vec![2])],
        vec![NodePublicKey(vec![9])],
    );

    let server_builder = StoffelServer::builder(0)
        .bind("127.0.0.1:20500")
        .peer(1, "127.0.0.1:20501")
        .with_verified_ordering(ordering.clone());
    assert!(server_builder.has_configured_verified_ordering());
    assert_eq!(
        server_builder.configured_verified_ordering().unwrap(),
        &ordering
    );
    let server = server_builder.build()?;
    assert_eq!(server.verified_ordering(), Some(&ordering));
    let server_summary = server.summary();
    assert!(server_summary.has_verified_ordering);
    assert!(toml::to_string(&server_summary)?.contains("has_verified_ordering = true"));

    let client_builder = StoffelClient::builder()
        .server("127.0.0.1:20500")
        .server("127.0.0.1:20501")
        .with_verified_ordering(ordering.clone());
    assert!(client_builder.has_configured_verified_ordering());
    assert_eq!(
        client_builder.configured_verified_ordering().unwrap(),
        &ordering
    );
    let client = client_builder.build()?;
    assert_eq!(client.verified_ordering(), Some(&ordering));
    assert_eq!(client.verify_ordering().await?, ordering);
    let client_summary = client.summary();
    assert!(client_summary.has_verified_ordering);
    assert!(toml::to_string(&client_summary)?.contains("has_verified_ordering = true"));
    Ok(())
}

#[test]
fn offchain_coordinator_surface_reexports_core_types() {
    let _ = std::any::type_name::<
        stoffel::coordinator::OffChainCoordinator<
            stoffel_mpc_coordinator_shared::tests::fake_coord::HoneyBadgerShareValueType,
            stoffel_mpc_coordinator_shared::tests::fake_coord::HoneyBadgerShareType,
        >,
    >();

    let client: stoffel::coordinator::ClientIdentity = vec![1, 2, 3];

    assert_eq!(client, vec![1, 2, 3]);
}

#[test]
fn coordinator_errors_convert_into_sdk_error() {
    let error = stoffel::Error::from(CoordinatorError::IndexAlreadyReserved(7));
    assert!(matches!(error, stoffel::Error::Coordinator(_)));
}

#[test]
fn sdk_errors_expose_categories_for_recovery_logic() {
    #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct ErrorSummary {
        category: ErrorCategory,
    }

    let network = stoffel::Error::from(stoffel::NetworkError::Timeout);
    assert_eq!(network.category(), ErrorCategory::Network);
    assert_eq!(network.category().as_str(), "network");
    assert_eq!(network.category().to_string(), "network");
    assert_eq!(
        "network".parse::<ErrorCategory>().unwrap(),
        ErrorCategory::Network
    );
    assert!(network.is_recoverable());
    assert!(ErrorCategory::Network.is_recoverable());
    assert_eq!(
        network.recovery_hint(),
        Some("check connectivity and retry with the same program and inputs")
    );

    let preprocessing = stoffel::Error::Preprocessing("not enough triples".to_owned());
    assert_eq!(preprocessing.category(), ErrorCategory::Preprocessing);
    assert_eq!(ErrorCategory::Preprocessing.as_str(), "preprocessing");
    assert!(preprocessing.is_recoverable());
    assert_eq!(
        ErrorCategory::Preprocessing.recovery_hint(),
        Some("ensure each server has enough triples and random shares before retrying")
    );

    let config = stoffel::Error::Configuration("bad threshold".to_owned());
    assert_eq!(config.category(), ErrorCategory::Configuration);
    assert!(!config.is_recoverable());
    assert!(!ErrorCategory::Configuration.is_recoverable());
    assert_eq!(
        config.recovery_hint(),
        Some("fix the invalid SDK configuration before retrying")
    );

    let missing_function = stoffel::Error::FunctionNotFound("main".to_owned());
    assert_eq!(missing_function.category(), ErrorCategory::Runtime);
    assert!(!missing_function.is_recoverable());
    assert_eq!(missing_function.recovery_hint(), None);

    let summary = ErrorSummary {
        category: ErrorCategory::ConfigParse,
    };
    let serialized = toml::to_string(&summary).unwrap();
    assert_eq!(serialized.trim(), "category = \"config_parse\"");
    let reparsed: ErrorSummary = toml::from_str(&serialized).unwrap();
    assert_eq!(reparsed, summary);

    let err = "bad_category".parse::<ErrorCategory>().unwrap_err();
    assert!(matches!(
        err,
        stoffel::Error::Configuration(message)
            if message.contains("unsupported error category")
    ));
}

#[test]
fn common_crypto_types_have_small_sdk_helpers() {
    let share = Share::new("threshold-key");
    assert_eq!(share.key_name(), "threshold-key");
    assert_eq!(share.data(), None);
    assert!(share.is_opaque());
    assert!(!share.is_feldman());
    assert_eq!(share.commitment_count(), 0);
    assert_eq!(share.public_key(), None);

    let opaque = Share::opaque("hb-key", [0xaa, 0xbb]);
    assert_eq!(opaque.data(), Some(&[0xaa, 0xbb][..]));
    assert!(opaque.is_opaque());
    assert!(!opaque.has_commitments());

    let feldman = Share::feldman("avss-key", [0x01, 0x02], [[0x10, 0x20], [0x30, 0x40]]);
    assert_eq!(feldman.key_name(), "avss-key");
    assert_eq!(feldman.data(), Some(&[0x01, 0x02][..]));
    assert!(feldman.is_feldman());
    assert_eq!(feldman.commitment_count(), 2);
    assert_eq!(feldman.commitment(1), Some(&[0x30, 0x40][..]));
    assert_eq!(
        feldman.public_key(),
        Some(PublicKey::new("avss-key", [0x10, 0x20]))
    );

    let public_key = PublicKey::new("threshold-key", [1, 2, 3]);
    assert_eq!(public_key.key_name(), "threshold-key");
    assert_eq!(public_key.as_bytes(), &[1, 2, 3]);
    assert_eq!(public_key.into_bytes(), vec![1, 2, 3]);

    let field = FieldElement::from(&[4_u8, 5, 6][..]);
    assert_eq!(field.as_bytes(), &[4, 5, 6]);
    assert_eq!(field.into_bytes(), vec![4, 5, 6]);

    let group = GroupElement::from_bytes(vec![7, 8, 9]);
    assert_eq!(group.as_bytes(), &[7, 8, 9]);
    assert_eq!(GroupElement::from(&[1_u8, 2][..]).into_bytes(), vec![1, 2]);

    let _round: Round = stoffel::coordinator::Round::Preprocessing;
    let mask_index: MaskIndex = 42;
    assert_eq!(mask_index, 42);
}

#[test]
fn value_helpers_make_outputs_easy_to_read() {
    let borrowed_string = "borrowed".to_owned();
    let values = [
        Value::I64(-7),
        Value::U64(7),
        Value::Bool(true),
        Value::Float(1.5),
        Value::String("done".to_owned()),
        Value::Bytes(vec![0xab, 0xcd]),
        Value::List(vec![Value::I64(1), Value::I64(2)]),
        Value::Unit,
    ];

    assert_eq!(values[0].as_i64(), Some(-7));
    assert_eq!(values[1].as_u64(), Some(7));
    assert_eq!(values[2].as_bool(), Some(true));
    assert_eq!(values[3].as_f64(), Some(1.5));
    assert_eq!(values[4].as_str(), Some("done"));
    assert_eq!(values[6].as_list().map(<[Value]>::len), Some(2));
    assert_eq!(values[0].kind(), "i64");
    assert_eq!(values[0].summary().kind, "i64");
    assert_eq!(values[0].summary().item_count, None);
    assert_eq!(values[1].as_u64(), Some(7));
    assert_eq!(values[2].as_bool(), Some(true));
    assert_eq!(values[3].as_f64(), Some(1.5));
    assert_eq!(values[4].as_str(), Some("done"));
    assert_eq!(values[4].summary().byte_len, Some(4));
    assert_eq!(values[5].as_bytes(), Some(&[0xab, 0xcd][..]));
    assert_eq!(values[5].summary().byte_len, Some(2));
    assert_eq!(
        values[6]
            .as_list()
            .unwrap()
            .iter()
            .map(Value::as_i64)
            .collect::<Vec<_>>(),
        vec![Some(1), Some(2)]
    );
    assert_eq!(values[6].summary().item_count, Some(2));
    assert!(values[7].is_unit());
    assert_eq!(values[4].clone().into_string(), Some("done".to_owned()));
    assert_eq!(values[5].clone().into_bytes(), Some(vec![0xab, 0xcd]));
    assert_eq!(
        values[6].clone().into_list(),
        Some(vec![Value::I64(1), Value::I64(2)])
    );
    assert_eq!(values[0].as_bool(), None);

    assert_eq!(Value::from(1.25_f32).as_f64(), Some(1.25));
    assert_eq!(Value::from(&borrowed_string).as_str(), Some("borrowed"));
    assert_eq!(
        Value::from(&[0x10_u8, 0x20][..]).as_bytes(),
        Some(&[0x10, 0x20][..])
    );
    assert_eq!(
        Value::from([0xaa_u8, 0xbb]).as_bytes(),
        Some(&[0xaa, 0xbb][..])
    );
    assert_eq!(values[5].to_string(), "0xabcd");
    assert_eq!(values[6].to_string(), "[1, 2]");
    let summary_toml = toml::to_string(&values[6].summary()).unwrap();
    assert!(summary_toml.contains("kind = \"list\""));
    let reparsed_summary: ValueSummary = toml::from_str(&summary_toml).unwrap();
    assert_eq!(reparsed_summary, values[6].summary());
    assert!(Value::from(()).is_unit());
    assert_eq!(
        Value::from(borrowed_string.as_str()).into_string(),
        Some("borrowed".to_owned())
    );
    assert_eq!(Value::from([0x01, 0x02]).into_bytes(), Some(vec![1, 2]));
    assert_eq!(
        Value::from(vec![Value::I64(1)]).into_list(),
        Some(vec![Value::I64(1)])
    );
}

#[test]
fn sdk_values_support_fallible_typed_extraction() -> stoffel::Result<()> {
    let number = Value::I64(-7);
    let text = Value::String("done".to_owned());
    let bytes = Value::Bytes(vec![0xab, 0xcd]);
    let list = Value::List(vec![Value::Bool(true), Value::Unit]);

    assert_eq!(i64::try_from(&number)?, -7);
    assert_eq!(i64::try_from(number)?, -7);
    assert_eq!(<&str>::try_from(&text)?, "done");
    assert_eq!(String::try_from(text)?, "done".to_owned());
    assert_eq!(<&[u8]>::try_from(&bytes)?, &[0xab, 0xcd][..]);
    assert_eq!(Vec::<u8>::try_from(bytes)?, vec![0xab, 0xcd]);
    assert_eq!(<&[Value]>::try_from(&list)?.len(), 2);
    assert_eq!(Vec::<Value>::try_from(list)?.len(), 2);
    assert!(bool::try_from(&Value::Bool(true))?);
    assert_eq!(f64::try_from(&Value::Float(1.5))?, 1.5);
    assert_eq!(u64::try_from(&Value::U64(7))?, 7);
    assert_eq!(<()>::try_from(Value::Unit)?, ());
    assert_eq!(
        String::try_from(&Value::String("borrowed".to_owned()))?,
        "borrowed"
    );
    assert_eq!(Vec::<u8>::try_from(&Value::Bytes(vec![1, 2]))?, vec![1, 2]);
    assert_eq!(<()>::try_from(&Value::Unit)?, ());

    let err = i64::try_from(Value::Bool(false)).unwrap_err();
    assert!(matches!(
        err,
        stoffel::Error::InvalidInput(message)
            if message.contains("expected i64 SDK value, got bool")
    ));
    assert!(matches!(
        String::try_from(Value::Unit),
        Err(stoffel::Error::InvalidInput(_))
    ));
    assert!(matches!(
        Vec::<u8>::try_from(Value::String("nope".to_owned())),
        Err(stoffel::Error::InvalidInput(_))
    ));
    assert!(matches!(
        Vec::<Value>::try_from(Value::Bool(false)),
        Err(stoffel::Error::InvalidInput(_))
    ));
    assert!(matches!(
        <()>::try_from(Value::Bool(false)),
        Err(stoffel::Error::InvalidInput(_))
    ));
    Ok(())
}

#[test]
fn sdk_values_and_crypto_wrappers_are_serde_payloads() -> stoffel::Result<()> {
    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Payload {
        values: Vec<Value>,
        share: Share,
        public_key: PublicKey,
        field: FieldElement,
        group: GroupElement,
    }

    let payload = Payload {
        values: vec![
            Value::I64(-7),
            Value::Bool(true),
            Value::Bytes(vec![0xab, 0xcd]),
            Value::List(vec![Value::String("nested".to_owned()), Value::Unit]),
        ],
        share: Share::feldman("threshold-key", [0x01, 0x02], [[0x03], [0x04]]),
        public_key: PublicKey::new("threshold-key", [1, 2, 3]),
        field: FieldElement::from_bytes([4, 5, 6]),
        group: GroupElement::from_bytes([7, 8, 9]),
    };

    let serialized = toml::to_string(&payload)?;
    assert!(serialized.contains("key_name = \"threshold-key\""));
    assert!(serialized.contains("I64 = -7"));

    let reparsed: Payload = toml::from_str(&serialized)?;
    assert_eq!(reparsed, payload);
    assert_eq!(
        reparsed.share.public_key(),
        Some(PublicKey::new("threshold-key", [0x03]))
    );
    assert_eq!(reparsed.values[2].as_bytes(), Some(&[0xab, 0xcd][..]));
    assert_eq!(reparsed.field.as_bytes(), &[4, 5, 6]);
    Ok(())
}

#[tokio::test]
async fn avss_engine_surface_does_not_fake_protocol_operations() -> stoffel::Result<()> {
    let server = StoffelServer::builder(0)
        .bind("127.0.0.1:19400")
        .avss(Curve::Bls12_381)
        .build()?;

    let engine = server.create_avss_engine().await?;
    assert_eq!(engine.curve(), Curve::Bls12_381);
    assert!(!engine.is_live());

    let err = engine.generate_random_share("key").await.unwrap_err();
    assert!(matches!(err, stoffel::Error::Unsupported(_)));
    let err = engine
        .generate_random_share_with_session("key")
        .await
        .unwrap_err();
    assert!(matches!(err, stoffel::Error::Unsupported(_)));
    let err = engine
        .generate_share_with_secret("key", FieldElement::from_bytes([1, 2, 3]))
        .await
        .unwrap_err();
    assert!(matches!(err, stoffel::Error::Unsupported(_)));
    let err = engine
        .generate_share_with_secret_and_session("key", FieldElement::from_bytes([1, 2, 3]))
        .await
        .unwrap_err();
    assert!(matches!(err, stoffel::Error::Unsupported(_)));
    let err = engine.await_received_share("key", 0).await.unwrap_err();
    assert!(matches!(err, stoffel::Error::Unsupported(_)));
    let err = engine.get_share("key").await.unwrap_err();
    assert!(matches!(err, stoffel::Error::Unsupported(_)));
    let err = engine.get_public_key("key").await.unwrap_err();
    assert!(matches!(err, stoffel::Error::Unsupported(_)));
    let err = engine
        .open_share_in_exp(
            &Share::opaque("key", [1, 2, 3]),
            &GroupElement::from_bytes([4, 5, 6]),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, stoffel::Error::Unsupported(_)));

    let hb_server = StoffelServer::builder(0)
        .bind("127.0.0.1:19401")
        .honeybadger()
        .build()?;
    let err = hb_server.create_avss_engine().await.unwrap_err();
    assert!(matches!(err, stoffel::Error::Configuration(_)));
    Ok(())
}

#[tokio::test]
async fn client_and_server_lifecycle_validate_real_network_configuration() -> stoffel::Result<()> {
    assert_eq!("connected".parse::<ClientState>()?, ClientState::Connected);
    assert!(matches!(
        "unknown".parse::<ClientState>(),
        Err(stoffel::Error::Configuration(_))
    ));

    let empty_servers = StoffelClient::builder().build().unwrap_err();
    assert!(matches!(
        empty_servers,
        stoffel::Error::Configuration(message) if message.contains("at least one server")
    ));

    let builder_err = StoffelClient::builder().servers([" "]).build().unwrap_err();
    assert!(matches!(builder_err, stoffel::Error::Configuration(_)));

    let invalid_server_err = StoffelClient::builder()
        .servers(["not a socket address"])
        .build()
        .unwrap_err();
    assert!(matches!(
        invalid_server_err,
        stoffel::Error::Configuration(_)
    ));

    let duplicate_server_err = StoffelClient::builder()
        .server("127.0.0.1:19500")
        .server("127.0.0.1:19500")
        .build()
        .unwrap_err();
    assert!(matches!(
        duplicate_server_err,
        stoffel::Error::Configuration(_)
    ));

    let connect_err = StoffelClient::connect(&[" "]).await.unwrap_err();
    assert!(matches!(connect_err, stoffel::Error::Configuration(_)));

    let zero_timeout_err = StoffelClient::builder()
        .server("127.0.0.1:19500")
        .connection_timeout(Duration::ZERO)
        .connect()
        .await
        .unwrap_err();
    assert!(matches!(zero_timeout_err, stoffel::Error::Configuration(_)));

    let client_err = StoffelClient::builder()
        .server("127.0.0.1:19500")
        .connection_timeout(Duration::from_millis(50))
        .connect()
        .await
        .unwrap_err();
    assert!(matches!(client_err, stoffel::Error::NetworkConnection(_)));

    let runtime = Stoffel::compile(CLEAR_ADD_SOURCE)?.build()?;
    let client_builder = runtime
        .client()
        .servers(["127.0.0.1:19500"])
        .connection_timeout(Duration::from_secs(3));
    assert!(client_builder.configured_program().is_some());
    assert_eq!(
        client_builder.configured_connection_timeout(),
        Duration::from_secs(3)
    );
    assert!(client_builder.configured_offchain_io().is_none());
    assert!(!client_builder.has_configured_offchain_io());
    let client = client_builder.build()?;
    assert!(client.has_program());
    assert_eq!(client.program().unwrap().function_count(), 1);
    assert_eq!(client.state().to_string(), "disconnected");

    let plain_client = StoffelClient::builder()
        .servers(["127.0.0.1:19500"])
        .build()?;
    assert!(!plain_client.has_program());
    assert!(plain_client.program().is_none());
    assert_eq!(plain_client.offchain_io(), None);
    assert!(matches!(
        plain_client.run(&[1_i64]).await,
        Err(stoffel::Error::Configuration(message))
            if message.contains("off-chain client IO")
    ));

    let missing_function = client.run_function("missing", &[1_i64]).await.unwrap_err();
    assert!(matches!(
        missing_function,
        stoffel::Error::FunctionNotFound(_)
    ));
    let wrong_input_count = client.run_function("main", &[1_i64]).await.unwrap_err();
    assert!(matches!(wrong_input_count, stoffel::Error::InvalidInput(_)));
    let submit_wrong_input_count = client.submit(&[1_i64]).await.unwrap_err();
    assert!(matches!(
        submit_wrong_input_count,
        stoffel::Error::InvalidInput(_)
    ));
    let submit_missing_function = client
        .submit_function("missing", &[1_i64])
        .await
        .unwrap_err();
    assert!(matches!(
        submit_missing_function,
        stoffel::Error::FunctionNotFound(_)
    ));
    let submit_function_wrong_input_count =
        client.submit_function("main", &[1_i64]).await.unwrap_err();
    assert!(matches!(
        submit_function_wrong_input_count,
        stoffel::Error::InvalidInput(_)
    ));
    let submit_function_err = client
        .submit_function("main", &[1_i64, 2_i64])
        .await
        .unwrap_err();
    assert!(matches!(
        submit_function_err,
        stoffel::Error::Configuration(_)
    ));

    let unconfigured_server = StoffelServer::builder(0).bind("127.0.0.1:19500").build()?;
    assert_eq!(unconfigured_server.state(), ServerState::Created);
    assert_eq!(unconfigured_server.state().to_string(), "created");
    let start_err = unconfigured_server.start().await.unwrap_err();
    assert!(matches!(start_err, stoffel::Error::Configuration(_)));
    assert_eq!(unconfigured_server.state(), ServerState::Created);
    assert!(!unconfigured_server.ready());
    let health = unconfigured_server.health();
    assert!(health.is_degraded());
    assert!(!health.is_healthy());
    assert!(!health.is_unhealthy());
    assert!(health
        .reason()
        .unwrap()
        .contains("not started by a live networking backend"));

    let missing_runner = runtime
        .server(0)
        .bind("127.0.0.1:19500")
        .peer(1, "127.0.0.1:19501")
        .peer(2, "127.0.0.1:19502")
        .peer(3, "127.0.0.1:19503")
        .peer(4, "127.0.0.1:19504")
        .runner_path(tempdir()?.path().join("missing-stoffel-run"))
        .build()?;
    let start_err = missing_runner.start().await.unwrap_err();
    assert!(matches!(
        start_err,
        stoffel::Error::Unsupported(message) if message.contains("stoffel-run")
    ));

    let client_io_runtime = Stoffel::compile(
        r#"
def main() -> int64:
  var share = ClientStore.take_share(0, 0)
  return share.open()
"#,
    )?
    .parties(5)
    .threshold(1)
    .build()?;
    let client_io_without_coordinator = client_io_runtime
        .server(0)
        .bind("127.0.0.1:19600")
        .peer(1, "127.0.0.1:19601")
        .peer(2, "127.0.0.1:19602")
        .peer(3, "127.0.0.1:19603")
        .peer(4, "127.0.0.1:19604")
        .expected_clients(1)
        .build()?;
    let start_err = client_io_without_coordinator.start().await.unwrap_err();
    assert!(matches!(
        start_err,
        stoffel::Error::Configuration(message) if message.contains("off-chain coordinator")
    ));

    let identity_dir = tempdir()?;
    let party_cert = identity_dir.path().join("party.pem");
    let party_key = identity_dir.path().join("party.key");
    let client_cert = identity_dir.path().join("client.pem");
    std::fs::write(&party_cert, "party cert")?;
    std::fs::write(&party_key, "party key")?;
    std::fs::write(&client_cert, "client cert")?;
    let offchain_server = OffChainServerConfig::builder()
        .coordinator("127.0.0.1:19700")
        .rpc_bind("127.0.0.1:19710")
        .identity_files(&party_cert, &party_key)
        .timestamp(7)
        .expected_client_cert(&client_cert)
        .build()?;
    let client_io_with_coordinator = client_io_runtime
        .server(0)
        .bind("127.0.0.1:19610")
        .peer(1, "127.0.0.1:19611")
        .peer(2, "127.0.0.1:19612")
        .peer(3, "127.0.0.1:19613")
        .peer(4, "127.0.0.1:19614")
        .expected_clients(1)
        .runner_path(identity_dir.path().join("missing-stoffel-run"))
        .offchain_coordinator(offchain_server)
        .build()?;
    let start_err = client_io_with_coordinator.start().await.unwrap_err();
    assert!(matches!(
        start_err,
        stoffel::Error::Unsupported(message) if message.contains("stoffel-run")
    ));

    let mismatch = client_io_runtime
        .server(0)
        .bind("127.0.0.1:19620")
        .peer(1, "127.0.0.1:19621")
        .peer(2, "127.0.0.1:19622")
        .peer(3, "127.0.0.1:19623")
        .peer(4, "127.0.0.1:19624")
        .expected_clients(2)
        .offchain_coordinator(
            OffChainServerConfig::builder()
                .coordinator("127.0.0.1:19720")
                .rpc_bind("127.0.0.1:19721")
                .identity_files(&party_cert, &party_key)
                .timestamp(8)
                .expected_client_cert(&client_cert)
                .build()?,
        )
        .build()
        .unwrap_err();
    assert!(matches!(
        mismatch,
        stoffel::Error::Configuration(message) if message.contains("expected_clients")
    ));

    let follower_without_bootstrap = runtime
        .server(1)
        .bind("127.0.0.1:19501")
        .peer(0, "127.0.0.1:19500")
        .peer(2, "127.0.0.1:19502")
        .peer(3, "127.0.0.1:19503")
        .peer(4, "127.0.0.1:19504")
        .build()?;
    let start_err = follower_without_bootstrap.start().await.unwrap_err();
    assert!(matches!(
        start_err,
        stoffel::Error::Configuration(message) if message.contains("bootstrap")
    ));

    let health = HealthStatus::Unhealthy {
        reason: "server has been shut down".to_owned(),
    };
    assert!(health.is_unhealthy());
    assert_eq!(health.reason(), Some("server has been shut down"));
    assert_eq!(health.to_string(), "unhealthy: server has been shut down");

    let health_toml = toml::to_string(&health)?;
    assert!(health_toml.contains("Unhealthy"));
    let reparsed_health: HealthStatus = toml::from_str(&health_toml)?;
    assert_eq!(reparsed_health, health);

    let duplicate_peer = StoffelServer::builder(0)
        .bind("127.0.0.1:19500")
        .peer(1, "127.0.0.1:19501")
        .peer(1, "127.0.0.1:19511")
        .build()
        .unwrap_err();
    assert!(matches!(duplicate_peer, stoffel::Error::Configuration(_)));
    Ok(())
}

#[tokio::test]
async fn client_connect_uses_real_quic_transport() -> stoffel::Result<()> {
    // The server-side QUIC listener runs before StoffelClient::connect (which
    // installs the ring provider); under --all-features both rustls providers
    // are compiled in, so rustls cannot auto-select one and panics without an
    // explicit install.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address: SocketAddr = listener.local_addr()?;
    drop(listener);

    let mut server_network = QuicNetworkManager::new();
    server_network
        .listen(address)
        .await
        .map_err(stoffel::Error::NetworkConnection)?;
    let accept_task = tokio::spawn(async move {
        server_network
            .accept()
            .await
            .map(|_| ())
            .map_err(stoffel::Error::NetworkConnection)
    });

    let address = address.to_string();
    let client = StoffelClient::connect(&[address.as_str()]).await?;
    assert_eq!(client.state(), ClientState::Connected);
    assert!(client.is_connected());
    assert!(client.network_manager().is_some());
    assert!(client.transport_client_id().is_some());
    assert_eq!(client.summary().server_count, 1);
    assert!(client.summary().connected);

    accept_task
        .await
        .map_err(|error| stoffel::Error::NetworkConnection(error.to_string()))??;
    Ok(())
}

#[test]
fn server_metrics_can_be_snapshotted_without_exporter_setup() -> stoffel::Result<()> {
    let server = StoffelServer::builder(0)
        .bind("127.0.0.1:19700")
        .with_preprocessing(20, 10)
        .build()?;

    assert_eq!(server.metrics().preprocessing_triples_remaining(), 20);
    assert_eq!(server.metrics().preprocessing_random_shares_remaining(), 10);

    server.metrics().record_connected_peers(4);
    server.metrics().record_connected_clients(2);
    server.metrics().record_preprocessing_remaining(12, 6);
    server.metrics().record_computation_latency_ms(25);
    server
        .metrics()
        .record_computation_latency(Duration::from_millis(35));
    server.metrics().record_consensus_latency_ms(7);
    server
        .metrics()
        .record_consensus_latency(Duration::from_millis(11));
    assert_eq!(server.metrics().increment_computations_completed(), 1);
    assert_eq!(server.metrics().increment_computations_failed(), 1);
    assert_eq!(server.metrics().computation_latency_average_ms(), Some(30));
    assert_eq!(server.metrics().consensus_latency_average_ms(), Some(9));

    let snapshot = server.metrics().snapshot();
    assert_eq!(
        snapshot,
        ServerMetricsSnapshot {
            connected_peers: 4,
            connected_clients: 2,
            computations_completed: 1,
            computations_failed: 1,
            preprocessing_triples_remaining: 12,
            preprocessing_random_shares_remaining: 6,
            computation_latency_ms: 35,
            computation_latency_count: 2,
            computation_latency_total_ms: 60,
            computation_latency_max_ms: 35,
            consensus_latency_ms: 11,
            consensus_latency_count: 2,
            consensus_latency_total_ms: 18,
            consensus_latency_max_ms: 11,
        }
    );

    let snapshot_toml = toml::to_string(&snapshot)?;
    assert!(snapshot_toml.contains("connected_peers = 4"));
    let reparsed_snapshot: ServerMetricsSnapshot = toml::from_str(&snapshot_toml)?;
    assert_eq!(reparsed_snapshot, snapshot);
    assert_eq!(snapshot.computation_latency_average_ms(), Some(30));
    assert_eq!(snapshot.consensus_latency_average_ms(), Some(9));
    assert_eq!(snapshot.computation_count(), 2);
    Ok(())
}

#[test]
fn tracing_can_be_initialized_from_sdk_config() -> stoffel::Result<()> {
    let config = TracingConfig::builder()
        .max_level(Level::DEBUG)
        .ansi(false)
        .compact(false)
        .build();

    assert_eq!(config.max_level(), Level::DEBUG);
    assert!(!config.ansi());
    assert!(!config.compact());
    assert_eq!(config.service_name(), "stoffel-rust-sdk");
    config.validate()?;
    let summary = config.summary();
    assert_eq!(summary.max_level, "DEBUG");
    assert!(!summary.ansi);
    assert!(!summary.compact);
    assert_eq!(summary.service_name, "stoffel-rust-sdk");
    let summary_toml = toml::to_string(&summary)?;
    assert!(summary_toml.contains("service_name = \"stoffel-rust-sdk\""));
    let reparsed_summary: TracingConfigSummary = toml::from_str(&summary_toml)?;
    assert_eq!(reparsed_summary, summary);

    let otel_config = TracingConfig::builder()
        .service_name("stoffel-test-app")
        .max_level(Level::TRACE)
        .build();
    assert_eq!(otel_config.service_name(), "stoffel-test-app");
    assert_eq!(otel_config.max_level(), Level::TRACE);
    assert_eq!(otel_config.summary().service_name, "stoffel-test-app");

    let invalid = TracingConfig::builder().service_name(" ").build();
    let err = invalid.validate().unwrap_err();
    assert!(matches!(
        err,
        stoffel::Error::Configuration(message) if message.contains("service_name")
    ));

    static TRACING_INIT: OnceLock<stoffel::Result<()>> = OnceLock::new();
    let result = TRACING_INIT.get_or_init(|| {
        TracingConfig::builder()
            .max_level(Level::INFO)
            .ansi(false)
            .install()
    });

    match result {
        Ok(()) => Ok(()),
        Err(stoffel::Error::Configuration(message))
            if message.contains("global default subscriber") =>
        {
            Ok(())
        }
        Err(error) => Err(stoffel::Error::Configuration(error.to_string())),
    }
}
