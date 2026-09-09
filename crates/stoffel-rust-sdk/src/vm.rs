//! StoffelVM execution integration.
//!
//! Clear execution embeds the VM directly. Local MPC execution delegates to the
//! real localhost coordinator/party runner in `stoffel-vm`, preserving the
//! PRD's non-simulated local network behavior.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::client_value_codec::{decode_fixed_point_value, encode_fixed_point_value};
use crate::config::MpcBackend;
use crate::error::{Error, Result};
use crate::program::Program;
use crate::runtime::StoffelRuntime;
use crate::types::Value;
use stoffel_vm_types::core_types::{ShareDataFormat, ShareType, TableRef, Value as VmValue};

pub fn execute_clear(runtime: &StoffelRuntime, function_name: &str) -> Result<Vec<Value>> {
    let args = runtime.input_values_for_function(function_name)?;
    execute_clear_with_sdk_args(runtime, function_name, &args)
}

pub(crate) fn execute_clear_with_sdk_args(
    runtime: &StoffelRuntime,
    function_name: &str,
    args: &[Value],
) -> Result<Vec<Value>> {
    runtime
        .program()
        .validate_function_args(function_name, args)?;

    let mut vm = stoffel_vm::core_vm::VirtualMachine::try_new()
        .map_err(|error| Error::Computation(error.to_string()))?;
    for function in runtime
        .program()
        .binary()
        .try_to_vm_functions()
        .map_err(|error| Error::Bytecode(format!("{error:?}")))?
    {
        vm.try_register_function(function)
            .map_err(|error| Error::Computation(error.to_string()))?;
    }

    let vm_args = args
        .iter()
        .map(|value| sdk_value_to_vm_value(&mut vm, value))
        .collect::<Result<Vec<_>>>()?;
    let value = vm
        .execute_with_args(function_name, &vm_args)
        .map_err(|error| Error::Computation(error.to_string()))?;
    let value = sdk_value_from_vm_value(&mut vm, value, &mut HashSet::new(), 0)?;
    match value {
        Value::List(values) => Ok(values),
        value => Ok(vec![value]),
    }
}

pub fn execute_clear_with_args(
    runtime: &StoffelRuntime,
    function_name: &str,
    args: &[stoffel_vm_types::core_types::Value],
) -> Result<Vec<Value>> {
    let sdk_args = args
        .iter()
        .filter_map(|value| Value::from_vm_value(value.clone()))
        .collect::<Vec<_>>();
    if sdk_args.len() == args.len() {
        runtime
            .program()
            .validate_function_args(function_name, &sdk_args)?;
    } else if runtime.program().function(function_name).is_none() {
        return Err(Error::FunctionNotFound(function_name.to_owned()));
    }

    let mut vm = stoffel_vm::core_vm::VirtualMachine::try_new()
        .map_err(|error| Error::Computation(error.to_string()))?;
    for function in runtime
        .program()
        .binary()
        .try_to_vm_functions()
        .map_err(|error| Error::Bytecode(format!("{error:?}")))?
    {
        vm.try_register_function(function)
            .map_err(|error| Error::Computation(error.to_string()))?;
    }

    let value = vm
        .execute_with_args(function_name, args)
        .map_err(|error| Error::Computation(error.to_string()))?;
    let value = sdk_value_from_vm_value(&mut vm, value, &mut HashSet::new(), 0)?;
    match value {
        Value::List(values) => Ok(values),
        value => Ok(vec![value]),
    }
}

pub async fn execute_local(runtime: &StoffelRuntime, function_name: &str) -> Result<Vec<Value>> {
    execute_local_with_options(runtime, function_name, LocalExecutionOptions::default()).await
}

/// Execute a local MPC entrypoint whose VM return is secret-shared.
///
/// Use [`execute_local`] for public VM returns. This method requires exactly
/// one unrevealed return share from every compute party and preserves each
/// party's backend bytes without reconstruction.
pub async fn execute_local_returning_party_shares(
    runtime: &StoffelRuntime,
    function_name: &str,
) -> Result<LocalShareExecutionOutput> {
    execute_local_returning_party_shares_options(
        runtime,
        function_name,
        LocalExecutionOptions::default(),
    )
    .await
}

#[derive(Debug, Clone, Default)]
pub(crate) struct LocalExecutionOptions {
    pub(crate) runner_path: Option<PathBuf>,
    pub(crate) timeout: Option<Duration>,
}

/// A client's reconstructed output values, received via `send_to_client` and
/// reconstructed by the off-chain client — the actual client-side result, not
/// a public reveal to the compute nodes.
///
/// `values` are decoded through the loaded program's client-IO manifest, so a
/// 1-bit secret int comes back as [`Value::Bool`], a wider secret int as
/// [`Value::I64`], an unsigned secret int as [`Value::U64`], and a fixed-point
/// share as [`Value::Float`]. Output positions the manifest does not describe
/// (e.g. a developer-specified count with no static schema) fall back to
/// [`Value::U64`]. The untyped reconstructed field values remain available via
/// `raw` for callers that need them.
#[derive(Debug, Clone, PartialEq)]
pub struct LocalClientOutput {
    pub client_slot: u64,
    pub values: Vec<Value>,
    pub raw: Vec<u64>,
}

/// One party's uninterpreted secret-share payload returned by the VM.
///
/// The SDK exposes the share metadata so callers can validate compatibility,
/// but deliberately provides no reconstruction or decoding operation. The
/// backend bytes can be borrowed for hashing or sealing, or consumed for
/// durable storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpaqueShare {
    /// The Stoffel secret type carried by this share.
    pub share_type: ShareType,
    /// The MPC backend's serialization format. The SDK treats the serialized
    /// bytes as opaque regardless of this tag.
    pub backend_format: ShareDataFormat,
    bytes: Vec<u8>,
}

impl OpaqueShare {
    fn from_runner(share: stoffel_vm_runner::ReturnedShare) -> Self {
        Self {
            share_type: share.share_type,
            backend_format: share.format,
            bytes: share.data,
        }
    }

    /// Borrow the exact party-local backend serialization.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume this value and return the exact party-local backend
    /// serialization.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// One compute party's secret VM return and printed public output.
///
/// `returned_share` contains the exact party-local backend serialization held
/// by this party. The SDK validates only its type/format metadata; it never
/// compares or reconstructs the secret payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalPartyShareOutput {
    /// Runner-assigned compute-party name.
    pub party: String,
    /// This party's public program output, excluding VM return markers.
    pub program_output: String,
    /// This party's unrevealed VM return value.
    pub returned_share: OpaqueShare,
}

/// Result of a local MPC execution whose VM return remains secret-shared.
///
/// There is deliberately no public `values` field: public VM returns use
/// [`execute_local`], while this type guarantees exactly one
/// [`LocalPartyShareOutput::returned_share`] per party. Printed output remains
/// party-scoped so callers must choose whether and how to establish agreement.
#[derive(Debug, Clone, PartialEq)]
pub struct LocalShareExecutionOutput {
    /// Party-local outputs, each paired with exactly one opaque return share.
    pub party_outputs: Vec<LocalPartyShareOutput>,
    /// Values explicitly reconstructed for clients via `send_to_client`.
    /// These are separate from the unreconstructed VM return shares.
    pub client_outputs: Vec<LocalClientOutput>,
}

impl LocalShareExecutionOutput {
    /// Iterate over the returned party-local shares in party-output order.
    pub fn shares(&self) -> impl ExactSizeIterator<Item = &OpaqueShare> {
        self.party_outputs.iter().map(|party| &party.returned_share)
    }
}

#[derive(Debug)]
struct LocalPartyExecutionDetails {
    party: String,
    program_output: String,
    returned_shares: Vec<OpaqueShare>,
}

#[derive(Debug)]
struct LocalExecutionDetails {
    values: Vec<Value>,
    program_output: String,
    party_outputs: Vec<LocalPartyExecutionDetails>,
    client_outputs: Vec<LocalClientOutput>,
}

impl LocalExecutionDetails {
    fn has_party_shares(&self) -> bool {
        self.party_outputs
            .iter()
            .any(|party| !party.returned_shares.is_empty())
    }
}

impl LocalClientOutput {
    /// Pack boolean outputs into bytes, LSB-first within each byte (output bit
    /// `i` becomes bit `i % 8` of byte `i / 8`). This is the inverse of the
    /// LSB-first bit layout AES and other bit-decomposed circuits use, so a
    /// 128-bit ciphertext block round-trips straight back to its 16 bytes.
    ///
    /// Non-boolean outputs are treated as set when non-zero; the trailing
    /// partial byte (when the output count is not a multiple of 8) is
    /// zero-padded in its high bits.
    pub fn bytes(&self) -> Vec<u8> {
        let mut out = vec![0u8; self.values.len().div_ceil(8)];
        for (index, value) in self.values.iter().enumerate() {
            if value_is_set(value) {
                out[index / 8] |= 1 << (index % 8);
            }
        }
        out
    }

    /// The outputs as booleans (non-zero ⇒ `true`), in order.
    pub fn bools(&self) -> Vec<bool> {
        self.values.iter().map(value_is_set).collect()
    }
}

fn value_is_set(value: &Value) -> bool {
    match value {
        Value::Bool(bit) => *bit,
        Value::I64(value) => *value != 0,
        Value::U64(value) => *value != 0,
        _ => false,
    }
}

/// Decode one reconstructed field value into a typed SDK [`Value`] using the
/// share type the manifest declared for that output position.
fn decode_client_output_value(raw: u64, share_type: ShareType) -> Result<Value> {
    Ok(match share_type {
        ShareType::SecretInt { bit_length: 1 } => Value::Bool(raw != 0),
        ShareType::SecretInt { .. } => Value::I64(raw as i64),
        ShareType::SecretUInt { .. } => Value::U64(raw),
        ShareType::SecretFixedPoint { precision } => {
            Value::Float(decode_fixed_point_value(raw as i64, precision)?)
        }
    })
}

pub(crate) async fn execute_local_with_options(
    runtime: &StoffelRuntime,
    function_name: &str,
    options: LocalExecutionOptions,
) -> Result<Vec<Value>> {
    let (returned, _program_output, _client_outputs) =
        execute_local_capturing_with_options(runtime, function_name, options).await?;
    Ok(returned)
}

/// Like [`execute_local_with_options`] but also returns the program's printed
/// output (everything the program emitted via `print`, with the VM's internal
/// `Program returned:` markers stripped). Used to surface client-facing results
/// that a returned aggregate (e.g. a `list`) only exposes as an opaque handle.
pub(crate) async fn execute_local_capturing_with_options(
    runtime: &StoffelRuntime,
    function_name: &str,
    options: LocalExecutionOptions,
) -> Result<(Vec<Value>, String, Vec<LocalClientOutput>)> {
    let output = execute_local_details_with_options(runtime, function_name, options).await?;
    if output.has_party_shares() {
        return Err(Error::Computation(
            "secret VM returns are party-local; use execute_local_returning_party_shares() to preserve them"
                .to_owned(),
        ));
    }
    Ok((output.values, output.program_output, output.client_outputs))
}

pub(crate) async fn execute_local_returning_party_shares_options(
    runtime: &StoffelRuntime,
    function_name: &str,
    options: LocalExecutionOptions,
) -> Result<LocalShareExecutionOutput> {
    let output = execute_local_details_with_options(runtime, function_name, options).await?;
    if !output.has_party_shares() {
        return Err(Error::Computation(
            "the VM returned public values; use execute_local() for public returns".to_owned(),
        ));
    }

    let party_outputs = output
        .party_outputs
        .into_iter()
        .map(|mut party| {
            if party.returned_shares.len() != 1 {
                return Err(Error::Computation(format!(
                    "local party {} returned {} secret shares, expected exactly one VM return share",
                    party.party,
                    party.returned_shares.len()
                )));
            }
            Ok(LocalPartyShareOutput {
                party: party.party,
                program_output: party.program_output,
                returned_share: party
                    .returned_shares
                    .pop()
                    .expect("share count was checked above"),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(LocalShareExecutionOutput {
        party_outputs,
        client_outputs: output.client_outputs,
    })
}

/// Run a real local MPC network and retain enough internal detail to support
/// both the public-return and party-share SDK surfaces.
async fn execute_local_details_with_options(
    runtime: &StoffelRuntime,
    function_name: &str,
    options: LocalExecutionOptions,
) -> Result<LocalExecutionDetails> {
    if runtime.program().function(function_name).is_none() {
        return Err(Error::FunctionNotFound(function_name.to_owned()));
    }
    let vm_inputs = runtime.input_values_for_function(function_name)?;
    if !vm_inputs.is_empty() {
        return Err(Error::Unsupported(
            "SDK local coordinator execution does not support direct function parameters; use a no-argument entrypoint and `with_client_input` for ClientStore values"
                .to_owned(),
        ));
    }

    let mpc_config = runtime
        .mpc_config()
        .ok_or_else(|| Error::Configuration("MPC configuration is required".to_owned()))?;
    let flattened_client_inputs = flatten_local_client_inputs(runtime.client_inputs())?;
    validate_flattened_local_client_inputs(runtime, &flattened_client_inputs)?;
    let local_client_inputs =
        local_client_inputs_for_runner(runtime.program(), &flattened_client_inputs)?;
    let runner_path = resolve_stoffel_run_binary(
        options
            .runner_path
            .as_deref()
            .or_else(|| runtime.local_runner_binary_path()),
    )?;
    eprintln!(
        "[stoffel] using stoffel-run binary: {}",
        runner_path.display()
    );

    let mut runner = stoffel_vm_runner::LocalCoordinatorRunner::builder(
        runner_path,
        runtime.program().binary().clone(),
    )
    .entry(function_name)
    .backend(local_runner_backend(mpc_config.backend))
    .curve(local_runner_curve(mpc_config.backend))
    .parties(mpc_config.parties)
    .threshold(mpc_config.threshold);
    if let Some(timeout) = options.timeout {
        runner = runner.timeout(timeout);
    }
    if let Some(expected_clients) = runtime.configured_expected_clients() {
        runner = runner.expected_output_clients(expected_clients);
    }
    for (client_slot, count) in runtime.client_output_counts() {
        runner = runner.client_output_count(*client_slot, *count);
    }
    runner = runner.client_inputs(local_client_inputs);

    let output = runner
        .build()
        .map_err(|error| Error::Configuration(error.to_string()))?
        .run()
        .await
        .map_err(|error| Error::Computation(error.to_string()))?;

    let party_outputs = output
        .party_outputs
        .iter()
        .map(|party| {
            let returned_shares = party
                .returned_shares()
                .map_err(|error| {
                    Error::Computation(format!(
                        "could not decode secret VM return from party {}: {error}",
                        party.name
                    ))
                })?
                .into_iter()
                .map(OpaqueShare::from_runner)
                .collect();
            Ok(LocalPartyExecutionDetails {
                party: party.name.clone(),
                program_output: local_program_output_without_return_markers(&party.stdout),
                returned_shares,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let has_party_shares = party_outputs
        .iter()
        .any(|party| !party.returned_shares.is_empty());
    let program_output = party_outputs
        .first()
        .map(|party| party.program_output.clone())
        .unwrap_or_default();
    print!("{program_output}");

    let values = if has_party_shares {
        validate_party_share_returns(&output, &party_outputs)?;
        Vec::new()
    } else {
        let returned = output.consistent_returned_values().map_err(|error| {
            Error::Computation(format!(
                "local coordinator run did not produce consistent VM return values: {error}\noutput:\n{}",
                output.combined_output
            ))
        })?;
        returned
            .iter()
            .map(|value| parse_runner_return_value(value))
            .collect::<Result<Vec<_>>>()?
    };
    let manifest = runtime.program().client_io_manifest();
    let client_outputs = output
        .client_outputs
        .iter()
        .map(|record| {
            let output_types = manifest
                .clients
                .iter()
                .find(|client| client.client_slot == record.client_slot)
                .map(|client| client.outputs.as_slice())
                .unwrap_or(&[]);
            let typed = record
                .values
                .iter()
                .enumerate()
                .map(|(index, &raw)| match output_types.get(index) {
                    Some(share_type) => decode_client_output_value(raw, *share_type),
                    None => Ok(Value::U64(raw)),
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(LocalClientOutput {
                client_slot: record.client_slot,
                values: typed,
                raw: record.values.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(LocalExecutionDetails {
        values,
        program_output,
        party_outputs,
        client_outputs,
    })
}

fn validate_party_share_returns(
    output: &stoffel_vm_runner::LocalCoordinatorRunOutput,
    party_outputs: &[LocalPartyExecutionDetails],
) -> Result<()> {
    let Some(first_party) = party_outputs.first() else {
        return Err(Error::Computation(
            "local coordinator run did not produce any party output".to_owned(),
        ));
    };
    let expected_metadata = first_party
        .returned_shares
        .iter()
        .map(|share| (share.share_type, share.backend_format))
        .collect::<Vec<_>>();

    for (raw_party, party) in output.party_outputs.iter().zip(party_outputs) {
        if raw_party.returned_values().len() != party.returned_shares.len() {
            return Err(Error::Computation(format!(
                "local party {} mixed secret and public VM return values",
                party.party
            )));
        }
        let metadata = party
            .returned_shares
            .iter()
            .map(|share| (share.share_type, share.backend_format))
            .collect::<Vec<_>>();
        if metadata != expected_metadata {
            return Err(Error::Computation(format!(
                "local party {} returned opaque share metadata {:?}, expected {:?} from party {}",
                party.party, metadata, expected_metadata, first_party.party
            )));
        }
    }
    Ok(())
}

fn local_program_output_without_return_markers(stdout: &str) -> String {
    let mut output = String::new();
    for line in stdout.lines() {
        if line.trim().starts_with("Program returned: ") {
            continue;
        }
        output.push_str(line);
        output.push('\n');
    }
    output
}

fn local_runner_backend(backend: MpcBackend) -> stoffel_vm::net::MpcBackendKind {
    match backend {
        MpcBackend::HoneyBadger => stoffel_vm::net::MpcBackendKind::HoneyBadger,
        MpcBackend::Avss { .. } => stoffel_vm::net::MpcBackendKind::Avss,
    }
}

fn local_runner_curve(backend: MpcBackend) -> stoffel_vm::net::MpcCurveConfig {
    match backend.curve() {
        None | Some(crate::config::Curve::Bls12_381) => stoffel_vm::net::MpcCurveConfig::Bls12_381,
        Some(crate::config::Curve::Bn254) => stoffel_vm::net::MpcCurveConfig::Bn254,
        Some(crate::config::Curve::Curve25519) => stoffel_vm::net::MpcCurveConfig::Curve25519,
        Some(crate::config::Curve::Ed25519) => stoffel_vm::net::MpcCurveConfig::Ed25519,
        Some(crate::config::Curve::Secp256k1) => stoffel_vm::net::MpcCurveConfig::Secp256k1,
        Some(crate::config::Curve::Secp256r1) => stoffel_vm::net::MpcCurveConfig::Secp256r1,
    }
}

fn validate_flattened_local_client_inputs(
    runtime: &StoffelRuntime,
    flattened_client_inputs: &[(u64, Vec<Value>)],
) -> Result<()> {
    runtime
        .program()
        .validate_owned_client_inputs(flattened_client_inputs)
}

fn flatten_local_client_inputs(inputs: &[(u64, Vec<Value>)]) -> Result<Vec<(u64, Vec<Value>)>> {
    inputs
        .iter()
        .map(|(client_slot, values)| {
            let mut flattened = Vec::new();
            for value in values {
                flatten_local_client_input_value(value, &mut flattened)?;
            }
            Ok((*client_slot, flattened))
        })
        .collect()
}

fn flatten_local_client_input_value(value: &Value, out: &mut Vec<Value>) -> Result<()> {
    match value {
        Value::List(values) => {
            for value in values {
                flatten_local_client_input_value(value, out)?;
            }
            Ok(())
        }
        Value::Object(_) => Err(Error::InvalidInput(
            "local coordinator client inputs cannot directly encode objects; pass their scalar secret fields or use typed lowering"
                .to_owned(),
        )),
        Value::I64(_)
        | Value::U64(_)
        | Value::Bool(_)
        | Value::Bytes(_)
        | Value::Float(_)
        | Value::String(_)
        | Value::Unit => {
            out.push(value.clone());
            Ok(())
        }
    }
}

fn local_client_inputs_for_runner(
    program: &Program,
    inputs: &[(u64, Vec<Value>)],
) -> Result<Vec<stoffel_vm_runner::LocalClientInput>> {
    inputs
        .iter()
        .map(|(client_slot, values)| {
            let input_types = program
                .client(*client_slot)
                .map(|client| client.inputs())
                .unwrap_or(&[]);
            let encoded = values
                .iter()
                .enumerate()
                .map(|(index, value)| {
                    local_client_input_value(value, input_types.get(index).copied())
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(stoffel_vm_runner::LocalClientInput::raw(
                *client_slot,
                encoded,
            ))
        })
        .collect()
}

fn local_client_input_value(value: &Value, share_type: Option<ShareType>) -> Result<String> {
    match (share_type, value) {
        (Some(ShareType::SecretFixedPoint { precision }), value) => {
            Ok(encode_fixed_point_value(value, precision)?.to_string())
        }
        (_, Value::I64(value)) => Ok(value.to_string()),
        (_, Value::U64(value)) if i64::try_from(*value).is_ok() => Ok(value.to_string()),
        (_, Value::U64(value)) => Ok(format!("0x{value:x}")),
        (_, Value::Bool(value)) => Ok(if *value { "1" } else { "0" }.to_owned()),
        (_, Value::Bytes(value)) => Ok(format!("0x{}", hex_encode(value))),
        (Some(share_type), value) => Err(Error::InvalidInput(format!(
            "local client input kind '{}' is not compatible with manifest share type {share_type:?}",
            value.kind()
        ))),
        (None, Value::Float(_))
        | (None, Value::String(_))
        | (None, Value::List(_))
        | (None, Value::Object(_))
        | (None, Value::Unit) => Err(Error::InvalidInput(
            "local coordinator client inputs without manifest types support integers, booleans, 0x-prefixed hex bytes, and lists of those values"
                .to_owned(),
        )),
    }
}

fn resolve_stoffel_run_binary(explicit_path: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit_path {
        return resolve_existing_runner_path(path).ok_or_else(|| {
            Error::Unsupported(format!(
                "SDK local coordinator execution requires an existing stoffel-run binary; configured path does not exist: {}",
                path.display()
            ))
        });
    }

    if let Some(path) = std::env::var_os("STOFFEL_RUN_BIN").map(PathBuf::from) {
        return resolve_existing_runner_path(&path).ok_or_else(|| {
            Error::Unsupported(format!(
                "SDK local coordinator execution requires an existing stoffel-run binary; STOFFEL_RUN_BIN points to a missing path: {}",
                path.display()
            ))
        });
    }

    if let Some(path) = built_workspace_runner() {
        return Ok(path);
    }

    if let Some(path) = sibling_runner() {
        return Ok(path);
    }

    if !running_from_workspace_target() {
        if let Some(path) = path_runner() {
            return Ok(path);
        }
    }

    if let Some(workspace_root) = workspace_root() {
        return Err(Error::Unsupported(format!(
            "SDK local coordinator execution requires a built workspace stoffel-run binary at {}; build it with `cargo build -p stoffel-vm-runner --bin stoffel-run`, set STOFFEL_RUN_BIN, or call `local_runner_path`",
            workspace_root
                .join("target")
                .join(if cfg!(debug_assertions) { "debug" } else { "release" })
                .join(format!("stoffel-run{}", std::env::consts::EXE_SUFFIX))
                .display()
        )));
    }

    if let Some(path) = path_runner() {
        return Ok(path);
    }

    Err(Error::Unsupported(
        "SDK local coordinator execution requires a stoffel-run binary; install it with `cargo install --path crates/stoffel-vm-runner` (or `cargo install stoffel-vm-runner`) so it lands on your PATH, set STOFFEL_RUN_BIN, call `local_runner_path`, or build `cargo build -p stoffel-vm-runner --bin stoffel-run`"
            .to_owned(),
    ))
}

/// Look for a `stoffel-run` binary sitting next to the current executable.
/// This is the case after the `stoffel` CLI installer, which drops both
/// `stoffel` and `stoffel-run` into the same directory (e.g. `~/.local/bin`).
fn sibling_runner() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let candidate = exe.with_file_name("stoffel-run");
    candidate.exists().then_some(candidate)
}

/// Look for a `stoffel-run` binary anywhere on the user's PATH.
fn path_runner() -> Option<PathBuf> {
    find_binary_on_path("stoffel-run")
}

fn built_workspace_runner() -> Option<PathBuf> {
    let workspace_root = workspace_root()?;
    let mut candidates = Vec::new();

    if let Some(profile_dir) = current_target_profile_dir() {
        candidates.push(profile_dir.join(format!("stoffel-run{}", std::env::consts::EXE_SUFFIX)));
    }

    candidates.push(
        workspace_root
            .join("target")
            .join(if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            })
            .join(format!("stoffel-run{}", std::env::consts::EXE_SUFFIX)),
    );

    candidates.push(
        workspace_root
            .join("target")
            .join("debug")
            .join(format!("stoffel-run{}", std::env::consts::EXE_SUFFIX)),
    );

    candidates
        .into_iter()
        .find(|candidate| is_executable_file(candidate))
}

fn current_target_profile_dir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    target_profile_dir_from_exe(&exe)
}

fn running_from_workspace_target() -> bool {
    let (Some(workspace_root), Ok(exe)) = (workspace_root(), std::env::current_exe()) else {
        return false;
    };
    path_is_under(&exe, &workspace_root.join("target"))
}

fn path_is_under(path: &Path, ancestor: &Path) -> bool {
    path.ancestors().any(|candidate| candidate == ancestor)
}

fn target_profile_dir_from_exe(exe: &Path) -> Option<PathBuf> {
    let parent = exe.parent()?;
    let profile_dir = if parent.file_name().is_some_and(|name| name == "deps") {
        parent.parent()?
    } else {
        parent
    };
    profile_dir
        .parent()
        .and_then(Path::file_name)
        .is_some_and(|name| name == "target")
        .then(|| profile_dir.to_path_buf())
}

fn find_binary_on_path(binary_name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;

    find_binary_in_path(binary_name, &path)
}

fn find_binary_in_path(binary_name: &str, path: &std::ffi::OsStr) -> Option<PathBuf> {
    let binary_name = format!("{binary_name}{}", std::env::consts::EXE_SUFFIX);

    std::env::split_paths(&path)
        .map(|dir| dir.join(&binary_name))
        .find(|candidate| is_executable_file(candidate))
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    path.is_file()
        && path
            .metadata()
            .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

fn resolve_existing_runner_path(path: &Path) -> Option<PathBuf> {
    if path.exists() {
        return Some(path.to_path_buf());
    }
    if path.is_absolute() {
        return None;
    }
    workspace_root()
        .map(|root| root.join(path))
        .filter(|candidate| candidate.exists())
}

fn workspace_root() -> Option<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .map(Path::to_path_buf)
}

fn parse_runner_return_value(value: &str) -> Result<Value> {
    let value = value.trim();
    if let Some(rest) = value.strip_prefix("byte[") {
        let (declared_len, encoded) = rest.split_once("] 0x").ok_or_else(|| {
            Error::Computation(format!("invalid byte-array runner result '{value}'"))
        })?;
        let declared_len = declared_len.parse::<usize>().map_err(|error| {
            Error::Computation(format!(
                "invalid byte-array length in runner result '{value}': {error}"
            ))
        })?;
        let bytes = hex_decode(encoded)?;
        if bytes.len() != declared_len {
            return Err(Error::Computation(format!(
                "runner result declared {declared_len} byte(s), encoded {}",
                bytes.len()
            )));
        }
        return Ok(Value::Bytes(bytes));
    }
    if value == "true" {
        return Ok(Value::Bool(true));
    }
    if value == "false" {
        return Ok(Value::Bool(false));
    }
    if value == "()" || value == "Unit" {
        return Ok(Value::Unit);
    }
    if let Ok(value) = value.parse::<i64>() {
        return Ok(Value::I64(value));
    }
    if let Ok(value) = value.parse::<u64>() {
        return Ok(Value::U64(value));
    }
    if let Ok(value) = value.parse::<f64>() {
        return Ok(Value::Float(value));
    }
    Ok(Value::String(value.to_owned()))
}

fn hex_decode(encoded: &str) -> Result<Vec<u8>> {
    if !encoded.len().is_multiple_of(2) {
        return Err(Error::Computation(
            "runner byte-array result contains odd-length hex".to_owned(),
        ));
    }
    let (pairs, remainder) = encoded.as_bytes().as_chunks::<2>();
    debug_assert!(remainder.is_empty());
    pairs
        .iter()
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Error::Computation(format!(
            "runner byte-array result contains non-hex byte {:?}",
            char::from(byte)
        ))),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn sdk_value_to_vm_value(
    vm: &mut stoffel_vm::core_vm::VirtualMachine,
    value: &Value,
) -> Result<VmValue> {
    match value {
        Value::I64(value) => Ok(VmValue::I64(*value)),
        Value::U64(value) => Ok(VmValue::U64(*value)),
        Value::Bool(value) => Ok(VmValue::Bool(*value)),
        Value::Float(value) => Ok(VmValue::Float((*value).into())),
        Value::String(value) => Ok(VmValue::String(value.clone())),
        Value::Bytes(_) => Err(Error::InvalidInput(
            "byte inputs are only supported for local coordinator client inputs".to_owned(),
        )),
        Value::List(values) => {
            let array_ref = vm
                .create_array_ref(values.len())
                .map_err(|error| Error::Computation(error.to_string()))?;
            let values = values
                .iter()
                .map(|value| sdk_value_to_vm_value(vm, value))
                .collect::<Result<Vec<_>>>()?;
            vm.push_array_ref_values(array_ref, &values)
                .map_err(|error| Error::Computation(error.to_string()))?;
            Ok(VmValue::from(array_ref))
        }
        Value::Object(fields) => {
            let object_ref = vm
                .create_object_ref()
                .map_err(|error| Error::Computation(error.to_string()))?;
            let table_ref = TableRef::from(object_ref);
            for (name, field_value) in fields {
                let field_value = sdk_value_to_vm_value(vm, field_value)?;
                vm.set_table_field(table_ref, VmValue::String(name.clone()), field_value)
                    .map_err(|error| Error::Computation(error.to_string()))?;
            }
            Ok(VmValue::from(object_ref))
        }
        Value::Unit => Ok(VmValue::Unit),
    }
}

fn sdk_value_from_vm_value(
    vm: &mut stoffel_vm::core_vm::VirtualMachine,
    value: VmValue,
    active_tables: &mut HashSet<TableRef>,
    depth: usize,
) -> Result<Value> {
    const MAX_TABLE_DEPTH: usize = 32;

    match value {
        VmValue::Array(array_ref) => {
            if depth >= MAX_TABLE_DEPTH {
                return Err(Error::Computation(format!(
                    "VM array output exceeds maximum SDK conversion depth of {MAX_TABLE_DEPTH}"
                )));
            }
            let table_ref = TableRef::from(array_ref);
            if !active_tables.insert(table_ref) {
                return Err(Error::Computation(format!(
                    "VM array output contains a cycle at array ref {}",
                    array_ref.id()
                )));
            }
            let len = vm
                .read_array_ref_len(array_ref)
                .map_err(|error| Error::Computation(error.to_string()))?;
            let mut values = Vec::with_capacity(len);
            for index in 0..len {
                let index = i64::try_from(index).map_err(|_| {
                    Error::Computation("VM array index cannot be represented as int64".to_owned())
                })?;
                let item = vm
                    .read_table_field(TableRef::from(array_ref), &VmValue::I64(index))
                    .map_err(|error| Error::Computation(error.to_string()))?
                    .ok_or_else(|| {
                        Error::Computation(format!("VM array is missing element at index {index}"))
                    })?;
                values.push(sdk_value_from_vm_value(vm, item, active_tables, depth + 1)?);
            }
            active_tables.remove(&table_ref);
            Ok(Value::List(values))
        }
        VmValue::Object(object_ref) => {
            if depth >= MAX_TABLE_DEPTH {
                return Err(Error::Computation(format!(
                    "VM object output exceeds maximum SDK conversion depth of {MAX_TABLE_DEPTH}"
                )));
            }
            let table_ref = TableRef::from(object_ref);
            if !active_tables.insert(table_ref) {
                return Err(Error::Computation(format!(
                    "VM object output contains a cycle at object ref {}",
                    object_ref.id()
                )));
            }
            let len = vm
                .read_object_ref_len(object_ref)
                .map_err(|error| Error::Computation(error.to_string()))?;
            let entries = vm
                .read_object_ref_entries(object_ref, len)
                .map_err(|error| Error::Computation(error.to_string()))?;
            let mut fields = std::collections::BTreeMap::new();
            for (key, value) in entries {
                let VmValue::String(key) = key else {
                    return Err(Error::Computation(format!(
                        "VM object output contains a non-string field key: {key:?}"
                    )));
                };
                fields.insert(
                    key,
                    sdk_value_from_vm_value(vm, value, active_tables, depth + 1)?,
                );
            }
            active_tables.remove(&table_ref);
            Ok(Value::Object(fields))
        }
        value => Value::from_vm_value(value).ok_or_else(|| {
            Error::Computation(
                "VM returned a value that cannot be represented by the public SDK Value type"
                    .to_owned(),
            )
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decode_client_output_value, find_binary_in_path, local_client_inputs_for_runner,
        local_program_output_without_return_markers, parse_runner_return_value, path_is_under,
        target_profile_dir_from_exe, validate_party_share_returns, LocalPartyExecutionDetails,
        OpaqueShare,
    };
    use crate::types::Value;
    use std::path::PathBuf;
    use stoffel_vm_runner::{LocalCoordinatorRunOutput, LocalPartyOutput, ReturnedShare};
    use stoffel_vm_types::core_types::{ShareDataFormat, ShareType};

    fn opaque_party(name: &str, payload: u8) -> (LocalPartyOutput, LocalPartyExecutionDetails) {
        let returned_share = ReturnedShare::new(
            ShareType::secret_int(64),
            ShareDataFormat::Feldman,
            vec![payload],
        );
        let encoded = returned_share.to_string();
        let share = OpaqueShare::from_runner(returned_share);
        (
            LocalPartyOutput {
                name: name.to_owned(),
                stdout: format!("Program returned: {encoded}\n"),
                stderr: String::new(),
                combined: format!("Program returned: {encoded}\n"),
            },
            LocalPartyExecutionDetails {
                party: name.to_owned(),
                program_output: String::new(),
                returned_shares: vec![share],
            },
        )
    }

    #[test]
    fn local_client_inputs_use_manifest_fixed_point_precision() -> crate::Result<()> {
        let runtime = crate::Stoffel::compile(
            r#"
def main() -> int64:
  var num_elements: int64 = 2
  var num_clients: int64 = 2
  var element_index: int64 = 0
  while element_index < num_elements:
    discard ClientStore.take_share_fixed(0, element_index)
    var client_index: int64 = 1
    while client_index < num_clients:
      discard ClientStore.take_share_fixed(client_index, element_index)
      client_index += 1
    element_index += 1
  return 0
"#,
        )?
        .build()?;
        let inputs = vec![
            (0, vec![Value::I64(0), Value::I64(0)]),
            (1, vec![Value::I64(1), Value::I64(1)]),
        ];

        let encoded = local_client_inputs_for_runner(runtime.program(), &inputs)?;

        assert_eq!(encoded.len(), 2);
        assert_eq!(encoded[0].values, vec!["0", "0"]);
        assert_eq!(encoded[1].values, vec!["65536", "65536"]);
        Ok(())
    }

    #[test]
    fn local_fixed_point_client_outputs_decode_semantically() -> crate::Result<()> {
        let share_type = ShareType::default_secret_fixed_point();

        assert_eq!(
            decode_client_output_value(98_304, share_type)?,
            Value::Float(1.5)
        );
        assert_eq!(
            decode_client_output_value((-32_768_i64) as u64, share_type)?,
            Value::Float(-0.5)
        );
        Ok(())
    }

    #[test]
    fn opaque_party_returns_allow_distinct_payloads_with_matching_metadata() {
        let (raw_a, party_a) = opaque_party("party-0", 0x11);
        let (raw_b, party_b) = opaque_party("party-1", 0x22);
        let output = LocalCoordinatorRunOutput {
            combined_output: String::new(),
            party_outputs: vec![raw_a, raw_b],
            client_outputs: Vec::new(),
        };

        validate_party_share_returns(&output, &[party_a, party_b]).unwrap();
    }

    #[test]
    fn opaque_party_returns_reject_mixed_public_and_secret_markers() {
        let (mut raw, party) = opaque_party("party-0", 0x11);
        raw.combined.push_str("Program returned: 7\n");
        let output = LocalCoordinatorRunOutput {
            combined_output: String::new(),
            party_outputs: vec![raw],
            client_outputs: Vec::new(),
        };

        let error = validate_party_share_returns(&output, &[party]).unwrap_err();
        assert!(error.to_string().contains("mixed secret and public"));
    }

    #[test]
    fn local_program_output_filter_removes_runner_return_markers() {
        let stdout = "polynomial p\nProgram returned: ()\n";

        assert_eq!(
            local_program_output_without_return_markers(stdout),
            "polynomial p\n"
        );
    }

    #[test]
    fn runner_byte_array_result_decodes_to_sdk_bytes() {
        assert_eq!(
            parse_runner_return_value("byte[4] 0x0011aaff").unwrap(),
            Value::Bytes(vec![0x00, 0x11, 0xaa, 0xff])
        );
    }

    #[test]
    fn runner_byte_array_result_rejects_length_mismatch() {
        assert!(parse_runner_return_value("byte[3] 0x0011").is_err());
    }

    #[test]
    fn find_binary_in_path_finds_executable_file() {
        let missing_dir = tempfile::tempdir().unwrap();
        let bin_dir = tempfile::tempdir().unwrap();
        let binary = bin_dir
            .path()
            .join(format!("stoffel-run{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&binary, b"#!/bin/sh\n").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut permissions = std::fs::metadata(&binary).unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(&binary, permissions).unwrap();
        }

        let path = std::env::join_paths([missing_dir.path(), bin_dir.path()]).unwrap();

        assert_eq!(find_binary_in_path("stoffel-run", &path), Some(binary));
    }

    #[test]
    fn target_profile_dir_from_test_exe_uses_parent_of_deps_dir() {
        let exe: PathBuf = ["workspace", "target", "debug", "deps", "sdk_usage-abc"]
            .iter()
            .collect();

        assert_eq!(
            target_profile_dir_from_exe(&exe),
            Some(["workspace", "target", "debug"].iter().collect())
        );
    }

    #[test]
    fn path_is_under_detects_workspace_target_executables() {
        let exe: PathBuf = ["workspace", "target", "debug", "deps", "sdk_usage-abc"]
            .iter()
            .collect();
        let target: PathBuf = ["workspace", "target"].iter().collect();
        let other: PathBuf = ["workspace", "other-target"].iter().collect();

        assert!(path_is_under(&exe, &target));
        assert!(!path_is_under(&exe, &other));
    }
}
