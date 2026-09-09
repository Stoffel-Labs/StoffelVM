//! Build-script helpers for generating typed client IO bindings from `.stflb`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Cursor;
use std::path::Path;

use stoffellang::stoffel_vm_types::compiled_binary::{
    utils, ClientIoSchema, CompiledBinary, MpcBackend, MpcCurve,
};
pub use stoffellang::stoffel_vm_types::core_types::ShareType;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("bytecode error: {0}")]
    Bytecode(String),
    #[error("compilation error: {0}")]
    Compilation(String),
    #[error("configuration error: {0}")]
    Configuration(String),
    #[error("unsupported binding: {0}")]
    Unsupported(String),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone)]
pub struct Program {
    binary: CompiledBinary,
}

impl Program {
    pub fn new(binary: CompiledBinary) -> Self {
        Self { binary }
    }

    pub fn from_bytecode(bytecode: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytecode);
        let binary = CompiledBinary::deserialize(&mut cursor)
            .map_err(|error| Error::Bytecode(format!("{error:?}")))?;
        if cursor.position() != bytecode.len() as u64 {
            return Err(Error::Bytecode(format!(
                "bytecode contains {} trailing byte(s)",
                bytecode.len() as u64 - cursor.position()
            )));
        }
        Ok(Self::new(binary))
    }

    pub fn from_bytecode_file(path: impl AsRef<Path>) -> Result<Self> {
        let bytecode = std::fs::read(path)?;
        Self::from_bytecode(&bytecode)
    }

    pub fn compile_file(path: impl AsRef<Path>) -> Result<Self> {
        Self::compile_file_with_entrypoints(path, std::iter::empty::<&str>())
    }

    pub fn compile_file_with_entrypoints<'a>(
        path: impl AsRef<Path>,
        entry_points: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self> {
        let path = path.as_ref();
        let source = std::fs::read_to_string(path)?;
        let options = stoffellang::CompilerOptions {
            optimize: false,
            optimization_level: 0,
            print_ir: false,
            mpc_backend: MpcBackend::HoneyBadger,
            mpc_curve: MpcCurve::Bls12_381,
            entry_points: entry_points.into_iter().map(ToOwned::to_owned).collect(),
            ..Default::default()
        };
        let compiled = stoffellang::compile_file(path, &source, &options)
            .map_err(|errors| Error::Compilation(format_compiler_errors(&errors)))?;
        Ok(Self::new(stoffellang::convert_to_binary(&compiled)))
    }

    pub fn save_bytecode(&self, path: impl AsRef<Path>) -> Result<()> {
        utils::save_to_file(&self.binary, path)
            .map_err(|error| Error::Bytecode(format!("{error:?}")))
    }

    fn has_client_io(&self) -> bool {
        !self.binary.client_io_manifest.clients.is_empty()
    }

    fn clients(&self) -> impl Iterator<Item = ClientMetadata<'_>> {
        self.binary
            .client_io_manifest
            .clients
            .iter()
            .map(ClientMetadata)
    }

    fn client(&self, client_slot: u64) -> Option<ClientMetadata<'_>> {
        self.binary
            .client_io_manifest
            .clients
            .iter()
            .find(|client| client.client_slot == client_slot)
            .map(ClientMetadata)
    }

    fn function_names(&self) -> impl Iterator<Item = &str> {
        self.binary
            .functions
            .iter()
            .map(|function| function.name.as_str())
    }

    fn bytecode_backend(&self) -> MpcBackend {
        self.binary.client_io_manifest.mpc_backend
    }

    fn bytecode_curve(&self) -> MpcCurve {
        self.binary.client_io_manifest.mpc_curve
    }
}

#[derive(Debug, Clone, Copy)]
struct ClientMetadata<'a>(&'a ClientIoSchema);

impl ClientMetadata<'_> {
    fn client_slot(&self) -> u64 {
        self.0.client_slot
    }

    fn input_count(&self) -> usize {
        self.0.inputs.len()
    }

    fn inputs(&self) -> &[ShareType] {
        &self.0.inputs
    }

    fn outputs(&self) -> &[ShareType] {
        &self.0.outputs
    }
}

fn format_compiler_errors(errors: &[stoffellang::CompilerError]) -> String {
    errors
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingsConfig {
    pub crate_path: String,
    pub derives: Vec<String>,
    pub entrypoints: Vec<EntrypointBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntrypointBinding {
    pub entrypoint: String,
    pub method_name: String,
    pub inputs: Vec<EntrypointInputBinding>,
    pub output_type_name: String,
    pub output_client_slot: u64,
    pub output_types: Vec<ShareType>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntrypointInputBinding {
    pub client_slot: u64,
    pub argument_name: String,
    pub type_name: String,
}

impl EntrypointBinding {
    pub fn new(entrypoint: impl Into<String>) -> Self {
        let entrypoint = entrypoint.into();
        Self {
            method_name: sanitize_identifier(&entrypoint),
            inputs: Vec::new(),
            output_type_name: entrypoint_output_struct_name(&entrypoint),
            entrypoint,
            output_client_slot: 0,
            output_types: Vec::new(),
        }
    }

    pub fn method_name(mut self, method_name: impl Into<String>) -> Self {
        self.method_name = sanitize_identifier(&method_name.into());
        self
    }

    pub fn input(
        mut self,
        client_slot: u64,
        argument_name: impl Into<String>,
        type_name: impl Into<String>,
    ) -> Self {
        self.inputs.push(EntrypointInputBinding {
            client_slot,
            argument_name: sanitize_identifier(&argument_name.into()),
            type_name: sanitize_type_name(&type_name.into()),
        });
        self
    }

    pub fn output(
        mut self,
        client_slot: u64,
        type_name: impl Into<String>,
        output_types: impl Into<Vec<ShareType>>,
    ) -> Self {
        self.output_client_slot = client_slot;
        self.output_type_name = sanitize_type_name(&type_name.into());
        self.output_types = output_types.into();
        self
    }

    pub fn output_client(mut self, client_slot: u64) -> Self {
        self.output_client_slot = client_slot;
        self
    }

    pub fn output_types(mut self, output_types: impl Into<Vec<ShareType>>) -> Self {
        self.output_types = output_types.into();
        self
    }
}

impl Default for BindingsConfig {
    fn default() -> Self {
        Self {
            crate_path: "stoffel".to_owned(),
            derives: vec![
                "Debug".to_owned(),
                "Clone".to_owned(),
                "PartialEq".to_owned(),
            ],
            entrypoints: Vec::new(),
        }
    }
}

/// Generate Rust client IO bindings from a compiled `.stflb` file.
///
/// This is intended for application `build.rs` files:
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let out_dir = std::env::var("OUT_DIR")?;
/// stoffel_bindgen::generate_bindings(
///     "program.stflb",
///     format!("{out_dir}/stoffel_bindings.rs"),
/// )?;
/// # Ok(())
/// # }
/// ```
pub fn generate_bindings(
    bytecode_path: impl AsRef<Path>,
    out_file: impl AsRef<Path>,
) -> Result<()> {
    generate_bindings_with_config(bytecode_path, out_file, BindingsConfig::default())
}

/// Generate Rust client IO bindings from a compiled `.stflb` file with custom
/// crate path or derives.
pub fn generate_bindings_with_config(
    bytecode_path: impl AsRef<Path>,
    out_file: impl AsRef<Path>,
    config: BindingsConfig,
) -> Result<()> {
    let program = Program::from_bytecode_file(bytecode_path)?;
    generate_bindings_from_program(&program, out_file, config)
}

pub fn generate_bindings_from_source(
    source_path: impl AsRef<Path>,
    out_file: impl AsRef<Path>,
    config: BindingsConfig,
) -> Result<()> {
    let entry_points = config
        .entrypoints
        .iter()
        .map(|entrypoint| entrypoint.entrypoint.as_str());
    let program = Program::compile_file_with_entrypoints(source_path, entry_points)?;
    generate_bindings_from_program(&program, out_file, config)
}

/// Generate Rust client IO bindings from an already compiled program.
pub fn generate_bindings_from_program(
    program: &Program,
    out_file: impl AsRef<Path>,
    config: BindingsConfig,
) -> Result<()> {
    let source = generate_bindings_source(program, &config)?;
    std::fs::write(out_file, source)?;
    Ok(())
}

pub(crate) fn generate_bindings_source(
    program: &Program,
    config: &BindingsConfig,
) -> Result<String> {
    let mut source = String::new();
    writeln!(
        source,
        "// This file is generated by stoffel::generate_bindings. Do not edit by hand."
    )
    .expect("writing to String cannot fail");
    writeln!(source).expect("writing to String cannot fail");

    emit_program_manifest(&mut source, program, config)?;
    writeln!(source).expect("writing to String cannot fail");

    if !program.has_client_io() {
        writeln!(source, "// The program does not declare ClientStore IO.").expect("infallible");
        return Ok(source);
    }

    for client in program.clients() {
        let slot = client.client_slot();
        emit_payload(
            &mut source,
            &config.crate_path,
            &config.derives,
            &format!("Client{slot}Inputs"),
            "input",
            client.inputs(),
            true,
        )?;
        writeln!(source).expect("writing to String cannot fail");
        emit_payload(
            &mut source,
            &config.crate_path,
            &config.derives,
            &format!("Client{slot}Outputs"),
            "output",
            client.outputs(),
            false,
        )?;
        writeln!(source).expect("writing to String cannot fail");
    }

    if !config.entrypoints.is_empty() {
        emit_program_client(&mut source, program, config)?;
    }

    Ok(source)
}

fn emit_program_manifest(
    source: &mut String,
    program: &Program,
    config: &BindingsConfig,
) -> Result<()> {
    let crate_path = &config.crate_path;
    let output_types = merged_client_output_types(program, config)?;

    writeln!(source, "pub struct ProgramManifest;").expect("writing to String cannot fail");
    writeln!(
        source,
        "impl {crate_path}::GeneratedProgramManifest for ProgramManifest {{"
    )
    .expect("writing to String cannot fail");
    writeln!(
        source,
        "    const BACKEND: {crate_path}::MpcBackend = {};",
        sdk_backend_expr(
            crate_path,
            program.bytecode_backend(),
            program.bytecode_curve()
        )
    )
    .expect("writing to String cannot fail");
    writeln!(
        source,
        "    fn client_input_types(client_slot: u64) -> Option<&'static [{crate_path}::ClientValueType]> {{"
    )
    .expect("writing to String cannot fail");
    writeln!(source, "        match client_slot {{").expect("writing to String cannot fail");
    for client in program.clients() {
        writeln!(
            source,
            "            {} => Some(&{}),",
            client.client_slot(),
            client_value_type_array(crate_path, client.inputs())?
        )
        .expect("writing to String cannot fail");
    }
    writeln!(source, "            _ => None,").expect("writing to String cannot fail");
    writeln!(source, "        }}").expect("writing to String cannot fail");
    writeln!(source, "    }}").expect("writing to String cannot fail");

    writeln!(
        source,
        "    fn client_output_types(client_slot: u64) -> Option<&'static [{crate_path}::ClientValueType]> {{"
    )
    .expect("writing to String cannot fail");
    writeln!(source, "        match client_slot {{").expect("writing to String cannot fail");
    for (client_slot, outputs) in output_types {
        writeln!(
            source,
            "            {} => Some(&{}),",
            client_slot,
            client_value_type_array(crate_path, &outputs)?
        )
        .expect("writing to String cannot fail");
    }
    writeln!(source, "            _ => None,").expect("writing to String cannot fail");
    writeln!(source, "        }}").expect("writing to String cannot fail");
    writeln!(source, "    }}").expect("writing to String cannot fail");
    writeln!(source, "}}").expect("writing to String cannot fail");
    Ok(())
}

fn merged_client_output_types(
    program: &Program,
    config: &BindingsConfig,
) -> Result<BTreeMap<u64, Vec<ShareType>>> {
    let mut output_types = BTreeMap::new();
    for client in program.clients() {
        output_types.insert(client.client_slot(), client.outputs().to_vec());
    }
    for entrypoint in &config.entrypoints {
        if entrypoint.output_types.is_empty() {
            continue;
        }
        match output_types.get_mut(&entrypoint.output_client_slot) {
            Some(existing) if existing.is_empty() => {
                *existing = entrypoint.output_types.clone();
            }
            Some(existing) if *existing == entrypoint.output_types => {}
            Some(existing) => {
                return Err(Error::Configuration(format!(
                    "entrypoint '{}' declares {} output value(s) for client {}, but the manifest already has {} incompatible output value(s)",
                    entrypoint.entrypoint,
                    entrypoint.output_types.len(),
                    entrypoint.output_client_slot,
                    existing.len()
                )));
            }
            None => {
                output_types.insert(
                    entrypoint.output_client_slot,
                    entrypoint.output_types.clone(),
                );
            }
        }
    }
    Ok(output_types)
}

fn sdk_backend_expr(crate_path: &str, backend: MpcBackend, curve: MpcCurve) -> String {
    match backend {
        MpcBackend::HoneyBadger => format!("{crate_path}::MpcBackend::HoneyBadger"),
        MpcBackend::Avss => format!(
            "{crate_path}::MpcBackend::Avss {{ curve: {} }}",
            sdk_curve_expr(crate_path, curve)
        ),
    }
}

fn sdk_curve_expr(crate_path: &str, curve: MpcCurve) -> String {
    let variant = match curve {
        MpcCurve::Bls12_381 => "Bls12_381",
        MpcCurve::Bn254 => "Bn254",
        MpcCurve::Curve25519 => "Curve25519",
        MpcCurve::Ed25519 => "Ed25519",
        MpcCurve::Secp256k1 => "Secp256k1",
        MpcCurve::Secp256r1 => "Secp256r1",
    };
    format!("{crate_path}::Curve::{variant}")
}

fn client_value_type_array(crate_path: &str, share_types: &[ShareType]) -> Result<String> {
    let mut values = String::from("[");
    for (index, share_type) in share_types.iter().enumerate() {
        if index > 0 {
            values.push_str(", ");
        }
        write!(
            values,
            "{crate_path}::ClientValueType::{}",
            client_value_type_variant(*share_type)?
        )
        .expect("writing to String cannot fail");
    }
    values.push(']');
    Ok(values)
}

fn emit_payload(
    source: &mut String,
    crate_path: &str,
    derives: &[String],
    struct_name: &str,
    field_prefix: &str,
    share_types: &[ShareType],
    is_input: bool,
) -> Result<()> {
    if !derives.is_empty() {
        writeln!(source, "#[derive({})]", derives.join(", "))
            .expect("writing to String cannot fail");
    }
    writeln!(source, "pub struct {struct_name} {{").expect("writing to String cannot fail");
    for (ordinal, share_type) in share_types.iter().enumerate() {
        writeln!(
            source,
            "    pub {field_prefix}_{ordinal}: {},",
            rust_type(*share_type)?
        )
        .expect("writing to String cannot fail");
    }
    writeln!(source, "}}").expect("writing to String cannot fail");

    if is_input {
        emit_share_payload_convenience(source, crate_path, struct_name, field_prefix, share_types)?;
        emit_inputs_impl(source, crate_path, struct_name, field_prefix, share_types)
    } else {
        emit_share_payload_convenience(source, crate_path, struct_name, field_prefix, share_types)?;
        emit_outputs_impl(source, crate_path, struct_name, field_prefix, share_types)
    }
}

fn emit_inputs_impl(
    source: &mut String,
    crate_path: &str,
    struct_name: &str,
    field_prefix: &str,
    share_types: &[ShareType],
) -> Result<()> {
    writeln!(
        source,
        "impl {crate_path}::TypedClientInputs for {struct_name} {{"
    )
    .expect("writing to String cannot fail");
    writeln!(
        source,
        "    fn into_values(self) -> Vec<{crate_path}::Value> {{"
    )
    .expect("writing to String cannot fail");
    writeln!(source, "        vec![").expect("writing to String cannot fail");
    for ordinal in 0..share_types.len() {
        writeln!(
            source,
            "            {crate_path}::Value::from(self.{field_prefix}_{ordinal}),"
        )
        .expect("writing to String cannot fail");
    }
    writeln!(source, "        ]").expect("writing to String cannot fail");
    writeln!(source, "    }}").expect("writing to String cannot fail");
    emit_value_types(source, crate_path, share_types)?;
    writeln!(source, "}}").expect("writing to String cannot fail");
    Ok(())
}

fn emit_outputs_impl(
    source: &mut String,
    crate_path: &str,
    struct_name: &str,
    field_prefix: &str,
    share_types: &[ShareType],
) -> Result<()> {
    writeln!(
        source,
        "impl {crate_path}::TypedClientOutputs for {struct_name} {{"
    )
    .expect("writing to String cannot fail");
    writeln!(
        source,
        "    fn from_values(values: Vec<{crate_path}::Value>) -> {crate_path}::Result<Self> {{"
    )
    .expect("writing to String cannot fail");
    writeln!(source, "        let expected = Self::value_types().len();")
        .expect("writing to String cannot fail");
    writeln!(source, "        let actual = values.len();").expect("writing to String cannot fail");
    writeln!(source, "        if actual != expected {{").expect("writing to String cannot fail");
    writeln!(
        source,
        "            return Err({crate_path}::Error::InvalidInput(format!(\"expected {{expected}} typed outputs, got {{actual}}\")));"
    )
    .expect("writing to String cannot fail");
    writeln!(source, "        }}").expect("writing to String cannot fail");
    writeln!(source, "        let mut values = values.into_iter();")
        .expect("writing to String cannot fail");
    writeln!(source, "        Ok(Self {{").expect("writing to String cannot fail");
    for (ordinal, share_type) in share_types.iter().enumerate() {
        writeln!(
            source,
            "            {field_prefix}_{ordinal}: <{} as {crate_path}::ClientOutputValue>::try_from_sdk_value(values.next().expect(\"length checked\"))?,",
            rust_type(*share_type)?
        )
        .expect("writing to String cannot fail");
    }
    writeln!(source, "        }})").expect("writing to String cannot fail");
    writeln!(source, "    }}").expect("writing to String cannot fail");
    emit_value_types(source, crate_path, share_types)?;
    writeln!(source, "}}").expect("writing to String cannot fail");
    Ok(())
}

fn emit_share_payload_convenience(
    source: &mut String,
    crate_path: &str,
    struct_name: &str,
    field_prefix: &str,
    share_types: &[ShareType],
) -> Result<()> {
    let rust_types = share_types
        .iter()
        .map(|share_type| rust_type(*share_type))
        .collect::<Result<Vec<_>>>()?;
    emit_payload_convenience(source, crate_path, struct_name, field_prefix, &rust_types);
    Ok(())
}

fn emit_payload_convenience(
    source: &mut String,
    crate_path: &str,
    struct_name: &str,
    field_prefix: &str,
    rust_types: &[&str],
) {
    let len = rust_types.len();
    writeln!(source, "impl {struct_name} {{").expect("writing to String cannot fail");
    writeln!(source, "    pub const LEN: usize = {len};").expect("writing to String cannot fail");

    if let Some(first_type) = rust_types.first().copied() {
        if rust_types.iter().all(|rust_type| *rust_type == first_type) {
            writeln!(
                source,
                "    pub fn from_array(values: [{first_type}; {len}]) -> Self {{"
            )
            .expect("writing to String cannot fail");
            writeln!(source, "        let mut values = values.into_iter();")
                .expect("writing to String cannot fail");
            writeln!(source, "        Self {{").expect("writing to String cannot fail");
            for ordinal in 0..len {
                writeln!(
                    source,
                    "            {field_prefix}_{ordinal}: values.next().expect(\"length checked\"),"
                )
                .expect("writing to String cannot fail");
            }
            writeln!(source, "        }}").expect("writing to String cannot fail");
            writeln!(source, "    }}").expect("writing to String cannot fail");

            writeln!(
                source,
                "    pub fn into_array(self) -> [{first_type}; {len}] {{"
            )
            .expect("writing to String cannot fail");
            write!(source, "        [").expect("writing to String cannot fail");
            for ordinal in 0..len {
                if ordinal > 0 {
                    write!(source, ", ").expect("writing to String cannot fail");
                }
                write!(source, "self.{field_prefix}_{ordinal}")
                    .expect("writing to String cannot fail");
            }
            writeln!(source, "]").expect("writing to String cannot fail");
            writeln!(source, "    }}").expect("writing to String cannot fail");
        }
    }

    if len > 0 && len.is_multiple_of(8) && rust_types.iter().all(|rust_type| *rust_type == "bool") {
        let byte_len = len / 8;
        writeln!(
            source,
            "    pub fn from_lsb_bytes(bytes: impl AsRef<[u8]>) -> {crate_path}::Result<Self> {{"
        )
        .expect("writing to String cannot fail");
        writeln!(source, "        let bytes = bytes.as_ref();")
            .expect("writing to String cannot fail");
        writeln!(source, "        if bytes.len() != {byte_len} {{")
            .expect("writing to String cannot fail");
        writeln!(
            source,
            "            return Err({crate_path}::Error::InvalidInput(format!(\"expected {byte_len} byte(s), got {{}}\", bytes.len())));"
        )
        .expect("writing to String cannot fail");
        writeln!(source, "        }}").expect("writing to String cannot fail");
        writeln!(source, "        let mut bits = [false; {len}];")
            .expect("writing to String cannot fail");
        writeln!(
            source,
            "        for (byte_index, byte) in bytes.iter().enumerate() {{"
        )
        .expect("writing to String cannot fail");
        writeln!(source, "            for bit in 0..8 {{").expect("writing to String cannot fail");
        writeln!(
            source,
            "                bits[byte_index * 8 + bit] = ((byte >> bit) & 1) == 1;"
        )
        .expect("writing to String cannot fail");
        writeln!(source, "            }}").expect("writing to String cannot fail");
        writeln!(source, "        }}").expect("writing to String cannot fail");
        writeln!(source, "        Ok(Self::from_array(bits))")
            .expect("writing to String cannot fail");
        writeln!(source, "    }}").expect("writing to String cannot fail");

        writeln!(source, "    pub fn bytes_lsb_first(&self) -> Vec<u8> {{")
            .expect("writing to String cannot fail");
        writeln!(source, "        let mut bytes = vec![0_u8; {byte_len}];")
            .expect("writing to String cannot fail");
        for ordinal in 0..len {
            writeln!(
                source,
                "        if self.{field_prefix}_{ordinal} {{ bytes[{}] |= 1 << {}; }}",
                ordinal / 8,
                ordinal % 8
            )
            .expect("writing to String cannot fail");
        }
        writeln!(source, "        bytes").expect("writing to String cannot fail");
        writeln!(source, "    }}").expect("writing to String cannot fail");

        writeln!(
            source,
            "    pub fn from_hex(hex: impl AsRef<str>) -> {crate_path}::Result<Self> {{"
        )
        .expect("writing to String cannot fail");
        writeln!(source, "        let hex = hex.as_ref();").expect("writing to String cannot fail");
        writeln!(source, "        if hex.len() != {} {{", byte_len * 2)
            .expect("writing to String cannot fail");
        writeln!(
            source,
            "            return Err({crate_path}::Error::InvalidInput(format!(\"expected {} hex digit(s), got {{}}\", hex.len())));",
            byte_len * 2
        )
        .expect("writing to String cannot fail");
        writeln!(source, "        }}").expect("writing to String cannot fail");
        writeln!(source, "        let mut bytes = [0_u8; {byte_len}];")
            .expect("writing to String cannot fail");
        writeln!(
            source,
            "        for (index, byte) in bytes.iter_mut().enumerate() {{"
        )
        .expect("writing to String cannot fail");
        writeln!(source, "            let start = index * 2;")
            .expect("writing to String cannot fail");
        writeln!(
            source,
            "            *byte = u8::from_str_radix(&hex[start..start + 2], 16).map_err(|error| {crate_path}::Error::InvalidInput(format!(\"invalid hex byte {{index}}: {{error}}\")))?;"
        )
        .expect("writing to String cannot fail");
        writeln!(source, "        }}").expect("writing to String cannot fail");
        writeln!(source, "        Ok(Self::from(bytes))").expect("writing to String cannot fail");
        writeln!(source, "    }}").expect("writing to String cannot fail");

        writeln!(source, "    pub fn to_hex(&self) -> String {{")
            .expect("writing to String cannot fail");
        writeln!(
            source,
            "        self.bytes_lsb_first().iter().map(|byte| format!(\"{{byte:02x}}\")).collect()"
        )
        .expect("writing to String cannot fail");
        writeln!(source, "    }}").expect("writing to String cannot fail");
    }

    writeln!(source, "}}").expect("writing to String cannot fail");

    if len > 0 && len.is_multiple_of(8) && rust_types.iter().all(|rust_type| *rust_type == "bool") {
        let byte_len = len / 8;
        writeln!(source, "impl From<[u8; {byte_len}]> for {struct_name} {{")
            .expect("writing to String cannot fail");
        writeln!(source, "    fn from(bytes: [u8; {byte_len}]) -> Self {{")
            .expect("writing to String cannot fail");
        writeln!(
            source,
            "        Self::from_lsb_bytes(bytes).expect(\"fixed-size byte array length is generated correctly\")"
        )
        .expect("writing to String cannot fail");
        writeln!(source, "    }}").expect("writing to String cannot fail");
        writeln!(source, "}}").expect("writing to String cannot fail");

        writeln!(source, "impl TryFrom<&[u8]> for {struct_name} {{")
            .expect("writing to String cannot fail");
        writeln!(source, "    type Error = {crate_path}::Error;")
            .expect("writing to String cannot fail");
        writeln!(
            source,
            "    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {{"
        )
        .expect("writing to String cannot fail");
        writeln!(source, "        Self::from_lsb_bytes(bytes)")
            .expect("writing to String cannot fail");
        writeln!(source, "    }}").expect("writing to String cannot fail");
        writeln!(source, "}}").expect("writing to String cannot fail");

        writeln!(source, "impl TryFrom<Vec<u8>> for {struct_name} {{")
            .expect("writing to String cannot fail");
        writeln!(source, "    type Error = {crate_path}::Error;")
            .expect("writing to String cannot fail");
        writeln!(
            source,
            "    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {{"
        )
        .expect("writing to String cannot fail");
        writeln!(source, "        Self::from_lsb_bytes(bytes)")
            .expect("writing to String cannot fail");
        writeln!(source, "    }}").expect("writing to String cannot fail");
        writeln!(source, "}}").expect("writing to String cannot fail");

        writeln!(source, "impl TryFrom<&str> for {struct_name} {{")
            .expect("writing to String cannot fail");
        writeln!(source, "    type Error = {crate_path}::Error;")
            .expect("writing to String cannot fail");
        writeln!(
            source,
            "    fn try_from(hex: &str) -> Result<Self, Self::Error> {{"
        )
        .expect("writing to String cannot fail");
        writeln!(source, "        Self::from_hex(hex)").expect("writing to String cannot fail");
        writeln!(source, "    }}").expect("writing to String cannot fail");
        writeln!(source, "}}").expect("writing to String cannot fail");

        writeln!(source, "impl TryFrom<String> for {struct_name} {{")
            .expect("writing to String cannot fail");
        writeln!(source, "    type Error = {crate_path}::Error;")
            .expect("writing to String cannot fail");
        writeln!(
            source,
            "    fn try_from(hex: String) -> Result<Self, Self::Error> {{"
        )
        .expect("writing to String cannot fail");
        writeln!(source, "        Self::from_hex(hex)").expect("writing to String cannot fail");
        writeln!(source, "    }}").expect("writing to String cannot fail");
        writeln!(source, "}}").expect("writing to String cannot fail");

        writeln!(source, "impl std::fmt::Display for {struct_name} {{")
            .expect("writing to String cannot fail");
        writeln!(
            source,
            "    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{"
        )
        .expect("writing to String cannot fail");
        writeln!(source, "        f.write_str(&self.to_hex())")
            .expect("writing to String cannot fail");
        writeln!(source, "    }}").expect("writing to String cannot fail");
        writeln!(source, "}}").expect("writing to String cannot fail");
    }
}

fn emit_value_types(
    source: &mut String,
    crate_path: &str,
    share_types: &[ShareType],
) -> Result<()> {
    writeln!(
        source,
        "    fn value_types() -> Vec<{crate_path}::ClientValueType> {{"
    )
    .expect("writing to String cannot fail");
    writeln!(source, "        vec![").expect("writing to String cannot fail");
    for share_type in share_types {
        writeln!(
            source,
            "            {crate_path}::ClientValueType::{},",
            client_value_type_variant(*share_type)?
        )
        .expect("writing to String cannot fail");
    }
    writeln!(source, "        ]").expect("writing to String cannot fail");
    writeln!(source, "    }}").expect("writing to String cannot fail");
    Ok(())
}

fn emit_program_client(
    source: &mut String,
    program: &Program,
    config: &BindingsConfig,
) -> Result<()> {
    let crate_path = &config.crate_path;
    let function_names = program
        .function_names()
        .collect::<std::collections::HashSet<_>>();
    let mut semantic_payloads =
        std::collections::BTreeMap::<String, (Vec<ShareType>, bool, bool)>::new();
    for entrypoint in &config.entrypoints {
        if !function_names.contains(entrypoint.entrypoint.as_str()) {
            return Err(Error::Configuration(format!(
                "cannot generate binding for unknown entrypoint `{}`",
                entrypoint.entrypoint
            )));
        }
        if entrypoint.output_types.is_empty() {
            return Err(Error::Configuration(format!(
                "entrypoint `{}` must declare output_types",
                entrypoint.entrypoint
            )));
        }
        merge_semantic_payload(
            &mut semantic_payloads,
            entrypoint.output_type_name.clone(),
            entrypoint.output_types.clone(),
            false,
            true,
        )?;
        for input in &entrypoint.inputs {
            let client = program.client(input.client_slot).ok_or_else(|| {
                Error::Configuration(format!(
                    "entrypoint `{}` declares input for unknown client slot {}",
                    entrypoint.entrypoint, input.client_slot
                ))
            })?;
            merge_semantic_payload(
                &mut semantic_payloads,
                input.type_name.clone(),
                client.inputs().to_vec(),
                true,
                false,
            )?;
        }
    }

    for (type_name, (share_types, needs_input, needs_output)) in &semantic_payloads {
        emit_semantic_payload(
            source,
            crate_path,
            &config.derives,
            type_name,
            share_types,
            *needs_input,
            *needs_output,
        )?;
        writeln!(source).expect("writing to String cannot fail");
    }

    let input_clients = program
        .clients()
        .filter(|client| client.input_count() > 0)
        .map(|client| client.client_slot())
        .collect::<Vec<_>>();
    let max_input_client = input_clients.iter().copied().max();
    let max_output_client = config
        .entrypoints
        .iter()
        .map(|entrypoint| entrypoint.output_client_slot)
        .max();
    let expected_clients = max_input_client
        .into_iter()
        .chain(max_output_client)
        .max()
        .map(|client_slot| client_slot.saturating_add(1))
        .unwrap_or(0);

    writeln!(source, "#[derive(Debug, Clone)]").expect("writing to String cannot fail");
    writeln!(source, "pub struct ProgramClient {{").expect("writing to String cannot fail");
    writeln!(source, "    program_path: std::path::PathBuf,")
        .expect("writing to String cannot fail");
    writeln!(source, "    parties: usize,").expect("writing to String cannot fail");
    writeln!(source, "    threshold: usize,").expect("writing to String cannot fail");
    writeln!(source, "    timeout: std::time::Duration,").expect("writing to String cannot fail");
    writeln!(source, "    optimization_level: u8,").expect("writing to String cannot fail");
    writeln!(source, "    local_runner_path: Option<std::path::PathBuf>,")
        .expect("writing to String cannot fail");
    writeln!(source, "}}").expect("writing to String cannot fail");
    writeln!(source).expect("writing to String cannot fail");
    writeln!(source, "impl ProgramClient {{").expect("writing to String cannot fail");
    writeln!(
        source,
        "    pub fn new(program_path: impl AsRef<std::path::Path>) -> Self {{"
    )
    .expect("writing to String cannot fail");
    writeln!(source, "        Self {{").expect("writing to String cannot fail");
    writeln!(
        source,
        "            program_path: program_path.as_ref().to_path_buf(),"
    )
    .expect("writing to String cannot fail");
    writeln!(source, "            parties: 5,").expect("writing to String cannot fail");
    writeln!(source, "            threshold: 1,").expect("writing to String cannot fail");
    writeln!(source, "            optimization_level: 0,").expect("writing to String cannot fail");
    writeln!(
        source,
        "            timeout: std::time::Duration::from_secs(900),"
    )
    .expect("writing to String cannot fail");
    writeln!(source, "            local_runner_path: None,")
        .expect("writing to String cannot fail");
    writeln!(source, "        }}").expect("writing to String cannot fail");
    writeln!(source, "    }}").expect("writing to String cannot fail");
    writeln!(source).expect("writing to String cannot fail");
    writeln!(
        source,
        "    pub fn optimization_level(mut self, optimization_level: u8) -> Self {{"
    )
    .expect("writing to String cannot fail");
    writeln!(
        source,
        "        self.optimization_level = optimization_level;"
    )
    .expect("writing to String cannot fail");
    writeln!(source, "        self").expect("writing to String cannot fail");
    writeln!(source, "    }}").expect("writing to String cannot fail");
    writeln!(source).expect("writing to String cannot fail");
    writeln!(
        source,
        "    pub fn parties(mut self, parties: usize) -> Self {{"
    )
    .expect("writing to String cannot fail");
    writeln!(source, "        self.parties = parties;").expect("writing to String cannot fail");
    writeln!(source, "        self").expect("writing to String cannot fail");
    writeln!(source, "    }}").expect("writing to String cannot fail");
    writeln!(source).expect("writing to String cannot fail");
    writeln!(
        source,
        "    pub fn threshold(mut self, threshold: usize) -> Self {{"
    )
    .expect("writing to String cannot fail");
    writeln!(source, "        self.threshold = threshold;").expect("writing to String cannot fail");
    writeln!(source, "        self").expect("writing to String cannot fail");
    writeln!(source, "    }}").expect("writing to String cannot fail");
    writeln!(source).expect("writing to String cannot fail");
    writeln!(
        source,
        "    pub fn timeout(mut self, timeout: std::time::Duration) -> Self {{"
    )
    .expect("writing to String cannot fail");
    writeln!(source, "        self.timeout = timeout;").expect("writing to String cannot fail");
    writeln!(source, "        self").expect("writing to String cannot fail");
    writeln!(source, "    }}").expect("writing to String cannot fail");
    writeln!(source).expect("writing to String cannot fail");
    writeln!(
        source,
        "    pub fn local_runner_path(mut self, path: impl AsRef<std::path::Path>) -> Self {{"
    )
    .expect("writing to String cannot fail");
    writeln!(
        source,
        "        self.local_runner_path = Some(path.as_ref().to_path_buf());"
    )
    .expect("writing to String cannot fail");
    writeln!(source, "        self").expect("writing to String cannot fail");
    writeln!(source, "    }}").expect("writing to String cannot fail");
    writeln!(source).expect("writing to String cannot fail");
    writeln!(
        source,
        "    pub fn local_runner_path_from_env(mut self, name: &str) -> Self {{"
    )
    .expect("writing to String cannot fail");
    writeln!(source, "        if let Ok(path) = std::env::var(name) {{")
        .expect("writing to String cannot fail");
    writeln!(
        source,
        "            self.local_runner_path = Some(path.into());"
    )
    .expect("writing to String cannot fail");
    writeln!(source, "        }}").expect("writing to String cannot fail");
    writeln!(source, "        self").expect("writing to String cannot fail");
    writeln!(source, "    }}").expect("writing to String cannot fail");

    for entrypoint in &config.entrypoints {
        emit_entrypoint_method(
            source,
            crate_path,
            entrypoint,
            &input_clients,
            expected_clients,
        )?;
    }
    writeln!(source, "}}").expect("writing to String cannot fail");
    Ok(())
}

fn merge_semantic_payload(
    payloads: &mut std::collections::BTreeMap<String, (Vec<ShareType>, bool, bool)>,
    type_name: String,
    share_types: Vec<ShareType>,
    needs_input: bool,
    needs_output: bool,
) -> Result<()> {
    if let Some((existing_types, existing_input, existing_output)) = payloads.get_mut(&type_name) {
        if *existing_types != share_types {
            return Err(Error::Configuration(format!(
                "semantic binding type `{type_name}` was used with incompatible value shapes"
            )));
        }
        *existing_input |= needs_input;
        *existing_output |= needs_output;
    } else {
        payloads.insert(type_name, (share_types, needs_input, needs_output));
    }
    Ok(())
}

fn emit_semantic_payload(
    source: &mut String,
    crate_path: &str,
    derives: &[String],
    struct_name: &str,
    share_types: &[ShareType],
    needs_input: bool,
    needs_output: bool,
) -> Result<()> {
    if !derives.is_empty() {
        writeln!(source, "#[derive({})]", derives.join(", "))
            .expect("writing to String cannot fail");
    }
    writeln!(source, "pub struct {struct_name} {{").expect("writing to String cannot fail");
    for (ordinal, share_type) in share_types.iter().enumerate() {
        writeln!(
            source,
            "    pub value_{ordinal}: {},",
            rust_type(*share_type)?
        )
        .expect("writing to String cannot fail");
    }
    writeln!(source, "}}").expect("writing to String cannot fail");
    emit_share_payload_convenience(source, crate_path, struct_name, "value", share_types)?;
    if needs_input {
        emit_inputs_impl(source, crate_path, struct_name, "value", share_types)?;
    }
    if needs_output {
        emit_outputs_impl(source, crate_path, struct_name, "value", share_types)?;
    }
    Ok(())
}

fn emit_entrypoint_method(
    source: &mut String,
    crate_path: &str,
    entrypoint: &EntrypointBinding,
    input_clients: &[u64],
    expected_clients: u64,
) -> Result<()> {
    let output_struct = &entrypoint.output_type_name;
    let input_bindings = if entrypoint.inputs.is_empty() {
        input_clients
            .iter()
            .map(|client_slot| EntrypointInputBinding {
                client_slot: *client_slot,
                argument_name: format!("client{client_slot}_inputs"),
                type_name: format!("Client{client_slot}Inputs"),
            })
            .collect::<Vec<_>>()
    } else {
        entrypoint.inputs.clone()
    };
    writeln!(source).expect("writing to String cannot fail");
    write!(source, "    pub async fn {}(&self", entrypoint.method_name)
        .expect("writing to String cannot fail");
    for input in &input_bindings {
        write!(
            source,
            ", {}: impl std::convert::TryInto<{}>",
            input.argument_name, input.type_name
        )
        .expect("writing to String cannot fail");
    }
    writeln!(source, ") -> {crate_path}::Result<{output_struct}> {{")
        .expect("writing to String cannot fail");
    for input in &input_bindings {
        writeln!(
            source,
            "        let {}: {} = {}.try_into().map_err(|_| {crate_path}::Error::InvalidInput(\"invalid {}\".to_owned()))?;",
            input.argument_name,
            input.type_name,
            input.argument_name,
            input.argument_name
        )
        .expect("writing to String cannot fail");
    }
    writeln!(
        source,
        "        let mut program = {crate_path}::Stoffel::compile_file(&self.program_path)?"
    )
    .expect("writing to String cannot fail");
    writeln!(
        source,
        "            .entry_points([{:?}])",
        entrypoint.entrypoint
    )
    .expect("writing to String cannot fail");
    writeln!(
        source,
        "            .optimization_level(self.optimization_level)"
    )
    .expect("writing to String cannot fail");
    writeln!(source, "            .manifest::<ProgramManifest>()")
        .expect("writing to String cannot fail");
    writeln!(source, "            .parties(self.parties)").expect("writing to String cannot fail");
    writeln!(source, "            .threshold(self.threshold)")
        .expect("writing to String cannot fail");
    writeln!(
        source,
        "            .expected_output_clients({expected_clients}usize)"
    )
    .expect("writing to String cannot fail");
    writeln!(
        source,
        "            .client_output_count({}, {}u64)",
        entrypoint.output_client_slot,
        entrypoint.output_types.len()
    )
    .expect("writing to String cannot fail");
    for input in &input_bindings {
        writeln!(
            source,
            "            .with_client_input({}, &<{} as {crate_path}::TypedClientInputs>::into_values({}))",
            input.client_slot,
            input.type_name,
            input.argument_name
        )
        .expect("writing to String cannot fail");
    }
    writeln!(source, "            ;").expect("writing to String cannot fail");
    writeln!(
        source,
        "        if let Some(path) = &self.local_runner_path {{"
    )
    .expect("writing to String cannot fail");
    writeln!(
        source,
        "            program = program.local_runner_path(path);"
    )
    .expect("writing to String cannot fail");
    writeln!(source, "        }}").expect("writing to String cannot fail");
    writeln!(
        source,
        "        let (_returned, outputs) = program.execute_local_function_capturing_client_outputs_with_timeout(\"{}\", self.timeout).await?;",
        entrypoint.entrypoint
    )
    .expect("writing to String cannot fail");
    writeln!(
        source,
        "        let output = outputs.iter().find(|output| output.client_slot == {}).ok_or_else(|| {crate_path}::Error::Computation(\"client {} did not receive output\".to_owned()))?;",
        entrypoint.output_client_slot,
        entrypoint.output_client_slot
    )
    .expect("writing to String cannot fail");
    writeln!(
        source,
        "        <{output_struct} as {crate_path}::TypedClientOutputs>::from_values(output.values.clone())"
    )
    .expect("writing to String cannot fail");
    writeln!(source, "    }}").expect("writing to String cannot fail");
    Ok(())
}

fn rust_type(share_type: ShareType) -> Result<&'static str> {
    match share_type {
        ShareType::SecretField => Err(Error::Unsupported(
            "field shares require raw field output; bounded scalar bindings are not supported"
                .to_owned(),
        )),
        ShareType::SecretInt { bit_length: 1 } => Ok("bool"),
        ShareType::SecretInt { bit_length: 2..=8 } => Ok("i8"),
        ShareType::SecretInt { bit_length: 9..=16 } => Ok("i16"),
        ShareType::SecretInt {
            bit_length: 17..=32,
        } => Ok("i32"),
        ShareType::SecretInt {
            bit_length: 33..=64,
        } => Ok("i64"),
        ShareType::SecretUInt { bit_length: 1..=8 } => Ok("u8"),
        ShareType::SecretUInt { bit_length: 9..=16 } => Ok("u16"),
        ShareType::SecretUInt {
            bit_length: 17..=32,
        } => Ok("u32"),
        ShareType::SecretUInt {
            bit_length: 33..=64,
        } => Ok("u64"),
        ShareType::SecretFixedPoint { .. } => Ok("f64"),
        ShareType::SecretInt { bit_length } => Err(Error::Unsupported(format!(
            "cannot generate Rust binding for secret integer bit length {bit_length}"
        ))),
        ShareType::SecretUInt { bit_length } => Err(Error::Unsupported(format!(
            "cannot generate Rust binding for secret unsigned integer bit length {bit_length}"
        ))),
    }
}

fn client_value_type_variant(share_type: ShareType) -> Result<&'static str> {
    match share_type {
        ShareType::SecretField => Err(Error::Unsupported(
            "field shares require raw field output; bounded scalar bindings are not supported"
                .to_owned(),
        )),
        ShareType::SecretInt { bit_length: 1 } => Ok("Boolean"),
        ShareType::SecretInt { bit_length } if bit_length > 1 => Ok("Integer"),
        ShareType::SecretUInt { .. } => Ok("Integer"),
        ShareType::SecretFixedPoint { .. } => Ok("FixedPoint"),
        ShareType::SecretInt { bit_length } => Err(Error::Unsupported(format!(
            "cannot generate Rust binding for secret integer bit length {bit_length}"
        ))),
    }
}

fn sanitize_identifier(value: &str) -> String {
    let mut identifier = String::with_capacity(value.len());
    for (index, ch) in value.chars().enumerate() {
        if ch == '_' || ch.is_ascii_alphanumeric() {
            if index == 0 && ch.is_ascii_digit() {
                identifier.push('_');
            }
            identifier.push(ch);
        } else {
            identifier.push('_');
        }
    }
    if identifier.is_empty() {
        "_".to_owned()
    } else {
        identifier
    }
}

fn sanitize_type_name(value: &str) -> String {
    let mut out = String::new();
    for segment in value
        .split(|ch: char| ch == '_' || !ch.is_ascii_alphanumeric())
        .filter(|segment| !segment.is_empty())
    {
        let mut chars = segment.chars();
        if let Some(first) = chars.next() {
            if out.is_empty() && first.is_ascii_digit() {
                out.push('_');
            }
            out.push(first.to_ascii_uppercase());
            out.extend(chars);
        }
    }
    if out.is_empty() {
        "_".to_owned()
    } else {
        out
    }
}

fn entrypoint_output_struct_name(method_name: &str) -> String {
    let mut out = String::new();
    for segment in method_name.split('_').filter(|segment| !segment.is_empty()) {
        let mut chars = segment.chars();
        if let Some(first) = chars.next() {
            out.push(first.to_ascii_uppercase());
            out.extend(chars);
        }
    }
    if out.is_empty() {
        out.push_str("Entrypoint");
    }
    out.push_str("Output");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use stoffellang::stoffel_vm_types::compiled_binary::{ClientIoManifest, ClientIoSchema};

    #[test]
    fn generated_bindings_preserve_secret_integer_widths() -> Result<()> {
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

        let generated =
            generate_bindings_source(&Program::new(binary), &BindingsConfig::default())?;

        for (ordinal, rust_type) in ["i8", "i16", "i32", "i64", "u8", "u16", "u32", "u64"]
            .into_iter()
            .enumerate()
        {
            assert!(generated.contains(&format!("pub input_{ordinal}: {rust_type}")));
            assert!(generated.contains(&format!("pub output_{ordinal}: {rust_type}")));
        }

        Ok(())
    }

    #[test]
    fn generated_client_forwards_selected_optimization_level() -> Result<()> {
        let mut generated = String::new();
        emit_entrypoint_method(
            &mut generated,
            "stoffel",
            &EntrypointBinding::new("hash").output(0, "Digest", vec![ShareType::boolean()]),
            &[],
            1,
        )?;

        assert!(generated.contains(".optimization_level(self.optimization_level)"));
        Ok(())
    }
}
