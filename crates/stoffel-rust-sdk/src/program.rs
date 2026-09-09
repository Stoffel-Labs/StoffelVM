//! Compiled program metadata and bytecode helpers.
//!
//! `Program` wraps `stoffel-vm-types` bytecode and exposes SDK-friendly
//! metadata for functions, ClientStore schemas, and CLI-compatible bytecode
//! round trips.

use std::fmt;
use std::io::Cursor;
use std::path::Path;

use serde::{Deserialize, Serialize};
use stoffel_vm_types::compiled_binary::{
    utils, ClientIoManifest, ClientIoSchema, CompiledBinary, CompiledFunction, CompiledInstruction,
    FunctionType,
};
use stoffel_vm_types::core_types::{ShareType, Value as VmValue};
use stoffel_vm_types::registers::DEFAULT_SECRET_REGISTER_START;

use crate::compiler;
use crate::error::{Error, Result};
use crate::types::Value;

#[derive(Debug, Clone)]
pub struct Program {
    binary: CompiledBinary,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum LocalInputShape {
    Clear(Value),
    Share(ShareType),
    List(Vec<LocalInputShape>),
    Object(Vec<(String, LocalInputShape)>),
}

impl LocalInputShape {
    pub(crate) fn secret_from_value(value: &Value) -> Self {
        match value {
            Value::List(values) => Self::List(
                values
                    .iter()
                    .map(Self::secret_from_value)
                    .collect::<Vec<_>>(),
            ),
            Value::Object(fields) => Self::Object(
                fields
                    .iter()
                    .map(|(name, value)| (name.clone(), Self::secret_from_value(value)))
                    .collect(),
            ),
            Value::I64(_)
            | Value::U64(_)
            | Value::Float(_)
            | Value::String(_)
            | Value::Bytes(_)
            | Value::Unit => Self::Share(ShareType::default_secret_int()),
            Value::Bool(_) => Self::Share(ShareType::SecretInt { bit_length: 1 }),
        }
    }

    pub(crate) fn clear_from_value(value: &Value) -> Self {
        match value {
            Value::List(values) => Self::List(
                values
                    .iter()
                    .map(Self::clear_from_value)
                    .collect::<Vec<_>>(),
            ),
            Value::Object(fields) => Self::Object(
                fields
                    .iter()
                    .map(|(name, value)| (name.clone(), Self::clear_from_value(value)))
                    .collect(),
            ),
            value => Self::Clear(value.clone()),
        }
    }

    fn share_count(&self) -> usize {
        match self {
            Self::Clear(_) => 0,
            Self::Share(_) => 1,
            Self::List(items) => items.iter().map(Self::share_count).sum(),
            Self::Object(fields) => fields.iter().map(|(_, shape)| shape.share_count()).sum(),
        }
    }

    fn share_types(&self, out: &mut Vec<ShareType>) {
        match self {
            Self::Clear(_) => {}
            Self::Share(ty) => out.push(*ty),
            Self::List(items) => {
                for item in items {
                    item.share_types(out);
                }
            }
            Self::Object(fields) => {
                for (_, shape) in fields {
                    shape.share_types(out);
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramSummary {
    pub function_count: usize,
    pub function_names: Vec<String>,
    pub functions: Vec<FunctionSummary>,
    pub total_instruction_count: usize,
    pub total_register_count: usize,
    pub bytecode_backend: String,
    pub bytecode_curve: String,
    pub client_count: usize,
    pub client_slots: Vec<u64>,
    pub clients: Vec<ClientMetadataSummary>,
    pub total_client_input_count: usize,
    pub total_client_output_count: usize,
    pub minimum_expected_clients: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionSummary {
    pub name: String,
    pub arg_count: usize,
    pub parameters: Vec<String>,
    pub parameter_types: Vec<FunctionType>,
    pub return_type: FunctionType,
    pub register_count: usize,
    pub instruction_count: usize,
    pub upvalue_count: usize,
    pub parent: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientMetadataSummary {
    pub client_slot: u64,
    pub input_count: usize,
    pub output_count: usize,
    pub inputs: Vec<ShareType>,
    pub outputs: Vec<ShareType>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BytecodeSummary {
    pub byte_len: usize,
    pub program: ProgramSummary,
}

impl Program {
    pub fn new(binary: CompiledBinary) -> Self {
        Self { binary }
    }

    pub fn from_bytecode(bytecode: &[u8]) -> Result<Self> {
        compiler::load_bytecode(bytecode)
    }

    pub fn from_bytecode_file(path: impl AsRef<Path>) -> Result<Self> {
        let bytecode = std::fs::read(path)?;
        Self::from_bytecode(&bytecode)
    }

    pub fn to_bytecode(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.binary
            .serialize(&mut Cursor::new(&mut bytes))
            .map_err(|error| Error::Bytecode(format!("{error:?}")))?;
        Ok(bytes)
    }

    pub fn save_bytecode(&self, path: impl AsRef<Path>) -> Result<()> {
        utils::save_to_file(&self.binary, path)
            .map_err(|error| Error::Bytecode(format!("{error:?}")))
    }

    pub fn bytecode_summary(&self) -> Result<BytecodeSummary> {
        Ok(BytecodeSummary {
            byte_len: self.to_bytecode()?.len(),
            program: self.summary(),
        })
    }

    pub fn disassemble(&self) -> String {
        stoffellang::binary_converter::disassemble(&self.binary)
    }

    pub fn function_count(&self) -> usize {
        self.binary.functions.len()
    }

    pub fn function_names(&self) -> impl Iterator<Item = &str> {
        self.binary
            .functions
            .iter()
            .map(|function| function.name.as_str())
    }

    pub fn total_instruction_count(&self) -> usize {
        self.binary
            .functions
            .iter()
            .map(|function| function.instructions.len())
            .sum()
    }

    pub fn total_register_count(&self) -> usize {
        self.binary
            .functions
            .iter()
            .map(|function| function.register_count)
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.binary.functions.is_empty()
    }

    pub fn summary(&self) -> ProgramSummary {
        ProgramSummary {
            function_count: self.function_count(),
            function_names: self.function_names().map(ToOwned::to_owned).collect(),
            functions: self
                .functions()
                .map(|function| function.summary())
                .collect(),
            total_instruction_count: self.total_instruction_count(),
            total_register_count: self.total_register_count(),
            bytecode_backend: bytecode_backend_name(self.bytecode_backend()).to_owned(),
            bytecode_curve: bytecode_curve_name(self.bytecode_curve()).to_owned(),
            client_count: self.client_count(),
            client_slots: self.client_slots().collect(),
            clients: self.clients().map(|client| client.summary()).collect(),
            total_client_input_count: self.total_client_input_count(),
            total_client_output_count: self.total_client_output_count(),
            minimum_expected_clients: self.minimum_expected_clients(),
        }
    }

    pub fn client_io_manifest(&self) -> &ClientIoManifest {
        &self.binary.client_io_manifest
    }

    pub fn client_count(&self) -> usize {
        self.binary.client_io_manifest.clients.len()
    }

    pub fn client_slots(&self) -> impl Iterator<Item = u64> + '_ {
        self.binary
            .client_io_manifest
            .clients
            .iter()
            .map(|client| client.client_slot)
    }

    pub fn total_client_input_count(&self) -> usize {
        self.binary
            .client_io_manifest
            .clients
            .iter()
            .map(|client| client.inputs.len())
            .sum()
    }

    pub fn total_client_output_count(&self) -> usize {
        self.binary
            .client_io_manifest
            .clients
            .iter()
            .map(|client| client.outputs.len())
            .sum()
    }

    pub fn minimum_expected_clients(&self) -> usize {
        self.binary
            .client_io_manifest
            .clients
            .iter()
            .map(|client| usize::try_from(client.client_slot).unwrap_or(usize::MAX))
            .map(|client_slot| client_slot.saturating_add(1))
            .max()
            .unwrap_or(0)
    }

    pub fn has_client_io(&self) -> bool {
        !self.binary.client_io_manifest.clients.is_empty()
    }

    /// Whether the program reads client INPUTS via `ClientStore` (as opposed to
    /// only delivering client OUTPUTS via `send_to_client`). The local
    /// named-input adapter synthesizes the input wrapper itself, so it can only
    /// wrap programs that take their inputs as function parameters — i.e. those
    /// with no client input metadata. Output-only client IO is fine and is
    /// preserved through wrapping.
    pub fn has_client_input_metadata(&self) -> bool {
        self.binary
            .client_io_manifest
            .clients
            .iter()
            .any(|client| !client.inputs.is_empty())
    }

    pub fn validate_expected_clients(&self, expected_clients: usize) -> Result<()> {
        let minimum_expected_clients = self.minimum_expected_clients();
        if minimum_expected_clients > expected_clients {
            return Err(Error::Configuration(format!(
                "program declares ClientStore slot(s) requiring expected_clients >= {minimum_expected_clients}, but expected_clients is {expected_clients}"
            )));
        }
        Ok(())
    }

    pub fn validate_client_inputs(&self, inputs: &[(u64, &[Value])]) -> Result<()> {
        let has_declared_clients = self.has_client_io();
        if !has_declared_clients && inputs.is_empty() {
            return Ok(());
        }
        if has_declared_clients
            && inputs.is_empty()
            && self.clients().any(|metadata| metadata.input_count() > 0)
        {
            return Err(Error::Configuration(
                "program declares ClientStore input metadata; provide local client inputs"
                    .to_owned(),
            ));
        }
        if !has_declared_clients {
            let mut seen_slots = std::collections::HashSet::with_capacity(inputs.len());
            for (client_slot, _values) in inputs {
                if !seen_slots.insert(*client_slot) {
                    return Err(Error::Configuration(format!(
                        "client slot {client_slot} was provided more than once"
                    )));
                }
            }
            return Ok(());
        }

        let mut seen_slots = std::collections::HashSet::with_capacity(inputs.len());
        for (client_slot, values) in inputs {
            if !seen_slots.insert(*client_slot) {
                return Err(Error::Configuration(format!(
                    "client slot {client_slot} was provided more than once"
                )));
            }
            let Some(metadata) = self.client(*client_slot) else {
                return Err(Error::Configuration(format!(
                    "client slot {client_slot} is not declared in the program client IO manifest"
                )));
            };
            if metadata.input_count() != values.len() {
                return Err(Error::Configuration(format!(
                    "client slot {client_slot} expects {} inputs, got {}",
                    metadata.input_count(),
                    values.len()
                )));
            }
        }

        for metadata in self.clients() {
            if metadata.input_count() > 0 && !seen_slots.contains(&metadata.client_slot()) {
                return Err(Error::Configuration(format!(
                    "client slot {} is declared in the program client IO manifest but no input was provided",
                    metadata.client_slot()
                )));
            }
        }

        Ok(())
    }

    pub(crate) fn validate_owned_client_inputs(&self, inputs: &[(u64, Vec<Value>)]) -> Result<()> {
        let borrowed = inputs
            .iter()
            .map(|(client_slot, values)| (*client_slot, values.as_slice()))
            .collect::<Vec<_>>();
        self.validate_client_inputs(&borrowed)
    }

    pub fn clients(&self) -> impl Iterator<Item = ClientMetadata<'_>> {
        self.binary
            .client_io_manifest
            .clients
            .iter()
            .map(ClientMetadata)
    }

    pub fn client(&self, client_slot: u64) -> Option<ClientMetadata<'_>> {
        self.binary
            .client_io_manifest
            .clients
            .iter()
            .find(|client| client.client_slot == client_slot)
            .map(ClientMetadata)
    }

    pub fn bytecode_backend(&self) -> stoffel_vm_types::compiled_binary::MpcBackend {
        self.binary.client_io_manifest.mpc_backend
    }

    pub fn bytecode_curve(&self) -> stoffel_vm_types::compiled_binary::MpcCurve {
        self.binary.client_io_manifest.mpc_curve
    }

    pub(crate) fn with_local_client_input_wrapper(
        &self,
        call_name: &str,
        entry_name: &str,
        input_shapes: &[LocalInputShape],
    ) -> Result<Self> {
        if input_shapes.is_empty() {
            return Err(Error::Configuration(
                "local client input wrapper requires at least one input".to_owned(),
            ));
        }

        let mut binary = self.binary.clone();
        if binary
            .functions
            .iter()
            .any(|function| function.name == entry_name)
        {
            return Err(Error::Configuration(format!(
                "local client input wrapper entry '{entry_name}' already exists"
            )));
        }
        let Some(_target_function) = binary
            .functions
            .iter()
            .find(|function| function.name == call_name)
        else {
            return Err(Error::FunctionNotFound(call_name.to_owned()));
        };
        let input_count = input_shapes
            .iter()
            .map(LocalInputShape::share_count)
            .sum::<usize>();
        let mut input_types = Vec::with_capacity(input_count);
        for shape in input_shapes {
            shape.share_types(&mut input_types);
        }

        let mut instructions = Vec::with_capacity(input_count * 8 + input_shapes.len() + 2);
        let mut registers = WrapperRegisters::new();
        let mut next_share_index = 0usize;
        let mut arg_registers = Vec::with_capacity(input_shapes.len());
        for shape in input_shapes {
            let register = emit_local_input_shape(
                shape,
                &mut binary,
                &mut instructions,
                &mut next_share_index,
                &mut registers,
            )?;
            arg_registers.push(register);
        }
        for register in arg_registers {
            instructions.push(CompiledInstruction::PUSHARG(register));
        }
        instructions.push(CompiledInstruction::CALL(call_name.to_owned()));
        instructions.push(CompiledInstruction::RET(0));

        let register_count = registers.register_count();
        binary.functions.push(CompiledFunction {
            name: entry_name.to_owned(),
            register_count,
            parameters: Vec::new(),
            parameter_types: Vec::new(),
            return_type: FunctionType::Unknown,
            upvalues: Vec::new(),
            parent: None,
            labels: Default::default(),
            instructions,
        });

        // The wrapper synthesizes all client inputs (clear constants + secret
        // `take_share*` loads) on client slot 0, so it owns the input schema.
        // Any client OUTPUT schema the program declares (e.g. `send_to_client`)
        // is orthogonal and must be preserved, so a wrapped program can still
        // deliver results to its clients.
        if input_count > 0 {
            if let Some(client) = binary
                .client_io_manifest
                .clients
                .iter_mut()
                .find(|client| client.client_slot == 0)
            {
                client.inputs = input_types;
            } else {
                binary.client_io_manifest.clients.push(ClientIoSchema {
                    client_slot: 0,
                    inputs: input_types,
                    outputs: Vec::new(),
                });
            }
        }

        Ok(Self::new(binary))
    }

    pub fn functions(&self) -> impl Iterator<Item = FunctionMetadata<'_>> {
        self.binary.functions.iter().map(FunctionMetadata)
    }

    pub fn function(&self, name: &str) -> Option<FunctionMetadata<'_>> {
        self.binary
            .functions
            .iter()
            .find(|function| function.name == name)
            .map(FunctionMetadata)
    }

    pub fn main(&self) -> Option<FunctionMetadata<'_>> {
        self.function("main")
    }

    pub fn binary(&self) -> &CompiledBinary {
        &self.binary
    }

    pub fn validate_function_inputs(
        &self,
        function_name: &str,
        inputs: &[(String, Value)],
    ) -> Result<()> {
        let function = self
            .function(function_name)
            .ok_or_else(|| Error::FunctionNotFound(function_name.to_owned()))?;
        function.validate_inputs(inputs)
    }

    pub fn validate_function_args(&self, function_name: &str, args: &[Value]) -> Result<()> {
        let function = self
            .function(function_name)
            .ok_or_else(|| Error::FunctionNotFound(function_name.to_owned()))?;
        function.validate_args(args)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ClientMetadata<'a>(&'a ClientIoSchema);

impl<'a> ClientMetadata<'a> {
    pub fn client_slot(&self) -> u64 {
        self.0.client_slot
    }

    pub fn input_count(&self) -> usize {
        self.0.inputs.len()
    }

    pub fn output_count(&self) -> usize {
        self.0.outputs.len()
    }

    pub fn inputs(&self) -> &'a [ShareType] {
        &self.0.inputs
    }

    pub fn outputs(&self) -> &'a [ShareType] {
        &self.0.outputs
    }

    pub fn summary(&self) -> ClientMetadataSummary {
        ClientMetadataSummary {
            client_slot: self.client_slot(),
            input_count: self.input_count(),
            output_count: self.output_count(),
            inputs: self.inputs().to_vec(),
            outputs: self.outputs().to_vec(),
        }
    }
}

impl fmt::Display for ClientMetadata<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "client {}: {} input(s), {} output(s)",
            self.client_slot(),
            self.input_count(),
            self.output_count()
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FunctionMetadata<'a>(&'a CompiledFunction);

impl<'a> FunctionMetadata<'a> {
    pub fn name(&self) -> &str {
        &self.0.name
    }

    pub fn arg_count(&self) -> usize {
        self.0.parameters.len()
    }

    pub fn parameters(&self) -> &[String] {
        &self.0.parameters
    }

    pub fn parameter_names(&self) -> impl Iterator<Item = &str> {
        self.0.parameters.iter().map(String::as_str)
    }

    pub fn parameter_types(&self) -> &[FunctionType] {
        &self.0.parameter_types
    }

    pub fn return_type(&self) -> &FunctionType {
        &self.0.return_type
    }

    pub fn register_count(&self) -> usize {
        self.0.register_count
    }

    pub fn instruction_count(&self) -> usize {
        self.0.instructions.len()
    }

    pub fn upvalue_count(&self) -> usize {
        self.0.upvalues.len()
    }

    pub fn parent(&self) -> Option<&str> {
        self.0.parent.as_deref()
    }

    pub fn summary(&self) -> FunctionSummary {
        FunctionSummary {
            name: self.name().to_owned(),
            arg_count: self.arg_count(),
            parameters: self.parameters().to_vec(),
            parameter_types: self.parameter_types().to_vec(),
            return_type: self.return_type().clone(),
            register_count: self.register_count(),
            instruction_count: self.instruction_count(),
            upvalue_count: self.upvalue_count(),
            parent: self.parent().map(ToOwned::to_owned),
        }
    }

    pub fn validate_inputs(&self, inputs: &[(String, Value)]) -> Result<()> {
        for (name, _) in inputs {
            if !self.0.parameters.iter().any(|parameter| parameter == name) {
                return Err(Error::InvalidInput(format!(
                    "unexpected input '{name}' for function '{}'",
                    self.name()
                )));
            }
        }

        for parameter in &self.0.parameters {
            let mut matches = inputs.iter().filter(|(name, _)| name == parameter);
            let Some((_, value)) = matches.next() else {
                return Err(Error::InvalidInput(format!(
                    "missing input '{parameter}' for function '{}'",
                    self.name()
                )));
            };
            if matches.next().is_some() {
                return Err(Error::InvalidInput(format!(
                    "duplicate input '{parameter}' for function '{}'",
                    self.name()
                )));
            }
            let ty = self
                .0
                .parameter_types
                .get(
                    self.0
                        .parameters
                        .iter()
                        .position(|name| name == parameter)
                        .unwrap_or(usize::MAX),
                )
                .unwrap_or(&FunctionType::Unknown);
            validate_value_against_function_type(parameter, value, ty)?;
        }

        Ok(())
    }

    pub fn validate_args(&self, args: &[Value]) -> Result<()> {
        let expected = self.arg_count();
        let actual = args.len();
        if actual != expected {
            return Err(Error::InvalidInput(format!(
                "function '{}' expects {expected} argument(s), got {actual}",
                self.name()
            )));
        }

        for (index, value) in args.iter().enumerate() {
            let parameter = self
                .0
                .parameters
                .get(index)
                .map(String::as_str)
                .unwrap_or("argument");
            let ty = self
                .0
                .parameter_types
                .get(index)
                .unwrap_or(&FunctionType::Unknown);
            validate_value_against_function_type(parameter, value, ty)?;
        }

        Ok(())
    }
}

impl fmt::Display for FunctionMetadata<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}(", self.name())?;
        for (index, parameter) in self.parameter_names().enumerate() {
            if index > 0 {
                f.write_str(", ")?;
            }
            f.write_str(parameter)?;
        }
        write!(f, ")")
    }
}

fn validate_value_against_function_type(
    path: &str,
    value: &Value,
    ty: &FunctionType,
) -> Result<()> {
    let expected = ty.underlying_type();
    if expected.is_unknown_like() {
        return Ok(());
    }

    match expected {
        FunctionType::Int { signed, bits } => validate_integer(path, value, *signed, *bits),
        FunctionType::Float | FunctionType::Fixed { .. } => match value {
            Value::Float(_) | Value::I64(_) | Value::U64(_) => Ok(()),
            _ => invalid_type(path, expected, value),
        },
        FunctionType::String => match value {
            Value::String(_) => Ok(()),
            _ => invalid_type(path, expected, value),
        },
        FunctionType::Bool => match value {
            Value::Bool(_) => Ok(()),
            _ => invalid_type(path, expected, value),
        },
        FunctionType::Nil | FunctionType::Void => match value {
            Value::Unit => Ok(()),
            _ => invalid_type(path, expected, value),
        },
        FunctionType::List(element_type) => match value {
            Value::List(values) => values.iter().enumerate().try_for_each(|(index, item)| {
                validate_value_against_function_type(&format!("{path}[{index}]"), item, element_type)
            }),
            _ => invalid_type(path, expected, value),
        },
        FunctionType::Dict(key_type, value_type) => match value {
            Value::Object(fields) => fields.iter().try_for_each(|(key, item)| {
                if !key_type.is_unknown_like() && !matches!(key_type.underlying_type(), FunctionType::String) {
                    return Err(Error::InvalidInput(format!(
                        "input '{path}' expects {expected}, but SDK object inputs only provide string keys"
                    )));
                }
                validate_value_against_function_type(&format!("{path}.{key}"), item, value_type)
            }),
            _ => invalid_type(path, expected, value),
        },
        FunctionType::Object(_) => match value {
            Value::Object(_) => Ok(()),
            _ => invalid_type(path, expected, value),
        },
        FunctionType::Secret(_)
        | FunctionType::Generic(_, _)
        | FunctionType::TypeVar(_)
        | FunctionType::Unknown => Ok(()),
    }
}

fn validate_integer(path: &str, value: &Value, signed: bool, bits: u8) -> Result<()> {
    let max_unsigned = if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    if signed {
        let max = if bits >= 64 {
            i64::MAX
        } else {
            (1i64 << (bits - 1)) - 1
        };
        let min = if bits >= 64 {
            i64::MIN
        } else {
            -(1i64 << (bits - 1))
        };
        match value {
            Value::I64(value) if *value >= min && *value <= max => Ok(()),
            Value::U64(value) if *value <= max as u64 => Ok(()),
            _ => invalid_type(path, &FunctionType::Int { signed, bits }, value),
        }
    } else {
        match value {
            Value::U64(value) if *value <= max_unsigned => Ok(()),
            Value::I64(value) if *value >= 0 && (*value as u64) <= max_unsigned => Ok(()),
            _ => invalid_type(path, &FunctionType::Int { signed, bits }, value),
        }
    }
}

fn invalid_type(path: &str, expected: &FunctionType, value: &Value) -> Result<()> {
    Err(Error::InvalidInput(format!(
        "input '{path}' expects {expected}, got {}",
        value.kind()
    )))
}

fn bytecode_backend_name(backend: stoffel_vm_types::compiled_binary::MpcBackend) -> &'static str {
    match backend {
        stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger => "honeybadger",
        stoffel_vm_types::compiled_binary::MpcBackend::Avss => "avss",
    }
}

fn bytecode_curve_name(curve: stoffel_vm_types::compiled_binary::MpcCurve) -> &'static str {
    match curve {
        stoffel_vm_types::compiled_binary::MpcCurve::Bls12_381 => "bls12_381",
        stoffel_vm_types::compiled_binary::MpcCurve::Bn254 => "bn254",
        stoffel_vm_types::compiled_binary::MpcCurve::Curve25519 => "curve25519",
        stoffel_vm_types::compiled_binary::MpcCurve::Ed25519 => "ed25519",
        stoffel_vm_types::compiled_binary::MpcCurve::Secp256k1 => "secp256k1",
        stoffel_vm_types::compiled_binary::MpcCurve::Secp256r1 => "p-256",
    }
}

/// Register-frame bookkeeping for the local input wrapper.
///
/// The VM splits the register frame into a clear bank (indices below
/// [`DEFAULT_SECRET_REGISTER_START`]) and a secret bank (at or above it), so a
/// clear value must live in a low index and a secret share in a high one. The
/// wrapper builds aggregate (list/object) inputs by materializing each element
/// into a temporary register and immediately consuming it with `array_push`/
/// `set_field`; those element registers are dead afterwards, so we reuse them
/// instead of allocating one per element (a 128-element list would otherwise
/// overflow the 14-slot clear bank and corrupt the secret bank). `next_*` is the
/// reusable cursor and `high_*` is the high-water mark used to size the frame.
struct WrapperRegisters {
    next_clear: usize,
    next_secret: usize,
    high_clear: usize,
    high_secret: usize,
    used_secret: bool,
}

impl WrapperRegisters {
    /// Registers 0 and 1 are scratch for the builtin call ABI (return value and
    /// argument staging), so clear allocation starts at 2.
    const FIRST_CLEAR_REGISTER: usize = 2;

    fn new() -> Self {
        Self {
            next_clear: Self::FIRST_CLEAR_REGISTER,
            next_secret: DEFAULT_SECRET_REGISTER_START,
            high_clear: Self::FIRST_CLEAR_REGISTER,
            high_secret: DEFAULT_SECRET_REGISTER_START,
            used_secret: false,
        }
    }

    fn allocate_clear(&mut self) -> usize {
        let register = self.next_clear;
        self.next_clear += 1;
        self.high_clear = self.high_clear.max(self.next_clear);
        register
    }

    fn allocate_secret(&mut self) -> usize {
        let register = self.next_secret;
        self.next_secret += 1;
        self.high_secret = self.high_secret.max(self.next_secret);
        self.used_secret = true;
        register
    }

    fn register_count(&self) -> usize {
        if self.used_secret {
            self.high_clear.max(self.high_secret)
        } else {
            self.high_clear
        }
    }
}

fn emit_local_input_shape(
    shape: &LocalInputShape,
    binary: &mut CompiledBinary,
    instructions: &mut Vec<CompiledInstruction>,
    next_share_index: &mut usize,
    registers: &mut WrapperRegisters,
) -> Result<usize> {
    match shape {
        LocalInputShape::Clear(value) => {
            let dest = registers.allocate_clear();
            let const_index = binary.constants.len();
            binary
                .constants
                .push(clear_sdk_value_to_vm_constant(value)?);
            instructions.push(CompiledInstruction::LDI(dest, const_index));
            Ok(dest)
        }
        LocalInputShape::Share(share_type) => {
            let dest = registers.allocate_secret();
            let client_index_const = binary.constants.len();
            binary.constants.push(VmValue::U64(0));
            let share_index_const = binary.constants.len();
            binary
                .constants
                .push(VmValue::U64(*next_share_index as u64));
            *next_share_index += 1;
            instructions.push(CompiledInstruction::LDI(0, client_index_const));
            instructions.push(CompiledInstruction::LDI(1, share_index_const));
            instructions.push(CompiledInstruction::PUSHARG(0));
            instructions.push(CompiledInstruction::PUSHARG(1));
            // Pick the ClientStore loader that tags the share with the declared
            // type. The boolean gates (NOT/AND/XOR) reject the default 64-bit
            // integer share, so a 1-bit secret must be loaded via
            // `take_share_bool`; fixed-point likewise needs `take_share_fixed`.
            let take_method = match share_type {
                ShareType::SecretInt { bit_length: 1 } => "ClientStore.take_share_bool",
                ShareType::SecretFixedPoint { .. } => "ClientStore.take_share_fixed",
                _ => "ClientStore.take_share",
            };
            instructions.push(CompiledInstruction::CALL(take_method.to_owned()));
            instructions.push(CompiledInstruction::MOV(dest, 0));
            Ok(dest)
        }
        LocalInputShape::List(items) => {
            let dest = registers.allocate_clear();
            instructions.push(CompiledInstruction::CALL("create_array".to_owned()));
            instructions.push(CompiledInstruction::MOV(dest, 0));
            for item in items {
                // Each element is consumed immediately by `array_push`, so its
                // register is dead afterwards: snapshot the cursors, emit, push,
                // then rewind to reuse the registers for the next element. The
                // array handle in `dest` was allocated before the snapshot, so
                // it survives.
                let saved_clear = registers.next_clear;
                let saved_secret = registers.next_secret;
                let item_register = emit_local_input_shape(
                    item,
                    binary,
                    instructions,
                    next_share_index,
                    registers,
                )?;
                instructions.push(CompiledInstruction::PUSHARG(dest));
                instructions.push(CompiledInstruction::PUSHARG(item_register));
                instructions.push(CompiledInstruction::CALL("array_push".to_owned()));
                registers.next_clear = saved_clear;
                registers.next_secret = saved_secret;
            }
            Ok(dest)
        }
        LocalInputShape::Object(fields) => {
            let dest = registers.allocate_clear();
            instructions.push(CompiledInstruction::CALL("create_object".to_owned()));
            instructions.push(CompiledInstruction::MOV(dest, 0));
            for (field_name, field_shape) in fields {
                // Key and value are both live until `set_field`, then dead;
                // rewind afterwards so the next field reuses their registers.
                let saved_clear = registers.next_clear;
                let saved_secret = registers.next_secret;
                let key_register = registers.allocate_clear();
                let key_const = binary.constants.len();
                binary.constants.push(VmValue::String(field_name.clone()));
                instructions.push(CompiledInstruction::LDI(key_register, key_const));
                let value_register = emit_local_input_shape(
                    field_shape,
                    binary,
                    instructions,
                    next_share_index,
                    registers,
                )?;
                instructions.push(CompiledInstruction::PUSHARG(dest));
                instructions.push(CompiledInstruction::PUSHARG(key_register));
                instructions.push(CompiledInstruction::PUSHARG(value_register));
                instructions.push(CompiledInstruction::CALL("set_field".to_owned()));
                registers.next_clear = saved_clear;
                registers.next_secret = saved_secret;
            }
            Ok(dest)
        }
    }
}

fn clear_sdk_value_to_vm_constant(value: &Value) -> Result<VmValue> {
    match value {
        Value::I64(value) => Ok(VmValue::I64(*value)),
        Value::U64(value) => Ok(VmValue::U64(*value)),
        Value::Bool(value) => Ok(VmValue::Bool(*value)),
        Value::Float(value) => Ok(VmValue::Float((*value).into())),
        Value::String(value) => Ok(VmValue::String(value.clone())),
        Value::Unit => Ok(VmValue::Unit),
        Value::Bytes(_) => Err(Error::InvalidInput(
            "clear byte values cannot be embedded in local named-input wrappers".to_owned(),
        )),
        Value::List(_) | Value::Object(_) => Err(Error::InvalidInput(
            "internal error: structured clear value was not lowered recursively".to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MpcBackend;

    #[test]
    fn local_client_input_wrapper_places_secret_inputs_in_secret_registers() -> Result<()> {
        let program = crate::compiler::compile_source(
            "def main(a: secret int64, b: secret int64) -> secret int64:\n  return a + b",
            "test.stfl",
            MpcBackend::HoneyBadger,
        )?;

        let wrapped = program.with_local_client_input_wrapper(
            "main",
            "__stoffel_sdk_local_entry",
            &[
                LocalInputShape::Share(ShareType::default_secret_int()),
                LocalInputShape::Share(ShareType::default_secret_int()),
            ],
        )?;
        let wrapper = wrapped
            .binary
            .functions
            .iter()
            .find(|function| function.name == "__stoffel_sdk_local_entry")
            .expect("wrapper function should be present");

        assert!(wrapper.register_count >= DEFAULT_SECRET_REGISTER_START + 2);
        assert!(
            wrapper
                .instructions
                .contains(&CompiledInstruction::MOV(DEFAULT_SECRET_REGISTER_START, 0)),
            "first ClientStore share must be moved into a secret register"
        );
        assert!(
            wrapper.instructions.contains(&CompiledInstruction::MOV(
                DEFAULT_SECRET_REGISTER_START + 1,
                0
            )),
            "second ClientStore share must be moved into a secret register"
        );

        let main_call = wrapper
            .instructions
            .iter()
            .position(|instruction| {
                matches!(instruction, CompiledInstruction::CALL(name) if name == "main")
            })
            .expect("wrapper should call main");
        assert_eq!(
            &wrapper.instructions[main_call - 2..main_call],
            &[
                CompiledInstruction::PUSHARG(DEFAULT_SECRET_REGISTER_START),
                CompiledInstruction::PUSHARG(DEFAULT_SECRET_REGISTER_START + 1),
            ]
        );
        assert!(
            !wrapper.instructions.iter().any(
                |instruction| matches!(instruction, CompiledInstruction::CALL(name) if name == "Share.open")
            ),
            "the local wrapper should return the secret VM value without inserting an open"
        );

        Ok(())
    }

    #[test]
    fn local_client_input_wrapper_preserves_secret_bool_share_type() -> Result<()> {
        let program = crate::compiler::compile_source(
            "def main(a: list[secret bool]) -> bool:\n  return a[0].reveal()",
            "test.stfl",
            MpcBackend::HoneyBadger,
        )?;

        let wrapped = program.with_local_client_input_wrapper(
            "main",
            "__stoffel_sdk_local_entry",
            &[LocalInputShape::List(vec![
                LocalInputShape::Share(ShareType::SecretInt { bit_length: 1 }),
                LocalInputShape::Share(ShareType::SecretInt { bit_length: 1 }),
            ])],
        )?;

        assert_eq!(
            wrapped.binary.client_io_manifest.clients[0].inputs,
            vec![
                ShareType::SecretInt { bit_length: 1 },
                ShareType::SecretInt { bit_length: 1 },
            ]
        );
        Ok(())
    }

    #[test]
    fn local_client_input_wrapper_keeps_clear_only_inputs_in_clear_registers() -> Result<()> {
        let program = crate::compiler::compile_source(
            "def main(a: int64, b: int64) -> int64:\n  return a + b",
            "test.stfl",
            MpcBackend::HoneyBadger,
        )?;

        let wrapped = program.with_local_client_input_wrapper(
            "main",
            "__stoffel_sdk_local_entry",
            &[
                LocalInputShape::Clear(Value::I64(1)),
                LocalInputShape::Clear(Value::I64(2)),
            ],
        )?;
        let wrapper = wrapped
            .binary
            .functions
            .iter()
            .find(|function| function.name == "__stoffel_sdk_local_entry")
            .expect("wrapper function should be present");

        assert!(wrapper.register_count < DEFAULT_SECRET_REGISTER_START);
        assert!(
            wrapped.binary.client_io_manifest.clients.is_empty(),
            "clear-only named input wrappers must not declare client input metadata"
        );

        Ok(())
    }
}
