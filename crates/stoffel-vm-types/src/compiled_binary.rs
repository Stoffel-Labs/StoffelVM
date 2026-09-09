//! # Compiled Binary Format for StoffelVM
//!
//! This module defines the binary format used to represent compiled StoffelVM programs.
//! It provides a portable structure that can be shared between the VM and compiler,
//! allowing for seamless interoperability.
//!
//! The binary format consists of:
//! - A header with magic bytes "STFL" and version information
//! - A constant pool for shared values
//! - A function table with metadata about each function
//! - Function bodies containing the actual instructions
//!
//! This module is designed to be portable and can be copied directly to the compiler
//! codebase without modification.

use crate::core_types::{F64, FixedPointPrecision, ShareType, Value};
use crate::functions::{FunctionError, ResolvedFunctionHeader, VMFunction};
use crate::instructions::{
    Instruction, ReducedOpcode, ResolvedInstruction, ResolvedInstructionInput,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::{self, Read, Write};

// Magic bytes that identify a StoffelVM bytecode file
pub const MAGIC_BYTES: &[u8; 4] = b"STFL";
// Current bytecode format version
// v10: added runtime-client input templates to the client-IO manifest
pub const FORMAT_VERSION: u16 = 10;
pub const CLIENT_IO_MANIFEST_FORMAT_VERSION: u16 = 2;
pub const MPC_BACKEND_MANIFEST_FORMAT_VERSION: u16 = 3;
pub const MPC_CURVE_MANIFEST_FORMAT_VERSION: u16 = 4;
pub const FUNCTION_TYPE_METADATA_FORMAT_VERSION: u16 = 5;
/// Version at which the client IO manifest carries a `PreprocessingDemand`.
pub const PREPROCESSING_DEMAND_MANIFEST_FORMAT_VERSION: u16 = 8;
/// Version at which the client IO manifest can describe homogeneous client
/// inputs whose slots are selected at runtime by `get_number_clients()`.
pub const DYNAMIC_CLIENT_INPUT_MANIFEST_FORMAT_VERSION: u16 = 10;

const MAX_BINARY_COLLECTION_LEN: usize = 1_000_000;
/// Per-function instruction vectors are allowed to grow far larger than the
/// generic collection bound: a fully-unrolled MPC circuit (e.g. AES-128 at -O3
/// with raised inline/unroll budgets) legitimately reaches ~2M instructions.
/// Keep this finite as a guardrail against a corrupt length field triggering a
/// multi-GB allocation, but size it with headroom over the largest real circuit.
const MAX_INSTRUCTION_COUNT: usize = 8_000_000;
const MAX_BINARY_STRING_BYTES: usize = 16 * 1024 * 1024;

/// Error types that can occur during serialization or deserialization
#[derive(Debug)]
pub enum BinaryError {
    /// An I/O error occurred
    IoError(io::Error),
    /// Invalid magic bytes in the file header
    InvalidMagicBytes,
    /// Unsupported format version
    UnsupportedVersion(u16),
    /// Invalid data in the bytecode file
    InvalidData(String),
}

impl From<io::Error> for BinaryError {
    fn from(error: io::Error) -> Self {
        BinaryError::IoError(error)
    }
}

impl From<FunctionError> for BinaryError {
    fn from(error: FunctionError) -> Self {
        invalid_data(error.to_string())
    }
}

/// Result type for binary operations
pub type BinaryResult<T> = Result<T, BinaryError>;

fn invalid_data(message: impl Into<String>) -> BinaryError {
    BinaryError::InvalidData(message.into())
}

fn normalized_parameter_types(function: &CompiledFunction) -> Vec<FunctionType> {
    let mut parameter_types = function.parameter_types.clone();
    parameter_types.resize(function.parameters.len(), FunctionType::Unknown);
    parameter_types.truncate(function.parameters.len());
    parameter_types
}

fn resolve_compiled_label(
    label: &str,
    labels: &HashMap<String, usize>,
    instruction_count: usize,
) -> BinaryResult<usize> {
    let target = labels
        .get(label)
        .copied()
        .ok_or_else(|| invalid_data(format!("unknown label '{label}'")))?;
    if target > instruction_count {
        return Err(invalid_data(format!(
            "label '{label}' points past the instruction stream: {target} > {instruction_count}"
        )));
    }
    Ok(target)
}

fn compact_resolved_operand(field: &'static str, value: usize) -> BinaryResult<u32> {
    u32::try_from(value).map_err(|_| invalid_data(format!("{field} {value} exceeds u32::MAX")))
}

pub struct ResolvedInstructionReader<'a, R: Read> {
    reader: &'a mut R,
    name: String,
    parameters: Vec<String>,
    upvalues: Vec<String>,
    parent: Option<String>,
    register_count: usize,
    labels: HashMap<String, usize>,
    constants: &'a [Value],
    instruction_count: usize,
    remaining: usize,
    instruction_index: usize,
    hasher: DefaultHasher,
}

impl<R: Read> ResolvedInstructionReader<'_, R> {
    pub fn header(&self) -> ResolvedFunctionHeader {
        ResolvedFunctionHeader {
            name: self.name.clone(),
            parameters: self.parameters.clone(),
            upvalues: self.upvalues.clone(),
            parent: self.parent.clone(),
            register_count: self.register_count,
            instruction_count: self.instruction_count,
        }
    }

    pub fn next_instruction(&mut self) -> BinaryResult<Option<ResolvedInstructionInput>> {
        if self.remaining == 0 {
            return Ok(None);
        }

        let instruction = CompiledBinary::deserialize_instruction(self.reader)?;
        instruction.hash(&mut self.hasher);
        let instruction_index = self.instruction_index;
        self.instruction_index += 1;
        self.remaining -= 1;

        CompiledBinary::compiled_instruction_into_resolved_input(
            instruction,
            &self.labels,
            self.instruction_count,
            |const_idx| {
                self.constants.get(const_idx).cloned().ok_or_else(|| {
                    invalid_data(format!(
                        "Function instruction {} references constant {} but constant pool has {} values",
                        instruction_index,
                        const_idx,
                        self.constants.len()
                    ))
                })
            },
        )
        .map(Some)
    }

    fn drain(&mut self) -> BinaryResult<()> {
        while self.next_instruction()?.is_some() {}
        Ok(())
    }

    fn finish(self) -> u64 {
        self.hasher.finish()
    }
}

fn usize_to_u16(value: usize, field: &str) -> BinaryResult<u16> {
    u16::try_from(value).map_err(|_| invalid_data(format!("{field} {value} exceeds u16::MAX")))
}

fn usize_to_u32(value: usize, field: &str) -> BinaryResult<u32> {
    u32::try_from(value).map_err(|_| invalid_data(format!("{field} {value} exceeds u32::MAX")))
}

fn write_usize_as_u16<W: Write>(writer: &mut W, value: usize, field: &str) -> BinaryResult<()> {
    writer.write_all(&usize_to_u16(value, field)?.to_le_bytes())?;
    Ok(())
}

fn write_usize_as_u32<W: Write>(writer: &mut W, value: usize, field: &str) -> BinaryResult<()> {
    writer.write_all(&usize_to_u32(value, field)?.to_le_bytes())?;
    Ok(())
}

fn write_len_prefixed_str_u16<W: Write>(
    writer: &mut W,
    value: &str,
    field: &str,
) -> BinaryResult<()> {
    let bytes = value.as_bytes();
    write_usize_as_u16(writer, bytes.len(), field)?;
    writer.write_all(bytes)?;
    Ok(())
}

fn write_len_prefixed_str_u32<W: Write>(
    writer: &mut W,
    value: &str,
    field: &str,
) -> BinaryResult<()> {
    let bytes = value.as_bytes();
    write_usize_as_u32(writer, bytes.len(), field)?;
    writer.write_all(bytes)?;
    Ok(())
}

fn read_u16<R: Read>(reader: &mut R) -> BinaryResult<u16> {
    let mut bytes = [0u8; 2];
    reader.read_exact(&mut bytes)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u8<R: Read>(reader: &mut R) -> BinaryResult<u8> {
    let mut bytes = [0u8; 1];
    reader.read_exact(&mut bytes)?;
    Ok(bytes[0])
}

fn read_u32<R: Read>(reader: &mut R) -> BinaryResult<u32> {
    let mut bytes = [0u8; 4];
    reader.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64<R: Read>(reader: &mut R) -> BinaryResult<u64> {
    let mut bytes = [0u8; 8];
    reader.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_usize_u32<R: Read>(reader: &mut R, field: &str) -> BinaryResult<usize> {
    let value = read_u32(reader)?;
    usize::try_from(value).map_err(|_| invalid_data(format!("{field} {value} exceeds usize::MAX")))
}

fn read_u32_len_bounded<R: Read>(reader: &mut R, field: &str, max: usize) -> BinaryResult<usize> {
    let value = read_u32(reader)?;
    let max_u32 = u32::try_from(max).unwrap_or(u32::MAX);
    if value > max_u32 {
        return Err(invalid_data(format!(
            "{field} {value} exceeds maximum supported {max}"
        )));
    }
    usize::try_from(value).map_err(|_| invalid_data(format!("{field} {value} exceeds usize::MAX")))
}

fn read_exact_vec<R: Read>(reader: &mut R, len: usize, field: &str) -> BinaryResult<Vec<u8>> {
    if len > MAX_BINARY_STRING_BYTES {
        return Err(invalid_data(format!(
            "{field} {len} exceeds maximum supported {MAX_BINARY_STRING_BYTES}"
        )));
    }

    let mut bytes = Vec::new();
    bytes.try_reserve_exact(len).map_err(|err| {
        invalid_data(format!("{field} {len} bytes could not be allocated: {err}"))
    })?;
    bytes.resize(len, 0);
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn read_len_prefixed_string_u16<R: Read>(
    reader: &mut R,
    field: &str,
    invalid_utf8: &str,
) -> BinaryResult<String> {
    let len = usize::from(read_u16(reader)?);
    let bytes = read_exact_vec(reader, len, field)?;
    String::from_utf8(bytes).map_err(|_| invalid_data(invalid_utf8))
}

fn read_len_prefixed_string_u32<R: Read>(
    reader: &mut R,
    field: &str,
    invalid_utf8: &str,
) -> BinaryResult<String> {
    let len = read_u32_len_bounded(reader, field, MAX_BINARY_STRING_BYTES)?;
    let bytes = read_exact_vec(reader, len, field)?;
    String::from_utf8(bytes).map_err(|_| invalid_data(invalid_utf8))
}

fn reserve_vec<T>(values: &mut Vec<T>, len: usize, field: &str) -> BinaryResult<()> {
    values
        .try_reserve(len)
        .map_err(|err| invalid_data(format!("{field} {len} could not be allocated: {err}")))
}

/// Represents a compiled StoffelVM program
///
/// This struct contains all the information needed to execute a program in the VM,
/// including constants, functions, and their instructions.
#[derive(Debug, Clone)]
pub struct CompiledBinary {
    /// Version of the binary format
    pub version: u16,
    /// Shared constant pool
    pub constants: Vec<Value>,
    /// Functions in the program
    pub functions: Vec<CompiledFunction>,
    /// VM-backed client input/output schema metadata.
    pub client_io_manifest: ClientIoManifest,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientIoManifest {
    pub mpc_backend: MpcBackend,
    pub mpc_curve: MpcCurve,
    pub clients: Vec<ClientIoSchema>,
    /// Static estimate of the MPC preprocessing material the program consumes,
    /// emitted by the compiler so the runtime can pre-generate enough up front.
    /// `#[serde(default)]` keeps older binaries (without this field) loadable.
    #[serde(default)]
    pub preprocessing_demand: PreprocessingDemand,
    /// Homogeneous input schemas for client slots reached through a runtime
    /// `ClientStore.get_number_clients()` loop. Each template applies from
    /// `first_client_slot` onward; a concrete schema in `clients` takes
    /// precedence.
    #[serde(default)]
    pub dynamic_client_inputs: Vec<DynamicClientInputSchema>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynamicClientInputSchema {
    pub first_client_slot: u64,
    pub inputs: Vec<ShareType>,
}

impl ClientIoManifest {
    /// Resolve the semantic input layout for a runtime client slot. Concrete
    /// schemas win; otherwise the most specific dynamic template applies.
    pub fn input_types_for_client_slot(&self, client_slot: u64) -> Option<&[ShareType]> {
        let concrete = self
            .clients
            .iter()
            .find(|schema| schema.client_slot == client_slot);
        if let Some(schema) = concrete.filter(|schema| !schema.inputs.is_empty()) {
            return Some(&schema.inputs);
        }
        let dynamic = self
            .dynamic_client_inputs
            .iter()
            .filter(|schema| schema.first_client_slot <= client_slot)
            .max_by_key(|schema| schema.first_client_slot)
            .map(|schema| schema.inputs.as_slice());
        dynamic.or_else(|| concrete.map(|schema| schema.inputs.as_slice()))
    }
}

/// Compiler estimate of preprocessing material a program consumes, used to size
/// the runtime preprocessing pass. Counts are *static estimates* weighted by
/// literal loop bounds; `dynamic` flags that the true demand may exceed the
/// estimate (e.g. data-dependent loops, recursion, or runtime-sized batches),
/// so the runtime should also be ready to top up on the fly.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreprocessingDemand {
    /// Beaver triples — one per secret*secret multiplication.
    pub triples: u64,
    /// Program-visible random field shares — masks for inputs/reveals and
    /// direct `Share.random_field` requests. Backends may allocate extra
    /// internal randoms for derived material such as triples.
    pub randoms: u64,
    /// Random bits — `frac_bits` per secret fixed-point division (truncation).
    pub prandbits: u64,
    /// Random integers — one per direct `Share.random_int` request (including
    /// typed `Share.random`, which lowers to it) and one per secret fixed-point
    /// division (truncation).
    pub prandints: u64,
    /// True when the static estimate may undercount (data-dependent loops,
    /// recursion, or runtime-sized batch operations).
    pub dynamic: bool,
}

impl PreprocessingDemand {
    /// Add another op's demand, saturating.
    pub fn add(&mut self, triples: u64, randoms: u64, prandbits: u64, prandints: u64) {
        self.triples = self.triples.saturating_add(triples);
        self.randoms = self.randoms.saturating_add(randoms);
        self.prandbits = self.prandbits.saturating_add(prandbits);
        self.prandints = self.prandints.saturating_add(prandints);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientIoSchema {
    pub client_slot: u64,
    pub inputs: Vec<ShareType>,
    pub outputs: Vec<ShareType>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FunctionType {
    Int {
        signed: bool,
        bits: u8,
    },
    Float,
    Fixed {
        bits: u8,
    },
    String,
    Bool,
    Nil,
    Void,
    Secret(Box<FunctionType>),
    List(Box<FunctionType>),
    Dict(Box<FunctionType>, Box<FunctionType>),
    Object(String),
    Generic(String, Vec<FunctionType>),
    TypeVar(String),
    #[default]
    Unknown,
}

impl FunctionType {
    pub fn int64() -> Self {
        Self::Int {
            signed: true,
            bits: 64,
        }
    }

    pub fn uint64() -> Self {
        Self::Int {
            signed: false,
            bits: 64,
        }
    }

    pub fn fix64() -> Self {
        Self::Fixed { bits: 64 }
    }

    pub fn fix32() -> Self {
        Self::Fixed { bits: 32 }
    }

    pub fn underlying_type(&self) -> &FunctionType {
        match self {
            FunctionType::Secret(inner) => inner.underlying_type(),
            _ => self,
        }
    }

    pub fn is_unknown_like(&self) -> bool {
        matches!(
            self.underlying_type(),
            FunctionType::Unknown | FunctionType::TypeVar(_) | FunctionType::Generic(_, _)
        )
    }
}

impl std::fmt::Display for FunctionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FunctionType::Int { signed, bits } => {
                if *signed {
                    write!(f, "int{bits}")
                } else {
                    write!(f, "uint{bits}")
                }
            }
            FunctionType::Float => f.write_str("float"),
            FunctionType::Fixed { bits } => write!(f, "fix{bits}"),
            FunctionType::String => f.write_str("string"),
            FunctionType::Bool => f.write_str("bool"),
            FunctionType::Nil => f.write_str("None"),
            FunctionType::Void => f.write_str("void"),
            FunctionType::Secret(inner) => write!(f, "secret {inner}"),
            FunctionType::List(inner) => write!(f, "list[{inner}]"),
            FunctionType::Dict(key, value) => write!(f, "dict[{key}, {value}]"),
            FunctionType::Object(name) | FunctionType::TypeVar(name) => f.write_str(name),
            FunctionType::Generic(name, params) => {
                write!(f, "{name}[")?;
                for (index, param) in params.iter().enumerate() {
                    if index > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{param}")?;
                }
                f.write_str("]")
            }
            FunctionType::Unknown => f.write_str("<unknown>"),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum MpcBackend {
    #[default]
    HoneyBadger,
    Avss,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum MpcCurve {
    #[default]
    Bls12_381,
    Bn254,
    Curve25519,
    Ed25519,
    Secp256k1,
    Secp256r1,
}

/// Represents a compiled function in the program
///
/// This struct contains all the metadata and instructions for a single function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledFunction {
    /// Function name
    pub name: String,
    /// Number of registers used by the function
    pub register_count: usize,
    /// Parameter names
    pub parameters: Vec<String>,
    /// Source-level parameter types, if present in bytecode metadata.
    pub parameter_types: Vec<FunctionType>,
    /// Source-level return type, if present in bytecode metadata.
    pub return_type: FunctionType,
    /// Upvalue names (for closures)
    pub upvalues: Vec<String>,
    /// Parent function name (for nested functions)
    pub parent: Option<String>,
    /// Label definitions
    pub labels: HashMap<String, usize>,
    /// Function instructions
    pub instructions: Vec<CompiledInstruction>,
}

/// Represents a compiled instruction
///
/// This enum mirrors the Instruction enum but uses indices into the constant pool
/// instead of embedding values directly.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CompiledInstruction {
    // No operation
    NOP,
    // Load value from stack to register
    LD(usize, i32), // LD r1, [sp+0]
    // Load immediate value to register
    LDI(usize, usize), // LDI r1, const_idx
    // Move value from one register to another
    MOV(usize, usize), // MOV r1, r2
    // Arithmetic operations
    ADD(usize, usize, usize), // ADD r1, r2, r3
    SUB(usize, usize, usize), // SUB r1, r2, r3
    MUL(usize, usize, usize), // MUL r1, r2, r3
    DIV(usize, usize, usize), // DIV r1, r2, r3
    MOD(usize, usize, usize), // MOD r1, r2, r3
    // Bitwise operations
    AND(usize, usize, usize), // AND r1, r2, r3
    OR(usize, usize, usize),  // OR r1, r2, r3
    XOR(usize, usize, usize), // XOR r1, r2, r3
    NOT(usize, usize),        // NOT r1, r2
    SHL(usize, usize, usize), // SHL r1, r2, r3
    SHR(usize, usize, usize), // SHR r1, r2, r3
    // Control flow
    JMP(String),    // JMP label
    JMPEQ(String),  // JMPEQ label
    JMPNEQ(String), // JMPNEQ label
    JMPLT(String),  // JMPLT label
    JMPGT(String),  // JMPGT label
    // Function handling
    CALL(String),   // CALL function_name
    RET(usize),     // RET r1
    PUSHARG(usize), // PUSHARG r1
    // Comparison
    CMP(usize, usize), // CMP r1, r2
    // Spill-slot access
    LDS(usize, usize), // LDS r1, slot
    STS(usize, usize), // STS slot, r1
}

impl Default for CompiledBinary {
    fn default() -> Self {
        Self::new()
    }
}

impl CompiledBinary {
    /// Creates a new empty compiled binary
    pub fn new() -> Self {
        CompiledBinary {
            version: FORMAT_VERSION,
            constants: Vec::new(),
            functions: Vec::new(),
            client_io_manifest: ClientIoManifest::default(),
        }
    }

    /// Creates a compiled binary from a collection of VM functions
    ///
    /// This method converts VMFunction objects to the compiled binary format,
    /// collecting all constants into a shared pool.
    ///
    /// # Arguments
    ///
    /// * `functions` - A slice of VMFunction objects to convert
    ///
    /// # Returns
    ///
    /// A new CompiledBinary containing the converted functions
    pub fn from_vm_functions(functions: &[VMFunction]) -> Self {
        let mut binary = CompiledBinary::new();
        let mut constant_map = HashMap::new();

        for function in functions {
            binary.add_function_from_vm(function, &mut constant_map);
        }

        binary
    }

    /// Adds a constant to the pool if it doesn't already exist
    ///
    /// # Arguments
    ///
    /// * `value` - The value to add
    /// * `constant_map` - A map from values to their indices in the constant pool
    ///
    /// # Returns
    ///
    /// The index of the constant in the pool
    fn add_constant_if_new(
        &mut self,
        value: &Value,
        constant_map: &mut HashMap<Value, usize>,
    ) -> usize {
        if let Some(&index) = constant_map.get(value) {
            return index;
        }

        let index = self.constants.len();
        self.constants.push(value.clone());
        constant_map.insert(value.clone(), index);
        index
    }

    /// Adds a function from a VMFunction
    ///
    /// # Arguments
    ///
    /// * `vm_function` - The VMFunction to convert
    /// * `constant_map` - A map from values to their indices in the constant pool
    fn add_function_from_vm(
        &mut self,
        vm_function: &VMFunction,
        constant_map: &mut HashMap<Value, usize>,
    ) {
        let mut compiled_instructions = Vec::new();

        // Convert instructions
        for instruction in vm_function.instructions() {
            let compiled = match instruction {
                Instruction::NOP => CompiledInstruction::NOP,
                Instruction::LD(reg, offset) => CompiledInstruction::LD(*reg, *offset),
                Instruction::LDI(reg, value) => {
                    let const_idx = self.add_constant_if_new(value, constant_map);
                    CompiledInstruction::LDI(*reg, const_idx)
                }
                Instruction::MOV(target, source) => CompiledInstruction::MOV(*target, *source),
                Instruction::ADD(target, src1, src2) => {
                    CompiledInstruction::ADD(*target, *src1, *src2)
                }
                Instruction::SUB(target, src1, src2) => {
                    CompiledInstruction::SUB(*target, *src1, *src2)
                }
                Instruction::MUL(target, src1, src2) => {
                    CompiledInstruction::MUL(*target, *src1, *src2)
                }
                Instruction::DIV(target, src1, src2) => {
                    CompiledInstruction::DIV(*target, *src1, *src2)
                }
                Instruction::MOD(target, src1, src2) => {
                    CompiledInstruction::MOD(*target, *src1, *src2)
                }
                Instruction::AND(target, src1, src2) => {
                    CompiledInstruction::AND(*target, *src1, *src2)
                }
                Instruction::OR(target, src1, src2) => {
                    CompiledInstruction::OR(*target, *src1, *src2)
                }
                Instruction::XOR(target, src1, src2) => {
                    CompiledInstruction::XOR(*target, *src1, *src2)
                }
                Instruction::NOT(target, source) => CompiledInstruction::NOT(*target, *source),
                Instruction::SHL(target, src1, src2) => {
                    CompiledInstruction::SHL(*target, *src1, *src2)
                }
                Instruction::SHR(target, src1, src2) => {
                    CompiledInstruction::SHR(*target, *src1, *src2)
                }
                Instruction::JMP(label) => CompiledInstruction::JMP(label.clone()),
                Instruction::JMPEQ(label) => CompiledInstruction::JMPEQ(label.clone()),
                Instruction::JMPNEQ(label) => CompiledInstruction::JMPNEQ(label.clone()),
                Instruction::JMPLT(label) => CompiledInstruction::JMPLT(label.clone()),
                Instruction::JMPGT(label) => CompiledInstruction::JMPGT(label.clone()),
                Instruction::CALL(function_name) => {
                    CompiledInstruction::CALL(function_name.clone())
                }
                Instruction::RET(reg) => CompiledInstruction::RET(*reg),
                Instruction::PUSHARG(reg) => CompiledInstruction::PUSHARG(*reg),
                Instruction::CMP(reg1, reg2) => CompiledInstruction::CMP(*reg1, *reg2),
                Instruction::LDS(reg, slot) => CompiledInstruction::LDS(*reg, *slot),
                Instruction::STS(slot, reg) => CompiledInstruction::STS(*slot, *reg),
            };

            compiled_instructions.push(compiled);
        }

        // Create the compiled function
        let compiled_function = CompiledFunction {
            name: vm_function.name().to_string(),
            register_count: vm_function.register_count(),
            parameters: vm_function.parameters().to_vec(),
            parameter_types: vec![FunctionType::Unknown; vm_function.parameters().len()],
            return_type: FunctionType::Unknown,
            upvalues: vm_function.upvalues().to_vec(),
            parent: vm_function.parent().map(str::to_owned),
            labels: vm_function.labels().clone(),
            instructions: compiled_instructions,
        };

        self.functions.push(compiled_function);
    }

    fn compiled_instruction_to_vm_instruction<F>(
        instruction: &CompiledInstruction,
        mut constant_lookup: F,
    ) -> BinaryResult<Instruction>
    where
        F: FnMut(usize) -> BinaryResult<Value>,
    {
        Ok(match instruction {
            CompiledInstruction::NOP => Instruction::NOP,
            CompiledInstruction::LD(reg, offset) => Instruction::LD(*reg, *offset),
            CompiledInstruction::LDI(reg, const_idx) => {
                Instruction::LDI(*reg, constant_lookup(*const_idx)?)
            }
            CompiledInstruction::MOV(target, source) => Instruction::MOV(*target, *source),
            CompiledInstruction::ADD(target, src1, src2) => Instruction::ADD(*target, *src1, *src2),
            CompiledInstruction::SUB(target, src1, src2) => Instruction::SUB(*target, *src1, *src2),
            CompiledInstruction::MUL(target, src1, src2) => Instruction::MUL(*target, *src1, *src2),
            CompiledInstruction::DIV(target, src1, src2) => Instruction::DIV(*target, *src1, *src2),
            CompiledInstruction::MOD(target, src1, src2) => Instruction::MOD(*target, *src1, *src2),
            CompiledInstruction::AND(target, src1, src2) => Instruction::AND(*target, *src1, *src2),
            CompiledInstruction::OR(target, src1, src2) => Instruction::OR(*target, *src1, *src2),
            CompiledInstruction::XOR(target, src1, src2) => Instruction::XOR(*target, *src1, *src2),
            CompiledInstruction::NOT(target, source) => Instruction::NOT(*target, *source),
            CompiledInstruction::SHL(target, src1, src2) => Instruction::SHL(*target, *src1, *src2),
            CompiledInstruction::SHR(target, src1, src2) => Instruction::SHR(*target, *src1, *src2),
            CompiledInstruction::JMP(label) => Instruction::JMP(label.clone()),
            CompiledInstruction::JMPEQ(label) => Instruction::JMPEQ(label.clone()),
            CompiledInstruction::JMPNEQ(label) => Instruction::JMPNEQ(label.clone()),
            CompiledInstruction::JMPLT(label) => Instruction::JMPLT(label.clone()),
            CompiledInstruction::JMPGT(label) => Instruction::JMPGT(label.clone()),
            CompiledInstruction::CALL(function_name) => Instruction::CALL(function_name.clone()),
            CompiledInstruction::RET(reg) => Instruction::RET(*reg),
            CompiledInstruction::PUSHARG(reg) => Instruction::PUSHARG(*reg),
            CompiledInstruction::CMP(reg1, reg2) => Instruction::CMP(*reg1, *reg2),
            CompiledInstruction::LDS(reg, slot) => Instruction::LDS(*reg, *slot),
            CompiledInstruction::STS(slot, reg) => Instruction::STS(*slot, *reg),
        })
    }

    fn vm_function_from_instructions(
        function: &CompiledFunction,
        instructions: Vec<Instruction>,
    ) -> VMFunction {
        VMFunction::new(
            function.name.clone(),
            function.parameters.clone(),
            function.upvalues.clone(),
            function.parent.clone(),
            function.register_count,
            instructions,
            function.labels.clone(),
        )
    }

    fn try_compiled_function_to_vm_function(
        &self,
        function: &CompiledFunction,
    ) -> BinaryResult<VMFunction> {
        let mut instructions = Vec::with_capacity(function.instructions.len());
        for (instruction_index, instruction) in function.instructions.iter().enumerate() {
            instructions.push(Self::compiled_instruction_to_vm_instruction(
                instruction,
                |const_idx| {
                    self.constants.get(const_idx).cloned().ok_or_else(|| {
                        invalid_data(format!(
                            "Function {} instruction {} references constant {} but constant pool has {} values",
                            function.name,
                            instruction_index,
                            const_idx,
                            self.constants.len()
                        ))
                    })
                },
            )?);
        }

        let mut vm_function = Self::vm_function_from_instructions(function, instructions);
        vm_function.try_normalize_register_count()?;
        Ok(vm_function)
    }

    fn compiled_instruction_into_resolved_instruction<F>(
        instruction: CompiledInstruction,
        labels: &HashMap<String, usize>,
        instruction_count: usize,
        constants: &mut Vec<Value>,
        call_target_names: &mut Vec<String>,
        mut constant_lookup: F,
    ) -> BinaryResult<ResolvedInstruction>
    where
        F: FnMut(usize) -> BinaryResult<Value>,
    {
        Ok(match instruction {
            CompiledInstruction::NOP => ResolvedInstruction::NOP,
            CompiledInstruction::LD(reg, offset) => {
                ResolvedInstruction::LD(compact_resolved_operand("LD register", reg)?, offset)
            }
            CompiledInstruction::LDI(reg, const_idx) => {
                let value = constant_lookup(const_idx)?;
                let local_const_idx = constants.len();
                constants.push(value);
                ResolvedInstruction::LDI(
                    compact_resolved_operand("LDI register", reg)?,
                    compact_resolved_operand("LDI constant index", local_const_idx)?,
                )
            }
            CompiledInstruction::MOV(target, source) => ResolvedInstruction::MOV(
                compact_resolved_operand("MOV target register", target)?,
                compact_resolved_operand("MOV source register", source)?,
            ),
            CompiledInstruction::ADD(target, src1, src2) => ResolvedInstruction::ADD(
                compact_resolved_operand("ADD target register", target)?,
                compact_resolved_operand("ADD left register", src1)?,
                compact_resolved_operand("ADD right register", src2)?,
            ),
            CompiledInstruction::SUB(target, src1, src2) => ResolvedInstruction::SUB(
                compact_resolved_operand("SUB target register", target)?,
                compact_resolved_operand("SUB left register", src1)?,
                compact_resolved_operand("SUB right register", src2)?,
            ),
            CompiledInstruction::MUL(target, src1, src2) => ResolvedInstruction::MUL(
                compact_resolved_operand("MUL target register", target)?,
                compact_resolved_operand("MUL left register", src1)?,
                compact_resolved_operand("MUL right register", src2)?,
            ),
            CompiledInstruction::DIV(target, src1, src2) => ResolvedInstruction::DIV(
                compact_resolved_operand("DIV target register", target)?,
                compact_resolved_operand("DIV left register", src1)?,
                compact_resolved_operand("DIV right register", src2)?,
            ),
            CompiledInstruction::MOD(target, src1, src2) => ResolvedInstruction::MOD(
                compact_resolved_operand("MOD target register", target)?,
                compact_resolved_operand("MOD left register", src1)?,
                compact_resolved_operand("MOD right register", src2)?,
            ),
            CompiledInstruction::AND(target, src1, src2) => ResolvedInstruction::AND(
                compact_resolved_operand("AND target register", target)?,
                compact_resolved_operand("AND left register", src1)?,
                compact_resolved_operand("AND right register", src2)?,
            ),
            CompiledInstruction::OR(target, src1, src2) => ResolvedInstruction::OR(
                compact_resolved_operand("OR target register", target)?,
                compact_resolved_operand("OR left register", src1)?,
                compact_resolved_operand("OR right register", src2)?,
            ),
            CompiledInstruction::XOR(target, src1, src2) => ResolvedInstruction::XOR(
                compact_resolved_operand("XOR target register", target)?,
                compact_resolved_operand("XOR left register", src1)?,
                compact_resolved_operand("XOR right register", src2)?,
            ),
            CompiledInstruction::NOT(target, source) => ResolvedInstruction::NOT(
                compact_resolved_operand("NOT target register", target)?,
                compact_resolved_operand("NOT source register", source)?,
            ),
            CompiledInstruction::SHL(target, src1, src2) => ResolvedInstruction::SHL(
                compact_resolved_operand("SHL target register", target)?,
                compact_resolved_operand("SHL left register", src1)?,
                compact_resolved_operand("SHL right register", src2)?,
            ),
            CompiledInstruction::SHR(target, src1, src2) => ResolvedInstruction::SHR(
                compact_resolved_operand("SHR target register", target)?,
                compact_resolved_operand("SHR left register", src1)?,
                compact_resolved_operand("SHR right register", src2)?,
            ),
            CompiledInstruction::JMP(label) => ResolvedInstruction::JMP(compact_resolved_operand(
                "JMP target",
                resolve_compiled_label(&label, labels, instruction_count)?,
            )?),
            CompiledInstruction::JMPEQ(label) => {
                ResolvedInstruction::JMPEQ(compact_resolved_operand(
                    "JMPEQ target",
                    resolve_compiled_label(&label, labels, instruction_count)?,
                )?)
            }
            CompiledInstruction::JMPNEQ(label) => {
                ResolvedInstruction::JMPNEQ(compact_resolved_operand(
                    "JMPNEQ target",
                    resolve_compiled_label(&label, labels, instruction_count)?,
                )?)
            }
            CompiledInstruction::JMPLT(label) => {
                ResolvedInstruction::JMPLT(compact_resolved_operand(
                    "JMPLT target",
                    resolve_compiled_label(&label, labels, instruction_count)?,
                )?)
            }
            CompiledInstruction::JMPGT(label) => {
                ResolvedInstruction::JMPGT(compact_resolved_operand(
                    "JMPGT target",
                    resolve_compiled_label(&label, labels, instruction_count)?,
                )?)
            }
            CompiledInstruction::CALL(function_name) => {
                let call_idx = call_target_names.len();
                call_target_names.push(function_name);
                ResolvedInstruction::CALL(compact_resolved_operand("CALL target index", call_idx)?)
            }
            CompiledInstruction::RET(reg) => {
                ResolvedInstruction::RET(compact_resolved_operand("RET register", reg)?)
            }
            CompiledInstruction::PUSHARG(reg) => {
                ResolvedInstruction::PUSHARG(compact_resolved_operand("PUSHARG register", reg)?)
            }
            CompiledInstruction::CMP(reg1, reg2) => ResolvedInstruction::CMP(
                compact_resolved_operand("CMP left register", reg1)?,
                compact_resolved_operand("CMP right register", reg2)?,
            ),
            CompiledInstruction::LDS(reg, slot) => ResolvedInstruction::LDS(
                compact_resolved_operand("LDS register", reg)?,
                compact_resolved_operand("LDS slot", slot)?,
            ),
            CompiledInstruction::STS(slot, reg) => ResolvedInstruction::STS(
                compact_resolved_operand("STS slot", slot)?,
                compact_resolved_operand("STS register", reg)?,
            ),
        })
    }

    fn compiled_instruction_into_resolved_input<F>(
        instruction: CompiledInstruction,
        labels: &HashMap<String, usize>,
        instruction_count: usize,
        mut constant_lookup: F,
    ) -> BinaryResult<ResolvedInstructionInput>
    where
        F: FnMut(usize) -> BinaryResult<Value>,
    {
        Ok(match instruction {
            CompiledInstruction::NOP => ResolvedInstructionInput::NOP,
            CompiledInstruction::LD(reg, offset) => {
                ResolvedInstructionInput::LD(compact_resolved_operand("LD register", reg)?, offset)
            }
            CompiledInstruction::LDI(reg, const_idx) => ResolvedInstructionInput::LDI(
                compact_resolved_operand("LDI register", reg)?,
                constant_lookup(const_idx)?,
            ),
            CompiledInstruction::MOV(target, source) => ResolvedInstructionInput::MOV(
                compact_resolved_operand("MOV target register", target)?,
                compact_resolved_operand("MOV source register", source)?,
            ),
            CompiledInstruction::ADD(target, src1, src2) => ResolvedInstructionInput::ADD(
                compact_resolved_operand("ADD target register", target)?,
                compact_resolved_operand("ADD left register", src1)?,
                compact_resolved_operand("ADD right register", src2)?,
            ),
            CompiledInstruction::SUB(target, src1, src2) => ResolvedInstructionInput::SUB(
                compact_resolved_operand("SUB target register", target)?,
                compact_resolved_operand("SUB left register", src1)?,
                compact_resolved_operand("SUB right register", src2)?,
            ),
            CompiledInstruction::MUL(target, src1, src2) => ResolvedInstructionInput::MUL(
                compact_resolved_operand("MUL target register", target)?,
                compact_resolved_operand("MUL left register", src1)?,
                compact_resolved_operand("MUL right register", src2)?,
            ),
            CompiledInstruction::DIV(target, src1, src2) => ResolvedInstructionInput::DIV(
                compact_resolved_operand("DIV target register", target)?,
                compact_resolved_operand("DIV left register", src1)?,
                compact_resolved_operand("DIV right register", src2)?,
            ),
            CompiledInstruction::MOD(target, src1, src2) => ResolvedInstructionInput::MOD(
                compact_resolved_operand("MOD target register", target)?,
                compact_resolved_operand("MOD left register", src1)?,
                compact_resolved_operand("MOD right register", src2)?,
            ),
            CompiledInstruction::AND(target, src1, src2) => ResolvedInstructionInput::AND(
                compact_resolved_operand("AND target register", target)?,
                compact_resolved_operand("AND left register", src1)?,
                compact_resolved_operand("AND right register", src2)?,
            ),
            CompiledInstruction::OR(target, src1, src2) => ResolvedInstructionInput::OR(
                compact_resolved_operand("OR target register", target)?,
                compact_resolved_operand("OR left register", src1)?,
                compact_resolved_operand("OR right register", src2)?,
            ),
            CompiledInstruction::XOR(target, src1, src2) => ResolvedInstructionInput::XOR(
                compact_resolved_operand("XOR target register", target)?,
                compact_resolved_operand("XOR left register", src1)?,
                compact_resolved_operand("XOR right register", src2)?,
            ),
            CompiledInstruction::NOT(target, source) => ResolvedInstructionInput::NOT(
                compact_resolved_operand("NOT target register", target)?,
                compact_resolved_operand("NOT source register", source)?,
            ),
            CompiledInstruction::SHL(target, src1, src2) => ResolvedInstructionInput::SHL(
                compact_resolved_operand("SHL target register", target)?,
                compact_resolved_operand("SHL left register", src1)?,
                compact_resolved_operand("SHL right register", src2)?,
            ),
            CompiledInstruction::SHR(target, src1, src2) => ResolvedInstructionInput::SHR(
                compact_resolved_operand("SHR target register", target)?,
                compact_resolved_operand("SHR left register", src1)?,
                compact_resolved_operand("SHR right register", src2)?,
            ),
            CompiledInstruction::JMP(label) => {
                ResolvedInstructionInput::JMP(compact_resolved_operand(
                    "JMP target",
                    resolve_compiled_label(&label, labels, instruction_count)?,
                )?)
            }
            CompiledInstruction::JMPEQ(label) => {
                ResolvedInstructionInput::JMPEQ(compact_resolved_operand(
                    "JMPEQ target",
                    resolve_compiled_label(&label, labels, instruction_count)?,
                )?)
            }
            CompiledInstruction::JMPNEQ(label) => {
                ResolvedInstructionInput::JMPNEQ(compact_resolved_operand(
                    "JMPNEQ target",
                    resolve_compiled_label(&label, labels, instruction_count)?,
                )?)
            }
            CompiledInstruction::JMPLT(label) => {
                ResolvedInstructionInput::JMPLT(compact_resolved_operand(
                    "JMPLT target",
                    resolve_compiled_label(&label, labels, instruction_count)?,
                )?)
            }
            CompiledInstruction::JMPGT(label) => {
                ResolvedInstructionInput::JMPGT(compact_resolved_operand(
                    "JMPGT target",
                    resolve_compiled_label(&label, labels, instruction_count)?,
                )?)
            }
            CompiledInstruction::CALL(function_name) => {
                ResolvedInstructionInput::CALL(function_name)
            }
            CompiledInstruction::RET(reg) => {
                ResolvedInstructionInput::RET(compact_resolved_operand("RET register", reg)?)
            }
            CompiledInstruction::PUSHARG(reg) => ResolvedInstructionInput::PUSHARG(
                compact_resolved_operand("PUSHARG register", reg)?,
            ),
            CompiledInstruction::CMP(reg1, reg2) => ResolvedInstructionInput::CMP(
                compact_resolved_operand("CMP left register", reg1)?,
                compact_resolved_operand("CMP right register", reg2)?,
            ),
            CompiledInstruction::LDS(reg, slot) => ResolvedInstructionInput::LDS(
                compact_resolved_operand("LDS register", reg)?,
                compact_resolved_operand("LDS slot", slot)?,
            ),
            CompiledInstruction::STS(slot, reg) => ResolvedInstructionInput::STS(
                compact_resolved_operand("STS slot", slot)?,
                compact_resolved_operand("STS register", reg)?,
            ),
        })
    }

    fn try_to_raw_vm_functions(&self) -> BinaryResult<Vec<VMFunction>> {
        let mut vm_functions = Vec::with_capacity(self.functions.len());
        for function in &self.functions {
            vm_functions.push(self.try_compiled_function_to_vm_function(function)?);
        }
        Ok(vm_functions)
    }

    /// Converts the compiled binary back to VM functions.
    ///
    /// This keeps the legacy behavior of returning every function entry as-is,
    /// including duplicate names. Prefer `try_to_vm_functions` for executable
    /// program loading when bytecode validity should be handled as data.
    ///
    /// # Panics
    ///
    /// Panics when a function references invalid bytecode metadata such as a
    /// missing constant or unrepresentable register frame. Use
    /// `try_to_vm_functions` to receive those failures as `BinaryError` values.
    pub fn to_vm_functions(&self) -> Vec<VMFunction> {
        self.try_to_raw_vm_functions()
            .expect("compiled binary contains invalid function data; use try_to_vm_functions for recoverable errors")
    }

    /// Converts the compiled binary back to VM functions with executable program validation.
    ///
    /// Function names are VM program identifiers, so conflicting duplicates are
    /// rejected. Identical duplicates are ignored to tolerate older bytecode
    /// fixtures that accidentally emitted the same wrapper twice.
    pub fn try_to_vm_functions(&self) -> BinaryResult<Vec<VMFunction>> {
        let mut seen: HashMap<&str, &CompiledFunction> = HashMap::new();
        let mut vm_functions = Vec::new();

        for function in &self.functions {
            if let Some(existing) = seen.get(function.name.as_str()) {
                if *existing == function {
                    continue;
                }

                return Err(invalid_data(format!(
                    "duplicate function '{}' has conflicting definitions",
                    function.name
                )));
            }

            seen.insert(function.name.as_str(), function);
            vm_functions.push(self.try_compiled_function_to_vm_function(function)?);
        }

        Ok(vm_functions)
    }

    /// Consumes the compiled binary and converts it to source-preserving VM
    /// functions.
    pub fn try_into_vm_functions(self) -> BinaryResult<Vec<VMFunction>> {
        let CompiledBinary {
            version,
            constants,
            functions,
            client_io_manifest,
        } = self;
        let mut seen: HashMap<String, usize> = HashMap::new();
        let mut unique_functions: Vec<CompiledFunction> = Vec::new();

        for function in functions {
            if let Some(existing_index) = seen.get(function.name.as_str()) {
                if unique_functions[*existing_index] == function {
                    continue;
                }

                return Err(invalid_data(format!(
                    "duplicate function '{}' has conflicting definitions",
                    function.name
                )));
            }

            seen.insert(function.name.clone(), unique_functions.len());
            unique_functions.push(function);
        }

        CompiledBinary {
            version,
            constants,
            functions: unique_functions,
            client_io_manifest,
        }
        .try_to_raw_vm_functions()
    }

    /// Serializes the compiled binary to a writer
    ///
    /// # Arguments
    ///
    /// * `writer` - A writer to write the binary data to
    ///
    /// # Returns
    ///
    /// A result indicating success or an error
    pub fn serialize<W: Write>(&self, writer: &mut W) -> BinaryResult<()> {
        // Write file header
        writer.write_all(MAGIC_BYTES)?;
        writer.write_all(&self.version.to_le_bytes())?;

        // Write constant pool
        write_usize_as_u32(writer, self.constants.len(), "constant count")?;

        for constant in &self.constants {
            self.serialize_value(constant, writer)?;
        }

        // Write functions
        write_usize_as_u32(writer, self.functions.len(), "function count")?;

        for function in &self.functions {
            self.serialize_function(function, writer)?;
        }

        if self.version >= CLIENT_IO_MANIFEST_FORMAT_VERSION {
            Self::serialize_client_io_manifest(
                &self.client_io_manifest,
                self.version >= MPC_BACKEND_MANIFEST_FORMAT_VERSION,
                self.version >= MPC_CURVE_MANIFEST_FORMAT_VERSION,
                self.version >= PREPROCESSING_DEMAND_MANIFEST_FORMAT_VERSION,
                self.version >= DYNAMIC_CLIENT_INPUT_MANIFEST_FORMAT_VERSION,
                writer,
            )?;
        }

        Ok(())
    }

    fn serialize_client_io_manifest<W: Write>(
        manifest: &ClientIoManifest,
        include_backend: bool,
        include_curve: bool,
        include_demand: bool,
        include_dynamic_client_inputs: bool,
        writer: &mut W,
    ) -> BinaryResult<()> {
        if include_backend {
            Self::serialize_mpc_backend(manifest.mpc_backend, writer)?;
        }
        if include_curve {
            Self::serialize_mpc_curve(manifest.mpc_curve, writer)?;
        }
        write_usize_as_u32(writer, manifest.clients.len(), "client IO schema count")?;
        for client in &manifest.clients {
            writer.write_all(&client.client_slot.to_le_bytes())?;
            write_usize_as_u32(writer, client.inputs.len(), "client IO input count")?;
            for share_type in &client.inputs {
                Self::serialize_share_type(*share_type, writer)?;
            }
            write_usize_as_u32(writer, client.outputs.len(), "client IO output count")?;
            for share_type in &client.outputs {
                Self::serialize_share_type(*share_type, writer)?;
            }
        }
        if include_demand {
            let demand = &manifest.preprocessing_demand;
            writer.write_all(&demand.triples.to_le_bytes())?;
            writer.write_all(&demand.randoms.to_le_bytes())?;
            writer.write_all(&demand.prandbits.to_le_bytes())?;
            writer.write_all(&demand.prandints.to_le_bytes())?;
            writer.write_all(&[u8::from(demand.dynamic)])?;
        }
        if include_dynamic_client_inputs {
            write_usize_as_u32(
                writer,
                manifest.dynamic_client_inputs.len(),
                "dynamic client input schema count",
            )?;
            for schema in &manifest.dynamic_client_inputs {
                writer.write_all(&schema.first_client_slot.to_le_bytes())?;
                write_usize_as_u32(writer, schema.inputs.len(), "dynamic client input count")?;
                for share_type in &schema.inputs {
                    Self::serialize_share_type(*share_type, writer)?;
                }
            }
        }
        Ok(())
    }

    fn serialize_mpc_backend<W: Write>(backend: MpcBackend, writer: &mut W) -> BinaryResult<()> {
        let tag = match backend {
            MpcBackend::HoneyBadger => 0u8,
            MpcBackend::Avss => 1u8,
        };
        writer.write_all(&[tag])?;
        Ok(())
    }

    fn serialize_mpc_curve<W: Write>(curve: MpcCurve, writer: &mut W) -> BinaryResult<()> {
        let tag = match curve {
            MpcCurve::Bls12_381 => 0u8,
            MpcCurve::Bn254 => 1u8,
            MpcCurve::Curve25519 => 2u8,
            MpcCurve::Ed25519 => 3u8,
            MpcCurve::Secp256k1 => 4u8,
            MpcCurve::Secp256r1 => 5u8,
        };
        writer.write_all(&[tag])?;
        Ok(())
    }

    fn serialize_share_type<W: Write>(share_type: ShareType, writer: &mut W) -> BinaryResult<()> {
        match share_type {
            ShareType::SecretInt { bit_length } => {
                writer.write_all(&[0u8])?;
                write_usize_as_u32(writer, bit_length, "SecretInt bit length")?;
            }
            ShareType::SecretUInt { bit_length } => {
                writer.write_all(&[2u8])?;
                write_usize_as_u32(writer, bit_length, "SecretUInt bit length")?;
            }
            ShareType::SecretFixedPoint { precision } => {
                writer.write_all(&[1u8])?;
                write_usize_as_u32(writer, precision.total_bits(), "fixed-point total bits")?;
                write_usize_as_u32(
                    writer,
                    precision.fractional_bits(),
                    "fixed-point fractional bits",
                )?;
            }
        }
        Ok(())
    }

    /// Serializes a value to a writer
    ///
    /// # Arguments
    ///
    /// * `value` - The value to serialize
    /// * `writer` - A writer to write the binary data to
    ///
    /// # Returns
    ///
    /// A result indicating success or an error
    fn serialize_value<W: Write>(&self, value: &Value, writer: &mut W) -> BinaryResult<()> {
        match value {
            Value::Unit => {
                writer.write_all(&[0u8])?; // Type tag for Unit
            }
            Value::I64(i) => {
                writer.write_all(&[1u8])?; // Type tag for Int
                writer.write_all(&i.to_le_bytes())?;
            }
            Value::I32(i) => {
                writer.write_all(&[2u8])?; // Type tag for I32
                writer.write_all(&i.to_le_bytes())?;
            }
            Value::I16(i) => {
                writer.write_all(&[3u8])?; // Type tag for I16
                writer.write_all(&i.to_le_bytes())?;
            }
            Value::I8(i) => {
                writer.write_all(&[4u8])?; // Type tag for I8
                writer.write_all(&i.to_le_bytes())?;
            }
            Value::U8(i) => {
                writer.write_all(&[5u8])?; // Type tag for U8
                writer.write_all(&[*i])?;
            }
            Value::U16(i) => {
                writer.write_all(&[6u8])?; // Type tag for U16
                writer.write_all(&i.to_le_bytes())?;
            }
            Value::U32(i) => {
                writer.write_all(&[7u8])?; // Type tag for U32
                writer.write_all(&i.to_le_bytes())?;
            }
            Value::U64(i) => {
                writer.write_all(&[8u8])?; // Type tag for U64
                writer.write_all(&i.to_le_bytes())?;
            }
            Value::Float(f) => {
                writer.write_all(&[9u8])?; // Type tag for Float
                writer.write_all(&f.0.to_le_bytes())?;
            }
            Value::Bool(b) => {
                writer.write_all(&[10u8])?; // Type tag for Bool
                writer.write_all(&[if *b { 1u8 } else { 0u8 }])?;
            }
            Value::String(s) => {
                writer.write_all(&[11u8])?; // Type tag for String
                write_len_prefixed_str_u32(writer, s, "string length")?;
            }
            // Complex types like Object, Array, Foreign, Closure, and Share are not
            // directly serializable in this format. They would need special handling
            // or conversion to serializable forms.
            _ => {
                return Err(BinaryError::InvalidData(format!(
                    "Unsupported value type for serialization: {:?}",
                    value
                )));
            }
        }

        Ok(())
    }

    /// Serializes a function to a writer
    ///
    /// # Arguments
    ///
    /// * `function` - The function to serialize
    /// * `writer` - A writer to write the binary data to
    ///
    /// # Returns
    ///
    /// A result indicating success or an error
    fn serialize_function<W: Write>(
        &self,
        function: &CompiledFunction,
        writer: &mut W,
    ) -> BinaryResult<()> {
        // Write function name
        write_len_prefixed_str_u16(writer, &function.name, "function name length")?;

        // Write register count
        write_usize_as_u16(writer, function.register_count, "register count")?;

        // Write parameters
        write_usize_as_u16(writer, function.parameters.len(), "parameter count")?;
        for param in &function.parameters {
            write_len_prefixed_str_u16(writer, param, "parameter name length")?;
        }
        if self.version >= FUNCTION_TYPE_METADATA_FORMAT_VERSION {
            let parameter_types = normalized_parameter_types(function);
            write_usize_as_u16(writer, parameter_types.len(), "parameter type count")?;
            for ty in &parameter_types {
                Self::serialize_function_type(ty, writer)?;
            }
            Self::serialize_function_type(&function.return_type, writer)?;
        }

        // Write upvalues
        write_usize_as_u16(writer, function.upvalues.len(), "upvalue count")?;
        for upvalue in &function.upvalues {
            write_len_prefixed_str_u16(writer, upvalue, "upvalue name length")?;
        }

        // Write parent function name (if any)
        if let Some(ref parent) = function.parent {
            writer.write_all(&[1u8])?; // Has parent
            write_len_prefixed_str_u16(writer, parent, "parent function name length")?;
        } else {
            writer.write_all(&[0u8])?; // No parent
        }

        // Write labels
        write_usize_as_u16(writer, function.labels.len(), "label count")?;
        for (label, &offset) in &function.labels {
            write_len_prefixed_str_u16(writer, label, "label name length")?;
            write_usize_as_u32(writer, offset, "label offset")?;
        }

        // Write instructions
        write_usize_as_u32(writer, function.instructions.len(), "instruction count")?;
        for instruction in &function.instructions {
            self.serialize_instruction(instruction, writer)?;
        }

        Ok(())
    }

    fn serialize_function_type<W: Write>(ty: &FunctionType, writer: &mut W) -> BinaryResult<()> {
        match ty {
            FunctionType::Int { signed, bits } => {
                writer.write_all(&[0u8])?;
                writer.write_all(&[*signed as u8, *bits])?;
            }
            FunctionType::Float => writer.write_all(&[1u8])?,
            FunctionType::Fixed { bits: 64 } => writer.write_all(&[13u8])?,
            FunctionType::Fixed { bits } => {
                writer.write_all(&[14u8])?;
                writer.write_all(&[*bits])?;
            }
            FunctionType::String => writer.write_all(&[2u8])?,
            FunctionType::Bool => writer.write_all(&[3u8])?,
            FunctionType::Nil => writer.write_all(&[4u8])?,
            FunctionType::Void => writer.write_all(&[5u8])?,
            FunctionType::Secret(inner) => {
                writer.write_all(&[6u8])?;
                Self::serialize_function_type(inner, writer)?;
            }
            FunctionType::List(inner) => {
                writer.write_all(&[7u8])?;
                Self::serialize_function_type(inner, writer)?;
            }
            FunctionType::Dict(key, value) => {
                writer.write_all(&[8u8])?;
                Self::serialize_function_type(key, writer)?;
                Self::serialize_function_type(value, writer)?;
            }
            FunctionType::Object(name) => {
                writer.write_all(&[9u8])?;
                write_len_prefixed_str_u16(writer, name, "function type object name length")?;
            }
            FunctionType::Generic(name, params) => {
                writer.write_all(&[10u8])?;
                write_len_prefixed_str_u16(writer, name, "function generic type name length")?;
                write_usize_as_u16(writer, params.len(), "function generic parameter count")?;
                for param in params {
                    Self::serialize_function_type(param, writer)?;
                }
            }
            FunctionType::TypeVar(name) => {
                writer.write_all(&[11u8])?;
                write_len_prefixed_str_u16(writer, name, "function type variable name length")?;
            }
            FunctionType::Unknown => writer.write_all(&[12u8])?,
        }
        Ok(())
    }

    /// Serializes an instruction to a writer
    ///
    /// # Arguments
    ///
    /// * `instruction` - The instruction to serialize
    /// * `writer` - A writer to write the binary data to
    ///
    /// # Returns
    ///
    /// A result indicating success or an error
    fn serialize_instruction<W: Write>(
        &self,
        instruction: &CompiledInstruction,
        writer: &mut W,
    ) -> BinaryResult<()> {
        match instruction {
            CompiledInstruction::NOP => {
                writer.write_all(&[ReducedOpcode::NOP as u8])?;
            }
            CompiledInstruction::LD(reg, offset) => {
                writer.write_all(&[ReducedOpcode::LD as u8])?;
                write_usize_as_u32(writer, *reg, "LD register")?;
                writer.write_all(&offset.to_le_bytes())?;
            }
            CompiledInstruction::LDI(reg, const_idx) => {
                writer.write_all(&[ReducedOpcode::LDI as u8])?;
                write_usize_as_u32(writer, *reg, "LDI register")?;
                write_usize_as_u32(writer, *const_idx, "LDI constant index")?;
            }
            CompiledInstruction::MOV(target, source) => {
                writer.write_all(&[ReducedOpcode::MOV as u8])?;
                write_usize_as_u32(writer, *target, "MOV target register")?;
                write_usize_as_u32(writer, *source, "MOV source register")?;
            }
            CompiledInstruction::ADD(target, src1, src2) => {
                writer.write_all(&[ReducedOpcode::ADD as u8])?;
                write_usize_as_u32(writer, *target, "ADD target register")?;
                write_usize_as_u32(writer, *src1, "ADD left register")?;
                write_usize_as_u32(writer, *src2, "ADD right register")?;
            }
            CompiledInstruction::SUB(target, src1, src2) => {
                writer.write_all(&[ReducedOpcode::SUB as u8])?;
                write_usize_as_u32(writer, *target, "SUB target register")?;
                write_usize_as_u32(writer, *src1, "SUB left register")?;
                write_usize_as_u32(writer, *src2, "SUB right register")?;
            }
            CompiledInstruction::MUL(target, src1, src2) => {
                writer.write_all(&[ReducedOpcode::MUL as u8])?;
                write_usize_as_u32(writer, *target, "MUL target register")?;
                write_usize_as_u32(writer, *src1, "MUL left register")?;
                write_usize_as_u32(writer, *src2, "MUL right register")?;
            }
            CompiledInstruction::DIV(target, src1, src2) => {
                writer.write_all(&[ReducedOpcode::DIV as u8])?;
                write_usize_as_u32(writer, *target, "DIV target register")?;
                write_usize_as_u32(writer, *src1, "DIV left register")?;
                write_usize_as_u32(writer, *src2, "DIV right register")?;
            }
            CompiledInstruction::MOD(target, src1, src2) => {
                writer.write_all(&[ReducedOpcode::MOD as u8])?;
                write_usize_as_u32(writer, *target, "MOD target register")?;
                write_usize_as_u32(writer, *src1, "MOD left register")?;
                write_usize_as_u32(writer, *src2, "MOD right register")?;
            }
            CompiledInstruction::AND(target, src1, src2) => {
                writer.write_all(&[ReducedOpcode::AND as u8])?;
                write_usize_as_u32(writer, *target, "AND target register")?;
                write_usize_as_u32(writer, *src1, "AND left register")?;
                write_usize_as_u32(writer, *src2, "AND right register")?;
            }
            CompiledInstruction::OR(target, src1, src2) => {
                writer.write_all(&[ReducedOpcode::OR as u8])?;
                write_usize_as_u32(writer, *target, "OR target register")?;
                write_usize_as_u32(writer, *src1, "OR left register")?;
                write_usize_as_u32(writer, *src2, "OR right register")?;
            }
            CompiledInstruction::XOR(target, src1, src2) => {
                writer.write_all(&[ReducedOpcode::XOR as u8])?;
                write_usize_as_u32(writer, *target, "XOR target register")?;
                write_usize_as_u32(writer, *src1, "XOR left register")?;
                write_usize_as_u32(writer, *src2, "XOR right register")?;
            }
            CompiledInstruction::NOT(target, source) => {
                writer.write_all(&[ReducedOpcode::NOT as u8])?;
                write_usize_as_u32(writer, *target, "NOT target register")?;
                write_usize_as_u32(writer, *source, "NOT source register")?;
            }
            CompiledInstruction::SHL(target, src1, src2) => {
                writer.write_all(&[ReducedOpcode::SHL as u8])?;
                write_usize_as_u32(writer, *target, "SHL target register")?;
                write_usize_as_u32(writer, *src1, "SHL left register")?;
                write_usize_as_u32(writer, *src2, "SHL right register")?;
            }
            CompiledInstruction::SHR(target, src1, src2) => {
                writer.write_all(&[ReducedOpcode::SHR as u8])?;
                write_usize_as_u32(writer, *target, "SHR target register")?;
                write_usize_as_u32(writer, *src1, "SHR left register")?;
                write_usize_as_u32(writer, *src2, "SHR right register")?;
            }
            CompiledInstruction::JMP(label) => {
                writer.write_all(&[ReducedOpcode::JMP as u8])?;
                write_len_prefixed_str_u16(writer, label, "JMP label length")?;
            }
            CompiledInstruction::JMPEQ(label) => {
                writer.write_all(&[ReducedOpcode::JMPEQ as u8])?;
                write_len_prefixed_str_u16(writer, label, "JMPEQ label length")?;
            }
            CompiledInstruction::JMPNEQ(label) => {
                writer.write_all(&[ReducedOpcode::JMPNEQ as u8])?;
                write_len_prefixed_str_u16(writer, label, "JMPNEQ label length")?;
            }
            CompiledInstruction::JMPLT(label) => {
                writer.write_all(&[ReducedOpcode::JMPLT as u8])?;
                write_len_prefixed_str_u16(writer, label, "JMPLT label length")?;
            }
            CompiledInstruction::JMPGT(label) => {
                writer.write_all(&[ReducedOpcode::JMPGT as u8])?;
                write_len_prefixed_str_u16(writer, label, "JMPGT label length")?;
            }
            CompiledInstruction::CALL(function_name) => {
                writer.write_all(&[ReducedOpcode::CALL as u8])?;
                write_len_prefixed_str_u16(writer, function_name, "CALL function name length")?;
            }
            CompiledInstruction::RET(reg) => {
                writer.write_all(&[ReducedOpcode::RET as u8])?;
                write_usize_as_u32(writer, *reg, "RET register")?;
            }
            CompiledInstruction::PUSHARG(reg) => {
                writer.write_all(&[ReducedOpcode::PUSHARG as u8])?;
                write_usize_as_u32(writer, *reg, "PUSHARG register")?;
            }
            CompiledInstruction::CMP(reg1, reg2) => {
                writer.write_all(&[ReducedOpcode::CMP as u8])?;
                write_usize_as_u32(writer, *reg1, "CMP left register")?;
                write_usize_as_u32(writer, *reg2, "CMP right register")?;
            }
            CompiledInstruction::LDS(reg, slot) => {
                writer.write_all(&[ReducedOpcode::LDS as u8])?;
                write_usize_as_u32(writer, *reg, "LDS register")?;
                write_usize_as_u32(writer, *slot, "LDS slot")?;
            }
            CompiledInstruction::STS(slot, reg) => {
                writer.write_all(&[ReducedOpcode::STS as u8])?;
                write_usize_as_u32(writer, *slot, "STS slot")?;
                write_usize_as_u32(writer, *reg, "STS register")?;
            }
        }

        Ok(())
    }

    /// Deserializes a compiled binary from a reader
    ///
    /// # Arguments
    ///
    /// * `reader` - A reader to read the binary data from
    ///
    /// # Returns
    ///
    /// A result containing the deserialized compiled binary or an error
    pub fn deserialize<R: Read>(reader: &mut R) -> BinaryResult<Self> {
        // Read and verify file header
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if magic != *MAGIC_BYTES {
            return Err(BinaryError::InvalidMagicBytes);
        }

        let version = read_u16(reader)?;
        if version > FORMAT_VERSION {
            return Err(BinaryError::UnsupportedVersion(version));
        }

        // Read constant pool
        let constant_count =
            read_u32_len_bounded(reader, "constant count", MAX_BINARY_COLLECTION_LEN)?;

        let mut constants = Vec::new();
        reserve_vec(&mut constants, constant_count, "constant count")?;
        for _ in 0..constant_count {
            let value = Self::deserialize_value(reader)?;
            constants.push(value);
        }

        // Read functions
        let function_count =
            read_u32_len_bounded(reader, "function count", MAX_BINARY_COLLECTION_LEN)?;

        let mut functions = Vec::new();
        reserve_vec(&mut functions, function_count, "function count")?;
        for _ in 0..function_count {
            let function = Self::deserialize_function(reader, version)?;
            functions.push(function);
        }

        let client_io_manifest = if version >= CLIENT_IO_MANIFEST_FORMAT_VERSION {
            Self::deserialize_client_io_manifest(
                reader,
                version >= MPC_BACKEND_MANIFEST_FORMAT_VERSION,
                version >= MPC_CURVE_MANIFEST_FORMAT_VERSION,
                version >= PREPROCESSING_DEMAND_MANIFEST_FORMAT_VERSION,
                version >= DYNAMIC_CLIENT_INPUT_MANIFEST_FORMAT_VERSION,
            )?
        } else {
            ClientIoManifest::default()
        };

        Ok(CompiledBinary {
            version,
            constants,
            functions,
            client_io_manifest,
        })
    }

    /// Streams a compiled binary from `reader`, lowering and yielding each VM
    /// function without retaining the full compiled function table.
    ///
    /// The bytecode manifest is stored after the function table, so it is
    /// returned once all functions have been read and yielded. Identical
    /// duplicate function records are skipped; conflicting duplicates are
    /// rejected, matching `try_into_vm_functions`.
    pub fn try_for_each_vm_function_from_reader<R, F>(
        reader: &mut R,
        mut callback: F,
    ) -> BinaryResult<(usize, u16, ClientIoManifest)>
    where
        R: Read,
        F: FnMut(VMFunction) -> BinaryResult<()>,
    {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if magic != *MAGIC_BYTES {
            return Err(BinaryError::InvalidMagicBytes);
        }

        let version = read_u16(reader)?;
        if version > FORMAT_VERSION {
            return Err(BinaryError::UnsupportedVersion(version));
        }

        let constant_count =
            read_u32_len_bounded(reader, "constant count", MAX_BINARY_COLLECTION_LEN)?;

        let mut constants = Vec::new();
        reserve_vec(&mut constants, constant_count, "constant count")?;
        for _ in 0..constant_count {
            constants.push(Self::deserialize_value(reader)?);
        }

        let function_record_count =
            read_u32_len_bounded(reader, "function count", MAX_BINARY_COLLECTION_LEN)?;
        let mut seen: HashMap<String, u64> = HashMap::new();
        let mut function_count = 0;

        for _ in 0..function_record_count {
            let (vm_function, fingerprint) =
                Self::deserialize_vm_function(reader, version, &constants)?;
            if let Some(existing_fingerprint) = seen.get(vm_function.name()) {
                if *existing_fingerprint == fingerprint {
                    continue;
                }

                return Err(invalid_data(format!(
                    "duplicate function '{}' has conflicting definitions",
                    vm_function.name()
                )));
            }

            seen.insert(vm_function.name().to_string(), fingerprint);
            callback(vm_function)?;
            function_count += 1;
        }

        let client_io_manifest = if version >= CLIENT_IO_MANIFEST_FORMAT_VERSION {
            Self::deserialize_client_io_manifest(
                reader,
                version >= MPC_BACKEND_MANIFEST_FORMAT_VERSION,
                version >= MPC_CURVE_MANIFEST_FORMAT_VERSION,
                version >= PREPROCESSING_DEMAND_MANIFEST_FORMAT_VERSION,
                version >= DYNAMIC_CLIENT_INPUT_MANIFEST_FORMAT_VERSION,
            )?
        } else {
            ClientIoManifest::default()
        };

        Ok((function_count, version, client_io_manifest))
    }

    pub fn try_for_each_resolved_vm_function_from_reader<R, F>(
        reader: &mut R,
        mut callback: F,
    ) -> BinaryResult<(usize, u16, ClientIoManifest)>
    where
        R: Read,
        F: FnMut(ResolvedFunctionHeader, &mut ResolvedInstructionReader<'_, R>) -> BinaryResult<()>,
    {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if magic != *MAGIC_BYTES {
            return Err(BinaryError::InvalidMagicBytes);
        }

        let version = read_u16(reader)?;
        if version > FORMAT_VERSION {
            return Err(BinaryError::UnsupportedVersion(version));
        }

        let constant_count =
            read_u32_len_bounded(reader, "constant count", MAX_BINARY_COLLECTION_LEN)?;

        let mut constants = Vec::new();
        reserve_vec(&mut constants, constant_count, "constant count")?;
        for _ in 0..constant_count {
            constants.push(Self::deserialize_value(reader)?);
        }

        let function_record_count =
            read_u32_len_bounded(reader, "function count", MAX_BINARY_COLLECTION_LEN)?;
        let mut seen: HashMap<String, u64> = HashMap::new();
        let mut function_count = 0;

        for _ in 0..function_record_count {
            let (name, mut stream) =
                Self::deserialize_resolved_function_stream(reader, version, &constants)?;
            if seen.contains_key(&name) {
                stream.drain()?;
            } else {
                let header = stream.header();
                callback(header, &mut stream)?;
                stream.drain()?;
            }

            let fingerprint = stream.finish();
            if let Some(existing_fingerprint) = seen.get(&name) {
                if *existing_fingerprint != fingerprint {
                    return Err(invalid_data(format!(
                        "duplicate function '{}' has conflicting definitions",
                        name
                    )));
                }
                continue;
            }

            seen.insert(name, fingerprint);
            function_count += 1;
        }

        let client_io_manifest = if version >= CLIENT_IO_MANIFEST_FORMAT_VERSION {
            Self::deserialize_client_io_manifest(
                reader,
                version >= MPC_BACKEND_MANIFEST_FORMAT_VERSION,
                version >= MPC_CURVE_MANIFEST_FORMAT_VERSION,
                version >= PREPROCESSING_DEMAND_MANIFEST_FORMAT_VERSION,
                version >= DYNAMIC_CLIENT_INPUT_MANIFEST_FORMAT_VERSION,
            )?
        } else {
            ClientIoManifest::default()
        };

        Ok((function_count, version, client_io_manifest))
    }

    fn deserialize_client_io_manifest<R: Read>(
        reader: &mut R,
        has_backend: bool,
        has_curve: bool,
        has_demand: bool,
        has_dynamic_client_inputs: bool,
    ) -> BinaryResult<ClientIoManifest> {
        let mpc_backend = if has_backend {
            Self::deserialize_mpc_backend(reader)?
        } else {
            MpcBackend::default()
        };
        let mpc_curve = if has_curve {
            Self::deserialize_mpc_curve(reader)?
        } else {
            MpcCurve::default()
        };
        let client_count =
            read_u32_len_bounded(reader, "client IO schema count", MAX_BINARY_COLLECTION_LEN)?;
        let mut clients = Vec::new();
        reserve_vec(&mut clients, client_count, "client IO schema count")?;
        for _ in 0..client_count {
            let client_slot = read_u64(reader)?;
            let input_count =
                read_u32_len_bounded(reader, "client IO input count", MAX_BINARY_COLLECTION_LEN)?;
            let mut inputs = Vec::new();
            reserve_vec(&mut inputs, input_count, "client IO input count")?;
            for _ in 0..input_count {
                inputs.push(Self::deserialize_share_type(reader)?);
            }

            let output_count =
                read_u32_len_bounded(reader, "client IO output count", MAX_BINARY_COLLECTION_LEN)?;
            let mut outputs = Vec::new();
            reserve_vec(&mut outputs, output_count, "client IO output count")?;
            for _ in 0..output_count {
                outputs.push(Self::deserialize_share_type(reader)?);
            }

            clients.push(ClientIoSchema {
                client_slot,
                inputs,
                outputs,
            });
        }
        let preprocessing_demand = if has_demand {
            PreprocessingDemand {
                triples: read_u64(reader)?,
                randoms: read_u64(reader)?,
                prandbits: read_u64(reader)?,
                prandints: read_u64(reader)?,
                dynamic: read_u8(reader)? != 0,
            }
        } else {
            PreprocessingDemand::default()
        };
        let dynamic_client_inputs = if has_dynamic_client_inputs {
            let schema_count = read_u32_len_bounded(
                reader,
                "dynamic client input schema count",
                MAX_BINARY_COLLECTION_LEN,
            )?;
            let mut schemas = Vec::new();
            reserve_vec(
                &mut schemas,
                schema_count,
                "dynamic client input schema count",
            )?;
            for _ in 0..schema_count {
                let first_client_slot = read_u64(reader)?;
                let input_count = read_u32_len_bounded(
                    reader,
                    "dynamic client input count",
                    MAX_BINARY_COLLECTION_LEN,
                )?;
                let mut inputs = Vec::new();
                reserve_vec(&mut inputs, input_count, "dynamic client input count")?;
                for _ in 0..input_count {
                    inputs.push(Self::deserialize_share_type(reader)?);
                }
                schemas.push(DynamicClientInputSchema {
                    first_client_slot,
                    inputs,
                });
            }
            schemas
        } else {
            Vec::new()
        };
        Ok(ClientIoManifest {
            mpc_backend,
            mpc_curve,
            clients,
            preprocessing_demand,
            dynamic_client_inputs,
        })
    }

    fn deserialize_mpc_backend<R: Read>(reader: &mut R) -> BinaryResult<MpcBackend> {
        let mut tag = [0u8; 1];
        reader.read_exact(&mut tag)?;
        match tag[0] {
            0 => Ok(MpcBackend::HoneyBadger),
            1 => Ok(MpcBackend::Avss),
            tag => Err(invalid_data(format!(
                "unknown MPC backend tag {tag} in IO manifest"
            ))),
        }
    }

    fn deserialize_mpc_curve<R: Read>(reader: &mut R) -> BinaryResult<MpcCurve> {
        let mut tag = [0u8; 1];
        reader.read_exact(&mut tag)?;
        match tag[0] {
            0 => Ok(MpcCurve::Bls12_381),
            1 => Ok(MpcCurve::Bn254),
            2 => Ok(MpcCurve::Curve25519),
            3 => Ok(MpcCurve::Ed25519),
            4 => Ok(MpcCurve::Secp256k1),
            5 => Ok(MpcCurve::Secp256r1),
            tag => Err(invalid_data(format!(
                "unknown MPC curve tag {tag} in IO manifest"
            ))),
        }
    }

    fn deserialize_share_type<R: Read>(reader: &mut R) -> BinaryResult<ShareType> {
        let mut type_tag = [0u8; 1];
        reader.read_exact(&mut type_tag)?;
        match type_tag[0] {
            0 => {
                let bit_length = read_usize_u32(reader, "SecretInt bit length")?;
                ShareType::try_secret_int(bit_length).map_err(|error| {
                    invalid_data(format!(
                        "invalid SecretInt metadata in IO manifest: {error}"
                    ))
                })
            }
            2 => {
                let bit_length = read_usize_u32(reader, "SecretUInt bit length")?;
                ShareType::try_secret_uint(bit_length).map_err(|error| {
                    invalid_data(format!(
                        "invalid SecretUInt metadata in IO manifest: {error}"
                    ))
                })
            }
            1 => {
                let total_bits = read_usize_u32(reader, "fixed-point total bits")?;
                let fractional_bits = read_usize_u32(reader, "fixed-point fractional bits")?;
                let precision =
                    FixedPointPrecision::try_new(total_bits, fractional_bits).map_err(|error| {
                        invalid_data(format!(
                            "invalid SecretFixedPoint metadata in IO manifest: {error}"
                        ))
                    })?;
                Ok(ShareType::SecretFixedPoint { precision })
            }
            tag => Err(invalid_data(format!(
                "unknown ShareType tag {tag} in IO manifest"
            ))),
        }
    }

    /// Deserializes a value from a reader
    ///
    /// # Arguments
    ///
    /// * `reader` - A reader to read the binary data from
    ///
    /// # Returns
    ///
    /// A result containing the deserialized value or an error
    fn deserialize_value<R: Read>(reader: &mut R) -> BinaryResult<Value> {
        let mut type_tag = [0u8; 1];
        reader.read_exact(&mut type_tag)?;

        match type_tag[0] {
            0 => Ok(Value::Unit),
            1 => {
                let mut bytes = [0u8; 8];
                reader.read_exact(&mut bytes)?;
                Ok(Value::I64(i64::from_le_bytes(bytes)))
            }
            2 => {
                let mut bytes = [0u8; 4];
                reader.read_exact(&mut bytes)?;
                Ok(Value::I32(i32::from_le_bytes(bytes)))
            }
            3 => {
                let mut bytes = [0u8; 2];
                reader.read_exact(&mut bytes)?;
                Ok(Value::I16(i16::from_le_bytes(bytes)))
            }
            4 => {
                let mut byte = [0u8; 1];
                reader.read_exact(&mut byte)?;
                Ok(Value::I8(i8::from_le_bytes(byte)))
            }
            5 => {
                let mut byte = [0u8; 1];
                reader.read_exact(&mut byte)?;
                Ok(Value::U8(byte[0]))
            }
            6 => {
                let mut bytes = [0u8; 2];
                reader.read_exact(&mut bytes)?;
                Ok(Value::U16(u16::from_le_bytes(bytes)))
            }
            7 => {
                let mut bytes = [0u8; 4];
                reader.read_exact(&mut bytes)?;
                Ok(Value::U32(u32::from_le_bytes(bytes)))
            }
            8 => {
                let mut bytes = [0u8; 8];
                reader.read_exact(&mut bytes)?;
                Ok(Value::U64(u64::from_le_bytes(bytes)))
            }
            9 => {
                let mut bytes = [0u8; 8];
                reader.read_exact(&mut bytes)?;
                Ok(Value::Float(F64(f64::from_le_bytes(bytes))))
            }
            10 => {
                let mut byte = [0u8; 1];
                reader.read_exact(&mut byte)?;
                Ok(Value::Bool(byte[0] != 0))
            }
            11 => {
                let string = read_len_prefixed_string_u32(
                    reader,
                    "string length",
                    "Invalid UTF-8 in string",
                )?;
                Ok(Value::String(string))
            }
            _ => Err(BinaryError::InvalidData(format!(
                "Unknown value type tag: {}",
                type_tag[0]
            ))),
        }
    }

    /// Deserializes a function from a reader
    ///
    /// # Arguments
    ///
    /// * `reader` - A reader to read the binary data from
    ///
    /// # Returns
    ///
    /// A result containing the deserialized function or an error
    fn deserialize_function<R: Read>(
        reader: &mut R,
        version: u16,
    ) -> BinaryResult<CompiledFunction> {
        // Read function name
        let name = read_len_prefixed_string_u16(
            reader,
            "function name length",
            "Invalid UTF-8 in function name",
        )?;

        // Read register count
        let register_count = usize::from(read_u16(reader)?);

        // Read parameters
        let param_count = usize::from(read_u16(reader)?);

        let mut parameters = Vec::new();
        reserve_vec(&mut parameters, param_count, "parameter count")?;
        for _ in 0..param_count {
            let param = read_len_prefixed_string_u16(
                reader,
                "parameter name length",
                "Invalid UTF-8 in parameter name",
            )?;
            parameters.push(param);
        }
        let (parameter_types, return_type) = if version >= FUNCTION_TYPE_METADATA_FORMAT_VERSION {
            let type_count = usize::from(read_u16(reader)?);
            if type_count != parameters.len() {
                return Err(invalid_data(format!(
                    "function '{}' declares {} parameter name(s) but {} parameter type(s)",
                    name,
                    parameters.len(),
                    type_count
                )));
            }
            let mut parameter_types = Vec::new();
            reserve_vec(&mut parameter_types, type_count, "parameter type count")?;
            for _ in 0..type_count {
                parameter_types.push(Self::deserialize_function_type(reader)?);
            }
            let return_type = Self::deserialize_function_type(reader)?;
            (parameter_types, return_type)
        } else {
            (
                vec![FunctionType::Unknown; parameters.len()],
                FunctionType::Unknown,
            )
        };

        // Read upvalues
        let upvalue_count = usize::from(read_u16(reader)?);

        let mut upvalues = Vec::new();
        reserve_vec(&mut upvalues, upvalue_count, "upvalue count")?;
        for _ in 0..upvalue_count {
            let upvalue = read_len_prefixed_string_u16(
                reader,
                "upvalue name length",
                "Invalid UTF-8 in upvalue name",
            )?;
            upvalues.push(upvalue);
        }

        // Read parent function name (if any)
        let mut has_parent_byte = [0u8; 1];
        reader.read_exact(&mut has_parent_byte)?;
        let parent = match has_parent_byte[0] {
            0 => None,
            1 => Some(read_len_prefixed_string_u16(
                reader,
                "parent function name length",
                "Invalid UTF-8 in parent function name",
            )?),
            other => {
                return Err(invalid_data(format!(
                    "Invalid parent presence flag: {other}"
                )));
            }
        };

        // Read labels
        let label_count = usize::from(read_u16(reader)?);

        let mut labels = HashMap::new();
        labels.try_reserve(label_count).map_err(|err| {
            invalid_data(format!(
                "label count {label_count} could not be allocated: {err}"
            ))
        })?;
        for _ in 0..label_count {
            let label = read_len_prefixed_string_u16(
                reader,
                "label name length",
                "Invalid UTF-8 in label name",
            )?;
            let offset = read_usize_u32(reader, "label offset")?;

            labels.insert(label, offset);
        }

        // Read instructions
        let instruction_count =
            read_u32_len_bounded(reader, "instruction count", MAX_INSTRUCTION_COUNT)?;

        let mut instructions = Vec::new();
        reserve_vec(&mut instructions, instruction_count, "instruction count")?;
        for _ in 0..instruction_count {
            let instruction = Self::deserialize_instruction(reader)?;
            instructions.push(instruction);
        }

        Ok(CompiledFunction {
            name,
            register_count,
            parameters,
            parameter_types,
            return_type,
            upvalues,
            parent,
            labels,
            instructions,
        })
    }

    fn deserialize_vm_function<R: Read>(
        reader: &mut R,
        version: u16,
        constants: &[Value],
    ) -> BinaryResult<(VMFunction, u64)> {
        let name = read_len_prefixed_string_u16(
            reader,
            "function name length",
            "Invalid UTF-8 in function name",
        )?;
        let mut hasher = DefaultHasher::new();
        name.hash(&mut hasher);

        let register_count = usize::from(read_u16(reader)?);
        register_count.hash(&mut hasher);

        let param_count = usize::from(read_u16(reader)?);
        let mut parameters = Vec::new();
        reserve_vec(&mut parameters, param_count, "parameter count")?;
        for _ in 0..param_count {
            parameters.push(read_len_prefixed_string_u16(
                reader,
                "parameter name length",
                "Invalid UTF-8 in parameter name",
            )?);
        }
        parameters.hash(&mut hasher);

        let (parameter_types, return_type) = if version >= FUNCTION_TYPE_METADATA_FORMAT_VERSION {
            let type_count = usize::from(read_u16(reader)?);
            if type_count != parameters.len() {
                return Err(invalid_data(format!(
                    "function '{}' declares {} parameter name(s) but {} parameter type(s)",
                    name,
                    parameters.len(),
                    type_count
                )));
            }
            let mut parameter_types = Vec::new();
            reserve_vec(&mut parameter_types, type_count, "parameter type count")?;
            for _ in 0..type_count {
                parameter_types.push(Self::deserialize_function_type(reader)?);
            }
            let return_type = Self::deserialize_function_type(reader)?;
            (parameter_types, return_type)
        } else {
            (
                vec![FunctionType::Unknown; parameters.len()],
                FunctionType::Unknown,
            )
        };
        parameter_types.hash(&mut hasher);
        return_type.hash(&mut hasher);

        let upvalue_count = usize::from(read_u16(reader)?);
        let mut upvalues = Vec::new();
        reserve_vec(&mut upvalues, upvalue_count, "upvalue count")?;
        for _ in 0..upvalue_count {
            upvalues.push(read_len_prefixed_string_u16(
                reader,
                "upvalue name length",
                "Invalid UTF-8 in upvalue name",
            )?);
        }
        upvalues.hash(&mut hasher);

        let mut has_parent_byte = [0u8; 1];
        reader.read_exact(&mut has_parent_byte)?;
        let parent = match has_parent_byte[0] {
            0 => None,
            1 => Some(read_len_prefixed_string_u16(
                reader,
                "parent function name length",
                "Invalid UTF-8 in parent function name",
            )?),
            other => {
                return Err(invalid_data(format!(
                    "Invalid parent presence flag: {other}"
                )));
            }
        };
        parent.hash(&mut hasher);

        let label_count = usize::from(read_u16(reader)?);
        let mut labels = HashMap::new();
        labels.try_reserve(label_count).map_err(|err| {
            invalid_data(format!(
                "label count {label_count} could not be allocated: {err}"
            ))
        })?;
        for _ in 0..label_count {
            let label = read_len_prefixed_string_u16(
                reader,
                "label name length",
                "Invalid UTF-8 in label name",
            )?;
            let offset = read_usize_u32(reader, "label offset")?;
            labels.insert(label, offset);
        }
        let mut sorted_labels: Vec<_> = labels.iter().collect();
        sorted_labels.sort_unstable_by_key(|(label, _)| *label);
        sorted_labels.len().hash(&mut hasher);
        for (label, offset) in sorted_labels {
            label.hash(&mut hasher);
            offset.hash(&mut hasher);
        }

        let instruction_count =
            read_u32_len_bounded(reader, "instruction count", MAX_INSTRUCTION_COUNT)?;
        instruction_count.hash(&mut hasher);
        let mut resolved_instructions = Vec::with_capacity(instruction_count);
        let mut constant_values = Vec::new();
        let mut call_target_names = Vec::new();
        for instruction_index in 0..instruction_count {
            let instruction = Self::deserialize_instruction(reader)?;
            instruction.hash(&mut hasher);
            resolved_instructions.push(Self::compiled_instruction_into_resolved_instruction(
                instruction,
                &labels,
                instruction_count,
                &mut constant_values,
                &mut call_target_names,
                |const_idx| {
                    constants.get(const_idx).cloned().ok_or_else(|| {
                        invalid_data(format!(
                            "Function {} instruction {} references constant {} but constant pool has {} values",
                            name,
                            instruction_index,
                            const_idx,
                            constants.len()
                        ))
                    })
                },
            )?);
        }

        let vm_function = VMFunction::try_new_resolved_with_call_targets(
            name,
            parameters,
            upvalues,
            parent,
            register_count,
            resolved_instructions,
            constant_values,
            call_target_names,
        )?;
        Ok((vm_function, hasher.finish()))
    }

    fn deserialize_resolved_function_stream<'a, R: Read>(
        reader: &'a mut R,
        version: u16,
        constants: &'a [Value],
    ) -> BinaryResult<(String, ResolvedInstructionReader<'a, R>)> {
        let name = read_len_prefixed_string_u16(
            reader,
            "function name length",
            "Invalid UTF-8 in function name",
        )?;
        let mut hasher = DefaultHasher::new();
        name.hash(&mut hasher);

        let mut register_count = usize::from(read_u16(reader)?);
        register_count.hash(&mut hasher);

        let param_count = usize::from(read_u16(reader)?);
        let mut parameters = Vec::new();
        reserve_vec(&mut parameters, param_count, "parameter count")?;
        for _ in 0..param_count {
            parameters.push(read_len_prefixed_string_u16(
                reader,
                "parameter name length",
                "Invalid UTF-8 in parameter name",
            )?);
        }
        parameters.hash(&mut hasher);

        let (parameter_types, return_type) = if version >= FUNCTION_TYPE_METADATA_FORMAT_VERSION {
            let type_count = usize::from(read_u16(reader)?);
            if type_count != parameters.len() {
                return Err(invalid_data(format!(
                    "function '{}' declares {} parameter name(s) but {} parameter type(s)",
                    name,
                    parameters.len(),
                    type_count
                )));
            }
            let mut parameter_types = Vec::new();
            reserve_vec(&mut parameter_types, type_count, "parameter type count")?;
            for _ in 0..type_count {
                parameter_types.push(Self::deserialize_function_type(reader)?);
            }
            let return_type = Self::deserialize_function_type(reader)?;
            (parameter_types, return_type)
        } else {
            (
                vec![FunctionType::Unknown; parameters.len()],
                FunctionType::Unknown,
            )
        };
        parameter_types.hash(&mut hasher);
        return_type.hash(&mut hasher);

        let upvalue_count = usize::from(read_u16(reader)?);
        let mut upvalues = Vec::new();
        reserve_vec(&mut upvalues, upvalue_count, "upvalue count")?;
        for _ in 0..upvalue_count {
            upvalues.push(read_len_prefixed_string_u16(
                reader,
                "upvalue name length",
                "Invalid UTF-8 in upvalue name",
            )?);
        }
        upvalues.hash(&mut hasher);

        let mut has_parent_byte = [0u8; 1];
        reader.read_exact(&mut has_parent_byte)?;
        let parent = match has_parent_byte[0] {
            0 => None,
            1 => Some(read_len_prefixed_string_u16(
                reader,
                "parent function name length",
                "Invalid UTF-8 in parent function name",
            )?),
            other => {
                return Err(invalid_data(format!(
                    "Invalid parent presence flag: {other}"
                )));
            }
        };
        parent.hash(&mut hasher);

        let label_count = usize::from(read_u16(reader)?);
        let mut labels = HashMap::new();
        labels.try_reserve(label_count).map_err(|err| {
            invalid_data(format!(
                "label count {label_count} could not be allocated: {err}"
            ))
        })?;
        for _ in 0..label_count {
            let label = read_len_prefixed_string_u16(
                reader,
                "label name length",
                "Invalid UTF-8 in label name",
            )?;
            let offset = read_usize_u32(reader, "label offset")?;
            labels.insert(label, offset);
        }
        let mut sorted_labels: Vec<_> = labels.iter().collect();
        sorted_labels.sort_unstable_by_key(|(label, _)| *label);
        sorted_labels.len().hash(&mut hasher);
        for (label, offset) in sorted_labels {
            label.hash(&mut hasher);
            offset.hash(&mut hasher);
        }

        let instruction_count =
            read_u32_len_bounded(reader, "instruction count", MAX_INSTRUCTION_COUNT)?;
        instruction_count.hash(&mut hasher);

        register_count = register_count
            .max(crate::registers::MIN_FRAME_REGISTER_COUNT)
            .max(parameters.len());

        let stream = ResolvedInstructionReader {
            reader,
            name: name.clone(),
            parameters,
            upvalues,
            parent,
            register_count,
            labels,
            constants,
            instruction_count,
            remaining: instruction_count,
            instruction_index: 0,
            hasher,
        };
        Ok((name, stream))
    }

    fn deserialize_function_type<R: Read>(reader: &mut R) -> BinaryResult<FunctionType> {
        let mut tag = [0u8; 1];
        reader.read_exact(&mut tag)?;
        Ok(match tag[0] {
            0 => {
                let mut data = [0u8; 2];
                reader.read_exact(&mut data)?;
                let bits = data[1];
                if bits == 0 {
                    return Err(invalid_data(
                        "integer function type bit width must be non-zero",
                    ));
                }
                FunctionType::Int {
                    signed: data[0] != 0,
                    bits,
                }
            }
            1 => FunctionType::Float,
            13 => FunctionType::Fixed { bits: 64 },
            2 => FunctionType::String,
            3 => FunctionType::Bool,
            4 => FunctionType::Nil,
            5 => FunctionType::Void,
            6 => FunctionType::Secret(Box::new(Self::deserialize_function_type(reader)?)),
            7 => FunctionType::List(Box::new(Self::deserialize_function_type(reader)?)),
            8 => FunctionType::Dict(
                Box::new(Self::deserialize_function_type(reader)?),
                Box::new(Self::deserialize_function_type(reader)?),
            ),
            9 => FunctionType::Object(read_len_prefixed_string_u16(
                reader,
                "function type object name length",
                "Invalid UTF-8 in function type object name",
            )?),
            10 => {
                let name = read_len_prefixed_string_u16(
                    reader,
                    "function generic type name length",
                    "Invalid UTF-8 in function generic type name",
                )?;
                let param_count = usize::from(read_u16(reader)?);
                let mut params = Vec::new();
                reserve_vec(&mut params, param_count, "function generic parameter count")?;
                for _ in 0..param_count {
                    params.push(Self::deserialize_function_type(reader)?);
                }
                FunctionType::Generic(name, params)
            }
            11 => FunctionType::TypeVar(read_len_prefixed_string_u16(
                reader,
                "function type variable name length",
                "Invalid UTF-8 in function type variable name",
            )?),
            12 => FunctionType::Unknown,
            14 => {
                let mut bits = [0u8; 1];
                reader.read_exact(&mut bits)?;
                if bits[0] == 0 {
                    return Err(invalid_data(
                        "fixed-point function type bit width must be non-zero",
                    ));
                }
                FunctionType::Fixed { bits: bits[0] }
            }
            tag => return Err(invalid_data(format!("unknown function type tag {tag}"))),
        })
    }

    /// Deserializes an instruction from a reader
    ///
    /// # Arguments
    ///
    /// * `reader` - A reader to read the binary data from
    ///
    /// # Returns
    ///
    /// A result containing the deserialized instruction or an error
    fn deserialize_instruction<R: Read>(reader: &mut R) -> BinaryResult<CompiledInstruction> {
        let mut opcode_byte = [0u8; 1];
        reader.read_exact(&mut opcode_byte)?;
        let opcode = opcode_byte[0];

        match opcode {
            x if x == ReducedOpcode::NOP as u8 => Ok(CompiledInstruction::NOP),
            x if x == ReducedOpcode::LD as u8 => {
                let reg = read_usize_u32(reader, "LD register")?;

                let mut offset_bytes = [0u8; 4];
                reader.read_exact(&mut offset_bytes)?;
                let offset = i32::from_le_bytes(offset_bytes);

                Ok(CompiledInstruction::LD(reg, offset))
            }
            x if x == ReducedOpcode::LDI as u8 => {
                let reg = read_usize_u32(reader, "LDI register")?;
                let const_idx = read_usize_u32(reader, "LDI constant index")?;

                Ok(CompiledInstruction::LDI(reg, const_idx))
            }
            x if x == ReducedOpcode::MOV as u8 => {
                let target = read_usize_u32(reader, "MOV target register")?;
                let source = read_usize_u32(reader, "MOV source register")?;

                Ok(CompiledInstruction::MOV(target, source))
            }
            x if x == ReducedOpcode::ADD as u8 => {
                let target = read_usize_u32(reader, "ADD target register")?;
                let src1 = read_usize_u32(reader, "ADD left register")?;
                let src2 = read_usize_u32(reader, "ADD right register")?;

                Ok(CompiledInstruction::ADD(target, src1, src2))
            }
            x if x == ReducedOpcode::SUB as u8 => {
                let target = read_usize_u32(reader, "SUB target register")?;
                let src1 = read_usize_u32(reader, "SUB left register")?;
                let src2 = read_usize_u32(reader, "SUB right register")?;

                Ok(CompiledInstruction::SUB(target, src1, src2))
            }
            x if x == ReducedOpcode::MUL as u8 => {
                let target = read_usize_u32(reader, "MUL target register")?;
                let src1 = read_usize_u32(reader, "MUL left register")?;
                let src2 = read_usize_u32(reader, "MUL right register")?;

                Ok(CompiledInstruction::MUL(target, src1, src2))
            }
            x if x == ReducedOpcode::DIV as u8 => {
                let target = read_usize_u32(reader, "DIV target register")?;
                let src1 = read_usize_u32(reader, "DIV left register")?;
                let src2 = read_usize_u32(reader, "DIV right register")?;

                Ok(CompiledInstruction::DIV(target, src1, src2))
            }
            x if x == ReducedOpcode::MOD as u8 => {
                let target = read_usize_u32(reader, "MOD target register")?;
                let src1 = read_usize_u32(reader, "MOD left register")?;
                let src2 = read_usize_u32(reader, "MOD right register")?;

                Ok(CompiledInstruction::MOD(target, src1, src2))
            }
            x if x == ReducedOpcode::AND as u8 => {
                let target = read_usize_u32(reader, "AND target register")?;
                let src1 = read_usize_u32(reader, "AND left register")?;
                let src2 = read_usize_u32(reader, "AND right register")?;

                Ok(CompiledInstruction::AND(target, src1, src2))
            }
            x if x == ReducedOpcode::OR as u8 => {
                let target = read_usize_u32(reader, "OR target register")?;
                let src1 = read_usize_u32(reader, "OR left register")?;
                let src2 = read_usize_u32(reader, "OR right register")?;

                Ok(CompiledInstruction::OR(target, src1, src2))
            }
            x if x == ReducedOpcode::XOR as u8 => {
                let target = read_usize_u32(reader, "XOR target register")?;
                let src1 = read_usize_u32(reader, "XOR left register")?;
                let src2 = read_usize_u32(reader, "XOR right register")?;

                Ok(CompiledInstruction::XOR(target, src1, src2))
            }
            x if x == ReducedOpcode::NOT as u8 => {
                let target = read_usize_u32(reader, "NOT target register")?;
                let source = read_usize_u32(reader, "NOT source register")?;

                Ok(CompiledInstruction::NOT(target, source))
            }
            x if x == ReducedOpcode::SHL as u8 => {
                let target = read_usize_u32(reader, "SHL target register")?;
                let src1 = read_usize_u32(reader, "SHL left register")?;
                let src2 = read_usize_u32(reader, "SHL right register")?;

                Ok(CompiledInstruction::SHL(target, src1, src2))
            }
            x if x == ReducedOpcode::SHR as u8 => {
                let target = read_usize_u32(reader, "SHR target register")?;
                let src1 = read_usize_u32(reader, "SHR left register")?;
                let src2 = read_usize_u32(reader, "SHR right register")?;

                Ok(CompiledInstruction::SHR(target, src1, src2))
            }
            x if x == ReducedOpcode::JMP as u8 => {
                let label = read_len_prefixed_string_u16(
                    reader,
                    "JMP label length",
                    "Invalid UTF-8 in label",
                )?;

                Ok(CompiledInstruction::JMP(label))
            }
            x if x == ReducedOpcode::JMPEQ as u8 => {
                let label = read_len_prefixed_string_u16(
                    reader,
                    "JMPEQ label length",
                    "Invalid UTF-8 in label",
                )?;

                Ok(CompiledInstruction::JMPEQ(label))
            }
            x if x == ReducedOpcode::JMPNEQ as u8 => {
                let label = read_len_prefixed_string_u16(
                    reader,
                    "JMPNEQ label length",
                    "Invalid UTF-8 in label",
                )?;

                Ok(CompiledInstruction::JMPNEQ(label))
            }
            x if x == ReducedOpcode::JMPLT as u8 => {
                let label = read_len_prefixed_string_u16(
                    reader,
                    "JMPLT label length",
                    "Invalid UTF-8 in label",
                )?;

                Ok(CompiledInstruction::JMPLT(label))
            }
            x if x == ReducedOpcode::JMPGT as u8 => {
                let label = read_len_prefixed_string_u16(
                    reader,
                    "JMPGT label length",
                    "Invalid UTF-8 in label",
                )?;

                Ok(CompiledInstruction::JMPGT(label))
            }
            x if x == ReducedOpcode::CALL as u8 => {
                let function_name = read_len_prefixed_string_u16(
                    reader,
                    "CALL function name length",
                    "Invalid UTF-8 in function name",
                )?;

                Ok(CompiledInstruction::CALL(function_name))
            }
            x if x == ReducedOpcode::RET as u8 => {
                let reg = read_usize_u32(reader, "RET register")?;

                Ok(CompiledInstruction::RET(reg))
            }
            x if x == ReducedOpcode::PUSHARG as u8 => {
                let reg = read_usize_u32(reader, "PUSHARG register")?;

                Ok(CompiledInstruction::PUSHARG(reg))
            }
            x if x == ReducedOpcode::CMP as u8 => {
                let reg1 = read_usize_u32(reader, "CMP left register")?;
                let reg2 = read_usize_u32(reader, "CMP right register")?;

                Ok(CompiledInstruction::CMP(reg1, reg2))
            }
            x if x == ReducedOpcode::LDS as u8 => {
                let reg = read_usize_u32(reader, "LDS register")?;
                let slot = read_usize_u32(reader, "LDS slot")?;
                Ok(CompiledInstruction::LDS(reg, slot))
            }
            x if x == ReducedOpcode::STS as u8 => {
                let slot = read_usize_u32(reader, "STS slot")?;
                let reg = read_usize_u32(reader, "STS register")?;
                Ok(CompiledInstruction::STS(slot, reg))
            }
            _ => Err(BinaryError::InvalidData(format!(
                "Unknown opcode: {}",
                opcode
            ))),
        }
    }
}

/// Utility functions for working with compiled binaries
pub mod utils {
    use super::*;
    use std::fs::File;
    use std::path::Path;

    /// Loads a compiled binary from a file
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the file
    ///
    /// # Returns
    ///
    /// A result containing the loaded compiled binary or an error
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> BinaryResult<CompiledBinary> {
        let mut file = File::open(path)?;
        CompiledBinary::deserialize(&mut file)
    }

    /// Saves a compiled binary to a file
    ///
    /// # Arguments
    ///
    /// * `binary` - The compiled binary to save
    /// * `path` - The path to the file
    ///
    /// # Returns
    ///
    /// A result indicating success or an error
    pub fn save_to_file<P: AsRef<Path>>(binary: &CompiledBinary, path: P) -> BinaryResult<()> {
        // The serializer writes each field with a tiny write_all; unbuffered, every
        // instruction becomes several write(2) syscalls. Buffer ~1MB and flush.
        let mut writer = std::io::BufWriter::with_capacity(1 << 20, File::create(path)?);
        binary.serialize(&mut writer)?;
        writer.flush()?;
        Ok(())
    }

    /// Converts a compiled binary to VM functions
    ///
    /// # Arguments
    ///
    /// * `binary` - The compiled binary to convert
    ///
    /// # Returns
    ///
    /// A vector of VM functions
    pub fn to_vm_functions(binary: &CompiledBinary) -> Vec<VMFunction> {
        binary.to_vm_functions()
    }

    /// Converts a compiled binary to executable VM functions.
    ///
    /// Returns an error when a binary contains conflicting duplicate function
    /// names. Identical duplicate function records are deduplicated.
    pub fn try_to_vm_functions(binary: &CompiledBinary) -> BinaryResult<Vec<VMFunction>> {
        binary.try_to_vm_functions()
    }

    /// Creates a compiled binary from VM functions
    ///
    /// # Arguments
    ///
    /// * `functions` - The VM functions to convert
    ///
    /// # Returns
    ///
    /// A compiled binary
    pub fn from_vm_functions(functions: &[VMFunction]) -> CompiledBinary {
        CompiledBinary::from_vm_functions(functions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn assert_invalid_data<T>(result: BinaryResult<T>, expected: &str) {
        match result {
            Err(BinaryError::InvalidData(message)) => {
                assert!(
                    message.contains(expected),
                    "expected error containing {expected:?}, got {message:?}"
                );
            }
            Err(other) => panic!("expected InvalidData error, got {other:?}"),
            Ok(_) => panic!("expected operation to fail"),
        }
    }

    fn binary_header() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC_BYTES);
        bytes.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes
    }

    fn binary_header_with_version(version: u16) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC_BYTES);
        bytes.extend_from_slice(&version.to_le_bytes());
        bytes
    }

    fn append_empty_function_prefix(bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&4u16.to_le_bytes());
        bytes.extend_from_slice(b"main");
        bytes.extend_from_slice(&0u16.to_le_bytes()); // register count
        bytes.extend_from_slice(&0u16.to_le_bytes()); // parameters
        bytes.extend_from_slice(&0u16.to_le_bytes()); // parameter types
        bytes.push(12); // return type: Unknown
        bytes.extend_from_slice(&0u16.to_le_bytes()); // upvalues
        bytes.push(0); // no parent
        bytes.extend_from_slice(&0u16.to_le_bytes()); // labels
    }

    #[test]
    fn bytecode_v2_client_io_manifest_round_trips() {
        let mut binary = CompiledBinary::new();
        binary.client_io_manifest = ClientIoManifest {
            mpc_backend: MpcBackend::Avss,
            mpc_curve: MpcCurve::Ed25519,
            clients: vec![
                ClientIoSchema {
                    client_slot: 7,
                    inputs: vec![
                        ShareType::secret_int(64),
                        ShareType::boolean(),
                        ShareType::secret_fixed_point_from_bits(96, 24),
                    ],
                    outputs: vec![
                        ShareType::secret_fixed_point_from_bits(128, 32),
                        ShareType::secret_int(16),
                    ],
                },
                ClientIoSchema {
                    client_slot: 9,
                    inputs: vec![],
                    outputs: vec![ShareType::boolean()],
                },
            ],
            preprocessing_demand: PreprocessingDemand::default(),
            dynamic_client_inputs: vec![DynamicClientInputSchema {
                first_client_slot: 10,
                inputs: vec![ShareType::secret_fixed_point_from_bits(64, 16); 4],
            }],
        };

        let mut buffer = Vec::new();
        binary.serialize(&mut buffer).unwrap();

        let deserialized = CompiledBinary::deserialize(&mut Cursor::new(&buffer)).unwrap();
        assert_eq!(deserialized.version, FORMAT_VERSION);
        assert_eq!(deserialized.client_io_manifest, binary.client_io_manifest);
    }

    #[test]
    fn bytecode_v2_client_io_manifest_defaults_to_honeybadger_backend() {
        let mut bytes = binary_header_with_version(2);
        bytes.extend_from_slice(&0u32.to_le_bytes()); // constants
        bytes.extend_from_slice(&0u32.to_le_bytes()); // functions
        bytes.extend_from_slice(&0u32.to_le_bytes()); // client schemas

        let deserialized = CompiledBinary::deserialize(&mut Cursor::new(bytes)).unwrap();
        assert_eq!(deserialized.version, 2);
        assert_eq!(
            deserialized.client_io_manifest.mpc_backend,
            MpcBackend::HoneyBadger
        );
        assert_eq!(
            deserialized.client_io_manifest.mpc_curve,
            MpcCurve::Bls12_381
        );
        assert!(deserialized.client_io_manifest.clients.is_empty());
    }

    #[test]
    fn bytecode_v3_avss_manifest_defaults_to_bls12381_curve() {
        let mut bytes = binary_header_with_version(3);
        bytes.extend_from_slice(&0u32.to_le_bytes()); // constants
        bytes.extend_from_slice(&0u32.to_le_bytes()); // functions
        bytes.push(1); // avss backend
        bytes.extend_from_slice(&0u32.to_le_bytes()); // client schemas

        let deserialized = CompiledBinary::deserialize(&mut Cursor::new(bytes)).unwrap();
        assert_eq!(deserialized.version, 3);
        assert_eq!(
            deserialized.client_io_manifest.mpc_backend,
            MpcBackend::Avss
        );
        assert_eq!(
            deserialized.client_io_manifest.mpc_curve,
            MpcCurve::Bls12_381
        );
        assert!(deserialized.client_io_manifest.clients.is_empty());
    }

    #[test]
    fn bytecode_v1_deserializes_with_empty_client_io_manifest() {
        let mut bytes = binary_header_with_version(1);
        bytes.extend_from_slice(&0u32.to_le_bytes()); // constants
        bytes.extend_from_slice(&0u32.to_le_bytes()); // functions

        let deserialized = CompiledBinary::deserialize(&mut Cursor::new(bytes)).unwrap();
        assert_eq!(deserialized.version, 1);
        assert_eq!(
            deserialized.client_io_manifest.mpc_backend,
            MpcBackend::HoneyBadger
        );
        assert!(deserialized.client_io_manifest.clients.is_empty());
    }

    #[test]
    fn deserialize_rejects_invalid_share_type_metadata() {
        let mut bytes = binary_header();
        bytes.extend_from_slice(&0u32.to_le_bytes()); // constants
        bytes.extend_from_slice(&0u32.to_le_bytes()); // functions
        bytes.push(0); // HoneyBadger backend
        bytes.push(0); // BLS12-381 curve
        bytes.extend_from_slice(&1u32.to_le_bytes()); // client schemas
        bytes.extend_from_slice(&0u64.to_le_bytes()); // client slot
        bytes.extend_from_slice(&1u32.to_le_bytes()); // inputs
        bytes.push(0); // SecretInt
        bytes.extend_from_slice(&0u32.to_le_bytes()); // invalid bit length
        bytes.extend_from_slice(&0u32.to_le_bytes()); // outputs

        assert_invalid_data(
            CompiledBinary::deserialize(&mut Cursor::new(bytes)),
            "invalid SecretInt metadata",
        );
    }

    #[test]
    fn test_create_and_convert() {
        // Create a simple function
        let function = VMFunction::new(
            "test_function".to_string(),
            vec![],
            vec![],
            None,
            2,
            vec![
                Instruction::NOP,
                Instruction::LDI(0, Value::I64(42)),
                Instruction::RET(0),
            ],
            HashMap::new(),
        );

        // Convert to compiled binary
        let binary = CompiledBinary::from_vm_functions(&[function]);

        // Check the binary
        assert_eq!(binary.version, FORMAT_VERSION);
        assert_eq!(binary.constants.len(), 1);
        assert_eq!(binary.functions.len(), 1);
        assert_eq!(binary.functions[0].name, "test_function");
        assert_eq!(binary.functions[0].register_count, 2);
        assert_eq!(binary.functions[0].instructions.len(), 3);

        // Convert back to VM functions
        let vm_functions = binary.to_vm_functions();

        // Check the VM functions
        assert_eq!(vm_functions.len(), 1);
        assert_eq!(vm_functions[0].name(), "test_function");
        assert_eq!(vm_functions[0].register_count(), 2);
        assert_eq!(vm_functions[0].instructions().len(), 3);

        // Check that the instructions were converted correctly
        match &vm_functions[0].instructions()[0] {
            Instruction::NOP => {}
            _ => panic!("Expected NOP instruction"),
        }

        match &vm_functions[0].instructions()[1] {
            Instruction::LDI(reg, value) => {
                assert_eq!(*reg, 0);
                assert_eq!(*value, Value::I64(42));
            }
            _ => panic!("Expected LDI instruction"),
        }

        match &vm_functions[0].instructions()[2] {
            Instruction::RET(reg) => {
                assert_eq!(*reg, 0);
            }
            _ => panic!("Expected RET instruction"),
        }
    }

    #[test]
    fn from_vm_functions_assigns_constant_indices_while_converting() {
        let function = VMFunction::new(
            "main".to_string(),
            vec![],
            vec![],
            None,
            2,
            vec![
                Instruction::LDI(0, Value::I64(7)),
                Instruction::LDI(1, Value::I64(7)),
                Instruction::LDI(0, Value::I64(9)),
                Instruction::RET(0),
            ],
            HashMap::new(),
        );

        let binary = CompiledBinary::from_vm_functions(&[function]);

        assert_eq!(binary.constants, vec![Value::I64(7), Value::I64(9)]);
        assert_eq!(
            binary.functions[0].instructions,
            vec![
                CompiledInstruction::LDI(0, 0),
                CompiledInstruction::LDI(1, 0),
                CompiledInstruction::LDI(0, 1),
                CompiledInstruction::RET(0),
            ]
        );
    }

    #[test]
    fn try_to_vm_functions_deduplicates_identical_function_records() {
        let function = VMFunction::new(
            "main".to_string(),
            vec![],
            vec![],
            None,
            1,
            vec![
                Instruction::NOP,
                Instruction::LDI(0, Value::I64(42)),
                Instruction::RET(0),
            ],
            HashMap::new(),
        );
        let mut binary = CompiledBinary::from_vm_functions(&[function]);
        binary.functions.push(binary.functions[0].clone());

        assert_eq!(
            binary.to_vm_functions().len(),
            2,
            "legacy conversion preserves raw function table entries"
        );
        let vm_functions = binary
            .try_to_vm_functions()
            .expect("identical duplicate functions should be accepted");

        assert_eq!(vm_functions.len(), 1);
        assert_eq!(vm_functions[0].name(), "main");
    }

    #[test]
    fn try_to_vm_functions_rejects_conflicting_duplicate_names() {
        let first = VMFunction::new(
            "main".to_string(),
            vec![],
            vec![],
            None,
            1,
            vec![Instruction::LDI(0, Value::I64(1)), Instruction::RET(0)],
            HashMap::new(),
        );
        let second = VMFunction::new(
            "main".to_string(),
            vec![],
            vec![],
            None,
            1,
            vec![Instruction::LDI(0, Value::I64(2)), Instruction::RET(0)],
            HashMap::new(),
        );
        let binary = CompiledBinary::from_vm_functions(&[first, second]);

        assert_invalid_data(
            binary.try_to_vm_functions(),
            "duplicate function 'main' has conflicting definitions",
        );
    }

    #[test]
    fn try_to_vm_functions_rejects_invalid_constant_indices() {
        let binary = CompiledBinary {
            version: FORMAT_VERSION,
            constants: vec![],
            functions: vec![CompiledFunction {
                name: "main".to_string(),
                register_count: 1,
                parameters: vec![],
                parameter_types: vec![],
                return_type: FunctionType::Unknown,
                upvalues: vec![],
                parent: None,
                labels: HashMap::new(),
                instructions: vec![CompiledInstruction::LDI(0, 0)],
            }],
            client_io_manifest: ClientIoManifest::default(),
        };

        assert_invalid_data(
            binary.try_to_vm_functions(),
            "Function main instruction 0 references constant 0 but constant pool has 0 values",
        );
    }

    #[test]
    fn try_to_vm_functions_rejects_unrepresentable_frame_register_count() {
        let binary = CompiledBinary {
            version: FORMAT_VERSION,
            constants: vec![Value::I64(1)],
            functions: vec![CompiledFunction {
                name: "main".to_string(),
                register_count: 1,
                parameters: vec![],
                parameter_types: vec![],
                return_type: FunctionType::Unknown,
                upvalues: vec![],
                parent: None,
                labels: HashMap::new(),
                instructions: vec![CompiledInstruction::LDI(usize::MAX, 0)],
            }],
            client_io_manifest: ClientIoManifest::default(),
        };

        assert_invalid_data(
            binary.try_to_vm_functions(),
            "Function main references register",
        );
        assert_invalid_data(
            binary.try_to_vm_functions(),
            "cannot fit in a frame register count",
        );
    }

    #[test]
    #[should_panic(expected = "compiled binary contains invalid function data")]
    fn to_vm_functions_panics_on_invalid_constant_indices() {
        let binary = CompiledBinary {
            version: FORMAT_VERSION,
            constants: vec![],
            functions: vec![CompiledFunction {
                name: "main".to_string(),
                register_count: 1,
                parameters: vec![],
                parameter_types: vec![],
                return_type: FunctionType::Unknown,
                upvalues: vec![],
                parent: None,
                labels: HashMap::new(),
                instructions: vec![CompiledInstruction::LDI(0, 0)],
            }],
            client_io_manifest: ClientIoManifest::default(),
        };

        let _ = binary.to_vm_functions();
    }

    #[test]
    #[should_panic(expected = "compiled binary contains invalid function data")]
    fn to_vm_functions_panics_on_invalid_frame_register_count() {
        let binary = CompiledBinary {
            version: FORMAT_VERSION,
            constants: vec![Value::I64(1)],
            functions: vec![CompiledFunction {
                name: "main".to_string(),
                register_count: 1,
                parameters: vec![],
                parameter_types: vec![],
                return_type: FunctionType::Unknown,
                upvalues: vec![],
                parent: None,
                labels: HashMap::new(),
                instructions: vec![CompiledInstruction::LDI(usize::MAX, 0)],
            }],
            client_io_manifest: ClientIoManifest::default(),
        };

        let _ = binary.to_vm_functions();
    }

    #[test]
    fn test_serialize_deserialize() {
        // Create a simple function
        let function = VMFunction::new(
            "test_function".to_string(),
            vec![],
            vec![],
            None,
            2,
            vec![
                Instruction::NOP,
                Instruction::LDI(0, Value::I64(42)),
                Instruction::RET(0),
            ],
            HashMap::new(),
        );

        // Convert to compiled binary
        let binary = CompiledBinary::from_vm_functions(&[function]);

        // Serialize the binary
        let mut buffer = Vec::new();
        binary.serialize(&mut buffer).unwrap();

        // Deserialize the binary
        let deserialized = CompiledBinary::deserialize(&mut Cursor::new(&buffer)).unwrap();

        // Check the deserialized binary
        assert_eq!(deserialized.version, FORMAT_VERSION);
        assert_eq!(deserialized.constants.len(), 1);
        assert_eq!(deserialized.functions.len(), 1);
        assert_eq!(deserialized.functions[0].name, "test_function");
        assert_eq!(deserialized.functions[0].register_count, 2);
        assert_eq!(deserialized.functions[0].instructions.len(), 3);

        // Convert back to VM functions
        let vm_functions = deserialized.to_vm_functions();

        // Check the VM functions
        assert_eq!(vm_functions.len(), 1);
        assert_eq!(vm_functions[0].name(), "test_function");
        assert_eq!(vm_functions[0].register_count(), 2);
        assert_eq!(vm_functions[0].instructions().len(), 3);
        assert!(matches!(
            vm_functions[0].instructions()[0],
            Instruction::NOP
        ));
    }

    #[test]
    fn bytecode_v7_function_type_metadata_round_trips() {
        let mut binary = CompiledBinary::new();
        binary.functions.push(CompiledFunction {
            name: "main".to_string(),
            register_count: 3,
            parameters: vec!["a".to_string(), "n".to_string()],
            parameter_types: vec![
                FunctionType::List(Box::new(FunctionType::List(
                    Box::new(FunctionType::int64()),
                ))),
                FunctionType::Secret(Box::new(FunctionType::fix32())),
            ],
            return_type: FunctionType::List(Box::new(FunctionType::fix32())),
            upvalues: vec![],
            parent: None,
            labels: HashMap::new(),
            instructions: vec![CompiledInstruction::RET(0)],
        });

        let mut buffer = Vec::new();
        binary.serialize(&mut buffer).unwrap();

        let deserialized = CompiledBinary::deserialize(&mut Cursor::new(&buffer)).unwrap();
        let function = &deserialized.functions[0];
        assert_eq!(deserialized.version, FORMAT_VERSION);
        assert_eq!(
            function.parameter_types,
            binary.functions[0].parameter_types
        );
        assert_eq!(function.return_type, binary.functions[0].return_type);
    }

    #[test]
    fn serialize_deserialize_preserves_negative_i8_constants() {
        let function = VMFunction::new(
            "signed_byte".to_string(),
            vec![],
            vec![],
            None,
            1,
            vec![Instruction::LDI(0, Value::I8(-7)), Instruction::RET(0)],
            HashMap::new(),
        );
        let binary = CompiledBinary::from_vm_functions(&[function]);

        let mut buffer = Vec::new();
        binary.serialize(&mut buffer).unwrap();

        let deserialized = CompiledBinary::deserialize(&mut Cursor::new(&buffer)).unwrap();
        let vm_functions = deserialized.to_vm_functions();

        match &vm_functions[0].instructions()[0] {
            Instruction::LDI(reg, value) => {
                assert_eq!(*reg, 0);
                assert_eq!(*value, Value::I8(-7));
            }
            other => panic!("Expected LDI instruction, got {other:?}"),
        }
    }

    #[test]
    fn serialize_rejects_function_metadata_that_exceeds_binary_format() {
        let binary = CompiledBinary {
            version: FORMAT_VERSION,
            constants: vec![],
            functions: vec![CompiledFunction {
                name: "oversized_register_frame".to_string(),
                register_count: usize::from(u16::MAX) + 1,
                parameters: vec![],
                parameter_types: vec![],
                return_type: FunctionType::Unknown,
                upvalues: vec![],
                parent: None,
                labels: HashMap::new(),
                instructions: vec![],
            }],
            client_io_manifest: ClientIoManifest::default(),
        };

        let mut buffer = Vec::new();
        assert_invalid_data(binary.serialize(&mut buffer), "register count");
    }

    #[test]
    fn serialize_rejects_u16_string_lengths_that_exceed_binary_format() {
        let binary = CompiledBinary {
            version: FORMAT_VERSION,
            constants: vec![],
            functions: vec![CompiledFunction {
                name: "x".repeat(usize::from(u16::MAX) + 1),
                register_count: 0,
                parameters: vec![],
                parameter_types: vec![],
                return_type: FunctionType::Unknown,
                upvalues: vec![],
                parent: None,
                labels: HashMap::new(),
                instructions: vec![],
            }],
            client_io_manifest: ClientIoManifest::default(),
        };

        let mut buffer = Vec::new();
        assert_invalid_data(binary.serialize(&mut buffer), "function name length");
    }

    #[test]
    fn serialize_rejects_instruction_operands_that_exceed_binary_format() {
        let oversized_operand = match usize::try_from(u64::from(u32::MAX) + 1) {
            Ok(value) => value,
            Err(_) => return,
        };
        let binary = CompiledBinary {
            version: FORMAT_VERSION,
            constants: vec![],
            functions: vec![CompiledFunction {
                name: "oversized_operand".to_string(),
                register_count: 1,
                parameters: vec![],
                parameter_types: vec![],
                return_type: FunctionType::Unknown,
                upvalues: vec![],
                parent: None,
                labels: HashMap::new(),
                instructions: vec![CompiledInstruction::RET(oversized_operand)],
            }],
            client_io_manifest: ClientIoManifest::default(),
        };

        let mut buffer = Vec::new();
        assert_invalid_data(binary.serialize(&mut buffer), "RET register");
    }

    #[test]
    fn serialize_rejects_label_offsets_that_exceed_binary_format() {
        let oversized_offset = match usize::try_from(u64::from(u32::MAX) + 1) {
            Ok(value) => value,
            Err(_) => return,
        };
        let mut labels = HashMap::new();
        labels.insert("too_far".to_string(), oversized_offset);

        let binary = CompiledBinary {
            version: FORMAT_VERSION,
            constants: vec![],
            functions: vec![CompiledFunction {
                name: "oversized_label_offset".to_string(),
                register_count: 0,
                parameters: vec![],
                parameter_types: vec![],
                return_type: FunctionType::Unknown,
                upvalues: vec![],
                parent: None,
                labels,
                instructions: vec![],
            }],
            client_io_manifest: ClientIoManifest::default(),
        };

        let mut buffer = Vec::new();
        assert_invalid_data(binary.serialize(&mut buffer), "label offset");
    }

    #[test]
    fn deserialize_rejects_constant_count_above_supported_limit_before_allocation() {
        let mut bytes = binary_header();
        bytes.extend_from_slice(
            &(u32::try_from(MAX_BINARY_COLLECTION_LEN).unwrap() + 1).to_le_bytes(),
        );

        assert_invalid_data(
            CompiledBinary::deserialize(&mut Cursor::new(bytes)),
            "constant count",
        );
    }

    #[test]
    fn deserialize_rejects_function_count_above_supported_limit_before_allocation() {
        let mut bytes = binary_header();
        bytes.extend_from_slice(&0u32.to_le_bytes()); // constants
        bytes.extend_from_slice(
            &(u32::try_from(MAX_BINARY_COLLECTION_LEN).unwrap() + 1).to_le_bytes(),
        );

        assert_invalid_data(
            CompiledBinary::deserialize(&mut Cursor::new(bytes)),
            "function count",
        );
    }

    #[test]
    fn deserialize_rejects_string_payload_above_supported_limit_before_allocation() {
        let mut bytes = binary_header();
        bytes.extend_from_slice(&1u32.to_le_bytes()); // one constant
        bytes.push(11); // Value::String
        bytes.extend_from_slice(
            &(u32::try_from(MAX_BINARY_STRING_BYTES).unwrap() + 1).to_le_bytes(),
        );

        assert_invalid_data(
            CompiledBinary::deserialize(&mut Cursor::new(bytes)),
            "string length",
        );
    }

    #[test]
    fn deserialize_rejects_instruction_count_above_supported_limit_before_allocation() {
        let mut bytes = binary_header();
        bytes.extend_from_slice(&0u32.to_le_bytes()); // constants
        bytes.extend_from_slice(&1u32.to_le_bytes()); // functions
        append_empty_function_prefix(&mut bytes);
        bytes.extend_from_slice(&(u32::try_from(MAX_INSTRUCTION_COUNT).unwrap() + 1).to_le_bytes());

        assert_invalid_data(
            CompiledBinary::deserialize(&mut Cursor::new(bytes)),
            "instruction count",
        );
    }

    #[test]
    fn deserialize_rejects_invalid_parent_presence_flag() {
        let mut bytes = binary_header();
        bytes.extend_from_slice(&0u32.to_le_bytes()); // constants
        bytes.extend_from_slice(&1u32.to_le_bytes()); // functions
        bytes.extend_from_slice(&4u16.to_le_bytes());
        bytes.extend_from_slice(b"main");
        bytes.extend_from_slice(&0u16.to_le_bytes()); // register count
        bytes.extend_from_slice(&0u16.to_le_bytes()); // parameters
        bytes.extend_from_slice(&0u16.to_le_bytes()); // parameter types
        bytes.push(12); // return type: Unknown
        bytes.extend_from_slice(&0u16.to_le_bytes()); // upvalues
        bytes.push(2); // invalid parent flag

        assert_invalid_data(
            CompiledBinary::deserialize(&mut Cursor::new(bytes)),
            "Invalid parent presence flag",
        );
    }

    #[test]
    fn test_complex_function() {
        // Create a function with labels and jumps
        let mut labels = HashMap::new();
        labels.insert("loop_start".to_string(), 2);
        labels.insert("loop_end".to_string(), 7);

        let function = VMFunction::new(
            "factorial".to_string(),
            vec!["n".to_string()],
            vec![],
            None,
            4,
            vec![
                // Initialize result to 1
                Instruction::LDI(1, Value::I64(1)),
                // Initialize counter to n
                Instruction::MOV(2, 0),
                // loop_start:
                // Check if counter <= 1
                Instruction::LDI(3, Value::I64(1)),
                Instruction::CMP(2, 3),
                Instruction::JMPEQ("loop_end".to_string()),
                // result = result * counter
                Instruction::MUL(1, 1, 2),
                // counter = counter - 1
                Instruction::SUB(2, 2, 3),
                // Jump back to loop_start
                Instruction::JMP("loop_start".to_string()),
                // loop_end:
                // Return result
                Instruction::MOV(0, 1),
                Instruction::RET(0),
            ],
            labels,
        );

        // Convert to compiled binary
        let binary = CompiledBinary::from_vm_functions(&[function]);

        // Serialize the binary
        let mut buffer = Vec::new();
        binary.serialize(&mut buffer).unwrap();

        // Deserialize the binary
        let deserialized = CompiledBinary::deserialize(&mut Cursor::new(&buffer)).unwrap();

        // Convert back to VM functions
        let vm_functions = deserialized.to_vm_functions();

        // Check the VM functions
        assert_eq!(vm_functions.len(), 1);
        assert_eq!(vm_functions[0].name(), "factorial");
        assert_eq!(vm_functions[0].parameters(), &["n".to_string()]);
        assert_eq!(vm_functions[0].register_count(), 4);
        assert_eq!(vm_functions[0].instructions().len(), 10);

        // Check that the labels were deserialized correctly
        assert_eq!(vm_functions[0].labels().len(), 2);
        assert_eq!(vm_functions[0].labels().get("loop_start"), Some(&2));
        assert_eq!(vm_functions[0].labels().get("loop_end"), Some(&7));
    }

    #[test]
    fn to_vm_functions_expands_compact_secret_register_counts() {
        let binary = CompiledBinary {
            version: FORMAT_VERSION,
            constants: vec![Value::I64(42)],
            functions: vec![CompiledFunction {
                name: "uses_secret_bank".to_string(),
                register_count: 2,
                parameters: vec![],
                parameter_types: vec![],
                return_type: FunctionType::Unknown,
                upvalues: vec![],
                parent: None,
                labels: HashMap::new(),
                instructions: vec![
                    CompiledInstruction::LDI(16, 0),
                    CompiledInstruction::RET(16),
                ],
            }],
            client_io_manifest: ClientIoManifest::default(),
        };

        let vm_functions = binary.to_vm_functions();

        assert_eq!(vm_functions[0].register_count(), 17);
    }

    #[test]
    fn try_into_vm_functions_expands_compact_secret_register_counts() {
        let binary = CompiledBinary {
            version: FORMAT_VERSION,
            constants: vec![Value::I64(42)],
            functions: vec![CompiledFunction {
                name: "uses_secret_bank".to_string(),
                register_count: 2,
                parameters: vec![],
                parameter_types: vec![],
                return_type: FunctionType::Unknown,
                upvalues: vec![],
                parent: None,
                labels: HashMap::new(),
                instructions: vec![
                    CompiledInstruction::LDI(16, 0),
                    CompiledInstruction::RET(16),
                ],
            }],
            client_io_manifest: ClientIoManifest::default(),
        };

        let vm_functions = binary.try_into_vm_functions().unwrap();

        assert_eq!(vm_functions[0].register_count(), 17);
    }

    #[test]
    fn try_for_each_vm_function_from_reader_expands_compact_secret_register_counts() {
        let binary = CompiledBinary {
            version: FORMAT_VERSION,
            constants: vec![Value::I64(42)],
            functions: vec![CompiledFunction {
                name: "uses_secret_bank".to_string(),
                register_count: 2,
                parameters: vec![],
                parameter_types: vec![],
                return_type: FunctionType::Unknown,
                upvalues: vec![],
                parent: None,
                labels: HashMap::new(),
                instructions: vec![
                    CompiledInstruction::LDI(16, 0),
                    CompiledInstruction::RET(16),
                ],
            }],
            client_io_manifest: ClientIoManifest::default(),
        };
        let mut bytes = Vec::new();
        binary.serialize(&mut bytes).unwrap();

        let mut register_counts = Vec::new();
        let (count, _version, _manifest) = CompiledBinary::try_for_each_vm_function_from_reader(
            &mut Cursor::new(bytes),
            |function| {
                register_counts.push(function.register_count());
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(count, 1);
        assert_eq!(register_counts, vec![17]);
    }

    #[test]
    fn try_for_each_vm_function_from_reader_streams_functions_and_returns_manifest() {
        let binary = CompiledBinary {
            version: FORMAT_VERSION,
            constants: vec![Value::I64(42)],
            functions: vec![CompiledFunction {
                name: "uses_secret_bank".to_string(),
                register_count: 2,
                parameters: vec![],
                parameter_types: vec![],
                return_type: FunctionType::Unknown,
                upvalues: vec![],
                parent: None,
                labels: HashMap::new(),
                instructions: vec![
                    CompiledInstruction::LDI(16, 0),
                    CompiledInstruction::RET(16),
                ],
            }],
            client_io_manifest: ClientIoManifest {
                preprocessing_demand: PreprocessingDemand {
                    triples: 7,
                    randoms: 2,
                    prandbits: 0,
                    prandints: 0,
                    dynamic: false,
                },
                ..ClientIoManifest::default()
            },
        };
        let mut bytes = Vec::new();
        binary.serialize(&mut bytes).unwrap();

        let mut register_counts = Vec::new();
        let (count, version, manifest) = CompiledBinary::try_for_each_vm_function_from_reader(
            &mut Cursor::new(bytes),
            |function| {
                register_counts.push(function.register_count());
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(count, 1);
        assert_eq!(version, FORMAT_VERSION);
        assert_eq!(register_counts, vec![17]);
        assert_eq!(manifest.preprocessing_demand.triples, 7);
        assert_eq!(manifest.preprocessing_demand.randoms, 2);
    }

    #[test]
    fn try_to_vm_functions_preserves_source_instructions_for_tracing() {
        let binary = CompiledBinary {
            version: FORMAT_VERSION,
            constants: vec![Value::I64(42)],
            functions: vec![CompiledFunction {
                name: "traceable".to_string(),
                register_count: 1,
                parameters: vec![],
                parameter_types: vec![],
                return_type: FunctionType::Unknown,
                upvalues: vec![],
                parent: None,
                labels: HashMap::new(),
                instructions: vec![CompiledInstruction::LDI(0, 0), CompiledInstruction::RET(0)],
            }],
            client_io_manifest: ClientIoManifest::default(),
        };

        let functions = binary.try_to_vm_functions().unwrap();

        assert_eq!(functions.len(), 1);
        let instructions = functions[0].instructions();
        assert_eq!(instructions.len(), 2);
        assert!(matches!(
            instructions[0],
            Instruction::LDI(0, Value::I64(42))
        ));
        assert!(matches!(instructions[1], Instruction::RET(0)));
    }

    #[test]
    fn try_for_each_vm_function_from_reader_skips_identical_duplicate_records() {
        let function = CompiledFunction {
            name: "same".to_string(),
            register_count: 1,
            parameters: vec![],
            parameter_types: vec![],
            return_type: FunctionType::Unknown,
            upvalues: vec![],
            parent: None,
            labels: HashMap::new(),
            instructions: vec![CompiledInstruction::RET(0)],
        };
        let binary = CompiledBinary {
            version: FORMAT_VERSION,
            constants: vec![],
            functions: vec![function.clone(), function],
            client_io_manifest: ClientIoManifest::default(),
        };
        let mut bytes = Vec::new();
        binary.serialize(&mut bytes).unwrap();

        let mut names = Vec::new();
        let (count, _version, _manifest) = CompiledBinary::try_for_each_vm_function_from_reader(
            &mut Cursor::new(bytes),
            |function| {
                names.push(function.name().to_string());
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(count, 1);
        assert_eq!(names, vec!["same"]);
    }

    #[test]
    fn try_for_each_vm_function_from_reader_rejects_conflicting_duplicate_records() {
        let mut first = CompiledFunction {
            name: "same".to_string(),
            register_count: 1,
            parameters: vec![],
            parameter_types: vec![],
            return_type: FunctionType::Unknown,
            upvalues: vec![],
            parent: None,
            labels: HashMap::new(),
            instructions: vec![CompiledInstruction::RET(0)],
        };
        let mut second = first.clone();
        second.instructions = vec![CompiledInstruction::LDI(0, 0), CompiledInstruction::RET(0)];
        first.instructions = vec![CompiledInstruction::RET(0)];
        let binary = CompiledBinary {
            version: FORMAT_VERSION,
            constants: vec![Value::I64(42)],
            functions: vec![first, second],
            client_io_manifest: ClientIoManifest::default(),
        };
        let mut bytes = Vec::new();
        binary.serialize(&mut bytes).unwrap();

        let err =
            CompiledBinary::try_for_each_vm_function_from_reader(&mut Cursor::new(bytes), |_| {
                Ok(())
            })
            .unwrap_err();

        assert!(
            matches!(err, BinaryError::InvalidData(message) if message.contains("duplicate function 'same'"))
        );
    }
}
