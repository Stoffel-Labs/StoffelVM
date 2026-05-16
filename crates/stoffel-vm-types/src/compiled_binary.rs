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

use crate::core_types::{F64, Value};
use crate::functions::{FunctionError, VMFunction};
use crate::instructions::{Instruction, ReducedOpcode};
use std::collections::HashMap;
use std::io::{self, Read, Write};

// Magic bytes that identify a StoffelVM bytecode file
pub const MAGIC_BYTES: &[u8; 4] = b"STFL";
// Current bytecode format version
pub const FORMAT_VERSION: u16 = 1;

const MAX_BINARY_COLLECTION_LEN: usize = 1_000_000;
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

fn read_u32<R: Read>(reader: &mut R) -> BinaryResult<u32> {
    let mut bytes = [0u8; 4];
    reader.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
            };

            compiled_instructions.push(compiled);
        }

        // Create the compiled function
        let compiled_function = CompiledFunction {
            name: vm_function.name().to_string(),
            register_count: vm_function.register_count(),
            parameters: vm_function.parameters().to_vec(),
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
            let function = Self::deserialize_function(reader)?;
            functions.push(function);
        }

        Ok(CompiledBinary {
            version,
            constants,
            functions,
        })
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
    fn deserialize_function<R: Read>(reader: &mut R) -> BinaryResult<CompiledFunction> {
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
            read_u32_len_bounded(reader, "instruction count", MAX_BINARY_COLLECTION_LEN)?;

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
            upvalues,
            parent,
            labels,
            instructions,
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
        let mut file = File::create(path)?;
        binary.serialize(&mut file)
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

    fn append_empty_function_prefix(bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&4u16.to_le_bytes());
        bytes.extend_from_slice(b"main");
        bytes.extend_from_slice(&0u16.to_le_bytes()); // register count
        bytes.extend_from_slice(&0u16.to_le_bytes()); // parameters
        bytes.extend_from_slice(&0u16.to_le_bytes()); // upvalues
        bytes.push(0); // no parent
        bytes.extend_from_slice(&0u16.to_le_bytes()); // labels
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
                upvalues: vec![],
                parent: None,
                labels: HashMap::new(),
                instructions: vec![CompiledInstruction::LDI(0, 0)],
            }],
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
                upvalues: vec![],
                parent: None,
                labels: HashMap::new(),
                instructions: vec![CompiledInstruction::LDI(usize::MAX, 0)],
            }],
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
                upvalues: vec![],
                parent: None,
                labels: HashMap::new(),
                instructions: vec![CompiledInstruction::LDI(0, 0)],
            }],
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
                upvalues: vec![],
                parent: None,
                labels: HashMap::new(),
                instructions: vec![CompiledInstruction::LDI(usize::MAX, 0)],
            }],
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
                upvalues: vec![],
                parent: None,
                labels: HashMap::new(),
                instructions: vec![],
            }],
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
                upvalues: vec![],
                parent: None,
                labels: HashMap::new(),
                instructions: vec![],
            }],
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
                upvalues: vec![],
                parent: None,
                labels: HashMap::new(),
                instructions: vec![CompiledInstruction::RET(oversized_operand)],
            }],
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
                upvalues: vec![],
                parent: None,
                labels,
                instructions: vec![],
            }],
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
        bytes.extend_from_slice(
            &(u32::try_from(MAX_BINARY_COLLECTION_LEN).unwrap() + 1).to_le_bytes(),
        );

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
                upvalues: vec![],
                parent: None,
                labels: HashMap::new(),
                instructions: vec![
                    CompiledInstruction::LDI(16, 0),
                    CompiledInstruction::RET(16),
                ],
            }],
        };

        let vm_functions = binary.to_vm_functions();

        assert_eq!(vm_functions[0].register_count(), 17);
    }
}
