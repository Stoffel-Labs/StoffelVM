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

use crate::core_types::Value;
use crate::functions::VMFunction;
use crate::instructions::{Instruction, ReducedOpcode};
use std::collections::HashMap;
use std::io::{self, Read, Write};

// Magic bytes that identify a StoffelVM bytecode file
pub const MAGIC_BYTES: &[u8; 4] = b"STFL";
// Current bytecode format version
pub const FORMAT_VERSION: u16 = 1;

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

/// Result type for binary operations
pub type BinaryResult<T> = Result<T, BinaryError>;

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
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
pub enum CompiledInstruction {
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

        // First pass: collect all constants
        for function in functions {
            for instruction in &function.instructions {
                if let Instruction::LDI(_, value) = instruction {
                    binary.add_constant_if_new(value, &mut constant_map);
                }
            }
        }

        // Second pass: convert functions
        for function in functions {
            binary.add_function_from_vm(function, &constant_map);
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
        constant_map: &HashMap<Value, usize>,
    ) {
        let mut compiled_instructions = Vec::new();

        // Convert instructions
        for instruction in &vm_function.instructions {
            let compiled = match instruction {
                Instruction::LD(reg, offset) => CompiledInstruction::LD(*reg, *offset),
                Instruction::LDI(reg, value) => {
                    let const_idx = constant_map.get(value).unwrap_or(&0);
                    CompiledInstruction::LDI(*reg, *const_idx)
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
            name: vm_function.name.clone(),
            register_count: vm_function.register_count,
            parameters: vm_function.parameters.clone(),
            upvalues: vm_function.upvalues.clone(),
            parent: vm_function.parent.clone(),
            labels: vm_function.labels.clone(),
            instructions: compiled_instructions,
        };

        self.functions.push(compiled_function);
    }

    /// Converts the compiled binary back to VM functions
    ///
    /// # Returns
    ///
    /// A vector of VMFunction objects
    pub fn to_vm_functions(&self) -> Vec<VMFunction> {
        let mut vm_functions = Vec::new();

        for function in &self.functions {
            let mut instructions = Vec::new();

            // Convert instructions
            for instruction in &function.instructions {
                let vm_instruction = match instruction {
                    CompiledInstruction::LD(reg, offset) => Instruction::LD(*reg, *offset),
                    CompiledInstruction::LDI(reg, const_idx) => {
                        let value = self
                            .constants
                            .get(*const_idx)
                            .cloned()
                            .unwrap_or(Value::Unit);
                        Instruction::LDI(*reg, value)
                    }
                    CompiledInstruction::MOV(target, source) => Instruction::MOV(*target, *source),
                    CompiledInstruction::ADD(target, src1, src2) => {
                        Instruction::ADD(*target, *src1, *src2)
                    }
                    CompiledInstruction::SUB(target, src1, src2) => {
                        Instruction::SUB(*target, *src1, *src2)
                    }
                    CompiledInstruction::MUL(target, src1, src2) => {
                        Instruction::MUL(*target, *src1, *src2)
                    }
                    CompiledInstruction::DIV(target, src1, src2) => {
                        Instruction::DIV(*target, *src1, *src2)
                    }
                    CompiledInstruction::MOD(target, src1, src2) => {
                        Instruction::MOD(*target, *src1, *src2)
                    }
                    CompiledInstruction::AND(target, src1, src2) => {
                        Instruction::AND(*target, *src1, *src2)
                    }
                    CompiledInstruction::OR(target, src1, src2) => {
                        Instruction::OR(*target, *src1, *src2)
                    }
                    CompiledInstruction::XOR(target, src1, src2) => {
                        Instruction::XOR(*target, *src1, *src2)
                    }
                    CompiledInstruction::NOT(target, source) => Instruction::NOT(*target, *source),
                    CompiledInstruction::SHL(target, src1, src2) => {
                        Instruction::SHL(*target, *src1, *src2)
                    }
                    CompiledInstruction::SHR(target, src1, src2) => {
                        Instruction::SHR(*target, *src1, *src2)
                    }
                    CompiledInstruction::JMP(label) => Instruction::JMP(label.clone()),
                    CompiledInstruction::JMPEQ(label) => Instruction::JMPEQ(label.clone()),
                    CompiledInstruction::JMPNEQ(label) => Instruction::JMPNEQ(label.clone()),
                    CompiledInstruction::JMPLT(label) => Instruction::JMPLT(label.clone()),
                    CompiledInstruction::JMPGT(label) => Instruction::JMPGT(label.clone()),
                    CompiledInstruction::CALL(function_name) => {
                        Instruction::CALL(function_name.clone())
                    }
                    CompiledInstruction::RET(reg) => Instruction::RET(*reg),
                    CompiledInstruction::PUSHARG(reg) => Instruction::PUSHARG(*reg),
                    CompiledInstruction::CMP(reg1, reg2) => Instruction::CMP(*reg1, *reg2),
                };

                instructions.push(vm_instruction);
            }

            // Create the VM function
            let vm_function = VMFunction::new(
                function.name.clone(),
                function.parameters.clone(),
                function.upvalues.clone(),
                function.parent.clone(),
                function.register_count,
                instructions,
                function.labels.clone(),
            );

            vm_functions.push(vm_function);
        }

        vm_functions
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
        let constant_count = self.constants.len() as u32;
        writer.write_all(&constant_count.to_le_bytes())?;

        for constant in &self.constants {
            self.serialize_value(constant, writer)?;
        }

        // Write functions
        let function_count = self.functions.len() as u32;
        writer.write_all(&function_count.to_le_bytes())?;

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
                writer.write_all(&[*i as u8])?;
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
                writer.write_all(&f.to_le_bytes())?;
            }
            Value::Bool(b) => {
                writer.write_all(&[10u8])?; // Type tag for Bool
                writer.write_all(&[if *b { 1u8 } else { 0u8 }])?;
            }
            Value::String(s) => {
                writer.write_all(&[11u8])?; // Type tag for String
                let bytes = s.as_bytes();
                let len = bytes.len() as u32;
                writer.write_all(&len.to_le_bytes())?;
                writer.write_all(bytes)?;
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
        let name_bytes = function.name.as_bytes();
        let name_len = name_bytes.len() as u16;
        writer.write_all(&name_len.to_le_bytes())?;
        writer.write_all(name_bytes)?;

        // Write register count
        writer.write_all(&(function.register_count as u16).to_le_bytes())?;

        // Write parameters
        let param_count = function.parameters.len() as u16;
        writer.write_all(&param_count.to_le_bytes())?;
        for param in &function.parameters {
            let param_bytes = param.as_bytes();
            let param_len = param_bytes.len() as u16;
            writer.write_all(&param_len.to_le_bytes())?;
            writer.write_all(param_bytes)?;
        }

        // Write upvalues
        let upvalue_count = function.upvalues.len() as u16;
        writer.write_all(&upvalue_count.to_le_bytes())?;
        for upvalue in &function.upvalues {
            let upvalue_bytes = upvalue.as_bytes();
            let upvalue_len = upvalue_bytes.len() as u16;
            writer.write_all(&upvalue_len.to_le_bytes())?;
            writer.write_all(upvalue_bytes)?;
        }

        // Write parent function name (if any)
        if let Some(ref parent) = function.parent {
            writer.write_all(&[1u8])?; // Has parent
            let parent_bytes = parent.as_bytes();
            let parent_len = parent_bytes.len() as u16;
            writer.write_all(&parent_len.to_le_bytes())?;
            writer.write_all(parent_bytes)?;
        } else {
            writer.write_all(&[0u8])?; // No parent
        }

        // Write labels
        let label_count = function.labels.len() as u16;
        writer.write_all(&label_count.to_le_bytes())?;
        for (label, &offset) in &function.labels {
            let label_bytes = label.as_bytes();
            let label_len = label_bytes.len() as u16;
            writer.write_all(&label_len.to_le_bytes())?;
            writer.write_all(label_bytes)?;
            writer.write_all(&(offset as u32).to_le_bytes())?;
        }

        // Write instructions
        let instruction_count = function.instructions.len() as u32;
        writer.write_all(&instruction_count.to_le_bytes())?;
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
            CompiledInstruction::LD(reg, offset) => {
                writer.write_all(&[ReducedOpcode::LD as u8])?;
                writer.write_all(&(*reg as u32).to_le_bytes())?;
                writer.write_all(&(*offset as i32).to_le_bytes())?;
            }
            CompiledInstruction::LDI(reg, const_idx) => {
                writer.write_all(&[ReducedOpcode::LDI as u8])?;
                writer.write_all(&(*reg as u32).to_le_bytes())?;
                writer.write_all(&(*const_idx as u32).to_le_bytes())?;
            }
            CompiledInstruction::MOV(target, source) => {
                writer.write_all(&[ReducedOpcode::MOV as u8])?;
                writer.write_all(&(*target as u32).to_le_bytes())?;
                writer.write_all(&(*source as u32).to_le_bytes())?;
            }
            CompiledInstruction::ADD(target, src1, src2) => {
                writer.write_all(&[ReducedOpcode::ADD as u8])?;
                writer.write_all(&(*target as u32).to_le_bytes())?;
                writer.write_all(&(*src1 as u32).to_le_bytes())?;
                writer.write_all(&(*src2 as u32).to_le_bytes())?;
            }
            CompiledInstruction::SUB(target, src1, src2) => {
                writer.write_all(&[ReducedOpcode::SUB as u8])?;
                writer.write_all(&(*target as u32).to_le_bytes())?;
                writer.write_all(&(*src1 as u32).to_le_bytes())?;
                writer.write_all(&(*src2 as u32).to_le_bytes())?;
            }
            CompiledInstruction::MUL(target, src1, src2) => {
                writer.write_all(&[ReducedOpcode::MUL as u8])?;
                writer.write_all(&(*target as u32).to_le_bytes())?;
                writer.write_all(&(*src1 as u32).to_le_bytes())?;
                writer.write_all(&(*src2 as u32).to_le_bytes())?;
            }
            CompiledInstruction::DIV(target, src1, src2) => {
                writer.write_all(&[ReducedOpcode::DIV as u8])?;
                writer.write_all(&(*target as u32).to_le_bytes())?;
                writer.write_all(&(*src1 as u32).to_le_bytes())?;
                writer.write_all(&(*src2 as u32).to_le_bytes())?;
            }
            CompiledInstruction::MOD(target, src1, src2) => {
                writer.write_all(&[ReducedOpcode::MOD as u8])?;
                writer.write_all(&(*target as u32).to_le_bytes())?;
                writer.write_all(&(*src1 as u32).to_le_bytes())?;
                writer.write_all(&(*src2 as u32).to_le_bytes())?;
            }
            CompiledInstruction::AND(target, src1, src2) => {
                writer.write_all(&[ReducedOpcode::AND as u8])?;
                writer.write_all(&(*target as u32).to_le_bytes())?;
                writer.write_all(&(*src1 as u32).to_le_bytes())?;
                writer.write_all(&(*src2 as u32).to_le_bytes())?;
            }
            CompiledInstruction::OR(target, src1, src2) => {
                writer.write_all(&[ReducedOpcode::OR as u8])?;
                writer.write_all(&(*target as u32).to_le_bytes())?;
                writer.write_all(&(*src1 as u32).to_le_bytes())?;
                writer.write_all(&(*src2 as u32).to_le_bytes())?;
            }
            CompiledInstruction::XOR(target, src1, src2) => {
                writer.write_all(&[ReducedOpcode::XOR as u8])?;
                writer.write_all(&(*target as u32).to_le_bytes())?;
                writer.write_all(&(*src1 as u32).to_le_bytes())?;
                writer.write_all(&(*src2 as u32).to_le_bytes())?;
            }
            CompiledInstruction::NOT(target, source) => {
                writer.write_all(&[ReducedOpcode::NOT as u8])?;
                writer.write_all(&(*target as u32).to_le_bytes())?;
                writer.write_all(&(*source as u32).to_le_bytes())?;
            }
            CompiledInstruction::SHL(target, src1, src2) => {
                writer.write_all(&[ReducedOpcode::SHL as u8])?;
                writer.write_all(&(*target as u32).to_le_bytes())?;
                writer.write_all(&(*src1 as u32).to_le_bytes())?;
                writer.write_all(&(*src2 as u32).to_le_bytes())?;
            }
            CompiledInstruction::SHR(target, src1, src2) => {
                writer.write_all(&[ReducedOpcode::SHR as u8])?;
                writer.write_all(&(*target as u32).to_le_bytes())?;
                writer.write_all(&(*src1 as u32).to_le_bytes())?;
                writer.write_all(&(*src2 as u32).to_le_bytes())?;
            }
            CompiledInstruction::JMP(label) => {
                writer.write_all(&[ReducedOpcode::JMP as u8])?;
                let label_bytes = label.as_bytes();
                let label_len = label_bytes.len() as u16;
                writer.write_all(&label_len.to_le_bytes())?;
                writer.write_all(label_bytes)?;
            }
            CompiledInstruction::JMPEQ(label) => {
                writer.write_all(&[ReducedOpcode::JMPEQ as u8])?;
                let label_bytes = label.as_bytes();
                let label_len = label_bytes.len() as u16;
                writer.write_all(&label_len.to_le_bytes())?;
                writer.write_all(label_bytes)?;
            }
            CompiledInstruction::JMPNEQ(label) => {
                writer.write_all(&[ReducedOpcode::JMPNEQ as u8])?;
                let label_bytes = label.as_bytes();
                let label_len = label_bytes.len() as u16;
                writer.write_all(&label_len.to_le_bytes())?;
                writer.write_all(label_bytes)?;
            }
            CompiledInstruction::JMPLT(label) => {
                writer.write_all(&[ReducedOpcode::JMPLT as u8])?;
                let label_bytes = label.as_bytes();
                let label_len = label_bytes.len() as u16;
                writer.write_all(&label_len.to_le_bytes())?;
                writer.write_all(label_bytes)?;
            }
            CompiledInstruction::JMPGT(label) => {
                writer.write_all(&[ReducedOpcode::JMPGT as u8])?;
                let label_bytes = label.as_bytes();
                let label_len = label_bytes.len() as u16;
                writer.write_all(&label_len.to_le_bytes())?;
                writer.write_all(label_bytes)?;
            }
            CompiledInstruction::CALL(function_name) => {
                writer.write_all(&[ReducedOpcode::CALL as u8])?;
                let name_bytes = function_name.as_bytes();
                let name_len = name_bytes.len() as u16;
                writer.write_all(&name_len.to_le_bytes())?;
                writer.write_all(name_bytes)?;
            }
            CompiledInstruction::RET(reg) => {
                writer.write_all(&[ReducedOpcode::RET as u8])?;
                writer.write_all(&(*reg as u32).to_le_bytes())?;
            }
            CompiledInstruction::PUSHARG(reg) => {
                writer.write_all(&[ReducedOpcode::PUSHARG as u8])?;
                writer.write_all(&(*reg as u32).to_le_bytes())?;
            }
            CompiledInstruction::CMP(reg1, reg2) => {
                writer.write_all(&[ReducedOpcode::CMP as u8])?;
                writer.write_all(&(*reg1 as u32).to_le_bytes())?;
                writer.write_all(&(*reg2 as u32).to_le_bytes())?;
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

        let mut version_bytes = [0u8; 2];
        reader.read_exact(&mut version_bytes)?;
        let version = u16::from_le_bytes(version_bytes);
        if version > FORMAT_VERSION {
            return Err(BinaryError::UnsupportedVersion(version));
        }

        // Read constant pool
        let mut count_bytes = [0u8; 4];
        reader.read_exact(&mut count_bytes)?;
        let constant_count = u32::from_le_bytes(count_bytes) as usize;

        let mut constants = Vec::with_capacity(constant_count);
        for _ in 0..constant_count {
            let value = Self::deserialize_value(reader)?;
            constants.push(value);
        }

        // Read functions
        reader.read_exact(&mut count_bytes)?;
        let function_count = u32::from_le_bytes(count_bytes) as usize;

        let mut functions = Vec::with_capacity(function_count);
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
                Ok(Value::I8(byte[0] as i8))
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
                Ok(Value::Float(i64::from_le_bytes(bytes)))
            }
            10 => {
                let mut byte = [0u8; 1];
                reader.read_exact(&mut byte)?;
                Ok(Value::Bool(byte[0] != 0))
            }
            11 => {
                let mut len_bytes = [0u8; 4];
                reader.read_exact(&mut len_bytes)?;
                let len = u32::from_le_bytes(len_bytes) as usize;

                let mut string_bytes = vec![0u8; len];
                reader.read_exact(&mut string_bytes)?;

                let string = String::from_utf8(string_bytes)
                    .map_err(|_| BinaryError::InvalidData("Invalid UTF-8 in string".to_string()))?;

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
        let mut name_len_bytes = [0u8; 2];
        reader.read_exact(&mut name_len_bytes)?;
        let name_len = u16::from_le_bytes(name_len_bytes) as usize;

        let mut name_bytes = vec![0u8; name_len];
        reader.read_exact(&mut name_bytes)?;
        let name = String::from_utf8(name_bytes)
            .map_err(|_| BinaryError::InvalidData("Invalid UTF-8 in function name".to_string()))?;

        // Read register count
        let mut reg_count_bytes = [0u8; 2];
        reader.read_exact(&mut reg_count_bytes)?;
        let register_count = u16::from_le_bytes(reg_count_bytes) as usize;

        // Read parameters
        let mut param_count_bytes = [0u8; 2];
        reader.read_exact(&mut param_count_bytes)?;
        let param_count = u16::from_le_bytes(param_count_bytes) as usize;

        let mut parameters = Vec::with_capacity(param_count);
        for _ in 0..param_count {
            let mut param_len_bytes = [0u8; 2];
            reader.read_exact(&mut param_len_bytes)?;
            let param_len = u16::from_le_bytes(param_len_bytes) as usize;

            let mut param_bytes = vec![0u8; param_len];
            reader.read_exact(&mut param_bytes)?;
            let param = String::from_utf8(param_bytes).map_err(|_| {
                BinaryError::InvalidData("Invalid UTF-8 in parameter name".to_string())
            })?;

            parameters.push(param);
        }

        // Read upvalues
        let mut upvalue_count_bytes = [0u8; 2];
        reader.read_exact(&mut upvalue_count_bytes)?;
        let upvalue_count = u16::from_le_bytes(upvalue_count_bytes) as usize;

        let mut upvalues = Vec::with_capacity(upvalue_count);
        for _ in 0..upvalue_count {
            let mut upvalue_len_bytes = [0u8; 2];
            reader.read_exact(&mut upvalue_len_bytes)?;
            let upvalue_len = u16::from_le_bytes(upvalue_len_bytes) as usize;

            let mut upvalue_bytes = vec![0u8; upvalue_len];
            reader.read_exact(&mut upvalue_bytes)?;
            let upvalue = String::from_utf8(upvalue_bytes).map_err(|_| {
                BinaryError::InvalidData("Invalid UTF-8 in upvalue name".to_string())
            })?;

            upvalues.push(upvalue);
        }

        // Read parent function name (if any)
        let mut has_parent_byte = [0u8; 1];
        reader.read_exact(&mut has_parent_byte)?;
        let parent = if has_parent_byte[0] == 1 {
            let mut parent_len_bytes = [0u8; 2];
            reader.read_exact(&mut parent_len_bytes)?;
            let parent_len = u16::from_le_bytes(parent_len_bytes) as usize;

            let mut parent_bytes = vec![0u8; parent_len];
            reader.read_exact(&mut parent_bytes)?;
            let parent = String::from_utf8(parent_bytes).map_err(|_| {
                BinaryError::InvalidData("Invalid UTF-8 in parent function name".to_string())
            })?;

            Some(parent)
        } else {
            None
        };

        // Read labels
        let mut label_count_bytes = [0u8; 2];
        reader.read_exact(&mut label_count_bytes)?;
        let label_count = u16::from_le_bytes(label_count_bytes) as usize;

        let mut labels = HashMap::with_capacity(label_count);
        for _ in 0..label_count {
            let mut label_len_bytes = [0u8; 2];
            reader.read_exact(&mut label_len_bytes)?;
            let label_len = u16::from_le_bytes(label_len_bytes) as usize;

            let mut label_bytes = vec![0u8; label_len];
            reader.read_exact(&mut label_bytes)?;
            let label = String::from_utf8(label_bytes)
                .map_err(|_| BinaryError::InvalidData("Invalid UTF-8 in label name".to_string()))?;

            let mut offset_bytes = [0u8; 4];
            reader.read_exact(&mut offset_bytes)?;
            let offset = u32::from_le_bytes(offset_bytes) as usize;

            labels.insert(label, offset);
        }

        // Read instructions
        let mut instruction_count_bytes = [0u8; 4];
        reader.read_exact(&mut instruction_count_bytes)?;
        let instruction_count = u32::from_le_bytes(instruction_count_bytes) as usize;

        let mut instructions = Vec::with_capacity(instruction_count);
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
            x if x == ReducedOpcode::LD as u8 => {
                let mut reg_bytes = [0u8; 4];
                reader.read_exact(&mut reg_bytes)?;
                let reg = u32::from_le_bytes(reg_bytes) as usize;

                let mut offset_bytes = [0u8; 4];
                reader.read_exact(&mut offset_bytes)?;
                let offset = i32::from_le_bytes(offset_bytes);

                Ok(CompiledInstruction::LD(reg, offset))
            }
            x if x == ReducedOpcode::LDI as u8 => {
                let mut reg_bytes = [0u8; 4];
                reader.read_exact(&mut reg_bytes)?;
                let reg = u32::from_le_bytes(reg_bytes) as usize;

                let mut const_idx_bytes = [0u8; 4];
                reader.read_exact(&mut const_idx_bytes)?;
                let const_idx = u32::from_le_bytes(const_idx_bytes) as usize;

                Ok(CompiledInstruction::LDI(reg, const_idx))
            }
            x if x == ReducedOpcode::MOV as u8 => {
                let mut target_bytes = [0u8; 4];
                reader.read_exact(&mut target_bytes)?;
                let target = u32::from_le_bytes(target_bytes) as usize;

                let mut source_bytes = [0u8; 4];
                reader.read_exact(&mut source_bytes)?;
                let source = u32::from_le_bytes(source_bytes) as usize;

                Ok(CompiledInstruction::MOV(target, source))
            }
            x if x == ReducedOpcode::ADD as u8 => {
                let mut target_bytes = [0u8; 4];
                reader.read_exact(&mut target_bytes)?;
                let target = u32::from_le_bytes(target_bytes) as usize;

                let mut src1_bytes = [0u8; 4];
                reader.read_exact(&mut src1_bytes)?;
                let src1 = u32::from_le_bytes(src1_bytes) as usize;

                let mut src2_bytes = [0u8; 4];
                reader.read_exact(&mut src2_bytes)?;
                let src2 = u32::from_le_bytes(src2_bytes) as usize;

                Ok(CompiledInstruction::ADD(target, src1, src2))
            }
            x if x == ReducedOpcode::SUB as u8 => {
                let mut target_bytes = [0u8; 4];
                reader.read_exact(&mut target_bytes)?;
                let target = u32::from_le_bytes(target_bytes) as usize;

                let mut src1_bytes = [0u8; 4];
                reader.read_exact(&mut src1_bytes)?;
                let src1 = u32::from_le_bytes(src1_bytes) as usize;

                let mut src2_bytes = [0u8; 4];
                reader.read_exact(&mut src2_bytes)?;
                let src2 = u32::from_le_bytes(src2_bytes) as usize;

                Ok(CompiledInstruction::SUB(target, src1, src2))
            }
            x if x == ReducedOpcode::MUL as u8 => {
                let mut target_bytes = [0u8; 4];
                reader.read_exact(&mut target_bytes)?;
                let target = u32::from_le_bytes(target_bytes) as usize;

                let mut src1_bytes = [0u8; 4];
                reader.read_exact(&mut src1_bytes)?;
                let src1 = u32::from_le_bytes(src1_bytes) as usize;

                let mut src2_bytes = [0u8; 4];
                reader.read_exact(&mut src2_bytes)?;
                let src2 = u32::from_le_bytes(src2_bytes) as usize;

                Ok(CompiledInstruction::MUL(target, src1, src2))
            }
            x if x == ReducedOpcode::DIV as u8 => {
                let mut target_bytes = [0u8; 4];
                reader.read_exact(&mut target_bytes)?;
                let target = u32::from_le_bytes(target_bytes) as usize;

                let mut src1_bytes = [0u8; 4];
                reader.read_exact(&mut src1_bytes)?;
                let src1 = u32::from_le_bytes(src1_bytes) as usize;

                let mut src2_bytes = [0u8; 4];
                reader.read_exact(&mut src2_bytes)?;
                let src2 = u32::from_le_bytes(src2_bytes) as usize;

                Ok(CompiledInstruction::DIV(target, src1, src2))
            }
            x if x == ReducedOpcode::MOD as u8 => {
                let mut target_bytes = [0u8; 4];
                reader.read_exact(&mut target_bytes)?;
                let target = u32::from_le_bytes(target_bytes) as usize;

                let mut src1_bytes = [0u8; 4];
                reader.read_exact(&mut src1_bytes)?;
                let src1 = u32::from_le_bytes(src1_bytes) as usize;

                let mut src2_bytes = [0u8; 4];
                reader.read_exact(&mut src2_bytes)?;
                let src2 = u32::from_le_bytes(src2_bytes) as usize;

                Ok(CompiledInstruction::MOD(target, src1, src2))
            }
            x if x == ReducedOpcode::AND as u8 => {
                let mut target_bytes = [0u8; 4];
                reader.read_exact(&mut target_bytes)?;
                let target = u32::from_le_bytes(target_bytes) as usize;

                let mut src1_bytes = [0u8; 4];
                reader.read_exact(&mut src1_bytes)?;
                let src1 = u32::from_le_bytes(src1_bytes) as usize;

                let mut src2_bytes = [0u8; 4];
                reader.read_exact(&mut src2_bytes)?;
                let src2 = u32::from_le_bytes(src2_bytes) as usize;

                Ok(CompiledInstruction::AND(target, src1, src2))
            }
            x if x == ReducedOpcode::OR as u8 => {
                let mut target_bytes = [0u8; 4];
                reader.read_exact(&mut target_bytes)?;
                let target = u32::from_le_bytes(target_bytes) as usize;

                let mut src1_bytes = [0u8; 4];
                reader.read_exact(&mut src1_bytes)?;
                let src1 = u32::from_le_bytes(src1_bytes) as usize;

                let mut src2_bytes = [0u8; 4];
                reader.read_exact(&mut src2_bytes)?;
                let src2 = u32::from_le_bytes(src2_bytes) as usize;

                Ok(CompiledInstruction::OR(target, src1, src2))
            }
            x if x == ReducedOpcode::XOR as u8 => {
                let mut target_bytes = [0u8; 4];
                reader.read_exact(&mut target_bytes)?;
                let target = u32::from_le_bytes(target_bytes) as usize;

                let mut src1_bytes = [0u8; 4];
                reader.read_exact(&mut src1_bytes)?;
                let src1 = u32::from_le_bytes(src1_bytes) as usize;

                let mut src2_bytes = [0u8; 4];
                reader.read_exact(&mut src2_bytes)?;
                let src2 = u32::from_le_bytes(src2_bytes) as usize;

                Ok(CompiledInstruction::XOR(target, src1, src2))
            }
            x if x == ReducedOpcode::NOT as u8 => {
                let mut target_bytes = [0u8; 4];
                reader.read_exact(&mut target_bytes)?;
                let target = u32::from_le_bytes(target_bytes) as usize;

                let mut source_bytes = [0u8; 4];
                reader.read_exact(&mut source_bytes)?;
                let source = u32::from_le_bytes(source_bytes) as usize;

                Ok(CompiledInstruction::NOT(target, source))
            }
            x if x == ReducedOpcode::SHL as u8 => {
                let mut target_bytes = [0u8; 4];
                reader.read_exact(&mut target_bytes)?;
                let target = u32::from_le_bytes(target_bytes) as usize;

                let mut src1_bytes = [0u8; 4];
                reader.read_exact(&mut src1_bytes)?;
                let src1 = u32::from_le_bytes(src1_bytes) as usize;

                let mut src2_bytes = [0u8; 4];
                reader.read_exact(&mut src2_bytes)?;
                let src2 = u32::from_le_bytes(src2_bytes) as usize;

                Ok(CompiledInstruction::SHL(target, src1, src2))
            }
            x if x == ReducedOpcode::SHR as u8 => {
                let mut target_bytes = [0u8; 4];
                reader.read_exact(&mut target_bytes)?;
                let target = u32::from_le_bytes(target_bytes) as usize;

                let mut src1_bytes = [0u8; 4];
                reader.read_exact(&mut src1_bytes)?;
                let src1 = u32::from_le_bytes(src1_bytes) as usize;

                let mut src2_bytes = [0u8; 4];
                reader.read_exact(&mut src2_bytes)?;
                let src2 = u32::from_le_bytes(src2_bytes) as usize;

                Ok(CompiledInstruction::SHR(target, src1, src2))
            }
            x if x == ReducedOpcode::JMP as u8 => {
                let mut label_len_bytes = [0u8; 2];
                reader.read_exact(&mut label_len_bytes)?;
                let label_len = u16::from_le_bytes(label_len_bytes) as usize;

                let mut label_bytes = vec![0u8; label_len];
                reader.read_exact(&mut label_bytes)?;
                let label = String::from_utf8(label_bytes)
                    .map_err(|_| BinaryError::InvalidData("Invalid UTF-8 in label".to_string()))?;

                Ok(CompiledInstruction::JMP(label))
            }
            x if x == ReducedOpcode::JMPEQ as u8 => {
                let mut label_len_bytes = [0u8; 2];
                reader.read_exact(&mut label_len_bytes)?;
                let label_len = u16::from_le_bytes(label_len_bytes) as usize;

                let mut label_bytes = vec![0u8; label_len];
                reader.read_exact(&mut label_bytes)?;
                let label = String::from_utf8(label_bytes)
                    .map_err(|_| BinaryError::InvalidData("Invalid UTF-8 in label".to_string()))?;

                Ok(CompiledInstruction::JMPEQ(label))
            }
            x if x == ReducedOpcode::JMPNEQ as u8 => {
                let mut label_len_bytes = [0u8; 2];
                reader.read_exact(&mut label_len_bytes)?;
                let label_len = u16::from_le_bytes(label_len_bytes) as usize;

                let mut label_bytes = vec![0u8; label_len];
                reader.read_exact(&mut label_bytes)?;
                let label = String::from_utf8(label_bytes)
                    .map_err(|_| BinaryError::InvalidData("Invalid UTF-8 in label".to_string()))?;

                Ok(CompiledInstruction::JMPNEQ(label))
            }
            x if x == ReducedOpcode::JMPLT as u8 => {
                let mut label_len_bytes = [0u8; 2];
                reader.read_exact(&mut label_len_bytes)?;
                let label_len = u16::from_le_bytes(label_len_bytes) as usize;

                let mut label_bytes = vec![0u8; label_len];
                reader.read_exact(&mut label_bytes)?;
                let label = String::from_utf8(label_bytes)
                    .map_err(|_| BinaryError::InvalidData("Invalid UTF-8 in label".to_string()))?;

                Ok(CompiledInstruction::JMPLT(label))
            }
            x if x == ReducedOpcode::JMPGT as u8 => {
                let mut label_len_bytes = [0u8; 2];
                reader.read_exact(&mut label_len_bytes)?;
                let label_len = u16::from_le_bytes(label_len_bytes) as usize;

                let mut label_bytes = vec![0u8; label_len];
                reader.read_exact(&mut label_bytes)?;
                let label = String::from_utf8(label_bytes)
                    .map_err(|_| BinaryError::InvalidData("Invalid UTF-8 in label".to_string()))?;

                Ok(CompiledInstruction::JMPGT(label))
            }
            x if x == ReducedOpcode::CALL as u8 => {
                let mut name_len_bytes = [0u8; 2];
                reader.read_exact(&mut name_len_bytes)?;
                let name_len = u16::from_le_bytes(name_len_bytes) as usize;

                let mut name_bytes = vec![0u8; name_len];
                reader.read_exact(&mut name_bytes)?;
                let function_name = String::from_utf8(name_bytes).map_err(|_| {
                    BinaryError::InvalidData("Invalid UTF-8 in function name".to_string())
                })?;

                Ok(CompiledInstruction::CALL(function_name))
            }
            x if x == ReducedOpcode::RET as u8 => {
                let mut reg_bytes = [0u8; 4];
                reader.read_exact(&mut reg_bytes)?;
                let reg = u32::from_le_bytes(reg_bytes) as usize;

                Ok(CompiledInstruction::RET(reg))
            }
            x if x == ReducedOpcode::PUSHARG as u8 => {
                let mut reg_bytes = [0u8; 4];
                reader.read_exact(&mut reg_bytes)?;
                let reg = u32::from_le_bytes(reg_bytes) as usize;

                Ok(CompiledInstruction::PUSHARG(reg))
            }
            x if x == ReducedOpcode::CMP as u8 => {
                let mut reg1_bytes = [0u8; 4];
                reader.read_exact(&mut reg1_bytes)?;
                let reg1 = u32::from_le_bytes(reg1_bytes) as usize;

                let mut reg2_bytes = [0u8; 4];
                reader.read_exact(&mut reg2_bytes)?;
                let reg2 = u32::from_le_bytes(reg2_bytes) as usize;

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

    #[test]
    fn test_create_and_convert() {
        // Create a simple function
        let function = VMFunction::new(
            "test_function".to_string(),
            vec![],
            vec![],
            None,
            2,
            vec![Instruction::LDI(0, Value::I64(42)), Instruction::RET(0)],
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
        assert_eq!(binary.functions[0].instructions.len(), 2);

        // Convert back to VM functions
        let vm_functions = binary.to_vm_functions();

        // Check the VM functions
        assert_eq!(vm_functions.len(), 1);
        assert_eq!(vm_functions[0].name, "test_function");
        assert_eq!(vm_functions[0].register_count, 2);
        assert_eq!(vm_functions[0].instructions.len(), 2);

        // Check that the instructions were converted correctly
        match &vm_functions[0].instructions[0] {
            Instruction::LDI(reg, value) => {
                assert_eq!(*reg, 0);
                assert_eq!(*value, Value::I64(42));
            }
            _ => panic!("Expected LDI instruction"),
        }

        match &vm_functions[0].instructions[1] {
            Instruction::RET(reg) => {
                assert_eq!(*reg, 0);
            }
            _ => panic!("Expected RET instruction"),
        }
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
            vec![Instruction::LDI(0, Value::I64(42)), Instruction::RET(0)],
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
        assert_eq!(deserialized.functions[0].instructions.len(), 2);

        // Convert back to VM functions
        let vm_functions = deserialized.to_vm_functions();

        // Check the VM functions
        assert_eq!(vm_functions.len(), 1);
        assert_eq!(vm_functions[0].name, "test_function");
        assert_eq!(vm_functions[0].register_count, 2);
        assert_eq!(vm_functions[0].instructions.len(), 2);
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
        assert_eq!(vm_functions[0].name, "factorial");
        assert_eq!(vm_functions[0].parameters, vec!["n".to_string()]);
        assert_eq!(vm_functions[0].register_count, 4);
        assert_eq!(vm_functions[0].instructions.len(), 10);

        // Check that the labels were deserialized correctly
        assert_eq!(vm_functions[0].labels.len(), 2);
        assert_eq!(vm_functions[0].labels.get("loop_start"), Some(&2));
        assert_eq!(vm_functions[0].labels.get("loop_end"), Some(&7));
    }
}
