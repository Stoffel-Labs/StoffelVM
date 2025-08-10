//! # Instruction Set for StoffelVM
//!
//! This module defines the instruction set for the StoffelVM, a register-based virtual machine.
//! The VM uses a dual representation of instructions:
//!
//! 1. `Instruction` - Human-readable symbolic representation used during function definition
//! 2. `ResolvedInstruction` - Optimized representation with numeric indices for faster execution
//!
//! The instruction set is designed to be simple yet powerful, supporting memory operations,
//! arithmetic, bitwise operations, control flow, and function calls.

use crate::core_types::Value;

/// Raw opcodes for VM instructions
///
/// These are the low-level numeric representations of instructions used by the VM.
/// Each opcode corresponds to a specific operation in the VM's instruction set.
#[repr(u8)]
pub enum ReducedOpcode {
    // LD r1 [sp+0]
    LD = 0x00,
    // LDI r1 10
    LDI = 0x01,
    // MOV r1 r2
    MOV = 0x02,
    // ADD r1, r2, r3
    ADD = 0x03,
    // SUB r1, r2, r3
    SUB = 0x04,
    // MUL r1, r2, r3
    MUL = 0x05,
    // DIV r1, r2, r3
    DIV = 0x06,
    // MOD r1, r2, r3
    MOD = 0x07,
    // AND r1, r2, r3
    AND = 0x08,
    // OR r1, r2, r3
    OR = 0x09,
    // XOR r1, r2, r3
    XOR = 0x0A,
    // NOT r1, r2
    NOT = 0x0B,
    // SHL <target>, <source>, <amount>
    // SHL r1, r2, 1
    SHL = 0x0C,
    // SHR <target>, <source>, <amount>
    // SHR r1, r2, 1
    SHR = 0x0D,
    // JMP <jump_to>
    JMP = 0x0E,
    // JMPEQ <jump_to>
    JMPEQ = 0x0F,
    // JMPNEQ <jump_to>
    JMPNEQ = 0x10,
    // JMPLT <jump_to> (Jump if Less Than, compare_flag == -1)
    JMPLT = 0x15,
    // JMPGT <jump_to> (Jump if Greater Than, compare_flag == 1)
    JMPGT = 0x16,
    // CALL <function>
    CALL = 0x11,
    // RET r1
    RET = 0x12,
    // PUSHARG r1
    PUSHARG = 0x13,
    // CMP r1 r2
    CMP = 0x14,
}

/// Memory address or register operand
///
/// Represents the different types of operands that can be used in VM instructions.
/// This provides flexibility in addressing modes for the VM.
#[derive(Debug, Clone)]
pub enum Operand {
    /// A register (r0, r1, etc.) - used for storing and manipulating values
    Register(usize),
    /// Stack pointer offset [sp+n] - used for accessing function arguments
    StackAddr(i32),
    /// An immediate value (constant) - used for embedding values directly in instructions
    Immediate(Value),
    /// A jump label - used for control flow instructions
    Label(String),
}

/// Symbolic instruction set for the VM
///
/// This is the human-readable representation of instructions used during function definition.
/// Each variant corresponds to a specific operation in the VM and includes the necessary
/// operands for that operation.
///
/// Instructions are later resolved to `ResolvedInstruction` for more efficient execution.
#[derive(Debug, Clone, Hash)]
pub enum Instruction {
    // Load value from stack to register
    LD(usize, i32), // LD r1, [sp+0]
    // Load immediate value to register
    LDI(usize, Value), // LDI r1, 10
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
    JMPLT(String),  // JMPLT label (Jump if Less Than) use inverted comparison for JUMPLTE
    JMPGT(String),  // JMPGT label (Jump if Greater Than) use inverted comparison for JUMPGTE
    // Function handling
    CALL(String),   // CALL function_name
    RET(usize),     // RET r1
    PUSHARG(usize), // PUSHARG r1
    // Comparison
    CMP(usize, usize), // CMP r1, r2
}

/// Resolved instruction with numeric indices instead of strings
///
/// This is an optimized representation of instructions used during execution.
/// String identifiers (like function names and labels) are replaced with numeric indices,
/// allowing for faster execution without string lookups.
///
/// This representation is generated from the symbolic `Instruction` enum during function
/// registration and is used by the VM's execution engine.
#[derive(Debug, Clone, Copy)]
pub enum ResolvedInstruction {
    // Load value from stack to register
    LD(usize, i32), // LD r1, [sp+0]
    // Load immediate value to register
    LDI(usize, usize), // LDI r1, const_idx (register, constant index)
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
    JMP(usize),    // JMP to instruction index
    JMPEQ(usize),  // JMPEQ to instruction index
    JMPNEQ(usize), // JMPNEQ to instruction index
    JMPLT(usize),  // JMPLT to instruction index
    JMPGT(usize),  // JMPGT to instruction index
    // Function handling
    CALL(usize),    // CALL function index
    RET(usize),     // RET r1
    PUSHARG(usize), // PUSHARG r1
    // Comparison
    CMP(usize, usize), // CMP r1, r2
}
