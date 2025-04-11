use crate::core_types::Value;

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
#[derive(Debug, Clone)]
pub enum Operand {
    Register(usize),                   // A register (r0, r1, etc.)
    StackAddr(i32),                    // Stack pointer offset [sp+n]
    Immediate(Value),                  // An immediate value (constant)
    Label(String),                     // A jump label
}

/// Instruction set matching ReducedOpcode
#[derive(Debug, Clone)]
#[derive(Hash)]
pub enum Instruction {
    // Load value from stack to register
    LD(usize, i32),                      // LD r1, [sp+0]
    // Load immediate value to register
    LDI(usize, Value),                   // LDI r1, 10
    // Move value from one register to another
    MOV(usize, usize),                   // MOV r1, r2
    // Arithmetic operations
    ADD(usize, usize, usize),            // ADD r1, r2, r3
    SUB(usize, usize, usize),            // SUB r1, r2, r3
    MUL(usize, usize, usize),            // MUL r1, r2, r3
    DIV(usize, usize, usize),            // DIV r1, r2, r3
    MOD(usize, usize, usize),            // MOD r1, r2, r3
    // Bitwise operations
    AND(usize, usize, usize),            // AND r1, r2, r3
    OR(usize, usize, usize),             // OR r1, r2, r3
    XOR(usize, usize, usize),            // XOR r1, r2, r3
    NOT(usize, usize),                   // NOT r1, r2
    SHL(usize, usize, usize),            // SHL r1, r2, r3
    SHR(usize, usize, usize),            // SHR r1, r2, r3
    // Control flow
    JMP(String),                         // JMP label
    JMPEQ(String),                       // JMPEQ label
    JMPNEQ(String),                      // JMPNEQ label
    // Function handling
    CALL(String),                        // CALL function_name
    RET(usize),                          // RET r1
    PUSHARG(usize),                      // PUSHARG r1
    // Comparison
    CMP(usize, usize),                   // CMP r1, r2
}