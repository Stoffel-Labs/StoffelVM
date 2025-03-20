use std::convert::TryFrom;
use std::fmt;
use std::rc::Rc;


// TODO: add REVEAL HIDE opcodes
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

pub enum RedOpcode {
    LD {
        source_idx: usize,
        target_idx: usize,
    },
    LDI {
        target_idx: usize,
        immediate_value: u64,
    },
    MOV {
        source_idx: usize,
        target_idx: usize,
    },
    ADD {
        source1_idx: usize,
        source2_idx: usize,
        target_idx: usize,
    },
    SUB {
        source1_idx: usize,
        source2_idx: usize,
        target_idx: usize,
    },
    MUL {
        source1_idx: usize,
        source2_idx: usize,
        target_idx: usize,
    },
    DIV {
        source1_idx: usize,
        source2_idx: usize,
        target_idx: usize,
    },
    MOD {
        source1_idx: usize,
        source2_idx: usize,
        target_idx: usize,
    },
    AND {
        source1_idx: usize,
        source2_idx: usize,
        target_idx: usize,
    },
    OR {
        source1_idx: usize,
        source2_idx: usize,
        target_idx: usize,
    },
    XOR {
        source1_idx: usize,
        source2_idx: usize,
        target_idx: usize,
    },
    NOT {
        // Using this value
        source_idx: usize,
        // NOT this value
        target_idx: usize,
    },
    SHL {
        source1_idx: usize,
        source2_idx: usize,
        target_idx: usize,
    },
    SHR {
        source1_idx: usize,
        source2_idx: usize,
        target_idx: usize,
    },
    JMP {
        target_idx: usize,
    },
    JMPEQ {
        target_idx: usize,
    },
    JMPNEQ {
        target_idx: usize,
    },
    CALL {
        target_idx: usize,
    },
    RET {
        source_idx: usize,
    },
    PUSHARG {
        source_idx: usize,
    },
    // TODO: I can't remember why I wrote this
    STORE {
        source_idx: usize,
    },
    CMP {
        source1_idx: usize,
        source2_idx: usize,
    },
}

#[derive(Debug, Clone)]
pub struct OpCodeConversionError;

// Generation of an error is completely separate from how it is displayed.
// There's no need to be concerned about cluttering complex logic with the display style.
//
// Note that we don't store any extra info about the errors. This means we can't state
// which string failed to parse without modifying our types to carry that information.
impl fmt::Display for OpCodeConversionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "failed to parse opcode")
    }
}

impl TryFrom<u8> for ReducedOpcode {
    type Error = OpCodeConversionError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(ReducedOpcode::LD),
            0x01 => Ok(ReducedOpcode::LDI),
            0x02 => Ok(ReducedOpcode::MOV),
            0x03 => Ok(ReducedOpcode::ADD),
            0x04 => Ok(ReducedOpcode::SUB),
            0x05 => Ok(ReducedOpcode::MUL),
            0x06 => Ok(ReducedOpcode::DIV),
            0x07 => Ok(ReducedOpcode::MOD),
            0x08 => Ok(ReducedOpcode::AND),
            0x09 => Ok(ReducedOpcode::OR),
            0x0A => Ok(ReducedOpcode::XOR),
            0x0B => Ok(ReducedOpcode::NOT),
            0x0C => Ok(ReducedOpcode::SHL),
            0x0D => Ok(ReducedOpcode::SHR),
            0x0E => Ok(ReducedOpcode::JMP),
            0x0F => Ok(ReducedOpcode::JMPEQ),
            0x10 => Ok(ReducedOpcode::JMPNEQ),
            0x11 => Ok(ReducedOpcode::CALL),
            0x12 => Ok(ReducedOpcode::RET),
            0x13 => Ok(ReducedOpcode::PUSHARG),
            0x14 => Ok(ReducedOpcode::CMP),
            _ => Err(OpCodeConversionError),
        }
    }
}

pub struct Decoder {
    curr_pos: usize,
    // Rc Bc I dont want to have all the bytecode copied multiple times tbh
    program: Option<Rc<Vec<u8>>>,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            curr_pos: 0,
            program: None,
        }
    }

    pub fn load_program(&mut self, program: Rc<Vec<u8>>) {
        self.program = Some(program);
    }

    pub fn decode_program(&mut self) -> Vec<RedOpcode> {
        let mut decoded_opcodes = Vec::new();
        while let Some(opcode) = self.next_opcode() {
            decoded_opcodes.push(opcode);
        }
        decoded_opcodes
    }

    // finally working I think
    // TODO: write more tests than j going through with pen and paper
    pub fn next_opcode(&mut self) -> Option<RedOpcode> {
        let program = self.program.clone()?;

        if self.curr_pos >= program.len() {
            return None;
        }

        let opcode = ReducedOpcode::try_from(program[self.curr_pos]).ok()?;
        self.curr_pos += 1;

        let red_opcode = match opcode {
            ReducedOpcode::LD => {
                if self.curr_pos + 2 > program.len() {
                    return None;
                }
                let source_idx = program[self.curr_pos] as usize;
                let target_idx = program[self.curr_pos + 1] as usize;
                self.curr_pos += 2;
                RedOpcode::LD {
                    source_idx,
                    target_idx,
                }
            }
            ReducedOpcode::LDI => {
                if self.curr_pos + 9 > program.len() {
                    return None;
                }
                let target_idx = program[self.curr_pos] as usize;
                self.curr_pos += 1;
                let immediate_value =
                    u64::from_le_bytes(program[self.curr_pos..self.curr_pos + 8].try_into().ok()?);
                self.curr_pos += 8;
                RedOpcode::LDI {
                    target_idx,
                    immediate_value,
                }
            }
            ReducedOpcode::MOV => {
                if self.curr_pos + 2 > program.len() {
                    return None;
                }
                let source_idx = program[self.curr_pos] as usize;
                let target_idx = program[self.curr_pos + 1] as usize;
                self.curr_pos += 2;
                RedOpcode::MOV {
                    source_idx,
                    target_idx,
                }
            }
            ReducedOpcode::ADD
            | ReducedOpcode::SUB
            | ReducedOpcode::MUL
            | ReducedOpcode::DIV
            | ReducedOpcode::MOD
            | ReducedOpcode::AND
            | ReducedOpcode::OR
            | ReducedOpcode::XOR
            | ReducedOpcode::SHL
            | ReducedOpcode::SHR => {
                if self.curr_pos + 3 > program.len() {
                    return None;
                }
                let source1_idx = program[self.curr_pos] as usize;
                let source2_idx = program[self.curr_pos + 1] as usize;
                let target_idx = program[self.curr_pos + 2] as usize;
                self.curr_pos += 3;

                match opcode {
                    ReducedOpcode::ADD => RedOpcode::ADD {
                        source1_idx,
                        source2_idx,
                        target_idx,
                    },
                    ReducedOpcode::SUB => RedOpcode::SUB {
                        source1_idx,
                        source2_idx,
                        target_idx,
                    },
                    ReducedOpcode::MUL => RedOpcode::MUL {
                        source1_idx,
                        source2_idx,
                        target_idx,
                    },
                    ReducedOpcode::DIV => RedOpcode::DIV {
                        source1_idx,
                        source2_idx,
                        target_idx,
                    },
                    ReducedOpcode::MOD => RedOpcode::MOD {
                        source1_idx,
                        source2_idx,
                        target_idx,
                    },
                    ReducedOpcode::AND => RedOpcode::AND {
                        source1_idx,
                        source2_idx,
                        target_idx,
                    },
                    ReducedOpcode::OR => RedOpcode::OR {
                        source1_idx,
                        source2_idx,
                        target_idx,
                    },
                    ReducedOpcode::XOR => RedOpcode::XOR {
                        source1_idx,
                        source2_idx,
                        target_idx,
                    },
                    ReducedOpcode::SHL => RedOpcode::SHL {
                        source1_idx,
                        source2_idx,
                        target_idx,
                    },
                    ReducedOpcode::SHR => RedOpcode::SHR {
                        source1_idx,
                        source2_idx,
                        target_idx,
                    },
                    _ => unreachable!(),
                }
            }
            ReducedOpcode::NOT => {
                if self.curr_pos + 2 > program.len() {
                    return None;
                }
                let source_idx = program[self.curr_pos] as usize;
                let target_idx = program[self.curr_pos + 1] as usize;
                self.curr_pos += 2;
                RedOpcode::NOT {
                    source_idx,
                    target_idx,
                }
            }
            ReducedOpcode::CMP => {
                if self.curr_pos + 2 > program.len() {
                    return None;
                }
                let source1_idx = program[self.curr_pos] as usize;
                let source2_idx = program[self.curr_pos + 1] as usize;
                self.curr_pos += 2;
                RedOpcode::CMP {
                    source1_idx,
                    source2_idx,
                }
            }
            ReducedOpcode::JMP
            | ReducedOpcode::JMPEQ
            | ReducedOpcode::JMPNEQ
            | ReducedOpcode::CALL => {
                if self.curr_pos + 1 > program.len() {
                    return None;
                }
                let target_idx = program[self.curr_pos] as usize;
                self.curr_pos += 1;

                match opcode {
                    ReducedOpcode::JMP => RedOpcode::JMP { target_idx },
                    ReducedOpcode::JMPEQ => RedOpcode::JMPEQ { target_idx },
                    ReducedOpcode::JMPNEQ => RedOpcode::JMPNEQ { target_idx },
                    ReducedOpcode::CALL => RedOpcode::CALL { target_idx },
                    _ => unreachable!(),
                }
            }
            ReducedOpcode::RET | ReducedOpcode::PUSHARG => {
                if self.curr_pos + 1 > program.len() {
                    return None;
                }
                let source_idx = program[self.curr_pos] as usize;
                self.curr_pos += 1;

                match opcode {
                    ReducedOpcode::RET => RedOpcode::RET { source_idx },
                    ReducedOpcode::PUSHARG => RedOpcode::PUSHARG { source_idx },
                    _ => unreachable!(),
                }
            }
        };

        Some(red_opcode)
    }
}

// // TODO: Rip out half the opcodes because we can just have the runtime handle secret or clear
// #[repr(u8)]
// pub enum OpCode {
//     // Load immediate clear value into register
//     LDI = 0x00,
//     // Load immediate secret value into register
//     LDSI = 0x01,
//     // Move Clear
//     MOVC = 0x02,
//     // Move Secret
//     MOVS = 0x03,
//     // Add clear
//     ADDC = 0x04,
//     // Add secret
//     ADDS = 0x05,
//     // Add mixed
//     ADDM = 0x06,
//     // Add clear immediate
//     ADDCI = 0x07,
//     // Add secret immediate
//     ADDSI = 0x08,
//     // Subtract clear
//     SUBC = 0x09,
//     // Subtract secret
//     SUBS = 0x0A,
//     // Subtract mixed left
//     SUBML = 0x0B,
//     // Subtract mixed right
//     SUBMR = 0x0C,
//     // Subtract clear immediate
//     SUBCI = 0x0D,
//     // Subtract secret immediate
//     SUBSI = 0x0E,
//     // Multiply clear
//     MULC = 0x0F,
//     // Multiply secret
//     MULS = 0x10,
//     // Multiply mixed
//     MULM = 0x11,
//     // Multiply clear immediate
//     MULCI = 0x12,
//     // Multiply secret immediate
//     MULSI = 0x13,
//     // divide clear
//     DIVC = 0x14,
//     // divide clear immediate
//     DIVCI = 0x15,
//     // modulo clear
//     MODC = 0x16,
//     // modulo clear immediate
//     MODCI = 0x17,
//     // floor divide clear ( tbh this is probably going to be the default behavior as in always floor div )
//     FLOORDIVC = 0x18,
//     // binary AND clear
//     ANDC = 0x19,
//     // binary XOR clear
//     XORC = 0x1A,
//     // binary OR clear
//     ORC = 0x1B,
//     // binary NOT clear
//     NOTC = 0x1C,
//     // binary shift left clear
//     SHLC = 0x1D,
//     // binary shift right clear
//     SHRC = 0x1E,
//     // binary shift left clear immediate
//     SHLCI = 0x1F,
//     // binary shift right clear immediate
//     SHRCI = 0x20,
//     // binary shift right secret immediate
//     SHRSI = 0x21,
//     // unconditional jump
//     JMP = 0x22,
//     // conditional jump if register isnt 0
//     JMPNZ = 0x23,
//     // conditional jump if register is 0
//     JMPEQZ = 0x24,
//     // fixed point ops
//     ADD_FX = 0x25,
//     SUB_FX = 0x26,
//     MUL_FX = 0x27,
//     DIV_FX = 0x28,
//     NEG_FX = 0x29,
//     ABS_FX = 0x2A,
//     MUL_ACC_FX = 0x2B,
//     SQRT_FX = 0x2C,
//     EXP_FX = 0x2D,
//     LOG_FX = 0x2E,
//     CMP_EQ_FX = 0x2F,
//     CMP_LT_FX = 0x30,
//     CMP_GT_FX = 0x31,
//     //Thread related TODO: figure out how to approach these
//     // load something
//     LDTN = 0x32,
//     // load arg?
//     LDARG = 0x33,
//     // Start / Stop the tape?
//     START = 0x34,
//     STOP = 0x35,
//     // Split off into a thread, is this because we need parallel work or do we need async because if latter we can coroutine
//     RUN_TAPE = 0x36,
//     JOIN_TAPE = 0x37,
//     // Crash the whole runtime!? 😭
//     CRASH = 0x38,
//     // Set requirement on computation module
//     REQBL = 0x39,
//     TIME = 0x40,
//     PRINTINT = 0x41,
//     INVOKE_RANGEPROOF = 0x42,
//     INVOKE_DATA_ORACLE = 0x43,
//     // Add function-related opcodes
//     CALL = 0x50,
//     RET = 0x51,
//     PUSHARG = 0x52,
// }
// // TODO: figure out what other traits we probably need
//
// impl TryFrom<u8> for OpCode {
//     type Error = ();
//
//     fn try_from(value: u8) -> Result<Self, Self::Error> {
//         match value {
//             0x00 => Ok(OpCode::LDI),
//             0x01 => Ok(OpCode::LDSI),
//             0x02 => Ok(OpCode::MOVC),
//             0x03 => Ok(OpCode::MOVS),
//             0x04 => Ok(OpCode::ADDC),
//             0x05 => Ok(OpCode::ADDS),
//             0x06 => Ok(OpCode::ADDM),
//             0x07 => Ok(OpCode::ADDCI),
//             0x08 => Ok(OpCode::ADDSI),
//             0x09 => Ok(OpCode::SUBC),
//             0x0A => Ok(OpCode::SUBS),
//             0x0B => Ok(OpCode::SUBML),
//             0x0C => Ok(OpCode::SUBMR),
//             0x0D => Ok(OpCode::SUBCI),
//             0x0E => Ok(OpCode::SUBSI),
//             0x0F => Ok(OpCode::MULC),
//             0x10 => Ok(OpCode::MULS),
//             0x11 => Ok(OpCode::MULM),
//             0x12 => Ok(OpCode::MULCI),
//             0x13 => Ok(OpCode::MULSI),
//             0x14 => Ok(OpCode::DIVC),
//             0x15 => Ok(OpCode::DIVCI),
//             0x16 => Ok(OpCode::MODC),
//             0x17 => Ok(OpCode::MODCI),
//             0x18 => Ok(OpCode::FLOORDIVC),
//             0x19 => Ok(OpCode::ANDC),
//             0x1A => Ok(OpCode::XORC),
//             0x1B => Ok(OpCode::ORC),
//             0x1C => Ok(OpCode::NOTC),
//             0x1D => Ok(OpCode::SHLC),
//             0x1E => Ok(OpCode::SHRC),
//             0x1F => Ok(OpCode::SHLCI),
//             0x20 => Ok(OpCode::SHRCI),
//             0x21 => Ok(OpCode::SHRSI),
//             0x22 => Ok(OpCode::JMP),
//             0x23 => Ok(OpCode::JMPNZ),
//             0x24 => Ok(OpCode::JMPEQZ),
//             0x25 => Ok(OpCode::ADD_FX),
//             0x26 => Ok(OpCode::SUB_FX),
//             0x27 => Ok(OpCode::MUL_FX),
//             0x28 => Ok(OpCode::DIV_FX),
//             0x29 => Ok(OpCode::NEG_FX),
//             0x2A => Ok(OpCode::ABS_FX),
//             0x2B => Ok(OpCode::MUL_ACC_FX),
//             0x2C => Ok(OpCode::SQRT_FX),
//             0x2D => Ok(OpCode::EXP_FX),
//             0x2E => Ok(OpCode::LOG_FX),
//             0x2F => Ok(OpCode::CMP_EQ_FX),
//             0x30 => Ok(OpCode::CMP_LT_FX),
//             0x31 => Ok(OpCode::CMP_GT_FX),
//             0x32 => Ok(OpCode::LDTN),
//             0x33 => Ok(OpCode::LDARG),
//             0x34 => Ok(OpCode::START),
//             0x35 => Ok(OpCode::STOP),
//             0x36 => Ok(OpCode::RUN_TAPE),
//             0x37 => Ok(OpCode::JOIN_TAPE),
//             0x50 => Ok(OpCode::CALL),
//             0x51 => Ok(OpCode::RET),
//             0x52 => Ok(OpCode::PUSHARG),
//             0x42 => Ok(OpCode::INVOKE_RANGEPROOF),
//             0x43 => Ok(OpCode::INVOKE_DATA_ORACLE),
//             _ => Err(()),
//         }
//     }
// }
