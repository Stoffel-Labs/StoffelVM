use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::ptr;

use crate::bytecode::{BytecodeChunk, CompiledProgram, Constant};
use crate::compiler::{compile, CompilerOptions};
use crate::errors::CompilerError;
use stoffel_vm_types::compiled_binary::{MpcBackend, MpcCurve};

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CCompilerOptions {
    pub optimize: c_int,
    pub optimization_level: u8,
    pub print_ir: c_int,
}

impl From<CCompilerOptions> for CompilerOptions {
    fn from(c_options: CCompilerOptions) -> Self {
        CompilerOptions {
            optimize: c_options.optimize != 0,
            optimization_level: c_options.optimization_level,
            print_ir: c_options.print_ir != 0,
            mpc_backend: MpcBackend::default(),
            mpc_curve: MpcCurve::default(),
            entry_points: Vec::new(),
            inline_budget: None,
            unroll_budget: None,
            unroll_max_expansion: None,
        }
    }
}

#[repr(C)]
pub struct CCompilerError {
    pub message: *mut c_char,
    pub file: *mut c_char,
    pub line: usize,
    pub column: usize,
    pub severity: c_int,
    pub category: c_int,
    pub code: *mut c_char,
    pub hint: *mut c_char,
}

#[repr(C)]
pub struct CCompilerErrors {
    pub errors: *mut CCompilerError,
    pub count: usize,
}

#[repr(C)]
pub struct CConstant {
    pub const_type: c_int,
    pub data: CConstantData,
}

#[repr(C)]
pub union CConstantData {
    pub i64_val: i64,
    pub i32_val: i32,
    pub i16_val: i16,
    pub i8_val: i8,
    pub u64_val: u64,
    pub u32_val: u32,
    pub u16_val: u16,
    pub u8_val: u8,
    pub float_val: i64,
    pub bool_val: c_int,
    pub string_val: *mut c_char,
    pub object_val: usize,
    pub array_val: usize,
    pub foreign_val: usize,
}

#[repr(C)]
pub struct CInstruction {
    pub opcode: u8,
    pub operand1: usize,
    pub operand2: usize,
    pub operand3: usize,
}

#[repr(C)]
pub struct CBytecodeChunk {
    pub instructions: *mut CInstruction,
    pub instruction_count: usize,
    pub constants: *mut CConstant,
    pub constant_count: usize,
}

#[repr(C)]
pub struct CCompiledProgram {
    pub main_chunk: CBytecodeChunk,
    pub function_chunks: *mut CFunctionChunk,
    pub function_count: usize,
}

#[repr(C)]
pub struct CFunctionChunk {
    pub name: *mut c_char,
    pub chunk: CBytecodeChunk,
}

#[repr(C)]
pub struct CCompilationResult {
    pub success: c_int,
    pub program: *mut CCompiledProgram,
    pub errors: CCompilerErrors,
}

unsafe fn string_to_c_char(s: &str) -> *mut c_char {
    if let Ok(c_string) = CString::new(s) {
        c_string.into_raw()
    } else {
        ptr::null_mut()
    }
}

unsafe fn rust_errors_to_c(errors: Vec<CompilerError>) -> CCompilerErrors {
    if errors.is_empty() {
        return CCompilerErrors {
            errors: ptr::null_mut(),
            count: 0,
        };
    }

    let error_count = errors.len();
    let mut c_errors = Vec::with_capacity(error_count);

    for error in errors {
        let c_error = CCompilerError {
            message: string_to_c_char(&error.message),
            file: string_to_c_char(&error.location.file),
            line: error.location.line,
            column: error.location.column,
            severity: match error.severity {
                crate::errors::ErrorSeverity::Warning => 0,
                crate::errors::ErrorSeverity::Error => 1,
                crate::errors::ErrorSeverity::Fatal => 2,
            },
            category: match error.category {
                crate::errors::ErrorCategory::Syntax => 0,
                crate::errors::ErrorCategory::Type => 1,
                crate::errors::ErrorCategory::Semantic => 2,
                crate::errors::ErrorCategory::Internal => 3,
            },
            code: string_to_c_char(error.code),
            hint: if let Some(hint) = &error.hint {
                string_to_c_char(hint)
            } else {
                ptr::null_mut()
            },
        };
        c_errors.push(c_error);
    }

    let errors_ptr = c_errors.as_mut_ptr();
    std::mem::forget(c_errors);

    CCompilerErrors {
        errors: errors_ptr,
        count: error_count,
    }
}

unsafe fn constant_to_c(constant: &Constant) -> CConstant {
    match constant {
        Constant::I64(val) => {
            let mut data = CConstantData { i64_val: 0 };
            data.i64_val = *val;
            CConstant {
                const_type: 0,
                data,
            }
        }
        Constant::I32(val) => {
            let mut data = CConstantData { i32_val: 0 };
            data.i32_val = *val;
            CConstant {
                const_type: 1,
                data,
            }
        }
        Constant::I16(val) => {
            let mut data = CConstantData { i16_val: 0 };
            data.i16_val = *val;
            CConstant {
                const_type: 2,
                data,
            }
        }
        Constant::I8(val) => {
            let mut data = CConstantData { i8_val: 0 };
            data.i8_val = *val;
            CConstant {
                const_type: 3,
                data,
            }
        }
        Constant::U8(val) => {
            let mut data = CConstantData { u8_val: 0 };
            data.u8_val = *val;
            CConstant {
                const_type: 4,
                data,
            }
        }
        Constant::U16(val) => {
            let mut data = CConstantData { u16_val: 0 };
            data.u16_val = *val;
            CConstant {
                const_type: 5,
                data,
            }
        }
        Constant::U32(val) => {
            let mut data = CConstantData { u32_val: 0 };
            data.u32_val = *val;
            CConstant {
                const_type: 6,
                data,
            }
        }
        Constant::U64(val) => {
            let mut data = CConstantData { u64_val: 0 };
            data.u64_val = *val;
            CConstant {
                const_type: 7,
                data,
            }
        }
        Constant::Float(val) => {
            let mut data = CConstantData { float_val: 0 };
            data.float_val = f64::from(*val).to_bits() as i64;
            CConstant {
                const_type: 8,
                data,
            }
        }
        Constant::Bool(val) => {
            let mut data = CConstantData { bool_val: 0 };
            data.bool_val = if *val { 1 } else { 0 };
            CConstant {
                const_type: 9,
                data,
            }
        }
        Constant::String(val) => {
            let mut data = CConstantData {
                string_val: ptr::null_mut(),
            };
            data.string_val = string_to_c_char(val);
            CConstant {
                const_type: 10,
                data,
            }
        }
        Constant::Object(val) => {
            let mut data = CConstantData { object_val: 0 };
            data.object_val = *val;
            CConstant {
                const_type: 11,
                data,
            }
        }
        Constant::Array(val) => {
            let mut data = CConstantData { array_val: 0 };
            data.array_val = *val;
            CConstant {
                const_type: 12,
                data,
            }
        }
        Constant::Foreign(val) => {
            let mut data = CConstantData { foreign_val: 0 };
            data.foreign_val = *val;
            CConstant {
                const_type: 13,
                data,
            }
        }
        Constant::Closure(_, _) => {
            let mut data = CConstantData { object_val: 0 };
            data.object_val = 0;
            CConstant {
                const_type: 14,
                data,
            }
        }
        Constant::Unit => {
            let mut data = CConstantData { u8_val: 0 };
            data.u8_val = 0;
            CConstant {
                const_type: 15,
                data,
            }
        }
        Constant::Share(_, _) => {
            let mut data = CConstantData { object_val: 0 };
            data.object_val = 0;
            CConstant {
                const_type: 16,
                data,
            }
        }
    }
}

unsafe fn instruction_to_c(
    instruction: &stoffel_vm_types::instructions::Instruction,
) -> CInstruction {
    match instruction {
        stoffel_vm_types::instructions::Instruction::NOP => CInstruction {
            opcode: stoffel_vm_types::instructions::ReducedOpcode::NOP as u8,
            operand1: 0,
            operand2: 0,
            operand3: 0,
        },
        stoffel_vm_types::instructions::Instruction::LD(reg, offset) => CInstruction {
            opcode: 0,
            operand1: *reg,
            operand2: *offset as usize,
            operand3: 0,
        },
        stoffel_vm_types::instructions::Instruction::LDI(reg, _value) => CInstruction {
            opcode: 1,
            operand1: *reg,
            operand2: 0,
            operand3: 0,
        },
        stoffel_vm_types::instructions::Instruction::MOV(dest, src) => CInstruction {
            opcode: 2,
            operand1: *dest,
            operand2: *src,
            operand3: 0,
        },
        stoffel_vm_types::instructions::Instruction::ADD(dest, src1, src2) => CInstruction {
            opcode: 3,
            operand1: *dest,
            operand2: *src1,
            operand3: *src2,
        },
        stoffel_vm_types::instructions::Instruction::SUB(dest, src1, src2) => CInstruction {
            opcode: 4,
            operand1: *dest,
            operand2: *src1,
            operand3: *src2,
        },
        stoffel_vm_types::instructions::Instruction::MUL(dest, src1, src2) => CInstruction {
            opcode: 5,
            operand1: *dest,
            operand2: *src1,
            operand3: *src2,
        },
        stoffel_vm_types::instructions::Instruction::DIV(dest, src1, src2) => CInstruction {
            opcode: 6,
            operand1: *dest,
            operand2: *src1,
            operand3: *src2,
        },
        stoffel_vm_types::instructions::Instruction::MOD(dest, src1, src2) => CInstruction {
            opcode: 7,
            operand1: *dest,
            operand2: *src1,
            operand3: *src2,
        },
        stoffel_vm_types::instructions::Instruction::AND(dest, src1, src2) => CInstruction {
            opcode: 8,
            operand1: *dest,
            operand2: *src1,
            operand3: *src2,
        },
        stoffel_vm_types::instructions::Instruction::OR(dest, src1, src2) => CInstruction {
            opcode: 9,
            operand1: *dest,
            operand2: *src1,
            operand3: *src2,
        },
        stoffel_vm_types::instructions::Instruction::XOR(dest, src1, src2) => CInstruction {
            opcode: 10,
            operand1: *dest,
            operand2: *src1,
            operand3: *src2,
        },
        stoffel_vm_types::instructions::Instruction::NOT(dest, src) => CInstruction {
            opcode: 11,
            operand1: *dest,
            operand2: *src,
            operand3: 0,
        },
        stoffel_vm_types::instructions::Instruction::SHL(dest, src, amount) => CInstruction {
            opcode: 12,
            operand1: *dest,
            operand2: *src,
            operand3: *amount,
        },
        stoffel_vm_types::instructions::Instruction::SHR(dest, src, amount) => CInstruction {
            opcode: 13,
            operand1: *dest,
            operand2: *src,
            operand3: *amount,
        },
        stoffel_vm_types::instructions::Instruction::JMP(_label) => CInstruction {
            opcode: 14,
            operand1: 0,
            operand2: 0,
            operand3: 0,
        },
        stoffel_vm_types::instructions::Instruction::JMPEQ(_label) => CInstruction {
            opcode: 15,
            operand1: 0,
            operand2: 0,
            operand3: 0,
        },
        stoffel_vm_types::instructions::Instruction::JMPNEQ(_label) => CInstruction {
            opcode: 16,
            operand1: 0,
            operand2: 0,
            operand3: 0,
        },
        stoffel_vm_types::instructions::Instruction::JMPLT(_label) => CInstruction {
            opcode: 17,
            operand1: 0,
            operand2: 0,
            operand3: 0,
        },
        stoffel_vm_types::instructions::Instruction::JMPGT(_label) => CInstruction {
            opcode: 18,
            operand1: 0,
            operand2: 0,
            operand3: 0,
        },
        stoffel_vm_types::instructions::Instruction::CALL(_function) => CInstruction {
            opcode: 19,
            operand1: 0,
            operand2: 0,
            operand3: 0,
        },
        stoffel_vm_types::instructions::Instruction::RET(reg) => CInstruction {
            opcode: 20,
            operand1: *reg,
            operand2: 0,
            operand3: 0,
        },
        stoffel_vm_types::instructions::Instruction::PUSHARG(reg) => CInstruction {
            opcode: 21,
            operand1: *reg,
            operand2: 0,
            operand3: 0,
        },
        stoffel_vm_types::instructions::Instruction::CMP(reg1, reg2) => CInstruction {
            opcode: 22,
            operand1: *reg1,
            operand2: *reg2,
            operand3: 0,
        },
        stoffel_vm_types::instructions::Instruction::LDS(reg, slot) => CInstruction {
            opcode: stoffel_vm_types::instructions::ReducedOpcode::LDS as u8,
            operand1: *reg,
            operand2: *slot,
            operand3: 0,
        },
        stoffel_vm_types::instructions::Instruction::STS(slot, reg) => CInstruction {
            opcode: stoffel_vm_types::instructions::ReducedOpcode::STS as u8,
            operand1: *slot,
            operand2: *reg,
            operand3: 0,
        },
    }
}

unsafe fn bytecode_chunk_to_c(chunk: &BytecodeChunk) -> CBytecodeChunk {
    let mut c_instructions = Vec::with_capacity(chunk.instructions.len());
    for instruction in &chunk.instructions {
        c_instructions.push(instruction_to_c(instruction));
    }

    let mut c_constants = Vec::with_capacity(chunk.constants.len());
    for constant in &chunk.constants {
        c_constants.push(constant_to_c(constant));
    }

    let instructions_ptr = c_instructions.as_mut_ptr();
    let constants_ptr = c_constants.as_mut_ptr();

    std::mem::forget(c_instructions);
    std::mem::forget(c_constants);

    CBytecodeChunk {
        instructions: instructions_ptr,
        instruction_count: chunk.instructions.len(),
        constants: constants_ptr,
        constant_count: chunk.constants.len(),
    }
}

unsafe fn compiled_program_to_c(program: CompiledProgram) -> *mut CCompiledProgram {
    let main_chunk = bytecode_chunk_to_c(&program.main_chunk);

    let function_count = program.function_chunks.len();
    let mut function_chunks = Vec::with_capacity(function_count);
    for (name, chunk) in program.function_chunks {
        let c_chunk = CFunctionChunk {
            name: string_to_c_char(&name),
            chunk: bytecode_chunk_to_c(&chunk),
        };
        function_chunks.push(c_chunk);
    }

    let function_chunks_ptr = if function_chunks.is_empty() {
        ptr::null_mut()
    } else {
        let ptr = function_chunks.as_mut_ptr();
        std::mem::forget(function_chunks);
        ptr
    };

    let c_program = Box::new(CCompiledProgram {
        main_chunk,
        function_chunks: function_chunks_ptr,
        function_count,
    });

    Box::into_raw(c_program)
}

#[no_mangle]
/// Compile Stoffel source code through the C ABI.
///
/// # Safety
///
/// `source` and `filename` must be valid, null-terminated C strings. `options` may be null or
/// point to a valid `CCompilerOptions`. The returned pointer must be released with
/// `stoffel_free_compilation_result`.
pub unsafe extern "C" fn stoffel_compile(
    source: *const c_char,
    filename: *const c_char,
    options: *const CCompilerOptions,
) -> *mut CCompilationResult {
    if source.is_null() || filename.is_null() {
        return ptr::null_mut();
    }

    let source_str = match CStr::from_ptr(source).to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let filename_str = match CStr::from_ptr(filename).to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let compiler_options = if options.is_null() {
        CompilerOptions::default()
    } else {
        CompilerOptions::from(*options)
    };

    let result = compile(source_str, filename_str, &compiler_options);

    let c_result = match result {
        Ok(program) => CCompilationResult {
            success: 1,
            program: compiled_program_to_c(program),
            errors: CCompilerErrors {
                errors: ptr::null_mut(),
                count: 0,
            },
        },
        Err(errors) => CCompilationResult {
            success: 0,
            program: ptr::null_mut(),
            errors: rust_errors_to_c(errors),
        },
    };

    Box::into_raw(Box::new(c_result))
}

#[no_mangle]
/// Free a compilation result returned by `stoffel_compile`.
///
/// # Safety
///
/// `result` must be null or a pointer returned by `stoffel_compile` that has not already been
/// freed.
pub unsafe extern "C" fn stoffel_free_compilation_result(result: *mut CCompilationResult) {
    if result.is_null() {
        return;
    }

    let result = Box::from_raw(result);

    if !result.program.is_null() {
        stoffel_free_compiled_program(result.program);
    }

    stoffel_free_compiler_errors(&result.errors);
}

#[no_mangle]
/// Free a compiled program allocated by this library.
///
/// # Safety
///
/// `program` must be null or a pointer allocated by this library that has not already been freed.
pub unsafe extern "C" fn stoffel_free_compiled_program(program: *mut CCompiledProgram) {
    if program.is_null() {
        return;
    }

    let program = Box::from_raw(program);

    stoffel_free_bytecode_chunk(&program.main_chunk);

    if !program.function_chunks.is_null() {
        let function_chunks = Vec::from_raw_parts(
            program.function_chunks,
            program.function_count,
            program.function_count,
        );

        for chunk in function_chunks {
            if !chunk.name.is_null() {
                drop(CString::from_raw(chunk.name));
            }
            stoffel_free_bytecode_chunk(&chunk.chunk);
        }
    }
}

#[no_mangle]
/// Free a bytecode chunk allocated by this library.
///
/// # Safety
///
/// `chunk` must be null or point to a `CBytecodeChunk` allocated by this library.
pub unsafe extern "C" fn stoffel_free_bytecode_chunk(chunk: *const CBytecodeChunk) {
    if chunk.is_null() {
        return;
    }

    let chunk = &*chunk;

    if !chunk.instructions.is_null() {
        Vec::from_raw_parts(
            chunk.instructions,
            chunk.instruction_count,
            chunk.instruction_count,
        );
    }

    if !chunk.constants.is_null() {
        let constants =
            Vec::from_raw_parts(chunk.constants, chunk.constant_count, chunk.constant_count);

        for constant in constants {
            if constant.const_type == 10 && !constant.data.string_val.is_null() {
                drop(CString::from_raw(constant.data.string_val));
            }
        }
    }
}

#[no_mangle]
/// Free compiler errors allocated by this library.
///
/// # Safety
///
/// `errors` must be null or point to a `CCompilerErrors` value allocated by this library.
pub unsafe extern "C" fn stoffel_free_compiler_errors(errors: *const CCompilerErrors) {
    if errors.is_null() {
        return;
    }

    let errors = &*errors;

    if !errors.errors.is_null() {
        let error_vec = Vec::from_raw_parts(errors.errors, errors.count, errors.count);

        for error in error_vec {
            if !error.message.is_null() {
                drop(CString::from_raw(error.message));
            }
            if !error.file.is_null() {
                drop(CString::from_raw(error.file));
            }
            if !error.code.is_null() {
                drop(CString::from_raw(error.code));
            }
            if !error.hint.is_null() {
                drop(CString::from_raw(error.hint));
            }
        }
    }
}

#[no_mangle]
/// Return the compiler version as a static C string.
///
/// # Safety
///
/// The returned pointer is static and must not be freed.
pub unsafe extern "C" fn stoffel_get_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}
