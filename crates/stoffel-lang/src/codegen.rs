use crate::ast::{AstNode, Pragma};
use crate::bytecode::{BytecodeChunk, CompiledProgram, Constant, Instruction};
use crate::errors::{CompilerError, CompilerResult, SourceLocation};
use crate::register_allocator::{self, AllocationError, PhysicalRegister, VirtualRegister};
use crate::symbol_table::SymbolType;
use stoffel_vm_types::compiled_binary::{
    ClientIoManifest, ClientIoSchema, FunctionType, MpcBackend, PreprocessingDemand,
};
use stoffel_vm_types::core_types::{ShareType, DEFAULT_FIXED_POINT_FRACTIONAL_BITS};
use stoffel_vm_types::registers::DEFAULT_SECRET_REGISTER_START;

use std::collections::HashMap;
use std::collections::HashSet;
const SECRET_REGISTER_START: usize = DEFAULT_SECRET_REGISTER_START;
const MAX_REGISTERS: usize = SECRET_REGISTER_START * 2;

/// It receives the generator state, the function definition node, and the pragma node.
type PragmaHandler = fn(&mut CodeGenerator, &AstNode, &Pragma) -> CompilerResult<()>;

fn int_literal_u64(node: Option<&AstNode>) -> Option<u64> {
    match node {
        Some(AstNode::Literal {
            value: crate::ast::Value::Int { value, .. },
            ..
        }) => u64::try_from(*value).ok(),
        _ => None,
    }
}

fn infer_single_share_type(node: &AstNode) -> Option<ShareType> {
    match node {
        AstNode::FunctionCall { function, .. } => match function.as_ref() {
            AstNode::Identifier(name, _)
                if matches!(
                    name.as_str(),
                    "Share.from_field"
                        | "Share.random_field"
                        | "Share.add_field"
                        | "Share.mul_field"
                        | "add_field"
                        | "mul_field"
                ) =>
            {
                Some(ShareType::SecretField)
            }
            AstNode::Identifier(name, _) if name == "ClientStore.take_share_fixed" => {
                Some(ShareType::default_secret_fixed_point())
            }
            AstNode::Identifier(name, _) if name == "ClientStore.take_share_bool" => {
                Some(ShareType::boolean())
            }
            AstNode::Identifier(name, _) if name == "ClientStore.sum_shares_fixed" => {
                Some(ShareType::default_secret_fixed_point())
            }
            AstNode::Identifier(name, _) if name == "ClientStore.sum_shares_bool" => {
                Some(ShareType::boolean())
            }
            AstNode::Identifier(name, _) if name == "ClientStore.sum_shares" => {
                Some(ShareType::default_secret_int())
            }
            AstNode::Identifier(name, _) if name == "ClientStore.take_share" => {
                Some(ShareType::default_secret_int())
            }
            AstNode::Identifier(name, _) if name.ends_with("from_clear_fixed") => {
                Some(ShareType::default_secret_fixed_point())
            }
            AstNode::Identifier(name, _) if name.ends_with("from_clear_int") => {
                Some(ShareType::default_secret_int())
            }
            AstNode::Identifier(name, _) if name.ends_with("from_clear_uint") => {
                Some(ShareType::secret_uint(64))
            }
            _ => None,
        },
        _ => None,
    }
}

fn fixed_share_type(bits: u8) -> ShareType {
    let total_bits = usize::from(bits);
    ShareType::secret_fixed_point_from_bits(
        total_bits,
        DEFAULT_FIXED_POINT_FRACTIONAL_BITS.min(total_bits.saturating_sub(1)),
    )
}

pub(crate) fn share_type_for_secret_scalar_symbol_type(ty: &SymbolType) -> Option<ShareType> {
    if !ty.is_secret() {
        return None;
    }
    if ty.underlying_type() == &SymbolType::Bool {
        return Some(ShareType::boolean());
    }
    if let SymbolType::Fixed { bits } = ty.underlying_type() {
        return Some(fixed_share_type(*bits));
    }
    ty.bit_width().map(|bit_width| {
        if ty.is_signed() {
            ShareType::secret_int(usize::from(bit_width))
        } else {
            ShareType::secret_uint(usize::from(bit_width))
        }
    })
}

fn symbol_type_to_function_type(ty: SymbolType) -> FunctionType {
    match ty {
        SymbolType::Int64 => FunctionType::Int {
            signed: true,
            bits: 64,
        },
        SymbolType::Int32 => FunctionType::Int {
            signed: true,
            bits: 32,
        },
        SymbolType::Int16 => FunctionType::Int {
            signed: true,
            bits: 16,
        },
        SymbolType::Int8 => FunctionType::Int {
            signed: true,
            bits: 8,
        },
        SymbolType::UInt64 => FunctionType::Int {
            signed: false,
            bits: 64,
        },
        SymbolType::UInt32 => FunctionType::Int {
            signed: false,
            bits: 32,
        },
        SymbolType::UInt16 => FunctionType::Int {
            signed: false,
            bits: 16,
        },
        SymbolType::UInt8 => FunctionType::Int {
            signed: false,
            bits: 8,
        },
        SymbolType::Float => FunctionType::Float,
        SymbolType::Fixed { bits } => FunctionType::Fixed { bits },
        SymbolType::String => FunctionType::String,
        SymbolType::Bool => FunctionType::Bool,
        SymbolType::Nil => FunctionType::Nil,
        SymbolType::Void => FunctionType::Void,
        SymbolType::Secret(inner) => {
            FunctionType::Secret(Box::new(symbol_type_to_function_type(*inner)))
        }
        SymbolType::TypeName(name) => FunctionType::Object(name),
        SymbolType::TypeVar(name) => FunctionType::TypeVar(name),
        SymbolType::Unknown => FunctionType::Unknown,
        SymbolType::List(inner) => {
            FunctionType::List(Box::new(symbol_type_to_function_type(*inner)))
        }
        SymbolType::Dict(key, value) => FunctionType::Dict(
            Box::new(symbol_type_to_function_type(*key)),
            Box::new(symbol_type_to_function_type(*value)),
        ),
        SymbolType::Object(name) => FunctionType::Object(name),
        SymbolType::Generic(name, params) => FunctionType::Generic(
            name,
            params
                .into_iter()
                .map(symbol_type_to_function_type)
                .collect(),
        ),
    }
}

fn is_share_random_call(function: &AstNode) -> bool {
    matches!(function, AstNode::Identifier(name, _) if name == "Share.random")
}

#[derive(Debug)]
struct CodeGenerator {
    // Holds instructions using VirtualRegisters during generation for a scope.
    current_instructions: Vec<Instruction>,
    // Holds labels mapped to their *virtual* instruction index.
    current_labels: HashMap<String, usize>,
    // Counter for allocating new virtual registers.
    next_virtual_reg: usize,
    // Tracks the required secrecy for each virtual register, indexed by VR id
    // (VRs are minted sequentially from 0). True = Secret.
    vr_secrecy: Vec<bool>,
    // Variable symbol table (maps name to VirtualRegister index). Local to the current scope.
    symbol_table: HashMap<String, usize>,
    // Source-level types for variables in this scope.
    symbol_types: HashMap<String, SymbolType>,
    // User object fields available for default construction in this scope.
    object_field_types: HashMap<String, Vec<(String, SymbolType)>>,
    // Compiled functions.
    compiled_functions: HashMap<String, BytecodeChunk>,
    // If present, this chunk represents `def main(...)` promoted to the program entry.
    main_proc_chunk: Option<BytecodeChunk>,
    // If present, this chunk represents a pragma-marked entry function.
    entry_main_chunk: Option<BytecodeChunk>,
    // Known built-in functions (names only, no bytecode generated).
    known_builtins: HashSet<String>,
    // Pragma handlers: Maps pragma names to their handler functions.
    pragma_handlers: HashMap<String, PragmaHandler>,
    // Constants identified during code generation for this chunk.
    identified_constants: Vec<Constant>,
    client_inputs: HashMap<u64, Vec<Option<ShareType>>>,
    client_outputs: HashMap<u64, Vec<ShareType>>,
    variable_share_types: HashMap<String, ShareType>,
    variable_share_lists: HashMap<String, Vec<ShareType>>,
    clear_int_constants: HashMap<String, u64>,
    /// Names of variables reassigned somewhere in the current function body.
    /// Such variables (e.g. `while`-loop counters) are not constants, so their
    /// initial value must not be used to statically resolve client-IO slots.
    reassigned_vars: HashSet<String>,
    active_loop_bounds: Vec<(String, u64)>,
    /// (continue_label, break_label) for each enclosing loop, innermost last
    loop_label_stack: Vec<(String, String)>,
    /// Optimization level compilation runs at (0 when the optimizer is off). Gates
    /// the codegen-side spill-traffic passes so -O0 output stays byte-identical.
    opt_level: u8,
}

/// Kill-switch for the opt-level >= 1 spill-traffic passes (the slot-reload cache in
/// `lower_spills_into_slots` and post-RA self-MOV elimination): set
/// `STOFFEL_SPILL_CACHE=0` to disable both for A/B comparisons.
fn spill_opt_enabled() -> bool {
    std::env::var("STOFFEL_SPILL_CACHE").map_or(true, |v| v != "0")
}

/// Debug hook: set `STOFFEL_SPILL_STATS=1` to print per-function spill-lowering
/// statistics (rounds, slots, reload cache hit/miss per bank, self-MOVs removed).
fn spill_stats_enabled() -> bool {
    std::env::var("STOFFEL_SPILL_STATS").is_ok()
}

#[derive(Default, Debug)]
struct SpillLoweringStats {
    rounds: usize,
    spill_slots: usize,
    /// Reloads served from a cached scratch register, per bank ([clear, secret]).
    reload_hits: [usize; 2],
    /// Reloads that had to emit an `LDS`, per bank ([clear, secret]).
    reload_misses: [usize; 2],
    spilled_defs: usize,
}

/// Cached scratch registers per bank; kept strictly below `SPILL_RESERVE` minus the
/// per-instruction transient scratches (2 reloads + 1 store = 3), so every unspillable
/// scratch always finds a home: 2 cached + 3 transient = 5 < 6.
const SPILL_SLOT_CACHE_CAPACITY: usize = 2;

/// Tiny per-bank LRU mapping spill slot -> scratch VR currently holding that slot's
/// value within the current basic block (see `lower_spills_into_slots`).
#[derive(Default)]
struct SpillSlotCache {
    /// `[clear, secret]`; entries ordered least- to most-recently used.
    banks: [Vec<(usize, usize)>; 2],
}

impl SpillSlotCache {
    fn lookup(&mut self, is_secret: bool, slot: usize) -> Option<usize> {
        let bank = &mut self.banks[is_secret as usize];
        let pos = bank.iter().position(|&(s, _)| s == slot)?;
        let entry = bank.remove(pos);
        bank.push(entry);
        Some(entry.1)
    }

    fn insert(&mut self, is_secret: bool, slot: usize, scratch_vr: usize) {
        let bank = &mut self.banks[is_secret as usize];
        if let Some(pos) = bank.iter().position(|&(s, _)| s == slot) {
            bank.remove(pos);
        } else if bank.len() == SPILL_SLOT_CACHE_CAPACITY {
            bank.remove(0);
        }
        bank.push((slot, scratch_vr));
    }

    fn clear(&mut self) {
        self.banks[0].clear();
        self.banks[1].clear();
    }
}

/// Constant pinning (`pin_hot_constants`) only scans functions at least this
/// large: small functions rarely re-materialize a constant often enough to
/// clear `CONST_PIN_MIN_FREQ`, and skipping them keeps -O1 compile cost flat.
const CONST_PIN_MIN_INSTRUCTIONS: usize = 256;
/// An immediate must be re-materialized at least this often to earn a pin
/// (each pin permanently reserves one clear physical register).
const CONST_PIN_MIN_FREQ: usize = 32;
const CONST_PIN_DEFAULT_MAX: usize = 4;
const CONST_PIN_HARD_CAP: usize = 6;

/// Number of constants `pin_hot_constants` may pin. `STOFFEL_CONST_PIN_MAX`
/// overrides the default for tuning (0 disables the pass entirely); the hard
/// cap keeps the clear spillable pool from collapsing under `SPILL_RESERVE`.
fn const_pin_max() -> usize {
    std::env::var("STOFFEL_CONST_PIN_MAX")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(CONST_PIN_DEFAULT_MAX)
        .min(CONST_PIN_HARD_CAP)
}

/// Identity of a pinnable `LDI` immediate, keyed on the full typed constant:
/// `I64(4)`, `I32(4)` and `U8(4)` are distinct keys because the VM rejects
/// mixed-width arithmetic, so folding widths would miscompile. Floats key by
/// raw bit pattern (bit-unequal NaNs pin separately, which is always safe).
/// `Ord` exists so candidate selection has a deterministic tie-break.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum PinKey {
    I64(i64),
    I32(i32),
    I16(i16),
    I8(i8),
    U64(u64),
    U32(u32),
    U16(u16),
    U8(u8),
    F64Bits(u64),
    Bool(bool),
    Unit,
}

fn pin_key(value: &crate::core_types::Value) -> Option<PinKey> {
    use crate::core_types::Value;
    Some(match value {
        Value::I64(v) => PinKey::I64(*v),
        Value::I32(v) => PinKey::I32(*v),
        Value::I16(v) => PinKey::I16(*v),
        Value::I8(v) => PinKey::I8(*v),
        Value::U64(v) => PinKey::U64(*v),
        Value::U32(v) => PinKey::U32(*v),
        Value::U16(v) => PinKey::U16(*v),
        Value::U8(v) => PinKey::U8(*v),
        Value::Float(f) => PinKey::F64Bits(f.0.to_bits()),
        Value::Bool(b) => PinKey::Bool(*b),
        Value::Unit => PinKey::Unit,
        _ => return None,
    })
}

impl CodeGenerator {
    fn new() -> Self {
        let known_builtins = crate::builtin_registry::builtin_registry().known_call_names();

        CodeGenerator {
            current_instructions: Vec::new(),
            current_labels: HashMap::new(),
            next_virtual_reg: 0, // Start virtual registers from 0
            vr_secrecy: Vec::new(),
            // Symbol table starts empty for each new generator instance (e.g., per function)
            symbol_table: HashMap::new(),
            symbol_types: HashMap::new(),
            object_field_types: HashMap::new(),
            compiled_functions: HashMap::new(),
            main_proc_chunk: None,
            entry_main_chunk: None,
            known_builtins,
            pragma_handlers: Self::register_pragma_handlers(),
            identified_constants: Vec::new(),
            client_inputs: HashMap::new(),
            client_outputs: HashMap::new(),
            variable_share_types: HashMap::new(),
            variable_share_lists: HashMap::new(),
            clear_int_constants: HashMap::new(),
            reassigned_vars: HashSet::new(),
            active_loop_bounds: Vec::new(),
            loop_label_stack: Vec::new(),
            opt_level: 0,
        }
    }

    /// Whether the opt-level >= 1 spill-traffic passes (slot-reload cache and post-RA
    /// self-MOV elimination) are active for this generator.
    fn spill_opt_active(&self) -> bool {
        self.opt_level >= 1 && spill_opt_enabled()
    }

    /// Warn that a client-I/O call could not be recorded in the client-IO
    /// manifest because its client slot is not statically resolvable (e.g. a
    /// function parameter rather than a literal/loop-variable/constant). Such
    /// calls still work at runtime, but generated bindings and the local
    /// runner's output-count detection will be incomplete for that client.
    fn warn_unrecorded_client_io(function_name: &str, kind: &str) {
        eprintln!(
            "warning: client {kind} call `{function_name}` uses a client slot that \
             cannot be resolved statically; it is omitted from the client-IO manifest, \
             so generated bindings and local-runner output-count detection will be \
             incomplete for it. Use a literal, loop-variable, or constant client slot."
        );
    }

    /// Registers built-in pragma handlers.
    fn register_pragma_handlers() -> HashMap<String, PragmaHandler> {
        let mut handlers: HashMap<String, PragmaHandler> = HashMap::new();

        // Register the "builtin" pragma handler
        handlers.insert("builtin".to_string(), handle_builtin_pragma);

        handlers
    }

    /// Allocates a new unique virtual register.
    /// Records whether the register needs to hold a secret value.
    fn allocate_virtual_register(&mut self, is_secret: bool) -> VirtualRegister {
        let vr = VirtualRegister(self.next_virtual_reg);
        self.next_virtual_reg += 1;
        debug_assert_eq!(vr.0, self.vr_secrecy.len());
        self.vr_secrecy.push(is_secret);
        vr
    }

    fn emit_unit_value(&mut self) -> (VirtualRegister, bool) {
        let vr = self.allocate_virtual_register(false);
        self.identified_constants.push(Constant::Unit);
        self.emit(Instruction::LDI(vr.0, crate::core_types::Value::Unit));
        (vr, false)
    }

    fn compile_default_value_for_type(
        &mut self,
        ty: &SymbolType,
        is_secret_register: bool,
    ) -> CompilerResult<(VirtualRegister, bool)> {
        if let Some(object_name) = self.default_object_type_name(ty) {
            self.emit(Instruction::CALL("create_object".to_string()));
            let object_vr = self.allocate_virtual_register(false);
            self.emit(Instruction::MOV(object_vr.0, 0));

            if let Some(fields) = self.object_field_types.get(&object_name).cloned() {
                for (field_name, field_type) in fields {
                    if let Some((field_vr, _)) =
                        self.compile_default_field_value_for_type(&field_type)?
                    {
                        let field_const = Constant::String(field_name);
                        self.identified_constants.push(field_const.clone());
                        let field_name_vr = self.allocate_virtual_register(false);
                        self.emit(Instruction::LDI(
                            field_name_vr.0,
                            crate::core_types::Value::from(field_const),
                        ));

                        self.emit(Instruction::PUSHARG(object_vr.0));
                        self.emit(Instruction::PUSHARG(field_name_vr.0));
                        self.emit(Instruction::PUSHARG(field_vr.0));
                        self.emit(Instruction::CALL("set_field".to_string()));
                    }
                }
            }

            Ok((object_vr, false))
        } else {
            match ty.underlying_type() {
                SymbolType::List(_) => {
                    self.emit(Instruction::CALL("create_array".to_string()));
                    let array_vr = self.allocate_virtual_register(false);
                    self.emit(Instruction::MOV(array_vr.0, 0));
                    Ok((array_vr, false))
                }
                _ => {
                    if is_secret_register {
                        let clear_constant = match ty.underlying_type() {
                            SymbolType::Float | SymbolType::Fixed { .. } => {
                                Constant::Float(crate::bytecode::F64::new(0.0))
                            }
                            SymbolType::Bool => Constant::Bool(false),
                            ty if ty.is_integer() => Constant::I64(0),
                            _ => Constant::Unit,
                        };
                        let clear_vr = self.allocate_virtual_register(false);
                        self.identified_constants.push(clear_constant.clone());
                        self.emit(Instruction::LDI(
                            clear_vr.0,
                            crate::core_types::Value::from(clear_constant),
                        ));
                        let secret_vr = self.allocate_virtual_register(true);
                        self.emit(Instruction::MOV(secret_vr.0, clear_vr.0));
                        Ok((secret_vr, true))
                    } else {
                        let vr = self.allocate_virtual_register(false);
                        self.identified_constants.push(Constant::Unit);
                        self.emit(Instruction::LDI(vr.0, crate::core_types::Value::Unit));
                        Ok((vr, false))
                    }
                }
            }
        }
    }

    fn compile_default_field_value_for_type(
        &mut self,
        ty: &SymbolType,
    ) -> CompilerResult<Option<(VirtualRegister, bool)>> {
        match ty.underlying_type() {
            SymbolType::List(_) => self.compile_default_value_for_type(ty, false).map(Some),
            _ if self.default_object_type_name(ty).is_some() => {
                self.compile_default_value_for_type(ty, false).map(Some)
            }
            _ => Ok(None),
        }
    }

    fn default_object_type_name(&self, ty: &SymbolType) -> Option<String> {
        match ty.underlying_type() {
            SymbolType::Object(name) | SymbolType::TypeName(name)
                if self.object_field_types.contains_key(name) =>
            {
                Some(name.clone())
            }
            _ => None,
        }
    }

    /// Adds an instruction to the current temporary list.
    fn emit(&mut self, instruction: Instruction) {
        self.current_instructions.push(instruction);
    }

    fn fresh_virtual_register(
        next_virtual_reg: &mut usize,
        secrecy_map: &mut Vec<bool>,
        is_secret: bool,
    ) -> VirtualRegister {
        let vr = VirtualRegister(*next_virtual_reg);
        *next_virtual_reg += 1;
        debug_assert_eq!(vr.0, secrecy_map.len());
        secrecy_map.push(is_secret);
        vr
    }

    #[allow(dead_code)]
    fn emit_spill_key_load(
        out: &mut Vec<Instruction>,
        constants: &mut Vec<Constant>,
        next_virtual_reg: &mut usize,
        secrecy_map: &mut Vec<bool>,
        spilled_vr: VirtualRegister,
    ) -> VirtualRegister {
        let key = Constant::String(format!("__stoffel_spill_{}", spilled_vr.0));
        constants.push(key.clone());
        let key_vr = Self::fresh_virtual_register(next_virtual_reg, secrecy_map, false);
        out.push(Instruction::LDI(
            key_vr.0,
            crate::core_types::Value::from(key),
        ));
        key_vr
    }

    #[allow(dead_code)]
    fn emit_spill_load(
        out: &mut Vec<Instruction>,
        constants: &mut Vec<Constant>,
        next_virtual_reg: &mut usize,
        secrecy_map: &mut Vec<bool>,
        spill_object_vr: VirtualRegister,
        spilled_vr: VirtualRegister,
    ) -> VirtualRegister {
        let key_vr =
            Self::emit_spill_key_load(out, constants, next_virtual_reg, secrecy_map, spilled_vr);
        out.push(Instruction::PUSHARG(spill_object_vr.0));
        out.push(Instruction::PUSHARG(key_vr.0));
        out.push(Instruction::CALL("get_field".to_string()));

        let value_is_secret = secrecy_map.get(spilled_vr.0).copied().unwrap_or(false);
        let value_vr = Self::fresh_virtual_register(next_virtual_reg, secrecy_map, value_is_secret);
        out.push(Instruction::MOV(value_vr.0, 0));
        value_vr
    }

    #[allow(dead_code)]
    fn emit_spill_store(
        out: &mut Vec<Instruction>,
        constants: &mut Vec<Constant>,
        next_virtual_reg: &mut usize,
        secrecy_map: &mut Vec<bool>,
        spill_object_vr: VirtualRegister,
        spilled_vr: VirtualRegister,
        value_vr: VirtualRegister,
    ) {
        let key_vr =
            Self::emit_spill_key_load(out, constants, next_virtual_reg, secrecy_map, spilled_vr);
        out.push(Instruction::PUSHARG(spill_object_vr.0));
        out.push(Instruction::PUSHARG(key_vr.0));
        out.push(Instruction::PUSHARG(value_vr.0));
        out.push(Instruction::CALL("set_field".to_string()));
    }

    /// Remaps a spill-lowered instruction's operands in place. `mapped_uses` and
    /// `mapped_def` hold `(old, scratch)` VR pairs (at most two uses and one def
    /// per instruction); unmapped operands are left untouched. The def/use
    /// classification of each operand position must stay in sync with
    /// `InstructionRegisterAnalysis::uses`/`defs`.
    fn remap_instruction_registers_in_place(
        instruction: &mut Instruction,
        mapped_uses: &[Option<(usize, usize)>; 2],
        mapped_def: Option<(usize, usize)>,
    ) {
        let map_use = |r: &mut usize| {
            for mapping in mapped_uses.iter().flatten() {
                if mapping.0 == *r {
                    *r = mapping.1;
                    return;
                }
            }
        };
        let map_def = |r: &mut usize| {
            if let Some((old, scratch)) = mapped_def {
                if old == *r {
                    *r = scratch;
                }
            }
        };

        match instruction {
            Instruction::LD(r, _) | Instruction::LDI(r, _) | Instruction::LDS(r, _) => map_def(r),
            Instruction::MOV(dest, src) | Instruction::NOT(dest, src) => {
                map_def(dest);
                map_use(src);
            }
            Instruction::ADD(dest, a, b)
            | Instruction::SUB(dest, a, b)
            | Instruction::MUL(dest, a, b)
            | Instruction::DIV(dest, a, b)
            | Instruction::MOD(dest, a, b)
            | Instruction::AND(dest, a, b)
            | Instruction::OR(dest, a, b)
            | Instruction::XOR(dest, a, b)
            | Instruction::SHL(dest, a, b)
            | Instruction::SHR(dest, a, b) => {
                map_def(dest);
                map_use(a);
                map_use(b);
            }
            Instruction::RET(src) | Instruction::PUSHARG(src) | Instruction::STS(_, src) => {
                map_use(src)
            }
            Instruction::CMP(a, b) => {
                map_use(a);
                map_use(b);
            }
            Instruction::JMP(_)
            | Instruction::JMPEQ(_)
            | Instruction::JMPNEQ(_)
            | Instruction::JMPLT(_)
            | Instruction::JMPGT(_)
            | Instruction::CALL(_)
            | Instruction::NOP => {}
        }
    }

    /// Lower spilled virtual registers to stack-slot traffic (LDS/STS).
    ///
    /// Each spilled VR is given a stable spill slot. Every use is reloaded into a fresh
    /// short-lived scratch register with `LDS` immediately before the instruction, and
    /// every def is computed into a fresh scratch register and written back with `STS`
    /// immediately after. Because `LDS`/`STS` are single instructions (not CALLs) they
    /// can sit anywhere — including between the `PUSHARG`s of a call — so no operand needs
    /// to be held live across a whole argument run. That keeps reload pressure bounded by
    /// a couple of scratch registers and lets the spill loop converge in a couple of
    /// rounds regardless of how large (e.g. inlined) the function is.
    ///
    /// `next_spill_slot` is the function-wide monotonic slot counter, so slots never
    /// collide across spill rounds.
    ///
    /// When `cache_enabled` is set (opt-level >= 1, see `spill_opt_enabled`), a tiny
    /// per-bank LRU of slot -> scratch VR forwards repeated reloads of the same slot
    /// within a basic block to the scratch register that already holds the value
    /// (including the store scratch of a preceding def), eliding the `LDS`. The cache
    /// is invalidated at every label target and after every control transfer, so a
    /// cached scratch never crosses a block boundary. Capacity is bounded so cached
    /// scratches (2/bank) plus the per-instruction transients (<= 3) stay under
    /// `SPILL_RESERVE`; cached scratches spanning `CALL`s are safe because the VM
    /// preserves all registers across calls except physical R0, which the allocator
    /// never hands out (it is reserved for the precolored ABI result VR0).
    #[allow(clippy::too_many_arguments)]
    fn lower_spills_into_slots(
        instructions: Vec<Instruction>,
        labels: HashMap<String, usize>,
        next_virtual_reg: &mut usize,
        secrecy_map: &mut Vec<bool>,
        spilled_vrs: &[VirtualRegister],
        next_spill_slot: &mut usize,
        cache_enabled: bool,
        stats: &mut SpillLoweringStats,
    ) -> (Vec<Instruction>, HashMap<String, usize>) {
        // Dense spilled/slot tables indexed by VR id: every operand VR was minted
        // before this round, so ids are bounded by the current counter.
        let mut spilled = vec![false; *next_virtual_reg];
        let mut slot_of = vec![usize::MAX; *next_virtual_reg];
        for &vr in spilled_vrs {
            if !spilled[vr.0] {
                spilled[vr.0] = true;
                slot_of[vr.0] = *next_spill_slot;
                *next_spill_slot += 1;
            }
        }

        let mut out = Vec::with_capacity(instructions.len() + spilled_vrs.len() * 4);
        let mut old_to_new = vec![0usize; instructions.len() + 1];
        let num_instructions = instructions.len();

        // Block-boundary set over the ORIGINAL instruction indices: label targets
        // start new blocks (control transfers are handled after each instruction).
        let label_targets: HashSet<usize> = if cache_enabled {
            labels.values().copied().collect()
        } else {
            HashSet::new()
        };
        let mut cache = SpillSlotCache::default();

        for (i, mut instruction) in instructions.into_iter().enumerate() {
            old_to_new[i] = out.len();

            if cache_enabled && label_targets.contains(&i) {
                cache.clear();
            }

            // Reload each spilled use into a fresh scratch register just before the
            // instruction (at most two uses per instruction), unless a cached scratch
            // already holds this slot's value.
            let mut mapped_uses: [Option<(usize, usize)>; 2] = [None; 2];
            let mut mapped_use_count = 0;
            for used_vr in register_allocator::use_regs(&instruction)
                .into_iter()
                .flatten()
            {
                if spilled[used_vr] && !mapped_uses.iter().flatten().any(|&(old, _)| old == used_vr)
                {
                    let is_secret = secrecy_map.get(used_vr).copied().unwrap_or(false);
                    let slot = slot_of[used_vr];
                    let scratch_id = if let Some(cached) = cache_enabled
                        .then(|| cache.lookup(is_secret, slot))
                        .flatten()
                    {
                        stats.reload_hits[is_secret as usize] += 1;
                        cached
                    } else {
                        stats.reload_misses[is_secret as usize] += 1;
                        let scratch =
                            Self::fresh_virtual_register(next_virtual_reg, secrecy_map, is_secret);
                        out.push(Instruction::LDS(scratch.0, slot));
                        if cache_enabled {
                            cache.insert(is_secret, slot, scratch.0);
                        }
                        scratch.0
                    };
                    mapped_uses[mapped_use_count] = Some((used_vr, scratch_id));
                    mapped_use_count += 1;
                }
            }

            // A spilled def (at most one) is computed into a fresh scratch register,
            // then stored back.
            let mut mapped_def: Option<(usize, usize)> = None;
            if let Some(def_vr) = register_allocator::def_reg(&instruction) {
                if spilled[def_vr] {
                    let is_secret = secrecy_map.get(def_vr).copied().unwrap_or(false);
                    let scratch =
                        Self::fresh_virtual_register(next_virtual_reg, secrecy_map, is_secret);
                    mapped_def = Some((def_vr, scratch.0));
                    stats.spilled_defs += 1;
                }
            }

            let ends_block = matches!(
                instruction,
                Instruction::JMP(_)
                    | Instruction::JMPEQ(_)
                    | Instruction::JMPNEQ(_)
                    | Instruction::JMPLT(_)
                    | Instruction::JMPGT(_)
                    | Instruction::RET(_)
            );

            Self::remap_instruction_registers_in_place(&mut instruction, &mapped_uses, mapped_def);
            out.push(instruction);

            if let Some((spilled_vr, scratch_vr)) = mapped_def {
                out.push(Instruction::STS(slot_of[spilled_vr], scratch_vr));
                if cache_enabled {
                    // Store-forwarding: the store scratch now holds the slot's value,
                    // superseding any previously cached reload of the same slot.
                    let is_secret = secrecy_map.get(spilled_vr).copied().unwrap_or(false);
                    cache.insert(is_secret, slot_of[spilled_vr], scratch_vr);
                }
            }

            if cache_enabled && ends_block {
                cache.clear();
            }
        }
        old_to_new[num_instructions] = out.len();

        let lowered_labels = labels
            .into_iter()
            .map(|(label, index)| {
                let mapped = old_to_new
                    .get(index)
                    .copied()
                    .unwrap_or_else(|| *old_to_new.last().unwrap_or(&out.len()));
                (label, mapped)
            })
            .collect();

        (out, lowered_labels)
    }

    /// Post-RA cleanup: delete `MOV(r, r)` no-ops left behind when the allocator
    /// coalesces a copy's source and destination into the same physical register
    /// (including the `MOV(0, 0)` form of a post-CALL result capture, which is
    /// final-form by the time this runs — `rewrite_instructions_with` has already
    /// rewritten the ABI source). Labels are remapped with the same
    /// boundary-inclusive old-to-new index table `lower_spills_into_slots` uses,
    /// so labels pointing one past the end (or at a deleted MOV) stay valid.
    fn eliminate_self_movs(
        instructions: Vec<Instruction>,
        labels: &mut HashMap<String, usize>,
    ) -> Vec<Instruction> {
        let num_instructions = instructions.len();
        let mut out = Vec::with_capacity(num_instructions);
        let mut old_to_new = vec![0usize; num_instructions + 1];
        for (i, instruction) in instructions.into_iter().enumerate() {
            old_to_new[i] = out.len();
            if matches!(instruction, Instruction::MOV(dest, src) if dest == src) {
                continue;
            }
            out.push(instruction);
        }
        old_to_new[num_instructions] = out.len();
        for index in labels.values_mut() {
            *index = old_to_new.get(*index).copied().unwrap_or(out.len());
        }
        out
    }

    /// Pre-RA constant pinning (opt-level >= 1): hoist the hottest `LDI`
    /// immediates into K fresh clear VRs, loaded once in a prologue prepended at
    /// function entry (entry dominates everything, so no dominance analysis is
    /// needed) and precolored to the top of the clear bank. `linear_scan_partition`
    /// reserves precolored physical registers for the whole function, so pinned
    /// constants are never evicted and never chosen as spill victims. Every
    /// `LDI(vr, c)` whose constant is pinned is deleted and `vr` renamed to the
    /// pinned VR, provided `vr` is a single-def clear non-precolored VR other
    /// than VR0 (VR0 is the ABI result register: the post-CALL `MOV(dest, 0)`
    /// rewrite in `rewrite_instructions_with` reads physical R0, so VR0 must
    /// never be renamed). An `LDI` whose previous *surviving* instruction is a
    /// `CALL` is also kept: deleting it would make a following `MOV(dest, 0)`
    /// newly CALL-adjacent and trip that same rewrite special case.
    fn pin_hot_constants(
        instructions: &mut Vec<Instruction>,
        labels: &mut HashMap<String, usize>,
        next_virtual_reg: &mut usize,
        secrecy_map: &mut Vec<bool>,
        precolored: &mut HashMap<VirtualRegister, PhysicalRegister>,
        diagnostic_name: &str,
    ) {
        Self::pin_hot_constants_with_limits(
            instructions,
            labels,
            next_virtual_reg,
            secrecy_map,
            precolored,
            CONST_PIN_MIN_INSTRUCTIONS,
            CONST_PIN_MIN_FREQ,
            const_pin_max(),
            diagnostic_name,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn pin_hot_constants_with_limits(
        instructions: &mut Vec<Instruction>,
        labels: &mut HashMap<String, usize>,
        next_virtual_reg: &mut usize,
        secrecy_map: &mut Vec<bool>,
        precolored: &mut HashMap<VirtualRegister, PhysicalRegister>,
        min_instructions: usize,
        min_freq: usize,
        max_pins: usize,
        diagnostic_name: &str,
    ) {
        if instructions.len() < min_instructions || max_pins == 0 {
            return;
        }

        // Pin homes: top of the clear bank downward, skipping physical registers
        // already reserved (ABI R0 and the R0..Rn-1 parameter slots).
        let reserved: HashSet<usize> = precolored.values().map(|p| p.0).collect();
        let homes: Vec<usize> = (1..SECRET_REGISTER_START)
            .rev()
            .filter(|r| !reserved.contains(r))
            .take(max_pins)
            .collect();
        if homes.is_empty() {
            return;
        }

        // Defs per VR plus per-typed-constant LDI frequencies. The first-seen
        // `Value` is kept as the representative for the prologue load (all
        // occurrences of a key are bit-identical by construction of `PinKey`).
        let mut def_count = vec![0u32; *next_virtual_reg];
        let mut freq: HashMap<PinKey, (usize, crate::core_types::Value)> = HashMap::new();
        for inst in instructions.iter() {
            if let Some(def) = register_allocator::def_reg(inst) {
                if let Some(count) = def_count.get_mut(def) {
                    *count += 1;
                }
            }
            if let Instruction::LDI(_, value) = inst {
                if let Some(key) = pin_key(value) {
                    freq.entry(key)
                        .and_modify(|(count, _)| *count += 1)
                        .or_insert_with(|| (1, value.clone()));
                }
            }
        }
        let mut candidates: Vec<(PinKey, usize, crate::core_types::Value)> = freq
            .into_iter()
            .filter(|(_, (count, _))| *count >= min_freq)
            .map(|(key, (count, value))| (key, count, value))
            .collect();
        if candidates.is_empty() {
            return;
        }
        // Deterministic selection: frequency descending, typed key as tie-break
        // (HashMap iteration order must not leak into emitted code).
        candidates.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        candidates.truncate(homes.len());

        let mut pinned_vr_of: HashMap<PinKey, usize> = HashMap::with_capacity(candidates.len());
        let mut prologue: Vec<Instruction> = Vec::with_capacity(candidates.len());
        for ((key, _, value), &home) in candidates.iter().zip(homes.iter()) {
            let vr = Self::fresh_virtual_register(next_virtual_reg, secrecy_map, false);
            precolored.insert(vr, PhysicalRegister(home));
            pinned_vr_of.insert(*key, vr.0);
            prologue.push(Instruction::LDI(vr.0, value.clone()));
        }

        // Pass 1: decide deletions and build the dense rename map. This must be
        // a separate pass because a use may sit textually *before* its VR's
        // single def (a loop-carried read reached via a backedge), and every use
        // of a renamed VR has to be remapped, not just those after the def.
        let num_instructions = instructions.len();
        let mut delete = vec![false; num_instructions];
        let mut rename = vec![usize::MAX; def_count.len()];
        let mut deleted = 0usize;
        let mut prev_out_is_call = false;
        for (i, inst) in instructions.iter().enumerate() {
            if let Instruction::LDI(dest, value) = inst {
                let single_def_clear = def_count.get(*dest) == Some(&1)
                    && !secrecy_map.get(*dest).copied().unwrap_or(true);
                if *dest != 0
                    && single_def_clear
                    && !prev_out_is_call
                    && !precolored.contains_key(&VirtualRegister(*dest))
                {
                    if let Some(&pinned) = pin_key(value).and_then(|k| pinned_vr_of.get(&k)) {
                        rename[*dest] = pinned;
                        delete[i] = true;
                        deleted += 1;
                        // A deleted LDI emits nothing: `prev_out_is_call` keeps
                        // tracking the previous surviving instruction.
                        continue;
                    }
                }
            }
            prev_out_is_call = matches!(inst, Instruction::CALL(_));
        }
        if deleted == 0 {
            // Nothing to rewrite; drop the speculative pins again so the
            // allocator keeps the full clear bank.
            for (key, _, _) in &candidates {
                if let Some(vr) = pinned_vr_of.get(key) {
                    precolored.remove(&VirtualRegister(*vr));
                }
            }
            return;
        }

        // Pass 2: prepend the prologue, drop deleted LDIs, remap renamed uses
        // (renamed VRs are single-def with the def deleted, so defs never need
        // remapping), and shift labels through the usual boundary-inclusive
        // old-to-new index table.
        let old = std::mem::take(instructions);
        let mut out = Vec::with_capacity(num_instructions + prologue.len() - deleted);
        out.append(&mut prologue);
        let mut old_to_new = vec![0usize; num_instructions + 1];
        for (i, mut inst) in old.into_iter().enumerate() {
            old_to_new[i] = out.len();
            if delete[i] {
                continue;
            }
            let mut mapped_uses: [Option<(usize, usize)>; 2] = [None; 2];
            let mut mapped_use_count = 0;
            for used in register_allocator::use_regs(&inst).into_iter().flatten() {
                let target = rename.get(used).copied().unwrap_or(usize::MAX);
                if target != usize::MAX
                    && !mapped_uses
                        .iter()
                        .flatten()
                        .any(|&(old_vr, _)| old_vr == used)
                {
                    mapped_uses[mapped_use_count] = Some((used, target));
                    mapped_use_count += 1;
                }
            }
            Self::remap_instruction_registers_in_place(&mut inst, &mapped_uses, None);
            out.push(inst);
        }
        old_to_new[num_instructions] = out.len();
        for index in labels.values_mut() {
            *index = old_to_new.get(*index).copied().unwrap_or(out.len());
        }
        *instructions = out;

        if spill_stats_enabled() {
            let pins: Vec<String> = candidates
                .iter()
                .zip(homes.iter())
                .map(|((key, count, _), home)| format!("{key:?}x{count}->R{home}"))
                .collect();
            eprintln!(
                "CONST_PIN {diagnostic_name}: pinned={} deleted_ldis={deleted} pins=[{}]",
                candidates.len(),
                pins.join(", "),
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn allocate_registers_with_object_spills(
        instructions: &mut Vec<Instruction>,
        labels: &mut HashMap<String, usize>,
        next_virtual_reg: &mut usize,
        secrecy_map: &mut Vec<bool>,
        precolored: &HashMap<VirtualRegister, PhysicalRegister>,
        protected_prologue_len: usize,
        diagnostic_name: &str,
        spill_slot_cache: bool,
    ) -> CompilerResult<register_allocator::DenseAllocation> {
        let k_clear = SECRET_REGISTER_START;
        let k_secret = MAX_REGISTERS - k_clear;
        // Once spilling has started, hold back this many registers per pool so the reload
        // and store temporaries that spill lowering introduces (which we mark unspillable)
        // always have a home. This is what lets the loop converge in a couple of rounds:
        // a value that has already been spilled never needs to be spilled again.
        const SPILL_RESERVE: usize = 6;

        // Virtual registers created by spill lowering (the short-lived reload/store
        // scratch registers). They are never chosen as spill victims and may use the
        // reserved headroom above. Nothing else mints VRs inside the loop below, so
        // the unspillable set is always the contiguous id range
        // [unspillable_start, *next_virtual_reg) — a threshold compare instead of a set.
        let mut unspillable_start: Option<usize> = None;
        // Pin virtual register 0 to physical R0, the ABI result/scratch register.
        // Every CALL/builtin writes its result into physical R0, which codegen reads
        // back via `MOV(dest, 0)` — a use with no corresponding virtual-register def.
        // Left unpinned (e.g. in a zero-parameter function that makes calls), the
        // allocator sees VR0 as an always-live, never-defined value and spills it,
        // emitting `LDS` loads with no matching `STS` (reading an uninitialized Unit
        // and feeding it into clear/secret conversions). Precoloring keeps VR0 in R0
        // and out of the spill candidate set (matching the -O0 identity invariant and
        // the post-CALL `MOV` special-case in `rewrite_instructions`). For functions
        // with parameters this is already implied (parameter 0 is VR0 → R0); doing it
        // unconditionally covers the zero-parameter case. Precoloring (not the
        // `unspillable` set) is used deliberately so it doesn't trip the spill-reserve
        // heuristic, which keys off `unspillable` being non-empty.
        let precolored = {
            let mut precolored = precolored.clone();
            precolored
                .entry(register_allocator::VirtualRegister(0))
                .or_insert(register_allocator::PhysicalRegister(0));
            precolored
        };
        // Monotonic spill-slot counter so slots never collide across rounds.
        let mut next_spill_slot: usize = 0;
        let _ = protected_prologue_len; // spill traffic is position-independent now

        let live_in_vrs: Vec<VirtualRegister> = precolored.keys().copied().collect();
        let mut spill_stats = SpillLoweringStats::default();
        for _ in 0..64 {
            let intervals =
                register_allocator::analyze_liveness_cfg_dense(instructions, labels, &live_in_vrs);
            // No headroom needed until the first spill introduces unspillable temporaries,
            // so functions that fit get the full register file.
            let reserve = if unspillable_start.is_none() {
                0
            } else {
                SPILL_RESERVE
            };
            match register_allocator::linear_scan_partition(
                &intervals,
                k_clear,
                k_secret,
                reserve,
                secrecy_map,
                &precolored,
                unspillable_start.unwrap_or(register_allocator::NO_UNSPILLABLE),
            ) {
                Ok(allocation) => {
                    if spill_stats_enabled() && spill_stats.rounds > 0 {
                        eprintln!(
                            "SPILL_STATS {diagnostic_name}: rounds={} slots={} defs={} \
                             reload_hits=[clear {}, secret {}] reload_misses=[clear {}, secret {}] cache={}",
                            spill_stats.rounds,
                            spill_stats.spill_slots,
                            spill_stats.spilled_defs,
                            spill_stats.reload_hits[0],
                            spill_stats.reload_hits[1],
                            spill_stats.reload_misses[0],
                            spill_stats.reload_misses[1],
                            spill_slot_cache,
                        );
                    }
                    if std::env::var("STOFFEL_RA_CHECK").is_ok() {
                        Self::ra_interference_check(&allocation, &intervals, diagnostic_name);
                        Self::ra_liveness_coverage_check(instructions, &intervals, diagnostic_name);
                        Self::ra_pool_check(
                            &allocation,
                            secrecy_map,
                            k_clear,
                            k_secret,
                            diagnostic_name,
                        );
                    }
                    return Ok(allocation);
                }
                Err(AllocationError::NeedsSpilling(spilled_vrs)) => {
                    let first_new_vr = *next_virtual_reg;
                    // The slot-reload cache runs only in the FIRST spill round (which
                    // carries the mass of the spill traffic). Cached scratches live
                    // longer than plain per-use transients, and letting every round
                    // add its own long-lived cached scratches accumulates unspillable
                    // pressure across rounds: each round then displaces a few more
                    // spillable VRs and convergence dribbles out over many rounds
                    // (measured 2 -> 12 on the unrolled AES main). Later rounds use
                    // the plain transient scheme, restoring B1-like convergence.
                    let cache_this_round = spill_slot_cache && spill_stats.rounds == 0;
                    spill_stats.rounds += 1;
                    let old_instructions = std::mem::take(instructions);
                    let old_labels = std::mem::take(labels);
                    let (lowered_instructions, lowered_labels) = Self::lower_spills_into_slots(
                        old_instructions,
                        old_labels,
                        next_virtual_reg,
                        secrecy_map,
                        &spilled_vrs,
                        &mut next_spill_slot,
                        cache_this_round,
                        &mut spill_stats,
                    );
                    spill_stats.spill_slots = next_spill_slot;
                    *instructions = lowered_instructions;
                    *labels = lowered_labels;
                    // Every VR minted during lowering is spill machinery: keep it out of
                    // future spill decisions. Contiguous-range invariant: later rounds
                    // only ever mint ids above the recorded start.
                    debug_assert!(unspillable_start.is_none_or(|start| start <= first_new_vr));
                    if unspillable_start.is_none() && *next_virtual_reg > first_new_vr {
                        unspillable_start = Some(first_new_vr);
                    }
                }
                Err(AllocationError::PoolExhausted(_, _)) => {
                    return Err(CompilerError::internal_error(format!(
                        "Register allocation failed for {diagnostic_name}: Pool exhausted"
                    )));
                }
            }
        }

        Err(CompilerError::internal_error(format!(
            "Register allocation failed for {diagnostic_name}: object spill lowering did not converge"
        ))
        .with_hint("Try splitting the function into smaller helper functions."))
    }

    /// DEBUG: verify the RA's final assignment has no two genuinely-overlapping live
    /// intervals sharing a physical register (an interference violation). Uses the RA's
    /// own non-interference rule — `earlier.end <= later.start` may share (read-before-
    /// write at the boundary instruction); `earlier.end > later.start` is a real overlap.
    #[allow(dead_code)]
    fn ra_interference_check(
        allocation: &register_allocator::DenseAllocation,
        intervals: &[Option<register_allocator::LiveInterval>],
        name: &str,
    ) {
        let mut by_reg: HashMap<
            register_allocator::PhysicalRegister,
            Vec<(usize, usize, register_allocator::VirtualRegister)>,
        > = HashMap::new();
        for (id, phys) in allocation.iter().enumerate() {
            let Some(phys) = phys else { continue };
            if let Some(iv) = intervals.get(id).copied().flatten() {
                by_reg.entry(*phys).or_default().push((
                    iv.start,
                    iv.end,
                    register_allocator::VirtualRegister(id),
                ));
            }
        }
        let mut total = 0usize;
        for (phys, mut lst) in by_reg {
            lst.sort_by_key(|x| x.0);
            // Active-set sweep: VRs started but not yet ended (end > current start).
            let mut active: Vec<(usize, register_allocator::VirtualRegister)> = Vec::new();
            for (s, e, vr) in &lst {
                active.retain(|(ae, _)| *ae > *s);
                for (_, avr) in &active {
                    total += 1;
                    if total <= 12 {
                        eprintln!(
                            "RA_INTERFERENCE {name} phys={} overlaps vr={:?}[{},{}] and avr={:?}",
                            phys.0, vr, s, e, avr
                        );
                    }
                }
                active.push((*e, *vr));
            }
        }
        if total > 0 {
            eprintln!("RA_INTERFERENCE {name} total violations: {total}");
        }
    }

    /// DEBUG: verify every instruction's used VR is inside its computed live interval —
    /// a use outside the interval means liveness under-approximated the live range (the
    /// RA would then reuse that register before the real last use -> value corruption).
    #[allow(dead_code)]
    fn ra_liveness_coverage_check(
        instructions: &[Instruction],
        intervals: &[Option<register_allocator::LiveInterval>],
        name: &str,
    ) {
        use crate::register_allocator::InstructionRegisterAnalysis;
        let mut total = 0usize;
        for (ip, inst) in instructions.iter().enumerate() {
            for used_vr in inst.uses() {
                if let Some(iv) = intervals.get(used_vr.0).copied().flatten().as_ref() {
                    if ip < iv.start || ip > iv.end {
                        total += 1;
                        if total <= 12 {
                            eprintln!(
                                "LIVENESS_MISS {name} ip={ip} vr={used_vr:?} interval=[{},{}] (use outside interval)",
                                iv.start, iv.end
                            );
                        }
                    }
                }
            }
        }
        if total > 0 {
            eprintln!("LIVENESS_MISS {name} total violations: {total}");
        }
    }

    /// DEBUG: verify every VR's secrecy matches its physical register's pool. A secret
    /// VR placed in a clear register (or vice versa) makes the VM mis-execute MOVs
    /// (reveal vs copy) and MPC ops on it.
    #[allow(dead_code)]
    fn ra_pool_check(
        allocation: &register_allocator::DenseAllocation,
        secrecy_map: &[bool],
        k_clear: usize,
        k_secret: usize,
        name: &str,
    ) {
        let secret_end = k_clear + k_secret;
        let mut total = 0usize;
        for (id, phys) in allocation.iter().enumerate() {
            let Some(phys) = phys else { continue };
            let vr = register_allocator::VirtualRegister(id);
            // R0 (0) is the ABI register; skip it.
            if phys.0 == 0 {
                continue;
            }
            let is_secret = secrecy_map.get(vr.0).copied().unwrap_or(false);
            let in_secret_pool = (k_clear..secret_end).contains(&phys.0);
            let in_clear_pool = (1..k_clear).contains(&phys.0);
            if is_secret && !in_secret_pool {
                total += 1;
                if total <= 12 {
                    eprintln!(
                        "POOL_MISMATCH {name} secret vr={vr:?} in non-secret phys={} (clear_pool={in_clear_pool})",
                        phys.0
                    );
                }
            } else if !is_secret && !in_clear_pool {
                total += 1;
                if total <= 12 {
                    eprintln!(
                        "POOL_MISMATCH {name} clear vr={vr:?} in non-clear phys={}",
                        phys.0
                    );
                }
            }
        }
        if total > 0 {
            eprintln!("POOL_MISMATCH {name} total violations: {total}");
        }
    }

    fn record_client_io_call(&mut self, function_name: &str, arguments: &[AstNode]) {
        match function_name {
            "ClientStore.take_share"
            | "ClientStore.take_share_fixed"
            | "ClientStore.take_share_bool" => {
                // The client slot may be a literal, a loop variable (records every
                // client in the loop range), or a clear-int constant. Runtime
                // client-count loops are recorded later by client_io_planner as
                // dynamic input templates, so they are intentionally silent here.
                let Some(client_slots) = self.input_ordinals_for_node(arguments.first()) else {
                    return;
                };
                let Some(input_ordinals) = self.input_ordinals_for_node(arguments.get(1)) else {
                    return;
                };
                let share_type = if function_name == "ClientStore.take_share_fixed" {
                    ShareType::default_secret_fixed_point()
                } else if function_name == "ClientStore.take_share_bool" {
                    // `secret bool` is a 1-bit secret integer share.
                    ShareType::try_secret_int(1).unwrap_or_else(|_| ShareType::default_secret_int())
                } else {
                    ShareType::default_secret_int()
                };
                for client_slot in client_slots {
                    let inputs = self.client_inputs.entry(client_slot).or_default();
                    for input_ordinal in &input_ordinals {
                        let ordinal = *input_ordinal as usize;
                        if inputs.len() <= ordinal {
                            inputs.resize(ordinal + 1, None);
                        }
                        inputs[ordinal] = Some(share_type);
                    }
                }
            }
            "ClientStore.sum_shares"
            | "ClientStore.sum_shares_bool"
            | "ClientStore.sum_shares_fixed" => {
                let Some(input_ordinals) = self.input_ordinals_for_node(arguments.first()) else {
                    return;
                };
                let Some(client_counts) = self.input_ordinals_for_node(arguments.get(1)) else {
                    return;
                };
                let share_type = match function_name {
                    "ClientStore.sum_shares_bool" => ShareType::boolean(),
                    "ClientStore.sum_shares_fixed" => ShareType::default_secret_fixed_point(),
                    _ => ShareType::default_secret_int(),
                };
                for client_count in client_counts {
                    for client_slot in 0..client_count.max(1) {
                        let inputs = self.client_inputs.entry(client_slot).or_default();
                        for input_ordinal in &input_ordinals {
                            let ordinal = *input_ordinal as usize;
                            if inputs.len() <= ordinal {
                                inputs.resize(ordinal + 1, None);
                            }
                            inputs[ordinal] = Some(share_type);
                        }
                    }
                }
            }
            "MpcOutput.send_to_client" => {
                let Some(client_slots) = self.input_ordinals_for_node(arguments.first()) else {
                    Self::warn_unrecorded_client_io(function_name, "output");
                    return;
                };
                if let Some(value) = arguments.get(1) {
                    let outputs = self.output_share_types_for_node(value);
                    for client_slot in client_slots {
                        self.client_outputs
                            .entry(client_slot)
                            .or_default()
                            .extend(outputs.clone());
                    }
                }
            }
            "send_to_client" => {
                let Some(client_slots) = self.input_ordinals_for_node(arguments.get(1)) else {
                    Self::warn_unrecorded_client_io(function_name, "output");
                    return;
                };
                let share_type = arguments
                    .first()
                    .and_then(|argument| self.share_type_for_node(argument))
                    .unwrap_or_else(ShareType::default_secret_int);
                for client_slot in client_slots {
                    self.client_outputs
                        .entry(client_slot)
                        .or_default()
                        .push(share_type);
                }
            }
            _ => {}
        }
    }

    fn override_client_input_share_type_for_annotation(
        &mut self,
        value: Option<&AstNode>,
        share_type: Option<ShareType>,
    ) {
        let Some(share_type) = share_type else {
            return;
        };
        let Some(AstNode::FunctionCall {
            function,
            arguments,
            ..
        }) = value
        else {
            return;
        };
        let AstNode::Identifier(function_name, _) = function.as_ref() else {
            return;
        };
        // An explicit annotation refines the manifest entry beyond the
        // builtin's default: `secret bool`/`secret uintN` for take_share,
        // a concrete fixed-point layout for take_share_fixed.
        let annotation_applies = match function_name.as_str() {
            "ClientStore.take_share" | "ClientStore.sum_shares" => {
                !matches!(share_type, ShareType::SecretFixedPoint { .. })
            }
            "ClientStore.take_share_bool" | "ClientStore.sum_shares_bool" => {
                share_type.is_boolean()
            }
            "ClientStore.take_share_fixed" | "ClientStore.sum_shares_fixed" => {
                matches!(share_type, ShareType::SecretFixedPoint { .. })
            }
            _ => false,
        };
        if !annotation_applies {
            return;
        }
        if matches!(
            function_name.as_str(),
            "ClientStore.sum_shares"
                | "ClientStore.sum_shares_bool"
                | "ClientStore.sum_shares_fixed"
        ) {
            let Some(input_ordinals) = self.input_ordinals_for_node(arguments.first()) else {
                return;
            };
            let Some(client_counts) = self.input_ordinals_for_node(arguments.get(1)) else {
                return;
            };
            for client_count in client_counts {
                for client_slot in 0..client_count.max(1) {
                    let inputs = self.client_inputs.entry(client_slot).or_default();
                    for input_ordinal in &input_ordinals {
                        let ordinal = *input_ordinal as usize;
                        if inputs.len() <= ordinal {
                            inputs.resize(ordinal + 1, None);
                        }
                        inputs[ordinal] = Some(share_type);
                    }
                }
            }
            return;
        }
        let Some(client_slot) = int_literal_u64(arguments.first()) else {
            return;
        };
        let Some(input_ordinals) = self.input_ordinals_for_node(arguments.get(1)) else {
            return;
        };
        let inputs = self.client_inputs.entry(client_slot).or_default();
        for input_ordinal in input_ordinals {
            let ordinal = input_ordinal as usize;
            if inputs.len() <= ordinal {
                inputs.resize(ordinal + 1, None);
            }
            inputs[ordinal] = Some(share_type);
        }
    }

    fn record_share_list_append_call(&mut self, function_name: &str, arguments: &[AstNode]) {
        if function_name != "append" && function_name != "array_push" {
            return;
        }
        let Some(AstNode::Identifier(list_name, _)) = arguments.first() else {
            return;
        };
        let share_type = arguments
            .get(1)
            .and_then(|argument| self.share_type_for_node(argument))
            // A user helper declared as returning the generic `Share` object
            // does not carry a concrete bit layout through semantic typing.
            // The VM treats such shares as the default secret integer unless a
            // more precise annotation is available, so mirror that fallback in
            // the client-IO manifest instead of leaving an appended output list
            // empty (which would omit the client from output coordination).
            .unwrap_or_else(ShareType::default_secret_int);
        let repeat = self.active_loop_iteration_count();
        self.variable_share_lists
            .entry(list_name.clone())
            .or_default()
            .extend(std::iter::repeat_n(share_type, repeat));
    }

    fn input_ordinals_for_node(&self, node: Option<&AstNode>) -> Option<Vec<u64>> {
        match node? {
            AstNode::Literal { .. } => int_literal_u64(node).map(|ordinal| vec![ordinal]),
            AstNode::Identifier(name, _) => self
                .active_loop_bounds
                .iter()
                .rev()
                .find_map(|(loop_var, bound)| {
                    (loop_var == name).then(|| (0..*bound).collect::<Vec<_>>())
                })
                .or_else(|| self.clear_int_constants.get(name).map(|value| vec![*value])),
            _ => None,
        }
    }

    fn loop_bound_for_condition(&self, condition: &AstNode) -> Option<(String, u64)> {
        let AstNode::BinaryOperation {
            op, left, right, ..
        } = condition
        else {
            return None;
        };
        if op != "<" {
            return None;
        }
        let AstNode::Identifier(loop_var, _) = left.as_ref() else {
            return None;
        };
        let bound = int_literal_u64(Some(right.as_ref())).or_else(|| match right.as_ref() {
            AstNode::Identifier(name, _) => self.clear_int_constants.get(name).copied(),
            _ => None,
        })?;
        Some((loop_var.clone(), bound))
    }

    fn active_loop_iteration_count(&self) -> usize {
        self.active_loop_bounds
            .iter()
            .map(|(_, bound)| usize::try_from(*bound).unwrap_or(usize::MAX))
            .fold(1_usize, usize::saturating_mul)
    }

    fn share_type_for_node(&self, node: &AstNode) -> Option<ShareType> {
        match node {
            AstNode::Identifier(name, _) => self.variable_share_types.get(name).copied(),
            AstNode::FunctionCall {
                resolved_return_type,
                ..
            } => resolved_return_type
                .as_ref()
                .and_then(share_type_for_secret_scalar_symbol_type)
                .or_else(|| infer_single_share_type(node)),
            AstNode::BinaryOperation { left, right, .. } => {
                let left = self.share_type_for_node(left);
                let right = self.share_type_for_node(right);
                match (left, right) {
                    (
                        Some(ShareType::SecretFixedPoint { precision }),
                        Some(ShareType::SecretFixedPoint { .. }),
                    )
                    | (
                        Some(ShareType::SecretFixedPoint { precision }),
                        Some(ShareType::SecretInt { .. }),
                    )
                    | (
                        Some(ShareType::SecretInt { .. }),
                        Some(ShareType::SecretFixedPoint { precision }),
                    ) => Some(ShareType::SecretFixedPoint { precision }),
                    (Some(left), _) => Some(left),
                    (_, Some(right)) => Some(right),
                    _ => None,
                }
            }
            // Index and field access nodes carry their element type through the
            // semantic symbol table even when no scalar value has been assigned
            // to a named variable yet. Preserve that type for client-output
            // manifests instead of degrading, for example, `secret bool` list
            // elements to the default 64-bit secret integer.
            _ => self
                .type_hint_for_node(node)
                .as_ref()
                .and_then(share_type_for_secret_scalar_symbol_type),
        }
    }

    fn output_share_types_for_node(&self, node: &AstNode) -> Vec<ShareType> {
        match node {
            AstNode::Identifier(name, _) => self
                .variable_share_lists
                .get(name)
                .cloned()
                .or_else(|| {
                    self.variable_share_types
                        .get(name)
                        .copied()
                        .map(|ty| vec![ty])
                })
                .unwrap_or_else(|| vec![ShareType::default_secret_int()]),
            AstNode::ListLiteral { elements, .. } => elements
                .iter()
                .map(|element| {
                    self.share_type_for_node(element)
                        .unwrap_or_else(ShareType::default_secret_int)
                })
                .collect(),
            _ => vec![self
                .share_type_for_node(node)
                .unwrap_or_else(ShareType::default_secret_int)],
        }
    }

    fn is_clear_scalar_literal_for_share(node: &AstNode, share_type: ShareType) -> bool {
        match node {
            AstNode::Literal { value, .. } => matches!(
                (share_type, value),
                (ShareType::SecretInt { .. }, crate::ast::Value::Int { .. })
                    | (ShareType::SecretInt { .. }, crate::ast::Value::Bool(_))
                    | (ShareType::SecretUInt { .. }, crate::ast::Value::Int { .. })
                    | (
                        ShareType::SecretFixedPoint { .. },
                        crate::ast::Value::Int { .. }
                    )
                    | (
                        ShareType::SecretFixedPoint { .. },
                        crate::ast::Value::Float(_)
                    )
            ),
            AstNode::UnaryOperation { op, operand, .. } if op == "-" => {
                Self::is_clear_scalar_literal_for_share(operand, share_type)
            }
            _ => false,
        }
    }

    fn emit_i64_literal(&mut self, value: i64) -> VirtualRegister {
        let vr = self.allocate_virtual_register(false);
        self.identified_constants.push(Constant::I64(value));
        self.emit(Instruction::LDI(
            vr.0,
            crate::core_types::Value::from(Constant::I64(value)),
        ));
        vr
    }

    fn compile_clear_scalar_literal_as_share(
        &mut self,
        expr: &AstNode,
        share_type: ShareType,
    ) -> CompilerResult<Option<(VirtualRegister, bool)>> {
        if !Self::is_clear_scalar_literal_for_share(expr, share_type) {
            return Ok(None);
        }

        let (clear_vr, _clear_is_secret) = self.compile_node(expr)?;
        match share_type {
            ShareType::SecretField => return Ok(None),
            ShareType::SecretInt { bit_length } => {
                let bit_length_vr = self.emit_i64_literal(bit_length as i64);
                self.emit(Instruction::PUSHARG(clear_vr.0));
                self.emit(Instruction::PUSHARG(bit_length_vr.0));
                self.emit(Instruction::CALL("Share.from_clear_int".to_string()));
            }
            ShareType::SecretUInt { bit_length } => {
                let bit_length_vr = self.emit_i64_literal(bit_length as i64);
                self.emit(Instruction::PUSHARG(clear_vr.0));
                self.emit(Instruction::PUSHARG(bit_length_vr.0));
                self.emit(Instruction::CALL("Share.from_clear_uint".to_string()));
            }
            ShareType::SecretFixedPoint { precision } => {
                let total_bits_vr = self.emit_i64_literal(precision.total_bits() as i64);
                let fractional_bits_vr = self.emit_i64_literal(precision.fractional_bits() as i64);
                self.emit(Instruction::PUSHARG(clear_vr.0));
                self.emit(Instruction::PUSHARG(total_bits_vr.0));
                self.emit(Instruction::PUSHARG(fractional_bits_vr.0));
                self.emit(Instruction::CALL("Share.from_clear_fixed".to_string()));
            }
        }

        let result_vr = self.allocate_virtual_register(true);
        self.emit(Instruction::MOV(result_vr.0, 0));
        Ok(Some((result_vr, true)))
    }

    fn client_io_manifest(&self) -> ClientIoManifest {
        let mut slots = self
            .client_inputs
            .keys()
            .chain(self.client_outputs.keys())
            .copied()
            .collect::<Vec<_>>();
        slots.sort_unstable();
        slots.dedup();

        ClientIoManifest {
            mpc_backend: MpcBackend::default(),
            mpc_curve: stoffel_vm_types::compiled_binary::MpcCurve::default(),
            clients: slots
                .into_iter()
                .map(|client_slot| {
                    let inputs = self
                        .client_inputs
                        .get(&client_slot)
                        .map(|inputs| {
                            inputs
                                .iter()
                                .map(|share_type| {
                                    share_type.unwrap_or_else(ShareType::default_secret_int)
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    let outputs = self
                        .client_outputs
                        .get(&client_slot)
                        .cloned()
                        .unwrap_or_default();
                    ClientIoSchema {
                        client_slot,
                        inputs,
                        outputs,
                    }
                })
                .collect(),
            // Preprocessing demand is computed interprocedurally over the whole
            // program AST by `preprocessing_planner` and stamped into the
            // manifest in `generate_bytecode`; leave it at the default here.
            preprocessing_demand: PreprocessingDemand::default(),
            dynamic_client_inputs: Vec::new(),
        }
    }

    fn merge_client_io_from(&mut self, other: &CodeGenerator) {
        for (client_slot, inputs) in &other.client_inputs {
            let target = self.client_inputs.entry(*client_slot).or_default();
            if target.len() < inputs.len() {
                target.resize(inputs.len(), None);
            }
            for (idx, share_type) in inputs.iter().enumerate() {
                if share_type.is_some() {
                    target[idx] = *share_type;
                }
            }
        }
        for (client_slot, outputs) in &other.client_outputs {
            self.client_outputs
                .entry(*client_slot)
                .or_default()
                .extend(outputs.iter().copied());
        }
    }

    /// Adds a label pointing to the *next* instruction index.
    fn add_label(&mut self, label: String) {
        let pos = self.current_instructions.len();
        self.current_labels.insert(label, pos);
    }

    fn type_hint_for_node(&self, node: &AstNode) -> Option<SymbolType> {
        match node {
            AstNode::Identifier(name, _) => self.symbol_types.get(name).cloned(),
            AstNode::FieldAccess {
                object, field_name, ..
            } => self
                .type_hint_for_node(object)
                .and_then(|object_type| self.field_type_for_object_type(&object_type, field_name)),
            AstNode::IndexAccess { base, .. } => {
                self.type_hint_for_node(base).and_then(|base_type| {
                    match base_type.underlying_type() {
                        SymbolType::List(element_type) => Some(element_type.as_ref().clone()),
                        SymbolType::String => Some(SymbolType::String),
                        SymbolType::Dict(_, value_type) => Some(value_type.as_ref().clone()),
                        _ => None,
                    }
                })
            }
            AstNode::FunctionCall {
                resolved_return_type,
                ..
            } => resolved_return_type.clone(),
            AstNode::Literal { value, .. } => match value {
                crate::ast::Value::Int { kind, .. } => match kind {
                    Some(crate::ast::IntKind::Signed(crate::ast::IntWidth::W8)) => {
                        Some(SymbolType::Int8)
                    }
                    Some(crate::ast::IntKind::Signed(crate::ast::IntWidth::W16)) => {
                        Some(SymbolType::Int16)
                    }
                    Some(crate::ast::IntKind::Signed(crate::ast::IntWidth::W32)) => {
                        Some(SymbolType::Int32)
                    }
                    Some(crate::ast::IntKind::Signed(crate::ast::IntWidth::W64)) => {
                        Some(SymbolType::Int64)
                    }
                    Some(crate::ast::IntKind::Unsigned(crate::ast::IntWidth::W8)) => {
                        Some(SymbolType::UInt8)
                    }
                    Some(crate::ast::IntKind::Unsigned(crate::ast::IntWidth::W16)) => {
                        Some(SymbolType::UInt16)
                    }
                    Some(crate::ast::IntKind::Unsigned(crate::ast::IntWidth::W32)) => {
                        Some(SymbolType::UInt32)
                    }
                    Some(crate::ast::IntKind::Unsigned(crate::ast::IntWidth::W64)) => {
                        Some(SymbolType::UInt64)
                    }
                    None => Some(SymbolType::Int64),
                },
                crate::ast::Value::Float(_) => Some(SymbolType::Float),
                crate::ast::Value::String(_) => Some(SymbolType::String),
                crate::ast::Value::Bool(_) => Some(SymbolType::Bool),
                crate::ast::Value::Nil => Some(SymbolType::Nil),
            },
            AstNode::ListLiteral { elements, .. } => Some(SymbolType::List(Box::new(
                elements
                    .first()
                    .and_then(|element| self.type_hint_for_node(element))
                    .unwrap_or(SymbolType::Unknown),
            ))),
            AstNode::BinaryOperation {
                op, left, right, ..
            } => {
                let left_type = self.type_hint_for_node(left);
                let right_type = self.type_hint_for_node(right);
                match (op.as_str(), left_type.as_ref(), right_type.as_ref()) {
                    ("+", Some(left_type), Some(right_type))
                        if matches!(left_type.underlying_type(), SymbolType::List(_))
                            && matches!(right_type.underlying_type(), SymbolType::List(_)) =>
                    {
                        Some(left_type.clone())
                    }
                    ("*", Some(left_type), Some(right_type))
                        if matches!(left_type.underlying_type(), SymbolType::List(_))
                            && right_type.underlying_type().is_integer() =>
                    {
                        Some(left_type.clone())
                    }
                    ("*", Some(left_type), Some(right_type))
                        if left_type.underlying_type().is_integer()
                            && matches!(right_type.underlying_type(), SymbolType::List(_)) =>
                    {
                        Some(right_type.clone())
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn expression_has_list_type(&self, node: &AstNode) -> bool {
        self.type_hint_for_node(node)
            .is_some_and(|ty| matches!(ty.underlying_type(), SymbolType::List(_)))
    }

    fn is_autovivifying_list_mutator(function_name: &str) -> bool {
        matches!(function_name, "append" | "array_push" | "extend" | "insert")
    }

    fn compile_autovivified_list_expression(
        &mut self,
        node: &AstNode,
    ) -> CompilerResult<(VirtualRegister, bool)> {
        match node {
            AstNode::IndexAccess { base, index, .. } if self.expression_has_list_type(node) => {
                let (base_vr, base_is_secret) = self.compile_autovivified_list_expression(base)?;
                let (index_vr, index_is_secret) = self.compile_node(index)?;

                self.emit(Instruction::PUSHARG(base_vr.0));
                self.emit(Instruction::PUSHARG(index_vr.0));
                self.emit(Instruction::CALL("get_or_create_array_field".to_string()));

                let result_vr = self.allocate_virtual_register(false);
                self.emit(Instruction::MOV(result_vr.0, 0));
                Ok((result_vr, base_is_secret || index_is_secret))
            }
            _ => self.compile_node(node),
        }
    }

    fn field_type_for_object_type(
        &self,
        object_type: &SymbolType,
        field_name: &str,
    ) -> Option<SymbolType> {
        let object_name = match object_type.underlying_type() {
            SymbolType::Object(name) | SymbolType::TypeName(name) => name,
            _ => return None,
        };
        self.object_field_types.get(object_name).and_then(|fields| {
            fields
                .iter()
                .find_map(|(name, ty)| (name == field_name).then(|| ty.clone()))
        })
    }

    /// Compiles an AST node, returning the VirtualRegister holding the result
    /// and a boolean indicating if the result is secret.
    fn compile_node(&mut self, node: &AstNode) -> CompilerResult<(VirtualRegister, bool)> {
        match node {
            // --- Literals ---
            AstNode::Literal { value: lit, .. } => {
                // Literals are initially clear
                let vr = self.allocate_virtual_register(false); // Literals are clear
                let constant = match lit {
                    crate::ast::Value::Int { value, kind } => {
                        match kind {
                            Some(crate::ast::IntKind::Signed(w)) => match w {
                                crate::ast::IntWidth::W8 => Constant::I8(*value as i8),
                                crate::ast::IntWidth::W16 => Constant::I16(*value as i16),
                                crate::ast::IntWidth::W32 => Constant::I32(*value as i32),
                                crate::ast::IntWidth::W64 => Constant::I64(*value as i64),
                            },
                            Some(crate::ast::IntKind::Unsigned(w)) => match w {
                                crate::ast::IntWidth::W8 => Constant::U8(*value as u8),
                                crate::ast::IntWidth::W16 => Constant::U16(*value as u16),
                                crate::ast::IntWidth::W32 => Constant::U32(*value as u32),
                                crate::ast::IntWidth::W64 => Constant::U64(*value as u64),
                            },
                            None => Constant::I64(*value as i64), // default behavior
                        }
                    }
                    crate::ast::Value::Float(f) => {
                        Constant::Float(crate::bytecode::F64::new(f64::from_bits(*f)))
                    }
                    crate::ast::Value::String(s) => Constant::String(s.clone()),
                    crate::ast::Value::Bool(b) => Constant::Bool(*b),
                    crate::ast::Value::Nil => Constant::Unit,
                };
                // Record constant and convert to Value
                self.identified_constants.push(constant.clone());
                let value = crate::core_types::Value::from(constant);
                self.emit(Instruction::LDI(vr.0, value));
                Ok((vr, false)) // Return VR and its secrecy (false)
            }
            // --- Identifiers ---
            AstNode::Identifier(name, _location) => {
                // Semantic analysis already verified this identifier exists.
                // Look it up to get its register.
                if let Some(&vr_index) = self.symbol_table.get(name) {
                    let vr = VirtualRegister(vr_index);
                    let is_secret = *self
                        .vr_secrecy
                        .get(vr.0)
                        .expect("Identifier VR missing from secrecy map");
                    Ok((vr, is_secret))
                } else {
                    // Builtin objects like ClientStore don't need registers - they're accessed via methods
                    // Just return a dummy register (this shouldn't be reached for properly transformed code)
                    Err(CompilerError::internal_error(format!(
                        "Codegen failed: Symbol '{}' passed semantic analysis but not found in codegen symbol table",
                        name
                    )))
                }
            }
            AstNode::VariableDeclaration {
                name,
                value,
                type_annotation,
                is_mutable: _,
                is_secret,
                location: _,
            } => {
                // Determine if the initial value needs a secret register
                // Secrecy comes from a `secret` type annotation.
                // Semantic analysis should have ensured consistency if both are present.
                let annotation_type = type_annotation.as_ref().map(|n| SymbolType::from_ast(n));
                let value_type_hint = value
                    .as_deref()
                    .and_then(|expr| self.type_hint_for_node(expr));
                let declared_type = annotation_type
                    .clone()
                    .or(value_type_hint.clone())
                    .unwrap_or(SymbolType::Unknown);
                let final_type = if declared_type.is_secret() || *is_secret {
                    declared_type.with_secret_modifier()
                } else {
                    declared_type
                };
                let explicit_secret = final_type.uses_secret_register();
                let annotation_share_type = share_type_for_secret_scalar_symbol_type(&final_type);
                let value_share_type = annotation_share_type.or_else(|| {
                    value
                        .as_deref()
                        .and_then(|expr| self.share_type_for_node(expr))
                });
                let value_share_list = value.as_deref().and_then(|expr| match expr {
                    AstNode::ListLiteral { elements, .. } => Some(
                        elements
                            .iter()
                            .map(|element| {
                                self.share_type_for_node(element)
                                    .unwrap_or_else(ShareType::default_secret_int)
                            })
                            .collect::<Vec<_>>(),
                    ),
                    AstNode::Identifier(identifier, _) => {
                        self.variable_share_lists.get(identifier).cloned()
                    }
                    _ => None,
                });

                let (value_vr, value_is_secret) = match value {
                    Some(val_expr) => {
                        let (vr, is_sec) = if let Some(share_type) = annotation_share_type {
                            match self
                                .compile_clear_scalar_literal_as_share(val_expr, share_type)?
                            {
                                Some(result) => result,
                                None => self.compile_node(val_expr)?,
                            }
                        } else {
                            self.compile_node(val_expr)?
                        };
                        let needs_secret = explicit_secret || is_sec;
                        let target_vr = self.allocate_virtual_register(needs_secret);
                        self.emit(Instruction::MOV(target_vr.0, vr.0));
                        (target_vr, needs_secret)
                    }
                    None => self.compile_default_value_for_type(&final_type, explicit_secret)?,
                };

                // Store the variable name and its register in the symbol table.
                self.symbol_table.insert(name.clone(), value_vr.0);
                self.symbol_types.insert(name.clone(), final_type);
                if let Some(share_types) = value_share_list {
                    self.variable_share_lists.insert(name.clone(), share_types);
                    self.variable_share_types.remove(name);
                } else if let Some(share_type) = value_share_type {
                    self.variable_share_types.insert(name.clone(), share_type);
                    self.override_client_input_share_type_for_annotation(
                        value.as_deref(),
                        Some(share_type),
                    );
                    self.variable_share_lists.remove(name);
                } else {
                    self.variable_share_types.remove(name);
                    self.variable_share_lists.remove(name);
                }
                if let Some(value) = value
                    .as_deref()
                    .and_then(|node| int_literal_u64(Some(node)))
                    .filter(|_| !self.reassigned_vars.contains(name))
                {
                    self.clear_int_constants.insert(name.clone(), value);
                } else {
                    self.clear_int_constants.remove(name);
                }
                // Update vr_secrecy for this VR to ensure it has the correct flag.
                // Sentinel VRs (e.g. VirtualRegister(0) from EnumDefinition/Import arms)
                // may not have been minted, so guard the indexed write.
                if let Some(slot) = self.vr_secrecy.get_mut(value_vr.0) {
                    *slot = value_is_secret;
                }

                Ok((value_vr, value_is_secret)) // Return the VR holding the initial value and its secrecy
            }
            // --- Operations ---
            AstNode::UnaryOperation {
                op,
                operand,
                location,
            } => {
                let operand_type_hint = self.type_hint_for_node(operand);
                let (operand_vr, operand_is_secret) = self.compile_node(operand)?;
                let result_is_secret = operand_is_secret; // Unary ops preserve secrecy
                let dest_vr = self.allocate_virtual_register(result_is_secret);

                match op.as_str() {
                    "-" => {
                        let zero_vr = self.allocate_virtual_register(false);
                        // The zero must match the operand's width: the VM rejects
                        // mixed-width SUB, so `-x` on int32 needs an I32 zero.
                        let zero_constant =
                            match operand_type_hint.as_ref().map(SymbolType::underlying_type) {
                                Some(SymbolType::Float | SymbolType::Fixed { .. }) => {
                                    Constant::Float(crate::bytecode::F64::new(0.0))
                                }
                                Some(SymbolType::Int32) => Constant::I32(0),
                                Some(SymbolType::Int16) => Constant::I16(0),
                                Some(SymbolType::Int8) => Constant::I8(0),
                                _ => Constant::I64(0),
                            };
                        self.identified_constants.push(zero_constant.clone());
                        self.emit(Instruction::LDI(
                            zero_vr.0,
                            crate::core_types::Value::from(zero_constant),
                        ));
                        self.emit(Instruction::SUB(dest_vr.0, zero_vr.0, operand_vr.0));
                    }
                    "not" => self.emit(Instruction::NOT(dest_vr.0, operand_vr.0)),
                    _ => {
                        return Err(CompilerError::semantic_error(
                            format!("Unsupported unary operator: {}", op),
                            location.clone(),
                        )
                        .with_hint("Supported unary operators are: - and not"));
                    }
                }

                Ok((dest_vr, result_is_secret))
            }
            AstNode::BinaryOperation {
                op,
                left,
                right,
                location,
            } => {
                let left_type_hint = self.type_hint_for_node(left);
                let right_type_hint = self.type_hint_for_node(right);
                let is_list_concat = op == "+"
                    && matches!(
                        (
                            left_type_hint.as_ref().map(SymbolType::underlying_type),
                            right_type_hint.as_ref().map(SymbolType::underlying_type),
                        ),
                        (Some(SymbolType::List(_)), Some(SymbolType::List(_)))
                    );
                let is_left_list = matches!(
                    left_type_hint.as_ref().map(SymbolType::underlying_type),
                    Some(SymbolType::List(_))
                );
                let is_right_list = matches!(
                    right_type_hint.as_ref().map(SymbolType::underlying_type),
                    Some(SymbolType::List(_))
                );
                // Semantic analysis guarantees a clear integer count. Hints are
                // intentionally partial (e.g. conditional expressions), so do not
                // require a count hint to lower an already checked repetition.
                let is_list_repeat = op == "*" && (is_left_list || is_right_list);
                let is_list_equality =
                    matches!(op.as_str(), "==" | "!=") && is_left_list && is_right_list;
                let (left_vr, left_is_secret) = self.compile_node(left)?;
                let (right_vr, right_is_secret) = self.compile_node(right)?;

                let mut result_is_secret = left_is_secret || right_is_secret;

                if is_list_concat {
                    self.emit(Instruction::PUSHARG(left_vr.0));
                    self.emit(Instruction::PUSHARG(right_vr.0));
                    self.emit(Instruction::CALL("array_concat".to_string()));

                    let result_vr = self.allocate_virtual_register(false);
                    self.emit(Instruction::MOV(result_vr.0, 0));
                    return Ok((result_vr, false));
                }

                if is_list_repeat {
                    let (array_vr, count_vr) = if is_left_list {
                        (left_vr, right_vr)
                    } else {
                        (right_vr, left_vr)
                    };
                    self.emit(Instruction::PUSHARG(array_vr.0));
                    self.emit(Instruction::PUSHARG(count_vr.0));
                    self.emit(Instruction::CALL("array_repeat".to_string()));

                    let result_vr = self.allocate_virtual_register(false);
                    self.emit(Instruction::MOV(result_vr.0, 0));
                    return Ok((result_vr, false));
                }

                if is_list_equality {
                    self.emit(Instruction::PUSHARG(left_vr.0));
                    self.emit(Instruction::PUSHARG(right_vr.0));
                    self.emit(Instruction::CALL("array_equals".to_string()));

                    let result_vr = self.allocate_virtual_register(false);
                    self.emit(Instruction::MOV(result_vr.0, 0));
                    if op == "!=" {
                        self.emit(Instruction::NOT(result_vr.0, result_vr.0));
                    }
                    return Ok((result_vr, false));
                }

                match op.as_str() {
                    "in" => {
                        // x in xs lowers to the builtin contains(xs, x).
                        self.emit(Instruction::PUSHARG(right_vr.0));
                        self.emit(Instruction::PUSHARG(left_vr.0));
                        self.emit(Instruction::CALL("contains".to_string()));
                        let result_vr = self.allocate_virtual_register(false);
                        self.emit(Instruction::MOV(result_vr.0, 0));
                        Ok((result_vr, false))
                    }
                    "mod" => {
                        // Floored modulo, lowered from the truncating MOD
                        // (remainder) instruction as ((a % b) + b) % b. This
                        // yields a result with the divisor's sign for every
                        // operand-sign combination, whereas '%' keeps the
                        // dividend's sign.
                        let rem_vr = self.allocate_virtual_register(result_is_secret);
                        self.emit(Instruction::MOD(rem_vr.0, left_vr.0, right_vr.0));
                        let shifted_vr = self.allocate_virtual_register(result_is_secret);
                        self.emit(Instruction::ADD(shifted_vr.0, rem_vr.0, right_vr.0));
                        let dest_vr = self.allocate_virtual_register(result_is_secret);
                        self.emit(Instruction::MOD(dest_vr.0, shifted_vr.0, right_vr.0));
                        Ok((dest_vr, result_is_secret))
                    }
                    "+" | "-" | "*" | "/" | "%" | // Arithmetic
                    "and" | "or" | "xor" | // Logical/Bitwise
                    "shl" | "shr" // Shifts
                    => {
                        let dest_vr = self.allocate_virtual_register(result_is_secret);
                        match op.as_str() {
                            "+" => self.emit(Instruction::ADD(dest_vr.0, left_vr.0, right_vr.0)),
                            "-" => self.emit(Instruction::SUB(dest_vr.0, left_vr.0, right_vr.0)),
                            "*" => self.emit(Instruction::MUL(dest_vr.0, left_vr.0, right_vr.0)),
                            "/" => self.emit(Instruction::DIV(dest_vr.0, left_vr.0, right_vr.0)),
                            "%" => self.emit(Instruction::MOD(dest_vr.0, left_vr.0, right_vr.0)),
                            "and" => self.emit(Instruction::AND(dest_vr.0, left_vr.0, right_vr.0)),
                            "or" => self.emit(Instruction::OR(dest_vr.0, left_vr.0, right_vr.0)),
                            "xor" => self.emit(Instruction::XOR(dest_vr.0, left_vr.0, right_vr.0)),
                            "shl" => self.emit(Instruction::SHL(dest_vr.0, left_vr.0, right_vr.0)),
                            "shr" => self.emit(Instruction::SHR(dest_vr.0, left_vr.0, right_vr.0)),
                            _ => unreachable!(),
                        }
                        Ok((dest_vr, result_is_secret))
                    }
                    "==" | "!=" | "<" | "<=" | ">" | ">=" => {
                        // Comparison operators produce a boolean result.
                        // Secrecy follows operands: secret if either side is secret.
                        result_is_secret = left_is_secret || right_is_secret;
                        let bool_dest_vr = self.allocate_virtual_register(result_is_secret);

                        // Emit CMP instruction
                        self.emit(Instruction::CMP(left_vr.0, right_vr.0));

                        // Emit the appropriate conditional jump
                        match op.as_str() {
                            "==" | "!=" | "<" | ">" => {
                                // Standard logic: Jump to true label if condition met
                                let true_label = format!("cmp_true_{}", self.current_instructions.len());
                                let end_label = format!("cmp_end_{}", self.current_instructions.len());

                                let jump_instruction = match op.as_str() {
                                    "==" => Instruction::JMPEQ(true_label.clone()),
                                    "!=" => Instruction::JMPNEQ(true_label.clone()),
                                    "<" => Instruction::JMPLT(true_label.clone()),
                                    ">" => Instruction::JMPGT(true_label.clone()),
                                    _ => unreachable!(),
                                };
                                self.emit(jump_instruction);

                                // If condition is false
                                // Load clear/secret false according to destination secrecy
                                self.identified_constants.push(Constant::Bool(false));
                                self.emit(Instruction::LDI(bool_dest_vr.0, crate::core_types::Value::Bool(false)));
                                self.emit(Instruction::JMP(end_label.clone()));

                                // Define the true label's position
                                self.add_label(true_label);
                                self.identified_constants.push(Constant::Bool(true));
                                self.emit(Instruction::LDI(bool_dest_vr.0, crate::core_types::Value::Bool(true)));

                                // Define the end label's position
                                self.add_label(end_label);
                            },
                            "<=" | ">=" => {
                                // Inverted logic: Jump to false label if opposite condition met
                                let false_label = format!("cmp_false_{}", self.current_instructions.len());
                                let end_label = format!("cmp_end_{}", self.current_instructions.len());

                                let jump_instruction = match op.as_str() {
                                    "<=" => Instruction::JMPGT(false_label.clone()), // Jump if >
                                    ">=" => Instruction::JMPLT(false_label.clone()), // Jump if <
                                    _ => unreachable!(),
                                };
                                self.emit(jump_instruction);

                                // If condition is true (jump not taken)
                                self.identified_constants.push(Constant::Bool(true));
                                self.emit(Instruction::LDI(bool_dest_vr.0, crate::core_types::Value::Bool(true)));
                                self.emit(Instruction::JMP(end_label.clone()));

                                // Define the false label's position
                                self.add_label(false_label);
                                self.identified_constants.push(Constant::Bool(false));
                                self.emit(Instruction::LDI(bool_dest_vr.0, crate::core_types::Value::Bool(false)));

                                // Define the end label's position
                                self.add_label(end_label);
                            },
                            _ => unreachable!(), // Should be covered by outer match
                        };

                        // left_vr and right_vr are used. bool_dest_vr is defined.
                        Ok((bool_dest_vr, result_is_secret))
                    },
                    _ => Err(CompilerError::semantic_error(format!("Unsupported binary operator: {}", op), location.clone())
                        .with_hint("Supported operators are: +, -, *, /, ==, !=, <, <=, >, >=".to_string())),
                }
            }
            // --- Assignment ---
            AstNode::Assignment {
                target,
                value,
                location,
            } => {
                match target.as_ref() {
                    AstNode::Identifier(name, _target_loc) => {
                        let target_share_type =
                            self.variable_share_types.get(name).copied().or_else(|| {
                                self.symbol_types
                                    .get(name)
                                    .and_then(share_type_for_secret_scalar_symbol_type)
                            });
                        let (value_vr, _value_is_secret) = if let Some(share_type) =
                            target_share_type
                        {
                            match self.compile_clear_scalar_literal_as_share(value, share_type)? {
                                Some(result) => result,
                                None => self.compile_node(value)?,
                            }
                        } else {
                            self.compile_node(value)?
                        };
                        let dest_vr_index =
                            self.symbol_table.get(name).cloned().ok_or_else(|| {
                                CompilerError::internal_error(format!(
                                    "Assignment target '{}' not found in symbol table",
                                    name
                                ))
                            })?;
                        // The MOV instruction implicitly handles potential hide/reveal
                        // based on the source and destination register halves.
                        self.emit(Instruction::MOV(dest_vr_index, value_vr.0));

                        // Assignment itself doesn't produce a value/register to be used further.
                        if let Some(value) = int_literal_u64(Some(value.as_ref()))
                            .filter(|_| !self.reassigned_vars.contains(name))
                        {
                            self.clear_int_constants.insert(name.clone(), value);
                        } else {
                            self.clear_int_constants.remove(name);
                        }
                        Ok(self.emit_unit_value())
                    }
                    AstNode::FieldAccess {
                        object,
                        field_name,
                        location: _,
                    } => {
                        // Compile object and value
                        let (obj_vr, _obj_is_secret) = self.compile_node(object)?;
                        let (val_vr, _val_is_secret) = self.compile_node(value)?;

                        // Load field name as string constant
                        let field_const = Constant::String(field_name.clone());
                        self.identified_constants.push(field_const.clone());
                        let field_vr = self.allocate_virtual_register(false);
                        self.emit(Instruction::LDI(
                            field_vr.0,
                            crate::core_types::Value::from(field_const),
                        ));

                        // Call set_field(object, field_name, value)
                        self.emit(Instruction::PUSHARG(obj_vr.0));
                        self.emit(Instruction::PUSHARG(field_vr.0));
                        self.emit(Instruction::PUSHARG(val_vr.0));
                        self.emit(Instruction::CALL("set_field".to_string()));

                        Ok(self.emit_unit_value())
                    }
                    AstNode::IndexAccess {
                        base,
                        index,
                        location: _,
                    } => {
                        // Compile base, index, and value
                        let (base_vr, _base_is_secret) =
                            self.compile_autovivified_list_expression(base)?;
                        let (idx_vr, _idx_is_secret) = self.compile_node(index)?;
                        let (val_vr, _val_is_secret) = self.compile_node(value)?;

                        // Call set_field(base, index, value)
                        self.emit(Instruction::PUSHARG(base_vr.0));
                        self.emit(Instruction::PUSHARG(idx_vr.0));
                        self.emit(Instruction::PUSHARG(val_vr.0));
                        self.emit(Instruction::CALL("set_field".to_string()));

                        Ok(self.emit_unit_value())
                    }
                    _ => Err(CompilerError::semantic_error(
                        "Invalid assignment target",
                        location.clone(),
                    )),
                }
            }
            // --- Control Flow & Functions ---
            AstNode::FunctionCall {
                function,
                arguments,
                location: _,
                resolved_return_type,
            } => {
                if arguments.is_empty() && is_share_random_call(function) {
                    if let Some(return_type) = resolved_return_type.as_ref() {
                        if let Some(share_type) =
                            share_type_for_secret_scalar_symbol_type(return_type)
                        {
                            let bit_length = match share_type {
                                ShareType::SecretInt { bit_length }
                                | ShareType::SecretUInt { bit_length } => bit_length,
                                ShareType::SecretFixedPoint { .. } | ShareType::SecretField => {
                                    unreachable!()
                                }
                            };
                            let bit_length_vr = self.allocate_virtual_register(false);
                            self.identified_constants
                                .push(Constant::I64(bit_length as i64));
                            self.emit(Instruction::LDI(
                                bit_length_vr.0,
                                crate::core_types::Value::from(Constant::I64(bit_length as i64)),
                            ));
                            self.emit(Instruction::PUSHARG(bit_length_vr.0));
                            self.emit(Instruction::CALL("Share.random_int".to_string()));

                            let result_vr = self.allocate_virtual_register(true);
                            self.emit(Instruction::MOV(result_vr.0, 0));
                            return Ok((result_vr, true));
                        }
                    }
                }

                if let (
                    AstNode::Identifier(function_name, _),
                    Some(SymbolType::Object(object_name)),
                ) = (function.as_ref(), resolved_return_type.as_ref())
                {
                    if function_name == object_name
                        && arguments
                            .iter()
                            .all(|arg| matches!(arg, AstNode::NamedArgument { .. }))
                    {
                        self.emit(Instruction::CALL("create_object".to_string()));

                        let obj_vr = self.allocate_virtual_register(false);
                        self.emit(Instruction::MOV(obj_vr.0, 0));

                        for arg in arguments {
                            let AstNode::NamedArgument {
                                name: field_name,
                                value,
                                ..
                            } = arg
                            else {
                                unreachable!("constructor arguments were checked above");
                            };

                            let (value_vr, _value_is_secret) = self.compile_node(value)?;

                            let field_const = Constant::String(field_name.clone());
                            self.identified_constants.push(field_const.clone());
                            let field_vr = self.allocate_virtual_register(false);
                            self.emit(Instruction::LDI(
                                field_vr.0,
                                crate::core_types::Value::from(field_const),
                            ));

                            self.emit(Instruction::PUSHARG(obj_vr.0));
                            self.emit(Instruction::PUSHARG(field_vr.0));
                            self.emit(Instruction::PUSHARG(value_vr.0));
                            self.emit(Instruction::CALL("set_field".to_string()));
                        }

                        return Ok((obj_vr, false));
                    }
                }

                // 1. Identify the function name
                // Semantic analysis already verified the function exists and is callable.
                let raw_function_name =
                    match function.as_ref() {
                        AstNode::Identifier(name, _) => name.clone(),
                        // Semantic analysis should have caught non-identifier calls if unsupported
                        _ => return Err(CompilerError::internal_error(
                            "Codegen expected identifier for function call after semantic analysis"
                                .to_string(),
                        )),
                    };

                // 2. Map source-level builtin aliases to actual VM function names.
                let function_name = crate::builtin_registry::builtin_registry()
                    .vm_symbol_for_call(&raw_function_name)
                    .map(str::to_string)
                    .unwrap_or(raw_function_name);

                self.record_client_io_call(&function_name, arguments);
                self.record_share_list_append_call(&function_name, arguments);

                // 3. Compile arguments first (do NOT emit PUSHARG yet) to keep PUSHARGs contiguous before CALL
                let mut arg_vrs = Vec::with_capacity(arguments.len());
                for (index, arg) in arguments.iter().enumerate() {
                    let (arg_vr, _arg_is_secret) =
                        if index == 0 && Self::is_autovivifying_list_mutator(&function_name) {
                            self.compile_autovivified_list_expression(arg)?
                        } else {
                            self.compile_node(arg)?
                        };
                    arg_vrs.push(arg_vr);
                }
                // After all arguments are compiled, emit contiguous PUSHARGs in order
                for vr in &arg_vrs {
                    self.emit(Instruction::PUSHARG(vr.0));
                }

                // 4. Determine result type and secrecy from resolved type (added by semantic analysis)
                let return_type = resolved_return_type
                    .as_ref()
                    .cloned()
                    .unwrap_or(SymbolType::Unknown);

                let result_is_secret = return_type.uses_secret_register();
                let result_vr = self.allocate_virtual_register(result_is_secret);

                self.emit(Instruction::CALL(function_name.clone()));
                // Only move the result if the function actually returns something
                if return_type != SymbolType::Void {
                    self.emit(Instruction::MOV(result_vr.0, 0)); // Assume result is in r0 (physical) after call
                }

                Ok((result_vr, result_is_secret)) // Return the VR holding the result
            }
            AstNode::NamedArgument { location, .. } => Err(CompilerError::internal_error(format!(
                "Codegen received named argument outside object constructor at {}:{}",
                location.line, location.column
            ))),
            AstNode::IfExpression {
                condition,
                then_branch,
                else_branch,
            } => {
                let (condition_vr, condition_is_secret) = self.compile_node(condition)?;
                if condition_is_secret {
                    return Err(CompilerError::semantic_error(
                        "Cannot use secret value as condition in 'if'",
                        condition.location(),
                    ));
                }

                // Compare the boolean condition VR against Bool(false)
                // Note: Condition itself is already boolean, but CMP sets flags for jumps.
                let false_vr = self.allocate_virtual_register(false); // false is clear
                self.identified_constants.push(Constant::Bool(false));
                self.emit(Instruction::LDI(
                    false_vr.0,
                    crate::core_types::Value::Bool(false),
                ));
                self.emit(Instruction::CMP(condition_vr.0, false_vr.0)); // Compare condition == false

                let else_label = format!("else_{}", self.current_instructions.len());
                let end_label = format!("end_if_{}", self.current_instructions.len());

                // Jump to else when condition == false
                self.emit(Instruction::JMPEQ(else_label.clone()));

                // --- Then Branch ---
                let (then_vr, then_is_secret) = self.compile_node(then_branch)?;
                // Provisional result register uses then-branch secrecy; may be updated after else
                let result_is_secret = then_is_secret;
                let result_vr = self.allocate_virtual_register(result_is_secret);
                self.emit(Instruction::MOV(result_vr.0, then_vr.0));
                // Skip else branch after executing then branch
                self.emit(Instruction::JMP(end_label.clone()));

                // --- Else Branch ---
                self.add_label(else_label);
                let (else_vr, else_is_secret) = match else_branch.as_deref() {
                    Some(branch) => self.compile_node(branch)?,
                    None => {
                        // If no else, evaluate to Unit (clear)
                        let vr = self.allocate_virtual_register(false);
                        self.identified_constants.push(Constant::Unit);
                        self.emit(Instruction::LDI(vr.0, crate::core_types::Value::Unit));
                        (vr, false)
                    }
                };
                // Update secrecy if needed (result is secret if either branch is secret)
                let final_result_is_secret = result_is_secret || else_is_secret;
                if final_result_is_secret != result_is_secret {
                    // Update secrecy map so allocator places this VR into correct bank
                    // (guarded: sentinel VRs may not have been minted).
                    if let Some(slot) = self.vr_secrecy.get_mut(result_vr.0) {
                        *slot = final_result_is_secret;
                    }
                }
                self.emit(Instruction::MOV(result_vr.0, else_vr.0));

                // --- End Label ---
                self.add_label(end_label);
                Ok((result_vr, final_result_is_secret))
            }
            AstNode::Block(nodes) => {
                let mut last_vr = self.allocate_virtual_register(false); // Default VR for empty block (clear)
                let mut last_vr_is_secret = false;
                for node in nodes {
                    (last_vr, last_vr_is_secret) = self.compile_node(node)?;
                }
                Ok((last_vr, last_vr_is_secret))
            }
            AstNode::Return { value, location: _ } => {
                // Determine secrecy based on function signature's return type (TODO)
                let (value_vr, value_is_secret) = match value {
                    Some(v) => self.compile_node(v)?,
                    None => {
                        // Return Unit (assume clear default)
                        let vr = self.allocate_virtual_register(false);
                        self.identified_constants.push(Constant::Unit);
                        self.emit(Instruction::LDI(vr.0, crate::core_types::Value::Unit));
                        (vr, false)
                    }
                };
                // Return the value directly from its virtual register; the VM will place it in caller's R0.
                self.emit(Instruction::RET(value_vr.0));
                Ok((value_vr, value_is_secret)) // Return VR, though RET is terminal
            }
            AstNode::DiscardStatement {
                expression,
                location: _,
            } => {
                let (vr, is_secret) = self.compile_node(expression)?;
                // The VR's live range ends here. Allocator handles it.
                Ok((vr, is_secret)) // Return the VR, but its value isn't used further
            }
            AstNode::FieldAccess {
                object,
                field_name,
                location: _,
            } => {
                let (object_vr, _object_is_secret) = self.compile_node(object)?;

                // Load field name as string constant
                let field_const = Constant::String(field_name.clone());
                self.identified_constants.push(field_const.clone());
                let field_vr = self.allocate_virtual_register(false);
                self.emit(Instruction::LDI(
                    field_vr.0,
                    crate::core_types::Value::from(field_const),
                ));

                // Call get_field(object, field_name)
                self.emit(Instruction::PUSHARG(object_vr.0));
                self.emit(Instruction::PUSHARG(field_vr.0));
                self.emit(Instruction::CALL("get_field".to_string()));

                let result_is_secret = self
                    .type_hint_for_node(node)
                    .is_some_and(|ty| ty.uses_secret_register());
                let result_vr = self.allocate_virtual_register(result_is_secret);
                self.emit(Instruction::MOV(result_vr.0, 0)); // Result is in r0

                Ok((result_vr, result_is_secret))
            }
            AstNode::EnumDefinition { .. } => {
                // Enums are compile-time constants (semantic analysis folds
                // member accesses to literals); nothing to emit.
                Ok((VirtualRegister(0), false))
            }
            AstNode::Break => {
                let Some((_, break_label)) = self.loop_label_stack.last().cloned() else {
                    return Err(CompilerError::semantic_error(
                        "'break' outside of a loop",
                        SourceLocation::default(),
                    ));
                };
                self.emit(Instruction::JMP(break_label));
                // Unreachable placeholder value so the statement has a register.
                let nil_vr = self.allocate_virtual_register(false);
                self.identified_constants.push(Constant::Unit);
                self.emit(Instruction::LDI(nil_vr.0, crate::core_types::Value::Unit));
                Ok((nil_vr, false))
            }
            AstNode::Continue => {
                let Some((continue_label, _)) = self.loop_label_stack.last().cloned() else {
                    return Err(CompilerError::semantic_error(
                        "'continue' outside of a loop",
                        SourceLocation::default(),
                    ));
                };
                self.emit(Instruction::JMP(continue_label));
                let nil_vr = self.allocate_virtual_register(false);
                self.identified_constants.push(Constant::Unit);
                self.emit(Instruction::LDI(nil_vr.0, crate::core_types::Value::Unit));
                Ok((nil_vr, false))
            }
            AstNode::WhileLoop {
                condition,
                body,
                location: _,
            } => {
                let loop_start_label = format!("loop_start_{}", self.current_instructions.len());
                let end_loop_label = format!("loop_end_{}", self.current_instructions.len());
                let loop_bound = self.loop_bound_for_condition(condition);

                // Define the label for the start of the loop (condition check)
                self.add_label(loop_start_label.clone());

                // Compile condition (assume clear for CMP/JMP)
                let (condition_vr, condition_is_secret) = self.compile_node(condition)?;
                if condition_is_secret {
                    return Err(CompilerError::semantic_error(
                        "Cannot use secret value as condition in 'while'",
                        condition.location(),
                    ));
                }

                // Compare the boolean condition VR against Bool(false)
                let false_vr = self.allocate_virtual_register(false); // false is clear
                self.identified_constants.push(Constant::Bool(false));
                self.emit(Instruction::LDI(
                    false_vr.0,
                    crate::core_types::Value::Bool(false),
                ));
                self.emit(Instruction::CMP(condition_vr.0, false_vr.0)); // Compare condition == false

                self.emit(Instruction::JMPEQ(end_loop_label.clone()));
                // condition_vr, false_vr used up to here.

                // break exits the loop; continue re-checks the condition.
                self.loop_label_stack
                    .push((loop_start_label.clone(), end_loop_label.clone()));
                let body_result = if let Some((loop_var, bound)) = loop_bound {
                    self.active_loop_bounds.push((loop_var, bound));
                    let result = self.compile_node(body);
                    self.active_loop_bounds.pop();
                    result
                } else {
                    self.compile_node(body)
                };
                self.loop_label_stack.pop();
                let (_body_vr, _body_is_secret) = body_result?;
                // Result of body is discarded. Its live range ends.

                // Jump back to condition check
                self.emit(Instruction::JMP(loop_start_label));

                // Define the end label's position
                self.add_label(end_loop_label);

                // While loops evaluate to Unit
                let nil_vr = self.allocate_virtual_register(false); // Unit is clear
                self.identified_constants.push(Constant::Unit);
                self.emit(Instruction::LDI(nil_vr.0, crate::core_types::Value::Unit));
                Ok((nil_vr, false))
            }
            AstNode::ForLoop {
                variables,
                iterable,
                body,
                location,
            } => {
                let outer_bindings = self.symbol_table.clone();
                let outer_types = self.symbol_types.clone();
                let outer_objects = self.object_field_types.clone();
                // Support: single var over range a .. b (exclusive) or over a list/array
                if variables.len() != 1 {
                    return Err(CompilerError::semantic_error(
                        "For-loop with multiple variables not supported yet",
                        location.clone(),
                    ));
                }

                let var_name = variables[0].clone();

                // Check if iterable is a range or a collection
                match iterable.as_ref() {
                    AstNode::BinaryOperation {
                        op,
                        left,
                        right,
                        location: _,
                    } if op == ".." => {
                        // Range iteration: for i in start..end, excluding end
                        let (start_vr, start_is_secret) = self.compile_node(left)?;
                        let (end_vr, end_is_secret) = self.compile_node(right)?;
                        if start_is_secret || end_is_secret {
                            return Err(CompilerError::semantic_error(
                                "Secret values are not supported in for-loop range bounds",
                                iterable.location(),
                            ));
                        }

                        // Allocate loop variable (clear) and initialize with start
                        let loop_vr = self.allocate_virtual_register(false);
                        self.emit(Instruction::MOV(loop_vr.0, start_vr.0));

                        // Insert loop variable into symbol table, saving any previous binding
                        let prev_binding = self.symbol_table.insert(var_name.clone(), loop_vr.0);

                        // Labels
                        let loop_start_label =
                            format!("for_start_{}", self.current_instructions.len());
                        let loop_end_label = format!("for_end_{}", self.current_instructions.len());

                        // Start label
                        self.add_label(loop_start_label.clone());

                        let loop_continue_label =
                            format!("for_continue_{}", self.current_instructions.len());

                        // If i >= end: exit
                        self.emit(Instruction::CMP(loop_vr.0, end_vr.0));
                        self.emit(Instruction::JMPGT(loop_end_label.clone()));
                        self.emit(Instruction::JMPEQ(loop_end_label.clone()));

                        // Body. continue jumps to the increment, break to the end.
                        self.loop_label_stack
                            .push((loop_continue_label.clone(), loop_end_label.clone()));
                        // Track the literal iteration count of `a..b` so that
                        // share-list append tracking and client-IO ordinal
                        // resolution can size loop-built lists correctly.
                        let range_count =
                            match (int_literal_u64(Some(left)), int_literal_u64(Some(right))) {
                                (Some(a), Some(b)) if b > a => Some(b - a),
                                _ => None,
                            };
                        let range_bounded = range_count.is_some();
                        if let Some(count) = range_count {
                            self.active_loop_bounds.push((var_name.clone(), count));
                        }
                        let body_result = self.compile_node(body);
                        if range_bounded {
                            self.active_loop_bounds.pop();
                        }
                        self.loop_label_stack.pop();
                        let (_body_vr, _body_is_secret) = body_result?;

                        // i = i + 1
                        self.add_label(loop_continue_label);
                        let one_vr = self.allocate_virtual_register(false);
                        let one_val = crate::core_types::Value::from(Constant::I64(1));
                        self.identified_constants.push(Constant::I64(1));
                        self.emit(Instruction::LDI(one_vr.0, one_val));
                        self.emit(Instruction::ADD(loop_vr.0, loop_vr.0, one_vr.0));

                        // Keep the upper bound (end_vr) live across the body to avoid clobbering by temps
                        let end_keepalive = self.allocate_virtual_register(false);
                        self.emit(Instruction::MOV(end_keepalive.0, end_vr.0));

                        // Jump back
                        self.emit(Instruction::JMP(loop_start_label));

                        // End label
                        self.add_label(loop_end_label);

                        // Restore/cleanup symbol table mapping
                        match prev_binding {
                            Some(old_idx) => {
                                self.symbol_table.insert(var_name, old_idx);
                            }
                            None => {
                                self.symbol_table.remove(&variables[0]);
                            }
                        }
                    }
                    _ => {
                        // Collection iteration: for item in list
                        // Compile the collection expression
                        let (collection_vr, collection_is_secret) = self.compile_node(iterable)?;

                        // Get the length of the collection: array_length(collection)
                        self.emit(Instruction::PUSHARG(collection_vr.0));
                        self.emit(Instruction::CALL("array_length".to_string()));
                        let len_vr = self.allocate_virtual_register(false);
                        self.emit(Instruction::MOV(len_vr.0, 0)); // Result is in r0

                        // Allocate index variable (internal, starts at 0)
                        let index_vr = self.allocate_virtual_register(false);
                        let zero_vr = self.allocate_virtual_register(false);
                        self.identified_constants.push(Constant::I64(0));
                        self.emit(Instruction::LDI(
                            zero_vr.0,
                            crate::core_types::Value::from(Constant::I64(0)),
                        ));
                        self.emit(Instruction::MOV(index_vr.0, zero_vr.0));

                        // Allocate the loop element variable in the same bank as the iterable.
                        // The current bytecode does not carry element-level secrecy metadata, so
                        // clear collections must stay in clear registers to avoid accidental MPC
                        // execution during ordinary local loops.
                        let elem_vr = self.allocate_virtual_register(collection_is_secret);

                        // Insert loop variable (element) into symbol table
                        let prev_binding = self.symbol_table.insert(var_name.clone(), elem_vr.0);

                        // Labels
                        let loop_start_label =
                            format!("for_start_{}", self.current_instructions.len());
                        let loop_end_label = format!("for_end_{}", self.current_instructions.len());

                        // Start label
                        self.add_label(loop_start_label.clone());

                        // If index >= len: exit
                        self.emit(Instruction::CMP(index_vr.0, len_vr.0));
                        self.emit(Instruction::JMPGT(loop_end_label.clone()));
                        self.emit(Instruction::JMPEQ(loop_end_label.clone()));

                        // Get element: elem = get_field(collection, index)
                        self.emit(Instruction::PUSHARG(collection_vr.0));
                        self.emit(Instruction::PUSHARG(index_vr.0));
                        self.emit(Instruction::CALL("get_field".to_string()));
                        self.emit(Instruction::MOV(elem_vr.0, 0)); // Result is in r0

                        let loop_continue_label =
                            format!("for_continue_{}", self.current_instructions.len());

                        // Body. continue jumps to the increment, break to the end.
                        self.loop_label_stack
                            .push((loop_continue_label.clone(), loop_end_label.clone()));
                        let body_result = self.compile_node(body);
                        self.loop_label_stack.pop();
                        let (_body_vr, _body_is_secret) = body_result?;

                        // index = index + 1
                        self.add_label(loop_continue_label);
                        let one_vr = self.allocate_virtual_register(false);
                        self.identified_constants.push(Constant::I64(1));
                        self.emit(Instruction::LDI(
                            one_vr.0,
                            crate::core_types::Value::from(Constant::I64(1)),
                        ));
                        self.emit(Instruction::ADD(index_vr.0, index_vr.0, one_vr.0));

                        // Keep collection and length alive across the body
                        let collection_keepalive =
                            self.allocate_virtual_register(collection_is_secret);
                        self.emit(Instruction::MOV(collection_keepalive.0, collection_vr.0));
                        let len_keepalive = self.allocate_virtual_register(false);
                        self.emit(Instruction::MOV(len_keepalive.0, len_vr.0));

                        // Jump back
                        self.emit(Instruction::JMP(loop_start_label));

                        // End label
                        self.add_label(loop_end_label);

                        // Restore/cleanup symbol table mapping
                        match prev_binding {
                            Some(old_idx) => {
                                self.symbol_table.insert(var_name, old_idx);
                            }
                            None => {
                                self.symbol_table.remove(&variables[0]);
                            }
                        }
                    }
                }

                // For-loops evaluate to Unit
                // For-loop declarations have lexical scope, while writes to
                // existing outer registers retain their runtime effects.
                self.symbol_table = outer_bindings;
                self.symbol_types = outer_types;
                self.object_field_types = outer_objects;
                let nil_vr = self.allocate_virtual_register(false);
                self.identified_constants.push(Constant::Unit);
                self.emit(Instruction::LDI(nil_vr.0, crate::core_types::Value::Unit));
                Ok((nil_vr, false))
            }
            AstNode::FunctionDefinition {
                name,
                type_params,
                parameters,
                return_type,
                body,
                is_secret: _,
                pragmas,
                location,
                node_id: _,
            } => {
                // --- Check for Pragmas ---
                let mut skip_compilation = false;
                for pragma in pragmas {
                    let pragma_name = match pragma {
                        Pragma::Simple(name, _) => name,
                        Pragma::KeyValue(name, _, _) => name,
                    };

                    if let Some(handler) = self.pragma_handlers.get(pragma_name) {
                        handler(self, node, pragma)?;
                        // Check if the handler indicates compilation should be skipped
                        if pragma_name == "builtin" {
                            // Register the function name as a known built-in.
                            if let Some(name) = name {
                                self.known_builtins.insert(name.clone());
                            }
                            skip_compilation = true;
                        }
                    }
                }
                if skip_compilation {
                    return Ok((VirtualRegister(usize::MAX), false)); // Indicate success, no VR
                }
                // --- Compile the function body ---
                let mut function_generator = CodeGenerator::new();
                function_generator.opt_level = self.opt_level;
                function_generator.object_field_types = self.object_field_types.clone();
                // A variable that is reassigned anywhere in the body (e.g. a
                // `while`-loop counter) is not a constant, so it must not be
                // resolved to its initial value when statically determining
                // client-IO slots/ordinals.
                collect_reassigned_vars(body, &mut function_generator.reassigned_vars);

                // --- Add parameters to the function_generator's symbol table ---
                let mut param_vrs: Vec<VirtualRegister> = Vec::new();
                for param in parameters.iter() {
                    // Determine parameter secrecy from its type annotation
                    let param_type = param
                        .type_annotation
                        .as_ref()
                        .map(|n| SymbolType::from_ast_with_type_params(n, type_params))
                        .unwrap_or(SymbolType::Unknown);
                    let param_is_secret = param_type.uses_secret_register();
                    // Function arguments enter in the clear ABI parameter slots
                    // (R0..Rn-1). The prologue copies them into typed locals below,
                    // which converts clear-to-secret when the source parameter is
                    // secret. Model the incoming ABI slot as clear so precoloring it
                    // to R0..Rn-1 cannot put a secret virtual register in the clear
                    // physical bank.
                    let param_vr = function_generator.allocate_virtual_register(false);
                    let local_vr = function_generator.allocate_virtual_register(param_is_secret);
                    function_generator.emit(Instruction::MOV(local_vr.0, param_vr.0));
                    function_generator
                        .symbol_table
                        .insert(param.name.clone(), local_vr.0); // Store copied local VR index
                    function_generator
                        .symbol_types
                        .insert(param.name.clone(), param_type);
                    if let Some(share_type) = function_generator
                        .symbol_types
                        .get(&param.name)
                        .and_then(share_type_for_secret_scalar_symbol_type)
                    {
                        function_generator
                            .variable_share_types
                            .insert(param.name.clone(), share_type);
                    }
                    param_vrs.push(param_vr);
                }

                // Compile the function body using the new generator.
                let (_body_result_reg, _body_is_secret) = function_generator.compile_node(body)?;
                self.merge_client_io_from(&function_generator);

                // --- Perform Register Allocation ---
                let mut virtual_instructions = function_generator.current_instructions;
                let mut function_labels = function_generator.current_labels;
                let mut secrecy_map = function_generator.vr_secrecy;
                let function_constants = function_generator.identified_constants;
                let mut next_virtual_reg = function_generator.next_virtual_reg;

                // Precolor parameter VRs to ABI registers R0..Rn-1
                let mut precolored: HashMap<VirtualRegister, PhysicalRegister> = HashMap::new();
                for (i, vr) in param_vrs.iter().enumerate() {
                    precolored.insert(*vr, PhysicalRegister(i));
                }

                let diagnostic_name = format!("function '{}'", name.as_deref().unwrap_or("<anon>"));
                if self.opt_level >= 1 {
                    Self::pin_hot_constants(
                        &mut virtual_instructions,
                        &mut function_labels,
                        &mut next_virtual_reg,
                        &mut secrecy_map,
                        &mut precolored,
                        &diagnostic_name,
                    );
                }
                let spill_opt = self.spill_opt_active();
                let allocation = Self::allocate_registers_with_object_spills(
                    &mut virtual_instructions,
                    &mut function_labels,
                    &mut next_virtual_reg,
                    &mut secrecy_map,
                    &precolored,
                    param_vrs.len(),
                    &diagnostic_name,
                    spill_opt,
                )?;

                // Rewrite instructions with physical registers
                let mut final_instructions = register_allocator::rewrite_instructions_dense(
                    &virtual_instructions,
                    &allocation,
                );
                if spill_opt {
                    final_instructions =
                        Self::eliminate_self_movs(final_instructions, &mut function_labels);
                }

                // Finalize the function's bytecode chunk.
                let mut function_chunk = BytecodeChunk::new();
                function_chunk.instructions = final_instructions;
                function_chunk.labels = function_labels;
                function_chunk.constants = dedupe_constants(function_constants);
                function_chunk.parameters =
                    parameters.iter().map(|param| param.name.clone()).collect();
                function_chunk.parameter_types = parameters
                    .iter()
                    .map(|param| {
                        param
                            .type_annotation
                            .as_ref()
                            .map(|n| SymbolType::from_ast_with_type_params(n, type_params))
                            .unwrap_or(SymbolType::Unknown)
                    })
                    .map(symbol_type_to_function_type)
                    .collect();
                function_chunk.return_type = return_type
                    .as_ref()
                    .map(|n| SymbolType::from_ast_with_type_params(n, type_params))
                    .map(symbol_type_to_function_type)
                    .unwrap_or(stoffel_vm_types::compiled_binary::FunctionType::Void);
                function_chunk.upvalues = collect_upvalue_names(body);

                // Store the compiled chunk appropriately.
                if let Some(func_name) = name {
                    if func_name == "main" {
                        // `def main(...)` is the program entry.
                        if self.main_proc_chunk.is_some() {
                            return Err(CompilerError::semantic_error(
                                "Multiple 'main' procedures defined".to_string(),
                                location.clone(),
                            ));
                        }
                        self.main_proc_chunk = Some(function_chunk);
                    } else {
                        // Detect explicit entry: allow pragma "entry" for now; otherwise store as normal function.
                        if self.compiled_functions.contains_key(func_name) {
                            // TODO: Allow overloading later?
                            return Err(CompilerError::semantic_error(
                                format!("Function '{}' already defined", func_name),
                                location.clone(),
                            ));
                        }
                        let is_entry = pragmas
                            .iter()
                            .any(|p| matches!(p, Pragma::Simple(n, _) if n == "entry"));
                        if is_entry {
                            if self.entry_main_chunk.is_some() {
                                return Err(CompilerError::semantic_error(
                                    "Multiple explicit 'main' entries defined".to_string(),
                                    location.clone(),
                                )
                                .with_hint("Only one entry function is allowed"));
                            }
                            self.entry_main_chunk = Some(function_chunk.clone());
                        }
                        self.compiled_functions
                            .insert(func_name.clone(), function_chunk);
                    }
                } else {
                    // TODO: Handle anonymous functions (lambdas)
                    return Err(CompilerError::internal_error(
                        "Anonymous function definition not yet supported".to_string(),
                    ));
                }

                // Function definition itself doesn't produce a value in the outer scope.
                Ok((VirtualRegister(usize::MAX), false)) // Return dummy VR
            }
            AstNode::ObjectDefinition {
                name,
                base_type: _,
                fields,
                is_secret: _,
                location: _,
            } => {
                // Object definitions are type declarations - no bytecode is generated.
                // The type information is registered in semantic analysis.
                // At runtime, objects are created via constructor calls (to be implemented).
                //
                // For now, we just register the object type's field information for later use
                // when compiling object instantiation and field access.
                //
                let field_types = fields
                    .iter()
                    .map(|field| {
                        let mut field_type = SymbolType::from_ast(&field.type_annotation);
                        if field.is_secret && !field_type.is_secret() {
                            field_type = field_type.with_secret_modifier();
                        }
                        (field.name.clone(), field_type)
                    })
                    .collect::<Vec<_>>();
                self.object_field_types.insert(name.clone(), field_types);

                // Object definition doesn't produce a runtime value
                Ok((VirtualRegister(usize::MAX), false))
            }
            AstNode::TypeAlias { .. }
            | AstNode::BuiltinTypeDefinition { .. }
            | AstNode::BuiltinObjectDefinition { .. } => {
                // These declarations are compile-time metadata only.
                Ok((VirtualRegister(usize::MAX), false))
            }
            AstNode::ListLiteral { elements, .. } => {
                // Create array with capacity
                let capacity_const = Constant::I64(elements.len() as i64);
                self.identified_constants.push(capacity_const.clone());
                let cap_vr = self.allocate_virtual_register(false);
                self.emit(Instruction::LDI(
                    cap_vr.0,
                    crate::core_types::Value::from(capacity_const),
                ));
                self.emit(Instruction::PUSHARG(cap_vr.0));
                self.emit(Instruction::CALL("create_array".to_string()));

                let array_vr = self.allocate_virtual_register(false);
                self.emit(Instruction::MOV(array_vr.0, 0)); // Result is in r0

                // Push each element using array_push
                for elem in elements {
                    let (elem_vr, _elem_is_secret) = self.compile_node(elem)?;
                    self.emit(Instruction::PUSHARG(array_vr.0));
                    self.emit(Instruction::PUSHARG(elem_vr.0));
                    self.emit(Instruction::CALL("array_push".to_string()));
                }

                Ok((array_vr, false))
            }
            AstNode::DictLiteral { pairs, .. } => {
                // Create object
                self.emit(Instruction::CALL("create_object".to_string()));

                let obj_vr = self.allocate_virtual_register(false);
                self.emit(Instruction::MOV(obj_vr.0, 0)); // Result is in r0

                // Set each key-value pair using set_field
                for (key, value) in pairs {
                    let (key_vr, _key_is_secret) = self.compile_node(key)?;
                    let (val_vr, _val_is_secret) = self.compile_node(value)?;

                    self.emit(Instruction::PUSHARG(obj_vr.0));
                    self.emit(Instruction::PUSHARG(key_vr.0));
                    self.emit(Instruction::PUSHARG(val_vr.0));
                    self.emit(Instruction::CALL("set_field".to_string()));
                }

                Ok((obj_vr, false))
            }
            AstNode::IndexAccess {
                base,
                index,
                location: _,
            } => {
                let (base_vr, base_is_secret) = self.compile_node(base)?;
                let (index_vr, index_is_secret) = self.compile_node(index)?;

                // Call get_field(base, index)
                self.emit(Instruction::PUSHARG(base_vr.0));
                self.emit(Instruction::PUSHARG(index_vr.0));
                self.emit(Instruction::CALL("get_field".to_string()));

                let result_is_secret = base_is_secret
                    || index_is_secret
                    || self
                        .type_hint_for_node(node)
                        .is_some_and(|ty| ty.uses_secret_register());
                let result_vr = self.allocate_virtual_register(result_is_secret);
                self.emit(Instruction::MOV(result_vr.0, 0)); // Result is in r0

                Ok((result_vr, result_is_secret))
            }
            // Import statements are processed at the multi-file compilation level
            // and don't generate any bytecode themselves
            AstNode::Import { .. } => {
                // Imports are a no-op in codegen - they're handled during semantic analysis
                Ok((VirtualRegister(0), false))
            }
            _ => Err(CompilerError::internal_error(format!(
                "Codegen not implemented for AST node: {:?}",
                node
            ))),
        }
    }

    /// Finalizes the entire compiled program, including the main chunk and all function chunks.
    fn finalize_program(mut self) -> CompilerResult<CompiledProgram> {
        let client_io_manifest = self.client_io_manifest();

        // If both an explicit entry and `def main` exist, error clearly.
        if self.entry_main_chunk.is_some() && self.main_proc_chunk.is_some() {
            return Err(CompilerError::semantic_error(
                "Both explicit 'main' and 'def main' entries are defined".to_string(),
                crate::errors::SourceLocation::default(),
            )
            .with_hint("Use only one entry point; prefer 'def main(...)'"));
        }

        // If explicit entry is set, ensure no top-level code and use it as entry chunk.
        if let Some(entry_chunk) = self.entry_main_chunk.take() {
            if !self.current_instructions.is_empty() {
                return Err(CompilerError::semantic_error(
                    "Cannot mix top-level code with explicit 'main' entry".to_string(),
                    crate::errors::SourceLocation::default(),
                )
                .with_hint("Move top-level code into the entry function declared with 'main'"));
            }
            return Ok(CompiledProgram {
                main_chunk: entry_chunk,
                function_chunks: self.compiled_functions,
                client_io_manifest,
            });
        }
        // `def main(...)` is an entry chunk and cannot be mixed with top-level code.
        if let Some(main_proc) = self.main_proc_chunk.take() {
            if self.current_instructions.is_empty() {
                return Ok(CompiledProgram {
                    main_chunk: main_proc,
                    function_chunks: self.compiled_functions,
                    client_io_manifest,
                });
            } else {
                return Err(CompilerError::semantic_error(
                    "Cannot mix top-level code with 'def main' entry".to_string(),
                    crate::errors::SourceLocation::default(),
                )
                .with_hint("Move top-level code into 'def main(...)'"));
            }
        }

        // If there are no top-level instructions but a 'main' function exists,
        // insert a call to 'main' so the program entry has executable bytecode.
        if self.current_instructions.is_empty() && self.compiled_functions.contains_key("main") {
            self.current_instructions
                .push(Instruction::CALL("main".to_string()));
        }
        // Perform register allocation for the main chunk's instructions
        let mut main_instructions = self.current_instructions; // Instructions generated for the main body
        let mut main_labels = self.current_labels;
        let main_constants = self.identified_constants;
        let mut secrecy_map = self.vr_secrecy;
        let mut next_virtual_reg = self.next_virtual_reg;
        // No precolored mapping for the top-level/main chunk until constant
        // pinning adds its own entries.
        let mut main_precolored: HashMap<VirtualRegister, PhysicalRegister> = HashMap::new();
        // Field access (not `spill_opt_active`): `self` is partially moved here.
        if self.opt_level >= 1 {
            Self::pin_hot_constants(
                &mut main_instructions,
                &mut main_labels,
                &mut next_virtual_reg,
                &mut secrecy_map,
                &mut main_precolored,
                "main program body",
            );
        }
        let spill_opt = self.opt_level >= 1 && spill_opt_enabled();
        let allocation = Self::allocate_registers_with_object_spills(
            &mut main_instructions,
            &mut main_labels,
            &mut next_virtual_reg,
            &mut secrecy_map,
            &main_precolored,
            0,
            "main program body",
            spill_opt,
        )?;

        let mut final_main_instructions =
            register_allocator::rewrite_instructions_dense(&main_instructions, &allocation);
        if spill_opt {
            final_main_instructions =
                Self::eliminate_self_movs(final_main_instructions, &mut main_labels);
        }
        let mut main_chunk = BytecodeChunk::new();
        main_chunk.instructions = final_main_instructions;
        main_chunk.labels = main_labels;
        main_chunk.constants = dedupe_constants(main_constants);

        Ok(CompiledProgram {
            main_chunk,
            function_chunks: self.compiled_functions,
            client_io_manifest,
        })
    }
}

// --- Pragma Handler Implementations ---

/// Handles the `{.builtin.}` pragma.
/// This function is called when the "builtin" pragma is encountered during code generation.
fn handle_builtin_pragma(
    _generator: &mut CodeGenerator, // We need this to register the name
    _func_def_node: &AstNode,       // The FunctionDefinition node
    _pragma: &Pragma,               // The specific pragma node
) -> CompilerResult<()> {
    // The core logic for 'builtin' is simply *not* compiling the body.
    Ok(())
}

fn dedupe_constants(constants: Vec<Constant>) -> Vec<Constant> {
    use std::collections::HashSet;
    // `Constant`'s derived equality/hash are structural, and `Value::from` maps each
    // variant field-preservingly onto a distinct `Value` variant, so deduping on the
    // `Constant` itself keeps exactly the elements the previous `Value`-keyed set
    // kept — without a clone + `Value` conversion per element (only first
    // occurrences are cloned into the set).
    let mut seen: HashSet<Constant> = HashSet::new();
    let mut out = Vec::with_capacity(constants.len());
    for c in constants.into_iter() {
        if !seen.contains(&c) {
            seen.insert(c.clone());
            out.push(c);
        }
    }
    out
}

fn collect_upvalue_names(node: &AstNode) -> Vec<String> {
    fn visit(node: &AstNode, out: &mut Vec<String>) {
        match node {
            AstNode::FunctionCall {
                function,
                arguments,
                ..
            } => {
                if let AstNode::Identifier(name, _) = function.as_ref() {
                    if matches!(name.as_str(), "get_upvalue" | "set_upvalue") {
                        if let Some(AstNode::Literal {
                            value: crate::ast::Value::String(upvalue),
                            ..
                        }) = arguments.first()
                        {
                            if !out.contains(upvalue) {
                                out.push(upvalue.clone());
                            }
                        }
                    }
                }

                visit(function, out);
                for argument in arguments {
                    visit(argument, out);
                }
            }
            AstNode::Block(statements) => {
                for statement in statements {
                    visit(statement, out);
                }
            }
            AstNode::VariableDeclaration {
                value: Some(value), ..
            } => visit(value, out),
            AstNode::VariableDeclaration { value: None, .. } => {}
            AstNode::Assignment { target, value, .. } => {
                visit(target, out);
                visit(value, out);
            }
            AstNode::Return {
                value: Some(value), ..
            } => visit(value, out),
            AstNode::Return { value: None, .. } => {}
            AstNode::DiscardStatement { expression, .. } => visit(expression, out),
            AstNode::IfExpression {
                condition,
                then_branch,
                else_branch,
            } => {
                visit(condition, out);
                visit(then_branch, out);
                if let Some(else_branch) = else_branch {
                    visit(else_branch, out);
                }
            }
            AstNode::WhileLoop {
                condition, body, ..
            } => {
                visit(condition, out);
                visit(body, out);
            }
            AstNode::ForLoop { iterable, body, .. } => {
                visit(iterable, out);
                visit(body, out);
            }
            AstNode::BinaryOperation { left, right, .. } => {
                visit(left, out);
                visit(right, out);
            }
            AstNode::UnaryOperation { operand, .. } => visit(operand, out),
            AstNode::NamedArgument { value, .. } => visit(value, out),
            AstNode::FieldAccess { object, .. } => visit(object, out),
            AstNode::IndexAccess { base, index, .. } => {
                visit(base, out);
                visit(index, out);
            }
            AstNode::ListLiteral { elements, .. }
            | AstNode::TupleLiteral(elements)
            | AstNode::SetLiteral(elements) => {
                for element in elements {
                    visit(element, out);
                }
            }
            AstNode::DictLiteral { pairs, .. } => {
                for (key, value) in pairs {
                    visit(key, out);
                    visit(value, out);
                }
            }
            AstNode::CommandCall {
                command, arguments, ..
            } => {
                visit(command, out);
                for argument in arguments {
                    visit(argument, out);
                }
            }
            AstNode::FunctionDefinition { .. } => {}
            _ => {}
        }
    }

    let mut upvalues = Vec::new();
    visit(node, &mut upvalues);
    upvalues
}

/// Collect the names of all variables that are reassigned (the LHS of an
/// `Assignment`) within `node`, not descending into nested function definitions
/// (which have their own scope and are seeded separately). Used to exclude
/// loop counters and other mutated variables from constant-slot resolution.
fn collect_reassigned_vars(node: &AstNode, out: &mut HashSet<String>) {
    match node {
        AstNode::Assignment { target, value, .. } => {
            if let AstNode::Identifier(name, _) = target.as_ref() {
                out.insert(name.clone());
            }
            collect_reassigned_vars(target, out);
            collect_reassigned_vars(value, out);
        }
        AstNode::Block(statements) => {
            for statement in statements {
                collect_reassigned_vars(statement, out);
            }
        }
        AstNode::VariableDeclaration {
            value: Some(value), ..
        } => collect_reassigned_vars(value, out),
        AstNode::Return {
            value: Some(value), ..
        } => collect_reassigned_vars(value, out),
        AstNode::DiscardStatement { expression, .. } => collect_reassigned_vars(expression, out),
        AstNode::IfExpression {
            condition,
            then_branch,
            else_branch,
        } => {
            collect_reassigned_vars(condition, out);
            collect_reassigned_vars(then_branch, out);
            if let Some(else_branch) = else_branch {
                collect_reassigned_vars(else_branch, out);
            }
        }
        AstNode::WhileLoop {
            condition, body, ..
        } => {
            collect_reassigned_vars(condition, out);
            collect_reassigned_vars(body, out);
        }
        AstNode::ForLoop { iterable, body, .. } => {
            collect_reassigned_vars(iterable, out);
            collect_reassigned_vars(body, out);
        }
        AstNode::BinaryOperation { left, right, .. } => {
            collect_reassigned_vars(left, out);
            collect_reassigned_vars(right, out);
        }
        AstNode::UnaryOperation { operand, .. } => collect_reassigned_vars(operand, out),
        AstNode::NamedArgument { value, .. } => collect_reassigned_vars(value, out),
        AstNode::FieldAccess { object, .. } => collect_reassigned_vars(object, out),
        AstNode::IndexAccess { base, index, .. } => {
            collect_reassigned_vars(base, out);
            collect_reassigned_vars(index, out);
        }
        AstNode::FunctionCall {
            function,
            arguments,
            ..
        } => {
            collect_reassigned_vars(function, out);
            for argument in arguments {
                collect_reassigned_vars(argument, out);
            }
        }
        AstNode::CommandCall {
            command, arguments, ..
        } => {
            collect_reassigned_vars(command, out);
            for argument in arguments {
                collect_reassigned_vars(argument, out);
            }
        }
        AstNode::ListLiteral { elements, .. }
        | AstNode::TupleLiteral(elements)
        | AstNode::SetLiteral(elements) => {
            for element in elements {
                collect_reassigned_vars(element, out);
            }
        }
        AstNode::DictLiteral { pairs, .. } => {
            for (key, value) in pairs {
                collect_reassigned_vars(key, out);
                collect_reassigned_vars(value, out);
            }
        }
        // Do not descend into nested function definitions: their bodies are
        // analyzed against their own reassignment set.
        AstNode::FunctionDefinition { .. } => {}
        _ => {}
    }
}

pub fn generate_bytecode(node: &AstNode) -> CompilerResult<CompiledProgram> {
    generate_bytecode_with_opt_level(node, 0)
}

/// `generate_bytecode` with the effective optimization level (0 when the optimizer
/// is disabled), which gates codegen-side opt-level >= 1 passes such as the spill
/// slot-reload cache and post-RA self-MOV elimination.
pub fn generate_bytecode_with_opt_level(
    node: &AstNode,
    opt_level: u8,
) -> CompilerResult<CompiledProgram> {
    generate_bytecode_with_opt_level_and_backend(node, opt_level, MpcBackend::default())
}

pub fn generate_bytecode_with_opt_level_and_backend(
    node: &AstNode,
    opt_level: u8,
    mpc_backend: MpcBackend,
) -> CompilerResult<CompiledProgram> {
    let mut generator = CodeGenerator::new();
    generator.opt_level = opt_level;
    collect_reassigned_vars(node, &mut generator.reassigned_vars);
    let (_result_vr, _result_is_secret) = generator.compile_node(node)?;
    let mut program = generator.finalize_program()?;
    // Codegen records direct ClientStore calls inside each function. Augment
    // that data by following literal clear-integer arguments through helper
    // calls so client slots and ordinals hidden behind helpers are not omitted.
    crate::client_io_planner::merge_inferred_client_inputs(node, &mut program.client_io_manifest);
    // Compute the program's MPC preprocessing demand interprocedurally over the
    // whole AST (call-multiplicity- and list-length-aware) and stamp it into the
    // client-IO manifest, replacing the placeholder set during finalisation.
    program.client_io_manifest.preprocessing_demand =
        crate::preprocessing_planner::plan_preprocessing_demand_for_backend(node, mpc_backend);
    program.client_io_manifest.mpc_backend = mpc_backend;
    if std::env::var("STOFFEL_DEBUG_DEMAND").is_ok() {
        eprintln!(
            "[stoffel-lang] preprocessing demand: {:?}",
            program.client_io_manifest.preprocessing_demand
        );
    }
    Ok(program)
}

#[cfg(test)]
mod tests {
    use super::{dedupe_constants, CodeGenerator, Constant, SpillLoweringStats};
    use crate::bytecode::Instruction;
    use crate::core_types::Value;
    use crate::register_allocator::{PhysicalRegister, VirtualRegister};
    use std::collections::HashMap;

    fn count_op(instructions: &[Instruction], f: impl Fn(&Instruction) -> bool) -> usize {
        instructions.iter().filter(|i| f(i)).count()
    }

    fn lower(
        instructions: Vec<Instruction>,
        labels: HashMap<String, usize>,
        num_vrs: usize,
        secret_vrs: &[usize],
        spilled: &[usize],
        cache_enabled: bool,
    ) -> (Vec<Instruction>, HashMap<String, usize>) {
        let mut next_virtual_reg = num_vrs;
        let mut secrecy_map = vec![false; num_vrs];
        for &vr in secret_vrs {
            secrecy_map[vr] = true;
        }
        let spilled_vrs: Vec<VirtualRegister> =
            spilled.iter().map(|&v| VirtualRegister(v)).collect();
        let mut next_spill_slot = 0;
        let mut stats = SpillLoweringStats::default();
        CodeGenerator::lower_spills_into_slots(
            instructions,
            labels,
            &mut next_virtual_reg,
            &mut secrecy_map,
            &spilled_vrs,
            &mut next_spill_slot,
            cache_enabled,
            &mut stats,
        )
    }

    /// A def's store scratch is forwarded to later same-block uses of the same
    /// spilled VR, eliding every reload; with the cache off, each use reloads.
    #[test]
    fn slot_cache_forwards_def_to_uses_within_block() {
        let instructions = vec![
            Instruction::LDI(1, Value::I64(5)), // def spilled VR1
            Instruction::MOV(2, 1),             // use VR1
            Instruction::MOV(3, 1),             // use VR1
        ];

        let (out, _) = lower(instructions.clone(), HashMap::new(), 4, &[], &[1], true);
        assert_eq!(count_op(&out, |i| matches!(i, Instruction::LDS(..))), 0);
        assert_eq!(count_op(&out, |i| matches!(i, Instruction::STS(..))), 1);
        // Both uses must read the store scratch that holds VR1's value.
        let Instruction::STS(_, store_scratch) = out[1] else {
            panic!("expected STS after the def, got {out:?}");
        };
        assert!(matches!(out[2], Instruction::MOV(2, s) if s == store_scratch));
        assert!(matches!(out[3], Instruction::MOV(3, s) if s == store_scratch));

        let (out_off, _) = lower(instructions, HashMap::new(), 4, &[], &[1], false);
        assert_eq!(count_op(&out_off, |i| matches!(i, Instruction::LDS(..))), 2);
    }

    /// Label targets and control transfers invalidate the cache, so a use in the
    /// next block reloads from the slot instead of trusting a stale scratch.
    #[test]
    fn slot_cache_cleared_at_labels_and_jumps() {
        let instructions = vec![
            Instruction::LDI(1, Value::I64(5)), // def spilled VR1
            Instruction::MOV(2, 1),             // same-block use: forwarded
            Instruction::MOV(3, 1),             // label target: must reload
            Instruction::JMP("l".to_string()),
            Instruction::MOV(4, 1), // after a jump: must reload
        ];
        let labels: HashMap<String, usize> = [("l".to_string(), 2)].into();

        let (out, lowered_labels) = lower(instructions, labels, 5, &[], &[1], true);
        assert_eq!(count_op(&out, |i| matches!(i, Instruction::LDS(..))), 2);
        // The label must now point at the reload that precedes its instruction:
        // [LDI, STS, MOV, LDS, MOV, JMP, LDS, MOV].
        assert_eq!(lowered_labels["l"], 3);
        assert!(matches!(out[3], Instruction::LDS(..)));
    }

    /// The per-bank LRU holds two slots; a third reload evicts the least recently
    /// used entry, and banks do not evict each other.
    #[test]
    fn slot_cache_lru_eviction_is_per_bank() {
        // VR1..VR3 clear + VR17 secret, all spilled; each def caches its slot.
        let instructions = vec![
            Instruction::LDI(1, Value::I64(1)),
            Instruction::LDI(2, Value::I64(2)),
            Instruction::LDI(17, Value::I64(3)), // secret bank entry
            Instruction::LDI(3, Value::I64(4)),  // evicts VR1 (clear LRU)
            Instruction::MOV(4, 2),              // hit (clear)
            Instruction::MOV(5, 3),              // hit (clear)
            Instruction::MOV(6, 1),              // miss: VR1 was evicted
            Instruction::MOV(18, 17),            // hit (secret survived clear traffic)
        ];

        let (out, _) = lower(
            instructions,
            HashMap::new(),
            19,
            &[17, 18],
            &[1, 2, 3, 17],
            true,
        );
        let reloads: Vec<&Instruction> = out
            .iter()
            .filter(|i| matches!(i, Instruction::LDS(..)))
            .collect();
        assert_eq!(reloads.len(), 1, "only the evicted slot reloads: {out:?}");
        // Slot 0 belongs to VR1 (first spilled VR listed).
        assert!(matches!(reloads[0], Instruction::LDS(_, 0)));
    }

    /// Self-MOV elimination drops `MOV(r, r)` and remaps labels with the
    /// boundary-inclusive table (labels at a deleted MOV or one past the end).
    #[test]
    fn eliminate_self_movs_drops_noops_and_remaps_labels() {
        let instructions = vec![
            Instruction::MOV(1, 1), // deleted
            Instruction::LDI(2, Value::I64(7)),
            Instruction::MOV(3, 3), // deleted
            Instruction::MOV(4, 2),
        ];
        let mut labels: HashMap<String, usize> = [
            ("start".to_string(), 0),
            ("mid".to_string(), 2),
            ("keep".to_string(), 3),
            ("end".to_string(), 4),
        ]
        .into();

        let out = CodeGenerator::eliminate_self_movs(instructions, &mut labels);

        assert_eq!(out.len(), 2, "self-MOVs must be deleted: {out:?}");
        assert!(matches!(out[0], Instruction::LDI(2, _)));
        assert!(matches!(out[1], Instruction::MOV(4, 2)));
        assert_eq!(labels["start"], 0);
        assert_eq!(labels["mid"], 1);
        assert_eq!(labels["keep"], 1);
        assert_eq!(labels["end"], 2);
    }

    /// Runs `pin_hot_constants_with_limits` with test-sized thresholds and
    /// returns the rewritten stream plus the updated labels/precolored map.
    #[allow(clippy::type_complexity)]
    fn pin(
        mut instructions: Vec<Instruction>,
        mut labels: HashMap<String, usize>,
        num_vrs: usize,
        secret_vrs: &[usize],
        precolored_in: &[(usize, usize)],
        min_freq: usize,
        max_pins: usize,
    ) -> (
        Vec<Instruction>,
        HashMap<String, usize>,
        HashMap<VirtualRegister, PhysicalRegister>,
    ) {
        let mut next_virtual_reg = num_vrs;
        let mut secrecy_map = vec![false; num_vrs];
        for &vr in secret_vrs {
            secrecy_map[vr] = true;
        }
        let mut precolored: HashMap<VirtualRegister, PhysicalRegister> = precolored_in
            .iter()
            .map(|&(vr, pr)| (VirtualRegister(vr), PhysicalRegister(pr)))
            .collect();
        CodeGenerator::pin_hot_constants_with_limits(
            &mut instructions,
            &mut labels,
            &mut next_virtual_reg,
            &mut secrecy_map,
            &mut precolored,
            0,
            min_freq,
            max_pins,
            "test",
        );
        (instructions, labels, precolored)
    }

    /// Hot immediates of *different* typed widths pin separately (I64(4) and
    /// U8(4) must never merge), replaced LDIs are deleted with their uses
    /// renamed to the pinned VR, and labels shift through the prologue.
    #[test]
    fn const_pin_pins_typed_constants_separately_and_shifts_labels() {
        let mut instructions = Vec::new();
        for i in 0..32 {
            instructions.push(Instruction::LDI(1 + 2 * i, Value::I64(4)));
            instructions.push(Instruction::PUSHARG(1 + 2 * i));
        }
        for i in 0..32 {
            instructions.push(Instruction::LDI(65 + 2 * i, Value::U8(4)));
            instructions.push(Instruction::PUSHARG(65 + 2 * i));
        }
        instructions.push(Instruction::JMP("top".to_string()));
        let n = instructions.len();
        let labels: HashMap<String, usize> =
            [("top".to_string(), 0), ("end".to_string(), n)].into();

        let (out, labels, precolored) = pin(instructions, labels, 129, &[], &[], 32, 6);

        // Two pins loaded in the prologue; equal frequencies tie-break on the
        // typed key, so I64(4) pins first (R15), then U8(4) (R14).
        let Instruction::LDI(pin_i64, Value::I64(4)) = out[0] else {
            panic!("expected I64(4) prologue load, got {:?}", out[0]);
        };
        let Instruction::LDI(pin_u8, Value::U8(4)) = out[1] else {
            panic!("expected U8(4) prologue load, got {:?}", out[1]);
        };
        assert_ne!(pin_i64, pin_u8, "typed constants must not merge");
        assert_eq!(precolored[&VirtualRegister(pin_i64)], PhysicalRegister(15));
        assert_eq!(precolored[&VirtualRegister(pin_u8)], PhysicalRegister(14));
        // All 64 hot LDIs deleted; every PUSHARG renamed to its pin.
        assert_eq!(out.len(), 2 + 64 + 1);
        assert_eq!(
            count_op(&out, |i| matches!(i, Instruction::LDI(..))),
            2,
            "all hot LDIs must be deleted: {out:?}"
        );
        for inst in &out[2..2 + 32] {
            assert!(matches!(inst, Instruction::PUSHARG(r) if *r == pin_i64));
        }
        for inst in &out[2 + 32..2 + 64] {
            assert!(matches!(inst, Instruction::PUSHARG(r) if *r == pin_u8));
        }
        // Labels shift by the prologue (a label on a deleted LDI lands on the
        // next surviving instruction) and the one-past-the-end label stays valid.
        assert_eq!(labels["top"], 2);
        assert_eq!(labels["end"], out.len());
    }

    /// VR0, precolored VRs, multi-def VRs and secret-bank VRs are never renamed
    /// even when their immediate is pinned, and pin homes skip physical
    /// registers already reserved by the precolored map.
    #[test]
    fn const_pin_guards_vr0_precolored_multi_def_and_secret() {
        let mut instructions = vec![
            Instruction::LDI(0, Value::I64(9)),  // VR0: ABI result register
            Instruction::LDI(1, Value::I64(9)),  // precolored (parameter)
            Instruction::LDI(2, Value::I64(9)),  // multi-def below
            Instruction::MOV(2, 1),              // second def of VR2
            Instruction::LDI(17, Value::I64(9)), // secret-bank VR
        ];
        for i in 0..32 {
            instructions.push(Instruction::LDI(20 + i, Value::I64(9)));
            instructions.push(Instruction::PUSHARG(20 + i));
        }

        // R15 is already taken, so the single pin must land in R14.
        let (out, _, precolored) = pin(instructions, HashMap::new(), 60, &[17], &[(1, 15)], 32, 6);

        let Instruction::LDI(pinned, Value::I64(9)) = out[0] else {
            panic!("expected prologue load, got {:?}", out[0]);
        };
        assert_eq!(precolored[&VirtualRegister(pinned)], PhysicalRegister(14));
        // The four guarded LDIs survive; the 32 hot ones are gone.
        let surviving: Vec<usize> = out
            .iter()
            .filter_map(|i| match i {
                Instruction::LDI(dest, _) if *dest != pinned => Some(*dest),
                _ => None,
            })
            .collect();
        assert_eq!(surviving, vec![0, 1, 2, 17], "guarded LDIs must survive");
        assert!(out
            .iter()
            .all(|i| !matches!(i, Instruction::PUSHARG(r) if *r != pinned)));
    }

    /// An LDI whose previous surviving instruction is a CALL is kept, so a
    /// following `MOV(dest, 0)` never becomes newly CALL-adjacent (the post-CALL
    /// MOV rewrite reads physical R0). A later LDI in the same run is still
    /// deletable once a surviving instruction sits between it and the CALL.
    #[test]
    fn const_pin_keeps_ldi_directly_after_call() {
        let mut instructions = vec![
            Instruction::CALL("f".to_string()),
            Instruction::LDI(1, Value::I64(5)), // kept: CALL-adjacent
            Instruction::MOV(2, 0),             // must stay the post-CALL capture
            Instruction::LDI(3, Value::I64(5)), // deletable
            Instruction::PUSHARG(1),
            Instruction::PUSHARG(3),
        ];
        for i in 0..32 {
            instructions.push(Instruction::LDI(10 + i, Value::I64(5)));
            instructions.push(Instruction::PUSHARG(10 + i));
        }

        let (out, _, _) = pin(instructions, HashMap::new(), 50, &[], &[], 32, 6);

        let Instruction::LDI(pinned, Value::I64(5)) = out[0] else {
            panic!("expected prologue load, got {:?}", out[0]);
        };
        assert!(matches!(out[1], Instruction::CALL(_)));
        assert!(
            matches!(out[2], Instruction::LDI(1, Value::I64(5))),
            "the CALL-adjacent LDI must survive: {:?}",
            &out[..4]
        );
        assert!(matches!(out[3], Instruction::MOV(2, 0)));
        // VR1 keeps its own register (not renamed); VR3 was renamed to the pin.
        assert!(matches!(out[4], Instruction::PUSHARG(1)));
        assert!(matches!(out[5], Instruction::PUSHARG(r) if r == pinned));
    }

    /// When every occurrence of a hot constant is guarded, the pass backs out
    /// entirely: no prologue, no precolored entries, instructions untouched.
    #[test]
    fn const_pin_backs_out_when_nothing_is_deletable() {
        let mut instructions = Vec::new();
        for _ in 0..32 {
            instructions.push(Instruction::LDI(1, Value::I64(7))); // multi-def VR1
        }
        instructions.push(Instruction::PUSHARG(1));
        let before = instructions.clone();

        let (out, _, precolored) = pin(instructions, HashMap::new(), 2, &[], &[], 32, 6);

        assert_eq!(
            format!("{out:?}"),
            format!("{before:?}"),
            "stream must be untouched"
        );
        assert!(precolored.is_empty(), "speculative pins must be dropped");
    }

    #[test]
    fn dedupe_removes_duplicates_and_preserves_order() {
        let input = vec![
            Constant::I64(1),
            Constant::Bool(true),
            Constant::I64(1), // dup
            Constant::String("a".into()),
            Constant::String("a".into()), // dup
            Constant::Unit,
            Constant::Unit,       // dup
            Constant::Bool(true), // dup
            Constant::I64(2),
        ];

        let out = dedupe_constants(input);

        assert_eq!(out.len(), 5, "Expected 5 unique constants");
        assert!(matches!(out[0], Constant::I64(1)));
        assert!(matches!(out[1], Constant::Bool(true)));
        assert!(matches!(out[2], Constant::String(ref s) if s == "a"));
        assert!(matches!(out[3], Constant::Unit));
        assert!(matches!(out[4], Constant::I64(2)));
    }
}
