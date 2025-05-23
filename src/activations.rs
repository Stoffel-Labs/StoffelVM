use rustc_hash::FxHashMap;
use std::fmt;
use smallvec::SmallVec;
use object_pool::{Pool, Reusable};
use crate::core_types::{Upvalue, Value};
use crate::instructions::Instruction;

pub type ActivationRecordRef<'a> = object_pool::Reusable<'a, ActivationRecord>;

use crate::instructions::ResolvedInstruction;

#[derive(Clone)]
pub struct ActivationRecord {
    pub function_name: String,
    pub locals: FxHashMap<String, Value>,
    pub registers: SmallVec<[Value; 16]>,
    pub instructions: SmallVec<[Instruction; 32]>,
    pub upvalues: Vec<Upvalue>,
    pub stack: SmallVec<[Value; 8]>,
    pub compare_flag: i32,
    pub instruction_pointer: usize,
    pub cached_instructions: Option<SmallVec<[Instruction; 32]>>,
    pub resolved_instructions: Option<SmallVec<[ResolvedInstruction; 32]>>,
    pub constant_values: Option<SmallVec<[Value; 16]>>,
    pub closure: Option<Value>, // Store the original closure for upvalue updates
}

impl ActivationRecord {
    // Create a new ActivationRecord with default values for the new fields
    pub fn new(function_name: String, locals: FxHashMap<String, Value>, registers: SmallVec<[Value; 16]>,
               instructions: SmallVec<[Instruction; 32]>, upvalues: Vec<Upvalue>, stack: SmallVec<[Value; 8]>,
               compare_flag: i32, instruction_pointer: usize, cached_instructions: Option<SmallVec<[Instruction; 32]>>) -> Self {
        ActivationRecord {
            function_name,
            locals,
            registers,
            instructions,
            upvalues,
            stack,
            compare_flag,
            instruction_pointer,
            cached_instructions,
            resolved_instructions: None,
            constant_values: None,
            closure: None,
        }
    }

    pub fn reset(&mut self) {
        self.function_name.clear();
        self.locals.clear();
        self.registers.clear();
        self.instructions.clear();
        self.upvalues.clear();
        self.stack.clear();
        self.compare_flag = 0;
        self.instruction_pointer = 0;
        self.cached_instructions = None;
        self.resolved_instructions = None;
        self.constant_values = None;
        self.closure = None;
    }
}

// Add activation record pool
pub struct ActivationRecordPool {
    pool: Pool<ActivationRecord>,
}

impl ActivationRecordPool {
    pub fn new(max_size: usize) -> Self {
        Self { pool: Pool::new(max_size, || ActivationRecord {
            function_name: String::new(),
            locals: FxHashMap::default(),
            registers: SmallVec::new(),
            instructions: SmallVec::new(),
            upvalues: Vec::new(),
            stack: SmallVec::new(),
            compare_flag: 0,
            instruction_pointer: 0,
            cached_instructions: None,
            resolved_instructions: None,
            constant_values: None,
            closure: None,
        }) }
    }

    pub fn get(&self) -> Reusable<ActivationRecord> {
        let mut res = self.pool.try_pull().unwrap();
        res.reset();
        res
    }

    pub fn return_record(&self, record: ActivationRecordRef) {
        drop(record); // Automatically returns to pool
    }
}

impl fmt::Debug for ActivationRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ActivationRecord {{ function: {}, ip: {}, registers: {:?}, locals: {:?}, upvalues: {:?}, stack: {:?}, compare_flag: {} }}",
               self.function_name, self.instruction_pointer, self.registers, self.locals, self.upvalues, self.stack, self.compare_flag)
    }
}
