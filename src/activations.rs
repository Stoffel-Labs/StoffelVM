//! # Activation Records for StoffelVM
//!
//! This module defines the activation record system for the StoffelVM.
//! Activation records represent function call frames and contain all the state
//! needed for function execution, including:
//!
//! - Local variables and registers
//! - Function instructions
//! - Upvalues (captured variables)
//! - Argument stack
//! - Instruction pointer
//!
//! The module also provides an object pool for efficient activation record reuse,
//! which helps reduce memory allocation overhead during function calls.

use rustc_hash::FxHashMap;
use std::fmt;
use smallvec::SmallVec;
use object_pool::{Pool, Reusable};
use crate::core_types::{Upvalue, Value};
use crate::instructions::Instruction;

/// Reference to a pooled activation record
///
/// This type represents a reference to an activation record that will be
/// automatically returned to the pool when dropped.
pub type ActivationRecordRef<'a> = object_pool::Reusable<'a, ActivationRecord>;

use crate::instructions::ResolvedInstruction;

/// Activation record for function calls
///
/// An activation record represents a function call frame and contains all the state
/// needed for function execution. It is created when a function is called and
/// remains active until the function returns.
///
/// The VM maintains a stack of activation records, with the top record representing
/// the currently executing function. When a function calls another function, a new
/// activation record is pushed onto the stack.
#[derive(Clone)]
pub struct ActivationRecord {
    /// Name of the function being executed
    pub function_name: String,
    /// Local variables by name
    pub locals: FxHashMap<String, Value>,
    /// Register values (optimized for small functions)
    pub registers: SmallVec<[Value; 16]>,
    /// Function instructions
    pub instructions: SmallVec<[Instruction; 32]>,
    /// Captured variables from outer scopes
    pub upvalues: Vec<Upvalue>,
    /// Argument stack for function calls
    pub stack: SmallVec<[Value; 8]>,
    /// Comparison flag for conditional jumps
    pub compare_flag: i32,
    /// Current instruction pointer
    pub instruction_pointer: usize,
    /// Cached instructions for faster execution
    pub cached_instructions: Option<SmallVec<[Instruction; 32]>>,
    /// Resolved instructions with numeric indices
    pub resolved_instructions: Option<SmallVec<[ResolvedInstruction; 32]>>,
    /// Constant values extracted from instructions
    pub constant_values: Option<SmallVec<[Value; 16]>>,
    /// Original closure for upvalue updates
    pub closure: Option<Value>,
}

impl ActivationRecord {
    /// Create a new activation record with the specified parameters
    ///
    /// # Arguments
    /// * `function_name` - Name of the function being executed
    /// * `locals` - Local variables by name
    /// * `registers` - Register values
    /// * `instructions` - Function instructions
    /// * `upvalues` - Captured variables from outer scopes
    /// * `stack` - Argument stack for function calls
    /// * `compare_flag` - Comparison flag for conditional jumps
    /// * `instruction_pointer` - Current instruction pointer
    /// * `cached_instructions` - Cached instructions for faster execution
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

    /// Reset the activation record to its initial state
    ///
    /// This method is called when an activation record is returned to the pool,
    /// to prepare it for reuse. It clears all state and resets all values to
    /// their defaults.
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

/// Pool for efficient activation record reuse
///
/// This pool manages a set of activation records that can be reused across
/// function calls, reducing memory allocation overhead. When a function returns,
/// its activation record is returned to the pool for later reuse.
///
/// The pool has a maximum size to prevent unbounded growth, and will create
/// new activation records when needed if the pool is empty.
pub struct ActivationRecordPool {
    /// The underlying object pool
    pool: Pool<ActivationRecord>,
}

impl ActivationRecordPool {
    /// Create a new activation record pool with the specified maximum size
    ///
    /// # Arguments
    /// * `max_size` - Maximum number of activation records to keep in the pool
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

    /// Get an activation record from the pool
    ///
    /// This method retrieves an activation record from the pool, or creates a new
    /// one if the pool is empty. The returned record is automatically reset to
    /// its initial state.
    ///
    /// The returned `Reusable<ActivationRecord>` will automatically return the
    /// activation record to the pool when dropped.
    pub fn get(&self) -> Reusable<ActivationRecord> {
        let mut res = self.pool.try_pull().unwrap();
        res.reset();
        res
    }

    /// Explicitly return an activation record to the pool
    ///
    /// This method is rarely needed, as activation records are automatically
    /// returned to the pool when their `Reusable` wrapper is dropped.
    /// It's provided for cases where explicit control over the return timing
    /// is needed.
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
