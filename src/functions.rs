//! # Function System for StoffelVM
//!
//! This module defines the function types and related functionality for the StoffelVM.
//! The VM supports two primary function types:
//!
//! 1. `VMFunction` - Functions defined in the VM's instruction set
//! 2. `ForeignFunction` - Functions implemented in Rust and exposed to the VM
//!
//! The module also provides the infrastructure for function resolution, closure creation,
//! and the Foreign Function Interface (FFI) system that bridges Rust and the VM.
//!
//! Functions in StoffelVM support:
//! - Parameter passing
//! - Return values
//! - Lexical scoping with upvalues
//! - Nested function definitions
//! - First-class functions and closures

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use crate::instructions::Instruction;
use crate::core_types::Value;
use crate::vm_state::VMState;

use crate::instructions::ResolvedInstruction;
use smallvec::SmallVec;

/// VM function definition
///
/// Represents a function defined in the VM's instruction set. These functions
/// are the primary unit of execution in the VM and can be called directly or
/// wrapped in closures.
///
/// VM functions support:
/// - Named parameters
/// - Upvalue capture for lexical scoping
/// - Nested function definitions
/// - Register-based execution
/// - Label-based control flow
#[derive(Clone)]
pub struct VMFunction {
    /// Cached copy of instructions for faster execution
    pub cached_instructions: Option<Vec<Instruction>>,
    /// Optimized instructions with resolved indices
    pub resolved_instructions: Option<SmallVec<[ResolvedInstruction; 32]>>,
    /// Constant values extracted from instructions
    pub constant_values: Option<SmallVec<[Value; 16]>>,
    /// Function name (used for lookup and debugging)
    pub name: String,
    /// Parameter names (used for binding arguments)
    pub parameters: Vec<String>,
    /// Names of variables captured from outer scopes
    pub upvalues: Vec<String>,
    /// Parent function name (for nested functions)
    pub parent: Option<String>,
    /// Number of registers used by this function
    pub register_count: usize,
    /// List of instructions that make up the function body
    pub instructions: Vec<Instruction>,
    /// Mapping from label names to instruction indices
    pub labels: HashMap<String, usize>,
}

impl VMFunction {
    /// Create a new VM function with the specified parameters
    ///
    /// # Arguments
    /// * `name` - Function name used for lookup and debugging
    /// * `parameters` - List of parameter names
    /// * `upvalues` - List of variable names captured from outer scopes
    /// * `parent` - Optional parent function name (for nested functions)
    /// * `register_count` - Number of registers used by this function
    /// * `instructions` - List of instructions that make up the function body
    /// * `labels` - Mapping from label names to instruction indices
    pub fn new(name: String, parameters: Vec<String>, upvalues: Vec<String>, parent: Option<String>, 
               register_count: usize, instructions: Vec<Instruction>, labels: HashMap<String, usize>) -> Self {
        VMFunction {
            cached_instructions: None,
            resolved_instructions: None,
            constant_values: None,
            name,
            parameters,
            upvalues,
            parent,
            register_count,
            instructions,
            labels,
        }
    }

    /// Cache the function's instructions for faster execution
    ///
    /// This creates a copy of the instructions that can be used during execution
    /// without modifying the original instructions.
    pub fn cache_instructions(&mut self) {
        if self.cached_instructions.is_none() {
            let cached = self.instructions.clone();
            self.cached_instructions = Some(cached);
        }
    }

    /// Resolve symbolic instructions to optimized numeric form
    ///
    /// This process:
    /// 1. Collects all constant values into a separate array
    /// 2. Resolves label references to instruction indices
    /// 3. Converts string-based function calls to index-based calls
    /// 4. Creates an optimized instruction set for faster execution
    ///
    /// The resolved instructions use numeric indices instead of strings,
    /// allowing for faster execution without string lookups.
    pub fn resolve_instructions(&mut self) {
        if self.resolved_instructions.is_some() {
            return; // Already resolved
        }

        let mut resolved = SmallVec::<[ResolvedInstruction; 32]>::new();
        let mut constants = SmallVec::<[Value; 16]>::new();
        let mut const_indices = HashMap::new();

        // Resolve label references to instruction indices
        let mut label_indices = HashMap::new();
        for (label, &idx) in &self.labels {
            label_indices.insert(label.clone(), idx);
        }

        // First pass: collect all constant values and build a mapping from instruction index to constant index
        for (idx, instruction) in self.instructions.iter().enumerate() {
            if let Instruction::LDI(_, value) = instruction {
                let const_idx = constants.len();
                constants.push(value.clone());
                const_indices.insert(idx, const_idx);
            }
        }

        // Second pass: resolve instructions
        for (idx, instruction) in self.instructions.iter().enumerate() {
            match instruction {
                Instruction::LD(reg, offset) => {
                    resolved.push(ResolvedInstruction::LD(*reg, *offset));
                },
                Instruction::LDI(reg, _) => {
                    // Get the constant index from the mapping
                    let const_idx = const_indices.get(&idx).unwrap_or(&0);
                    resolved.push(ResolvedInstruction::LDI(*reg, *const_idx));
                },
                Instruction::MOV(dest, src) => {
                    resolved.push(ResolvedInstruction::MOV(*dest, *src));
                },
                Instruction::ADD(dest, src1, src2) => {
                    resolved.push(ResolvedInstruction::ADD(*dest, *src1, *src2));
                },
                Instruction::SUB(dest, src1, src2) => {
                    resolved.push(ResolvedInstruction::SUB(*dest, *src1, *src2));
                },
                Instruction::MUL(dest, src1, src2) => {
                    resolved.push(ResolvedInstruction::MUL(*dest, *src1, *src2));
                },
                Instruction::DIV(dest, src1, src2) => {
                    resolved.push(ResolvedInstruction::DIV(*dest, *src1, *src2));
                },
                Instruction::MOD(dest, src1, src2) => {
                    resolved.push(ResolvedInstruction::MOD(*dest, *src1, *src2));
                },
                Instruction::AND(dest, src1, src2) => {
                    resolved.push(ResolvedInstruction::AND(*dest, *src1, *src2));
                },
                Instruction::OR(dest, src1, src2) => {
                    resolved.push(ResolvedInstruction::OR(*dest, *src1, *src2));
                },
                Instruction::XOR(dest, src1, src2) => {
                    resolved.push(ResolvedInstruction::XOR(*dest, *src1, *src2));
                },
                Instruction::NOT(dest, src) => {
                    resolved.push(ResolvedInstruction::NOT(*dest, *src));
                },
                Instruction::SHL(dest, src, amount) => {
                    resolved.push(ResolvedInstruction::SHL(*dest, *src, *amount));
                },
                Instruction::SHR(dest, src, amount) => {
                    resolved.push(ResolvedInstruction::SHR(*dest, *src, *amount));
                },
                Instruction::JMP(label) => {
                    let target = *label_indices.get(label).unwrap_or(&0);
                    resolved.push(ResolvedInstruction::JMP(target));
                },
                Instruction::JMPEQ(label) => {
                    let target = *label_indices.get(label).unwrap_or(&0);
                    resolved.push(ResolvedInstruction::JMPEQ(target));
                },
                Instruction::JMPNEQ(label) => {
                    let target = *label_indices.get(label).unwrap_or(&0);
                    resolved.push(ResolvedInstruction::JMPNEQ(target));
                },
                Instruction::JMPLT(label) => {
                    let target = *label_indices.get(label).unwrap_or(&0);
                    resolved.push(ResolvedInstruction::JMPLT(target));
                },
                Instruction::JMPGT(label) => {
                    let target = *label_indices.get(label).unwrap_or(&0);
                    resolved.push(ResolvedInstruction::JMPGT(target));
                },
                Instruction::CALL(func_name) => {
                    // Store the function name as a constant and use its index
                    let const_idx = constants.len();
                    constants.push(Value::String(func_name.clone()));
                    resolved.push(ResolvedInstruction::CALL(const_idx));
                },
                Instruction::RET(reg) => {
                    resolved.push(ResolvedInstruction::RET(*reg));
                },
                Instruction::PUSHARG(reg) => {
                    resolved.push(ResolvedInstruction::PUSHARG(*reg));
                },
                Instruction::CMP(reg1, reg2) => {
                    resolved.push(ResolvedInstruction::CMP(*reg1, *reg2));
                },
            }
        }

        self.resolved_instructions = Some(resolved);
        self.constant_values = Some(constants);
    }
}

// Implement Hash manually to avoid issues with HashMap
impl Hash for VMFunction {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.parameters.hash(state);
        self.upvalues.hash(state);
        self.parent.hash(state);
        self.register_count.hash(state);
        self.instructions.hash(state);
        // Skip hashing labels
    }
}

/// Foreign (native) function type
///
/// This type represents a Rust function that can be called from the VM.
/// It takes a context containing arguments and VM state, and returns
/// either a value or an error string.
pub type ForeignFunctionPtr = Arc<dyn Fn(ForeignFunctionContext) -> Result<Value, String> + Send + Sync>;

/// Context passed to foreign functions
///
/// This structure provides foreign functions with:
/// 1. Access to their arguments
/// 2. Access to the VM state for interacting with the VM
///
/// Foreign functions can use this context to read arguments, manipulate
/// VM state, and interact with objects and arrays in the VM.
pub struct ForeignFunctionContext<'a> {
    /// Arguments passed to the function
    pub args: &'a [Value],
    /// Reference to the VM state for interaction
    pub vm_state: &'a mut VMState,
}

/// Foreign function wrapper
///
/// This structure wraps a Rust function to make it callable from the VM.
/// It associates a name with the function for lookup in the VM's function registry.
///
/// Foreign functions are a key part of the VM's FFI system, allowing the VM
/// to call into Rust code for functionality that would be difficult or inefficient
/// to implement in the VM's instruction set.
pub struct ForeignFunction {
    /// Name of the function (used for lookup)
    pub name: String,
    /// The actual Rust function implementation
    pub func: ForeignFunctionPtr,
}

impl PartialEq for ForeignFunction {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for ForeignFunction {}

impl Hash for ForeignFunction {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
    }
}

impl Clone for ForeignFunction {
    fn clone(&self) -> Self {
        ForeignFunction {
            name: self.name.clone(),
            func: Arc::clone(&self.func)
        }
    }
}

/// Function definition - can be either VM or foreign
///
/// This enum represents the two types of functions supported by the VM:
/// 1. VM functions defined in the VM's instruction set
/// 2. Foreign functions implemented in Rust
///
/// The VM treats both types uniformly when calling them, but their
/// implementations and execution models differ significantly.
#[derive(Clone, Hash)]
pub enum Function {
    /// A function defined in the VM's instruction set
    VM(VMFunction),
    /// A function implemented in Rust and exposed to the VM
    Foreign(ForeignFunction),
}
