//! # VM State Management for StoffelVM
//!
//! This module defines the runtime state of the StoffelVM and provides the core
//! execution engine. It manages:
//!
//! - Function registry and lookup
//! - Activation record stack for function calls
//! - Object and array storage
//! - Foreign object management
//! - Instruction execution
//! - Hook system for debugging and instrumentation
//!
//! The VM state is the central component that orchestrates all aspects of
//! program execution, from function calls to object manipulation.

use crate::activations::{ActivationRecord, ActivationRecordPool};
use crate::core_types::{Closure, ForeignObjectStorage, ObjectStore, Upvalue, Value};
use crate::functions::{ForeignFunctionContext, Function};
use crate::instructions::{Instruction, ResolvedInstruction};
use crate::runtime_hooks::{HookContext, HookEvent, HookManager};
use rustc_hash::FxHashMap;
use smallvec::{smallvec, SmallVec};
use std::sync::Arc;

/// Runtime state of the virtual machine
///
/// This structure maintains the complete state of the VM during execution,
/// including the function registry, activation record stack, object storage,
/// and hook system for debugging.
///
/// The VM state is the central component that orchestrates all aspects of
/// program execution, from function calls to object manipulation.
pub struct VMState {
    /// Registry of all functions (both VM and foreign)
    pub functions: FxHashMap<String, Function>,
    /// Stack of activation records for function calls
    pub activation_records: SmallVec<[ActivationRecord; 8]>,
    /// Current instruction being executed
    pub current_instruction: usize,
    /// Cache for instructions during execution
    pub instruction_cache: SmallVec<[Instruction; 32]>,
    /// Pool for efficient activation record reuse
    pub activation_pool: ActivationRecordPool,
    /// Storage for objects and arrays
    pub object_store: ObjectStore,
    /// Storage for foreign (Rust) objects
    pub foreign_objects: ForeignObjectStorage,
    /// Hook manager for debugging and instrumentation
    pub hook_manager: HookManager,
}

impl Default for VMState {
    fn default() -> Self {
        Self::new()
    }
}

impl VMState {
    /// Create a new VM state with default values
    ///
    /// This initializes all components of the VM state:
    /// - Empty function registry
    /// - Empty activation record stack
    /// - Activation record pool with capacity for 1024 records
    /// - Empty object and array storage
    /// - Empty foreign object storage
    /// - Default hook manager
    pub fn new() -> Self {
        VMState {
            functions: FxHashMap::default(),
            activation_records: smallvec![],
            current_instruction: 0,
            instruction_cache: SmallVec::with_capacity(32),
            activation_pool: ActivationRecordPool::new(1024),
            object_store: ObjectStore::new(),
            foreign_objects: ForeignObjectStorage::new(),
            hook_manager: HookManager::new(),
        }
    }

    /// Get the number of activation records on the stack
    ///
    /// This is a helper method to safely get the length of the activation record stack.
    /// It's used to determine the current call depth and for stack traversal.
    pub fn activation_records_len(&self) -> usize {
        self.activation_records.len()
    }

    /// Get a mutable reference to the current (top) activation record
    ///
    /// This method returns a reference to the activation record at the top of the stack,
    /// which represents the currently executing function.
    ///
    /// # Panics
    /// Panics if the activation record stack is empty.
    pub fn current_activation_record(&mut self) -> &mut ActivationRecord {
        self.activation_records.last_mut().unwrap()
    }

    /// Find an upvalue (captured variable) by name in the activation record stack
    ///
    /// This method searches for a variable with the given name in the current
    /// lexical scope, which includes:
    /// 1. Local variables in the current activation record
    /// 2. Upvalues (captured variables) in the current activation record
    /// 3. Local variables and upvalues in parent activation records
    ///
    /// The search proceeds from the top of the stack (most recent call) to the
    /// bottom (oldest call), implementing lexical scoping rules.
    ///
    /// # Arguments
    /// * `name` - The name of the variable to find
    ///
    /// # Returns
    /// * `Some(Value)` - The value of the variable if found
    /// * `None` - If no variable with the given name is found
    pub fn find_upvalue(&self, name: &str) -> Option<Value> {
        for i in (0..self.activation_records_len()).rev() {
            let record = &self.activation_records[i];
            // First check local variables in this activation record
            if let Some(value) = record.locals.get(name) {
                return Some(value.clone());
            }

            // Then check upvalues (captured variables) in this activation record
            for upvalue in &record.upvalues {
                if upvalue.name == name {
                    return Some(upvalue.value.clone());
                }
            }
        }
        None
    }

    /// Trigger a register read hook event
    ///
    /// This method is called when a register is read during instruction execution.
    /// It creates a RegisterRead event and passes it to the hook manager for processing.
    ///
    /// # Arguments
    /// * `reg` - The register index being read
    /// * `value` - The value being read from the register
    ///
    /// # Returns
    /// * `Ok(())` - If all hooks executed successfully
    /// * `Err(String)` - If any hook returned an error
    pub fn trigger_register_read(&self, reg: usize, value: &Value) -> Result<(), String> {
        let event = HookEvent::RegisterRead(reg, value.clone());
        self.hook_manager.trigger(&event, self)
    }

    /// Trigger a register write hook event
    ///
    /// This method is called when a register is written during instruction execution.
    /// It creates a RegisterWrite event and passes it to the hook manager for processing.
    ///
    /// # Arguments
    /// * `reg` - The register index being written
    /// * `old_value` - The previous value in the register
    /// * `new_value` - The new value being written to the register
    ///
    /// # Returns
    /// * `Ok(())` - If all hooks executed successfully
    /// * `Err(String)` - If any hook returned an error
    pub fn trigger_register_write(
        &self,
        reg: usize,
        old_value: &Value,
        new_value: &Value,
    ) -> Result<(), String> {
        let event = HookEvent::RegisterWrite(reg, old_value.clone(), new_value.clone());
        self.hook_manager.trigger(&event, self)
    }

    /// Trigger a hook event with a snapshot of the current VM state
    ///
    /// This helper method creates a snapshot of the current VM state and passes it
    /// to the hook manager along with the event. This allows hooks to inspect the
    /// VM state without requiring a mutable borrow of the activation records.
    ///
    /// # Arguments
    /// * `event` - The hook event to trigger
    ///
    /// # Returns
    /// * `Ok(())` - If all hooks executed successfully
    /// * `Err(String)` - If any hook returned an error
    pub fn trigger_hook_with_snapshot(&self, event: &HookEvent) -> Result<(), String> {
        let context = HookContext::new(
            &self.activation_records,
            self.current_instruction,
            &self.functions,
        );
        self.hook_manager.trigger_with_context(event, &context)
    }

    /// Create a closure from a function and captured variables
    ///
    /// A closure combines a function with variables captured from its lexical environment.
    /// This method:
    /// 1. Finds the values of the specified upvalue names in the current scope
    /// 2. Creates a new closure with those upvalues
    /// 3. Triggers a ClosureCreated hook event
    /// 4. Returns the closure as a Value
    ///
    /// # Arguments
    /// * `function_name` - The name of the function to wrap in a closure
    /// * `upvalue_names` - The names of variables to capture from the current scope
    ///
    /// # Returns
    /// * `Ok(Value::Closure)` - The created closure
    /// * `Err(String)` - If an upvalue couldn't be found or a hook returned an error
    pub fn create_closure(
        &mut self,
        function_name: &str,
        upvalue_names: &[String],
    ) -> Result<Value, String> {
        // Find and collect all upvalues from the current scope
        let mut upvalues = Vec::new();
        for name in upvalue_names {
            let value = self
                .find_upvalue(name)
                .ok_or_else(|| format!("Could not find upvalue {} when creating closure", name))?;

            upvalues.push(Upvalue {
                name: name.clone(),
                value,
            });
        }

        // Create the closure with the function and captured upvalues
        let closure = Closure {
            function_id: function_name.to_string(),
            upvalues: upvalues.clone(),
        };

        // Trigger a hook event for debugging/instrumentation
        let event = HookEvent::ClosureCreated(function_name.to_string(), upvalues);
        self.hook_manager.trigger(&event, self)?;

        // Return the closure wrapped in a Value
        Ok(Value::Closure(Arc::new(closure)))
    }

    pub fn execute_until_return(&mut self) -> Result<Value, String> {
        // let mut temp_buffer = SmallVec::<[Value; 8]>::new();

        // Store the activation records length before we enter the loop
        let activation_records_len = self.activation_records_len();

        // Create a loop that doesn't hold a mutable borrow across iterations
        loop {
            // Check if we have any activation records
            if self.activation_records.is_empty() {
                return Err("Unexpected end of execution".to_string());
            }

            // Get the current record's function name and instruction pointer
            let function_name;
            let ip;
            let use_resolved;
            {
                let current_record = self.activation_records.last().unwrap();
                function_name = current_record.function_name.clone();
                ip = current_record.instruction_pointer;
                use_resolved = current_record.resolved_instructions.is_some();
            }

            // Prepare the instruction cache
            self.instruction_cache.clear();
            let cached_instructions = {
                let current_record = self.activation_records.last().unwrap();
                current_record.cached_instructions.clone()
            };

            if let Some(cached) = cached_instructions {
                self.instruction_cache = cached;
            } else {
                let instructions = {
                    let current_record = self.activation_records.last().unwrap();
                    current_record.instructions.clone()
                };
                self.instruction_cache.extend(instructions);

                // Update the cached instructions
                {
                    let current_record = self.activation_records.last_mut().unwrap();
                    current_record.cached_instructions = Some(self.instruction_cache.clone());
                }
            }

            let vm_function = match self.functions.get(&function_name) {
                Some(Function::VM(vm_func)) => vm_func.clone(),
                Some(Function::Foreign(_)) => {
                    return Err(format!("Cannot execute foreign function {}", function_name));
                }
                None => return Err(format!("Function {} not found", function_name)),
            };

            // Check if we're at the end of the function
            let is_end_of_function = if use_resolved {
                let resolved_len = {
                    let current_record = self.activation_records.last().unwrap();
                    current_record.resolved_instructions.as_ref().unwrap().len()
                };
                ip >= resolved_len
            } else {
                ip >= vm_function.instructions.len()
            };

            if is_end_of_function {
                if activation_records_len == 1 {
                    return Ok(self.activation_records[0].registers[0].clone());
                } else {
                    let result = self.activation_records.last().unwrap().registers[0].clone();
                    self.activation_records.pop();
                    if self.activation_records.is_empty() {
                        return Ok(result);
                    }
                    continue;
                }
            }

            // Get the instruction to execute
            let instruction = if use_resolved {
                // We'll still need the original instruction for hooks and debugging
                let resolved_idx = {
                    let current_record = self.activation_records.last().unwrap();
                    current_record.resolved_instructions.as_ref().unwrap()[ip]
                };

                // Convert resolved instruction back to regular instruction for hooks
                // This is necessary for compatibility with the hook system
                match resolved_idx {
                    ResolvedInstruction::LD(reg, offset) => Instruction::LD(reg, offset),
                    ResolvedInstruction::LDI(reg, const_idx) => {
                        // Get the constant value from the constant pool using the stored constant index
                        let constant_value = {
                            let current_record = self.activation_records.last().unwrap();
                            if let Some(constants) = &current_record.constant_values {
                                if const_idx < constants.len() {
                                    constants[const_idx].clone()
                                } else {
                                    // Error: constant not found
                                    return Err(format!(
                                        "Constant index {} out of bounds",
                                        const_idx
                                    ));
                                }
                            } else {
                                // Error: constants not available
                                return Err(format!("Constant values not available for function"));
                            }
                        };
                        Instruction::LDI(reg, constant_value)
                    }
                    ResolvedInstruction::MOV(dest, src) => Instruction::MOV(dest, src),
                    ResolvedInstruction::ADD(dest, src1, src2) => {
                        Instruction::ADD(dest, src1, src2)
                    }
                    ResolvedInstruction::SUB(dest, src1, src2) => {
                        Instruction::SUB(dest, src1, src2)
                    }
                    ResolvedInstruction::MUL(dest, src1, src2) => {
                        Instruction::MUL(dest, src1, src2)
                    }
                    ResolvedInstruction::DIV(dest, src1, src2) => {
                        Instruction::DIV(dest, src1, src2)
                    }
                    ResolvedInstruction::MOD(dest, src1, src2) => {
                        Instruction::MOD(dest, src1, src2)
                    }
                    ResolvedInstruction::AND(dest, src1, src2) => {
                        Instruction::AND(dest, src1, src2)
                    }
                    ResolvedInstruction::OR(dest, src1, src2) => Instruction::OR(dest, src1, src2),
                    ResolvedInstruction::XOR(dest, src1, src2) => {
                        Instruction::XOR(dest, src1, src2)
                    }
                    ResolvedInstruction::NOT(dest, src) => Instruction::NOT(dest, src),
                    ResolvedInstruction::SHL(dest, src, amount) => {
                        Instruction::SHL(dest, src, amount)
                    }
                    ResolvedInstruction::SHR(dest, src, amount) => {
                        Instruction::SHR(dest, src, amount)
                    }
                    ResolvedInstruction::JMP(target) => {
                        // Convert numeric target back to label for compatibility
                        // This is inefficient but necessary for hooks
                        let label = format!("label_{}", target);
                        Instruction::JMP(label)
                    }
                    ResolvedInstruction::JMPEQ(target) => {
                        let label = format!("label_{}", target);
                        Instruction::JMPEQ(label)
                    }
                    ResolvedInstruction::JMPNEQ(target) => {
                        let label = format!("label_{}", target);
                        Instruction::JMPNEQ(label)
                    }
                    ResolvedInstruction::JMPLT(target) => {
                        let label = format!("label_{}", target);
                        Instruction::JMPLT(label)
                    }
                    ResolvedInstruction::JMPGT(target) => {
                        let label = format!("label_{}", target);
                        Instruction::JMPGT(label)
                    }
                    ResolvedInstruction::CALL(func_idx) => {
                        // Get the function name from the constant pool
                        let function_name = {
                            let current_record = self.activation_records.last().unwrap();
                            if let Some(constants) = &current_record.constant_values {
                                if func_idx < constants.len() {
                                    match &constants[func_idx] {
                                        Value::String(name) => name.clone(),
                                        _ => return Err(format!("Expected string constant for function name at index {}", func_idx))
                                    }
                                } else {
                                    return Err(format!(
                                        "Function name constant index {} out of bounds",
                                        func_idx
                                    ));
                                }
                            } else {
                                return Err(format!("Constant values not available for function"));
                            }
                        };
                        Instruction::CALL(function_name)
                    }
                    ResolvedInstruction::RET(reg) => Instruction::RET(reg),
                    ResolvedInstruction::PUSHARG(reg) => Instruction::PUSHARG(reg),
                    ResolvedInstruction::CMP(reg1, reg2) => Instruction::CMP(reg1, reg2),
                }
            } else {
                if self.instruction_cache.is_empty() {
                    // If instruction cache is empty, get instructions from the function
                    let instructions = vm_function.instructions.clone();
                    self.instruction_cache.extend(instructions);

                    // Update the cached instructions in the current record
                    let current_record = self.activation_records.last_mut().unwrap();
                    current_record.cached_instructions = Some(self.instruction_cache.clone());
                }
                self.instruction_cache[ip].clone()
            };

            self.current_instruction = ip;

            // Update the instruction pointer
            {
                let current_record = self.activation_records.last_mut().unwrap();
                current_record.instruction_pointer += 1;
            }

            // Only create hook events if hooks are registered
            if !self.hook_manager.hooks.is_empty() {
                let event = HookEvent::BeforeInstructionExecute(instruction.clone());
                self.trigger_hook_with_snapshot(&event)?;
            }

            // Clone the instruction before matching to avoid reference issues
            let instruction_clone = instruction.clone();
            match instruction_clone {
                Instruction::LD(dest_reg, offset) => {
                    // Get stack length and check bounds
                    let stack_len;
                    {
                        let current_record = self.activation_records.last().unwrap();
                        stack_len = current_record.stack.len();
                    }

                    let idx = (stack_len as i32) + offset - 1;
                    if idx < 0 || idx >= stack_len as i32 {
                        return Err(format!("Stack address [sp+{}] out of bounds", offset));
                    }

                    // Get value from stack
                    let value;
                    {
                        let current_record = self.activation_records.last().unwrap();
                        value = current_record.stack[idx as usize].clone();
                    }

                    // Update register
                    let old_value;
                    {
                        let current_record = self.activation_records.last_mut().unwrap();
                        old_value = current_record.registers[dest_reg].clone();
                        current_record.registers[dest_reg] = value.clone();
                    }

                    // Only create hook events if hooks are registered
                    if !self.hook_manager.hooks.is_empty() {
                        let event = HookEvent::RegisterWrite(dest_reg, old_value, value);
                        self.trigger_hook_with_snapshot(&event)?;
                    }
                }
                Instruction::LDI(dest_reg, value) => {
                    // Update register
                    let old_value;
                    {
                        let current_record = self.activation_records.last_mut().unwrap();
                        old_value = current_record.registers[dest_reg].clone();
                        current_record.registers[dest_reg] = value.clone();
                    }

                    let event = HookEvent::RegisterWrite(dest_reg, old_value, value);
                    self.trigger_hook_with_snapshot(&event)?;
                }
                Instruction::MOV(dest_reg, src_reg) => {
                    // Get value from source register
                    let value;
                    let old_value;
                    {
                        let current_record = self.activation_records.last().unwrap();
                        value = current_record.registers[src_reg].clone();
                    }

                    // Update destination register
                    {
                        let current_record = self.activation_records.last_mut().unwrap();
                        old_value = current_record.registers[dest_reg].clone();
                        current_record.registers[dest_reg] = value.clone();
                    }

                    let read_event = HookEvent::RegisterRead(src_reg, value.clone());
                    self.trigger_hook_with_snapshot(&read_event)?;

                    let write_event = HookEvent::RegisterWrite(dest_reg, old_value, value);
                    self.trigger_hook_with_snapshot(&write_event)?;
                }
                Instruction::ADD(dest_reg, src1_reg, src2_reg) => {
                    let record = self.activation_records.last_mut().unwrap();
                    let src1 = &record.registers[src1_reg];
                    let src2 = &record.registers[src2_reg];

                    match (src1, src2) {
                        (Value::Int(a), Value::Int(b)) => {
                            let result_value = Value::Int(a + b);
                            let old_value = record.registers[dest_reg].clone();
                            record.registers[dest_reg] = result_value.clone();

                            let event = HookEvent::RegisterWrite(dest_reg, old_value, result_value);
                            self.hook_manager.trigger(&event, self)?;
                        }
                        _ => return Err("Type error in ADD operation".to_string()),
                    }
                }
                Instruction::SUB(dest_reg, src1_reg, src2_reg) => {
                    let record = self.activation_records.last_mut().unwrap();
                    let src1 = &record.registers[src1_reg];
                    let src2 = &record.registers[src2_reg];

                    match (src1, src2) {
                        (Value::Int(a), Value::Int(b)) => {
                            let result_value = Value::Int(a - b);
                            let old_value = record.registers[dest_reg].clone();
                            record.registers[dest_reg] = result_value.clone();

                            let event = HookEvent::RegisterWrite(dest_reg, old_value, result_value);
                            self.hook_manager.trigger(&event, self)?;
                        }
                        _ => return Err("Type error in SUB operation".to_string()),
                    }
                }
                Instruction::MUL(dest_reg, src1_reg, src2_reg) => {
                    let record = self.activation_records.last_mut().unwrap();
                    let src1 = &record.registers[src1_reg];
                    let src2 = &record.registers[src2_reg];

                    match (src1, src2) {
                        (Value::Int(a), Value::Int(b)) => {
                            let result_value = Value::Int(a * b);
                            let old_value = record.registers[dest_reg].clone();
                            record.registers[dest_reg] = result_value.clone();

                            let event = HookEvent::RegisterWrite(dest_reg, old_value, result_value);
                            self.hook_manager.trigger(&event, self)?;
                        }
                        _ => return Err("Type error in MUL operation".to_string()),
                    }
                }
                Instruction::DIV(dest_reg, src1_reg, src2_reg) => {
                    let record = self.activation_records.last_mut().unwrap();
                    let src1 = &record.registers[src1_reg];
                    let src2 = &record.registers[src2_reg];

                    match (src1, src2) {
                        (Value::Int(a), Value::Int(b)) => {
                            if *b == 0 {
                                return Err("Division by zero".to_string());
                            }
                            let result_value = Value::Int(a / b);
                            let old_value = record.registers[dest_reg].clone();
                            record.registers[dest_reg] = result_value.clone();

                            let event = HookEvent::RegisterWrite(dest_reg, old_value, result_value);
                            self.hook_manager.trigger(&event, self)?;
                        }
                        _ => return Err("Type error in DIV operation".to_string()),
                    }
                }
                Instruction::MOD(dest_reg, src1_reg, src2_reg) => {
                    let record = self.activation_records.last_mut().unwrap();
                    let src1 = &record.registers[src1_reg];
                    let src2 = &record.registers[src2_reg];

                    match (src1, src2) {
                        (Value::Int(a), Value::Int(b)) => {
                            if *b == 0 {
                                return Err("Modulo by zero".to_string());
                            }
                            let result_value = Value::Int(a % b);
                            let old_value = record.registers[dest_reg].clone();
                            record.registers[dest_reg] = result_value.clone();

                            let event = HookEvent::RegisterWrite(dest_reg, old_value, result_value);
                            self.hook_manager.trigger(&event, self)?;
                        }
                        _ => return Err("Type error in MOD operation".to_string()),
                    }
                }
                Instruction::AND(dest_reg, src1_reg, src2_reg) => {
                    let record = self.activation_records.last_mut().unwrap();
                    let src1 = &record.registers[src1_reg];
                    let src2 = &record.registers[src2_reg];

                    let result_value = match (src1, src2) {
                        (Value::Int(a), Value::Int(b)) => Value::Int(a & b),
                        (Value::Bool(a), Value::Bool(b)) => Value::Bool(*a && *b),
                        _ => return Err("Type error in AND operation".to_string()),
                    };

                    let old_value = record.registers[dest_reg].clone();
                    record.registers[dest_reg] = result_value.clone();

                    let event = HookEvent::RegisterWrite(dest_reg, old_value, result_value);
                    self.hook_manager.trigger(&event, self)?;
                }
                Instruction::OR(dest_reg, src1_reg, src2_reg) => {
                    let record = self.activation_records.last_mut().unwrap();
                    let src1 = &record.registers[src1_reg];
                    let src2 = &record.registers[src2_reg];

                    let result_value = match (src1, src2) {
                        (Value::Int(a), Value::Int(b)) => Value::Int(a | b),
                        (Value::Bool(a), Value::Bool(b)) => Value::Bool(*a || *b),
                        _ => return Err("Type error in OR operation".to_string()),
                    };

                    let old_value = record.registers[dest_reg].clone();
                    record.registers[dest_reg] = result_value.clone();

                    let event = HookEvent::RegisterWrite(dest_reg, old_value, result_value);
                    self.hook_manager.trigger(&event, self)?;
                }
                Instruction::XOR(dest_reg, src1_reg, src2_reg) => {
                    let record = self.activation_records.last_mut().unwrap();
                    let src1 = &record.registers[src1_reg];
                    let src2 = &record.registers[src2_reg];

                    let result_value = match (src1, src2) {
                        (Value::Int(a), Value::Int(b)) => Value::Int(a ^ b),
                        (Value::Bool(a), Value::Bool(b)) => Value::Bool(a ^ b),
                        _ => return Err("Type error in XOR operation".to_string()),
                    };

                    let old_value = record.registers[dest_reg].clone();
                    record.registers[dest_reg] = result_value.clone();

                    let event = HookEvent::RegisterWrite(dest_reg, old_value, result_value);
                    self.hook_manager.trigger(&event, self)?;
                }
                Instruction::NOT(dest_reg, src_reg) => {
                    let record = self.activation_records.last_mut().unwrap();
                    let src = &record.registers[src_reg];

                    let result_value = match src {
                        Value::Int(a) => Value::Int(!a),
                        Value::Bool(a) => Value::Bool(!a),
                        _ => return Err("Type error in NOT operation".to_string()),
                    };

                    let old_value = record.registers[dest_reg].clone();
                    record.registers[dest_reg] = result_value.clone();

                    let event = HookEvent::RegisterWrite(dest_reg, old_value, result_value);
                    self.hook_manager.trigger(&event, self)?;
                }
                Instruction::SHL(dest_reg, src_reg, amount_reg) => {
                    let record = self.activation_records.last_mut().unwrap();
                    let src = &record.registers[src_reg];
                    let amount = &record.registers[amount_reg];

                    match (src, amount) {
                        (Value::Int(a), Value::Int(b)) => {
                            let result_value = Value::Int(a << b);
                            let old_value = record.registers[dest_reg].clone();
                            record.registers[dest_reg] = result_value.clone();

                            let event = HookEvent::RegisterWrite(dest_reg, old_value, result_value);
                            self.hook_manager.trigger(&event, self)?;
                        }
                        _ => return Err("Type error in SHL operation".to_string()),
                    }
                }
                Instruction::SHR(dest_reg, src_reg, amount_reg) => {
                    let record = self.activation_records.last_mut().unwrap();
                    let src = &record.registers[src_reg];
                    let amount = &record.registers[amount_reg];

                    match (src, amount) {
                        (Value::Int(a), Value::Int(b)) => {
                            let result_value = Value::Int(a >> b);
                            let old_value = record.registers[dest_reg].clone();
                            record.registers[dest_reg] = result_value.clone();

                            let event = HookEvent::RegisterWrite(dest_reg, old_value, result_value);
                            self.hook_manager.trigger(&event, self)?;
                        }
                        _ => return Err("Type error in SHR operation".to_string()),
                    }
                }
                Instruction::JMP(ref label) => {
                    // If we're using resolved instructions, get the target from the resolved instruction
                    if use_resolved {
                        let resolved_idx = {
                            let current_record = self.activation_records.last().unwrap();
                            current_record.resolved_instructions.as_ref().unwrap()[ip]
                        };

                        if let ResolvedInstruction::JMP(target) = resolved_idx {
                            self.activation_records
                                .last_mut()
                                .unwrap()
                                .instruction_pointer = target;
                        } else {
                            return Err(format!(
                                "Expected JMP instruction, got {:?}",
                                resolved_idx
                            ));
                        }
                    } else {
                        // Otherwise, look up the label in the function's labels HashMap
                        let target = vm_function
                            .labels
                            .get(label)
                            .ok_or_else(|| format!("Label '{}' not found", label))?
                            .clone();

                        self.activation_records
                            .last_mut()
                            .unwrap()
                            .instruction_pointer = target;
                    }
                }
                Instruction::JMPEQ(ref label) => {
                    let should_jump = self.activation_records.last().unwrap().compare_flag == 0;

                    if should_jump {
                        if use_resolved {
                            let resolved_idx = {
                                let current_record = self.activation_records.last().unwrap();
                                current_record.resolved_instructions.as_ref().unwrap()[ip]
                            };

                            if let ResolvedInstruction::JMPEQ(target) = resolved_idx {
                                self.activation_records
                                    .last_mut()
                                    .unwrap()
                                    .instruction_pointer = target;
                            } else {
                                return Err(format!(
                                    "Expected JMPEQ instruction, got {:?}",
                                    resolved_idx
                                ));
                            }
                        } else {
                            let target = vm_function
                                .labels
                                .get(label)
                                .ok_or_else(|| format!("Label '{}' not found", label))?
                                .clone();

                            self.activation_records
                                .last_mut()
                                .unwrap()
                                .instruction_pointer = target;
                        }
                    }
                }
                Instruction::JMPNEQ(ref label) => {
                    let should_jump = self.activation_records.last().unwrap().compare_flag != 0;

                    if should_jump {
                        if use_resolved {
                            let resolved_idx = {
                                let current_record = self.activation_records.last().unwrap();
                                current_record.resolved_instructions.as_ref().unwrap()[ip]
                            };

                            if let ResolvedInstruction::JMPNEQ(target) = resolved_idx {
                                self.activation_records
                                    .last_mut()
                                    .unwrap()
                                    .instruction_pointer = target;
                            } else {
                                return Err(format!(
                                    "Expected JMPNEQ instruction, got {:?}",
                                    resolved_idx
                                ));
                            }
                        } else {
                            let target = vm_function
                                .labels
                                .get(label)
                                .ok_or_else(|| format!("Label '{}' not found", label))?
                                .clone();

                            self.activation_records
                                .last_mut()
                                .unwrap()
                                .instruction_pointer = target;
                        }
                    }
                }
                Instruction::JMPLT(ref label) => {
                    // Jump if Less Than (compare_flag == -1)
                    let should_jump = self.activation_records.last().unwrap().compare_flag == -1;

                    if should_jump {
                        if use_resolved {
                            let resolved_idx = {
                                let current_record = self.activation_records.last().unwrap();
                                current_record.resolved_instructions.as_ref().unwrap()[ip]
                            };

                            if let ResolvedInstruction::JMPLT(target) = resolved_idx {
                                self.activation_records
                                    .last_mut()
                                    .unwrap()
                                    .instruction_pointer = target;
                            } else {
                                return Err(format!(
                                    "Expected JMPLT instruction, got {:?}",
                                    resolved_idx
                                ));
                            }
                        } else {
                            let target = vm_function
                                .labels
                                .get(label)
                                .ok_or_else(|| format!("Label '{}' not found", label))?
                                .clone();

                            self.activation_records
                                .last_mut()
                                .unwrap()
                                .instruction_pointer = target;
                        }
                    }
                }
                Instruction::JMPGT(ref label) => {
                    // Jump if Greater Than (compare_flag == 1)
                    let should_jump = self.activation_records.last().unwrap().compare_flag == 1;
                    if should_jump {
                        if use_resolved {
                            let resolved_idx = {
                                let current_record = self.activation_records.last().unwrap();
                                current_record.resolved_instructions.as_ref().unwrap()[ip]
                            };

                            if let ResolvedInstruction::JMPGT(target) = resolved_idx {
                                self.activation_records
                                    .last_mut()
                                    .unwrap()
                                    .instruction_pointer = target;
                            } else {
                                return Err(format!(
                                    "Expected JMPGT instruction, got {:?}",
                                    resolved_idx
                                ));
                            }
                        } else {
                            let target = vm_function
                                .labels
                                .get(label)
                                .ok_or_else(|| format!("Label '{}' not found", label))?
                                .clone();

                            self.activation_records
                                .last_mut()
                                .unwrap()
                                .instruction_pointer = target;
                        }
                    }
                }
                Instruction::CALL(ref function_name) => {
                    // Get arguments from stack
                    let args;
                    {
                        let current_record = self.activation_records.last().unwrap();
                        args = current_record.stack.clone();
                    }

                    let function = self
                        .functions
                        .get(function_name)
                        .ok_or_else(|| format!("Function \'{}\' not found", function_name))?
                        .clone();

                    let activation_count_before = self.activation_records.len();

                    // Clear the stack and trigger StackPop events
                    let mut popped_values = Vec::new();
                    {
                        let current_record = self.activation_records.last_mut().unwrap();
                        while let Some(value) = current_record.stack.pop() {
                            popped_values.push(value);
                        }
                        // Stack is now empty
                    }

                    // Trigger stack pop events after releasing the mutable borrow
                    for value in popped_values {
                        let event = HookEvent::StackPop(value);
                        self.hook_manager.trigger(&event, self)?;
                    }

                    match function {
                        Function::VM(vm_func) => {
                            if vm_func.parameters.len() != args.len() {
                                return Err(format!(
                                    "Function {} expects {} arguments but got {}",
                                    function_name,
                                    vm_func.parameters.len(),
                                    args.len()
                                ));
                            }

                            // Initialize upvalues for the function
                            let mut upvalues = Vec::new();
                            for name in &vm_func.upvalues {
                                let value = self.find_upvalue(name).ok_or_else(|| {
                                    format!("Could not find upvalue {} when calling function", name)
                                })?;

                                upvalues.push(Upvalue {
                                    name: name.clone(),
                                    value,
                                });
                            }

                            let closure = Closure {
                                function_id: function_name.clone(),
                                upvalues: upvalues.clone(),
                            };
                            let closure_value = Value::Closure(Arc::new(closure));

                            let event =
                                HookEvent::BeforeFunctionCall(closure_value, args.clone().to_vec());
                            self.hook_manager.trigger(&event, self)?;

                            let new_record = ActivationRecord {
                                function_name: function_name.clone(),
                                locals: FxHashMap::default(),
                                registers: SmallVec::from_vec(vec![
                                    Value::Unit;
                                    vm_func.register_count
                                ]),
                                upvalues,
                                instruction_pointer: 0,
                                stack: SmallVec::new(),
                                compare_flag: 0,
                                instructions: SmallVec::from(vm_func.instructions.clone()),
                                cached_instructions: vm_func
                                    .cached_instructions
                                    .as_ref()
                                    .map(|v| SmallVec::from_vec(v.clone())),
                                resolved_instructions: vm_func.resolved_instructions.clone(),
                                constant_values: vm_func.constant_values.clone(),
                                closure: None,
                            };

                            let args_len = args.len();

                            let mut record = self.activation_pool.get();
                            *record = new_record;
                            self.activation_records.push((*record).clone());

                            {
                                let record = self.activation_records.last_mut().unwrap();
                                for (i, param_name) in vm_func.parameters.iter().enumerate() {
                                    record.registers[i] = args[i].clone();
                                    record.locals.insert(param_name.clone(), args[i].clone());
                                }
                            }

                            if self.activation_records.len() >= 2 {
                                let prev_record_idx = self.activation_records.len() - 2;
                                // Pop values from the actual previous activation record, not a clone
                                let mut popped_values = Vec::new();
                                {
                                    let prev_record = &mut self.activation_records[prev_record_idx];
                                    for _ in 0..args_len {
                                        if let Some(value) = prev_record.stack.pop() {
                                            popped_values.push(value);
                                        }
                                    }
                                    prev_record.stack.clear();
                                }

                                // Trigger stack pop events after releasing the mutable borrow
                                for value in popped_values {
                                    let event = HookEvent::StackPop(value);
                                    self.hook_manager.trigger(&event, self)?;
                                }
                            }
                        }
                        Function::Foreign(foreign_func) => {
                            let func_value =
                                Value::String(format!("<foreign function {}>", function_name));

                            let event = HookEvent::BeforeFunctionCall(
                                func_value.clone(),
                                args.clone().to_vec(),
                            );
                            self.hook_manager.trigger(&event, self)?;

                            let context = ForeignFunctionContext {
                                args: &args,
                                vm_state: self,
                            };

                            let result = (foreign_func.func)(context)?;

                            if self.activation_records.len() > activation_count_before {
                                continue;
                            }

                            // Check if there are any activation records left
                            if self.activation_records.is_empty() {
                                return Ok(result);
                            }

                            let old_value;
                            let mut popped_items = SmallVec::<[Value; 8]>::new();
                            {
                                let record = self.activation_records.last_mut().unwrap();
                                old_value = record.registers[0].clone();
                                record.registers[0] = result.clone();

                                // First collect the items from the stack
                                for _ in 0..args.len() {
                                    if let Some(value) = record.stack.pop() {
                                        popped_items.push(value);
                                    }
                                }
                                // Clear the stack after collecting all items
                                record.stack.clear();
                            }

                            let reg_event = HookEvent::RegisterWrite(0, old_value, result.clone());
                            self.hook_manager.trigger(&reg_event, self)?;

                            let fn_event = HookEvent::AfterFunctionCall(func_value, result);
                            self.hook_manager.trigger(&fn_event, self)?;

                            for value in popped_items {
                                let event = HookEvent::StackPop(value);
                                self.hook_manager.trigger(&event, self)?;
                            }
                        }
                    }

                    // Check if there are any activation records left
                    if !self.activation_records.is_empty() {
                        // Pop each value from the stack and trigger a StackPop event for each one
                        let mut popped_values = Vec::new();
                        {
                            let record = self.activation_records.last_mut().unwrap();
                            while let Some(value) = record.stack.pop() {
                                popped_values.push(value);
                            }
                            // Stack is now empty
                        }

                        // Trigger stack pop events after releasing the mutable borrow
                        for value in popped_values {
                            let event = HookEvent::StackPop(value);
                            self.hook_manager.trigger(&event, self)?;
                        }
                    }
                }
                Instruction::RET(reg) => {
                    let current_record = self.activation_records.last().unwrap();
                    let return_value = current_record.registers[reg].clone();
                    let returning_from = current_record.function_name.clone();

                    // If this is a closure, update the upvalues in the original closure
                    if let Some(Value::Closure(closure_arc)) = &current_record.closure {
                        // Clone the closure_arc to get ownership
                        let closure_arc = Arc::clone(closure_arc);
                        // Get a mutable reference to the closure by creating a new one
                        let mut new_closure = (*closure_arc).clone();

                        // Update the upvalues in the new closure with the values from the activation record
                        new_closure.upvalues = current_record.upvalues.clone();

                        // Replace the original closure with the new one in the activation record
                        let current_record = self.activation_records.last_mut().unwrap();
                        current_record.closure = Some(Value::Closure(Arc::new(new_closure)));
                    }

                    // If we only have one activation record (main function), just return
                    if self.activation_records.len() <= 1 {
                        let event = HookEvent::AfterInstructionExecute(instruction.clone());
                        self.hook_manager.trigger(&event, self)?;
                        return Ok(return_value);
                    }

                    // Pop the current activation record
                    self.activation_records.pop();

                    // Get the parent record (which is now the last one)
                    let parent_record = self.activation_records.last_mut().unwrap();

                    // Set the return value in register 0 of the parent activation record
                    let old_value = parent_record.registers[0].clone();
                    parent_record.registers[0] = return_value.clone();

                    let event = HookEvent::RegisterWrite(0, old_value, return_value.clone());
                    self.hook_manager.trigger(&event, self)?;

                    let closure_value = Value::String(format!("<function {}>", returning_from));
                    let event = HookEvent::AfterFunctionCall(closure_value, return_value);
                    self.hook_manager.trigger(&event, self)?;
                }
                Instruction::PUSHARG(reg) => {
                    let value = self.activation_records.last().unwrap().registers[reg].clone();

                    let record = self.activation_records.last_mut().unwrap();
                    record.stack.push(value.clone());

                    let event = HookEvent::StackPush(value);
                    self.hook_manager.trigger(&event, self)?;
                }
                Instruction::CMP(reg1, reg2) => {
                    let record = self.activation_records.last_mut().unwrap();
                    let val1 = &record.registers[reg1];
                    let val2 = &record.registers[reg2];

                    let compare_result = match (val1, val2) {
                        (Value::Int(a), Value::Int(b)) => {
                            if a < b {
                                -1
                            } else if a > b {
                                1
                            } else {
                                0
                            }
                        }
                        (Value::String(a), Value::String(b)) => {
                            if a < b {
                                -1
                            } else if a > b {
                                1
                            } else {
                                0
                            }
                        }
                        (Value::Bool(a), Value::Bool(b)) => match (a, b) {
                            (false, true) => -1,
                            (true, false) => 1,
                            _ => 0,
                        },
                        _ => return Err(format!("Cannot compare {:?} and {:?}", val1, val2)),
                    };

                    record.compare_flag = compare_result;
                }
            }

            let event = HookEvent::AfterInstructionExecute(instruction.clone());
            self.hook_manager.trigger(&event, self)?;
            // The loop will never exit normally, it will always return from within
            // or continue to the next iteration
        }
    }

    pub fn call_foreign_function(&mut self, name: &str, args: &[Value]) -> Result<Value, String> {
        let function = self
            .functions
            .get(name)
            .ok_or_else(|| format!("Foreign function {} not found", name))?
            .clone();

        match function {
            Function::Foreign(foreign_func) => {
                let func_value = Value::String(format!("<foreign function {}>", name));

                let event = HookEvent::BeforeFunctionCall(func_value.clone(), args.to_vec());
                self.hook_manager.trigger(&event, self)?;

                let context = ForeignFunctionContext {
                    args,
                    vm_state: self,
                };

                let result = (foreign_func.func)(context)?;

                let event = HookEvent::AfterFunctionCall(func_value, result.clone());
                self.hook_manager.trigger(&event, self)?;

                Ok(result)
            }
            Function::VM(_) => Err(format!(
                "Expected foreign function, but {} is a VM function",
                name
            )),
        }
    }
}
