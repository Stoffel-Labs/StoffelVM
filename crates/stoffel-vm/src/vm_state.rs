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

use crate::foreign_functions::{ForeignFunctionContext, Function};
use crate::net::client_store::ClientInputStore;
use crate::runtime_hooks::{HookContext, HookEvent, HookManager};
use ark_bls12_381::Fr;
use ark_ff::{Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rustc_hash::FxHashMap;
use smallvec::{SmallVec, smallvec};
use std::sync::Arc;
use stoffel_vm_types::activations::{ActivationRecord, ActivationRecordPool};
use stoffel_vm_types::core_types::{
    BOOLEAN_SECRET_INT_BITS, Closure, F64, ForeignObjectStorage, ObjectStore, ShareType, Upvalue, Value,
};
use stoffel_vm_types::functions::VMFunction;
use stoffel_vm_types::instructions::{Instruction, ResolvedInstruction};
use stoffelmpc_mpc::common::types::{TypeError, fixed::SecretFixedPoint, integer::SecretInt};
use stoffelmpc_mpc::common::SecretSharingScheme;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelnet::network_utils::ClientId;

type SecretIntShare = SecretInt<Fr, RobustShare<Fr>>;
type SecretFixedPointShare = SecretFixedPoint<Fr, RobustShare<Fr>>;

// ============================================================================
// Automatic Reveal Batching
// ============================================================================

/// Queued reveal operation waiting to be batched
#[derive(Clone)]
struct QueuedReveal {
    /// The share type (SecretInt or SecretFixedPoint)
    share_type: ShareType,
    /// Serialized share data
    share_data: Vec<u8>,
    /// Destination register for the revealed value
    dest_reg: usize,
}

/// Automatic reveal batching for MPC operations
///
/// This struct collects reveal operations and executes them in batches
/// to reduce network round trips. Instead of revealing immediately when
/// a MOV from secret to clear register occurs, reveals are queued and
/// executed as a batch when the value is actually needed.
pub struct RevealBatcher {
    /// Pending reveals waiting to be flushed
    pending: Vec<QueuedReveal>,
    /// Whether auto-batching is enabled
    pub enabled: bool,
    /// Maximum pending reveals before forced flush
    max_pending: usize,
}

impl Default for RevealBatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl RevealBatcher {
    /// Create a new reveal batcher with default settings
    pub fn new() -> Self {
        Self {
            pending: Vec::new(),
            enabled: true,
            max_pending: 1024, // Prevent unbounded growth
        }
    }

    /// Queue a reveal operation, returns the queue index for the PendingReveal marker
    pub fn queue(&mut self, ty: ShareType, data: Vec<u8>, dest_reg: usize) -> usize {
        let index = self.pending.len();
        self.pending.push(QueuedReveal {
            share_type: ty,
            share_data: data,
            dest_reg,
        });
        index
    }

    /// Check if we have pending reveals
    #[inline]
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Get number of pending reveals
    #[inline]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Check if we should auto-flush (reached max pending)
    #[inline]
    pub fn should_auto_flush(&self) -> bool {
        self.pending.len() >= self.max_pending
    }

    /// Flush all pending reveals, returns (register, value) pairs
    ///
    /// This method batch-reveals all pending shares and returns the results
    /// paired with their destination registers.
    pub fn flush(
        &mut self,
        engine: &dyn crate::net::mpc_engine::MpcEngine,
    ) -> Result<Vec<(usize, Value)>, String> {
        if self.pending.is_empty() {
            return Ok(vec![]);
        }

        // Group by share type - for now assume all same type (typical case)
        // TODO: Support mixed types by grouping and batching separately
        let first_type = self.pending[0].share_type;

        let shares: Vec<Vec<u8>> = self.pending.iter().map(|r| r.share_data.clone()).collect();

        // Batch reveal!
        let revealed = engine.batch_open_shares(first_type, &shares)?;

        // Build results with register destinations
        let results: Vec<(usize, Value)> = self
            .pending
            .iter()
            .zip(revealed)
            .map(|(queued, value)| (queued.dest_reg, value))
            .collect();

        self.pending.clear();
        Ok(results)
    }

    /// Clear all pending reveals without executing them
    pub fn clear(&mut self) {
        self.pending.clear();
    }
}

// ============================================================================
// Macros for reducing code duplication
// ============================================================================

/// Macro to implement integer comparison for all numeric types
macro_rules! impl_cmp {
    ($val1:expr, $val2:expr) => {
        if $val1 < $val2 {
            -1
        } else if $val1 > $val2 {
            1
        } else {
            0
        }
    };
}

// ============================================================================
// VM State Structure
// ============================================================================

/// Runtime state of the virtual machine
///
/// This structure maintains the complete state of the VM during execution,
/// including the function registry, activation record stack, object storage,
/// and hook system for debugging.
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
    /// Optional MPC engine used to drive secret-sharing protocols
    pub mpc_engine: Option<Arc<dyn crate::net::mpc_engine::MpcEngine>>,
    /// Per-VM client store used for loading MPC inputs
    client_store: Arc<ClientInputStore>,
    /// Automatic reveal batching for MPC operations
    pub reveal_batcher: RevealBatcher,
}

impl Default for VMState {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Core VM State Implementation
// ============================================================================

impl VMState {
    /// Create a new VM state with default values
    #[inline]
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
            mpc_engine: None,
            client_store: Arc::new(ClientInputStore::new()),
            reveal_batcher: RevealBatcher::new(),
        }
    }

    /// Get the number of activation records on the stack
    #[inline]
    pub fn activation_records_len(&self) -> usize {
        self.activation_records.len()
    }

    /// Get a mutable reference to the current (top) activation record
    #[inline]
    pub fn current_activation_record(&mut self) -> &mut ActivationRecord {
        self.activation_records.last_mut().unwrap()
    }

    /// Find an upvalue (captured variable) by name in the activation record stack
    pub fn find_upvalue(&self, name: &str) -> Option<Value> {
        for record in self.activation_records.iter().rev() {
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

    /// Check if hooks are enabled (fast path)
    #[inline(always)]
    fn hooks_enabled(&self) -> bool {
        !self.hook_manager.hooks.is_empty()
    }

    /// Trigger a register read hook event
    #[inline]
    pub fn trigger_register_read(&self, reg: usize, value: &Value) -> Result<(), String> {
        if self.hooks_enabled() {
            let event = HookEvent::RegisterRead(reg, value.clone());
            self.hook_manager.trigger(&event, self)
        } else {
            Ok(())
        }
    }

    /// Trigger a register write hook event
    #[inline]
    pub fn trigger_register_write(
        &self,
        reg: usize,
        old_value: &Value,
        new_value: &Value,
    ) -> Result<(), String> {
        if self.hooks_enabled() {
            let event = HookEvent::RegisterWrite(reg, old_value.clone(), new_value.clone());
            self.hook_manager.trigger(&event, self)
        } else {
            Ok(())
        }
    }

    /// Trigger a hook event with a snapshot of the current VM state
    #[inline]
    pub fn trigger_hook_with_snapshot(&self, event: &HookEvent) -> Result<(), String> {
        if self.hook_manager.hooks.is_empty() {
            return Ok(());
        }

        let context = HookContext::new(
            &self.activation_records,
            self.current_instruction,
            &self.functions,
        );
        self.hook_manager.trigger_with_context(event, &context)
    }

    /// Create a closure from a function and captured variables
    pub fn create_closure(
        &mut self,
        function_name: &str,
        upvalue_names: &[String],
    ) -> Result<Value, String> {
        let mut upvalues = Vec::with_capacity(upvalue_names.len());
        for name in upvalue_names {
            let value = self
                .find_upvalue(name)
                .ok_or_else(|| format!("Could not find upvalue {} when creating closure", name))?;

            upvalues.push(Upvalue {
                name: name.clone(),
                value,
            });
        }

        let closure = Closure {
            function_id: function_name.to_string(),
            upvalues: upvalues.clone(),
        };

        if self.hooks_enabled() {
            let event = HookEvent::ClosureCreated(function_name.to_string(), upvalues);
            self.hook_manager.trigger(&event, self)?;
        }

        Ok(Value::Closure(Arc::new(closure)))
    }
}

// ============================================================================
// Async MPC Operation Types
// ============================================================================

/// Represents a pending MPC operation that needs async execution
#[derive(Debug, Clone)]
pub enum PendingMpcOperation {
    /// Multiply two shares - requires MPC network communication
    MultiplyShare {
        share_type: ShareType,
        left_data: Vec<u8>,
        right_data: Vec<u8>,
        dest_reg: usize,
    },
    /// Open (reveal) a share - requires collecting shares from other parties
    OpenShare {
        share_type: ShareType,
        share_data: Vec<u8>,
        dest_reg: usize,
    },
}

/// Result of a single VM step - either completed or needs async MPC
#[derive(Debug)]
pub enum StepResult {
    /// Instruction executed successfully, continue to next
    Continue,
    /// Function returned a value
    Return(Value),
    /// Need to perform an async MPC operation before continuing
    NeedsMpc(PendingMpcOperation),
}

// ============================================================================
// Instruction Execution Engine
// ============================================================================

impl VMState {
    /// Main execution loop - runs until a return instruction is encountered
    pub fn execute_until_return(&mut self) -> Result<Value, String> {
        let initial_activation_depth = self.activation_records_len();
        let hooks_enabled = self.hooks_enabled();

        loop {
            if self.activation_records.is_empty() {
                return Err("Unexpected end of execution".to_string());
            }

            // Get current execution context
            let (function_name, ip, use_resolved) = {
                let record = self.activation_records.last().unwrap();
                (
                    record.function_name.clone(),
                    record.instruction_pointer,
                    record.resolved_instructions.is_some(),
                )
            };

            // Ensure resolved instructions are available
            self.ensure_resolved_instructions(&function_name)?;

            // Get the VM function
            let vm_function = match self.functions.get(&function_name) {
                Some(Function::VM(vm_func)) => vm_func.clone(),
                Some(Function::Foreign(_)) => {
                    return Err(format!("Cannot execute foreign function {}", function_name));
                }
                None => return Err(format!("Function {} not found", function_name)),
            };

            // Check if we've reached the end of the function
            let is_end = self.is_end_of_function(ip, use_resolved, &vm_function)?;

            if is_end {
                if let Some(result) = self.handle_function_end(initial_activation_depth)? {
                    return Ok(result);
                }
                continue;
            }

            // Get and execute the current instruction
            let instruction = self.fetch_instruction(ip, use_resolved, &vm_function)?;
            self.current_instruction = ip;

            // Advance instruction pointer
            self.activation_records.last_mut().unwrap().instruction_pointer += 1;

            // Trigger before-execution hook
            if hooks_enabled {
                let event = HookEvent::BeforeInstructionExecute(instruction.clone());
                self.trigger_hook_with_snapshot(&event)?;
            }

            // Execute the instruction
            let execution_result = self.execute_instruction(
                &instruction,
                use_resolved,
                ip,
                hooks_enabled,
                initial_activation_depth,
            )?;

            // Handle special return values from instruction execution
            if let Some(return_value) = execution_result {
                return Ok(return_value);
            }

            // Trigger after-execution hook
            if hooks_enabled {
                let event = HookEvent::AfterInstructionExecute(instruction);
                self.trigger_hook_with_snapshot(&event)?;
            }
        }
    }

    /// Async execution loop - runs until a return instruction is encountered.
    ///
    /// Unlike `execute_until_return`, this method is async-compatible and will
    /// properly await MPC operations instead of blocking the runtime.
    ///
    /// # Arguments
    /// * `async_engine` - The async MPC engine to use for MPC operations
    ///
    /// # Returns
    /// The return value of the function execution
    pub async fn execute_until_return_async<E: crate::net::mpc_engine::AsyncMpcEngine>(
        &mut self,
        async_engine: &E,
    ) -> Result<Value, String> {
        let initial_activation_depth = self.activation_records_len();
        let hooks_enabled = self.hooks_enabled();

        loop {
            // Execute one step
            let step_result =
                self.execute_step(initial_activation_depth, hooks_enabled)?;

            match step_result {
                StepResult::Continue => {
                    // Continue to next instruction
                    continue;
                }
                StepResult::Return(value) => {
                    return Ok(value);
                }
                StepResult::NeedsMpc(op) => {
                    // Handle the MPC operation asynchronously
                    self.handle_mpc_operation_async(async_engine, op).await?;
                }
            }
        }
    }

    /// Execute a single instruction step, returning the result
    ///
    /// This is the core of the step-based execution model that enables
    /// async MPC operations without blocking.
    fn execute_step(
        &mut self,
        initial_activation_depth: usize,
        hooks_enabled: bool,
    ) -> Result<StepResult, String> {
        if self.activation_records.is_empty() {
            return Err("Unexpected end of execution".to_string());
        }

        // Get current execution context
        let (function_name, ip, use_resolved) = {
            let record = self.activation_records.last().unwrap();
            (
                record.function_name.clone(),
                record.instruction_pointer,
                record.resolved_instructions.is_some(),
            )
        };

        // Ensure resolved instructions are available
        self.ensure_resolved_instructions(&function_name)?;

        // Get the VM function
        let vm_function = match self.functions.get(&function_name) {
            Some(Function::VM(vm_func)) => vm_func.clone(),
            Some(Function::Foreign(_)) => {
                return Err(format!("Cannot execute foreign function {}", function_name));
            }
            None => return Err(format!("Function {} not found", function_name)),
        };

        // Check if we've reached the end of the function
        let is_end = self.is_end_of_function(ip, use_resolved, &vm_function)?;

        if is_end {
            if let Some(result) = self.handle_function_end(initial_activation_depth)? {
                return Ok(StepResult::Return(result));
            }
            return Ok(StepResult::Continue);
        }

        // Get and execute the current instruction
        let instruction = self.fetch_instruction(ip, use_resolved, &vm_function)?;
        self.current_instruction = ip;

        // Advance instruction pointer
        self.activation_records.last_mut().unwrap().instruction_pointer += 1;

        // Trigger before-execution hook
        if hooks_enabled {
            let event = HookEvent::BeforeInstructionExecute(instruction.clone());
            self.trigger_hook_with_snapshot(&event)?;
        }

        // Check if this instruction needs async MPC
        if let Some(pending_op) = self.check_mpc_operation(&instruction)? {
            return Ok(StepResult::NeedsMpc(pending_op));
        }

        // Execute the instruction synchronously
        let execution_result = self.execute_instruction(
            &instruction,
            use_resolved,
            ip,
            hooks_enabled,
            initial_activation_depth,
        )?;

        // Handle special return values from instruction execution
        if let Some(return_value) = execution_result {
            return Ok(StepResult::Return(return_value));
        }

        // Trigger after-execution hook
        if hooks_enabled {
            let event = HookEvent::AfterInstructionExecute(instruction);
            self.trigger_hook_with_snapshot(&event)?;
        }

        Ok(StepResult::Continue)
    }

    /// Check if an instruction requires an async MPC operation
    ///
    /// Returns Some(PendingMpcOperation) if the instruction needs MPC,
    /// None if it can be executed synchronously.
    fn check_mpc_operation(&self, instruction: &Instruction) -> Result<Option<PendingMpcOperation>, String> {
        match instruction {
            Instruction::MUL(dest, src1, src2) => {
                let record = self.activation_records.last().unwrap();
                let left = &record.registers[*src1];
                let right = &record.registers[*src2];

                // Check if this is a Share * Share multiplication (requires MPC)
                match (left, right) {
                    (
                        Value::Share(ty @ ShareType::SecretInt { .. }, left_data),
                        Value::Share(ShareType::SecretInt { .. }, right_data),
                    ) => {
                        // Verify MPC engine is available
                        let engine = self.mpc_engine().ok_or("MPC engine not configured")?;
                        if !engine.is_ready() {
                            return Err("MPC engine configured but not ready".to_string());
                        }
                        Ok(Some(PendingMpcOperation::MultiplyShare {
                            share_type: *ty,
                            left_data: left_data.clone(),
                            right_data: right_data.clone(),
                            dest_reg: *dest,
                        }))
                    }
                    (
                        Value::Share(ty @ ShareType::SecretFixedPoint { .. }, left_data),
                        Value::Share(ShareType::SecretFixedPoint { .. }, right_data),
                    ) => {
                        let engine = self.mpc_engine().ok_or("MPC engine not configured")?;
                        if !engine.is_ready() {
                            return Err("MPC engine configured but not ready".to_string());
                        }
                        Ok(Some(PendingMpcOperation::MultiplyShare {
                            share_type: *ty,
                            left_data: left_data.clone(),
                            right_data: right_data.clone(),
                            dest_reg: *dest,
                        }))
                    }
                    // All other MUL cases (scalars, share*scalar) are local operations
                    _ => Ok(None),
                }
            }
            // DIV with shares could also need MPC in future, but currently it's local
            // CALL to certain builtins might reveal shares
            // For now, only MUL Share*Share needs async
            _ => Ok(None),
        }
    }

    /// Handle an MPC operation asynchronously
    async fn handle_mpc_operation_async<E: crate::net::mpc_engine::AsyncMpcEngine>(
        &mut self,
        engine: &E,
        operation: PendingMpcOperation,
    ) -> Result<(), String> {
        match operation {
            PendingMpcOperation::MultiplyShare {
                share_type,
                left_data,
                right_data,
                dest_reg,
            } => {
                // Perform the async multiplication
                let result = engine
                    .multiply_share_async(share_type, &left_data, &right_data)
                    .await
                    .map_err(|e| format!("Async MPC multiply_share failed: {}", e))?;

                // Store the result
                let record = self.activation_records.last_mut().unwrap();
                record.registers[dest_reg] = Value::Share(share_type, result);
                Ok(())
            }
            PendingMpcOperation::OpenShare {
                share_type,
                share_data,
                dest_reg,
            } => {
                // Perform the async open
                let result = engine
                    .open_share_async(share_type, &share_data)
                    .await
                    .map_err(|e| format!("Async MPC open_share failed: {}", e))?;

                // Store the result
                let record = self.activation_records.last_mut().unwrap();
                record.registers[dest_reg] = result;
                Ok(())
            }
        }
    }

    /// Ensure resolved instructions are available for the current function
    #[inline]
    fn ensure_resolved_instructions(&mut self, function_name: &str) -> Result<(), String> {
        let needs_resolving = {
            let record = self.activation_records.last().unwrap();
            record.resolved_instructions.is_none()
        };

        if needs_resolving {
            if let Some(Function::VM(mut vm_func)) = self.functions.get(function_name).cloned() {
                vm_func.resolve_instructions();
                let record = self.activation_records.last_mut().unwrap();
                record.resolved_instructions = vm_func.resolved_instructions.clone();
                record.constant_values = vm_func.constant_values.clone();
            }
        }
        Ok(())
    }

    /// Check if we've reached the end of the current function
    #[inline]
    fn is_end_of_function(
        &self,
        ip: usize,
        use_resolved: bool,
        vm_function: &VMFunction,
    ) -> Result<bool, String> {
        if use_resolved {
            let record = self.activation_records.last().unwrap();
            let resolved_len = record.resolved_instructions.as_ref().unwrap().len();
            Ok(ip >= resolved_len)
        } else {
            Ok(ip >= vm_function.instructions.len())
        }
    }

    /// Handle reaching the end of a function
    fn handle_function_end(
        &mut self,
        initial_activation_depth: usize,
    ) -> Result<Option<Value>, String> {
        if initial_activation_depth == 1 {
            return Ok(Some(self.activation_records[0].registers[0].clone()));
        }

        let result = self.activation_records.last().unwrap().registers[0].clone();
        self.activation_records.pop();

        if self.activation_records.is_empty() {
            return Ok(Some(result));
        }

        Ok(None) // Continue execution
    }

    /// Fetch the current instruction
    fn fetch_instruction(
        &mut self,
        ip: usize,
        use_resolved: bool,
        vm_function: &VMFunction,
    ) -> Result<Instruction, String> {
        if use_resolved {
            self.fetch_resolved_instruction(ip)
        } else {
            self.fetch_regular_instruction(ip, vm_function)
        }
    }

    /// Fetch instruction from resolved instructions
    fn fetch_resolved_instruction(&self, ip: usize) -> Result<Instruction, String> {
        let record = self.activation_records.last().unwrap();
        let resolved = &record.resolved_instructions.as_ref().unwrap()[ip];

        match *resolved {
            ResolvedInstruction::LD(reg, offset) => Ok(Instruction::LD(reg, offset)),
            ResolvedInstruction::LDI(reg, const_idx) => {
                let value = self.get_constant_value(const_idx)?;
                Ok(Instruction::LDI(reg, value))
            }
            ResolvedInstruction::MOV(dest, src) => Ok(Instruction::MOV(dest, src)),
            ResolvedInstruction::ADD(dest, src1, src2) => Ok(Instruction::ADD(dest, src1, src2)),
            ResolvedInstruction::SUB(dest, src1, src2) => Ok(Instruction::SUB(dest, src1, src2)),
            ResolvedInstruction::MUL(dest, src1, src2) => Ok(Instruction::MUL(dest, src1, src2)),
            ResolvedInstruction::DIV(dest, src1, src2) => Ok(Instruction::DIV(dest, src1, src2)),
            ResolvedInstruction::MOD(dest, src1, src2) => Ok(Instruction::MOD(dest, src1, src2)),
            ResolvedInstruction::AND(dest, src1, src2) => Ok(Instruction::AND(dest, src1, src2)),
            ResolvedInstruction::OR(dest, src1, src2) => Ok(Instruction::OR(dest, src1, src2)),
            ResolvedInstruction::XOR(dest, src1, src2) => Ok(Instruction::XOR(dest, src1, src2)),
            ResolvedInstruction::NOT(dest, src) => Ok(Instruction::NOT(dest, src)),
            ResolvedInstruction::SHL(dest, src, amount) => Ok(Instruction::SHL(dest, src, amount)),
            ResolvedInstruction::SHR(dest, src, amount) => Ok(Instruction::SHR(dest, src, amount)),
            ResolvedInstruction::JMP(target) => Ok(Instruction::JMP(format!("label_{}", target))),
            ResolvedInstruction::JMPEQ(target) => {
                Ok(Instruction::JMPEQ(format!("label_{}", target)))
            }
            ResolvedInstruction::JMPNEQ(target) => {
                Ok(Instruction::JMPNEQ(format!("label_{}", target)))
            }
            ResolvedInstruction::JMPLT(target) => {
                Ok(Instruction::JMPLT(format!("label_{}", target)))
            }
            ResolvedInstruction::JMPGT(target) => {
                Ok(Instruction::JMPGT(format!("label_{}", target)))
            }
            ResolvedInstruction::CALL(func_idx) => {
                let func_name = self.get_function_name_from_constant(func_idx)?;
                Ok(Instruction::CALL(func_name))
            }
            ResolvedInstruction::RET(reg) => Ok(Instruction::RET(reg)),
            ResolvedInstruction::PUSHARG(reg) => Ok(Instruction::PUSHARG(reg)),
            ResolvedInstruction::CMP(reg1, reg2) => Ok(Instruction::CMP(reg1, reg2)),
        }
    }

    /// Fetch instruction from regular instruction cache
    #[inline]
    fn fetch_regular_instruction(
        &mut self,
        ip: usize,
        vm_function: &VMFunction,
    ) -> Result<Instruction, String> {
        if self.instruction_cache.is_empty() {
            self.instruction_cache.extend(vm_function.instructions.iter().cloned());
        }
        Ok(self.instruction_cache[ip].clone())
    }

    /// Get a constant value by index
    #[inline]
    fn get_constant_value(&self, const_idx: usize) -> Result<Value, String> {
        let record = self.activation_records.last().unwrap();
        record
            .constant_values
            .as_ref()
            .and_then(|c| c.get(const_idx).cloned())
            .ok_or_else(|| format!("Constant index {} out of bounds", const_idx))
    }

    /// Get function name from constant pool
    #[inline]
    fn get_function_name_from_constant(&self, func_idx: usize) -> Result<String, String> {
        let value = self.get_constant_value(func_idx)?;
        match value {
            Value::String(name) => Ok(name),
            _ => Err(format!(
                "Expected string constant for function name at index {}",
                func_idx
            )),
        }
    }

    /// Execute a single instruction
    fn execute_instruction(
        &mut self,
        instruction: &Instruction,
        use_resolved: bool,
        ip: usize,
        hooks_enabled: bool,
        initial_activation_depth: usize,
    ) -> Result<Option<Value>, String> {
        match instruction {
            Instruction::LD(dest_reg, offset) => {
                self.execute_ld(*dest_reg, *offset, hooks_enabled)?;
            }
            Instruction::LDI(dest_reg, value) => {
                self.execute_ldi(*dest_reg, value.clone(), hooks_enabled)?;
            }
            Instruction::MOV(dest_reg, src_reg) => {
                self.execute_mov(*dest_reg, *src_reg, hooks_enabled)?;
            }
            Instruction::ADD(dest, src1, src2) => {
                self.execute_add(*dest, *src1, *src2, hooks_enabled)?;
            }
            Instruction::SUB(dest, src1, src2) => {
                self.execute_sub(*dest, *src1, *src2, hooks_enabled)?;
            }
            Instruction::MUL(dest, src1, src2) => {
                self.execute_mul(*dest, *src1, *src2, hooks_enabled)?;
            }
            Instruction::DIV(dest, src1, src2) => {
                self.execute_div(*dest, *src1, *src2, hooks_enabled)?;
            }
            Instruction::MOD(dest, src1, src2) => {
                self.execute_mod(*dest, *src1, *src2, hooks_enabled)?;
            }
            Instruction::AND(dest, src1, src2) => {
                self.execute_and(*dest, *src1, *src2, hooks_enabled)?;
            }
            Instruction::OR(dest, src1, src2) => {
                self.execute_or(*dest, *src1, *src2, hooks_enabled)?;
            }
            Instruction::XOR(dest, src1, src2) => {
                self.execute_xor(*dest, *src1, *src2, hooks_enabled)?;
            }
            Instruction::NOT(dest, src) => {
                self.execute_not(*dest, *src, hooks_enabled)?;
            }
            Instruction::SHL(dest, src, amount) => {
                self.execute_shl(*dest, *src, *amount, hooks_enabled)?;
            }
            Instruction::SHR(dest, src, amount) => {
                self.execute_shr(*dest, *src, *amount, hooks_enabled)?;
            }
            Instruction::JMP(label) => {
                self.execute_jmp(label, use_resolved, ip)?;
            }
            Instruction::JMPEQ(label) => {
                self.execute_jmpeq(label, use_resolved, ip)?;
            }
            Instruction::JMPNEQ(label) => {
                self.execute_jmpneq(label, use_resolved, ip)?;
            }
            Instruction::JMPLT(label) => {
                self.execute_jmplt(label, use_resolved, ip)?;
            }
            Instruction::JMPGT(label) => {
                self.execute_jmpgt(label, use_resolved, ip)?;
            }
            Instruction::CALL(function_name) => {
                if let Some(result) =
                    self.execute_call(function_name, hooks_enabled, initial_activation_depth)?
                {
                    return Ok(Some(result));
                }
            }
            Instruction::RET(reg) => {
                if let Some(result) = self.execute_ret(*reg, instruction, hooks_enabled)? {
                    return Ok(Some(result));
                }
            }
            Instruction::PUSHARG(reg) => {
                self.execute_pusharg(*reg, hooks_enabled)?;
            }
            Instruction::CMP(reg1, reg2) => {
                self.execute_cmp(*reg1, *reg2)?;
            }
        }

        Ok(None)
    }
}

// ============================================================================
// Individual Instruction Handlers
// ============================================================================

impl VMState {
    /// Execute LD instruction - Load from stack to register
    #[inline]
    fn execute_ld(&mut self, dest_reg: usize, offset: i32, hooks_enabled: bool) -> Result<(), String> {
        let value = {
            let record = self.activation_records.last().unwrap();
            let stack_len = record.stack.len() as i32;
            let idx = stack_len + offset - 1;
            if idx < 0 || idx >= stack_len {
                return Err(format!("Stack address [sp+{}] out of bounds", offset));
            }
            record.stack[idx as usize].clone()
        };

        let record = self.activation_records.last_mut().unwrap();
        if hooks_enabled {
            let old_value = record.registers[dest_reg].clone();
            record.registers[dest_reg] = value;
            let event = HookEvent::RegisterWrite(dest_reg, old_value, record.registers[dest_reg].clone());
            self.trigger_hook_with_snapshot(&event)?;
        } else {
            record.registers[dest_reg] = value;
        }
        Ok(())
    }

    /// Execute LDI instruction - Load immediate to register
    #[inline]
    fn execute_ldi(&mut self, dest_reg: usize, value: Value, hooks_enabled: bool) -> Result<(), String> {
        let record = self.activation_records.last_mut().unwrap();
        if hooks_enabled {
            let old_value = record.registers[dest_reg].clone();
            record.registers[dest_reg] = value.clone();
            let event = HookEvent::RegisterWrite(dest_reg, old_value, value);
            self.trigger_hook_with_snapshot(&event)?;
        } else {
            record.registers[dest_reg] = value;
        }
        Ok(())
    }

    /// Execute MOV instruction - Move between registers (with secret sharing conversion)
    fn execute_mov(&mut self, dest_reg: usize, src_reg: usize, hooks_enabled: bool) -> Result<(), String> {
        // Determine what kind of conversion is needed and clone necessary data
        // We do this in a separate block to avoid borrow conflicts with reveal_share
        let (conversion_type, src_value_clone) = {
            let record = self.activation_records.last().unwrap();
            let src_value = &record.registers[src_reg];

            // Secret register boundary: registers >= 16 are secret
            if dest_reg >= 16 && src_reg < 16 {
                // Clear -> Secret conversion
                if matches!(src_value, Value::Share(_, _)) {
                    (0, src_value.clone()) // Already a share, just clone
                } else {
                    (1, src_value.clone()) // Need to convert to share
                }
            } else if dest_reg < 16 && src_reg >= 16 {
                // Secret -> Clear conversion (reveal with batching)
                (2, src_value.clone())
            } else {
                // No conversion, just clone
                (0, src_value.clone())
            }
        };

        // Perform the conversion (now with mutable self access for reveal_share)
        let result_value = match conversion_type {
            1 => self.convert_to_share(&src_value_clone)?,
            2 => self.reveal_share(&src_value_clone, dest_reg)?,
            _ => src_value_clone,
        };

        let record = self.activation_records.last_mut().unwrap();
        if hooks_enabled {
            let src_value = record.registers[src_reg].clone();
            let old_value = record.registers[dest_reg].clone();
            record.registers[dest_reg] = result_value.clone();

            let read_event = HookEvent::RegisterRead(src_reg, src_value);
            self.trigger_hook_with_snapshot(&read_event)?;

            let write_event = HookEvent::RegisterWrite(dest_reg, old_value, result_value);
            self.trigger_hook_with_snapshot(&write_event)?;
        } else {
            record.registers[dest_reg] = result_value;
        }
        Ok(())
    }

    /// Convert a clear value to a secret share
    #[inline]
    fn convert_to_share(&self, value: &Value) -> Result<Value, String> {
        let engine = self
            .mpc_engine()
            .ok_or_else(|| "MPC engine not configured".to_string())?;
        if !engine.is_ready() {
            return Err("MPC engine configured but not ready".to_string());
        }

        match value {
            Value::I64(_) => {
                let ty = ShareType::default_secret_int();
                let bytes = engine
                    .input_share(ty, value)
                    .map_err(|e| format!("MPC input_share failed: {}", e))?;
                Ok(Value::Share(ty, bytes))
            }
            Value::Float(_) => {
                let ty = ShareType::default_secret_fixed_point();
                let bytes = engine
                    .input_share(ty, value)
                    .map_err(|e| format!("MPC input_share failed: {}", e))?;
                Ok(Value::Share(ty, bytes))
            }
            Value::Bool(_) => {
                let ty = ShareType::boolean();
                let bytes = engine
                    .input_share(ty, value)
                    .map_err(|e| format!("MPC input_share failed: {}", e))?;
                Ok(Value::Share(ty, bytes))
            }
            _ => Err("Only primitive types (Int, Float, Bool) can be converted to shares".to_string()),
        }
    }

    /// Reveal a secret share to a clear value (immediate, no batching)
    #[inline]
    fn reveal_share_immediate(&self, value: &Value) -> Result<Value, String> {
        let engine = self
            .mpc_engine()
            .ok_or_else(|| "MPC engine not configured".to_string())?;
        if !engine.is_ready() {
            return Err("MPC engine configured but not ready".to_string());
        }

        match value {
            Value::Share(ty @ ShareType::SecretInt { .. }, data) => engine
                .open_share(*ty, data)
                .map_err(|e| format!("MPC open_share failed: {}", e)),
            Value::Share(ty @ ShareType::SecretFixedPoint { .. }, data) => engine
                .open_share(*ty, data)
                .map_err(|e| format!("MPC open_share failed: {}", e)),
            _ => Err("Invalid share type for conversion to clear value".to_string()),
        }
    }

    /// Reveal a secret share to a clear value, with optional batching
    ///
    /// If batching is enabled, this queues the reveal and returns a PendingReveal marker.
    /// The actual reveal happens when the value is used (via flush_pending_reveals).
    fn reveal_share(&mut self, value: &Value, dest_reg: usize) -> Result<Value, String> {
        // If batching is disabled, reveal immediately
        if !self.reveal_batcher.enabled {
            return self.reveal_share_immediate(value);
        }

        // Check for MPC engine
        let engine = self
            .mpc_engine()
            .ok_or_else(|| "MPC engine not configured".to_string())?;
        if !engine.is_ready() {
            return Err("MPC engine configured but not ready".to_string());
        }

        match value {
            Value::Share(ty, data) => {
                // Queue the reveal instead of executing immediately
                let index = self.reveal_batcher.queue(*ty, data.clone(), dest_reg);

                // Check if we should auto-flush (hit max pending)
                if self.reveal_batcher.should_auto_flush() {
                    self.flush_pending_reveals()?;
                    // Return the actual revealed value (it's now in the register)
                    let record = self.activation_records.last().unwrap();
                    Ok(record.registers[dest_reg].clone())
                } else {
                    // Return marker - actual reveal deferred
                    Ok(Value::PendingReveal(index))
                }
            }
            _ => Err("Invalid share type for conversion to clear value".to_string()),
        }
    }

    /// Flush all pending reveals and update destination registers
    ///
    /// This batch-reveals all queued shares and stores the results in their
    /// respective destination registers.
    pub fn flush_pending_reveals(&mut self) -> Result<(), String> {
        if !self.reveal_batcher.has_pending() {
            return Ok(());
        }

        let engine = self
            .mpc_engine()
            .ok_or_else(|| "MPC engine not configured".to_string())?;

        let results = self.reveal_batcher.flush(engine.as_ref())?;

        // Update all destination registers with revealed values
        let record = self.activation_records.last_mut().unwrap();
        for (reg, value) in results {
            record.registers[reg] = value;
        }

        Ok(())
    }

    /// Ensure a register value is resolved (not a PendingReveal)
    ///
    /// If the register contains a PendingReveal marker, this flushes all pending
    /// reveals and returns the resolved value.
    #[inline]
    fn ensure_resolved(&mut self, reg: usize) -> Result<(), String> {
        let record = self.activation_records.last().unwrap();

        if matches!(record.registers[reg], Value::PendingReveal(_)) {
            // This register has a pending reveal - flush all pending
            self.flush_pending_reveals()?;
        }

        Ok(())
    }

    /// Ensure multiple registers are resolved
    #[inline]
    fn ensure_registers_resolved(&mut self, regs: &[usize]) -> Result<(), String> {
        let record = self.activation_records.last().unwrap();

        // Check if any register has a pending reveal
        let needs_flush = regs
            .iter()
            .any(|&reg| matches!(record.registers[reg], Value::PendingReveal(_)));

        if needs_flush {
            self.flush_pending_reveals()?;
        }

        Ok(())
    }

    /// Execute ADD instruction
    fn execute_add(
        &mut self,
        dest_reg: usize,
        src1_reg: usize,
        src2_reg: usize,
        hooks_enabled: bool,
    ) -> Result<(), String> {
        // Ensure source registers are resolved (flush pending reveals if needed)
        self.ensure_registers_resolved(&[src1_reg, src2_reg])?;

        let record = self.activation_records.last_mut().unwrap();
        let src1 = &record.registers[src1_reg];
        let src2 = &record.registers[src2_reg];

        let result_value = match (src1, src2) {
            (Value::I64(a), Value::I64(b)) => Value::I64(a + b),
            (Value::I32(a), Value::I32(b)) => Value::I32(a + b),
            (Value::I16(a), Value::I16(b)) => Value::I16(a + b),
            (Value::I8(a), Value::I8(b)) => Value::I8(a + b),
            (Value::U8(a), Value::U8(b)) => Value::U8(a + *b),
            (Value::U16(a), Value::U16(b)) => Value::U16(a + *b),
            (Value::U32(a), Value::U32(b)) => Value::U32(a + *b),
            (Value::U64(a), Value::U64(b)) => Value::U64(a + *b),
            // Share + Share (offline addition)
            (
                Value::Share(ty_left @ ShareType::SecretInt { .. }, data1),
                Value::Share(ty_right @ ShareType::SecretInt { .. }, data2),
            ) => {
                // Debug: log share IDs before addition
                let lhs_share = Self::decode_share_bytes(data1)?;
                let rhs_share = Self::decode_share_bytes(data2)?;
                // tracing::info!(
                //     "ADD Share+Share: lhs.id={}, rhs.id={}, lhs.degree={}, rhs.degree={}",
                //     lhs_share.id,
                //     rhs_share.id,
                //     lhs_share.degree,
                //     rhs_share.degree
                // );
                let bytes = Self::secret_int_binary_op(
                    "addition",
                    *ty_left,
                    data1,
                    *ty_right,
                    data2,
                    |lhs, rhs| lhs + rhs,
                )?;
                Value::Share(*ty_left, bytes)
            }
            (
                Value::Share(ty_left @ ShareType::SecretFixedPoint { .. }, data1),
                Value::Share(ty_right @ ShareType::SecretFixedPoint { .. }, data2),
            ) => {
                let bytes = Self::secret_fixed_point_binary_op(
                    "addition",
                    *ty_left,
                    data1,
                    *ty_right,
                    data2,
                    |lhs, rhs| lhs + rhs,
                )?;
                Value::Share(*ty_left, bytes)
            }
            // Share + Scalar (offline - local computation)
            (Value::Share(ty @ ShareType::SecretInt { .. }, data), Value::I64(scalar)) => {
                tracing::info!("ADD Share+Scalar: scalar={}", scalar);
                let bytes = Self::secret_int_add_scalar(*ty, data, *scalar)?;
                Value::Share(*ty, bytes)
            }
            (Value::I64(scalar), Value::Share(ty @ ShareType::SecretInt { .. }, data)) => {
                tracing::info!("ADD Scalar+Share: scalar={}", scalar);
                let bytes = Self::secret_int_add_scalar(*ty, data, *scalar)?;
                Value::Share(*ty, bytes)
            }
            (Value::Share(ty @ ShareType::SecretFixedPoint { .. }, data), Value::I64(scalar)) => {
                let bytes = Self::secret_fixed_point_add_scalar(*ty, data, *scalar)?;
                Value::Share(*ty, bytes)
            }
            (Value::I64(scalar), Value::Share(ty @ ShareType::SecretFixedPoint { .. }, data)) => {
                let bytes = Self::secret_fixed_point_add_scalar(*ty, data, *scalar)?;
                Value::Share(*ty, bytes)
            }
            _ => return Err("Type error in ADD operation".to_string()),
        };

        if hooks_enabled {
            let old_value = record.registers[dest_reg].clone();
            record.registers[dest_reg] = result_value.clone();
            let event = HookEvent::RegisterWrite(dest_reg, old_value, result_value);
            self.hook_manager.trigger(&event, self)?;
        } else {
            record.registers[dest_reg] = result_value;
        }
        Ok(())
    }

    /// Execute SUB instruction
    fn execute_sub(
        &mut self,
        dest_reg: usize,
        src1_reg: usize,
        src2_reg: usize,
        hooks_enabled: bool,
    ) -> Result<(), String> {
        // Ensure source registers are resolved (flush pending reveals if needed)
        self.ensure_registers_resolved(&[src1_reg, src2_reg])?;

        let record = self.activation_records.last_mut().unwrap();
        let src1 = &record.registers[src1_reg];
        let src2 = &record.registers[src2_reg];

        let result_value = match (src1, src2) {
            (Value::I64(a), Value::I64(b)) => Value::I64(a - b),
            (Value::I32(a), Value::I32(b)) => Value::I32(a - b),
            (Value::I16(a), Value::I16(b)) => Value::I16(a - b),
            (Value::I8(a), Value::I8(b)) => Value::I8(a - b),
            (Value::U8(a), Value::U8(b)) => Value::U8(a.saturating_sub(*b)),
            (Value::U16(a), Value::U16(b)) => Value::U16(a.saturating_sub(*b)),
            (Value::U32(a), Value::U32(b)) => Value::U32(a.saturating_sub(*b)),
            (Value::U64(a), Value::U64(b)) => Value::U64(a.saturating_sub(*b)),
            // Share - Share (offline subtraction)
            (
                Value::Share(ty_left @ ShareType::SecretInt { .. }, data1),
                Value::Share(ty_right @ ShareType::SecretInt { .. }, data2),
            ) => {
                let bytes = Self::secret_int_binary_op(
                    "subtraction",
                    *ty_left,
                    data1,
                    *ty_right,
                    data2,
                    |lhs, rhs| lhs - rhs,
                )?;
                Value::Share(*ty_left, bytes)
            }
            (
                Value::Share(ty_left @ ShareType::SecretFixedPoint { .. }, data1),
                Value::Share(ty_right @ ShareType::SecretFixedPoint { .. }, data2),
            ) => {
                let bytes = Self::secret_fixed_point_binary_op(
                    "subtraction",
                    *ty_left,
                    data1,
                    *ty_right,
                    data2,
                    |lhs, rhs| lhs - rhs,
                )?;
                Value::Share(*ty_left, bytes)
            }
            // Share - Scalar (offline - local computation)
            (Value::Share(ty @ ShareType::SecretInt { .. }, data), Value::I64(scalar)) => {
                let bytes = Self::secret_int_sub_scalar(*ty, data, *scalar)?;
                Value::Share(*ty, bytes)
            }
            // Scalar - Share (offline - local computation)
            (Value::I64(scalar), Value::Share(ty @ ShareType::SecretInt { .. }, data)) => {
                let bytes = Self::scalar_sub_secret_int(*ty, *scalar, data)?;
                Value::Share(*ty, bytes)
            }
            (Value::Share(ty @ ShareType::SecretFixedPoint { .. }, data), Value::I64(scalar)) => {
                let bytes = Self::secret_fixed_point_sub_scalar(*ty, data, *scalar)?;
                Value::Share(*ty, bytes)
            }
            (Value::I64(scalar), Value::Share(ty @ ShareType::SecretFixedPoint { .. }, data)) => {
                let bytes = Self::scalar_sub_secret_fixed_point(*ty, *scalar, data)?;
                Value::Share(*ty, bytes)
            }
            _ => return Err("Type error in SUB operation".to_string()),
        };

        if hooks_enabled {
            let old_value = record.registers[dest_reg].clone();
            record.registers[dest_reg] = result_value.clone();
            let event = HookEvent::RegisterWrite(dest_reg, old_value, result_value);
            self.hook_manager.trigger(&event, self)?;
        } else {
            record.registers[dest_reg] = result_value;
        }
        Ok(())
    }

    /// Execute MUL instruction
    fn execute_mul(
        &mut self,
        dest_reg: usize,
        src1_reg: usize,
        src2_reg: usize,
        hooks_enabled: bool,
    ) -> Result<(), String> {
        // Ensure source registers are resolved (flush pending reveals if needed)
        self.ensure_registers_resolved(&[src1_reg, src2_reg])?;

        // Clone operands first to avoid borrow issues with MPC engine access
        let (left, right) = {
            let record = self.activation_records.last().unwrap();
            (
                record.registers[src1_reg].clone(),
                record.registers[src2_reg].clone(),
            )
        };

        let computed: Value = match (&left, &right) {
            (Value::I64(a), Value::I64(b)) => Value::I64(a * b),
            (Value::I32(a), Value::I32(b)) => Value::I32(a * b),
            (Value::I16(a), Value::I16(b)) => Value::I16(a * b),
            (Value::I8(a), Value::I8(b)) => Value::I8(a * b),
            (Value::U8(a), Value::U8(b)) => Value::U8(a * *b),
            (Value::U16(a), Value::U16(b)) => Value::U16(a * *b),
            (Value::U32(a), Value::U32(b)) => Value::U32(a * *b),
            (Value::U64(a), Value::U64(b)) => Value::U64(a * *b),
            // Share * Share (online multiplication)
            (
                Value::Share(ty1 @ ShareType::SecretInt { .. }, data1),
                Value::Share(ShareType::SecretInt { .. }, data2),
            ) => {
                let engine = self
                    .mpc_engine()
                    .ok_or_else(|| "MPC engine not configured".to_string())?;
                if !engine.is_ready() {
                    return Err("MPC engine configured but not ready".to_string());
                }
                let product = engine
                    .multiply_share(*ty1, data1, data2)
                    .map_err(|e| format!("MPC multiply_share failed: {}", e))?;
                Value::Share(*ty1, product)
            }
            (
                Value::Share(ty1 @ ShareType::SecretFixedPoint { .. }, data1),
                Value::Share(ShareType::SecretFixedPoint { .. }, data2),
            ) => {
                let engine = self
                    .mpc_engine()
                    .ok_or_else(|| "MPC engine not configured".to_string())?;
                if !engine.is_ready() {
                    return Err("MPC engine configured but not ready".to_string());
                }
                let product = engine
                    .multiply_share(*ty1, data1, data2)
                    .map_err(|e| format!("MPC multiply_share failed: {}", e))?;
                Value::Share(*ty1, product)
            }
            // Share * Scalar (offline - local computation, no MPC required)
            (Value::Share(ty @ ShareType::SecretInt { .. }, data), Value::I64(scalar)) => {
                let bytes = Self::secret_int_mul_scalar(*ty, data, *scalar)?;
                Value::Share(*ty, bytes)
            }
            (Value::I64(scalar), Value::Share(ty @ ShareType::SecretInt { .. }, data)) => {
                let bytes = Self::secret_int_mul_scalar(*ty, data, *scalar)?;
                Value::Share(*ty, bytes)
            }
            (Value::Share(ty @ ShareType::SecretFixedPoint { .. }, data), Value::I64(scalar)) => {
                let bytes = Self::secret_fixed_point_mul_scalar(*ty, data, *scalar)?;
                Value::Share(*ty, bytes)
            }
            (Value::I64(scalar), Value::Share(ty @ ShareType::SecretFixedPoint { .. }, data)) => {
                let bytes = Self::secret_fixed_point_mul_scalar(*ty, data, *scalar)?;
                Value::Share(*ty, bytes)
            }
            _ => return Err("Type error in MUL operation".to_string()),
        };

        let record = self.activation_records.last_mut().unwrap();
        if hooks_enabled {
            let old_value = record.registers[dest_reg].clone();
            record.registers[dest_reg] = computed.clone();
            let event = HookEvent::RegisterWrite(dest_reg, old_value, computed);
            self.hook_manager.trigger(&event, self)?;
        } else {
            record.registers[dest_reg] = computed;
        }
        Ok(())
    }

    /// Execute DIV instruction
    fn execute_div(
        &mut self,
        dest_reg: usize,
        src1_reg: usize,
        src2_reg: usize,
        hooks_enabled: bool,
    ) -> Result<(), String> {
        // Ensure source registers are resolved (flush pending reveals if needed)
        self.ensure_registers_resolved(&[src1_reg, src2_reg])?;

        let record = self.activation_records.last_mut().unwrap();
        let src1 = &record.registers[src1_reg];
        let src2 = &record.registers[src2_reg];

        let result_value = match (src1, src2) {
            (Value::I64(a), Value::I64(b)) => {
                if *b == 0 {
                    return Err("Division by zero".to_string());
                }
                Value::I64(a / b)
            }
            (Value::I32(a), Value::I32(b)) => {
                if *b == 0 {
                    return Err("Division by zero".to_string());
                }
                Value::I32(a / b)
            }
            (Value::I16(a), Value::I16(b)) => {
                if *b == 0 {
                    return Err("Division by zero".to_string());
                }
                Value::I16(a / b)
            }
            (Value::I8(a), Value::I8(b)) => {
                if *b == 0 {
                    return Err("Division by zero".to_string());
                }
                Value::I8(a / b)
            }
            (Value::U8(a), Value::U8(b)) => {
                if *b == 0 {
                    return Err("Division by zero".to_string());
                }
                Value::U8(a / *b)
            }
            (Value::U16(a), Value::U16(b)) => {
                if *b == 0 {
                    return Err("Division by zero".to_string());
                }
                Value::U16(a / *b)
            }
            (Value::U32(a), Value::U32(b)) => {
                if *b == 0 {
                    return Err("Division by zero".to_string());
                }
                Value::U32(a / *b)
            }
            (Value::U64(a), Value::U64(b)) => {
                if *b == 0 {
                    return Err("Division by zero".to_string());
                }
                Value::U64(a / *b)
            }
            // Float / I64 - for floating-point arithmetic
            (Value::Float(a), Value::I64(b)) => {
                if *b == 0 {
                    return Err("Division by zero".to_string());
                }
                Value::Float(F64(a.0 / *b as f64))
            }
            // I64 / Float - symmetric case
            (Value::I64(a), Value::Float(b)) => {
                if b.0 == 0.0 {
                    return Err("Division by zero".to_string());
                }
                Value::Float(F64(*a as f64 / b.0))
            }
            // Float / Float
            (Value::Float(a), Value::Float(b)) => {
                if b.0 == 0.0 {
                    return Err("Division by zero".to_string());
                }
                Value::Float(F64(a.0 / b.0))
            }
            // Share / Share (online division) - TODO: requires MPC protocol
            (
                Value::Share(ShareType::SecretInt { .. }, _data1),
                Value::Share(ShareType::SecretInt { .. }, _data2),
            ) => todo!("Share / Share division requires MPC protocol"),
            (
                Value::Share(ShareType::SecretFixedPoint { .. }, _data1),
                Value::Share(ShareType::SecretFixedPoint { .. }, _data2),
            ) => todo!("Share / Share division requires MPC protocol"),
            // Share / Scalar (offline - local computation via field inverse)
            (Value::Share(ty @ ShareType::SecretInt { .. }, data), Value::I64(scalar)) => {
                let bytes = Self::secret_int_div_scalar(*ty, data, *scalar)?;
                Value::Share(*ty, bytes)
            }
            (Value::Share(ty @ ShareType::SecretFixedPoint { .. }, data), Value::I64(scalar)) => {
                let bytes = Self::secret_fixed_point_div_scalar(*ty, data, *scalar)?;
                Value::Share(*ty, bytes)
            }
            _ => return Err("Type error in DIV operation".to_string()),
        };

        if hooks_enabled {
            let old_value = record.registers[dest_reg].clone();
            record.registers[dest_reg] = result_value.clone();
            let event = HookEvent::RegisterWrite(dest_reg, old_value, result_value);
            self.hook_manager.trigger(&event, self)?;
        } else {
            record.registers[dest_reg] = result_value;
        }
        Ok(())
    }

    /// Execute MOD instruction
    fn execute_mod(
        &mut self,
        dest_reg: usize,
        src1_reg: usize,
        src2_reg: usize,
        hooks_enabled: bool,
    ) -> Result<(), String> {
        // Ensure source registers are resolved (flush pending reveals if needed)
        self.ensure_registers_resolved(&[src1_reg, src2_reg])?;

        let record = self.activation_records.last_mut().unwrap();
        let src1 = &record.registers[src1_reg];
        let src2 = &record.registers[src2_reg];

        let result_value = match (src1, src2) {
            (Value::I64(a), Value::I64(b)) => {
                if *b == 0 {
                    return Err("Modulo by zero".to_string());
                }
                Value::I64(a % b)
            }
            (Value::I32(a), Value::I32(b)) => {
                if *b == 0 {
                    return Err("Modulo by zero".to_string());
                }
                Value::I32(a % b)
            }
            (Value::I16(a), Value::I16(b)) => {
                if *b == 0 {
                    return Err("Modulo by zero".to_string());
                }
                Value::I16(a % b)
            }
            (Value::I8(a), Value::I8(b)) => {
                if *b == 0 {
                    return Err("Modulo by zero".to_string());
                }
                Value::I8(a % b)
            }
            (Value::U8(a), Value::U8(b)) => {
                if *b == 0 {
                    return Err("Modulo by zero".to_string());
                }
                Value::U8(a % *b)
            }
            (Value::U16(a), Value::U16(b)) => {
                if *b == 0 {
                    return Err("Modulo by zero".to_string());
                }
                Value::U16(a % *b)
            }
            (Value::U32(a), Value::U32(b)) => {
                if *b == 0 {
                    return Err("Modulo by zero".to_string());
                }
                Value::U32(a % *b)
            }
            (Value::U64(a), Value::U64(b)) => {
                if *b == 0 {
                    return Err("Modulo by zero".to_string());
                }
                Value::U64(a % *b)
            }
            // Share % Share (online modulo) - TODO
            (
                Value::Share(ShareType::SecretInt { .. }, _data1),
                Value::Share(ShareType::SecretInt { .. }, _data2),
            ) => todo!(),
            (
                Value::Share(ShareType::SecretFixedPoint { .. }, _data1),
                Value::Share(ShareType::SecretFixedPoint { .. }, _data2),
            ) => todo!(),
            _ => return Err("Type error in MOD operation".to_string()),
        };

        if hooks_enabled {
            let old_value = record.registers[dest_reg].clone();
            record.registers[dest_reg] = result_value.clone();
            let event = HookEvent::RegisterWrite(dest_reg, old_value, result_value);
            self.hook_manager.trigger(&event, self)?;
        } else {
            record.registers[dest_reg] = result_value;
        }
        Ok(())
    }

    /// Execute AND instruction
    fn execute_and(
        &mut self,
        dest_reg: usize,
        src1_reg: usize,
        src2_reg: usize,
        hooks_enabled: bool,
    ) -> Result<(), String> {
        // Ensure source registers are resolved (flush pending reveals if needed)
        self.ensure_registers_resolved(&[src1_reg, src2_reg])?;

        let record = self.activation_records.last_mut().unwrap();
        let src1 = &record.registers[src1_reg];
        let src2 = &record.registers[src2_reg];

        let result_value = match (src1, src2) {
            (Value::I64(a), Value::I64(b)) => Value::I64(a & b),
            (Value::Bool(a), Value::Bool(b)) => Value::Bool(*a && *b),
            // Share & Share - TODO
            (
                Value::Share(ShareType::SecretInt { .. }, _data1),
                Value::Share(ShareType::SecretInt { .. }, _data2),
            ) => todo!(),
            _ => return Err("Type error in AND operation".to_string()),
        };

        if hooks_enabled {
            let old_value = record.registers[dest_reg].clone();
            record.registers[dest_reg] = result_value.clone();
            let event = HookEvent::RegisterWrite(dest_reg, old_value, result_value);
            self.hook_manager.trigger(&event, self)?;
        } else {
            record.registers[dest_reg] = result_value;
        }
        Ok(())
    }

    /// Execute OR instruction
    fn execute_or(
        &mut self,
        dest_reg: usize,
        src1_reg: usize,
        src2_reg: usize,
        hooks_enabled: bool,
    ) -> Result<(), String> {
        // Ensure source registers are resolved (flush pending reveals if needed)
        self.ensure_registers_resolved(&[src1_reg, src2_reg])?;

        let record = self.activation_records.last_mut().unwrap();
        let src1 = &record.registers[src1_reg];
        let src2 = &record.registers[src2_reg];

        let result_value = match (src1, src2) {
            (Value::I64(a), Value::I64(b)) => Value::I64(a | b),
            (Value::Bool(a), Value::Bool(b)) => Value::Bool(*a || *b),
            // Share | Share - TODO
            (
                Value::Share(ShareType::SecretInt { .. }, _data1),
                Value::Share(ShareType::SecretInt { .. }, _data2),
            ) => todo!(),
            _ => return Err("Type error in OR operation".to_string()),
        };

        if hooks_enabled {
            let old_value = record.registers[dest_reg].clone();
            record.registers[dest_reg] = result_value.clone();
            let event = HookEvent::RegisterWrite(dest_reg, old_value, result_value);
            self.hook_manager.trigger(&event, self)?;
        } else {
            record.registers[dest_reg] = result_value;
        }
        Ok(())
    }

    /// Execute XOR instruction
    fn execute_xor(
        &mut self,
        dest_reg: usize,
        src1_reg: usize,
        src2_reg: usize,
        hooks_enabled: bool,
    ) -> Result<(), String> {
        // Ensure source registers are resolved (flush pending reveals if needed)
        self.ensure_registers_resolved(&[src1_reg, src2_reg])?;

        let record = self.activation_records.last_mut().unwrap();
        let src1 = &record.registers[src1_reg];
        let src2 = &record.registers[src2_reg];

        let result_value = match (src1, src2) {
            (Value::I64(a), Value::I64(b)) => Value::I64(a ^ b),
            (Value::Bool(a), Value::Bool(b)) => Value::Bool(a ^ b),
            // Share ^ Share - TODO
            (
                Value::Share(ShareType::SecretInt { .. }, _data1),
                Value::Share(ShareType::SecretInt { .. }, _data2),
            ) => todo!(),
            _ => return Err("Type error in XOR operation".to_string()),
        };

        if hooks_enabled {
            let old_value = record.registers[dest_reg].clone();
            record.registers[dest_reg] = result_value.clone();
            let event = HookEvent::RegisterWrite(dest_reg, old_value, result_value);
            self.hook_manager.trigger(&event, self)?;
        } else {
            record.registers[dest_reg] = result_value;
        }
        Ok(())
    }

    /// Execute NOT instruction
    fn execute_not(
        &mut self,
        dest_reg: usize,
        src_reg: usize,
        hooks_enabled: bool,
    ) -> Result<(), String> {
        // Ensure source register is resolved (flush pending reveals if needed)
        self.ensure_resolved(src_reg)?;

        let record = self.activation_records.last_mut().unwrap();
        let src = &record.registers[src_reg];

        let result_value = match src {
            Value::I64(a) => Value::I64(!a),
            Value::Bool(a) => Value::Bool(!a),
            // ~Share - TODO
            Value::Share(ShareType::SecretInt { .. }, _data) => todo!(),
            _ => return Err("Type error in NOT operation".to_string()),
        };

        if hooks_enabled {
            let old_value = record.registers[dest_reg].clone();
            record.registers[dest_reg] = result_value.clone();
            let event = HookEvent::RegisterWrite(dest_reg, old_value, result_value);
            self.hook_manager.trigger(&event, self)?;
        } else {
            record.registers[dest_reg] = result_value;
        }
        Ok(())
    }

    /// Execute SHL instruction
    fn execute_shl(
        &mut self,
        dest_reg: usize,
        src_reg: usize,
        amount_reg: usize,
        hooks_enabled: bool,
    ) -> Result<(), String> {
        // Ensure source registers are resolved (flush pending reveals if needed)
        self.ensure_registers_resolved(&[src_reg, amount_reg])?;

        let record = self.activation_records.last_mut().unwrap();
        let src = &record.registers[src_reg];
        let amount = &record.registers[amount_reg];

        let result_value = match (src, amount) {
            (Value::I64(a), Value::I64(b)) => Value::I64(a << b),
            // Share << Int - TODO
            (Value::Share(ShareType::SecretInt { .. }, _data), Value::I64(_b)) => todo!(),
            _ => return Err("Type error in SHL operation".to_string()),
        };

        if hooks_enabled {
            let old_value = record.registers[dest_reg].clone();
            record.registers[dest_reg] = result_value.clone();
            let event = HookEvent::RegisterWrite(dest_reg, old_value, result_value);
            self.hook_manager.trigger(&event, self)?;
        } else {
            record.registers[dest_reg] = result_value;
        }
        Ok(())
    }

    /// Execute SHR instruction
    fn execute_shr(
        &mut self,
        dest_reg: usize,
        src_reg: usize,
        amount_reg: usize,
        hooks_enabled: bool,
    ) -> Result<(), String> {
        // Ensure source registers are resolved (flush pending reveals if needed)
        self.ensure_registers_resolved(&[src_reg, amount_reg])?;

        let record = self.activation_records.last_mut().unwrap();
        let src = &record.registers[src_reg];
        let amount = &record.registers[amount_reg];

        let result_value = match (src, amount) {
            (Value::I64(a), Value::I64(b)) => Value::I64(a >> b),
            // Share >> Int - TODO
            (Value::Share(ShareType::SecretInt { .. }, _data), Value::I64(_b)) => todo!(),
            _ => return Err("Type error in SHR operation".to_string()),
        };

        if hooks_enabled {
            let old_value = record.registers[dest_reg].clone();
            record.registers[dest_reg] = result_value.clone();
            let event = HookEvent::RegisterWrite(dest_reg, old_value, result_value);
            self.hook_manager.trigger(&event, self)?;
        } else {
            record.registers[dest_reg] = result_value;
        }
        Ok(())
    }
}

// ============================================================================
// Jump Instruction Handlers
// ============================================================================

impl VMState {
    /// Execute JMP instruction
    #[inline]
    fn execute_jmp(&mut self, label: &str, use_resolved: bool, ip: usize) -> Result<(), String> {
        let target = self.resolve_jump_target(label, use_resolved, ip, "JMP")?;
        self.activation_records.last_mut().unwrap().instruction_pointer = target;
        Ok(())
    }

    /// Execute JMPEQ instruction
    #[inline]
    fn execute_jmpeq(&mut self, label: &str, use_resolved: bool, ip: usize) -> Result<(), String> {
        if self.activation_records.last().unwrap().compare_flag == 0 {
            let target = self.resolve_jump_target(label, use_resolved, ip, "JMPEQ")?;
            self.activation_records.last_mut().unwrap().instruction_pointer = target;
        }
        Ok(())
    }

    /// Execute JMPNEQ instruction
    #[inline]
    fn execute_jmpneq(&mut self, label: &str, use_resolved: bool, ip: usize) -> Result<(), String> {
        if self.activation_records.last().unwrap().compare_flag != 0 {
            let target = self.resolve_jump_target(label, use_resolved, ip, "JMPNEQ")?;
            self.activation_records.last_mut().unwrap().instruction_pointer = target;
        }
        Ok(())
    }

    /// Execute JMPLT instruction
    #[inline]
    fn execute_jmplt(&mut self, label: &str, use_resolved: bool, ip: usize) -> Result<(), String> {
        if self.activation_records.last().unwrap().compare_flag == -1 {
            let target = self.resolve_jump_target(label, use_resolved, ip, "JMPLT")?;
            self.activation_records.last_mut().unwrap().instruction_pointer = target;
        }
        Ok(())
    }

    /// Execute JMPGT instruction
    #[inline]
    fn execute_jmpgt(&mut self, label: &str, use_resolved: bool, ip: usize) -> Result<(), String> {
        if self.activation_records.last().unwrap().compare_flag == 1 {
            let target = self.resolve_jump_target(label, use_resolved, ip, "JMPGT")?;
            self.activation_records.last_mut().unwrap().instruction_pointer = target;
        }
        Ok(())
    }

    /// Resolve jump target from resolved instruction or label
    fn resolve_jump_target(
        &self,
        label: &str,
        use_resolved: bool,
        ip: usize,
        instr_name: &str,
    ) -> Result<usize, String> {
        if use_resolved {
            let record = self.activation_records.last().unwrap();
            let resolved = &record.resolved_instructions.as_ref().unwrap()[ip];
            match resolved {
                ResolvedInstruction::JMP(target)
                | ResolvedInstruction::JMPEQ(target)
                | ResolvedInstruction::JMPNEQ(target)
                | ResolvedInstruction::JMPLT(target)
                | ResolvedInstruction::JMPGT(target) => Ok(*target),
                _ => Err(format!("Expected {} instruction, got {:?}", instr_name, resolved)),
            }
        } else {
            let function_name = &self.activation_records.last().unwrap().function_name;
            match self.functions.get(function_name) {
                Some(Function::VM(vm_func)) => vm_func
                    .labels
                    .get(label)
                    .copied()
                    .ok_or_else(|| format!("Label '{}' not found", label)),
                _ => Err(format!("Function {} not found", function_name)),
            }
        }
    }
}

// ============================================================================
// Function Call and Return Handlers
// ============================================================================

impl VMState {
    /// Execute CALL instruction
    fn execute_call(
        &mut self,
        function_name: &str,
        hooks_enabled: bool,
        initial_activation_depth: usize,
    ) -> Result<Option<Value>, String> {
        // Get arguments from stack
        let args: SmallVec<[Value; 8]> = self.activation_records.last().unwrap().stack.clone();

        let function = self
            .functions
            .get(function_name)
            .ok_or_else(|| format!("Function '{}' not found", function_name))?
            .clone();

        let activation_count_before = self.activation_records.len();

        // Clear caller's stack
        self.clear_stack_with_hooks(hooks_enabled)?;

        match function {
            Function::VM(vm_func) => {
                self.call_vm_function(function_name, &vm_func, &args, hooks_enabled)?;
            }
            Function::Foreign(foreign_func) => {
                if let Some(result) = self.call_foreign_function_internal(
                    function_name,
                    &foreign_func,
                    &args,
                    hooks_enabled,
                    activation_count_before,
                    initial_activation_depth,
                )? {
                    return Ok(Some(result));
                }
            }
        }

        // Clean up any remaining stack items
        if !self.activation_records.is_empty() {
            self.clear_stack_with_hooks(hooks_enabled)?;
        }

        Ok(None)
    }

    /// Clear the current activation record's stack, triggering hooks if enabled
    fn clear_stack_with_hooks(&mut self, hooks_enabled: bool) -> Result<(), String> {
        let mut popped_values = Vec::new();
        {
            let record = self.activation_records.last_mut().unwrap();
            while let Some(value) = record.stack.pop() {
                popped_values.push(value);
            }
        }

        if hooks_enabled {
            for value in popped_values {
                let event = HookEvent::StackPop(value);
                self.hook_manager.trigger(&event, self)?;
            }
        }
        Ok(())
    }

    /// Call a VM function
    fn call_vm_function(
        &mut self,
        function_name: &str,
        vm_func: &VMFunction,
        args: &SmallVec<[Value; 8]>,
        hooks_enabled: bool,
    ) -> Result<(), String> {
        if vm_func.parameters.len() != args.len() {
            return Err(format!(
                "Function {} expects {} arguments but got {}",
                function_name,
                vm_func.parameters.len(),
                args.len()
            ));
        }

        // Initialize upvalues
        let mut upvalues = Vec::with_capacity(vm_func.upvalues.len());
        for name in &vm_func.upvalues {
            let value = self.find_upvalue(name).ok_or_else(|| {
                format!("Could not find upvalue {} when calling function", name)
            })?;
            upvalues.push(Upvalue {
                name: name.clone(),
                value,
            });
        }

        if hooks_enabled {
            let closure = Closure {
                function_id: function_name.to_string(),
                upvalues: upvalues.clone(),
            };
            let closure_value = Value::Closure(Arc::new(closure));
            let event = HookEvent::BeforeFunctionCall(closure_value, args.to_vec());
            self.hook_manager.trigger(&event, self)?;
        }

        // Create new activation record
        let new_record = ActivationRecord {
            function_name: function_name.to_string(),
            locals: FxHashMap::default(),
            registers: SmallVec::from_vec(vec![Value::Unit; vm_func.register_count]),
            upvalues,
            instruction_pointer: 0,
            stack: SmallVec::new(),
            compare_flag: 0,
            instructions: SmallVec::from(vm_func.instructions.clone()),
            resolved_instructions: vm_func.resolved_instructions.clone(),
            constant_values: vm_func.constant_values.clone(),
            closure: None,
        };

        let mut record = self.activation_pool.get();
        *record = new_record;
        self.activation_records.push((*record).clone());

        // Initialize parameters
        {
            let record = self.activation_records.last_mut().unwrap();
            for (i, param_name) in vm_func.parameters.iter().enumerate() {
                record.registers[i] = args[i].clone();
                record.locals.insert(param_name.clone(), args[i].clone());
            }
        }

        // Clean up previous activation record's stack
        if self.activation_records.len() >= 2 {
            let prev_idx = self.activation_records.len() - 2;
            let args_len = args.len();
            let mut popped = Vec::new();
            {
                let prev_record = &mut self.activation_records[prev_idx];
                for _ in 0..args_len {
                    if let Some(value) = prev_record.stack.pop() {
                        popped.push(value);
                    }
                }
                prev_record.stack.clear();
            }

            if hooks_enabled {
                for value in popped {
                    let event = HookEvent::StackPop(value);
                    self.hook_manager.trigger(&event, self)?;
                }
            }
        }

        Ok(())
    }

    /// Call a foreign function
    fn call_foreign_function_internal(
        &mut self,
        function_name: &str,
        foreign_func: &crate::foreign_functions::ForeignFunction,
        args: &SmallVec<[Value; 8]>,
        hooks_enabled: bool,
        activation_count_before: usize,
        _initial_activation_depth: usize,
    ) -> Result<Option<Value>, String> {
        let func_value = Value::String(format!("<foreign function {}>", function_name));

        if hooks_enabled {
            let event = HookEvent::BeforeFunctionCall(func_value.clone(), args.to_vec());
            self.hook_manager.trigger(&event, self)?;
        }

        let context = ForeignFunctionContext {
            args,
            vm_state: self,
        };

        let result = (foreign_func.func)(context)?;

        // Check if the foreign function pushed new activation records
        if self.activation_records.len() > activation_count_before {
            return Ok(None); // Continue execution in the new context
        }

        if self.activation_records.is_empty() {
            return Ok(Some(result));
        }

        // Store result and clean up
        // First, update registers and collect stack items
        let (old_value, popped) = {
            let record = self.activation_records.last_mut().unwrap();
            let old_value = record.registers[0].clone();
            record.registers[0] = result.clone();

            // Clean up stack
            let mut popped = SmallVec::<[Value; 8]>::new();
            for _ in 0..args.len() {
                if let Some(value) = record.stack.pop() {
                    popped.push(value);
                }
            }
            record.stack.clear();
            (old_value, popped)
        };

        // Now trigger hooks (after releasing the mutable borrow)
        if hooks_enabled {
            let reg_event = HookEvent::RegisterWrite(0, old_value, result.clone());
            self.hook_manager.trigger(&reg_event, self)?;

            for value in popped {
                let event = HookEvent::StackPop(value);
                self.hook_manager.trigger(&event, self)?;
            }
        }

        if hooks_enabled {
            let fn_event = HookEvent::AfterFunctionCall(func_value, result);
            self.hook_manager.trigger(&fn_event, self)?;
        }

        Ok(None)
    }

    /// Execute RET instruction
    fn execute_ret(
        &mut self,
        reg: usize,
        instruction: &Instruction,
        hooks_enabled: bool,
    ) -> Result<Option<Value>, String> {
        // Ensure return register is resolved (flush pending reveals if needed)
        self.ensure_resolved(reg)?;

        // Also flush any remaining pending reveals before returning
        // This ensures clean state when exiting a function
        self.flush_pending_reveals()?;

        let (return_value, returning_from) = {
            let record = self.activation_records.last().unwrap();
            (record.registers[reg].clone(), record.function_name.clone())
        };

        // Handle closure upvalue updates
        self.update_closure_upvalues();

        // If only one activation record, this is the final return
        if self.activation_records.len() <= 1 {
            if hooks_enabled {
                let event = HookEvent::AfterInstructionExecute(instruction.clone());
                self.hook_manager.trigger(&event, self)?;
            }
            return Ok(Some(return_value));
        }

        // Pop current record and set result in parent
        self.activation_records.pop();

        let parent_record = self.activation_records.last_mut().unwrap();
        if hooks_enabled {
            let old_value = parent_record.registers[0].clone();
            parent_record.registers[0] = return_value.clone();

            let event = HookEvent::RegisterWrite(0, old_value, return_value.clone());
            self.hook_manager.trigger(&event, self)?;

            let closure_value = Value::String(format!("<function {}>", returning_from));
            let event = HookEvent::AfterFunctionCall(closure_value, return_value);
            self.hook_manager.trigger(&event, self)?;
        } else {
            parent_record.registers[0] = return_value;
        }

        Ok(None)
    }

    /// Update closure upvalues when returning from a closure
    fn update_closure_upvalues(&mut self) {
        let record = self.activation_records.last_mut().unwrap();
        if let Some(Value::Closure(closure_arc)) = &record.closure {
            let mut new_closure = (**closure_arc).clone();
            new_closure.upvalues = record.upvalues.clone();
            record.closure = Some(Value::Closure(Arc::new(new_closure)));
        }
    }

    /// Execute PUSHARG instruction
    #[inline]
    fn execute_pusharg(&mut self, reg: usize, hooks_enabled: bool) -> Result<(), String> {
        // Ensure register is resolved (flush pending reveals if needed)
        self.ensure_resolved(reg)?;

        let value = self.activation_records.last().unwrap().registers[reg].clone();
        self.activation_records.last_mut().unwrap().stack.push(value.clone());

        if hooks_enabled {
            let event = HookEvent::StackPush(value);
            self.hook_manager.trigger(&event, self)?;
        }
        Ok(())
    }

    /// Execute CMP instruction
    fn execute_cmp(&mut self, reg1: usize, reg2: usize) -> Result<(), String> {
        // Ensure source registers are resolved (flush pending reveals if needed)
        self.ensure_registers_resolved(&[reg1, reg2])?;

        let record = self.activation_records.last_mut().unwrap();
        let val1 = &record.registers[reg1];
        let val2 = &record.registers[reg2];

        let compare_result = match (val1, val2) {
            (Value::I64(a), Value::I64(b)) => impl_cmp!(a, b),
            (Value::I32(a), Value::I32(b)) => impl_cmp!(a, b),
            (Value::I16(a), Value::I16(b)) => impl_cmp!(a, b),
            (Value::I8(a), Value::I8(b)) => impl_cmp!(a, b),
            (Value::U8(a), Value::U8(b)) => impl_cmp!(a, b),
            (Value::U16(a), Value::U16(b)) => impl_cmp!(a, b),
            (Value::U32(a), Value::U32(b)) => impl_cmp!(a, b),
            (Value::U64(a), Value::U64(b)) => impl_cmp!(a, b),
            (Value::String(a), Value::String(b)) => impl_cmp!(a, b),
            (Value::Bool(a), Value::Bool(b)) => match (a, b) {
                (false, true) => -1,
                (true, false) => 1,
                _ => 0,
            },
            // Share comparison (Int)
            (
                Value::Share(ShareType::SecretInt { .. }, data1),
                Value::Share(ShareType::SecretInt { .. }, data2),
            ) => {
                let mut bytes1 = [0u8; 8];
                let mut bytes2 = [0u8; 8];
                bytes1.copy_from_slice(&data1[0..8]);
                bytes2.copy_from_slice(&data2[0..8]);
                let val1 = i64::from_le_bytes(bytes1);
                let val2 = i64::from_le_bytes(bytes2);
                impl_cmp!(val1, val2)
            }
            // Share comparison (Float)
            (
                Value::Share(ShareType::SecretFixedPoint { .. }, data1),
                Value::Share(ShareType::SecretFixedPoint { .. }, data2),
            ) => {
                let mut bytes1 = [0u8; 8];
                let mut bytes2 = [0u8; 8];
                bytes1.copy_from_slice(&data1[0..8]);
                bytes2.copy_from_slice(&data2[0..8]);
                let val1 = i64::from_le_bytes(bytes1);
                let val2 = i64::from_le_bytes(bytes2);
                impl_cmp!(val1, val2)
            }
            _ => return Err(format!("Cannot compare {:?} and {:?}", val1, val2)),
        };

        record.compare_flag = compare_result;
        Ok(())
    }
}

// ============================================================================
// Foreign Function Interface
// ============================================================================

impl VMState {
    pub fn call_foreign_function(&mut self, name: &str, args: &[Value]) -> Result<Value, String> {
        let function = self
            .functions
            .get(name)
            .ok_or_else(|| format!("Foreign function {} not found", name))?
            .clone();

        match function {
            Function::Foreign(foreign_func) => {
                let func_value = Value::String(format!("<foreign function {}>", name));

                if self.hooks_enabled() {
                    let event = HookEvent::BeforeFunctionCall(func_value.clone(), args.to_vec());
                    self.hook_manager.trigger(&event, self)?;
                }

                let context = ForeignFunctionContext {
                    args,
                    vm_state: self,
                };

                let result = (foreign_func.func)(context)?;

                if self.hooks_enabled() {
                    let event = HookEvent::AfterFunctionCall(func_value, result.clone());
                    self.hook_manager.trigger(&event, self)?;
                }

                Ok(result)
            }
            Function::VM(_) => Err(format!(
                "Expected foreign function, but {} is a VM function",
                name
            )),
        }
    }
}

// ============================================================================
// MPC Engine Integration
// ============================================================================

impl VMState {
    /// Attach an MPC engine to the VM state
    pub fn set_mpc_engine(&mut self, engine: Arc<dyn crate::net::mpc_engine::MpcEngine>) {
        self.mpc_engine = Some(engine);
    }

    /// Get a clone of the configured MPC engine
    #[inline]
    pub fn mpc_engine(&self) -> Option<Arc<dyn crate::net::mpc_engine::MpcEngine>> {
        self.mpc_engine.as_ref().map(Arc::clone)
    }

    /// Ensure an MPC engine is configured and ready
    pub fn ensure_mpc_ready(&self) -> Result<(), String> {
        match &self.mpc_engine {
            Some(engine) if engine.is_ready() => Ok(()),
            Some(_) => Err("MPC engine configured but not ready".to_string()),
            None => Err("MPC engine not configured".to_string()),
        }
    }

    /// Hydrate the VM's client input store from the MPC engine's input store
    ///
    /// This method copies all client input shares from the MPC engine's internal
    /// storage to the VM's ClientInputStore, making them available for the VM
    /// to load during program execution.
    ///
    /// # Requirements
    /// - An MPC engine must be configured via `set_mpc_engine()`
    /// - The MPC engine must implement `MpcEngineClientOps`
    /// - When using HoneyBadgerMpcEngine, client inputs must have been initialized
    ///   via the HB input protocol before calling this method
    ///
    /// # Returns
    /// The number of clients whose inputs were hydrated
    ///
    /// # Example
    /// ```ignore
    /// // After MPC preprocessing and client input initialization
    /// let count = vm.state.hydrate_from_mpc_engine()?;
    /// println!("Hydrated inputs from {} clients", count);
    /// ```
    pub fn hydrate_from_mpc_engine(&self) -> Result<usize, String> {
        use crate::net::hb_engine::HoneyBadgerMpcEngine;

        let engine = self
            .mpc_engine
            .as_ref()
            .ok_or("MPC engine not configured")?;

        // Try to downcast to HoneyBadgerMpcEngine which implements MpcEngineClientOps
        // Note: In the future, we could make this more generic with Any trait
        if let Some(hb_engine) = engine
            .as_any()
            .and_then(|any| any.downcast_ref::<HoneyBadgerMpcEngine>())
        {
            use crate::net::mpc_engine::MpcEngineClientOps;
            hb_engine.hydrate_client_inputs_sync(&self.client_store)
        } else {
            Err("MPC engine does not support client input hydration".to_string())
        }
    }

    /// Clear the client input store and re-hydrate from the MPC engine
    pub fn refresh_client_inputs(&self) -> Result<usize, String> {
        self.client_store.clear();
        self.hydrate_from_mpc_engine()
    }

    /// Get the number of clients that have provided inputs
    #[inline]
    pub fn client_store_len(&self) -> usize {
        self.client_store.len()
    }

    /// Get a sorted list of client IDs
    pub fn client_ids(&self) -> Vec<ClientId> {
        self.client_store.client_ids()
    }

    /// Get a client ID by index (sorted order)
    pub fn client_id_at_index(&self, index: usize) -> Option<ClientId> {
        self.client_store.client_id_at(index)
    }

    /// Access the underlying client store
    pub fn client_store(&self) -> Arc<ClientInputStore> {
        self.client_store.clone()
    }

    /// Load a client's input share from the global client store
    pub fn load_client_share(&self, client_id: ClientId, index: usize) -> Result<Value, String> {
        let share = self
            .client_store
            .get_client_share(client_id, index)
            .ok_or_else(|| format!("No share found for client {} at index {}", client_id, index))?;

        // Removed noisy debug logging
        // tracing::info!(
        //     "load_client_share: client_id={}, index={}, share.id={}, share.degree={}, value={:?}",
        //     client_id, index, share.id, share.degree, share.share[0].into_bigint().0
        // );

        let mut share_bytes = Vec::new();
        share
            .serialize_compressed(&mut share_bytes)
            .map_err(|e| format!("Failed to serialize share: {}", e))?;

        Ok(Value::Share(ShareType::secret_int(64), share_bytes))
    }

    /// Load a client's input share as a fixed-point share from the global client store
    pub fn load_client_share_fixed(&self, client_id: ClientId, index: usize) -> Result<Value, String> {
        let share = self
            .client_store
            .get_client_share(client_id, index)
            .ok_or_else(|| format!("No share found for client {} at index {}", client_id, index))?;

        let mut share_bytes = Vec::new();
        share
            .serialize_compressed(&mut share_bytes)
            .map_err(|e| format!("Failed to serialize share: {}", e))?;

        Ok(Value::Share(ShareType::default_secret_fixed_point(), share_bytes))
    }

    /// Load all of a client's input shares from the global client store
    pub fn load_client_inputs(&self, client_id: ClientId) -> Result<Vec<Value>, String> {
        let shares = self
            .client_store
            .get_client_input(client_id)
            .ok_or_else(|| format!("No inputs found for client {}", client_id))?;

        let mut values = Vec::with_capacity(shares.len());
        for share in shares {
            let mut share_bytes = Vec::new();
            share
                .serialize_compressed(&mut share_bytes)
                .map_err(|e| format!("Failed to serialize share: {}", e))?;
            values.push(Value::Share(ShareType::secret_int(64), share_bytes));
        }

        Ok(values)
    }

    /// Check if a client has provided inputs
    #[inline]
    pub fn has_client_input(&self, client_id: ClientId) -> bool {
        self.client_store.has_client_input(client_id)
    }

    /// Get the number of shares a client has provided
    #[inline]
    pub fn get_client_input_count(&self, client_id: ClientId) -> usize {
        self.client_store.get_client_input_count(client_id)
    }

    /// Send output share(s) to a specific client for private reconstruction
    ///
    /// This uses the MPC engine's output protocol to send this party's share
    /// to a designated client. The client collects shares from all parties
    /// and reconstructs the secret privately.
    ///
    /// # Arguments
    /// * `client_id` - The ID of the client to receive the output
    /// * `share_bytes` - The serialized share data to send
    /// * `input_len` - Number of values being sent
    ///
    /// # Returns
    /// Ok(()) on success, or an error if no MPC engine is configured
    pub fn send_output_to_client(
        &self,
        client_id: ClientId,
        share_bytes: &[u8],
        input_len: usize,
    ) -> Result<(), String> {
        let engine = self
            .mpc_engine
            .as_ref()
            .ok_or_else(|| "No MPC engine configured for output protocol".to_string())?;

        if !engine.is_ready() {
            return Err("MPC engine is not ready".to_string());
        }

        engine.send_output_to_client(client_id, share_bytes, input_len)
    }
}

// ============================================================================
// Secret Share Helpers
// ============================================================================

impl VMState {
    fn decode_share_bytes(bytes: &[u8]) -> Result<RobustShare<Fr>, String> {
        RobustShare::<Fr>::deserialize_compressed(bytes)
            .map_err(|e| format!("Failed to decode share bytes: {}", e))
    }

    fn encode_share_bytes(share: &RobustShare<Fr>) -> Result<Vec<u8>, String> {
        let mut encoded = Vec::new();
        share
            .serialize_compressed(&mut encoded)
            .map_err(|e| format!("Failed to encode share bytes: {}", e))?;
        Ok(encoded)
    }

    pub fn secret_int_from_bytes(ty: ShareType, bytes: &[u8]) -> Result<SecretIntShare, String> {
        match ty {
            ShareType::SecretInt { bit_length } => {
                let share = Self::decode_share_bytes(bytes)?;
                Ok(SecretInt::new(share, bit_length))
            }
            _ => Err("Expected secret integer share type".to_string()),
        }
    }

    fn secret_fixed_point_from_bytes(
        ty: ShareType,
        bytes: &[u8],
    ) -> Result<SecretFixedPointShare, String> {
        match ty {
            ShareType::SecretFixedPoint { precision } => {
                let share = Self::decode_share_bytes(bytes)?;
                Ok(SecretFixedPoint::new_with_precision(share, precision))
            }
            _ => Err("Expected secret fixed-point share type".to_string()),
        }
    }

    fn secret_int_to_bytes(secret: SecretIntShare) -> Result<Vec<u8>, String> {
        Self::encode_share_bytes(secret.share())
    }

    fn secret_fixed_point_to_bytes(secret: SecretFixedPointShare) -> Result<Vec<u8>, String> {
        Self::encode_share_bytes(secret.value())
    }

    fn secret_int_binary_op<F>(
        op_name: &str,
        lhs_ty: ShareType,
        lhs_bytes: &[u8],
        rhs_ty: ShareType,
        rhs_bytes: &[u8],
        op: F,
    ) -> Result<Vec<u8>, String>
    where
        F: FnOnce(SecretIntShare, SecretIntShare) -> Result<SecretIntShare, TypeError>,
    {
        let lhs = Self::secret_int_from_bytes(lhs_ty, lhs_bytes)?;
        let rhs = Self::secret_int_from_bytes(rhs_ty, rhs_bytes)?;
        let result = op(lhs, rhs).map_err(|e| Self::map_type_error(op_name, e))?;
        Self::secret_int_to_bytes(result)
    }

    fn secret_fixed_point_binary_op<F>(
        op_name: &str,
        lhs_ty: ShareType,
        lhs_bytes: &[u8],
        rhs_ty: ShareType,
        rhs_bytes: &[u8],
        op: F,
    ) -> Result<Vec<u8>, String>
    where
        F: FnOnce(
            SecretFixedPointShare,
            SecretFixedPointShare,
        ) -> Result<SecretFixedPointShare, TypeError>,
    {
        let lhs = Self::secret_fixed_point_from_bytes(lhs_ty, lhs_bytes)?;
        let rhs = Self::secret_fixed_point_from_bytes(rhs_ty, rhs_bytes)?;
        let result = op(lhs, rhs).map_err(|e| Self::map_type_error(op_name, e))?;
        Self::secret_fixed_point_to_bytes(result)
    }

    #[inline]
    fn map_type_error(op_name: &str, err: TypeError) -> String {
        format!("Secret share {op_name} failed: {}", err)
    }

    // ============================================================================
    // Scalar Operations on Shares (Local Computation - No MPC Required)
    // ============================================================================

    /// Add a scalar (public value) to a SecretInt share.
    /// This is a local operation: share + scalar = share with updated value.
    fn secret_int_add_scalar(
        ty: ShareType,
        share_bytes: &[u8],
        scalar: i64,
    ) -> Result<Vec<u8>, String> {
        let secret = Self::secret_int_from_bytes(ty, share_bytes)?;
        let share = secret.share();
        let scalar_fr = Fr::from(scalar as u64);
        // Create new share with scalar added to the share value
        let new_share_value = share.share[0] + scalar_fr;
        let new_share = RobustShare::new(new_share_value, share.id, share.degree);
        let bit_length = match ty {
            ShareType::SecretInt { bit_length } => bit_length,
            _ => return Err("Expected SecretInt type".to_string()),
        };
        let result = SecretInt::new(new_share, bit_length);
        Self::secret_int_to_bytes(result)
    }

    /// Subtract a scalar (public value) from a SecretInt share.
    /// This is a local operation: share - scalar = share with updated value.
    fn secret_int_sub_scalar(
        ty: ShareType,
        share_bytes: &[u8],
        scalar: i64,
    ) -> Result<Vec<u8>, String> {
        let secret = Self::secret_int_from_bytes(ty, share_bytes)?;
        let share = secret.share();
        let scalar_fr = Fr::from(scalar as u64);
        let new_share_value = share.share[0] - scalar_fr;
        let new_share = RobustShare::new(new_share_value, share.id, share.degree);
        let bit_length = match ty {
            ShareType::SecretInt { bit_length } => bit_length,
            _ => return Err("Expected SecretInt type".to_string()),
        };
        let result = SecretInt::new(new_share, bit_length);
        Self::secret_int_to_bytes(result)
    }

    /// Subtract a SecretInt share from a scalar (public value).
    /// This is a local operation: scalar - share = negated share + scalar.
    fn scalar_sub_secret_int(
        ty: ShareType,
        scalar: i64,
        share_bytes: &[u8],
    ) -> Result<Vec<u8>, String> {
        let secret = Self::secret_int_from_bytes(ty, share_bytes)?;
        let share = secret.share();
        let scalar_fr = Fr::from(scalar as u64);
        // scalar - share = -(share - scalar) = -share + scalar
        let new_share_value = scalar_fr - share.share[0];
        let new_share = RobustShare::new(new_share_value, share.id, share.degree);
        let bit_length = match ty {
            ShareType::SecretInt { bit_length } => bit_length,
            _ => return Err("Expected SecretInt type".to_string()),
        };
        let result = SecretInt::new(new_share, bit_length);
        Self::secret_int_to_bytes(result)
    }

    /// Multiply a SecretInt share by a scalar (public value).
    /// This is a local operation: share * scalar = share with scaled value.
    fn secret_int_mul_scalar(
        ty: ShareType,
        share_bytes: &[u8],
        scalar: i64,
    ) -> Result<Vec<u8>, String> {
        let secret = Self::secret_int_from_bytes(ty, share_bytes)?;
        let share = secret.share();
        let scalar_fr = Fr::from(scalar as u64);
        let new_share_value = share.share[0] * scalar_fr;
        // Degree doesn't change for scalar multiplication
        let new_share = RobustShare::new(new_share_value, share.id, share.degree);
        let bit_length = match ty {
            ShareType::SecretInt { bit_length } => bit_length,
            _ => return Err("Expected SecretInt type".to_string()),
        };
        let result = SecretInt::new(new_share, bit_length);
        Self::secret_int_to_bytes(result)
    }

    /// Divide a SecretInt share by a scalar (public value).
    /// This is a local operation: share / scalar = share * (1/scalar).
    /// Note: This performs field division, not integer division.
    fn secret_int_div_scalar(
        ty: ShareType,
        share_bytes: &[u8],
        scalar: i64,
    ) -> Result<Vec<u8>, String> {
        if scalar == 0 {
            return Err("Division by zero".to_string());
        }
        let secret = Self::secret_int_from_bytes(ty, share_bytes)?;
        let share = secret.share();
        let scalar_fr = Fr::from(scalar as u64);
        // Compute multiplicative inverse and multiply
        let scalar_inv = scalar_fr
            .inverse()
            .ok_or_else(|| "Scalar has no inverse in field".to_string())?;
        let new_share_value = share.share[0] * scalar_inv;
        let new_share = RobustShare::new(new_share_value, share.id, share.degree);
        let bit_length = match ty {
            ShareType::SecretInt { bit_length } => bit_length,
            _ => return Err("Expected SecretInt type".to_string()),
        };
        let result = SecretInt::new(new_share, bit_length);
        Self::secret_int_to_bytes(result)
    }

    /// Add a scalar to a SecretFixedPoint share.
    fn secret_fixed_point_add_scalar(
        ty: ShareType,
        share_bytes: &[u8],
        scalar: i64,
    ) -> Result<Vec<u8>, String> {
        let secret = Self::secret_fixed_point_from_bytes(ty, share_bytes)?;
        let share = secret.value();
        let scalar_fr = Fr::from(scalar as u64);
        let new_share_value = share.share[0] + scalar_fr;
        let new_share = RobustShare::new(new_share_value, share.id, share.degree);
        let precision = match ty {
            ShareType::SecretFixedPoint { precision } => precision,
            _ => return Err("Expected SecretFixedPoint type".to_string()),
        };
        let result = SecretFixedPoint::new_with_precision(new_share, precision);
        Self::secret_fixed_point_to_bytes(result)
    }

    /// Subtract a scalar from a SecretFixedPoint share.
    fn secret_fixed_point_sub_scalar(
        ty: ShareType,
        share_bytes: &[u8],
        scalar: i64,
    ) -> Result<Vec<u8>, String> {
        let secret = Self::secret_fixed_point_from_bytes(ty, share_bytes)?;
        let share = secret.value();
        let scalar_fr = Fr::from(scalar as u64);
        let new_share_value = share.share[0] - scalar_fr;
        let new_share = RobustShare::new(new_share_value, share.id, share.degree);
        let precision = match ty {
            ShareType::SecretFixedPoint { precision } => precision,
            _ => return Err("Expected SecretFixedPoint type".to_string()),
        };
        let result = SecretFixedPoint::new_with_precision(new_share, precision);
        Self::secret_fixed_point_to_bytes(result)
    }

    /// Subtract a SecretFixedPoint share from a scalar.
    fn scalar_sub_secret_fixed_point(
        ty: ShareType,
        scalar: i64,
        share_bytes: &[u8],
    ) -> Result<Vec<u8>, String> {
        let secret = Self::secret_fixed_point_from_bytes(ty, share_bytes)?;
        let share = secret.value();
        let scalar_fr = Fr::from(scalar as u64);
        let new_share_value = scalar_fr - share.share[0];
        let new_share = RobustShare::new(new_share_value, share.id, share.degree);
        let precision = match ty {
            ShareType::SecretFixedPoint { precision } => precision,
            _ => return Err("Expected SecretFixedPoint type".to_string()),
        };
        let result = SecretFixedPoint::new_with_precision(new_share, precision);
        Self::secret_fixed_point_to_bytes(result)
    }

    /// Multiply a SecretFixedPoint share by a scalar.
    fn secret_fixed_point_mul_scalar(
        ty: ShareType,
        share_bytes: &[u8],
        scalar: i64,
    ) -> Result<Vec<u8>, String> {
        let secret = Self::secret_fixed_point_from_bytes(ty, share_bytes)?;
        let share = secret.value();
        let scalar_fr = Fr::from(scalar as u64);
        let new_share_value = share.share[0] * scalar_fr;
        let new_share = RobustShare::new(new_share_value, share.id, share.degree);
        let precision = match ty {
            ShareType::SecretFixedPoint { precision } => precision,
            _ => return Err("Expected SecretFixedPoint type".to_string()),
        };
        let result = SecretFixedPoint::new_with_precision(new_share, precision);
        Self::secret_fixed_point_to_bytes(result)
    }

    /// Divide a SecretFixedPoint share by a scalar.
    fn secret_fixed_point_div_scalar(
        ty: ShareType,
        share_bytes: &[u8],
        scalar: i64,
    ) -> Result<Vec<u8>, String> {
        if scalar == 0 {
            return Err("Division by zero".to_string());
        }
        let secret = Self::secret_fixed_point_from_bytes(ty, share_bytes)?;
        let share = secret.value();
        let scalar_fr = Fr::from(scalar as u64);
        let scalar_inv = scalar_fr
            .inverse()
            .ok_or_else(|| "Scalar has no inverse in field".to_string())?;
        let new_share_value = share.share[0] * scalar_inv;
        let new_share = RobustShare::new(new_share_value, share.id, share.degree);
        let precision = match ty {
            ShareType::SecretFixedPoint { precision } => precision,
            _ => return Err("Expected SecretFixedPoint type".to_string()),
        };
        let result = SecretFixedPoint::new_with_precision(new_share, precision);
        Self::secret_fixed_point_to_bytes(result)
    }

    // ============================================================================
    // Public Share Arithmetic Methods (for mpc_builtins)
    // ============================================================================

    /// Add two secret shares (public wrapper for mpc_builtins)
    pub fn secret_share_add(
        &self,
        ty: ShareType,
        lhs_bytes: &[u8],
        rhs_bytes: &[u8],
    ) -> Result<Vec<u8>, String> {
        match ty {
            ShareType::SecretInt { .. } => {
                Self::secret_int_binary_op("addition", ty, lhs_bytes, ty, rhs_bytes, |l, r| l + r)
            }
            ShareType::SecretFixedPoint { .. } => {
                Self::secret_fixed_point_binary_op("addition", ty, lhs_bytes, ty, rhs_bytes, |l, r| {
                    l + r
                })
            }
        }
    }

    /// Subtract two secret shares (public wrapper for mpc_builtins)
    pub fn secret_share_sub(
        &self,
        ty: ShareType,
        lhs_bytes: &[u8],
        rhs_bytes: &[u8],
    ) -> Result<Vec<u8>, String> {
        match ty {
            ShareType::SecretInt { .. } => {
                Self::secret_int_binary_op("subtraction", ty, lhs_bytes, ty, rhs_bytes, |l, r| {
                    l - r
                })
            }
            ShareType::SecretFixedPoint { .. } => {
                Self::secret_fixed_point_binary_op(
                    "subtraction",
                    ty,
                    lhs_bytes,
                    ty,
                    rhs_bytes,
                    |l, r| l - r,
                )
            }
        }
    }

    /// Negate a secret share (public wrapper for mpc_builtins)
    pub fn secret_share_neg(&self, ty: ShareType, share_bytes: &[u8]) -> Result<Vec<u8>, String> {
        match ty {
            ShareType::SecretInt { bit_length } => {
                let secret = Self::secret_int_from_bytes(ty, share_bytes)?;
                let share = secret.share();
                let new_share_value = -share.share[0];
                let new_share = RobustShare::new(new_share_value, share.id, share.degree);
                let result = SecretInt::new(new_share, bit_length);
                Self::secret_int_to_bytes(result)
            }
            ShareType::SecretFixedPoint { precision } => {
                let secret = Self::secret_fixed_point_from_bytes(ty, share_bytes)?;
                let share = secret.value();
                let new_share_value = -share.share[0];
                let new_share = RobustShare::new(new_share_value, share.id, share.degree);
                let result = SecretFixedPoint::new_with_precision(new_share, precision);
                Self::secret_fixed_point_to_bytes(result)
            }
        }
    }

    /// Add scalar to a secret share (public wrapper for mpc_builtins)
    pub fn secret_share_add_scalar(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
        scalar: i64,
    ) -> Result<Vec<u8>, String> {
        match ty {
            ShareType::SecretInt { .. } => Self::secret_int_add_scalar(ty, share_bytes, scalar),
            ShareType::SecretFixedPoint { .. } => {
                Self::secret_fixed_point_add_scalar(ty, share_bytes, scalar)
            }
        }
    }

    /// Multiply secret share by scalar (public wrapper for mpc_builtins)
    pub fn secret_share_mul_scalar(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
        scalar: i64,
    ) -> Result<Vec<u8>, String> {
        match ty {
            ShareType::SecretInt { .. } => Self::secret_int_mul_scalar(ty, share_bytes, scalar),
            ShareType::SecretFixedPoint { .. } => {
                Self::secret_fixed_point_mul_scalar(ty, share_bytes, scalar)
            }
        }
    }

    /// Local interpolation - reconstruct secret from array of shares (public wrapper for mpc_builtins)
    pub fn secret_share_interpolate_local(
        &self,
        ty: ShareType,
        shares: &[Vec<u8>],
    ) -> Result<Value, String> {
        if shares.is_empty() {
            return Err("Cannot interpolate from empty shares array".to_string());
        }

        // Decode all shares
        let mut robust_shares: Vec<RobustShare<Fr>> = Vec::with_capacity(shares.len());
        for (i, share_bytes) in shares.iter().enumerate() {
            let share = Self::decode_share_bytes(share_bytes)
                .map_err(|e| format!("Failed to decode share at index {}: {}", i, e))?;
            robust_shares.push(share);
        }

        // Get n_parties from MPC engine if available
        let n_parties = self.mpc_engine().map(|e| e.n_parties()).unwrap_or(shares.len());

        // Recover the secret using Lagrange interpolation
        let (_degree, secret) = RobustShare::recover_secret(&robust_shares, n_parties)
            .map_err(|e| format!("Failed to recover secret: {:?}", e))?;

        // Convert field element back to value based on share type
        match ty {
            ShareType::SecretInt { bit_length } if bit_length == 1 => {
                // Boolean
                use ark_ff::Zero;
                Ok(Value::Bool(!secret.is_zero()))
            }
            ShareType::SecretInt { .. } => {
                let limbs: [u64; 4] = secret.into_bigint().0;
                Ok(Value::I64(limbs[0] as i64))
            }
            ShareType::SecretFixedPoint { precision } => {
                let limbs: [u64; 4] = secret.into_bigint().0;
                let scaled_value = limbs[0] as i64;
                let f = precision.f();
                let scale = (1u64 << f) as f64;
                let float_value = scaled_value as f64 / scale;
                Ok(Value::Float(F64(float_value)))
            }
        }
    }
}
