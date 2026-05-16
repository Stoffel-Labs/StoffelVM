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

use crate::error::VmResult;
use crate::net::mpc_engine::MpcEngine;
use crate::output::{StdoutOutputSink, VmOutputResult, VmOutputSink};
use crate::program::{CallTarget, Program};
use crate::reveal_destination::FrameDepth;
use crate::runtime_hooks::{HookManager, InstructionCursor};
use crate::runtime_instruction::RuntimeFunction;
use mpc_runtime::MpcRuntimeState;
use smallvec::SmallVec;
use std::sync::Arc;
#[cfg(test)]
use stoffel_vm_types::activations::ActivationRecord;
use stoffel_vm_types::activations::{ActivationStack, InstructionPointer};
use stoffel_vm_types::core_types::{ForeignObjectStorage, ObjectStore, TableMemory, Value};
use stoffel_vm_types::registers::{RegisterIndex, RegisterLayout};

mod calls;
mod effect;
mod execution;
mod foreign_objects;
mod frame;
mod hooks;
mod instructions;
mod mpc;
mod mpc_operation;
mod mpc_runtime;
mod program_registry;
mod register_access;
mod share_objects;
mod table_memory;
mod upvalues;

pub(crate) use effect::{CompletedVmEffect, VmEffect, VmExecutionBudget, VmRunSlice};

pub(crate) struct VMStateConfig {
    table_memory: Box<dyn TableMemory>,
    register_layout: RegisterLayout,
    mpc_engine: Option<Arc<dyn MpcEngine>>,
    output_sink: Arc<dyn VmOutputSink>,
}

impl Default for VMStateConfig {
    fn default() -> Self {
        Self {
            table_memory: Box::new(ObjectStore::new()),
            register_layout: RegisterLayout::default(),
            mpc_engine: None,
            output_sink: Arc::new(StdoutOutputSink),
        }
    }
}

impl VMStateConfig {
    pub(crate) fn with_table_memory(mut self, table_memory: Box<dyn TableMemory>) -> Self {
        self.table_memory = table_memory;
        self
    }

    pub(crate) fn with_register_layout(mut self, register_layout: RegisterLayout) -> Self {
        self.register_layout = register_layout;
        self
    }

    pub(crate) fn with_mpc_engine(mut self, mpc_engine: Arc<dyn MpcEngine>) -> Self {
        self.mpc_engine = Some(mpc_engine);
        self
    }

    pub(crate) fn with_output_sink(mut self, output_sink: Arc<dyn VmOutputSink>) -> Self {
        self.output_sink = output_sink;
        self
    }
}

// ============================================================================
// VM State Structure
// ============================================================================

/// Runtime state of the virtual machine
///
/// This structure maintains the complete state of the VM during execution,
/// including the function registry, activation record stack, object storage,
/// and hook system for debugging.
pub(crate) struct VMState {
    /// Registered program functions (both VM and foreign)
    program: Program,
    /// Last resolved call target, scoped to this VM state.
    ///
    /// Runtime instruction payloads are shared across cloned programs, so call
    /// target caching must stay VM-local rather than living in `RuntimeFunction`.
    last_call_target: Option<(Arc<str>, CallTarget)>,
    /// Stack of activation records for function calls
    call_stack: ActivationStack,
    /// Runtime instruction payloads aligned with `call_stack`.
    ///
    /// The VM crate owns lowered instructions, while `ActivationRecord` lives in
    /// `stoffel-vm-types`. Keeping the resolved payload alongside each frame
    /// preserves that crate boundary and avoids per-instruction registry lookups.
    frame_runtime_functions: SmallVec<[Option<Arc<RuntimeFunction>>; 8]>,
    /// Current instruction cursor exposed to hook snapshots.
    current_instruction: Option<InstructionCursor>,
    /// Storage for Lua-like table objects and arrays.
    table_memory: Box<dyn TableMemory>,
    /// Storage for foreign (Rust) objects
    foreign_objects: ForeignObjectStorage,
    /// Hook manager for debugging and instrumentation
    hook_manager: HookManager,
    /// MPC engine, client inputs, and reveal batching state.
    mpc_runtime: MpcRuntimeState,
    /// Clear/secret register-bank layout used for implicit share/reveal moves
    register_layout: RegisterLayout,
    /// Runtime output boundary used by standard-library print.
    output_sink: Arc<dyn VmOutputSink>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CallStackCheckpoint {
    frame_depth: FrameDepth,
}

impl CallStackCheckpoint {
    pub(crate) const fn new(depth: usize) -> Self {
        Self {
            frame_depth: FrameDepth::new(depth),
        }
    }

    const fn depth(self) -> usize {
        self.frame_depth.depth()
    }

    const fn frame_depth_floor(self) -> FrameDepth {
        self.frame_depth
    }

    const fn has_active_frame(self, current_depth: usize) -> bool {
        current_depth > self.depth()
    }

    const fn is_current_depth(self, current_depth: usize) -> bool {
        current_depth == self.depth()
    }

    fn is_returning_from_entry_frame(self, current_depth: usize) -> bool {
        current_depth.checked_sub(self.depth()) == Some(1)
    }
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
    pub(crate) fn new() -> Self {
        Self::from_config(VMStateConfig::default())
    }

    pub(crate) fn from_config(config: VMStateConfig) -> Self {
        let mut mpc_runtime = MpcRuntimeState::new();
        if let Some(engine) = config.mpc_engine {
            mpc_runtime.set_engine(engine);
        }

        VMState {
            program: Program::new(),
            last_call_target: None,
            call_stack: ActivationStack::new(),
            frame_runtime_functions: SmallVec::new(),
            current_instruction: None,
            table_memory: config.table_memory,
            foreign_objects: ForeignObjectStorage::new(),
            hook_manager: HookManager::new(),
            mpc_runtime,
            register_layout: config.register_layout,
            output_sink: config.output_sink,
        }
    }

    pub(crate) fn try_clone_with_independent_runtime(&self) -> VmResult<Self> {
        let config = VMStateConfig::default()
            .with_table_memory(self.table_memory.try_clone_empty()?)
            .with_register_layout(self.register_layout)
            .with_output_sink(Arc::clone(&self.output_sink));

        let mut cloned = Self::from_config(config);
        cloned.program = self.program.clone();
        cloned.mpc_runtime = self.mpc_runtime.clone_independent();
        Ok(cloned)
    }

    #[cfg(test)]
    pub(crate) fn push_activation_record(&mut self, record: ActivationRecord) {
        self.push_activation_frame(record, None);
    }

    /// Get the number of active call frames on the VM call stack.
    #[inline]
    pub(crate) fn call_stack_depth(&self) -> usize {
        self.call_stack.len()
    }

    pub(crate) fn unwind_call_stack_to(&mut self, checkpoint: CallStackCheckpoint) {
        self.mpc_runtime
            .clear_reveals_at_or_above(checkpoint.frame_depth_floor());
        self.truncate_activation_frames(checkpoint.depth());
        self.sync_current_instruction_to_current_frame();
    }

    #[cfg(test)]
    pub(crate) fn set_register_layout(&mut self, layout: RegisterLayout) {
        self.register_layout = layout;
    }

    #[cfg(test)]
    pub(crate) fn register_layout(&self) -> RegisterLayout {
        self.register_layout
    }

    pub(crate) fn prepare_register_arguments(
        &self,
        args: &[Value],
    ) -> VmResult<SmallVec<[Value; 8]>> {
        self.prepare_register_arguments_for_layout(self.register_layout, args)
    }

    pub(crate) fn set_output_sink(&mut self, output_sink: Arc<dyn VmOutputSink>) {
        self.output_sink = output_sink;
    }

    pub(crate) fn output_sink(&self) -> Arc<dyn VmOutputSink> {
        Arc::clone(&self.output_sink)
    }

    pub(crate) fn write_output_line(&self, line: &str) -> VmOutputResult<()> {
        self.output_sink.write_line(line)
    }

    pub(super) fn set_current_instruction(
        &mut self,
        function_name: impl Into<Arc<str>>,
        instruction_pointer: InstructionPointer,
    ) {
        self.current_instruction = Some(InstructionCursor::new(function_name, instruction_pointer));
    }

    pub(super) fn clear_current_instruction(&mut self) {
        self.current_instruction = None;
    }

    pub(super) fn sync_current_instruction_to_current_frame(&mut self) {
        self.current_instruction = self.call_stack.current().and_then(|record| {
            record
                .instruction_pointer()
                .previous()
                .map(|instruction_pointer| {
                    InstructionCursor::new(record.function_name_arc(), instruction_pointer)
                })
        });
    }

    pub(crate) fn prepare_register_arguments_for_layout(
        &self,
        layout: RegisterLayout,
        args: &[Value],
    ) -> VmResult<SmallVec<[Value; 8]>> {
        let mut prepared = SmallVec::with_capacity(args.len());
        for (register, value) in args.iter().enumerate() {
            prepared.push(self.prepare_register_write_value_for_layout(
                layout,
                RegisterIndex::new(register),
                value.clone(),
            )?);
        }
        Ok(prepared)
    }

    /// Get a reference to the current (top) activation record.
    #[inline]
    #[cfg(test)]
    pub(crate) fn current_activation_record(&self) -> Option<&ActivationRecord> {
        self.call_stack.current()
    }
}

#[cfg(test)]
mod tests;
