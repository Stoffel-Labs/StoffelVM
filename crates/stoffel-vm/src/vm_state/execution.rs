use super::mpc_operation::PendingMpcOperation;
use super::{CallStackCheckpoint, VMState, VmEffect, VmExecutionBudget, VmRunSlice};
use crate::error::{VmError, VmResult};
use crate::runtime_hooks::HookEvent;
use crate::runtime_instruction::{FetchedInstruction, RuntimeFunction};
use std::sync::Arc;
use stoffel_vm_types::activations::InstructionPointer;
use stoffel_vm_types::core_types::Value;
use stoffel_vm_types::instructions::Instruction;

#[derive(Debug, Clone, Copy)]
pub(super) struct ExecutionContext {
    checkpoint: CallStackCheckpoint,
    hooks_enabled: bool,
}

impl ExecutionContext {
    pub(super) const fn new(checkpoint: CallStackCheckpoint, hooks_enabled: bool) -> Self {
        Self {
            checkpoint,
            hooks_enabled,
        }
    }

    pub(super) const fn checkpoint(self) -> CallStackCheckpoint {
        self.checkpoint
    }

    pub(super) const fn hooks_enabled(self) -> bool {
        self.hooks_enabled
    }
}

#[derive(Debug)]
pub(super) enum InstructionOutcome {
    Continue,
    Return(Value),
}

#[derive(Debug)]
pub(super) enum InstructionEffect {
    Completed(InstructionOutcome),
    PendingMpc(PendingMpcOperation),
}

/// Result of a single VM step.
#[derive(Debug)]
enum StepResult {
    Continue,
    Return(Value),
    NeedsMpc {
        operation: PendingMpcOperation,
        after_instruction: Option<Instruction>,
    },
}

enum PreparedStep<'function> {
    Instruction(PreparedInstruction<'function>),
    Return(Value),
    Continue,
}

enum CompletedStep {
    Continue,
    Return(Value),
}

struct PreparedInstruction<'function> {
    fetched: FetchedInstruction<'function>,
    hook_instruction: Option<Instruction>,
}

impl<'function> PreparedInstruction<'function> {
    fn without_hooks(fetched: FetchedInstruction<'function>) -> Self {
        Self {
            fetched,
            hook_instruction: None,
        }
    }

    fn with_hooks(fetched: FetchedInstruction<'function>, hook_instruction: Instruction) -> Self {
        Self {
            fetched,
            hook_instruction: Some(hook_instruction),
        }
    }

    #[inline]
    fn fetched(&self) -> FetchedInstruction<'function> {
        self.fetched
    }

    fn hook_instruction(&self) -> VmResult<&Instruction> {
        self.hook_instruction
            .as_ref()
            .ok_or(VmError::InstructionOutOfBounds { index: usize::MAX })
    }

    fn cloned_hook_instruction(&self) -> VmResult<Instruction> {
        self.hook_instruction().cloned()
    }
}

#[derive(Default)]
struct RuntimeFunctionCache {
    frame_depth: Option<usize>,
    runtime_function: Option<Arc<RuntimeFunction>>,
}

impl RuntimeFunctionCache {
    #[inline]
    fn current<'cache>(&'cache mut self, state: &mut VMState) -> VmResult<&'cache RuntimeFunction> {
        let frame_depth = state
            .call_stack_depth()
            .checked_sub(1)
            .ok_or(VmError::NoActiveActivationRecord)?;
        if self.frame_depth == Some(frame_depth) {
            return self
                .runtime_function
                .as_deref()
                .ok_or(VmError::NoActiveActivationRecord);
        }

        self.refresh(state, frame_depth)
    }

    #[cold]
    #[inline(never)]
    fn refresh<'cache>(
        &'cache mut self,
        state: &mut VMState,
        frame_depth: usize,
    ) -> VmResult<&'cache RuntimeFunction> {
        self.runtime_function = Some(state.current_runtime_function()?);
        self.frame_depth = Some(frame_depth);
        self.runtime_function
            .as_deref()
            .ok_or(VmError::NoActiveActivationRecord)
    }
}

impl VMState {
    /// Main execution loop - runs until a return instruction is encountered.
    #[cfg(test)]
    pub(crate) fn execute_until_return(&mut self) -> VmResult<Value> {
        let checkpoint = self
            .call_stack_depth()
            .checked_sub(1)
            .map(CallStackCheckpoint::new)
            .ok_or(VmError::NoActivationRecordToExecute)?;
        self.execute_until_return_to_depth(checkpoint)
    }

    pub(crate) fn execute_until_return_to_depth(
        &mut self,
        checkpoint: CallStackCheckpoint,
    ) -> VmResult<Value> {
        let result = self.execute_until_return_to_depth_inner(checkpoint);
        if result.is_err() {
            self.unwind_call_stack_to(checkpoint);
        }
        result
    }

    fn execute_until_return_to_depth_inner(
        &mut self,
        checkpoint: CallStackCheckpoint,
    ) -> VmResult<Value> {
        let context = ExecutionContext::new(checkpoint, self.hooks_enabled());
        let mut runtime_cache = RuntimeFunctionCache::default();

        if context.hooks_enabled() {
            loop {
                let runtime_function = runtime_cache.current(self)?;
                match self.execute_local_step(context, runtime_function)? {
                    CompletedStep::Continue => continue,
                    CompletedStep::Return(value) => return Ok(value),
                }
            }
        } else {
            self.execute_until_return_without_hooks(context, runtime_cache)
        }
    }

    fn execute_until_return_without_hooks(
        &mut self,
        context: ExecutionContext,
        mut runtime_cache: RuntimeFunctionCache,
    ) -> VmResult<Value> {
        // Keep fetch and dispatch in one loop. This is the ordinary clear-VM hot
        // path, so avoid constructing PreparedStep/CompletedStep for every
        // instruction and give LLVM one loop body in which to retain the frame,
        // instruction pointer, and runtime function cache.
        let checkpoint = context.checkpoint();
        let mut clear_fast_paths_enabled = !self.mpc_runtime.has_any_pending_reveals();
        loop {
            if !checkpoint.has_active_frame(self.call_stack.len()) {
                return Err(VmError::UnexpectedEndOfExecution);
            }
            let frame_depth = self.call_stack.len() - 1;
            let runtime_function = if runtime_cache.frame_depth == Some(frame_depth) {
                runtime_cache
                    .runtime_function
                    .as_deref()
                    .expect("a populated runtime cache always contains its function")
            } else {
                runtime_cache.refresh(self, frame_depth)?
            };
            let instruction_table = runtime_function.instruction_table();
            let instruction = {
                let frame = self
                    .call_stack
                    .current_mut()
                    .expect("an active checkpoint always has a current frame");
                let mut instruction_pointer = frame.instruction_pointer();
                let instruction = loop {
                    // SAFETY: RuntimeFunction appends an implicit-return sentinel,
                    // and lowering validates every jump target at or before it.
                    let fetched =
                        unsafe { instruction_table.get_instruction_unchecked(instruction_pointer) };
                    instruction_pointer = InstructionPointer::new(
                        // The fetched cursor indexes a live allocation which
                        // also contains an implicit-return sentinel, so it
                        // cannot be usize::MAX.
                        instruction_pointer.index().wrapping_add(1),
                    );
                    let (clear_instructions, clear_instruction_pointer) =
                        Self::execute_clear_instruction_run_on_frame_without_hooks::<false>(
                            frame,
                            fetched,
                            instruction_table,
                            instruction_pointer,
                            clear_fast_paths_enabled,
                            usize::MAX,
                        );
                    instruction_pointer = clear_instruction_pointer;
                    if clear_instructions != 0 {
                        continue;
                    }
                    break fetched;
                };
                frame.set_instruction_pointer(instruction_pointer);
                instruction
            };
            match self.execute_local_fetched_instruction_without_hooks(instruction, checkpoint)? {
                InstructionOutcome::Continue => {
                    clear_fast_paths_enabled = !self.mpc_runtime.has_any_pending_reveals();
                }
                InstructionOutcome::Return(value) => return Ok(value),
            }
        }
    }

    fn execute_local_step(
        &mut self,
        context: ExecutionContext,
        runtime_function: &RuntimeFunction,
    ) -> VmResult<CompletedStep> {
        let fetched = match self.prepare_next_step(context, runtime_function)? {
            PreparedStep::Instruction(prepared) => prepared,
            PreparedStep::Return(value) => return Ok(CompletedStep::Return(value)),
            PreparedStep::Continue => return Ok(CompletedStep::Continue),
        };

        let execution_result = self.execute_local_instruction(
            fetched.fetched(),
            fetched.hook_instruction()?,
            context,
        )?;

        self.complete_prepared_instruction(fetched, execution_result, context)
    }

    fn complete_prepared_instruction(
        &mut self,
        fetched: PreparedInstruction,
        execution_result: InstructionOutcome,
        context: ExecutionContext,
    ) -> VmResult<CompletedStep> {
        match execution_result {
            InstructionOutcome::Return(return_value) => {
                return Ok(CompletedStep::Return(return_value));
            }
            InstructionOutcome::Continue => {}
        }

        if context.hooks_enabled() {
            let event = HookEvent::AfterInstructionExecute(fetched.cloned_hook_instruction()?);
            self.trigger_hook_with_snapshot(&event)?;
        }

        Ok(CompletedStep::Continue)
    }

    /// Run synchronous VM work until completion, an online effect, or a local
    /// instruction budget boundary.
    ///
    /// This method intentionally does not await. The async host is responsible
    /// for executing yielded effects and resuming the VM with the result.
    pub(crate) fn run_until_effect_or_budget_to_depth(
        &mut self,
        checkpoint: CallStackCheckpoint,
        budget: VmExecutionBudget,
    ) -> VmResult<VmRunSlice> {
        let context = ExecutionContext::new(checkpoint, self.hooks_enabled());
        let executed_instructions = 0usize;
        let runtime_cache = RuntimeFunctionCache::default();

        if context.hooks_enabled() {
            return self.run_until_effect_or_budget_with_hooks(
                context,
                budget,
                executed_instructions,
                runtime_cache,
            );
        }

        self.run_until_effect_or_budget_without_hooks(
            context,
            budget,
            executed_instructions,
            runtime_cache,
        )
    }

    fn run_until_effect_or_budget_with_hooks(
        &mut self,
        context: ExecutionContext,
        budget: VmExecutionBudget,
        mut executed_instructions: usize,
        mut runtime_cache: RuntimeFunctionCache,
    ) -> VmResult<VmRunSlice> {
        loop {
            if budget.is_exhausted(executed_instructions) {
                return Ok(VmRunSlice::BudgetExhausted);
            }

            let runtime_function = runtime_cache.current(self)?;
            match self.execute_async_step(context, runtime_function)? {
                StepResult::Continue => {
                    // The pre-step budget check guarantees this cannot overflow,
                    // even when the configured maximum is `usize::MAX`.
                    executed_instructions += 1;
                }
                StepResult::Return(value) => return Ok(VmRunSlice::Complete(value)),
                StepResult::NeedsMpc {
                    operation,
                    after_instruction,
                } => {
                    return Ok(VmRunSlice::Yield(VmEffect::new(
                        operation,
                        after_instruction,
                        context.hooks_enabled(),
                    )));
                }
            }
        }
    }

    fn run_until_effect_or_budget_without_hooks(
        &mut self,
        context: ExecutionContext,
        budget: VmExecutionBudget,
        mut executed_instructions: usize,
        mut runtime_cache: RuntimeFunctionCache,
    ) -> VmResult<VmRunSlice> {
        // Hot path for online MPC execution (no debug hooks). Keeping fetch and
        // execute in one interpreter loop lets the compiler retain the frame and
        // instruction pointers in registers across instructions, instead of
        // crossing function-call boundaries and constructing/destructing the
        // `PreparedStep` / `StepResult` intermediate enums on every instruction.
        let checkpoint = context.checkpoint();
        let mut clear_fast_paths_enabled = !self.mpc_runtime.has_any_pending_reveals();
        loop {
            if !checkpoint.has_active_frame(self.call_stack.len()) {
                return Err(VmError::UnexpectedEndOfExecution);
            }
            let frame_depth = self.call_stack.len() - 1;
            let runtime_function = if runtime_cache.frame_depth == Some(frame_depth) {
                runtime_cache
                    .runtime_function
                    .as_deref()
                    .expect("a populated runtime cache always contains its function")
            } else {
                runtime_cache.refresh(self, frame_depth)?
            };
            let instruction_table = runtime_function.instruction_table();

            // ---- fetch + local fast run ----
            // Keep the current frame borrowed across consecutive clear local
            // instructions. Generic instructions, function end, and a budget
            // boundary release the borrow before touching the rest of VMState.
            let (instruction, budget_exhausted) = {
                let frame = self
                    .call_stack
                    .current_mut()
                    .expect("an active checkpoint always has a current frame");
                let mut instruction_pointer = frame.instruction_pointer();
                let exit = loop {
                    if budget.is_exhausted(executed_instructions) {
                        break (None, true);
                    }
                    // SAFETY: RuntimeFunction appends an implicit-return sentinel,
                    // and lowering validates every jump target at or before it.
                    let fetched =
                        unsafe { instruction_table.get_instruction_unchecked(instruction_pointer) };
                    instruction_pointer = InstructionPointer::new(
                        // The fetched cursor indexes a live allocation which
                        // also contains an implicit-return sentinel, so it
                        // cannot be usize::MAX.
                        instruction_pointer.index().wrapping_add(1),
                    );
                    let (clear_instructions, clear_instruction_pointer) =
                        Self::execute_clear_instruction_run_on_frame_without_hooks::<true>(
                            frame,
                            fetched,
                            instruction_table,
                            instruction_pointer,
                            clear_fast_paths_enabled,
                            budget.remaining(executed_instructions),
                        );
                    instruction_pointer = clear_instruction_pointer;
                    if clear_instructions != 0 {
                        executed_instructions += clear_instructions;
                        continue;
                    }
                    break (Some(fetched), false);
                };
                frame.set_instruction_pointer(instruction_pointer);
                exit
            };
            if budget_exhausted {
                return Ok(VmRunSlice::BudgetExhausted);
            }
            let instruction = match instruction {
                Some(instruction) => instruction,
                None => {
                    // Ran past the end of this function's instruction vector:
                    // resolve its return value and pop the activation frame.
                    if let Some(result) =
                        self.handle_function_end(ExecutionContext::new(checkpoint, false))?
                    {
                        return Ok(VmRunSlice::Complete(result));
                    }
                    clear_fast_paths_enabled = !self.mpc_runtime.has_any_pending_reveals();
                    continue;
                }
            };

            // ---- execute (plan an async MPC effect, otherwise run locally) ----
            match self.execute_effect_fetched_instruction_without_hooks(instruction, checkpoint)? {
                InstructionEffect::Completed(InstructionOutcome::Continue) => {
                    if !instruction.is_implicit_return() {
                        executed_instructions += 1;
                    }
                    clear_fast_paths_enabled = !self.mpc_runtime.has_any_pending_reveals();
                }
                InstructionEffect::Completed(InstructionOutcome::Return(value)) => {
                    return Ok(VmRunSlice::Complete(value));
                }
                InstructionEffect::PendingMpc(operation) => {
                    return Ok(VmRunSlice::Yield(VmEffect::new(operation, None, false)));
                }
            }
        }
    }

    fn execute_async_step(
        &mut self,
        context: ExecutionContext,
        runtime_function: &RuntimeFunction,
    ) -> VmResult<StepResult> {
        let fetched = match self.prepare_next_step(context, runtime_function)? {
            PreparedStep::Instruction(fetched) => fetched,
            PreparedStep::Return(value) => return Ok(StepResult::Return(value)),
            PreparedStep::Continue => return Ok(StepResult::Continue),
        };

        let execution_result = self.execute_effect_instruction(
            fetched.fetched(),
            fetched.hook_instruction()?,
            context,
        )?;

        match execution_result {
            InstructionEffect::Completed(outcome) => {
                match self.complete_prepared_instruction(fetched, outcome, context)? {
                    CompletedStep::Continue => Ok(StepResult::Continue),
                    CompletedStep::Return(value) => Ok(StepResult::Return(value)),
                }
            }
            InstructionEffect::PendingMpc(operation) => Ok(StepResult::NeedsMpc {
                operation,
                after_instruction: context
                    .hooks_enabled()
                    .then(|| fetched.cloned_hook_instruction())
                    .transpose()?,
            }),
        }
    }

    fn prepare_next_step<'function>(
        &mut self,
        context: ExecutionContext,
        runtime_function: &'function RuntimeFunction,
    ) -> VmResult<PreparedStep<'function>> {
        if context.hooks_enabled() {
            return self.prepare_next_step_with_hooks(context, runtime_function);
        }

        self.prepare_next_step_without_hooks(context.checkpoint(), runtime_function)
    }

    fn prepare_next_step_without_hooks<'function>(
        &mut self,
        checkpoint: CallStackCheckpoint,
        runtime_function: &'function RuntimeFunction,
    ) -> VmResult<PreparedStep<'function>> {
        if !checkpoint.has_active_frame(self.call_stack.len()) {
            return Err(VmError::UnexpectedEndOfExecution);
        }

        let fetched = {
            let frame = self.current_frame_mut()?;
            let instruction_pointer = frame.instruction_pointer();
            if let Some(fetched) = runtime_function.get_instruction(instruction_pointer) {
                frame.advance_instruction_pointer_after_fetch();
                Some(fetched)
            } else {
                None
            }
        };

        let Some(fetched) = fetched else {
            if let Some(result) =
                self.handle_function_end(ExecutionContext::new(checkpoint, false))?
            {
                return Ok(PreparedStep::Return(result));
            }
            return Ok(PreparedStep::Continue);
        };

        Ok(PreparedStep::Instruction(
            PreparedInstruction::without_hooks(fetched),
        ))
    }

    fn prepare_next_step_with_hooks<'function>(
        &mut self,
        context: ExecutionContext,
        runtime_function: &'function RuntimeFunction,
    ) -> VmResult<PreparedStep<'function>> {
        let checkpoint = context.checkpoint();
        if !checkpoint.has_active_frame(self.call_stack.len()) {
            return Err(VmError::UnexpectedEndOfExecution);
        }

        let prepared = {
            let frame = self.current_frame_mut()?;
            let instruction_pointer = frame.instruction_pointer();
            if let Some(fetched) = runtime_function.get_instruction(instruction_pointer) {
                let hook_function_name = frame.function_name_arc();
                frame.advance_instruction_pointer_after_fetch();
                Some((fetched, instruction_pointer, hook_function_name))
            } else {
                None
            }
        };

        let Some((fetched, instruction_pointer, hook_function_name)) = prepared else {
            if let Some(result) = self.handle_function_end(context)? {
                return Ok(PreparedStep::Return(result));
            }
            return Ok(PreparedStep::Continue);
        };

        let hook_instruction = self
            .program
            .instruction_at(hook_function_name.as_ref(), instruction_pointer)
            .cloned()
            .ok_or(VmError::InstructionOutOfBounds {
                index: instruction_pointer.index(),
            })?;

        self.set_current_instruction(hook_function_name, instruction_pointer);
        let event = HookEvent::BeforeInstructionExecute(hook_instruction.clone());
        self.trigger_hook_with_snapshot(&event)?;

        Ok(PreparedStep::Instruction(PreparedInstruction::with_hooks(
            fetched,
            hook_instruction,
        )))
    }

    fn handle_function_end(&mut self, context: ExecutionContext) -> VmResult<Option<Value>> {
        let return_register = self.current_return_register()?;
        let return_value = self.resolve_register(return_register)?.into_value();

        match self.return_current_frame(
            return_value,
            None,
            context.hooks_enabled(),
            context.checkpoint(),
        )? {
            InstructionOutcome::Continue => Ok(None),
            InstructionOutcome::Return(value) => Ok(Some(value)),
        }
    }
}
