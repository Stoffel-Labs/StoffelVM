use super::mpc_operation::PendingMpcOperation;
use super::{CallStackCheckpoint, VMState, VmEffect, VmExecutionBudget, VmRunSlice};
use crate::error::{VmError, VmResult};
use crate::runtime_hooks::HookEvent;
use crate::runtime_instruction::{FetchedInstruction, RuntimeFunction};
use std::sync::Arc;
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
    Instruction(FetchedInstruction<'function>),
    Return(Value),
    Continue,
}

enum CompletedStep {
    Continue,
    Return(Value),
}

#[derive(Default)]
struct RuntimeFunctionCache {
    frame_depth: Option<usize>,
    runtime_function: Option<Arc<RuntimeFunction>>,
}

impl RuntimeFunctionCache {
    fn current<'cache>(&'cache mut self, state: &mut VMState) -> VmResult<&'cache RuntimeFunction> {
        let frame_depth = state.current_frame_depth()?.depth();
        if self.frame_depth != Some(frame_depth) {
            self.runtime_function = Some(state.current_runtime_function()?);
            self.frame_depth = Some(frame_depth);
        }

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
            loop {
                let runtime_function = runtime_cache.current(self)?;
                match self.execute_local_step_without_hooks(context, runtime_function)? {
                    CompletedStep::Continue => continue,
                    CompletedStep::Return(value) => return Ok(value),
                }
            }
        }
    }

    fn execute_local_step_without_hooks(
        &mut self,
        context: ExecutionContext,
        runtime_function: &RuntimeFunction,
    ) -> VmResult<CompletedStep> {
        let fetched =
            match self.prepare_next_step_without_hooks(context.checkpoint(), runtime_function)? {
                PreparedStep::Instruction(fetched) => fetched,
                PreparedStep::Return(value) => return Ok(CompletedStep::Return(value)),
                PreparedStep::Continue => return Ok(CompletedStep::Continue),
            };

        match self.execute_local_instruction_without_hooks(
            fetched.runtime_instruction(),
            context.checkpoint(),
        )? {
            InstructionOutcome::Continue => Ok(CompletedStep::Continue),
            InstructionOutcome::Return(value) => Ok(CompletedStep::Return(value)),
        }
    }

    fn execute_local_step(
        &mut self,
        context: ExecutionContext,
        runtime_function: &RuntimeFunction,
    ) -> VmResult<CompletedStep> {
        let fetched = match self.prepare_next_step(context, runtime_function)? {
            PreparedStep::Instruction(fetched) => fetched,
            PreparedStep::Return(value) => return Ok(CompletedStep::Return(value)),
            PreparedStep::Continue => return Ok(CompletedStep::Continue),
        };

        let execution_result = self.execute_local_instruction(
            fetched.runtime_instruction(),
            fetched.hook_instruction(),
            context,
        )?;

        self.complete_prepared_instruction(fetched, execution_result, context)
    }

    fn complete_prepared_instruction(
        &mut self,
        fetched: FetchedInstruction,
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
            let event = HookEvent::AfterInstructionExecute(fetched.hook_instruction().clone());
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
                    executed_instructions = executed_instructions.saturating_add(1);
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
        loop {
            if budget.is_exhausted(executed_instructions) {
                return Ok(VmRunSlice::BudgetExhausted);
            }

            let runtime_function = runtime_cache.current(self)?;
            match self.execute_async_step_without_hooks(context, runtime_function)? {
                StepResult::Continue => {
                    executed_instructions = executed_instructions.saturating_add(1);
                }
                StepResult::Return(value) => return Ok(VmRunSlice::Complete(value)),
                StepResult::NeedsMpc {
                    operation,
                    after_instruction,
                } => {
                    return Ok(VmRunSlice::Yield(VmEffect::new(
                        operation,
                        after_instruction,
                        false,
                    )));
                }
            }
        }
    }

    fn execute_async_step_without_hooks(
        &mut self,
        context: ExecutionContext,
        runtime_function: &RuntimeFunction,
    ) -> VmResult<StepResult> {
        let fetched =
            match self.prepare_next_step_without_hooks(context.checkpoint(), runtime_function)? {
                PreparedStep::Instruction(fetched) => fetched,
                PreparedStep::Return(value) => return Ok(StepResult::Return(value)),
                PreparedStep::Continue => return Ok(StepResult::Continue),
            };

        match self.execute_effect_instruction_without_hooks(
            fetched.runtime_instruction(),
            context.checkpoint(),
        )? {
            InstructionEffect::Completed(InstructionOutcome::Continue) => Ok(StepResult::Continue),
            InstructionEffect::Completed(InstructionOutcome::Return(value)) => {
                Ok(StepResult::Return(value))
            }
            InstructionEffect::PendingMpc(operation) => Ok(StepResult::NeedsMpc {
                operation,
                after_instruction: None,
            }),
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
            fetched.runtime_instruction(),
            fetched.hook_instruction(),
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
                    .then(|| fetched.hook_instruction().clone()),
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

        Ok(PreparedStep::Instruction(fetched))
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

        self.set_current_instruction(hook_function_name, instruction_pointer);
        let event = HookEvent::BeforeInstructionExecute(fetched.hook_instruction().clone());
        self.trigger_hook_with_snapshot(&event)?;

        Ok(PreparedStep::Instruction(fetched))
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
