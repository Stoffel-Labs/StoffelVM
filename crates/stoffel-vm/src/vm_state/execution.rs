use super::mpc_operation::PendingMpcOperation;
use super::{
    instructions::InstructionExecutor, CallStackCheckpoint, VMState, VmEffect, VmExecutionBudget,
    VmRunSlice,
};
use crate::error::{VmError, VmResult};
use crate::runtime_hooks::HookEvent;
use crate::runtime_instruction::{FetchedInstruction, RuntimeFunction};
use std::sync::Arc;
use stoffel_vm_types::activations::InstructionPointer;
use stoffel_vm_types::core_types::Value;

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
        instruction: FetchedInstruction,
    },
}

enum PreparedStep {
    Instruction(FetchedInstruction),
    Return(Value),
    Continue,
}

enum CompletedStep {
    Continue,
    Return(Value),
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

        loop {
            match self.execute_local_step(context)? {
                CompletedStep::Continue => continue,
                CompletedStep::Return(value) => return Ok(value),
            }
        }
    }

    fn execute_local_step(&mut self, context: ExecutionContext) -> VmResult<CompletedStep> {
        let fetched = match self.prepare_next_step(context)? {
            PreparedStep::Instruction(fetched) => fetched,
            PreparedStep::Return(value) => return Ok(CompletedStep::Return(value)),
            PreparedStep::Continue => return Ok(CompletedStep::Continue),
        };

        let execution_result = InstructionExecutor::new(
            self,
            fetched.runtime_instruction(),
            fetched.hook_instruction(),
            context,
        )
        .execute_local()?;

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
        let mut executed_instructions = 0usize;

        loop {
            if budget.is_exhausted(executed_instructions) {
                return Ok(VmRunSlice::BudgetExhausted);
            }

            match self.execute_async_step(context)? {
                StepResult::Continue => {
                    executed_instructions = executed_instructions.saturating_add(1);
                }
                StepResult::Return(value) => return Ok(VmRunSlice::Complete(value)),
                StepResult::NeedsMpc {
                    operation,
                    instruction,
                } => {
                    return Ok(VmRunSlice::Yield(VmEffect::new(
                        operation,
                        instruction.hook_instruction().clone(),
                        context.hooks_enabled(),
                    )));
                }
            }
        }
    }

    fn execute_async_step(&mut self, context: ExecutionContext) -> VmResult<StepResult> {
        let fetched = match self.prepare_next_step(context)? {
            PreparedStep::Instruction(fetched) => fetched,
            PreparedStep::Return(value) => return Ok(StepResult::Return(value)),
            PreparedStep::Continue => return Ok(StepResult::Continue),
        };

        let execution_result = InstructionExecutor::new(
            self,
            fetched.runtime_instruction(),
            fetched.hook_instruction(),
            context,
        )
        .execute_effect()?;

        match execution_result {
            InstructionEffect::Completed(outcome) => {
                match self.complete_prepared_instruction(fetched, outcome, context)? {
                    CompletedStep::Continue => Ok(StepResult::Continue),
                    CompletedStep::Return(value) => Ok(StepResult::Return(value)),
                }
            }
            InstructionEffect::PendingMpc(operation) => Ok(StepResult::NeedsMpc {
                operation,
                instruction: fetched,
            }),
        }
    }

    fn prepare_next_step(&mut self, context: ExecutionContext) -> VmResult<PreparedStep> {
        let checkpoint = context.checkpoint();
        if !checkpoint.has_active_frame(self.call_stack.len()) {
            return Err(VmError::UnexpectedEndOfExecution);
        }

        let (function_name, instruction_pointer, fetched) = {
            let record = self.current_frame()?;
            let function_name = record.function_name().to_owned();
            let instruction_pointer = record.instruction_pointer();
            let runtime_function = self.runtime_function(&function_name)?;
            if self.is_end_of_function(instruction_pointer, &runtime_function) {
                (function_name, instruction_pointer, None)
            } else {
                (
                    function_name,
                    instruction_pointer,
                    Some(self.fetch_instruction(instruction_pointer, runtime_function)?),
                )
            }
        };

        let Some(fetched) = fetched else {
            if let Some(result) = self.handle_function_end(context)? {
                return Ok(PreparedStep::Return(result));
            }
            return Ok(PreparedStep::Continue);
        };

        self.set_current_instruction(function_name, instruction_pointer);
        self.current_frame_mut()?
            .try_advance_instruction_pointer()?;

        if context.hooks_enabled() {
            let event = HookEvent::BeforeInstructionExecute(fetched.hook_instruction().clone());
            self.trigger_hook_with_snapshot(&event)?;
        }

        Ok(PreparedStep::Instruction(fetched))
    }

    pub(crate) fn runtime_function(&self, function_name: &str) -> VmResult<Arc<RuntimeFunction>> {
        self.program.runtime_function(function_name)
    }

    #[inline]
    fn is_end_of_function(
        &self,
        instruction_pointer: InstructionPointer,
        runtime_function: &RuntimeFunction,
    ) -> bool {
        instruction_pointer.index() >= runtime_function.len()
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

    fn fetch_instruction(
        &self,
        instruction_pointer: InstructionPointer,
        runtime_function: Arc<RuntimeFunction>,
    ) -> VmResult<FetchedInstruction> {
        FetchedInstruction::fetch(instruction_pointer, runtime_function)
    }
}
