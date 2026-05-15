use super::mpc_operation::{CompletedMpcOperation, PendingMpcOperation};
use crate::error::VmResult;
use crate::net::mpc_engine::AsyncMpcEngine;
use stoffel_vm_types::core_types::Value;
use stoffel_vm_types::instructions::Instruction;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VmExecutionBudget {
    max_instructions: usize,
}

impl VmExecutionBudget {
    pub(crate) const fn max_instructions(max_instructions: usize) -> Self {
        Self { max_instructions }
    }

    pub(crate) const fn is_exhausted(self, executed_instructions: usize) -> bool {
        executed_instructions >= self.max_instructions
    }
}

#[derive(Debug)]
pub(crate) enum VmRunSlice {
    Complete(Value),
    Yield(VmEffect),
    BudgetExhausted,
}

#[derive(Debug)]
pub(crate) struct VmEffect {
    operation: PendingMpcOperation,
    after_instruction: Instruction,
    hooks_enabled: bool,
}

impl VmEffect {
    pub(super) fn new(
        operation: PendingMpcOperation,
        after_instruction: Instruction,
        hooks_enabled: bool,
    ) -> Self {
        Self {
            operation,
            after_instruction,
            hooks_enabled,
        }
    }

    pub(crate) async fn execute<E: AsyncMpcEngine + ?Sized>(
        self,
        engine: &E,
    ) -> VmResult<CompletedVmEffect> {
        let completed = self.operation.execute_async(engine).await?;
        Ok(CompletedVmEffect {
            operation: completed,
            after_instruction: self.after_instruction,
            hooks_enabled: self.hooks_enabled,
        })
    }
}

#[derive(Debug)]
pub(crate) struct CompletedVmEffect {
    operation: CompletedMpcOperation,
    after_instruction: Instruction,
    hooks_enabled: bool,
}

impl CompletedVmEffect {
    pub(super) fn into_parts(self) -> (CompletedMpcOperation, Instruction, bool) {
        (self.operation, self.after_instruction, self.hooks_enabled)
    }
}
