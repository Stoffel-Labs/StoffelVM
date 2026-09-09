use super::mpc_operation::{
    CompletedMpcOperation, PendingMpcBuiltinOperation, PendingMpcOperation,
};
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

    pub(crate) const fn remaining(self, executed_instructions: usize) -> usize {
        self.max_instructions.saturating_sub(executed_instructions)
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
    after_instruction: Option<Instruction>,
    hooks_enabled: bool,
}

impl VmEffect {
    pub(super) fn new(
        operation: PendingMpcOperation,
        after_instruction: Option<Instruction>,
        hooks_enabled: bool,
    ) -> Self {
        debug_assert_eq!(after_instruction.is_some(), hooks_enabled);
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

    pub(crate) fn summary(&self) -> VmEffectSummary {
        VmEffectSummary::from_operation(&self.operation)
    }
}

#[derive(Debug)]
pub(crate) struct CompletedVmEffect {
    operation: CompletedMpcOperation,
    after_instruction: Option<Instruction>,
    hooks_enabled: bool,
}

impl CompletedVmEffect {
    pub(super) fn into_parts(self) -> (CompletedMpcOperation, Option<Instruction>, bool) {
        (self.operation, self.after_instruction, self.hooks_enabled)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VmEffectKind {
    Input,
    Multiply,
    BooleanBit,
    Open,
    BuiltinInput,
    BuiltinMul,
    BuiltinBatchMul,
    BuiltinOpen,
    BuiltinBatchOpen,
    BuiltinOther,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VmEffectSummary {
    pub(crate) kind: VmEffectKind,
    pub(crate) items: usize,
}

impl VmEffectSummary {
    fn from_operation(operation: &PendingMpcOperation) -> Self {
        match operation {
            PendingMpcOperation::Input { .. } => Self::new(VmEffectKind::Input, 1),
            PendingMpcOperation::Multiply { .. } => Self::new(VmEffectKind::Multiply, 1),
            PendingMpcOperation::BooleanBit { .. } => Self::new(VmEffectKind::BooleanBit, 1),
            PendingMpcOperation::Open { .. } => Self::new(VmEffectKind::Open, 1),
            PendingMpcOperation::BuiltinCall(call) => match call.operation() {
                PendingMpcBuiltinOperation::InputShare { .. } => {
                    Self::new(VmEffectKind::BuiltinInput, 1)
                }
                PendingMpcBuiltinOperation::Mul { .. } => Self::new(VmEffectKind::BuiltinMul, 1),
                PendingMpcBuiltinOperation::BatchMul { left_data, .. }
                | PendingMpcBuiltinOperation::BatchMulMixed { left_data, .. } => {
                    Self::new(VmEffectKind::BuiltinBatchMul, left_data.len())
                }
                PendingMpcBuiltinOperation::Open { .. } => Self::new(VmEffectKind::BuiltinOpen, 1),
                PendingMpcBuiltinOperation::BatchOpen { share_data, .. } => {
                    Self::new(VmEffectKind::BuiltinBatchOpen, share_data.len())
                }
                _ => Self::new(VmEffectKind::BuiltinOther, 1),
            },
        }
    }

    const fn new(kind: VmEffectKind, items: usize) -> Self {
        Self { kind, items }
    }
}
