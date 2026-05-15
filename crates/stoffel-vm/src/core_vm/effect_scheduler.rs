use crate::error::VmResult;
use crate::net::mpc_engine::AsyncMpcEngine;
use crate::vm_state::{CallStackCheckpoint, VMState, VmExecutionBudget, VmRunSlice};
use stoffel_vm_types::core_types::Value;

const DEFAULT_LOCAL_INSTRUCTION_BUDGET: usize = 1024;

#[derive(Debug, Clone, Copy)]
pub(crate) struct AsyncEffectScheduler {
    local_budget: VmExecutionBudget,
}

impl Default for AsyncEffectScheduler {
    fn default() -> Self {
        Self::new(DEFAULT_LOCAL_INSTRUCTION_BUDGET)
    }
}

impl AsyncEffectScheduler {
    pub(crate) const fn new(local_instruction_budget: usize) -> Self {
        Self {
            local_budget: VmExecutionBudget::max_instructions(local_instruction_budget),
        }
    }

    pub(crate) async fn execute_to_depth<E: AsyncMpcEngine + ?Sized>(
        self,
        state: &mut VMState,
        checkpoint: CallStackCheckpoint,
        engine: &E,
    ) -> VmResult<Value> {
        loop {
            match state.run_until_effect_or_budget_to_depth(checkpoint, self.local_budget)? {
                VmRunSlice::Complete(value) => return Ok(value),
                VmRunSlice::BudgetExhausted => tokio::task::yield_now().await,
                VmRunSlice::Yield(effect) => {
                    state.ensure_async_engine_matches(engine)?;
                    let completed = effect.execute(engine).await?;
                    state.apply_completed_vm_effect(completed)?;
                }
            }
        }
    }
}
