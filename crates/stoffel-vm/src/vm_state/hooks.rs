use super::VMState;
use crate::error::{VmError, VmResult};
use crate::runtime_hooks::{HookCallback, HookContext, HookEvent, HookId, HookPredicate};

impl VMState {
    pub(crate) fn hook_context(&self) -> HookContext<'_> {
        HookContext::new(
            self.call_stack.as_slice(),
            self.current_instruction.clone(),
            &self.program,
        )
    }

    pub(crate) fn try_register_hook_boxed(
        &mut self,
        predicate: Box<HookPredicate>,
        callback: Box<HookCallback>,
        priority: i32,
    ) -> VmResult<HookId> {
        self.hook_manager
            .try_register_hook(predicate, callback, priority)
            .map_err(VmError::from)
    }

    pub(crate) fn unregister_hook(&mut self, hook_id: HookId) -> bool {
        self.hook_manager.unregister_hook(hook_id)
    }

    pub(crate) fn enable_hook(&mut self, hook_id: HookId) -> bool {
        self.hook_manager.enable_hook(hook_id)
    }

    pub(crate) fn disable_hook(&mut self, hook_id: HookId) -> bool {
        self.hook_manager.disable_hook(hook_id)
    }

    /// Check if hooks are enabled (fast path).
    #[inline(always)]
    pub(crate) fn hooks_enabled(&self) -> bool {
        self.hook_manager.has_enabled_hooks()
    }

    /// Trigger a hook event with a snapshot of the current VM state.
    #[inline]
    pub(crate) fn trigger_hook_with_snapshot(&self, event: &HookEvent) -> VmResult<()> {
        if !self.hook_manager.has_enabled_hooks() {
            return Ok(());
        }

        let context = self.hook_context();
        Ok(self.hook_manager.trigger_with_context(event, &context)?)
    }
}
