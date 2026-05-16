use super::VirtualMachine;
use crate::runtime_hooks::{HookCallbackError, HookCallbackResult, HookContext, HookEvent, HookId};
use crate::VirtualMachineResult;

impl VirtualMachine {
    /// Register a hook with the VM and return a typed hook handle.
    pub fn try_register_hook<P, C>(
        &mut self,
        predicate: P,
        callback: C,
        priority: i32,
    ) -> VirtualMachineResult<HookId>
    where
        P: Fn(&HookEvent) -> bool + 'static + Send + Sync,
        C: Fn(&HookEvent, &HookContext) -> Result<(), String> + 'static + Send + Sync,
    {
        self.try_register_typed_hook(
            predicate,
            move |event, context| callback(event, context).map_err(HookCallbackError::from),
            priority,
        )
    }

    /// Register a typed hook with the VM and return a typed hook handle.
    pub fn try_register_typed_hook<P, C>(
        &mut self,
        predicate: P,
        callback: C,
        priority: i32,
    ) -> VirtualMachineResult<HookId>
    where
        P: Fn(&HookEvent) -> bool + 'static + Send + Sync,
        C: Fn(&HookEvent, &HookContext) -> HookCallbackResult + 'static + Send + Sync,
    {
        Ok(self
            .state
            .try_register_hook_boxed(Box::new(predicate), Box::new(callback), priority)?)
    }

    #[track_caller]
    pub fn register_hook<P, C>(&mut self, predicate: P, callback: C, priority: i32) -> HookId
    where
        P: Fn(&HookEvent) -> bool + 'static + Send + Sync,
        C: Fn(&HookEvent, &HookContext) -> Result<(), String> + 'static + Send + Sync,
    {
        self.try_register_hook(predicate, callback, priority)
            .expect("invalid hook registration")
    }

    #[track_caller]
    pub fn register_typed_hook<P, C>(&mut self, predicate: P, callback: C, priority: i32) -> HookId
    where
        P: Fn(&HookEvent) -> bool + 'static + Send + Sync,
        C: Fn(&HookEvent, &HookContext) -> HookCallbackResult + 'static + Send + Sync,
    {
        self.try_register_typed_hook(predicate, callback, priority)
            .expect("invalid hook registration")
    }

    /// Unregister a hook by typed handle.
    pub fn unregister_hook(&mut self, hook_id: HookId) -> bool {
        self.state.unregister_hook(hook_id)
    }

    /// Enable a hook by typed handle.
    pub fn enable_hook(&mut self, hook_id: HookId) -> bool {
        self.state.enable_hook(hook_id)
    }

    /// Disable a hook by typed handle.
    pub fn disable_hook(&mut self, hook_id: HookId) -> bool {
        self.state.disable_hook(hook_id)
    }
}
