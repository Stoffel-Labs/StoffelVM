use super::effect_scheduler::AsyncEffectScheduler;
use super::VirtualMachine;
use crate::foreign_functions::ForeignFunctionContext;
use crate::net::mpc_engine::AsyncMpcEngine;
use crate::{error::VmError, VirtualMachineResult};
use stoffel_vm_types::core_types::Value;

/// One VM entry-point invocation in a concurrent async execution batch.
///
/// Batched execution clones the VM's immutable program metadata into an
/// independent runtime state per invocation, so activation stacks, registers,
/// pending reveals, and table memory do not alias between concurrently running
/// programs.
#[derive(Debug, Clone, PartialEq)]
pub struct VmEntryInvocation {
    function_name: String,
    args: Vec<Value>,
}

impl VmEntryInvocation {
    pub fn new(function_name: impl Into<String>, args: impl Into<Vec<Value>>) -> Self {
        Self {
            function_name: function_name.into(),
            args: args.into(),
        }
    }

    pub fn without_args(function_name: impl Into<String>) -> Self {
        Self::new(function_name, Vec::new())
    }

    pub fn function_name(&self) -> &str {
        &self.function_name
    }

    pub fn args(&self) -> &[Value] {
        &self.args
    }
}

impl VirtualMachine {
    fn execute_vm_entry_with_args<F>(
        &mut self,
        function_name: &str,
        args: &[Value],
        foreign_error: F,
    ) -> VirtualMachineResult<Value>
    where
        F: FnOnce(&str) -> VmError,
    {
        let base_depth = self
            .state
            .push_entry_frame(function_name, args, foreign_error)?;
        Ok(self.state.execute_until_return_to_depth(base_depth)?)
    }

    async fn execute_vm_entry_async_with_args<E, F>(
        &mut self,
        function_name: &str,
        args: &[Value],
        async_engine: &E,
        foreign_error: F,
    ) -> VirtualMachineResult<Value>
    where
        E: AsyncMpcEngine + ?Sized,
        F: FnOnce(&str) -> VmError,
    {
        let base_depth = self
            .state
            .push_entry_frame(function_name, args, foreign_error)?;
        let result = AsyncEffectScheduler::default()
            .execute_to_depth(&mut self.state, base_depth, async_engine)
            .await;
        if result.is_err() {
            self.state.unwind_call_stack_to(base_depth);
        }
        Ok(result?)
    }

    pub fn execute_with_args(
        &mut self,
        function_name: &str,
        args: &[Value],
    ) -> VirtualMachineResult<Value> {
        let foreign_function = self.state.foreign_function(function_name)?;

        if let Some(foreign_function) = foreign_function {
            return Ok(foreign_function
                .call(ForeignFunctionContext::new(args, &mut self.state))
                .map_err(VmError::from)?);
        }

        self.execute_vm_entry_with_args(function_name, args, Self::foreign_entry_error)
    }

    /// Execute a zero-argument VM function.
    ///
    /// Use [`VirtualMachine::execute_with_args`] when the entry point expects
    /// parameters or when intentionally invoking a foreign function directly.
    pub fn execute(&mut self, main_function: &str) -> VirtualMachineResult<Value> {
        self.execute_vm_entry_with_args(main_function, &[], Self::foreign_entry_error)
    }

    /// Execute the VM with a given main function using async MPC operations.
    ///
    /// This version uses the async-native execution which only awaits when
    /// MPC operations (like share multiplication) are needed.
    pub async fn execute_async<E: AsyncMpcEngine + ?Sized>(
        &mut self,
        main_function: &str,
        async_engine: &E,
    ) -> VirtualMachineResult<Value> {
        self.execute_async_with_args(main_function, &[], async_engine)
            .await
    }

    /// Execute a VM function with arguments using async MPC operations.
    ///
    /// The entry point must be a VM function. Foreign functions are synchronous
    /// callbacks and can be invoked through [`VirtualMachine::execute_with_args`].
    pub async fn execute_async_with_args<E: AsyncMpcEngine + ?Sized>(
        &mut self,
        main_function: &str,
        args: &[Value],
        async_engine: &E,
    ) -> VirtualMachineResult<Value> {
        self.execute_vm_entry_async_with_args(
            main_function,
            args,
            async_engine,
            Self::foreign_entry_error,
        )
        .await
    }

    /// Execute multiple zero-argument VM entry points concurrently.
    ///
    /// Each entry point runs in an independent clone of this VM's runtime state.
    /// Instruction execution remains synchronous within a task, while async MPC
    /// effects yield back to the async scheduler so other entries can progress.
    /// Results are returned in the same order as the requested entry points.
    pub async fn execute_many_async<E, I, S>(
        &self,
        function_names: I,
        async_engine: &E,
    ) -> VirtualMachineResult<Vec<Value>>
    where
        E: AsyncMpcEngine + ?Sized,
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let invocations = function_names
            .into_iter()
            .map(|function_name| VmEntryInvocation::without_args(function_name.as_ref()));
        self.execute_many_async_with_args(invocations, async_engine)
            .await
    }

    /// Execute multiple VM entry-point invocations concurrently.
    ///
    /// This is the composable async boundary for running multiple VM programs
    /// over one MPC engine. The current VM acts as a template: every invocation
    /// gets an independent runtime clone, and the shared async MPC engine is
    /// awaited only when a VM task yields an online MPC effect.
    pub async fn execute_many_async_with_args<E, I>(
        &self,
        invocations: I,
        async_engine: &E,
    ) -> VirtualMachineResult<Vec<Value>>
    where
        E: AsyncMpcEngine + ?Sized,
        I: IntoIterator<Item = VmEntryInvocation>,
    {
        let mut executions = Vec::new();
        for invocation in invocations {
            let mut vm = self.try_clone_with_independent_state()?;
            executions.push(async move {
                vm.execute_async_with_args(
                    invocation.function_name(),
                    invocation.args(),
                    async_engine,
                )
                .await
            });
        }

        futures::future::try_join_all(executions).await
    }

    /// Execute a function specifically for benchmarking purposes.
    ///
    /// This zero-argument convenience wrapper skips the foreign-function entry
    /// lookup used by [`VirtualMachine::execute_with_args`]. Use
    /// [`VirtualMachine::execute_for_benchmark_with_args`] for parameterized
    /// benchmark functions.
    pub fn execute_for_benchmark(&mut self, function_name: &str) -> VirtualMachineResult<Value> {
        self.execute_for_benchmark_with_args(function_name, &[])
    }

    /// Execute a VM function with arguments for benchmarking purposes.
    ///
    /// This method assumes the function has already been registered. It still
    /// validates arity and register layout, but avoids the foreign-function
    /// direct-call path so benchmark loops measure VM dispatch consistently.
    pub fn execute_for_benchmark_with_args(
        &mut self,
        function_name: &str,
        args: &[Value],
    ) -> VirtualMachineResult<Value> {
        self.execute_vm_entry_with_args(function_name, args, Self::foreign_entry_error)
    }

    /// Create a clone of this VM with its own independent runtime state.
    ///
    /// Program metadata is shared immutably, while heap-like table memory is
    /// re-created through the configured table-memory backend.
    pub fn try_clone_with_independent_state(&self) -> VirtualMachineResult<Self> {
        Ok(Self {
            state: self.state.try_clone_with_independent_runtime()?,
        })
    }

    fn foreign_entry_error(function: &str) -> VmError {
        VmError::CannotExecuteForeignFunction {
            function: function.to_owned(),
        }
    }
}
