use super::{services::ForeignFunctionVmServices, ForeignArguments, ForeignFunctionCallbackResult};
use crate::error::VmResult;
use crate::runtime_hooks::HookEvent;
use parking_lot::Mutex;
use std::sync::Arc;
use stoffel_vm_types::core_types::{ForeignObjectRef, Value};

/// Context passed to foreign functions.
///
/// The context is the narrow bridge between Rust callbacks and VM services:
/// arguments are exposed immutably, while VM interaction goes through focused
/// extension impls in this module family.
pub struct ForeignFunctionContext<'a> {
    pub(super) args: &'a [Value],
    pub(super) services: &'a mut dyn ForeignFunctionVmServices,
}

impl<'a> ForeignFunctionContext<'a> {
    pub(crate) fn new(args: &'a [Value], services: &'a mut dyn ForeignFunctionVmServices) -> Self {
        Self { args, services }
    }

    /// All arguments passed to this foreign call.
    pub fn args(&self) -> &[Value] {
        self.args
    }

    /// Number of arguments passed to this foreign call.
    pub fn len(&self) -> usize {
        self.args.len()
    }

    /// Whether this foreign call received no arguments.
    pub fn is_empty(&self) -> bool {
        self.args.is_empty()
    }

    /// Get an argument by index.
    pub fn arg(&self, index: usize) -> Option<&Value> {
        self.args.get(index)
    }

    /// View this call's arguments through a named validation helper.
    pub fn named_args(&self, function: &'static str) -> ForeignArguments<'_> {
        ForeignArguments::new(function, self.args)
    }

    /// Retrieve a typed Rust object previously registered as a VM foreign object.
    pub fn get_foreign_object<T: 'static + Send + Sync>(
        &self,
        object_ref: ForeignObjectRef,
    ) -> Option<Arc<Mutex<T>>> {
        self.services
            .get_foreign_object_any_ref(object_ref)
            .and_then(|object| object.downcast::<Mutex<T>>().ok())
    }

    /// Retrieve a typed Rust object previously registered as a VM foreign object.
    pub fn get_foreign_object_ref<T: 'static + Send + Sync>(
        &self,
        object_ref: ForeignObjectRef,
    ) -> Option<Arc<Mutex<T>>> {
        self.get_foreign_object(object_ref)
    }

    /// Emit a line through the VM's configured output sink.
    pub fn write_output_line(&self, line: &str) -> ForeignFunctionCallbackResult<()> {
        Ok(self.services.write_output_line(line)?)
    }

    pub(crate) fn trigger_hook_with_snapshot(&self, event: &HookEvent) -> VmResult<()> {
        self.services.trigger_hook_with_snapshot(event)
    }

    pub(crate) fn hooks_enabled(&self) -> bool {
        self.services.hooks_enabled()
    }

    pub(crate) fn create_closure_value(
        &mut self,
        function_name: String,
        upvalue_names: &[String],
    ) -> VmResult<Value> {
        self.services
            .create_closure_value(function_name, upvalue_names)
    }

    pub(crate) fn call_closure_value(
        &mut self,
        closure_value: &Value,
        args: &[Value],
    ) -> VmResult<()> {
        self.services.call_closure_value(closure_value, args)
    }

    pub(crate) fn get_upvalue_value(&self, name: &str) -> VmResult<Value> {
        self.services.get_upvalue_value(name)
    }

    pub(crate) fn set_upvalue_value(&mut self, name: &str, new_value: Value) -> VmResult<()> {
        self.services.set_upvalue_value(name, new_value)
    }
}
