use super::VMState;
use crate::error::{VmError, VmResult};
use crate::reveal_destination::{FrameDepth, RevealDestination};
use crate::runtime_hooks::{HookEvent, HookRegister, RegisterWritePreviousValue};
use crate::runtime_instruction::{RuntimeFunction, RuntimeRegister};
use std::sync::Arc;
use stoffel_vm_types::activations::ActivationRecord;
use stoffel_vm_types::core_types::Value;
use stoffel_vm_types::registers::{RegisterIndex, RegisterLayout};

impl VMState {
    pub(super) fn push_activation_frame(
        &mut self,
        record: ActivationRecord,
        runtime_function: Option<Arc<RuntimeFunction>>,
    ) {
        debug_assert_eq!(self.call_stack.len(), self.frame_runtime_functions.len());
        self.call_stack.push(record);
        self.frame_runtime_functions.push(runtime_function);
    }

    pub(super) fn pop_activation_frame(&mut self) -> Option<ActivationRecord> {
        debug_assert_eq!(self.call_stack.len(), self.frame_runtime_functions.len());
        let runtime_function = self.frame_runtime_functions.pop();
        let record = self.call_stack.pop();
        debug_assert_eq!(record.is_some(), runtime_function.is_some());
        record
    }

    pub(super) fn truncate_activation_frames(&mut self, depth: usize) {
        self.call_stack.truncate(depth);
        self.frame_runtime_functions.truncate(depth);
        debug_assert_eq!(self.call_stack.len(), self.frame_runtime_functions.len());
    }

    /// Get the current activation record or return a VM error instead of panicking.
    #[inline]
    pub(crate) fn current_frame(&self) -> VmResult<&ActivationRecord> {
        self.call_stack
            .current()
            .ok_or(VmError::NoActiveActivationRecord)
    }

    /// Get the current mutable activation record or return a VM error instead of panicking.
    #[inline]
    pub(crate) fn current_frame_mut(&mut self) -> VmResult<&mut ActivationRecord> {
        self.call_stack
            .current_mut()
            .ok_or(VmError::NoActiveActivationRecord)
    }

    pub(super) fn current_runtime_function(&mut self) -> VmResult<Arc<RuntimeFunction>> {
        let frame_depth = self.current_frame_depth()?.depth();
        if let Some(Some(runtime_function)) = self.frame_runtime_functions.get(frame_depth) {
            return Ok(Arc::clone(runtime_function));
        }

        let function_name = self.current_frame()?.function_name().to_owned();
        let runtime_function = self.program.runtime_function(&function_name)?;
        let slot = self
            .frame_runtime_functions
            .get_mut(frame_depth)
            .ok_or(VmError::NoActiveActivationRecord)?;
        *slot = Some(Arc::clone(&runtime_function));

        Ok(runtime_function)
    }

    #[inline]
    pub(super) fn register_out_of_bounds(register: usize, register_count: usize) -> VmError {
        VmError::RegisterOutOfBounds {
            register,
            register_count,
        }
    }

    #[inline]
    pub(super) fn current_register_layout(&self) -> VmResult<RegisterLayout> {
        Ok(self.current_frame()?.register_layout())
    }

    #[inline]
    pub(super) fn current_frame_depth(&self) -> VmResult<FrameDepth> {
        self.call_stack_depth()
            .checked_sub(1)
            .map(FrameDepth::new)
            .ok_or(VmError::NoActiveActivationRecord)
    }

    #[inline]
    pub(super) fn share_runtime(&self) -> VmResult<crate::net::share_runtime::MpcShareRuntime<'_>> {
        self.mpc_runtime.share_runtime()
    }

    #[inline]
    pub(super) fn current_return_register(&self) -> VmResult<RuntimeRegister> {
        RuntimeRegister::return_register(self.current_frame()?.register_count())
    }

    #[inline]
    pub(super) fn hook_register(&self, register: RuntimeRegister) -> VmResult<HookRegister> {
        let record = self.current_frame()?;
        Self::ensure_frame_contains_register(record, register)?;
        Ok(HookRegister::new(
            register.index(),
            record.register_layout(),
        ))
    }

    #[inline]
    pub(super) fn write_current_register(
        &mut self,
        register: RuntimeRegister,
        value: Value,
        hooks_enabled: bool,
    ) -> VmResult<()> {
        if !hooks_enabled {
            return self.assign_current_register_without_previous(register, value);
        }

        let (old_value, value) = self.assign_current_register(register, value)?;

        let event = HookEvent::RegisterWrite(self.hook_register(register)?, old_value, value);
        self.trigger_hook_with_snapshot(&event)?;
        Ok(())
    }

    pub(super) fn assign_current_register_without_previous(
        &mut self,
        register: RuntimeRegister,
        value: Value,
    ) -> VmResult<()> {
        if !self.mpc_runtime.has_any_pending_reveals() {
            let register_index = register.register_index();
            let register_number = register.index();
            let record = self.current_frame_mut()?;
            Self::ensure_frame_contains_register(record, register)?;

            if record.register_layout().is_clear(register_index) {
                if let Some(slot) = record.register_mut(register_index) {
                    *slot = value;
                    return Ok(());
                }

                let register_count = record.register_count();
                record
                    .replace_register_value(register_index, value)
                    .ok_or_else(|| Self::register_out_of_bounds(register_number, register_count))?;
                return Ok(());
            }
        }

        let (register_index, register_number, value) =
            self.prepare_current_register_write(register, value)?;
        self.replace_current_register_value(register_index, register_number, value)?;
        Ok(())
    }

    pub(super) fn assign_current_register(
        &mut self,
        register: RuntimeRegister,
        value: Value,
    ) -> VmResult<(RegisterWritePreviousValue, Value)> {
        let (register_index, register_number, value) =
            self.prepare_current_register_write(register, value)?;
        let old_value =
            self.replace_current_register_value(register_index, register_number, value.clone())?;
        Ok((RegisterWritePreviousValue::from(old_value), value))
    }

    #[inline]
    fn prepare_current_register_write(
        &mut self,
        register: RuntimeRegister,
        value: Value,
    ) -> VmResult<(RegisterIndex, usize, Value)> {
        let register_index = register.register_index();
        let register_number = register.index();
        let layout = {
            let record = self.current_frame()?;
            Self::ensure_frame_contains_register(record, register)?;
            record.register_layout()
        };
        let value = self.prepare_register_write_value_for_layout(layout, register_index, value)?;
        if self.mpc_runtime.has_any_pending_reveals() {
            let frame_depth = self.current_frame_depth()?;
            let destination = RevealDestination::new(frame_depth, register);
            self.mpc_runtime.cancel_reveal_destination(destination);
        }

        Ok((register_index, register_number, value))
    }

    #[inline]
    fn replace_current_register_value(
        &mut self,
        register_index: RegisterIndex,
        register_number: usize,
        value: Value,
    ) -> VmResult<stoffel_vm_types::registers::RegisterSlot> {
        let record = self.current_frame_mut()?;
        let register_count = record.register_count();
        record
            .replace_register_value(register_index, value)
            .ok_or_else(|| Self::register_out_of_bounds(register_number, register_count))
    }

    pub(super) fn ensure_frame_contains_register(
        record: &ActivationRecord,
        register: RuntimeRegister,
    ) -> VmResult<()> {
        let register_count = record.register_count();
        if register.index() < register_count {
            Ok(())
        } else {
            Err(Self::register_out_of_bounds(
                register.index(),
                register_count,
            ))
        }
    }

    fn write_pending_reveal_placeholder(&mut self, dest: RuntimeRegister) -> VmResult<()> {
        let dest_reg = dest.register_index();
        let dest_number = dest.index();
        let record = self.current_frame_mut()?;
        let register_count = record.register_count();
        record
            .set_register_pending_reveal(dest_reg)
            .ok_or_else(|| Self::register_out_of_bounds(dest_number, register_count))?;
        Ok(())
    }

    pub(super) fn prepare_register_write_value(
        &self,
        register: RuntimeRegister,
        value: Value,
    ) -> VmResult<Value> {
        let layout = self.current_register_layout()?;
        self.prepare_register_write_value_for_layout(layout, register.register_index(), value)
    }

    pub(super) fn prepare_register_write_value_for_layout(
        &self,
        layout: RegisterLayout,
        register: RegisterIndex,
        value: Value,
    ) -> VmResult<Value> {
        if !layout.is_secret(register) {
            return Ok(value);
        }

        match value {
            Value::Share(_, _) | Value::Unit => Ok(value),
            clear => {
                self.convert_to_share(&clear)
                    .map_err(|err| VmError::ClearValueInSecretRegister {
                        value_type: clear.type_name(),
                        register: register.index(),
                        reason: err.to_string(),
                    })
            }
        }
    }

    /// Convert a clear value to a secret share.
    #[inline]
    pub(super) fn convert_to_share(&self, value: &Value) -> VmResult<Value> {
        self.share_runtime()?.share_clear_value(value)
    }

    /// Reveal a secret share to a clear value immediately, without batching.
    #[inline]
    pub(super) fn reveal_share_immediate(&self, value: &Value) -> VmResult<Value> {
        self.share_runtime()?.open_share_value(value)
    }

    /// Queue a secret share reveal to a clear register.
    pub(super) fn queue_reveal_to_register(
        &mut self,
        value: &Value,
        dest: RuntimeRegister,
    ) -> VmResult<()> {
        if !self.mpc_runtime.is_reveal_batching_enabled() {
            let revealed = self.reveal_share_immediate(value)?;
            return self.write_current_register(dest, revealed, false);
        }

        self.mpc_runtime.ensure_ready()?;
        let frame_depth = self.current_frame_depth()?;
        let destination = RevealDestination::new(frame_depth, dest);

        match value {
            Value::Share(ty, sd) => {
                self.mpc_runtime.queue_reveal(destination, *ty, sd.clone());

                if self.mpc_runtime.should_auto_flush_reveals(frame_depth) {
                    self.flush_pending_reveals()
                } else {
                    self.write_pending_reveal_placeholder(dest)
                }
            }
            _ => Err(VmError::InvalidShareRevealValue),
        }
    }

    /// Flush all pending reveals and update destination registers.
    pub(super) fn flush_pending_reveals(&mut self) -> VmResult<()> {
        let frame_depth = self.current_frame_depth()?;
        if !self.mpc_runtime.has_pending_reveals(frame_depth) {
            return Ok(());
        }

        let results = self.mpc_runtime.flush_reveals(frame_depth)?;
        let results = results
            .into_iter()
            .map(|revealed| {
                let (destination, value) = revealed.into_parts();
                debug_assert_eq!(destination.frame_depth(), frame_depth);
                let register = destination.register();
                self.prepare_register_write_value(register, value)
                    .map(|value| (register, value))
            })
            .collect::<Result<Vec<_>, _>>()?;

        for (reg, value) in results {
            self.assign_current_register_without_previous(reg, value)?;
        }

        Ok(())
    }
}
