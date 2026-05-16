use super::VMState;
use crate::error::{VmError, VmResult};
use crate::reveal_destination::RevealDestination;
use crate::runtime_instruction::RuntimeRegister;
use stoffel_vm_types::activations::ActivationRecord;
use stoffel_vm_types::core_types::Value;

#[derive(Debug, Clone)]
pub(super) struct ResolvedRegister {
    value: Value,
}

impl ResolvedRegister {
    fn new(value: Value) -> Self {
        Self { value }
    }

    pub(super) fn into_value(self) -> Value {
        self.value
    }
}

#[derive(Debug, Clone)]
pub(super) struct ResolvedRegisterPair {
    left: ResolvedRegister,
    right: ResolvedRegister,
}

impl ResolvedRegisterPair {
    fn new(left: ResolvedRegister, right: ResolvedRegister) -> Self {
        Self { left, right }
    }

    pub(super) fn into_values(self) -> (Value, Value) {
        (self.left.into_value(), self.right.into_value())
    }
}

impl VMState {
    #[inline]
    pub(super) fn current_register_value(
        &self,
        register: RuntimeRegister,
    ) -> VmResult<ResolvedRegister> {
        let record = self.current_frame()?;
        let value = Self::register_value_ref(record, register)?.clone();

        Ok(ResolvedRegister::new(value))
    }

    #[inline]
    pub(super) fn resolve_register(
        &mut self,
        register: RuntimeRegister,
    ) -> VmResult<ResolvedRegister> {
        self.ensure_registers_resolved(&[register])?;
        let record = self.current_frame()?;
        let value = Self::resolved_register_value_ref(record, register)?.clone();
        Ok(ResolvedRegister::new(value))
    }

    #[inline]
    pub(super) fn resolve_register_pair(
        &mut self,
        left_register: RuntimeRegister,
        right_register: RuntimeRegister,
    ) -> VmResult<ResolvedRegisterPair> {
        self.ensure_registers_resolved(&[left_register, right_register])?;
        let record = self.current_frame()?;
        Ok(ResolvedRegisterPair::new(
            ResolvedRegister::new(
                Self::resolved_register_value_ref(record, left_register)?.clone(),
            ),
            ResolvedRegister::new(
                Self::resolved_register_value_ref(record, right_register)?.clone(),
            ),
        ))
    }

    #[inline]
    pub(super) fn with_resolved_register<T>(
        &mut self,
        register: RuntimeRegister,
        f: impl FnOnce(&Value, &Self) -> VmResult<T>,
    ) -> VmResult<T> {
        self.ensure_registers_resolved(&[register])?;
        let record = self.current_frame()?;
        let value = Self::resolved_register_value_ref(record, register)?;
        f(value, self)
    }

    #[inline]
    pub(super) fn with_resolved_register_pair<T>(
        &mut self,
        left_register: RuntimeRegister,
        right_register: RuntimeRegister,
        f: impl FnOnce(&Value, &Value, &Self) -> VmResult<T>,
    ) -> VmResult<T> {
        self.ensure_registers_resolved(&[left_register, right_register])?;
        let record = self.current_frame()?;
        let left = Self::resolved_register_value_ref(record, left_register)?;
        let right = Self::resolved_register_value_ref(record, right_register)?;
        f(left, right, self)
    }

    fn ensure_registers_resolved(&mut self, regs: &[RuntimeRegister]) -> VmResult<()> {
        let record = self.current_frame()?;
        if !self.mpc_runtime.has_any_pending_reveals() {
            for &reg in regs {
                Self::ensure_frame_contains_register(record, reg)?;
            }
            return Ok(());
        }

        let frame_depth = self.current_frame_depth()?;

        let needs_flush = regs.iter().try_fold(false, |needs_flush, &reg| {
            Self::ensure_frame_contains_register(record, reg)?;
            Ok::<bool, VmError>(
                needs_flush
                    || self
                        .mpc_runtime
                        .has_pending_reveal_destination(RevealDestination::new(frame_depth, reg)),
            )
        })?;

        if needs_flush {
            self.flush_pending_reveals()?;
        }

        Ok(())
    }

    #[inline]
    fn register_value_ref(
        record: &ActivationRecord,
        register: RuntimeRegister,
    ) -> VmResult<&Value> {
        Self::ensure_frame_contains_register(record, register)?;
        record
            .register(register.register_index())
            .ok_or(VmError::PendingRevealWithoutQueuedBatch {
                register: register.index(),
            })
    }

    #[inline]
    fn resolved_register_value_ref(
        record: &ActivationRecord,
        register: RuntimeRegister,
    ) -> VmResult<&Value> {
        record
            .register(register.register_index())
            .ok_or(VmError::PendingRevealWithoutQueuedBatch {
                register: register.index(),
            })
    }
}
