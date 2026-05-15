use super::VMState;
use crate::error::{VmError, VmResult};
use crate::reveal_destination::RevealDestination;
use crate::runtime_instruction::RuntimeRegister;
use stoffel_vm_types::core_types::Value;

#[derive(Debug, Clone)]
pub(super) struct ResolvedRegister {
    value: Value,
}

impl ResolvedRegister {
    fn new(value: Value) -> Self {
        Self { value }
    }

    pub(super) fn value(&self) -> &Value {
        &self.value
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

    pub(super) fn left_value(&self) -> &Value {
        self.left.value()
    }

    pub(super) fn right_value(&self) -> &Value {
        self.right.value()
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
        Self::ensure_frame_contains_register(record, register)?;
        let register_index = register.register_index();
        let register_number = register.index();
        let value = record.register(register_index).cloned().ok_or(
            VmError::PendingRevealWithoutQueuedBatch {
                register: register_number,
            },
        )?;

        Ok(ResolvedRegister::new(value))
    }

    #[inline]
    pub(super) fn current_register_pair(
        &self,
        left_register: RuntimeRegister,
        right_register: RuntimeRegister,
    ) -> VmResult<ResolvedRegisterPair> {
        Ok(ResolvedRegisterPair::new(
            self.current_register_value(left_register)?,
            self.current_register_value(right_register)?,
        ))
    }

    #[inline]
    pub(super) fn resolve_register(
        &mut self,
        register: RuntimeRegister,
    ) -> VmResult<ResolvedRegister> {
        self.ensure_registers_resolved(&[register])?;
        self.current_register_value(register)
    }

    #[inline]
    pub(super) fn resolve_register_pair(
        &mut self,
        left_register: RuntimeRegister,
        right_register: RuntimeRegister,
    ) -> VmResult<ResolvedRegisterPair> {
        self.ensure_registers_resolved(&[left_register, right_register])?;
        self.current_register_pair(left_register, right_register)
    }

    fn ensure_registers_resolved(&mut self, regs: &[RuntimeRegister]) -> VmResult<()> {
        let record = self.current_frame()?;
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

        let record = self.current_frame()?;
        for &reg in regs {
            let register_index = reg.register_index();
            if record.register(register_index).is_none() {
                return Err(VmError::PendingRevealWithoutQueuedBatch {
                    register: reg.index(),
                });
            }
        }

        Ok(())
    }
}
