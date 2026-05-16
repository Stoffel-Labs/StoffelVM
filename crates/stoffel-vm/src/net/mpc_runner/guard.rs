use std::sync::Arc;

use parking_lot::Mutex;

use crate::core_vm::VirtualMachine;

use super::error::{MpcRunnerError, MpcRunnerResult};

pub(super) struct RunnerVmGuard {
    vm_slot: Arc<Mutex<Option<VirtualMachine>>>,
    vm: Option<VirtualMachine>,
}

impl RunnerVmGuard {
    pub(super) fn take(vm_slot: &Arc<Mutex<Option<VirtualMachine>>>) -> MpcRunnerResult<Self> {
        let vm = vm_slot
            .lock()
            .take()
            .ok_or(MpcRunnerError::VmAlreadyExecuting)?;
        Ok(Self {
            vm_slot: Arc::clone(vm_slot),
            vm: Some(vm),
        })
    }

    pub(super) fn vm_mut(&mut self) -> MpcRunnerResult<&mut VirtualMachine> {
        self.vm.as_mut().ok_or(MpcRunnerError::VmGuardEmpty)
    }

    pub(super) fn restore(mut self) -> MpcRunnerResult<()> {
        let vm = self.vm.take().ok_or(MpcRunnerError::VmGuardEmpty)?;
        restore_vm_slot(&self.vm_slot, vm)
    }
}

impl Drop for RunnerVmGuard {
    fn drop(&mut self) {
        if let Some(vm) = self.vm.take() {
            let restore_result = restore_vm_slot(&self.vm_slot, vm);
            debug_assert!(restore_result.is_ok(), "failed to restore runner VM slot");
        }
    }
}

fn restore_vm_slot(
    vm_slot: &Arc<Mutex<Option<VirtualMachine>>>,
    vm: VirtualMachine,
) -> MpcRunnerResult<()> {
    let mut slot = vm_slot.lock();
    if slot.is_none() {
        *slot = Some(vm);
        Ok(())
    } else {
        Err(MpcRunnerError::VmSlotOccupiedDuringRestore)
    }
}
