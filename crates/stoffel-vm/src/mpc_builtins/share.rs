use crate::core_vm::VirtualMachine;
use crate::VirtualMachineResult;

mod constructors;
mod local_ops;
mod metadata;
mod network_ops;
mod result;

/// Register Share module builtins.
pub(crate) fn register(vm: &mut VirtualMachine) -> VirtualMachineResult<()> {
    constructors::register(vm)?;
    local_ops::register(vm)?;
    network_ops::register(vm)?;
    metadata::register(vm)?;
    Ok(())
}
