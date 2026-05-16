use crate::vm_state::VMState;

mod builder;
mod effect_scheduler;
mod execution;
mod hooks;
mod mpc;
mod output;
mod registration;
mod table_memory;

pub use builder::VirtualMachineBuilder;
pub use execution::VmEntryInvocation;

/// The register-based virtual machine
pub struct VirtualMachine {
    state: VMState,
}

#[cfg(test)]
mod tests;
