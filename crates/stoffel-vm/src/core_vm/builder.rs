use super::VirtualMachine;
use crate::net::mpc_engine::MpcEngine;
use crate::output::VmOutputSink;
use crate::vm_state::{VMState, VMStateConfig};
use crate::VirtualMachineResult;
use std::sync::Arc;
use stoffel_vm_types::core_types::TableMemory;
use stoffel_vm_types::registers::RegisterLayout;

impl Default for VirtualMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualMachine {
    /// Fallibly create a VM with the default standard library and MPC builtins.
    pub fn try_new() -> VirtualMachineResult<Self> {
        Self::builder().try_build()
    }

    /// Create a VM with the default standard library and MPC builtins.
    ///
    /// Panics if default builtin registration fails. Prefer
    /// [`VirtualMachine::try_new`] in code that should surface construction
    /// errors to callers.
    pub fn new() -> Self {
        Self::builder().build()
    }

    fn empty() -> Self {
        Self::empty_with_state_config(VMStateConfig::default())
    }

    fn empty_with_state_config(config: VMStateConfig) -> Self {
        VirtualMachine {
            state: VMState::from_config(config),
        }
    }

    pub fn builder() -> VirtualMachineBuilder {
        VirtualMachineBuilder::default()
    }

    pub fn without_builtins() -> Self {
        Self::empty()
    }

    /// Fallibly create a VM with its own independent state.
    ///
    /// Kept as a named constructor for call sites that make isolation explicit.
    pub fn try_new_independent() -> VirtualMachineResult<Self> {
        Self::try_new()
    }

    /// Create a VM with its own independent state.
    ///
    /// Panics if default builtin registration fails. Prefer
    /// [`VirtualMachine::try_new_independent`] in code that should surface
    /// construction errors to callers.
    pub fn new_independent() -> Self {
        Self::new()
    }
}

pub struct VirtualMachineBuilder {
    standard_library: bool,
    mpc_builtins: bool,
    mpc_engine: Option<Arc<dyn MpcEngine>>,
    register_layout: RegisterLayout,
    table_memory: Option<Box<dyn TableMemory>>,
    output_sink: Option<Arc<dyn VmOutputSink>>,
}

impl Default for VirtualMachineBuilder {
    fn default() -> Self {
        Self {
            standard_library: true,
            mpc_builtins: true,
            mpc_engine: None,
            register_layout: RegisterLayout::default(),
            table_memory: None,
            output_sink: None,
        }
    }
}

impl VirtualMachineBuilder {
    pub fn with_standard_library(mut self, enabled: bool) -> Self {
        self.standard_library = enabled;
        self
    }

    pub fn with_mpc_builtins(mut self, enabled: bool) -> Self {
        self.mpc_builtins = enabled;
        self
    }

    pub fn with_mpc_engine(mut self, engine: Arc<dyn MpcEngine>) -> Self {
        self.mpc_engine = Some(engine);
        self
    }

    pub fn with_register_layout(mut self, layout: RegisterLayout) -> Self {
        self.register_layout = layout;
        self
    }

    pub fn with_table_memory<M>(mut self, memory: M) -> Self
    where
        M: TableMemory + 'static,
    {
        self.table_memory = Some(Box::new(memory));
        self
    }

    pub fn with_boxed_table_memory(mut self, memory: Box<dyn TableMemory>) -> Self {
        self.table_memory = Some(memory);
        self
    }

    pub fn with_output_sink<S>(mut self, output_sink: S) -> Self
    where
        S: VmOutputSink + 'static,
    {
        self.output_sink = Some(Arc::new(output_sink));
        self
    }

    pub fn with_shared_output_sink(mut self, output_sink: Arc<dyn VmOutputSink>) -> Self {
        self.output_sink = Some(output_sink);
        self
    }

    pub fn try_build(self) -> VirtualMachineResult<VirtualMachine> {
        let mut state_config = VMStateConfig::default().with_register_layout(self.register_layout);
        if let Some(table_memory) = self.table_memory {
            state_config = state_config.with_table_memory(table_memory);
        }
        if let Some(engine) = self.mpc_engine {
            state_config = state_config.with_mpc_engine(engine);
        }
        if let Some(output_sink) = self.output_sink {
            state_config = state_config.with_output_sink(output_sink);
        }
        let mut vm = VirtualMachine::empty_with_state_config(state_config);

        if self.standard_library {
            vm.try_register_standard_library()?;
        }

        if self.mpc_builtins {
            vm.try_register_mpc_builtins()?;
        }

        Ok(vm)
    }

    #[track_caller]
    pub fn build(self) -> VirtualMachine {
        self.try_build()
            .expect("invalid virtual machine builder configuration")
    }
}
