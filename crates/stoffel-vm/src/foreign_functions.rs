use std::hash::{Hash, Hasher};
use std::sync::Arc;
use stoffel_vm_types::core_types::Value;
use stoffel_vm_types::functions::VMFunction;
use crate::vm_state::VMState;

/// Foreign (native) function type
///
/// This type represents a Rust function that can be called from the VM.
/// It takes a context containing arguments and VM state, and returns
/// either a value or an error string.
pub type ForeignFunctionPtr =
    Arc<dyn Fn(ForeignFunctionContext) -> Result<Value, String> + Send + Sync>;

/// Context passed to foreign functions
///
/// This structure provides foreign functions with:
/// 1. Access to their arguments
/// 2. Access to the VM state for interacting with the VM
///
/// Foreign functions can use this context to read arguments, manipulate
/// VM state, and interact with objects and arrays in the VM.
pub struct ForeignFunctionContext<'a> {
    /// Arguments passed to the function
    pub args: &'a [Value],
    /// Reference to the VM state for interaction
    pub vm_state: &'a mut VMState,
}

/// Foreign function wrapper
///
/// This structure wraps a Rust function to make it callable from the VM.
/// It associates a name with the function for lookup in the VM's function registry.
///
/// Foreign functions are a key part of the VM's FFI system, allowing the VM
/// to call into Rust code for functionality that would be difficult or inefficient
/// to implement in the VM's instruction set.
pub struct ForeignFunction {
    /// Name of the function (used for lookup)
    pub name: String,
    /// The actual Rust function implementation
    pub func: ForeignFunctionPtr,
}

impl PartialEq for ForeignFunction {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for ForeignFunction {}

impl Hash for ForeignFunction {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
    }
}

impl Clone for ForeignFunction {
    fn clone(&self) -> Self {
        ForeignFunction {
            name: self.name.clone(),
            func: Arc::clone(&self.func),
        }
    }
}

/// Function definition - can be either VM or foreign
///
/// This enum represents the two types of functions supported by the VM:
/// 1. VM functions defined in the VM's instruction set
/// 2. Foreign functions implemented in Rust
///
/// The VM treats both types uniformly when calling them, but their
/// implementations and execution models differ significantly.
#[derive(Clone, Hash)]
pub enum Function {
    /// A function defined in the VM's instruction set
    VM(VMFunction),
    /// A function implemented in Rust and exposed to the VM
    Foreign(ForeignFunction),
}