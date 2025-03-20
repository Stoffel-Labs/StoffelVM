use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use crate::instructions::Instruction;
use crate::core_types::Value;
use crate::vm_state::VMState;

/// VM function definition
#[derive(Clone, PartialEq, Eq)]
pub struct VMFunction {
    pub name: String,
    pub parameters: Vec<String>,
    pub upvalues: Vec<String>,          // Variables captured from outer scopes
    pub parent: Option<String>,         // Parent function name (for nested functions)
    pub register_count: usize,
    pub instructions: Vec<Instruction>,
    pub labels: HashMap<String, usize>, // Label to instruction index mapping
}

// Implement Hash manually to avoid issues with HashMap
impl Hash for VMFunction {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.parameters.hash(state);
        self.upvalues.hash(state);
        self.parent.hash(state);
        self.register_count.hash(state);
        self.instructions.hash(state);
        // Skip hashing labels
    }
}

/// Foreign (native) function type
pub type ForeignFunctionPtr = Arc<dyn Fn(ForeignFunctionContext) -> Result<Value, String> + Send + Sync>;

/// Context passed to foreign functions
pub struct ForeignFunctionContext<'a> {
    pub args: &'a [Value],
// Assuming VMState is defined elsewhere, import or define it here:
    pub vm_state: &'a mut VMState,
}

/// Foreign function wrapper
pub struct ForeignFunction {
    pub name: String,
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
            func: Arc::clone(&self.func)
        }
    }
}

/// Function definition - can be either VM or foreign
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Function {
    VM(VMFunction),
    Foreign(ForeignFunction),
}