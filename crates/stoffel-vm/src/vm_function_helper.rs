use stoffel_vm_types::functions::VMFunction;
use stoffel_vm_types::instructions::Instruction;
use std::collections::HashMap;

/// Helper function to create a VMFunction with default values for the new fields
pub fn create_vmfunction(
    name: String,
    parameters: Vec<String>,
    upvalues: Vec<String>,
    parent: Option<String>,
    register_count: usize,
    instructions: Vec<Instruction>,
    labels: HashMap<String, usize>,
) -> VMFunction {
    VMFunction {
        resolved_instructions: None,
        constant_values: None,
        name,
        parameters,
        upvalues,
        parent,
        register_count,
        instructions,
        labels,
    }
}
