use std::collections::HashMap;
use crate::functions::VMFunction;
use crate::instructions::Instruction;

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
        cached_instructions: None,
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