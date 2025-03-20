use std::collections::HashMap;
use std::fmt;
use crate::types::{Upvalue, Value};

#[derive(Clone)]
pub struct ActivationRecord {
    pub function_name: String,
    pub locals: HashMap<String, Value>,
    pub registers: Vec<Value>,
    pub upvalues: Vec<Upvalue>,         // Captured values from outer scopes
    pub instruction_pointer: usize,
    pub stack: Vec<Value>,              // Stack for function arguments and local vars
    pub compare_flag: i32,              // Result of last comparison (-1, 0, 1)
}

impl fmt::Debug for ActivationRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ActivationRecord {{ function: {}, ip: {}, registers: {:?}, locals: {:?}, upvalues: {:?}, stack: {:?}, compare_flag: {} }}",
               self.function_name, self.instruction_pointer, self.registers, self.locals, self.upvalues, self.stack, self.compare_flag)
    }
}