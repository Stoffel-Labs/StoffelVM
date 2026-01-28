//! WebAssembly bindings for StoffelVM
//!
//! This module provides wasm-bindgen exports that allow the VM to be used
//! from JavaScript in web browsers and Node.js environments.
//!
//! Note: This module provides sync-only execution. MPC operations are not
//! available in WASM builds and will return an error if encountered.

use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize};
use stoffel_vm_types::compiled_binary::CompiledBinary;
use stoffel_vm_types::core_types::Value;

/// Initialize the WASM module with better panic messages for debugging.
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

/// Result of a VM execution
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct ExecutionResult {
    success: bool,
    value_type: String,
    value_repr: String,
    error: Option<String>,
}

#[wasm_bindgen]
impl ExecutionResult {
    /// Returns true if execution succeeded
    #[wasm_bindgen(getter)]
    pub fn success(&self) -> bool {
        self.success
    }

    /// Get the type of the returned value (e.g., "int64", "bool", "unit")
    #[wasm_bindgen(getter)]
    pub fn value_type(&self) -> String {
        self.value_type.clone()
    }

    /// Get a string representation of the returned value
    #[wasm_bindgen(getter)]
    pub fn value_repr(&self) -> String {
        self.value_repr.clone()
    }

    /// Get the error message if execution failed
    #[wasm_bindgen(getter)]
    pub fn error(&self) -> Option<String> {
        self.error.clone()
    }

    /// Get the result as a JavaScript value (for primitive types)
    #[wasm_bindgen]
    pub fn as_js_value(&self) -> JsValue {
        if !self.success {
            return JsValue::NULL;
        }

        // Parse the value representation based on type
        match self.value_type.as_str() {
            "int64" | "i64" => {
                if let Ok(n) = self.value_repr.parse::<i64>() {
                    JsValue::from(n as f64)
                } else {
                    JsValue::from_str(&self.value_repr)
                }
            }
            "bool" => JsValue::from(self.value_repr == "true"),
            "float" | "f64" => {
                if let Ok(f) = self.value_repr.parse::<f64>() {
                    JsValue::from(f)
                } else {
                    JsValue::from_str(&self.value_repr)
                }
            }
            "string" => JsValue::from_str(&self.value_repr),
            "unit" => JsValue::UNDEFINED,
            _ => JsValue::from_str(&self.value_repr),
        }
    }
}

impl From<Result<Value, String>> for ExecutionResult {
    fn from(result: Result<Value, String>) -> Self {
        match result {
            Ok(value) => {
                let (value_type, value_repr) = match &value {
                    Value::I64(n) => ("int64".to_string(), n.to_string()),
                    Value::I32(n) => ("i32".to_string(), n.to_string()),
                    Value::I16(n) => ("i16".to_string(), n.to_string()),
                    Value::I8(n) => ("i8".to_string(), n.to_string()),
                    Value::U64(n) => ("u64".to_string(), n.to_string()),
                    Value::U32(n) => ("u32".to_string(), n.to_string()),
                    Value::U16(n) => ("u16".to_string(), n.to_string()),
                    Value::U8(n) => ("u8".to_string(), n.to_string()),
                    Value::Float(f) => ("float".to_string(), f.0.to_string()),
                    Value::Bool(b) => ("bool".to_string(), b.to_string()),
                    Value::String(s) => ("string".to_string(), s.clone()),
                    Value::Unit => ("unit".to_string(), "()".to_string()),
                    Value::Array(id) => ("array".to_string(), format!("Array({})", id)),
                    Value::Object(id) => ("object".to_string(), format!("Object({})", id)),
                    Value::Foreign(id) => ("foreign".to_string(), format!("Foreign({})", id)),
                    Value::Closure(c) => ("closure".to_string(), format!("Closure({})", c.function_id)),
                    Value::Share(share_type, _) => (
                        "share".to_string(),
                        format!("Share({:?}) - MPC not available in WASM", share_type),
                    ),
                };
                ExecutionResult {
                    success: true,
                    value_type,
                    value_repr,
                    error: None,
                }
            }
            Err(e) => ExecutionResult {
                success: false,
                value_type: "error".to_string(),
                value_repr: String::new(),
                error: Some(e),
            },
        }
    }
}

/// A lightweight VM wrapper for WASM
///
/// This provides a simplified interface for running Stoffel programs in the browser.
/// Only synchronous (non-MPC) execution is supported.
#[wasm_bindgen]
pub struct WasmVM {
    functions: std::collections::HashMap<String, stoffel_vm_types::functions::VMFunction>,
    constants: Vec<Value>,
}

#[wasm_bindgen]
impl WasmVM {
    /// Create a new WasmVM from bytecode
    #[wasm_bindgen(constructor)]
    pub fn from_bytecode(bytecode: &[u8]) -> Result<WasmVM, JsValue> {
        use std::io::Cursor;

        let mut cursor = Cursor::new(bytecode);
        let binary = CompiledBinary::deserialize(&mut cursor)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize bytecode: {:?}", e)))?;

        let vm_functions = binary.to_vm_functions();

        let mut functions = std::collections::HashMap::new();
        for func in vm_functions {
            functions.insert(func.name.clone(), func);
        }

        Ok(WasmVM {
            functions,
            constants: binary.constants,
        })
    }

    /// List all available function names
    #[wasm_bindgen]
    pub fn list_functions(&self) -> Vec<JsValue> {
        self.functions
            .keys()
            .map(|name| JsValue::from_str(name))
            .collect()
    }

    /// Check if a function exists
    #[wasm_bindgen]
    pub fn has_function(&self, name: &str) -> bool {
        self.functions.contains_key(name)
    }

    /// Execute a function by name (sync-only, no MPC support)
    ///
    /// Returns an ExecutionResult with the return value or error.
    #[wasm_bindgen]
    pub fn execute(&mut self, function_name: &str) -> ExecutionResult {
        // Check if function exists
        let func = match self.functions.get(function_name) {
            Some(f) => f.clone(),
            None => {
                return ExecutionResult {
                    success: false,
                    value_type: "error".to_string(),
                    value_repr: String::new(),
                    error: Some(format!("Function '{}' not found", function_name)),
                }
            }
        };

        // Create a minimal execution context
        let result = execute_function_sync(&func, &self.functions, &self.constants);
        ExecutionResult::from(result)
    }
}

/// Execute a function synchronously without MPC support
fn execute_function_sync(
    func: &stoffel_vm_types::functions::VMFunction,
    functions: &std::collections::HashMap<String, stoffel_vm_types::functions::VMFunction>,
    constants: &[Value],
) -> Result<Value, String> {
    use stoffel_vm_types::instructions::Instruction;

    // Simple register-based execution
    let mut registers: Vec<Value> = vec![Value::Unit; func.register_count.max(32)];
    let mut call_stack: Vec<(String, usize, Vec<Value>, Vec<Value>)> = vec![];
    let mut current_func = func.clone();
    let mut pc: usize = 0;
    let mut arg_stack: Vec<Value> = vec![];

    // Maximum instruction count to prevent infinite loops
    let max_instructions = 10_000_000;
    let mut instruction_count = 0;

    loop {
        if instruction_count >= max_instructions {
            return Err("Execution timeout: exceeded maximum instruction count".to_string());
        }
        instruction_count += 1;

        if pc >= current_func.instructions.len() {
            // Implicit return
            if call_stack.is_empty() {
                return Ok(registers[0].clone());
            } else {
                let (prev_func_name, prev_pc, prev_registers, prev_args) = call_stack.pop().unwrap();
                let return_val = registers[0].clone();
                current_func = functions.get(&prev_func_name).cloned()
                    .ok_or_else(|| format!("Function '{}' not found during return", prev_func_name))?;
                pc = prev_pc;
                registers = prev_registers;
                arg_stack = prev_args;
                // Store return value in register 0
                registers[0] = return_val;
                continue;
            }
        }

        let instruction = &current_func.instructions[pc];
        pc += 1;

        match instruction {
            Instruction::LDI(reg, value) => {
                registers[*reg] = value.clone();
            }
            Instruction::LD(reg, offset) => {
                // Load from argument stack
                let idx = (*offset) as usize;
                if idx < arg_stack.len() {
                    registers[*reg] = arg_stack[idx].clone();
                }
            }
            Instruction::MOV(dest, src) => {
                registers[*dest] = registers[*src].clone();
            }
            Instruction::ADD(dest, src1, src2) => {
                let result = match (&registers[*src1], &registers[*src2]) {
                    (Value::I64(a), Value::I64(b)) => Value::I64(a.wrapping_add(*b)),
                    (Value::I32(a), Value::I32(b)) => Value::I32(a.wrapping_add(*b)),
                    (Value::Float(a), Value::Float(b)) => Value::Float(stoffel_vm_types::core_types::F64(a.0 + b.0)),
                    (Value::Share(_, _), _) | (_, Value::Share(_, _)) => {
                        return Err("MPC operations (Share arithmetic) not available in WASM".to_string());
                    }
                    _ => return Err(format!("Cannot add {:?} and {:?}", registers[*src1], registers[*src2])),
                };
                registers[*dest] = result;
            }
            Instruction::SUB(dest, src1, src2) => {
                let result = match (&registers[*src1], &registers[*src2]) {
                    (Value::I64(a), Value::I64(b)) => Value::I64(a.wrapping_sub(*b)),
                    (Value::I32(a), Value::I32(b)) => Value::I32(a.wrapping_sub(*b)),
                    (Value::Float(a), Value::Float(b)) => Value::Float(stoffel_vm_types::core_types::F64(a.0 - b.0)),
                    (Value::Share(_, _), _) | (_, Value::Share(_, _)) => {
                        return Err("MPC operations (Share arithmetic) not available in WASM".to_string());
                    }
                    _ => return Err(format!("Cannot subtract {:?} from {:?}", registers[*src2], registers[*src1])),
                };
                registers[*dest] = result;
            }
            Instruction::MUL(dest, src1, src2) => {
                let result = match (&registers[*src1], &registers[*src2]) {
                    (Value::I64(a), Value::I64(b)) => Value::I64(a.wrapping_mul(*b)),
                    (Value::I32(a), Value::I32(b)) => Value::I32(a.wrapping_mul(*b)),
                    (Value::Float(a), Value::Float(b)) => Value::Float(stoffel_vm_types::core_types::F64(a.0 * b.0)),
                    (Value::Share(_, _), _) | (_, Value::Share(_, _)) => {
                        return Err("MPC operations (Share multiplication) not available in WASM".to_string());
                    }
                    _ => return Err(format!("Cannot multiply {:?} and {:?}", registers[*src1], registers[*src2])),
                };
                registers[*dest] = result;
            }
            Instruction::DIV(dest, src1, src2) => {
                let result = match (&registers[*src1], &registers[*src2]) {
                    (Value::I64(a), Value::I64(b)) => {
                        if *b == 0 { return Err("Division by zero".to_string()); }
                        Value::I64(a / b)
                    }
                    (Value::I32(a), Value::I32(b)) => {
                        if *b == 0 { return Err("Division by zero".to_string()); }
                        Value::I32(a / b)
                    }
                    (Value::Float(a), Value::Float(b)) => Value::Float(stoffel_vm_types::core_types::F64(a.0 / b.0)),
                    _ => return Err(format!("Cannot divide {:?} by {:?}", registers[*src1], registers[*src2])),
                };
                registers[*dest] = result;
            }
            Instruction::MOD(dest, src1, src2) => {
                let result = match (&registers[*src1], &registers[*src2]) {
                    (Value::I64(a), Value::I64(b)) => {
                        if *b == 0 { return Err("Modulo by zero".to_string()); }
                        Value::I64(a % b)
                    }
                    (Value::I32(a), Value::I32(b)) => {
                        if *b == 0 { return Err("Modulo by zero".to_string()); }
                        Value::I32(a % b)
                    }
                    _ => return Err(format!("Cannot modulo {:?} by {:?}", registers[*src1], registers[*src2])),
                };
                registers[*dest] = result;
            }
            Instruction::AND(dest, src1, src2) => {
                let result = match (&registers[*src1], &registers[*src2]) {
                    (Value::I64(a), Value::I64(b)) => Value::I64(a & b),
                    (Value::Bool(a), Value::Bool(b)) => Value::Bool(*a && *b),
                    _ => return Err(format!("Cannot AND {:?} and {:?}", registers[*src1], registers[*src2])),
                };
                registers[*dest] = result;
            }
            Instruction::OR(dest, src1, src2) => {
                let result = match (&registers[*src1], &registers[*src2]) {
                    (Value::I64(a), Value::I64(b)) => Value::I64(a | b),
                    (Value::Bool(a), Value::Bool(b)) => Value::Bool(*a || *b),
                    _ => return Err(format!("Cannot OR {:?} and {:?}", registers[*src1], registers[*src2])),
                };
                registers[*dest] = result;
            }
            Instruction::XOR(dest, src1, src2) => {
                let result = match (&registers[*src1], &registers[*src2]) {
                    (Value::I64(a), Value::I64(b)) => Value::I64(a ^ b),
                    (Value::Bool(a), Value::Bool(b)) => Value::Bool(*a ^ *b),
                    _ => return Err(format!("Cannot XOR {:?} and {:?}", registers[*src1], registers[*src2])),
                };
                registers[*dest] = result;
            }
            Instruction::NOT(dest, src) => {
                let result = match &registers[*src] {
                    Value::I64(a) => Value::I64(!a),
                    Value::Bool(a) => Value::Bool(!*a),
                    _ => return Err(format!("Cannot NOT {:?}", registers[*src])),
                };
                registers[*dest] = result;
            }
            Instruction::SHL(dest, src, amount) => {
                let result = match &registers[*src] {
                    Value::I64(a) => Value::I64(a << amount),
                    _ => return Err(format!("Cannot SHL {:?}", registers[*src])),
                };
                registers[*dest] = result;
            }
            Instruction::SHR(dest, src, amount) => {
                let result = match &registers[*src] {
                    Value::I64(a) => Value::I64(a >> amount),
                    _ => return Err(format!("Cannot SHR {:?}", registers[*src])),
                };
                registers[*dest] = result;
            }
            Instruction::CMP(reg1, reg2) => {
                // Set comparison flags (stored in a special way)
                // For simplicity, we'll use register 31 as the comparison result
                let cmp_result = match (&registers[*reg1], &registers[*reg2]) {
                    (Value::I64(a), Value::I64(b)) => {
                        if a < b { -1 } else if a > b { 1 } else { 0 }
                    }
                    (Value::I32(a), Value::I32(b)) => {
                        if a < b { -1 } else if a > b { 1 } else { 0 }
                    }
                    (Value::Float(a), Value::Float(b)) => {
                        if a.0 < b.0 { -1 } else if a.0 > b.0 { 1 } else { 0 }
                    }
                    (Value::Bool(a), Value::Bool(b)) => {
                        if *a == *b { 0 } else if *a { 1 } else { -1 }
                    }
                    _ => return Err(format!("Cannot compare {:?} and {:?}", registers[*reg1], registers[*reg2])),
                };
                // Store comparison result for jump instructions
                if registers.len() > 31 {
                    registers[31] = Value::I64(cmp_result);
                }
            }
            Instruction::JMP(label) => {
                if let Some(&target) = current_func.labels.get(label) {
                    pc = target;
                } else {
                    return Err(format!("Label '{}' not found", label));
                }
            }
            Instruction::JMPEQ(label) => {
                let cmp_val = if registers.len() > 31 {
                    match &registers[31] {
                        Value::I64(n) => *n,
                        _ => 0,
                    }
                } else { 0 };
                if cmp_val == 0 {
                    if let Some(&target) = current_func.labels.get(label) {
                        pc = target;
                    } else {
                        return Err(format!("Label '{}' not found", label));
                    }
                }
            }
            Instruction::JMPNEQ(label) => {
                let cmp_val = if registers.len() > 31 {
                    match &registers[31] {
                        Value::I64(n) => *n,
                        _ => 0,
                    }
                } else { 0 };
                if cmp_val != 0 {
                    if let Some(&target) = current_func.labels.get(label) {
                        pc = target;
                    } else {
                        return Err(format!("Label '{}' not found", label));
                    }
                }
            }
            Instruction::JMPLT(label) => {
                let cmp_val = if registers.len() > 31 {
                    match &registers[31] {
                        Value::I64(n) => *n,
                        _ => 0,
                    }
                } else { 0 };
                if cmp_val < 0 {
                    if let Some(&target) = current_func.labels.get(label) {
                        pc = target;
                    } else {
                        return Err(format!("Label '{}' not found", label));
                    }
                }
            }
            Instruction::JMPGT(label) => {
                let cmp_val = if registers.len() > 31 {
                    match &registers[31] {
                        Value::I64(n) => *n,
                        _ => 0,
                    }
                } else { 0 };
                if cmp_val > 0 {
                    if let Some(&target) = current_func.labels.get(label) {
                        pc = target;
                    } else {
                        return Err(format!("Label '{}' not found", label));
                    }
                }
            }
            Instruction::PUSHARG(reg) => {
                arg_stack.push(registers[*reg].clone());
            }
            Instruction::CALL(func_name) => {
                // Check for built-in functions
                if func_name == "print" {
                    // Print is a no-op in WASM (could log to console)
                    if !arg_stack.is_empty() {
                        // In a real implementation, we'd log this
                        let _ = arg_stack.pop();
                    }
                    registers[0] = Value::Unit;
                    arg_stack.clear();
                    continue;
                }

                // Look up the function
                let callee = functions.get(func_name)
                    .ok_or_else(|| format!("Function '{}' not found", func_name))?;

                // Save current state
                call_stack.push((
                    current_func.name.clone(),
                    pc,
                    registers.clone(),
                    std::mem::take(&mut arg_stack),
                ));

                // Set up new function
                current_func = callee.clone();
                pc = 0;
                registers = vec![Value::Unit; current_func.register_count.max(32)];

                // Arguments are now in the saved arg_stack, accessible via LD
                let args = call_stack.last().map(|s| s.3.clone()).unwrap_or_default();
                arg_stack = args;
            }
            Instruction::RET(reg) => {
                let return_val = registers[*reg].clone();

                if call_stack.is_empty() {
                    return Ok(return_val);
                }

                let (prev_func_name, prev_pc, prev_registers, prev_args) = call_stack.pop().unwrap();
                current_func = functions.get(&prev_func_name).cloned()
                    .ok_or_else(|| format!("Function '{}' not found during return", prev_func_name))?;
                pc = prev_pc;
                registers = prev_registers;
                arg_stack = prev_args;
                // Store return value in register 0
                registers[0] = return_val;
            }
        }
    }
}

/// Get the VM version
#[wasm_bindgen]
pub fn vm_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_result_from_value() {
        let result: ExecutionResult = Ok(Value::I64(42)).into();
        assert!(result.success);
        assert_eq!(result.value_type, "int64");
        assert_eq!(result.value_repr, "42");
    }

    #[test]
    fn test_execution_result_from_error() {
        let result: ExecutionResult = Err("test error".to_string()).into();
        assert!(!result.success);
        assert_eq!(result.error, Some("test error".to_string()));
    }
}
