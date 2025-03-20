use std::collections::HashMap;
use std::sync::Arc;
use crate::activationshenanigans::ActivationRecord;
use crate::functions::{ForeignFunctionContext, Function};
use crate::hooks::{HookEvent, HookManager};
use crate::instructions::Instruction;
use crate::types::{Closure, ForeignObjectStorage, ObjectStore, Upvalue, Value};

// VM internal state
pub struct VMState {
    pub functions: HashMap<String, Function>,
    pub activation_records: Vec<ActivationRecord>,
    pub current_instruction: usize,
    pub object_store: ObjectStore,
    pub foreign_objects: ForeignObjectStorage,
    pub hook_manager: HookManager,
}

impl VMState {
    pub fn new() -> Self {
        VMState {
            functions: HashMap::new(),
            activation_records: Vec::new(),
            current_instruction: 0,
            object_store: ObjectStore::new(),
            foreign_objects: ForeignObjectStorage::new(),
            hook_manager: HookManager::new(),
        }
    }

    // Returns the current activation record
    pub fn current_activation_record(&mut self) -> &mut ActivationRecord {
        self.activation_records.last_mut().unwrap()
    }

    // Find upvalue in the current scope chain
    pub fn find_upvalue(&self, name: &str) -> Option<Value> {
        for record in self.activation_records.iter().rev() {
            if let Some(value) = record.locals.get(name) {
                return Some(value.clone());
            }

            for upvalue in &record.upvalues {
                if upvalue.name == name {
                    return Some(upvalue.value.clone());
                }
            }
        }
        None
    }

    // Register value read/write events
    pub fn trigger_register_read(&self, reg: usize, value: &Value) -> Result<(), String> {
        let event = HookEvent::RegisterRead(reg, value.clone());
        self.hook_manager.trigger(&event, self)
    }

    pub fn trigger_register_write(&self, reg: usize, old_value: &Value, new_value: &Value) -> Result<(), String> {
        let event = HookEvent::RegisterWrite(reg, old_value.clone(), new_value.clone());
        self.hook_manager.trigger(&event, self)
    }

    // Create a closure from a function and upvalues
    pub fn create_closure(&mut self, function_name: &str, upvalue_names: &[String]) -> Result<Value, String> {
        let mut upvalues = Vec::new();
        for name in upvalue_names {
            let value = self.find_upvalue(name)
                .ok_or_else(|| format!("Could not find upvalue {} when creating closure", name))?;

            upvalues.push(Upvalue {
                name: name.clone(),
                value,
            });
        }

        // Create the closure
        let closure = Closure {
            function_id: function_name.to_string(),
            upvalues: upvalues.clone(),
        };

        // Trigger closure created hook
        let event = HookEvent::ClosureCreated(function_name.to_string(), upvalues);
        self.hook_manager.trigger(&event, self)?;

        Ok(Value::Closure(Arc::new(closure)))
    }

    // Execute until return instruction
    pub fn execute_until_return(&mut self) -> Result<Value, String> {
        loop {
            let function_name;
            let ip;
            let activation_records_len;


            {
                let current_record = self.activation_records.last().unwrap();
                function_name = current_record.function_name.clone();
                ip = current_record.instruction_pointer;
                activation_records_len = self.activation_records.len();
            }

            let vm_function = match self.functions.get(&function_name) {
                Some(Function::VM(vm_func)) => vm_func.clone(),
                Some(Function::Foreign(_)) => {
                    return Err(format!("Cannot execute foreign function {}", function_name));
                }
                None => return Err(format!("Function {} not found", function_name)),
            };

            if ip >= vm_function.instructions.len() {
                if activation_records_len == 1 {
                    return Ok(self.activation_records[0].registers[0].clone());
                } else {
                    let result = self.activation_records.last().unwrap().registers[0].clone();
                    self.activation_records.pop();
                    if self.activation_records.is_empty() {
                        return Ok(result);
                    }
                    continue;
                }
            }

            let instruction = vm_function.instructions[ip].clone();

            self.current_instruction = ip;
            self.activation_records.last_mut().unwrap().instruction_pointer += 1;

            let event = HookEvent::BeforeInstructionExecute(instruction.clone());
            self.hook_manager.trigger(&event, self)?;

            match instruction.clone() {
                Instruction::LD(dest_reg, offset) => {
                    let record = self.activation_records.last().unwrap();
                    let idx = (record.stack.len() as i32) + offset - 1;
                    if idx < 0 || idx >= record.stack.len() as i32 {
                        return Err(format!("Stack address [sp+{}] out of bounds", offset));
                    }
                    let value = record.stack[idx as usize].clone();

                    let record = self.activation_records.last_mut().unwrap();
                    let old_value = record.registers[dest_reg].clone();
                    record.registers[dest_reg] = value.clone();

                    let event = HookEvent::RegisterWrite(dest_reg, old_value, value);
                    self.hook_manager.trigger(&event, self)?;
                },
                Instruction::LDI(dest_reg, value) => {
                    let record = self.activation_records.last_mut().unwrap();
                    let old_value = record.registers[dest_reg].clone();
                    record.registers[dest_reg] = value.clone();

                    let event = HookEvent::RegisterWrite(dest_reg, old_value, value);
                    self.hook_manager.trigger(&event, self)?;
                },
                Instruction::MOV(dest_reg, src_reg) => {
                    let record = self.activation_records.last_mut().unwrap();
                    let value = record.registers[src_reg].clone();
                    let old_value = record.registers[dest_reg].clone();
                    record.registers[dest_reg] = value.clone();

                    let read_event = HookEvent::RegisterRead(src_reg, value.clone());
                    self.hook_manager.trigger(&read_event, self)?;

                    let write_event = HookEvent::RegisterWrite(dest_reg, old_value, value);
                    self.hook_manager.trigger(&write_event, self)?;
                },
                Instruction::ADD(dest_reg, src1_reg, src2_reg) => {
                    let record = self.activation_records.last_mut().unwrap();
                    let src1 = &record.registers[src1_reg];
                    let src2 = &record.registers[src2_reg];

                    match (src1, src2) {
                        (Value::Int(a), Value::Int(b)) => {
                            let result_value = Value::Int(a + b);
                            let old_value = record.registers[dest_reg].clone();
                            record.registers[dest_reg] = result_value.clone();

                            let event = HookEvent::RegisterWrite(dest_reg, old_value, result_value);
                            self.hook_manager.trigger(&event, self)?;
                        },
                        _ => return Err("Type error in ADD operation".to_string()),
                    }
                },
                Instruction::SUB(dest_reg, src1_reg, src2_reg) => {
                    let record = self.activation_records.last_mut().unwrap();
                    let src1 = &record.registers[src1_reg];
                    let src2 = &record.registers[src2_reg];

                    match (src1, src2) {
                        (Value::Int(a), Value::Int(b)) => {
                            let result_value = Value::Int(a - b);
                            let old_value = record.registers[dest_reg].clone();
                            record.registers[dest_reg] = result_value.clone();

                            let event = HookEvent::RegisterWrite(dest_reg, old_value, result_value);
                            self.hook_manager.trigger(&event, self)?;
                        },
                        _ => return Err("Type error in SUB operation".to_string()),
                    }
                },
                Instruction::MUL(dest_reg, src1_reg, src2_reg) => {
                    let record = self.activation_records.last_mut().unwrap();
                    let src1 = &record.registers[src1_reg];
                    let src2 = &record.registers[src2_reg];

                    match (src1, src2) {
                        (Value::Int(a), Value::Int(b)) => {
                            let result_value = Value::Int(a * b);
                            let old_value = record.registers[dest_reg].clone();
                            record.registers[dest_reg] = result_value.clone();

                            let event = HookEvent::RegisterWrite(dest_reg, old_value, result_value);
                            self.hook_manager.trigger(&event, self)?;
                        },
                        _ => return Err("Type error in MUL operation".to_string()),
                    }
                },
                Instruction::DIV(dest_reg, src1_reg, src2_reg) => {
                    let record = self.activation_records.last_mut().unwrap();
                    let src1 = &record.registers[src1_reg];
                    let src2 = &record.registers[src2_reg];

                    match (src1, src2) {
                        (Value::Int(a), Value::Int(b)) => {
                            if *b == 0 {
                                return Err("Division by zero".to_string());
                            }
                            let result_value = Value::Int(a / b);
                            let old_value = record.registers[dest_reg].clone();
                            record.registers[dest_reg] = result_value.clone();

                            let event = HookEvent::RegisterWrite(dest_reg, old_value, result_value);
                            self.hook_manager.trigger(&event, self)?;
                        },
                        _ => return Err("Type error in DIV operation".to_string()),
                    }
                },
                Instruction::MOD(dest_reg, src1_reg, src2_reg) => {
                    let record = self.activation_records.last_mut().unwrap();
                    let src1 = &record.registers[src1_reg];
                    let src2 = &record.registers[src2_reg];

                    match (src1, src2) {
                        (Value::Int(a), Value::Int(b)) => {
                            if *b == 0 {
                                return Err("Modulo by zero".to_string());
                            }
                            let result_value = Value::Int(a % b);
                            let old_value = record.registers[dest_reg].clone();
                            record.registers[dest_reg] = result_value.clone();

                            let event = HookEvent::RegisterWrite(dest_reg, old_value, result_value);
                            self.hook_manager.trigger(&event, self)?;
                        },
                        _ => return Err("Type error in MOD operation".to_string()),
                    }
                },
                Instruction::AND(dest_reg, src1_reg, src2_reg) => {
                    let record = self.activation_records.last_mut().unwrap();
                    let src1 = &record.registers[src1_reg];
                    let src2 = &record.registers[src2_reg];

                    let result_value = match (src1, src2) {
                        (Value::Int(a), Value::Int(b)) => Value::Int(a & b),
                        (Value::Bool(a), Value::Bool(b)) => Value::Bool(*a && *b),
                        _ => return Err("Type error in AND operation".to_string()),
                    };

                    let old_value = record.registers[dest_reg].clone();
                    record.registers[dest_reg] = result_value.clone();

                    let event = HookEvent::RegisterWrite(dest_reg, old_value, result_value);
                    self.hook_manager.trigger(&event, self)?;
                },
                Instruction::OR(dest_reg, src1_reg, src2_reg) => {
                    let record = self.activation_records.last_mut().unwrap();
                    let src1 = &record.registers[src1_reg];
                    let src2 = &record.registers[src2_reg];

                    let result_value = match (src1, src2) {
                        (Value::Int(a), Value::Int(b)) => Value::Int(a | b),
                        (Value::Bool(a), Value::Bool(b)) => Value::Bool(*a || *b),
                        _ => return Err("Type error in OR operation".to_string()),
                    };

                    let old_value = record.registers[dest_reg].clone();
                    record.registers[dest_reg] = result_value.clone();

                    let event = HookEvent::RegisterWrite(dest_reg, old_value, result_value);
                    self.hook_manager.trigger(&event, self)?;
                },
                Instruction::XOR(dest_reg, src1_reg, src2_reg) => {
                    let record = self.activation_records.last_mut().unwrap();
                    let src1 = &record.registers[src1_reg];
                    let src2 = &record.registers[src2_reg];

                    let result_value = match (src1, src2) {
                        (Value::Int(a), Value::Int(b)) => Value::Int(a ^ b),
                        (Value::Bool(a), Value::Bool(b)) => Value::Bool(a ^ b),
                        _ => return Err("Type error in XOR operation".to_string()),
                    };

                    let old_value = record.registers[dest_reg].clone();
                    record.registers[dest_reg] = result_value.clone();

                    let event = HookEvent::RegisterWrite(dest_reg, old_value, result_value);
                    self.hook_manager.trigger(&event, self)?;
                },
                Instruction::NOT(dest_reg, src_reg) => {
                    let record = self.activation_records.last_mut().unwrap();
                    let src = &record.registers[src_reg];

                    let result_value = match src {
                        Value::Int(a) => Value::Int(!a),
                        Value::Bool(a) => Value::Bool(!a),
                        _ => return Err("Type error in NOT operation".to_string()),
                    };

                    let old_value = record.registers[dest_reg].clone();
                    record.registers[dest_reg] = result_value.clone();

                    let event = HookEvent::RegisterWrite(dest_reg, old_value, result_value);
                    self.hook_manager.trigger(&event, self)?;
                },
                Instruction::SHL(dest_reg, src_reg, amount_reg) => {
                    let record = self.activation_records.last_mut().unwrap();
                    let src = &record.registers[src_reg];
                    let amount = &record.registers[amount_reg];

                    match (src, amount) {
                        (Value::Int(a), Value::Int(b)) => {
                            let result_value = Value::Int(a << b);
                            let old_value = record.registers[dest_reg].clone();
                            record.registers[dest_reg] = result_value.clone();

                            let event = HookEvent::RegisterWrite(dest_reg, old_value, result_value);
                            self.hook_manager.trigger(&event, self)?;
                        },
                        _ => return Err("Type error in SHL operation".to_string()),
                    }
                },
                Instruction::SHR(dest_reg, src_reg, amount_reg) => {
                    let record = self.activation_records.last_mut().unwrap();
                    let src = &record.registers[src_reg];
                    let amount = &record.registers[amount_reg];

                    match (src, amount) {
                        (Value::Int(a), Value::Int(b)) => {
                            let result_value = Value::Int(a >> b);
                            let old_value = record.registers[dest_reg].clone();
                            record.registers[dest_reg] = result_value.clone();

                            let event = HookEvent::RegisterWrite(dest_reg, old_value, result_value);
                            self.hook_manager.trigger(&event, self)?;
                        },
                        _ => return Err("Type error in SHR operation".to_string()),
                    }
                },
                Instruction::JMP(label) => {
                    let target = vm_function.labels.get(&label)
                        .ok_or_else(|| format!("Label '{}' not found", label))?
                        .clone();

                    self.activation_records.last_mut().unwrap().instruction_pointer = target;
                },
                Instruction::JMPEQ(label) => {
                    let should_jump = self.activation_records.last().unwrap().compare_flag == 0;

                    if should_jump {
                        let target = vm_function.labels.get(&label)
                            .ok_or_else(|| format!("Label '{}' not found", label))?
                            .clone();

                        self.activation_records.last_mut().unwrap().instruction_pointer = target;
                    }
                },
                Instruction::JMPNEQ(label) => {
                    let should_jump = self.activation_records.last().unwrap().compare_flag != 0;

                    if should_jump {
                        let target = vm_function.labels.get(&label)
                            .ok_or_else(|| format!("Label '{}' not found", label))?
                            .clone();

                        self.activation_records.last_mut().unwrap().instruction_pointer = target;
                    }
                },
                Instruction::CALL(function_name) => {
                    let args = self.activation_records.last().unwrap().stack.clone();
                    let function = self.functions.get(&function_name)
                        .ok_or_else(|| format!("Function \'{}\' not found", function_name))?
                        .clone();

                    // Record activation stack size BEFORE the function call
                    let activation_count_before = self.activation_records.len();

                    self.activation_records.last_mut().unwrap().stack.clear();

                    match function {
                        Function::VM(vm_func) => {
                            if vm_func.parameters.len() != args.len() {
                                return Err(format!("Function {} expects {} arguments but got {}",
                                                   function_name, vm_func.parameters.len(), args.len()));
                            }

                            let closure = Closure {
                                function_id: function_name.clone(),
                                upvalues: Vec::new(),
                            };
                            let closure_value = Value::Closure(Arc::new(closure));

                            let event = HookEvent::BeforeFunctionCall(closure_value, args.clone());
                            self.hook_manager.trigger(&event, self)?;

                            let new_record = ActivationRecord {
                                function_name: function_name.clone(),
                                locals: HashMap::new(),
                                registers: vec![Value::Unit; vm_func.register_count],
                                upvalues: Vec::new(),
                                instruction_pointer: 0,
                                stack: Vec::new(),
                                compare_flag: 0,
                            };

                            let args_len = args.len();

                            self.activation_records.push(new_record);

                            {
                                let record = self.activation_records.last_mut().unwrap();
                                for (i, param_name) in vm_func.parameters.iter().enumerate() {
                                    record.registers[i] = args[i].clone();
                                    record.locals.insert(param_name.clone(), args[i].clone());
                                }
                            }

                            if self.activation_records.len() >= 2 {
                                let prev_record_idx = self.activation_records.len() - 2;
                                let prev_record = &mut self.activation_records[prev_record_idx].clone();
                                for _ in 0..args_len {
                                    if let Some(value) = prev_record.stack.pop() {
                                        let event = HookEvent::StackPop(value);
                                        self.hook_manager.trigger(&event, self)?;
                                    }
                                }
                            }
                        },
                        Function::Foreign(foreign_func) => {
                            let func_value = Value::String(format!("<foreign function {}>", function_name));

                            let event = HookEvent::BeforeFunctionCall(func_value.clone(), args.clone());
                            self.hook_manager.trigger(&event, self)?;

                            let context = ForeignFunctionContext {
                                args: &args,
                                vm_state: self,
                            };

                            let result = (foreign_func.func)(context)?;

                            if self.activation_records.len() > activation_count_before {
                                continue;
                            }

                            let old_value;
                            let mut popped_items = Vec::new();
                            {
                                // Normal case - process the function result
                                let record = self.activation_records.last_mut().unwrap();
                                old_value = record.registers[0].clone();
                                record.registers[0] = result.clone();

                                for _ in 0..args.len() {
                                    if let Some(value) = record.stack.pop() {
                                        popped_items.push(value);
                                    }
                                }
                                record.stack.clear();
                            }

                            let reg_event = HookEvent::RegisterWrite(0, old_value, result.clone());
                            self.hook_manager.trigger(&reg_event, self)?;

                            let fn_event = HookEvent::AfterFunctionCall(func_value, result);
                            self.hook_manager.trigger(&fn_event, self)?;

                            // Clean up the stack
                            for value in popped_items {
                                let event = HookEvent::StackPop(value);
                                self.hook_manager.trigger(&event, self)?;
                            }
                        }
                    }

                    // Always clear the stack after a function call
                    self.activation_records.last_mut().unwrap().stack.clear();
                },
                Instruction::RET(reg) => {
                    let return_value = self.activation_records.last().unwrap().registers[reg].clone();
                    let returning_from = self.activation_records.last().unwrap().function_name.clone();

                    // If we only have one activation record (main function), just return
                    if self.activation_records.len() <= 1 {
                        let event = HookEvent::AfterInstructionExecute(instruction.clone());
                        self.hook_manager.trigger(&event, self)?;
                        return Ok(return_value);
                    }

                    // Get the upvalues from the activation record we're returning from
                    let current_upvalues = self.activation_records.last().unwrap().upvalues.clone();

                    // Pop the current activation record
                    self.activation_records.pop();

                    // Now, update any closures in the parent's registers with upvalues from this function
                    let parent_record = self.activation_records.last_mut().unwrap();

                    // Look for any closures in the registers that reference the returning function
                    for reg_value in &mut parent_record.registers {
                        if let Value::Closure(closure_arc) = reg_value {
                            // If this closure matches the function we're returning from
                            if closure_arc.function_id == returning_from {
                                // We need to update this closure with the current upvalues
                                // Clone the existing Arc to make it mutable
                                let mut closure = (**closure_arc).clone();

                                // Update the closure's upvalues with current values
                                for upvalue in &mut closure.upvalues {
                                    for current_upvalue in &current_upvalues {
                                        if upvalue.name == current_upvalue.name {
                                            // Update this upvalue with the latest value
                                            upvalue.value = current_upvalue.value.clone();
                                        }
                                    }
                                }

                                // Replace the original closure with the updated one
                                *reg_value = Value::Closure(Arc::new(closure));
                            }
                        }
                    }

                    // Set the return value in register 0 of the parent activation record
                    let old_value = parent_record.registers[0].clone();
                    parent_record.registers[0] = return_value.clone();

                    let event = HookEvent::RegisterWrite(0, old_value, return_value.clone());
                    self.hook_manager.trigger(&event, self)?;

                    let closure_value = Value::String(format!("<function {}>", returning_from));
                    let event = HookEvent::AfterFunctionCall(closure_value, return_value);
                    self.hook_manager.trigger(&event, self)?;
                },
                Instruction::PUSHARG(reg) => {
                    let value = self.activation_records.last().unwrap().registers[reg].clone();

                    let record = self.activation_records.last_mut().unwrap();
                    record.stack.push(value.clone());

                    let event = HookEvent::StackPush(value);
                    self.hook_manager.trigger(&event, self)?;
                },
                Instruction::CMP(reg1, reg2) => {
                    let record = self.activation_records.last_mut().unwrap();
                    let val1 = &record.registers[reg1];
                    let val2 = &record.registers[reg2];

                    let compare_result = match (val1, val2) {
                        (Value::Int(a), Value::Int(b)) => {
                            if a < b { -1 } else if a > b { 1 } else { 0 }
                        },
                        (Value::String(a), Value::String(b)) => {
                            if a < b { -1 } else if a > b { 1 } else { 0 }
                        },
                        (Value::Bool(a), Value::Bool(b)) => {
                            match (a, b) {
                                (false, true) => -1,
                                (true, false) => 1,
                                _ => 0,
                            }
                        },
                        _ => return Err(format!("Cannot compare {:?} and {:?}", val1, val2)),
                    };

                    record.compare_flag = compare_result;
                },
            }

            let event = HookEvent::AfterInstructionExecute(instruction.clone());
            self.hook_manager.trigger(&event, self)?;
        }
    }

    // Call a foreign function
    pub fn call_foreign_function(&mut self, name: &str, args: &[Value]) -> Result<Value, String> {
        let function = self.functions.get(name).ok_or_else(||
            format!("Foreign function {} not found", name))?
            .clone();

        match function {
            Function::Foreign(foreign_func) => {
                let func_value = Value::String(format!("<foreign function {}>", name));

                let event = HookEvent::BeforeFunctionCall(func_value.clone(), args.to_vec());
                self.hook_manager.trigger(&event, self)?;

                let context = ForeignFunctionContext {
                    args,
                    vm_state: self,
                };

                let result = (foreign_func.func)(context)?;

                let event = HookEvent::AfterFunctionCall(func_value, result.clone());
                self.hook_manager.trigger(&event, self)?;

                Ok(result)
            },
            Function::VM(_) => {
                Err(format!("Expected foreign function, but {} is a VM function", name))
            }
        }
    }
}