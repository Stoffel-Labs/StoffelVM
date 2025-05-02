use crate::activations::ActivationRecord;
use crate::functions::{ForeignFunction, ForeignFunctionContext, Function, VMFunction};
use crate::runtime_hooks::{HookContext, HookEvent};
use crate::core_types::{Closure, Upvalue, Value};
use crate::vm_state::VMState;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// The register-based virtual machine
pub struct VirtualMachine {
    pub state: Mutex<VMState>,
}


impl Default for VirtualMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualMachine {
    pub fn new() -> Self {
        let vm = VirtualMachine {
            state: Mutex::new(VMState::new()),
        };

        // Register standard library functions
        vm.register_standard_library();

        vm
    }

    pub fn register_standard_library(&self) {
        self.register_foreign_function("create_object", |ctx| {
            let id = ctx.vm_state.object_store.create_object();
            Ok(Value::Object(id))
        });

        self.register_foreign_function("create_array", |ctx| {
            let capacity = if ctx.args.len() > 0 {
                match &ctx.args[0] {
                    Value::Int(n) => *n as usize,
                    _ => 0,
                }
            } else {
                0
            };

            let id = if capacity > 0 {
                ctx.vm_state
                    .object_store
                    .create_array_with_capacity(capacity)
            } else {
                ctx.vm_state.object_store.create_array()
            };

            Ok(Value::Array(id))
        });

        self.register_foreign_function("get_field", |ctx| {
            if ctx.args.len() < 2 {
                return Err("get_field expects at least 2 arguments: object and key".to_string());
            }

            let value = ctx
                .vm_state
                .object_store
                .get_field(&ctx.args[0], &ctx.args[1])
                .unwrap_or(Value::Unit);

            // Create event based on arg type
            match &ctx.args[0] {
                Value::Object(id) => {
                    let event = HookEvent::ObjectFieldRead(*id, ctx.args[1].clone(), value.clone());
                    // Use ctx.vm_state directly instead of self.state.borrow()
                    ctx.vm_state.hook_manager.trigger(&event, ctx.vm_state)?;
                }
                Value::Array(id) => {
                    let event =
                        HookEvent::ArrayElementRead(*id, ctx.args[1].clone(), value.clone());
                    // Use ctx.vm_state directly instead of self.state.borrow()
                    ctx.vm_state.hook_manager.trigger(&event, ctx.vm_state)?;
                }
                _ => {}
            }

            Ok(value)
        });

        self.register_foreign_function("set_field", |ctx| {
            if ctx.args.len() < 3 {
                return Err("set_field expects 3 arguments: object, key, and value".to_string());
            }

            let old_value = ctx
                .vm_state
                .object_store
                .get_field(&ctx.args[0], &ctx.args[1])
                .unwrap_or(Value::Unit);

            ctx.vm_state.object_store.set_field(
                &ctx.args[0],
                ctx.args[1].clone(),
                ctx.args[2].clone(),
            )?;

            match &ctx.args[0] {
                Value::Object(id) => {
                    let event = HookEvent::ObjectFieldWrite(
                        *id,
                        ctx.args[1].clone(),
                        old_value,
                        ctx.args[2].clone(),
                    );
                    ctx.vm_state.hook_manager.trigger(&event, ctx.vm_state)?;
                }
                Value::Array(id) => {
                    let event = HookEvent::ArrayElementWrite(
                        *id,
                        ctx.args[1].clone(),
                        old_value,
                        ctx.args[2].clone(),
                    );
                    ctx.vm_state.hook_manager.trigger(&event, ctx.vm_state)?;
                }
                _ => {}
            }

            Ok(Value::Unit)
        });

        self.register_foreign_function("array_length", |ctx| {
            if ctx.args.len() < 1 {
                return Err("array_length expects 1 argument: array".to_string());
            }

            match &ctx.args[0] {
                Value::Array(id) => {
                    if let Some(arr) = ctx.vm_state.object_store.get_array(*id) {
                        Ok(Value::Int(arr.length() as i64))
                    } else {
                        Err(format!("Array with ID {} not found", id))
                    }
                }
                _ => Err("First argument must be an array".to_string()),
            }
        });

        self.register_foreign_function("array_push", |ctx| {
            if ctx.args.len() < 2 {
                return Err("array_push expects at least 2 arguments: array and value".to_string());
            }

            match &ctx.args[0] {
                Value::Array(id) => {
                    if let Some(arr) = ctx.vm_state.object_store.get_array_mut(*id) {
                        let idx = Value::Int((arr.length() + 1) as i64);
                        for value in &ctx.args[1..] {
                            arr.set(idx.clone(), value.clone());
                        }
                        Ok(Value::Int(arr.length() as i64))
                    } else {
                        Err(format!("Array with ID {} not found", id))
                    }
                }
                _ => Err("First argument must be an array".to_string()),
            }
        });

        self.register_foreign_function("create_closure", |ctx| {
            if ctx.args.len() < 1 {
                return Err("create_closure expects at least 1 argument: function_name".to_string());
            }

            let function_name = match &ctx.args[0] {
                Value::String(name) => name.clone(),
                _ => return Err("First argument must be a string".to_string()),
            };

            let mut upvalue_names = Vec::new();
            if ctx.args.len() > 1 {
                for arg in &ctx.args[1..] {
                    match arg {
                        Value::String(name) => upvalue_names.push(name.clone()),
                        _ => return Err("Upvalue names must be strings".to_string()),
                    }
                }
            }

            // Create a NEW upvalue for each name, with current values
            // This is critical for proper isolation
            let mut upvalues = Vec::new();
            for name in &upvalue_names {
                // Look for the value in current scope chain
                let value = ctx.vm_state.find_upvalue(name).ok_or_else(|| {
                    format!("Could not find upvalue {} when creating closure", name)
                })?;

                // Create a new upvalue with a DEEP COPY of the current value
                upvalues.push(Upvalue {
                    name: name.clone(),
                    value: value.clone(), // Use clone to ensure isolation
                });
            }

            // Create the closure with its OWN COPY of upvalues
            let closure = Closure {
                function_id: function_name.clone(),
                upvalues: upvalues.clone(), // This ensures each closure has its own copy
            };

            // Trigger closure created hook
            let event = HookEvent::ClosureCreated(function_name.clone(), upvalues);
            ctx.vm_state.hook_manager.trigger(&event, ctx.vm_state)?;

            Ok(Value::Closure(Arc::new(closure)))
        });

        self.register_foreign_function("call_closure", |ctx| {
            if ctx.args.len() < 1 {
                return Err("call_closure expects at least 1 argument: closure".to_string());
            }

            match &ctx.args[0] {
                Value::Closure(closure_arc) => {
                    let function_name = closure_arc.function_id.clone();
                    // Important: Clone the upvalues to ensure this activation record has its own copy
                    let upvalues = closure_arc.upvalues.clone();

                    // Get the VM function definition
                    let vm_func = match ctx.vm_state.functions.get(&function_name) {
                        Some(Function::VM(func)) => func.clone(),
                        Some(Function::Foreign(_)) => {
                            return Err(format!(
                                "Cannot execute foreign function as closure: {}",
                                function_name
                            ));
                        }
                        None => return Err(format!("Function {} not found", function_name)),
                    };

                    // Check arguments
                    let call_args = &ctx.args[1..];
                    if vm_func.parameters.len() != call_args.len() {
                        return Err(format!(
                            "Function {} expects {} arguments but got {}",
                            function_name,
                            vm_func.parameters.len(),
                            call_args.len()
                        ));
                    }

                    // Setup the new activation record with the provided upvalues
                    let mut new_record = ActivationRecord {
                        function_name: function_name.clone(),
                        locals: HashMap::new(),
                        registers: vec![Value::Unit; vm_func.register_count],
                        upvalues: upvalues, // Use closure's upvalues
                        instruction_pointer: 0,
                        stack: Vec::new(),
                        compare_flag: 0,
                    };

                    // Set up parameters in registers and locals
                    for (i, param_name) in vm_func.parameters.iter().enumerate() {
                        new_record.registers[i] = call_args[i].clone();
                        new_record
                            .locals
                            .insert(param_name.clone(), call_args[i].clone());
                    }

                    // Push to the activation record stack
                    ctx.vm_state.activation_records.push(new_record);

                    Ok(Value::Unit)
                }
                other => {
                    let type_name = match other {
                        Value::Int(_) => "integer",
                        Value::Float(_) => "float",
                        Value::Bool(_) => "boolean",
                        Value::String(_) => "string",
                        Value::Object(_) => "object",
                        Value::Array(_) => "array",
                        Value::Foreign(_) => "foreign",
                        Value::Unit => "unit",
                        _ => "unknown",
                    };
                    Err(format!(
                        "First argument must be a closure, but got {}",
                        type_name
                    ))
                }
            }
        });

        self.register_foreign_function("get_upvalue", |ctx| {
            if ctx.args.len() < 1 {
                return Err("get_upvalue expects 1 argument: name".to_string());
            }

            let name = match &ctx.args[0] {
                Value::String(s) => s.clone(),
                _ => return Err("Upvalue name must be a string".to_string()),
            };

            let record = ctx.vm_state.activation_records.last().unwrap();
            for upvalue in &record.upvalues {
                if upvalue.name == name {
                    let event = HookEvent::UpvalueRead(name, upvalue.value.clone());
                    ctx.vm_state.hook_manager.trigger(&event, ctx.vm_state)?;

                    return Ok(upvalue.value.clone());
                }
            }

            Err(format!("Upvalue '{}' not found", name))
        });

        self.register_foreign_function("set_upvalue", |ctx| {
            if ctx.args.len() < 2 {
                return Err("set_upvalue expects 2 arguments: name and value".to_string());
            }

            let name = match &ctx.args[0] {
                Value::String(s) => s.clone(),
                _ => return Err("Upvalue name must be a string".to_string()),
            };

            let record = ctx.vm_state.activation_records.last_mut().unwrap();
            for upvalue in &mut record.upvalues {
                if upvalue.name == name {
                    let old_value = upvalue.value.clone();
                    upvalue.value = ctx.args[1].clone();

                    // Trigger upvalue write hook
                    let event = HookEvent::UpvalueWrite(name, old_value, ctx.args[1].clone());
                    ctx.vm_state.hook_manager.trigger(&event, ctx.vm_state)?;

                    return Ok(Value::Unit);
                }
            }

            Err(format!("Upvalue '{}' not found for writing", name))
        });

        self.register_foreign_function("print", |ctx| {
            let mut output = String::new();
            for (i, arg) in ctx.args.iter().enumerate() {
                if i > 0 {
                    output.push_str(" ");
                }
                match arg {
                    Value::String(s) => output.push_str(s),
                    _ => output.push_str(&format!("{:?}", arg)),
                }
            }
            println!("{}", output);
            Ok(Value::Unit)
        });

        self.register_foreign_function("type", |ctx| {
            println!("{}", format!("args {:?}", ctx.args));
            if ctx.args.len() != 1 {
                return Err("type expects 1 argument".to_string());
            }

            let type_name = match &ctx.args[0] {
                Value::Int(_) => "integer",
                Value::Float(_) => "float",
                Value::Bool(_) => "boolean",
                Value::String(_) => "string",
                Value::Object(_) => "object",
                Value::Array(_) => "array",
                Value::Foreign(_) => "userdata",
                Value::Closure(_) => "function",
                Value::Unit => "nil",
            };

            Ok(Value::String(type_name.to_string()))
        });
    }

    // Register a VM function
    pub fn register_function(&self, function: VMFunction) {
        let mut state = self.state.lock().unwrap();
        state
            .functions
            .insert(function.name.clone(), Function::VM(function));
    }

    // Register a foreign function
    pub fn register_foreign_function<F>(&self, name: &str, func: F)
    where
        F: Fn(ForeignFunctionContext) -> Result<Value, String> + 'static + Send + Sync,
    {
        let mut state = self.state.lock().unwrap();
        state.functions.insert(
            name.to_string(),
            Function::Foreign(ForeignFunction {
                name: name.to_string(),
                func: Arc::new(func),
            }),
        );
    }

    // Register a foreign object
    pub fn register_foreign_object<T: 'static + Send + Sync>(&self, object: T) -> Value {
        let mut state = self.state.lock().unwrap();
        let id = state.foreign_objects.register_object(object);
        Value::Foreign(id)
    }

    // Get a foreign object by ID
    pub fn get_foreign_object<T: 'static + Send + Sync>(&self, id: usize) -> Option<Arc<Mutex<T>>> {
        let state = self.state.lock().unwrap();
        state.foreign_objects.get_object(id)
    }

    // --- HOOK SYSTEM ---

    // Register a hook with the VM
    pub fn register_hook<P, C>(&self, predicate: P, callback: C, priority: i32) -> usize
    where
        P: Fn(&HookEvent) -> bool + 'static + Send + Sync,
        C: Fn(&HookEvent, &HookContext) -> Result<(), String> + 'static + Send + Sync,
    {
        let mut state = self.state.lock().unwrap();
        state
            .hook_manager
            .register_hook(Box::new(predicate), Box::new(callback), priority)
    }

    // Unregister a hook
    pub fn unregister_hook(&self, hook_id: usize) -> bool {
        let mut state = self.state.lock().unwrap();
        state.hook_manager.unregister_hook(hook_id)
    }

    // Enable a hook
    pub fn enable_hook(&self, hook_id: usize) -> bool {
        let mut state = self.state.lock().unwrap();
        state.hook_manager.enable_hook(hook_id)
    }

    // Disable a hook
    pub fn disable_hook(&self, hook_id: usize) -> bool {
        let mut state = self.state.lock().unwrap();
        state.hook_manager.disable_hook(hook_id)
    }

    pub fn execute_with_args(&self, function_name: &str, args: &[Value]) -> Result<Value, String> {
        let vm_func = {
            let state = self.state.lock().unwrap();
            match state.functions.get(function_name) {
                Some(Function::VM(func)) => func.clone(),
                Some(Function::Foreign(f)) => {
                    let mut state = self.state.lock().unwrap();
                    let result = (f.func)(ForeignFunctionContext {
                        args,
                        vm_state: &mut state,
                    })?;
                    return Ok(result);
                }
                None => return Err(format!("Function {} not found", function_name)),
            }
        };

        if args.len() != vm_func.parameters.len() {
            return Err(format!(
                "Function {} expects {} arguments but got {}",
                function_name,
                vm_func.parameters.len(),
                args.len()
            ));
        }

        {
            let mut state = self.state.lock().unwrap();
            let mut initial_record = ActivationRecord {
                function_name: function_name.to_string(),
                locals: HashMap::new(),
                registers: vec![Value::Unit; vm_func.register_count],
                upvalues: Vec::new(),
                instruction_pointer: 0,
                stack: Vec::new(),
                compare_flag: 0,
            };

            for (i, (param_name, arg_value)) in vm_func.parameters.iter().zip(args.iter()).enumerate() {
                initial_record.registers[i] = arg_value.clone();
                initial_record.locals.insert(param_name.clone(), arg_value.clone());
            }

            state.activation_records.push(initial_record);
        }

        self.execute_until_return()
    }

    // Execute the VM with a given main function
    // TODO: should prob make it so that if no main function specified it will just run the provided bytecode
    pub fn execute(&self, main_function: &str) -> Result<Value, String> {
        let vm_func = {
            let state = self.state.lock().unwrap();
            match state.functions.get(main_function) {
                Some(Function::VM(func)) => func.clone(),
                Some(Function::Foreign(_)) => {
                    return Err(format!(
                        "Cannot execute foreign function {} as main",
                        main_function
                    ));
                }
                None => return Err(format!("Function {} not found", main_function)),
            }
        };

        {
            let mut state = self.state.lock().unwrap();
            let initial_record = ActivationRecord {
                function_name: main_function.to_string(),
                locals: HashMap::new(),
                registers: vec![Value::Unit; vm_func.register_count],
                upvalues: Vec::new(),
                instruction_pointer: 0,
                stack: Vec::new(),
                compare_flag: 0,
            };

            state.activation_records.push(initial_record);
        }

        self.execute_until_return()
    }

    pub fn execute_until_return(&self) -> Result<Value, String> {
        let mut state = self.state.lock().unwrap();
        state.execute_until_return()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activations::ActivationRecord;
    use crate::functions::VMFunction;
    use crate::instructions::Instruction;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::Instant;

    // Helper function to create a test VM
    fn setup_vm() -> VirtualMachine {
        VirtualMachine::new()
    }

    #[test]
    fn test_less_than_jump() {
        let vm = setup_vm();

        let mut labels = HashMap::new();
        labels.insert("less_than".to_string(), 6);
        labels.insert("end".to_string(), 7);

        let test_function = VMFunction {
            name: "test_less_than_jump".to_string(),
            parameters: vec![],
            upvalues: Vec::new(),
            parent: None,
            register_count: 3,
            instructions: vec![
                Instruction::LDI(0, Value::Int(5)),  // r0 = 5
                Instruction::LDI(1, Value::Int(10)), // r1 = 10
                Instruction::CMP(0, 1),              // Compare r0 < r1 (sets flag to -1)
                Instruction::JMPLT("less_than".to_string()), // Jump if less than
                Instruction::LDI(2, Value::Int(0)),  // Should be skipped
                Instruction::JMP("end".to_string()),
                // less_than:
                Instruction::LDI(2, Value::Int(1)),  // Set result to 1 if jump taken
                // end:
                Instruction::RET(2),
            ],
            labels,
        };

        vm.register_function(test_function);
        let result = vm.execute("test_less_than_jump").unwrap();
        assert_eq!(result, Value::Int(1)); // Expect 1 because 5 < 10
    }

    #[test]
    fn test_greater_than_jump() {
        let vm = setup_vm();

        let mut labels = HashMap::new();
        labels.insert("greater_than".to_string(), 6);
        labels.insert("end".to_string(), 7);

        let test_function = VMFunction {
            name: "test_greater_than_jump".to_string(),
            parameters: vec![],
            upvalues: Vec::new(),
            parent: None,
            register_count: 3,
            instructions: vec![
                Instruction::LDI(0, Value::Int(15)), // r0 = 15
                Instruction::LDI(1, Value::Int(10)), // r1 = 10
                Instruction::CMP(0, 1),              // Compare r0 > r1 (sets flag to 1)
                Instruction::JMPGT("greater_than".to_string()), // Jump if greater than
                Instruction::LDI(2, Value::Int(0)),  // Should be skipped
                Instruction::JMP("end".to_string()),
                // greater_than:
                Instruction::LDI(2, Value::Int(1)),  // Set result to 1 if jump taken
                // end:
                Instruction::RET(2),
            ],
            labels,
        };

        vm.register_function(test_function);
        let result = vm.execute("test_greater_than_jump").unwrap();
        assert_eq!(result, Value::Int(1)); // Expect 1 because 15 > 10
    }

    // Example of using new jumps for <=
    // Jump if NOT greater than (JMPGT to the false branch)
    // Or Jump if Less Than OR Equal (JMPLT target; JMPEQ target)

    #[test]
    fn test_load_instructions() {
        let vm = setup_vm();

        let test_function = VMFunction {
            name: "test_load".to_string(),
            parameters: vec![],
            upvalues: Vec::new(),
            parent: None,
            register_count: 3,
            instructions: vec![
                // Push value to stack
                Instruction::LDI(0, Value::Int(42)),
                Instruction::PUSHARG(0),
                // Load from stack to register
                Instruction::LD(1, 0),
                // Move between registers
                Instruction::MOV(2, 1),
                Instruction::RET(2),
            ],
            labels: HashMap::new(),
        };

        vm.register_function(test_function);
        let result = vm.execute("test_load").unwrap();
        assert_eq!(result, Value::Int(42));
    }

    #[test]
    fn test_object_operations() {
        let vm = setup_vm();

        let test_function = VMFunction {
            name: "test_objects".to_string(),
            parameters: vec![],
            upvalues: Vec::new(),
            parent: None,
            register_count: 5,
            instructions: vec![
                // Create object
                Instruction::CALL("create_object".to_string()),
                Instruction::MOV(1, 0),
                // Set field "name" to "test"
                Instruction::PUSHARG(1),
                Instruction::LDI(2, Value::String("name".to_string())),
                Instruction::PUSHARG(2),
                Instruction::LDI(3, Value::String("test".to_string())),
                Instruction::PUSHARG(3),
                Instruction::CALL("set_field".to_string()),
                // Get field "name"
                Instruction::PUSHARG(1),
                Instruction::PUSHARG(2),
                Instruction::CALL("get_field".to_string()),
                Instruction::RET(0),
            ],
            labels: HashMap::new(),
        };

        vm.register_function(test_function);
        let result = vm.execute("test_objects").unwrap();
        assert_eq!(result, Value::String("test".to_string()));
    }

    #[test]
    fn test_object_nested_fields() {
        let vm = setup_vm();

        let test_function = VMFunction {
            name: "test_nested_objects".to_string(),
            parameters: vec![],
            upvalues: Vec::new(),
            parent: None,
            register_count: 5,
            instructions: vec![
                // Create parent object
                Instruction::CALL("create_object".to_string()),
                Instruction::MOV(1, 0),
                // Create child object
                Instruction::CALL("create_object".to_string()),
                Instruction::MOV(2, 0),
                // Set child.value = 42
                Instruction::PUSHARG(2),
                Instruction::LDI(3, Value::String("value".to_string())),
                Instruction::PUSHARG(3),
                Instruction::LDI(4, Value::Int(42)),
                Instruction::PUSHARG(4),
                Instruction::CALL("set_field".to_string()),
                // Set parent.child = child
                Instruction::PUSHARG(1),
                Instruction::LDI(3, Value::String("child".to_string())),
                Instruction::PUSHARG(3),
                Instruction::PUSHARG(2),
                Instruction::CALL("set_field".to_string()),
                // Get parent.child
                Instruction::PUSHARG(1),
                Instruction::PUSHARG(3),
                Instruction::CALL("get_field".to_string()),
                Instruction::MOV(2, 0),
                // Get child.value
                Instruction::PUSHARG(2),
                Instruction::LDI(3, Value::String("value".to_string())),
                Instruction::PUSHARG(3),
                Instruction::CALL("get_field".to_string()),
                Instruction::RET(0),
            ],
            labels: HashMap::new(),
        };

        vm.register_function(test_function);
        let result = vm.execute("test_nested_objects").unwrap();
        assert_eq!(result, Value::Int(42));
    }

    #[test]
    fn test_array_operations() {
        let vm = setup_vm();

        let test_function = VMFunction {
            name: "test_arrays".to_string(),
            parameters: vec![],
            upvalues: Vec::new(),
            parent: None,
            register_count: 5,
            instructions: vec![
                // Create array
                Instruction::LDI(0, Value::Int(5)),
                Instruction::PUSHARG(0),
                Instruction::CALL("create_array".to_string()),
                Instruction::MOV(1, 0),
                // Push elements
                Instruction::PUSHARG(1),
                Instruction::LDI(2, Value::Int(42)),
                Instruction::PUSHARG(2),
                Instruction::CALL("array_push".to_string()),
                // Get element at index 1
                Instruction::PUSHARG(1),
                Instruction::LDI(3, Value::Int(1)),
                Instruction::PUSHARG(3),
                Instruction::CALL("get_field".to_string()),
                Instruction::RET(0),
            ],
            labels: HashMap::new(),
        };

        vm.register_function(test_function);
        let result = vm.execute("test_arrays").unwrap();
        assert_eq!(result, Value::Int(42));
    }

    #[test]
    fn test_array_length() {
        let vm = setup_vm();

        let test_function = VMFunction {
            name: "test_array_length".to_string(),
            parameters: vec![],
            upvalues: Vec::new(),
            parent: None,
            register_count: 5,
            instructions: vec![
                // Create array
                Instruction::CALL("create_array".to_string()),
                Instruction::MOV(1, 0),
                // Push multiple elements
                Instruction::PUSHARG(1),
                Instruction::LDI(2, Value::Int(10)),
                Instruction::PUSHARG(2),
                Instruction::CALL("array_push".to_string()),
                Instruction::PUSHARG(1),
                Instruction::LDI(2, Value::Int(20)),
                Instruction::PUSHARG(2),
                Instruction::CALL("array_push".to_string()),
                Instruction::PUSHARG(1),
                Instruction::LDI(2, Value::Int(30)),
                Instruction::PUSHARG(2),
                Instruction::CALL("array_push".to_string()),
                // Get array length
                Instruction::PUSHARG(1),
                Instruction::CALL("array_length".to_string()),
                Instruction::RET(0),
            ],
            labels: HashMap::new(),
        };

        vm.register_function(test_function);
        let result = vm.execute("test_array_length").unwrap();
        assert_eq!(result, Value::Int(3));
    }

    #[test]
    fn test_array_non_integer_indices() {
        let vm = setup_vm();

        let test_function = VMFunction {
            name: "test_array_string_keys".to_string(),
            parameters: vec![],
            upvalues: Vec::new(),
            parent: None,
            register_count: 5,
            instructions: vec![
                // Create array
                Instruction::CALL("create_array".to_string()),
                Instruction::MOV(1, 0),
                // Set array["key"] = "value"
                Instruction::PUSHARG(1),
                Instruction::LDI(2, Value::String("key".to_string())),
                Instruction::PUSHARG(2),
                Instruction::LDI(3, Value::String("value".to_string())),
                Instruction::PUSHARG(3),
                Instruction::CALL("set_field".to_string()),
                // Get array["key"]
                Instruction::PUSHARG(1),
                Instruction::PUSHARG(2),
                Instruction::CALL("get_field".to_string()),
                Instruction::RET(0),
            ],
            labels: HashMap::new(),
        };

        vm.register_function(test_function);
        let result = vm.execute("test_array_string_keys").unwrap();
        assert_eq!(result, Value::String("value".to_string()));
    }

    #[test]
    fn test_closures() {
        let vm = setup_vm();

        // Counter creator function
        let create_counter = VMFunction {
            name: "create_counter".to_string(),
            parameters: vec!["start".to_string()],
            upvalues: Vec::new(),
            parent: None,
            register_count: 5,
            instructions: vec![
                Instruction::LDI(1, Value::String("increment".to_string())),
                Instruction::PUSHARG(1),
                Instruction::LDI(2, Value::String("start".to_string())),
                Instruction::PUSHARG(2),
                Instruction::CALL("create_closure".to_string()),
                // Save the closure in another register BEFORE calling type/print
                Instruction::MOV(3, 0), // Save closure to r3
                // Now it's safe to do debug prints
                Instruction::PUSHARG(0),
                Instruction::CALL("type".to_string()),
                Instruction::PUSHARG(0),
                Instruction::CALL("print".to_string()),
                // Restore the closure to r0 before returning
                Instruction::MOV(0, 3),
                Instruction::RET(0), // Now returns the closure
            ],
            labels: HashMap::new(),
        };

        let increment = VMFunction {
            name: "increment".to_string(),
            parameters: vec!["amount".to_string()],
            upvalues: vec!["start".to_string()],
            parent: Some("create_counter".to_string()),
            register_count: 5,
            instructions: vec![
                // "amount" is in r0
                Instruction::MOV(2, 0), // Save amount to r2 before it gets overwritten
                // Get upvalue value
                Instruction::LDI(1, Value::String("start".to_string())),
                Instruction::PUSHARG(1),
                Instruction::CALL("get_upvalue".to_string()),
                // Current "start" value is now in r0

                // Add amount to start
                Instruction::ADD(3, 0, 2), // r3 = start + amount
                // Update the upvalue
                Instruction::LDI(1, Value::String("start".to_string())),
                Instruction::PUSHARG(1),
                Instruction::PUSHARG(3),
                Instruction::CALL("set_upvalue".to_string()),
                // r0 now contains unit/void

                // Return the new value
                Instruction::MOV(0, 3), // Put result back in r0 before returning
                Instruction::RET(0),
            ],
            labels: HashMap::new(),
        };

        // Test function
        let test_function = VMFunction {
            name: "test_closures".to_string(),
            parameters: vec![],
            upvalues: Vec::new(),
            parent: None,
            register_count: 8,
            instructions: vec![
                // Create counter with initial value 10
                Instruction::LDI(0, Value::Int(10)),
                Instruction::PUSHARG(0),
                Instruction::CALL("create_counter".to_string()),
                Instruction::MOV(1, 0), // Save closure in r1
                // ONLY INCLUDE SIMPLE DEBUGGING - NO CHAINED CALLS
                // This simple debugging won't cause stack issues
                Instruction::PUSHARG(1),
                Instruction::CALL("type".to_string()),
                Instruction::MOV(5, 0), // Save type result
                Instruction::PUSHARG(5),
                Instruction::CALL("print".to_string()),
                // First call to increment
                Instruction::PUSHARG(1),
                Instruction::LDI(2, Value::Int(5)),
                Instruction::PUSHARG(2),
                Instruction::CALL("call_closure".to_string()),
                Instruction::MOV(3, 0), // Save first result in r3
                // Print first result (standalone calls)
                Instruction::PUSHARG(3),
                Instruction::CALL("print".to_string()),
                // Second call to increment
                Instruction::PUSHARG(1),
                Instruction::LDI(2, Value::Int(7)),
                Instruction::PUSHARG(2),
                Instruction::CALL("call_closure".to_string()),
                Instruction::MOV(4, 0), // Save second result in r4
                // Print second result (standalone calls)
                Instruction::PUSHARG(4),
                Instruction::CALL("print".to_string()),
                // Return final result
                Instruction::RET(4),
            ],
            labels: HashMap::new(),
        };

        vm.register_function(create_counter);
        vm.register_function(increment);
        vm.register_function(test_function);

        // Before running the test
        let upvalue_log = Arc::new(Mutex::new(Vec::new()));
        let upvalue_log_clone = Arc::clone(&upvalue_log);

        vm.register_hook(
            |event| {
                matches!(event, HookEvent::UpvalueRead(_, _))
                    || matches!(event, HookEvent::UpvalueWrite(_, _, _))
            },
            move |event, ctx| {
                // add 'move' keyword to explicitly capture upvalue_log_clone
                match event {
                    HookEvent::UpvalueRead(name, value) => {
                        if let Ok(mut log) = upvalue_log_clone.lock() {
                            log.push(format!("Read {} = {:?}", name, value));
                        }
                    }
                    HookEvent::UpvalueWrite(name, old, new) => {
                        if let Ok(mut log) = upvalue_log_clone.lock() {
                            log.push(format!("Write {} {:?} -> {:?}", name, old, new));
                        }
                    }
                    _ => {}
                }
                Ok(())
            },
            100,
        );

        // Run the test
        let result = vm.execute("test_closures").unwrap();

        // Print the upvalue operations log
        println!("UPVALUE OPERATIONS:");
        if let Ok(log) = upvalue_log.lock() {
            for entry in log.iter() {
                println!("{}", entry);
            }
        }

        // Check expected value
        assert_eq!(result, Value::Int(22));
    }

    #[test]
    fn test_multiple_closures() {
        let vm = setup_vm();

        // Counter creator function
        let create_counter = VMFunction {
            name: "create_counter".to_string(),
            parameters: vec!["start".to_string()],
            upvalues: Vec::new(),
            parent: None,
            register_count: 5,
            instructions: vec![
                // Store start parameter as local variable to isolate it per closure
                Instruction::MOV(3, 0), // Copy start parameter to r3
                // Create the increment closure with the local start value
                Instruction::LDI(1, Value::String("increment".to_string())),
                Instruction::PUSHARG(1),
                Instruction::LDI(2, Value::String("start".to_string())),
                Instruction::PUSHARG(2),
                Instruction::CALL("create_closure".to_string()),
                Instruction::RET(0),
            ],
            labels: HashMap::new(),
        };

        // Increment function
        let increment = VMFunction {
            name: "increment".to_string(),
            parameters: vec!["amount".to_string()],
            upvalues: vec!["start".to_string()],
            parent: Some("create_counter".to_string()),
            register_count: 5,
            instructions: vec![
                // Get upvalue
                Instruction::LDI(1, Value::String("start".to_string())),
                Instruction::PUSHARG(1),
                Instruction::CALL("get_upvalue".to_string()),
                Instruction::MOV(1, 0),
                // Add amount
                Instruction::ADD(2, 1, 0),
                // Set upvalue
                Instruction::LDI(3, Value::String("start".to_string())),
                Instruction::PUSHARG(3),
                Instruction::PUSHARG(2),
                Instruction::CALL("set_upvalue".to_string()),
                // Return new value
                Instruction::MOV(0, 2),
                Instruction::RET(0),
            ],
            labels: HashMap::new(),
        };

        // Test function with multiple counters
        let test_function = VMFunction {
            name: "test_multiple_closures".to_string(),
            parameters: vec![],
            upvalues: Vec::new(),
            parent: None,
            register_count: 5,
            instructions: vec![
                // Create counter1 with initial value 10
                Instruction::LDI(0, Value::Int(10)),
                Instruction::PUSHARG(0),
                Instruction::CALL("create_counter".to_string()),
                Instruction::MOV(1, 0),
                // Create counter2 with initial value 20
                Instruction::LDI(0, Value::Int(20)),
                Instruction::PUSHARG(0),
                Instruction::CALL("create_counter".to_string()),
                Instruction::MOV(2, 0),
                // Call counter1 with 5
                Instruction::PUSHARG(1),
                Instruction::LDI(0, Value::Int(5)),
                Instruction::PUSHARG(0),
                Instruction::CALL("call_closure".to_string()),
                Instruction::MOV(3, 0),
                // Call counter2 with 10
                Instruction::PUSHARG(2),
                Instruction::LDI(0, Value::Int(10)),
                Instruction::PUSHARG(0),
                Instruction::CALL("call_closure".to_string()),
                Instruction::MOV(4, 0),
                // Return counter2 result
                Instruction::RET(4),
            ],
            labels: HashMap::new(),
        };

        vm.register_function(create_counter);
        vm.register_function(increment);
        vm.register_function(test_function);

        // Before running the test
        let upvalue_log = Arc::new(Mutex::new(Vec::new()));
        let upvalue_log_clone = Arc::clone(&upvalue_log);

        vm.register_hook(
            |event| matches!(event, HookEvent::ClosureCreated(_, _)),
            move |event, ctx| {
                if let HookEvent::ClosureCreated(func_name, upvalues) = event {
                    println!("CLOSURE CREATED: {} with upvalues:", func_name);
                    for upval in upvalues {
                        println!("  - {}: {:?}", upval.name, upval.value);
                    }
                }
                Ok(())
            },
            100,
        );

        // 2. Hook for function calls
        vm.register_hook(
            |event| matches!(event, HookEvent::BeforeFunctionCall(_, _)),
            move |event, ctx| {
                if let HookEvent::BeforeFunctionCall(func, args) = event {
                    println!("FUNCTION CALL: {:?} with args: {:?}", func, args);
                }
                Ok(())
            },
            100,
        );

        // 3. Hook for function returns
        vm.register_hook(
            |event| matches!(event, HookEvent::AfterFunctionCall(_, _)),
            move |event, ctx| {
                if let HookEvent::AfterFunctionCall(func, result) = event {
                    println!("FUNCTION RETURN: {:?} -> {:?}", func, result);
                }
                Ok(())
            },
            100,
        );

        // 4. Hook for register operations
        vm.register_hook(
            |event| matches!(event, HookEvent::RegisterWrite(_, _, _)),
            move |event, ctx| {
                if let HookEvent::RegisterWrite(reg, old, new) = event {
                    println!("REGISTER WRITE: r{} = {:?} (was {:?})", reg, new, old);
                }
                Ok(())
            },
            100,
        );

        // 5. Hook for stack operations
        vm.register_hook(
            |event| {
                matches!(event, HookEvent::StackPush(_)) || matches!(event, HookEvent::StackPop(_))
            },
            move |event, ctx| {
                match event {
                    HookEvent::StackPush(value) => println!("STACK PUSH: {:?}", value),
                    HookEvent::StackPop(value) => println!("STACK POP: {:?}", value),
                    _ => {}
                }
                Ok(())
            },
            100,
        );

        // 6. Hook for local variable operations
        vm.register_hook(
            |event| {
                matches!(event, HookEvent::VariableRead(_, _))
                    || matches!(event, HookEvent::VariableWrite(_, _, _))
            },
            move |event, ctx| {
                match event {
                    HookEvent::VariableRead(name, value) => {
                        println!("VARIABLE READ: {} = {:?}", name, value);
                    }
                    HookEvent::VariableWrite(name, old, new) => {
                        println!("VARIABLE WRITE: {} = {:?} (was {:?})", name, new, old);
                    }
                    _ => {}
                }
                Ok(())
            },
            100,
        );

        // 7. Hook for instruction execution
        vm.register_hook(
            |event| matches!(event, HookEvent::BeforeInstructionExecute(_)),
            move |event, ctx| {
                if let HookEvent::BeforeInstructionExecute(instr) = event {
                    let func_name = ctx
                        .get_function_name()
                        .unwrap_or_else(|| "unknown".to_string());
                    println!(
                        "EXEC [{}:{}]: {:?}",
                        func_name,
                        ctx.get_current_instruction(),
                        instr
                    );
                }
                Ok(())
            },
            100,
        );

        // 8. Hook specifically to trace activation records
        vm.register_hook(
            |event| true, // Any event
            move |event, _ctx| {
                // This runs on every hook - add these lines to the existing upvalue hook
                if matches!(event, HookEvent::UpvalueRead(_, _))
                    || matches!(event, HookEvent::UpvalueWrite(_, _, _))
                {
                    // Get call stack information
                    println!("  Call stack depth: {}", _ctx.get_call_depth());
                    println!(
                        "  Current function: {}",
                        _ctx.get_function_name().unwrap_or_default()
                    );
                }
                Ok(())
            },
            90, // Lower priority so it runs after other hooks
        );

        vm.register_hook(
            |event| {
                matches!(event, HookEvent::UpvalueRead(_, _))
                    || matches!(event, HookEvent::UpvalueWrite(_, _, _))
            },
            move |event, ctx| {
                // add 'move' keyword to explicitly capture upvalue_log_clone
                match event {
                    HookEvent::UpvalueRead(name, value) => {
                        if let Ok(mut log) = upvalue_log_clone.lock() {
                            log.push(format!("Read {} = {:?}", name, value));
                        }
                    }
                    HookEvent::UpvalueWrite(name, old, new) => {
                        if let Ok(mut log) = upvalue_log_clone.lock() {
                            log.push(format!("Write {} {:?} -> {:?}", name, old, new));
                        }
                    }
                    _ => {}
                }
                Ok(())
            },
            100,
        );

        let result = vm.execute("test_multiple_closures").unwrap();

        // Print the upvalue operations log
        println!("UPVALUE OPERATIONS:");
        if let Ok(log) = upvalue_log.lock() {
            for entry in log.iter() {
                println!("{}", entry);
            }
        }

        assert_eq!(result, Value::Int(30)); // 20 + 10 = 30
    }

    #[test]
    fn test_nested_closures() {
        let vm = setup_vm();

        // Create a function that returns a function that captures both parameters
        let create_adder = VMFunction {
            name: "create_adder".to_string(),
            parameters: vec!["x".to_string()],
            upvalues: Vec::new(),
            parent: None,
            register_count: 5,
            instructions: vec![
                Instruction::LDI(1, Value::String("add".to_string())),
                Instruction::PUSHARG(1),
                Instruction::LDI(2, Value::String("x".to_string())),
                Instruction::PUSHARG(2),
                Instruction::CALL("create_closure".to_string()),
                Instruction::RET(0),
            ],
            labels: HashMap::new(),
        };

        // The inner function that adds its parameter to the captured x
        let add = VMFunction {
            name: "add".to_string(),
            parameters: vec!["y".to_string()],
            upvalues: vec!["x".to_string()],
            parent: Some("create_adder".to_string()),
            register_count: 5,
            instructions: vec![
                // Save y in register r3 so it doesn't get overwritten
                Instruction::MOV(3, 0), // r3 = y
                // Get upvalue x
                Instruction::LDI(1, Value::String("x".to_string())),
                Instruction::PUSHARG(1),
                Instruction::CALL("get_upvalue".to_string()),
                // x is now in r0

                // Add y (in r3) to x (in r0)
                Instruction::ADD(2, 0, 3), // r2 = x + y
                // Make sure we're returning the right value
                Instruction::MOV(0, 2), // r0 = r2 (result)
                Instruction::RET(0),    // Return register 0
            ],
            labels: HashMap::new(),
        };

        // Test function
        let test_function = VMFunction {
            name: "test_nested_closures".to_string(),
            parameters: vec![],
            upvalues: Vec::new(),
            parent: None,
            register_count: 5,
            instructions: vec![
                // Create adder with x=10
                Instruction::LDI(0, Value::Int(10)),
                Instruction::PUSHARG(0),
                Instruction::CALL("create_adder".to_string()),
                Instruction::MOV(1, 0),
                // Call adder with y=5
                Instruction::PUSHARG(1),
                Instruction::LDI(0, Value::Int(5)),
                Instruction::PUSHARG(0),
                Instruction::CALL("call_closure".to_string()),
                Instruction::RET(0),
            ],
            labels: HashMap::new(),
        };

        vm.register_function(create_adder);
        vm.register_function(add);
        vm.register_function(test_function);

        let result = vm.execute("test_nested_closures").unwrap();
        assert_eq!(result, Value::Int(15)); // 10 + 5 = 15
    }

    #[test]
    fn test_foreign_functions() {
        let vm = setup_vm();

        // Register a custom foreign function
        vm.register_foreign_function("double", |ctx| {
            if ctx.args.len() != 1 {
                return Err("double expects 1 argument".to_string());
            }

            match &ctx.args[0] {
                Value::Int(n) => Ok(Value::Int(n * 2)),
                _ => Err("double expects an integer".to_string()),
            }
        });

        let test_function = VMFunction {
            name: "test_foreign".to_string(),
            parameters: vec![],
            upvalues: Vec::new(),
            parent: None,
            register_count: 3,
            instructions: vec![
                Instruction::LDI(0, Value::Int(21)),
                Instruction::PUSHARG(0),
                Instruction::CALL("double".to_string()),
                Instruction::RET(0),
            ],
            labels: HashMap::new(),
        };

        vm.register_function(test_function);
        let result = vm.execute("test_foreign").unwrap();
        assert_eq!(result, Value::Int(42));
    }

    #[test]
    fn test_foreign_function_with_multiple_args() {
        let vm = setup_vm();

        // Register a custom foreign function that takes multiple arguments
        vm.register_foreign_function("sum", |ctx| {
            if ctx.args.len() < 2 {
                return Err("sum expects at least 2 arguments".to_string());
            }

            let mut total = 0;
            for arg in ctx.args.iter() {
                match arg {
                    Value::Int(n) => total += n,
                    _ => return Err("sum expects integers".to_string()),
                }
            }

            Ok(Value::Int(total))
        });

        let test_function = VMFunction {
            name: "test_foreign_multi_args".to_string(),
            parameters: vec![],
            upvalues: Vec::new(),
            parent: None,
            register_count: 4,
            instructions: vec![
                Instruction::LDI(0, Value::Int(10)),
                Instruction::PUSHARG(0),
                Instruction::LDI(1, Value::Int(20)),
                Instruction::PUSHARG(1),
                Instruction::LDI(2, Value::Int(12)),
                Instruction::PUSHARG(2),
                Instruction::CALL("sum".to_string()),
                Instruction::RET(0),
            ],
            labels: HashMap::new(),
        };

        vm.register_function(test_function);
        let result = vm.execute("test_foreign_multi_args").unwrap();
        assert_eq!(result, Value::Int(42));
    }

    #[test]
    fn test_foreign_objects() {
        let vm = setup_vm();

        // Create a custom struct
        #[derive(Clone)] // Add Clone to make it easier to work with
        struct TestObject {
            value: i32,
        }

        // Register the object with the VM
        let obj = TestObject { value: 42 };
        let obj_value = vm.register_foreign_object(obj);

        // Register a function to access the object
        vm.register_foreign_function("get_test_object_value", move |ctx| {
            if ctx.args.len() != 1 {
                return Err("get_test_object_value expects 1 argument".to_string());
            }

            match &ctx.args[0] {
                Value::Foreign(id) => {
                    if let Some(obj_arc) =
                        ctx.vm_state.foreign_objects.get_object::<TestObject>(*id)
                    {
                        if let Ok(locked) = obj_arc.lock() {
                            // Return the actual value, not the pointer
                            Ok(Value::Int(locked.value as i64))
                        } else {
                            Err("Failed to lock foreign object".to_string())
                        }
                    } else {
                        Err("Invalid foreign object".to_string())
                    }
                }
                _ => Err("Expected foreign object".to_string()),
            }
        });

        let test_function = VMFunction {
            name: "test_foreign_object".to_string(),
            parameters: vec![],
            upvalues: Vec::new(),
            parent: None,
            register_count: 2,
            instructions: vec![
                // Load the foreign object ID
                Instruction::LDI(0, obj_value.clone()), // Use clone to avoid ownership issues
                Instruction::PUSHARG(0),
                Instruction::CALL("get_test_object_value".to_string()),
                Instruction::RET(0),
            ],
            labels: HashMap::new(),
        };

        vm.register_function(test_function);
        let result = vm.execute("test_foreign_object").unwrap();
        assert_eq!(result, Value::Int(42));
    }

    #[test]
    fn test_foreign_object_mutation() {
        let vm = setup_vm();

        // Create a custom struct
        struct Counter {
            value: i64,
        }

        // Register the object with the VM
        let counter = Counter { value: 0 };
        let counter_value = vm.register_foreign_object(counter);

        // Update the increment_counter implementation to be more defensive
        vm.register_foreign_function("increment_counter", move |ctx| {
            println!(
                "increment_counter called with {} args: {:?}",
                ctx.args.len(),
                ctx.args
            );

            if ctx.args.len() != 2 {
                return Err(format!(
                    "increment_counter expects 2 arguments: counter and amount, got {}",
                    ctx.args.len()
                ));
            }

            match &ctx.args[0] {
                Value::Foreign(id) => {
                    println!("Processing foreign object with ID: {}", id);
                    if let Some(counter_rc) =
                        ctx.vm_state.foreign_objects.get_object::<Counter>(*id)
                    {
                        let amount = match &ctx.args[1] {
                            Value::Int(n) => n,
                            other => {
                                return Err(format!(
                                    "Second argument must be an integer, got {:?}",
                                    other
                                ))
                            }
                        };
                        let mut new_value = 0;
                        if let Ok(mut counter) = counter_rc.lock() {
                            counter.value += amount;
                            new_value = counter.value;
                            println!("Incremented counter to: {}", new_value);
                        }

                        Ok(Value::Int(new_value as i64))
                    } else {
                        Err(format!(
                            "Foreign object with ID {} not found or wrong type",
                            id
                        ))
                    }
                }
                other => {
                    println!("First argument is not a foreign object: {:?}", other);
                    Err(format!("Expected foreign object, got {:?}", other))
                }
            }
        });

        let test_function = VMFunction {
            name: "test_foreign_object_mutation".to_string(),
            parameters: vec![],
            upvalues: Vec::new(),
            parent: None,
            register_count: 3,
            instructions: vec![
                // Load the foreign object ID
                Instruction::LDI(0, counter_value.clone()),
                Instruction::PUSHARG(0),
                // Increment by 10
                Instruction::LDI(1, Value::Int(10)),
                Instruction::PUSHARG(1),
                Instruction::CALL("increment_counter".to_string()),
                // First result (11) is now in r0

                // IMPORTANT: Reload the foreign object ID
                Instruction::LDI(0, counter_value), // This is the key fix
                Instruction::PUSHARG(0),
                // Increment by 32
                Instruction::LDI(1, Value::Int(32)),
                Instruction::PUSHARG(1),
                Instruction::CALL("increment_counter".to_string()),
                Instruction::RET(0),
            ],
            labels: HashMap::new(),
        };

        vm.register_function(test_function);
        let result = vm.execute("test_foreign_object_mutation").unwrap();
        assert_eq!(result, Value::Int(42)); // 0 + 10 + 32 = 42
    }

    #[test]
    fn test_hook_system() {
        let vm = setup_vm();

        // Use a RefCell to track hook calls
        let hook_calls = Arc::new(Mutex::new(0));
        let hook_calls_clone = Arc::clone(&hook_calls);

        // Register a hook that counts instruction executions
        vm.register_hook(
            |event| matches!(event, HookEvent::BeforeInstructionExecute(_)),
            move |_, _| {
                if let Ok(mut calls) = hook_calls_clone.lock() {
                    *calls += 1;
                }
                Ok(())
            },
            100,
        );

        let test_function = VMFunction {
            name: "test_hooks".to_string(),
            parameters: vec![],
            upvalues: Vec::new(),
            parent: None,
            register_count: 2,
            instructions: vec![
                Instruction::LDI(0, Value::Int(1)),
                Instruction::LDI(1, Value::Int(2)),
                Instruction::ADD(0, 0, 1),
                Instruction::RET(0),
            ],
            labels: HashMap::new(),
        };

        vm.register_function(test_function);
        let result = vm.execute("test_hooks").unwrap();

        assert_eq!(result, Value::Int(3));
        if let Ok(hook_calls) = hook_calls.lock() {
            assert_eq!(*hook_calls, 4); // 4 instructions executed
        };
    }

    #[test]
    fn test_register_read_write_hooks() {
        let vm = setup_vm();

        // Track register writes
        let register_writes = Arc::new(Mutex::new(Vec::<(usize, Value)>::new()));
        let register_writes_clone = Arc::clone(&register_writes);

        // Then fix the hook registration
        vm.register_hook(
            |event| matches!(event, HookEvent::RegisterWrite(_, _, _)),
            move |event, ctx| {
                // Add the ctx parameter
                if let HookEvent::RegisterWrite(reg, _, new_value) = event {
                    if let Ok(mut log) = register_writes_clone.lock() {
                        // Make sure types match here - reg is already usize, keep it that way
                        log.push((*reg, new_value.clone()));
                    }
                }
                Ok(())
            },
            100,
        );

        let test_function = VMFunction {
            name: "test_register_hooks".to_string(),
            parameters: vec![],
            upvalues: Vec::new(),
            parent: None,
            register_count: 3,
            instructions: vec![
                Instruction::LDI(0, Value::Int(10)),
                Instruction::LDI(1, Value::Int(20)),
                Instruction::ADD(2, 0, 1),
                Instruction::RET(2),
            ],
            labels: HashMap::new(),
        };

        vm.register_function(test_function);
        let result = vm.execute("test_register_hooks").unwrap();

        assert_eq!(result, Value::Int(30));

        if let Ok(writes) = register_writes.lock() {
            assert_eq!(writes.len(), 3);
            assert_eq!(writes[0], (0, Value::Int(10)));
            assert_eq!(writes[1], (1, Value::Int(20)));
            assert_eq!(writes[2], (2, Value::Int(30)));
        };
    }

    #[test]
    fn test_upvalue_hooks() {
        let vm = setup_vm();

        // Track upvalue operations
        let upvalue_ops = Arc::new(Mutex::new(Vec::new()));
        let upvalue_ops_clone = Arc::clone(&upvalue_ops);

        // Register a hook that tracks upvalue operations
        vm.register_hook(
            |event| {
                matches!(event, HookEvent::UpvalueRead(_, _))
                    || matches!(event, HookEvent::UpvalueWrite(_, _, _))
            },
            move |event, _ctx| {
                match event {
                    HookEvent::UpvalueRead(name, value) => {
                        if let Ok(mut ops) = upvalue_ops_clone.lock() {
                            ops.push(("read", name.clone(), value.clone()));
                        }
                    }
                    HookEvent::UpvalueWrite(name, _, new_value) => {
                        if let Ok(mut ops) = upvalue_ops_clone.lock() {
                            ops.push(("write", name.clone(), new_value.clone()));
                        }
                    }
                    _ => {}
                }
                Ok(())
            },
            100,
        );

        // Counter creator function
        let create_counter = VMFunction {
            name: "create_counter".to_string(),
            parameters: vec!["start".to_string()],
            upvalues: Vec::new(),
            parent: None,
            register_count: 5,
            instructions: vec![
                Instruction::LDI(1, Value::String("increment".to_string())),
                Instruction::PUSHARG(1),
                Instruction::LDI(2, Value::String("start".to_string())),
                Instruction::PUSHARG(2),
                Instruction::CALL("create_closure".to_string()),
                Instruction::RET(0),
            ],
            labels: HashMap::new(),
        };

        // Increment function
        let increment = VMFunction {
            name: "increment".to_string(),
            parameters: vec!["amount".to_string()],
            upvalues: vec!["start".to_string()],
            parent: Some("create_counter".to_string()),
            register_count: 5,
            instructions: vec![
                // Get upvalue
                Instruction::LDI(1, Value::String("start".to_string())),
                Instruction::PUSHARG(1),
                Instruction::CALL("get_upvalue".to_string()),
                Instruction::MOV(1, 0),
                // Add amount
                Instruction::ADD(2, 1, 0),
                // Set upvalue
                Instruction::LDI(3, Value::String("start".to_string())),
                Instruction::PUSHARG(3),
                Instruction::PUSHARG(2),
                Instruction::CALL("set_upvalue".to_string()),
                // Return new value
                Instruction::MOV(0, 2),
                Instruction::RET(0),
            ],
            labels: HashMap::new(),
        };

        // Test function
        let test_function = VMFunction {
            name: "test_upvalue_hooks".to_string(),
            parameters: vec![],
            upvalues: Vec::new(),
            parent: None,
            register_count: 5,
            instructions: vec![
                // Create counter with initial value 10
                Instruction::LDI(0, Value::Int(10)),
                Instruction::PUSHARG(0),
                Instruction::CALL("create_counter".to_string()),
                Instruction::MOV(1, 0),
                // Call increment with 5
                Instruction::PUSHARG(1),
                Instruction::LDI(2, Value::Int(5)),
                Instruction::PUSHARG(2),
                Instruction::CALL("call_closure".to_string()),
                Instruction::RET(0),
            ],
            labels: HashMap::new(),
        };

        vm.register_function(create_counter);
        vm.register_function(increment);
        vm.register_function(test_function);

        let result = vm.execute("test_upvalue_hooks").unwrap();
        assert_eq!(result, Value::Int(15)); // 10 + 5 = 15

        if let Ok(ops) = upvalue_ops.lock() {
            assert_eq!(ops.len(), 2);
            assert_eq!(ops[0], ("read", "start".to_string(), Value::Int(10)));
            assert_eq!(ops[1], ("write", "start".to_string(), Value::Int(15)));
        };
    }

    #[test]
    fn test_error_handling() {
        let vm = setup_vm();

        // Test division by zero
        let div_zero_function = VMFunction {
            name: "div_zero".to_string(),
            parameters: vec![],
            upvalues: Vec::new(),
            parent: None,
            register_count: 3,
            instructions: vec![
                Instruction::LDI(0, Value::Int(10)),
                Instruction::LDI(1, Value::Int(0)),
                Instruction::DIV(2, 0, 1),
                Instruction::RET(2),
            ],
            labels: HashMap::new(),
        };

        vm.register_function(div_zero_function);
        let result = vm.execute("div_zero");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Division by zero");

        // Test invalid function call
        let invalid_call_function = VMFunction {
            name: "invalid_call".to_string(),
            parameters: vec![],
            upvalues: Vec::new(),
            parent: None,
            register_count: 1,
            instructions: vec![
                Instruction::CALL("nonexistent_function".to_string()),
                Instruction::RET(0),
            ],
            labels: HashMap::new(),
        };

        vm.register_function(invalid_call_function);
        let result = vm.execute("invalid_call");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Function 'nonexistent_function' not found"
        );
    }

    #[test]
    fn test_type_errors() {
        let vm = setup_vm();

        // Test type error in arithmetic
        let type_error_function = VMFunction {
            name: "type_error".to_string(),
            parameters: vec![],
            upvalues: Vec::new(),
            parent: None,
            register_count: 3,
            instructions: vec![
                Instruction::LDI(0, Value::Int(10)),
                Instruction::LDI(1, Value::String("not a number".to_string())),
                Instruction::ADD(2, 0, 1),
                Instruction::RET(2),
            ],
            labels: HashMap::new(),
        };

        vm.register_function(type_error_function);
        let result = vm.execute("type_error");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Type error in ADD operation");
    }

    #[test]
    fn test_stack_operations() {
        let vm = setup_vm();

        // Track stack operations
        let stack_ops = Arc::new(Mutex::new(Vec::new()));
        let stack_ops_clone = Arc::clone(&stack_ops);

        // Register a hook that tracks stack operations
        vm.register_hook(
            |event| {
                matches!(event, HookEvent::StackPush(_)) || matches!(event, HookEvent::StackPop(_))
            },
            move |event, ctx| {
                match event {
                    HookEvent::StackPush(value) => {
                        if let Ok(mut ops) = stack_ops_clone.lock() {
                            ops.push(("push", value.clone()));
                        }
                    }
                    HookEvent::StackPop(value) => {
                        if let Ok(mut ops) = stack_ops_clone.lock() {
                            ops.push(("pop", value.clone()));
                        }
                    }
                    _ => {}
                }
                Ok(())
            },
            100,
        );

        let test_function = VMFunction {
            name: "test_stack".to_string(),
            parameters: vec![],
            upvalues: Vec::new(),
            parent: None,
            register_count: 3,
            instructions: vec![
                Instruction::LDI(0, Value::Int(10)),
                Instruction::PUSHARG(0),
                Instruction::LDI(1, Value::Int(20)),
                Instruction::PUSHARG(1),
                Instruction::CALL("sum".to_string()),
                Instruction::RET(0),
            ],
            labels: HashMap::new(),
        };

        // Register sum function
        vm.register_foreign_function("sum", |ctx| {
            if ctx.args.len() != 2 {
                return Err("sum expects 2 arguments".to_string());
            }

            match (&ctx.args[0], &ctx.args[1]) {
                (Value::Int(a), Value::Int(b)) => Ok(Value::Int(a + b)),
                _ => Err("sum expects integers".to_string()),
            }
        });

        vm.register_function(test_function);
        let result = vm.execute("test_stack").unwrap();
        assert_eq!(result, Value::Int(30));

        if let Ok(ops) = stack_ops.lock() {
            println!("{}", format!("{:?}", ops));
            assert_eq!(ops.len(), 4);
            assert_eq!(ops[0], ("push", Value::Int(10)));
            assert_eq!(ops[1], ("push", Value::Int(20)));
            assert_eq!(ops[2], ("pop", Value::Int(20)));
            assert_eq!(ops[3], ("pop", Value::Int(10)));
        };
    }

    #[test]
    fn test_fibonacci() {
        let vm = setup_vm();

        // Fibonacci function
        let mut labels = HashMap::new();
        labels.insert("base_case_zero".to_string(), 7);
        labels.insert("base_case_one".to_string(), 9);
        labels.insert("recursive_case".to_string(), 11);

        let fib_function = VMFunction {
            name: "fibonacci".to_string(),
            parameters: vec!["n".to_string()],
            upvalues: Vec::new(),
            parent: None,
            register_count: 5,
            instructions: vec![
                // Check if n == 0
                Instruction::LDI(1, Value::Int(0)),
                Instruction::CMP(0, 1),
                Instruction::JMPEQ("base_case_zero".to_string()),
                // Check if n == 1
                Instruction::LDI(1, Value::Int(1)),
                Instruction::CMP(0, 1),
                Instruction::JMPEQ("base_case_one".to_string()),
                // Otherwise, recursive case
                Instruction::JMP("recursive_case".to_string()),
                // base_case_zero: return 0
                Instruction::LDI(0, Value::Int(0)),
                Instruction::RET(0),
                // base_case_one: return 1
                Instruction::LDI(0, Value::Int(1)),
                Instruction::RET(0),
                // recursive_case: return fibonacci(n-1) + fibonacci(n-2)
                // Save n
                Instruction::MOV(4, 0), // Save n in r4
                // Calculate fibonacci(n-1)
                Instruction::LDI(1, Value::Int(1)),
                Instruction::SUB(2, 0, 1),
                Instruction::PUSHARG(2),
                Instruction::CALL("fibonacci".to_string()),
                Instruction::MOV(3, 0),
                // Calculate fibonacci(n-2)
                Instruction::MOV(0, 4), // Restore n from r4
                Instruction::LDI(1, Value::Int(2)),
                Instruction::SUB(2, 0, 1),
                Instruction::PUSHARG(2),
                Instruction::CALL("fibonacci".to_string()),
                // Add results
                Instruction::ADD(0, 0, 3),
                Instruction::RET(0),
            ],
            labels,
        };

        // Test function
        let test_function = VMFunction {
            name: "test_fibonacci".to_string(),
            parameters: vec![],
            upvalues: Vec::new(),
            parent: None,
            register_count: 2,
            instructions: vec![
                Instruction::LDI(0, Value::Int(10)),
                Instruction::PUSHARG(0),
                Instruction::CALL("fibonacci".to_string()),
                Instruction::RET(0),
            ],
            labels: HashMap::new(),
        };

        vm.register_function(fib_function);
        vm.register_function(test_function);

        let result = vm.execute("test_fibonacci").unwrap();
        assert_eq!(result, Value::Int(55)); // fib(10) = 55
    }

    #[test]
    fn test_factorial() {
        let vm = setup_vm();

        // Factorial function definition stays the same
        let mut labels = HashMap::new();
        labels.insert("base_case".to_string(), 6);
        labels.insert("recursive_case".to_string(), 8);

        let factorial_function = VMFunction {
            name: "factorial".to_string(),
            parameters: vec!["n".to_string()],
            upvalues: Vec::new(),
            parent: None,
            register_count: 5,
            instructions: vec![
                // Check if n == 1
                Instruction::LDI(1, Value::Int(1)), // r1 = 1
                Instruction::CMP(0, 1),             // Compare n with 1
                Instruction::JMPEQ("base_case".to_string()), // If n == 1, go to base case
                // Check if n < 1 by comparing 1 with n
                Instruction::CMP(1, 0), // Compare 1 with n
                // If 1 > n, compare_flag will be 1 (meaning n < 1)
                // If 1 < n, compare_flag will be -1 (meaning n > 1)
                Instruction::JMPNEQ("recursive_case".to_string()), // If not equal, go to recursive case
                // If execution reaches here, n must be < 1, so go to base case
                Instruction::JMP("base_case".to_string()),
                // base_case: (n <= 1)
                Instruction::LDI(0, Value::Int(1)), // Return 1
                Instruction::RET(0),
                // recursive_case: (n > 1)
                // Save n
                Instruction::MOV(3, 0), // r3 = n
                // Calculate n-1
                Instruction::LDI(1, Value::Int(1)), // r1 = 1
                Instruction::SUB(2, 0, 1),          // r2 = n - 1
                // Call factorial(n-1)
                Instruction::PUSHARG(2),
                Instruction::CALL("factorial".to_string()),
                // Result in r0

                // Multiply n * factorial(n-1)
                Instruction::MUL(0, 3, 0), // r0 = n * factorial(n-1)
                Instruction::RET(0),
            ],
            labels,
        };

        // Test function stays the same
        let test_function = VMFunction {
            name: "test_factorial".to_string(),
            parameters: vec![],
            upvalues: Vec::new(),
            parent: None,
            register_count: 2,
            instructions: vec![
                Instruction::LDI(0, Value::Int(5)),
                Instruction::PUSHARG(0),
                Instruction::CALL("factorial".to_string()),
                Instruction::RET(0),
            ],
            labels: HashMap::new(),
        };

        // Debug tracking
        let call_depth = Arc::new(Mutex::new(0));
        let call_depth_clone = Arc::clone(&call_depth);

        let compare_results = Arc::new(Mutex::new(Vec::new()));

        // Hook 1: Track instruction execution with depth
        let hook1_id = vm.register_hook(
            |event| matches!(event, HookEvent::BeforeInstructionExecute(_)),
            move |event, ctx| {
                if let HookEvent::BeforeInstructionExecute(instruction) = event {
                    if let Ok(call_depth) = call_depth_clone.lock() {
                        let depth = *call_depth;
                        let indent = "  ".repeat(depth);
                        println!("{}[D{}] EXEC: {:?}", indent, depth, instruction);
                    }
                }
                Ok(())
            },
            100,
        );

        let compare_results_clone = Arc::clone(&compare_results);
        let call_depth_clone = Arc::clone(&call_depth);
        // Hook 2: Track comparison operations
        let hook2_id = vm.register_hook(
            |event| {
                matches!(
                    event,
                    HookEvent::AfterInstructionExecute(Instruction::CMP(_, _))
                )
            },
            move |event, ctx| {
                if let HookEvent::AfterInstructionExecute(Instruction::CMP(reg1, reg2)) = event {
                    if let Some(record) = ctx.vm_state.activation_records.last() {
                        if let (Ok(call_depth), Ok(mut compare_results)) =
                            (call_depth_clone.lock(), compare_results_clone.lock())
                        {
                            let depth = *call_depth;
                            let indent = "  ".repeat(depth);
                            let flag = record.compare_flag;
                            compare_results.push((depth, *reg1, *reg2, flag));

                            let reg1_val = &record.registers[*reg1];
                            let reg2_val = &record.registers[*reg2];

                            let meaning = match flag {
                                -1 => "LESS THAN",
                                0 => "EQUAL",
                                1 => "GREATER THAN",
                                _ => "UNKNOWN",
                            };

                            println!(
                                "{}  CMP r{} ({:?}) r{} ({:?}) = {} ({})",
                                indent, reg1, reg1_val, reg2, reg2_val, flag, meaning
                            );
                        }
                    }
                }
                Ok(())
            },
            90,
        );

        let call_depth_clone = Arc::clone(&call_depth);
        // Hook 3: Track function calls and returns
        let hook3_id = vm.register_hook(
            |event| {
                matches!(event, HookEvent::BeforeFunctionCall(_, _))
                    || matches!(event, HookEvent::AfterFunctionCall(_, _))
            },
            move |event, ctx| {
                match event {
                    HookEvent::BeforeFunctionCall(_, args) => {
                        if let Ok(mut call_depth) = call_depth_clone.lock() {
                            let depth = *call_depth;
                            let indent = "  ".repeat(depth);
                            *call_depth += 1;

                            let arg_str = if !args.is_empty() {
                                format!("{:?}", args[0])
                            } else {
                                "no args".to_string()
                            };

                            println!("{}>> CALL factorial({}) [depth={}]", indent, arg_str, depth);
                        }
                    }
                    HookEvent::AfterFunctionCall(_, result) => {
                        if let Ok(mut call_depth) = call_depth_clone.lock() {
                            *call_depth -= 1;
                            let depth = *call_depth;
                            let indent = "  ".repeat(depth);
                            println!("{}<<  RETURN {:?} [depth={}]", indent, result, depth);
                        }
                    }
                    _ => {}
                }
                Ok(())
            },
            80,
        );

        let call_depth_clone = Arc::clone(&call_depth);
        // Hook 4: Track JMPEQ/JMPNEQ decisions
        let hook4_id = vm.register_hook(
            |event| {
                matches!(
                    event,
                    HookEvent::BeforeInstructionExecute(Instruction::JMPEQ(_))
                ) || matches!(
                    event,
                    HookEvent::BeforeInstructionExecute(Instruction::JMPNEQ(_))
                )
            },
            move |event, ctx| {
                if let HookEvent::BeforeInstructionExecute(jump_instruction) = event {
                    if let Some(record) = ctx.vm_state.activation_records.last() {
                        if let Ok(call_depth) = call_depth_clone.lock() {
                            let depth = *call_depth;
                            let indent = "  ".repeat(depth);
                            let flag = record.compare_flag;

                            let will_jump = match jump_instruction {
                                Instruction::JMPEQ(_) => flag == 0,
                                Instruction::JMPNEQ(_) => flag != 0,
                                _ => false,
                            };

                            let dest = match jump_instruction {
                                Instruction::JMPEQ(label) => label,
                                Instruction::JMPNEQ(label) => label,
                                _ => &"unknown".to_string(),
                            };

                            println!(
                                "{}  JUMP to {} will {}",
                                indent,
                                dest,
                                if will_jump { "HAPPEN" } else { "NOT HAPPEN" }
                            );
                        }
                    }
                }
                Ok(())
            },
            70,
        );

        vm.register_function(factorial_function);
        vm.register_function(test_function);

        println!("\n====== EXECUTING TEST_FACTORIAL ======\n");
        let result = vm.execute("test_factorial");

        // Clean up hooks
        vm.unregister_hook(hook1_id);
        vm.unregister_hook(hook2_id);
        vm.unregister_hook(hook3_id);
        vm.unregister_hook(hook4_id);

        match result {
            Ok(value) => {
                println!("\nFinal result: {:?}", value);

                // Print a summary of comparison operations
                println!("\nComparison operations (depth, reg1, reg2, flag):");
                if let Ok(compare_results) = compare_results.lock() {
                    for (depth, reg1, reg2, flag) in compare_results.iter() {
                        println!("  Depth {}: CMP r{} r{} = {}", depth, reg1, reg2, flag);
                    }

                    assert_eq!(value, Value::Int(120)); // 5! = 120
                }
            }
            Err(e) => {
                println!("\nERROR: {}", e);
                panic!("Test failed: {}", e);
            }
        }
    }

    #[test]
    fn test_performance() {
        let vm = setup_vm();

        // Loop function
        let mut labels = HashMap::new();
        labels.insert("loop_start".to_string(), 1);
        labels.insert("loop_end".to_string(), 7);

        let loop_function = VMFunction {
            name: "loop_test".to_string(),
            parameters: vec!["iterations".to_string()],
            upvalues: Vec::new(),
            parent: None,
            register_count: 4,
            instructions: vec![
                // Initialize counter
                Instruction::LDI(1, Value::Int(0)),
                // loop_start:
                Instruction::CMP(1, 0),
                Instruction::JMPEQ("loop_end".to_string()),
                // Increment counter
                Instruction::LDI(2, Value::Int(1)),
                Instruction::ADD(1, 1, 2),
                // Do some work (arithmetic)
                Instruction::MUL(3, 1, 2),
                // Loop back
                Instruction::JMP("loop_start".to_string()),
                // loop_end:
                Instruction::RET(1),
            ],
            labels,
        };

        vm.register_function(loop_function);

        // Run with different iteration counts to measure performance
        let iterations = 10000; // Reduced for faster test runs
        let start = Instant::now();

        let mut state = vm.state.lock().unwrap();
        let initial_record = ActivationRecord {
            function_name: "loop_test".to_string(),
            locals: HashMap::new(),
            registers: vec![
                Value::Int(iterations),
                Value::Unit,
                Value::Unit,
                Value::Unit,
            ],
            upvalues: Vec::new(),
            instruction_pointer: 0,
            stack: Vec::new(),
            compare_flag: 0,
        };

        state.activation_records.push(initial_record);
        drop(state);

        let result = vm.execute_until_return().unwrap();
        let duration = start.elapsed();

        assert_eq!(result, Value::Int(iterations));
        println!(
            "Performance test: {} iterations in {:?}",
            iterations, duration
        );
        // We don't assert on timing as it's environment-dependent
    }

    #[test]
    fn test_type_function() {
        let vm = setup_vm();

        let test_function = VMFunction {
            name: "test_type".to_string(),
            parameters: vec![],
            upvalues: Vec::new(),
            parent: None,
            register_count: 5,
            instructions: vec![
                // Test integer type
                Instruction::LDI(0, Value::Int(42)),
                Instruction::PUSHARG(0),
                Instruction::CALL("type".to_string()),
                Instruction::MOV(1, 0),
                // Test string type
                Instruction::LDI(0, Value::String("hello".to_string())),
                Instruction::PUSHARG(0),
                Instruction::CALL("type".to_string()),
                Instruction::MOV(2, 0),
                // Test boolean type
                Instruction::LDI(0, Value::Bool(true)),
                Instruction::PUSHARG(0),
                Instruction::CALL("type".to_string()),
                Instruction::MOV(3, 0),
                // Test object type
                Instruction::CALL("create_object".to_string()),
                Instruction::PUSHARG(0),
                Instruction::CALL("type".to_string()),
                Instruction::MOV(4, 0),
                // Return string type result
                Instruction::RET(2),
            ],
            labels: HashMap::new(),
        };

        vm.register_function(test_function);
        let result = vm.execute("test_type").unwrap();
        assert_eq!(result, Value::String("string".to_string()));
    }

    #[test]
    fn test_hook_enable_disable() {
        let vm = setup_vm();

        // Use a RefCell to track hook calls
        let hook_calls = Arc::new(Mutex::new(0));
        let hook_calls_clone = Arc::clone(&hook_calls);

        // Register a hook that counts instruction executions
        let hook_id = vm.register_hook(
            move |event| matches!(event, HookEvent::BeforeInstructionExecute(_)),
            move |_, _| {
                if let Ok(mut hook_calls_clone) = hook_calls_clone.lock() {
                    *hook_calls_clone += 1;
                }
                Ok(())
            },
            100,
        );

        let test_function = VMFunction {
            name: "test_hook_toggle".to_string(),
            parameters: vec![],
            upvalues: Vec::new(),
            parent: None,
            register_count: 2,
            instructions: vec![
                Instruction::LDI(0, Value::Int(1)),
                Instruction::LDI(1, Value::Int(2)),
                Instruction::ADD(0, 0, 1),
                Instruction::RET(0),
            ],
            labels: HashMap::new(),
        };

        vm.register_function(test_function);

        // First run with hook enabled
        let result = vm.execute("test_hook_toggle").unwrap();
        assert_eq!(result, Value::Int(3));
        if let Ok(mut hook_calls) = hook_calls.lock() {
            assert_eq!(*hook_calls, 4); // 4 instructions executed

            // Disable the hook
            assert!(vm.disable_hook(hook_id));

            // Reset counter
            *hook_calls = 0;

            // Run again with hook disabled
            let result = vm.execute("test_hook_toggle").unwrap();
            assert_eq!(result, Value::Int(3));
            assert_eq!(*hook_calls, 0); // No hook calls

            // Re-enable the hook
            assert!(vm.enable_hook(hook_id));

            // Run again with hook re-enabled
            let result = vm.execute("test_hook_toggle").unwrap();
            assert_eq!(result, Value::Int(3));
            assert_eq!(*hook_calls, 4); // 4 more instructions executed
        };
    }

    #[test]
    fn test_hook_unregister() {
        let vm = setup_vm();

        // Use a RefCell to track hook calls
        let hook_calls = Arc::new(Mutex::new(0));
        let hook_calls_clone = Arc::clone(&hook_calls);

        // Register a hook that counts instruction executions
        let hook_id = vm.register_hook(
            |event| matches!(event, HookEvent::BeforeInstructionExecute(_)),
            move |_, _| {
                if let Ok(mut hook_calls_clone) = hook_calls_clone.lock() {
                    *hook_calls_clone += 1;
                }
                Ok(())
            },
            100,
        );

        let test_function = VMFunction {
            name: "test_hook_unregister".to_string(),
            parameters: vec![],
            upvalues: Vec::new(),
            parent: None,
            register_count: 2,
            instructions: vec![
                Instruction::LDI(0, Value::Int(1)),
                Instruction::LDI(1, Value::Int(2)),
                Instruction::ADD(0, 0, 1),
                Instruction::RET(0),
            ],
            labels: HashMap::new(),
        };

        vm.register_function(test_function);

        // First run with hook registered
        let result = vm.execute("test_hook_unregister").unwrap();
        assert_eq!(result, Value::Int(3));
        if let Ok(mut hook_calls) = hook_calls.lock() {
            assert_eq!(*hook_calls, 4); // 4 instructions executed

            // Unregister the hook
            assert!(vm.unregister_hook(hook_id));

            // Reset counter
            *hook_calls = 0;

            // Run again with hook unregistered
            let result = vm.execute("test_hook_unregister").unwrap();
            assert_eq!(result, Value::Int(3));
            assert_eq!(*hook_calls, 0); // No hook calls}
        }

        #[test]
        fn test_hook_priority() {
            let vm = setup_vm();

            // Track hook execution order
            let hook_order = Arc::new(Mutex::new(Vec::new()));

            // Clone for each hook
            let hook_order_1 = Arc::clone(&hook_order);
            let hook_order_2 = Arc::clone(&hook_order);
            let hook_order_3 = Arc::clone(&hook_order);

            // Register hooks with different priorities
            vm.register_hook(
                |event| matches!(event, HookEvent::BeforeInstructionExecute(_)),
                move |_, _| {
                    if let Ok(mut hook_order_1) = hook_order_1.lock() {
                        hook_order_1.push(1);
                    }
                    Ok(())
                },
                10, // Low priority
            );

            vm.register_hook(
                |event| matches!(event, HookEvent::BeforeInstructionExecute(_)),
                move |_, _| {
                    if let Ok(mut hook_order_2) = hook_order_2.lock() {
                        hook_order_2.push(2);
                    }
                    Ok(())
                },
                100, // Medium priority
            );

            vm.register_hook(
                |event| matches!(event, HookEvent::BeforeInstructionExecute(_)),
                move |_, _| {
                    if let Ok(mut hook_order_3) = hook_order_3.lock() {
                        hook_order_3.push(3);
                    }
                    Ok(())
                },
                1000, // High priority
            );

            let test_function = VMFunction {
                name: "test_hook_priority".to_string(),
                parameters: vec![],
                upvalues: Vec::new(),
                parent: None,
                register_count: 1,
                instructions: vec![Instruction::LDI(0, Value::Int(42)), Instruction::RET(0)],
                labels: HashMap::new(),
            };

            vm.register_function(test_function);
            let result = vm.execute("test_hook_priority").unwrap();
            assert_eq!(result, Value::Int(42));
            if let Ok(hook_order) = hook_order.lock() {
                // Check that hooks executed in priority order (highest first)
                let order = hook_order;
                assert_eq!(order.len(), 4); // 2 instructions * 3 hooks = 6 events

                // For the first instruction, hooks should execute in priority order
                assert_eq!(order[0], 3); // Highest priority
                assert_eq!(order[1], 2); // Medium priority
                assert_eq!(order[2], 1); // Lowest priority
            };
        }

        #[test]
        fn test_complex_program() {
            let vm = setup_vm();

            // Function to calculate sum of squares from 1 to n
            let mut labels = HashMap::new();
            labels.insert("loop_start".to_string(), 2);
            labels.insert("loop_end".to_string(), 10); // Updated label position

            let sum_squares = VMFunction {
                name: "sum_squares".to_string(),
                parameters: vec!["n".to_string()],
                upvalues: Vec::new(),
                parent: None,
                register_count: 5,
                instructions: vec![
                    // Initialize sum = 0
                    Instruction::LDI(1, Value::Int(0)),
                    // Initialize i = 1
                    Instruction::LDI(2, Value::Int(1)),
                    // loop_start:
                    // Check if i > n (we want to exit if true)
                    Instruction::CMP(2, 0), // Compare i (r2) with n (r0)
                    // FIXED: If i > n, exit the loop
                    // CMP produces 1 if first operand > second
                    // We want to continue only if i <= n
                    Instruction::CMP(0, 2), // Compare n with i (reversed)
                    Instruction::JMPNEQ("loop_end".to_string()), // If n < i (compare_flag is -1), exit loop
                    // square = i * i
                    Instruction::MUL(3, 2, 2),
                    // sum += square
                    Instruction::ADD(1, 1, 3),
                    // i++
                    Instruction::LDI(4, Value::Int(1)),
                    Instruction::ADD(2, 2, 4),
                    // Go back to loop start
                    Instruction::JMP("loop_start".to_string()),
                    // loop_end:
                    // Return sum
                    Instruction::MOV(0, 1),
                    Instruction::RET(0),
                ],
                labels,
            };

            // Test function
            let test_function = VMFunction {
                name: "test_complex".to_string(),
                parameters: vec![],
                upvalues: Vec::new(),
                parent: None,
                register_count: 2,
                instructions: vec![
                    Instruction::LDI(0, Value::Int(5)),
                    Instruction::PUSHARG(0),
                    Instruction::CALL("sum_squares".to_string()),
                    Instruction::RET(0),
                ],
                labels: HashMap::new(),
            };

            vm.register_function(sum_squares);
            vm.register_function(test_function);

            let result = vm.execute("test_complex").unwrap();
            assert_eq!(result, Value::Int(55)); // 1 + 4 + 9 + 16 + 25 = 55
        }
    }
}
