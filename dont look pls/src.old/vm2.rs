use std::collections::HashMap;
use std::fmt;
use std::rc::Rc;
use std::cell::{RefCell, Ref, RefMut};
use std::any::Any;
use std::hash::Hash;

/// Represents an array in the VM
#[derive(Debug, Clone)]
struct Array {
    elements: Vec<Value>,
    extra_fields: HashMap<Value, Value>, // For non-integer or sparse indices
}

impl Array {
    fn new() -> Self {
        Array {
            elements: Vec::new(),
            extra_fields: HashMap::new(),
        }
    }

    fn with_capacity(capacity: usize) -> Self {
        Array {
            elements: Vec::with_capacity(capacity),
            extra_fields: HashMap::new(),
        }
    }

    fn get(&self, key: &Value) -> Option<&Value> {
        match key {
            Value::Int(idx) if *idx >= 1 && (*idx as usize) <= self.elements.len() => {
                // Convert from 1-based to 0-based index
                Some(&self.elements[*idx as usize - 1])
            },
            _ => self.extra_fields.get(key),
        }
    }

    fn set(&mut self, key: Value, value: Value) {
        match key {
            Value::Int(idx) if idx >= 1 => {
                let idx_usize = idx as usize - 1; // Convert to 0-based

                // If writing to next position, just push
                if idx_usize == self.elements.len() {
                    self.elements.push(value);
                    return;
                }

                // If writing within existing array, update
                if idx_usize < self.elements.len() {
                    self.elements[idx_usize] = value;
                    return;
                }

                // For small gaps, extend the array
                if idx_usize < self.elements.len() + 16 {
                    self.elements.resize(idx_usize + 1, Value::Unit);
                    self.elements[idx_usize] = value;
                    return;
                }

                // For large gaps, use sparse storage
                self.extra_fields.insert(Value::Int(idx), value);
            },
            _ => {
                // Non-integer keys go to extra fields
                self.extra_fields.insert(key, value);
            }
        }
    }

    fn length(&self) -> usize {
        self.elements.len()
    }
}

/// Represents an upvalue - a variable from an outer scope
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct Upvalue {
    name: String,
    value: Value,
}

/// Represents a closure - a function with its captured environment
#[derive(Clone, PartialEq, Eq, Hash)]
struct Closure {
    function_id: String,    // Reference to the base function
    upvalues: Vec<Upvalue>, // Captured values from outer scopes
}

/// Value types supported by the VM
#[derive(Clone, PartialEq, Eq, Hash)]
enum Value {
    Int(i64),
    Float(i64),  // Represented as fixed-point for Eq/Hash
    Bool(bool),
    String(String),
    Object(usize),    // Regular object reference
    Array(usize),     // Array reference
    Foreign(usize),   // External object reference
    Closure(Rc<Closure>), // Function closure
    Unit,
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Int(i) => write!(f, "{}", i),
            Value::Float(fp) => {
                let float_val = *fp as f64 / 1000.0;
                write!(f, "{}", float_val)
            },
            Value::Bool(b) => write!(f, "{}", b),
            Value::String(s) => write!(f, "\"{}\"", s),
            Value::Object(id) => write!(f, "Object({})", id),
            Value::Array(id) => write!(f, "Array({})", id),
            Value::Foreign(id) => write!(f, "Foreign({})", id),
            Value::Closure(c) => write!(f, "Function({})", c.function_id),
            Value::Unit => write!(f, "()"),
        }
    }
}

/// Object structure
#[derive(Debug, Clone)]
struct Object {
    fields: HashMap<Value, Value>,
}

/// Combined object/array storage
#[derive(Default)]
struct ObjectStore {
    objects: HashMap<usize, Object>,
    arrays: HashMap<usize, Array>,
    next_id: usize,
}

impl ObjectStore {
    fn new() -> Self {
        ObjectStore {
            objects: HashMap::new(),
            arrays: HashMap::new(),
            next_id: 1,
        }
    }

    fn create_object(&mut self) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        self.objects.insert(id, Object {
            fields: HashMap::new(),
        });
        id
    }

    fn create_array(&mut self) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        self.arrays.insert(id, Array::new());
        id
    }

    fn create_array_with_capacity(&mut self, capacity: usize) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        self.arrays.insert(id, Array::with_capacity(capacity));
        id
    }

    fn get_object(&self, id: usize) -> Option<&Object> {
        self.objects.get(&id)
    }

    fn get_object_mut(&mut self, id: usize) -> Option<&mut Object> {
        self.objects.get_mut(&id)
    }

    fn get_array(&self, id: usize) -> Option<&Array> {
        self.arrays.get(&id)
    }

    fn get_array_mut(&mut self, id: usize) -> Option<&mut Array> {
        self.arrays.get_mut(&id)
    }

    fn get_field(&self, value: &Value, key: &Value) -> Option<Value> {
        match value {
            Value::Object(id) => {
                self.get_object(*id).and_then(|obj| obj.fields.get(key).cloned())
            },
            Value::Array(id) => {
                self.get_array(*id).and_then(|arr| arr.get(key).cloned())
            },
            _ => None
        }
    }

    fn set_field(&mut self, value: &Value, key: Value, field_value: Value) -> Result<(), String> {
        match value {
            Value::Object(id) => {
                if let Some(obj) = self.get_object_mut(*id) {
                    obj.fields.insert(key, field_value);
                    Ok(())
                } else {
                    Err(format!("Object with ID {} not found", id))
                }
            },
            Value::Array(id) => {
                if let Some(arr) = self.get_array_mut(*id) {
                    arr.set(key, field_value);
                    Ok(())
                } else {
                    Err(format!("Array with ID {} not found", id))
                }
            },
            _ => Err("Expected object or array".to_string())
        }
    }
}

/// Enhanced operand types for move instructions
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Operand {
    Register(usize),                    // A register (r0, r1, etc.)
    Variable(String),                   // A variable from the heap
    Constant(Value),                    // An immediate value
    Field(Box<Operand>, Box<Operand>),  // Field access: object[key]
    Upvalue(String),                    // Variable from outer scope
}

// Define CallTarget to handle both register and direct function calls
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum CallTarget {
    Register(usize),
    FunctionName(String),
}

/// Instruction set for our register-based virtual machine
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Instruction {
    Move(Operand, Operand),             // Universal move: src -> dest
    Add(usize, usize, usize),           // r_dest = r_src1 + r_src2
    Sub(usize, usize, usize),           // r_dest = r_src1 - r_src2
    Mul(usize, usize, usize),           // r_dest = r_src1 * r_src2
    Div(usize, usize, usize),           // r_dest = r_src1 / r_src2
    Call(CallTarget, Vec<usize>, usize), // Call function, with params, result reg
    Return(usize),                      // Return from function with result in register r
    Jump(usize),                        // Jump to instruction index
    JumpIfZero(usize, usize),           // Jump if register is zero
    CreateObject(usize),                // Create an object, store in register
    CreateArray(usize),                 // Create an array, store in register
    ArrayLength(usize, usize),          // r_dest = length(r_array)
    CreateClosure(usize, String, Vec<String>), // Create closure in register, for function, with upvalues
}

/// VM function definition
#[derive(Clone, PartialEq, Eq, Hash)]
struct VMFunction {
    name: String,
    parameters: Vec<String>,
    upvalues: Vec<String>,          // Variables captured from outer scopes
    parent: Option<String>,         // Parent function name (for nested functions)
    register_count: usize,
    instructions: Vec<Instruction>,
}

/// Foreign (native) function type - changed to take VM by Rc<RefCell>
type ForeignFunctionPtr = dyn Fn(&mut VMState, &[Value]) -> Result<Value, String>;

/// Foreign function wrapper
struct ForeignFunction {
    name: String,
    func: Box<ForeignFunctionPtr>,
}

impl PartialEq for ForeignFunction {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for ForeignFunction {}

impl Hash for ForeignFunction {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state);
    }
}

impl Clone for ForeignFunction {
    fn clone(&self) -> Self {
        // Cloning a function pointer is impractical
        // This implementation returns a placeholder function that errors when called
        ForeignFunction {
            name: self.name.clone(),
            func: Box::new(|_, _| Err("Cloned function cannot be called".to_string()))
        }
    }
}

/// Function definition - can be either VM or foreign
#[derive(Clone, PartialEq, Eq, Hash)]
enum Function {
    VM(VMFunction),
    Foreign(ForeignFunction),
}

/// Activation record for function call
#[derive(Clone)]
struct ActivationRecord {
    function_name: String,
    locals: HashMap<String, Value>,
    registers: Vec<Value>,
    upvalues: Vec<Upvalue>,         // Captured values from outer scopes
    instruction_pointer: usize,
}

impl fmt::Debug for ActivationRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ActivationRecord {{ function: {}, ip: {}, registers: {:?}, locals: {:?}, upvalues: {:?} }}",
               self.function_name, self.instruction_pointer, self.registers, self.locals, self.upvalues)
    }
}

/// Foreign object storage
struct ForeignObjectStorage {
    objects: HashMap<usize, Rc<RefCell<Box<dyn Any>>>>,
    next_id: usize,
}

impl ForeignObjectStorage {
    fn new() -> Self {
        ForeignObjectStorage {
            objects: HashMap::new(),
            next_id: 1,
        }
    }

    fn register_object<T: 'static>(&mut self, object: T) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        self.objects.insert(id, Rc::new(RefCell::new(Box::new(object))));
        id
    }

    fn get_object<T: 'static>(&self, id: usize) -> Option<Rc<RefCell<T>>> {
        self.objects.get(&id).and_then(|obj| {
            let borrowed = obj.borrow();
            if let Some(cast) = borrowed.downcast_ref::<T>() {
                let cloned = Rc::clone(obj);
                let typed: Rc<RefCell<T>> = unsafe {
                    std::mem::transmute(cloned)
                };
                Some(typed)
            } else {
                None
            }
        })
    }
}

/// Hook event types
#[derive(Debug, Clone)]
enum HookEvent {
    BeforeInstructionExecute(Instruction),
    AfterInstructionExecute(Instruction),
    RegisterRead(usize, Value),
    RegisterWrite(usize, Value, Value),
    VariableRead(String, Value),
    VariableWrite(String, Value, Value),
    UpvalueRead(String, Value),
    UpvalueWrite(String, Value, Value),
    ObjectFieldRead(usize, Value, Value),
    ObjectFieldWrite(usize, Value, Value, Value),
    ArrayElementRead(usize, Value, Value),
    ArrayElementWrite(usize, Value, Value, Value),
    BeforeFunctionCall(Value, Vec<Value>),
    AfterFunctionCall(Value, Value),
    ClosureCreated(String, Vec<Upvalue>),
}

/// Hook predicate that determines if a hook should fire
type HookPredicate = dyn Fn(&HookEvent) -> bool;

/// Hook callback that executes when a hook is triggered
type HookCallback = dyn Fn(&HookEvent) -> Result<(), String>;

/// A hook registered with the VM
struct Hook {
    id: usize,
    predicate: Box<HookPredicate>,
    callback: Box<HookCallback>,
    enabled: bool,
    priority: i32,
}

/// Hook manager to handle hook registration and triggering
struct HookManager {
    hooks: Vec<Hook>,
    next_hook_id: usize,
}

impl HookManager {
    fn new() -> Self {
        HookManager {
            hooks: Vec::new(),
            next_hook_id: 1,
        }
    }

    fn register_hook(
        &mut self,
        predicate: Box<HookPredicate>,
        callback: Box<HookCallback>,
        priority: i32,
    ) -> usize {
        let id = self.next_hook_id;
        self.next_hook_id += 1;

        self.hooks.push(Hook {
            id,
            predicate,
            callback,
            enabled: true,
            priority,
        });

        // Sort hooks by priority
        self.hooks.sort_by(|a, b| b.priority.cmp(&a.priority));

        id
    }

    fn unregister_hook(&mut self, hook_id: usize) -> bool {
        let len = self.hooks.len();
        self.hooks.retain(|hook| hook.id != hook_id);
        len != self.hooks.len()
    }

    fn enable_hook(&mut self, hook_id: usize) -> bool {
        if let Some(hook) = self.hooks.iter_mut().find(|h| h.id == hook_id) {
            hook.enabled = true;
            return true;
        }
        false
    }

    fn disable_hook(&mut self, hook_id: usize) -> bool {
        if let Some(hook) = self.hooks.iter_mut().find(|h| h.id == hook_id) {
            hook.enabled = false;
            return true;
        }
        false
    }

    fn trigger(&self, event: &HookEvent) -> Result<(), String> {
        // Find enabled hooks that match the predicate
        let matching_hooks: Vec<_> = self.hooks.iter()
            .filter(|hook| hook.enabled && (hook.predicate)(event))
            .collect();

        // Execute callbacks
        for hook in matching_hooks {
            (hook.callback)(event)?;
        }

        Ok(())
    }
}

// VM internal state to be wrapped in RefCell
struct VMState {
    functions: HashMap<String, Function>,
    activation_records: Vec<ActivationRecord>,
    current_instruction: usize,
    object_store: ObjectStore,
    foreign_objects: ForeignObjectStorage,
    hook_manager: HookManager,
}

/// The register-based virtual machine with RefCell for internal state
struct VirtualMachine {
    state: RefCell<VMState>,
}

impl VirtualMachine {
    fn new() -> Self {
        let mut vm_state = VMState {
            functions: HashMap::new(),
            activation_records: Vec::new(),
            current_instruction: 0,
            object_store: ObjectStore::new(),
            foreign_objects: ForeignObjectStorage::new(),
            hook_manager: HookManager::new(),
        };

        // Create VM
        let vm = VirtualMachine {
            state: RefCell::new(vm_state),
        };

        // Register standard library functions
        vm.register_standard_library();

        vm
    }

    fn register_standard_library(&self) {
        // Register basic array functions
        self.register_foreign_function("array_push", |vm_state, args| {
            if args.len() < 2 {
                return Err("array_push expects at least 2 arguments: array and value".to_string());
            }

            match &args[0] {
                Value::Array(id) => {
                    if let Some(arr) = vm_state.object_store.get_array_mut(*id) {
                        let idx = Value::Int((arr.length() + 1) as i64);
                        for value in &args[1..] {
                            arr.set(idx.clone(), value.clone());
                        }
                        Ok(Value::Int(arr.length() as i64))
                    } else {
                        Err(format!("Array with ID {} not found", id))
                    }
                },
                _ => Err("First argument must be an array".to_string())
            }
        });

        // print function
        self.register_foreign_function("print", |_vm_state, args| {
            let mut output = String::new();
            for (i, arg) in args.iter().enumerate() {
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

        // type function - returns the type of a value as a string
        self.register_foreign_function("type", |_vm_state, args| {
            if args.len() != 1 {
                return Err("type expects 1 argument".to_string());
            }

            let type_name = match &args[0] {
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
    fn register_function(&self, function: VMFunction) {
        let mut state = self.state.borrow_mut();
        state.functions.insert(function.name.clone(), Function::VM(function));
    }

    // Register a foreign function
    fn register_foreign_function<F>(&self, name: &str, func: F)
    where
        F: Fn(&mut VMState, &[Value]) -> Result<Value, String> + 'static
    {
        let mut state = self.state.borrow_mut();
        state.functions.insert(
            name.to_string(),
            Function::Foreign(ForeignFunction {
                name: name.to_string(),
                func: Box::new(func)
            })
        );
    }

    // Register a foreign object
    fn register_foreign_object<T: 'static>(&self, object: T) -> Value {
        let mut state = self.state.borrow_mut();
        let id = state.foreign_objects.register_object(object);
        Value::Foreign(id)
    }

    // Get a foreign object by ID
    fn get_foreign_object<T: 'static>(&self, id: usize) -> Option<Rc<RefCell<T>>> {
        let state = self.state.borrow();
        state.foreign_objects.get_object(id)
    }

    // --- HOOK SYSTEM ---

    // Register a hook with the VM
    fn register_hook<P, C>(&self, predicate: P, callback: C, priority: i32) -> usize
    where
        P: Fn(&HookEvent) -> bool + 'static,
        C: Fn(&HookEvent) -> Result<(), String> + 'static
    {
        let mut state = self.state.borrow_mut();
        state.hook_manager.register_hook(Box::new(predicate), Box::new(callback), priority)
    }

    // Unregister a hook
    fn unregister_hook(&self, hook_id: usize) -> bool {
        let mut state = self.state.borrow_mut();
        state.hook_manager.unregister_hook(hook_id)
    }

    // Enable a hook
    fn enable_hook(&self, hook_id: usize) -> bool {
        let mut state = self.state.borrow_mut();
        state.hook_manager.enable_hook(hook_id)
    }

    // Disable a hook
    fn disable_hook(&self, hook_id: usize) -> bool {
        let mut state = self.state.borrow_mut();
        state.hook_manager.disable_hook(hook_id)
    }

    // Execute the VM with a given main function
    fn execute(&self, main_function: &str) -> Result<Value, String> {
        // Get the function
        let vm_func = {
            let state = self.state.borrow();
            match state.functions.get(main_function) {
                Some(Function::VM(func)) => func.clone(),
                Some(Function::Foreign(_)) => {
                    return Err(format!("Cannot execute foreign function {} as main", main_function));
                }
                None => return Err(format!("Function {} not found", main_function)),
            }
        };

        // Initialize registers with default values
        let registers = vec![Value::Unit; vm_func.register_count];

        // Setup initial activation record
        {
            let mut state = self.state.borrow_mut();
            let initial_record = ActivationRecord {
                function_name: main_function.to_string(),
                locals: HashMap::new(),
                registers,
                upvalues: Vec::new(),
                instruction_pointer: 0,
            };

            state.activation_records.push(initial_record);
        }

        // Execute until we get a return from the main function
        self.execute_until_return()
    }

    // Execute the VM until a return instruction is encountered
    fn execute_until_return(&self) -> Result<Value, String> {
        loop {
            // Get current function and instruction pointer
            let (function_name, ip, activation_records_len) = {
                let state = self.state.borrow();
                let current_record = state.activation_records.last().unwrap();
                (
                    current_record.function_name.clone(),
                    current_record.instruction_pointer,
                    state.activation_records.len()
                )
            };

            // Get the function
            let vm_function = {
                let state = self.state.borrow();
                match state.functions.get(&function_name) {
                    Some(Function::VM(vm_func)) => vm_func.clone(),
                    Some(Function::Foreign(_)) => {
                        return Err(format!("Cannot execute foreign function {}", function_name));
                    }
                    None => return Err(format!("Function {} not found", function_name)),
                }
            };

            // Exit if we've reached the end of the function
            if ip >= vm_function.instructions.len() {
                if activation_records_len == 1 {
                    // End of function, return register 0 (convention)
                    let state = self.state.borrow();
                    return Ok(state.activation_records[0].registers[0].clone());
                } else {
                    // Pop activation record and continue in caller
                    let mut state = self.state.borrow_mut();
                    let result = state.activation_records.last().unwrap().registers[0].clone();
                    state.activation_records.pop();
                    if state.activation_records.is_empty() {
                        return Ok(result);
                    }
                    continue;
                }
            }

            // Get the current instruction
            let instruction = vm_function.instructions[ip].clone();

            // Increment the instruction pointer for next cycle (may be overridden)
            {
                let mut state = self.state.borrow_mut();
                state.current_instruction = ip;
                state.activation_records.last_mut().unwrap().instruction_pointer += 1;

                // Trigger before instruction hook
                let event = HookEvent::BeforeInstructionExecute(instruction.clone());
                state.hook_manager.trigger(&event)?;
            }

            // Execute the instruction
            match instruction.clone() {
                Instruction::Move(dest, src) => {
                    let value = self.read_operand(&src)?;
                    self.write_operand(&dest, value)?;
                },
                Instruction::Add(dest, src1, src2) => {
                    // Get values safely
                    let (a, b) = {
                        let state = self.state.borrow();
                        let current_record = state.activation_records.last().unwrap();
                        match (&current_record.registers[src1], &current_record.registers[src2]) {
                            (Value::Int(a), Value::Int(b)) => (*a, *b),
                            _ => return Err("Type error in addition".to_string()),
                        }
                    };

                    // Perform operation and update register
                    {
                        let mut state = self.state.borrow_mut();
                        let current_record = state.activation_records.last_mut().unwrap();
                        let result_value = Value::Int(a + b);
                        let old_value = current_record.registers[dest].clone();
                        current_record.registers[dest] = result_value.clone();

                        // Trigger hook
                        let event = HookEvent::RegisterWrite(dest, old_value, result_value);
                        state.hook_manager.trigger(&event)?;
                    }
                },
                Instruction::Sub(dest, src1, src2) => {
                    // Get values safely
                    let (a, b) = {
                        let state = self.state.borrow();
                        let current_record = state.activation_records.last().unwrap();
                        match (&current_record.registers[src1], &current_record.registers[src2]) {
                            (Value::Int(a), Value::Int(b)) => (*a, *b),
                            _ => return Err("Type error in subtraction".to_string()),
                        }
                    };

                    // Perform operation and update register
                    {
                        let mut state = self.state.borrow_mut();
                        let current_record = state.activation_records.last_mut().unwrap();
                        let result_value = Value::Int(a - b);
                        let old_value = current_record.registers[dest].clone();
                        current_record.registers[dest] = result_value.clone();

                        // Trigger hook
                        let event = HookEvent::RegisterWrite(dest, old_value, result_value);
                        state.hook_manager.trigger(&event)?;
                    }
                },
                Instruction::Mul(dest, src1, src2) => {
                    // Get values safely
                    let (a, b) = {
                        let state = self.state.borrow();
                        let current_record = state.activation_records.last().unwrap();
                        match (&current_record.registers[src1], &current_record.registers[src2]) {
                            (Value::Int(a), Value::Int(b)) => (*a, *b),
                            _ => return Err("Type error in multiplication".to_string()),
                        }
                    };

                    // Perform operation and update register
                    {
                        let mut state = self.state.borrow_mut();
                        let current_record = state.activation_records.last_mut().unwrap();
                        let result_value = Value::Int(a * b);
                        let old_value = current_record.registers[dest].clone();
                        current_record.registers[dest] = result_value.clone();

                        // Trigger hook
                        let event = HookEvent::RegisterWrite(dest, old_value, result_value);
                        state.hook_manager.trigger(&event)?;
                    }
                },
                Instruction::Div(dest, src1, src2) => {
                    // Get values safely
                    let (a, b) = {
                        let state = self.state.borrow();
                        let current_record = state.activation_records.last().unwrap();
                        match (&current_record.registers[src1], &current_record.registers[src2]) {
                            (Value::Int(a), Value::Int(b)) => {
                                if *b == 0 {
                                    return Err("Division by zero".to_string());
                                }
                                (*a, *b)
                            },
                            _ => return Err("Type error in division".to_string()),
                        }
                    };

                    // Perform operation and update register
                    {
                        let mut state = self.state.borrow_mut();
                        let current_record = state.activation_records.last_mut().unwrap();
                        let result_value = Value::Int(a / b);
                        let old_value = current_record.registers[dest].clone();
                        current_record.registers[dest] = result_value.clone();

                        // Trigger hook
                        let event = HookEvent::RegisterWrite(dest, old_value, result_value);
                        state.hook_manager.trigger(&event)?;
                    }
                },
                Instruction::CreateObject(dest_reg) => {
                    let mut state = self.state.borrow_mut();
                    // Create a new object
                    let obj_id = state.object_store.create_object();

                    // Store the object reference in the destination register
                    let current_record = state.activation_records.last_mut().unwrap();
                    let old_value = current_record.registers[dest_reg].clone();
                    let new_value = Value::Object(obj_id);
                    current_record.registers[dest_reg] = new_value.clone();

                    // Trigger register write hook
                    let event = HookEvent::RegisterWrite(dest_reg, old_value, new_value);
                    state.hook_manager.trigger(&event)?;
                },
                Instruction::CreateArray(dest_reg) => {
                    let mut state = self.state.borrow_mut();
                    // Create a new array
                    let arr_id = state.object_store.create_array();

                    // Store the array reference in the destination register
                    let current_record = state.activation_records.last_mut().unwrap();
                    let old_value = current_record.registers[dest_reg].clone();
                    let new_value = Value::Array(arr_id);
                    current_record.registers[dest_reg] = new_value.clone();

                    // Trigger register write hook
                    let event = HookEvent::RegisterWrite(dest_reg, old_value, new_value);
                    state.hook_manager.trigger(&event)?;
                },
                Instruction::ArrayLength(dest_reg, array_reg) => {
                    // Get array and calculate length
                    let length = {
                        let state = self.state.borrow();
                        let current_record = state.activation_records.last().unwrap();

                        match &current_record.registers[array_reg] {
                            Value::Array(id) => {
                                if let Some(arr) = state.object_store.get_array(*id) {
                                    // Get the array length
                                    arr.length()
                                } else {
                                    return Err(format!("Array with ID {} not found", id));
                                }
                            },
                            _ => return Err("Expected array for length operation".to_string()),
                        }
                    };

                    // Update destination register
                    {
                        let mut state = self.state.borrow_mut();
                        let current_record = state.activation_records.last_mut().unwrap();

                        // Store in destination register
                        let old_value = current_record.registers[dest_reg].clone();
                        let new_value = Value::Int(length as i64);
                        current_record.registers[dest_reg] = new_value.clone();

                        // Trigger register write hook
                        let event = HookEvent::RegisterWrite(dest_reg, old_value, new_value);
                        state.hook_manager.trigger(&event)?;
                    }
                },
                Instruction::CreateClosure(dest_reg, function_name, upvalue_names) => {
                    // Create a closure with captured upvalues
                    let closure_value = self.create_closure(&function_name, &upvalue_names)?;

                    // Store the closure in the destination register
                    let mut state = self.state.borrow_mut();
                    let current_record = state.activation_records.last_mut().unwrap();
                    let old_value = current_record.registers[dest_reg].clone();
                    current_record.registers[dest_reg] = closure_value.clone();

                    // Trigger register write hook
                    let event = HookEvent::RegisterWrite(dest_reg, old_value, closure_value);
                    state.hook_manager.trigger(&event)?;
                },
                Instruction::Call(target, param_regs, result_reg) => {
                    // Get the function value and args
                    let (func_value, args) = {
                        let state = self.state.borrow();
                        let current_record = state.activation_records.last().unwrap();

                        // Get the function value based on the target
                        let func_value = match &target {
                            CallTarget::Register(reg) => {
                                current_record.registers[*reg].clone()
                            },
                            CallTarget::FunctionName(name) => {
                                // Check if the function exists
                                if !state.functions.contains_key(name) {
                                    return Err(format!("Function '{}' not found", name));
                                }

                                // For foreign functions, return a placeholder value
                                if let Some(Function::Foreign(_)) = state.functions.get(name) {
                                    Value::String(format!("<foreign function {}>", name))
                                } else {
                                    // Create a temporary closure for the function
                                    let closure = Closure {
                                        function_id: name.clone(),
                                        upvalues: Vec::new(),
                                    };
                                    Value::Closure(Rc::new(closure))
                                }
                            }
                        };

                        // Prepare arguments
                        let mut args = Vec::new();
                        for &reg in &param_regs {
                            args.push(current_record.registers[reg].clone());
                        }

                        (func_value, args)
                    };

                    match func_value {
                        Value::Closure(closure) => {
                            // Check if this is a tail call that can be optimized
                            let (is_tail, is_recursive, vm_func) = {
                                let state = self.state.borrow();
                                let function_id = &closure.function_id;
                                let is_tail = self.is_tail_position(&function_name, ip);
                                let is_recursive = self.is_recursive_call(&function_name, function_id);

                                let vm_func = match state.functions.get(function_id) {
                                    Some(Function::VM(func)) => Some(func.clone()),
                                    _ => None,
                                };

                                (is_tail, is_recursive, vm_func)
                            };

                            if is_tail && is_recursive && vm_func.is_some() {
                                // This is a tail-recursive call - optimize it
                                let vm_func = vm_func.unwrap();

                                // Check parameter count
                                if vm_func.parameters.len() != param_regs.len() {
                                    return Err(format!("Function {} expects {} arguments but got {}",
                                                       closure.function_id, vm_func.parameters.len(), param_regs.len()));
                                }

                                // Update activation record for tail call
                                {
                                    let mut state = self.state.borrow_mut();
                                    let record = state.activation_records.last_mut().unwrap();

                                    // Create a new temporary HashMap for locals
                                    let mut new_locals = HashMap::new();

                                    // Copy special result register info if available
                                    if let Some(result_reg_entry) = record.locals.iter()
                                        .find(|(k, _)| k.starts_with("__result_reg_"))
                                        .map(|(k, v)| (k.clone(), v.clone())) {
                                        new_locals.insert(result_reg_entry.0, result_reg_entry.1);
                                    }

                                    // Build parameter map using values from current registers
                                    for (i, &reg) in param_regs.iter().enumerate() {
                                        let param_name = &vm_func.parameters[i];
                                        let arg_value = record.registers[reg].clone();
                                        new_locals.insert(param_name.clone(), arg_value);
                                    }

                                    // Update the activation record
                                    record.locals = new_locals;
                                    record.upvalues = closure.upvalues.clone();
                                    record.instruction_pointer = 0;
                                }

                                // No need to process further - we've reset the instruction pointer
                                continue;
                            } else {
                                // Regular function call using the closure
                                self.call_closure(Rc::clone(&closure), args, result_reg)?;
                            }
                        },
                        Value::String(name) if name.starts_with("<foreign function ") => {
                            // Extract function name
                            let name = name.trim_start_matches("<foreign function ")
                                .trim_end_matches(">");

                            // Call foreign function
                            let result = self.call_vm_function(name, args)?;

                            // Store result
                            let mut state = self.state.borrow_mut();
                            let current_record = state.activation_records.last_mut().unwrap();
                            let old_value = current_record.registers[result_reg].clone();
                            current_record.registers[result_reg] = result.clone();

                            // Trigger register write hook
                            let event = HookEvent::RegisterWrite(result_reg, old_value, result);
                            state.hook_manager.trigger(&event)?;
                        },
                        _ => return Err(format!("Cannot call non-function value: {:?}", func_value)),
                    }
                },
                Instruction::Return(reg) => {
                    // Get return value and setup for return
                    let (return_value, returning_from, activation_records_len) = {
                        let state = self.state.borrow();
                        let current_record = state.activation_records.last().unwrap();
                        (
                            current_record.registers[reg].clone(),
                            current_record.function_name.clone(),
                            state.activation_records.len()
                        )
                    };

                    if activation_records_len <= 1 {
                        // We're in the outermost function, return the value
                        let mut state = self.state.borrow_mut();

                        // Trigger after instruction hook before returning
                        let event = HookEvent::AfterInstructionExecute(instruction.clone());
                        state.hook_manager.trigger(&event)?;

                        return Ok(return_value);
                    }

                    // Return to caller
                    let result_reg: Option<i64> = {
                        let mut state = self.state.borrow_mut();

                        // Pop the current activation record
                        state.activation_records.pop();

                        // Get the result register from the caller's activation record
                        let result_reg_key = format!("__result_reg_{}", returning_from);
                        if let Some(Value::Int(result_reg)) = state.activation_records.last().unwrap()
                            .locals.get(&result_reg_key) {
                            Some(*result_reg)
                        } else {
                            None
                        }
                    };

                    // Store return value if needed
                    if let Some(result_reg) = result_reg {
                        let mut state = self.state.borrow_mut();
                        let current_record = state.activation_records.last_mut().unwrap();

                        // Store return value in the result register
                        let old_value = current_record.registers[result_reg as usize].clone();
                        current_record.registers[result_reg as usize] = return_value.clone();

                        // Trigger register write hook
                        let event = HookEvent::RegisterWrite(result_reg as usize, old_value, return_value.clone());
                        state.hook_manager.trigger(&event)?;

                        // Create a closure value for the hook
                        let closure_value = Value::String(format!("<function {}>", returning_from));

                        // Trigger after function call hook
                        let event = HookEvent::AfterFunctionCall(closure_value, return_value);
                        state.hook_manager.trigger(&event)?;
                    }
                },
                Instruction::Jump(target) => {
                    let mut state = self.state.borrow_mut();
                    state.activation_records.last_mut().unwrap().instruction_pointer = target;
                },
                Instruction::JumpIfZero(reg, target) => {
                    let should_jump = {
                        let state = self.state.borrow();
                        let current_record = state.activation_records.last().unwrap();
                        match &current_record.registers[reg] {
                            Value::Int(0) | Value::Bool(false) => true,
                            _ => false,
                        }
                    };

                    if should_jump {
                        let mut state = self.state.borrow_mut();
                        state.activation_records.last_mut().unwrap().instruction_pointer = target;
                    }
                },
            }

            // Trigger after instruction hook
            {
                let mut state = self.state.borrow_mut();
                let event = HookEvent::AfterInstructionExecute(instruction.clone());
                state.hook_manager.trigger(&event)?;
            }
        }
    }

    // Helper methods to avoid borrow issues

    // Check if instruction is in tail position
    fn is_tail_position(&self, function_name: &str, instruction_index: usize) -> bool {
        let state = self.state.borrow();
        if let Some(Function::VM(function)) = state.functions.get(function_name) {
            // Direct tail position: last instruction in the function
            if instruction_index == function.instructions.len() - 1 {
                return true;
            }

            // Check if it's followed only by a return
            if instruction_index + 1 < function.instructions.len() {
                match &function.instructions[instruction_index + 1] {
                    Instruction::Return(_) => return true,
                    _ => {}
                }
            }
        }
        false
    }

    // Check if call is recursive
    fn is_recursive_call(&self, caller: &str, callee: &str) -> bool {
        caller == callee
    }

    // Find upvalue in the current scope chain
    fn find_upvalue(&self, name: &str) -> Option<Value> {
        let state = self.state.borrow();
        // Search from the innermost scope outward
        for record in state.activation_records.iter().rev() {
            // Check locals first
            if let Some(value) = record.locals.get(name) {
                return Some(value.clone());
            }

            // Then check upvalues
            for upvalue in &record.upvalues {
                if upvalue.name == name {
                    return Some(upvalue.value.clone());
                }
            }
        }
        None
    }

    // Read a value from an operand
    fn read_operand(&self, operand: &Operand) -> Result<Value, String> {
        match operand {
            Operand::Register(reg) => {
                let value = {
                    let state = self.state.borrow();
                    state.activation_records.last().unwrap().registers[*reg].clone()
                };

                // Trigger register read hook
                {
                    let mut state = self.state.borrow_mut();
                    let event = HookEvent::RegisterRead(*reg, value.clone());
                    state.hook_manager.trigger(&event)?;
                }

                Ok(value)
            },
            Operand::Variable(name) => {
                let value = {
                    let state = self.state.borrow();
                    state.activation_records.last().unwrap().locals.get(name)
                        .ok_or_else(|| format!("Variable {} not found", name))?
                        .clone()
                };

                // Trigger variable read hook
                {
                    let mut state = self.state.borrow_mut();
                    let event = HookEvent::VariableRead(name.clone(), value.clone());
                    state.hook_manager.trigger(&event)?;
                }

                Ok(value)
            },
            Operand::Upvalue(name) => {
                // Find the upvalue in the current scope
                let value = {
                    let state = self.state.borrow();
                    let record = state.activation_records.last().unwrap();
                    record.upvalues.iter()
                        .find(|uv| uv.name == *name)
                        .map(|uv| uv.value.clone())
                        .ok_or_else(|| format!("Upvalue {} not found", name))?
                };

                // Trigger upvalue read hook
                {
                    let mut state = self.state.borrow_mut();
                    let event = HookEvent::UpvalueRead(name.clone(), value.clone());
                    state.hook_manager.trigger(&event)?;
                }

                Ok(value)
            },
            Operand::Constant(value) => {
                Ok(value.clone())
            },
            Operand::Field(obj_operand, key_operand) => {
                // Evaluate the object/array operand
                let container = self.read_operand(obj_operand)?;

                // Evaluate the key operand
                let key = self.read_operand(key_operand)?;

                match &container {
                    Value::Object(id) => {
                        let (obj_id, value) = {
                            let state = self.state.borrow();
                            if let Some(obj) = state.object_store.get_object(*id) {
                                (*id, obj.fields.get(&key).cloned().unwrap_or(Value::Unit))
                            } else {
                                return Err(format!("Object with ID {} not found", id));
                            }
                        };

                        // Trigger object field read hook
                        {
                            let mut state = self.state.borrow_mut();
                            let event = HookEvent::ObjectFieldRead(obj_id, key.clone(), value.clone());
                            state.hook_manager.trigger(&event)?;
                        }

                        Ok(value)
                    },
                    Value::Array(id) => {
                        let (arr_id, value) = {
                            let state = self.state.borrow();
                            if let Some(arr) = state.object_store.get_array(*id) {
                                (*id, arr.get(&key).cloned().unwrap_or(Value::Unit))
                            } else {
                                return Err(format!("Array with ID {} not found", id));
                            }
                        };

                        // Trigger array element read hook
                        {
                            let mut state = self.state.borrow_mut();
                            let event = HookEvent::ArrayElementRead(arr_id, key.clone(), value.clone());
                            state.hook_manager.trigger(&event)?;
                        }

                        Ok(value)
                    },
                    _ => Err("Expected object or array for field access".to_string()),
                }
            }
        }
    }

    // Write a value to an operand
    fn write_operand(&self, operand: &Operand, value: Value) -> Result<(), String> {
        match operand {
            Operand::Register(reg) => {
                let old_value = {
                    let state = self.state.borrow();
                    let record = state.activation_records.last().unwrap();
                    if *reg < record.registers.len() {
                        record.registers[*reg].clone()
                    } else {
                        return Err(format!("Register r{} out of bounds", reg));
                    }
                };

                // Update register and trigger hook
                {
                    let mut state = self.state.borrow_mut();
                    state.activation_records.last_mut().unwrap().registers[*reg] = value.clone();

                    // Trigger register write hook
                    let event = HookEvent::RegisterWrite(*reg, old_value, value);
                    state.hook_manager.trigger(&event)?;
                }

                Ok(())
            },
            Operand::Variable(name) => {
                let old_value = {
                    let state = self.state.borrow();
                    state.activation_records.last().unwrap().locals.get(name)
                        .cloned().unwrap_or(Value::Unit)
                };

                // Update variable and trigger hook
                {
                    let mut state = self.state.borrow_mut();
                    state.activation_records.last_mut().unwrap().locals.insert(name.clone(), value.clone());

                    // Trigger variable write hook
                    let event = HookEvent::VariableWrite(name.clone(), old_value, value);
                    state.hook_manager.trigger(&event)?;
                }

                Ok(())
            },
            Operand::Upvalue(name) => {
                // Find the upvalue in the current activation record
                let upvalue_index_opt = {
                    let state = self.state.borrow();
                    let record = state.activation_records.last().unwrap();
                    record.upvalues.iter().position(|uv| uv.name == *name)
                };

                if let Some(index) = upvalue_index_opt {
                    // Get old value and update
                    let old_value = {
                        let state = self.state.borrow();
                        state.activation_records.last().unwrap().upvalues[index].value.clone()
                    };

                    {
                        let mut state = self.state.borrow_mut();
                        state.activation_records.last_mut().unwrap().upvalues[index].value = value.clone();

                        // Trigger upvalue write hook
                        let event = HookEvent::UpvalueWrite(name.clone(), old_value, value);
                        state.hook_manager.trigger(&event)?;
                    }

                    Ok(())
                } else {
                    Err(format!("Upvalue {} not found for writing", name))
                }
            },
            Operand::Constant(_) => {
                Err("Cannot write to a constant".to_string())
            },
            Operand::Field(obj_operand, key_operand) => {
                // Evaluate the object/array operand
                let container = self.read_operand(obj_operand)?;

                // Evaluate the key operand
                let key = self.read_operand(key_operand)?;

                match &container {
                    Value::Object(id) => {
                        let (obj_id, old_value) = {
                            let state = self.state.borrow();
                            if let Some(obj) = state.object_store.get_object(*id) {
                                (*id, obj.fields.get(&key).cloned().unwrap_or(Value::Unit))
                            } else {
                                return Err(format!("Object with ID {} not found", id));
                            }
                        };

                        // Update object field
                        {
                            let mut state = self.state.borrow_mut();
                            if let Some(obj) = state.object_store.get_object_mut(obj_id) {
                                obj.fields.insert(key.clone(), value.clone());

                                // Trigger object field write hook
                                let event = HookEvent::ObjectFieldWrite(obj_id, key, old_value, value);
                                state.hook_manager.trigger(&event)?;

                                Ok(())
                            } else {
                                Err(format!("Object with ID {} not found during update", obj_id))
                            }
                        }
                    },
                    Value::Array(id) => {
                        let (arr_id, old_value) = {
                            let state = self.state.borrow();
                            if let Some(arr) = state.object_store.get_array(*id) {
                                (*id, arr.get(&key).cloned().unwrap_or(Value::Unit))
                            } else {
                                return Err(format!("Array with ID {} not found", id));
                            }
                        };

                        // Update array element
                        {
                            let mut state = self.state.borrow_mut();
                            if let Some(arr) = state.object_store.get_array_mut(arr_id) {
                                arr.set(key.clone(), value.clone());

                                // Trigger array element write hook
                                let event = HookEvent::ArrayElementWrite(arr_id, key, old_value, value);
                                state.hook_manager.trigger(&event)?;

                                Ok(())
                            } else {
                                Err(format!("Array with ID {} not found during update", arr_id))
                            }
                        }
                    },
                    _ => Err("Expected object or array for field access".to_string()),
                }
            }
        }
    }

    // Create a closure from a function and upvalues
    fn create_closure(&self, function_name: &str, upvalue_names: &[String]) -> Result<Value, String> {
        // Capture upvalues from the current environment
        let mut upvalues = Vec::new();
        for name in upvalue_names {
            let value = self.find_upvalue(name)
                .ok_or_else(|| format!("Could not find upvalue {} when creating closure", name))?;

            upvalues.push(Upvalue {
                name: name.clone(),
                value: value.clone(),
            });
        }

        // Create the closure
        let closure = Closure {
            function_id: function_name.to_string(),
            upvalues: upvalues.clone(),
        };

        // Trigger closure created hook
        {
            let mut state = self.state.borrow_mut();
            let event = HookEvent::ClosureCreated(function_name.to_string(), upvalues);
            state.hook_manager.trigger(&event)?;
        }

        Ok(Value::Closure(Rc::new(closure)))
    }

    // Call a function from a closure
    fn call_closure(&self, closure: Rc<Closure>, args: Vec<Value>, result_reg: usize) -> Result<(), String> {
        let function_name = closure.function_id.clone();

        // Get the function
        let vm_func = {
            let state = self.state.borrow();
            match state.functions.get(&function_name) {
                Some(Function::VM(func)) => func.clone(),
                Some(Function::Foreign(_)) => {
                    return Err(format!("Cannot create closure for foreign function {}", function_name));
                }
                None => return Err(format!("Function {} not found", function_name)),
            }
        };

        // Check parameter count
        if vm_func.parameters.len() != args.len() {
            return Err(format!("Function {} expects {} arguments but got {}",
                               function_name, vm_func.parameters.len(), args.len()));
        }

        // Create a new activation record and setup for call
        {
            let mut state = self.state.borrow_mut();

            // Trigger before function call hook
            let event = HookEvent::BeforeFunctionCall(Value::Closure(Rc::clone(&closure)), args.clone());
            state.hook_manager.trigger(&event)?;

            // Create a new activation record for the function call
            let mut new_record = ActivationRecord {
                function_name: function_name.clone(),
                locals: HashMap::new(),
                registers: vec![Value::Unit; vm_func.register_count],
                upvalues: closure.upvalues.clone(),
                instruction_pointer: 0,
            };

            // Set up parameters
            for (i, param_name) in vm_func.parameters.iter().enumerate() {
                new_record.locals.insert(param_name.clone(), args[i].clone());
            }

            // Store the result register in the calling record
            let calling_record_idx = state.activation_records.len() - 1;

            // Push the new activation record
            state.activation_records.push(new_record);

            // Set up for return
            state.activation_records[calling_record_idx].locals.insert(
                format!("__result_reg_{}", function_name),
                Value::Int(result_reg as i64)
            );
        }

        Ok(())
    }

    // Call a VM function from Rust
    pub fn call_vm_function(&self, name: &str, args: Vec<Value>) -> Result<Value, String> {
        // Find the function
        let function = {
            let state = self.state.borrow();
            state.functions.get(name).cloned().ok_or_else(||
                format!("Function {} not found", name))?
        };

        match function {
            Function::VM(vm_func) => {
                // Check parameter count
                if vm_func.parameters.len() != args.len() {
                    return Err(format!("Function {} expects {} arguments but got {}",
                                       name, vm_func.parameters.len(), args.len()));
                }

                // Setup for call
                {
                    let mut state = self.state.borrow_mut();

                    // Create a closure with no upvalues
                    let closure = Closure {
                        function_id: name.to_string(),
                        upvalues: Vec::new(),
                    };

                    let closure_value = Value::Closure(Rc::new(closure));

                    // Trigger before function call hook
                    let event = HookEvent::BeforeFunctionCall(closure_value.clone(), args.clone());
                    state.hook_manager.trigger(&event)?;

                    // Create new activation record
                    let mut new_record = ActivationRecord {
                        function_name: name.to_string(),
                        locals: HashMap::new(),
                        registers: vec![Value::Unit; vm_func.register_count],
                        upvalues: Vec::new(),
                        instruction_pointer: 0,
                    };

                    // Set up parameters
                    for (i, param_name) in vm_func.parameters.iter().enumerate() {
                        new_record.locals.insert(param_name.clone(), args[i].clone());
                    }

                    // Save current execution state
                    let saved_records = std::mem::take(&mut state.activation_records);

                    // Push the new activation record
                    state.activation_records.push(new_record);
                }

                // Execute the function
                let result = self.execute_until_return()?;

                // Restore original state and trigger hook
                {
                    let mut state = self.state.borrow_mut();

                    // Create a closure with no upvalues for the hook
                    let closure = Closure {
                        function_id: name.to_string(),
                        upvalues: Vec::new(),
                    };
                    let closure_value = Value::Closure(Rc::new(closure));

                    // Trigger after function call hook
                    let event = HookEvent::AfterFunctionCall(closure_value, result.clone());
                    state.hook_manager.trigger(&event)?;
                }

                Ok(result)
            },
            Function::Foreign(foreign_func) => {
                // Create a fake function value for the hook
                let func_value = Value::String(format!("<foreign function {}>", name));

                // Trigger before function call hook
                {
                    let mut state = self.state.borrow_mut();
                    let event = HookEvent::BeforeFunctionCall(func_value.clone(), args.clone());
                    state.hook_manager.trigger(&event)?;
                }

                // Call the foreign function directly with mutable state
                let result = {
                    let mut state = self.state.borrow_mut();
                    (foreign_func.func)(&mut state, &args)?
                };

                // Trigger after function call hook
                {
                    let mut state = self.state.borrow_mut();
                    let event = HookEvent::AfterFunctionCall(func_value, result.clone());
                    state.hook_manager.trigger(&event)?;
                }

                Ok(result)
            }
        }
    }
}

fn main() {
    // Example program demonstrating nested functions with closures
    let vm = VirtualMachine::new();

    // Define a function that returns a counter function
    // This shows lexical scoping and closures
    let create_counter = VMFunction {
        name: "create_counter".to_string(),
        parameters: vec!["start".to_string()],
        upvalues: Vec::new(),
        parent: None,
        register_count: 3,
        instructions: vec![
            // Load the starting value
            Instruction::Move(Operand::Register(0), Operand::Variable("start".to_string())),

            // Create the increment closure, capturing 'start'
            Instruction::CreateClosure(1, "increment".to_string(), vec!["start".to_string()]),

            // Return the function
            Instruction::Return(1),
        ],
    };

    // The nested increment function that will capture 'start'
    let increment = VMFunction {
        name: "increment".to_string(),
        parameters: vec!["amount".to_string()],
        upvalues: vec!["start".to_string()], // Captured from outer scope
        parent: Some("create_counter".to_string()),
        register_count: 4,
        instructions: vec![
            // Load the captured value and the parameter
            Instruction::Move(Operand::Register(0), Operand::Upvalue("start".to_string())),
            Instruction::Move(Operand::Register(1), Operand::Variable("amount".to_string())),

            // Increment the value: start = start + amount
            Instruction::Add(2, 0, 1),
            Instruction::Move(Operand::Upvalue("start".to_string()), Operand::Register(2)),

            // Return the new value
            Instruction::Return(2),
        ],
    };

    // Main function to test closures
    let main_function = VMFunction {
        name: "main".to_string(),
        parameters: vec![],
        upvalues: Vec::new(),
        parent: None,
        register_count: 5,
        instructions: vec![
            // Create a counter starting at 10: counter = create_counter(10)
            Instruction::Move(Operand::Register(0), Operand::Constant(Value::Int(10))),
            Instruction::Call(CallTarget::FunctionName("create_counter".to_string()), vec![0], 1),  // Store counter function in r1

            // Call the counter function with different increments
            // counter(5)
            Instruction::Move(Operand::Register(0), Operand::Constant(Value::Int(5))),
            Instruction::Call(CallTarget::Register(1), vec![0], 2),  // Call counter(5), result in r2

            // Print the result (should be 15)
            Instruction::Call(CallTarget::FunctionName("print".to_string()), vec![2], 3),

            // counter(7)
            Instruction::Move(Operand::Register(0), Operand::Constant(Value::Int(7))),
            Instruction::Call(CallTarget::Register(1), vec![0], 3),  // Call counter(7), result in r3

            // Print the result (should be 22)
            Instruction::Call(CallTarget::FunctionName("print".to_string()), vec![3], 4),

            // Return the final counter value
            Instruction::Return(3),
        ],
    };

    // Register functions
    vm.register_function(create_counter);
    vm.register_function(increment);
    vm.register_function(main_function);

    // Register a hook to monitor upvalue access
    vm.register_hook(
        |event| {
            match event {
                HookEvent::UpvalueRead(_, _) => true,
                HookEvent::UpvalueWrite(_, _, _) => true,
                HookEvent::ClosureCreated(_, _) => true,
                _ => false,
            }
        },
        |event| {
            match event {
                HookEvent::UpvalueRead(name, value) => {
                    println!("HOOK: Read upvalue {}: {:?}", name, value);
                },
                HookEvent::UpvalueWrite(name, old_val, new_val) => {
                    println!("HOOK: Write upvalue {}: {:?} -> {:?}", name, old_val, new_val);
                },
                HookEvent::ClosureCreated(func_name, upvalues) => {
                    println!("HOOK: Created closure for {} with upvalues: {:?}", func_name, upvalues);
                },
                _ => {}
            }
            Ok(())
        },
        100
    );

    // Execute the program
    match vm.execute("main") {
        Ok(result) => println!("Main function returned: {:?}", result),
        Err(err) => println!("Error: {}", err),
    }
}