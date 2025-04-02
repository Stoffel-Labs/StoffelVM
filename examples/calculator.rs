use stoffel_vm::core_vm::VirtualMachine;
use stoffel_vm::functions::VMFunction;
use stoffel_vm::instructions::Instruction;
use stoffel_vm::core_types::Value;
use std::collections::HashMap;


// TODO: figure out why our noble memory safe program is in fact not memory safe in this

fn main() -> Result<(), String> {
    // Initialize the VM
    let vm = VirtualMachine::new();
    
    // Create a function to add two numbers
    let add = VMFunction {
        name: "add".to_string(),
        parameters: vec!["a".to_string(), "b".to_string()],
        upvalues: vec![],
        parent: None,
        register_count: 3,
        instructions: vec![
            // Parameters are loaded into r0 and r1 automatically
            // Add r0 and r1, storing result in r2
            Instruction::ADD(2, 0, 1),
            // Return the result
            Instruction::RET(2),
        ],
        labels: HashMap::new(),
    };
    
    // Create a function to subtract two numbers
    let subtract = VMFunction {
        name: "subtract".to_string(),
        parameters: vec!["a".to_string(), "b".to_string()],
        upvalues: vec![],
        parent: None,
        register_count: 3,
        instructions: vec![
            // Parameters are loaded into r0 and r1 automatically
            // Subtract r1 from r0, storing result in r2
            Instruction::SUB(2, 0, 1),
            // Return the result
            Instruction::RET(2),
        ],
        labels: HashMap::new(),
    };
    
    // Create a function to multiply two numbers
    let multiply = VMFunction {
        name: "multiply".to_string(),
        parameters: vec!["a".to_string(), "b".to_string()],
        upvalues: vec![],
        parent: None,
        register_count: 3,
        instructions: vec![
            // Parameters are loaded into r0 and r1 automatically
            // Multiply r0 and r1, storing result in r2
            Instruction::MUL(2, 0, 1),
            // Return the result
            Instruction::RET(2),
        ],
        labels: HashMap::new(),
    };
    
    // Create a function to divide two numbers
    let divide = VMFunction {
        name: "divide".to_string(),
        parameters: vec!["a".to_string(), "b".to_string()],
        upvalues: vec![],
        parent: None,
        register_count: 3,
        instructions: vec![
            // Parameters are loaded into r0 and r1 automatically
            // Divide r0 by r1, storing result in r2
            Instruction::DIV(2, 0, 1),
            // Return the result
            Instruction::RET(2),
        ],
        labels: HashMap::new(),
    };
    
    // Create a calculator function that takes an operation and two numbers
    let calculator = VMFunction {
        name: "calculator".to_string(),
        parameters: vec!["operation".to_string(), "a".to_string(), "b".to_string()],
        upvalues: vec![],
        parent: None,
        register_count: 5,
        instructions: vec![
            // Load operation strings for comparison
            Instruction::LDI(3, Value::String("add".to_string())),
            // Compare operation with "add"
            Instruction::CMP(0, 3),
            // If equal, call add function
            Instruction::JMPEQ("call_add".to_string()),
            
            // Load "subtract" for comparison
            Instruction::LDI(3, Value::String("subtract".to_string())),
            // Compare operation with "subtract"
            Instruction::CMP(0, 3),
            // If equal, call subtract function
            Instruction::JMPEQ("call_subtract".to_string()),
            
            // Load "multiply" for comparison
            Instruction::LDI(3, Value::String("multiply".to_string())),
            // Compare operation with "multiply"
            Instruction::CMP(0, 3),
            // If equal, call multiply function
            Instruction::JMPEQ("call_multiply".to_string()),
            
            // Load "divide" for comparison
            Instruction::LDI(3, Value::String("divide".to_string())),
            // Compare operation with "divide"
            Instruction::CMP(0, 3),
            // If equal, call divide function
            Instruction::JMPEQ("call_divide".to_string()),
            
            // If no match, return error message
            Instruction::LDI(0, Value::String("Invalid operation".to_string())),
            Instruction::RET(0),
            
            // call_add:
            Instruction::PUSHARG(1), // Push a
            Instruction::PUSHARG(2), // Push b
            Instruction::CALL("add".to_string()),
            Instruction::RET(0),
            
            // call_subtract:
            Instruction::PUSHARG(1), // Push a
            Instruction::PUSHARG(2), // Push b
            Instruction::CALL("subtract".to_string()),
            Instruction::RET(0),
            
            // call_multiply:
            Instruction::PUSHARG(1), // Push a
            Instruction::PUSHARG(2), // Push b
            Instruction::CALL("multiply".to_string()),
            Instruction::RET(0),
            
            // call_divide:
            Instruction::PUSHARG(1), // Push a
            Instruction::PUSHARG(2), // Push b
            Instruction::CALL("divide".to_string()),
            Instruction::RET(0),
        ],
        labels: {
            let mut labels = HashMap::new();
            labels.insert("call_add".to_string(), 14);
            labels.insert("call_subtract".to_string(), 18);
            labels.insert("call_multiply".to_string(), 22);
            labels.insert("call_divide".to_string(), 26);
            labels
        },
    };
    
    // Register all functions with the VM
    vm.register_function(add);
    vm.register_function(subtract);
    vm.register_function(multiply);
    vm.register_function(divide);
    vm.register_function(calculator);
    
    // Test the calculator with different operations
    let operations = vec!["add", "subtract", "multiply", "divide"];
    let a = 10;
    let b = 5;
    
    for op in operations {
        let args = vec![
            Value::String(op.to_string()),
            Value::Int(a),
            Value::Int(b),
        ];
        
        let result = vm.execute_with_args("calculator", &args)?;
        println!("{} {} {} = {:?}", a, op, b, result);
    }
    
    Ok(())
}
