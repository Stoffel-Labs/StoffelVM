use std::collections::HashMap;
use stoffel_vm::core_types::Value;
use stoffel_vm::core_vm::VirtualMachine;
use stoffel_vm::functions::VMFunction;
use stoffel_vm::instructions::Instruction;

// TODO: figure out why our noble memory safe program is in fact not memory safe in this

fn main() -> Result<(), String> {
    // Initialize the VM
    let mut vm = VirtualMachine::new();

    // Create a function to add two numbers
    let add = VMFunction::new(
        "add".to_string(),
        vec!["a".to_string(), "b".to_string()],
        vec![],
        None,
        3,
        vec![
            // Parameters are loaded into r0 and r1 automatically
            // Add r0 and r1, storing result in r2
            Instruction::ADD(2, 0, 1),
            // Return the result
            Instruction::RET(2),
        ],
        HashMap::new(),
    );

    // Create a function to subtract two numbers
    let subtract = VMFunction::new(
        "subtract".to_string(),
        vec!["a".to_string(), "b".to_string()],
        vec![],
        None,
        3,
        vec![
            // Parameters are loaded into r0 and r1 automatically
            // Subtract r1 from r0, storing result in r2
            Instruction::SUB(2, 0, 1),
            // Return the result
            Instruction::RET(2),
        ],
        HashMap::new(),
    );

    // Create a function to multiply two numbers
    let multiply = VMFunction::new(
        "multiply".to_string(),
        vec!["a".to_string(), "b".to_string()],
        vec![],
        None,
        3,
        vec![
            // Parameters are loaded into r0 and r1 automatically
            // Multiply r0 and r1, storing result in r2
            Instruction::MUL(2, 0, 1),
            // Return the result
            Instruction::RET(2),
        ],
        HashMap::new(),
    );

    // Create a function to divide two numbers
    let divide = VMFunction::new(
        "divide".to_string(),
        vec!["a".to_string(), "b".to_string()],
        vec![],
        None,
        3,
        vec![
            // Parameters are loaded into r0 and r1 automatically
            // Divide r0 by r1, storing result in r2
            Instruction::DIV(2, 0, 1),
            // Return the result
            Instruction::RET(2),
        ],
        HashMap::new(),
    );

    // Create a calculator function that takes an operation and two numbers
    let mut calculator_labels = HashMap::new();
    calculator_labels.insert("call_add".to_string(), 14);
    calculator_labels.insert("call_subtract".to_string(), 18);
    calculator_labels.insert("call_multiply".to_string(), 22);
    calculator_labels.insert("call_divide".to_string(), 26);

    let calculator = VMFunction::new(
        "calculator".to_string(),
        vec!["operation".to_string(), "a".to_string(), "b".to_string()],
        vec![],
        None,
        5,
        vec![
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
        calculator_labels,
    );

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
        let args = vec![Value::String(op.to_string()), Value::I64(a), Value::I64(b)];

        let result = vm.execute_with_args("calculator", &args)?;
        println!("{} {} {} = {:?}", a, op, b, result);
    }

    Ok(())
}
