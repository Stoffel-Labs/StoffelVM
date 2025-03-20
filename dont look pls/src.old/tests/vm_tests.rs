use crate::vm::{VM, RegisterType};
use crate::operations::opcodes::ReducedOpcode;

#[tokio::test]
async fn test_basic_addition_program() {
    let mut vm = VM::new();
    
    // Create a simple program that adds two numbers
    // Load Immediate r0, 5
    // Load Immediate r1, 3
    // Add r0, r1, r2
    let program = vec![
        ReducedOpcode::LDI as u8, 0, 5, 0, 0, 0, 0, 0, 0, 0,  // Load 5 into r0
        ReducedOpcode::LDI as u8, 1, 3, 0, 0, 0, 0, 0, 0, 0,  // Load 3 into r1
        ReducedOpcode::ADD as u8, 0, 1, 2,  // Add r0 and r1, store in r2
    ];
    
    vm.load_program(program);
    vm.run().await;
    
    let result = vm.get_register(2).unwrap();
    assert_eq!(result.value, 8);
    assert_eq!(result.reg_type, RegisterType::Clear);
}

#[tokio::test]
async fn test_function_call() {
    let mut vm = VM::new();

    // Register a simple function that adds 1 to the argument
    let function_code = vec![
        ReducedOpcode::ADD as u8, 0, 1, 0,  // Add r0 and r1, store in r0
        ReducedOpcode::RET as u8, 0,  // Return
    ];

    let function_id = vm.register_function(function_code, 1, 2, 0);

    // Create main program that calls the function
    let program = vec![
        ReducedOpcode::LDI as u8, 0, 5, 0, 0, 0, 0, 0, 0, 0,
        ReducedOpcode::PUSHARG as u8, 0,  // Push 5 as an argument
        ReducedOpcode::CALL as u8, function_id as u8,  // Call our function
    ];

    vm.load_program(program);
    vm.run().await;

    let result = vm.get_register(0).unwrap();
    assert_eq!(result.value, 6);
}
