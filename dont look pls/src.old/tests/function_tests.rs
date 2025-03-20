use crate::vm::{VM, RegisterType, print_registers};
use std::rc::Rc;

#[tokio::test]
async fn test_simple_function_call() {
    let mut vm = VM::new();
    
    // Create a function that adds two numbers
    // Function code: add two numbers and return result in r0
    let add_function = vec![
        0x03, 0, 1, 0,  // ADD r0, r1, r0 (add first two arguments, store in r0)
        0x12, 0         // RET r0 (return value in r0)
    ];
    
    // Register the function with 2 parameters
    let function_id = vm.register_function(add_function, 2, 0, 0);
    
    // Main program
    let program = vec![
        0x01, 0, 5, 0, 0, 0, 0, 0, 0, 0,  // LDI r0, 5
        0x01, 1, 3, 0, 0, 0, 0, 0, 0, 0,  // LDI r1, 3
        0x13, 0,                          // PUSHARG r0 (push 5)
        0x13, 1,                          // PUSHARG r1 (push 3)
        0x11, function_id as u8,          // CALL function_id
        // After return, result should be in r0
    ];
    
    vm.load_program(program);
    vm.run().await;
    
    // Check if the result is correct (5 + 3 = 8)
    assert_eq!(vm.get_register(0).unwrap().value, 8);
}

#[tokio::test]
async fn test_nested_function_calls() {
    let mut vm = VM::new();
    
    // Function 1: doubles a number
    let double_function = vec![
        0x03, 0, 0, 0,  // ADD r0, r0, r0 (double the input)
        0x12, 0         // RET r0
    ];
    
    // Function 2: adds 10 to a number
    let add_ten_function = vec![
        0x01, 1, 10, 0, 0, 0, 0, 0, 0, 0,  // LDI r1, 10
        0x03, 0, 1, 0,                     // ADD r0, r1, r0
        0x12, 0                            // RET r0
    ];
    
    // Register both functions
    let double_id = vm.register_function(double_function, 1, 1, 0);
    let add_ten_id = vm.register_function(add_ten_function, 1, 1, 0);
    
    // Main program: calculate (5*2)+10
    let program = vec![
        0x01, 0, 5, 0, 0, 0, 0, 0, 0, 0,  // LDI r0, 5
        0x13, 0,                          // PUSHARG r0 (push 5)
        0x11, double_id as u8,            // CALL double_function
        // r0 now contains 10
        0x13, 0,                          // PUSHARG r0 (push 10)
        0x11, add_ten_id as u8,           // CALL add_ten_function
        // r0 now contains 20
    ];
    
    vm.load_program(program);
    vm.run().await;
    
    // Check if the result is correct ((5*2)+10 = 20)
    assert_eq!(vm.get_register(0).unwrap().value, 20);
}

#[tokio::test]
async fn test_function_with_multiple_arguments() {
    let mut vm = VM::new();
    
    // Function that multiplies three numbers
    let multiply_function = vec![
        0x05, 0, 1, 0,  // MUL r0, r1, r0 (multiply first two args)
        0x05, 0, 2, 0,  // MUL r0, r2, r0 (multiply by third arg)
        0x12, 0         // RET r0
    ];
    
    // Register the function with 3 parameters
    let function_id = vm.register_function(multiply_function, 3, 0, 0);
    
    // Main program
    let program = vec![
        0x01, 0, 2, 0, 0, 0, 0, 0, 0, 0,  // LDI r0, 2
        0x01, 1, 3, 0, 0, 0, 0, 0, 0, 0,  // LDI r1, 3
        0x01, 2, 4, 0, 0, 0, 0, 0, 0, 0,  // LDI r2, 4
        0x13, 0,                          // PUSHARG r0 (push 2)
        0x13, 1,                          // PUSHARG r1 (push 3)
        0x13, 2,                          // PUSHARG r2 (push 4)
        0x11, function_id as u8,          // CALL function_id
        // After return, result should be in r0
    ];
    
    vm.load_program(program);
    vm.run().await;
    
    // Check if the result is correct (2 * 3 * 4 = 24)
    assert_eq!(vm.get_register(0).unwrap().value, 24);
}

#[tokio::test]
async fn test_register_preservation_across_calls() {
    let mut vm = VM::new();
    
    // Function that adds 1 to its argument
    let increment_function = vec![
        0x01, 1, 1, 0, 0, 0, 0, 0, 0, 0,  // LDI r1, 1
        0x03, 0, 1, 0,                    // ADD r0, r1, r0
        0x12, 0                           // RET r0
    ];
    
    // Register the function
    let function_id = vm.register_function(increment_function, 1, 1, 0);
    
    // Main program
    let program = vec![
        0x01, 0, 5, 0, 0, 0, 0, 0, 0, 0,  // LDI r0, 5
        0x01, 1, 10, 0, 0, 0, 0, 0, 0, 0, // LDI r1, 10
        0x13, 0,                          // PUSHARG r0 (push 5)
        0x11, function_id as u8,          // CALL function_id
        // r0 now contains 6, r1 should still be 10
    ];
    
    vm.load_program(program);
    vm.run().await;
    
    // Check if r0 has the correct return value
    assert_eq!(vm.get_register(0).unwrap().value, 6);
    
    // Check if r1 was preserved
    assert_eq!(vm.get_register(1).unwrap().value, 10);
}

#[tokio::test]
async fn test_current_activation_record_tracking() {
    let mut vm = VM::new();
    
    // Create a function that adds two numbers
    let add_function = vec![
        0x03, 0, 1, 0,  // ADD r0, r1, r0
        0x12, 0         // RET r0
    ];
    
    let function_id = vm.register_function(add_function, 2, 0, 0);
    
    // Main program
    let program = vec![
        0x01, 0, 5, 0, 0, 0, 0, 0, 0, 0,  // LDI r0, 5
        0x01, 1, 3, 0, 0, 0, 0, 0, 0, 0,  // LDI r1, 3
        0x13, 0,                          // PUSHARG r0
        0x13, 1,                          // PUSHARG r1
        0x11, function_id as u8,          // CALL function_id
    ];
    
    vm.load_program(program);
    vm.run().await;
    
    // After the program completes, there should be no current activation record
    assert_eq!(vm.get_current_activation_record_index(), None);
}

#[tokio::test]
async fn test_register_isolation_in_functions() {
    let mut vm = VM::new();
    
    // Function that modifies multiple registers
    let modify_registers_function = vec![
        0x01, 0, 100, 0, 0, 0, 0, 0, 0, 0,  // LDI r0, 100
        0x01, 1, 200, 0, 0, 0, 0, 0, 0, 0,  // LDI r1, 200
        0x01, 2, 44, 1, 0, 0, 0, 0, 0, 0,  // LDI r2, 300
        0x12, 0                            // RET r0
    ];
    
    // Register the function
    let function_id = vm.register_function(modify_registers_function, 1, 3, 0);
    
    // Main program
    let program = vec![
        0x01, 0, 5, 0, 0, 0, 0, 0, 0, 0,    // LDI r0, 5
        0x01, 1, 10, 0, 0, 0, 0, 0, 0, 0,   // LDI r1, 10
        0x01, 2, 15, 0, 0, 0, 0, 0, 0, 0,   // LDI r2, 15
        0x13, 0,                           // PUSHARG r0
        0x11, function_id as u8,           // CALL function_id
        // After return, r0 should contain 100 (return value)
        // But r1 and r2 should still be 10 and 15
    ];
    
    vm.load_program(program);
    vm.run().await;
    
    // Check if r0 has the return value from the function
    assert_eq!(vm.get_register(0).unwrap().value, 100);
    
    // Check if r1 and r2 were preserved (not affected by function's modifications)
    assert_eq!(vm.get_register(1).unwrap().value, 10);
    assert_eq!(vm.get_register(2).unwrap().value, 15);
}

#[tokio::test]
async fn test_nested_function_register_isolation() {
    // TODO: Implement a test for nested function calls
    // to ensure register isolation works correctly
    // when functions call other functions
}
