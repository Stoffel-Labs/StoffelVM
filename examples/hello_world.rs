use stoffel_vm::core_vm::VirtualMachine;
use stoffel_vm::functions::VMFunction;
use stoffel_vm::instructions::Instruction;
use stoffel_vm::core_types::Value;
use std::collections::HashMap;

fn main() -> Result<(), String> {
    // Initialize the VM
    let mut vm = VirtualMachine::new();

    // Create a simple hello world function
    let hello_world = VMFunction::new(
        "hello_world".to_string(),
        vec![],
        vec![],
        None,
        1,
        vec![
            // Load "Hello, World!" string into register 0
            Instruction::LDI(0, Value::String("Hello, World!".to_string())),
            // Push register 0 as argument for print function
            Instruction::PUSHARG(0),
            // Call the built-in print function
            Instruction::CALL("print".to_string()),
            // Return Unit (void)
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    // Register the function with the VM
    vm.register_function(hello_world);

    // Execute the function
    let result = vm.execute("hello_world")?;

    println!("Program returned: {:?}", result);

    Ok(())
}
