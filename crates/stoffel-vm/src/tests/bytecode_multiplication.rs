use stoffel_vm::core_vm::VirtualMachine;
use stoffel_vm_types::{
    compiled_binary::utils::{from_vm_functions, load_from_file, save_to_file, to_vm_functions},
    core_types::Value,
    functions::VMFunction,
    instructions::Instruction,
};

// This test verifies that we can:
// 1) Build a simple program
// 2) Compile it to Stoffel bytecode (.stfl)
// 3) Load it back from bytecode and execute via the VM
//
// Program:
//   r0 <- 42
//   r1 <- 37
//   r2 <- r0 * r1
//   ret r2
#[test]
fn test_execute_program_from_stoffel_bytecode_mul_clear() {
    // Build a simple function (human-readable form)
    let func = VMFunction {
        name: "main".to_string(),
        parameters: vec![],
        upvalues: vec![],
        parent: None,
        register_count: 3,
        instructions: vec![
            Instruction::LDI(0, Value::I64(42)),
            Instruction::LDI(1, Value::I64(37)),
            Instruction::MUL(2, 0, 1),
            Instruction::RET(2),
        ],
        labels: Default::default(),
    };

    // Compile to a bytecode binary
    let binary = from_vm_functions(&[func]);

    // Write to a temporary .stfl file
    let mut path = std::env::temp_dir();
    path.push("bytecode_mul_clear.stfl");
    save_to_file(&binary, &path).expect("failed to save compiled bytecode");

    // Load the compiled bytecode from disk
    let loaded = load_from_file(&path).expect("failed to load compiled bytecode");

    // Convert back to VM functions (the VM only sees functions reconstructed from bytecode)
    let vm_functions = to_vm_functions(&loaded);
    assert!(!vm_functions.is_empty());

    // Execute the loaded program via VM
    let mut vm = VirtualMachine::new();
    vm.register_standard_library();
    for f in vm_functions {
        vm.register_function(f);
    }

    let result = vm.execute("main").expect("VM execution failed");
    assert_eq!(result, Value::I64(42 * 37));
}
