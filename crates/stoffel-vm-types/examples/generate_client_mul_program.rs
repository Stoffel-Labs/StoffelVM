//! Generates a simple client addition program for Docker testing
//!
//! This program takes input from two clients (client 0 and client 1),
//! adds them together, and returns the result.
//!
//! Note: We use ADD instead of MUL because MPC multiplication requires
//! coordinated batch operations that the VM doesn't support yet.
//!
//! Run with: cargo run --example generate_client_mul_program

use std::collections::HashMap;
use stoffel_vm_types::compiled_binary::{CompiledBinary, utils::save_to_file};
use stoffel_vm_types::core_types::Value;
use stoffel_vm_types::functions::VMFunction;
use stoffel_vm_types::instructions::Instruction;

fn main() {
    // Build the client addition program
    let instructions = vec![
        // Get number of clients (for informational purposes)
        Instruction::CALL("ClientStore.get_number_clients".to_string()),
        Instruction::MOV(2, 0), // reg2 = num_clients
        // Load first client's input (client 0, share 0)
        Instruction::LDI(0, Value::I64(0)), // client_index = 0
        Instruction::PUSHARG(0),
        Instruction::LDI(1, Value::I64(0)), // share_index = 0
        Instruction::PUSHARG(1),
        Instruction::CALL("ClientStore.take_share".to_string()),
        Instruction::MOV(16, 0), // reg16 = client 0's input
        // Load second client's input (client 1, share 0)
        Instruction::LDI(0, Value::I64(1)), // client_index = 1
        Instruction::PUSHARG(0),
        Instruction::LDI(1, Value::I64(0)), // share_index = 0
        Instruction::PUSHARG(1),
        Instruction::CALL("ClientStore.take_share".to_string()),
        Instruction::MOV(17, 0), // reg17 = client 1's input
        // Add the two inputs (secret share addition is local, doesn't need MPC protocol)
        Instruction::ADD(18, 16, 17), // reg18 = reg16 + reg17
        // Return the share directly (no reveal needed for this test)
        // Note: RET from a secret register (>=16) returns the Share value as-is
        Instruction::RET(18),
    ];

    // Create the main function
    let main_function = VMFunction::new(
        "main".to_string(),
        vec![], // no parameters
        vec![], // no upvalues
        None,   // no parent
        20,     // register count
        instructions,
        HashMap::new(), // no labels
    );

    // Create compiled binary from the function
    let binary = CompiledBinary::from_vm_functions(&[main_function]);

    // Save to file
    let output_path = "crates/stoffel-vm/src/tests/binaries/client_mul.stflb";
    save_to_file(&binary, output_path).expect("Failed to save binary");

    println!("Generated client addition program: {}", output_path);
    println!("This program:");
    println!("  - Takes input from client 0 (share 0)");
    println!("  - Takes input from client 1 (share 0)");
    println!("  - Adds them together (local secret share operation)");
    println!("  - Returns the result (share)");
    println!();
    println!("Expected result for inputs 15 and 25: 40");
}
