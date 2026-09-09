//! Generates a simple client multiplication program for Docker testing
//!
//! This program takes one secret integer from each of two clients, multiplies
//! them, and returns the secret result. The explicit client and preprocessing
//! manifest keeps the checked-in fixture safe for standing execution.
//!
//! Run with: cargo run --example generate_client_mul_program

use std::collections::HashMap;
use stoffel_vm_types::compiled_binary::{ClientIoSchema, CompiledBinary, utils::save_to_file};
use stoffel_vm_types::core_types::{ShareType, Value};
use stoffel_vm_types::functions::VMFunction;
use stoffel_vm_types::instructions::Instruction;

fn main() {
    // Build the client multiplication program.
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
        // Multiply the two inputs (one Beaver triple).
        Instruction::MUL(18, 16, 17), // reg18 = reg16 * reg17
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
    let mut binary = CompiledBinary::from_vm_functions(&[main_function]);
    binary.client_io_manifest.clients = vec![
        ClientIoSchema {
            client_slot: 0,
            inputs: vec![ShareType::default_secret_int()],
            outputs: Vec::new(),
        },
        ClientIoSchema {
            client_slot: 1,
            inputs: vec![ShareType::default_secret_int()],
            outputs: Vec::new(),
        },
    ];
    binary.client_io_manifest.preprocessing_demand.triples = 1;

    // Save to file
    let output_path = "crates/stoffel-vm/src/tests/binaries/client_mul.stflb";
    save_to_file(&binary, output_path).expect("Failed to save binary");

    println!("Generated client multiplication program: {}", output_path);
    println!("This program:");
    println!("  - Takes input from client 0 (share 0)");
    println!("  - Takes input from client 1 (share 0)");
    println!("  - Multiplies them using one Beaver triple");
    println!("  - Returns the result (share)");
    println!();
    println!("Expected result for inputs 15 and 25: 375");
}
