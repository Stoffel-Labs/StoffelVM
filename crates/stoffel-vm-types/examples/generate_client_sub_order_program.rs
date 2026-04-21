//! Generates a client-order-sensitive subtraction program for coordinator tests.
//!
//! The program computes `client[0] - client[1]` over secret shares, so swapping
//! which physical client reserves slot 0 versus slot 1 changes the result.
//!
//! Run with:
//!   cargo run -p stoffel-vm-types --example generate_client_sub_order_program

use std::collections::HashMap;

use stoffel_vm_types::compiled_binary::{CompiledBinary, utils::save_to_file};
use stoffel_vm_types::core_types::Value;
use stoffel_vm_types::functions::VMFunction;
use stoffel_vm_types::instructions::Instruction;

fn main() {
    let instructions = vec![
        Instruction::CALL("ClientStore.get_number_clients".to_string()),
        Instruction::MOV(2, 0),
        Instruction::LDI(0, Value::I64(0)),
        Instruction::PUSHARG(0),
        Instruction::LDI(1, Value::I64(0)),
        Instruction::PUSHARG(1),
        Instruction::CALL("ClientStore.take_share".to_string()),
        Instruction::MOV(16, 0),
        Instruction::LDI(0, Value::I64(1)),
        Instruction::PUSHARG(0),
        Instruction::LDI(1, Value::I64(0)),
        Instruction::PUSHARG(1),
        Instruction::CALL("ClientStore.take_share".to_string()),
        Instruction::MOV(17, 0),
        Instruction::SUB(18, 16, 17),
        Instruction::RET(18),
    ];

    let main_function = VMFunction::new(
        "main".to_string(),
        vec![],
        vec![],
        None,
        20,
        instructions,
        HashMap::new(),
    );

    let binary = CompiledBinary::from_vm_functions(&[main_function]);
    let output_path = "crates/stoffel-vm/src/tests/binaries/client_sub_order.stflb";
    save_to_file(&binary, output_path).expect("Failed to save binary");

    println!("Generated client subtraction program: {}", output_path);
    println!("This program computes client[0] - client[1].");
    println!("Swapping coordinator reservation indices changes the result.");
}
