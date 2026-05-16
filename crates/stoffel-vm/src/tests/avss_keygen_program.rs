//! AVSS Keygen Program Generator
//!
//! Generates a `.stflb` bytecode program that performs distributed key generation
//! using the AVSS backend. The program:
//! 1. Calls `Share.random()` to run cooperative DKG (no party knows the secret)
//! 2. Calls `Share.get_commitment(share, 0)` to extract the public key
//! 3. Returns the public key bytes (all parties produce the same result)

use stoffel_vm_types::{
    compiled_binary::utils::{from_vm_functions, save_to_file},
    core_types::Value,
    functions::VMFunction,
    instructions::Instruction,
};

/// Build the AVSS keygen program as bytecode instructions.
pub fn build_avss_keygen_program() -> Vec<Instruction> {
    vec![
        // r0 = Share.random()  → jointly-random share (DKG)
        Instruction::CALL("Share.random".to_string()),
        // r1 = share object
        Instruction::MOV(1, 0),
        // r2 = 0 (commitment index 0 = public key)
        Instruction::LDI(2, Value::I64(0)),
        // Share.get_commitment(r1, r2) → byte array
        Instruction::PUSHARG(1),
        Instruction::PUSHARG(2),
        Instruction::CALL("Share.get_commitment".to_string()),
        // return the public key byte array
        Instruction::RET(0),
    ]
}

/// Generate and save the AVSS keygen bytecode to the test binaries directory.
#[test]
fn generate_avss_keygen_bytecode() {
    let func = VMFunction::new(
        "main".to_string(),
        vec![],
        vec![],
        None,
        4,
        build_avss_keygen_program(),
        Default::default(),
    );

    let binary = from_vm_functions(&[func]);

    // Save to the test binaries directory
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/tests/binaries/avss_keygen.stflb");
    save_to_file(&binary, &path).expect("failed to save avss_keygen bytecode");

    // Verify we can load it back
    let loaded =
        stoffel_vm_types::compiled_binary::utils::load_from_file(&path).expect("failed to reload");
    let functions = stoffel_vm_types::compiled_binary::utils::try_to_vm_functions(&loaded)
        .expect("generated AVSS keygen bytecode should be executable");
    assert_eq!(functions.len(), 1);
    assert_eq!(functions[0].name(), "main");
    assert_eq!(functions[0].instructions().len(), 7);
}
