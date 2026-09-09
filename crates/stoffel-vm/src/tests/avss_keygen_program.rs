//! AVSS Keygen Program Generator
//!
//! Generates a `.stflb` bytecode program that performs distributed key generation
//! using the AVSS backend. The program:
//! 1. Calls `Share.random_field()` to run cooperative DKG (no party knows the secret)
//! 2. Calls `Share.get_commitment(share, 0)` to extract the public key
//! 3. Returns the public key bytes (all parties produce the same result)

use stoffel_vm_types::{
    compiled_binary::utils::{
        from_vm_functions, load_from_file, save_to_file, try_to_vm_functions,
    },
    core_types::Value,
    functions::VMFunction,
    instructions::Instruction,
};

/// Build the AVSS keygen program as bytecode instructions.
pub fn build_avss_keygen_program() -> Vec<Instruction> {
    vec![
        // r0 = Share.random_field()  → jointly-random share (DKG)
        Instruction::CALL("Share.random_field".to_string()),
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

#[test]
fn avss_keygen_bytecode_round_trips_without_mutating_fixtures() {
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

    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("avss_keygen.stflb");
    save_to_file(&binary, &path).expect("failed to save avss_keygen bytecode");

    let loaded = load_from_file(&path).expect("failed to reload");
    let functions =
        try_to_vm_functions(&loaded).expect("generated AVSS keygen bytecode should be executable");
    assert_eq!(functions.len(), 1);
    assert_eq!(functions[0].name(), "main");
    assert_eq!(functions[0].instructions().len(), 7);
}
