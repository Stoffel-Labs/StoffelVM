//! AVSS certificate program generators.
//!
//! These fixtures are intended for the AVSS/local-store path, not the
//! coordinator client path. The keygen program loads an existing persistent CA
//! signing share if present, generates one only on first use, and returns the
//! public key. The signing program loads that share and signs the TBS digest
//! supplied through client input with threshold ECDSA.
//!
//! The signing program follows the Bar-Ilan/Beaver inversion trick:
//! `[delta] = [gamma] * [k]`, `delta = Open([delta])`, and
//! `[k^-1] = delta^-1 * [gamma]`. It then computes
//! `[s] = [e/k] + r * [sk/k]` with one additional secure multiplication.
//!
//! The signing program sends DER-ready ECDSA material to the output client as
//! two fixed-width big-endian field outputs, `r || s`. It does not emit an
//! X.509 signatureAlgorithm wrapper or DER-encoded ECDSA signature.
//!
//! The canonical human-readable Stoffel source for these flows lives under
//! `crates/stoffel-lang/examples/`. This module keeps Rust-side bytecode
//! builders for VM-level fixture coverage.

use std::collections::HashMap;

use stoffel_vm_types::{
    compiled_binary::utils::{
        from_vm_functions, load_from_file, save_to_file, try_to_vm_functions,
    },
    core_types::Value,
    functions::VMFunction,
    instructions::Instruction,
};

pub const DEFAULT_AVSS_CERTIFICATE_KEY_ID: &str = "ca:avss:sk:v1";
pub const THRESHOLD_ECDSA_DEMO_MESSAGE_INPUT: &str = "stoffel-avss-threshold-ecdsa-demo-message-v1";

/// Build a program that loads or creates the AVSS CA signing key share.
///
/// Result: `pk`, the SEC1-compressed commitment[0] public key bytes.
pub fn build_avss_certificate_keygen_program() -> (Vec<Instruction>, HashMap<String, usize>) {
    build_avss_certificate_keygen_program_for_key(DEFAULT_AVSS_CERTIFICATE_KEY_ID)
}

pub fn build_avss_certificate_keygen_program_for_key(
    key_id: &str,
) -> (Vec<Instruction>, HashMap<String, usize>) {
    let instructions = vec![
        // r1 = storage key
        Instruction::LDI(1, Value::String(key_id.to_owned())),
        // If the key already exists, load it instead of rotating the CA key.
        Instruction::PUSHARG(1),
        Instruction::CALL("LocalStorage.exists".to_owned()),
        Instruction::MOV(2, 0),
        Instruction::LDI(3, Value::Bool(true)),
        Instruction::CMP(2, 3),
        Instruction::JMPEQ("load_existing_key".to_owned()),
        // r4 = Share.random_field() -- cooperative DKG for the CA signing key
        Instruction::CALL("Share.random_field".to_owned()),
        Instruction::MOV(4, 0),
        // LocalStorage.store(key, sk)
        Instruction::PUSHARG(1),
        Instruction::PUSHARG(4),
        Instruction::CALL("LocalStorage.store".to_owned()),
        Instruction::JMP("return_public_key".to_owned()),
        // r4 = LocalStorage.load(key) -- persisted CA signing share
        Instruction::PUSHARG(1),
        Instruction::CALL("LocalStorage.load".to_owned()),
        Instruction::MOV(4, 0),
        // Return commitment[0] as a SEC1-compressed public key.
        Instruction::LDI(5, Value::I64(0)),
        Instruction::PUSHARG(4),
        Instruction::PUSHARG(5),
        Instruction::CALL("Share.get_commitment".to_owned()),
        Instruction::MOV(7, 0),
        Instruction::CALL("Mpc.curve".to_owned()),
        Instruction::MOV(6, 0),
        Instruction::PUSHARG(7),
        Instruction::PUSHARG(6),
        Instruction::CALL("Crypto.point_to_sec1".to_owned()),
        Instruction::RET(0),
    ];

    let mut labels = HashMap::new();
    labels.insert("load_existing_key".to_owned(), 13);
    labels.insert("return_public_key".to_owned(), 16);

    (instructions, labels)
}

/// Build a program that loads the persisted AVSS CA key and signs a TBS digest.
///
/// Digest source: client input 0, share 0, opened as the public ECDSA message
/// representative in the runtime curve field.
/// Output-client result: `r || s`, where:
/// - `r` and `s` are fixed-width big-endian X9.62 integers
/// - `[delta] = [gamma] * [k]`
/// - `[k^-1] = Open([delta])^-1 * [gamma]`
/// - `R = Open(Convert([k]))`
/// - `r = x(R) mod curve_order`
/// - `[s] = [e/k] + r * [sk/k]`
pub fn build_avss_certificate_sign_program() -> (Vec<Instruction>, HashMap<String, usize>) {
    build_avss_certificate_sign_program_for_key(DEFAULT_AVSS_CERTIFICATE_KEY_ID)
}

pub fn build_avss_certificate_sign_program_for_key(
    key_id: &str,
) -> (Vec<Instruction>, HashMap<String, usize>) {
    let instructions = vec![
        // r1 = storage key
        Instruction::LDI(1, Value::String(key_id.to_owned())),
        // r4 = LocalStorage.load(key) -- persisted CA signing share
        Instruction::PUSHARG(1),
        Instruction::CALL("LocalStorage.load".to_owned()),
        Instruction::MOV(4, 0),
        // r3 = pk = commitment[0](sk)
        Instruction::LDI(2, Value::I64(0)),
        Instruction::PUSHARG(4),
        Instruction::PUSHARG(2),
        Instruction::CALL("Share.get_commitment".to_owned()),
        Instruction::MOV(3, 0),
        // r5 = runtime curve name.
        Instruction::CALL("Mpc.curve".to_owned()),
        Instruction::MOV(5, 0),
        // r6 = e, the client-supplied TBS digest field element.
        Instruction::PUSHARG(2),
        Instruction::PUSHARG(2),
        Instruction::CALL("ClientStore.take_share".to_owned()),
        Instruction::MOV(6, 0),
        Instruction::PUSHARG(6),
        Instruction::CALL("Share.open_field".to_owned()),
        Instruction::MOV(6, 0),
        // r7 = [gamma], r8 = [k].
        Instruction::CALL("Share.random_field".to_owned()),
        Instruction::MOV(7, 0),
        Instruction::CALL("Share.random_field".to_owned()),
        Instruction::MOV(8, 0),
        // r9 = [delta] = [gamma] * [k].
        Instruction::PUSHARG(7),
        Instruction::PUSHARG(8),
        Instruction::CALL("Share.mul".to_owned()),
        Instruction::MOV(9, 0),
        // r9 = delta, opened as a clear field element.
        Instruction::PUSHARG(9),
        Instruction::CALL("Share.open_field".to_owned()),
        Instruction::MOV(9, 0),
        // r9 = delta^-1.
        Instruction::PUSHARG(9),
        Instruction::PUSHARG(5),
        Instruction::CALL("Crypto.field_inv".to_owned()),
        Instruction::MOV(9, 0),
        // r10 = [k^-1] = delta^-1 * [gamma].
        Instruction::PUSHARG(7),
        Instruction::PUSHARG(9),
        Instruction::CALL("Share.mul_field".to_owned()),
        Instruction::MOV(10, 0),
        // r11 = R = Open(Convert([k])), r12 = ECDSA r = x(R) mod q.
        Instruction::PUSHARG(8),
        Instruction::PUSHARG(5),
        Instruction::CALL("Share.open_exp".to_owned()),
        Instruction::MOV(11, 0),
        Instruction::PUSHARG(11),
        Instruction::PUSHARG(5),
        Instruction::CALL("Crypto.point_x_to_field".to_owned()),
        Instruction::MOV(12, 0),
        // r13 = [sk/k] = [sk] * [k^-1].
        Instruction::PUSHARG(4),
        Instruction::PUSHARG(10),
        Instruction::CALL("Share.mul".to_owned()),
        Instruction::MOV(13, 0),
        Instruction::PUSHARG(10),
        Instruction::PUSHARG(6),
        Instruction::CALL("Share.mul_field".to_owned()),
        Instruction::MOV(14, 0),
        // r15 = r * [sk/k].
        Instruction::PUSHARG(13),
        Instruction::PUSHARG(12),
        Instruction::CALL("Share.mul_field".to_owned()),
        Instruction::MOV(15, 0),
        // r15 = [s] = [e/k] + r * [sk/k].
        Instruction::PUSHARG(14),
        Instruction::PUSHARG(15),
        Instruction::CALL("Share.add".to_owned()),
        Instruction::MOV(15, 0),
        // r17 = [r], produced locally from a zero share so output does not trigger a nested input round.
        Instruction::PUSHARG(4),
        Instruction::LDI(16, Value::I64(0)),
        Instruction::PUSHARG(16),
        Instruction::CALL("Share.mul_scalar".to_owned()),
        Instruction::MOV(16, 0),
        Instruction::PUSHARG(16),
        Instruction::PUSHARG(12),
        Instruction::CALL("Share.add_field".to_owned()),
        Instruction::MOV(17, 0),
        // Send [r], [s] to output client 0.
        Instruction::LDI(18, Value::I64(2)),
        Instruction::PUSHARG(18),
        Instruction::CALL("create_array".to_owned()),
        Instruction::MOV(18, 0),
        Instruction::PUSHARG(18),
        Instruction::PUSHARG(17),
        Instruction::CALL("array_push".to_owned()),
        Instruction::PUSHARG(18),
        Instruction::PUSHARG(15),
        Instruction::CALL("array_push".to_owned()),
        Instruction::LDI(2, Value::I64(0)),
        Instruction::PUSHARG(2),
        Instruction::PUSHARG(18),
        Instruction::CALL("MpcOutput.send_to_client".to_owned()),
        // Return public r || pk for party logs and manual diagnostics.
        Instruction::PUSHARG(12),
        Instruction::PUSHARG(5),
        Instruction::CALL("Crypto.field_to_scalar_bytes".to_owned()),
        Instruction::MOV(19, 0),
        Instruction::PUSHARG(3),
        Instruction::PUSHARG(5),
        Instruction::CALL("Crypto.point_to_sec1".to_owned()),
        Instruction::MOV(20, 0),
        Instruction::PUSHARG(19),
        Instruction::PUSHARG(20),
        Instruction::CALL("Bytes.concat".to_owned()),
        Instruction::RET(0),
    ];

    (instructions, HashMap::new())
}

/// Build a fresh-key threshold ECDSA demo program for the given curve.
///
/// This mirrors the existing threshold signature fixtures: the program performs
/// DKG for `sk`, signs a fixed demo message with threshold ECDSA, and returns
/// fixed-width big-endian `r || s` plus a SEC1-compressed public key.
pub fn build_threshold_ecdsa_program(
    curve_name: &str,
) -> (Vec<Instruction>, HashMap<String, usize>) {
    let instructions = vec![
        // r1 = [sk] from cooperative DKG, r3 = pk = commitment[0](sk).
        Instruction::CALL("Share.random_field".to_owned()),
        Instruction::MOV(1, 0),
        Instruction::LDI(2, Value::I64(0)),
        Instruction::PUSHARG(1),
        Instruction::PUSHARG(2),
        Instruction::CALL("Share.get_commitment".to_owned()),
        Instruction::MOV(3, 0),
        // r4 = fixed ECDSA curve name for this fixture.
        Instruction::LDI(4, Value::String(curve_name.to_owned())),
        // r5 = e, the demo message digest reduced into the curve scalar field.
        Instruction::LDI(
            2,
            Value::String(THRESHOLD_ECDSA_DEMO_MESSAGE_INPUT.to_owned()),
        ),
        Instruction::PUSHARG(2),
        Instruction::CALL("Bytes.from_string".to_owned()),
        Instruction::PUSHARG(0),
        Instruction::CALL("Crypto.sha256".to_owned()),
        Instruction::PUSHARG(0),
        Instruction::PUSHARG(4),
        Instruction::CALL("Crypto.hash_to_field".to_owned()),
        Instruction::MOV(5, 0),
        // r6 = [gamma], r7 = [k].
        Instruction::CALL("Share.random_field".to_owned()),
        Instruction::MOV(6, 0),
        Instruction::CALL("Share.random_field".to_owned()),
        Instruction::MOV(7, 0),
        // r8 = [delta] = [gamma] * [k].
        Instruction::PUSHARG(6),
        Instruction::PUSHARG(7),
        Instruction::CALL("Share.mul".to_owned()),
        Instruction::MOV(8, 0),
        // r8 = delta, r8 = delta^-1, r9 = [k^-1].
        Instruction::PUSHARG(8),
        Instruction::CALL("Share.open_field".to_owned()),
        Instruction::MOV(8, 0),
        Instruction::PUSHARG(8),
        Instruction::PUSHARG(4),
        Instruction::CALL("Crypto.field_inv".to_owned()),
        Instruction::MOV(8, 0),
        Instruction::PUSHARG(6),
        Instruction::PUSHARG(8),
        Instruction::CALL("Share.mul_field".to_owned()),
        Instruction::MOV(9, 0),
        // r10 = R = Open(Convert([k])), r11 = ECDSA r = x(R) mod q.
        Instruction::PUSHARG(7),
        Instruction::PUSHARG(4),
        Instruction::CALL("Share.open_exp".to_owned()),
        Instruction::MOV(10, 0),
        Instruction::PUSHARG(10),
        Instruction::PUSHARG(4),
        Instruction::CALL("Crypto.point_x_to_field".to_owned()),
        Instruction::MOV(11, 0),
        // r12 = [sk/k], r13 = [e/k], r14 = r * [sk/k].
        Instruction::PUSHARG(1),
        Instruction::PUSHARG(9),
        Instruction::CALL("Share.mul".to_owned()),
        Instruction::MOV(12, 0),
        Instruction::PUSHARG(9),
        Instruction::PUSHARG(5),
        Instruction::CALL("Share.mul_field".to_owned()),
        Instruction::MOV(13, 0),
        Instruction::PUSHARG(12),
        Instruction::PUSHARG(11),
        Instruction::CALL("Share.mul_field".to_owned()),
        Instruction::MOV(14, 0),
        // [s] = [e/k] + r * [sk/k], then open s.
        Instruction::PUSHARG(13),
        Instruction::PUSHARG(14),
        Instruction::CALL("Share.add".to_owned()),
        Instruction::PUSHARG(0),
        Instruction::CALL("Share.open_field".to_owned()),
        Instruction::MOV(15, 0),
        // Convert internal ark field/point encodings to DER-ready ECDSA bytes.
        Instruction::PUSHARG(11),
        Instruction::PUSHARG(4),
        Instruction::CALL("Crypto.field_to_scalar_bytes".to_owned()),
        Instruction::MOV(11, 0),
        Instruction::PUSHARG(15),
        Instruction::PUSHARG(4),
        Instruction::CALL("Crypto.field_to_scalar_bytes".to_owned()),
        Instruction::MOV(15, 0),
        Instruction::PUSHARG(3),
        Instruction::PUSHARG(4),
        Instruction::CALL("Crypto.point_to_sec1".to_owned()),
        Instruction::MOV(3, 0),
        // return r || s || pk
        Instruction::PUSHARG(11),
        Instruction::PUSHARG(15),
        Instruction::CALL("Bytes.concat".to_owned()),
        Instruction::PUSHARG(0),
        Instruction::PUSHARG(3),
        Instruction::CALL("Bytes.concat".to_owned()),
        Instruction::RET(0),
    ];

    (instructions, HashMap::new())
}

fn certificate_function(
    instructions: Vec<Instruction>,
    labels: HashMap<String, usize>,
    register_count: usize,
) -> VMFunction {
    VMFunction::new(
        "main".to_owned(),
        vec![],
        vec![],
        None,
        register_count,
        instructions,
        labels,
    )
}

fn write_and_validate_bytecode(name: &str, function: VMFunction, expected_len: usize) {
    let expected_register_count = function.register_count();
    let binary = from_vm_functions(&[function]);
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join(name);

    save_to_file(&binary, &path).expect("failed to save AVSS certificate bytecode");

    let loaded = load_from_file(&path).expect("failed to reload AVSS certificate bytecode");
    let functions =
        try_to_vm_functions(&loaded).expect("generated certificate bytecode should be executable");

    assert_eq!(functions.len(), 1);
    assert_eq!(functions[0].name(), "main");
    assert_eq!(functions[0].instructions().len(), expected_len);
    assert_eq!(functions[0].register_count(), expected_register_count);
}

#[test]
fn avss_certificate_keygen_loads_existing_key_before_generating() {
    let (instructions, labels) = build_avss_certificate_keygen_program();

    assert!(matches!(
        &instructions[2],
        Instruction::CALL(name) if name == "LocalStorage.exists"
    ));
    assert!(matches!(
        &instructions[6],
        Instruction::JMPEQ(label) if label == "load_existing_key"
    ));
    assert!(matches!(
        &instructions[*labels.get("load_existing_key").expect("load label") + 1],
        Instruction::CALL(name) if name == "LocalStorage.load"
    ));
    assert!(matches!(
        &instructions[7],
        Instruction::CALL(name) if name == "Share.random_field"
    ));
}

#[test]
fn avss_certificate_keygen_and_sign_programs_use_requested_key_id() {
    let requested_key = "ca:avss:sk:root-a";
    let (keygen_instructions, _) = build_avss_certificate_keygen_program_for_key(requested_key);
    let (sign_instructions, _) = build_avss_certificate_sign_program_for_key(requested_key);

    assert!(matches!(
        &keygen_instructions[0],
        Instruction::LDI(_, Value::String(key)) if key == requested_key
    ));
    assert!(matches!(
        &sign_instructions[0],
        Instruction::LDI(_, Value::String(key)) if key == requested_key
    ));
}

#[test]
fn avss_certificate_bytecode_round_trips_without_mutating_fixtures() {
    let (keygen_instructions, keygen_labels) = build_avss_certificate_keygen_program();
    let keygen_len = keygen_instructions.len();
    write_and_validate_bytecode(
        "avss_certificate_keygen.stflb",
        certificate_function(keygen_instructions, keygen_labels, 8),
        keygen_len,
    );

    let (sign_instructions, sign_labels) = build_avss_certificate_sign_program();
    let sign_len = sign_instructions.len();
    write_and_validate_bytecode(
        "avss_certificate_sign.stflb",
        certificate_function(sign_instructions, sign_labels, 21),
        sign_len,
    );

    let (secp_instructions, secp_labels) = build_threshold_ecdsa_program("secp256k1");
    let secp_len = secp_instructions.len();
    write_and_validate_bytecode(
        "threshold_ecdsa_secp256k1.stflb",
        certificate_function(secp_instructions, secp_labels, 16),
        secp_len,
    );

    let (p256_instructions, p256_labels) = build_threshold_ecdsa_program("p-256");
    let p256_len = p256_instructions.len();
    write_and_validate_bytecode(
        "threshold_ecdsa_p256.stflb",
        certificate_function(p256_instructions, p256_labels, 16),
        p256_len,
    );
}
