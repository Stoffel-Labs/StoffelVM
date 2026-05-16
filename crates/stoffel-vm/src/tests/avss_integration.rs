//! AVSS Integration Tests
//!
//! This module tests the AVSS (Asynchronously Verifiable Secret Sharing) functionality:
//! 1. Unit tests for AVSS share objects and builtins
//! 2. Integration tests with simulated network
//! 3. Example VM program that extracts public key from AVSS result

use ark_bls12_381::{Fr, G1Projective as G1};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use std::collections::HashMap;

use crate::core_vm::VirtualMachine;
use crate::tests::test_utils::{read_vm_table_byte_array, setup_test_tracing};
use stoffel_vm_types::core_types::{ObjectRef, Value};
use stoffel_vm_types::functions::VMFunction;
use stoffel_vm_types::instructions::Instruction;

type AvssPartyMaterial = (Vec<u8>, Vec<Vec<u8>>);
type SimulatedAvssShares = Vec<AvssPartyMaterial>;

/// Create a mock AVSS share for testing
/// This simulates what the AVSS protocol would produce
fn create_mock_avss_share(party_id: usize, threshold: usize) -> (Vec<u8>, Vec<Vec<u8>>, G1) {
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
    use ark_std::test_rng;

    let mut rng = test_rng();
    let secret = Fr::rand(&mut rng);

    // Generate polynomial with random coefficients
    let mut poly = DensePolynomial::rand(threshold, &mut rng);
    poly[0] = secret;

    // Generate commitments: C_i = g^a_i
    let commitments: Vec<G1> = poly.coeffs.iter().map(|c| G1::generator() * c).collect();

    // Generate share for this party: y = p(party_id)
    let x = Fr::from((party_id + 1) as u64);
    let share_value = poly.evaluate(&x);

    // Serialize share
    let mut share_bytes = Vec::new();
    share_value
        .serialize_compressed(&mut share_bytes)
        .expect("Failed to serialize share");

    // Serialize commitments
    let commitment_bytes: Vec<Vec<u8>> = commitments
        .iter()
        .map(|c| {
            let mut bytes = Vec::new();
            c.into_affine()
                .serialize_compressed(&mut bytes)
                .expect("Failed to serialize commitment");
            bytes
        })
        .collect();

    // Public key is commitment[0] = g^secret
    let public_key = commitments[0];

    (share_bytes, commitment_bytes, public_key)
}

fn create_vm_avss_share(
    vm: &mut VirtualMachine,
    key_name: &str,
    share_bytes: Vec<u8>,
    commitment_bytes: Vec<Vec<u8>>,
    party_id: usize,
) -> usize {
    match vm
        .create_avss_share_object(key_name, share_bytes, commitment_bytes, party_id)
        .expect("create AVSS share object")
    {
        Value::Object(object_ref) => object_ref.id(),
        other => panic!("Expected AVSS share object, got: {:?}", other),
    }
}

/// Test that AVSS share objects can be created and queried
#[test]
fn test_avss_share_object_creation() {
    setup_test_tracing();

    let mut vm = VirtualMachine::new();
    let key_name = "test_key";
    let party_id = 1usize;
    let threshold = 2;

    let (share_bytes, commitment_bytes, expected_public_key) =
        create_mock_avss_share(party_id, threshold);

    let obj_id = create_vm_avss_share(
        &mut vm,
        key_name,
        share_bytes,
        commitment_bytes.clone(),
        party_id,
    );

    let obj = Value::from(ObjectRef::new(obj_id));
    assert!(vm.is_avss_share_object(&obj));

    // Verify key name
    let retrieved_key_name = vm.avss_key_name(&obj).unwrap();
    assert_eq!(retrieved_key_name, key_name);

    // Verify commitment count
    let count = vm.avss_commitment_count(&obj).unwrap();
    assert_eq!(count, commitment_bytes.len());

    // Verify public key (commitment[0])
    let public_key_bytes = vm.avss_commitment(&obj, 0).unwrap();
    assert_eq!(public_key_bytes, commitment_bytes[0]);

    // Deserialize and verify it matches the expected public key
    let retrieved_pk = G1::deserialize_compressed(&public_key_bytes[..])
        .expect("Failed to deserialize public key");
    assert_eq!(retrieved_pk, expected_public_key);
}

/// Test AVSS builtins through VM function calls
#[test]
fn test_avss_builtins_via_vm() {
    setup_test_tracing();

    let mut vm = VirtualMachine::new();
    let party_id = 0usize;
    let threshold = 1;

    let (share_bytes, commitment_bytes, _expected_public_key) =
        create_mock_avss_share(party_id, threshold);

    let obj_id = create_vm_avss_share(
        &mut vm,
        "vm_test_key",
        share_bytes,
        commitment_bytes.clone(),
        party_id,
    );

    let test_is_avss_share_fn = VMFunction::new(
        "test_is_avss_share".to_string(),
        vec![],
        Vec::new(),
        None,
        4,
        vec![
            Instruction::LDI(0, Value::from(ObjectRef::new(obj_id))),
            Instruction::PUSHARG(0),
            Instruction::CALL("Avss.is_avss_share".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    vm.register_function(test_is_avss_share_fn);

    let result = vm.execute("test_is_avss_share").expect("Execution failed");
    assert_eq!(
        result,
        Value::Bool(true),
        "Should recognize AVSS share object"
    );
}

/// Test that Avss.get_commitment(share, 0) returns the public key (commitment[0])
#[test]
fn test_avss_get_public_key_via_commitment_zero() {
    setup_test_tracing();

    let mut vm = VirtualMachine::new();
    let party_id = 2usize;
    let threshold = 1;

    let (share_bytes, commitment_bytes, expected_public_key) =
        create_mock_avss_share(party_id, threshold);

    let obj_id = create_vm_avss_share(
        &mut vm,
        "pk_test_key",
        share_bytes,
        commitment_bytes.clone(),
        party_id,
    );

    let get_public_key_fn = VMFunction::new(
        "get_public_key".to_string(),
        vec![],
        Vec::new(),
        None,
        4,
        vec![
            Instruction::LDI(0, Value::from(ObjectRef::new(obj_id))),
            Instruction::LDI(1, Value::I64(0)), // commitment index 0 = public key
            Instruction::PUSHARG(0),
            Instruction::PUSHARG(1),
            Instruction::CALL("Avss.get_commitment".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    vm.register_function(get_public_key_fn);

    let result = vm.execute("get_public_key").expect("Execution failed");

    match result {
        Value::Array(arr_id) => {
            let pk_bytes = read_vm_table_byte_array(&mut vm, arr_id.id()).unwrap();
            let len = pk_bytes.len();
            assert!(len > 0, "Public key should have non-zero length");

            let retrieved_pk = G1::deserialize_compressed(&pk_bytes[..])
                .expect("Failed to deserialize public key");
            assert_eq!(
                retrieved_pk, expected_public_key,
                "Retrieved public key should match expected"
            );
        }
        other => panic!("Expected Array result, got: {:?}", other),
    }
}

/// Test Avss.get_commitment builtin for arbitrary index
#[test]
fn test_avss_get_commitment_builtin() {
    setup_test_tracing();

    let mut vm = VirtualMachine::new();
    let party_id = 0usize;
    let threshold = 2; // This gives us 3 commitments (degree + 1)

    let (share_bytes, commitment_bytes, _) = create_mock_avss_share(party_id, threshold);

    let obj_id = create_vm_avss_share(
        &mut vm,
        "commitment_test_key",
        share_bytes,
        commitment_bytes.clone(),
        party_id,
    );

    let get_commitment_fn = VMFunction::new(
        "get_commitment_1".to_string(),
        vec![],
        Vec::new(),
        None,
        4,
        vec![
            Instruction::LDI(0, Value::from(ObjectRef::new(obj_id))),
            Instruction::LDI(1, Value::I64(1)),
            Instruction::PUSHARG(0),
            Instruction::PUSHARG(1),
            Instruction::CALL("Avss.get_commitment".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    vm.register_function(get_commitment_fn);

    let result = vm.execute("get_commitment_1").expect("Execution failed");

    match result {
        Value::Array(arr_id) => {
            let bytes = read_vm_table_byte_array(&mut vm, arr_id.id()).unwrap();
            assert_eq!(
                bytes, commitment_bytes[1],
                "Commitment at index 1 should match"
            );
        }
        other => panic!("Expected Array result, got: {:?}", other),
    }
}

/// Test Avss.commitment_count builtin
#[test]
fn test_avss_commitment_count_builtin() {
    setup_test_tracing();

    let mut vm = VirtualMachine::new();
    let party_id = 0usize;
    let threshold = 3; // This gives us 4 commitments (degree + 1)

    let (share_bytes, commitment_bytes, _) = create_mock_avss_share(party_id, threshold);

    let expected_count = commitment_bytes.len();

    let obj_id = create_vm_avss_share(
        &mut vm,
        "count_test_key",
        share_bytes,
        commitment_bytes,
        party_id,
    );

    let get_count_fn = VMFunction::new(
        "get_commitment_count".to_string(),
        vec![],
        Vec::new(),
        None,
        4,
        vec![
            Instruction::LDI(0, Value::from(ObjectRef::new(obj_id))),
            Instruction::PUSHARG(0),
            Instruction::CALL("Avss.commitment_count".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    vm.register_function(get_count_fn);

    let result = vm
        .execute("get_commitment_count")
        .expect("Execution failed");

    assert_eq!(
        result,
        Value::I64(expected_count as i64),
        "Commitment count should match"
    );
}

/// Test Avss.get_key_name builtin
#[test]
fn test_avss_get_key_name_builtin() {
    setup_test_tracing();

    let mut vm = VirtualMachine::new();
    let key_name = "my_signing_key";
    let party_id = 0usize;
    let threshold = 1;

    let (share_bytes, commitment_bytes, _) = create_mock_avss_share(party_id, threshold);

    let obj_id = create_vm_avss_share(&mut vm, key_name, share_bytes, commitment_bytes, party_id);

    let get_key_name_fn = VMFunction::new(
        "get_key_name".to_string(),
        vec![],
        Vec::new(),
        None,
        4,
        vec![
            Instruction::LDI(0, Value::from(ObjectRef::new(obj_id))),
            Instruction::PUSHARG(0),
            Instruction::CALL("Avss.get_key_name".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    vm.register_function(get_key_name_fn);

    let result = vm.execute("get_key_name").expect("Execution failed");

    assert_eq!(
        result,
        Value::String(key_name.to_string()),
        "Key name should match"
    );
}

/// Example VM program that demonstrates AVSS public key extraction
#[test]
fn test_example_avss_public_key_program() {
    setup_test_tracing();
    tracing::info!("=== AVSS Public Key Extraction Example ===");

    let mut vm = VirtualMachine::new();

    let key_name = "signing_key";
    let party_id = 0usize;
    let threshold = 2;

    tracing::info!(
        "Creating mock AVSS result with key='{}', party_id={}, threshold={}",
        key_name,
        party_id,
        threshold
    );

    let (share_bytes, commitment_bytes, expected_public_key) =
        create_mock_avss_share(party_id, threshold);

    tracing::info!(
        "Generated {} commitments, public key size: {} bytes",
        commitment_bytes.len(),
        commitment_bytes[0].len()
    );

    let avss_share_obj_id =
        create_vm_avss_share(&mut vm, key_name, share_bytes, commitment_bytes, party_id);

    tracing::info!("Created AVSS share object with ID: {}", avss_share_obj_id);

    let main_fn = VMFunction::new(
        "main".to_string(),
        vec![],
        Vec::new(),
        None,
        4,
        vec![
            Instruction::LDI(0, Value::from(ObjectRef::new(avss_share_obj_id))),
            Instruction::LDI(1, Value::I64(0)), // commitment index 0 = public key
            Instruction::PUSHARG(0),
            Instruction::PUSHARG(1),
            Instruction::CALL("Avss.get_commitment".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    vm.register_function(main_fn);

    tracing::info!("Executing main program...");
    let result = vm.execute("main").expect("Execution failed");

    match result {
        Value::Array(arr_id) => {
            let pk_bytes = read_vm_table_byte_array(&mut vm, arr_id.id()).unwrap();
            let len = pk_bytes.len();
            tracing::info!("Got public key as byte array with {} bytes", len);

            let retrieved_pk = G1::deserialize_compressed(&pk_bytes[..])
                .expect("Failed to deserialize public key");

            assert_eq!(
                retrieved_pk, expected_public_key,
                "Public key should match expected value"
            );

            let pk_hex: String = pk_bytes.iter().map(|b| format!("{:02x}", b)).collect();
            tracing::info!("Public key (hex): {}", pk_hex);
            tracing::info!("=== Example completed successfully ===");
        }
        other => panic!("Expected Array result, got: {:?}", other),
    }
}

/// Test that non-AVSS objects are correctly rejected
#[test]
fn test_avss_builtin_rejects_non_avss_objects() {
    setup_test_tracing();

    let mut vm = VirtualMachine::new();

    // Create a regular object (not an AVSS share)
    let regular_obj_id = vm.create_object_ref().expect("create regular object").id();

    let test_fn = VMFunction::new(
        "test_reject".to_string(),
        vec![],
        Vec::new(),
        None,
        4,
        vec![
            Instruction::LDI(0, Value::from(ObjectRef::new(regular_obj_id))),
            Instruction::PUSHARG(0),
            Instruction::CALL("Avss.is_avss_share".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    vm.register_function(test_fn);

    let result = vm.execute("test_reject").expect("Execution failed");
    assert_eq!(
        result,
        Value::Bool(false),
        "Regular object should not be recognized as AVSS share"
    );
}

// ============================================================================
// End-to-End Test: 5 Parties AVSS Simulation
// ============================================================================

/// Simulate 5 parties running AVSS and producing consistent shares
fn simulate_avss_for_n_parties(n_parties: usize, threshold: usize) -> (SimulatedAvssShares, G1) {
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
    use ark_std::test_rng;

    let mut rng = test_rng();
    let secret = Fr::rand(&mut rng);

    let mut poly = DensePolynomial::rand(threshold, &mut rng);
    poly[0] = secret;

    let commitments: Vec<G1> = poly.coeffs.iter().map(|c| G1::generator() * c).collect();

    let commitment_bytes: Vec<Vec<u8>> = commitments
        .iter()
        .map(|c| {
            let mut bytes = Vec::new();
            c.into_affine()
                .serialize_compressed(&mut bytes)
                .expect("Failed to serialize commitment");
            bytes
        })
        .collect();

    let mut party_data = Vec::new();
    for party_id in 1..=n_parties {
        let x = Fr::from(party_id as u64);
        let share_value = poly.evaluate(&x);

        let mut share_bytes = Vec::new();
        share_value
            .serialize_compressed(&mut share_bytes)
            .expect("Failed to serialize share");

        party_data.push((share_bytes, commitment_bytes.clone()));
    }

    let public_key = commitments[0];

    (party_data, public_key)
}

/// End-to-end test: 5 parties run AVSS and extract public key
#[test]
fn test_e2e_5_parties_avss_public_key() {
    setup_test_tracing();
    tracing::info!("=== End-to-End AVSS Test: 5 Parties ===");

    let n_parties = 5;
    let threshold = 2;

    tracing::info!(
        "Step 1: Simulating AVSS with {} parties, threshold={}",
        n_parties,
        threshold
    );
    let (party_data, expected_public_key) = simulate_avss_for_n_parties(n_parties, threshold);

    tracing::info!(
        "AVSS produced {} commitments per party",
        party_data[0].1.len()
    );

    tracing::info!("Step 2: Creating VMs for each party");
    let mut party_vms: Vec<VirtualMachine> = Vec::new();

    for (party_id, (share_bytes, commitment_bytes)) in party_data.into_iter().enumerate() {
        let mut vm = VirtualMachine::new();

        let avss_share_id = create_vm_avss_share(
            &mut vm,
            "shared_key",
            share_bytes,
            commitment_bytes,
            party_id,
        );

        let extract_pk_fn = VMFunction::new(
            "get_avss_public_key".to_string(),
            vec![],
            Vec::new(),
            None,
            4,
            vec![
                Instruction::LDI(0, Value::from(ObjectRef::new(avss_share_id))),
                Instruction::LDI(1, Value::I64(0)), // commitment index 0 = public key
                Instruction::PUSHARG(0),
                Instruction::PUSHARG(1),
                Instruction::CALL("Avss.get_commitment".to_string()),
                Instruction::RET(0),
            ],
            HashMap::new(),
        );

        vm.register_function(extract_pk_fn);
        party_vms.push(vm);

        tracing::info!("Party {} VM initialized with AVSS share", party_id);
    }

    tracing::info!("Step 3: Executing VM programs on all parties");
    let mut extracted_public_keys: Vec<G1> = Vec::new();

    for (party_id, vm) in party_vms.iter_mut().enumerate() {
        let result = vm.execute("get_avss_public_key").expect("Execution failed");

        let pk_bytes = match result {
            Value::Array(arr_ref) => read_vm_table_byte_array(vm, arr_ref.id()).unwrap(),
            other => panic!("Party {} got unexpected result: {:?}", party_id, other),
        };

        let pk =
            G1::deserialize_compressed(&pk_bytes[..]).expect("Failed to deserialize public key");

        extracted_public_keys.push(pk);
        tracing::info!(
            "Party {} extracted public key ({} bytes)",
            party_id,
            pk_bytes.len()
        );
    }

    tracing::info!("Step 4: Verifying all parties have consistent public key");
    for (party_id, pk) in extracted_public_keys.iter().enumerate() {
        assert_eq!(
            *pk, expected_public_key,
            "Party {} public key doesn't match expected",
            party_id
        );
    }

    for i in 1..n_parties {
        assert_eq!(
            extracted_public_keys[i], extracted_public_keys[0],
            "Party {} public key doesn't match party 0",
            i
        );
    }

    tracing::info!("All {} parties have consistent public key!", n_parties);

    tracing::info!("Step 5: Output client receives and verifies public key");

    let mut pk_transmission_bytes = Vec::new();
    expected_public_key
        .into_affine()
        .serialize_compressed(&mut pk_transmission_bytes)
        .expect("Failed to serialize public key");

    let received_pk = G1::deserialize_compressed(&pk_transmission_bytes[..])
        .expect("Output client failed to deserialize public key");

    assert_eq!(
        received_pk, expected_public_key,
        "Output client received incorrect public key"
    );

    tracing::info!(
        "Output client successfully received public key ({} bytes)",
        pk_transmission_bytes.len()
    );

    let pk_hex: String = pk_transmission_bytes
        .iter()
        .take(16)
        .map(|b| format!("{:02x}", b))
        .collect();
    tracing::info!("Public key (first 16 bytes hex): {}...", pk_hex);
    tracing::info!("=== End-to-End Test Completed Successfully ===");
}

/// Test that demonstrates the complete AVSS workflow with input and output clients
#[test]
fn test_e2e_avss_with_input_output_clients() {
    setup_test_tracing();
    tracing::info!("=== AVSS with Input/Output Clients ===");

    let n_parties = 5;
    let threshold = 2;

    let input_client_ids = vec![100usize, 101, 102];
    tracing::info!(
        "Input clients: {:?} would contribute to the distributed secret",
        input_client_ids
    );

    let (party_data, expected_public_key) = simulate_avss_for_n_parties(n_parties, threshold);

    let mut party_vms: Vec<VirtualMachine> = Vec::new();
    for (party_id, (share_bytes, commitment_bytes)) in party_data.into_iter().enumerate() {
        let mut vm = VirtualMachine::new();

        let avss_share_id = create_vm_avss_share(
            &mut vm,
            "client_key",
            share_bytes,
            commitment_bytes,
            party_id,
        );

        let main_fn = VMFunction::new(
            "main".to_string(),
            vec![],
            Vec::new(),
            None,
            8,
            vec![
                Instruction::LDI(0, Value::from(ObjectRef::new(avss_share_id))),
                Instruction::LDI(1, Value::I64(0)), // commitment index 0 = public key
                Instruction::PUSHARG(0),
                Instruction::PUSHARG(1),
                Instruction::CALL("Avss.get_commitment".to_string()),
                Instruction::RET(0),
            ],
            HashMap::new(),
        );

        vm.register_function(main_fn);
        party_vms.push(vm);
    }

    let mut results: Vec<Vec<u8>> = Vec::new();
    for (party_id, vm) in party_vms.iter_mut().enumerate() {
        let result = vm.execute("main").expect("Execution failed");

        let pk_bytes = match result {
            Value::Array(arr_ref) => read_vm_table_byte_array(vm, arr_ref.id()).unwrap(),
            other => panic!("Unexpected result: {:?}", other),
        };

        results.push(pk_bytes);
        tracing::info!("Party {} completed VM execution", party_id);
    }

    let output_client_id = 200usize;
    tracing::info!(
        "Output client {} receiving public key from parties",
        output_client_id
    );

    for i in 1..n_parties {
        assert_eq!(results[i], results[0], "Inconsistent results from parties");
    }

    let final_pk = G1::deserialize_compressed(&results[0][..])
        .expect("Failed to deserialize final public key");

    assert_eq!(final_pk, expected_public_key);

    tracing::info!(
        "Output client {} successfully received consistent public key from all {} parties",
        output_client_id,
        n_parties
    );
    tracing::info!("=== Test Completed Successfully ===");
}
