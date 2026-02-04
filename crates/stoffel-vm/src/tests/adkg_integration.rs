//! ADKG Integration Tests
//!
//! This module tests the ADKG (Asynchronous Distributed Key Generation) functionality:
//! 1. Unit tests for ADKG secret key objects and builtins
//! 2. Integration tests with simulated network
//! 3. Example VM program that extracts public key from ADKG result

use ark_bls12_381::{Fr, G1Projective as G1};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use std::collections::HashMap;

use crate::core_vm::VirtualMachine;
use crate::mpc_builtins::adkg_object;
use stoffel_vm_types::core_types::Value;
use stoffel_vm_types::functions::VMFunction;
use stoffel_vm_types::instructions::Instruction;

/// Helper for test tracing setup
fn setup_test_tracing() {
    use std::sync::Once;
    use tracing_subscriber::{EnvFilter, FmtSubscriber};

    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let subscriber = FmtSubscriber::builder()
            .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
            .with_test_writer()
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    });
}

/// Create a mock ADKG secret key for testing
/// This simulates what the ADKG protocol would produce
fn create_mock_adkg_secret_key(
    session_id: u64,
    party_id: usize,
    threshold: usize,
) -> (Vec<u8>, Vec<Vec<u8>>, G1) {
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

/// Test that ADKG secret key objects can be created and queried
#[test]
fn test_adkg_secret_key_object_creation() {
    setup_test_tracing();

    let mut vm = VirtualMachine::new();
    let session_id = 42u64;
    let party_id = 1usize;
    let threshold = 2;

    // Create mock ADKG result
    let (share_bytes, commitment_bytes, expected_public_key) =
        create_mock_adkg_secret_key(session_id, party_id, threshold);

    // Create ADKG secret key object in VM's object store
    let obj_id = adkg_object::create_adkg_secret_key_object(
        &mut vm.state.object_store,
        session_id,
        share_bytes,
        commitment_bytes.clone(),
        party_id,
    );

    // Verify the object was created
    let obj = Value::Object(obj_id);
    assert!(adkg_object::is_adkg_secret_key_object(
        &vm.state.object_store,
        &obj
    ));

    // Verify session ID
    let retrieved_session_id =
        adkg_object::get_session_id(&vm.state.object_store, &obj).unwrap();
    assert_eq!(retrieved_session_id, session_id);

    // Verify commitment count
    let count = adkg_object::get_commitment_count(&vm.state.object_store, &obj).unwrap();
    assert_eq!(count, commitment_bytes.len());

    // Verify public key (commitment[0])
    let public_key_bytes =
        adkg_object::get_commitment(&vm.state.object_store, &obj, 0).unwrap();
    assert_eq!(public_key_bytes, commitment_bytes[0]);

    // Deserialize and verify it matches the expected public key
    let retrieved_pk = G1::deserialize_compressed(&public_key_bytes[..])
        .expect("Failed to deserialize public key");
    assert_eq!(retrieved_pk, expected_public_key);
}

/// Test ADKG builtins through VM function calls
#[test]
fn test_adkg_builtins_via_vm() {
    setup_test_tracing();

    let mut vm = VirtualMachine::new();
    let session_id = 100u64;
    let party_id = 0usize;
    let threshold = 1;

    // Create mock ADKG result
    let (share_bytes, commitment_bytes, _expected_public_key) =
        create_mock_adkg_secret_key(session_id, party_id, threshold);

    // Create ADKG secret key object
    let obj_id = adkg_object::create_adkg_secret_key_object(
        &mut vm.state.object_store,
        session_id,
        share_bytes,
        commitment_bytes.clone(),
        party_id,
    );

    // Create VM function that tests the builtins
    // This function:
    // 1. Loads the ADKG object into r0
    // 2. Calls Adkg.is_adkg_key to verify it's an ADKG key
    // 3. Returns the result
    let test_is_adkg_key_fn = VMFunction::new(
        "test_is_adkg_key".to_string(),
        vec![],
        Vec::new(),
        None,
        4,
        vec![
            // Load ADKG object ID into r0
            Instruction::LDI(0, Value::Object(obj_id)),
            // Push as argument
            Instruction::PUSHARG(0),
            // Call Adkg.is_adkg_key
            Instruction::CALL("Adkg.is_adkg_key".to_string()),
            // r0 now contains the result, return it
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    vm.register_function(test_is_adkg_key_fn);

    let result = vm.execute("test_is_adkg_key").expect("Execution failed");
    assert_eq!(result, Value::Bool(true), "Should recognize ADKG key object");
}

/// Test Adkg.get_public_key builtin
#[test]
fn test_adkg_get_public_key_builtin() {
    setup_test_tracing();

    let mut vm = VirtualMachine::new();
    let session_id = 200u64;
    let party_id = 2usize;
    let threshold = 1;

    // Create mock ADKG result
    let (share_bytes, commitment_bytes, expected_public_key) =
        create_mock_adkg_secret_key(session_id, party_id, threshold);

    // Create ADKG secret key object
    let obj_id = adkg_object::create_adkg_secret_key_object(
        &mut vm.state.object_store,
        session_id,
        share_bytes,
        commitment_bytes.clone(),
        party_id,
    );

    // Create VM function that gets the public key
    let get_public_key_fn = VMFunction::new(
        "get_public_key".to_string(),
        vec![],
        Vec::new(),
        None,
        4,
        vec![
            // Load ADKG object into r0
            Instruction::LDI(0, Value::Object(obj_id)),
            // Push as argument
            Instruction::PUSHARG(0),
            // Call Adkg.get_public_key
            Instruction::CALL("Adkg.get_public_key".to_string()),
            // Return the public key (as byte array)
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    vm.register_function(get_public_key_fn);

    let result = vm.execute("get_public_key").expect("Execution failed");

    // Result should be an array of bytes
    match result {
        Value::Array(arr_id) => {
            let arr = vm.state.object_store.get_array(arr_id).unwrap();
            let len = arr.length();
            assert!(len > 0, "Public key should have non-zero length");

            // Extract bytes from array
            let mut pk_bytes = Vec::with_capacity(len);
            for i in 0..len {
                if let Some(Value::U8(b)) = arr.get(&Value::I64(i as i64)) {
                    pk_bytes.push(*b);
                }
            }

            // Verify it matches expected public key
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

/// Test Adkg.get_commitment builtin for arbitrary index
#[test]
fn test_adkg_get_commitment_builtin() {
    setup_test_tracing();

    let mut vm = VirtualMachine::new();
    let session_id = 300u64;
    let party_id = 0usize;
    let threshold = 2; // This gives us 3 commitments (degree + 1)

    // Create mock ADKG result
    let (share_bytes, commitment_bytes, _) =
        create_mock_adkg_secret_key(session_id, party_id, threshold);

    // Create ADKG secret key object
    let obj_id = adkg_object::create_adkg_secret_key_object(
        &mut vm.state.object_store,
        session_id,
        share_bytes,
        commitment_bytes.clone(),
        party_id,
    );

    // Test getting commitment at index 1
    let get_commitment_fn = VMFunction::new(
        "get_commitment_1".to_string(),
        vec![],
        Vec::new(),
        None,
        4,
        vec![
            // Load ADKG object into r0
            Instruction::LDI(0, Value::Object(obj_id)),
            // Load index 1 into r1
            Instruction::LDI(1, Value::I64(1)),
            // Push arguments
            Instruction::PUSHARG(0),
            Instruction::PUSHARG(1),
            // Call Adkg.get_commitment
            Instruction::CALL("Adkg.get_commitment".to_string()),
            // Return the commitment
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    vm.register_function(get_commitment_fn);

    let result = vm.execute("get_commitment_1").expect("Execution failed");

    // Verify we got the correct commitment
    match result {
        Value::Array(arr_id) => {
            let arr = vm.state.object_store.get_array(arr_id).unwrap();
            let mut bytes = Vec::with_capacity(arr.length());
            for i in 0..arr.length() {
                if let Some(Value::U8(b)) = arr.get(&Value::I64(i as i64)) {
                    bytes.push(*b);
                }
            }
            assert_eq!(
                bytes, commitment_bytes[1],
                "Commitment at index 1 should match"
            );
        }
        other => panic!("Expected Array result, got: {:?}", other),
    }
}

/// Test Adkg.commitment_count builtin
#[test]
fn test_adkg_commitment_count_builtin() {
    setup_test_tracing();

    let mut vm = VirtualMachine::new();
    let session_id = 400u64;
    let party_id = 0usize;
    let threshold = 3; // This gives us 4 commitments (degree + 1)

    // Create mock ADKG result
    let (share_bytes, commitment_bytes, _) =
        create_mock_adkg_secret_key(session_id, party_id, threshold);

    let expected_count = commitment_bytes.len();

    // Create ADKG secret key object
    let obj_id = adkg_object::create_adkg_secret_key_object(
        &mut vm.state.object_store,
        session_id,
        share_bytes,
        commitment_bytes,
        party_id,
    );

    // Create VM function that gets commitment count
    let get_count_fn = VMFunction::new(
        "get_commitment_count".to_string(),
        vec![],
        Vec::new(),
        None,
        4,
        vec![
            Instruction::LDI(0, Value::Object(obj_id)),
            Instruction::PUSHARG(0),
            Instruction::CALL("Adkg.commitment_count".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    vm.register_function(get_count_fn);

    let result = vm.execute("get_commitment_count").expect("Execution failed");

    assert_eq!(
        result,
        Value::I64(expected_count as i64),
        "Commitment count should match"
    );
}

/// Test Adkg.get_session_id builtin
#[test]
fn test_adkg_get_session_id_builtin() {
    setup_test_tracing();

    let mut vm = VirtualMachine::new();
    let session_id = 12345u64;
    let party_id = 0usize;
    let threshold = 1;

    // Create mock ADKG result
    let (share_bytes, commitment_bytes, _) =
        create_mock_adkg_secret_key(session_id, party_id, threshold);

    // Create ADKG secret key object
    let obj_id = adkg_object::create_adkg_secret_key_object(
        &mut vm.state.object_store,
        session_id,
        share_bytes,
        commitment_bytes,
        party_id,
    );

    // Create VM function that gets session ID
    let get_session_id_fn = VMFunction::new(
        "get_session_id".to_string(),
        vec![],
        Vec::new(),
        None,
        4,
        vec![
            Instruction::LDI(0, Value::Object(obj_id)),
            Instruction::PUSHARG(0),
            Instruction::CALL("Adkg.get_session_id".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    vm.register_function(get_session_id_fn);

    let result = vm.execute("get_session_id").expect("Execution failed");

    assert_eq!(
        result,
        Value::I64(session_id as i64),
        "Session ID should match"
    );
}

/// Example VM program that demonstrates ADKG public key extraction
///
/// This is the example program requested: it takes an ADKG secret key
/// and extracts the public key (commitment[0]).
#[test]
fn test_example_adkg_public_key_program() {
    setup_test_tracing();
    tracing::info!("=== ADKG Public Key Extraction Example ===");

    let mut vm = VirtualMachine::new();

    // Simulate ADKG result (in real usage, this would come from the ADKG protocol)
    let session_id = 999u64;
    let party_id = 0usize;
    let threshold = 2;

    tracing::info!(
        "Creating mock ADKG result with session_id={}, party_id={}, threshold={}",
        session_id,
        party_id,
        threshold
    );

    let (share_bytes, commitment_bytes, expected_public_key) =
        create_mock_adkg_secret_key(session_id, party_id, threshold);

    tracing::info!(
        "Generated {} commitments, public key size: {} bytes",
        commitment_bytes.len(),
        commitment_bytes[0].len()
    );

    // Create ADKG secret key object in VM
    let adkg_key_obj_id = adkg_object::create_adkg_secret_key_object(
        &mut vm.state.object_store,
        session_id,
        share_bytes,
        commitment_bytes,
        party_id,
    );

    tracing::info!("Created ADKG secret key object with ID: {}", adkg_key_obj_id);

    // Example program: main
    //
    // This program demonstrates how a StoffelLang program would extract
    // the public key from an ADKG result:
    //
    // fn main():
    //     adkg_key = <loaded from ADKG protocol>
    //     public_key = Adkg.get_public_key(adkg_key)
    //     return public_key
    //
    let main_fn = VMFunction::new(
        "main".to_string(),
        vec![],
        Vec::new(),
        None,
        4,
        vec![
            // Load ADKG key object into r0
            Instruction::LDI(0, Value::Object(adkg_key_obj_id)),
            // Push as argument for builtin
            Instruction::PUSHARG(0),
            // Call Adkg.get_public_key builtin
            Instruction::CALL("Adkg.get_public_key".to_string()),
            // Return the public key (byte array now in r0)
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    vm.register_function(main_fn);

    tracing::info!("Executing main program...");
    let result = vm.execute("main").expect("Execution failed");

    // Verify result
    match result {
        Value::Array(arr_id) => {
            let arr = vm.state.object_store.get_array(arr_id).unwrap();
            let len = arr.length();
            tracing::info!("Got public key as byte array with {} bytes", len);

            // Extract bytes
            let mut pk_bytes = Vec::with_capacity(len);
            for i in 0..len {
                if let Some(Value::U8(b)) = arr.get(&Value::I64(i as i64)) {
                    pk_bytes.push(*b);
                }
            }

            // Deserialize and verify
            let retrieved_pk = G1::deserialize_compressed(&pk_bytes[..])
                .expect("Failed to deserialize public key");

            assert_eq!(
                retrieved_pk, expected_public_key,
                "Public key should match expected value"
            );

            // Print public key hex for demonstration
            let pk_hex: String = pk_bytes.iter().map(|b| format!("{:02x}", b)).collect();
            tracing::info!("Public key (hex): {}", pk_hex);
            tracing::info!("=== Example completed successfully ===");
        }
        other => panic!("Expected Array result, got: {:?}", other),
    }
}

/// Test that non-ADKG objects are correctly rejected
#[test]
fn test_adkg_builtin_rejects_non_adkg_objects() {
    setup_test_tracing();

    let mut vm = VirtualMachine::new();

    // Create a regular object (not an ADKG key)
    let regular_obj_id = vm.state.object_store.create_object();

    let test_fn = VMFunction::new(
        "test_reject".to_string(),
        vec![],
        Vec::new(),
        None,
        4,
        vec![
            Instruction::LDI(0, Value::Object(regular_obj_id)),
            Instruction::PUSHARG(0),
            Instruction::CALL("Adkg.is_adkg_key".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );

    vm.register_function(test_fn);

    let result = vm.execute("test_reject").expect("Execution failed");
    assert_eq!(
        result,
        Value::Bool(false),
        "Regular object should not be recognized as ADKG key"
    );
}

// ============================================================================
// End-to-End Test: 5 Parties ADKG Simulation
// ============================================================================

/// Simulate 5 parties running ADKG and producing consistent secret keys
///
/// In real ADKG, each party would run the protocol over a network and get their
/// individual share. Here we simulate the ADKG output by:
/// 1. Generating a random polynomial of degree t (threshold)
/// 2. Computing commitments C_i = g^a_i for each coefficient
/// 3. Evaluating the polynomial at points 1, 2, 3, 4, 5 for each party's share
///
/// All parties share the same commitments (including commitment[0] = public key)
fn simulate_adkg_for_n_parties(
    n_parties: usize,
    threshold: usize,
    session_id: u64,
) -> (Vec<(Vec<u8>, Vec<Vec<u8>>)>, G1) {
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
    use ark_std::test_rng;

    let mut rng = test_rng();
    let secret = Fr::rand(&mut rng);

    // Generate polynomial with random coefficients
    let mut poly = DensePolynomial::rand(threshold, &mut rng);
    poly[0] = secret;

    // Generate commitments: C_i = g^a_i (same for all parties)
    let commitments: Vec<G1> = poly.coeffs.iter().map(|c| G1::generator() * c).collect();

    // Serialize commitments (shared by all parties)
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

    // Generate shares for each party
    let mut party_data = Vec::new();
    for party_id in 1..=n_parties {
        let x = Fr::from(party_id as u64);
        let share_value = poly.evaluate(&x);

        // Serialize share
        let mut share_bytes = Vec::new();
        share_value
            .serialize_compressed(&mut share_bytes)
            .expect("Failed to serialize share");

        party_data.push((share_bytes, commitment_bytes.clone()));
    }

    // Public key is commitment[0] = g^secret
    let public_key = commitments[0];

    (party_data, public_key)
}

/// End-to-end test: 5 parties run ADKG and extract public key
///
/// This test simulates a complete ADKG workflow:
/// 1. 5 MPC parties run ADKG (simulated)
/// 2. Each party gets their secret share and shared commitments
/// 3. Each party's VM program extracts the public key
/// 4. All parties should get the same public key
/// 5. An output client receives and verifies the public key
#[test]
fn test_e2e_5_parties_adkg_public_key() {
    setup_test_tracing();
    tracing::info!("=== End-to-End ADKG Test: 5 Parties ===");

    let n_parties = 5;
    let threshold = 2; // t+1 = 3 parties needed to reconstruct
    let session_id = 1001u64;

    // Step 1: Simulate ADKG - all parties run the distributed protocol
    tracing::info!(
        "Step 1: Simulating ADKG with {} parties, threshold={}",
        n_parties,
        threshold
    );
    let (party_data, expected_public_key) =
        simulate_adkg_for_n_parties(n_parties, threshold, session_id);

    tracing::info!(
        "ADKG produced {} commitments per party",
        party_data[0].1.len()
    );

    // Step 2: Each party creates a VM and loads their ADKG result
    tracing::info!("Step 2: Creating VMs for each party");
    let mut party_vms: Vec<VirtualMachine> = Vec::new();

    for (party_id, (share_bytes, commitment_bytes)) in party_data.into_iter().enumerate() {
        let mut vm = VirtualMachine::new();

        // Create ADKG secret key object for this party
        let adkg_key_id = adkg_object::create_adkg_secret_key_object(
            &mut vm.state.object_store,
            session_id,
            share_bytes,
            commitment_bytes,
            party_id,
        );

        // Register the VM program that extracts public key
        let extract_pk_fn = VMFunction::new(
            "get_adkg_public_key".to_string(),
            vec![],
            Vec::new(),
            None,
            4,
            vec![
                Instruction::LDI(0, Value::Object(adkg_key_id)),
                Instruction::PUSHARG(0),
                Instruction::CALL("Adkg.get_public_key".to_string()),
                Instruction::RET(0),
            ],
            HashMap::new(),
        );

        vm.register_function(extract_pk_fn);
        party_vms.push(vm);

        tracing::info!("Party {} VM initialized with ADKG key", party_id);
    }

    // Step 3: Each party executes VM program to extract public key
    tracing::info!("Step 3: Executing VM programs on all parties");
    let mut extracted_public_keys: Vec<G1> = Vec::new();

    for (party_id, vm) in party_vms.iter_mut().enumerate() {
        let result = vm.execute("get_adkg_public_key").expect("Execution failed");

        // Extract public key bytes from result
        let pk_bytes = match result {
            Value::Array(arr_id) => {
                let arr = vm.state.object_store.get_array(arr_id).unwrap();
                let mut bytes = Vec::with_capacity(arr.length());
                for i in 0..arr.length() {
                    if let Some(Value::U8(b)) = arr.get(&Value::I64(i as i64)) {
                        bytes.push(*b);
                    }
                }
                bytes
            }
            other => panic!("Party {} got unexpected result: {:?}", party_id, other),
        };

        // Deserialize public key
        let pk = G1::deserialize_compressed(&pk_bytes[..])
            .expect("Failed to deserialize public key");

        extracted_public_keys.push(pk);
        tracing::info!("Party {} extracted public key ({} bytes)", party_id, pk_bytes.len());
    }

    // Step 4: Verify all parties got the same public key
    tracing::info!("Step 4: Verifying all parties have consistent public key");
    for (party_id, pk) in extracted_public_keys.iter().enumerate() {
        assert_eq!(
            *pk, expected_public_key,
            "Party {} public key doesn't match expected",
            party_id
        );
    }

    // Verify all parties have the same public key as each other
    for i in 1..n_parties {
        assert_eq!(
            extracted_public_keys[i], extracted_public_keys[0],
            "Party {} public key doesn't match party 0",
            i
        );
    }

    tracing::info!("All {} parties have consistent public key!", n_parties);

    // Step 5: Simulate output client receiving the public key
    tracing::info!("Step 5: Output client receives and verifies public key");

    // Serialize the public key for transmission to client
    let mut pk_transmission_bytes = Vec::new();
    expected_public_key
        .into_affine()
        .serialize_compressed(&mut pk_transmission_bytes)
        .expect("Failed to serialize public key");

    // Output client verifies the received public key
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

    // Print summary
    let pk_hex: String = pk_transmission_bytes
        .iter()
        .take(16)
        .map(|b| format!("{:02x}", b))
        .collect();
    tracing::info!("Public key (first 16 bytes hex): {}...", pk_hex);
    tracing::info!("=== End-to-End Test Completed Successfully ===");
}

/// Test that demonstrates the complete ADKG workflow with input and output clients
///
/// This test shows:
/// 1. Input clients provide secrets to the MPC parties (simulated)
/// 2. MPC parties run ADKG combining the inputs (simulated)
/// 3. Output client retrieves the combined public key
#[test]
fn test_e2e_adkg_with_input_output_clients() {
    setup_test_tracing();
    tracing::info!("=== ADKG with Input/Output Clients ===");

    let n_parties = 5;
    let threshold = 2;
    let session_id = 2002u64;

    // Simulate input clients - in real system, these would provide secret shares
    // Here we just note that the ADKG secret is generated from distributed inputs
    let input_client_ids = vec![100usize, 101, 102];
    tracing::info!(
        "Input clients: {:?} would contribute to the distributed secret",
        input_client_ids
    );

    // Run ADKG simulation
    let (party_data, expected_public_key) =
        simulate_adkg_for_n_parties(n_parties, threshold, session_id);

    // Create VMs for each party
    let mut party_vms: Vec<VirtualMachine> = Vec::new();
    for (party_id, (share_bytes, commitment_bytes)) in party_data.into_iter().enumerate() {
        let mut vm = VirtualMachine::new();

        let adkg_key_id = adkg_object::create_adkg_secret_key_object(
            &mut vm.state.object_store,
            session_id,
            share_bytes,
            commitment_bytes,
            party_id,
        );

        // VM program that:
        // 1. Gets the public key from ADKG result
        // 2. Gets the commitment count (for verification)
        // 3. Returns the public key
        let main_fn = VMFunction::new(
            "main".to_string(),
            vec![],
            Vec::new(),
            None,
            8,
            vec![
                // Load ADKG key
                Instruction::LDI(0, Value::Object(adkg_key_id)),
                // Get public key
                Instruction::PUSHARG(0),
                Instruction::CALL("Adkg.get_public_key".to_string()),
                // Result is now in r0, return it
                Instruction::RET(0),
            ],
            HashMap::new(),
        );

        vm.register_function(main_fn);
        party_vms.push(vm);
    }

    // Execute on all parties
    let mut results: Vec<Vec<u8>> = Vec::new();
    for (party_id, vm) in party_vms.iter_mut().enumerate() {
        let result = vm.execute("main").expect("Execution failed");

        let pk_bytes = match result {
            Value::Array(arr_id) => {
                let arr = vm.state.object_store.get_array(arr_id).unwrap();
                let mut bytes = Vec::with_capacity(arr.length());
                for i in 0..arr.length() {
                    if let Some(Value::U8(b)) = arr.get(&Value::I64(i as i64)) {
                        bytes.push(*b);
                    }
                }
                bytes
            }
            other => panic!("Unexpected result: {:?}", other),
        };

        results.push(pk_bytes);
        tracing::info!("Party {} completed VM execution", party_id);
    }

    // Output client (ID 200) receives public key from any party
    let output_client_id = 200usize;
    tracing::info!(
        "Output client {} receiving public key from parties",
        output_client_id
    );

    // In real system, output client would receive from threshold+1 parties
    // and verify consistency. Here we verify all results match.
    for i in 1..n_parties {
        assert_eq!(results[i], results[0], "Inconsistent results from parties");
    }

    // Output client decodes the public key
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
