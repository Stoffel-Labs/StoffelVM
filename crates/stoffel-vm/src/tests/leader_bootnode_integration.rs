//! Leader Bootnode Integration Test
//!
//! This test demonstrates the leader bootnode pattern where one party
//! acts as both bootnode and participant:
//!
//! 1. Leader starts bootnode in background and registers as party 0
//! 2. Other parties connect to leader's bootnode
//! 3. Session is established with shared instance_id
//! 4. Program bytes are synced via bootnode
//! 5. All parties execute fixed-point matrix averaging
//!
//! Matrix size: 6 elements (e.g., 2x3 or 3x2 matrix)

use ark_bls12_381::Fr;
use ark_std::rand::{Rng, SeedableRng};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use stoffelmpc_mpc::common::{MPCProtocol, PreprocessingMPCProtocol};
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelnet::network_utils::ClientId;
use tracing::info;

use crate::core_vm::VirtualMachine;
use crate::net::hb_engine::HoneyBadgerMpcEngine;
use crate::net::program_id_from_bytes;
use crate::tests::mpc_multiplication_integration::{
    setup_honeybadger_quic_clients, setup_honeybadger_quic_network, HoneyBadgerQuicConfig,
};
use stoffel_vm_types::compiled_binary::CompiledBinary;
use stoffel_vm_types::core_types::Value;
use stoffel_vm_types::functions::VMFunction;
use stoffel_vm_types::instructions::Instruction;

// Matrix configuration: 6 elements (2x3 or 3x2)
const MATRIX_SIZE: usize = 6;
const MATRIX_ROWS: usize = 2;
const MATRIX_COLS: usize = 3;

// Fixed-point configuration: 16 fractional bits (scale = 2^16 = 65536)
const FIXED_POINT_FRACTIONAL_BITS: u32 = 16;
const FIXED_POINT_SCALE: i64 = 1 << FIXED_POINT_FRACTIONAL_BITS;

// Number of registers used by the program
const PROGRAM_REGISTERS: usize = 24;

fn init_crypto_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }
    });
}

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

/// Build a federated averaging program that computes element-wise averages.
///
/// This program:
/// 1. Gets the number of clients from ClientStore
/// 2. Creates a result array
/// 3. For each element position:
///    a. Loads fixed-point shares from all clients
///    b. Sums shares (as secret shares)
///    c. Reveals the sum
///    d. Divides by num_clients to get average
///    e. Stores result in array
/// 4. Returns the result array
fn build_federated_average_program_6() -> (Vec<Instruction>, HashMap<String, usize>) {
    let matrix_size = MATRIX_SIZE;
    let mut instructions = Vec::new();
    let mut labels = HashMap::new();

    // Register allocation:
    // reg0 = general purpose / return value / function results
    // reg1 = num_clients
    // reg2 = client index (loop counter for summing)
    // reg3 = constant 1
    // reg4 = matrix_size constant
    // reg5 = element index (outer loop for element-wise processing)
    // reg6 = result array reference
    // reg7 = current element sum/average (clear register for revealed value)
    // reg8 = scratch
    // reg16 = current element sum accumulator (secret share)
    // reg17 = scratch for shares

    // Step 1: Get number of clients and initialize constants
    instructions.push(Instruction::CALL("ClientStore.get_number_clients".to_string()));
    instructions.push(Instruction::MOV(1, 0)); // reg1 = num_clients

    instructions.push(Instruction::LDI(3, Value::I64(1))); // reg3 = 1
    instructions.push(Instruction::LDI(4, Value::I64(matrix_size as i64))); // reg4 = matrix_size

    // Step 2: Create result array to store revealed averaged values
    instructions.push(Instruction::LDI(0, Value::I64(matrix_size as i64))); // capacity
    instructions.push(Instruction::PUSHARG(0));
    instructions.push(Instruction::CALL("create_array".to_string()));
    instructions.push(Instruction::MOV(6, 0)); // reg6 = result array

    // Step 3: Element-wise loop - for each element position
    instructions.push(Instruction::LDI(5, Value::I64(0))); // reg5 = 0 (element index)

    let elem_loop = "fp_elem_loop".to_string();
    let elem_process = "fp_elem_process".to_string();
    let elem_done = "fp_elem_done".to_string();
    let client_sum_loop = "fp_client_sum_loop".to_string();
    let client_sum_process = "fp_client_sum_process".to_string();
    let client_sum_done = "fp_client_sum_done".to_string();

    // === ELEMENT LOOP: process each matrix position ===
    labels.insert(elem_loop.clone(), instructions.len());
    instructions.push(Instruction::CMP(5, 4)); // Compare element_idx with matrix_size
    instructions.push(Instruction::JMPLT(elem_process.clone()));
    instructions.push(Instruction::JMP(elem_done.clone()));

    labels.insert(elem_process.clone(), instructions.len());

    // Initialize sum accumulator for this element position
    // Load first client's share to initialize the secret accumulator
    instructions.push(Instruction::LDI(0, Value::I64(0))); // client_index = 0
    instructions.push(Instruction::PUSHARG(0));
    instructions.push(Instruction::PUSHARG(5)); // element_index
    instructions.push(Instruction::CALL("ClientStore.take_share_fixed".to_string()));
    instructions.push(Instruction::MOV(16, 0)); // reg16 = first share (accumulator)

    // Sum remaining clients for this element
    instructions.push(Instruction::LDI(2, Value::I64(1))); // reg2 = 1 (start from client 1)

    // === CLIENT SUM LOOP: sum shares from all clients for this element ===
    labels.insert(client_sum_loop.clone(), instructions.len());
    instructions.push(Instruction::CMP(2, 1)); // Compare client_idx with num_clients
    instructions.push(Instruction::JMPLT(client_sum_process.clone()));
    instructions.push(Instruction::JMP(client_sum_done.clone()));

    labels.insert(client_sum_process.clone(), instructions.len());
    // Get share for current client, current element
    instructions.push(Instruction::PUSHARG(2)); // client_index
    instructions.push(Instruction::PUSHARG(5)); // element_index
    instructions.push(Instruction::CALL("ClientStore.take_share_fixed".to_string()));
    instructions.push(Instruction::MOV(17, 0)); // reg17 = share

    // Accumulate: reg16 += reg17
    instructions.push(Instruction::ADD(16, 16, 17));

    // Increment client counter
    instructions.push(Instruction::ADD(2, 2, 3)); // reg2++
    instructions.push(Instruction::JMP(client_sum_loop.clone()));

    // === END CLIENT SUM LOOP ===
    labels.insert(client_sum_done.clone(), instructions.len());

    // Reveal the sum - MOV from secret register to clear register triggers MPC reveal
    instructions.push(Instruction::MOV(7, 16)); // reg7 = revealed sum

    // Divide by num_clients to get average (operating on clear values)
    instructions.push(Instruction::DIV(7, 7, 1)); // reg7 = sum / num_clients

    // Store the revealed averaged value in the result array (1-indexed)
    instructions.push(Instruction::ADD(8, 5, 3)); // reg8 = element_index + 1 (1-indexed)
    instructions.push(Instruction::PUSHARG(6)); // result array ref
    instructions.push(Instruction::PUSHARG(8)); // index (1-based)
    instructions.push(Instruction::PUSHARG(7)); // value (revealed average)
    instructions.push(Instruction::CALL("set_field".to_string()));

    // Increment element counter
    instructions.push(Instruction::ADD(5, 5, 3)); // reg5++
    instructions.push(Instruction::JMP(elem_loop.clone()));

    // === END ELEMENT LOOP ===
    labels.insert(elem_done.clone(), instructions.len());

    // Return the result array
    instructions.push(Instruction::MOV(0, 6));
    instructions.push(Instruction::RET(0));

    (instructions, labels)
}

/// Create a compiled binary from the federated average program
#[allow(dead_code)]
fn create_federated_average_binary() -> Vec<u8> {
    let (instructions, labels) = build_federated_average_program_6();

    let vm_function = VMFunction::new(
        "federated_average".to_string(),
        vec![],
        Vec::new(),
        None,
        PROGRAM_REGISTERS,
        instructions,
        labels,
    );

    let binary = CompiledBinary::from_vm_functions(&[vm_function]);
    let mut buffer = Vec::new();
    binary.serialize(&mut buffer).expect("Failed to serialize binary");
    buffer
}

/// Test the leader bootnode pattern with fixed-point matrix averaging
///
/// This test:
/// 1. Creates 5 parties (simulating leader bootnode pattern)
/// 2. Runs preprocessing and client input distribution
/// 3. Executes fixed-point federated averaging
/// 4. Verifies element-wise average results
#[tokio::test(flavor = "multi_thread")]
async fn test_leader_bootnode_matrix_average_fixed_point() {
    init_crypto_provider();
    setup_test_tracing();

    info!("=== Starting Leader Bootnode Matrix Average Fixed-Point Test ===");
    info!(
        "Matrix: {}x{} = {} elements per client",
        MATRIX_ROWS, MATRIX_COLS, MATRIX_SIZE
    );
    info!(
        "Fixed-point: {} fractional bits, scale = {}",
        FIXED_POINT_FRACTIONAL_BITS, FIXED_POINT_SCALE
    );

    let n_parties = 5;
    let threshold = 1;
    let n_triples = 32;
    let n_random_shares = 64 + MATRIX_SIZE * 8;
    let instance_id = 77777;
    let base_port = 11000;

    let config = HoneyBadgerQuicConfig {
        mpc_timeout: Duration::from_secs(30),
        connection_retry_delay: Duration::from_millis(100),
        ..Default::default()
    };

    // Create the program binary (for reference/future use)
    info!("Creating federated average program binary...");
    let program_bytes = create_federated_average_binary();
    let program_id = program_id_from_bytes(&program_bytes);
    info!(
        "Program ID: {}, size: {} bytes",
        hex::encode(&program_id[..8]),
        program_bytes.len()
    );

    // Step 1: Create mesh network
    info!("Step 1: Creating {} MPC servers...", n_parties);
    let (mut servers, mut recv) = setup_honeybadger_quic_network::<Fr>(
        n_parties,
        threshold,
        n_triples,
        n_random_shares,
        instance_id,
        base_port,
        config.clone(),
    )
    .await
    .expect("Failed to create servers");

    let server_addresses: Vec<SocketAddr> = (0..n_parties)
        .map(|i| {
            format!("127.0.0.1:{}", base_port + i as u16)
                .parse()
                .unwrap()
        })
        .collect();

    // Generate test client data (matrices with fixed-point scaled values)
    let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
    let client_count = 3;
    let mut client_ids = Vec::new();
    let mut client_inputs = Vec::new();

    // Track per-element sums for expected average calculation
    let mut element_sums: Vec<f64> = vec![0.0; MATRIX_SIZE];

    info!(
        "Generating {} random matrices ({}x{}) from {} clients with fixed-point values...",
        client_count, MATRIX_ROWS, MATRIX_COLS, client_count
    );

    for idx in 0..client_count {
        let client_id = 900 + idx as ClientId;
        client_ids.push(client_id);

        let mut matrix_values: Vec<Fr> = Vec::new();
        let mut client_sum: f64 = 0.0;
        for elem_idx in 0..MATRIX_SIZE {
            let integer_part = rng.gen_range(1i64..=100i64);
            let fractional_part = rng.gen_range(0i64..=99i64);
            let value = integer_part as f64 + (fractional_part as f64 / 100.0);
            element_sums[elem_idx] += value;
            client_sum += value;

            let scaled_value = (value * FIXED_POINT_SCALE as f64) as u64;
            matrix_values.push(Fr::from(scaled_value));
        }
        client_inputs.push(matrix_values);

        info!(
            "  Client {}: generated {}x{} matrix with sum {:.2}",
            client_id, MATRIX_ROWS, MATRIX_COLS, client_sum
        );
    }

    // Calculate expected element-wise averages
    let expected_averages: Vec<f64> = element_sums.iter()
        .map(|sum| sum / client_count as f64)
        .collect();

    info!("Expected element-wise averages:");
    for (i, avg) in expected_averages.iter().enumerate() {
        let row = i / MATRIX_COLS;
        let col = i % MATRIX_COLS;
        info!("  [{},{}] = {:.4}", row, col, avg);
    }

    // Step 2: Start servers and spawn message processors
    info!("Step 2: Starting servers...");
    for (i, server) in servers.iter_mut().enumerate() {
        server.start().await.expect("Failed to start server");

        let mut node = server.node.clone();
        let network = server
            .network
            .clone()
            .expect("network should be set after start()");
        let mut rx = recv.remove(0);

        tokio::spawn(async move {
            while let Some(raw_msg) = rx.recv().await {
                if let Err(e) = node.process(raw_msg, network.clone()).await {
                    tracing::error!("Node {i} failed to process message: {e:?}");
                }
            }
        });
    }

    // Step 3: Connect servers
    info!("Step 3: Connecting servers in mesh topology...");
    for server in &servers {
        server.connect_to_peers().await.expect("Failed to connect");
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Step 4: Create input clients
    info!("Step 4: Creating {} matrix input clients...", client_count);
    let mut clients = setup_honeybadger_quic_clients::<Fr>(
        client_ids.clone(),
        server_addresses.clone(),
        n_parties,
        threshold,
        instance_id,
        client_inputs.clone(),
        MATRIX_SIZE,
        config.clone(),
    )
    .await
    .expect("Failed to create clients");

    for client in &mut clients {
        client
            .connect_to_servers()
            .await
            .expect("Client failed to connect");
        info!("✓ Client {} connected", client.client_id);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Step 5: Run preprocessing
    info!("Step 5: Running preprocessing...");
    let preprocessing_handles: Vec<_> = servers
        .iter()
        .enumerate()
        .map(|(i, server)| {
            let mut node = server.node.clone();
            let network = server
                .network
                .clone()
                .expect("network should be set after start()");
            tokio::spawn(async move {
                let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
                node.run_preprocessing(network, &mut rng)
                    .await
                    .expect("Preprocessing failed");
                info!("✓ Server {} preprocessing complete", i);
            })
        })
        .collect();
    futures::future::join_all(preprocessing_handles).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Step 6: Initialize input protocol for each client
    info!(
        "Step 6: Initializing input protocol for {} clients with {} shares each...",
        client_count, MATRIX_SIZE
    );
    for (idx, server) in servers.iter_mut().enumerate() {
        for client_id in &client_ids {
            let local_shares = server
                .node
                .preprocessing_material
                .lock()
                .await
                .take_random_shares(MATRIX_SIZE)
                .expect("Failed to take random shares");
            server
                .node
                .preprocess
                .input
                .init(
                    *client_id,
                    local_shares,
                    MATRIX_SIZE,
                    server.network.clone().expect("network should be set"),
                )
                .await
                .expect("input.init failed");
        }
        info!("✓ Server {} initialized input protocol", idx);
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Step 7: Create VMs and hydrate client stores
    info!("Step 7: Creating VMs and hydrating client stores...");
    let mut vms: Vec<Arc<parking_lot::Mutex<VirtualMachine>>> = Vec::new();
    for party_id in 0..n_parties {
        let mut vm = VirtualMachine::new();
        let engine = HoneyBadgerMpcEngine::from_existing_node(
            instance_id,
            party_id,
            n_parties,
            threshold,
            servers[party_id]
                .network
                .clone()
                .expect("network should be set"),
            servers[party_id].node.clone(),
        );
        vm.state.set_mpc_engine(engine);
        vms.push(Arc::new(parking_lot::Mutex::new(vm)));
    }

    // Hydrate VM client stores
    for (party_id, vm_arc) in vms.iter().enumerate() {
        let shares_for_party: Vec<(ClientId, Vec<RobustShare<Fr>>)> = {
            let input_store = servers[party_id]
                .node
                .preprocess
                .input
                .input_shares
                .lock()
                .await;
            input_store
                .iter()
                .map(|(client, shares)| (*client, shares.clone()))
                .collect()
        };
        let mut vm = vm_arc.lock();
        let store = vm.state.client_store();
        store.clear();
        for (client_id, shares) in shares_for_party {
            store.store_client_input(client_id, shares);
        }
        info!("✓ VM {} client store populated", party_id);
    }

    // Step 8: Register federated averaging program
    info!("Step 8: Registering federated averaging program...");
    let (fed_avg_program, fed_avg_labels) = build_federated_average_program_6();
    for vm_arc in &vms {
        let avg_fn = VMFunction::new(
            "federated_average".to_string(),
            vec![],
            Vec::new(),
            None,
            PROGRAM_REGISTERS,
            fed_avg_program.clone(),
            fed_avg_labels.clone(),
        );
        let mut vm = vm_arc.lock();
        vm.register_function(avg_fn);
    }

    // Step 9: Execute program on all VMs in parallel
    info!("Step 9: Executing federated averaging program on all parties...");
    use futures::FutureExt;
    let handles: Vec<_> = vms
        .iter()
        .enumerate()
        .map(|(pid, vm_arc)| {
            let vm_arc = vm_arc.clone();
            tokio::task::spawn_blocking(move || {
                let mut vm = vm_arc.lock();
                let val = vm
                    .execute("federated_average")
                    .map_err(|e| format!("VM execution failed at party {}: {}", pid, e))?;
                Ok::<(usize, Value), String>((pid, val))
            })
            .map(move |join_res| match join_res {
                Ok(inner) => inner,
                Err(e) => Err(format!("Join error executing VM {}: {:?}", pid, e)),
            })
        })
        .collect();

    let joined = tokio::time::timeout(Duration::from_secs(120), futures::future::join_all(handles))
        .await
        .expect("Timed out waiting for federated average VM executions");

    let mut results = Vec::new();
    for res in joined {
        let (pid, val) = res.expect("VM execution task failed");
        results.push((pid, val));
    }

    // Step 10: Verify results
    info!("Step 10: Verifying federated averaging results...");

    // All parties should return arrays with the same averaged values
    for (pid, val) in &results {
        match val {
            Value::Array(array_id) => {
                info!("Party {} returned array with id {}", pid, array_id);
            }
            other => {
                panic!("Party {} returned unexpected value type: {:?}", pid, other);
            }
        }
    }

    // Verify element-wise averages from the first party's VM
    {
        let (first_pid, first_val) = &results[0];
        if let Value::Array(array_id) = first_val {
            let vm = vms[*first_pid].lock();
            if let Some(arr) = vm.state.object_store.get_array(*array_id) {
                info!("Verifying {} averaged matrix elements:", arr.length());
                for elem_idx in 0..MATRIX_SIZE {
                    let idx_val = Value::I64((elem_idx + 1) as i64);
                    if let Some(elem_val) = arr.get(&idx_val) {
                        let computed_avg: f64 = match elem_val {
                            Value::I64(v) => *v as f64,
                            Value::Float(v) => v.0,
                            other => panic!("Element {} has unexpected type: {:?}", elem_idx, other),
                        };

                        let expected = expected_averages[elem_idx];
                        let diff = (computed_avg - expected).abs();

                        let row = elem_idx / MATRIX_COLS;
                        let col = elem_idx % MATRIX_COLS;

                        assert!(
                            diff <= 0.01,
                            "Element [{},{}] mismatch: got {:.4}, expected {:.4} (diff {:.4})",
                            row, col, computed_avg, expected, diff
                        );
                        info!(
                            "  ✓ [{},{}] = {:.4} (expected {:.4})",
                            row, col, computed_avg, expected
                        );
                    } else {
                        panic!("Element {} not found in result array", elem_idx);
                    }
                }
            } else {
                panic!("Array {} not found in VM object store", array_id);
            }
        }
    }

    // Verify all parties computed the same results
    info!("Verifying all parties have consistent results...");
    let reference_vals: Vec<f64> = {
        let (first_pid, first_val) = &results[0];
        let vm = vms[*first_pid].lock();
        let array_id = match first_val {
            Value::Array(id) => *id,
            _ => panic!("Expected array"),
        };
        let arr = vm.state.object_store.get_array(array_id).expect("array exists");
        (0..MATRIX_SIZE)
            .map(|i| {
                let idx = Value::I64((i + 1) as i64);
                match arr.get(&idx).expect("element exists") {
                    Value::I64(v) => *v as f64,
                    Value::Float(v) => v.0,
                    _ => panic!("unexpected type"),
                }
            })
            .collect()
    };

    for (pid, val) in &results[1..] {
        let vm = vms[*pid].lock();
        let array_id = match val {
            Value::Array(id) => *id,
            _ => panic!("Expected array"),
        };
        let arr = vm.state.object_store.get_array(array_id).expect("array exists");
        for (i, &ref_val) in reference_vals.iter().enumerate() {
            let idx = Value::I64((i + 1) as i64);
            let party_val: f64 = match arr.get(&idx).expect("element exists") {
                Value::I64(v) => *v as f64,
                Value::Float(v) => v.0,
                _ => panic!("unexpected type"),
            };
            let diff = (party_val - ref_val).abs();
            assert!(
                diff < 0.0001,
                "Party {} element {} mismatch: got {}, expected {} (diff {})",
                pid, i, party_val, ref_val, diff
            );
        }
        info!("  ✓ Party {} results match reference", pid);
    }

    // Cleanup
    info!("Step 11: Cleaning up...");
    for mut server in servers {
        server.stop().await;
    }
    for client in clients {
        let _ = client.stop().await;
    }

    info!("");
    info!("=== Leader Bootnode Matrix Average Fixed-Point Test PASSED ===");
    info!(
        "Successfully computed federated average of {} matrices ({}x{}) from {} clients",
        client_count, MATRIX_ROWS, MATRIX_COLS, client_count
    );
    info!("All {} parties computed identical element-wise averages", n_parties);
}
