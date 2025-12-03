//! Full VM-MPC mesh integration test
//!
//! This test demonstrates:
//! 1. Multiple VM nodes connecting in a mesh network
//! 2. Preprocessing to generate multiplication triples
//! 3. Clients sending secret shares to all nodes (stored in global store)
//! 4. Each VM node loading client shares from global store
//! 5. VMs executing bytecode that performs MPC multiplication
//! 6. Results verification

use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use ark_std::rand::{Rng, SeedableRng};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use stoffelmpc_mpc::common::{MPCProtocol, PreprocessingMPCProtocol};
use stoffelmpc_mpc::honeybadger::ProtocolType;
use stoffelmpc_mpc::common::SecretSharingScheme;
use stoffelmpc_mpc::honeybadger::output::output::OutputClient;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::WrappedMessage;
use stoffelnet::network_utils::ClientId;
use tokio::sync::Mutex;
use tracing::info;

use crate::core_vm::VirtualMachine;
use crate::net::hb_engine::HoneyBadgerMpcEngine;
use crate::net::mpc_engine::MpcEngine;
use crate::tests::mpc_multiplication_integration::{
    HoneyBadgerQuicConfig, HoneyBadgerQuicServer, setup_honeybadger_quic_clients,
    setup_honeybadger_quic_network,
};
use stoffel_vm_types::core_types::Value;
use stoffel_vm_types::functions::VMFunction;
use stoffel_vm_types::instructions::Instruction;

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

// Use a multi-thread Tokio runtime to allow synchronous bridges inside the VM's MPC engine
// (the engine uses block_in_place + block_on to wait for async MPC ops when called from sync VM code)
#[tokio::test(flavor = "multi_thread")]
async fn test_vm_mesh_full_integration() {
    init_crypto_provider();
    setup_test_tracing();

    info!("=== Starting Full VM Mesh Integration Test ===");

    // Configuration
    let n_parties = 5;
    let threshold = 1;
    let program_template = build_client_mul_program();
    let program_mul_count = program_template
        .iter()
        .filter(|instr| matches!(instr, Instruction::MUL(_, _, _)))
        .count()
        .max(1)
        * 3;
    let n_triples = program_mul_count;
    let n_random_shares = 2 + 2 * n_triples;
    info!("Number of triples: {:?} {:?}", n_triples, n_random_shares);
    let instance_id = 99999;
    let base_port = 9400;

    let config = HoneyBadgerQuicConfig {
        mpc_timeout: Duration::from_secs(10),
        connection_retry_delay: Duration::from_millis(100),
        ..Default::default()
    };

    // Step 1: Create mesh network of MPC servers
    info!(
        "Step 1: Creating {} MPC servers in mesh topology...",
        n_parties
    );
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
    let client_ids: Vec<ClientId> = vec![200, 201];
    let client_scalar_inputs = vec![15u64, 25u64];
    let client_inputs: Vec<Vec<Fr>> = client_scalar_inputs
        .iter()
        .map(|v| vec![Fr::from(*v)])
        .collect();
    let expected_product = (client_scalar_inputs[0] * client_scalar_inputs[1]) as i64;

    // Step 2: Start servers and spawn message processors
    info!("Step 2: Starting servers...");
    for (i, server) in servers.iter_mut().enumerate() {
        // Must call start() first to create the network Arc
        server.start().await.expect("Failed to start server");

        let mut node = server.node.clone();
        let network = server.network.clone().expect("network should be set after start()");
        let mut rx = recv.remove(0);

        tokio::spawn(async move {
            while let Some(raw_msg) = rx.recv().await {
                if let Err(e) = node.process(raw_msg, network.clone()).await {
                    tracing::error!("Node {i} failed to process message: {e:?}");
                }
            }
        });
    }

    // Step 3: Connect servers in mesh
    info!("Step 3: Connecting servers in mesh topology...");
    for server in &servers {
        server.connect_to_peers().await.expect("Failed to connect");
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Step 4: Create and connect real MPC clients that will submit inputs
    info!("Step 4: Creating and connecting MPC clients...");
    let mut clients = setup_honeybadger_quic_clients::<Fr>(
        client_ids.clone(),
        server_addresses,
        n_parties,
        threshold,
        instance_id,
        client_inputs,
        1,
        config.clone(),
    )
    .await
    .expect("Failed to create clients");
    for client in &mut clients {
        info!("Connecting client {} to servers...", client.client_id);
        client
            .connect_to_servers()
            .await
            .expect("Client failed to connect to servers");
        info!("✓ Client {} connected to all servers", client.client_id);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Step 5: Run preprocessing
    info!("Step 5: Running preprocessing on all servers...");
    let preprocessing_handles: Vec<_> = servers
        .iter()
        .enumerate()
        .map(|(i, server)| {
            let mut node = server.node.clone();
            let network = server.network.clone().expect("network should be set after start()");

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
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Step 6: Initialize the HB input protocol for each client so they can submit inputs
    info!("Step 6: Initializing client inputs on all servers...");
    for (i, server) in servers.iter_mut().enumerate() {
        for client_id in &client_ids {
            let local_shares = server
                .node
                .preprocessing_material
                .lock()
                .await
                .take_random_shares(1)
                .expect("Failed to take random shares for input");
            server
                .node
                .preprocess
                .input
                .init(*client_id, local_shares, 1, server.network.clone().expect("network should be set"))
                .await
                .expect("input.init failed");
            info!(
                "✓ Server {} initialized input protocol for client {}",
                i, client_id
            );
        }
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Step 7: Create VMs for each node
    info!("Step 7: Creating VMs for each node...");
    // Use Arc<parking_lot::Mutex<...>> so we can execute VMs concurrently from blocking tasks
    let mut vms: Vec<Arc<parking_lot::Mutex<VirtualMachine>>> = Vec::new();

    for party_id in 0..n_parties {
        let mut vm = VirtualMachine::new();

        // Attach MPC engine to VM, wrapping the already-running HB node for this party
        let mpc_engine = HoneyBadgerMpcEngine::from_existing_node(
            instance_id,
            party_id,
            n_parties,
            threshold,
            servers[party_id].network.clone().expect("network should be set"),
            servers[party_id].node.clone(),
        );

        vm.state.mpc_engine = Some(mpc_engine);
        vms.push(Arc::new(parking_lot::Mutex::new(vm)));

        info!(
            "✓ VM {} created with MPC engine (wrapped server node)",
            party_id
        );
    }

    // Step 8: Hydrate each VM's client store from its HoneyBadger node inputs
    info!("Step 8: Hydrating VM client stores from HoneyBadger inputs...");
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

    // Step 9: Register VM program that loads each client's input and multiplies them
    info!("Step 9: Registering VM programs...");

    for (party_id, vm_arc) in vms.iter().enumerate() {
        let multiply_fn = VMFunction::new(
            "multiply_client_inputs".to_string(),
            vec![],
            Vec::new(),
            None,
            CLIENT_PROGRAM_REGISTERS,
            program_template.clone(),
            HashMap::new(),
        );

        {
            let mut vm = vm_arc.lock();
            vm.register_function(multiply_fn);
        }
        info!("✓ VM {} program registered", party_id);
    }

    // Step 10: Execute VM programs on all parties (this triggers MPC multiplication)
    info!("Step 10: Executing VM programs on all parties...");

    use futures::FutureExt;
    let handles: Vec<_> = vms
        .iter()
        .enumerate()
        .map(|(pid, vm_arc)| {
            let vm_arc = vm_arc.clone();
            tokio::task::spawn_blocking(move || {
                let mut vm = vm_arc.lock();
                let val = vm
                    .execute("multiply_client_inputs")
                    .map_err(|e| format!("VM execution failed at party {}: {}", pid, e))?;
                Ok::<(usize, Value), String>((pid, val))
            })
            .map(move |join_res| match join_res {
                Ok(inner) => inner,
                Err(e) => Err(format!("Join error executing VM {}: {:?}", pid, e)),
            })
        })
        .collect();

    // Put a timeout guard to avoid infinite hangs in CI
    let join_all_fut = futures::future::join_all(handles);
    let joined = tokio::time::timeout(Duration::from_secs(30), join_all_fut)
        .await
        .expect("Timed out waiting for VMs to execute; possible deadlock if parties didn't run concurrently");

    let mut party_results: Vec<(usize, Value)> = Vec::new();
    for res in joined {
        let (pid, val) = res.expect("VM execution task failed");
        info!("✓ VM {} executed program", pid);
        party_results.push((pid, val));
    }

    // Step 11: Verify the clear results returned by each VM
    info!("Step 11: Verifying revealed results...");
    for (pid, val) in party_results.iter() {
        match val {
            Value::I64(v) => {
                assert_eq!(*v, expected_product);
                info!("✓ VM {} revealed result {}", pid, v);
            }
            other => panic!("Unexpected VM return value: {:?}", other),
        }
    }

    // Step 12: Summary
    info!("Step 12: Integration test summary");
    info!("✓ {} nodes connected in mesh topology", n_parties);
    info!("✓ Preprocessing generated {} triples", n_triples);
    info!(
        "✓ Clients {} and {} provided inputs: {} and {}",
        client_ids[0], client_ids[1], client_scalar_inputs[0], client_scalar_inputs[1]
    );
    info!("✓ VMs loaded client shares via ClientStore builtins");
    info!(
        "✓ MPC multiplication computed and revealed entirely in the VM: {} × {} = {}",
        client_scalar_inputs[0], client_scalar_inputs[1], expected_product
    );
    info!("");
    info!("=== Full VM Mesh Integration Test PASSED ===");

    // Cleanup
    for mut server in servers {
        server.stop().await;
    }
    for client in clients {
        let _ = client.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_vm_mesh_average_salary_integration() {
    init_crypto_provider();
    setup_test_tracing();

    info!("=== Starting VM Mesh Average Salary Integration Test ===");

    let n_parties = 5;
    let threshold = 1;
    // Preprocessing requirements:
    // - Triples: needed for MPC multiplication operations
    // - Random shares: needed for input protocol (2 per client per server)
    let n_triples = 32;
    // Each of the 5 servers needs random shares for up to MAX_AVG_CLIENTS clients with 2 inputs each
    let n_random_shares = 64 + MAX_AVG_CLIENTS * 4;
    let instance_id = 99998;
    let base_port = 9450;

    let config = HoneyBadgerQuicConfig {
        mpc_timeout: Duration::from_secs(10),
        connection_retry_delay: Duration::from_millis(100),
        ..Default::default()
    };

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

    let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
    let client_count = rng.gen_range(2..=6usize);
    let mut client_ids = Vec::new();
    let mut client_inputs = Vec::new();
    let mut expected_sum = 0i64;
    for idx in 0..client_count {
        let client_id = 500 + idx as ClientId;
        client_ids.push(client_id);
        let salary = rng.gen_range(40_000i64..=200_000i64);
        expected_sum += salary;
        client_inputs.push(vec![Fr::from(salary as u64), Fr::from(1u64)]);
    }
    let expected_average = expected_sum / client_count as i64;

    info!(
        "Average test will use {} clients; expected avg salary {}",
        client_count, expected_average
    );

    info!("Starting servers for average test...");
    for (i, server) in servers.iter_mut().enumerate() {
        // Must call start() first to create the network Arc
        server.start().await.expect("Failed to start server");

        let mut node = server.node.clone();
        let network = server.network.clone().expect("network should be set after start()");
        let mut rx = recv.remove(0);
        tokio::spawn(async move {
            while let Some(raw_msg) = rx.recv().await {
                if let Err(e) = node.process(raw_msg, network.clone()).await {
                    tracing::error!("Node {i} failed to process message: {e:?}");
                }
            }
        });
    }

    info!("Connecting servers...");
    for server in &servers {
        server.connect_to_peers().await.expect("Failed to connect");
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    info!("Creating {} salary clients...", client_count);
    let mut clients = setup_honeybadger_quic_clients::<Fr>(
        client_ids.clone(),
        server_addresses,
        n_parties,
        threshold,
        instance_id,
        client_inputs.clone(),
        2,
        config.clone(),
    )
    .await
    .expect("Failed to create clients");
    for client in &mut clients {
        client
            .connect_to_servers()
            .await
            .expect("Client failed to connect");
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    info!("Running preprocessing for average test...");
    let preprocessing_handles: Vec<_> = servers
        .iter()
        .enumerate()
        .map(|(i, server)| {
            let mut node = server.node.clone();
            let network = server.network.clone().expect("network should be set after start()");
            tokio::spawn(async move {
                let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
                node.run_preprocessing(network, &mut rng)
                    .await
                    .expect("Preprocessing failed");
                info!("✓ Server {} preprocessing complete (avg)", i);
            })
        })
        .collect();
    futures::future::join_all(preprocessing_handles).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    info!("Initializing HB inputs for salary clients...");
    for (idx, server) in servers.iter_mut().enumerate() {
        for client_id in &client_ids {
            let local_shares = server
                .node
                .preprocessing_material
                .lock()
                .await
                .take_random_shares(2)
                .expect("Failed to take random shares");
            server
                .node
                .preprocess
                .input
                .init(*client_id, local_shares, 2, server.network.clone().expect("network should be set"))
                .await
                .expect("input.init failed");
        }
        info!("✓ Server {} initialized input protocol", idx);
    }
    // Allow time for input protocol messages to propagate between servers
    tokio::time::sleep(Duration::from_millis(300)).await;

    info!("Creating VMs for average computation...");
    let mut vms: Vec<Arc<parking_lot::Mutex<VirtualMachine>>> = Vec::new();
    for party_id in 0..n_parties {
        let mut vm = VirtualMachine::new();
        let engine = HoneyBadgerMpcEngine::from_existing_node(
            instance_id,
            party_id,
            n_parties,
            threshold,
            servers[party_id].network.clone().expect("network should be set"),
            servers[party_id].node.clone(),
        );
        vm.state.set_mpc_engine(engine);
        vms.push(Arc::new(parking_lot::Mutex::new(vm)));
    }

    info!("Hydrating VM client stores for average test...");

    // First, let's verify that single client shares can be reconstructed
    {
        let first_client = client_ids[0];
        let mut all_shares_for_client: Vec<RobustShare<Fr>> = Vec::new();

        for party_id in 0..n_parties {
            let input_store = servers[party_id]
                .node
                .preprocess
                .input
                .input_shares
                .lock()
                .await;
            if let Some(shares) = input_store.get(&first_client) {
                all_shares_for_client.push(shares[0].clone());
            }
        }

        // Verify that individual client shares can be reconstructed
        let result = RobustShare::recover_secret(&all_shares_for_client, n_parties);
        assert!(result.is_ok(), "Failed to reconstruct individual client shares: {:?}", result.err());
    }

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
    }

    info!("Registering average salary program on all VMs...");
    let (avg_program, avg_labels) = build_average_salary_program();
    for vm_arc in &vms {
        let avg_fn = VMFunction::new(
            "average_salary".to_string(),
            vec![],
            Vec::new(),
            None,
            AVG_PROGRAM_REGISTERS,
            avg_program.clone(),
            avg_labels.clone(),
        );
        let mut vm = vm_arc.lock();
        vm.register_function(avg_fn);
    }

    // Verify that summed shares can be reconstructed before running the full VM test
    info!("Verifying sum shares reconstruction...");
    {
        let mut salary_sums: Vec<RobustShare<Fr>> = Vec::new();
        for (_party_id, vm_arc) in vms.iter().enumerate() {
            let vm = vm_arc.lock();
            let store = vm.state.client_store();
            let mut sum: Option<RobustShare<Fr>> = None;
            for client_id in &client_ids {
                if let Some(share) = store.get_client_share(*client_id, 0) {
                    sum = Some(match sum {
                        None => share.clone(),
                        Some(s) => (s + share.clone()).expect("Share addition failed"),
                    });
                }
            }
            if let Some(s) = sum {
                salary_sums.push(s);
            }
        }
        let result = RobustShare::recover_secret(&salary_sums, n_parties);
        assert!(result.is_ok(), "Failed to reconstruct summed shares: {:?}", result.err());
    }

    info!("Executing average salary program on all parties...");
    let handles: Vec<_> = vms
        .iter()
        .enumerate()
        .map(|(pid, vm_arc)| {
            let vm_arc = vm_arc.clone();
            tokio::task::spawn_blocking(move || {
                let mut vm = vm_arc.lock();
                let val = vm
                    .execute("average_salary")
                    .map_err(|e| format!("VM execution failed at party {}: {}", pid, e))?;
                Ok::<(usize, Value), String>((pid, val))
            })
        })
        .collect();
    let joined = tokio::time::timeout(Duration::from_secs(30), futures::future::join_all(handles))
        .await
        .expect("Timed out waiting for average salary VM executions");
    let mut results = Vec::new();
    for res in joined {
        let inner = res.expect("VM execution task failed");
        match inner {
            Ok((pid, val)) => results.push((pid, val)),
            Err(e) => panic!("VM execution failed: {}", e),
        }
    }

    info!("Verifying average salary results...");
    for (pid, val) in results {
        match val {
            Value::I64(v) => {
                assert_eq!(v, expected_average, "Party {} mismatch", pid);
                info!("✓ Party {} revealed average {}", pid, v);
            }
            other => panic!("Unexpected return value: {:?}", other),
        }
    }

    for mut server in servers {
        server.stop().await;
    }
    for client in clients {
        let _ = client.stop().await;
    }

    info!("=== VM Mesh Average Salary Integration Test PASSED ===");
}

const CLIENT_PROGRAM_REGISTERS: usize = 19;
const AVG_PROGRAM_REGISTERS: usize = 24;

fn build_client_mul_program() -> Vec<Instruction> {
    vec![
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
        Instruction::MUL(18, 16, 17),
        Instruction::MOV(0, 18),
        Instruction::RET(0),
    ]
}

fn build_average_salary_program() -> (Vec<Instruction>, HashMap<String, usize>) {
    let mut instructions = Vec::new();
    let mut labels = HashMap::new();

    // Get number of clients
    instructions.push(Instruction::CALL(
        "ClientStore.get_number_clients".to_string(),
    ));
    instructions.push(Instruction::MOV(1, 0));  // reg1 = num_clients

    // Initialize loop counter to 0
    instructions.push(Instruction::LDI(2, Value::I64(0)));  // reg2 = 0 (loop counter)
    instructions.push(Instruction::LDI(3, Value::I64(1)));  // reg3 = 1 (constant for increments)

    // Load first client's shares to initialize accumulators (client index 0)
    // This avoids creating an incompatible "zero share" via clear->secret conversion
    instructions.push(Instruction::LDI(0, Value::I64(0)));  // client_index = 0
    instructions.push(Instruction::PUSHARG(0));
    instructions.push(Instruction::LDI(4, Value::I64(0)));  // share_index = 0 (salary)
    instructions.push(Instruction::PUSHARG(4));
    instructions.push(Instruction::CALL("ClientStore.take_share".to_string()));
    instructions.push(Instruction::MOV(16, 0));  // reg16 = first client's salary share

    instructions.push(Instruction::LDI(0, Value::I64(0)));  // client_index = 0
    instructions.push(Instruction::PUSHARG(0));
    instructions.push(Instruction::LDI(4, Value::I64(1)));  // share_index = 1 (count)
    instructions.push(Instruction::PUSHARG(4));
    instructions.push(Instruction::CALL("ClientStore.take_share".to_string()));
    instructions.push(Instruction::MOV(17, 0));  // reg17 = first client's count share

    // Start loop from index 1 (already processed index 0)
    instructions.push(Instruction::LDI(2, Value::I64(1)));  // reg2 = 1 (loop counter starts at 1)

    let loop_label = "avg_loop_start".to_string();
    let process_label = "avg_process".to_string();
    let done_label = "avg_done".to_string();

    labels.insert(loop_label.clone(), instructions.len());
    instructions.push(Instruction::CMP(2, 1));
    instructions.push(Instruction::JMPLT(process_label.clone()));
    instructions.push(Instruction::JMP(done_label.clone()));

    labels.insert(process_label.clone(), instructions.len());
    // Get salary share (index 0) for current client
    instructions.push(Instruction::MOV(0, 2));  // reg0 = client_index
    instructions.push(Instruction::PUSHARG(0));
    instructions.push(Instruction::LDI(4, Value::I64(0)));  // share_index = 0 (salary)
    instructions.push(Instruction::PUSHARG(4));
    instructions.push(Instruction::CALL("ClientStore.take_share".to_string()));
    instructions.push(Instruction::MOV(18, 0));  // reg18 = salary share

    // Get count share (index 1) for current client
    instructions.push(Instruction::MOV(0, 2));  // reg0 = client_index
    instructions.push(Instruction::PUSHARG(0));
    instructions.push(Instruction::LDI(4, Value::I64(1)));  // share_index = 1 (count)
    instructions.push(Instruction::PUSHARG(4));
    instructions.push(Instruction::CALL("ClientStore.take_share".to_string()));
    instructions.push(Instruction::MOV(19, 0));  // reg19 = count share

    // Accumulate: reg16 += reg18, reg17 += reg19
    instructions.push(Instruction::ADD(16, 16, 18));
    instructions.push(Instruction::ADD(17, 17, 19));
    instructions.push(Instruction::ADD(2, 2, 3));  // reg2++ (increment loop counter)
    instructions.push(Instruction::JMP(loop_label.clone()));

    labels.insert(done_label.clone(), instructions.len());

    // Compute average: total_salary / total_count
    instructions.push(Instruction::MOV(2, 16));  // reg2 = total salary (secret)
    instructions.push(Instruction::MOV(3, 17));  // reg3 = total count (secret)
    instructions.push(Instruction::DIV(4, 2, 3));  // reg4 = salary / count (secret division)
    instructions.push(Instruction::MOV(0, 4));  // Move result to reg0 (triggers reveal)
    instructions.push(Instruction::RET(0));

    (instructions, labels)
}

const MAX_AVG_CLIENTS: usize = 8;

/// Test preprocessing with larger requirements to verify scalability
/// This test follows the same pattern as test_vm_mesh_full_integration which works,
/// but focuses on verifying preprocessing material generation with slightly larger requirements.
/// Note: Preprocessing requires clients to be connected first due to protocol dependencies.
#[tokio::test(flavor = "multi_thread")]
async fn test_vm_mesh_large_preprocessing() {
    init_crypto_provider();
    setup_test_tracing();

    info!("=== Starting Large Preprocessing Integration Test ===");

    let n_parties = 5;
    let threshold = 1;
    // Use same parameters as test_vm_mesh_full_integration
    let n_triples = 32;
    let n_random_shares = 2 + 2 * n_triples; // = 8
    let instance_id = 77777; // Unique instance ID
    let base_port = 9700; // Unique port range (far from 9400/9450/9500/9550)

    let config = HoneyBadgerQuicConfig {
        mpc_timeout: Duration::from_secs(30),
        connection_retry_delay: Duration::from_millis(100),
        ..Default::default()
    };

    info!(
        "Configuration: {} parties, {} triples, {} random shares",
        n_parties, n_triples, n_random_shares
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

    // Step 2: Start servers and spawn message processors
    info!("Step 2: Starting servers...");
    for (i, server) in servers.iter_mut().enumerate() {
        server.start().await.expect("Failed to start server");

        let mut node = server.node.clone();
        let network = server.network.clone().expect("network should be set after start()");
        let mut rx = recv.remove(0);

        tokio::spawn(async move {
            while let Some(raw_msg) = rx.recv().await {
                if let Err(e) = node.process(raw_msg, network.clone()).await {
                    tracing::error!("Node {i} failed to process message: {e:?}");
                }
            }
        });
    }

    // Step 3: Connect servers in mesh
    info!("Step 3: Connecting servers in mesh topology...");
    for server in &servers {
        server.connect_to_peers().await.expect("Failed to connect");
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    info!("✓ All {} servers connected in mesh", n_parties);

    // Step 4: Create and connect MPC clients (required for preprocessing protocol)
    info!("Step 4: Creating and connecting MPC clients...");
    let client_ids: Vec<ClientId> = vec![300, 301];
    let client_inputs: Vec<Vec<Fr>> = vec![
        vec![Fr::from(10u64)], // Client 300 input
        vec![Fr::from(20u64)], // Client 301 input
    ];

    let mut clients = setup_honeybadger_quic_clients::<Fr>(
        client_ids.clone(),
        server_addresses,
        n_parties,
        threshold,
        instance_id,
        client_inputs,
        1,
        config.clone(),
    )
    .await
    .expect("Failed to create clients");

    for client in &mut clients {
        client
            .connect_to_servers()
            .await
            .expect("Client failed to connect to servers");
        info!("✓ Client {} connected to all servers", client.client_id);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Step 5: Run preprocessing (matching the exact pattern from test_vm_mesh_full_integration)
    info!("Step 5: Running preprocessing on all servers...");
    let preprocessing_handles: Vec<_> = servers
        .iter()
        .enumerate()
        .map(|(i, server)| {
            let mut node = server.node.clone();
            let network = server.network.clone().expect("network should be set after start()");

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
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Step 6: Verify preprocessing material was generated
    info!("Step 6: Verifying preprocessing material...");
    for (i, server) in servers.iter().enumerate() {
        let material = server.node.preprocessing_material.lock().await;

        let (triples_count, random_shares_count, prandbit_count, prandint_count) = material.len();

        info!(
            "  Server {}: {} triples, {} random shares, {} prandbits, {} prandints",
            i, triples_count, random_shares_count, prandbit_count, prandint_count
        );

        assert!(
            triples_count > 0,
            "Server {} should have generated triples",
            i
        );
        assert!(
            random_shares_count > 0,
            "Server {} should have generated random shares",
            i
        );
    }

    // Cleanup
    info!("Step 7: Cleaning up...");
    for mut server in servers {
        server.stop().await;
    }
    for client in clients {
        let _ = client.stop().await;
    }

    info!("");
    info!("=== Large Preprocessing Integration Test PASSED ===");
    info!(
        "Successfully generated {} triples and {} random shares across {} parties",
        n_triples, n_random_shares, n_parties
    );
}

/// Build a program that computes the sum of all client salary shares
/// and returns the result as a secret share (no reveal).
/// The result is returned in reg16 which is a secret register.
fn build_sum_salary_program_no_reveal() -> (Vec<Instruction>, HashMap<String, usize>) {
    let mut instructions = Vec::new();
    let mut labels = HashMap::new();

    // Get number of clients
    instructions.push(Instruction::CALL(
        "ClientStore.get_number_clients".to_string(),
    ));
    instructions.push(Instruction::MOV(1, 0)); // reg1 = num_clients

    // Initialize loop counter
    instructions.push(Instruction::LDI(3, Value::I64(1))); // reg3 = 1 (constant for increments)

    // Load first client's salary share to initialize accumulator (client index 0)
    instructions.push(Instruction::LDI(0, Value::I64(0))); // client_index = 0
    instructions.push(Instruction::PUSHARG(0));
    instructions.push(Instruction::LDI(4, Value::I64(0))); // share_index = 0 (salary)
    instructions.push(Instruction::PUSHARG(4));
    instructions.push(Instruction::CALL("ClientStore.take_share".to_string()));
    instructions.push(Instruction::MOV(16, 0)); // reg16 = first client's salary share

    // Start loop from index 1
    instructions.push(Instruction::LDI(2, Value::I64(1))); // reg2 = 1 (loop counter starts at 1)

    let loop_label = "sum_loop_start".to_string();
    let process_label = "sum_process".to_string();
    let done_label = "sum_done".to_string();

    labels.insert(loop_label.clone(), instructions.len());
    instructions.push(Instruction::CMP(2, 1));
    instructions.push(Instruction::JMPLT(process_label.clone()));
    instructions.push(Instruction::JMP(done_label.clone()));

    labels.insert(process_label.clone(), instructions.len());
    // Get salary share (index 0) for current client
    instructions.push(Instruction::MOV(0, 2)); // reg0 = client_index
    instructions.push(Instruction::PUSHARG(0));
    instructions.push(Instruction::LDI(4, Value::I64(0))); // share_index = 0 (salary)
    instructions.push(Instruction::PUSHARG(4));
    instructions.push(Instruction::CALL("ClientStore.take_share".to_string()));
    instructions.push(Instruction::MOV(18, 0)); // reg18 = salary share

    // Accumulate: reg16 += reg18
    instructions.push(Instruction::ADD(16, 16, 18));
    instructions.push(Instruction::ADD(2, 2, 3)); // reg2++ (increment loop counter)
    instructions.push(Instruction::JMP(loop_label.clone()));

    labels.insert(done_label.clone(), instructions.len());

    // Return the secret share in reg16 (NO reveal - keep as secret)
    // RET(16) returns the value in reg16 directly without conversion
    instructions.push(Instruction::RET(16));

    (instructions, labels)
}

/// Test VM mesh integration with OutputClient for revealing result to a single client
///
/// This test demonstrates:
/// 1. Multiple VM nodes computing the sum of client salaries
/// 2. Each server sends its result share to a designated output client
/// 3. Only the output client reconstructs the final result
/// 4. Other parties never see the plaintext result
#[tokio::test(flavor = "multi_thread")]
async fn test_vm_mesh_output_client_integration() {
    init_crypto_provider();
    setup_test_tracing();

    info!("=== Starting VM Mesh Output Client Integration Test ===");

    let n_parties = 5;
    let threshold = 1;
    let n_triples = 8;
    let n_random_shares = 8 + 2 * n_triples;
    let instance_id = 66666;
    let base_port = 9650;
    let output_client_id: ClientId = 999; // Designated output recipient

    let config = HoneyBadgerQuicConfig {
        mpc_timeout: Duration::from_secs(30),
        connection_retry_delay: Duration::from_millis(100),
        ..Default::default()
    };

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

    // Generate test client data (salaries)
    let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
    let client_count = rng.gen_range(2..=4usize);
    let mut client_ids = Vec::new();
    let mut client_inputs = Vec::new();
    let mut expected_sum = 0i64;
    for idx in 0..client_count {
        let client_id = 600 + idx as ClientId;
        client_ids.push(client_id);
        let salary = rng.gen_range(50_000i64..=150_000i64);
        expected_sum += salary;
        client_inputs.push(vec![Fr::from(salary as u64)]);
    }

    info!(
        "Output client test: {} input clients, expected sum = {}",
        client_count, expected_sum
    );

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
    info!("Step 3: Connecting servers...");
    for server in &servers {
        server.connect_to_peers().await.expect("Failed to connect");
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Step 4: Create input clients
    info!("Step 4: Creating {} input clients...", client_count);
    let mut clients = setup_honeybadger_quic_clients::<Fr>(
        client_ids.clone(),
        server_addresses.clone(),
        n_parties,
        threshold,
        instance_id,
        client_inputs.clone(),
        1, // Each client sends 1 value (salary)
        config.clone(),
    )
    .await
    .expect("Failed to create clients");

    for client in &mut clients {
        client
            .connect_to_servers()
            .await
            .expect("Client failed to connect");
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
    info!("Step 6: Initializing input protocol...");
    for (idx, server) in servers.iter_mut().enumerate() {
        for client_id in &client_ids {
            let local_shares = server
                .node
                .preprocessing_material
                .lock()
                .await
                .take_random_shares(1)
                .expect("Failed to take random shares");
            server
                .node
                .preprocess
                .input
                .init(
                    *client_id,
                    local_shares,
                    1,
                    server
                        .network
                        .clone()
                        .expect("network should be set"),
                )
                .await
                .expect("input.init failed");
        }
        info!("✓ Server {} initialized input protocol", idx);
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Step 7: Create VMs and hydrate client stores
    info!("Step 7: Creating VMs...");
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
    }

    // Step 8: Register and execute sum program (no reveal)
    info!("Step 8: Registering sum program on all VMs...");
    let (sum_program, sum_labels) = build_sum_salary_program_no_reveal();
    for vm_arc in &vms {
        let sum_fn = VMFunction::new(
            "sum_salaries".to_string(),
            vec![],
            Vec::new(),
            None,
            AVG_PROGRAM_REGISTERS,
            sum_program.clone(),
            sum_labels.clone(),
        );
        let mut vm = vm_arc.lock();
        vm.register_function(sum_fn);
    }

    info!("Step 9: Executing sum program on all parties (keeping result secret)...");
    let mut result_shares: Vec<RobustShare<Fr>> = Vec::new();

    for (pid, vm_arc) in vms.iter().enumerate() {
        let vm_arc = vm_arc.clone();
        let result = tokio::task::spawn_blocking(move || {
            let mut vm = vm_arc.lock();
            vm.execute("sum_salaries")
        })
        .await
        .expect("Task failed");

        match result {
            Ok(Value::Share(_, data)) => {
                // Decode the share from the returned bytes
                let share: RobustShare<Fr> =
                    ark_serialize::CanonicalDeserialize::deserialize_compressed(data.as_slice())
                        .expect("Failed to deserialize share");
                info!(
                    "Party {} returned share: id={}, degree={}",
                    pid, share.id, share.degree
                );
                result_shares.push(share);
            }
            Ok(other) => {
                panic!("Party {} returned unexpected value type: {:?}", pid, other);
            }
            Err(e) => {
                panic!("Party {} VM execution failed: {}", pid, e);
            }
        }
    }

    // Step 10: Create OutputClient and simulate receiving shares
    // Note: In a real deployment, the OutputServer would send shares via network
    // to the OutputClient. Here we simulate the output protocol by directly
    // processing the output messages at the client.
    info!("Step 10: Setting up output protocol for client {}...", output_client_id);

    // Create the output client
    let output_client = Arc::new(Mutex::new(
        OutputClient::<Fr>::new(output_client_id as usize, n_parties, threshold, 1)
            .expect("Failed to create OutputClient"),
    ));

    // Simulate each server sending its output share to the client
    // In production, OutputServer.init() sends via network; here we directly
    // create and process the OutputMessage at the client
    for (party_id, _server) in servers.iter().enumerate() {
        let share = result_shares[party_id].clone();

        // Serialize the share as OutputServer would
        let mut payload = Vec::new();
        ark_serialize::CanonicalSerialize::serialize_compressed(&vec![share], &mut payload)
            .expect("Failed to serialize share");

        // Create the OutputMessage that would be sent over network
        let output_msg = stoffelmpc_mpc::honeybadger::output::OutputMessage::new(party_id, payload);

        // Process the message at the output client
        let mut client = output_client.lock().await;
        client
            .process(output_msg)
            .await
            .expect("OutputClient failed to process message");

        info!(
            "✓ Simulated server {} sending output share to client {}",
            party_id, output_client_id
        );
    }

    // Step 11: Verify the output client has reconstructed the result
    info!("Step 11: Verifying output client reconstruction...");

    let client = output_client.lock().await;
    let reconstructed_value = client.output.clone();

    match reconstructed_value {
        Some(secret) => {
            // Convert Fr back to i64 for comparison
            let recovered_sum = {
                let bigint = secret.into_bigint();
                bigint.0[0] as i64
            };

            info!("=== Output Client Reconstruction ===");
            info!("Expected sum: {}", expected_sum);
            info!("Recovered sum: {}", recovered_sum);

            assert_eq!(
                recovered_sum, expected_sum,
                "Recovered sum {} does not match expected sum {}",
                recovered_sum, expected_sum
            );

            info!("✓ Output client successfully reconstructed the correct sum!");
        }
        None => {
            panic!(
                "OutputClient failed to reconstruct the secret (received {} shares, needed {})",
                n_parties,
                2 * threshold + 1
            );
        }
    }

    // Cleanup
    info!("Step 12: Cleaning up...");
    for mut server in servers {
        server.stop().await;
    }
    for client in clients {
        let _ = client.stop().await;
    }

    info!("");
    info!("=== VM Mesh Output Client Integration Test PASSED ===");
    info!(
        "Successfully computed sum of {} salaries and revealed only to designated output client",
        client_count
    );
}

// ============================================================================
// Matrix Average Test Constants
// ============================================================================

/// Matrix dimensions for the federated matrix average test
const MATRIX_ROWS: usize = 2;
const MATRIX_COLS: usize = 3;
const MATRIX_SIZE: usize = MATRIX_ROWS * MATRIX_COLS;
const MATRIX_AVG_PROGRAM_REGISTERS: usize = 32;

/// Test VM mesh integration with federated matrix average computation
///
/// This test demonstrates:
/// 1. Multiple clients each submitting a flattened matrix of values
/// 2. VMs computing element-wise sum of all matrices
/// 3. VMs dividing the total sum by (client_count * matrix_size) to get overall average
/// 4. Result verification against expected average
///
/// Matrix layout: Each client submits a MATRIX_ROWS x MATRIX_COLS matrix
/// stored as a flattened array (row-major order).
///
/// The test computes a single aggregated average of all matrix elements
/// across all clients (total sum / total element count).
#[tokio::test(flavor = "multi_thread")]
async fn test_vm_mesh_matrix_average_integration() {
    init_crypto_provider();
    setup_test_tracing();

    info!("=== Starting VM Mesh Matrix Average Integration Test ===");
    info!(
        "Matrix dimensions: {}x{} = {} elements per client",
        MATRIX_ROWS, MATRIX_COLS, MATRIX_SIZE
    );

    let n_parties = 5;
    let threshold = 1;
    // Preprocessing requirements:
    // - We need triples for division
    // - Random shares needed for input protocol
    let n_triples = 32;
    let n_random_shares = 64 + MATRIX_SIZE * 8; // Random shares for inputs
    let instance_id = 55555;
    let base_port = 9750;

    let config = HoneyBadgerQuicConfig {
        mpc_timeout: Duration::from_secs(30),
        connection_retry_delay: Duration::from_millis(100),
        ..Default::default()
    };

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

    // Generate test client data (matrices)
    let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
    let client_count = rng.gen_range(2..=4usize);
    let mut client_ids = Vec::new();
    let mut client_inputs = Vec::new();
    let mut total_sum: i64 = 0;

    info!(
        "Generating {} random matrices ({}x{}) from {} clients...",
        client_count, MATRIX_ROWS, MATRIX_COLS, client_count
    );

    for idx in 0..client_count {
        let client_id = 700 + idx as ClientId;
        client_ids.push(client_id);

        // Generate a random matrix (values between 1-100)
        let mut matrix_values: Vec<Fr> = Vec::new();
        let mut client_sum: i64 = 0;
        for _i in 0..MATRIX_SIZE {
            let value = rng.gen_range(1i64..=100i64);
            total_sum += value;
            client_sum += value;
            matrix_values.push(Fr::from(value as u64));
        }
        client_inputs.push(matrix_values);

        info!(
            "  Client {}: generated {}x{} matrix with sum {}",
            client_id, MATRIX_ROWS, MATRIX_COLS, client_sum
        );
    }

    // Calculate expected overall average
    let total_elements = client_count * MATRIX_SIZE;
    let expected_average = total_sum / total_elements as i64;

    info!(
        "Total sum: {}, Total elements: {}, Expected average: {}",
        total_sum, total_elements, expected_average
    );

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
        MATRIX_SIZE, // Each client sends MATRIX_SIZE values
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
    info!("Step 6: Initializing input protocol for {} clients with {} shares each...",
          client_count, MATRIX_SIZE);
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
                    server
                        .network
                        .clone()
                        .expect("network should be set"),
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

    // Step 8: Register and execute matrix average program
    info!("Step 8: Registering matrix average program...");
    let (matrix_avg_program, matrix_avg_labels) = build_matrix_average_program(MATRIX_SIZE);
    for vm_arc in &vms {
        let avg_fn = VMFunction::new(
            "matrix_average".to_string(),
            vec![],
            Vec::new(),
            None,
            MATRIX_AVG_PROGRAM_REGISTERS,
            matrix_avg_program.clone(),
            matrix_avg_labels.clone(),
        );
        let mut vm = vm_arc.lock();
        vm.register_function(avg_fn);
    }

    info!("Step 9: Executing matrix average program on all parties...");
    use futures::FutureExt;
    let handles: Vec<_> = vms
        .iter()
        .enumerate()
        .map(|(pid, vm_arc)| {
            let vm_arc = vm_arc.clone();
            tokio::task::spawn_blocking(move || {
                let mut vm = vm_arc.lock();
                let val = vm
                    .execute("matrix_average")
                    .map_err(|e| format!("VM execution failed at party {}: {}", pid, e))?;
                Ok::<(usize, Value), String>((pid, val))
            })
            .map(move |join_res| match join_res {
                Ok(inner) => inner,
                Err(e) => Err(format!("Join error executing VM {}: {:?}", pid, e)),
            })
        })
        .collect();

    let joined = tokio::time::timeout(Duration::from_secs(60), futures::future::join_all(handles))
        .await
        .expect("Timed out waiting for matrix average VM executions");

    let mut results = Vec::new();
    for res in joined {
        let (pid, val) = res.expect("VM execution task failed");
        results.push((pid, val));
    }

    // Step 10: Verify results
    info!("Step 10: Verifying matrix average results...");
    for (pid, val) in results {
        match val {
            Value::I64(computed_avg) => {
                // Allow small variance due to integer division
                let diff = (computed_avg - expected_average).abs();
                assert!(
                    diff <= 1,
                    "Party {} average mismatch: got {}, expected {} (diff {})",
                    pid, computed_avg, expected_average, diff
                );
                info!(
                    "✓ Party {} computed average {} (expected {})",
                    pid, computed_avg, expected_average
                );
            }
            other => {
                panic!("Party {} returned unexpected value type: {:?}", pid, other);
            }
        }
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
    info!("=== VM Mesh Matrix Average Integration Test PASSED ===");
    info!(
        "Successfully computed federated average of {} matrices ({}x{}) from {} clients",
        client_count, MATRIX_ROWS, MATRIX_COLS, client_count
    );
    info!("Total sum: {}, Total elements: {}, Average: {}", total_sum, total_elements, expected_average);
}

/// Build a program that computes the overall average of all matrix elements from all clients
///
/// The program:
/// 1. Gets the number of clients
/// 2. For each client, for each matrix element:
///    - Sum all elements across all clients into a single accumulator
/// 3. Divide the total sum by (num_clients * matrix_size) to get the overall average
/// 4. Returns the average as a single I64 value
///
/// This uses nested loops:
/// - Outer loop: iterate over clients
/// - Inner loop: iterate over matrix elements for each client
fn build_matrix_average_program(matrix_size: usize) -> (Vec<Instruction>, HashMap<String, usize>) {
    let mut instructions = Vec::new();
    let mut labels = HashMap::new();

    // Register allocation:
    // reg0 = general purpose / return value
    // reg1 = num_clients
    // reg2 = client index (outer loop counter)
    // reg3 = constant 1
    // reg4 = matrix_size constant
    // reg5 = element index (inner loop counter)
    // reg6 = scratch
    // reg7 = total_elements (num_clients * matrix_size)
    // reg16 = total sum accumulator (secret)
    // reg17 = total_elements as share (for division)
    // reg18 = scratch for shares

    // Get number of clients
    instructions.push(Instruction::CALL(
        "ClientStore.get_number_clients".to_string(),
    ));
    instructions.push(Instruction::MOV(1, 0)); // reg1 = num_clients

    // Initialize constants
    instructions.push(Instruction::LDI(3, Value::I64(1))); // reg3 = 1
    instructions.push(Instruction::LDI(4, Value::I64(matrix_size as i64))); // reg4 = matrix_size

    // Compute total_elements = num_clients * matrix_size
    instructions.push(Instruction::MUL(7, 1, 4)); // reg7 = num_clients * matrix_size

    // Initialize client index to 0
    instructions.push(Instruction::LDI(2, Value::I64(0))); // reg2 = 0 (client index)

    // Load first element of first client to initialize accumulator
    // client_index = 0, element_index = 0
    instructions.push(Instruction::LDI(0, Value::I64(0))); // client_index = 0
    instructions.push(Instruction::PUSHARG(0));
    instructions.push(Instruction::LDI(5, Value::I64(0))); // element_index = 0
    instructions.push(Instruction::PUSHARG(5));
    instructions.push(Instruction::CALL("ClientStore.take_share".to_string()));
    instructions.push(Instruction::MOV(16, 0)); // reg16 = first share (accumulator)

    // Start inner loop from element index 1 (already loaded element 0)
    instructions.push(Instruction::LDI(5, Value::I64(1))); // reg5 = 1 (element index)

    // Labels for loops
    let client_loop_label = "matrix_client_loop".to_string();
    let client_process_label = "matrix_client_process".to_string();
    let client_done_label = "matrix_client_done".to_string();
    let element_loop_label = "matrix_element_loop".to_string();
    let element_process_label = "matrix_element_process".to_string();
    let element_done_label = "matrix_element_done".to_string();
    let first_client_inner_loop = "first_client_inner".to_string();
    let first_client_inner_process = "first_client_inner_process".to_string();
    let first_client_inner_done = "first_client_inner_done".to_string();

    // === First, finish processing elements 1..matrix_size for client 0 ===
    labels.insert(first_client_inner_loop.clone(), instructions.len());
    instructions.push(Instruction::CMP(5, 4)); // Compare element_idx with matrix_size
    instructions.push(Instruction::JMPLT(first_client_inner_process.clone()));
    instructions.push(Instruction::JMP(first_client_inner_done.clone()));

    labels.insert(first_client_inner_process.clone(), instructions.len());
    // Get share for client 0, current element
    instructions.push(Instruction::LDI(0, Value::I64(0))); // client_index = 0
    instructions.push(Instruction::PUSHARG(0));
    instructions.push(Instruction::PUSHARG(5)); // element_index
    instructions.push(Instruction::CALL("ClientStore.take_share".to_string()));
    instructions.push(Instruction::MOV(18, 0)); // reg18 = share

    // Accumulate
    instructions.push(Instruction::ADD(16, 16, 18));

    // Increment element counter
    instructions.push(Instruction::ADD(5, 5, 3)); // reg5++
    instructions.push(Instruction::JMP(first_client_inner_loop.clone()));

    labels.insert(first_client_inner_done.clone(), instructions.len());

    // Start client loop from index 1 (already processed client 0)
    instructions.push(Instruction::LDI(2, Value::I64(1))); // reg2 = 1 (client index)

    // === OUTER LOOP: iterate over remaining clients (1 to num_clients-1) ===
    labels.insert(client_loop_label.clone(), instructions.len());
    instructions.push(Instruction::CMP(2, 1)); // Compare client_idx with num_clients
    instructions.push(Instruction::JMPLT(client_process_label.clone()));
    instructions.push(Instruction::JMP(client_done_label.clone()));

    labels.insert(client_process_label.clone(), instructions.len());

    // Initialize element index for this client
    instructions.push(Instruction::LDI(5, Value::I64(0))); // reg5 = 0 (element index)

    // === INNER LOOP: iterate over all elements for current client ===
    labels.insert(element_loop_label.clone(), instructions.len());
    instructions.push(Instruction::CMP(5, 4)); // Compare element_idx with matrix_size
    instructions.push(Instruction::JMPLT(element_process_label.clone()));
    instructions.push(Instruction::JMP(element_done_label.clone()));

    labels.insert(element_process_label.clone(), instructions.len());
    // Get share for current client, current element
    instructions.push(Instruction::PUSHARG(2)); // client_index
    instructions.push(Instruction::PUSHARG(5)); // element_index
    instructions.push(Instruction::CALL("ClientStore.take_share".to_string()));
    instructions.push(Instruction::MOV(18, 0)); // reg18 = share

    // Accumulate: reg16 += reg18
    instructions.push(Instruction::ADD(16, 16, 18));

    // Increment element counter
    instructions.push(Instruction::ADD(5, 5, 3)); // reg5++
    instructions.push(Instruction::JMP(element_loop_label.clone()));

    // === END INNER LOOP ===
    labels.insert(element_done_label.clone(), instructions.len());

    // Increment client counter
    instructions.push(Instruction::ADD(2, 2, 3)); // reg2++
    instructions.push(Instruction::JMP(client_loop_label.clone()));

    // === END OUTER LOOP ===
    labels.insert(client_done_label.clone(), instructions.len());

    // Now reg16 has the total sum of all elements across all clients
    // First, reveal the secret sum by moving to a clear register
    // MOV from secret to clear triggers MPC reveal protocol
    instructions.push(Instruction::MOV(8, 16)); // reg8 = revealed sum (triggers reveal)

    // Divide revealed sum (reg8) by total_elements (reg7) - both are now clear I64
    instructions.push(Instruction::DIV(0, 8, 7)); // reg0 = sum / total_elements

    instructions.push(Instruction::RET(0));

    (instructions, labels)
}

// ============================================================================
// Fixed-Point Matrix Average Test
// ============================================================================

/// Fixed-point precision constants (must match DEFAULT_FIXED_POINT_FRACTIONAL_BITS)
const FIXED_POINT_FRACTIONAL_BITS: usize = 16;
const FIXED_POINT_SCALE: i64 = 1 << FIXED_POINT_FRACTIONAL_BITS; // 2^16 = 65536

/// Test VM mesh integration with federated matrix average using fixed-point arithmetic
///
/// This test demonstrates:
/// 1. Multiple clients each submitting fixed-point scaled matrix values
/// 2. VMs computing element-wise sum using SecretFixedPoint shares
/// 3. VMs dividing the total sum by element count and unscaling to get the average
/// 4. Result verification against expected average
///
/// Fixed-point representation: values are scaled by 2^16 before secret sharing.
/// After reveal, the result must be unscaled to get the actual average.
#[tokio::test(flavor = "multi_thread")]
async fn test_vm_mesh_matrix_average_fixed_point_integration() {
    init_crypto_provider();
    setup_test_tracing();

    info!("=== Starting VM Mesh Matrix Average Fixed-Point Integration Test ===");
    info!(
        "Matrix dimensions: {}x{} = {} elements per client",
        MATRIX_ROWS, MATRIX_COLS, MATRIX_SIZE
    );
    info!("Fixed-point scale: 2^{} = {}", FIXED_POINT_FRACTIONAL_BITS, FIXED_POINT_SCALE);

    let n_parties = 5;
    let threshold = 1;
    let n_triples = 32;
    let n_random_shares = 64 + MATRIX_SIZE * 8;
    let instance_id = 66666; // Different instance ID to avoid collision
    let base_port = 9800;   // Different port range

    let config = HoneyBadgerQuicConfig {
        mpc_timeout: Duration::from_secs(30),
        connection_retry_delay: Duration::from_millis(100),
        ..Default::default()
    };

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
    // For federated averaging, we need to track per-element values to compute expected averages
    let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
    let client_count = rng.gen_range(2..=4usize);
    let mut client_ids = Vec::new();
    let mut client_inputs = Vec::new();

    // Track unscaled values per element position for expected average calculation
    let mut element_sums: Vec<f64> = vec![0.0; MATRIX_SIZE];

    info!(
        "Generating {} random matrices ({}x{}) from {} clients with fixed-point values...",
        client_count, MATRIX_ROWS, MATRIX_COLS, client_count
    );

    for idx in 0..client_count {
        let client_id = 800 + idx as ClientId;
        client_ids.push(client_id);

        // Generate random matrix with decimal values (e.g., 1.5, 42.75)
        // Scale them by 2^16 for fixed-point representation
        let mut matrix_values: Vec<Fr> = Vec::new();
        let mut client_sum: f64 = 0.0;
        for elem_idx in 0..MATRIX_SIZE {
            // Generate a value with fractional component (e.g., 1.0 to 100.0)
            let integer_part = rng.gen_range(1i64..=100i64);
            let fractional_part = rng.gen_range(0i64..=99i64); // Two decimal places
            let value = integer_part as f64 + (fractional_part as f64 / 100.0);
            element_sums[elem_idx] += value;
            client_sum += value;

            // Scale to fixed-point representation
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
    info!("Step 6: Initializing input protocol for {} clients with {} shares each...",
          client_count, MATRIX_SIZE);
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
                    server
                        .network
                        .clone()
                        .expect("network should be set"),
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
    // This program computes element-wise averages and sends them back to clients
    info!("Step 8: Registering federated averaging program...");
    let (fed_avg_program, fed_avg_labels) = build_federated_average_program(MATRIX_SIZE, client_count);
    for vm_arc in &vms {
        let avg_fn = VMFunction::new(
            "federated_average".to_string(),
            vec![],
            Vec::new(),
            None,
            MATRIX_AVG_PROGRAM_REGISTERS,
            fed_avg_program.clone(),
            fed_avg_labels.clone(),
        );
        let mut vm = vm_arc.lock();
        vm.register_function(avg_fn);
    }

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
    // The VM returns an array of element-wise averages (still in fixed-point scaled format)
    info!("Step 10: Verifying federated averaging results...");

    // All parties should return arrays with the same averaged values
    for (pid, val) in &results {
        match val {
            Value::Array(array_id) => {
                info!("Party {} returned array with id {}", pid, array_id);
                // We'll verify the array contents match expected averages
                // The array stores revealed fixed-point values
            }
            other => {
                panic!("Party {} returned unexpected value type: {:?}", pid, other);
            }
        }
    }

    // Verify element-wise averages from the first party's VM
    // (All parties should have identical results after MPC)
    {
        let (first_pid, first_val) = &results[0];
        if let Value::Array(array_id) = first_val {
            let vm = vms[*first_pid].lock();
            if let Some(arr) = vm.state.object_store.get_array(*array_id) {
                info!("Verifying {} averaged matrix elements:", arr.length());
                for elem_idx in 0..MATRIX_SIZE {
                    // Arrays are 1-indexed in this VM
                    let idx_val = Value::I64((elem_idx + 1) as i64);
                    if let Some(elem_val) = arr.get(&idx_val) {
                        // Extract the computed average value
                        // SecretFixedPoint now reveals directly to f64 (via F64 wrapper)
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
            // Use approximate comparison for floating point
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
    info!("=== VM Mesh Federated Averaging Integration Test PASSED ===");
    info!(
        "Successfully computed federated average of {} matrices ({}x{}) from {} clients",
        client_count, MATRIX_ROWS, MATRIX_COLS, client_count
    );
    info!("All {} parties computed identical element-wise averages", n_parties);
}

/// Build a program that computes the overall average using fixed-point shares
///
/// Uses ClientStore.take_share_fixed to load shares as SecretFixedPoint type.
/// After summing and revealing, the result is still in fixed-point format
/// and needs to be unscaled for the final average.
fn build_matrix_average_program_fixed_point(matrix_size: usize) -> (Vec<Instruction>, HashMap<String, usize>) {
    let mut instructions = Vec::new();
    let mut labels = HashMap::new();

    // Register allocation (same as integer version):
    // reg0 = general purpose / return value
    // reg1 = num_clients
    // reg2 = client index (outer loop counter)
    // reg3 = constant 1
    // reg4 = matrix_size constant
    // reg5 = element index (inner loop counter)
    // reg6 = scratch
    // reg7 = total_elements (num_clients * matrix_size)
    // reg8 = revealed sum (scaled)
    // reg9 = FIXED_POINT_SCALE constant
    // reg16 = total sum accumulator (secret fixed-point)
    // reg18 = scratch for shares

    // Get number of clients
    instructions.push(Instruction::CALL(
        "ClientStore.get_number_clients".to_string(),
    ));
    instructions.push(Instruction::MOV(1, 0)); // reg1 = num_clients

    // Initialize constants
    instructions.push(Instruction::LDI(3, Value::I64(1))); // reg3 = 1
    instructions.push(Instruction::LDI(4, Value::I64(matrix_size as i64))); // reg4 = matrix_size
    instructions.push(Instruction::LDI(9, Value::I64(FIXED_POINT_SCALE))); // reg9 = 2^16

    // Compute total_elements = num_clients * matrix_size
    instructions.push(Instruction::MUL(7, 1, 4)); // reg7 = num_clients * matrix_size

    // Initialize client index to 0
    instructions.push(Instruction::LDI(2, Value::I64(0))); // reg2 = 0 (client index)

    // Load first element of first client to initialize accumulator (FIXED POINT)
    instructions.push(Instruction::LDI(0, Value::I64(0))); // client_index = 0
    instructions.push(Instruction::PUSHARG(0));
    instructions.push(Instruction::LDI(5, Value::I64(0))); // element_index = 0
    instructions.push(Instruction::PUSHARG(5));
    instructions.push(Instruction::CALL("ClientStore.take_share_fixed".to_string())); // Fixed-point share
    instructions.push(Instruction::MOV(16, 0)); // reg16 = first share (accumulator)

    // Start inner loop from element index 1
    instructions.push(Instruction::LDI(5, Value::I64(1))); // reg5 = 1 (element index)

    // Labels for loops
    let first_client_inner_loop = "fp_first_client_inner".to_string();
    let first_client_inner_process = "fp_first_client_inner_process".to_string();
    let first_client_inner_done = "fp_first_client_inner_done".to_string();
    let client_loop_label = "fp_matrix_client_loop".to_string();
    let client_process_label = "fp_matrix_client_process".to_string();
    let client_done_label = "fp_matrix_client_done".to_string();
    let element_loop_label = "fp_matrix_element_loop".to_string();
    let element_process_label = "fp_matrix_element_process".to_string();
    let element_done_label = "fp_matrix_element_done".to_string();

    // === First, finish processing elements 1..matrix_size for client 0 ===
    labels.insert(first_client_inner_loop.clone(), instructions.len());
    instructions.push(Instruction::CMP(5, 4)); // Compare element_idx with matrix_size
    instructions.push(Instruction::JMPLT(first_client_inner_process.clone()));
    instructions.push(Instruction::JMP(first_client_inner_done.clone()));

    labels.insert(first_client_inner_process.clone(), instructions.len());
    instructions.push(Instruction::LDI(0, Value::I64(0))); // client_index = 0
    instructions.push(Instruction::PUSHARG(0));
    instructions.push(Instruction::PUSHARG(5)); // element_index
    instructions.push(Instruction::CALL("ClientStore.take_share_fixed".to_string())); // Fixed-point share
    instructions.push(Instruction::MOV(18, 0)); // reg18 = share

    // Accumulate
    instructions.push(Instruction::ADD(16, 16, 18));

    // Increment element counter
    instructions.push(Instruction::ADD(5, 5, 3)); // reg5++
    instructions.push(Instruction::JMP(first_client_inner_loop.clone()));

    labels.insert(first_client_inner_done.clone(), instructions.len());

    // Start client loop from index 1 (already processed client 0)
    instructions.push(Instruction::LDI(2, Value::I64(1))); // reg2 = 1 (client index)

    // === OUTER LOOP: iterate over remaining clients ===
    labels.insert(client_loop_label.clone(), instructions.len());
    instructions.push(Instruction::CMP(2, 1)); // Compare client_idx with num_clients
    instructions.push(Instruction::JMPLT(client_process_label.clone()));
    instructions.push(Instruction::JMP(client_done_label.clone()));

    labels.insert(client_process_label.clone(), instructions.len());

    // Initialize element index for this client
    instructions.push(Instruction::LDI(5, Value::I64(0))); // reg5 = 0 (element index)

    // === INNER LOOP: iterate over all elements for current client ===
    labels.insert(element_loop_label.clone(), instructions.len());
    instructions.push(Instruction::CMP(5, 4)); // Compare element_idx with matrix_size
    instructions.push(Instruction::JMPLT(element_process_label.clone()));
    instructions.push(Instruction::JMP(element_done_label.clone()));

    labels.insert(element_process_label.clone(), instructions.len());
    // Get fixed-point share for current client, current element
    instructions.push(Instruction::PUSHARG(2)); // client_index
    instructions.push(Instruction::PUSHARG(5)); // element_index
    instructions.push(Instruction::CALL("ClientStore.take_share_fixed".to_string())); // Fixed-point share
    instructions.push(Instruction::MOV(18, 0)); // reg18 = share

    // Accumulate: reg16 += reg18
    instructions.push(Instruction::ADD(16, 16, 18));

    // Increment element counter
    instructions.push(Instruction::ADD(5, 5, 3)); // reg5++
    instructions.push(Instruction::JMP(element_loop_label.clone()));

    // === END INNER LOOP ===
    labels.insert(element_done_label.clone(), instructions.len());

    // Increment client counter
    instructions.push(Instruction::ADD(2, 2, 3)); // reg2++
    instructions.push(Instruction::JMP(client_loop_label.clone()));

    // === END OUTER LOOP ===
    labels.insert(client_done_label.clone(), instructions.len());

    // Reveal the secret sum (still scaled by 2^16)
    // Note: SecretFixedPoint shares reveal as Value::Float, which internally is i64
    instructions.push(Instruction::MOV(8, 16)); // reg8 = revealed sum (triggers reveal, returns Float)

    // For fixed-point division, we need Float/I64 support.
    // Current workaround: Return the revealed scaled sum directly.
    // The test will:
    // 1. Take the scaled sum (which is sum * 2^16)
    // 2. Divide by total_elements to get average * 2^16
    // 3. Divide by 2^16 to get actual average
    //
    // Since Float is internally i64, return it and compute average in test
    instructions.push(Instruction::MOV(0, 8));
    instructions.push(Instruction::RET(0));

    (instructions, labels)
}

/// Build a federated averaging program for machine learning
///
/// This implements the core of federated learning:
/// 1. Each client provides their local model weights (as a matrix)
/// 2. The servers compute element-wise averages across all client matrices
/// 3. The averaged matrix is sent back to each client
///
/// For a matrix of size `matrix_size` elements:
/// - Sum each element position across all `num_clients` clients
/// - Divide each sum by `num_clients` to get the average
/// - Store results in an array and return it
/// - Send averaged values back to each client
fn build_federated_average_program(matrix_size: usize, _num_clients: usize) -> (Vec<Instruction>, HashMap<String, usize>) {
    let mut instructions = Vec::new();
    let mut labels = HashMap::new();

    // Register allocation:
    // reg0 = general purpose / return value / function results
    // reg1 = num_clients
    // reg2 = client index (outer loop counter for summing)
    // reg3 = constant 1
    // reg4 = matrix_size constant
    // reg5 = element index (outer loop for element-wise processing)
    // reg6 = result array reference
    // reg7 = current element sum accumulator (clear register for revealed value)
    // reg8 = scratch
    // reg9 = current client index for output sending
    // reg10 = client_id for output
    // reg11 = 800 (base client id)
    // reg16 = current element sum accumulator (secret share)
    // reg17 = scratch for shares
    // reg18 = scratch for shares

    // Step 1: Get number of clients and initialize constants
    instructions.push(Instruction::CALL("ClientStore.get_number_clients".to_string()));
    instructions.push(Instruction::MOV(1, 0)); // reg1 = num_clients

    instructions.push(Instruction::LDI(3, Value::I64(1))); // reg3 = 1
    instructions.push(Instruction::LDI(4, Value::I64(matrix_size as i64))); // reg4 = matrix_size
    instructions.push(Instruction::LDI(11, Value::I64(800))); // reg11 = base client id

    // Step 2: Create result array to store revealed averaged values (for verification)
    instructions.push(Instruction::LDI(0, Value::I64(matrix_size as i64))); // capacity
    instructions.push(Instruction::PUSHARG(0));
    instructions.push(Instruction::CALL("create_array".to_string()));
    instructions.push(Instruction::MOV(6, 0)); // reg6 = result array (revealed values)

    // Create shares array to store secret shares for sending to clients
    instructions.push(Instruction::LDI(0, Value::I64(matrix_size as i64))); // capacity
    instructions.push(Instruction::PUSHARG(0));
    instructions.push(Instruction::CALL("create_array".to_string()));
    instructions.push(Instruction::MOV(12, 0)); // reg12 = shares array (secret shares)

    // Step 3: Element-wise loop - for each element position
    instructions.push(Instruction::LDI(5, Value::I64(0))); // reg5 = 0 (element index)

    let elem_loop = "fed_elem_loop".to_string();
    let elem_process = "fed_elem_process".to_string();
    let elem_done = "fed_elem_done".to_string();
    let client_sum_loop = "fed_client_sum_loop".to_string();
    let client_sum_process = "fed_client_sum_process".to_string();
    let client_sum_done = "fed_client_sum_done".to_string();

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

    // First reveal the sum (before dividing) - this is needed to get correct values
    // MOV from secret register to clear register triggers MPC reveal
    instructions.push(Instruction::MOV(7, 16)); // reg7 = revealed sum

    // Divide by num_clients to get average (now operating on clear values)
    instructions.push(Instruction::DIV(7, 7, 1)); // reg7 = sum / num_clients

    // Store the revealed averaged value in the result array
    instructions.push(Instruction::ADD(8, 5, 3)); // reg8 = element_index + 1 (1-indexed)
    instructions.push(Instruction::PUSHARG(6)); // result array ref
    instructions.push(Instruction::PUSHARG(8)); // index (1-based)
    instructions.push(Instruction::PUSHARG(7)); // value (revealed average)
    instructions.push(Instruction::CALL("set_field".to_string()));

    // Also store the secret share (before reveal) for sending to clients
    // We need to divide the secret share by num_clients
    // Re-compute: divide the original secret sum by num_clients
    // But we already revealed it... we need to copy the share before revealing
    // For now, we store the revealed value - clients will get clear values
    // TODO: To send secret shares, we need to copy the share before revealing
    instructions.push(Instruction::PUSHARG(12)); // shares array ref
    instructions.push(Instruction::PUSHARG(8)); // index (1-based)
    instructions.push(Instruction::PUSHARG(7)); // value (revealed average, not secret)
    instructions.push(Instruction::CALL("set_field".to_string()));

    // Increment element counter
    instructions.push(Instruction::ADD(5, 5, 3)); // reg5++
    instructions.push(Instruction::JMP(elem_loop.clone()));

    // === END ELEMENT LOOP ===
    labels.insert(elem_done.clone(), instructions.len());

    // Step 4: Output to clients
    // In standard federated learning, the averaged model is sent back to all clients.
    // Since we revealed the values, they are now clear (not secret shares).
    // All parties have the same averaged values, which can be sent to clients.
    //
    // For secret output (where only specific clients can learn the result),
    // we would need to keep values as shares and use MpcOutput.send_to_client.
    // That requires NOT revealing before the output protocol.
    //
    // For now, we've computed the federated average correctly and verified it.
    // The shares array contains the revealed averages that could be broadcast to clients.

    // Return the result array (with revealed averaged values)
    instructions.push(Instruction::MOV(0, 6));
    instructions.push(Instruction::RET(0));

    (instructions, labels)
}
