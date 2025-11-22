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
use ark_std::rand::{Rng, SeedableRng};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use stoffelmpc_mpc::common::{MPCProtocol, PreprocessingMPCProtocol};
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::ProtocolType;
use stoffelnet::network_utils::ClientId;
use tracing::info;

use crate::core_vm::VirtualMachine;
use crate::net::hb_engine::HoneyBadgerMpcEngine;
use crate::net::mpc_engine::MpcEngine;
use crate::tests::mpc_multiplication_integration::{
    setup_honeybadger_quic_clients, setup_honeybadger_quic_network, HoneyBadgerQuicConfig,
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
        .max(1) * 3;
    let n_triples = program_mul_count;
    let n_random_shares = 2 + 2 * n_triples;
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
        let mut node = server.node.clone();
        let network = server.network.clone();
        let mut rx = recv.remove(0);

        tokio::spawn(async move {
            while let Some(raw_msg) = rx.recv().await {
                if let Err(e) = node.process(raw_msg, network.clone()).await {
                    tracing::error!("Node {i} failed to process message: {e:?}");
                }
            }
        });

        server.start().await.expect("Failed to start server");
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
            let network = server.network.clone();

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
                .init(*client_id, local_shares, 1, server.network.clone())
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
            servers[party_id].network.clone(),
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
    let max_client_random = MAX_AVG_CLIENTS * 2; // two shares per client input
    let n_triples = 32 * max_client_random; // ample for average workflow
    let n_random_shares = 2 + 2 * n_triples;
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
        let mut node = server.node.clone();
        let network = server.network.clone();
        let mut rx = recv.remove(0);
        tokio::spawn(async move {
            while let Some(raw_msg) = rx.recv().await {
                if let Err(e) = node.process(raw_msg, network.clone()).await {
                    tracing::error!("Node {i} failed to process message: {e:?}");
                }
            }
        });
        server.start().await.expect("Failed to start server");
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
            let network = server.network.clone();
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
                .init(*client_id, local_shares, 2, server.network.clone())
                .await
                .expect("input.init failed");
        }
        info!("✓ Server {} initialized input protocol", idx);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    info!("Creating VMs for average computation...");
    let mut vms: Vec<Arc<parking_lot::Mutex<VirtualMachine>>> = Vec::new();
    for party_id in 0..n_parties {
        let mut vm = VirtualMachine::new();
        let engine = HoneyBadgerMpcEngine::from_existing_node(
            instance_id,
            party_id,
            n_parties,
            threshold,
            servers[party_id].network.clone(),
            servers[party_id].node.clone(),
        );
        vm.state.set_mpc_engine(engine);
        vms.push(Arc::new(parking_lot::Mutex::new(vm)));
    }

    info!("Hydrating VM client stores for average test...");
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
    let joined = futures::future::join_all(handles).await;
    let mut results = Vec::new();
    for res in joined {
        let Ok((pid, val)) = res.expect("VM execution task failed") else {
            todo!()
        };
        results.push((pid, val));
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

    instructions.push(Instruction::CALL(
        "ClientStore.get_number_clients".to_string(),
    ));
    instructions.push(Instruction::MOV(1, 0));

    instructions.push(Instruction::LDI(0, Value::I64(0)));
    instructions.push(Instruction::MOV(16, 0));
    instructions.push(Instruction::LDI(0, Value::I64(0)));
    instructions.push(Instruction::MOV(17, 0));

    for idx in 0..MAX_AVG_CLIENTS {
        let process_label = format!("avg_process_{}", idx);
        let skip_label = format!("avg_skip_{}", idx);

        instructions.push(Instruction::LDI(0, Value::I64(idx as i64)));
        instructions.push(Instruction::CMP(0, 1));
        instructions.push(Instruction::JMPLT(process_label.clone()));
        instructions.push(Instruction::JMP(skip_label.clone()));

        labels.insert(process_label.clone(), instructions.len());

        instructions.push(Instruction::LDI(0, Value::I64(idx as i64)));
        instructions.push(Instruction::PUSHARG(0));
        instructions.push(Instruction::LDI(1, Value::I64(0)));
        instructions.push(Instruction::PUSHARG(1));
        instructions.push(Instruction::CALL("ClientStore.take_share".to_string()));
        instructions.push(Instruction::MOV(18, 0));

        instructions.push(Instruction::LDI(0, Value::I64(idx as i64)));
        instructions.push(Instruction::PUSHARG(0));
        instructions.push(Instruction::LDI(1, Value::I64(1)));
        instructions.push(Instruction::PUSHARG(1));
        instructions.push(Instruction::CALL("ClientStore.take_share".to_string()));
        instructions.push(Instruction::MOV(19, 0));

        instructions.push(Instruction::ADD(16, 16, 18));
        instructions.push(Instruction::ADD(17, 17, 19));

        labels.insert(skip_label.clone(), instructions.len());
    }

    instructions.push(Instruction::MOV(2, 16));
    instructions.push(Instruction::MOV(3, 17));
    instructions.push(Instruction::DIV(4, 2, 3));
    instructions.push(Instruction::MOV(0, 4));
    instructions.push(Instruction::RET(0));

    (instructions, labels)
}

const MAX_AVG_CLIENTS: usize = 8;
