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
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::SeedableRng;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use stoffelmpc_mpc::common::{SecretSharingScheme, MPCProtocol, PreprocessingMPCProtocol};
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::ProtocolType;
use stoffelnet::network_utils::ClientId;
use tracing::info;

use crate::core_vm::VirtualMachine;
use crate::net::hb_engine::HoneyBadgerMpcEngine;
use crate::net::mpc_engine::MpcEngine;
use crate::tests::mpc_multiplication_integration::{
    HoneyBadgerQuicConfig, setup_honeybadger_quic_network,
};
use stoffel_vm_types::core_types::{ShareType, Value};
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
            .with_env_filter(
                EnvFilter::from_default_env().add_directive("info".parse().unwrap()),
            )
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
    let n_triples = 2 * threshold + 1;
    let n_random_shares = 2 + 2 * n_triples;
    let instance_id = 99999;
    let base_port = 9400;

    let config = HoneyBadgerQuicConfig {
        mpc_timeout: Duration::from_secs(10),
        connection_retry_delay: Duration::from_millis(100),
        ..Default::default()
    };

    // Step 1: Create mesh network of MPC servers
    info!("Step 1: Creating {} MPC servers in mesh topology...", n_parties);
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

    // Step 4: Run preprocessing
    info!("Step 4: Running preprocessing on all servers...");
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

    // Step 5: Simulate clients sending masked shares to each node (per-party storage)
    info!("Step 5: Clients submitting masked input shares to nodes...");
    let client_id: ClientId = 200;
    let input_x = Fr::from(15u64);
    let input_y = Fr::from(25u64);

    let mut rng = ark_std::test_rng();
    let shares_x = RobustShare::compute_shares(input_x, n_parties, threshold, None, &mut rng)
        .expect("Failed to compute shares for x");
    let shares_y = RobustShare::compute_shares(input_y, n_parties, threshold, None, &mut rng)
        .expect("Failed to compute shares for y");

    // Place each party's share into its node's input storage (what HB uses internally)
    for (party_id, server) in servers.iter_mut().enumerate() {
        let mut input_store = server.node.preprocess.input.input_shares.lock().await;
        input_store.insert(client_id, vec![shares_x[party_id].clone(), shares_y[party_id].clone()]);
    }
    info!("✓ Client {} shares stored on all HB nodes", client_id);

    // Step 6: Create VMs for each node
    info!("Step 6: Creating VMs for each node...");
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

        info!("✓ VM {} created with MPC engine (wrapped server node)", party_id);
    }

    // Step 7: Register VM program that loads client inputs and multiplies them
    info!("Step 7: Registering VM programs...");

    for (party_id, vm_arc) in vms.iter().enumerate() {
        // Read this party's shares directly from the HB node storage and embed into the program
        let shares_for_party = {
            let input_store = servers[party_id].node.preprocess.input.input_shares.lock().await;
            input_store.get(&client_id).cloned().expect("Party missing client shares")
        };

        use ark_serialize::CanonicalSerialize;
        let mut sx = Vec::new();
        let mut sy = Vec::new();
        shares_for_party[0].serialize_compressed(&mut sx).unwrap();
        shares_for_party[1].serialize_compressed(&mut sy).unwrap();

        // Create a function that multiplies the shares
        let multiply_fn = VMFunction::new(
            "multiply_client_inputs".to_string(),
            vec![],
            Vec::new(),
            None,
            3,
            vec![
                // LDI secret shares directly (register index doesn't affect share semantics)
                Instruction::LDI(0, Value::Share(ShareType::Int(64), sx)),
                Instruction::LDI(1, Value::Share(ShareType::Int(64), sy)),
                // This MUL will trigger MPC multiplication via the engine
                Instruction::MUL(2, 0, 1),
                // Return the resulting share; we'll open across parties afterwards
                Instruction::RET(2),
            ],
            HashMap::new(),
        );

        {
            let mut vm = vm_arc.lock();
            vm.register_function(multiply_fn);
        }
        info!("✓ VM {} program registered", party_id);
    }

    // Step 8: Execute VM programs on all parties (this triggers MPC multiplication)
    info!("Step 8: Executing VM programs on all parties...");

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

    // Step 9: Reveal and verify the result across parties using the engine's open_share registry
    info!("Step 9: Revealing and verifying result...");

    // Feed each returned share to open_share; when 2t+1 shares are present one will succeed
    let mut revealed: Option<Value> = None;
    for (pid, val) in party_results.iter() {
        let engine = {
            let vm = vms[*pid].lock();
            vm.state.mpc_engine().expect("Engine missing")
        };
        match val {
            Value::Share(ShareType::Int(_), bytes) => {
                match engine.open_share(ShareType::Int(64), bytes) {
                    Ok(clear) => {
                        revealed = Some(clear);
                        break;
                    }
                    Err(e) => {
                        info!("open_share at party {} pending/err: {}", pid, e);
                    }
                }
            }
            other => panic!("Unexpected VM return value: {:?}", other),
        }
    }

    let clear = revealed.expect("Failed to reconstruct result from shares");
    match clear {
        Value::I64(v) => {
            assert_eq!(v, 15 * 25);
            info!("✓ Revealed result: {}", v);
        }
        _ => panic!("Unexpected revealed value type: {:?}", clear),
    }

    // Step 10: Summary
    info!("Step 10: Integration test summary");
    info!("✓ {} nodes connected in mesh topology", n_parties);
    info!("✓ Preprocessing generated {} triples", n_triples);
    info!("✓ Client {} provided inputs: x=15, y=25", client_id);
    info!("✓ All nodes accessed client shares from their HB input storage");
    info!("✓ MPC multiplication computed and revealed: 15 × 25 = 375");
    info!("");
    info!("=== Full VM Mesh Integration Test PASSED ===");

    // Cleanup
    for mut server in servers {
        server.stop().await;
    }
}
