//! VM + HB Client end-to-end: 5-VM mesh where inputs are provided by a real HoneyBadgerMPCClient
//! and the VM executes a program that multiplies the two secret inputs and reveals the result.

use ark_bls12_381::Fr;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::SeedableRng;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use stoffelmpc_mpc::common::{MPCProtocol, PreprocessingMPCProtocol};
use stoffelmpc_mpc::honeybadger::ProtocolType;
use stoffelnet::network_utils::ClientId;
use tracing::info;

use crate::core_vm::VirtualMachine;
use crate::net::hb_engine::HoneyBadgerMpcEngine;
use crate::net::mpc_engine::MpcEngine;
use crate::tests::mpc_multiplication_integration::{
    setup_honeybadger_quic_clients, setup_honeybadger_quic_network, HoneyBadgerQuicConfig,
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
            .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
            .with_test_writer()
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    });
}

// Use a multi-thread Tokio runtime to allow the VM's sync MPC bridge to block safely.
#[tokio::test(flavor = "multi_thread")]
async fn test_vm_mesh_hbclient_integration() {
    init_crypto_provider();
    setup_test_tracing();

    info!("=== Starting VM + HB Client Mesh Integration Test ===");

    // Configuration (align with reference test_preprocessing_client_mul)
    let n_parties = 5;
    let threshold = 1;
    let n_triples = 2 * threshold + 1; // minimal but sufficient
    let n_random_shares = 2 + 2 * n_triples;
    let instance_id = 99999u64;
    let base_port = 9500u16; // distinct from other tests

    let mut config = HoneyBadgerQuicConfig::default();
    config.mpc_timeout = Duration::from_secs(10);
    config.connection_retry_delay = Duration::from_millis(100);

    // Step 1: Create servers
    info!("Step 1: Creating {} servers...", n_parties);
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

    // Prepare server addresses for clients
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
        let mut node = server.node.clone();
        let network = server.network.clone();
        let mut rx = recv.remove(0);
        tokio::spawn(async move {
            while let Some(raw_msg) = rx.recv().await {
                if let Err(e) = node.process(raw_msg, network.clone()).await {
                    tracing::error!("Node {i} failed to process message: {e:?}");
                }
            }
            tracing::info!("Receiver task for node {i} ended");
        });

        server.start().await.expect("Failed to start server");
        info!("✓ Started server {}", server.node_id);
    }

    // Step 3: Connect servers to each other
    info!("Step 3: Connecting servers to each other...");
    for server in &servers {
        server
            .connect_to_peers()
            .await
            .expect("Failed to connect to peers");
    }
    info!("✓ Servers connected to peers");

    // Step 4: Create HB clients and connect to servers
    info!("Step 4: Creating and connecting HB clients...");
    let client_ids: Vec<ClientId> = vec![100]; // single input client as in reference
    let inputs: Vec<Vec<Fr>> = vec![vec![Fr::from(10u64), Fr::from(20u64)]]; // same values
    let mut clients = setup_honeybadger_quic_clients::<Fr>(
        client_ids.clone(),
        server_addresses,
        n_parties,
        threshold,
        instance_id,
        inputs,
        2,
        config.clone(),
    )
    .await
    .expect("Failed to create clients");

    for client in &mut clients {
        client
            .connect_to_servers()
            .await
            .expect("Client failed to connect to servers");
        info!("✓ Client {} connected to servers", client.client_id);
    }

    // Step 5: Run preprocessing across servers (concurrently)
    info!("Step 5: Running preprocessing on all servers...");
    let preprocessing_timeout = Duration::from_secs(30);
    let preprocessing_handles: Vec<_> = servers
        .iter()
        .enumerate()
        .map(|(i, server)| {
            let mut node = server.node.clone();
            let network = server.network.clone();
            tokio::spawn(async move {
                info!("[Server {}] Starting preprocessing...", i);
                let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
                let res = tokio::time::timeout(preprocessing_timeout, async {
                    node.run_preprocessing(network, &mut rng).await
                })
                .await;
                match res {
                    Ok(Ok(())) => Ok::<(), String>(()),
                    Ok(Err(e)) => Err(format!("Preprocessing error: {e:?}")),
                    Err(_) => Err(format!(
                        "Preprocessing timeout after {:?}",
                        preprocessing_timeout
                    )),
                }
            })
        })
        .collect();

    let results = futures::future::join_all(preprocessing_handles).await;
    for (i, res) in results.iter().enumerate() {
        match res {
            Ok(Ok(())) => info!("✓ Server {} preprocessing complete", i),
            Ok(Err(e)) => panic!("Server {} preprocessing failed: {}", i, e),
            Err(e) => panic!("Server {} preprocessing task panicked: {:?}", i, e),
        }
    }

    // Step 6: Initialize client inputs via HB input protocol
    info!("Step 6: Initializing HB input protocol on servers...");
    let input_client = client_ids[0];
    for (i, server) in servers.iter_mut().enumerate() {
        // Take local random shares and call input.init for this client
        let local_shares = server
            .node
            .preprocessing_material
            .lock()
            .await
            .take_random_shares(2)
            .expect("Failed to take random shares for input");

        server
            .node
            .preprocess
            .input
            .init(input_client, local_shares, 2, server.network.clone())
            .await
            .expect("input.init failed");
        info!(
            "✓ Server {} initialized inputs for client {}",
            i, input_client
        );
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Step 7: Create one VM per party and attach an MPC engine that wraps this party's HB node
    info!("Step 7: Creating VMs and attaching MPC engines...");
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
    info!("✓ VMs created and MPC engines attached");

    // Step 8: Register per-party VM program that multiplies the two client inputs
    info!("Step 8: Registering VM programs...");
    for (party_id, vm_arc) in vms.iter().enumerate() {
        // Read this party's client shares from the HB input store
        let shares_for_party = {
            let input_store = servers[party_id]
                .node
                .preprocess
                .input
                .input_shares
                .lock()
                .await;
            input_store
                .get(&input_client)
                .cloned()
                .expect("Party missing client shares in HB input store")
        };

        let mut sx = Vec::new();
        let mut sy = Vec::new();
        shares_for_party[0].serialize_compressed(&mut sx).unwrap();
        shares_for_party[1].serialize_compressed(&mut sy).unwrap();

        let multiply_fn = VMFunction::new(
            "multiply_client_inputs".to_string(),
            vec![],
            Vec::new(),
            None,
            3,
            vec![
                Instruction::LDI(0, Value::Share(ShareType::secret_int(64), sx)),
                Instruction::LDI(1, Value::Share(ShareType::secret_int(64), sy)),
                Instruction::MUL(2, 0, 1),
                Instruction::RET(2),
            ],
            HashMap::new(),
        );

        let mut vm = vm_arc.lock();
        vm.register_function(multiply_fn);
        info!("✓ VM {} program registered", party_id);
    }

    // Step 9: Execute all VMs concurrently, triggering HB online multiplication
    info!("Step 9: Executing VM programs concurrently...");
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

    let joined = tokio::time::timeout(Duration::from_secs(60), futures::future::join_all(handles))
        .await
        .expect("Timed out waiting for VMs to execute; possible deadlock if parties didn't run concurrently");

    let mut party_results: Vec<(usize, Value)> = Vec::new();
    for res in joined {
        let (pid, val) = res.expect("VM execution task failed");
        info!("✓ VM {} executed program", pid);
        party_results.push((pid, val));
    }

    // Step 10: Reveal result using engine.open_share across parties
    info!("Step 10: Revealing and verifying result...");
    let mut revealed: Option<Value> = None;
    for (pid, val) in party_results.iter() {
        let engine = {
            let vm = vms[*pid].lock();
            vm.state.mpc_engine().expect("Engine missing on VM")
        };

        match val {
            Value::Share(ShareType::SecretInt { .. }, bytes) => {
                match engine.open_share(ShareType::secret_int(64), bytes) {
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
            assert_eq!(v, 10 * 20);
            info!("✓ Revealed result: {}", v);
        }
        _ => panic!("Unexpected revealed value type: {:?}", clear),
    }

    // Step 11: Cleanup
    info!("Step 11: Cleanup");
    for mut server in servers {
        server.stop().await;
    }
    // Stop clients (returns the MPC client object; we ignore it for now)
    for client in clients.into_iter() {
        let _ = client.stop().await;
    }

    info!("=== VM + HB Client Mesh Integration Test PASSED ===");
}
