use ark_bls12_381::Fr;
use ark_ff::{PrimeField, UniformRand};
use ark_std::{
    rand::{
        rngs::{OsRng, StdRng},
        SeedableRng,
    },
    test_rng,
};
use futures::future::join_all;
use std::{
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use stoffelnet::{
    network_utils::{ClientId, Network},
    transports::quic::{QuicNetworkManager, QuicNode},
};
use stoffelmpc_mpc::{
    common::{
        rbc::rbc::Avid,
        MPCProtocol,
        PreprocessingMPCProtocol,
        SecretSharingScheme,
        ShamirShare,
    },
    honeybadger::{
        input::input::{InputClient, InputServer},
        robust_interpolate::robust_interpolate::{Robust, RobustShare},
        HoneyBadgerMPCNode,
        HoneyBadgerMPCNodeOpts,
        ProtocolType,
        SessionId,
        WrappedMessage,
    },
};
use stoffelnet::transports::quic::NetworkManager;
use tokio::{
    sync::mpsc,
    time::{sleep, timeout},
};
use tokio::sync::Mutex;
use tracing::{info, warn, error};

/// Test setup configuration
const N_SERVERS: u16 = 5;
const THRESHOLD: usize = 1; // t = 1, so we can tolerate 1 faulty party
const CLIENT_ID: ClientId = 100;
const BASE_PORT: u16 = 8000;

/// Test data for multiplication
const INPUT_A: u64 = 42;
const INPUT_B: u64 = 37;
const EXPECTED_RESULT: u64 = INPUT_A * INPUT_B; // 1554

#[tokio::test]
async fn test_honeybadger_multiplication_with_quic() {
    // Initialize tracing for debugging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    info!("Starting HoneyBadgerMPC multiplication test with QUIC transport");

    // Step 1: Set up network addresses
    let server_addresses: Vec<SocketAddr> = (0..N_SERVERS)
        .map(|i| format!("127.0.0.1:{}", BASE_PORT + i).parse().unwrap())
        .collect();

    let client_address: SocketAddr = format!("127.0.0.1:{}", BASE_PORT + N_SERVERS)
        .parse()
        .unwrap();

    // Step 2: Create and start servers
    let mut server_handles = Vec::new();
    let mut server_nodes = Vec::new();

    for (server_id, &server_addr) in server_addresses.iter().enumerate() {
        let (server_node, handle) = create_server_node(
            server_id,
            server_addr,
            server_addresses.clone(),
        ).await;

        server_nodes.push(server_node);
        server_handles.push(handle);
    }

    // Step 3: Wait for servers to be ready
    sleep(Duration::from_millis(500)).await;
    info!("All servers started, waiting for network to stabilize");

    // Step 4: Run preprocessing on all servers
    info!("Starting preprocessing phase");
    let preprocessing_handles: Vec<_> = server_nodes
        .iter()
        .enumerate()
        .map(|(i, node)| {
            let mut node = node.clone();
            tokio::spawn(async move {
                let mut rng = StdRng::from_rng(OsRng).unwrap();
                if let Err(e) = node.run_preprocessing(Arc::new(QuicNetworkManager::new()), &mut rng).await {
                    error!("Preprocessing failed for server {}: {:?}", i, e);
                }
            })
        })
        .collect();

    // Wait for preprocessing to complete
    let results = join_all(preprocessing_handles).await;
    for (i, result) in results.into_iter().enumerate() {
        if let Err(e) = result {
            panic!("Server {} preprocessing task panicked: {:?}", i, e);
        }
    }
    info!("Preprocessing completed for all servers");

    // Step 5: Create and run client
    let client_handle = create_and_run_client(
        client_address,
        server_addresses.clone(),
    ).await;

    // Step 6: Wait for input phase to complete
    sleep(Duration::from_millis(1000)).await;
    info!("Input phase completed");

    // Step 7: Perform multiplication
    info!("Starting multiplication phase");
    let multiplication_handles: Vec<_> = server_nodes
        .iter()
        .enumerate()
        .map(|(i, node)| {
            let mut node = node.clone();
            tokio::spawn(async move {
                // Get input shares from the client
                let input_shares = get_input_shares_from_client(&node, CLIENT_ID).await;

                // Multiply the two input values
                let x_shares = vec![input_shares[0].clone()];  // First input
                let y_shares = vec![input_shares[1].clone()];  // Second input

                match node.mul(x_shares, y_shares, Arc::new(QuicNetworkManager::new())).await {
                    Ok(result_shares) => {
                        info!("Server {} multiplication completed", i);
                        result_shares
                    }
                    Err(e) => {
                        error!("Multiplication failed for server {}: {:?}", i, e);
                        vec![]
                    }
                }
            })
        })
        .collect();

    // Wait for multiplication to complete
    let multiplication_results = join_all(multiplication_handles).await;

    // Step 8: Verify results
    info!("Verifying multiplication results");
    let mut all_result_shares = Vec::new();

    for (i, result) in multiplication_results.into_iter().enumerate() {
        match result {
            Ok(shares) => {
                if !shares.is_empty() {
                    all_result_shares.push(shares[0].clone());
                    info!("Server {} produced result share", i);
                } else {
                    warn!("Server {} produced empty result", i);
                }
            }
            Err(e) => {
                error!("Server {} multiplication task failed: {:?}", i, e);
            }
        }
    }

    // Reconstruct the final result
    if all_result_shares.len() >= THRESHOLD + 1 {
        match RobustShare::recover_secret(&all_result_shares, N_SERVERS as usize) {
            Ok((_, result)) => {
                let result_u64 = result.into_bigint().into()[0];
                info!("Multiplication result: {}", result_u64);
                assert_eq!(result_u64, EXPECTED_RESULT,
                    "Expected {}, got {}", EXPECTED_RESULT, result_u64);
                info!("✅ Test passed! {} × {} = {}", INPUT_A, INPUT_B, result_u64);
            }
            Err(e) => {
                panic!("Failed to reconstruct result: {:?}", e);
            }
        }
    } else {
        panic!("Not enough result shares to reconstruct: got {}, need {}",
            all_result_shares.len(), THRESHOLD + 1);
    }

    // Step 9: Cleanup
    info!("Test completed successfully, cleaning up");

    // Cancel client
    client_handle.abort();

    // Cancel servers
    for handle in server_handles {
        handle.abort();
    }
}

async fn create_server_node(
    server_id: usize,
    server_addr: SocketAddr,
    all_server_addresses: Vec<SocketAddr>,
) -> (Arc<HoneyBadgerMPCNode<Fr, Avid>>, tokio::task::JoinHandle<()>) {
    let session_id = SessionId::new(ProtocolType::Mul, 1);

    // Create node configuration
    let opts = HoneyBadgerMPCNodeOpts::new(
        N_SERVERS as usize,
        THRESHOLD,
        THRESHOLD + 1, // Number of triples needed
        2 * (THRESHOLD + 1), // Number of random shares needed
        session_id,
    );

    // Create the MPC node
    let node = Arc::new(
        HoneyBadgerMPCNode::setup(server_id, opts)
            .expect("Failed to create HoneyBadgerMPC node")
    );

    // Create QUIC network manager
    let mut network_manager = QuicNetworkManager::with_node_id(server_id);

    // Add all server nodes to the network
    for (id, &addr) in all_server_addresses.iter().enumerate() {
        if id != server_id {
            network_manager.add_node_with_party_id(id, addr);
        }
    }

    // Start listening for incoming connections
    let mut network_arc = Arc::new(network_manager);
    let listen_result = network_arc.listen(server_addr).await;
    if let Err(e) = listen_result {
        panic!("Failed to start server {} listener: {:?}", server_id, e);
    }

    info!("Server {} listening on {}", server_id, server_addr);

    // Create message processing loop
    let node_clone = node.clone();
    let mut network_clone = network_arc.clone();
    let handle = tokio::spawn(async move {
        loop {
            // Accept incoming connections and process messages
            match network_clone.accept().await {
                Ok(mut connection) => {
                    let node = node_clone.clone();
                    let network = network_clone.clone();

                    tokio::spawn(async move {
                        loop {
                            match connection.receive().await {
                                Ok(message_bytes) => {
                                    if let Err(e) = node.process(message_bytes, network.clone()).await {
                                        warn!("Failed to process message: {:?}", e);
                                    }
                                }
                                Err(e) => {
                                    warn!("Connection receive error: {}", e);
                                    break;
                                }
                            }
                        }
                    });
                }
                Err(e) => {
                    warn!("Failed to accept connection: {}", e);
                    sleep(Duration::from_millis(100)).await;
                }
            }
        }
    });

    (node, handle)
}

async fn create_and_run_client(
    client_addr: SocketAddr,
    server_addresses: Vec<SocketAddr>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        info!("Starting client at {}", client_addr);

        // Create input client
        let inputs = vec![Fr::from(INPUT_A), Fr::from(INPUT_B)];
        let mut client = match InputClient::<Fr, Avid>::new(
            CLIENT_ID as usize,
            N_SERVERS,
            THRESHOLD,
            inputs,
        ) {
            Ok(client) => client,
            Err(e) => {
                error!("Failed to create input client: {:?}", e);
                return;
            }
        };

        // Create QUIC network manager for client
        let mut network_manager = QuicNetworkManager::with_node_id(CLIENT_ID as usize);

        // Add all servers to the client's network view
        for (id, &addr) in server_addresses.iter().enumerate() {
            network_manager.add_node_with_party_id(id, addr);
        }

        let network = Arc::new(network_manager);

        // Connect to all servers and send inputs
        for (server_id, &server_addr) in server_addresses.iter().enumerate() {
            match network.connect(server_addr).await {
                Ok(mut connection) => {
                    info!("Client connected to server {} at {}", server_id, server_addr);

                    // Process input protocol with this server
                    let network_clone = network.clone();
                    tokio::spawn(async move {
                        // In a real implementation, we would handle the input protocol here
                        // For this test, we simulate successful input sharing
                        info!("Simulating input sharing with server {}", server_id);
                        sleep(Duration::from_millis(100)).await;
                    });
                }
                Err(e) => {
                    error!("Failed to connect to server {}: {}", server_id, e);
                }
            }
        }

        // Keep client alive for the duration of the test
        sleep(Duration::from_secs(10)).await;
        info!("Client shutting down");
    })
}

async fn get_input_shares_from_client(
    node: &HoneyBadgerMPCNode<Fr, Avid>,
    client_id: ClientId,
) -> Vec<RobustShare<Fr>> {
    // In a real implementation, this would retrieve the actual input shares
    // from the input protocol. For this test, we create mock shares.
    let mut rng = test_rng();

    let input_a = Fr::from(INPUT_A);
    let input_b = Fr::from(INPUT_B);

    let shares_a = RobustShare::compute_shares(input_a, N_SERVERS, THRESHOLD, None, &mut rng)
        .expect("Failed to create shares for input A");
    let shares_b = RobustShare::compute_shares(input_b, N_SERVERS, THRESHOLD, None, &mut rng)
        .expect("Failed to create shares for input B");

    // Return this node's shares
    vec![shares_a[node.id].clone(), shares_b[node.id].clone()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expected_result_calculation() {
        assert_eq!(EXPECTED_RESULT, 1554);
        assert_eq!(INPUT_A * INPUT_B, 1554);
    }

    #[tokio::test]
    async fn test_quic_network_setup() {
        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let mut network = QuicNetworkManager::new();

        // Test that we can create a network manager and add nodes
        network.add_node_with_party_id(0, addr);

        // This is a basic smoke test to ensure the QUIC components compile
        assert_eq!(network.nodes.len(), 1);
    }

    #[tokio::test]
    async fn test_share_generation() {
        let mut rng = test_rng();
        let secret = Fr::from(42u64);

        let shares = RobustShare::compute_shares(secret, 5, 1, None, &mut rng)
            .expect("Failed to generate shares");

        assert_eq!(shares.len(), 5);

        // Test reconstruction
        let (_, recovered) = RobustShare::recover_secret(&shares[0..2], 5)
            .expect("Failed to recover secret");

        assert_eq!(recovered, secret);
    }
}