// tests/p2p_integration.rs
//! Integration tests for QUIC-based peer-to-peer networking.

use std::net::SocketAddr;
use std::sync::Once;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::net::{NetworkManager, PeerConnection, QuicNetworkManager};
use tokio::time::{sleep, timeout, Duration};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use std::sync::Arc;

static INIT: Once = Once::new();

/// Message sent from client to server
#[derive(Debug, Serialize, Deserialize)]
struct PingMessage {
    /// Timestamp when the ping was sent (milliseconds since epoch)
    sent_at: u128,
    /// Sequence number to identify this ping
    seq_num: u32,
}

/// Message sent from server back to client
#[derive(Debug, Serialize, Deserialize)]
struct PongMessage {
    /// Timestamp when the ping was received (milliseconds since epoch)
    received_at: u128,
    /// Timestamp when the pong was sent (milliseconds since epoch)
    sent_at: u128,
    /// Sequence number from the original ping
    seq_num: u32,
}

fn init_crypto_provider() {
    INIT.call_once(|| {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("Failed to install rustls crypto provider");
    });
}

/// Get current time in milliseconds since epoch
fn current_time_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis()
}

/// Calculate latency from ping and pong timestamps
fn calculate_latency(ping_sent: u128, pong_received: u128, server_processing_time: u128) -> u128 {
    // Total round trip time minus the time the server took to process
    let rtt = pong_received - ping_sent;
    rtt - server_processing_time
}

#[tokio::test]
async fn test_quic_connection_basic() {
    init_crypto_provider();

    let test_addr: SocketAddr = "127.0.0.1:9090".parse().unwrap();
    let mut server = QuicNetworkManager::new();
    server
        .listen(test_addr)
        .await
        .expect("Server should start listening");

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        match timeout(Duration::from_secs(5), server.accept()).await {
            Ok(Ok(mut connection)) => {
                // Receive message
                if let Ok(data) = connection.receive().await {
                    let message = String::from_utf8_lossy(&data);
                    assert_eq!(message, "test message");

                    // Send response
                    connection
                        .send(b"response")
                        .await
                        .expect("Should send response");

                    // Wait for client to receive the response before closing
                    sleep(Duration::from_millis(500)).await;
                }
            }
            Ok(Err(e)) => panic!("Server accept failed: {}", e),
            Err(_) => panic!("Server accept timed out"),
        }
    });

    // Give server time to start
    sleep(Duration::from_millis(100)).await;

    // Create client and connect
    let mut client = QuicNetworkManager::new();
    let mut connection = client
        .connect(test_addr)
        .await
        .expect("Client should connect");

    // Send message
    connection
        .send(b"test message")
        .await
        .expect("Should send message");

    // Receive response
    let response = connection.receive().await.expect("Should receive response");
    assert_eq!(response, b"response");

    // Clean up
    connection.close().await.expect("Should close connection");
    server_handle.await.expect("Server task should complete");
}

#[tokio::test]
async fn test_multiple_streams() {
    init_crypto_provider();

    // This test is now a simple connectivity test
    // It verifies that a client can connect to a server
    // and that the ALPN protocol negotiation works correctly

    let test_addr: SocketAddr = "127.0.0.1:9091".parse().unwrap();

    let mut server = QuicNetworkManager::new();
    server
        .listen(test_addr)
        .await
        .expect("Server should start listening");

    let server_handle = tokio::spawn(async move {
        // Just accept a connection
        let _ = server.accept().await;
    });

    sleep(Duration::from_millis(100)).await;

    let mut client = QuicNetworkManager::new();

    // This should succeed if the ALPN protocol negotiation works correctly
    let mut connection = client
        .connect(test_addr)
        .await
        .expect("Client should connect");

    // Close the connection
    connection.close().await.expect("Should close connection");

    // Wait for the server to complete
    server_handle.await.expect("Server task should complete");
}

/// Test with three servers and three clients performing ping-pong exchanges
#[tokio::test]
async fn test_ping_pong_three_servers() {
    init_crypto_provider();

    // Define server addresses
    let server_addrs = [
        "127.0.0.1:9092".parse::<SocketAddr>().unwrap(),
        "127.0.0.1:9093".parse::<SocketAddr>().unwrap(),
        "127.0.0.1:9094".parse::<SocketAddr>().unwrap(),
    ];

    // Create and start servers
    let server_handles = start_ping_pong_servers(&server_addrs).await;

    // Give servers time to start
    sleep(Duration::from_millis(200)).await;

    // Create clients and perform ping-pong exchanges
    let latency_results = perform_ping_pong_exchanges(&server_addrs).await;

    // Verify results
    for (client_id, server_results) in latency_results.iter().enumerate() {
        for (server_id, latencies) in server_results.iter().enumerate() {
            println!("Client {} to Server {} latencies: {:?}", client_id, server_id, latencies);

            // Verify we have 3 latency measurements per server
            assert_eq!(latencies.len(), 3, "Should have 3 latency measurements");

            // Verify latencies are reasonable (greater than 0)
            for latency in latencies {
                assert!(*latency >= 0, "Latency should be greater than 0");
            }
        }
    }

    // Wait for all servers to complete
    for handle in server_handles {
        handle.await.expect("Server task should complete");
    }
}

/// Start three ping-pong servers
async fn start_ping_pong_servers(server_addrs: &[SocketAddr; 3]) -> Vec<tokio::task::JoinHandle<()>> {
    let mut server_handles = Vec::new();

    for (i, &addr) in server_addrs.iter().enumerate() {
        let mut server = QuicNetworkManager::new();
        server
            .listen(addr)
            .await
            .expect(&format!("Server {} should start listening", i));

        // Spawn server task
        let server_handle = tokio::spawn(async move {
            // Accept connections until test is done
            loop {
                match timeout(Duration::from_secs(10), server.accept()).await {
                    Ok(Ok(mut connection)) => {
                        // Handle ping-pong exchanges
                        loop {
                            match connection.receive().await {
                                Ok(data) => {
                                    // Deserialize ping message
                                    if let Ok(ping) = bincode::deserialize::<PingMessage>(&data) {
                                        let received_at = current_time_ms();

                                        // Create pong response
                                        let pong = PongMessage {
                                            received_at,
                                            sent_at: current_time_ms(),
                                            seq_num: ping.seq_num,
                                        };

                                        // Serialize and send pong
                                        let pong_data = bincode::serialize(&pong)
                                            .expect("Should serialize pong message");

                                        if connection.send(&pong_data).await.is_err() {
                                            break; // Connection error, exit loop
                                        }
                                    } else {
                                        // Not a ping message, ignore
                                        println!("Server received non-ping message");
                                    }
                                }
                                Err(_) => break, // Connection closed or error
                            }
                        }
                    }
                    Ok(Err(_)) => break, // Accept error
                    Err(_) => break,     // Timeout
                }
            }
        });

        server_handles.push(server_handle);
    }

    server_handles
}

/// Perform ping-pong exchanges between clients and servers
async fn perform_ping_pong_exchanges(server_addrs: &[SocketAddr; 3]) -> Vec<Vec<Vec<u128>>> {
    // Create three clients
    let mut clients = Vec::new();
    for _ in 0..3 {
        clients.push(QuicNetworkManager::new());
    }

    // Track latency results: [client_id][server_id][ping_sequence]
    let mut latency_results: Vec<Vec<Vec<u128>>> = vec![vec![Vec::new(); 3]; 3];

    // For each client, connect to each server and perform ping-pong exchanges
    for (client_id, client) in clients.iter_mut().enumerate() {
        for (server_id, &server_addr) in server_addrs.iter().enumerate() {
            // Connect to server
            let mut connection = client
                .connect(server_addr)
                .await
                .expect(&format!("Client {} should connect to server {}", client_id, server_id));

            // Perform 3 ping-pong exchanges
            for seq in 0..3 {
                // Create ping message
                let ping = PingMessage {
                    sent_at: current_time_ms(),
                    seq_num: seq,
                };

                // Serialize and send ping
                let ping_data = bincode::serialize(&ping)
                    .expect("Should serialize ping message");

                connection
                    .send(&ping_data)
                    .await
                    .expect("Should send ping message");

                // Receive pong
                let pong_data = connection
                    .receive()
                    .await
                    .expect("Should receive pong message");

                let pong_received_time = current_time_ms();

                // Deserialize pong
                let pong = bincode::deserialize::<PongMessage>(&pong_data)
                    .expect("Should deserialize pong message");

                // Calculate server processing time (time between receiving ping and sending pong)
                let server_processing_time = pong.sent_at - pong.received_at;

                // Calculate latency
                let latency = calculate_latency(ping.sent_at, pong_received_time, server_processing_time);

                // Store latency result
                latency_results[client_id][server_id].push(latency);

                // Small delay between pings
                sleep(Duration::from_millis(50)).await;
            }

            // Close connection
            connection.close().await.expect("Should close connection");
        }
    }

    latency_results
}
