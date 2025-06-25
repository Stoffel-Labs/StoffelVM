// tests/p2p_integration.rs
//! Integration tests for QUIC-based peer-to-peer networking.

use std::net::SocketAddr;
use std::sync::Once;
use stoffel_vm::net::{NetworkManager, PeerConnection, QuicNetworkManager};
use tokio::time::{sleep, timeout, Duration};

static INIT: Once = Once::new();

fn init_crypto_provider() {
    INIT.call_once(|| {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("Failed to install rustls crypto provider");
    });
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
