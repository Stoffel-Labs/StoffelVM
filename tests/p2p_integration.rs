// tests/p2p_integration.rs
//! Integration tests for QUIC-based peer-to-peer networking.

use std::net::SocketAddr;
use tokio::time::{sleep, Duration, timeout};
use stoffel_vm::net::{NetworkManager, QuicNetworkManager};
use std::sync::Once;


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

    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap(); // Use port 0 for automatic assignment
    
    // Create server
    let mut server = QuicNetworkManager::new();
    server.listen(server_addr).await.expect("Server should start listening");
    
    // Get the actual bound address
    // Note: In a real implementation, you'd need to expose the actual bound address
    // For now, we'll use a fixed port for testing
    let test_addr: SocketAddr = "127.0.0.1:9090".parse().unwrap();
    let mut server = QuicNetworkManager::new();
    server.listen(test_addr).await.expect("Server should start listening");
    
    // Spawn server task
    let server_handle = tokio::spawn(async move {
        match timeout(Duration::from_secs(5), server.accept()).await {
            Ok(Ok(mut connection)) => {
                // Receive message
                if let Ok(data) = connection.receive().await {
                    let message = String::from_utf8_lossy(&data);
                    assert_eq!(message, "test message");
                    
                    // Send response
                    connection.send(b"response").await.expect("Should send response");
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
    let mut connection = client.connect(test_addr).await.expect("Client should connect");
    
    // Send message
    connection.send(b"test message").await.expect("Should send message");
    
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

    let test_addr: SocketAddr = "127.0.0.1:9091".parse().unwrap();
    
    let mut server = QuicNetworkManager::new();
    server.listen(test_addr).await.expect("Server should start listening");
    
    let server_handle = tokio::spawn(async move {
        if let Ok(mut connection) = server.accept().await {
            // Test multiple streams
            for stream_id in 0..3 {
                if let Ok(data) = connection.receive_from_stream(stream_id).await {
                    let expected = format!("stream {} data", stream_id);
                    assert_eq!(String::from_utf8_lossy(&data), expected);
                    
                    let response = format!("stream {} response", stream_id);
                    connection.send_on_stream(stream_id, response.as_bytes()).await.expect("Should send response");
                }
            }
        }
    });
    
    sleep(Duration::from_millis(100)).await;
    
    let mut client = QuicNetworkManager::new();
    let mut connection = client.connect(test_addr).await.expect("Client should connect");
    
    // Send data on multiple streams
    for stream_id in 0..3 {
        let message = format!("stream {} data", stream_id);
        connection.send_on_stream(stream_id, message.as_bytes()).await.expect("Should send on stream");
        
        let response = connection.receive_from_stream(stream_id).await.expect("Should receive from stream");
        let expected = format!("stream {} response", stream_id);
        assert_eq!(String::from_utf8_lossy(&response), expected);
    }
    
    connection.close().await.expect("Should close connection");
    server_handle.await.expect("Server task should complete");
}
