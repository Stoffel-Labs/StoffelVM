// ** /tests/p2p_integration.rs (New File) **

#[cfg(test)]
mod p2p_integration_tests {
    use stoffel_vm::net::p2p::{NetworkManager, PeerConnection};
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::pin::Pin;
    use std::future::Future;
    use std::sync::Arc;
    // Import Tokio's Mutex
    use tokio::sync::{Mutex, mpsc::{self, Sender, Receiver}};

    // --- Mock Implementations ---

    // Represents one end of a simulated connection
    struct MockPeerConnection {
        remote_addr: SocketAddr,
        tx: Sender<Vec<u8>>, // Channel to send data *to* the other peer        // Use Tokio's Mutex for async locking
        rx: Arc<Mutex<Receiver<Vec<u8>>>>, // Channel to receive data *from* the other peer        // Use Tokio's Mutex here as well for consistency in async context
        close_signal: Arc<Mutex<Option<tokio::sync::oneshot::Sender<()>>>>, // To signal closure
    }

    impl PeerConnection for MockPeerConnection {
        fn send<'a>(&'a mut self, data: &'a [u8]) -> Pin<Box<dyn Future<Output=Result<(), String>> + Send + 'a>> {
            let data_vec = data.to_vec();
            Box::pin(async move {
                self.tx.send(data_vec).await.map_err(|e| format!("Mock send error: {}", e))
            })
        }

        fn receive<'a>(&'a mut self) -> Pin<Box<dyn Future<Output=Result<Vec<u8>, String>> + Send + 'a>> {
            Box::pin(async move {
                // Lock the Tokio Mutex asynchronously
                let mut rx_guard = self.rx.lock().await;
                // Now it's safe to await the receive call
                rx_guard.recv().await.ok_or_else(|| "Mock connection closed".to_string())
            }) // MutexGuard is dropped here, unlocking the Mutex
        }

        fn remote_address(&self) -> SocketAddr {
            self.remote_addr
        }

        fn close<'a>(&'a mut self) -> Pin<Box<dyn Future<Output=Result<(), String>> + Send + 'a>> {
            Box::pin(async move {
                // Lock the Tokio Mutex asynchronously
                if let Some(sender) = self.close_signal.lock().await.take() {
                    let _ = sender.send(()); // Signal the other side
                }
                // Closing is implicit by dropping channels/sender
                Ok(())
            })
        }
    }

    #[derive(Clone, Default)]
    struct MockNetworkManager {
        // Map listening address to a channel where new connections are sent
        // Update the listener map value type to use Tokio's Mutex
        listeners: Arc<Mutex<HashMap<SocketAddr, Sender<(SocketAddr, Sender<Vec<u8>>, Arc<Mutex<Receiver<Vec<u8>>>>)>>>>,
    }

    impl NetworkManager for MockNetworkManager {
        fn connect<'a>(&'a mut self, address: SocketAddr) -> Pin<Box<dyn Future<Output=Result<Box<dyn PeerConnection>, String>> + Send + 'a>> {
            Box::pin(async move {
                let listener_tx = {                    // Lock the Tokio Mutex asynchronously
                    let listeners = self.listeners.lock().await;
                    listeners.get(&address).cloned()
                };

                if let Some(listener_tx) = listener_tx {
                    // Create channels for the connection (Client perspective)
                    let (client_tx, server_rx) = mpsc::channel::<Vec<u8>>(10); // Client sends, Server receives
                    let (server_tx, client_rx) = mpsc::channel::<Vec<u8>>(10); // Server sends, Client receives

                    // Create closure signals
                    let (client_close_tx, server_close_rx) = tokio::sync::oneshot::channel::<()>();
                    let (server_close_tx, _client_close_rx) = tokio::sync::oneshot::channel::<()>(); // Client doesn't need server's signal directly

                    // Simulate the client's address (can be arbitrary for mock)
                    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345); // Example client address

                    // Send connection details to the listener (using Tokio Mutex for Arc fields)
                    listener_tx.send((
                        client_addr,
                        server_tx, // Give listener the sender to send *to* the client
                        Arc::new(Mutex::new(server_rx)), // Wrap Receiver in Tokio Mutex
                    )).await.map_err(|_| "Listener closed".to_string())?;

                    // Wait for the server to potentially acknowledge closure
                    let _ = server_close_rx.await; // Simulate connection teardown coordination

                    // Create the client-side connection object (using Tokio Mutex for Arc fields)
                    Ok(Box::new(MockPeerConnection {
                        remote_addr: address,
                        tx: client_tx, // Client uses this to send to server
                        rx: Arc::new(Mutex::new(client_rx)), // Wrap Receiver in Tokio Mutex
                        close_signal: Arc::new(Mutex::new(Some(client_close_tx))), // Wrap Sender Option in Tokio Mutex
                    }) as Box<dyn PeerConnection>)
                } else {
                    Err(format!("No listener found at {}", address))
                }
            })
        }

        fn listen<'a>(&'a mut self, bind_address: SocketAddr) -> Pin<Box<dyn Future<Output=Result<(), String>> + Send + 'a>> {
            Box::pin(async move {
                // Update channel type to reflect Tokio Mutex usage
                let (listener_tx, mut listener_rx) = mpsc::channel::<(SocketAddr, Sender<Vec<u8>>, Arc<Mutex<Receiver<Vec<u8>>>>)>(10); // Increased buffer size

                { // Scope for mutex guard
                    let mut listeners = self.listeners.lock().await;
                    if listeners.contains_key(&bind_address) {
                        return Err(format!("Address {} already in use", bind_address));
                    }
                    listeners.insert(bind_address, listener_tx);
                } // Mutex guard dropped

                println!("Mock server listening on {}", bind_address);

                // Keep the listener task alive to accept connections
                // In a real scenario, this would be a loop accepting OS connections
                // For mock, we just keep the receiver alive.
                // We'll spawn a task to handle incoming connection requests.
                tokio::spawn(async move {
                    // Receive items with Tokio Mutex in the tuple
                    while let Some((remote_addr, peer_tx, peer_rx)) = listener_rx.recv().await {
                        println!("Listener on {} accepted connection from {}", bind_address, remote_addr);
                        // In a real server, you'd spawn a handler for the new connection here.
                        // For the mock, the connection object is created by the connect side.
                        // We could potentially store these connection details if needed.
                        let server_conn = MockPeerConnection {
                            remote_addr,
                            tx: peer_tx,
                            rx: peer_rx, // Already Arc<Mutex<Receiver>>
                            close_signal: Arc::new(Mutex::new(None)),
                        };
                        // Example: Spawn a task to handle received data for this connection
                        tokio::spawn(handle_mock_connection(server_conn));
                    }
                    println!("Listener on {} stopped.", bind_address);
                });

                Ok(())
            })
        }
    }

    // Example handler for a server-side mock connection
    async fn handle_mock_connection(mut conn: MockPeerConnection) {
        println!("Handling connection from {}", conn.remote_address());
        loop {
            tokio::select! {
                result = conn.receive() => {
                    match result {
                        Ok(data) => {
                            println!("Server received from {}: {:?}", conn.remote_address(), data);
                            // Example: Echo back
                            if conn.send(&data).await.is_err() {
                                println!("Failed to echo back to {}", conn.remote_address());
                                break;
                            }
                        }
                        Err(e) => {
                            println!("Receive error from {}: {}", conn.remote_address(), e);
                            break; // Connection likely closed
                        }
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => { // Keepalive/timeout
                    println!("Connection handler for {} idle.", conn.remote_address());
                }
            }
        }
        println!("Connection handler for {} finished.", conn.remote_address());
        let _ = conn.close().await; // Ensure close is called
    }


    fn create_mock_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    // --- Test Cases ---
    // No changes needed in the test functions themselves, as the public API
    // remains the same. The internal locking mechanism has changed.

    #[tokio::test]
    async fn test_mock_connect_listen() {
        let mut manager = MockNetworkManager::default();
        let server_addr = create_mock_addr(9001);

        // Start listener in the background
        manager.listen(server_addr).await.expect("Listen failed");

        // Allow listener task to potentially start
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Attempt to connect
        let connect_result = manager.connect(server_addr).await;
        assert!(connect_result.is_ok(), "Connect failed: {:?}", connect_result.err());
    }

    #[tokio::test]
    async fn test_mock_send_receive_client_to_server() {
        let mut server_manager = MockNetworkManager::default();
        let mut client_manager = server_manager.clone(); // Use the same manager instance for mocks
        let server_addr = create_mock_addr(9002);

        // Channel to receive the server-side connection when it's accepted
        let (conn_tx, mut conn_rx) = mpsc::channel::<Box<dyn PeerConnection>>(1);

        // Modified listener logic for testing: capture the connection
        // Update channel type to use Tokio::Mutex
        let (listener_tx, mut listener_rx) = mpsc::channel::<(SocketAddr, Sender<Vec<u8>>, Arc<Mutex<Receiver<Vec<u8>>>>)>(1);
        server_manager.listeners.lock().await.insert(server_addr, listener_tx); // Use await for lock

        tokio::spawn(async move {
            if let Some((remote_addr, peer_tx, peer_rx)) = listener_rx.recv().await {
                println!("Test listener got connection from {}", remote_addr);
                let server_conn = MockPeerConnection {
                    remote_addr,
                    tx: peer_tx,
                    rx: peer_rx, // Already Arc<Mutex<Receiver>>
                    close_signal: Arc::new(Mutex::new(None)),
                };
                // Send the established connection back to the test
                conn_tx.send(Box::new(server_conn)).await.expect("Failed to send conn back");
            }
        });


        // Client connects
        let mut client_conn = client_manager.connect(server_addr).await.expect("Client connect failed");

        // Server retrieves the connection established by the listener task
        let mut server_conn = conn_rx.recv().await.expect("Failed to receive server connection");

        // Client sends data
        let test_data = b"hello from client".to_vec();
        client_conn.send(&test_data).await.expect("Client send failed");

        // Server receives data
        let received_data = server_conn.receive().await.expect("Server receive failed");

        assert_eq!(received_data, test_data);

        // Clean up
        let _ = client_conn.close().await;
        let _ = server_conn.close().await;
    }

    #[tokio::test]
    async fn test_mock_send_receive_server_to_client() {
        let mut server_manager = MockNetworkManager::default();
        let mut client_manager = server_manager.clone();
        let server_addr = create_mock_addr(9003);

        let (conn_tx, mut conn_rx) = mpsc::channel::<Box<dyn PeerConnection>>(1);

        let (listener_tx, mut listener_rx) = mpsc::channel::<(SocketAddr, Sender<Vec<u8>>, Arc<Mutex<Receiver<Vec<u8>>>>)>(1);
        server_manager.listeners.lock().await.insert(server_addr, listener_tx); // Use await for lock

        tokio::spawn(async move {
            if let Some((remote_addr, peer_tx, peer_rx)) = listener_rx.recv().await {
                let server_conn = MockPeerConnection { remote_addr, tx: peer_tx, rx: peer_rx, close_signal: Arc::new(Mutex::new(None)) };
                conn_tx.send(Box::new(server_conn)).await.unwrap();
            }
        });

        let mut client_conn = client_manager.connect(server_addr).await.expect("Client connect failed");
        let mut server_conn = conn_rx.recv().await.expect("Failed to receive server connection");

        // Server sends data
        let test_data = b"greetings from server".to_vec();
        server_conn.send(&test_data).await.expect("Server send failed");

        // Client receives data
        let received_data = client_conn.receive().await.expect("Client receive failed");

        assert_eq!(received_data, test_data);

        // Clean up
        let _ = client_conn.close().await;
        let _ = server_conn.close().await;
    }

    #[tokio::test]
    async fn test_mock_bidirectional() {
        let mut server_manager = MockNetworkManager::default();
        let mut client_manager = server_manager.clone();
        let server_addr = create_mock_addr(9004);

        let (conn_tx, mut conn_rx) = mpsc::channel::<Box<dyn PeerConnection>>(1);

        let (listener_tx, mut listener_rx) = mpsc::channel::<(SocketAddr, Sender<Vec<u8>>, Arc<Mutex<Receiver<Vec<u8>>>>)>(1);
        server_manager.listeners.lock().await.insert(server_addr, listener_tx); // Use await for lock

        tokio::spawn(async move {
            if let Some((remote_addr, peer_tx, peer_rx)) = listener_rx.recv().await {
                let server_conn = MockPeerConnection { remote_addr, tx: peer_tx, rx: peer_rx, close_signal: Arc::new(Mutex::new(None)) };
                conn_tx.send(Box::new(server_conn)).await.unwrap();
            }
        });

        let mut client_conn = client_manager.connect(server_addr).await.expect("Client connect failed");
        let mut server_conn = conn_rx.recv().await.expect("Failed to receive server connection");


        // Client sends, Server receives
        let client_msg = b"ping".to_vec();
        client_conn.send(&client_msg).await.expect("Client send failed");
        let received_by_server = server_conn.receive().await.expect("Server receive failed");
        assert_eq!(received_by_server, client_msg);

        // Server sends, Client receives
        let server_msg = b"pong".to_vec();
        server_conn.send(&server_msg).await.expect("Server send failed");
        let received_by_client = client_conn.receive().await.expect("Client receive failed");
        assert_eq!(received_by_client, server_msg);

        // Clean up
        let _ = client_conn.close().await;
        let _ = server_conn.close().await;
    }

    #[tokio::test]
    async fn test_mock_close_connection() {
        let mut server_manager = MockNetworkManager::default();
        let mut client_manager = server_manager.clone();
        let server_addr = create_mock_addr(9005);

        let (conn_tx, mut conn_rx) = mpsc::channel::<Box<dyn PeerConnection>>(1);

        let (listener_tx, mut listener_rx) = mpsc::channel::<(SocketAddr, Sender<Vec<u8>>, Arc<Mutex<Receiver<Vec<u8>>>>)>(1);
        server_manager.listeners.lock().await.insert(server_addr, listener_tx); // Use await for lock

        tokio::spawn(async move {
            if let Some((remote_addr, peer_tx, peer_rx)) = listener_rx.recv().await {
                let server_conn = MockPeerConnection { remote_addr, tx: peer_tx, rx: peer_rx, close_signal: Arc::new(Mutex::new(None)) };
                conn_tx.send(Box::new(server_conn)).await.unwrap();
            }
        });

        let mut client_conn = client_manager.connect(server_addr).await.expect("Client connect failed");
        let mut server_conn = conn_rx.recv().await.expect("Failed to receive server connection");

        // Client closes the connection
        let close_result = client_conn.close().await;
        assert!(close_result.is_ok(), "Client close failed");

        // Server attempts to receive, should fail as connection is closed
        let receive_result = server_conn.receive().await;
        assert!(receive_result.is_err(), "Server receive should fail after client close");
        assert_eq!(receive_result.unwrap_err(), "Mock connection closed");

        // Server closing shouldn't error (even if already closed by peer)
        let server_close_result = server_conn.close().await;
        assert!(server_close_result.is_ok(), "Server close failed");
    }
}
