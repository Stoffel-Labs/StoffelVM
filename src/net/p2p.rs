// src/net/p2p.rs
//! # Peer-to-Peer Networking for StoffelVM
//!
//! This module provides the networking capabilities for StoffelVM, enabling
//! secure communication between distributed parties for multiparty computation.
//!
//! The networking layer is built on the QUIC protocol, which offers:
//! - Encrypted connections using TLS 1.3
//! - Low latency with 0-RTT connection establishment
//! - Stream multiplexing for concurrent data transfers
//! - Connection migration for network changes
//!
//! The module defines two primary abstractions:
//! - `PeerConnection`: Represents a connection to a single peer
//! - `NetworkManager`: Manages multiple peer connections
//!
//! The current implementation uses the Quinn library for QUIC support.

use bytes::Bytes;
use quinn::{Connection, Endpoint, ServerConfig, ClientConfig, Incoming};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::SocketAddr;
use std::pin::Pin;
use std::future::Future;
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::Mutex;

/// Represents a connection to a peer
///
/// This trait defines the interface for communicating with a remote peer.
/// It provides methods for sending and receiving data, managing streams,
/// and controlling the connection lifecycle.
///
/// The interface is transport-agnostic, allowing different implementations
/// to use different underlying protocols (e.g., QUIC, WebRTC, etc.).
pub trait PeerConnection: Send + Sync {
    /// Sends data to the peer on the default stream
    ///
    /// This is a convenience method that sends data on stream ID 0.
    /// For more control, use `send_on_stream`.
    ///
    /// # Arguments
    /// * `data` - The data to send
    ///
    /// # Returns
    /// * `Ok(())` - If the data was sent successfully
    /// * `Err(String)` - If there was an error sending the data
    fn send<'a>(&'a mut self, data: &'a [u8]) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

    /// Receives data from the peer on the default stream
    ///
    /// This is a convenience method that receives data from stream ID 0.
    /// For more control, use `receive_from_stream`.
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - The received data
    /// * `Err(String)` - If there was an error receiving data
    fn receive<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>>;

    /// Sends data on a specific stream
    ///
    /// This method allows sending data on a specific stream ID, enabling
    /// multiplexed communication with the peer.
    ///
    /// # Arguments
    /// * `stream_id` - The ID of the stream to send on
    /// * `data` - The data to send
    ///
    /// # Returns
    /// * `Ok(())` - If the data was sent successfully
    /// * `Err(String)` - If there was an error sending the data
    fn send_on_stream<'a>(&'a mut self, stream_id: u64, data: &'a [u8]) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

    /// Receives data from a specific stream
    ///
    /// This method allows receiving data from a specific stream ID, enabling
    /// multiplexed communication with the peer.
    ///
    /// # Arguments
    /// * `stream_id` - The ID of the stream to receive from
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - The received data
    /// * `Err(String)` - If there was an error receiving data
    fn receive_from_stream<'a>(&'a mut self, stream_id: u64) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>>;

    /// Returns the address of the remote peer
    ///
    /// This method provides the network address of the connected peer,
    /// which can be useful for logging, debugging, or identity verification.
    fn remote_address(&self) -> SocketAddr;

    /// Closes the connection
    ///
    /// This method gracefully terminates the connection with the peer.
    /// After calling this method, no more data can be sent or received.
    ///
    /// # Returns
    /// * `Ok(())` - If the connection was closed successfully
    /// * `Err(String)` - If there was an error closing the connection
    fn close<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
}

/// Manages network connections for the VM
///
/// This trait defines the interface for managing network connections in the VM.
/// It provides methods for establishing connections to peers, accepting incoming
/// connections, and listening for connection requests.
///
/// The NetworkManager is responsible for:
/// - Creating and configuring network endpoints
/// - Establishing outgoing connections
/// - Accepting incoming connections
/// - Managing connection lifecycle
///
/// Like the PeerConnection trait, this interface is transport-agnostic,
/// allowing different implementations to use different underlying protocols.
pub trait NetworkManager: Send + Sync {
    /// Establishes a connection to a new peer
    ///
    /// This method initiates an outgoing connection to a peer at the specified address.
    /// It handles the connection establishment process, including any necessary
    /// handshaking, encryption setup, and protocol negotiation.
    ///
    /// # Arguments
    /// * `address` - The network address of the peer to connect to
    ///
    /// # Returns
    /// * `Ok(Box<dyn PeerConnection>)` - A connection to the peer
    /// * `Err(String)` - If the connection could not be established
    fn connect<'a>(&'a mut self, address: SocketAddr) -> Pin<Box<dyn Future<Output = Result<Box<dyn PeerConnection>, String>> + Send + 'a>>;

    /// Accepts an incoming connection
    ///
    /// This method accepts a pending incoming connection from a peer.
    /// It should be called after `listen()` has been called to set up
    /// the listening endpoint.
    ///
    /// This method will block until a connection is available or an error occurs.
    ///
    /// # Returns
    /// * `Ok(Box<dyn PeerConnection>)` - A connection to the peer
    /// * `Err(String)` - If no connection could be accepted
    fn accept<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<Box<dyn PeerConnection>, String>> + Send + 'a>>;

    /// Listens for incoming connections
    ///
    /// This method sets up a network endpoint to listen for incoming connections
    /// at the specified address. After calling this method, `accept()` can be
    /// called to accept incoming connections.
    ///
    /// # Arguments
    /// * `bind_address` - The local address to bind to for listening
    ///
    /// # Returns
    /// * `Ok(())` - If the listening endpoint was set up successfully
    /// * `Err(String)` - If the listening endpoint could not be set up
    fn listen<'a>(&'a mut self, bind_address: SocketAddr) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
}

/// QUIC-based implementation of PeerConnection
///
/// This struct implements the PeerConnection trait using the QUIC protocol
/// via the Quinn library. It manages a QUIC connection to a remote peer and
/// provides methods for sending and receiving data over that connection.
///
/// QUIC provides several benefits for secure multiparty computation:
/// - Built-in encryption and authentication
/// - Reliable, ordered delivery of data
/// - Stream multiplexing for concurrent operations
/// - Connection migration for network changes
pub struct QuicPeerConnection {
    /// The underlying QUIC connection
    connection: Connection,
    /// The remote peer's address
    remote_addr: SocketAddr,
    /// Map of stream IDs to send/receive stream pairs
    streams: Arc<Mutex<HashMap<u64, (quinn::SendStream, quinn::RecvStream)>>>,
    /// Whether this connection is on the server side
    is_server: bool,
}

impl QuicPeerConnection {
    /// Creates a new QUIC peer connection
    ///
    /// # Arguments
    /// * `connection` - The underlying QUIC connection
    /// * `is_server` - Whether this connection is on the server side
    ///
    /// The `is_server` parameter determines the behavior when creating new streams:
    /// - Server connections accept incoming streams
    /// - Client connections open new streams
    pub fn new(connection: Connection, is_server: bool) -> Self {
        let remote_addr = connection.remote_address();
        Self {
            connection,
            remote_addr,
            streams: Arc::new(Mutex::new(HashMap::new())),
            is_server,
        }
    }

    /// Gets or creates a bidirectional stream with the given ID
    ///
    /// This method manages the lifecycle of QUIC streams:
    /// 1. If a stream with the given ID already exists, it is reused
    /// 2. Otherwise, a new stream is created:
    ///    - For server connections, by accepting an incoming stream
    ///    - For client connections, by opening a new stream
    ///
    /// # Arguments
    /// * `stream_id` - The ID of the stream to get or create
    ///
    /// # Returns
    /// * `Ok((SendStream, RecvStream))` - The send and receive halves of the stream
    /// * `Err(String)` - If the stream could not be created
    async fn get_or_create_stream(&mut self, stream_id: u64) -> Result<(quinn::SendStream, quinn::RecvStream), String> {
        let mut streams = self.streams.lock().await;
        if let Some((send, recv)) = streams.remove(&stream_id) {
            // Reuse existing stream
            Ok((send, recv))
        } else if self.is_server {
            // Server should accept incoming streams
            let (send, recv) = self.connection.accept_bi().await
                .map_err(|e| format!("Failed to accept bidirectional stream: {}", e))?;
            Ok((send, recv))
        } else {
            // Client should create new streams
            let (send, recv) = self.connection.open_bi().await
                .map_err(|e| format!("Failed to open bidirectional stream: {}", e))?;
            Ok((send, recv))
        }
    }
}

impl PeerConnection for QuicPeerConnection {
    fn send<'a>(&'a mut self, data: &'a [u8]) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            self.send_on_stream(0, data).await
        })
    }

    fn receive<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
        Box::pin(async move {
            self.receive_from_stream(0).await
        })
    }

    fn send_on_stream<'a>(&'a mut self, stream_id: u64, data: &'a [u8]) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let (mut send, recv) = self.get_or_create_stream(stream_id).await?;

            send.write_all(data).await
                .map_err(|e| format!("Failed to send data: {}", e))?;

            // Store the stream back for reuse
            let mut streams = self.streams.lock().await;
            streams.insert(stream_id, (send, recv));

            Ok(())
        })
    }

    fn receive_from_stream<'a>(&'a mut self, stream_id: u64) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
        Box::pin(async move {
            // Try multiple times to get or create the stream
            let mut attempts = 0;
            let max_attempts = 3;
            let mut last_error = String::new();

            while attempts < max_attempts {
                match self.get_or_create_stream(stream_id).await {
                    Ok((send, mut recv)) => {
                        // Read a chunk of data (up to 65536 bytes)
                        let mut buf = vec![0u8; 65536];
                        match recv.read(&mut buf).await {
                            Ok(Some(n)) => {
                                buf.truncate(n);

                                // Store the stream back for reuse
                                let mut streams = self.streams.lock().await;
                                streams.insert(stream_id, (send, recv));

                                return Ok(buf);
                            }
                            Ok(None) => {
                                last_error = "Connection closed by peer".to_string();
                            }
                            Err(e) => {
                                last_error = format!("Failed to receive data: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        last_error = e;
                    }
                }

                // Wait a bit before retrying
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                attempts += 1;
            }

            Err(last_error)
        })
    }

    fn remote_address(&self) -> SocketAddr {
        self.remote_addr
    }

    fn close<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            self.connection.close(0u32.into(), b"Connection closed");
            Ok(())
        })
    }
}

/// QUIC-based implementation of NetworkManager
///
/// This struct implements the NetworkManager trait using the QUIC protocol
/// via the Quinn library. It manages QUIC endpoints for both client and server
/// roles, and provides methods for establishing connections and accepting
/// incoming connections.
///
/// The implementation uses self-signed certificates for TLS, which is suitable
/// for development but should be replaced with proper certificate management
/// in production.
pub struct QuicNetworkManager {
    /// The QUIC endpoint for sending and receiving connections
    endpoint: Option<Endpoint>,
    /// Configuration for the server role
    server_config: Option<ServerConfig>,
    /// Configuration for the client role
    client_config: Option<ClientConfig>,
}

impl QuicNetworkManager {
    /// Creates a new QUIC network manager
    ///
    /// This initializes a network manager with no active endpoints or configurations.
    /// Before using the manager, you must call either `connect()` or `listen()`
    /// to set up the appropriate endpoint.
    pub fn new() -> Self {
        Self {
            endpoint: None,
            server_config: None,
            client_config: None,
        }
    }

    /// Creates an insecure client configuration for QUIC
    ///
    /// This method creates a client configuration that:
    /// 1. Skips server certificate verification (insecure, but useful for development)
    /// 2. Sets up ALPN protocols for protocol negotiation
    /// 3. Configures transport parameters
    ///
    /// # Warning
    /// This configuration is insecure and should only be used for development.
    /// In production, proper certificate verification should be implemented.
    ///
    /// # Returns
    /// * `Ok(ClientConfig)` - The client configuration
    /// * `Err(String)` - If the configuration could not be created
    fn create_insecure_client_config() -> Result<ClientConfig, String> {
        // Create a client crypto configuration that skips certificate verification
        let mut crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification::new()))
            .with_no_client_auth();

        // Set ALPN protocol to match the server
        crypto.alpn_protocols = vec![b"quic-example".to_vec()];

        // Create a QUIC client configuration with the crypto configuration
        let mut config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .map_err(|e| format!("Failed to create QUIC client config: {}", e))?
        ));

        // Set transport config
        config.transport_config(Arc::new({
            let mut transport = quinn::TransportConfig::default();
            transport.max_concurrent_uni_streams(0u32.into());
            transport
        }));

        Ok(config)
    }

    /// Creates a self-signed server configuration for QUIC
    ///
    /// This method creates a server configuration that:
    /// 1. Generates a self-signed certificate for TLS
    /// 2. Sets up ALPN protocols for protocol negotiation
    /// 3. Configures transport parameters
    ///
    /// # Warning
    /// This configuration uses a self-signed certificate, which is suitable for
    /// development but not for production. In production, proper certificates
    /// should be used.
    ///
    /// # Returns
    /// * `Ok(ServerConfig)` - The server configuration
    /// * `Err(String)` - If the configuration could not be created
    fn create_self_signed_server_config() -> Result<ServerConfig, String> {
        // Generate self-signed certificate
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .map_err(|e| format!("Failed to generate certificate: {}", e))?;

        // Convert the certificate and key to DER format
        let cert_der = CertificateDer::from(cert.serialize_der().unwrap());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.serialize_private_key_der()));

        // Create a server crypto configuration with the certificate
        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .map_err(|e| format!("Failed to create server crypto config: {}", e))?;

        // Set ALPN protocol
        server_crypto.alpn_protocols = vec![b"quic-example".to_vec()];

        // Create a QUIC server configuration with the crypto configuration
        let mut server_config = ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
                .map_err(|e| format!("Failed to create QUIC server config: {}", e))?
        ));

        // Configure transport parameters
        let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
        transport_config.max_concurrent_uni_streams(0u32.into());

        Ok(server_config)
    }
}

impl NetworkManager for QuicNetworkManager {
    fn connect<'a>(&'a mut self, address: SocketAddr) -> Pin<Box<dyn Future<Output = Result<Box<dyn PeerConnection>, String>> + Send + 'a>> {
        Box::pin(async move {
            if self.endpoint.is_none() {
                // Create client endpoint
                let client_config = Self::create_insecure_client_config()?;
                let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
                    .map_err(|e| format!("Failed to create client endpoint: {}", e))?;
                endpoint.set_default_client_config(client_config);
                self.endpoint = Some(endpoint);
            }

            let endpoint = self.endpoint.as_ref().unwrap();
            let connection = endpoint
                .connect(address, "localhost")
                .map_err(|e| format!("Failed to initiate connection: {}", e))?
                .await
                .map_err(|e| format!("Failed to establish connection: {}", e))?;

            Ok(Box::new(QuicPeerConnection::new(connection, false)) as Box<dyn PeerConnection>)
        })
    }

    fn accept<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<Box<dyn PeerConnection>, String>> + Send + 'a>> {
        Box::pin(async move {
            let endpoint = self.endpoint.as_ref()
                .ok_or_else(|| "Endpoint not initialized. Call listen() first.".to_string())?;

            let incoming = endpoint.accept().await
                .ok_or_else(|| "No incoming connections".to_string())?;

            let connection = incoming.await
                .map_err(|e| format!("Failed to accept connection: {}", e))?;

            Ok(Box::new(QuicPeerConnection::new(connection, true)) as Box<dyn PeerConnection>)
        })
    }

    fn listen<'a>(&'a mut self, bind_address: SocketAddr) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let server_config = Self::create_self_signed_server_config()?;
            let endpoint = Endpoint::server(server_config, bind_address)
                .map_err(|e| format!("Failed to create server endpoint: {}", e))?;

            self.endpoint = Some(endpoint);
            Ok(())
        })
    }
}

/// Certificate verifier that accepts any server certificate
///
/// This is a dummy implementation of the ServerCertVerifier trait that
/// accepts any server certificate without verification. It is used for
/// development and testing purposes only.
///
/// # Security Warning
///
/// This implementation is **extremely insecure** and vulnerable to
/// man-in-the-middle attacks. It should never be used in production.
/// In a production environment, proper certificate verification should
/// be implemented, typically using a trusted certificate authority.
#[derive(Debug)]
struct SkipServerVerification;

impl SkipServerVerification {
    /// Creates a new SkipServerVerification instance
    ///
    /// This is a simple constructor that returns a new instance of
    /// the SkipServerVerification struct.
    fn new() -> Self {
        Self
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
