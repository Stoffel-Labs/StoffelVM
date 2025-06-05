// src/net/p2p.rs
//! Peer-to-peer networking logic using QUIC and Noise.

use bytes::Bytes;
use quinn::{Connection, Endpoint, ServerConfig, ClientConfig, Incoming};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::SocketAddr;
use std::pin::Pin;
use std::future::Future;
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::Mutex;

/// Represents a connection to a peer.
pub trait PeerConnection: Send + Sync {
    /// Sends data to the peer.
    fn send<'a>(&'a mut self, data: &'a [u8]) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

    /// Receives data from the peer.
    fn receive<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>>;

    /// Sends data on a specific stream ID.
    fn send_on_stream<'a>(&'a mut self, stream_id: u64, data: &'a [u8]) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

    /// Receives data from a specific stream ID.
    fn receive_from_stream<'a>(&'a mut self, stream_id: u64) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>>;

    /// Returns the address of the remote peer.
    fn remote_address(&self) -> SocketAddr;

    /// Closes the connection.
    fn close<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
}

/// Manages connections to multiple peers.
pub trait NetworkManager: Send + Sync {
    /// Establishes a connection to a new peer.
    fn connect<'a>(&'a mut self, address: SocketAddr) -> Pin<Box<dyn Future<Output = Result<Box<dyn PeerConnection>, String>> + Send + 'a>>;

    /// Accepts an incoming connection.
    fn accept<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<Box<dyn PeerConnection>, String>> + Send + 'a>>;

    /// Listens for incoming connections.
    fn listen<'a>(&'a mut self, bind_address: SocketAddr) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

    // Additional methods for managing peers, handling events, etc.
}

pub struct QuicPeerConnection {
    connection: Connection,
    remote_addr: SocketAddr,
    streams: Arc<Mutex<HashMap<u64, (quinn::SendStream, quinn::RecvStream)>>>,
}

impl QuicPeerConnection {
    pub fn new(connection: Connection) -> Self {
        let remote_addr = connection.remote_address();
        Self {
            connection,
            remote_addr,
            streams: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn get_or_create_stream(&mut self, stream_id: u64) -> Result<(quinn::SendStream, quinn::RecvStream), String> {
        let mut streams = self.streams.lock().await;
        if let Some((send, recv)) = streams.remove(&stream_id) {
            Ok((send, recv))
        } else {
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
            let (send, mut recv) = self.get_or_create_stream(stream_id).await?;
            
            let data = recv.read_to_end(65536).await
                .map_err(|e| format!("Failed to receive data: {}", e))?;
            
            // Store the stream back for reuse
            let mut streams = self.streams.lock().await;
            streams.insert(stream_id, (send, recv));
            
            Ok(data)
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

pub struct QuicNetworkManager {
    endpoint: Option<Endpoint>,
    server_config: Option<ServerConfig>,
    client_config: Option<ClientConfig>,
}

impl QuicNetworkManager {
    pub fn new() -> Self {
        Self {
            endpoint: None,
            server_config: None,
            client_config: None,
        }
    }

    fn create_insecure_client_config() -> Result<ClientConfig, String> {
        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification::new()))
            .with_no_client_auth();
        
        let mut config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .map_err(|e| format!("Failed to create QUIC client config: {}", e))?
        ));
        
        // Set ALPN protocol
        config.transport_config(Arc::new({
            let mut transport = quinn::TransportConfig::default();
            transport.max_concurrent_uni_streams(0u32.into());
            transport
        }));
        
        Ok(config)
    }

    fn create_self_signed_server_config() -> Result<ServerConfig, String> {
        // Generate self-signed certificate
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .map_err(|e| format!("Failed to generate certificate: {}", e))?;
        
        let cert_der = CertificateDer::from(cert.serialize_der().unwrap());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.serialize_private_key_der()));
        
        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .map_err(|e| format!("Failed to create server crypto config: {}", e))?;
        
        server_crypto.alpn_protocols = vec![b"quic-example".to_vec()];
        
        let mut server_config = ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
                .map_err(|e| format!("Failed to create QUIC server config: {}", e))?
        ));
        
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
            
            Ok(Box::new(QuicPeerConnection::new(connection)) as Box<dyn PeerConnection>)
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
            
            Ok(Box::new(QuicPeerConnection::new(connection)) as Box<dyn PeerConnection>)
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

/// Dummy certificate verifier that treats any certificate as valid.
/// NOTE: This is vulnerable to MITM attacks, but convenient for testing.
#[derive(Debug)]
struct SkipServerVerification;

impl SkipServerVerification {
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
