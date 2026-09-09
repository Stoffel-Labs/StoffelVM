//! TLS utilities for mutual TLS (mTLS) connections using self-signed certificates.
//!
//! Both sides of a connection authenticate with self-signed certificates. Certificate
//! chain validation is intentionally skipped — only handshake signature verification
//! is performed — since self-signed certs have no CA chain to validate against.

use crate::CoordinatorError;
use jsonrpsee::async_client::Client;
use jsonrpsee::client_transport::ws::WsTransportClientBuilder;
use jsonrpsee::core::client::ClientBuilder;
use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::pki_types::ServerName;
use rustls::pki_types::UnixTime;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::ClientConfig;
use rustls::DistinguishedName;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use url::Url;

/// Server-side verifier that accepts any self-signed client certificate.
///
/// Skips chain validation entirely; used when clients authenticate with
/// self-signed certs that have no CA anchor.
#[derive(Debug)]
pub struct SelfSignedClientVerifier;

/// Client-side verifier that accepts any self-signed server certificate.
///
/// Skips chain validation entirely; used when the server presents a self-signed
/// cert that has no CA anchor.
#[derive(Debug)]
pub struct SelfSignedServerVerifier;

impl ClientCertVerifier for SelfSignedClientVerifier {
    /// Returns no CA hint subjects — chain validation is not performed.
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    /// Accepts any client certificate unconditionally.
    fn verify_client_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    /// Verifies the TLS 1.2 handshake signature using the ring crypto provider.
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

    /// Verifies the TLS 1.3 handshake signature using the ring crypto provider.
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

    /// Returns the signature schemes supported by the ring crypto provider.
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl ServerCertVerifier for SelfSignedServerVerifier {
    /// Accepts any server certificate unconditionally.
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    /// Verifies the TLS 1.2 handshake signature using the ring crypto provider.
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

    /// Verifies the TLS 1.3 handshake signature using the ring crypto provider.
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

    /// Returns the signature schemes supported by the ring crypto provider.
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Generates a self-signed certificate for the server, valid for `localhost` and `127.0.0.1`.
pub fn server_cert() -> Arc<rcgen::CertifiedKey<rcgen::KeyPair>> {
    let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];

    Arc::new(
        rcgen::generate_simple_self_signed(subject_alt_names)
            .expect("cert generation with fixed subject alt names never fails"),
    )
}

/// Generates a self-signed certificate for a client.
pub fn client_cert() -> Arc<rcgen::CertifiedKey<rcgen::KeyPair>> {
    let subject_alt_names = vec!["client".to_string()];

    Arc::new(
        rcgen::generate_simple_self_signed(subject_alt_names)
            .expect("cert generation with fixed subject alt names never fails"),
    )
}

/// Builds a `rustls::ServerConfig` for mTLS using `SelfSignedClientVerifier`.
///
/// Clients must present a certificate, but chain validation is skipped.
pub fn server_tls_config(
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
) -> Result<rustls::ServerConfig, CoordinatorError> {
    let certs = vec![CertificateDer::from(cert_der)];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));

    rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(SelfSignedClientVerifier {}))
        .with_single_cert(certs, key)
        .map_err(|e| CoordinatorError::TlsConfigError(e.to_string()))
}

/// Builds a `rustls::ClientConfig` for mTLS, presenting the given client certificate.
fn client_tls_config(
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
) -> Result<ClientConfig, CoordinatorError> {
    let certs = vec![CertificateDer::from(cert_der)];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));

    ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_client_auth_cert(certs, key)
        .map_err(|e| CoordinatorError::TlsConfigError(e.to_string()))
}

/// Connects to a remote WebSocket server over mTLS and returns a `Client`.
///
/// Establishes a TCP connection to `addr:port`, upgrades it to TLS using the
/// provided client certificate, and wraps the TLS stream in a WebSocket transport.
/// Server certificate chain validation is skipped via `SelfSignedServerVerifier`.
pub async fn setup_client(
    addr: &str,
    port: u16,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
) -> Result<Client, CoordinatorError> {
    let full_addr = format!("{}:{}", addr, port);
    let url = format!("wss://{}/", full_addr);
    let mut tls_config = client_tls_config(cert_der, key_der)?;
    tls_config
        .dangerous()
        .set_certificate_verifier(Arc::new(SelfSignedServerVerifier {}));

    let tls_connector = TlsConnector::from(Arc::new(tls_config));
    let tcp_stream = TcpStream::connect(&full_addr)
        .await
        .map_err(|e| CoordinatorError::ConnectError(e.to_string()))?;
    let domain = ServerName::try_from(addr)
        .map_err(|e| CoordinatorError::ConnectError(e.to_string()))?
        .to_owned();
    let tls_stream = tls_connector
        .connect(domain, tcp_stream)
        .await
        .map_err(|e| CoordinatorError::ConnectError(e.to_string()))?;

    let (sender, receiver) = WsTransportClientBuilder::default()
        .build_with_stream(
            Url::parse(&url).map_err(|e| CoordinatorError::ConnectError(e.to_string()))?,
            tls_stream,
        )
        .await
        .map_err(|e| CoordinatorError::ConnectError(e.to_string()))?;

    Ok(ClientBuilder::default().build_with_tokio(sender, receiver))
}
