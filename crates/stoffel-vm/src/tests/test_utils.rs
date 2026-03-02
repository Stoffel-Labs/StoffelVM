//! Shared test utilities for integration tests.

use std::sync::Once;

static CRYPTO_INIT: Once = Once::new();
static TRACING_INIT: Once = Once::new();

/// Initialize the rustls crypto provider (idempotent, safe to call from multiple tests).
pub(crate) fn init_crypto_provider() {
    CRYPTO_INIT.call_once(|| {
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }
    });
}

/// Set up a tracing subscriber for test output (idempotent, safe to call from multiple tests).
pub(crate) fn setup_test_tracing() {
    use tracing_subscriber::{EnvFilter, FmtSubscriber};

    TRACING_INIT.call_once(|| {
        let subscriber = FmtSubscriber::builder()
            .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
            .with_test_writer()
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    });
}
