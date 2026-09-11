use serde::Deserialize;
use std::path::{Path, PathBuf};
use stoffel::prelude::{NetworkDeployment, Stoffel, StoffelClient};

#[allow(dead_code, unused_mut, unused_variables)]
pub mod bindings {
    include!(concat!(env!("OUT_DIR"), "/stoffel_bindings.rs"));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Deployment {
    program: PathBuf,
    coordinator_host: String,
    coordinator_port: u16,
    timestamp: u64,
    parties: usize,
    threshold: usize,
    servers: Vec<String>,
    node_rpc_addresses: Vec<String>,
    client_cert: PathBuf,
    client_key: PathBuf,
}

impl Deployment {
    fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let mut config: Self = serde_json::from_slice(&std::fs::read(path)?)?;
        if config.servers.len() != config.parties
            || config.node_rpc_addresses.len() != config.parties
        {
            return Err("deployment address counts must match mpc.parties".into());
        }
        let root = path.parent().unwrap_or(Path::new("."));
        config.program = root.join(config.program);
        config.client_cert = root.join(config.client_cert);
        config.client_key = root.join(config.client_key);
        Ok(config)
    }
}

/// Connects an application client to the configured Stoffel deployment.
/// A real app can replace this file with its own configuration provider.
pub fn client() -> Result<StoffelClient, Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config_path = std::env::var_os("STOFFEL_DEPLOYMENT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("deploy/local/deployment.json")
        });
    let config = Deployment::load(&config_path)?;
    let runtime = Stoffel::load_file(&config.program)?
        .manifest::<bindings::ProgramManifest>()
        .parties(config.parties)
        .threshold(config.threshold)
        .build()?;
    let network = NetworkDeployment::builder(config.servers)
        .expected_clients(1)
        .threshold(config.threshold)
        .honeybadger()
        .build()?;
    let offchain = runtime
        .offchain_client_config(0)?
        .coordinator(config.coordinator_host, config.coordinator_port)
        .timestamp(config.timestamp)
        .node_rpc_addresses(config.node_rpc_addresses)
        .identity_files(config.client_cert, config.client_key)
        .timeout(std::time::Duration::from_secs(120))
        .build()?;

    Ok(runtime
        .client_for_deployment(&network)
        .client_id(0)
        .offchain_io(offchain)
        .build()?)
}
