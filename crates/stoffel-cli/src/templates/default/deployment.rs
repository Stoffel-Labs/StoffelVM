use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Public deployment metadata and paths to this participant's identity.
/// Relative paths are resolved beside the config, not against the working directory.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deployment {
    pub program: PathBuf,
    pub coordinator_host: String,
    pub coordinator_port: u16,
    pub timestamp: u64,
    pub servers: Vec<String>,
    pub node_rpc_addresses: Vec<String>,
    pub client_cert: PathBuf,
    pub client_key: PathBuf,
}

impl Deployment {
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let mut config: Self = serde_json::from_slice(&std::fs::read(path)?)?;
        if config.servers.len() != 5 || config.node_rpc_addresses.len() != 5 {
            return Err("this program deployment requires five mesh and five RPC addresses".into());
        }
        let root = path.parent().unwrap_or(Path::new("."));
        config.program = root.join(config.program);
        config.client_cert = root.join(config.client_cert);
        config.client_key = root.join(config.client_key);
        Ok(config)
    }
}
