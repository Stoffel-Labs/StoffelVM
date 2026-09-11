use serde::Deserialize;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use stoffel::prelude::{OffChainServerConfig, Stoffel, StoffelServer};

#[derive(Clone, Deserialize)]
struct ProjectConfig {
    mpc: MpcConfigFile,
}

#[derive(Clone, Deserialize)]
struct MpcConfigFile {
    parties: usize,
    threshold: usize,
}

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn settings() -> Result<MpcConfigFile, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(project_root().join("Stoffel.toml"))?;
    Ok(toml::from_str::<ProjectConfig>(&text)?.mpc)
}

fn env_or(name: &str, fallback: String) -> String {
    std::env::var(name).unwrap_or(fallback)
}

fn node_bind_address(party_id: usize) -> String {
    env_or(
        "STOFFEL_BIND_ADDRESS",
        format!("127.0.0.1:{}", 19_200 + party_id.saturating_mul(2)),
    )
}

fn node_rpc_address(party_id: usize) -> String {
    env_or(
        "STOFFEL_RPC_BIND_ADDRESS",
        format!("127.0.0.1:{}", 19_400 + party_id),
    )
}

fn node_mesh_address(party_id: usize) -> String {
    let port = if party_id == 0 {
        20_200
    } else {
        19_200 + party_id.saturating_mul(2)
    };
    format!("127.0.0.1:{port}")
}

fn coordinator_address() -> String {
    env_or(
        "STOFFEL_COORDINATOR_ADDRESS",
        "127.0.0.1:19300".to_owned(),
    )
}

fn identity_path(party_id: usize, suffix: &str) -> PathBuf {
    project_root().join(format!("deploy/local/node-{party_id}.{suffix}.der"))
}

fn client_certificate() -> PathBuf {
    project_root().join("deploy/local/client-0.cert.der")
}

fn deployment_timestamp() -> Result<u64, Box<dyn std::error::Error>> {
    #[derive(Deserialize)]
    struct DeploymentTimestamp {
        timestamp: u64,
    }
    let path = project_root().join("deploy/local/deployment.json");
    let config: DeploymentTimestamp = serde_json::from_slice(&std::fs::read(path)?)?;
    Ok(config.timestamp)
}

pub async fn start_party(party_id: usize) -> Result<StoffelServer, Box<dyn std::error::Error>> {
    let config = settings()?;
    if party_id >= config.parties {
        return Err(format!("party {party_id} is outside mpc.parties={}", config.parties).into());
    }

    let artifact = project_root().join("artifacts/program.stflb");
    if !artifact.exists() {
        return Err("missing artifacts/program.stflb; run `stoffel build --output artifacts/program.stflb` first".into());
    }
    let runtime = Stoffel::load_file(&artifact)?
        .parties(config.parties)
        .threshold(config.threshold)
        .build()?;
    let offchain = OffChainServerConfig::builder()
        .coordinator(coordinator_address())
        .rpc_bind(node_rpc_address(party_id))
        .identity_files(
            identity_path(party_id, "cert"),
            identity_path(party_id, "key"),
        )
        .timestamp(deployment_timestamp()?)
        .expected_client_cert(client_certificate())
        .build()?;

    let mut builder = runtime
        .server(party_id)
        .bind(node_bind_address(party_id))
        .peers(
            (0..config.parties)
                .filter(|peer_id| *peer_id != party_id)
                .map(|peer_id| (peer_id, node_mesh_address(peer_id))),
        )
        .expected_clients(1)
        .offchain_coordinator(offchain);
    if party_id > 0 {
        builder = builder.bootstrap(env_or(
            "STOFFEL_BOOTSTRAP_ADDRESS",
            "127.0.0.1:19200".to_owned(),
        ));
    }
    if let Some(path) = std::env::var_os("STOFFEL_RUN_BIN") {
        builder = builder.runner_path(path);
    }
    let server = builder.build()?;
    server.start().await?;
    Ok(server)
}

pub async fn start_all() -> Result<Vec<StoffelServer>, Box<dyn std::error::Error>> {
    let config = settings()?;
    let mut servers = Vec::with_capacity(config.parties);
    for party_id in 0..config.parties {
        servers.push(start_party(party_id).await?);
    }
    wait_for_rpc_services(config.parties).await?;
    Ok(servers)
}

async fn wait_for_rpc_services(parties: usize) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(90);
    for party_id in 0..parties {
        let address = node_rpc_address(party_id);
        loop {
            if tokio::net::TcpStream::connect(&address).await.is_ok() {
                break;
            }
            if Instant::now() >= deadline {
                return Err(format!("timed out waiting for MPC node RPC at {address}").into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    Ok(())
}

pub async fn shutdown_all(servers: Vec<StoffelServer>) -> Result<(), Box<dyn std::error::Error>> {
    for server in servers.into_iter().rev() {
        server.shutdown().await?;
    }
    Ok(())
}

#[allow(dead_code)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let party_id = std::env::args()
        .nth(1)
        .ok_or("usage: stoffel-server <party-id>")?
        .parse::<usize>()?;
    let server = start_party(party_id).await?;
    eprintln!("MPC server {party_id} started; press Ctrl-C to stop");
    tokio::signal::ctrl_c().await?;
    server.shutdown().await?;
    Ok(())
}
