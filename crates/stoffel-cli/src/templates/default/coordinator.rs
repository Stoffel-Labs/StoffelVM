use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use stoffel::coordinator::OffChainCoordinatorServer;
use stoffel_mpc_coordinator_off_chain::tests::fake_coord::{
    HoneyBadgerCoordinatorConnection, HoneyBadgerCoordinatorRPCServerSharedBase,
};

use x509_parser::parse_x509_certificate;

pub type LocalCoordinator = OffChainCoordinatorServer<HoneyBadgerCoordinatorConnection>;

#[derive(Deserialize)]
struct ProjectConfig {
    mpc: MpcConfig,
}

#[derive(Deserialize)]
struct MpcConfig {
    parties: usize,
    threshold: usize,
}

#[derive(Serialize, Deserialize)]
struct DeploymentFile {
    program: String,
    coordinator_host: String,
    coordinator_port: u16,
    timestamp: u64,
    parties: usize,
    threshold: usize,
    servers: Vec<String>,
    node_rpc_addresses: Vec<String>,
    client_cert: String,
    client_key: String,
}

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn settings() -> Result<MpcConfig, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(project_root().join("Stoffel.toml"))?;
    Ok(toml::from_str::<ProjectConfig>(&text)?.mpc)
}

fn deployment_dir() -> PathBuf {
    project_root().join("deploy/local")
}

fn identity(name: &str) -> Result<Arc<rcgen::CertifiedKey<rcgen::KeyPair>>, Box<dyn std::error::Error>> {
    let subject = name.replace('-', ".");
    let certified = rcgen::generate_simple_self_signed(vec![format!("{subject}.local")])?;
    Ok(Arc::new(certified))
}

fn write_identity(
    dir: &Path,
    name: &str,
    identity: &rcgen::CertifiedKey<rcgen::KeyPair>,
) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::write(dir.join(format!("{name}.cert.der")), identity.cert.der())?;
    std::fs::write(
        dir.join(format!("{name}.key.der")),
        identity.signing_key.serialize_der(),
    )?;
    Ok(())
}

fn public_key(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    let (_, certificate) = parse_x509_certificate(&bytes)
        .map_err(|error| format!("failed to parse {}: {error}", path.display()))?;
    Ok(certificate.public_key().subject_public_key.data.to_vec())
}

pub fn prepare_local() -> Result<(), Box<dyn std::error::Error>> {
    let config = settings()?;
    let dir = deployment_dir();
    if dir.exists() {
        let required = std::iter::once("coordinator.cert.der".to_owned())
            .chain(std::iter::once("coordinator.key.der".to_owned()))
            .chain(std::iter::once("client-0.cert.der".to_owned()))
            .chain(std::iter::once("client-0.key.der".to_owned()))
            .chain((0..config.parties).flat_map(|party| {
                [
                    format!("node-{party}.cert.der"),
                    format!("node-{party}.key.der"),
                ]
            }))
            .chain(std::iter::once("deployment.json".to_owned()));
        for name in required {
            if !dir.join(&name).exists() {
                return Err(format!(
                    "{} is incomplete; remove it and rerun the prepare command",
                    dir.display()
                )
                .into());
            }
        }
        let deployment: DeploymentFile =
            serde_json::from_slice(&std::fs::read(dir.join("deployment.json"))?)?;
        if deployment.parties != config.parties || deployment.threshold != config.threshold {
            return Err("Stoffel.toml changed after local identities were prepared; remove deploy/local and prepare again".into());
        }
        return Ok(());
    }

    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let coordinator = identity("coordinator")?;
    write_identity(&dir, "coordinator", &coordinator)?;
    let client = identity("client-0")?;
    write_identity(&dir, "client-0", &client)?;
    for party in 0..config.parties {
        let node = identity(&format!("node-{party}"))?;
        write_identity(&dir, &format!("node-{party}"), &node)?;
    }

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let deployment = DeploymentFile {
        program: "../../artifacts/program.stflb".to_owned(),
        coordinator_host: "127.0.0.1".to_owned(),
        coordinator_port: 19_300,
        timestamp,
        parties: config.parties,
        threshold: config.threshold,
        servers: (0..config.parties)
            .map(|party| {
                let port = if party == 0 { 20_200 } else { 19_200 + party * 2 };
                format!("127.0.0.1:{port}")
            })
            .collect(),
        node_rpc_addresses: (0..config.parties)
            .map(|party| format!("127.0.0.1:{}", 19_400 + party))
            .collect(),
        client_cert: "client-0.cert.der".to_owned(),
        client_key: "client-0.key.der".to_owned(),
    };
    std::fs::write(
        dir.join("deployment.json"),
        serde_json::to_vec_pretty(&deployment)?,
    )?;
    Ok(())
}

pub async fn start() -> Result<LocalCoordinator, Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = settings()?;
    let dir = deployment_dir();
    let deployment: DeploymentFile =
        serde_json::from_slice(&std::fs::read(dir.join("deployment.json"))?)?;
    let program = std::fs::read(dir.join(&deployment.program))?;
    let mut hasher = Hasher::new();
    hasher.update(b"stoffel-program-v1");
    hasher.update(&program);
    let program_id = *hasher.finalize().as_bytes();
    let node_public_keys = (0..config.parties)
        .map(|party| public_key(&dir.join(format!("node-{party}.cert.der"))))
        .collect::<Result<Vec<_>, _>>()?;
    let client_id = public_key(&dir.join("client-0.cert.der"))?;
    let state = HoneyBadgerCoordinatorRPCServerSharedBase::new(
        program_id,
        config.parties as u64,
        config.threshold as u64,
        node_public_keys,
        1,
        vec![client_id],
    );
    let host = std::env::var("STOFFEL_COORDINATOR_BIND")
        .unwrap_or_else(|_| deployment.coordinator_host.clone());
    let cert = std::fs::read(dir.join("coordinator.cert.der"))?;
    let key = std::fs::read(dir.join("coordinator.key.der"))?;
    Ok(LocalCoordinator::start_coord(
        state,
        &host,
        deployment.coordinator_port,
        config.threshold as u64,
        cert,
        key,
    )
    .await?)
}

#[allow(dead_code)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match std::env::args().nth(1).as_deref() {
        Some("prepare") => {
            prepare_local()?;
            println!("Prepared deploy/local identities and deployment.json");
        }
        Some("serve") => {
            prepare_local()?;
            let _coordinator = start().await?;
            eprintln!("Coordinator started; press Ctrl-C to stop");
            tokio::signal::ctrl_c().await?;
        }
        _ => return Err("usage: stoffel-coordinator <prepare|serve>".into()),
    }
    Ok(())
}
