use serde::Deserialize;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use stoffel::prelude::{NetworkDeployment, Stoffel};

#[allow(dead_code, unused_mut, unused_variables)]
mod stoffel_bindings {
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

/// This is the participant-owned code to integrate into your application.
/// It reads one private value and submits it directly to the MPC network.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config_path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("deploy/local/deployment.json")
        });
    let config = Deployment::load(&config_path)?;
    let runtime = Stoffel::load_file(&config.program)?
        .manifest::<stoffel_bindings::ProgramManifest>()
        .parties(config.parties)
        .threshold(config.threshold)
        .build()?;
    let deployment = NetworkDeployment::builder(config.servers)
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
    let client = runtime
        .client_for_deployment(&deployment)
        .client_id(0)
        .offchain_io(offchain)
        .build()?;

    eprintln!("Enter a private integer:");
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let private_input = input.trim().parse::<i64>()?;
    let deadline = Instant::now() + Duration::from_secs(90);
    let output: stoffel_bindings::Client0Outputs = loop {
        match client
            .run_typed(stoffel_bindings::Client0Inputs {
                input_0: private_input,
            })
            .await
        {
            Ok(output) => break output,
            Err(error)
                if Instant::now() < deadline
                    && (error.to_string().contains(
                        "Need round InputMaskReservation, current round is Idle",
                    ) || error.to_string().contains(
                        "Need round InputMaskReservation, current round is Preprocessing",
                    )) =>
            {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => return Err(error.into()),
        }
    };
    println!("Doubled result: {}", output.output_0);
    Ok(())
}
