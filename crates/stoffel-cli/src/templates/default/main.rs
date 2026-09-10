use std::io;
use std::path::PathBuf;
use stoffel::prelude::*;

mod deployment;

#[allow(dead_code, unused_mut, unused_variables)]
mod stoffel_bindings {
    include!(concat!(env!("OUT_DIR"), "/stoffel_bindings.rs"));
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config_path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("deploy/local/deployment.json")
        });
    let config = deployment::Deployment::load(&config_path)?;
    let runtime = Stoffel::load_file(&config.program)?
        .manifest::<stoffel_bindings::ProgramManifest>()
        .parties(5)
        .threshold(1)
        .build()?;
    let deployment = NetworkDeployment::builder(config.servers)
        .expected_clients(1)
        .threshold(1)
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

    // In your app, obtain this value from its owner's UI or application state.
    // Only this participant process sees the input; it goes directly to the MPC service.
    eprintln!("Enter a private integer:");
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input_0 = input.trim().parse::<i64>()?;
    let output: stoffel_bindings::Client0Outputs = client
        .run_typed(stoffel_bindings::Client0Inputs { input_0 })
        .await?;
    println!("Doubled result: {}", output.output_0);
    Ok(())
}
