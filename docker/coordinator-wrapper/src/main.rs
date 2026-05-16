use std::fs;

use clap::Parser;
use stoffel_mpc_coordinator::fake_coord::off_chain::{
    FakeCoordinatorRPCServerSharedBase, FakeOffChainCoordinatorServer,
};
use x509_parser::prelude::*;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    hash: String,

    #[arg(long, value_delimiter = ',', num_args = 1..)]
    initial_mpc_nodes: Vec<String>,

    #[arg(long)]
    server_cert: String,

    #[arg(long)]
    server_key: String,

    #[arg(long)]
    n: u64,

    #[arg(long)]
    t: u64,

    #[arg(long)]
    n_inputs: u64,

    #[arg(long, value_delimiter = ',', num_args = 1..)]
    output_clients: Vec<String>,

    #[arg(long, default_value = "0.0.0.0")]
    bind_addr: String,

    #[arg(long, default_value_t = 31415)]
    port: u16,
}

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install default crypto provider");

    let args = Args::parse();
    let _ = args.n_inputs;

    let hash: [u8; 32] = hex::decode(args.hash)
        .expect("invalid hash")
        .try_into()
        .expect("hash must be 32 bytes");

    let parse_public_keys = |cert_files: &[String]| -> Vec<Vec<u8>> {
        cert_files
            .iter()
            .map(|cert_file| {
                let cert_der = fs::read(cert_file).expect("could not read certificate file");
                let (_, parsed_cert) = X509Certificate::from_der(&cert_der)
                    .expect("Failed to parse X.509 certificate");
                parsed_cert
                    .public_key()
                    .subject_public_key
                    .data
                    .as_ref()
                    .to_vec()
            })
            .collect()
    };

    let public_keys = parse_public_keys(&args.initial_mpc_nodes);
    let output_client_keys = parse_public_keys(&args.output_clients);

    let server_cert_der = fs::read(args.server_cert).expect("could not read server cert");
    let server_key_der = fs::read(args.server_key).expect("could not read server key");

    let server_state = FakeCoordinatorRPCServerSharedBase::new(
        hash,
        args.n,
        args.t,
        public_keys,
        args.n_inputs,
        output_client_keys,
    );

    let coord = FakeOffChainCoordinatorServer::start_coord(
        server_state,
        &args.bind_addr,
        args.port,
        args.t,
        server_cert_der,
        server_key_der,
    )
    .await
    .expect("failed to start coordinator");

    println!("Listening on {}:{}", args.bind_addr, args.port);
    println!("Timestamp: {}", coord.get_timestamp());

    tokio::time::sleep(tokio::time::Duration::MAX).await;
}
