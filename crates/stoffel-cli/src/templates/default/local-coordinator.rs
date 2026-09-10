//! Local-only coordinator fixture. The app client does not depend on this process launcher.
use std::{fs, path::PathBuf};
use stoffel::OffChainCoordinatorServer;
use stoffel_mpc_coordinator_off_chain::tests::fake_coord::{
    HoneyBadgerCoordinatorConnection, HoneyBadgerCoordinatorRPCServerSharedBase,
};
use stoffel_mpc_coordinator_shared::self_signed_certs;
use x509_parser::prelude::{FromDer, X509Certificate};

fn public_key(path: PathBuf) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    let (_, cert) = X509Certificate::from_der(&bytes)?;
    Ok(cert.public_key().subject_public_key.data.to_vec())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dir = root.join("deploy/local");
    match std::env::args().nth(1).as_deref() {
        Some("prepare") => {
            // Never overwrite identities from an existing deployment.
            fs::create_dir_all(root.join("deploy"))?;
            fs::create_dir(&dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
            }
            for name in [
                "node-0",
                "node-1",
                "node-2",
                "node-3",
                "node-4",
                "client-0",
                "coordinator",
            ] {
                let identity = self_signed_certs::server_cert();
                fs::write(dir.join(format!("{name}.cert.der")), identity.cert.der())?;
                fs::write(
                    dir.join(format!("{name}.key.der")),
                    identity.signing_key.serialize_der(),
                )?;
            }
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            let config = serde_json::json!({
                "program": "../../artifacts/program.stflb",
                "coordinator_host": "127.0.0.1",
                "coordinator_port": 19300,
                "timestamp": timestamp,
                "servers": ["127.0.0.1:20200", "127.0.0.1:19202", "127.0.0.1:19204", "127.0.0.1:19206", "127.0.0.1:19208"],
                "node_rpc_addresses": ["127.0.0.1:19400", "127.0.0.1:19401", "127.0.0.1:19402", "127.0.0.1:19403", "127.0.0.1:19404"],
                "client_cert": "client-0.cert.der",
                "client_key": "client-0.key.der"
            });
            fs::write(
                dir.join("deployment.json"),
                serde_json::to_vec_pretty(&config)?,
            )?;
            println!("Prepared local identities and deploy/local/deployment.json");
        }
        Some("serve") => {
            // The published reference coordinator supplies the real RPC state machine.
            // It is a one-computation development fixture, not a production control plane.
            let nodes = (0..5)
                .map(|id| public_key(dir.join(format!("node-{id}.cert.der"))))
                .collect::<Result<Vec<_>, _>>()?;
            let client = public_key(dir.join("client-0.cert.der"))?;
            let program = fs::read(root.join("artifacts/program.stflb"))?;
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"stoffel-program-v1");
            hasher.update(&program);
            let hash = *hasher.finalize().as_bytes();
            let state =
                HoneyBadgerCoordinatorRPCServerSharedBase::new(hash, 5, 1, nodes, 1, vec![client]);
            let _server =
                OffChainCoordinatorServer::<HoneyBadgerCoordinatorConnection>::start_coord(
                    state,
                    "127.0.0.1",
                    19300,
                    1,
                    fs::read(dir.join("coordinator.cert.der"))?,
                    fs::read(dir.join("coordinator.key.der"))?,
                )
                .await?;
            println!("Coordinator ready");
            tokio::signal::ctrl_c().await?;
        }
        _ => return Err("usage: cargo run --example local-coordinator -- prepare|serve".into()),
    }
    Ok(())
}
