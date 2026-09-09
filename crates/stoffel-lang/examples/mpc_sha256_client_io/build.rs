use std::path::PathBuf;

use stoffel_bindgen::{BindingsConfig, EntrypointBinding, ShareType};

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=main.stfl");
    let out_file = PathBuf::from(std::env::var("OUT_DIR")?).join("stoffel_bindings.rs");
    stoffel_bindgen::generate_bindings_from_source(
        "main.stfl",
        out_file,
        BindingsConfig {
            entrypoints: vec![EntrypointBinding::new("hash_32_bytes")
                .input(0, "message", "SecretMessage32")
                .output(0, "Sha256Digest", vec![ShareType::secret_int(64); 8])],
            ..BindingsConfig::default()
        },
    )?;
    Ok(())
}
