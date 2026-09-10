use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=artifacts/program.stflb");
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let bytecode = root.join("artifacts/program.stflb");
    if !bytecode.is_file() {
        return Err("build bytecode first: stoffel build --output artifacts/program.stflb".into());
    }
    stoffel_bindgen::generate_bindings(
        bytecode,
        PathBuf::from(std::env::var("OUT_DIR")?).join("stoffel_bindings.rs"),
    )?;
    Ok(())
}
