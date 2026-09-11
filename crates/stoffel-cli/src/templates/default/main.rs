mod coordinator;
mod server;

/// Starts the local MPC infrastructure only. The participant client is a
/// separate binary so application code never lives inside the service process.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    coordinator::prepare_local()?;
    let _coordinator = coordinator::start().await?;
    let servers = server::start_all().await?;

    println!("Local Stoffel MPC services are ready.");
    println!("In another terminal run: cargo run --bin stoffel-client");
    println!("Press Ctrl-C here after the client receives its result.");

    tokio::signal::ctrl_c().await?;
    server::shutdown_all(servers).await?;
    Ok(())
}