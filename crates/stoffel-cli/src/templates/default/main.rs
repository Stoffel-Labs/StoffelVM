mod coordinator;
mod server;

/// Starts the local MPC infrastructure only. The participant client is a
/// separate binary so application code never lives inside the service process.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    coordinator::prepare_local()?;
    let _coordinator = coordinator::start().await?;
    let servers = server::start_all().await?;

    // Node RPC sockets open before preprocessing completes. Give the local
    // fixture time to enter the client-input round before advertising it.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    println!("Local Stoffel MPC services are ready.");
    println!("In another terminal run: cargo run --bin stoffel-client");
    println!("Press Ctrl-C here after the client receives its result.");

    tokio::signal::ctrl_c().await?;
    server::shutdown_all(servers).await?;
    Ok(())
}