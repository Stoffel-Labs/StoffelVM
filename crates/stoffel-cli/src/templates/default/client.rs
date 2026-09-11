mod deployment;

use deployment::bindings::{Client0Inputs, Client0Outputs};
use stoffel::prelude::StoffelClient;

/// This is the participant-owned code to integrate into your application.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let input = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "42".to_owned())
        .parse::<i64>()?;
    let client: StoffelClient = deployment::client()?;
    let output: Client0Outputs = client.run_typed(Client0Inputs { input_0: input }).await?;

    println!("Doubled result: {}", output.output_0);
    Ok(())
}
