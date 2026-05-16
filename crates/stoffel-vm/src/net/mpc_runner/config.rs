use std::time::Duration;

use crate::net::client_store::ClientInputHydrationCount;

/// Configuration for MPC runner behavior.
#[derive(Clone, Debug)]
pub struct MpcRunnerConfig {
    /// Timeout for VM execution.
    pub execution_timeout: Duration,
    /// Whether to automatically hydrate client inputs from MPC before execution.
    pub auto_hydrate: bool,
}

impl Default for MpcRunnerConfig {
    fn default() -> Self {
        Self {
            execution_timeout: Duration::from_secs(30),
            auto_hydrate: true,
        }
    }
}

/// Result of MPC-enabled VM execution.
pub struct MpcExecutionResult<T> {
    /// The return value from VM execution.
    pub value: T,
    /// Number of client inputs hydrated if auto-hydrate was enabled.
    pub clients_hydrated: ClientInputHydrationCount,
}
