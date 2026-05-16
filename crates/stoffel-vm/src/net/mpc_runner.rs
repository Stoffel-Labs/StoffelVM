//! MpcRunner - Helper for running VM with MPC background tasks.
//!
//! This module provides a convenient way to run a VM alongside async MPC
//! background tasks such as message processing and preprocessing.
//!
//! The runner encapsulates the pattern of:
//! 1. Running MPC message processing in a background task
//! 2. Running VM execution in a blocking or async-native context
//! 3. Coordinating between async MPC operations and VM operations

mod builder;
mod config;
mod error;
mod guard;
mod honeybadger;
mod runner;

pub use builder::MpcRunnerBuilder;
pub use config::{MpcExecutionResult, MpcRunnerConfig};
pub use error::{MpcRunnerError, MpcRunnerResult};
pub use runner::MpcRunner;

#[cfg(test)]
mod tests;
