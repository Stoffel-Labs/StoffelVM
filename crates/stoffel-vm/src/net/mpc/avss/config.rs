use std::sync::Arc;

use ark_ec::CurveGroup;
use ark_ff::{FftField, PrimeField};

use crate::net::engine_config::{DeploymentMode, MpcSessionConfig};
use crate::net::ExecutionScopedNetwork;

#[derive(Clone)]
pub struct AvssEngineConfig<F, G>
where
    F: FftField + PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    pub session: MpcSessionConfig,
    pub secret_key: F,
    pub public_keys: Arc<Vec<G>>,
    pub deployment_mode: DeploymentMode,
    pub protocol_network: Option<ExecutionScopedNetwork>,
    /// Program-visible random shares retained after preprocessing.
    pub n_random_shares: usize,
    /// Beaver triples requested from preprocessing. AVSS may round this up to
    /// its party-group generation granularity.
    pub n_triples: usize,
}

impl<F, G> AvssEngineConfig<F, G>
where
    F: FftField + PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    pub fn new(session: MpcSessionConfig, secret_key: F, public_keys: Arc<Vec<G>>) -> Self {
        Self {
            session,
            secret_key,
            public_keys,
            deployment_mode: DeploymentMode::OneShot,
            protocol_network: None,
            n_random_shares: super::DEFAULT_N_RANDOM_SHARES,
            n_triples: super::DEFAULT_N_TRIPLES,
        }
    }

    pub fn with_deployment_mode(mut self, deployment_mode: DeploymentMode) -> Self {
        self.deployment_mode = deployment_mode;
        self
    }

    pub fn with_protocol_network(mut self, protocol_network: ExecutionScopedNetwork) -> Self {
        self.protocol_network = Some(protocol_network);
        self
    }

    /// Override in-memory preprocessing targets for this engine.
    pub fn with_preprocessing_counts(mut self, n_random_shares: usize, n_triples: usize) -> Self {
        self.n_random_shares = n_random_shares;
        self.n_triples = n_triples;
        self
    }
}
