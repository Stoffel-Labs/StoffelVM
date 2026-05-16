use std::sync::Arc;

use ark_ec::CurveGroup;
use ark_ff::{FftField, PrimeField};

use crate::net::engine_config::MpcSessionConfig;

#[derive(Clone)]
pub struct AvssEngineConfig<F, G>
where
    F: FftField + PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    pub session: MpcSessionConfig,
    pub secret_key: F,
    pub public_keys: Arc<Vec<G>>,
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
        }
    }
}
