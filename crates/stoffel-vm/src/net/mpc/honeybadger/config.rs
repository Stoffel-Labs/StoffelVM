use crate::net::engine_config::MpcSessionConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HoneyBadgerPreprocessingConfig {
    pub triples: usize,
    pub random_shares: usize,
}

impl HoneyBadgerPreprocessingConfig {
    pub const fn new(triples: usize, random_shares: usize) -> Self {
        Self {
            triples,
            random_shares,
        }
    }
}

#[derive(Clone)]
pub struct HoneyBadgerEngineConfig {
    pub session: MpcSessionConfig,
    pub preprocessing: HoneyBadgerPreprocessingConfig,
}

impl HoneyBadgerEngineConfig {
    pub const fn new(
        session: MpcSessionConfig,
        preprocessing: HoneyBadgerPreprocessingConfig,
    ) -> Self {
        Self {
            session,
            preprocessing,
        }
    }
}
