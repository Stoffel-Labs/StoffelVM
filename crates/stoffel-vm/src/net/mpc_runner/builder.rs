use std::sync::Arc;
use std::time::Duration;

use ark_bls12_381::Fr;
use stoffelmpc_mpc::honeybadger::HoneyBadgerMPCNode;
use stoffelnet::transports::quic::QuicNetworkManager;

use crate::core_vm::VirtualMachine;
use crate::net::hb_engine::HoneyBadgerMpcEngine;
use crate::net::mpc_engine::{MpcSessionTopology, MpcSessionTopologyError};

use super::config::MpcRunnerConfig;
use super::error::MpcRunnerResult;
use super::honeybadger::RBCImpl;
use super::runner::MpcRunner;

/// Builder for creating MpcRunner with customizable options.
pub struct MpcRunnerBuilder {
    pub(super) topology: MpcSessionTopology,
    pub(super) config: MpcRunnerConfig,
}

impl MpcRunnerBuilder {
    /// Try to create a builder with validated MPC topology parameters.
    pub fn try_new(
        instance_id: u64,
        party_id: usize,
        n_parties: usize,
        threshold: usize,
    ) -> Result<Self, MpcSessionTopologyError> {
        let topology = MpcSessionTopology::try_new(instance_id, party_id, n_parties, threshold)?;
        Ok(Self::from_topology(topology))
    }

    /// Create a builder from a validated MPC session topology.
    pub fn from_topology(topology: MpcSessionTopology) -> Self {
        Self {
            topology,
            config: MpcRunnerConfig::default(),
        }
    }

    /// Validated topology used for engine construction.
    pub const fn topology(&self) -> MpcSessionTopology {
        self.topology
    }

    /// Set the execution timeout.
    pub fn execution_timeout(mut self, timeout: Duration) -> Self {
        self.config.execution_timeout = timeout;
        self
    }

    /// Disable auto-hydration of client inputs.
    pub fn disable_auto_hydrate(mut self) -> Self {
        self.config.auto_hydrate = false;
        self
    }

    /// Fallibly build the MpcRunner with an existing MPC node and network.
    pub fn try_build(
        self,
        network: Arc<QuicNetworkManager>,
        node: HoneyBadgerMPCNode<Fr, RBCImpl>,
    ) -> MpcRunnerResult<MpcRunner> {
        let topology = self.topology;
        let mpc_engine =
            HoneyBadgerMpcEngine::<ark_bls12_381::Fr, ark_bls12_381::G1Projective>::from_existing_node_with_topology(
                topology,
                network,
                node,
            );
        let vm = VirtualMachine::builder()
            .with_mpc_engine(mpc_engine.clone())
            .try_build()?;

        Ok(MpcRunner::with_config(vm, mpc_engine, self.config))
    }

    /// Build the MpcRunner with an existing MPC node and network.
    ///
    /// Panics if VM construction fails. Prefer [`Self::try_build`] in code that
    /// should surface construction errors to callers.
    #[track_caller]
    pub fn build(
        self,
        network: Arc<QuicNetworkManager>,
        node: HoneyBadgerMPCNode<Fr, RBCImpl>,
    ) -> MpcRunner {
        self.try_build(network, node)
            .expect("invalid MPC runner configuration")
    }
}
