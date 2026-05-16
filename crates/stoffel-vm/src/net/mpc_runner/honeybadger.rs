use std::sync::Arc;

use ark_bls12_381::Fr;
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::honeybadger::HoneyBadgerMPCNode;
use stoffelmpc_mpc::honeybadger::SessionId as HbSessionId;
use stoffelnet::transports::quic::QuicNetworkManager;

use crate::core_vm::VirtualMachine;
use crate::net::hb_engine::HoneyBadgerMpcEngine;
use crate::net::mpc_engine::MpcSessionTopology;

use super::config::MpcRunnerConfig;
use super::error::MpcRunnerResult;
use super::runner::MpcRunner;

pub(super) type RBCImpl = Avid<HbSessionId>;

impl MpcRunner<HoneyBadgerMpcEngine<ark_bls12_381::Fr, ark_bls12_381::G1Projective>> {
    /// Create an MpcRunner from raw HoneyBadger MPC components.
    ///
    /// This creates a VM, attaches the MPC engine, and sets up the message processor.
    pub fn try_from_node(
        instance_id: u64,
        party_id: usize,
        n_parties: usize,
        threshold: usize,
        network: Arc<QuicNetworkManager>,
        node: HoneyBadgerMPCNode<Fr, RBCImpl>,
    ) -> MpcRunnerResult<Self> {
        let topology = MpcSessionTopology::try_new(instance_id, party_id, n_parties, threshold)?;
        Self::try_from_node_with_topology(topology, network, node)
    }

    /// Fallibly create an MpcRunner from raw HoneyBadger MPC components and a validated topology.
    pub fn try_from_node_with_topology(
        topology: MpcSessionTopology,
        network: Arc<QuicNetworkManager>,
        node: HoneyBadgerMPCNode<Fr, RBCImpl>,
    ) -> MpcRunnerResult<Self> {
        let mpc_engine =
            HoneyBadgerMpcEngine::<ark_bls12_381::Fr, ark_bls12_381::G1Projective>::from_existing_node_with_topology(
                topology,
                network,
                node,
            );
        let vm = VirtualMachine::builder()
            .with_mpc_engine(mpc_engine.clone())
            .try_build()?;

        Ok(Self::with_config(
            vm,
            mpc_engine,
            MpcRunnerConfig::default(),
        ))
    }

    /// Create an MpcRunner from raw HoneyBadger MPC components and a validated topology.
    ///
    /// Panics if VM construction fails. Prefer [`Self::try_from_node_with_topology`]
    /// in code that should surface construction errors to callers.
    #[track_caller]
    pub fn from_node_with_topology(
        topology: MpcSessionTopology,
        network: Arc<QuicNetworkManager>,
        node: HoneyBadgerMPCNode<Fr, RBCImpl>,
    ) -> Self {
        Self::try_from_node_with_topology(topology, network, node)
            .expect("invalid MPC runner configuration")
    }
}
