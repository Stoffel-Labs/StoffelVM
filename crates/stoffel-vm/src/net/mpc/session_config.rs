use crate::net::mpc_engine::{
    MpcInstanceId, MpcPartyCount, MpcPartyId, MpcSessionTopology, MpcSessionTopologyError,
    MpcThreshold,
};
use crate::net::open_registry::OpenMessageRouter;
use std::sync::Arc;
use stoffelnet::network_utils::ClientId;
use stoffelnet::transports::quic::QuicNetworkManager;

/// Common MPC engine session wiring shared by backend implementations.
///
/// Backend constructors should take this named config instead of long
/// positional argument lists. The VM needs multiple swappable MPC backends, and
/// this keeps session identity, transport, client inputs, and open-message
/// routing consistent across those backends.
#[derive(Clone)]
pub struct MpcSessionConfig {
    topology: MpcSessionTopology,
    network: Arc<QuicNetworkManager>,
    input_ids: Vec<ClientId>,
    open_message_router: Arc<OpenMessageRouter>,
}

impl MpcSessionConfig {
    pub fn try_new(
        instance_id: u64,
        party_id: usize,
        n_parties: usize,
        threshold: usize,
        network: Arc<QuicNetworkManager>,
    ) -> Result<Self, MpcSessionTopologyError> {
        let topology = MpcSessionTopology::try_new(instance_id, party_id, n_parties, threshold)?;
        Ok(Self::from_topology(topology, network))
    }

    pub fn from_topology(topology: MpcSessionTopology, network: Arc<QuicNetworkManager>) -> Self {
        Self {
            topology,
            network,
            input_ids: Vec::new(),
            open_message_router: Arc::new(OpenMessageRouter::new()),
        }
    }

    pub const fn topology(&self) -> MpcSessionTopology {
        self.topology
    }

    pub const fn instance(&self) -> MpcInstanceId {
        self.topology.instance()
    }

    pub const fn party(&self) -> MpcPartyId {
        self.topology.party()
    }

    pub const fn party_count(&self) -> MpcPartyCount {
        self.topology.party_count()
    }

    pub const fn threshold_param(&self) -> MpcThreshold {
        self.topology.threshold_param()
    }

    pub fn network(&self) -> Arc<QuicNetworkManager> {
        Arc::clone(&self.network)
    }

    pub fn input_ids(&self) -> &[ClientId] {
        &self.input_ids
    }

    pub fn open_message_router(&self) -> Arc<OpenMessageRouter> {
        Arc::clone(&self.open_message_router)
    }

    pub fn into_parts(
        self,
    ) -> (
        MpcSessionTopology,
        Arc<QuicNetworkManager>,
        Vec<ClientId>,
        Arc<OpenMessageRouter>,
    ) {
        (
            self.topology,
            self.network,
            self.input_ids,
            self.open_message_router,
        )
    }

    pub fn with_input_ids(mut self, input_ids: Vec<ClientId>) -> Self {
        self.input_ids = input_ids;
        self
    }

    pub fn with_open_message_router(mut self, router: Arc<OpenMessageRouter>) -> Self {
        self.open_message_router = router;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_config_names_shared_engine_construction_inputs() {
        let network = Arc::new(QuicNetworkManager::new());
        let router = Arc::new(OpenMessageRouter::new());

        let config = MpcSessionConfig::try_new(42, 1, 4, 1, Arc::clone(&network))
            .expect("test topology should be valid")
            .with_input_ids(vec![10, 11])
            .with_open_message_router(Arc::clone(&router));

        assert_eq!(
            config.topology(),
            MpcSessionTopology::try_new(42, 1, 4, 1).unwrap()
        );
        assert_eq!(config.instance().id(), 42);
        assert_eq!(config.party().id(), 1);
        assert_eq!(config.party_count().count(), 4);
        assert_eq!(config.threshold_param().value(), 1);
        assert_eq!(config.input_ids(), &[10, 11]);
        assert!(Arc::ptr_eq(&config.network(), &network));
        assert!(Arc::ptr_eq(&config.open_message_router(), &router));
    }

    #[test]
    fn session_config_validates_topology() {
        let network = Arc::new(QuicNetworkManager::new());

        assert!(matches!(
            MpcSessionConfig::try_new(1, 0, 0, 0, Arc::clone(&network)),
            Err(MpcSessionTopologyError::ZeroParties)
        ));
        assert!(matches!(
            MpcSessionConfig::try_new(1, 2, 2, 0, Arc::clone(&network)),
            Err(MpcSessionTopologyError::PartyOutOfRange {
                party_id: 2,
                n_parties: 2
            })
        ));
        assert!(matches!(
            MpcSessionConfig::try_new(1, 0, 2, 2, Arc::clone(&network)),
            Err(MpcSessionTopologyError::ThresholdOutOfRange {
                threshold: 2,
                n_parties: 2
            })
        ));
    }
}
