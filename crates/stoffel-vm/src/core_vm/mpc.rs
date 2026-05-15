use super::VirtualMachine;
#[cfg(feature = "honeybadger")]
use crate::net::client_store::ClientInputStore;
use crate::net::client_store::ClientShare;
#[cfg(feature = "honeybadger")]
use crate::net::client_store::ClientShareIndex;
#[cfg(feature = "honeybadger")]
use crate::net::mpc_engine::AsyncMpcEngine;
use crate::net::mpc_engine::{MpcEngine, MpcRuntimeInfo};
use crate::VirtualMachineResult;
use std::sync::Arc;
use stoffel_vm_types::core_types::{ShareData, ShareType, Value};

impl VirtualMachine {
    /// Attach or replace the MPC backend used by this VM.
    pub fn set_mpc_engine(&mut self, engine: Arc<dyn MpcEngine>) {
        self.state.set_mpc_engine(engine);
    }

    /// Snapshot configured MPC runtime metadata without exposing backend operations.
    pub fn mpc_runtime_info(&self) -> Option<MpcRuntimeInfo> {
        self.state.mpc_runtime_info()
    }

    /// Verify that the configured MPC backend is ready for protocol work.
    pub fn ensure_mpc_ready(&self) -> VirtualMachineResult<()> {
        Ok(self.state.ensure_mpc_ready()?)
    }

    /// Open a VM share value through the configured MPC backend.
    pub fn open_share_value(&self, value: &Value) -> VirtualMachineResult<Value> {
        Ok(self.state.open_share_value(value)?)
    }

    /// Clear all client inputs owned by this VM.
    pub fn clear_client_inputs(&self) {
        self.state.clear_client_inputs();
    }

    #[cfg(feature = "honeybadger")]
    pub(crate) fn client_input_store_for_async_engine<E: AsyncMpcEngine + ?Sized>(
        &self,
        engine: &E,
    ) -> VirtualMachineResult<Arc<ClientInputStore>> {
        self.state.ensure_async_engine_matches(engine)?;
        Ok(self.state.client_input_store())
    }

    /// Retrieve a backend-neutral VM client share payload.
    pub fn client_share_data(
        &self,
        client_id: stoffelnet::network_utils::ClientId,
        index: crate::net::client_store::ClientShareIndex,
    ) -> Option<ClientShare> {
        self.state.client_share_data(client_id, index)
    }

    /// Store VM-level client share payloads through the VM boundary.
    pub fn store_client_shares(
        &self,
        client_id: stoffelnet::network_utils::ClientId,
        shares: Vec<ClientShare>,
    ) {
        self.state.store_client_shares(client_id, shares);
    }

    /// Atomically replace all client inputs with backend-neutral VM share payloads.
    ///
    /// Prefer this when orchestration already has [`ClientShare`] values. The
    /// protocol-specific helpers remain for callers that still hold backend-native
    /// share structs.
    pub fn replace_client_shares<I>(&self, inputs: I) -> usize
    where
        I: IntoIterator<Item = (stoffelnet::network_utils::ClientId, Vec<ClientShare>)>,
    {
        self.state.replace_client_shares(inputs)
    }

    /// Store HoneyBadger client shares through the VM boundary.
    #[cfg(feature = "honeybadger")]
    pub fn try_store_client_input<F>(
        &self,
        client_id: stoffelnet::network_utils::ClientId,
        shares: Vec<
            stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare<F>,
        >,
    ) -> VirtualMachineResult<usize>
    where
        F: ark_ff::FftField,
    {
        Ok(self.state.try_store_client_input(client_id, shares)?)
    }

    /// Replace all client inputs with HoneyBadger client shares.
    ///
    /// This is the HoneyBadger-specific hydration boundary for code that still
    /// holds robust shares. Inputs are serialized before the current store is
    /// cleared.
    ///
    /// Prefer [`VirtualMachine::replace_client_shares`] when the caller already
    /// has backend-neutral VM share payloads.
    #[cfg(feature = "honeybadger")]
    pub fn try_replace_client_inputs<F, I>(&self, inputs: I) -> VirtualMachineResult<usize>
    where
        F: ark_ff::FftField,
        I: IntoIterator<
            Item = (
                stoffelnet::network_utils::ClientId,
                Vec<
                    stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare<
                        F,
                    >,
                >,
            ),
        >,
    {
        Ok(self.state.try_replace_client_input(inputs)?)
    }

    /// Retrieve a HoneyBadger client share through the VM boundary.
    #[cfg(feature = "honeybadger")]
    pub fn client_share<F>(
        &self,
        client_id: stoffelnet::network_utils::ClientId,
        index: ClientShareIndex,
    ) -> Option<stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare<F>>
    where
        F: ark_ff::FftField,
    {
        self.state.client_share(client_id, index)
    }

    /// Store AVSS Feldman client shares through the VM boundary.
    #[cfg(feature = "avss")]
    pub fn try_store_client_input_feldman<F, G>(
        &self,
        client_id: stoffelnet::network_utils::ClientId,
        shares: Vec<stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare<F, G>>,
    ) -> VirtualMachineResult<usize>
    where
        F: ark_ff::FftField + ark_ff::PrimeField,
        G: ark_ec::CurveGroup<ScalarField = F>,
    {
        Ok(self
            .state
            .try_store_client_input_feldman(client_id, shares)?)
    }

    /// Hydrate client inputs from the configured MPC backend into the VM store.
    pub fn hydrate_from_mpc_engine(
        &self,
    ) -> VirtualMachineResult<crate::net::client_store::ClientInputHydrationCount> {
        Ok(self.state.hydrate_from_mpc_engine()?)
    }

    /// Clear and rehydrate client inputs from the configured MPC backend.
    pub fn refresh_client_inputs(
        &self,
    ) -> VirtualMachineResult<crate::net::client_store::ClientInputHydrationCount> {
        Ok(self.state.refresh_client_inputs()?)
    }

    /// Create a VM share object through the VM table-memory boundary.
    ///
    /// This is the typed API for tests and integrations that need to seed share
    /// objects without depending on the concrete table-memory backend.
    pub fn create_share_object(
        &mut self,
        share_type: ShareType,
        share_data: ShareData,
        party_id: usize,
    ) -> VirtualMachineResult<Value> {
        Ok(self
            .state
            .create_share_object_value(share_type, share_data, party_id)?)
    }

    /// Extract share metadata and payload from a VM share object.
    pub fn read_share_object(
        &mut self,
        value: &Value,
    ) -> VirtualMachineResult<(ShareType, ShareData)> {
        Ok(self.state.extract_share_data(value)?)
    }

    /// Create a VM AVSS share object through the VM table-memory boundary.
    ///
    /// This keeps AVSS setup code independent of the concrete table-memory
    /// backend, which matters for ORAM-style memory implementations where reads
    /// and writes must stay behind VM-owned semantic operations.
    #[cfg(feature = "avss")]
    pub fn create_avss_share_object(
        &mut self,
        key_name: &str,
        share_data: Vec<u8>,
        commitment_bytes: Vec<Vec<u8>>,
        party_id: usize,
    ) -> VirtualMachineResult<Value> {
        Ok(self.state.create_avss_share_object_value(
            key_name,
            share_data,
            commitment_bytes,
            party_id,
        )?)
    }

    /// Check whether a VM value is an AVSS share object.
    #[cfg(feature = "avss")]
    pub fn is_avss_share_object(&mut self, value: &Value) -> bool {
        self.state.is_avss_share_object(value)
    }

    /// Read the key name stored on an AVSS share object.
    #[cfg(feature = "avss")]
    pub fn avss_key_name(&mut self, value: &Value) -> VirtualMachineResult<String> {
        Ok(self.state.avss_key_name(value)?)
    }

    /// Read a serialized commitment from an AVSS share object.
    #[cfg(feature = "avss")]
    pub fn avss_commitment(
        &mut self,
        value: &Value,
        index: usize,
    ) -> VirtualMachineResult<Vec<u8>> {
        Ok(self.state.avss_commitment(value, index)?)
    }

    /// Read the number of commitments stored on an AVSS share object.
    #[cfg(feature = "avss")]
    pub fn avss_commitment_count(&mut self, value: &Value) -> VirtualMachineResult<usize> {
        Ok(self.state.avss_commitment_count(value)?)
    }
}
