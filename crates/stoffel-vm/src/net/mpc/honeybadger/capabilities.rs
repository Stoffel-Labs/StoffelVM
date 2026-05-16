use super::HoneyBadgerMpcEngine;
use crate::net::client_store::{
    ClientInputHydrationCount, ClientInputStore, ClientOutputShareCount,
};
use crate::net::curve::SupportedMpcField;
use crate::net::mpc_engine::{
    AsyncMpcEngine, AsyncMpcEngineClientOps, MpcEngine, MpcEngineClientOps, MpcEngineClientOutput,
    MpcEngineMultiplication, MpcEngineOpenInExponent, MpcEngineOperationResultExt,
    MpcEnginePreprocPersistence, MpcEngineRandomness, MpcEngineResult,
};
use crate::storage::preproc::PreprocStore;
use ark_ec::{CurveGroup, PrimeGroup};
use std::sync::Arc;
use stoffel_vm_types::core_types::{ClearShareInput, ClearShareValue, ShareData, ShareType};
use stoffelnet::network_utils::ClientId;

impl<F, G> MpcEngineMultiplication for HoneyBadgerMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    fn multiply_share(
        &self,
        ty: ShareType,
        left: &[u8],
        right: &[u8],
    ) -> MpcEngineResult<ShareData> {
        crate::net::try_block_on_current(self.multiply_share_async(ty, left, right))
            .map_mpc_engine_operation("multiply_share")
    }
}

impl<F, G> MpcEnginePreprocPersistence for HoneyBadgerMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    fn set_preproc_store(
        &self,
        store: Arc<dyn PreprocStore>,
        program_hash: [u8; 32],
    ) -> MpcEngineResult<()> {
        crate::net::try_block_on_current(async {
            *self.preproc_store.write().await = Some(store);
            *self.program_hash.write().await = Some(program_hash);
            Ok(())
        })
        .map_mpc_engine_operation("set_preproc_store")
    }
}

impl<F, G> MpcEngineRandomness for HoneyBadgerMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    fn random_share(&self, ty: ShareType) -> MpcEngineResult<ShareData> {
        crate::net::try_block_on_current(self.random_share_async_impl(ty))
            .map_mpc_engine_operation("random_share")
    }
}

impl<F, G> MpcEngineOpenInExponent for HoneyBadgerMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    fn open_share_in_exp(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
        generator_bytes: &[u8],
    ) -> MpcEngineResult<Vec<u8>> {
        self.open_share_in_exp_impl(ty, share_bytes, generator_bytes)
            .map_mpc_engine_operation("open_share_in_exp")
    }
}

impl<F, G> MpcEngineClientOutput for HoneyBadgerMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    fn send_output_to_client(
        &self,
        client_id: ClientId,
        shares: &[u8],
        output_share_count: ClientOutputShareCount,
    ) -> MpcEngineResult<()> {
        crate::net::try_block_on_current(self.send_output_to_client_async_impl(
            client_id,
            shares,
            output_share_count,
        ))
        .map_mpc_engine_operation("send_output_to_client")
    }
}

#[async_trait::async_trait]
impl<F, G> AsyncMpcEngine for HoneyBadgerMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    fn as_async_client_ops(&self) -> Option<&dyn AsyncMpcEngineClientOps> {
        Some(self)
    }

    fn as_async_consensus_ops(
        &self,
    ) -> Option<&dyn crate::net::mpc_engine::AsyncMpcEngineConsensus> {
        Some(self)
    }

    async fn input_share_async(&self, clear: ClearShareInput) -> MpcEngineResult<ShareData> {
        self.input_share(clear)
    }

    async fn multiply_share_async(
        &self,
        ty: ShareType,
        left: &[u8],
        right: &[u8],
    ) -> MpcEngineResult<ShareData> {
        self.multiply_share_async(ty, left, right)
            .await
            .map_mpc_engine_operation("async_multiply_share")
    }

    async fn open_share_async(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
    ) -> MpcEngineResult<ClearShareValue> {
        self.open_share_async_impl(ty, share_bytes)
            .await
            .map_mpc_engine_operation("async_open_share")
    }

    async fn batch_open_shares_async(
        &self,
        ty: ShareType,
        shares: &[Vec<u8>],
    ) -> MpcEngineResult<Vec<ClearShareValue>> {
        self.batch_open_shares_async_impl(ty, shares)
            .await
            .map_mpc_engine_operation("async_batch_open_shares")
    }

    async fn send_output_to_client_async(
        &self,
        client_id: ClientId,
        shares: &[u8],
        output_share_count: ClientOutputShareCount,
    ) -> MpcEngineResult<()> {
        self.send_output_to_client_async_impl(client_id, shares, output_share_count)
            .await
            .map_mpc_engine_operation("async_send_output_to_client")
    }

    async fn random_share_async(&self, ty: ShareType) -> MpcEngineResult<ShareData> {
        self.random_share_async_impl(ty)
            .await
            .map_mpc_engine_operation("async_random_share")
    }

    async fn open_share_in_exp_async(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
        generator_bytes: &[u8],
    ) -> MpcEngineResult<Vec<u8>> {
        self.open_share_in_exp_async_impl(ty, share_bytes, generator_bytes)
            .await
            .map_mpc_engine_operation("async_open_share_in_exp")
    }
}

#[async_trait::async_trait]
impl<F, G> AsyncMpcEngineClientOps for HoneyBadgerMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    async fn get_client_ids_async(&self) -> Vec<ClientId> {
        self.get_client_ids().await
    }

    async fn hydrate_client_inputs_async(
        &self,
        store: &ClientInputStore,
    ) -> MpcEngineResult<ClientInputHydrationCount> {
        self.hydrate_client_inputs(store)
            .await
            .map_mpc_engine_operation("hydrate_client_inputs_async")
    }

    async fn hydrate_client_inputs_for_async(
        &self,
        store: &ClientInputStore,
        client_ids: &[ClientId],
    ) -> MpcEngineResult<ClientInputHydrationCount> {
        self.hydrate_client_inputs_for(store, client_ids)
            .await
            .map_mpc_engine_operation("hydrate_client_inputs_for_async")
    }
}

impl<F, G> MpcEngineClientOps for HoneyBadgerMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    fn get_client_ids_sync(&self) -> Vec<ClientId> {
        // Use the async/sync bridging pattern
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                #[allow(deprecated)]
                match handle.runtime_flavor() {
                    tokio::runtime::RuntimeFlavor::MultiThread => {
                        tokio::task::block_in_place(|| handle.block_on(self.get_client_ids()))
                    }
                    _ => Vec::new(), // Cannot block on single-thread runtime
                }
            }
            Err(_) => {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .ok();
                rt.map(|rt| rt.block_on(self.get_client_ids()))
                    .unwrap_or_default()
            }
        }
    }

    fn hydrate_client_inputs_sync(
        &self,
        store: &ClientInputStore,
    ) -> MpcEngineResult<ClientInputHydrationCount> {
        crate::net::try_block_on_current(self.hydrate_client_inputs(store))
            .map_mpc_engine_operation("hydrate_client_inputs_sync")
    }

    fn hydrate_client_inputs_for_sync(
        &self,
        store: &ClientInputStore,
        client_ids: &[ClientId],
    ) -> MpcEngineResult<ClientInputHydrationCount> {
        crate::net::try_block_on_current(self.hydrate_client_inputs_for(store, client_ids))
            .map_mpc_engine_operation("hydrate_client_inputs_for_sync")
    }
}
