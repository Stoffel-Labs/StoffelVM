use super::HoneyBadgerMpcEngine;
use crate::net::client_store::{
    ClientInputHydrationCount, ClientInputStore, ClientOutputShareCount,
};
use crate::net::curve::SupportedMpcField;
use crate::net::mpc_engine::{
    AsyncMpcEngine, AsyncMpcEngineClientOps, MpcEngine, MpcEngineClientOps, MpcEngineClientOutput,
    MpcEngineError, MpcEngineFieldOpen, MpcEngineMultiplication, MpcEngineOpenInExponent,
    MpcEngineOperationResultExt, MpcEnginePreprocPersistence, MpcEngineRandomness, MpcEngineResult,
    MpcExponentGroup,
};
use crate::storage::preproc::PreprocStore;
use ark_ec::{CurveGroup, PrimeGroup};
use std::any::TypeId;
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

    fn batch_multiply_shares(
        &self,
        ty: ShareType,
        pairs: &[(Vec<u8>, Vec<u8>)],
    ) -> MpcEngineResult<Vec<ShareData>> {
        crate::net::try_block_on_current(self.batch_multiply_share_async(ty, pairs))
            .map_mpc_engine_operation("batch_multiply_shares")
    }

    fn divide_fixed_by_constant(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
        divisor_scaled: i64,
    ) -> MpcEngineResult<ShareData> {
        crate::net::try_block_on_current(self.divide_fixed_by_constant_async(
            ty,
            share_bytes,
            divisor_scaled,
        ))
        .map_mpc_engine_operation("divide_fixed_by_constant")
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

    fn random_integer_share(&self, ty: ShareType) -> MpcEngineResult<ShareData> {
        crate::net::try_block_on_current(self.random_integer_share_async_impl(ty))
            .map_mpc_engine_operation("random_integer_share")
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

    fn supports_exponent_group(&self, group: MpcExponentGroup) -> bool {
        match group {
            MpcExponentGroup::Bls12381G2 => TypeId::of::<F>() == TypeId::of::<ark_bls12_381::Fr>(),
            _ => self.native_exponent_group() == group,
        }
    }

    fn open_share_in_exp_group(
        &self,
        group: MpcExponentGroup,
        ty: ShareType,
        share_bytes: &[u8],
        generator_bytes: &[u8],
    ) -> MpcEngineResult<Vec<u8>> {
        if !self.supports_exponent_group(group) {
            return Err(MpcEngineError::operation_failed(
                "open_share_in_exp_group",
                group.unsupported_error(self.protocol_name()),
            ));
        }

        let result = match group {
            MpcExponentGroup::Bls12381G2 => {
                self.open_share_in_exp_bls12381_g2_impl(share_bytes, generator_bytes)
            }
            _ => self.open_share_in_exp_impl(ty, share_bytes, generator_bytes),
        };

        result.map_mpc_engine_operation("open_share_in_exp_group")
    }

    fn batch_open_shares_in_exp_group(
        &self,
        group: MpcExponentGroup,
        ty: ShareType,
        shares: &[Vec<u8>],
        generator_bytes: &[u8],
    ) -> MpcEngineResult<Vec<Vec<u8>>> {
        if !self.supports_exponent_group(group) {
            return Err(MpcEngineError::operation_failed(
                "batch_open_shares_in_exp_group",
                group.unsupported_error(self.protocol_name()),
            ));
        }

        if group == self.native_exponent_group() {
            let generators = vec![generator_bytes.to_vec(); shares.len()];
            return crate::net::try_block_on_current(
                self.batch_open_shares_in_exp_group_custom_async_impl(
                    group,
                    ty,
                    shares,
                    &generators,
                ),
            )
            .map_mpc_engine_operation("batch_open_shares_in_exp_group");
        }

        shares
            .iter()
            .map(|share| self.open_share_in_exp_group(group, ty, share, generator_bytes))
            .collect()
    }

    fn batch_open_shares_in_exp_group_custom(
        &self,
        group: MpcExponentGroup,
        ty: ShareType,
        shares: &[Vec<u8>],
        generators: &[Vec<u8>],
    ) -> MpcEngineResult<Vec<Vec<u8>>> {
        if shares.len() != generators.len() {
            return Err(MpcEngineError::operation_failed(
                "batch_open_shares_in_exp_group_custom",
                format!(
                    "share/generator length mismatch: {} != {}",
                    shares.len(),
                    generators.len()
                ),
            ));
        }
        if !self.supports_exponent_group(group) {
            return Err(MpcEngineError::operation_failed(
                "batch_open_shares_in_exp_group_custom",
                group.unsupported_error(self.protocol_name()),
            ));
        }

        if group == self.native_exponent_group() {
            return crate::net::try_block_on_current(
                self.batch_open_shares_in_exp_group_custom_async_impl(
                    group, ty, shares, generators,
                ),
            )
            .map_mpc_engine_operation("batch_open_shares_in_exp_group_custom");
        }

        shares
            .iter()
            .zip(generators)
            .map(|(share, generator)| self.open_share_in_exp_group(group, ty, share, generator))
            .collect()
    }
}

impl<F, G> MpcEngineFieldOpen for HoneyBadgerMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    fn open_share_as_field(&self, ty: ShareType, share_bytes: &[u8]) -> MpcEngineResult<Vec<u8>> {
        crate::net::try_block_on_current(self.open_share_as_field_async_impl(ty, share_bytes))
            .map_mpc_engine_operation("open_share_as_field")
    }

    fn batch_open_shares_as_fields(
        &self,
        ty: ShareType,
        shares: &[Vec<u8>],
    ) -> MpcEngineResult<Vec<Vec<u8>>> {
        crate::net::try_block_on_current(self.batch_open_shares_as_fields_async_impl(ty, shares))
            .map_mpc_engine_operation("batch_open_shares_as_fields")
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

    async fn reset_for_next_run(&self, new_instance_id: u64) -> MpcEngineResult<()> {
        self.reset_state_for_next_run(new_instance_id)
            .await
            .map_mpc_engine_operation("reset_for_next_run")
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

    async fn divide_fixed_by_constant_async(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
        divisor_scaled: i64,
    ) -> MpcEngineResult<ShareData> {
        HoneyBadgerMpcEngine::divide_fixed_by_constant_async(self, ty, share_bytes, divisor_scaled)
            .await
            .map_mpc_engine_operation("async_divide_fixed_by_constant")
    }

    async fn batch_multiply_share_async(
        &self,
        ty: ShareType,
        pairs: &[(Vec<u8>, Vec<u8>)],
    ) -> MpcEngineResult<Vec<ShareData>> {
        HoneyBadgerMpcEngine::batch_multiply_share_async(self, ty, pairs)
            .await
            .map_mpc_engine_operation("async_batch_multiply_share")
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

    fn try_random_share_cached(&self, _ty: ShareType) -> Option<MpcEngineResult<ShareData>> {
        self.try_reserve_random_share().map(|share| {
            Self::encode_share(&share)
                .map(|bytes| ShareData::Opaque(bytes.into()))
                .map_mpc_engine_operation("cached_random_share")
        })
    }

    async fn random_integer_share_async(&self, ty: ShareType) -> MpcEngineResult<ShareData> {
        self.random_integer_share_async_impl(ty)
            .await
            .map_mpc_engine_operation("async_random_integer_share")
    }

    async fn open_share_as_field_async(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
    ) -> MpcEngineResult<Vec<u8>> {
        self.open_share_as_field_async_impl(ty, share_bytes)
            .await
            .map_mpc_engine_operation("async_open_share_as_field")
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

    async fn open_share_in_exp_group_async(
        &self,
        group: MpcExponentGroup,
        ty: ShareType,
        share_bytes: &[u8],
        generator_bytes: &[u8],
    ) -> MpcEngineResult<Vec<u8>> {
        if !self.supports_exponent_group(group) {
            return Err(MpcEngineError::operation_failed(
                "async_open_share_in_exp_group",
                group.unsupported_error(self.protocol_name()),
            ));
        }

        let result = match group {
            MpcExponentGroup::Bls12381G2 => {
                self.open_share_in_exp_bls12381_g2_async_impl(share_bytes, generator_bytes)
                    .await
            }
            _ => {
                self.open_share_in_exp_async_impl(ty, share_bytes, generator_bytes)
                    .await
            }
        };

        result.map_mpc_engine_operation("async_open_share_in_exp_group")
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
