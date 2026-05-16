use super::HoneyBadgerMpcEngine;
use crate::net::curve::SupportedMpcField;
use crate::net::mpc_engine::{MpcEngineOperationResultExt, MpcEngineReservation, MpcEngineResult};
use crate::net::reservation::{ReservationGrant, ReservationRegistry};
use crate::storage::preproc::{self, PreprocKeyScope};
use ark_ec::{CurveGroup, PrimeGroup};
use std::sync::atomic::Ordering;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelnet::network_utils::ClientId;

#[async_trait::async_trait]
impl<F, G> MpcEngineReservation for HoneyBadgerMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    async fn init_reservations(
        &self,
        program_hash: [u8; 32],
        capacity: u64,
    ) -> MpcEngineResult<()> {
        async {
            let store = self.preproc_store.read().await.clone();
            let persistent_party_id = self.persistent_party_id.load(Ordering::SeqCst);
            if let Some(store) = store {
                if let Some(restored) =
                    ReservationRegistry::load(store.as_ref(), &program_hash, persistent_party_id)
                        .await
                        .map_err(|e| e.to_string())?
                {
                    *self.reservation.write().await = Some(restored);
                    return Ok::<(), String>(());
                }
            }
            *self.reservation.write().await = Some(ReservationRegistry::new(
                program_hash,
                persistent_party_id,
                capacity,
            ));
            Ok::<(), String>(())
        }
        .await
        .map_mpc_engine_operation("init_reservations")
    }

    async fn reserve_masks(
        &self,
        client_id: ClientId,
        n: u64,
    ) -> MpcEngineResult<ReservationGrant> {
        async {
            let guard = self.reservation.read().await;
            let reg = guard.as_ref().ok_or("reservations not initialized")?;
            reg.reserve(client_id, n).await.map_err(|e| e.to_string())
        }
        .await
        .map_mpc_engine_operation("reserve_masks")
    }

    async fn get_mask_share(&self, index: u64) -> MpcEngineResult<Vec<u8>> {
        async {
            let store = self.preproc_store.read().await.clone();
            let hash = *self.program_hash.read().await;
            let persistent_party_id = self.persistent_party_id.load(Ordering::SeqCst);
            let (store, hash) = match (store, hash) {
                (Some(s), Some(h)) => (s, h),
                _ => return Err::<Vec<u8>, String>("preproc store not configured".to_owned()),
            };

            let key = PreprocKeyScope::new(
                hash,
                F::field_kind(),
                self.topology.n_parties(),
                self.topology.threshold(),
                persistent_party_id,
            )
            .random_share();
            let blob = store.load(&key).await?.ok_or("no random shares stored")?;
            let index = preproc::u32_index(index, "preprocessing random share index")?;
            let share =
                preproc::deserialize_one_robust_share::<F>(&blob.data, blob.meta.item_size, index)?;
            Self::encode_share(&share)
        }
        .await
        .map_mpc_engine_operation("get_mask_share")
    }

    async fn submit_masked_input(
        &self,
        client_id: ClientId,
        index: u64,
        value: Vec<u8>,
    ) -> MpcEngineResult<()> {
        async {
            let guard = self.reservation.read().await;
            let reg = guard.as_ref().ok_or("reservations not initialized")?;
            reg.submit_masked_input(client_id, index, value)
                .await
                .map_err(|e| e.to_string())
        }
        .await
        .map_mpc_engine_operation("submit_masked_input")
    }

    async fn consume_masked_inputs(&self, indices: &[u64]) -> MpcEngineResult<Vec<(u64, Vec<u8>)>> {
        async {
            let masked_inputs = {
                let reg_guard = self.reservation.read().await;
                let reg = reg_guard.as_ref().ok_or("reservations not initialized")?;
                let mut inputs = Vec::with_capacity(indices.len());
                for &idx in indices {
                    let masked_input = reg
                        .get_masked_input(idx)
                        .await
                        .ok_or_else(|| format!("no masked input for index {idx}"))?;
                    inputs.push((idx, masked_input));
                }
                inputs
            };

            let store = self.preproc_store.read().await.clone();
            let hash = *self.program_hash.read().await;
            let persistent_party_id = self.persistent_party_id.load(Ordering::SeqCst);
            let (store, hash) = match (store, hash) {
                (Some(s), Some(h)) => (s, h),
                _ => {
                    return Err::<Vec<(u64, Vec<u8>)>, String>(
                        "preproc store not configured".to_owned(),
                    );
                }
            };
            let key = PreprocKeyScope::new(
                hash,
                F::field_kind(),
                self.topology.n_parties(),
                self.topology.threshold(),
                persistent_party_id,
            )
            .random_share();
            let blob = store.load(&key).await?.ok_or("no random shares stored")?;

            let mut result = Vec::with_capacity(indices.len());
            for (idx, masked_input_bytes) in &masked_inputs {
                let mask_index = preproc::u32_index(*idx, "preprocessing masked input index")?;
                let mask_share = preproc::deserialize_one_robust_share::<F>(
                    &blob.data,
                    blob.meta.item_size,
                    mask_index,
                )?;
                let masked_input = Self::decode_share(masked_input_bytes)?;

                let input_elem = masked_input.share[0] - mask_share.share[0];
                let input_share = RobustShare::new(input_elem, mask_share.id, mask_share.degree);
                result.push((*idx, Self::encode_share(&input_share)?));
            }

            {
                let reg_guard = self.reservation.read().await;
                let reg = reg_guard.as_ref().ok_or("reservations not initialized")?;
                reg.consume(indices).await.map_err(|e| e.to_string())?;
            }
            Ok::<Vec<(u64, Vec<u8>)>, String>(result)
        }
        .await
        .map_mpc_engine_operation("consume_masked_inputs")
    }

    async fn available_masks(&self) -> u64 {
        let guard = self.reservation.read().await;
        match guard.as_ref() {
            Some(reg) => reg.available().await,
            None => 0,
        }
    }

    async fn persist_reservations(&self) -> MpcEngineResult<()> {
        async {
            let reg_guard = self.reservation.read().await;
            let reg = match reg_guard.as_ref() {
                Some(r) => r,
                None => return Ok::<(), String>(()),
            };
            let store = self.preproc_store.read().await.clone();
            if let Some(store) = store {
                reg.persist(store.as_ref())
                    .await
                    .map_err(|e| e.to_string())?;
            }
            Ok::<(), String>(())
        }
        .await
        .map_mpc_engine_operation("persist_reservations")
    }
}
