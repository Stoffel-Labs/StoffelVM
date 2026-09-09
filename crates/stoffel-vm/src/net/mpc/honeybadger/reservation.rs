use super::HoneyBadgerMpcEngine;
use crate::net::curve::SupportedMpcField;
use crate::net::mpc_engine::{MpcEngineOperationResultExt, MpcEngineReservation, MpcEngineResult};
use crate::net::reservation::{ReservationGrant, ReservationRegistry};
use crate::storage::preproc::{self, PoolAvailability};
use ark_ec::{CurveGroup, PrimeGroup};
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelnet::network_utils::ClientId;

impl<F, G> HoneyBadgerMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    async fn persist_reservation_state_if_configured(&self) -> Result<(), String> {
        // Standing executions are intentionally not resumable: their owned
        // preprocessing bundle is burned on process death. Persisting logical
        // mask cursors would create state that cannot safely be resumed.
        if self.is_standing() {
            return Ok(());
        }
        let reg_guard = self.reservation.read().await;
        let Some(reg) = reg_guard.as_ref() else {
            return Ok(());
        };
        let store = self.preproc_store.read().await.clone();
        if let Some(store) = store {
            reg.persist(store.as_ref())
                .await
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

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
        self.init_reservations_for_run(program_hash, capacity, 0, PoolAvailability::default())
            .await
    }

    async fn init_reservations_for_run(
        &self,
        program_hash: [u8; 32],
        capacity: u64,
        run_id: u64,
        preproc_offset: PoolAvailability,
    ) -> MpcEngineResult<()> {
        async {
            let persistent_identity = self.persistent_identity();
            if self.is_standing() {
                *self.reservation.write().await = Some(ReservationRegistry::new_for_run(
                    program_hash,
                    persistent_identity,
                    capacity,
                    run_id,
                    PoolAvailability::default(),
                ));
                return Ok::<(), String>(());
            }

            let store = self.preproc_store.read().await.clone();
            if let Some(store) = store {
                if let Some(restored) = ReservationRegistry::load_for_run(
                    store.as_ref(),
                    &program_hash,
                    persistent_identity,
                    run_id,
                )
                .await
                .map_err(|e| e.to_string())?
                {
                    if !restored.is_fully_consumed().await {
                        *self.reservation.write().await = Some(restored);
                        return Ok::<(), String>(());
                    }
                }
            }
            *self.reservation.write().await = Some(ReservationRegistry::new_for_run(
                program_hash,
                persistent_identity,
                capacity,
                run_id,
                preproc_offset,
            ));
            self.persist_reservation_state_if_configured().await?;
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
            // Serializes logical allocation with destructive LMDB removal so
            // concurrent requests cannot disagree about index-to-share mapping.
            let mut standing_masks = if self.is_standing() {
                Some(self.reserved_mask_shares.lock().await)
            } else {
                None
            };
            let guard = self.reservation.read().await;
            let reg = guard.as_ref().ok_or("reservations not initialized")?;
            let grant = reg
                .reserve(self.client_identity(client_id).await?, n)
                .await
                .map_err(|e| e.to_string())?;
            drop(guard);

            if let Some(cache) = standing_masks.as_mut() {
                let count = usize::try_from(n)
                    .map_err(|_| format!("standing reserved mask count {n} exceeds usize range"))?;
                let shares = self.reserve_random_shares(count).await?;
                if shares.len() != count {
                    return Err(format!(
                        "standing reserved mask decode returned {} shares, expected {n}",
                        shares.len()
                    ));
                }
                for (index, share) in grant.indices().zip(shares.iter()) {
                    cache.insert(index, Self::encode_share(share)?);
                }
            }
            self.persist_reservation_state_if_configured().await?;
            Ok::<ReservationGrant, String>(grant)
        }
        .await
        .map_mpc_engine_operation("reserve_masks")
    }

    async fn get_mask_share(&self, index: u64) -> MpcEngineResult<Vec<u8>> {
        async {
            if self.is_standing() {
                return self
                    .reserved_mask_shares
                    .lock()
                    .await
                    .get(&index)
                    .cloned()
                    .ok_or_else(|| {
                        format!("standing mask index {index} was not reserved before retrieval")
                    });
            }
            let (store, _hash, scope) = self.preproc_scope().await?;
            let key = scope.random_share();
            let blob = store.load(&key).await?.ok_or("no random shares stored")?;
            let preproc_offset = {
                let guard = self.reservation.read().await;
                let offset = guard
                    .as_ref()
                    .map(|reg| reg.preproc_offset())
                    .ok_or("reservations not initialized")?
                    .await;
                offset
            };
            let physical = index
                .checked_add(u64::from(preproc_offset.random))
                .ok_or_else(|| "preprocessing random share physical index overflow".to_owned())?;
            let index = preproc::u32_index(physical, "preprocessing random share index")?;
            store.reserve_at(&key, index, 1).await?;
            let share =
                preproc::deserialize_one_robust_share::<F>(&blob.data, blob.meta.item_size, index)?;
            Self::encode_share(&share)
        }
        .await
        .map_mpc_engine_operation("get_mask_share")
    }

    async fn get_mask_shares(&self, indices: &[u64]) -> MpcEngineResult<Vec<Vec<u8>>> {
        async {
            if indices.is_empty() {
                return Ok(Vec::new());
            }
            if self.is_standing() {
                let cache = self.reserved_mask_shares.lock().await;
                return indices
                    .iter()
                    .map(|index| {
                        cache.get(index).cloned().ok_or_else(|| {
                            format!("standing mask index {index} was not reserved before retrieval")
                        })
                    })
                    .collect();
            }

            // A reservation grant is consecutive, and the runner requests all
            // grants in sorted order. Consume that complete range with one LMDB
            // cursor update and one blob load. Retain the scalar fallback for
            // compatibility with sparse/custom callers.
            let consecutive = indices
                .windows(2)
                .all(|window| window[0].checked_add(1) == Some(window[1]));
            if !consecutive {
                let mut shares = Vec::with_capacity(indices.len());
                for &index in indices {
                    shares.push(self.get_mask_share(index).await?);
                }
                return Ok(shares);
            }

            let (store, _hash, scope) = self.preproc_scope().await?;
            let key = scope.random_share();
            let blob = store.load(&key).await?.ok_or("no random shares stored")?;
            let preproc_offset = {
                let guard = self.reservation.read().await;
                guard
                    .as_ref()
                    .ok_or("reservations not initialized")?
                    .preproc_offset()
                    .await
            };
            let physical_start = indices[0]
                .checked_add(u64::from(preproc_offset.random))
                .ok_or_else(|| "preprocessing random share physical index overflow".to_owned())?;
            let physical_start =
                preproc::u32_index(physical_start, "preprocessing random share index")?;
            let count = u32::try_from(indices.len())
                .map_err(|_| "mask share batch length exceeds u32 range".to_owned())?;
            store.reserve_at(&key, physical_start, count).await?;

            let mut shares = Vec::with_capacity(indices.len());
            for offset in 0..count {
                let index = physical_start
                    .checked_add(offset)
                    .ok_or_else(|| "preprocessing random share batch index overflow".to_owned())?;
                let share = preproc::deserialize_one_robust_share::<F>(
                    &blob.data,
                    blob.meta.item_size,
                    index,
                )?;
                shares.push(Self::encode_share(&share)?);
            }
            Ok::<Vec<Vec<u8>>, String>(shares)
        }
        .await
        .map_mpc_engine_operation("get_mask_shares")
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
            reg.submit_masked_input(self.client_identity(client_id).await?, index, value)
                .await
                .map_err(|e| e.to_string())?;
            drop(guard);
            self.persist_reservation_state_if_configured().await
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

            let standing_masks = if self.is_standing() {
                Some(self.reserved_mask_shares.lock().await)
            } else {
                None
            };
            let persistent = if standing_masks.is_none() {
                let (store, _hash, scope) = self.preproc_scope().await?;
                let key = scope.random_share();
                let blob = store.load(&key).await?.ok_or("no random shares stored")?;
                let offset = {
                    let reg_guard = self.reservation.read().await;
                    reg_guard
                        .as_ref()
                        .ok_or("reservations not initialized")?
                        .preproc_offset()
                        .await
                };
                Some((store, key, blob, offset))
            } else {
                None
            };

            let mut result = Vec::with_capacity(indices.len());
            for (idx, masked_input_bytes) in &masked_inputs {
                let mask_share = if let Some(standing_masks) = standing_masks.as_ref() {
                    let bytes = standing_masks
                        .get(idx)
                        .ok_or_else(|| format!("no destructively reserved mask for index {idx}"))?;
                    Self::decode_share(bytes)?
                } else {
                    let (_, _, blob, preproc_offset) = persistent
                        .as_ref()
                        .ok_or("missing one-shot preprocessing state")?;
                    let physical = idx
                        .checked_add(u64::from(preproc_offset.random))
                        .ok_or_else(|| {
                            "preprocessing masked input physical index overflow".to_owned()
                        })?;
                    let mask_index =
                        preproc::u32_index(physical, "preprocessing masked input index")?;
                    preproc::deserialize_one_robust_share::<F>(
                        &blob.data,
                        blob.meta.item_size,
                        mask_index,
                    )?
                };
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
            if let Some(mut standing_masks) = standing_masks {
                for index in indices {
                    standing_masks.remove(index);
                }
            }
            self.persist_reservation_state_if_configured().await?;
            let all_reserved_slots_consumed = {
                let reg_guard = self.reservation.read().await;
                let reg = reg_guard.as_ref().ok_or("reservations not initialized")?;
                reg.all_reserved_slots_consumed().await
            };
            // Keep the mask blob while any allocated slot may still need it for unmasking.
            if let Some((store, key, _, _)) = persistent {
                if all_reserved_slots_consumed && store.available(&key).await? == 0 {
                    store.delete(&key).await?;
                }
            }
            Ok::<Vec<(u64, Vec<u8>)>, String>(result)
        }
        .await
        .map_mpc_engine_operation("consume_masked_inputs")
    }

    async fn retire_masks(&self, indices: &[u64]) -> MpcEngineResult<()> {
        async {
            {
                let reg_guard = self.reservation.read().await;
                let reg = reg_guard.as_ref().ok_or("reservations not initialized")?;
                reg.consume(indices).await.map_err(|e| e.to_string())?;
            }
            self.persist_reservation_state_if_configured().await?;
            let mut standing_masks = self.reserved_mask_shares.lock().await;
            for index in indices {
                standing_masks.remove(index);
            }
            Ok::<(), String>(())
        }
        .await
        .map_mpc_engine_operation("retire_masks")
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
