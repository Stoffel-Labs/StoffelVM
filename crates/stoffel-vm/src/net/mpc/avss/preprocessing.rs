use super::{AvssExecutionNetwork, AvssMpcEngine};
use crate::net::curve::SupportedMpcField;
use crate::storage::preproc::{
    self, agree_standing_preproc_plan_for_party, apply_standing_preproc_plan,
    standing_preproc_snapshot, OwnedPreprocBundle, PoolAvailability, PreprocBlob, PreprocKeyScope,
};
pub use crate::storage::preproc::{
    agree_standing_preproc_plan, StandingPreprocAction, StandingPreprocPlan,
    StandingPreprocSnapshot,
};
use ark_ec::CurveGroup;
use ark_std::rand::SeedableRng;
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelmpc_mpc::common::PreprocessingMPCProtocol;
use tracing::info;

fn ensure_decoded_count(label: &str, actual: usize, expected: u32) -> Result<(), String> {
    let expected = usize::try_from(expected)
        .map_err(|_| format!("{label} expected count exceeds usize::MAX"))?;
    if actual != expected {
        return Err(format!(
            "{label} decoded {actual} items, expected {expected}"
        ));
    }
    Ok(())
}

impl<F, G> AvssMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    /// Run cooperative preprocessing to generate random shares and Beaver triples.
    ///
    /// If a persistent store is configured, attempts to load from it first.
    /// After generation, persists the result for future runs.
    ///
    /// This clones the inner node so that preprocessing can run concurrently
    /// with the message processing loop (which also needs the node lock for
    /// `process()`). Both clones share `Arc<Mutex<>>` internal state
    /// (preprocessing_material, shares) so results are visible to either.
    pub async fn preprocess(&self) -> Result<(), String> {
        if self.is_standing() {
            return self.preprocess_standing().await;
        }

        if self.try_load_preproc().await? {
            return Ok(());
        }

        {
            let mut node_clone = self.clone_avss_node().await;
            let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
            PreprocessingMPCProtocol::<
                F,
                FeldmanShamirShare<F, G>,
                AvssExecutionNetwork,
            >::run_preprocessing(&mut *node_clone, self.protocol_net.clone(), &mut rng)
            .await
            .map_err(|e| format!("AVSS preprocessing failed: {:?}", e))?;
        }

        self.persist_preproc().await?;
        Ok(())
    }

    async fn preproc_scope(
        &self,
    ) -> Result<
        (
            std::sync::Arc<dyn crate::storage::preproc::PreprocStore>,
            [u8; 32],
            PreprocKeyScope,
        ),
        String,
    > {
        let store = self.preproc_store.read().await.clone();
        let config = *self.preproc_config.read().await;
        let (store, (hash, field_kind)) = match (store, config) {
            (Some(s), Some(c)) => (s, c),
            _ => return Err(
                "standing AVSS preprocessing requires configured preproc store and program hash"
                    .to_owned(),
            ),
        };
        if self.is_standing()
            && !self
                .use_program_preproc_reservoir
                .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(
                "standing execution preprocessing is owned in memory, not persisted".to_owned(),
            );
        }
        let scope = PreprocKeyScope::new(
            hash,
            field_kind,
            self.topology.n_parties(),
            self.topology.threshold(),
            self.local_identity,
        );
        Ok((store, hash, scope))
    }

    /// Exact preprocessing counts configured for this standing engine.
    ///
    /// Callers include these targets in the authenticated party proposal so
    /// mismatched configurations are rejected before an interactive
    /// preprocessing protocol starts.
    pub async fn standing_preproc_targets(&self) -> Result<PoolAvailability, String> {
        let node = self.clone_avss_node().await;
        Ok(PoolAvailability {
            beaver: preproc::u32_index(node.params.n_triples as u64, "AVSS beaver target")?,
            random: preproc::u32_index(node.params.n_v_random_shares as u64, "AVSS random target")?,
            prand_bit: 0,
            prand_int: 0,
        })
    }

    /// Install a destructively allocated reservoir bundle into this
    /// execution's private in-memory preprocessing pool.
    pub async fn activate_preallocated_standing(
        &self,
        bundle: OwnedPreprocBundle,
    ) -> Result<(), String> {
        if !self.is_standing() {
            return Err("preallocated AVSS activation requires standing mode".to_owned());
        }
        if self
            .use_program_preproc_reservoir
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err("an AVSS program reservoir cannot be activated as an execution".to_owned());
        }
        let targets = self.standing_preproc_targets().await?;
        let availability = bundle.availability();
        if availability != targets {
            return Err(format!(
                "preallocated AVSS bundle does not match target: available={availability:?}, target={targets:?}"
            ));
        }
        self.activate_preproc_bundle(bundle).await
    }

    async fn activate_preproc_bundle(&self, bundle: OwnedPreprocBundle) -> Result<(), String> {
        let triples = bundle
            .beaver
            .map(|item| {
                let mut decoded =
                    preproc::deserialize_avss_triples::<F, G>(&item.data, item.item_size, 0)?;
                ensure_decoded_count("preallocated AVSS triples", decoded.len(), item.count)?;
                Self::normalize_multiply_triples(&mut decoded);
                Ok::<_, String>(decoded)
            })
            .transpose()?;
        let random = bundle
            .random
            .map(|item| {
                let decoded =
                    preproc::deserialize_feldman_shares::<F, G>(&item.data, item.item_size, 0)?;
                ensure_decoded_count("preallocated AVSS random shares", decoded.len(), item.count)?;
                Ok::<_, String>(decoded)
            })
            .transpose()?;
        if bundle.prand_bit.is_some() || bundle.prand_int.is_some() {
            return Err("AVSS bundle contains HoneyBadger-only material".to_owned());
        }
        self.clone_avss_node()
            .await
            .preprocessing_material
            .lock()
            .await
            .add(triples, random);
        self.ready.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    pub async fn standing_preproc_snapshot(&self) -> Result<StandingPreprocSnapshot, String> {
        let (store, _hash, scope) = self.preproc_scope().await?;
        standing_preproc_snapshot(store.as_ref(), scope)
            .await
            .map_err(String::from)
    }

    pub async fn install_standing_preproc_plan(
        &self,
        snapshots: Vec<StandingPreprocSnapshot>,
        fresh_generation_id: [u8; 32],
    ) -> Result<StandingPreprocPlan, String> {
        let (store, _hash, scope) = self.preproc_scope().await?;
        let targets = self.standing_preproc_targets().await?;
        let plan = agree_standing_preproc_plan_for_party(
            store.as_ref(),
            scope,
            targets,
            &snapshots,
            self.topology.party_id(),
            self.topology.n_parties(),
            fresh_generation_id,
        )
        .await?;
        *self.standing_preproc_plan.lock().await = Some(plan);
        Ok(plan)
    }

    async fn preprocess_standing(&self) -> Result<(), String> {
        let targets = self.standing_preproc_targets().await?;
        let plan = if self.topology.n_parties() == 1 {
            agree_standing_preproc_plan(
                targets,
                &[self.standing_preproc_snapshot().await?],
                crate::net::session::ExecutionId::new().into_bytes(),
            )?
        } else {
            self.standing_preproc_plan.lock().await.take().ok_or_else(|| {
                "multi-party standing AVSS preprocessing requires a party-agreed inventory plan before protocol startup"
                    .to_owned()
            })?
        };
        let (store, _hash, scope) = self.preproc_scope().await?;
        apply_standing_preproc_plan(store.as_ref(), scope, targets, plan, |needed| {
            self.top_up_exact(needed)
        })
        .await?;
        Ok(())
    }

    async fn top_up_exact(&self, needed: PoolAvailability) -> Result<(), String> {
        if needed == PoolAvailability::default() {
            return Ok(());
        }
        let (store, _hash, scope) = self.preproc_scope().await?;

        let mut node_clone = self.clone_avss_node().await;
        node_clone.params.n_triples = needed.beaver as usize;
        node_clone.params.n_v_random_shares = needed.random as usize;
        let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
        PreprocessingMPCProtocol::<F, FeldmanShamirShare<F, G>, AvssExecutionNetwork>::run_preprocessing(
            &mut *node_clone,
            self.protocol_net.clone(),
            &mut rng,
        )
        .await
        .map_err(|e| format!("AVSS top-up preprocessing failed: {:?}", e))?;

        let mut to_append = Vec::new();
        {
            let mut prep = node_clone.preprocessing_material.lock().await;
            let (n_bt, n_rs) = prep.len();
            if n_bt > 0 {
                let items = prep.take_triples(n_bt).map_err(|e| format!("{e:?}"))?;
                let (data, item_size) = preproc::serialize_avss_triples::<F, G>(&items)?;
                let added = preproc::u32_index(items.len() as u64, "generated AVSS beaver")?;
                to_append.push((scope.beaver_triple(), item_size, added, data));
            }
            if n_rs > 0 {
                let items = prep
                    .take_v_random_shares(n_rs)
                    .map_err(|e| format!("{e:?}"))?;
                let (data, item_size) = preproc::serialize_feldman_shares::<F, G>(&items)?;
                let added = preproc::u32_index(items.len() as u64, "generated AVSS random")?;
                to_append.push((scope.random_share(), item_size, added, data));
            }
        }

        for (key, item_size, added, data) in to_append {
            store.append_items(&key, item_size, added, &data).await?;
        }

        Ok(())
    }

    /// Try to load AVSS preprocessing material from the persistent store.
    async fn try_load_preproc(&self) -> Result<bool, String> {
        let store = self.preproc_store.read().await.clone();
        let config = *self.preproc_config.read().await;
        let (store, (hash, field_kind)) = match (store, config) {
            (Some(store), Some(config)) => (store, config),
            _ => return Ok(false),
        };
        let scope = PreprocKeyScope::new(
            hash,
            field_kind,
            self.topology.n_parties(),
            self.topology.threshold(),
            self.local_identity,
        );
        let requested = store.scope_availability(&scope).await?;
        if requested == PoolAvailability::default() {
            return Ok(false);
        }

        let bundle = store.take_bundle_from_reservoir(&scope, requested).await?;
        self.activate_preproc_bundle(bundle).await?;
        info!(
            "Loaded AVSS preprocessing material from store for program {}",
            hex::encode(hash)
        );
        Ok(true)
    }

    /// Persist current AVSS preprocessing material to the store.
    ///
    /// Drains and serializes inside the lock, then stores after releasing.
    async fn persist_preproc(&self) -> Result<(), String> {
        let store = self.preproc_store.read().await.clone();
        let config = *self.preproc_config.read().await;
        let (store, (hash, field_kind)) = match (store, config) {
            (Some(s), Some(c)) => (s, c),
            _ => return Ok(()),
        };

        let scope = PreprocKeyScope::new(
            hash,
            field_kind,
            self.topology.n_parties(),
            self.topology.threshold(),
            self.local_identity,
        );
        let base = scope.beaver_triple();
        let mut to_store = Vec::new();

        {
            let node = self.clone_avss_node().await;
            let mut prep = node.preprocessing_material.lock().await;
            let (n_bt, n_rs) = prep.len();

            if n_bt > 0 {
                let items = prep.take_triples(n_bt).map_err(|e| format!("{e:?}"))?;
                let (data, item_size) = preproc::serialize_avss_triples::<F, G>(&items)?;
                to_store.push((
                    base.clone(),
                    PreprocBlob::try_new(data, item_size, items.len())?,
                ));
                prep.add(Some(items), None);
            }
            if n_rs > 0 {
                let items = prep
                    .take_v_random_shares(n_rs)
                    .map_err(|e| format!("{e:?}"))?;
                let (data, item_size) = preproc::serialize_feldman_shares::<F, G>(&items)?;
                to_store.push((
                    scope.random_share(),
                    PreprocBlob::try_new(data, item_size, items.len())?,
                ));
                prep.add(None, Some(items));
            }
        }

        for (key, blob) in &to_store {
            store.store(key, blob).await?;
        }

        info!(
            "Persisted AVSS preprocessing material to store for program {}",
            hex::encode(hash)
        );
        Ok(())
    }

    pub(super) async fn reserve_random_shares(
        &self,
        num_shares: usize,
    ) -> Result<Vec<FeldmanShamirShare<F, G>>, String> {
        let node = self.clone_avss_node().await;
        let result = node
            .preprocessing_material
            .lock()
            .await
            .take_v_random_shares(num_shares)
            .map_err(|error| format!("not enough AVSS random shares: {error:?}"));
        result
    }

    /// Reserve the correlated masks distributed to one external input client.
    /// Standing executions remove these shares from LMDB atomically before
    /// handing them to the input server; one-shot executions consume the
    /// engine's in-memory preprocessing material.
    pub async fn reserve_client_input_masks(
        &self,
        num_shares: usize,
    ) -> Result<Vec<FeldmanShamirShare<F, G>>, String> {
        self.reserve_random_shares(num_shares).await
    }
}
