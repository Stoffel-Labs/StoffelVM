use super::AvssMpcEngine;
use crate::net::curve::SupportedMpcField;
use crate::storage::preproc::{self, PreprocBlob, PreprocKeyScope};
use ark_ec::CurveGroup;
use ark_std::rand::SeedableRng;
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelmpc_mpc::common::PreprocessingMPCProtocol;
use stoffelnet::transports::quic::QuicNetworkManager;
use tracing::info;

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
        if self.try_load_preproc().await? {
            return Ok(());
        }

        {
            let mut node_clone = self.clone_avss_node().await;
            let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
            PreprocessingMPCProtocol::<
                F,
                FeldmanShamirShare<F, G>,
                QuicNetworkManager,
            >::run_preprocessing(&mut node_clone, self.net.clone(), &mut rng)
            .await
            .map_err(|e| format!("AVSS preprocessing failed: {:?}", e))?;
        }

        self.persist_preproc().await?;
        Ok(())
    }

    /// Try to load AVSS preprocessing material from the persistent store.
    async fn try_load_preproc(&self) -> Result<bool, String> {
        let store = self.preproc_store.read().await.clone();
        let config = *self.preproc_config.read().await;
        let (store, (hash, field_kind)) = match (store, config) {
            (Some(s), Some(c)) => (s, c),
            _ => return Ok(false),
        };

        let scope = PreprocKeyScope::new(
            hash,
            field_kind,
            self.topology.n_parties(),
            self.topology.threshold(),
            self.topology.party_id(),
        );
        let base = scope.beaver_triple();
        let k_rs = scope.random_share();
        let (triples, randoms) = tokio::try_join!(store.load(&base), store.load(&k_rs),)?;

        if triples.is_none() && randoms.is_none() {
            return Ok(false);
        }

        let node = self.clone_avss_node().await;
        let mut prep = node.preprocessing_material.lock().await;

        if let Some(blob) = triples {
            let decoded = preproc::deserialize_avss_triples::<F, G>(
                blob.unconsumed_data()?,
                blob.meta.item_size,
                0,
            )?;
            prep.add(Some(decoded), None);
        }
        if let Some(blob) = randoms {
            let decoded = preproc::deserialize_feldman_shares::<F, G>(
                blob.unconsumed_data()?,
                blob.meta.item_size,
                0,
            )?;
            prep.add(None, Some(decoded));
        }

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
            self.topology.party_id(),
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
}
