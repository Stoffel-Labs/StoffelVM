use super::HoneyBadgerMpcEngine;
use crate::net::client_store::{
    ClientInputHydrationCount, ClientInputStore, ClientOutputShareCount,
};
use crate::net::curve::SupportedMpcField;
use crate::net::mpc_engine::MpcEngine;
use ark_ec::{CurveGroup, PrimeGroup};
use ark_serialize::CanonicalDeserialize;
use std::time::Duration;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelnet::network_utils::ClientId;

impl<F, G> HoneyBadgerMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    /// Initialize input shares from a client. This must be called after preprocessing.
    /// The client provides shares for all parties, and each party stores its own share.
    pub async fn init_client_input(
        &self,
        client_id: ClientId,
        shares: Vec<RobustShare<F>>,
    ) -> Result<(), String> {
        if !self.is_ready() {
            return Err("MPC engine not ready".into());
        }

        let num_shares = shares.len();
        let local_shares = self
            .reserve_random_shares(num_shares)
            .await
            .map_err(|e| format!("Failed to take random shares: {}", e))?;

        let mut node = self.clone_node().await;
        node.preprocess
            .input
            .init(client_id, local_shares, num_shares, self.net.clone())
            .await
            .map_err(|e| format!("Failed to initialize client input: {:?}", e))?;

        Ok(())
    }

    /// Get the shares for a specific client after input initialization.
    ///
    /// Note: this waits for all inputs before returning.
    pub async fn get_client_shares(
        &self,
        client_id: ClientId,
    ) -> Result<Vec<RobustShare<F>>, String> {
        let all_inputs = self.wait_for_inputs().await?;
        all_inputs
            .get(&client_id)
            .cloned()
            .ok_or_else(|| format!("No shares found for client {}", client_id))
    }

    /// Get all client IDs that have submitted inputs to this HB node.
    ///
    /// Note: this waits for all inputs before returning.
    pub async fn get_client_ids(&self) -> Vec<ClientId> {
        match self.wait_for_inputs().await {
            Ok(inputs) => inputs.keys().copied().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Get all client inputs from the HB node's input store.
    ///
    /// Note: this waits for all inputs before returning.
    pub async fn get_all_client_inputs(
        &self,
    ) -> Result<Vec<(ClientId, Vec<RobustShare<F>>)>, String> {
        Ok(self.wait_for_inputs().await?.into_iter().collect())
    }

    async fn wait_for_inputs(
        &self,
    ) -> Result<std::collections::HashMap<ClientId, Vec<RobustShare<F>>>, String> {
        let mut node = self.clone_node().await;
        node.preprocess
            .input
            .wait_for_all_inputs(Duration::from_secs(30))
            .await
            .map_err(|e| format!("Failed to wait for inputs: {:?}", e))
    }

    /// Hydrate a ClientInputStore with all client inputs from the HB node.
    pub async fn hydrate_client_inputs(
        &self,
        store: &ClientInputStore,
    ) -> Result<ClientInputHydrationCount, String> {
        let all_inputs = self.get_all_client_inputs().await?;
        let count = all_inputs.len();

        for (client_id, shares) in all_inputs {
            store
                .try_store_client_input(client_id, shares)
                .map_err(|error| error.to_string())?;
        }

        Ok(ClientInputHydrationCount::new(count))
    }

    /// Hydrate a ClientInputStore with inputs from specific clients.
    pub async fn hydrate_client_inputs_for(
        &self,
        store: &ClientInputStore,
        client_ids: &[ClientId],
    ) -> Result<ClientInputHydrationCount, String> {
        let mut count = 0;
        for &client_id in client_ids {
            match self.get_client_shares(client_id).await {
                Ok(shares) => {
                    store
                        .try_store_client_input(client_id, shares)
                        .map_err(|error| error.to_string())?;
                    count += 1;
                }
                Err(error) => {
                    tracing::warn!("Failed to get shares for client {}: {}", client_id, error);
                }
            }
        }
        Ok(ClientInputHydrationCount::new(count))
    }

    /// Send output share(s) to a specific client using the OutputServer protocol.
    ///
    /// This is used for private output where only the designated client can
    /// reconstruct the result by collecting shares from all parties.
    pub async fn send_output_to_client_async_impl(
        &self,
        client_id: ClientId,
        shares_bytes: &[u8],
        output_share_count: ClientOutputShareCount,
    ) -> Result<(), String> {
        let input_len = output_share_count.count();

        let shares: Vec<RobustShare<F>> = if input_len == 1 {
            let single_share: RobustShare<F> =
                CanonicalDeserialize::deserialize_compressed(shares_bytes)
                    .map_err(|e| format!("Failed to deserialize single share: {:?}", e))?;
            vec![single_share]
        } else {
            CanonicalDeserialize::deserialize_compressed(shares_bytes)
                .map_err(|e| format!("Failed to deserialize shares: {:?}", e))?
        };

        if shares.len() != input_len {
            return Err(format!(
                "Share count mismatch: got {}, expected {}",
                shares.len(),
                input_len
            ));
        }

        let node = self.clone_node().await;
        node.output
            .init(client_id, shares, input_len, self.net.clone())
            .await
            .map_err(|e| format!("OutputServer.init failed: {:?}", e))
    }
}
