use super::AvssMpcEngine;
use crate::net::client_store::{
    ClientInputHydrationCount, ClientInputStore, ClientOutputShareCount,
};
use crate::net::curve::SupportedMpcField;
use ark_ec::CurveGroup;
use ark_serialize::CanonicalDeserialize;
use std::collections::HashMap;
use std::time::Duration;
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelnet::network_utils::ClientId;

impl<F, G> AvssMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    /// Get all client input shares after waiting for them to arrive.
    pub async fn get_all_client_inputs(
        &self,
    ) -> Result<HashMap<ClientId, Vec<FeldmanShamirShare<F, G>>>, String> {
        self.wait_for_inputs().await
    }

    /// Wait for all client inputs to arrive via the InputServer protocol.
    async fn wait_for_inputs(
        &self,
    ) -> Result<HashMap<ClientId, Vec<FeldmanShamirShare<F, G>>>, String> {
        let mut node = self.clone_avss_node().await;
        node.input_server
            .wait_for_all_inputs(Duration::from_secs(30))
            .await
            .map_err(|e| format!("Failed to wait for inputs: {:?}", e))
    }

    /// Get the list of client IDs that have registered inputs.
    pub async fn get_client_ids(&self) -> Vec<ClientId> {
        match self.wait_for_inputs().await {
            Ok(map) => map.keys().copied().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Copy all client input shares into the global ClientInputStore.
    pub async fn hydrate_client_inputs(
        &self,
        store: &ClientInputStore,
    ) -> Result<ClientInputHydrationCount, String> {
        let all_inputs = self.get_all_client_inputs().await?;
        let count = all_inputs.len();
        for (client_id, shares) in all_inputs {
            store
                .try_store_client_input_feldman(client_id, shares)
                .map_err(|error| error.to_string())?;
        }
        Ok(ClientInputHydrationCount::new(count))
    }

    /// Copy specific client input shares into the global ClientInputStore.
    pub async fn hydrate_client_inputs_for(
        &self,
        store: &ClientInputStore,
        client_ids: &[ClientId],
    ) -> Result<ClientInputHydrationCount, String> {
        let all_inputs = self.get_all_client_inputs().await?;
        let mut count = 0;
        for &client_id in client_ids {
            if let Some(shares) = all_inputs.get(&client_id) {
                store
                    .try_store_client_input_feldman(client_id, shares.clone())
                    .map_err(|error| error.to_string())?;
                count += 1;
            } else {
                tracing::warn!("No input shares for client {}", client_id);
            }
        }
        Ok(ClientInputHydrationCount::new(count))
    }

    /// Send output shares to a client for reconstruction.
    pub async fn send_output_to_client_async_impl(
        &self,
        client_id: ClientId,
        shares_bytes: &[u8],
        output_share_count: ClientOutputShareCount,
    ) -> Result<(), String> {
        let input_len = output_share_count.count();

        let shares: Vec<FeldmanShamirShare<F, G>> = if input_len == 1 {
            let single_share: FeldmanShamirShare<F, G> =
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

        let node = self.clone_avss_node().await;
        node.output_server
            .init(client_id, shares, input_len, self.net.clone())
            .await
            .map_err(|e| format!("OutputServer.init failed: {:?}", e))
    }
}
