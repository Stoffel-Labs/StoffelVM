use super::{HoneyBadgerClientOutputRecord, HoneyBadgerMpcEngine};
use crate::net::client_store::{
    ClientInputHydrationCount, ClientInputStore, ClientOutputShareCount,
};
use crate::net::curve::SupportedMpcField;
use crate::net::mpc_engine::MpcEngine;
use ark_ec::{CurveGroup, PrimeGroup};
use ark_serialize::CanonicalDeserialize;
use std::time::Duration;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelnet::network_utils::{ClientId, NetworkError};

const OUTPUT_SHARE_LIST_MAGIC: &[u8; 5] = b"VMOS1";

impl<F, G> HoneyBadgerMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    /// Reserve the correlated random shares used to initialize one direct
    /// client's input masks. Standing engines allocate atomically from their
    /// execution-scoped LMDB lane; ephemeral engines consume the in-memory
    /// preprocessing pool.
    pub async fn reserve_client_input_masks(
        &self,
        num_shares: usize,
    ) -> Result<Vec<RobustShare<F>>, String> {
        self.reserve_random_shares(num_shares).await
    }

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
            .reserve_client_input_masks(num_shares)
            .await
            .map_err(|e| format!("Failed to take random shares: {}", e))?;

        let mut node = self.clone_node().await;
        node.preprocess
            .input
            .init(
                client_id,
                local_shares,
                num_shares,
                self.protocol_net.clone(),
            )
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

        let shares: Vec<RobustShare<F>> =
            if let Some(shares) = decode_output_share_list(shares_bytes, input_len)? {
                shares
            } else if input_len == 1 {
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

        {
            let mut capture = self.client_output_capture.lock().await;
            if let Some(records) = capture.as_mut() {
                records.push(HoneyBadgerClientOutputRecord { client_id, shares });
                return Ok(());
            }
        }

        let transport_client_id = self.client_output_transport_id(client_id).await?;
        let node = self.clone_node().await;
        match node
            .output
            .init(
                transport_client_id,
                shares,
                input_len,
                self.protocol_net.clone(),
            )
            .await
        {
            Ok(()) => Ok(()),
            Err(stoffelmpc_mpc::honeybadger::output::OutputError::NetworkError(
                error @ (NetworkError::SendError | NetworkError::ClientNotFound(_)),
            )) => {
                // A threshold client legitimately disconnects after collecting
                // enough valid output shares. A slower party can therefore see
                // a closed connection even though the output was delivered and
                // the MPC transcript completed. Treat delivery loss as local
                // availability, not as a failure of the shared execution.
                tracing::warn!(
                    client_id,
                    transport_client_id,
                    ?error,
                    "client output share could not be delivered"
                );
                Ok(())
            }
            Err(stoffelmpc_mpc::honeybadger::output::OutputError::NetworkError(error)) => {
                Err(format!("OutputServer.init network failure: {error}"))
            }
            Err(error) => Err(format!("OutputServer.init failed: {error:?}")),
        }
    }
}

fn decode_output_share_list<F>(
    payload: &[u8],
    expected_count: usize,
) -> Result<Option<Vec<RobustShare<F>>>, String>
where
    F: SupportedMpcField,
{
    if !payload.starts_with(OUTPUT_SHARE_LIST_MAGIC) {
        return Ok(None);
    }

    let mut offset = OUTPUT_SHARE_LIST_MAGIC.len();
    let count = read_u32(payload, &mut offset)? as usize;
    if count != expected_count {
        return Err(format!(
            "Output share count mismatch: envelope has {}, expected {}",
            count, expected_count
        ));
    }

    let mut shares = Vec::with_capacity(count);
    for index in 0..count {
        let len = read_u32(payload, &mut offset)? as usize;
        let end = offset
            .checked_add(len)
            .ok_or_else(|| "Output share envelope length overflow".to_owned())?;
        if end > payload.len() {
            return Err(format!(
                "Output share envelope truncated at share {}",
                index
            ));
        }
        let share = RobustShare::<F>::deserialize_compressed(&payload[offset..end])
            .map_err(|e| format!("Failed to deserialize output share {}: {:?}", index, e))?;
        shares.push(share);
        offset = end;
    }

    if offset != payload.len() {
        return Err("Output share envelope has trailing bytes".to_owned());
    }

    Ok(Some(shares))
}

fn read_u32(payload: &[u8], offset: &mut usize) -> Result<u32, String> {
    let end = offset
        .checked_add(std::mem::size_of::<u32>())
        .ok_or_else(|| "Output share envelope offset overflow".to_owned())?;
    let bytes = payload
        .get(*offset..end)
        .ok_or_else(|| "Output share envelope is truncated".to_owned())?;
    *offset = end;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}
