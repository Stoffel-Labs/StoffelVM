use super::{AvssClientOutputRecord, AvssMpcEngine};
use crate::net::client_store::{
    ClientInputHydrationCount, ClientInputStore, ClientOutputShareCount,
};
use crate::net::curve::SupportedMpcField;
use ark_ec::CurveGroup;
use ark_serialize::CanonicalDeserialize;
use std::collections::HashMap;
use std::time::Duration;
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelnet::network_utils::{ClientId, NetworkError};

const OUTPUT_SHARE_LIST_MAGIC: &[u8; 5] = b"VMOS1";

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

        let shares: Vec<FeldmanShamirShare<F, G>> =
            if let Some(shares) = decode_output_share_list(shares_bytes, input_len)? {
                shares
            } else if input_len == 1 {
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

        {
            let mut capture = self.client_output_capture.lock().await;
            if let Some(records) = capture.as_mut() {
                records.push(AvssClientOutputRecord { client_id, shares });
                return Ok(());
            }
        }

        let transport_client_id = self.client_output_transport_id(client_id).await?;
        let node = self.clone_avss_node().await;
        match node
            .output_server
            .init(
                transport_client_id,
                shares,
                input_len,
                self.protocol_net.clone(),
            )
            .await
        {
            Ok(()) => Ok(()),
            Err(stoffelmpc_mpc::avss_mpc::output::AvssOutputError::NetworkError(
                error @ (NetworkError::SendError | NetworkError::ClientNotFound(_)),
            )) => {
                // Threshold reconstruction lets the client leave before every
                // honest party's send completes. Do not turn that expected
                // client churn into a divergent node execution result.
                tracing::warn!(
                    client_id,
                    transport_client_id,
                    ?error,
                    "AVSS client output share could not be delivered"
                );
                Ok(())
            }
            Err(stoffelmpc_mpc::avss_mpc::output::AvssOutputError::NetworkError(error)) => {
                Err(format!("OutputServer.init network failure: {error}"))
            }
            Err(error) => Err(format!("OutputServer.init failed: {error:?}")),
        }
    }
}

fn decode_output_share_list<F, G>(
    payload: &[u8],
    expected_count: usize,
) -> Result<Option<Vec<FeldmanShamirShare<F, G>>>, String>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F>,
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
        let share = FeldmanShamirShare::<F, G>::deserialize_compressed(&payload[offset..end])
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
