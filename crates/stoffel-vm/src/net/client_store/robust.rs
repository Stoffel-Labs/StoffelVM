use super::{ClientInputStore, ClientInputStoreError, ClientShare, ClientShareIndex};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use stoffel_vm_types::core_types::{ShareData, ShareType};
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelnet::network_utils::ClientId;

impl ClientInputStore {
    fn robust_client_shares<F>(
        client_id: ClientId,
        shares: Vec<RobustShare<F>>,
        share_type: Option<ShareType>,
    ) -> Result<Vec<ClientShare>, ClientInputStoreError>
    where
        F: ark_ff::FftField,
    {
        shares
            .into_iter()
            .enumerate()
            .map(|(share_index, share)| {
                let share_index = ClientShareIndex::new(share_index);
                let mut bytes = Vec::new();
                share.serialize_compressed(&mut bytes).map_err(|error| {
                    ClientInputStoreError::RobustShareSerialization {
                        client_id,
                        share_index,
                        reason: error.to_string(),
                    }
                })?;

                Ok(match share_type {
                    Some(share_type) => ClientShare::typed(share_type, ShareData::Opaque(bytes)),
                    None => ClientShare::untyped_bytes(bytes),
                })
            })
            .collect()
    }

    /// Store typed robust shares from a client.
    pub fn store_client_input<F>(&self, client_id: ClientId, shares: Vec<RobustShare<F>>)
    where
        F: ark_ff::FftField,
    {
        if let Err(error) = self.try_store_client_input(client_id, shares) {
            tracing::warn!(
                client_id = client_id,
                "Failed to store client input: {}",
                error
            );
        }
    }

    /// Store typed robust shares from a client, returning an error instead of
    /// silently dropping inputs that cannot be serialized.
    pub fn try_store_client_input<F>(
        &self,
        client_id: ClientId,
        shares: Vec<RobustShare<F>>,
    ) -> Result<usize, ClientInputStoreError>
    where
        F: ark_ff::FftField,
    {
        let client_shares = Self::robust_client_shares(client_id, shares, None)?;
        let count = client_shares.len();
        self.store_client_shares(client_id, client_shares);
        Ok(count)
    }

    /// Replace all stored client inputs with robust shares.
    ///
    /// Serialization is completed before the store is mutated, so a failed
    /// input does not leave the VM with a partially hydrated client store.
    pub fn try_replace_client_input<F, I>(&self, inputs: I) -> Result<usize, ClientInputStoreError>
    where
        F: ark_ff::FftField,
        I: IntoIterator<Item = (ClientId, Vec<RobustShare<F>>)>,
    {
        let mut total_shares = 0;
        let mut prepared = Vec::new();

        for (client_id, shares) in inputs {
            let client_shares = Self::robust_client_shares(client_id, shares, None)?;
            total_shares += client_shares.len();
            prepared.push((client_id, client_shares));
        }

        self.replace_client_shares(prepared);
        Ok(total_shares)
    }

    /// Store robust shares with VM-level type metadata.
    pub fn store_client_input_with_type<F>(
        &self,
        client_id: ClientId,
        shares: Vec<RobustShare<F>>,
        share_type: ShareType,
    ) where
        F: ark_ff::FftField,
    {
        if let Err(error) = self.try_store_client_input_with_type(client_id, shares, share_type) {
            tracing::warn!(
                client_id = client_id,
                "Failed to store typed client input: {}",
                error
            );
        }
    }

    /// Store robust shares with VM-level type metadata, returning an error
    /// instead of silently dropping inputs that cannot be serialized.
    pub fn try_store_client_input_with_type<F>(
        &self,
        client_id: ClientId,
        shares: Vec<RobustShare<F>>,
        share_type: ShareType,
    ) -> Result<usize, ClientInputStoreError>
    where
        F: ark_ff::FftField,
    {
        let client_shares = Self::robust_client_shares(client_id, shares, Some(share_type))?;
        let count = client_shares.len();
        self.store_client_shares(client_id, client_shares);
        Ok(count)
    }

    /// Retrieve typed shares for a specific client.
    pub fn get_client_input<F>(&self, client_id: ClientId) -> Option<Vec<RobustShare<F>>>
    where
        F: ark_ff::FftField,
    {
        let share_bytes = self.get_client_input_bytes(client_id)?;
        let mut shares = Vec::with_capacity(share_bytes.len());
        for (i, bytes) in share_bytes.iter().enumerate() {
            match RobustShare::<F>::deserialize_compressed(bytes.as_slice()) {
                Ok(share) => shares.push(share),
                Err(error) => {
                    tracing::warn!(
                        client_id = client_id,
                        share_index = %ClientShareIndex::new(i),
                        "Failed to deserialize RobustShare: {}",
                        error
                    );
                    return None;
                }
            }
        }
        Some(shares)
    }

    /// Retrieve a specific typed share for a client by index.
    pub fn get_client_share<F>(
        &self,
        client_id: ClientId,
        index: ClientShareIndex,
    ) -> Option<RobustShare<F>>
    where
        F: ark_ff::FftField,
    {
        let bytes = self.get_client_share_bytes(client_id, index)?;
        RobustShare::<F>::deserialize_compressed(bytes.as_slice()).ok()
    }
}
