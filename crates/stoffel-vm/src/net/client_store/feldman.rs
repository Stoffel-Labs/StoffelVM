use super::{ClientInputStore, ClientInputStoreError, ClientShare, ClientShareIndex};
use ark_ec::CurveGroup;
use ark_ff::{FftField, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use stoffel_vm_types::core_types::{ShareData, ShareType};
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelnet::network_utils::ClientId;

impl ClientInputStore {
    /// Store typed Feldman shares from a client (AVSS backend).
    pub fn store_client_input_feldman<F, G>(
        &self,
        client_id: ClientId,
        shares: Vec<FeldmanShamirShare<F, G>>,
    ) where
        F: FftField + PrimeField,
        G: CurveGroup<ScalarField = F>,
    {
        if let Err(error) = self.try_store_client_input_feldman(client_id, shares) {
            tracing::warn!(
                client_id = client_id,
                "Failed to store Feldman client input: {}",
                error
            );
        }
    }

    /// Store Feldman shares from a client, returning an error instead of
    /// silently dropping inputs or losing commitment metadata.
    pub fn try_store_client_input_feldman<F, G>(
        &self,
        client_id: ClientId,
        shares: Vec<FeldmanShamirShare<F, G>>,
    ) -> Result<usize, ClientInputStoreError>
    where
        F: FftField + PrimeField,
        G: CurveGroup<ScalarField = F>,
    {
        let client_shares = feldman_client_shares(client_id, shares, None)?;
        let count = client_shares.len();
        self.store_client_shares(client_id, client_shares);
        Ok(count)
    }

    /// Store typed Feldman shares from a client (AVSS backend).
    pub fn store_client_input_feldman_with_type<F, G>(
        &self,
        client_id: ClientId,
        shares: Vec<FeldmanShamirShare<F, G>>,
        share_type: ShareType,
    ) where
        F: FftField + PrimeField,
        G: CurveGroup<ScalarField = F>,
    {
        if let Err(error) =
            self.try_store_client_input_feldman_with_type(client_id, shares, share_type)
        {
            tracing::warn!(
                client_id = client_id,
                "Failed to store typed Feldman client input: {}",
                error
            );
        }
    }

    /// Store typed Feldman shares from a client, returning an error instead of
    /// silently dropping inputs or losing commitment metadata.
    pub fn try_store_client_input_feldman_with_type<F, G>(
        &self,
        client_id: ClientId,
        shares: Vec<FeldmanShamirShare<F, G>>,
        share_type: ShareType,
    ) -> Result<usize, ClientInputStoreError>
    where
        F: FftField + PrimeField,
        G: CurveGroup<ScalarField = F>,
    {
        let client_shares = feldman_client_shares(client_id, shares, Some(share_type))?;
        let count = client_shares.len();
        self.store_client_shares(client_id, client_shares);
        Ok(count)
    }

    /// Retrieve typed Feldman shares for a specific client (AVSS backend).
    pub fn get_client_input_feldman<F, G>(
        &self,
        client_id: ClientId,
    ) -> Option<Vec<FeldmanShamirShare<F, G>>>
    where
        F: FftField + PrimeField,
        G: CurveGroup<ScalarField = F>,
    {
        let share_bytes = self.get_client_input_bytes(client_id)?;
        let mut shares = Vec::with_capacity(share_bytes.len());
        for (i, bytes) in share_bytes.iter().enumerate() {
            match FeldmanShamirShare::<F, G>::deserialize_compressed(bytes.as_slice()) {
                Ok(share) => shares.push(share),
                Err(error) => {
                    tracing::warn!(
                        client_id = client_id,
                        share_index = %ClientShareIndex::new(i),
                        "Failed to deserialize FeldmanShamirShare: {}",
                        error
                    );
                    return None;
                }
            }
        }
        Some(shares)
    }

    /// Retrieve a specific typed Feldman share for a client by index (AVSS backend).
    pub fn get_client_share_feldman<F, G>(
        &self,
        client_id: ClientId,
        index: ClientShareIndex,
    ) -> Option<FeldmanShamirShare<F, G>>
    where
        F: FftField + PrimeField,
        G: CurveGroup<ScalarField = F>,
    {
        let bytes = self.get_client_share_bytes(client_id, index)?;
        FeldmanShamirShare::<F, G>::deserialize_compressed(bytes.as_slice()).ok()
    }
}

fn feldman_client_shares<F, G>(
    client_id: ClientId,
    shares: Vec<FeldmanShamirShare<F, G>>,
    share_type: Option<ShareType>,
) -> Result<Vec<ClientShare>, ClientInputStoreError>
where
    F: FftField + PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    shares
        .into_iter()
        .enumerate()
        .map(|(share_index, share)| {
            let share_index = ClientShareIndex::new(share_index);
            let mut bytes = Vec::new();
            share.serialize_compressed(&mut bytes).map_err(|error| {
                ClientInputStoreError::FeldmanShareSerialization {
                    client_id,
                    share_index,
                    reason: error.to_string(),
                }
            })?;
            let commitments = serialize_feldman_commitments(&share).map_err(|reason| {
                ClientInputStoreError::FeldmanCommitmentSerialization {
                    client_id,
                    share_index,
                    reason,
                }
            })?;
            let data = ShareData::Feldman {
                data: bytes,
                commitments,
            };
            Ok(match share_type {
                Some(share_type) => ClientShare::typed(share_type, data),
                None => ClientShare::untyped(data),
            })
        })
        .collect()
}

fn serialize_feldman_commitments<F, G>(
    share: &FeldmanShamirShare<F, G>,
) -> Result<Vec<Vec<u8>>, String>
where
    F: FftField + PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    share
        .commitments
        .iter()
        .map(|commitment| {
            let mut bytes = Vec::new();
            commitment
                .into_affine()
                .serialize_compressed(&mut bytes)
                .map_err(|e| format!("serialize commitment: {}", e))?;
            Ok(bytes)
        })
        .collect()
}
