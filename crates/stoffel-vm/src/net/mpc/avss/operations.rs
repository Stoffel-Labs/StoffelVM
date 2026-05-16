use super::AvssMpcEngine;
use ark_ec::CurveGroup;
use ark_ff::{FftField, PrimeField};

/// AVSS-specific operations trait.
///
/// This trait is object-safe and uses `Vec<u8>` for share data so it can be
/// used through `dyn AvssOperations` without knowing the concrete `(F, G)`.
pub trait AvssOperations {
    /// Generate a new random share and store it under `key_name` (async).
    /// Returns the serialized FeldmanShamirShare.
    fn avss_generate_share(
        &self,
        key_name: String,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + Send + '_>>;

    /// Get commitment at index for a stored share (synchronous).
    /// Index 0 is the public key.
    fn avss_get_commitment(&self, key_name: &str, index: usize) -> Result<Vec<u8>, String>;
}

impl<F, G> AvssOperations for AvssMpcEngine<F, G>
where
    F: FftField + PrimeField + Send + Sync + 'static,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    fn avss_generate_share(
        &self,
        key_name: String,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + Send + '_>>
    {
        Box::pin(async move {
            let share = self.generate_random_share(&key_name).await?;
            Self::encode_feldman_share(&share)
        })
    }

    fn avss_get_commitment(&self, key_name: &str, index: usize) -> Result<Vec<u8>, String> {
        let key_name = key_name.to_string();
        crate::net::block_on_current(async {
            let share = self
                .get_share(&key_name)
                .await
                .ok_or_else(|| format!("Key '{}' not found", key_name))?;
            let commitment = share
                .commitments
                .get(index)
                .ok_or_else(|| format!("Commitment index {} out of bounds", index))?;
            Self::encode_group_element(commitment)
        })
    }
}
