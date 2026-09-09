//! AVSS backend identity and API boundary types.
//!
//! The SDK exposes AVSS configuration and delegates live protocol operations to
//! `stoffel-vm` engines when a caller provides one.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::backend::Backend;
use crate::config::{Curve, MpcBackend};
use crate::error::{Error, Result};
use crate::types::{FieldElement, GroupElement, PublicKey, Share};
use ark_ec::CurveGroup;
use stoffel_vm::net::curve::{MpcCurveConfig, SupportedMpcCurvePair, SupportedMpcField};
use stoffel_vm::net::mpc::avss::{decode_avss_field, AvssMpcEngine};
use stoffel_vm::net::mpc_engine::AsyncMpcEngine;
use stoffel_vm_types::core_types::ShareType;
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;

#[derive(Debug, Clone)]
pub struct AvssBackend {
    curve: Curve,
}

impl AvssBackend {
    pub fn new(curve: Curve) -> Self {
        Self { curve }
    }

    pub fn curve(&self) -> Curve {
        self.curve
    }
}

impl Backend for AvssBackend {
    fn kind(&self) -> MpcBackend {
        MpcBackend::Avss { curve: self.curve }
    }

    fn name(&self) -> &'static str {
        "avss"
    }
}

#[derive(Clone)]
pub struct AvssEngine {
    curve: Curve,
    inner: Option<Arc<dyn ErasedAvssEngine>>,
}

type AvssOperation<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

trait ErasedAvssEngine: Send + Sync {
    fn generate_random_share<'a>(&'a self, key_name: &'a str) -> AvssOperation<'a, ()>;

    fn generate_random_share_with_session<'a>(
        &'a self,
        key_name: &'a str,
    ) -> AvssOperation<'a, u128>;

    fn generate_share_with_secret<'a>(
        &'a self,
        key_name: &'a str,
        secret: &'a FieldElement,
    ) -> AvssOperation<'a, ()>;

    fn generate_share_with_secret_and_session<'a>(
        &'a self,
        key_name: &'a str,
        secret: &'a FieldElement,
    ) -> AvssOperation<'a, u128>;

    fn await_received_share<'a>(
        &'a self,
        key_name: &'a str,
        expected_session_id: u128,
    ) -> AvssOperation<'a, ()>;

    fn get_share<'a>(&'a self, key_name: &'a str) -> AvssOperation<'a, Share>;

    fn get_public_key<'a>(&'a self, key_name: &'a str) -> AvssOperation<'a, PublicKey>;

    fn open_share_in_exp<'a>(
        &'a self,
        share: &'a Share,
        generator: &'a GroupElement,
    ) -> AvssOperation<'a, GroupElement>;
}

impl fmt::Debug for AvssEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AvssEngine")
            .field("curve", &self.curve)
            .field("live", &self.is_live())
            .finish_non_exhaustive()
    }
}

impl AvssEngine {
    pub(crate) fn unavailable(curve: Curve) -> Self {
        Self { curve, inner: None }
    }

    /// Wrap a live, generic AVSS VM engine.
    ///
    /// This is primarily for server/runtime code that already owns a configured
    /// VM engine. The curve is inferred from `G`, so callers cannot accidentally
    /// attach an engine under a different SDK curve. The SDK does not create a
    /// networked engine on its own.
    pub fn from_engine<F, G>(engine: Arc<AvssMpcEngine<F, G>>) -> Self
    where
        F: SupportedMpcField + ark_serialize::CanonicalDeserialize,
        G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
        (F, G): SupportedMpcCurvePair,
    {
        Self {
            curve: sdk_curve(<(F, G) as SupportedMpcCurvePair>::CURVE_CONFIG),
            inner: Some(engine),
        }
    }

    pub fn curve(&self) -> Curve {
        self.curve
    }

    pub fn is_live(&self) -> bool {
        self.inner.is_some()
    }

    #[tracing::instrument(skip_all, fields(curve = ?self.curve, key_name = key_name))]
    pub async fn generate_random_share(&self, key_name: &str) -> Result<()> {
        self.live_engine(format!("generate_random_share('{key_name}')"))?
            .generate_random_share(key_name)
            .await
    }

    /// Generate a share and return the exact session id recipients must bind to this key.
    pub async fn generate_random_share_with_session(&self, key_name: &str) -> Result<u128> {
        self.live_engine(format!("generate_random_share_with_session('{key_name}')"))?
            .generate_random_share_with_session(key_name)
            .await
    }

    #[tracing::instrument(skip_all, fields(curve = ?self.curve, key_name = key_name))]
    pub async fn generate_share_with_secret(
        &self,
        key_name: &str,
        secret: FieldElement,
    ) -> Result<()> {
        self.live_engine(format!("generate_share_with_secret('{key_name}', ...)"))?
            .generate_share_with_secret(key_name, &secret)
            .await
    }

    /// Generate a chosen-secret share and return its exact AVSS session id.
    pub async fn generate_share_with_secret_and_session(
        &self,
        key_name: &str,
        secret: FieldElement,
    ) -> Result<u128> {
        self.live_engine(format!(
            "generate_share_with_secret_and_session('{key_name}', ...)"
        ))?
        .generate_share_with_secret_and_session(key_name, &secret)
        .await
    }

    #[tracing::instrument(skip_all, fields(curve = ?self.curve, key_name = key_name))]
    pub async fn await_received_share(
        &self,
        key_name: &str,
        expected_session_id: u128,
    ) -> Result<()> {
        self.live_engine(format!(
            "await_received_share('{key_name}', session={expected_session_id})"
        ))?
        .await_received_share(key_name, expected_session_id)
        .await
    }

    pub async fn get_share(&self, key_name: &str) -> Result<Share> {
        self.live_engine(format!("get_share('{key_name}')"))?
            .get_share(key_name)
            .await
    }

    pub async fn get_public_key(&self, key_name: &str) -> Result<PublicKey> {
        self.live_engine(format!("get_public_key('{key_name}')"))?
            .get_public_key(key_name)
            .await
    }

    #[tracing::instrument(skip_all, fields(curve = ?self.curve, key_name = share.key_name))]
    pub async fn open_share_in_exp(
        &self,
        share: &Share,
        generator: &GroupElement,
    ) -> Result<GroupElement> {
        self.live_engine(format!("open_share_in_exp('{}', ...)", share.key_name))?
            .open_share_in_exp(share, generator)
            .await
    }

    fn live_engine(&self, operation: String) -> Result<&dyn ErasedAvssEngine> {
        self.inner
            .as_deref()
            .ok_or_else(|| self.unavailable_error(operation))
    }

    fn unavailable_error(&self, operation: String) -> Error {
        Error::Unsupported(format!(
            "{operation} requires a real AVSS engine from stoffel-vm/mpc-protocols; the SDK does not implement AVSS protocol logic"
        ))
    }
}

impl<F, G> ErasedAvssEngine for AvssMpcEngine<F, G>
where
    F: SupportedMpcField + ark_serialize::CanonicalDeserialize,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
    (F, G): SupportedMpcCurvePair,
{
    fn generate_random_share<'a>(&'a self, key_name: &'a str) -> AvssOperation<'a, ()> {
        Box::pin(engine_generate_random_share(self, key_name))
    }

    fn generate_random_share_with_session<'a>(
        &'a self,
        key_name: &'a str,
    ) -> AvssOperation<'a, u128> {
        Box::pin(engine_generate_random_share_with_session(self, key_name))
    }

    fn generate_share_with_secret<'a>(
        &'a self,
        key_name: &'a str,
        secret: &'a FieldElement,
    ) -> AvssOperation<'a, ()> {
        Box::pin(engine_generate_share_with_secret(self, key_name, secret))
    }

    fn generate_share_with_secret_and_session<'a>(
        &'a self,
        key_name: &'a str,
        secret: &'a FieldElement,
    ) -> AvssOperation<'a, u128> {
        Box::pin(engine_generate_share_with_secret_and_session(
            self, key_name, secret,
        ))
    }

    fn await_received_share<'a>(
        &'a self,
        key_name: &'a str,
        expected_session_id: u128,
    ) -> AvssOperation<'a, ()> {
        Box::pin(engine_await_received_share(
            self,
            key_name,
            expected_session_id,
        ))
    }

    fn get_share<'a>(&'a self, key_name: &'a str) -> AvssOperation<'a, Share> {
        Box::pin(engine_get_share(self, key_name))
    }

    fn get_public_key<'a>(&'a self, key_name: &'a str) -> AvssOperation<'a, PublicKey> {
        Box::pin(engine_get_public_key(self, key_name))
    }

    fn open_share_in_exp<'a>(
        &'a self,
        share: &'a Share,
        generator: &'a GroupElement,
    ) -> AvssOperation<'a, GroupElement> {
        Box::pin(engine_open_share_in_exp(self, share, generator))
    }
}

fn sdk_curve(curve: MpcCurveConfig) -> Curve {
    match curve {
        MpcCurveConfig::Bls12_381 => Curve::Bls12_381,
        MpcCurveConfig::Bn254 => Curve::Bn254,
        MpcCurveConfig::Curve25519 => Curve::Curve25519,
        MpcCurveConfig::Ed25519 => Curve::Ed25519,
        MpcCurveConfig::Secp256k1 => Curve::Secp256k1,
        MpcCurveConfig::Secp256r1 => Curve::Secp256r1,
    }
}

async fn engine_generate_random_share<F, G>(
    engine: &AvssMpcEngine<F, G>,
    key_name: &str,
) -> Result<()>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    engine
        .generate_random_share(key_name)
        .await
        .map(|_| ())
        .map_err(Error::Computation)
}

async fn engine_generate_random_share_with_session<F, G>(
    engine: &AvssMpcEngine<F, G>,
    key_name: &str,
) -> Result<u128>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    engine
        .generate_random_share_with_session(key_name)
        .await
        .map(|(session_id, _)| session_id)
        .map_err(Error::Computation)
}

async fn engine_generate_share_with_secret<F, G>(
    engine: &AvssMpcEngine<F, G>,
    key_name: &str,
    secret: &FieldElement,
) -> Result<()>
where
    F: SupportedMpcField + ark_serialize::CanonicalDeserialize,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    if secret.as_bytes().is_empty() {
        return Err(Error::InvalidInput(
            "AVSS field element bytes cannot be empty".to_owned(),
        ));
    }
    let secret = decode_avss_field::<F>(secret.as_bytes()).map_err(Error::Computation)?;
    engine
        .generate_share_with_secret(key_name, secret)
        .await
        .map(|_| ())
        .map_err(Error::Computation)
}

async fn engine_generate_share_with_secret_and_session<F, G>(
    engine: &AvssMpcEngine<F, G>,
    key_name: &str,
    secret: &FieldElement,
) -> Result<u128>
where
    F: SupportedMpcField + ark_serialize::CanonicalDeserialize,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    if secret.as_bytes().is_empty() {
        return Err(Error::InvalidInput(
            "AVSS field element bytes cannot be empty".to_owned(),
        ));
    }
    let secret = decode_avss_field::<F>(secret.as_bytes()).map_err(Error::Computation)?;
    engine
        .generate_share_with_secret_and_session(key_name, secret)
        .await
        .map(|(session_id, _)| session_id)
        .map_err(Error::Computation)
}

async fn engine_await_received_share<F, G>(
    engine: &AvssMpcEngine<F, G>,
    key_name: &str,
    expected_session_id: u128,
) -> Result<()>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    engine
        .await_received_share(key_name, expected_session_id)
        .await
        .map(|_| ())
        .map_err(Error::Computation)
}

async fn engine_get_share<F, G>(engine: &AvssMpcEngine<F, G>, key_name: &str) -> Result<Share>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    let share = engine
        .get_share(key_name)
        .await
        .ok_or_else(|| Error::Computation(format!("AVSS share '{key_name}' not found")))?;
    avss_share_to_sdk::<F, G>(key_name, &share)
}

async fn engine_get_public_key<F, G>(
    engine: &AvssMpcEngine<F, G>,
    key_name: &str,
) -> Result<PublicKey>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    let bytes = engine
        .get_public_key_bytes(key_name)
        .await
        .map_err(Error::Computation)?;
    Ok(PublicKey::new(key_name, bytes))
}

async fn engine_open_share_in_exp<F, G>(
    engine: &AvssMpcEngine<F, G>,
    share: &Share,
    generator: &GroupElement,
) -> Result<GroupElement>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    let Some(share_data) = share.data() else {
        return Err(Error::InvalidInput(format!(
            "AVSS share '{}' does not contain encoded share data",
            share.key_name
        )));
    };
    let bytes = engine
        .open_share_in_exp_async(
            ShareType::default_secret_int(),
            share_data,
            generator.as_bytes(),
        )
        .await
        .map_err(|error| Error::Computation(error.to_string()))?;
    Ok(GroupElement::from_bytes(bytes))
}

fn avss_share_to_sdk<F, G>(key_name: &str, share: &FeldmanShamirShare<F, G>) -> Result<Share>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    let data = AvssMpcEngine::<F, G>::share_to_share_data(share).map_err(Error::Computation)?;
    match data {
        stoffel_vm_types::core_types::ShareData::Feldman { data, commitments } => Ok(
            Share::feldman(key_name, data.to_vec(), commitments.to_vec()),
        ),
        stoffel_vm_types::core_types::ShareData::Opaque(data) => {
            Ok(Share::opaque(key_name, data.to_vec()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_live_engine_constructor_accepts_every_supported_avss_curve() {
        assert_generic_constructor::<ark_bls12_381::Fr, ark_bls12_381::G1Projective>();
        assert_generic_constructor::<ark_bn254::Fr, ark_bn254::G1Projective>();
        assert_generic_constructor::<ark_curve25519::Fr, ark_curve25519::EdwardsProjective>();
        assert_generic_constructor::<ark_ed25519::Fr, ark_ed25519::EdwardsProjective>();
        assert_generic_constructor::<ark_secp256k1::Fr, ark_secp256k1::Projective>();
        assert_generic_constructor::<ark_secp256r1::Fr, ark_secp256r1::Projective>();
    }

    fn assert_generic_constructor<F, G>()
    where
        F: SupportedMpcField + ark_serialize::CanonicalDeserialize,
        G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
        (F, G): SupportedMpcCurvePair,
    {
        let _: fn(Arc<AvssMpcEngine<F, G>>) -> AvssEngine = AvssEngine::from_engine::<F, G>;
    }
}
