//! Browser-side cryptographic boundary for coordinator-mediated Stoffel client I/O.
//!
//! Network requests remain in JavaScript so browsers can use their native WebSocket
//! implementation. This crate owns every operation involving clear client values:
//! authenticating requests, reconstructing masks, masking inputs, decrypting output
//! shares, and reconstructing the final result.

use ark_bls12_381::Fr;
use ark_ff::{BigInteger, FftField, PrimeField, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use hpke::{
    aead::AesGcm256,
    kdf::HkdfSha256,
    kem::{DhP256HkdfSha256, Kem},
    single_shot_open, Deserializable, OpModeR,
};
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    elliptic_curve::sec1::ToEncodedPoint,
    pkcs8::DecodePrivateKey,
    SecretKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::marker::PhantomData;
use std::rc::Rc;
use stoffel_vm_types::core_types::{FixedPointPrecision, ShareType};
use stoffel_vm_types::fixed_point_codec::{
    decode_fixed_point_float, encode_fixed_point_float, encode_fixed_point_integer,
};
use wasm_bindgen::prelude::*;

const AUTH_DOMAIN: &[u8] = b"stoffel-browser-rpc-auth-v1";
const OUTPUT_HPKE_DOMAIN: &[u8] = b"StoffelOutputShareEncryption";
const MAX_PARTIES: usize = 32;
const MAX_THRESHOLD: usize = 8;

type KemImpl = DhP256HkdfSha256;
type KdfImpl = HkdfSha256;
type AeadImpl = AesGcm256;

#[wasm_bindgen(typescript_custom_section)]
const TYPESCRIPT_TYPES: &'static str = r#"
export type ClientScalarType =
  | { kind: "boolean" }
  | { kind: "signed_integer"; bit_length: number }
  | { kind: "unsigned_integer"; bit_length: number }
  | { kind: "fixed_point"; total_bits: number; fractional_bits: number };

export type ClientScalarValue =
  | { kind: "boolean"; value: boolean }
  | { kind: "signed_integer"; value: bigint }
  | { kind: "unsigned_integer"; value: bigint }
  | { kind: "fixed_point"; value: number }
  | { kind: "field"; value: Uint8Array };

export interface TypedClientInput {
  share_type: ClientScalarType;
  value: ClientScalarValue;
}

export interface AssignedMaskShare {
  reserved_index: number | bigint;
  share_bytes: Uint8Array;
}

export interface MaskedInput {
  reserved_index: number;
  masked_input: Uint8Array;
}

export interface EncryptedOutputShare {
  encapped_key: Uint8Array;
  ciphertext: Uint8Array;
}

export interface SignedBrowserRequest {
  public_key: Uint8Array;
  nonce: number;
  signature: Uint8Array;
  body: Uint8Array;
}
"#;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("invalid P-256 PKCS#8 private key")]
    InvalidPrivateKey,
    #[error("execution ID must contain exactly 64 hexadecimal characters")]
    InvalidExecutionId,
    #[error("unsupported topology n={n}, t={t}")]
    InvalidTopology { n: usize, t: usize },
    #[error("failed to deserialize a coordinator share")]
    InvalidShare,
    #[error("share set contains inconsistent metadata")]
    InconsistentShares,
    #[error("not enough valid shares to reconstruct a value")]
    InsufficientShares,
    #[error("failed to decrypt an output share")]
    OutputDecryption,
    #[error("output party returned {actual} values, expected {expected}")]
    OutputArity { expected: usize, actual: usize },
    #[error("field value is outside the signed 64-bit client range")]
    OutputRange,
    #[error("invalid client scalar type: {0}")]
    InvalidScalarType(String),
    #[error("client value is incompatible with its scalar type: {0}")]
    InvalidScalarValue(String),
    #[error("request nonce overflowed for this execution")]
    NonceOverflow,
    #[error("JavaScript value conversion failed: {0}")]
    Js(String),
}

impl From<ClientError> for JsValue {
    fn from(value: ClientError) -> Self {
        js_sys::Error::new(&value.to_string()).into()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedBrowserRequest {
    pub public_key: Vec<u8>,
    pub nonce: u64,
    pub signature: Vec<u8>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssignedMaskShare {
    pub reserved_index: u64,
    pub share_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MaskedInput {
    pub reserved_index: u64,
    pub masked_input: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedOutputShare {
    pub encapped_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Browser-friendly form of the scalar share types in a compiled client I/O
/// manifest. Integer values are transferred as JavaScript `BigInt`s so all 64
/// bits survive the JavaScript/WASM boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClientScalarType {
    Boolean,
    SignedInteger {
        bit_length: usize,
    },
    UnsignedInteger {
        bit_length: usize,
    },
    FixedPoint {
        total_bits: usize,
        fractional_bits: usize,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ClientScalarValue {
    Boolean(bool),
    SignedInteger(i64),
    UnsignedInteger(u64),
    FixedPoint(f64),
    /// Exactly one canonical, big-endian scalar-field element. This mirrors
    /// the native client's `Value::Bytes` input path.
    Field(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TypedClientInput {
    pub share_type: ClientScalarType,
    pub value: ClientScalarValue,
}

/// Canonical-serialization-compatible projection of HoneyBadger's
/// `RobustShare<F>`. The marker is zero-sized on the wire.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
struct RobustShare<F: FftField> {
    share: [F; 1],
    id: usize,
    degree: usize,
    marker: PhantomData<fn()>,
}

impl<F: FftField> RobustShare<F> {
    #[cfg(test)]
    fn new(value: F, id: usize, degree: usize) -> Self {
        Self {
            share: [value],
            id,
            degree,
            marker: PhantomData,
        }
    }
}

struct ClientCore {
    signing_key: SigningKey,
    secret_key: SecretKey,
    public_key: Vec<u8>,
    parties: usize,
    threshold: usize,
}

/// Long-lived browser identity. It can open any number of simultaneous
/// execution handles while reusing the same key and topology.
#[wasm_bindgen]
pub struct StoffelWasmClient {
    core: Rc<ClientCore>,
    nonces: Rc<RefCell<HashMap<[u8; 32], u64>>>,
}

/// State belonging to one execution. Multiple handles from a client can be
/// active concurrently; nonces advance independently for each execution.
#[wasm_bindgen]
pub struct StoffelWasmExecution {
    core: Rc<ClientCore>,
    nonces: Rc<RefCell<HashMap<[u8; 32], u64>>>,
    execution_id: [u8; 32],
}

#[wasm_bindgen]
impl StoffelWasmClient {
    #[wasm_bindgen(constructor)]
    pub fn new(
        private_key_pkcs8: &[u8],
        parties: usize,
        threshold: usize,
    ) -> Result<Self, JsValue> {
        console_error_panic_hook::set_once();
        Self::from_pkcs8(private_key_pkcs8, parties, threshold).map_err(Into::into)
    }

    /// SEC1 uncompressed P-256 public key. This is the same byte string stored
    /// in the subjectPublicKey field of the existing demo client certificate.
    pub fn public_key(&self) -> Vec<u8> {
        self.core.public_key.clone()
    }

    /// Open (or resume) an execution. Opening two different IDs creates
    /// independent request streams; reopening the same ID continues its nonce.
    pub fn open_execution(&self, execution_id: &str) -> Result<StoffelWasmExecution, JsValue> {
        Ok(self.execution_handle(parse_execution_id(execution_id)?))
    }

    /// Resume an execution after a browser reload. `last_nonce` is the last
    /// successfully created request saved by the caller. An already-open local
    /// counter is never moved backward.
    pub fn resume_execution(
        &self,
        execution_id: &str,
        last_nonce: u64,
    ) -> Result<StoffelWasmExecution, JsValue> {
        let execution_id = parse_execution_id(execution_id)?;
        self.nonces
            .borrow_mut()
            .entry(execution_id)
            .and_modify(|current| *current = (*current).max(last_nonce))
            .or_insert(last_nonce);
        Ok(self.execution_handle(execution_id))
    }

    /// Release the local nonce counter after an execution is permanently
    /// retired. Existing handles for that ID must not be used afterward.
    pub fn forget_execution(&self, execution_id: &str) -> Result<(), JsValue> {
        self.nonces
            .borrow_mut()
            .remove(&parse_execution_id(execution_id)?);
        Ok(())
    }
}

#[wasm_bindgen]
impl StoffelWasmExecution {
    pub fn execution_id(&self) -> String {
        hex::encode(self.execution_id)
    }

    /// Last nonce allocated for this execution. Save this after signing when
    /// an in-progress execution must survive a page reload.
    pub fn current_nonce(&self) -> u64 {
        self.nonces
            .borrow()
            .get(&self.execution_id)
            .copied()
            .unwrap_or(0)
    }

    /// Sign with the next nonce for this execution. The counter is shared with
    /// other handles for the same execution and independent across IDs.
    #[wasm_bindgen(unchecked_return_type = "SignedBrowserRequest")]
    pub fn sign_request(&self, method: &str, body: &[u8]) -> Result<JsValue, JsValue> {
        let nonce = next_nonce(&self.nonces, self.execution_id)?;
        let message = authentication_message(method, &self.execution_id, nonce, body);
        let signature: Signature = self.core.signing_key.sign(&message);
        serde_wasm_bindgen::to_value(&SignedBrowserRequest {
            public_key: self.core.public_key.clone(),
            nonce,
            signature: signature.to_bytes().to_vec(),
            body: body.to_vec(),
        })
        .map_err(|error| ClientError::Js(error.to_string()).into())
    }

    /// Reconstruct and apply one mask per typed input.
    #[wasm_bindgen(unchecked_return_type = "MaskedInput[]")]
    pub fn mask_inputs(
        &self,
        first_reserved_index: u64,
        #[wasm_bindgen(unchecked_param_type = "TypedClientInput[]")] clear_inputs: JsValue,
        #[wasm_bindgen(unchecked_param_type = "AssignedMaskShare[][]")] node_responses: JsValue,
    ) -> Result<JsValue, JsValue> {
        let inputs: Vec<TypedClientInput> = serde_wasm_bindgen::from_value(clear_inputs)
            .map_err(|error| ClientError::Js(error.to_string()))?;
        let responses: Vec<Vec<AssignedMaskShare>> = serde_wasm_bindgen::from_value(node_responses)
            .map_err(|error| ClientError::Js(error.to_string()))?;
        let fields = inputs
            .iter()
            .map(typed_input_to_field)
            .collect::<Result<Vec<_>, _>>()?;
        serde_wasm_bindgen::to_value(&mask_fields_core(
            self.core.parties,
            self.core.threshold,
            first_reserved_index,
            &fields,
            &responses,
        )?)
        .map_err(|error| ClientError::Js(error.to_string()).into())
    }

    /// Decrypt and robustly reconstruct outputs using their manifest types.
    #[wasm_bindgen(unchecked_return_type = "ClientScalarValue[]")]
    pub fn decrypt_outputs(
        &self,
        #[wasm_bindgen(unchecked_param_type = "ClientScalarType[]")] output_types: JsValue,
        #[wasm_bindgen(unchecked_param_type = "EncryptedOutputShare[]")] encrypted_shares: JsValue,
    ) -> Result<JsValue, JsValue> {
        let output_types: Vec<ClientScalarType> = serde_wasm_bindgen::from_value(output_types)
            .map_err(|error| ClientError::Js(error.to_string()))?;
        let encrypted: Vec<EncryptedOutputShare> = serde_wasm_bindgen::from_value(encrypted_shares)
            .map_err(|error| ClientError::Js(error.to_string()))?;
        let values = decrypt_fields_core(
            &self.core,
            &self.execution_id,
            output_types.len(),
            &encrypted,
        )?
        .into_iter()
        .zip(output_types)
        .map(|(value, share_type)| field_to_typed_value(value, share_type))
        .collect::<Result<Vec<_>, _>>()?;
        to_js_value_with_bigints(&values)
    }
}

impl StoffelWasmClient {
    fn execution_handle(&self, execution_id: [u8; 32]) -> StoffelWasmExecution {
        StoffelWasmExecution {
            core: self.core.clone(),
            nonces: self.nonces.clone(),
            execution_id,
        }
    }

    pub fn from_pkcs8(
        private_key_pkcs8: &[u8],
        parties: usize,
        threshold: usize,
    ) -> Result<Self, ClientError> {
        validate_topology(parties, threshold)?;
        let secret_key = SecretKey::from_pkcs8_der(private_key_pkcs8)
            .map_err(|_| ClientError::InvalidPrivateKey)?;
        Self::from_secret_key(secret_key, parties, threshold)
    }

    fn from_secret_key(
        secret_key: SecretKey,
        parties: usize,
        threshold: usize,
    ) -> Result<Self, ClientError> {
        validate_topology(parties, threshold)?;
        let signing_key = SigningKey::from(secret_key.clone());
        let public_key = secret_key
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        Ok(Self {
            core: Rc::new(ClientCore {
                signing_key,
                secret_key,
                public_key,
                parties,
                threshold,
            }),
            nonces: Rc::new(RefCell::new(HashMap::new())),
        })
    }
}

fn mask_fields_core(
    parties: usize,
    threshold: usize,
    first_reserved_index: u64,
    clear_inputs: &[Fr],
    node_responses: &[Vec<AssignedMaskShare>],
) -> Result<Vec<MaskedInput>, ClientError> {
    let mut shares_by_index: BTreeMap<u64, Vec<RobustShare<Fr>>> = BTreeMap::new();
    for response in node_responses {
        for assigned in response {
            let share = RobustShare::<Fr>::deserialize_compressed(assigned.share_bytes.as_slice())
                .map_err(|_| ClientError::InvalidShare)?;
            shares_by_index
                .entry(assigned.reserved_index)
                .or_default()
                .push(share);
        }
    }

    clear_inputs
        .iter()
        .enumerate()
        .map(|(offset, clear)| {
            let reserved_index = first_reserved_index
                .checked_add(offset as u64)
                .ok_or(ClientError::OutputRange)?;
            let shares = shares_by_index
                .get(&reserved_index)
                .ok_or(ClientError::InsufficientShares)?;
            let mask = recover_robust_secret(shares, parties, threshold)?;
            let value = *clear + mask;
            let mut masked_input = Vec::new();
            value
                .serialize_compressed(&mut masked_input)
                .map_err(|_| ClientError::InvalidShare)?;
            Ok(MaskedInput {
                reserved_index,
                masked_input,
            })
        })
        .collect()
}

fn decrypt_fields_core(
    core: &ClientCore,
    execution_id: &[u8; 32],
    output_count: usize,
    encrypted_shares: &[EncryptedOutputShare],
) -> Result<Vec<Fr>, ClientError> {
    let raw_secret = core.secret_key.to_bytes();
    let hpke_secret = <KemImpl as Kem>::PrivateKey::from_bytes(&raw_secret)
        .map_err(|_| ClientError::InvalidPrivateKey)?;
    let info = output_encryption_info(execution_id);
    let mut by_output = vec![Vec::<RobustShare<Fr>>::new(); output_count];

    for encrypted in encrypted_shares {
        let encapped = <KemImpl as Kem>::EncappedKey::from_bytes(&encrypted.encapped_key)
            .map_err(|_| ClientError::OutputDecryption)?;
        let plaintext = single_shot_open::<AeadImpl, KdfImpl, KemImpl>(
            &OpModeR::Base,
            &hpke_secret,
            &encapped,
            &info,
            &encrypted.ciphertext,
            b"",
        )
        .map_err(|_| ClientError::OutputDecryption)?;
        let shares = Vec::<RobustShare<Fr>>::deserialize_compressed(plaintext.as_slice())
            .map_err(|_| ClientError::InvalidShare)?;
        if shares.len() != output_count {
            return Err(ClientError::OutputArity {
                expected: output_count,
                actual: shares.len(),
            });
        }
        for (index, share) in shares.into_iter().enumerate() {
            by_output[index].push(share);
        }
    }

    by_output
        .iter()
        .map(|shares| recover_robust_secret(shares, core.parties, core.threshold))
        .collect()
}

fn next_nonce(
    nonces: &RefCell<HashMap<[u8; 32], u64>>,
    execution_id: [u8; 32],
) -> Result<u64, ClientError> {
    let mut nonces = nonces.borrow_mut();
    let next = nonces
        .get(&execution_id)
        .copied()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(ClientError::NonceOverflow)?;
    nonces.insert(execution_id, next);
    Ok(next)
}

fn scalar_share_type(value: ClientScalarType) -> Result<ShareType, ClientError> {
    match value {
        ClientScalarType::Boolean => Ok(ShareType::boolean()),
        ClientScalarType::SignedInteger { bit_length: 1 } => Err(ClientError::InvalidScalarType(
            "use the boolean type for one-bit secrets".to_owned(),
        )),
        ClientScalarType::SignedInteger { bit_length } => ShareType::try_secret_int(bit_length)
            .map_err(|error| ClientError::InvalidScalarType(error.to_string())),
        ClientScalarType::UnsignedInteger { bit_length } => ShareType::try_secret_uint(bit_length)
            .map_err(|error| ClientError::InvalidScalarType(error.to_string())),
        ClientScalarType::FixedPoint {
            total_bits,
            fractional_bits,
        } => ShareType::try_secret_fixed_point_from_bits(total_bits, fractional_bits)
            .map_err(|error| ClientError::InvalidScalarType(error.to_string())),
    }
}

fn typed_input_to_field(input: &TypedClientInput) -> Result<Fr, ClientError> {
    let share_type = scalar_share_type(input.share_type)?;
    match (share_type, &input.value) {
        (ShareType::SecretInt { bit_length: 1 }, ClientScalarValue::Boolean(value)) => {
            Ok(Fr::from(*value as u64))
        }
        (ShareType::SecretInt { bit_length: 1 }, ClientScalarValue::SignedInteger(value)) => {
            Ok(Fr::from((*value != 0) as u64))
        }
        (ShareType::SecretInt { .. }, ClientScalarValue::SignedInteger(value)) => {
            Ok(field_from_i64(*value))
        }
        (ShareType::SecretInt { .. }, ClientScalarValue::UnsignedInteger(value)) => {
            let value = i64::try_from(*value).map_err(|_| {
                ClientError::InvalidScalarValue(
                    "unsigned secret integer input exceeds the signed 64-bit range".to_owned(),
                )
            })?;
            Ok(field_from_i64(value))
        }
        (ShareType::SecretInt { bit_length, .. }, ClientScalarValue::Field(bytes))
            if bit_length > 1 =>
        {
            canonical_field_from_be_bytes(bytes)
        }
        (ShareType::SecretUInt { .. }, ClientScalarValue::Field(bytes)) => {
            canonical_field_from_be_bytes(bytes)
        }
        (ShareType::SecretUInt { bit_length }, ClientScalarValue::UnsignedInteger(value)) => {
            validate_secret_uint_range(*value, bit_length)?;
            Ok(Fr::from(*value))
        }
        (ShareType::SecretUInt { bit_length }, ClientScalarValue::SignedInteger(value)) => {
            let value = u64::try_from(*value).map_err(|_| {
                ClientError::InvalidScalarValue(
                    "signed input for a secret unsigned integer must be non-negative".to_owned(),
                )
            })?;
            validate_secret_uint_range(value, bit_length)?;
            Ok(Fr::from(value))
        }
        (ShareType::SecretFixedPoint { precision }, ClientScalarValue::SignedInteger(value)) => {
            fixed_point_integer_to_field(i128::from(*value), precision)
        }
        (ShareType::SecretFixedPoint { precision }, ClientScalarValue::UnsignedInteger(value)) => {
            fixed_point_integer_to_field(i128::from(*value), precision)
        }
        (ShareType::SecretFixedPoint { precision }, ClientScalarValue::FixedPoint(value)) => {
            encode_fixed_point_float(*value, precision)
                .map(field_from_i64)
                .map_err(|error| ClientError::InvalidScalarValue(error.to_string()))
        }
        (share_type, value) => Err(ClientError::InvalidScalarValue(format!(
            "value {value:?} is not compatible with {share_type:?}"
        ))),
    }
}

fn field_to_typed_value(
    value: Fr,
    share_type: ClientScalarType,
) -> Result<ClientScalarValue, ClientError> {
    match scalar_share_type(share_type)? {
        ShareType::SecretField => Err(ClientError::InvalidScalarValue(
            "field shares require raw field output".to_owned(),
        )),
        ShareType::SecretInt { bit_length: 1 } => Ok(ClientScalarValue::Boolean(!value.is_zero())),
        ShareType::SecretInt { .. } => field_to_i64(value).map(ClientScalarValue::SignedInteger),
        ShareType::SecretUInt { bit_length } => {
            field_to_u64(value, bit_length).map(ClientScalarValue::UnsignedInteger)
        }
        ShareType::SecretFixedPoint { precision } => {
            let encoded = field_to_i64(value)?;
            decode_fixed_point_float(encoded, precision)
                .map(ClientScalarValue::FixedPoint)
                .map_err(|error| ClientError::InvalidScalarValue(error.to_string()))
        }
    }
}

fn fixed_point_integer_to_field(
    value: i128,
    precision: FixedPointPrecision,
) -> Result<Fr, ClientError> {
    encode_fixed_point_integer(value, precision)
        .map(field_from_i64)
        .map_err(|error| ClientError::InvalidScalarValue(error.to_string()))
}

fn validate_secret_uint_range(value: u64, bit_length: usize) -> Result<(), ClientError> {
    if bit_length >= 64 || value < (1u64 << bit_length) {
        Ok(())
    } else {
        Err(ClientError::InvalidScalarValue(format!(
            "secret unsigned integer input {value} does not fit in {bit_length} bit(s)"
        )))
    }
}

fn field_to_u64(value: Fr, bit_length: usize) -> Result<u64, ClientError> {
    let bigint = value.into_bigint();
    let limbs = bigint.as_ref();
    if limbs.iter().skip(1).all(|limb| *limb == 0) {
        let value = limbs.first().copied().unwrap_or(0);
        validate_secret_uint_range(value, bit_length)?;
        Ok(value)
    } else {
        Err(ClientError::InvalidScalarValue(
            "field output cannot be represented as an unsigned 64-bit integer".to_owned(),
        ))
    }
}

fn canonical_field_from_be_bytes(bytes: &[u8]) -> Result<Fr, ClientError> {
    let field_bytes = Fr::MODULUS_BIT_SIZE.div_ceil(8) as usize;
    if bytes.len() != field_bytes {
        return Err(ClientError::InvalidScalarValue(format!(
            "BLS12-381 field input must be exactly {field_bytes} canonical big-endian bytes, got {}",
            bytes.len()
        )));
    }
    let value = Fr::from_be_bytes_mod_order(bytes);
    let encoded = value.into_bigint().to_bytes_be();
    let mut canonical = vec![0u8; field_bytes];
    let start = field_bytes.checked_sub(encoded.len()).ok_or_else(|| {
        ClientError::InvalidScalarValue("field input is not canonical".to_owned())
    })?;
    canonical[start..].copy_from_slice(&encoded);
    if canonical == bytes {
        Ok(value)
    } else {
        Err(ClientError::InvalidScalarValue(
            "field input must be less than the scalar-field modulus".to_owned(),
        ))
    }
}

fn to_js_value_with_bigints<T: Serialize>(value: &T) -> Result<JsValue, JsValue> {
    value
        .serialize(
            &serde_wasm_bindgen::Serializer::new().serialize_large_number_types_as_bigints(true),
        )
        .map_err(|error| ClientError::Js(error.to_string()).into())
}

pub fn authentication_message(
    method: &str,
    execution_id: &[u8; 32],
    nonce: u64,
    body: &[u8],
) -> Vec<u8> {
    let body_hash = Sha256::digest(body);
    let mut message = Vec::with_capacity(AUTH_DOMAIN.len() + method.len() + 1 + 32 + 8 + 32);
    message.extend_from_slice(AUTH_DOMAIN);
    message.push(0);
    message.extend_from_slice(method.as_bytes());
    message.push(0);
    message.extend_from_slice(execution_id);
    message.extend_from_slice(&nonce.to_le_bytes());
    message.extend_from_slice(&body_hash);
    message
}

fn output_encryption_info(execution_id: &[u8; 32]) -> Vec<u8> {
    let mut info = Vec::with_capacity(OUTPUT_HPKE_DOMAIN.len() + execution_id.len());
    info.extend_from_slice(OUTPUT_HPKE_DOMAIN);
    info.extend_from_slice(execution_id);
    info
}

fn validate_topology(n: usize, t: usize) -> Result<(), ClientError> {
    if n == 0 || n > MAX_PARTIES || t == 0 || t > MAX_THRESHOLD || n < 3 * t + 1 {
        return Err(ClientError::InvalidTopology { n, t });
    }
    Ok(())
}

fn parse_execution_id(value: &str) -> Result<[u8; 32], ClientError> {
    if value.len() != 64 {
        return Err(ClientError::InvalidExecutionId);
    }
    hex::decode(value)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(ClientError::InvalidExecutionId)
}

fn field_from_i64(value: i64) -> Fr {
    if value >= 0 {
        Fr::from(value as u64)
    } else {
        -Fr::from(value.unsigned_abs())
    }
}

fn field_to_i64(value: Fr) -> Result<i64, ClientError> {
    let bigint = value.into_bigint();
    let negated = (-value).into_bigint();
    let to_u64 = |number: &<Fr as PrimeField>::BigInt| {
        let limbs = number.as_ref();
        limbs
            .iter()
            .skip(1)
            .all(|limb| *limb == 0)
            .then(|| limbs.first().copied().unwrap_or(0))
    };
    if !value.is_zero() && negated < bigint {
        let magnitude = to_u64(&negated).ok_or(ClientError::OutputRange)?;
        if magnitude == 1u64 << 63 {
            Ok(i64::MIN)
        } else {
            i64::try_from(magnitude)
                .map(|magnitude| -magnitude)
                .map_err(|_| ClientError::OutputRange)
        }
    } else {
        to_u64(&bigint)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or(ClientError::OutputRange)
    }
}

fn recover_robust_secret(
    shares: &[RobustShare<Fr>],
    n: usize,
    t: usize,
) -> Result<Fr, ClientError> {
    if shares.is_empty() {
        return Err(ClientError::InsufficientShares);
    }
    let degree = shares[0].degree;
    if degree > t
        || shares
            .iter()
            .any(|share| share.degree != degree || share.id >= n)
    {
        return Err(ClientError::InconsistentShares);
    }
    let mut ids = HashSet::new();
    if shares.iter().any(|share| !ids.insert(share.id)) {
        return Err(ClientError::InconsistentShares);
    }
    let required = degree + t + 1;
    if shares.len() < required {
        return Err(ClientError::InsufficientShares);
    }
    let domain =
        Radix2EvaluationDomain::<Fr>::new(n).ok_or(ClientError::InvalidTopology { n, t })?;
    let subset_size = degree + 1;
    let mut best: Option<(usize, Fr)> = None;
    for_each_combination(shares.len(), subset_size, |indices| {
        let points = indices
            .iter()
            .map(|index| (domain.element(shares[*index].id), shares[*index].share[0]))
            .collect::<Vec<_>>();
        let secret = lagrange_evaluate(&points, Fr::zero());
        let agreement = shares
            .iter()
            .filter(|share| lagrange_evaluate(&points, domain.element(share.id)) == share.share[0])
            .count();
        if best.is_none_or(|(best_agreement, _)| agreement > best_agreement) {
            best = Some((agreement, secret));
        }
    });
    match best {
        Some((agreement, secret)) if agreement >= required => Ok(secret),
        _ => Err(ClientError::InsufficientShares),
    }
}

fn lagrange_evaluate(points: &[(Fr, Fr)], at: Fr) -> Fr {
    points
        .iter()
        .enumerate()
        .fold(Fr::zero(), |sum, (j, (xj, yj))| {
            let basis = points
                .iter()
                .enumerate()
                .filter(|(m, _)| *m != j)
                .fold(Fr::from(1u64), |product, (_, (xm, _))| {
                    product * (at - xm) / (*xj - *xm)
                });
            sum + (*yj * basis)
        })
}

fn for_each_combination(n: usize, k: usize, mut visit: impl FnMut(&[usize])) {
    if k == 0 || k > n {
        return;
    }
    let mut indices = (0..k).collect::<Vec<_>>();
    loop {
        visit(&indices);
        let mut position = k;
        while position > 0 {
            position -= 1;
            if indices[position] != position + n - k {
                break;
            }
        }
        if position == 0 && indices[0] == n - k {
            break;
        }
        indices[position] += 1;
        for next in position + 1..k {
            indices[next] = indices[next - 1] + 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hpke::{single_shot_seal, OpModeS, Serializable};
    use p256::ecdsa::{signature::Verifier, VerifyingKey};
    use rand::{rngs::StdRng, SeedableRng};
    use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare as ProtocolRobustShare;

    fn shares(secret: Fr, n: usize, degree: usize) -> Vec<RobustShare<Fr>> {
        let domain = Radix2EvaluationDomain::<Fr>::new(n).unwrap();
        let slope = Fr::from(19u64);
        (0..n)
            .map(|id| {
                let x = domain.element(id);
                RobustShare::new(secret + slope * x, id, degree)
            })
            .collect()
    }

    #[test]
    fn reconstructs_with_one_corrupt_share() {
        let secret = field_from_i64(-41);
        let mut values = shares(secret, 5, 1);
        values[4].share[0] += Fr::from(7u64);
        assert_eq!(recover_robust_secret(&values, 5, 1).unwrap(), secret);
    }

    #[test]
    fn canonical_share_projection_round_trips() {
        let share = shares(Fr::from(9u64), 5, 1).remove(0);
        let mut bytes = Vec::new();
        share.serialize_compressed(&mut bytes).unwrap();
        assert_eq!(
            RobustShare::<Fr>::deserialize_compressed(bytes.as_slice()).unwrap(),
            share
        );
    }

    #[test]
    fn canonical_share_projection_matches_the_protocol_type() {
        let protocol_share = ProtocolRobustShare::new(Fr::from(29u64), 3, 1);
        let mut bytes = Vec::new();
        protocol_share.serialize_compressed(&mut bytes).unwrap();

        let projected = RobustShare::<Fr>::deserialize_compressed(bytes.as_slice()).unwrap();
        assert_eq!(projected.share, protocol_share.share);
        assert_eq!(projected.id, protocol_share.id);
        assert_eq!(projected.degree, protocol_share.degree);

        let mut projected_bytes = Vec::new();
        projected
            .serialize_compressed(&mut projected_bytes)
            .unwrap();
        let decoded =
            ProtocolRobustShare::<Fr>::deserialize_compressed(projected_bytes.as_slice()).unwrap();
        assert_eq!(decoded, protocol_share);
    }

    #[test]
    fn decrypts_protocol_output_batches_with_the_coordinator_domain() {
        let secret_key = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let client = StoffelWasmClient::from_secret_key(secret_key, 5, 1).unwrap();
        let execution_id = [0x42; 32];
        let hpke_public = <KemImpl as Kem>::PublicKey::from_bytes(&client.core.public_key).unwrap();
        let domain = Radix2EvaluationDomain::<Fr>::new(5).unwrap();
        let expected = [17i64, -9, 120, 3];
        let mut encrypted = Vec::new();
        let mut rng = StdRng::seed_from_u64(41);

        for party_id in 0..3 {
            let x = domain.element(party_id);
            let shares = expected
                .iter()
                .enumerate()
                .map(|(output, value)| {
                    let evaluation = field_from_i64(*value) + Fr::from((output + 5) as u64) * x;
                    ProtocolRobustShare::new(evaluation, party_id, 1)
                })
                .collect::<Vec<_>>();
            let mut plaintext = Vec::new();
            shares.serialize_compressed(&mut plaintext).unwrap();
            let (encapped_key, ciphertext) = single_shot_seal::<AeadImpl, KdfImpl, KemImpl, _>(
                &OpModeS::Base,
                &hpke_public,
                &output_encryption_info(&execution_id),
                &plaintext,
                b"",
                &mut rng,
            )
            .unwrap();
            encrypted.push(EncryptedOutputShare {
                encapped_key: encapped_key.to_bytes().to_vec(),
                ciphertext,
            });
        }

        assert_eq!(
            decrypt_fields_core(&client.core, &execution_id, expected.len(), &encrypted).unwrap(),
            expected.map(field_from_i64)
        );
    }

    #[test]
    fn authentication_message_is_signed_by_the_client_identity() {
        let secret = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let client = StoffelWasmClient::from_secret_key(secret, 5, 1).unwrap();
        let execution = [3u8; 32];
        let message = authentication_message("browser_round", &execution, 4, b"body");
        let signature: Signature = client.core.signing_key.sign(&message);
        let verifier = VerifyingKey::from_sec1_bytes(&client.core.public_key).unwrap();
        verifier.verify(&message, &signature).unwrap();
    }

    #[test]
    fn signed_field_values_decode_both_directions() {
        for expected in [i64::MIN, -100, -1, 0, 1, 100, i64::MAX] {
            assert_eq!(field_to_i64(field_from_i64(expected)).unwrap(), expected);
        }
    }

    #[test]
    fn typed_inputs_cover_native_scalar_client_values() {
        let cases = [
            (
                TypedClientInput {
                    share_type: ClientScalarType::Boolean,
                    value: ClientScalarValue::Boolean(true),
                },
                Fr::from(1u64),
            ),
            (
                TypedClientInput {
                    share_type: ClientScalarType::Boolean,
                    value: ClientScalarValue::SignedInteger(0),
                },
                Fr::from(0u64),
            ),
            (
                TypedClientInput {
                    share_type: ClientScalarType::SignedInteger { bit_length: 64 },
                    value: ClientScalarValue::SignedInteger(-91),
                },
                field_from_i64(-91),
            ),
            (
                TypedClientInput {
                    share_type: ClientScalarType::UnsignedInteger { bit_length: 16 },
                    value: ClientScalarValue::UnsignedInteger(65_535),
                },
                Fr::from(65_535u64),
            ),
            (
                TypedClientInput {
                    share_type: ClientScalarType::FixedPoint {
                        total_bits: 64,
                        fractional_bits: 16,
                    },
                    value: ClientScalarValue::FixedPoint(1.5),
                },
                field_from_i64(98_304),
            ),
            (
                TypedClientInput {
                    share_type: ClientScalarType::FixedPoint {
                        total_bits: 32,
                        fractional_bits: 8,
                    },
                    value: ClientScalarValue::SignedInteger(-2),
                },
                field_from_i64(-512),
            ),
        ];

        for (input, expected) in cases {
            assert_eq!(typed_input_to_field(&input).unwrap(), expected);
        }
    }

    #[test]
    fn typed_outputs_preserve_semantic_types() {
        assert_eq!(
            field_to_typed_value(Fr::from(2u64), ClientScalarType::Boolean).unwrap(),
            ClientScalarValue::Boolean(true)
        );
        assert_eq!(
            field_to_typed_value(
                field_from_i64(i64::MIN),
                ClientScalarType::SignedInteger { bit_length: 64 }
            )
            .unwrap(),
            ClientScalarValue::SignedInteger(i64::MIN)
        );
        assert_eq!(
            field_to_typed_value(
                Fr::from(u64::MAX),
                ClientScalarType::UnsignedInteger { bit_length: 64 }
            )
            .unwrap(),
            ClientScalarValue::UnsignedInteger(u64::MAX)
        );
        assert_eq!(
            field_to_typed_value(
                field_from_i64(-32_768),
                ClientScalarType::FixedPoint {
                    total_bits: 64,
                    fractional_bits: 16,
                }
            )
            .unwrap(),
            ClientScalarValue::FixedPoint(-0.5)
        );
    }

    #[test]
    fn typed_inputs_reject_range_and_kind_mismatches() {
        let too_wide = TypedClientInput {
            share_type: ClientScalarType::UnsignedInteger { bit_length: 8 },
            value: ClientScalarValue::UnsignedInteger(256),
        };
        assert!(typed_input_to_field(&too_wide).is_err());

        let negative_unsigned = TypedClientInput {
            share_type: ClientScalarType::UnsignedInteger { bit_length: 64 },
            value: ClientScalarValue::SignedInteger(-1),
        };
        assert!(typed_input_to_field(&negative_unsigned).is_err());

        // This intentionally mirrors the native client's compatibility path:
        // unsigned values supplied for a signed share are accepted when they
        // fit in i64, including the one-bit representation used for booleans.
        let bool_as_unsigned = TypedClientInput {
            share_type: ClientScalarType::Boolean,
            value: ClientScalarValue::UnsignedInteger(1),
        };
        assert_eq!(
            typed_input_to_field(&bool_as_unsigned).unwrap(),
            Fr::from(1u64)
        );

        assert!(scalar_share_type(ClientScalarType::SignedInteger { bit_length: 1 }).is_err());
        assert!(scalar_share_type(ClientScalarType::UnsignedInteger { bit_length: 0 }).is_err());
    }

    #[test]
    fn canonical_field_input_accepts_the_full_scalar_range_only() {
        let field_bytes = Fr::MODULUS_BIT_SIZE.div_ceil(8) as usize;
        let value = Fr::from(123u64);
        let encoded = value.into_bigint().to_bytes_be();
        let mut canonical = vec![0u8; field_bytes];
        canonical[field_bytes - encoded.len()..].copy_from_slice(&encoded);
        assert_eq!(canonical_field_from_be_bytes(&canonical).unwrap(), value);

        let modulus = Fr::MODULUS.to_bytes_be();
        let mut non_canonical = vec![0u8; field_bytes];
        non_canonical[field_bytes - modulus.len()..].copy_from_slice(&modulus);
        assert!(canonical_field_from_be_bytes(&non_canonical).is_err());
        assert!(canonical_field_from_be_bytes(&canonical[1..]).is_err());
    }

    #[test]
    fn nonce_sequences_are_shared_per_execution_and_concurrent_between_them() {
        let counters = RefCell::new(HashMap::new());
        let first = [1u8; 32];
        let second = [2u8; 32];

        assert_eq!(next_nonce(&counters, first).unwrap(), 1);
        assert_eq!(next_nonce(&counters, second).unwrap(), 1);
        assert_eq!(next_nonce(&counters, first).unwrap(), 2);
        assert_eq!(next_nonce(&counters, second).unwrap(), 2);
    }

    #[test]
    fn resumed_execution_never_rolls_a_nonce_backward() {
        let secret = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let client = StoffelWasmClient::from_secret_key(secret, 5, 1).unwrap();
        let id = "03".repeat(32);

        let handle = client.resume_execution(&id, 41).unwrap();
        assert_eq!(handle.current_nonce(), 41);
        assert_eq!(next_nonce(&client.nonces, handle.execution_id).unwrap(), 42);

        let resumed_with_stale_storage = client.resume_execution(&id, 10).unwrap();
        assert_eq!(resumed_with_stale_storage.current_nonce(), 42);
    }
}
