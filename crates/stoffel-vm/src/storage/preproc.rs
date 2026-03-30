//! Persistent preprocessing material storage.
//!
//! Stores MPC preprocessing material (Beaver triples, random shares, etc.)
//! keyed by program hash and MPC parameters. Backed by LMDB via the `heed`
//! crate for memory-mapped reads and ACID write transactions.

use crate::net::curve::MpcFieldKind;
use ark_ff::FftField;
use ark_serialize::{Compress, Validate};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use stoffelmpc_mpc::honeybadger::{
    fpmul::f256::F2_8,
    robust_interpolate::robust_interpolate::RobustShare,
    triple_gen::ShamirBeaverTriple,
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum PreprocStoreError {
    #[error("LMDB: {0}")]
    Lmdb(String),
    #[error("serialization: {0}")]
    Serialization(String),
    #[error("deserialization: {0}")]
    Deserialization(String),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("not found")]
    NotFound,
    #[error("insufficient material: need {need}, available {available}")]
    Insufficient { need: u32, available: u32 },
    #[error("task join: {0}")]
    Join(String),
}

impl From<heed::Error> for PreprocStoreError {
    fn from(e: heed::Error) -> Self {
        Self::Lmdb(e.to_string())
    }
}

impl From<bincode::Error> for PreprocStoreError {
    fn from(e: bincode::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}

impl From<tokio::task::JoinError> for PreprocStoreError {
    fn from(e: tokio::task::JoinError) -> Self {
        Self::Join(e.to_string())
    }
}

// Allows engines that use Result<_, String> to convert seamlessly.
impl From<PreprocStoreError> for String {
    fn from(e: PreprocStoreError) -> Self {
        e.to_string()
    }
}

// ---------------------------------------------------------------------------
// Key types
// ---------------------------------------------------------------------------

/// Kind of preprocessing material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MaterialKind {
    BeaverTriple = 0,
    RandomShare = 1,
    PRandBit = 2,
    PRandInt = 3,
}

/// Identifies a stored preprocessing blob.
///
/// Construct via [`PreprocKey::new`] to reduce field boilerplate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PreprocKey {
    pub program_hash: [u8; 32],
    pub field_kind: MpcFieldKind,
    pub n: usize,
    pub t: usize,
    pub party_id: usize,
    pub kind: MaterialKind,
}

impl PreprocKey {
    pub fn new(
        program_hash: [u8; 32],
        field_kind: MpcFieldKind,
        n: usize,
        t: usize,
        party_id: usize,
        kind: MaterialKind,
    ) -> Self {
        Self { program_hash, field_kind, n, t, party_id, kind }
    }

    /// Build a key with a different material kind, sharing all other fields.
    pub fn with_kind(&self, kind: MaterialKind) -> Self {
        Self { kind, ..self.clone() }
    }

    /// Encode as a compact byte key for LMDB lookups.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(49);
        buf.extend_from_slice(b"pp:");
        buf.extend_from_slice(&self.program_hash);
        buf.push(field_kind_tag(self.field_kind));
        buf.extend_from_slice(&(self.n as u32).to_le_bytes());
        buf.extend_from_slice(&(self.t as u32).to_le_bytes());
        buf.extend_from_slice(&(self.party_id as u32).to_le_bytes());
        buf.push(self.kind as u8);
        buf
    }

    /// Encode the metadata key (distinct from the data key).
    fn meta_key(&self) -> Vec<u8> {
        let mut k = self.encode();
        k.push(b'm');
        k
    }
}

fn field_kind_tag(fk: MpcFieldKind) -> u8 {
    match fk {
        MpcFieldKind::Bls12_381Fr => 0,
        MpcFieldKind::Bn254Fr => 1,
        MpcFieldKind::Curve25519Fr => 2,
    }
}

/// Metadata stored separately from the raw data so that `reserve()` and
/// `available()` avoid deserializing the (potentially large) data blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreprocMeta {
    pub count: u32,
    pub consumed: u32,
    pub item_size: u32,
}

impl PreprocMeta {
    pub fn available(&self) -> u32 {
        self.count.saturating_sub(self.consumed)
    }
}

/// Serialized preprocessing material with metadata + data.
#[derive(Debug, Clone)]
pub struct PreprocBlob {
    pub meta: PreprocMeta,
    pub data: Vec<u8>,
}

impl PreprocBlob {
    pub fn new(data: Vec<u8>, item_size: u32, count: u32) -> Self {
        Self {
            meta: PreprocMeta { count, consumed: 0, item_size },
            data,
        }
    }

    /// Byte slice of unconsumed items.
    pub fn unconsumed_data(&self) -> &[u8] {
        let offset = self.meta.consumed as usize * self.meta.item_size as usize;
        &self.data[offset..]
    }

    /// Slice a single item at the given index.
    pub fn item_data(&self, index: u32) -> Option<&[u8]> {
        let is = self.meta.item_size as usize;
        let start = index as usize * is;
        let end = start + is;
        if end <= self.data.len() { Some(&self.data[start..end]) } else { None }
    }
}

// ---------------------------------------------------------------------------
// Storage trait
// ---------------------------------------------------------------------------

/// Async trait for preprocessing material persistence.
#[async_trait::async_trait]
pub trait PreprocStore: Send + Sync + 'static {
    async fn store(&self, key: &PreprocKey, blob: &PreprocBlob) -> Result<(), PreprocStoreError>;
    async fn load(&self, key: &PreprocKey) -> Result<Option<PreprocBlob>, PreprocStoreError>;

    /// Atomically advance the consumed cursor. Returns new consumed count.
    async fn reserve(&self, key: &PreprocKey, n: u32) -> Result<u32, PreprocStoreError>;

    /// Items available (count - consumed). Returns 0 if not stored.
    async fn available(&self, key: &PreprocKey) -> Result<u32, PreprocStoreError>;
    async fn exists(&self, key: &PreprocKey) -> Result<bool, PreprocStoreError>;
    async fn delete(&self, key: &PreprocKey) -> Result<(), PreprocStoreError>;

    /// Store an opaque byte blob under a namespaced key (for reservations etc.).
    async fn store_blob(&self, ns: &[u8], key: &[u8], data: &[u8]) -> Result<(), PreprocStoreError>;
    /// Load an opaque byte blob by namespaced key.
    async fn load_blob(&self, ns: &[u8], key: &[u8]) -> Result<Option<Vec<u8>>, PreprocStoreError>;
}

// ---------------------------------------------------------------------------
// LMDB actor backend
// ---------------------------------------------------------------------------

type RmwFn = Box<dyn FnOnce(Option<&[u8]>) -> Result<Option<Vec<u8>>, PreprocStoreError> + Send>;

/// Request sent to the LMDB actor thread.
enum DbRequest {
    PutMulti { pairs: Vec<(Vec<u8>, Vec<u8>)>, reply: tokio::sync::oneshot::Sender<Result<(), PreprocStoreError>> },
    Get { key: Vec<u8>, reply: tokio::sync::oneshot::Sender<Result<Option<Vec<u8>>, PreprocStoreError>> },
    Delete { keys: Vec<Vec<u8>>, reply: tokio::sync::oneshot::Sender<Result<(), PreprocStoreError>> },
    Rmw { key: Vec<u8>, f: RmwFn, reply: tokio::sync::oneshot::Sender<Result<Option<Vec<u8>>, PreprocStoreError>> },
}

/// LMDB-backed preprocessing store using the actor pattern.
///
/// A dedicated `std::thread` owns the `heed::Env` and processes all
/// database operations sequentially.  Callers communicate via an `mpsc`
/// channel and await `oneshot` replies, guaranteeing that LMDB never
/// touches a tokio worker thread.
///
/// Metadata and data are stored under separate keys so that `reserve()` and
/// `available()` never touch the (potentially large) data blob.
pub struct LmdbPreprocStore {
    tx: std::sync::mpsc::Sender<DbRequest>,
    _thread: std::thread::JoinHandle<()>,
}

impl LmdbPreprocStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PreprocStoreError> {
        std::fs::create_dir_all(path.as_ref())?;
        let env = unsafe {
            heed::EnvOpenOptions::new()
                .map_size(1024 * 1024 * 1024) // 1 GB
                .max_dbs(1)
                .open(path.as_ref())
        }?;
        let mut wtxn = env.write_txn()?;
        let db: heed::Database<heed::types::Bytes, heed::types::Bytes> =
            env.create_database(&mut wtxn, Some("store"))?;
        wtxn.commit()?;

        let (tx, rx) = std::sync::mpsc::channel::<DbRequest>();
        let thread = std::thread::Builder::new()
            .name("lmdb-actor".into())
            .spawn(move || Self::actor_loop(env, db, rx))
            .map_err(PreprocStoreError::Io)?;

        Ok(Self { tx, _thread: thread })
    }

    pub fn default_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| ".".into())
            .join(".stoffel")
            .join("store")
    }

    fn actor_loop(
        env: heed::Env,
        db: heed::Database<heed::types::Bytes, heed::types::Bytes>,
        rx: std::sync::mpsc::Receiver<DbRequest>,
    ) {
        while let Ok(req) = rx.recv() {
            match req {
                DbRequest::PutMulti { pairs, reply } => {
                    let r = (|| {
                        let mut wtxn = env.write_txn()?;
                        for (k, v) in &pairs {
                            db.put(&mut wtxn, k, v)?;
                        }
                        wtxn.commit()?;
                        Ok(())
                    })();
                    let _ = reply.send(r);
                }
                DbRequest::Get { key, reply } => {
                    let r = (|| {
                        let rtxn = env.read_txn()?;
                        Ok(db.get(&rtxn, &key)?.map(|v| v.to_vec()))
                    })();
                    let _ = reply.send(r);
                }
                DbRequest::Delete { keys, reply } => {
                    let r = (|| {
                        let mut wtxn = env.write_txn()?;
                        for k in &keys {
                            db.delete(&mut wtxn, k)?;
                        }
                        wtxn.commit()?;
                        Ok(())
                    })();
                    let _ = reply.send(r);
                }
                DbRequest::Rmw { key, f, reply } => {
                    let r = (|| {
                        let mut wtxn = env.write_txn()?;
                        let current = db.get(&wtxn, &key)?;
                        let result = f(current)?;
                        if let Some(new_val) = &result {
                            db.put(&mut wtxn, &key, new_val)?;
                        }
                        wtxn.commit()?;
                        Ok(result)
                    })();
                    let _ = reply.send(r);
                }
            }
        }
    }

    async fn send(&self, req: DbRequest) -> Result<(), PreprocStoreError> {
        self.tx.send(req).map_err(|_| PreprocStoreError::Lmdb("actor thread gone".into()))
    }

    async fn get(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>, PreprocStoreError> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        self.send(DbRequest::Get { key, reply: reply_tx }).await?;
        reply_rx.await.map_err(|_| PreprocStoreError::Lmdb("actor reply dropped".into()))?
    }

    async fn put_multi(&self, pairs: Vec<(Vec<u8>, Vec<u8>)>) -> Result<(), PreprocStoreError> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        self.send(DbRequest::PutMulti { pairs, reply: reply_tx }).await?;
        reply_rx.await.map_err(|_| PreprocStoreError::Lmdb("actor reply dropped".into()))?
    }

    async fn delete_keys(&self, keys: Vec<Vec<u8>>) -> Result<(), PreprocStoreError> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        self.send(DbRequest::Delete { keys, reply: reply_tx }).await?;
        reply_rx.await.map_err(|_| PreprocStoreError::Lmdb("actor reply dropped".into()))?
    }

    async fn rmw(
        &self,
        key: Vec<u8>,
        f: impl FnOnce(Option<&[u8]>) -> Result<Option<Vec<u8>>, PreprocStoreError> + Send + 'static,
    ) -> Result<Option<Vec<u8>>, PreprocStoreError> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        self.send(DbRequest::Rmw { key, f: Box::new(f), reply: reply_tx }).await?;
        reply_rx.await.map_err(|_| PreprocStoreError::Lmdb("actor reply dropped".into()))?
    }
}

#[async_trait::async_trait]
impl PreprocStore for LmdbPreprocStore {
    async fn store(&self, key: &PreprocKey, blob: &PreprocBlob) -> Result<(), PreprocStoreError> {
        let meta_v = bincode::serialize(&blob.meta)?;
        self.put_multi(vec![
            (key.meta_key(), meta_v),
            (key.encode(), blob.data.clone()),
        ]).await
    }

    async fn load(&self, key: &PreprocKey) -> Result<Option<PreprocBlob>, PreprocStoreError> {
        let meta_bytes = match self.get(key.meta_key()).await? {
            Some(b) => b,
            None => return Ok(None),
        };
        let meta: PreprocMeta = bincode::deserialize(&meta_bytes)?;
        let data = self.get(key.encode()).await?.ok_or(PreprocStoreError::NotFound)?;
        Ok(Some(PreprocBlob { meta, data }))
    }

    async fn reserve(&self, key: &PreprocKey, n: u32) -> Result<u32, PreprocStoreError> {
        let result = self.rmw(key.meta_key(), move |raw| {
            let raw = raw.ok_or(PreprocStoreError::NotFound)?;
            let mut meta: PreprocMeta = bincode::deserialize(raw)?;
            if meta.consumed + n > meta.count {
                return Err(PreprocStoreError::Insufficient {
                    need: n,
                    available: meta.available(),
                });
            }
            meta.consumed += n;
            let v = bincode::serialize(&meta)?;
            Ok(Some(v))
        }).await?;
        // Decode the written-back metadata to return consumed count
        if let Some(v) = result {
            let meta: PreprocMeta = bincode::deserialize(&v)?;
            Ok(meta.consumed)
        } else {
            Err(PreprocStoreError::NotFound)
        }
    }

    async fn available(&self, key: &PreprocKey) -> Result<u32, PreprocStoreError> {
        match self.get(key.meta_key()).await? {
            Some(raw) => {
                let meta: PreprocMeta = bincode::deserialize(&raw)?;
                Ok(meta.available())
            }
            None => Ok(0),
        }
    }

    async fn exists(&self, key: &PreprocKey) -> Result<bool, PreprocStoreError> {
        Ok(self.get(key.meta_key()).await?.is_some())
    }

    async fn delete(&self, key: &PreprocKey) -> Result<(), PreprocStoreError> {
        self.delete_keys(vec![key.meta_key(), key.encode()]).await
    }

    async fn store_blob(&self, ns: &[u8], key: &[u8], data: &[u8]) -> Result<(), PreprocStoreError> {
        let mut k = ns.to_vec();
        k.extend_from_slice(key);
        self.put_multi(vec![(k, data.to_vec())]).await
    }

    async fn load_blob(&self, ns: &[u8], key: &[u8]) -> Result<Option<Vec<u8>>, PreprocStoreError> {
        let mut k = ns.to_vec();
        k.extend_from_slice(key);
        self.get(k).await
    }
}

// ---------------------------------------------------------------------------
// Serialization helpers (HoneyBadger)
// ---------------------------------------------------------------------------

fn write_robust_share<F: FftField>(share: &RobustShare<F>, buf: &mut Vec<u8>) -> Result<(), PreprocStoreError> {
    share.share[0]
        .serialize_with_mode(&mut *buf, Compress::Yes)
        .map_err(|e| PreprocStoreError::Serialization(e.to_string()))?;
    buf.extend_from_slice(&(share.id as u64).to_le_bytes());
    buf.extend_from_slice(&(share.degree as u64).to_le_bytes());
    Ok(())
}

fn robust_share_size<F: FftField>() -> usize {
    F::default().serialized_size(Compress::Yes) + 16
}

fn read_robust_share<F: FftField>(data: &[u8], item_size: usize) -> Result<RobustShare<F>, PreprocStoreError> {
    let field_size = item_size - 16;
    // Data originates from our own serialization so subgroup checks are not required.
    let elem = F::deserialize_with_mode(&data[..field_size], Compress::Yes, Validate::No)
        .map_err(|e| PreprocStoreError::Deserialization(e.to_string()))?;
    let id = u64::from_le_bytes(
        data[field_size..field_size + 8].try_into()
            .map_err(|_| PreprocStoreError::Deserialization("bad id bytes".into()))?,
    ) as usize;
    let degree = u64::from_le_bytes(
        data[field_size + 8..field_size + 16].try_into()
            .map_err(|_| PreprocStoreError::Deserialization("bad degree bytes".into()))?,
    ) as usize;
    Ok(RobustShare::new(elem, id, degree))
}

pub fn serialize_robust_shares<F: FftField>(
    shares: &[RobustShare<F>],
) -> Result<(Vec<u8>, u32), PreprocStoreError> {
    let is = robust_share_size::<F>();
    let mut buf = Vec::with_capacity(shares.len() * is);
    for s in shares {
        write_robust_share(s, &mut buf)?;
    }
    Ok((buf, is as u32))
}

pub fn deserialize_robust_shares<F: FftField>(
    data: &[u8],
    item_size: u32,
    offset: u32,
) -> Result<Vec<RobustShare<F>>, PreprocStoreError> {
    let is = item_size as usize;
    let start = offset as usize * is;
    let mut shares = Vec::new();
    let mut pos = start;
    while pos + is <= data.len() {
        shares.push(read_robust_share::<F>(&data[pos..], is)?);
        pos += is;
    }
    Ok(shares)
}

/// Deserialize a single `RobustShare<F>` at a byte offset.
pub fn deserialize_one_robust_share<F: FftField>(
    data: &[u8],
    item_size: u32,
    index: u32,
) -> Result<RobustShare<F>, PreprocStoreError> {
    let is = item_size as usize;
    let start = index as usize * is;
    if start + is > data.len() {
        return Err(PreprocStoreError::Deserialization(format!(
            "index {index} out of range (data len {})", data.len()
        )));
    }
    read_robust_share::<F>(&data[start..], is)
}

pub fn serialize_beaver_triples<F: FftField>(
    triples: &[ShamirBeaverTriple<F>],
) -> Result<(Vec<u8>, u32), PreprocStoreError> {
    let share_size = robust_share_size::<F>();
    let triple_size = share_size * 3;
    let mut buf = Vec::with_capacity(triples.len() * triple_size);
    for t in triples {
        write_robust_share(&t.a, &mut buf)?;
        write_robust_share(&t.b, &mut buf)?;
        write_robust_share(&t.mult, &mut buf)?;
    }
    Ok((buf, triple_size as u32))
}

pub fn deserialize_beaver_triples<F: FftField>(
    data: &[u8],
    item_size: u32,
    offset: u32,
) -> Result<Vec<ShamirBeaverTriple<F>>, PreprocStoreError> {
    let is = item_size as usize;
    let share_size = robust_share_size::<F>();
    let start = offset as usize * is;
    let mut triples = Vec::new();
    let mut pos = start;
    while pos + is <= data.len() {
        let a = read_robust_share::<F>(&data[pos..], share_size)?;
        let b = read_robust_share::<F>(&data[pos + share_size..], share_size)?;
        let mult = read_robust_share::<F>(&data[pos + 2 * share_size..], share_size)?;
        triples.push(ShamirBeaverTriple::new(a, b, mult));
        pos += is;
    }
    Ok(triples)
}

pub fn serialize_prandbit_shares<F: FftField>(
    shares: &[(RobustShare<F>, F2_8)],
) -> Result<(Vec<u8>, u32), PreprocStoreError> {
    let share_size = robust_share_size::<F>();
    let item_size = share_size + 1;
    let mut buf = Vec::with_capacity(shares.len() * item_size);
    for (s, f) in shares {
        write_robust_share(s, &mut buf)?;
        buf.push(f.0);
    }
    Ok((buf, item_size as u32))
}

pub fn deserialize_prandbit_shares<F: FftField>(
    data: &[u8],
    item_size: u32,
    offset: u32,
) -> Result<Vec<(RobustShare<F>, F2_8)>, PreprocStoreError> {
    let is = item_size as usize;
    let share_size = robust_share_size::<F>();
    let start = offset as usize * is;
    let mut result = Vec::new();
    let mut pos = start;
    while pos + is <= data.len() {
        let share = read_robust_share::<F>(&data[pos..], share_size)?;
        let f2_8 = F2_8(data[pos + share_size]);
        result.push((share, f2_8));
        pos += is;
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Serialization helpers (AVSS)
// ---------------------------------------------------------------------------

pub fn serialize_feldman_shares<F, G>(
    shares: &[stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare<F, G>],
) -> Result<(Vec<u8>, u32), PreprocStoreError>
where
    F: FftField,
    G: ark_ec::CurveGroup<ScalarField = F>,
{
    use ark_serialize::CanonicalSerialize;
    if shares.is_empty() {
        return Ok((vec![], 0));
    }
    let item_size = shares[0].serialized_size(Compress::Yes);
    let mut buf = Vec::with_capacity(shares.len() * item_size);
    for s in shares {
        s.serialize_with_mode(&mut buf, Compress::Yes)
            .map_err(|e| PreprocStoreError::Serialization(e.to_string()))?;
    }
    Ok((buf, item_size as u32))
}

pub fn deserialize_feldman_shares<F, G>(
    data: &[u8],
    item_size: u32,
    offset: u32,
) -> Result<Vec<stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare<F, G>>, PreprocStoreError>
where
    F: FftField,
    G: ark_ec::CurveGroup<ScalarField = F>,
{
    use ark_serialize::CanonicalDeserialize;
    let is = item_size as usize;
    let start = offset as usize * is;
    let mut shares = Vec::new();
    let mut pos = start;
    while pos + is <= data.len() {
        // Data originates from our own serialization so subgroup checks are not required.
        let share = stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare::<F, G>::deserialize_with_mode(
            &data[pos..pos + is], Compress::Yes, Validate::No,
        ).map_err(|e| PreprocStoreError::Deserialization(e.to_string()))?;
        shares.push(share);
        pos += is;
    }
    Ok(shares)
}

pub fn serialize_avss_triples<F, G>(
    triples: &[stoffelmpc_mpc::avss_mpc::triple_gen::BeaverTriple<F, G>],
) -> Result<(Vec<u8>, u32), PreprocStoreError>
where
    F: FftField,
    G: ark_ec::CurveGroup<ScalarField = F>,
{
    use ark_serialize::CanonicalSerialize;
    if triples.is_empty() {
        return Ok((vec![], 0));
    }
    let share_size = triples[0].a.serialized_size(Compress::Yes);
    let triple_size = share_size * 3;
    let mut buf = Vec::with_capacity(triples.len() * triple_size);
    for t in triples {
        t.a.serialize_with_mode(&mut buf, Compress::Yes)
            .map_err(|e| PreprocStoreError::Serialization(e.to_string()))?;
        t.b.serialize_with_mode(&mut buf, Compress::Yes)
            .map_err(|e| PreprocStoreError::Serialization(e.to_string()))?;
        t.c.serialize_with_mode(&mut buf, Compress::Yes)
            .map_err(|e| PreprocStoreError::Serialization(e.to_string()))?;
    }
    Ok((buf, triple_size as u32))
}

pub fn deserialize_avss_triples<F, G>(
    data: &[u8],
    item_size: u32,
    offset: u32,
) -> Result<Vec<stoffelmpc_mpc::avss_mpc::triple_gen::BeaverTriple<F, G>>, PreprocStoreError>
where
    F: FftField,
    G: ark_ec::CurveGroup<ScalarField = F>,
{
    use ark_serialize::CanonicalDeserialize;
    let is = item_size as usize;
    let share_size = is / 3;
    let start = offset as usize * is;
    let mut triples = Vec::new();
    let mut pos = start;
    while pos + is <= data.len() {
        // Data originates from our own serialization so subgroup checks are not required.
        let a = stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare::<F, G>::deserialize_with_mode(
            &data[pos..pos + share_size], Compress::Yes, Validate::No,
        ).map_err(|e| PreprocStoreError::Deserialization(e.to_string()))?;
        let b = stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare::<F, G>::deserialize_with_mode(
            &data[pos + share_size..pos + 2 * share_size], Compress::Yes, Validate::No,
        ).map_err(|e| PreprocStoreError::Deserialization(e.to_string()))?;
        let c = stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare::<F, G>::deserialize_with_mode(
            &data[pos + 2 * share_size..pos + 3 * share_size], Compress::Yes, Validate::No,
        ).map_err(|e| PreprocStoreError::Deserialization(e.to_string()))?;
        triples.push(stoffelmpc_mpc::avss_mpc::triple_gen::BeaverTriple { a, b, c });
        pos += is;
    }
    Ok(triples)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::UniformRand;
    use ark_std::rand::SeedableRng;

    fn random_share(rng: &mut impl ark_std::rand::Rng) -> RobustShare<Fr> {
        RobustShare::new(Fr::rand(rng), 1, 2)
    }

    fn random_triple(rng: &mut impl ark_std::rand::Rng) -> ShamirBeaverTriple<Fr> {
        ShamirBeaverTriple::new(random_share(rng), random_share(rng), random_share(rng))
    }

    #[test]
    fn robust_share_roundtrip() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42);
        let shares: Vec<_> = (0..5).map(|_| random_share(&mut rng)).collect();
        let (data, item_size) = serialize_robust_shares::<Fr>(&shares).unwrap();
        let decoded = deserialize_robust_shares::<Fr>(&data, item_size, 0).unwrap();
        assert_eq!(shares.len(), decoded.len());
        for (a, b) in shares.iter().zip(decoded.iter()) {
            assert_eq!(a.share[0], b.share[0]);
            assert_eq!(a.id, b.id);
            assert_eq!(a.degree, b.degree);
        }
    }

    #[test]
    fn robust_share_skip_consumed() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42);
        let shares: Vec<_> = (0..10).map(|_| random_share(&mut rng)).collect();
        let (data, item_size) = serialize_robust_shares::<Fr>(&shares).unwrap();
        let decoded = deserialize_robust_shares::<Fr>(&data, item_size, 3).unwrap();
        assert_eq!(decoded.len(), 7);
        assert_eq!(decoded[0].share[0], shares[3].share[0]);
    }

    #[test]
    fn single_share_read() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42);
        let shares: Vec<_> = (0..10).map(|_| random_share(&mut rng)).collect();
        let (data, item_size) = serialize_robust_shares::<Fr>(&shares).unwrap();
        let single = deserialize_one_robust_share::<Fr>(&data, item_size, 7).unwrap();
        assert_eq!(single.share[0], shares[7].share[0]);
    }

    #[test]
    fn beaver_triple_roundtrip() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42);
        let triples: Vec<_> = (0..4).map(|_| random_triple(&mut rng)).collect();
        let (data, item_size) = serialize_beaver_triples::<Fr>(&triples).unwrap();
        let decoded = deserialize_beaver_triples::<Fr>(&data, item_size, 0).unwrap();
        assert_eq!(triples.len(), decoded.len());
        for (a, b) in triples.iter().zip(decoded.iter()) {
            assert_eq!(a.a.share[0], b.a.share[0]);
            assert_eq!(a.b.share[0], b.b.share[0]);
            assert_eq!(a.mult.share[0], b.mult.share[0]);
        }
    }

    #[test]
    fn prandbit_roundtrip() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42);
        let shares: Vec<_> = (0..6)
            .map(|i| (random_share(&mut rng), F2_8(i as u8)))
            .collect();
        let (data, item_size) = serialize_prandbit_shares::<Fr>(&shares).unwrap();
        let decoded = deserialize_prandbit_shares::<Fr>(&data, item_size, 0).unwrap();
        assert_eq!(shares.len(), decoded.len());
        for (a, b) in shares.iter().zip(decoded.iter()) {
            assert_eq!(a.0.share[0], b.0.share[0]);
            assert_eq!(a.1, b.1);
        }
    }

    #[test]
    fn preproc_key_with_kind() {
        let base = PreprocKey::new([0xAB; 32], MpcFieldKind::Bn254Fr, 5, 2, 1, MaterialKind::BeaverTriple);
        let rs = base.with_kind(MaterialKind::RandomShare);
        assert_eq!(rs.program_hash, base.program_hash);
        assert_eq!(rs.kind, MaterialKind::RandomShare);
        assert_ne!(base.encode(), rs.encode());
    }

    #[tokio::test]
    async fn lmdb_store_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = LmdbPreprocStore::open(dir.path()).unwrap();

        let key = PreprocKey::new([0x01; 32], MpcFieldKind::Bn254Fr, 5, 2, 0, MaterialKind::RandomShare);
        let blob = PreprocBlob::new(vec![0xAA; 480], 48, 10);

        store.store(&key, &blob).await.unwrap();
        let loaded = store.load(&key).await.unwrap().unwrap();
        assert_eq!(loaded.meta.count, 10);
        assert_eq!(loaded.meta.consumed, 0);
        assert_eq!(loaded.meta.available(), 10);
        assert_eq!(loaded.data, blob.data);
    }

    #[tokio::test]
    async fn lmdb_reserve_metadata_only() {
        let dir = tempfile::tempdir().unwrap();
        let store = LmdbPreprocStore::open(dir.path()).unwrap();

        let key = PreprocKey::new([0x02; 32], MpcFieldKind::Bls12_381Fr, 3, 1, 0, MaterialKind::BeaverTriple);
        let blob = PreprocBlob::new(vec![0; 480], 48, 10);

        store.store(&key, &blob).await.unwrap();

        let consumed = store.reserve(&key, 4).await.unwrap();
        assert_eq!(consumed, 4);
        assert_eq!(store.available(&key).await.unwrap(), 6);

        let consumed = store.reserve(&key, 6).await.unwrap();
        assert_eq!(consumed, 10);
        assert_eq!(store.available(&key).await.unwrap(), 0);

        assert!(store.reserve(&key, 1).await.is_err());
    }

    #[tokio::test]
    async fn lmdb_blob_namespace() {
        let dir = tempfile::tempdir().unwrap();
        let store = LmdbPreprocStore::open(dir.path()).unwrap();

        store.store_blob(b"rsv:", b"key1", b"data1").await.unwrap();
        let loaded = store.load_blob(b"rsv:", b"key1").await.unwrap();
        assert_eq!(loaded, Some(b"data1".to_vec()));

        assert_eq!(store.load_blob(b"rsv:", b"missing").await.unwrap(), None);
    }
}
