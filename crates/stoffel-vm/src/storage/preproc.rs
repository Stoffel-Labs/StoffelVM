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
    fpmul::f256::Gf2568, robust_interpolate::robust_interpolate::RobustShare,
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
    #[error("{field} value {value} exceeds u32::MAX")]
    U32Overflow { field: &'static str, value: u64 },
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
/// Use [`PreprocKeyScope`] when deriving several material keys for the same
/// program/party namespace.
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
        Self {
            program_hash,
            field_kind,
            n,
            t,
            party_id,
            kind,
        }
    }

    /// Build a key with a different material kind, sharing all other fields.
    pub fn with_kind(&self, kind: MaterialKind) -> Self {
        Self {
            kind,
            ..self.clone()
        }
    }

    /// Encode as a compact byte key for LMDB lookups.
    pub fn encode(&self) -> Result<Vec<u8>, PreprocStoreError> {
        let mut buf = Vec::with_capacity(49);
        buf.extend_from_slice(b"pp:");
        buf.extend_from_slice(&self.program_hash);
        buf.push(field_kind_tag(self.field_kind));
        buf.extend_from_slice(&usize_to_u32(self.n, "preprocessing key n")?.to_le_bytes());
        buf.extend_from_slice(&usize_to_u32(self.t, "preprocessing key threshold")?.to_le_bytes());
        buf.extend_from_slice(
            &usize_to_u32(self.party_id, "preprocessing key party_id")?.to_le_bytes(),
        );
        buf.push(material_kind_tag(self.kind));
        Ok(buf)
    }

    /// Encode the metadata key (distinct from the data key).
    fn meta_key(&self) -> Result<Vec<u8>, PreprocStoreError> {
        let mut k = self.encode()?;
        k.push(b'm');
        Ok(k)
    }
}

/// Common namespace for preprocessing material keys belonging to one party.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PreprocKeyScope {
    pub program_hash: [u8; 32],
    pub field_kind: MpcFieldKind,
    pub n: usize,
    pub t: usize,
    pub party_id: usize,
}

impl PreprocKeyScope {
    pub fn new(
        program_hash: [u8; 32],
        field_kind: MpcFieldKind,
        n: usize,
        t: usize,
        party_id: usize,
    ) -> Self {
        Self {
            program_hash,
            field_kind,
            n,
            t,
            party_id,
        }
    }

    pub fn key(self, kind: MaterialKind) -> PreprocKey {
        PreprocKey::new(
            self.program_hash,
            self.field_kind,
            self.n,
            self.t,
            self.party_id,
            kind,
        )
    }

    pub fn beaver_triple(self) -> PreprocKey {
        self.key(MaterialKind::BeaverTriple)
    }

    pub fn random_share(self) -> PreprocKey {
        self.key(MaterialKind::RandomShare)
    }

    pub fn prand_bit(self) -> PreprocKey {
        self.key(MaterialKind::PRandBit)
    }

    pub fn prand_int(self) -> PreprocKey {
        self.key(MaterialKind::PRandInt)
    }
}

fn field_kind_tag(fk: MpcFieldKind) -> u8 {
    match fk {
        MpcFieldKind::Bls12_381Fr => 0,
        MpcFieldKind::Bn254Fr => 1,
        MpcFieldKind::Curve25519Fr => 2,
    }
}

fn material_kind_tag(kind: MaterialKind) -> u8 {
    match kind {
        MaterialKind::BeaverTriple => 0,
        MaterialKind::RandomShare => 1,
        MaterialKind::PRandBit => 2,
        MaterialKind::PRandInt => 3,
    }
}

fn usize_to_u32(value: usize, field: &'static str) -> Result<u32, PreprocStoreError> {
    u32::try_from(value).map_err(|_| PreprocStoreError::U32Overflow {
        field,
        value: u64::try_from(value).unwrap_or(u64::MAX),
    })
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
            meta: PreprocMeta {
                count,
                consumed: 0,
                item_size,
            },
            data,
        }
    }

    pub fn try_new(data: Vec<u8>, item_size: u32, count: usize) -> Result<Self, PreprocStoreError> {
        let count = usize_to_u32(count, "preprocessing item count")?;
        Ok(Self::new(data, item_size, count))
    }

    /// Byte slice of unconsumed items.
    pub fn unconsumed_data(&self) -> Result<&[u8], PreprocStoreError> {
        let offset = byte_offset(
            self.meta.consumed,
            self.meta.item_size,
            "preprocessing consumed offset",
        )?;
        self.data.get(offset..).ok_or_else(|| {
            PreprocStoreError::Deserialization(format!(
                "consumed offset {offset} out of range (data len {})",
                self.data.len()
            ))
        })
    }

    /// Slice a single item at the given index.
    pub fn item_data(&self, index: u32) -> Option<&[u8]> {
        let is = u32_to_usize(self.meta.item_size, "preprocessing item size").ok()?;
        let start = u32_to_usize(index, "preprocessing item index")
            .ok()?
            .checked_mul(is)?;
        let end = start.checked_add(is)?;
        if end <= self.data.len() {
            Some(&self.data[start..end])
        } else {
            None
        }
    }
}

pub fn u32_index(value: u64, field: &'static str) -> Result<u32, PreprocStoreError> {
    u32::try_from(value).map_err(|_| PreprocStoreError::U32Overflow { field, value })
}

fn u32_to_usize(value: u32, field: &'static str) -> Result<usize, PreprocStoreError> {
    usize::try_from(value).map_err(|_| PreprocStoreError::U32Overflow {
        field,
        value: u64::from(value),
    })
}

fn usize_to_u64(value: usize, field: &'static str) -> Result<u64, PreprocStoreError> {
    u64::try_from(value)
        .map_err(|_| PreprocStoreError::Serialization(format!("{field} {value} exceeds u64::MAX")))
}

fn u64_to_usize(value: u64, field: &'static str) -> Result<usize, PreprocStoreError> {
    usize::try_from(value).map_err(|_| {
        PreprocStoreError::Deserialization(format!("{field} {value} exceeds usize::MAX"))
    })
}

fn byte_offset(
    index: u32,
    item_size: u32,
    field: &'static str,
) -> Result<usize, PreprocStoreError> {
    let index = u32_to_usize(index, field)?;
    let item_size = u32_to_usize(item_size, "preprocessing item size")?;
    index.checked_mul(item_size).ok_or_else(|| {
        PreprocStoreError::Deserialization(format!(
            "{field} overflows usize: index={index}, item_size={item_size}"
        ))
    })
}

fn has_nonzero_item_size(
    data: &[u8],
    item_size: usize,
    field: &'static str,
) -> Result<bool, PreprocStoreError> {
    if item_size != 0 {
        return Ok(true);
    }
    if data.is_empty() {
        return Ok(false);
    }
    Err(PreprocStoreError::Deserialization(format!(
        "{field} item size is zero for non-empty data"
    )))
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
    async fn store_blob(&self, ns: &[u8], key: &[u8], data: &[u8])
        -> Result<(), PreprocStoreError>;
    /// Load an opaque byte blob by namespaced key.
    async fn load_blob(&self, ns: &[u8], key: &[u8]) -> Result<Option<Vec<u8>>, PreprocStoreError>;
}

// ---------------------------------------------------------------------------
// LMDB actor backend
// ---------------------------------------------------------------------------

type RmwFn = Box<dyn FnOnce(Option<&[u8]>) -> Result<Option<Vec<u8>>, PreprocStoreError> + Send>;

/// Request sent to the LMDB actor thread.
enum DbRequest {
    PutMulti {
        pairs: Vec<(Vec<u8>, Vec<u8>)>,
        reply: tokio::sync::oneshot::Sender<Result<(), PreprocStoreError>>,
    },
    Get {
        key: Vec<u8>,
        reply: tokio::sync::oneshot::Sender<Result<Option<Vec<u8>>, PreprocStoreError>>,
    },
    Delete {
        keys: Vec<Vec<u8>>,
        reply: tokio::sync::oneshot::Sender<Result<(), PreprocStoreError>>,
    },
    Rmw {
        key: Vec<u8>,
        f: RmwFn,
        reply: tokio::sync::oneshot::Sender<Result<Option<Vec<u8>>, PreprocStoreError>>,
    },
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

        Ok(Self {
            tx,
            _thread: thread,
        })
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
        self.tx
            .send(req)
            .map_err(|_| PreprocStoreError::Lmdb("actor thread gone".into()))
    }

    async fn get(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>, PreprocStoreError> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        self.send(DbRequest::Get {
            key,
            reply: reply_tx,
        })
        .await?;
        reply_rx
            .await
            .map_err(|_| PreprocStoreError::Lmdb("actor reply dropped".into()))?
    }

    async fn put_multi(&self, pairs: Vec<(Vec<u8>, Vec<u8>)>) -> Result<(), PreprocStoreError> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        self.send(DbRequest::PutMulti {
            pairs,
            reply: reply_tx,
        })
        .await?;
        reply_rx
            .await
            .map_err(|_| PreprocStoreError::Lmdb("actor reply dropped".into()))?
    }

    async fn delete_keys(&self, keys: Vec<Vec<u8>>) -> Result<(), PreprocStoreError> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        self.send(DbRequest::Delete {
            keys,
            reply: reply_tx,
        })
        .await?;
        reply_rx
            .await
            .map_err(|_| PreprocStoreError::Lmdb("actor reply dropped".into()))?
    }

    async fn rmw(
        &self,
        key: Vec<u8>,
        f: impl FnOnce(Option<&[u8]>) -> Result<Option<Vec<u8>>, PreprocStoreError> + Send + 'static,
    ) -> Result<Option<Vec<u8>>, PreprocStoreError> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        self.send(DbRequest::Rmw {
            key,
            f: Box::new(f),
            reply: reply_tx,
        })
        .await?;
        reply_rx
            .await
            .map_err(|_| PreprocStoreError::Lmdb("actor reply dropped".into()))?
    }
}

#[async_trait::async_trait]
impl PreprocStore for LmdbPreprocStore {
    async fn store(&self, key: &PreprocKey, blob: &PreprocBlob) -> Result<(), PreprocStoreError> {
        let meta_v = bincode::serialize(&blob.meta)?;
        self.put_multi(vec![
            (key.meta_key()?, meta_v),
            (key.encode()?, blob.data.clone()),
        ])
        .await
    }

    async fn load(&self, key: &PreprocKey) -> Result<Option<PreprocBlob>, PreprocStoreError> {
        let meta_bytes = match self.get(key.meta_key()?).await? {
            Some(b) => b,
            None => return Ok(None),
        };
        let meta: PreprocMeta = bincode::deserialize(&meta_bytes)?;
        let data = self
            .get(key.encode()?)
            .await?
            .ok_or(PreprocStoreError::NotFound)?;
        Ok(Some(PreprocBlob { meta, data }))
    }

    async fn reserve(&self, key: &PreprocKey, n: u32) -> Result<u32, PreprocStoreError> {
        let result = self
            .rmw(key.meta_key()?, move |raw| {
                let raw = raw.ok_or(PreprocStoreError::NotFound)?;
                let mut meta: PreprocMeta = bincode::deserialize(raw)?;
                let consumed =
                    meta.consumed
                        .checked_add(n)
                        .ok_or(PreprocStoreError::U32Overflow {
                            field: "preprocessing consumed count",
                            value: u64::from(meta.consumed) + u64::from(n),
                        })?;
                if consumed > meta.count {
                    return Err(PreprocStoreError::Insufficient {
                        need: n,
                        available: meta.available(),
                    });
                }
                meta.consumed = consumed;
                let v = bincode::serialize(&meta)?;
                Ok(Some(v))
            })
            .await?;
        // Decode the written-back metadata to return consumed count
        if let Some(v) = result {
            let meta: PreprocMeta = bincode::deserialize(&v)?;
            Ok(meta.consumed)
        } else {
            Err(PreprocStoreError::NotFound)
        }
    }

    async fn available(&self, key: &PreprocKey) -> Result<u32, PreprocStoreError> {
        match self.get(key.meta_key()?).await? {
            Some(raw) => {
                let meta: PreprocMeta = bincode::deserialize(&raw)?;
                Ok(meta.available())
            }
            None => Ok(0),
        }
    }

    async fn exists(&self, key: &PreprocKey) -> Result<bool, PreprocStoreError> {
        Ok(self.get(key.meta_key()?).await?.is_some())
    }

    async fn delete(&self, key: &PreprocKey) -> Result<(), PreprocStoreError> {
        self.delete_keys(vec![key.meta_key()?, key.encode()?]).await
    }

    async fn store_blob(
        &self,
        ns: &[u8],
        key: &[u8],
        data: &[u8],
    ) -> Result<(), PreprocStoreError> {
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

fn write_robust_share<F: FftField>(
    share: &RobustShare<F>,
    buf: &mut Vec<u8>,
) -> Result<(), PreprocStoreError> {
    share.share[0]
        .serialize_with_mode(&mut *buf, Compress::Yes)
        .map_err(|e| PreprocStoreError::Serialization(e.to_string()))?;
    buf.extend_from_slice(&usize_to_u64(share.id, "robust share id")?.to_le_bytes());
    buf.extend_from_slice(&usize_to_u64(share.degree, "robust share degree")?.to_le_bytes());
    Ok(())
}

fn robust_share_size<F: FftField>() -> usize {
    F::default().serialized_size(Compress::Yes) + 16
}

fn read_robust_share<F: FftField>(
    data: &[u8],
    item_size: usize,
) -> Result<RobustShare<F>, PreprocStoreError> {
    if item_size < 16 {
        return Err(PreprocStoreError::Deserialization(format!(
            "robust share item size {item_size} is too small"
        )));
    }
    let field_size = item_size - 16;
    // Data originates from our own serialization so subgroup checks are not required.
    let elem = F::deserialize_with_mode(&data[..field_size], Compress::Yes, Validate::No)
        .map_err(|e| PreprocStoreError::Deserialization(e.to_string()))?;
    let id = u64::from_le_bytes(
        data[field_size..field_size + 8]
            .try_into()
            .map_err(|_| PreprocStoreError::Deserialization("bad id bytes".into()))?,
    );
    let id = u64_to_usize(id, "robust share id")?;
    let degree = u64::from_le_bytes(
        data[field_size + 8..field_size + 16]
            .try_into()
            .map_err(|_| PreprocStoreError::Deserialization("bad degree bytes".into()))?,
    );
    let degree = u64_to_usize(degree, "robust share degree")?;
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
    Ok((buf, usize_to_u32(is, "robust share item size")?))
}

pub fn deserialize_robust_shares<F: FftField>(
    data: &[u8],
    item_size: u32,
    offset: u32,
) -> Result<Vec<RobustShare<F>>, PreprocStoreError> {
    let is = u32_to_usize(item_size, "robust share item size")?;
    if !has_nonzero_item_size(data, is, "robust share")? {
        return Ok(Vec::new());
    }
    let start = byte_offset(offset, item_size, "robust share offset")?;
    let mut shares = Vec::new();
    let mut pos = start;
    while let Some(end) = pos.checked_add(is).filter(|end| *end <= data.len()) {
        shares.push(read_robust_share::<F>(&data[pos..], is)?);
        pos = end;
    }
    Ok(shares)
}

/// Deserialize a single `RobustShare<F>` at a byte offset.
pub fn deserialize_one_robust_share<F: FftField>(
    data: &[u8],
    item_size: u32,
    index: u32,
) -> Result<RobustShare<F>, PreprocStoreError> {
    let is = u32_to_usize(item_size, "robust share item size")?;
    if is == 0 {
        return Err(PreprocStoreError::Deserialization(
            "robust share item size is zero".into(),
        ));
    }
    let start = byte_offset(index, item_size, "robust share index")?;
    if !matches!(start.checked_add(is), Some(end) if end <= data.len()) {
        return Err(PreprocStoreError::Deserialization(format!(
            "index {index} out of range (data len {})",
            data.len()
        )));
    }
    read_robust_share::<F>(&data[start..], is)
}

pub fn serialize_beaver_triples<F: FftField>(
    triples: &[ShamirBeaverTriple<F>],
) -> Result<(Vec<u8>, u32), PreprocStoreError> {
    let share_size = robust_share_size::<F>();
    let triple_size = share_size.checked_mul(3).ok_or_else(|| {
        PreprocStoreError::Serialization(format!(
            "beaver triple item size overflows usize: share_size={share_size}"
        ))
    })?;
    let mut buf = Vec::with_capacity(triples.len() * triple_size);
    for t in triples {
        write_robust_share(&t.a, &mut buf)?;
        write_robust_share(&t.b, &mut buf)?;
        write_robust_share(&t.mult, &mut buf)?;
    }
    Ok((buf, usize_to_u32(triple_size, "beaver triple item size")?))
}

pub fn deserialize_beaver_triples<F: FftField>(
    data: &[u8],
    item_size: u32,
    offset: u32,
) -> Result<Vec<ShamirBeaverTriple<F>>, PreprocStoreError> {
    let is = u32_to_usize(item_size, "beaver triple item size")?;
    if !has_nonzero_item_size(data, is, "beaver triple")? {
        return Ok(Vec::new());
    }
    let share_size = robust_share_size::<F>();
    let start = byte_offset(offset, item_size, "beaver triple offset")?;
    let mut triples = Vec::new();
    let mut pos = start;
    while let Some(end) = pos.checked_add(is).filter(|end| *end <= data.len()) {
        let a = read_robust_share::<F>(&data[pos..], share_size)?;
        let b = read_robust_share::<F>(&data[pos + share_size..], share_size)?;
        let mult = read_robust_share::<F>(&data[pos + 2 * share_size..], share_size)?;
        triples.push(ShamirBeaverTriple::new(a, b, mult));
        pos = end;
    }
    Ok(triples)
}

pub fn serialize_prandbit_shares<F: FftField>(
    shares: &[(RobustShare<F>, Gf2568)],
) -> Result<(Vec<u8>, u32), PreprocStoreError> {
    let share_size = robust_share_size::<F>();
    let item_size = share_size + 1;
    let mut buf = Vec::with_capacity(shares.len() * item_size);
    for (s, f) in shares {
        write_robust_share(s, &mut buf)?;
        buf.push(f.0);
    }
    Ok((buf, usize_to_u32(item_size, "prandbit item size")?))
}

pub fn deserialize_prandbit_shares<F: FftField>(
    data: &[u8],
    item_size: u32,
    offset: u32,
) -> Result<Vec<(RobustShare<F>, Gf2568)>, PreprocStoreError> {
    let is = u32_to_usize(item_size, "prandbit item size")?;
    if !has_nonzero_item_size(data, is, "prandbit")? {
        return Ok(Vec::new());
    }
    let share_size = robust_share_size::<F>();
    let start = byte_offset(offset, item_size, "prandbit offset")?;
    let mut result = Vec::new();
    let mut pos = start;
    while let Some(end) = pos.checked_add(is).filter(|end| *end <= data.len()) {
        let share = read_robust_share::<F>(&data[pos..], share_size)?;
        let f2_8 = Gf2568(data[pos + share_size]);
        result.push((share, f2_8));
        pos = end;
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
    Ok((buf, usize_to_u32(item_size, "feldman share item size")?))
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
    let is = u32_to_usize(item_size, "feldman share item size")?;
    if !has_nonzero_item_size(data, is, "feldman share")? {
        return Ok(Vec::new());
    }
    let start = byte_offset(offset, item_size, "feldman share offset")?;
    let mut shares = Vec::new();
    let mut pos = start;
    while let Some(end) = pos.checked_add(is).filter(|end| *end <= data.len()) {
        // Data originates from our own serialization so subgroup checks are not required.
        let share = stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare::<F, G>::deserialize_with_mode(
            &data[pos..end], Compress::Yes, Validate::No,
        ).map_err(|e| PreprocStoreError::Deserialization(e.to_string()))?;
        shares.push(share);
        pos = end;
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
    let triple_size = share_size.checked_mul(3).ok_or_else(|| {
        PreprocStoreError::Serialization(format!(
            "AVSS triple item size overflows usize: share_size={share_size}"
        ))
    })?;
    let mut buf = Vec::with_capacity(triples.len() * triple_size);
    for t in triples {
        t.a.serialize_with_mode(&mut buf, Compress::Yes)
            .map_err(|e| PreprocStoreError::Serialization(e.to_string()))?;
        t.b.serialize_with_mode(&mut buf, Compress::Yes)
            .map_err(|e| PreprocStoreError::Serialization(e.to_string()))?;
        t.c.serialize_with_mode(&mut buf, Compress::Yes)
            .map_err(|e| PreprocStoreError::Serialization(e.to_string()))?;
    }
    Ok((buf, usize_to_u32(triple_size, "AVSS triple item size")?))
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
    let is = u32_to_usize(item_size, "AVSS triple item size")?;
    if !has_nonzero_item_size(data, is, "AVSS triple")? {
        return Ok(Vec::new());
    }
    let share_size = is / 3;
    let start = byte_offset(offset, item_size, "AVSS triple offset")?;
    let mut triples = Vec::new();
    let mut pos = start;
    while let Some(end) = pos.checked_add(is).filter(|end| *end <= data.len()) {
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
        pos = end;
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
            .map(|i| (random_share(&mut rng), Gf2568(i as u8)))
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
        let base = PreprocKey::new(
            [0xAB; 32],
            MpcFieldKind::Bn254Fr,
            5,
            2,
            1,
            MaterialKind::BeaverTriple,
        );
        let rs = base.with_kind(MaterialKind::RandomShare);
        assert_eq!(rs.program_hash, base.program_hash);
        assert_eq!(rs.kind, MaterialKind::RandomShare);
        assert_ne!(base.encode().unwrap(), rs.encode().unwrap());
    }

    #[test]
    fn preproc_key_scope_preserves_shared_key_namespace() {
        let scope = PreprocKeyScope::new([0xCD; 32], MpcFieldKind::Bls12_381Fr, 7, 2, 3);

        let base = scope.beaver_triple();
        let random = scope.random_share();
        let prand_bit = scope.prand_bit();
        let prand_int = scope.prand_int();

        assert_eq!(base.program_hash, [0xCD; 32]);
        assert_eq!(base.n, 7);
        assert_eq!(base.t, 2);
        assert_eq!(base.party_id, 3);
        assert_eq!(base.kind, MaterialKind::BeaverTriple);
        assert_eq!(random, base.with_kind(MaterialKind::RandomShare));
        assert_eq!(prand_bit, base.with_kind(MaterialKind::PRandBit));
        assert_eq!(prand_int, base.with_kind(MaterialKind::PRandInt));
    }

    #[test]
    fn preproc_key_encode_rejects_values_outside_binary_key_domain() {
        if usize::BITS <= u32::BITS {
            return;
        }
        let oversized = usize::try_from(u64::from(u32::MAX) + 1).unwrap();
        let key = PreprocKey::new(
            [0xAB; 32],
            MpcFieldKind::Bn254Fr,
            oversized,
            2,
            1,
            MaterialKind::BeaverTriple,
        );
        let err = key
            .encode()
            .expect_err("oversized party count should be rejected");
        assert!(matches!(
            err,
            PreprocStoreError::U32Overflow {
                field: "preprocessing key n",
                ..
            }
        ));
    }

    #[test]
    fn preproc_blob_try_new_rejects_counts_outside_metadata_domain() {
        if usize::BITS <= u32::BITS {
            return;
        }
        let oversized = usize::try_from(u64::from(u32::MAX) + 1).unwrap();
        let err = PreprocBlob::try_new(Vec::new(), 0, oversized)
            .expect_err("oversized item counts should be rejected");
        assert!(matches!(
            err,
            PreprocStoreError::U32Overflow {
                field: "preprocessing item count",
                ..
            }
        ));
    }

    #[test]
    fn preproc_blob_unconsumed_data_rejects_corrupt_consumed_offset() {
        let blob = PreprocBlob {
            meta: PreprocMeta {
                count: 10,
                consumed: 5,
                item_size: 10,
            },
            data: vec![0; 10],
        };
        let err = blob
            .unconsumed_data()
            .expect_err("offset beyond data should be rejected");
        assert!(
            matches!(err, PreprocStoreError::Deserialization(_)),
            "expected deserialization error, got: {err}"
        );
    }

    #[test]
    fn deserialize_feldman_shares_rejects_zero_item_size_with_data() {
        let err = deserialize_feldman_shares::<Fr, ark_bn254::G1Projective>(&[1, 2, 3], 0, 0)
            .expect_err("zero item size with data should be rejected");
        assert!(
            matches!(err, PreprocStoreError::Deserialization(_)),
            "expected deserialization error, got: {err}"
        );
    }

    #[tokio::test]
    async fn lmdb_store_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = LmdbPreprocStore::open(dir.path()).unwrap();

        let key = PreprocKey::new(
            [0x01; 32],
            MpcFieldKind::Bn254Fr,
            5,
            2,
            0,
            MaterialKind::RandomShare,
        );
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

        let key = PreprocKey::new(
            [0x02; 32],
            MpcFieldKind::Bls12_381Fr,
            3,
            1,
            0,
            MaterialKind::BeaverTriple,
        );
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
