//! Persistent preprocessing material storage.
//!
//! Stores MPC preprocessing material (Beaver triples, random shares, etc.)
//! keyed by program hash and MPC parameters. Backed by LMDB via the `heed`
//! crate for memory-mapped reads and ACID write transactions.

use crate::net::curve::MpcFieldKind;
use crate::net::mpc_engine::DurableIdentityDigest;
use ark_ff::FftField;
use ark_serialize::{Compress, Validate};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::path::{Path, PathBuf};
use stoffelmpc_mpc::honeybadger::{
    fpmul::f256::Gf256, robust_interpolate::robust_interpolate::RobustShare,
    triple_gen::ShamirBeaverTriple,
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum PreprocStoreError {
    #[error("LMDB: {0}")]
    Lmdb(#[from] heed::Error),
    #[error("LMDB actor: {0}")]
    LmdbActor(String),
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
    #[error("preprocessing cursor mismatch: expected consumed {expected}, actual {actual}")]
    CursorMismatch { expected: u32, actual: u32 },
    #[error("preprocessing item size mismatch: expected {expected}, actual {actual}")]
    ItemSizeMismatch { expected: u32, actual: u32 },
    #[error("partial preprocessing item write: data length {data_len} is not divisible by item size {item_size}")]
    PartialItem { data_len: usize, item_size: u32 },
    #[error("preprocessing store() is forbidden in standing deployment mode")]
    StoreForbiddenInStandingMode,
    #[error("{field} value {value} exceeds u32::MAX")]
    U32Overflow { field: &'static str, value: u64 },
    #[error("task join: {0}")]
    Join(String),
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
/// program/node-identity namespace.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PreprocKey {
    pub program_hash: [u8; 32],
    pub field_kind: MpcFieldKind,
    pub n: usize,
    pub t: usize,
    pub node_identity: DurableIdentityDigest,
    pub kind: MaterialKind,
}

impl PreprocKey {
    pub fn new(
        program_hash: [u8; 32],
        field_kind: MpcFieldKind,
        n: usize,
        t: usize,
        node_identity: DurableIdentityDigest,
        kind: MaterialKind,
    ) -> Self {
        Self {
            program_hash,
            field_kind,
            n,
            t,
            node_identity,
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
        let mut buf = Vec::with_capacity(77);
        buf.extend_from_slice(b"pp:");
        buf.extend_from_slice(&self.program_hash);
        buf.push(field_kind_tag(self.field_kind));
        buf.extend_from_slice(&usize_to_u32(self.n, "preprocessing key n")?.to_le_bytes());
        buf.extend_from_slice(&usize_to_u32(self.t, "preprocessing key threshold")?.to_le_bytes());
        buf.extend_from_slice(&self.node_identity.as_bytes());
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PreprocKeyScope {
    pub program_hash: [u8; 32],
    pub field_kind: MpcFieldKind,
    pub n: usize,
    pub t: usize,
    pub node_identity: DurableIdentityDigest,
}

impl PreprocKeyScope {
    pub fn new(
        program_hash: [u8; 32],
        field_kind: MpcFieldKind,
        n: usize,
        t: usize,
        node_identity: DurableIdentityDigest,
    ) -> Self {
        Self {
            program_hash,
            field_kind,
            n,
            t,
            node_identity,
        }
    }

    pub fn key(self, kind: MaterialKind) -> PreprocKey {
        PreprocKey {
            program_hash: self.program_hash,
            field_kind: self.field_kind,
            n: self.n,
            t: self.t,
            node_identity: self.node_identity,
            kind,
        }
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
        MpcFieldKind::Secp256k1Fr => 3,
        MpcFieldKind::Secp256r1Fr => 4,
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

/// Metadata stored separately so cursor checks and inventory reads avoid
/// deserializing the potentially large data blob.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreprocMeta {
    pub count: u32,
    pub consumed: u32,
    pub item_size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StandingPreprocAction {
    Reuse,
    TopUp,
    Rebuild,
}

/// Party-exchanged inventory for one correlated preprocessing reservoir.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandingPreprocSnapshot {
    pub generation_id: Option<[u8; 32]>,
    pub beaver: PreprocMeta,
    pub random: PreprocMeta,
    pub prand_bit: PreprocMeta,
    pub prand_int: PreprocMeta,
}

impl StandingPreprocSnapshot {
    pub fn availability(self) -> PoolAvailability {
        PoolAvailability {
            beaver: self.beaver.available(),
            random: self.random.available(),
            prand_bit: self.prand_bit.available(),
            prand_int: self.prand_int.available(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StandingPreprocPlan {
    pub action: StandingPreprocAction,
    pub needed: PoolAvailability,
    pub generation_id: [u8; 32],
}

/// Agree on reuse, top-up, or rebuild from party-indexed inventories.
pub fn agree_standing_preproc_plan(
    targets: PoolAvailability,
    snapshots: &[StandingPreprocSnapshot],
    fresh_generation_id: [u8; 32],
) -> Result<StandingPreprocPlan, String> {
    let (&baseline, rest) = snapshots
        .split_first()
        .ok_or_else(|| "standing preprocessing agreement requires at least one party".to_owned())?;
    if baseline.generation_id.is_none() || rest.iter().any(|snapshot| *snapshot != baseline) {
        return Ok(StandingPreprocPlan {
            action: StandingPreprocAction::Rebuild,
            needed: targets,
            generation_id: fresh_generation_id,
        });
    }
    let available = baseline.availability();
    let needed = PoolAvailability {
        beaver: targets.beaver.saturating_sub(available.beaver),
        random: targets.random.saturating_sub(available.random),
        prand_bit: targets.prand_bit.saturating_sub(available.prand_bit),
        prand_int: targets.prand_int.saturating_sub(available.prand_int),
    };
    let action = if needed == PoolAvailability::default() {
        StandingPreprocAction::Reuse
    } else {
        StandingPreprocAction::TopUp
    };
    Ok(StandingPreprocPlan {
        action,
        needed,
        generation_id: if action == StandingPreprocAction::Reuse {
            baseline.generation_id.expect("generation checked above")
        } else {
            fresh_generation_id
        },
    })
}

impl PreprocMeta {
    pub fn available(&self) -> u32 {
        self.count.saturating_sub(self.consumed)
    }
}

/// Material atomically removed from the front of a preprocessing pool.
///
/// `data` contains exactly `count * item_size` bytes. The backing store no
/// longer contains these bytes when this value is returned, so a crash or a
/// second execution cannot allocate the same correlated material again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TakenPreproc {
    pub count: u32,
    pub item_size: u32,
    pub data: Vec<u8>,
}

/// Serialized preprocessing material with metadata + data.
#[derive(Debug, Clone)]
pub struct PreprocBlob {
    pub meta: PreprocMeta,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolAvailability {
    pub beaver: u32,
    pub random: u32,
    pub prand_bit: u32,
    pub prand_int: u32,
}

impl PoolAvailability {
    pub fn covers(self, required: Self) -> bool {
        self.beaver >= required.beaver
            && self.random >= required.random
            && self.prand_bit >= required.prand_bit
            && self.prand_int >= required.prand_int
    }

    const fn get(self, kind: MaterialKind) -> u32 {
        match kind {
            MaterialKind::BeaverTriple => self.beaver,
            MaterialKind::RandomShare => self.random,
            MaterialKind::PRandBit => self.prand_bit,
            MaterialKind::PRandInt => self.prand_int,
        }
    }

    fn set(&mut self, kind: MaterialKind, count: u32) {
        match kind {
            MaterialKind::BeaverTriple => self.beaver = count,
            MaterialKind::RandomShare => self.random = count,
            MaterialKind::PRandBit => self.prand_bit = count,
            MaterialKind::PRandInt => self.prand_int = count,
        }
    }
}

/// Preprocessing material removed atomically from a stable reservoir.
///
/// This value deliberately is not `Clone`: one successful take creates one
/// owner, and dropping that owner burns the material rather than making it
/// available to another execution.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct OwnedPreprocBundle {
    pub beaver: Option<TakenPreproc>,
    pub random: Option<TakenPreproc>,
    pub prand_bit: Option<TakenPreproc>,
    pub prand_int: Option<TakenPreproc>,
    pub remaining: PoolAvailability,
}

impl OwnedPreprocBundle {
    pub fn availability(&self) -> PoolAvailability {
        PoolAvailability {
            beaver: self.beaver.as_ref().map_or(0, |material| material.count),
            random: self.random.as_ref().map_or(0, |material| material.count),
            prand_bit: self.prand_bit.as_ref().map_or(0, |material| material.count),
            prand_int: self.prand_int.as_ref().map_or(0, |material| material.count),
        }
    }

    fn set(&mut self, kind: MaterialKind, material: TakenPreproc) {
        match kind {
            MaterialKind::BeaverTriple => self.beaver = Some(material),
            MaterialKind::RandomShare => self.random = Some(material),
            MaterialKind::PRandBit => self.prand_bit = Some(material),
            MaterialKind::PRandInt => self.prand_int = Some(material),
        }
    }
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
    async fn meta(&self, key: &PreprocKey) -> Result<Option<PreprocMeta>, PreprocStoreError>;
    async fn append_items(
        &self,
        key: &PreprocKey,
        item_size: u32,
        added: u32,
        data: &[u8],
    ) -> Result<u32, PreprocStoreError>;

    /// Atomically remove an owned bundle from a stable preprocessing reservoir.
    ///
    /// All four material kinds are validated and physically compacted in one
    /// LMDB transaction. A zero requested count produces `None` for that kind.
    async fn take_bundle_from_reservoir(
        &self,
        source: &PreprocKeyScope,
        requested: PoolAvailability,
    ) -> Result<OwnedPreprocBundle, PreprocStoreError>;

    /// Atomically advance the consumed cursor only if it is at `expected_consumed`.
    /// Returns new consumed count.
    async fn reserve_at(
        &self,
        key: &PreprocKey,
        expected_consumed: u32,
        n: u32,
    ) -> Result<u32, PreprocStoreError>;

    /// Items available (count - consumed). Returns 0 if not stored.
    async fn available(&self, key: &PreprocKey) -> Result<u32, PreprocStoreError>;
    async fn scope_availability(
        &self,
        scope: &PreprocKeyScope,
    ) -> Result<PoolAvailability, PreprocStoreError>;

    async fn delete(&self, key: &PreprocKey) -> Result<(), PreprocStoreError>;
    async fn atomic_increment(&self, ns: &[u8], key: &[u8]) -> Result<u64, PreprocStoreError>;

    /// Store an opaque byte blob under a namespaced key (for reservations etc.).
    async fn store_blob(&self, ns: &[u8], key: &[u8], data: &[u8])
        -> Result<(), PreprocStoreError>;
    /// Load an opaque byte blob by namespaced key.
    async fn load_blob(&self, ns: &[u8], key: &[u8]) -> Result<Option<Vec<u8>>, PreprocStoreError>;
    /// Delete an opaque namespaced blob.
    async fn delete_blob(&self, ns: &[u8], key: &[u8]) -> Result<(), PreprocStoreError>;
}

const STANDING_PREPROC_GENERATION_NAMESPACE: &[u8] = b"standing-preproc-generation-v1:";

fn standing_generation_key(scope: PreprocKeyScope) -> Result<Vec<u8>, PreprocStoreError> {
    scope.beaver_triple().encode()
}

pub async fn standing_preproc_snapshot(
    store: &dyn PreprocStore,
    scope: PreprocKeyScope,
) -> Result<StandingPreprocSnapshot, PreprocStoreError> {
    let generation_id = store
        .load_blob(
            STANDING_PREPROC_GENERATION_NAMESPACE,
            &standing_generation_key(scope)?,
        )
        .await?
        .map(|bytes| {
            bytes.try_into().map_err(|bytes: Vec<u8>| {
                PreprocStoreError::Deserialization(format!(
                    "standing preprocessing generation has {} bytes, expected 32",
                    bytes.len()
                ))
            })
        })
        .transpose()?;
    Ok(StandingPreprocSnapshot {
        generation_id,
        beaver: store
            .meta(&scope.beaver_triple())
            .await?
            .unwrap_or_default(),
        random: store.meta(&scope.random_share()).await?.unwrap_or_default(),
        prand_bit: store.meta(&scope.prand_bit()).await?.unwrap_or_default(),
        prand_int: store.meta(&scope.prand_int()).await?.unwrap_or_default(),
    })
}

pub async fn store_standing_preproc_generation(
    store: &dyn PreprocStore,
    scope: PreprocKeyScope,
    generation_id: [u8; 32],
) -> Result<(), PreprocStoreError> {
    store
        .store_blob(
            STANDING_PREPROC_GENERATION_NAMESPACE,
            &standing_generation_key(scope)?,
            &generation_id,
        )
        .await
}

/// Verify that every party agreed over one stable, party-indexed inventory,
/// then derive the shared reservoir action.
pub async fn agree_standing_preproc_plan_for_party(
    store: &dyn PreprocStore,
    scope: PreprocKeyScope,
    targets: PoolAvailability,
    snapshots: &[StandingPreprocSnapshot],
    party_id: usize,
    parties: usize,
    fresh_generation_id: [u8; 32],
) -> Result<StandingPreprocPlan, String> {
    if snapshots.len() != parties {
        return Err(format!(
            "standing preprocessing agreement received {} inventories, expected {parties}",
            snapshots.len()
        ));
    }
    let local = standing_preproc_snapshot(store, scope).await?;
    if snapshots.get(party_id) != Some(&local) {
        return Err(format!(
            "standing preprocessing local inventory changed during agreement: local={local:?}, exchanged={:?}",
            snapshots.get(party_id)
        ));
    }
    agree_standing_preproc_plan(targets, snapshots, fresh_generation_id)
}

/// Apply one party-agreed reservoir plan and return the resulting inventory.
/// Backend code supplies only its material generator; clearing, generation
/// ownership, and the final store read stay identical across MPC backends.
pub async fn apply_standing_preproc_plan<F, Fut>(
    store: &dyn PreprocStore,
    scope: PreprocKeyScope,
    targets: PoolAvailability,
    plan: StandingPreprocPlan,
    top_up: F,
) -> Result<StandingPreprocSnapshot, String>
where
    F: FnOnce(PoolAvailability) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    match plan.action {
        StandingPreprocAction::Reuse => {}
        StandingPreprocAction::TopUp => top_up(plan.needed).await?,
        StandingPreprocAction::Rebuild => {
            clear_standing_preproc_scope(store, scope).await?;
            top_up(plan.needed).await?;
        }
    }
    if plan.action != StandingPreprocAction::Reuse {
        store_standing_preproc_generation(store, scope, plan.generation_id).await?;
    }
    let final_snapshot = standing_preproc_snapshot(store, scope)
        .await
        .map_err(String::from)?;
    if final_snapshot.generation_id != Some(plan.generation_id)
        || !final_snapshot.availability().covers(targets)
    {
        return Err(format!(
            "standing preprocessing did not reach agreed plan: plan={plan:?}, final={final_snapshot:?}"
        ));
    }
    Ok(final_snapshot)
}

pub async fn clear_standing_preproc_scope(
    store: &dyn PreprocStore,
    scope: PreprocKeyScope,
) -> Result<(), PreprocStoreError> {
    for kind in MATERIAL_KINDS {
        store.delete(&scope.key(kind)).await?;
    }
    store
        .delete_blob(
            STANDING_PREPROC_GENERATION_NAMESPACE,
            &standing_generation_key(scope)?,
        )
        .await
}

// ---------------------------------------------------------------------------
// LMDB actor backend
// ---------------------------------------------------------------------------

type LmdbDatabase = heed::Database<heed::types::Bytes, heed::types::Bytes>;
type DbJob = Box<dyn FnOnce(&heed::Env, &LmdbDatabase) + Send + 'static>;

const MATERIAL_KINDS: [MaterialKind; 4] = [
    MaterialKind::BeaverTriple,
    MaterialKind::RandomShare,
    MaterialKind::PRandBit,
    MaterialKind::PRandInt,
];
struct ReservoirMaterialKeys {
    kind: MaterialKind,
    meta_key: Vec<u8>,
    data_key: Vec<u8>,
}

fn reservoir_material_keys(
    source: &PreprocKeyScope,
) -> Result<Vec<ReservoirMaterialKeys>, PreprocStoreError> {
    MATERIAL_KINDS
        .into_iter()
        .map(|kind| {
            let key = source.key(kind);
            Ok(ReservoirMaterialKeys {
                kind,
                meta_key: key.meta_key()?,
                data_key: key.encode()?,
            })
        })
        .collect()
}

const DEFAULT_LMDB_MAP_SIZE: usize = 1024 * 1024 * 1024;

fn lmdb_initial_map_size(path: &Path, requested: usize) -> Result<usize, PreprocStoreError> {
    if requested == 0 {
        return Err(PreprocStoreError::LmdbActor(
            "initial map size must be nonzero".into(),
        ));
    }
    let existing_len = match std::fs::metadata(path.join("data.mdb")) {
        Ok(metadata) => usize::try_from(metadata.len()).map_err(|_| {
            PreprocStoreError::LmdbActor(format!(
                "existing LMDB data file is too large for this platform: {} bytes",
                metadata.len()
            ))
        })?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(error) => return Err(error.into()),
    };

    let mut map_size = requested;
    while map_size <= existing_len {
        map_size = map_size.checked_mul(2).ok_or_else(|| {
            PreprocStoreError::LmdbActor(format!(
                "cannot size LMDB map above existing {existing_len}-byte data file"
            ))
        })?;
    }
    Ok(map_size)
}

fn is_lmdb_map_full(error: &PreprocStoreError) -> bool {
    matches!(
        error,
        PreprocStoreError::Lmdb(heed::Error::Mdb(heed::MdbError::MapFull))
    )
}

/// Retry one actor-owned write transaction after growing LMDB's virtual map.
///
/// Every transaction for this environment is created and completed on the
/// actor thread, so when `operation` returns there are no live transactions
/// owned by this store. That is the condition LMDB requires for a safe resize.
fn with_lmdb_map_growth<T>(
    env: &heed::Env,
    mut operation: impl FnMut() -> Result<T, PreprocStoreError>,
) -> Result<T, PreprocStoreError> {
    loop {
        match operation() {
            Err(error) if is_lmdb_map_full(&error) => {
                let current = env.info().map_size;
                let grown = current.checked_mul(2).ok_or_else(|| {
                    PreprocStoreError::LmdbActor(format!(
                        "cannot grow full LMDB map beyond {current} bytes"
                    ))
                })?;
                // SAFETY: LmdbPreprocStore serializes every transaction on this
                // actor thread, and the failed transaction was dropped before
                // `operation` returned.
                unsafe { env.resize(grown) }?;
                tracing::warn!(
                    old_map_size = current,
                    new_map_size = grown,
                    "grew preprocessing LMDB map after MDB_MAP_FULL"
                );
            }
            result => return result,
        }
    }
}

/// LMDB-backed preprocessing store using the actor pattern.
///
/// A dedicated `std::thread` owns the `heed::Env` and processes all
/// database operations sequentially.  Callers communicate via an `mpsc`
/// channel and await `oneshot` replies, guaranteeing that LMDB never
/// touches a tokio worker thread.
///
/// Metadata and data are stored under separate keys so inventory reads never
/// touch the potentially large data blob.
pub struct LmdbPreprocStore {
    tx: std::sync::mpsc::Sender<DbJob>,
    _thread: std::thread::JoinHandle<()>,
}

impl LmdbPreprocStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PreprocStoreError> {
        Self::open_with_map_size(path, DEFAULT_LMDB_MAP_SIZE)
    }

    /// Open a preprocessing store with an explicit initial LMDB map size.
    /// The actor automatically doubles this virtual limit when a write reaches
    /// it; this parameter controls only the initial reservation.
    pub fn open_with_map_size(
        path: impl AsRef<Path>,
        initial_map_size: usize,
    ) -> Result<Self, PreprocStoreError> {
        let path = path.as_ref();
        std::fs::create_dir_all(path)?;
        let initial_map_size = lmdb_initial_map_size(path, initial_map_size)?;
        let env = unsafe {
            heed::EnvOpenOptions::new()
                .map_size(initial_map_size)
                .max_dbs(1)
                .open(path)
        }?;
        let mut transaction = env.write_txn()?;
        let database = env.create_database(&mut transaction, Some("store"))?;
        transaction.commit()?;

        let (tx, rx) = std::sync::mpsc::channel::<DbJob>();
        let thread = std::thread::Builder::new()
            .name("lmdb-actor".into())
            .spawn(move || {
                while let Ok(job) = rx.recv() {
                    job(&env, &database);
                }
            })?;

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

    async fn run<T, F>(&self, operation: F) -> Result<T, PreprocStoreError>
    where
        T: Send + 'static,
        F: FnOnce(&heed::Env, &LmdbDatabase) -> Result<T, PreprocStoreError> + Send + 'static,
    {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        self.tx
            .send(Box::new(move |env, database| {
                let _ = reply_tx.send(operation(env, database));
            }))
            .map_err(|_| PreprocStoreError::LmdbActor("thread gone".into()))?;
        reply_rx
            .await
            .map_err(|_| PreprocStoreError::LmdbActor("reply dropped".into()))?
    }

    async fn reserve_cursor(
        &self,
        key: &PreprocKey,
        expected: u32,
        count: u32,
    ) -> Result<u32, PreprocStoreError> {
        let meta_key = key.meta_key()?;
        self.run(move |env, database| {
            with_lmdb_map_growth(env, || {
                let mut transaction = env.write_txn()?;
                let raw = database
                    .get(&transaction, &meta_key)?
                    .ok_or(PreprocStoreError::NotFound)?;
                let mut meta: PreprocMeta = bincode::deserialize(raw)?;
                if meta.consumed != expected {
                    return Err(PreprocStoreError::CursorMismatch {
                        expected,
                        actual: meta.consumed,
                    });
                }
                let consumed =
                    meta.consumed
                        .checked_add(count)
                        .ok_or(PreprocStoreError::U32Overflow {
                            field: "preprocessing consumed count",
                            value: u64::from(meta.consumed) + u64::from(count),
                        })?;
                if consumed > meta.count {
                    return Err(PreprocStoreError::Insufficient {
                        need: count,
                        available: meta.available(),
                    });
                }
                meta.consumed = consumed;
                database.put(&mut transaction, &meta_key, &bincode::serialize(&meta)?)?;
                transaction.commit()?;
                Ok(consumed)
            })
        })
        .await
    }
}
#[async_trait::async_trait]
impl PreprocStore for LmdbPreprocStore {
    async fn store(&self, key: &PreprocKey, blob: &PreprocBlob) -> Result<(), PreprocStoreError> {
        let meta_key = key.meta_key()?;
        let data_key = key.encode()?;
        let meta = bincode::serialize(&blob.meta)?;
        let data = blob.data.clone();
        self.run(move |env, database| {
            with_lmdb_map_growth(env, || {
                let mut transaction = env.write_txn()?;
                database.put(&mut transaction, &meta_key, &meta)?;
                database.put(&mut transaction, &data_key, &data)?;
                transaction.commit()?;
                Ok(())
            })
        })
        .await
    }

    async fn load(&self, key: &PreprocKey) -> Result<Option<PreprocBlob>, PreprocStoreError> {
        let meta_key = key.meta_key()?;
        let data_key = key.encode()?;
        self.run(move |env, database| {
            let transaction = env.read_txn()?;
            let Some(raw_meta) = database.get(&transaction, &meta_key)? else {
                return Ok(None);
            };
            let meta = bincode::deserialize(raw_meta)?;
            let data = database
                .get(&transaction, &data_key)?
                .ok_or(PreprocStoreError::NotFound)?
                .to_vec();
            Ok(Some(PreprocBlob { meta, data }))
        })
        .await
    }

    async fn meta(&self, key: &PreprocKey) -> Result<Option<PreprocMeta>, PreprocStoreError> {
        let key = key.meta_key()?;
        self.run(move |env, database| {
            let transaction = env.read_txn()?;
            database
                .get(&transaction, &key)?
                .map(bincode::deserialize)
                .transpose()
                .map_err(PreprocStoreError::from)
        })
        .await
    }

    async fn append_items(
        &self,
        key: &PreprocKey,
        item_size: u32,
        added: u32,
        data: &[u8],
    ) -> Result<u32, PreprocStoreError> {
        let item_size_usize = u32_to_usize(item_size, "append preprocessing item size")?;
        let expected_len = u32_to_usize(added, "append preprocessing count")?
            .checked_mul(item_size_usize)
            .ok_or_else(|| {
                PreprocStoreError::Serialization(format!(
                    "append data length overflows usize: added={added}, item_size={item_size}"
                ))
            })?;
        if data.len() != expected_len || (item_size == 0 && added != 0) {
            return Err(PreprocStoreError::PartialItem {
                data_len: data.len(),
                item_size,
            });
        }

        let meta_key = key.meta_key()?;
        let data_key = key.encode()?;
        let data = data.to_vec();
        self.run(move |env, database| {
            with_lmdb_map_growth(env, || {
                let mut transaction = env.write_txn()?;
                let mut meta = match database.get(&transaction, &meta_key)? {
                    Some(raw) => {
                        let meta: PreprocMeta = bincode::deserialize(raw)?;
                        if meta.item_size != item_size {
                            return Err(PreprocStoreError::ItemSizeMismatch {
                                expected: meta.item_size,
                                actual: item_size,
                            });
                        }
                        meta
                    }
                    None => PreprocMeta {
                        count: 0,
                        consumed: 0,
                        item_size,
                    },
                };
                let mut stored = database
                    .get(&transaction, &data_key)?
                    .map_or_else(Vec::new, ToOwned::to_owned);
                stored.extend_from_slice(&data);
                meta.count =
                    meta.count
                        .checked_add(added)
                        .ok_or(PreprocStoreError::U32Overflow {
                            field: "preprocessing item count",
                            value: u64::from(meta.count) + u64::from(added),
                        })?;
                database.put(&mut transaction, &data_key, &stored)?;
                database.put(&mut transaction, &meta_key, &bincode::serialize(&meta)?)?;
                transaction.commit()?;
                Ok(meta.count)
            })
        })
        .await
    }

    async fn take_bundle_from_reservoir(
        &self,
        source: &PreprocKeyScope,
        requested: PoolAvailability,
    ) -> Result<OwnedPreprocBundle, PreprocStoreError> {
        let materials = reservoir_material_keys(source)?;

        self.run(move |env, database| {
            with_lmdb_map_growth(env, || {
                let mut transaction = env.write_txn()?;
                let mut bundle = OwnedPreprocBundle::default();
                for material in &materials {
                    let count = requested.get(material.kind);
                    let Some(raw_meta) = database.get(&transaction, &material.meta_key)? else {
                        if database.get(&transaction, &material.data_key)?.is_some() {
                            return Err(PreprocStoreError::Deserialization(format!(
                                "preprocessing reservoir {:?} has data without metadata",
                                material.kind
                            )));
                        }
                        if count > 0 {
                            return Err(PreprocStoreError::NotFound);
                        }
                        continue;
                    };
                    let meta: PreprocMeta = bincode::deserialize(raw_meta)?;
                    if meta.consumed > meta.count || (meta.count > 0 && meta.item_size == 0) {
                        return Err(PreprocStoreError::Deserialization(format!(
                            "invalid preprocessing reservoir metadata for {:?}",
                            material.kind
                        )));
                    }
                    if count > meta.available() {
                        return Err(PreprocStoreError::Insufficient {
                            need: count,
                            available: meta.available(),
                        });
                    }
                    let source_data = database
                        .get(&transaction, &material.data_key)?
                        .ok_or(PreprocStoreError::NotFound)?;
                    let expected_len = byte_offset(
                        meta.count,
                        meta.item_size,
                        "preprocessing reservoir source size",
                    )?;
                    if source_data.len() != expected_len {
                        return Err(PreprocStoreError::Deserialization(format!(
                        "preprocessing reservoir {:?} contains {} bytes, expected {expected_len}",
                        material.kind,
                        source_data.len()
                    )));
                    }

                    let start = byte_offset(
                        meta.consumed,
                        meta.item_size,
                        "preprocessing reservoir bundle start",
                    )?;
                    let end_index =
                        meta.consumed
                            .checked_add(count)
                            .ok_or(PreprocStoreError::U32Overflow {
                                field: "preprocessing reservoir bundle end",
                                value: u64::from(meta.consumed) + u64::from(count),
                            })?;
                    let end = byte_offset(
                        end_index,
                        meta.item_size,
                        "preprocessing reservoir bundle end",
                    )?;
                    let remaining = meta.count - end_index;
                    bundle.remaining.set(material.kind, remaining);

                    // Retain only the slices that outlive this transaction. This
                    // avoids cloning the complete reservoir blob before extracting
                    // one execution's bundle.
                    let taken_data = (count > 0).then(|| source_data[start..end].to_vec());
                    let compacted_remaining = (remaining > 0
                        && !(meta.consumed == 0 && count == 0))
                        .then(|| source_data[end..].to_vec());

                    if let Some(data) = taken_data {
                        bundle.set(
                            material.kind,
                            TakenPreproc {
                                count,
                                item_size: meta.item_size,
                                data,
                            },
                        );
                    }

                    if remaining == 0 {
                        database.delete(&mut transaction, &material.meta_key)?;
                        database.delete(&mut transaction, &material.data_key)?;
                    } else if meta.consumed == 0 && count == 0 {
                        // The bytes are already compact and this kind was not
                        // requested; validating it is sufficient.
                    } else {
                        database.put(
                            &mut transaction,
                            &material.meta_key,
                            &bincode::serialize(&PreprocMeta {
                                count: remaining,
                                consumed: 0,
                                item_size: meta.item_size,
                            })?,
                        )?;
                        database.put(
                            &mut transaction,
                            &material.data_key,
                            compacted_remaining
                                .as_deref()
                                .expect("non-compact reservoir has remaining bytes"),
                        )?;
                    }
                }
                transaction.commit()?;
                Ok(bundle)
            })
        })
        .await
    }

    async fn reserve_at(
        &self,
        key: &PreprocKey,
        expected_consumed: u32,
        count: u32,
    ) -> Result<u32, PreprocStoreError> {
        self.reserve_cursor(key, expected_consumed, count).await
    }

    async fn available(&self, key: &PreprocKey) -> Result<u32, PreprocStoreError> {
        Ok(self.meta(key).await?.map_or(0, |meta| meta.available()))
    }

    async fn scope_availability(
        &self,
        scope: &PreprocKeyScope,
    ) -> Result<PoolAvailability, PreprocStoreError> {
        let keys = MATERIAL_KINDS
            .into_iter()
            .map(|kind| Ok((kind, scope.key(kind).meta_key()?)))
            .collect::<Result<Vec<_>, PreprocStoreError>>()?;
        self.run(move |env, database| {
            let transaction = env.read_txn()?;
            let mut availability = PoolAvailability::default();
            for (kind, key) in keys {
                let count = database
                    .get(&transaction, &key)?
                    .map(bincode::deserialize::<PreprocMeta>)
                    .transpose()?
                    .map_or(0, |meta| meta.available());
                availability.set(kind, count);
            }
            Ok(availability)
        })
        .await
    }

    async fn delete(&self, key: &PreprocKey) -> Result<(), PreprocStoreError> {
        let meta_key = key.meta_key()?;
        let data_key = key.encode()?;
        self.run(move |env, database| {
            with_lmdb_map_growth(env, || {
                let mut transaction = env.write_txn()?;
                database.delete(&mut transaction, &meta_key)?;
                database.delete(&mut transaction, &data_key)?;
                transaction.commit()?;
                Ok(())
            })
        })
        .await
    }

    async fn atomic_increment(
        &self,
        namespace: &[u8],
        key: &[u8],
    ) -> Result<u64, PreprocStoreError> {
        let key = [namespace, key].concat();
        self.run(move |env, database| {
            with_lmdb_map_growth(env, || {
                let mut transaction = env.write_txn()?;
                let current = match database.get(&transaction, &key)? {
                    Some(raw) if raw.len() == 8 => {
                        u64::from_le_bytes(raw.try_into().expect("length checked"))
                    }
                    Some(raw) => {
                        return Err(PreprocStoreError::Deserialization(format!(
                            "atomic increment value has {} bytes, expected 8",
                            raw.len()
                        )));
                    }
                    None => 0,
                };
                let next = current.checked_add(1).ok_or_else(|| {
                    PreprocStoreError::Serialization("atomic increment overflowed u64".to_owned())
                })?;
                database.put(&mut transaction, &key, &next.to_le_bytes())?;
                transaction.commit()?;
                Ok(next)
            })
        })
        .await
    }

    async fn store_blob(
        &self,
        namespace: &[u8],
        key: &[u8],
        data: &[u8],
    ) -> Result<(), PreprocStoreError> {
        let key = [namespace, key].concat();
        let data = data.to_vec();
        self.run(move |env, database| {
            with_lmdb_map_growth(env, || {
                let mut transaction = env.write_txn()?;
                database.put(&mut transaction, &key, &data)?;
                transaction.commit()?;
                Ok(())
            })
        })
        .await
    }

    async fn load_blob(
        &self,
        namespace: &[u8],
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, PreprocStoreError> {
        let key = [namespace, key].concat();
        self.run(move |env, database| {
            let transaction = env.read_txn()?;
            Ok(database.get(&transaction, &key)?.map(ToOwned::to_owned))
        })
        .await
    }

    async fn delete_blob(&self, namespace: &[u8], key: &[u8]) -> Result<(), PreprocStoreError> {
        let key = [namespace, key].concat();
        self.run(move |env, database| {
            with_lmdb_map_growth(env, || {
                let mut transaction = env.write_txn()?;
                database.delete(&mut transaction, &key)?;
                transaction.commit()?;
                Ok(())
            })
        })
        .await
    }
}
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

pub fn robust_share_size<F: FftField>() -> usize {
    F::default().serialized_size(Compress::Yes) + 16
}

pub fn robust_share_item_size<F: FftField>() -> Result<u32, PreprocStoreError> {
    usize_to_u32(robust_share_size::<F>(), "robust share item size")
}

pub fn beaver_triple_size<F: FftField>() -> Result<u32, PreprocStoreError> {
    let share_size = robust_share_size::<F>();
    let triple_size = share_size.checked_mul(3).ok_or_else(|| {
        PreprocStoreError::Serialization(format!(
            "beaver triple item size overflows usize: share_size={share_size}"
        ))
    })?;
    usize_to_u32(triple_size, "beaver triple item size")
}

pub fn prandbit_share_size<F: FftField>() -> Result<u32, PreprocStoreError> {
    let item_size = robust_share_size::<F>()
        .checked_add(1)
        .ok_or_else(|| PreprocStoreError::Serialization("prandbit item size overflow".into()))?;
    usize_to_u32(item_size, "prandbit item size")
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
    let triple_size = u32_to_usize(beaver_triple_size::<F>()?, "beaver triple item size")?;
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
    shares: &[(RobustShare<F>, Gf256)],
) -> Result<(Vec<u8>, u32), PreprocStoreError> {
    let item_size = u32_to_usize(prandbit_share_size::<F>()?, "prandbit item size")?;
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
) -> Result<Vec<(RobustShare<F>, Gf256)>, PreprocStoreError> {
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
        let f2_8 = Gf256(data[pos + share_size]);
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

    fn legacy_identity(party_id: usize) -> DurableIdentityDigest {
        DurableIdentityDigest::from_legacy_party_id(party_id)
    }
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
            .map(|i| (random_share(&mut rng), Gf256(i as u8)))
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
            legacy_identity(1),
            MaterialKind::BeaverTriple,
        );
        let rs = base.with_kind(MaterialKind::RandomShare);
        assert_eq!(rs.program_hash, base.program_hash);
        assert_eq!(rs.kind, MaterialKind::RandomShare);
        assert_ne!(base.encode().unwrap(), rs.encode().unwrap());
    }

    #[test]
    fn preproc_key_scope_preserves_shared_key_namespace() {
        let node_identity = legacy_identity(3);
        let scope =
            PreprocKeyScope::new([0xCD; 32], MpcFieldKind::Bls12_381Fr, 7, 2, node_identity);

        let base = scope.beaver_triple();
        let random = scope.random_share();
        let prand_bit = scope.prand_bit();
        let prand_int = scope.prand_int();

        assert_eq!(base.program_hash, [0xCD; 32]);
        assert_eq!(base.n, 7);
        assert_eq!(base.t, 2);
        assert_eq!(base.node_identity, node_identity);
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
            legacy_identity(1),
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
            legacy_identity(0),
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
    async fn lmdb_reserve_at_rejects_stale_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let store = LmdbPreprocStore::open(dir.path()).unwrap();

        let key = PreprocKey::new(
            [0x04; 32],
            MpcFieldKind::Bls12_381Fr,
            3,
            1,
            legacy_identity(0),
            MaterialKind::RandomShare,
        );
        let blob = PreprocBlob::new(vec![0; 144], 48, 3);

        store.store(&key, &blob).await.unwrap();

        let consumed = store.reserve_at(&key, 0, 1).await.unwrap();
        assert_eq!(consumed, 1);
        assert_eq!(store.available(&key).await.unwrap(), 2);

        let err = store.reserve_at(&key, 0, 1).await.unwrap_err();
        assert!(matches!(
            err,
            PreprocStoreError::CursorMismatch {
                expected: 0,
                actual: 1
            }
        ));
        assert_eq!(store.available(&key).await.unwrap(), 2);

        let consumed = store.reserve_at(&key, 1, 2).await.unwrap();
        assert_eq!(consumed, 3);
        assert_eq!(store.available(&key).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn lmdb_append_preserves_cursor_and_reports_scope_availability() {
        let dir = tempfile::tempdir().unwrap();
        let store = LmdbPreprocStore::open(dir.path()).unwrap();
        let scope =
            PreprocKeyScope::new([0x05; 32], MpcFieldKind::Bn254Fr, 4, 1, legacy_identity(0));
        let key = scope.random_share();
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(7);
        let shares_a: Vec<_> = (0..3).map(|_| random_share(&mut rng)).collect();
        let shares_b: Vec<_> = (0..2).map(|_| random_share(&mut rng)).collect();
        let (data_a, item_size) = serialize_robust_shares::<Fr>(&shares_a).unwrap();
        let (data_b, item_size_b) = serialize_robust_shares::<Fr>(&shares_b).unwrap();
        assert_eq!(item_size, item_size_b);

        assert_eq!(
            store
                .append_items(&key, item_size, shares_a.len() as u32, &data_a)
                .await
                .unwrap(),
            3
        );
        assert_eq!(store.reserve_at(&key, 0, 2).await.unwrap(), 2);
        assert_eq!(
            store
                .append_items(&key, item_size, shares_b.len() as u32, &data_b)
                .await
                .unwrap(),
            5
        );

        let meta = store.meta(&key).await.unwrap().unwrap();
        assert_eq!(meta.count, 5);
        assert_eq!(meta.consumed, 2);
        assert_eq!(meta.available(), 3);
        let availability = store.scope_availability(&scope).await.unwrap();
        assert_eq!(availability.random, 3);
        assert_eq!(availability.beaver, 0);
        assert_eq!(availability.prand_bit, 0);
        assert_eq!(availability.prand_int, 0);
    }

    #[tokio::test]
    async fn lmdb_append_rejects_partial_and_item_size_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let store = LmdbPreprocStore::open(dir.path()).unwrap();
        let key = PreprocKey::new(
            [0x06; 32],
            MpcFieldKind::Bn254Fr,
            4,
            1,
            legacy_identity(0),
            MaterialKind::RandomShare,
        );
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(8);
        let shares: Vec<_> = (0..2).map(|_| random_share(&mut rng)).collect();
        let (data, item_size) = serialize_robust_shares::<Fr>(&shares).unwrap();

        let err = store
            .append_items(&key, item_size, 1, &data[..data.len() - 1])
            .await
            .unwrap_err();
        assert!(matches!(err, PreprocStoreError::PartialItem { .. }));

        store.append_items(&key, item_size, 2, &data).await.unwrap();
        let wrong_size_data = vec![0u8; usize::try_from((item_size + 1) * 2).unwrap()];
        let err = store
            .append_items(&key, item_size + 1, 2, &wrong_size_data)
            .await
            .unwrap_err();
        assert!(matches!(err, PreprocStoreError::ItemSizeMismatch { .. }));
    }

    #[tokio::test]
    async fn reservoir_bundle_takes_multiple_kinds_and_physically_compacts_sources() {
        let dir = tempfile::tempdir().unwrap();
        let store = LmdbPreprocStore::open(dir.path()).unwrap();
        let identity = legacy_identity(3);
        let source = PreprocKeyScope::new([0x31; 32], MpcFieldKind::Bn254Fr, 5, 1, identity);

        store
            .store(
                &source.random_share(),
                &PreprocBlob::new(vec![10, 11, 20, 21, 30, 31], 2, 3),
            )
            .await
            .unwrap();
        store
            .store(
                &source.beaver_triple(),
                &PreprocBlob::new(vec![40, 41, 42, 43], 1, 4),
            )
            .await
            .unwrap();
        // A legacy consumed prefix is physically discarded by the move too.
        store
            .reserve_at(&source.random_share(), 0, 1)
            .await
            .unwrap();

        let bundle = store
            .take_bundle_from_reservoir(
                &source,
                PoolAvailability {
                    beaver: 4,
                    random: 1,
                    prand_bit: 0,
                    prand_int: 0,
                },
            )
            .await
            .unwrap();
        assert_eq!(bundle.random.unwrap().data, vec![20, 21]);
        assert_eq!(bundle.beaver.unwrap().data, vec![40, 41, 42, 43]);
        assert!(bundle.prand_bit.is_none());
        assert!(bundle.prand_int.is_none());
        assert_eq!(bundle.remaining.random, 1);
        assert_eq!(bundle.remaining.beaver, 0);

        let source_random = store.load(&source.random_share()).await.unwrap().unwrap();
        assert_eq!(source_random.meta.count, 1);
        assert_eq!(source_random.meta.consumed, 0);
        assert_eq!(source_random.data, vec![30, 31]);
        assert!(store.load(&source.beaver_triple()).await.unwrap().is_none());
        assert_eq!(
            store.scope_availability(&source).await.unwrap(),
            bundle.remaining
        );
    }

    #[tokio::test]
    async fn reservoir_bundle_is_all_or_nothing_when_any_kind_is_insufficient() {
        let dir = tempfile::tempdir().unwrap();
        let store = LmdbPreprocStore::open(dir.path()).unwrap();
        let identity = legacy_identity(4);
        let source = PreprocKeyScope::new([0x32; 32], MpcFieldKind::Bn254Fr, 5, 1, identity);
        store
            .store(
                &source.random_share(),
                &PreprocBlob::new(vec![1, 2, 3], 1, 3),
            )
            .await
            .unwrap();
        store
            .store(&source.beaver_triple(), &PreprocBlob::new(vec![9], 1, 1))
            .await
            .unwrap();

        let error = store
            .take_bundle_from_reservoir(
                &source,
                PoolAvailability {
                    beaver: 2,
                    random: 2,
                    prand_bit: 0,
                    prand_int: 0,
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            PreprocStoreError::Insufficient {
                need: 2,
                available: 1
            }
        ));
        assert_eq!(
            store
                .load(&source.random_share())
                .await
                .unwrap()
                .unwrap()
                .data,
            vec![1, 2, 3]
        );
        assert_eq!(
            store
                .load(&source.beaver_triple())
                .await
                .unwrap()
                .unwrap()
                .data,
            vec![9]
        );
    }

    #[tokio::test]
    async fn reservoir_bundle_zero_counts_return_none_and_compact_unrequested_sources() {
        let dir = tempfile::tempdir().unwrap();
        let store = LmdbPreprocStore::open(dir.path()).unwrap();
        let identity = legacy_identity(5);
        let source = PreprocKeyScope::new([0x33; 32], MpcFieldKind::Bn254Fr, 5, 1, identity);
        store
            .store(
                &source.random_share(),
                &PreprocBlob::new(vec![1, 2, 3], 1, 3),
            )
            .await
            .unwrap();
        store
            .reserve_at(&source.random_share(), 0, 1)
            .await
            .unwrap();

        let bundle = store
            .take_bundle_from_reservoir(&source, PoolAvailability::default())
            .await
            .unwrap();
        assert!(bundle.random.is_none());
        assert!(bundle.beaver.is_none());
        assert!(bundle.prand_bit.is_none());
        assert!(bundle.prand_int.is_none());
        assert_eq!(bundle.remaining.random, 2);

        let remaining = store.load(&source.random_share()).await.unwrap().unwrap();
        assert_eq!(remaining.meta.count, 2);
        assert_eq!(remaining.meta.consumed, 0);
        assert_eq!(remaining.data, vec![2, 3]);
    }

    #[tokio::test]
    async fn reservoir_bundle_rejects_corrupt_sources_before_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let store = LmdbPreprocStore::open(dir.path()).unwrap();
        let identity = legacy_identity(6);
        let source = PreprocKeyScope::new([0x34; 32], MpcFieldKind::Bn254Fr, 5, 1, identity);
        store
            .store(&source.random_share(), &PreprocBlob::new(vec![1, 2], 1, 2))
            .await
            .unwrap();

        // store() intentionally permits raw blobs; bundle taking is the security
        // boundary that validates exact physical sizing before moving anything.
        store
            .store(&source.beaver_triple(), &PreprocBlob::new(vec![9], 2, 1))
            .await
            .unwrap();
        let corrupt = store
            .take_bundle_from_reservoir(
                &source,
                PoolAvailability {
                    beaver: 1,
                    random: 1,
                    prand_bit: 0,
                    prand_int: 0,
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(corrupt, PreprocStoreError::Deserialization(_)));
        assert_eq!(store.available(&source.random_share()).await.unwrap(), 2);
    }
    #[tokio::test]
    async fn lmdb_atomic_increment_is_unique() {
        let dir = tempfile::tempdir().unwrap();
        let store = LmdbPreprocStore::open(dir.path()).unwrap();
        let mut values = Vec::new();
        for _ in 0..8 {
            values.push(
                store
                    .atomic_increment(b"epoch:", b"deployment")
                    .await
                    .unwrap(),
            );
        }
        assert_eq!(values, vec![1, 2, 3, 4, 5, 6, 7, 8]);
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

    #[tokio::test]
    async fn lmdb_append_grows_map_and_retries_full_write() {
        let dir = tempfile::tempdir().unwrap();
        // 64 KiB is deliberately too small for the value below, but remains a
        // multiple of both common 4 KiB and 16 KiB host page sizes.
        let store = LmdbPreprocStore::open_with_map_size(dir.path(), 64 * 1024).unwrap();
        let key = PreprocKey::new(
            [0xA5; 32],
            MpcFieldKind::Bn254Fr,
            5,
            1,
            legacy_identity(0),
            MaterialKind::BeaverTriple,
        );
        let data = vec![0xA5; 512 * 1024];

        assert_eq!(
            store
                .append_items(&key, 1, data.len() as u32, &data)
                .await
                .unwrap(),
            data.len() as u32
        );

        let loaded = store.load(&key).await.unwrap().unwrap();
        assert_eq!(loaded.meta.count, data.len() as u32);
        assert_eq!(loaded.data, data);
    }

    #[test]
    fn lmdb_reopen_map_size_covers_existing_data_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = std::fs::File::create(dir.path().join("data.mdb")).unwrap();
        file.set_len(512 * 1024).unwrap();

        assert_eq!(
            lmdb_initial_map_size(dir.path(), 64 * 1024).unwrap(),
            1024 * 1024
        );
    }
}
