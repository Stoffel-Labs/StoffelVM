use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::Notify;

use stoffel_vm_types::core_types::ClearShareValue;

use super::accumulators::{
    AbaState, BatchKey, BatchOpenAccumulator, ExpKey, ExpOpenAccumulator, ExpOpenProgress,
    ExpOpenRegistryKind, ExpOpenRequest, OpenAccumulator, OpenResult, RbcState, SingleKey,
};

const OPEN_REGISTRY_WAIT_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Copy)]
struct OpenSingleResultCodec<Wrap, Unwrap> {
    wrap_result: Wrap,
    unwrap_result: Unwrap,
    operation: &'static str,
}

/// Per-instance registry for all share accumulation and consensus state.
pub struct InstanceRegistry {
    instance_id: u64,
    // open share accumulation
    pub(super) single: Mutex<HashMap<SingleKey, OpenAccumulator>>,
    single_notify: Notify,
    pub(super) batch: Mutex<HashMap<BatchKey, BatchOpenAccumulator>>,
    batch_notify: Notify,
    // open-in-exponent accumulation (used by HB and AVSS)
    pub exp: Mutex<HashMap<ExpKey, ExpOpenAccumulator>>,
    pub exp_notify: Notify,
    // second EXP registry for AVSS G2 operations
    pub exp_g2: Mutex<HashMap<ExpKey, ExpOpenAccumulator>>,
    pub exp_g2_notify: Notify,
    // HB consensus
    pub rbc: Mutex<RbcState>,
    pub rbc_notify: Notify,
    pub aba: Mutex<AbaState>,
    pub aba_notify: Notify,
}

impl InstanceRegistry {
    pub(super) fn new(instance_id: u64) -> Self {
        Self {
            instance_id,
            single: Mutex::new(HashMap::new()),
            single_notify: Notify::new(),
            batch: Mutex::new(HashMap::new()),
            batch_notify: Notify::new(),
            exp: Mutex::new(HashMap::new()),
            exp_notify: Notify::new(),
            exp_g2: Mutex::new(HashMap::new()),
            exp_g2_notify: Notify::new(),
            rbc: Mutex::new(RbcState::default()),
            rbc_notify: Notify::new(),
            aba: Mutex::new(AbaState::default()),
            aba_notify: Notify::new(),
        }
    }

    pub fn instance_id(&self) -> u64 {
        self.instance_id
    }

    fn missing_sequence_error(operation: &str) -> String {
        format!("{operation} registry sequence was not assigned after local insertion")
    }

    fn missing_single_entry_error(seq: usize, type_key: &str) -> String {
        format!(
            "open_share registry entry disappeared for sequence {} and type '{}'",
            seq, type_key
        )
    }

    fn missing_batch_entry_error(seq: usize, type_key: &str, batch_size: usize) -> String {
        format!(
            "batch_open_shares registry entry disappeared for sequence {}, type '{}', batch size {}",
            seq, type_key, batch_size
        )
    }

    fn missing_exp_sequence_error(kind: ExpOpenRegistryKind) -> String {
        format!(
            "{:?} open-in-exponent registry sequence was not assigned after local insertion",
            kind
        )
    }

    fn missing_exp_entry_error(kind: ExpOpenRegistryKind, seq: usize) -> String {
        format!(
            "{:?} open-in-exponent registry entry disappeared for sequence {}",
            kind, seq
        )
    }

    fn exp_registry(
        &self,
        kind: ExpOpenRegistryKind,
    ) -> &Mutex<HashMap<ExpKey, ExpOpenAccumulator>> {
        match kind {
            ExpOpenRegistryKind::G1 => &self.exp,
            ExpOpenRegistryKind::G2 => &self.exp_g2,
        }
    }

    fn notify_exp_registry(&self, kind: ExpOpenRegistryKind) {
        match kind {
            ExpOpenRegistryKind::G1 => self.exp_notify.notify_waiters(),
            ExpOpenRegistryKind::G2 => self.exp_g2_notify.notify_waiters(),
        }
    }

    fn exp_notify(&self, kind: ExpOpenRegistryKind) -> &Notify {
        match kind {
            ExpOpenRegistryKind::G1 => &self.exp_notify,
            ExpOpenRegistryKind::G2 => &self.exp_g2_notify,
        }
    }

    pub fn contribute_exp_open(
        &self,
        kind: ExpOpenRegistryKind,
        my_sequence: &mut Option<usize>,
        party_id: usize,
        share_id: usize,
        partial_point: &[u8],
        required: usize,
    ) -> Result<ExpOpenProgress, String> {
        if required == 0 {
            return Err("open-in-exponent requires at least one contribution".to_string());
        }

        let mut reg = self.exp_registry(kind).lock();

        if my_sequence.is_none() {
            let mut seq = 0usize;
            loop {
                let entry = reg.entry(seq).or_default();
                if !entry.party_ids.contains(&party_id) {
                    entry
                        .partial_points
                        .push((share_id, partial_point.to_vec()));
                    entry.party_ids.push(party_id);
                    *my_sequence = Some(seq);
                    break;
                }
                seq = seq
                    .checked_add(1)
                    .ok_or_else(|| "open-in-exponent sequence allocator overflowed".to_string())?;
            }
        }

        let seq = my_sequence.ok_or_else(|| Self::missing_exp_sequence_error(kind))?;
        let entry = reg
            .get_mut(&seq)
            .ok_or_else(|| Self::missing_exp_entry_error(kind, seq))?;

        if let Some(result) = entry.result.clone() {
            return Ok(ExpOpenProgress::Ready(result));
        }

        if entry.partial_points.len() >= required {
            let partial_points = entry
                .partial_points
                .iter()
                .take(required)
                .cloned()
                .collect();
            return Ok(ExpOpenProgress::Collected {
                sequence: seq,
                partial_points,
            });
        }

        Ok(ExpOpenProgress::Pending {
            sequence: seq,
            current_count: entry.party_ids.len(),
        })
    }

    pub fn complete_exp_open(
        &self,
        kind: ExpOpenRegistryKind,
        sequence: usize,
        result: Vec<u8>,
    ) -> Result<(), String> {
        let mut reg = self.exp_registry(kind).lock();
        let entry = reg
            .get_mut(&sequence)
            .ok_or_else(|| Self::missing_exp_entry_error(kind, sequence))?;
        entry.result = Some(result);
        drop(reg);
        self.notify_exp_registry(kind);
        Ok(())
    }

    /// Contribute a group-valued partial point and wait for reconstruction.
    pub fn exp_open_wait<R>(
        &self,
        request: ExpOpenRequest<'_>,
        reconstruct: R,
    ) -> Result<Vec<u8>, String>
    where
        R: Fn(&[(usize, Vec<u8>)]) -> Result<Vec<u8>, String>,
    {
        if request.required == 0 {
            return Err("open-in-exponent requires at least one contribution".to_string());
        }
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
                return tokio::task::block_in_place(|| {
                    handle.block_on(self.exp_open_async(request, reconstruct))
                });
            }
        }
        self.exp_open_poll(request, reconstruct)
    }

    pub(crate) async fn exp_open_async<R>(
        &self,
        request: ExpOpenRequest<'_>,
        reconstruct: R,
    ) -> Result<Vec<u8>, String>
    where
        R: Fn(&[(usize, Vec<u8>)]) -> Result<Vec<u8>, String>,
    {
        let mut my_sequence: Option<usize> = None;
        let deadline = tokio::time::Instant::now()
            + tokio::time::Duration::from_secs(OPEN_REGISTRY_WAIT_TIMEOUT.as_secs());

        loop {
            let notified = self.exp_notify(request.kind).notified();

            if let Some(result) = self.try_exp_open(request, &mut my_sequence, &reconstruct)? {
                return Ok(result);
            }

            if tokio::time::Instant::now() >= deadline {
                return Err(request.timeout_message.to_string());
            }

            tokio::select! {
                _ = notified => {}
                _ = tokio::time::sleep_until(deadline) => {}
            }
        }
    }

    fn exp_open_poll<R>(
        &self,
        request: ExpOpenRequest<'_>,
        reconstruct: R,
    ) -> Result<Vec<u8>, String>
    where
        R: Fn(&[(usize, Vec<u8>)]) -> Result<Vec<u8>, String>,
    {
        let deadline = Instant::now() + OPEN_REGISTRY_WAIT_TIMEOUT;
        let mut my_sequence: Option<usize> = None;
        loop {
            if let Some(result) = self.try_exp_open(request, &mut my_sequence, &reconstruct)? {
                return Ok(result);
            }
            if Instant::now() >= deadline {
                return Err(request.timeout_message.to_string());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn try_exp_open<R>(
        &self,
        request: ExpOpenRequest<'_>,
        my_sequence: &mut Option<usize>,
        reconstruct: &R,
    ) -> Result<Option<Vec<u8>>, String>
    where
        R: Fn(&[(usize, Vec<u8>)]) -> Result<Vec<u8>, String>,
    {
        match self.contribute_exp_open(
            request.kind,
            my_sequence,
            request.party_id,
            request.share_id,
            request.partial_point,
            request.required,
        )? {
            ExpOpenProgress::Ready(result) => Ok(Some(result)),
            ExpOpenProgress::Pending { .. } => Ok(None),
            ExpOpenProgress::Collected {
                sequence,
                partial_points,
            } => {
                let result = reconstruct(&partial_points)?;
                self.complete_exp_open(request.kind, sequence, result.clone())?;
                Ok(Some(result))
            }
        }
    }

    // -- single open --------------------------------------------------------

    pub(super) fn insert_single(&self, type_key: &str, sender_party_id: usize, share: Vec<u8>) {
        let mut reg = self.single.lock();
        let type_key = type_key.to_owned();
        let mut seq = 0usize;
        loop {
            let entry = reg.entry((seq, type_key.clone())).or_default();
            if !entry.party_ids.contains(&sender_party_id) {
                entry.shares.push(share);
                entry.party_ids.push(sender_party_id);
                break;
            }
            seq += 1;
        }
        drop(reg);
        self.single_notify.notify_waiters();
    }

    /// Contribute a single share and wait until `required` parties have contributed.
    pub fn open_share_wait<R>(
        &self,
        party_id: usize,
        type_key: &str,
        share_bytes: &[u8],
        required: usize,
        reconstruct: R,
    ) -> Result<ClearShareValue, String>
    where
        R: FnOnce(&[Vec<u8>]) -> Result<ClearShareValue, String>,
    {
        self.open_single_wait(
            party_id,
            type_key,
            share_bytes,
            required,
            reconstruct,
            OpenSingleResultCodec {
                wrap_result: OpenResult::ClearShare,
                unwrap_result: Self::expect_clear_share_result,
                operation: "open_share",
            },
        )
    }

    pub fn open_bytes_wait<R>(
        &self,
        party_id: usize,
        type_key: &str,
        share_bytes: &[u8],
        required: usize,
        reconstruct: R,
    ) -> Result<Vec<u8>, String>
    where
        R: FnOnce(&[Vec<u8>]) -> Result<Vec<u8>, String>,
    {
        self.open_single_wait(
            party_id,
            type_key,
            share_bytes,
            required,
            reconstruct,
            OpenSingleResultCodec {
                wrap_result: OpenResult::Bytes,
                unwrap_result: Self::expect_bytes_result,
                operation: "open_share_as_field",
            },
        )
    }

    fn open_single_wait<T, R, Wrap, Unwrap>(
        &self,
        party_id: usize,
        type_key: &str,
        share_bytes: &[u8],
        required: usize,
        reconstruct: R,
        codec: OpenSingleResultCodec<Wrap, Unwrap>,
    ) -> Result<T, String>
    where
        T: Clone,
        R: FnOnce(&[Vec<u8>]) -> Result<T, String>,
        Wrap: Fn(T) -> OpenResult + Copy,
        Unwrap: Fn(OpenResult) -> Result<T, String> + Copy,
    {
        if required == 0 {
            return Err(format!(
                "{} requires at least one contribution",
                codec.operation
            ));
        }
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
                return tokio::task::block_in_place(|| {
                    handle.block_on(self.open_single_async(
                        party_id,
                        type_key.to_owned(),
                        share_bytes.to_vec(),
                        required,
                        reconstruct,
                        codec,
                    ))
                });
            }
        }
        self.open_single_poll(
            party_id,
            type_key.to_owned(),
            share_bytes,
            required,
            reconstruct,
            codec,
        )
    }

    #[cfg(any(feature = "avss", feature = "honeybadger", test))]
    pub(crate) async fn open_share_async<R>(
        &self,
        party_id: usize,
        type_key: String,
        share_bytes: Vec<u8>,
        required: usize,
        reconstruct: R,
    ) -> Result<ClearShareValue, String>
    where
        R: FnOnce(&[Vec<u8>]) -> Result<ClearShareValue, String>,
    {
        self.open_single_async(
            party_id,
            type_key,
            share_bytes,
            required,
            reconstruct,
            OpenSingleResultCodec {
                wrap_result: OpenResult::ClearShare,
                unwrap_result: Self::expect_clear_share_result,
                operation: "open_share",
            },
        )
        .await
    }

    #[cfg(feature = "avss")]
    pub(crate) async fn open_bytes_async<R>(
        &self,
        party_id: usize,
        type_key: String,
        share_bytes: Vec<u8>,
        required: usize,
        reconstruct: R,
    ) -> Result<Vec<u8>, String>
    where
        R: FnOnce(&[Vec<u8>]) -> Result<Vec<u8>, String>,
    {
        self.open_single_async(
            party_id,
            type_key,
            share_bytes,
            required,
            reconstruct,
            OpenSingleResultCodec {
                wrap_result: OpenResult::Bytes,
                unwrap_result: Self::expect_bytes_result,
                operation: "open_share_as_field",
            },
        )
        .await
    }

    async fn open_single_async<T, R, Wrap, Unwrap>(
        &self,
        party_id: usize,
        type_key: String,
        share_bytes: Vec<u8>,
        required: usize,
        reconstruct: R,
        codec: OpenSingleResultCodec<Wrap, Unwrap>,
    ) -> Result<T, String>
    where
        T: Clone,
        R: FnOnce(&[Vec<u8>]) -> Result<T, String>,
        Wrap: Fn(T) -> OpenResult + Copy,
        Unwrap: Fn(OpenResult) -> Result<T, String> + Copy,
    {
        let mut my_sequence: Option<usize> = None;
        let deadline = tokio::time::Instant::now()
            + tokio::time::Duration::from_secs(OPEN_REGISTRY_WAIT_TIMEOUT.as_secs());

        loop {
            let notified = self.single_notify.notified();
            let mut inserted_local = false;

            {
                let mut reg = self.single.lock();

                if my_sequence.is_none() {
                    let mut seq = 0;
                    loop {
                        let entry = reg.entry((seq, type_key.clone())).or_default();
                        if !entry.party_ids.contains(&party_id) {
                            entry.shares.push(share_bytes.clone());
                            entry.party_ids.push(party_id);
                            my_sequence = Some(seq);
                            inserted_local = true;
                            break;
                        }
                        seq += 1;
                    }
                }

                let seq =
                    my_sequence.ok_or_else(|| Self::missing_sequence_error(codec.operation))?;
                let key = (seq, type_key.clone());
                let entry = reg
                    .get_mut(&key)
                    .ok_or_else(|| Self::missing_single_entry_error(seq, &type_key))?;

                if let Some(result) = entry.result.clone() {
                    return (codec.unwrap_result)(result);
                }

                if entry.shares.len() >= required {
                    let collected: Vec<_> = entry.shares.iter().take(required).cloned().collect();
                    drop(reg);
                    let value = reconstruct(&collected)?;
                    let mut reg = self.single.lock();
                    let key = (seq, type_key.clone());
                    let entry = reg
                        .get_mut(&key)
                        .ok_or_else(|| Self::missing_single_entry_error(seq, &type_key))?;
                    entry.result = Some((codec.wrap_result)(value.clone()));
                    drop(reg);
                    self.single_notify.notify_waiters();
                    return Ok(value);
                }

                let current_count = entry.party_ids.len();
                drop(reg);

                if tokio::time::Instant::now() >= deadline {
                    return Err(format!(
                        "Timeout waiting for {} contributions ({}/{})",
                        codec.operation, current_count, required
                    ));
                }
            }

            if inserted_local {
                self.single_notify.notify_waiters();
            }

            tokio::select! {
                _ = notified => {}
                _ = tokio::time::sleep_until(deadline) => {}
            }
        }
    }

    fn open_single_poll<T, R, Wrap, Unwrap>(
        &self,
        party_id: usize,
        type_key: String,
        share_bytes: &[u8],
        required: usize,
        reconstruct: R,
        codec: OpenSingleResultCodec<Wrap, Unwrap>,
    ) -> Result<T, String>
    where
        T: Clone,
        R: FnOnce(&[Vec<u8>]) -> Result<T, String>,
        Wrap: Fn(T) -> OpenResult + Copy,
        Unwrap: Fn(OpenResult) -> Result<T, String> + Copy,
    {
        let mut my_sequence: Option<usize> = None;
        let deadline = Instant::now() + OPEN_REGISTRY_WAIT_TIMEOUT;

        loop {
            let mut reg = self.single.lock();

            if my_sequence.is_none() {
                let mut seq = 0;
                loop {
                    let entry = reg.entry((seq, type_key.clone())).or_default();
                    if !entry.party_ids.contains(&party_id) {
                        entry.shares.push(share_bytes.to_vec());
                        entry.party_ids.push(party_id);
                        my_sequence = Some(seq);
                        break;
                    }
                    seq += 1;
                }
            }

            let seq = my_sequence.ok_or_else(|| Self::missing_sequence_error(codec.operation))?;
            let key = (seq, type_key.clone());
            let entry = reg
                .get_mut(&key)
                .ok_or_else(|| Self::missing_single_entry_error(seq, &type_key))?;

            if let Some(result) = entry.result.clone() {
                return (codec.unwrap_result)(result);
            }

            if entry.shares.len() >= required {
                let collected: Vec<_> = entry.shares.iter().take(required).cloned().collect();
                drop(reg);
                let value = reconstruct(&collected)?;
                let mut reg = self.single.lock();
                let key = (seq, type_key.clone());
                let entry = reg
                    .get_mut(&key)
                    .ok_or_else(|| Self::missing_single_entry_error(seq, &type_key))?;
                entry.result = Some((codec.wrap_result)(value.clone()));
                return Ok(value);
            }

            let current_count = entry.party_ids.len();
            drop(reg);
            if Instant::now() >= deadline {
                return Err(format!(
                    "Timeout waiting for {} contributions ({}/{})",
                    codec.operation, current_count, required
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn expect_clear_share_result(result: OpenResult) -> Result<ClearShareValue, String> {
        match result {
            OpenResult::ClearShare(value) => Ok(value),
            OpenResult::Bytes(_) => Err("open_share registry result type mismatch".to_string()),
        }
    }

    fn expect_bytes_result(result: OpenResult) -> Result<Vec<u8>, String> {
        match result {
            OpenResult::Bytes(value) => Ok(value),
            OpenResult::ClearShare(_) => {
                Err("open_share byte registry result type mismatch".to_string())
            }
        }
    }

    // -- exp open -----------------------------------------------------------

    /// Insert a partial point contribution for open-in-exponent.
    pub fn insert_exp(&self, sender_party_id: usize, share_id: usize, partial_point: Vec<u8>) {
        let mut reg = self.exp.lock();
        let mut seq = 0usize;
        loop {
            let entry = reg.entry(seq).or_default();
            if !entry.party_ids.contains(&sender_party_id) {
                entry.partial_points.push((share_id, partial_point));
                entry.party_ids.push(sender_party_id);
                break;
            }
            seq += 1;
        }
        drop(reg);
        self.exp_notify.notify_waiters();
    }

    /// Insert a partial point contribution for G2 open-in-exponent (AVSS).
    pub fn insert_exp_g2(&self, sender_party_id: usize, share_id: usize, partial_point: Vec<u8>) {
        let mut reg = self.exp_g2.lock();
        let mut seq = 0usize;
        loop {
            let entry = reg.entry(seq).or_default();
            if !entry.party_ids.contains(&sender_party_id) {
                entry.partial_points.push((share_id, partial_point));
                entry.party_ids.push(sender_party_id);
                break;
            }
            seq += 1;
        }
        drop(reg);
        self.exp_g2_notify.notify_waiters();
    }

    // -- batch open ---------------------------------------------------------

    pub(super) fn insert_batch(
        &self,
        type_key: &str,
        sender_party_id: usize,
        shares: Vec<Vec<u8>>,
    ) {
        if shares.is_empty() {
            return;
        }
        let batch_size = shares.len();
        let mut reg = self.batch.lock();
        let type_key = type_key.to_owned();
        let mut seq = 0usize;
        loop {
            let entry = reg
                .entry((seq, type_key.clone(), batch_size))
                .or_insert_with(|| BatchOpenAccumulator::new(batch_size));
            if !entry.party_ids.contains(&sender_party_id) {
                for (pos, share_bytes) in shares.into_iter().enumerate() {
                    entry.shares_per_position[pos].push(share_bytes);
                }
                entry.party_ids.push(sender_party_id);
                break;
            }
            seq += 1;
        }
        drop(reg);
        self.batch_notify.notify_waiters();
    }

    /// Batch variant of [`open_share_wait`].
    pub fn batch_open_wait<R>(
        &self,
        party_id: usize,
        type_key: &str,
        shares: &[Vec<u8>],
        required: usize,
        reconstruct_one: R,
    ) -> Result<Vec<ClearShareValue>, String>
    where
        R: Fn(&[Vec<u8>], usize) -> Result<ClearShareValue, String>,
    {
        if shares.is_empty() {
            return Ok(vec![]);
        }
        if required == 0 {
            return Err("batch_open_shares requires at least one contribution".to_string());
        }
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
                return tokio::task::block_in_place(|| {
                    handle.block_on(self.batch_open_async(
                        party_id,
                        type_key.to_owned(),
                        shares.to_vec(),
                        required,
                        reconstruct_one,
                    ))
                });
            }
        }
        self.batch_open_poll(
            party_id,
            type_key.to_owned(),
            shares,
            required,
            reconstruct_one,
        )
    }

    pub(crate) async fn batch_open_async<R>(
        &self,
        party_id: usize,
        type_key: String,
        shares: Vec<Vec<u8>>,
        required: usize,
        reconstruct_one: R,
    ) -> Result<Vec<ClearShareValue>, String>
    where
        R: Fn(&[Vec<u8>], usize) -> Result<ClearShareValue, String>,
    {
        let batch_size = shares.len();
        let mut my_sequence: Option<usize> = None;
        let deadline = tokio::time::Instant::now()
            + tokio::time::Duration::from_secs(OPEN_REGISTRY_WAIT_TIMEOUT.as_secs());

        loop {
            let notified = self.batch_notify.notified();
            let mut inserted_local = false;

            {
                let mut reg = self.batch.lock();

                if my_sequence.is_none() {
                    let mut seq = 0;
                    loop {
                        let entry = reg
                            .entry((seq, type_key.clone(), batch_size))
                            .or_insert_with(|| BatchOpenAccumulator::new(batch_size));
                        if !entry.party_ids.contains(&party_id) {
                            for (pos, share_bytes) in shares.iter().enumerate() {
                                entry.shares_per_position[pos].push(share_bytes.clone());
                            }
                            entry.party_ids.push(party_id);
                            my_sequence = Some(seq);
                            inserted_local = true;
                            break;
                        }
                        seq += 1;
                    }
                }

                let seq =
                    my_sequence.ok_or_else(|| Self::missing_sequence_error("batch_open_shares"))?;
                let key = (seq, type_key.clone(), batch_size);
                let entry = reg
                    .get_mut(&key)
                    .ok_or_else(|| Self::missing_batch_entry_error(seq, &type_key, batch_size))?;

                if let Some(results) = entry.results.clone() {
                    return Ok(results);
                }

                if entry.party_ids.len() >= required {
                    let snapshot: Vec<Vec<Vec<u8>>> = entry
                        .shares_per_position
                        .iter()
                        .map(|pos| pos.iter().take(required).cloned().collect())
                        .collect();
                    drop(reg);

                    let mut results = Vec::with_capacity(batch_size);
                    for (pos, collected) in snapshot.iter().enumerate() {
                        results.push(reconstruct_one(collected, pos)?);
                    }

                    let mut reg = self.batch.lock();
                    let key = (seq, type_key.clone(), batch_size);
                    let entry = reg.get_mut(&key).ok_or_else(|| {
                        Self::missing_batch_entry_error(seq, &type_key, batch_size)
                    })?;
                    entry.results = Some(results.clone());
                    drop(reg);
                    self.batch_notify.notify_waiters();
                    return Ok(results);
                }

                let current_count = entry.party_ids.len();
                drop(reg);

                if tokio::time::Instant::now() >= deadline {
                    return Err(format!(
                        "Timeout waiting for batch_open_shares contributions ({}/{})",
                        current_count, required
                    ));
                }
            }

            if inserted_local {
                self.batch_notify.notify_waiters();
            }

            tokio::select! {
                _ = notified => {}
                _ = tokio::time::sleep_until(deadline) => {}
            }
        }
    }

    fn batch_open_poll<R>(
        &self,
        party_id: usize,
        type_key: String,
        shares: &[Vec<u8>],
        required: usize,
        reconstruct_one: R,
    ) -> Result<Vec<ClearShareValue>, String>
    where
        R: Fn(&[Vec<u8>], usize) -> Result<ClearShareValue, String>,
    {
        let batch_size = shares.len();
        let mut my_sequence: Option<usize> = None;
        let deadline = Instant::now() + OPEN_REGISTRY_WAIT_TIMEOUT;

        loop {
            let mut reg = self.batch.lock();

            if my_sequence.is_none() {
                let mut seq = 0;
                loop {
                    let entry = reg
                        .entry((seq, type_key.clone(), batch_size))
                        .or_insert_with(|| BatchOpenAccumulator::new(batch_size));
                    if !entry.party_ids.contains(&party_id) {
                        for (pos, share_bytes) in shares.iter().enumerate() {
                            entry.shares_per_position[pos].push(share_bytes.clone());
                        }
                        entry.party_ids.push(party_id);
                        my_sequence = Some(seq);
                        break;
                    }
                    seq += 1;
                }
            }

            let seq =
                my_sequence.ok_or_else(|| Self::missing_sequence_error("batch_open_shares"))?;
            let key = (seq, type_key.clone(), batch_size);
            let entry = reg
                .get_mut(&key)
                .ok_or_else(|| Self::missing_batch_entry_error(seq, &type_key, batch_size))?;

            if let Some(results) = entry.results.clone() {
                return Ok(results);
            }

            if entry.party_ids.len() >= required {
                let snapshot: Vec<Vec<Vec<u8>>> = entry
                    .shares_per_position
                    .iter()
                    .map(|pos| pos.iter().take(required).cloned().collect())
                    .collect();
                drop(reg);

                let mut results = Vec::with_capacity(batch_size);
                for (pos, collected) in snapshot.iter().enumerate() {
                    results.push(reconstruct_one(collected, pos)?);
                }

                let mut reg = self.batch.lock();
                let key = (seq, type_key.clone(), batch_size);
                let entry = reg
                    .get_mut(&key)
                    .ok_or_else(|| Self::missing_batch_entry_error(seq, &type_key, batch_size))?;
                entry.results = Some(results.clone());
                return Ok(results);
            }

            let current_count = entry.party_ids.len();
            drop(reg);
            if Instant::now() >= deadline {
                return Err(format!(
                    "Timeout waiting for batch_open_shares contributions ({}/{})",
                    current_count, required
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
