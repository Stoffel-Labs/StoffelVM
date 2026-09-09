use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use tokio::sync::Notify;

use stoffel_vm_types::core_types::ClearShareValue;

use super::accumulators::{
    BatchKey, BatchOpenAccumulator, ExpKey, ExpOpenAccumulator, ExpOpenProgress,
    ExpOpenRegistryKind, ExpOpenRequest, OpenAccumulator, OpenResult, RbcState, SingleKey,
};
use super::wire::{MAX_BATCH_ELEMENTS, MAX_WIRE_MESSAGE_LEN};

const DEFAULT_OPEN_REGISTRY_WAIT_TIMEOUT: Duration = Duration::from_secs(600);
// A quorum can finish one batch and begin the next while a slower party still
// retains the previous batch. Keep a bounded window for that legitimate skew;
// the position and byte budgets below continue to cap retained payload data.
pub(super) const MAX_PENDING_BATCH_ENTRIES_PER_SENDER: usize = 8;
pub(super) const MAX_PENDING_BATCH_POSITIONS_PER_SENDER: usize = MAX_BATCH_ELEMENTS;
pub(super) const MAX_PENDING_BATCH_BYTES_PER_SENDER: usize = MAX_WIRE_MESSAGE_LEN / 4;
const MAX_PENDING_BATCH_ENTRIES: usize = 256;
const MAX_PENDING_BATCH_POSITIONS: usize = 256 * MAX_BATCH_ELEMENTS;
const MAX_PENDING_BATCH_BYTES: usize = 64 * MAX_WIRE_MESSAGE_LEN;
const MAX_COMPLETED_BATCH_ENTRIES: usize = 64;

fn checked_batch_payload_bytes(shares: &[Vec<u8>]) -> Result<usize, String> {
    shares.iter().try_fold(0usize, |total, share| {
        total
            .checked_add(share.len())
            .ok_or_else(|| "batch_open_shares payload byte count overflowed".to_string())
    })
}

fn checked_retained_batch_bytes(
    registry: &HashMap<BatchKey, BatchOpenAccumulator>,
    sender_party_id: usize,
) -> Result<usize, String> {
    registry.values().try_fold(0usize, |entry_total, entry| {
        if entry.results.is_some() {
            return Ok(entry_total);
        }
        let Some(sender_index) = entry
            .party_ids
            .iter()
            .position(|party_id| *party_id == sender_party_id)
        else {
            return Ok(entry_total);
        };
        entry
            .shares_per_position
            .iter()
            .filter_map(|position| position.get(sender_index))
            .try_fold(entry_total, |total, share| {
                total
                    .checked_add(share.len())
                    .ok_or_else(|| "batch_open_shares retained byte count overflowed".to_string())
            })
    })
}

fn enforce_batch_retention_budget(
    registry: &HashMap<BatchKey, BatchOpenAccumulator>,
    sender_party_id: usize,
    batch_size: usize,
    shares: &[Vec<u8>],
    creates_entry: bool,
) -> Result<(), String> {
    let pending_entries = registry
        .values()
        .filter(|entry| entry.results.is_none() && !entry.party_ids.is_empty())
        .count();
    if creates_entry && pending_entries >= MAX_PENDING_BATCH_ENTRIES {
        return Err(format!(
            "batch_open_shares aggregate entry budget is full (max {MAX_PENDING_BATCH_ENTRIES})"
        ));
    }
    let pending_positions = registry
        .iter()
        .filter(|(_, entry)| entry.results.is_none() && !entry.party_ids.is_empty())
        .try_fold(0usize, |total, ((_, _, size), entry)| {
            size.checked_mul(entry.party_ids.len())
                .and_then(|positions| total.checked_add(positions))
        });
    let Some(next_aggregate_positions) =
        pending_positions.and_then(|total| total.checked_add(batch_size))
    else {
        return Err("batch_open_shares aggregate position count overflowed".to_string());
    };
    if next_aggregate_positions > MAX_PENDING_BATCH_POSITIONS {
        return Err(format!(
            "batch_open_shares aggregate position budget exceeded: {next_aggregate_positions} (max {MAX_PENDING_BATCH_POSITIONS})"
        ));
    }

    let sender_entries = registry
        .values()
        .filter(|entry| entry.results.is_none() && entry.party_ids.contains(&sender_party_id))
        .count();
    if sender_entries >= MAX_PENDING_BATCH_ENTRIES_PER_SENDER {
        return Err(format!(
            "batch_open_shares sender {sender_party_id} entry quota is full (max {MAX_PENDING_BATCH_ENTRIES_PER_SENDER})"
        ));
    }
    let retained_positions = registry
        .iter()
        .filter(|(_, entry)| entry.results.is_none() && entry.party_ids.contains(&sender_party_id))
        .try_fold(0usize, |total, ((_, _, size), _)| total.checked_add(*size));
    let Some(next_positions) = retained_positions.and_then(|total| total.checked_add(batch_size))
    else {
        return Err("batch_open_shares retained position count overflowed".to_string());
    };
    if next_positions > MAX_PENDING_BATCH_POSITIONS_PER_SENDER {
        return Err(format!(
            "batch_open_shares sender {sender_party_id} position budget exceeded: {next_positions} (max {MAX_PENDING_BATCH_POSITIONS_PER_SENDER})"
        ));
    }

    let retained = checked_retained_batch_bytes(registry, sender_party_id)?;
    let incoming = checked_batch_payload_bytes(shares)?;
    let total = retained
        .checked_add(incoming)
        .ok_or_else(|| "batch_open_shares retained byte count overflowed".to_string())?;
    if total > MAX_PENDING_BATCH_BYTES_PER_SENDER {
        return Err(format!(
            "batch_open_shares sender {sender_party_id} retained byte budget exceeded: {total} (max {MAX_PENDING_BATCH_BYTES_PER_SENDER})"
        ));
    }
    let aggregate_retained = registry.values().try_fold(0usize, |entry_total, entry| {
        if entry.results.is_some() {
            return Ok(entry_total);
        }
        entry
            .shares_per_position
            .iter()
            .flat_map(|position| position.iter())
            .try_fold(entry_total, |total, share| {
                total.checked_add(share.len()).ok_or_else(|| {
                    "batch_open_shares aggregate retained byte count overflowed".to_string()
                })
            })
    })?;
    let aggregate_total = aggregate_retained
        .checked_add(incoming)
        .ok_or_else(|| "batch_open_shares aggregate retained byte count overflowed".to_string())?;
    if aggregate_total > MAX_PENDING_BATCH_BYTES {
        return Err(format!(
            "batch_open_shares aggregate retained byte budget exceeded: {aggregate_total} (max {MAX_PENDING_BATCH_BYTES})"
        ));
    }
    Ok(())
}

fn compact_completed_batch_entry(entry: &mut BatchOpenAccumulator) {
    entry.party_ids.clear();
    entry.party_ids.shrink_to_fit();
    for position in &mut entry.shares_per_position {
        position.clear();
        position.shrink_to_fit();
    }
}

pub(super) fn open_registry_wait_timeout() -> Duration {
    std::env::var("STOFFEL_MPC_PROTOCOL_TIMEOUT_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_OPEN_REGISTRY_WAIT_TIMEOUT)
}

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
    batch_next_sequences: Mutex<HashMap<(usize, String, usize), usize>>,
    batch_completed_order: Mutex<VecDeque<BatchKey>>,
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
}

impl InstanceRegistry {
    pub(super) fn new(instance_id: u64) -> Self {
        Self {
            instance_id,
            single: Mutex::new(HashMap::new()),
            single_notify: Notify::new(),
            batch: Mutex::new(HashMap::new()),
            batch_next_sequences: Mutex::new(HashMap::new()),
            batch_completed_order: Mutex::new(VecDeque::new()),
            batch_notify: Notify::new(),
            exp: Mutex::new(HashMap::new()),
            exp_notify: Notify::new(),
            exp_g2: Mutex::new(HashMap::new()),
            exp_g2_notify: Notify::new(),
            rbc: Mutex::new(RbcState::default()),
            rbc_notify: Notify::new(),
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

    fn allocate_batch_sequence(
        &self,
        party_id: usize,
        type_key: &str,
        batch_size: usize,
    ) -> Result<usize, String> {
        let mut sequences = self.batch_next_sequences.lock();
        let next = sequences
            .entry((party_id, type_key.to_owned(), batch_size))
            .or_default();
        let sequence = *next;
        *next = next
            .checked_add(1)
            .ok_or_else(|| "batch_open_shares sequence allocator overflowed".to_string())?;
        Ok(sequence)
    }

    fn record_completed_batch(
        &self,
        key: BatchKey,
        registry: &mut HashMap<BatchKey, BatchOpenAccumulator>,
    ) {
        let mut order = self.batch_completed_order.lock();
        if !order.contains(&key) {
            order.push_back(key);
        }
        while order.len() > MAX_COMPLETED_BATCH_ENTRIES {
            if let Some(expired) = order.pop_front() {
                registry.remove(&expired);
            }
        }
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
        sequence: Option<usize>,
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
            let seq = match sequence {
                Some(seq) => seq,
                None => {
                    let mut seq = 0usize;
                    loop {
                        let entry = reg.entry(seq).or_default();
                        if !entry.party_ids.contains(&party_id) {
                            break seq;
                        }
                        seq = seq.checked_add(1).ok_or_else(|| {
                            "open-in-exponent sequence allocator overflowed".to_string()
                        })?;
                    }
                }
            };
            let entry = reg.entry(seq).or_default();
            if let Some(pos) = entry.party_ids.iter().position(|id| *id == party_id) {
                if entry.partial_points.get(pos) != Some(&(share_id, partial_point.to_vec())) {
                    return Err(format!(
                        "conflicting {:?} open-in-exponent payload for sequence {}, party {}",
                        kind, seq, party_id
                    ));
                }
            } else {
                entry
                    .partial_points
                    .push((share_id, partial_point.to_vec()));
                entry.party_ids.push(party_id);
            }
            *my_sequence = Some(seq);
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
        let deadline = tokio::time::Instant::now() + open_registry_wait_timeout();

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
        let deadline = Instant::now() + open_registry_wait_timeout();
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
            request.sequence,
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

    pub(super) fn insert_single(
        &self,
        seq: usize,
        type_key: &str,
        sender_party_id: usize,
        share: Vec<u8>,
    ) -> Result<(), String> {
        let mut reg = self.single.lock();
        let type_key = type_key.to_owned();
        let entry = reg.entry((seq, type_key.clone())).or_default();
        if let Some(pos) = entry.party_ids.iter().position(|id| *id == sender_party_id) {
            if entry.shares.get(pos) == Some(&share) {
                return Ok(());
            }
            return Err(format!(
                "conflicting open_share payload for sequence {seq}, type '{type_key}', party {sender_party_id}"
            ));
        }
        entry.shares.push(share);
        entry.party_ids.push(sender_party_id);
        drop(reg);
        self.single_notify.notify_waiters();
        Ok(())
    }

    pub(crate) fn insert_single_next(
        &self,
        type_key: &str,
        sender_party_id: usize,
        share: Vec<u8>,
    ) -> Result<usize, String> {
        let mut reg = self.single.lock();
        let type_key = type_key.to_owned();
        let mut seq = 0usize;
        loop {
            let entry = reg.entry((seq, type_key.clone())).or_default();
            if !entry.party_ids.contains(&sender_party_id) {
                entry.shares.push(share);
                entry.party_ids.push(sender_party_id);
                drop(reg);
                self.single_notify.notify_waiters();
                return Ok(seq);
            }
            seq = seq
                .checked_add(1)
                .ok_or_else(|| "open_share sequence allocator overflowed".to_string())?;
        }
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
            None,
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
            None,
            required,
            reconstruct,
            OpenSingleResultCodec {
                wrap_result: OpenResult::Bytes,
                unwrap_result: Self::expect_bytes_result,
                operation: "open_share_as_field",
            },
        )
    }

    pub(crate) fn open_share_at_wait<R>(
        &self,
        party_id: usize,
        type_key: &str,
        sequence: usize,
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
            Some(sequence),
            required,
            reconstruct,
            OpenSingleResultCodec {
                wrap_result: OpenResult::ClearShare,
                unwrap_result: Self::expect_clear_share_result,
                operation: "open_share",
            },
        )
    }

    pub(crate) fn open_bytes_at_wait<R>(
        &self,
        party_id: usize,
        type_key: &str,
        sequence: usize,
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
            Some(sequence),
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
        sequence: Option<usize>,
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
                        sequence,
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
            sequence,
            required,
            reconstruct,
            codec,
        )
    }

    pub(crate) async fn open_share_at_async<R>(
        &self,
        party_id: usize,
        type_key: String,
        sequence: usize,
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
            Some(sequence),
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

    pub(crate) async fn open_bytes_at_async<R>(
        &self,
        party_id: usize,
        type_key: String,
        sequence: usize,
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
            Some(sequence),
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
        sequence: Option<usize>,
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
        let deadline = tokio::time::Instant::now() + open_registry_wait_timeout();

        loop {
            let notified = self.single_notify.notified();
            let mut inserted_local = false;

            {
                let mut reg = self.single.lock();

                if my_sequence.is_none() {
                    let seq = match sequence {
                        Some(seq) => seq,
                        None => {
                            let mut seq = 0usize;
                            loop {
                                let entry = reg.entry((seq, type_key.clone())).or_default();
                                if !entry.party_ids.contains(&party_id) {
                                    break seq;
                                }
                                seq = seq.checked_add(1).ok_or_else(|| {
                                    "open_share sequence allocator overflowed".to_string()
                                })?;
                            }
                        }
                    };
                    let entry = reg.entry((seq, type_key.clone())).or_default();
                    if let Some(pos) = entry.party_ids.iter().position(|id| *id == party_id) {
                        if entry.shares.get(pos) != Some(&share_bytes) {
                            return Err(format!(
                                "conflicting local {} payload for sequence {}, type '{}'",
                                codec.operation, seq, type_key
                            ));
                        }
                    } else {
                        entry.shares.push(share_bytes.clone());
                        entry.party_ids.push(party_id);
                        inserted_local = true;
                    }
                    my_sequence = Some(seq);
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
        sequence: Option<usize>,
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
        let deadline = Instant::now() + open_registry_wait_timeout();

        loop {
            let mut reg = self.single.lock();

            if my_sequence.is_none() {
                let seq = match sequence {
                    Some(seq) => seq,
                    None => {
                        let mut seq = 0usize;
                        loop {
                            let entry = reg.entry((seq, type_key.clone())).or_default();
                            if !entry.party_ids.contains(&party_id) {
                                break seq;
                            }
                            seq = seq.checked_add(1).ok_or_else(|| {
                                "open_share sequence allocator overflowed".to_string()
                            })?;
                        }
                    }
                };
                let entry = reg.entry((seq, type_key.clone())).or_default();
                if let Some(pos) = entry.party_ids.iter().position(|id| *id == party_id) {
                    if entry.shares.get(pos).map(Vec::as_slice) != Some(share_bytes) {
                        return Err(format!(
                            "conflicting local {} payload for sequence {}, type '{}'",
                            codec.operation, seq, type_key
                        ));
                    }
                } else {
                    entry.shares.push(share_bytes.to_vec());
                    entry.party_ids.push(party_id);
                }
                my_sequence = Some(seq);
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
    pub fn insert_exp(
        &self,
        seq: usize,
        sender_party_id: usize,
        share_id: usize,
        partial_point: Vec<u8>,
    ) -> Result<(), String> {
        self.insert_exp_for_kind(
            ExpOpenRegistryKind::G1,
            seq,
            sender_party_id,
            share_id,
            partial_point,
        )
    }

    /// Insert a partial point contribution for G2 open-in-exponent (AVSS).
    pub fn insert_exp_g2(
        &self,
        seq: usize,
        sender_party_id: usize,
        share_id: usize,
        partial_point: Vec<u8>,
    ) -> Result<(), String> {
        self.insert_exp_for_kind(
            ExpOpenRegistryKind::G2,
            seq,
            sender_party_id,
            share_id,
            partial_point,
        )
    }

    pub(crate) fn insert_exp_next(
        &self,
        kind: ExpOpenRegistryKind,
        sender_party_id: usize,
        share_id: usize,
        partial_point: Vec<u8>,
    ) -> Result<usize, String> {
        let mut reg = self.exp_registry(kind).lock();
        let mut seq = 0usize;
        loop {
            let entry = reg.entry(seq).or_default();
            if !entry.party_ids.contains(&sender_party_id) {
                entry.partial_points.push((share_id, partial_point));
                entry.party_ids.push(sender_party_id);
                drop(reg);
                self.notify_exp_registry(kind);
                return Ok(seq);
            }
            seq = seq
                .checked_add(1)
                .ok_or_else(|| "open-in-exponent sequence allocator overflowed".to_string())?;
        }
    }

    fn insert_exp_for_kind(
        &self,
        kind: ExpOpenRegistryKind,
        seq: usize,
        sender_party_id: usize,
        share_id: usize,
        partial_point: Vec<u8>,
    ) -> Result<(), String> {
        let mut reg = self.exp_registry(kind).lock();
        let entry = reg.entry(seq).or_default();
        if let Some(pos) = entry.party_ids.iter().position(|id| *id == sender_party_id) {
            if entry.partial_points.get(pos) == Some(&(share_id, partial_point.clone())) {
                return Ok(());
            }
            return Err(format!(
                "conflicting {:?} open-in-exponent payload for sequence {}, party {}",
                kind, seq, sender_party_id
            ));
        }
        entry.partial_points.push((share_id, partial_point));
        entry.party_ids.push(sender_party_id);
        drop(reg);
        self.notify_exp_registry(kind);
        Ok(())
    }

    // -- batch open ---------------------------------------------------------

    pub(super) fn insert_batch(
        &self,
        seq: usize,
        type_key: &str,
        sender_party_id: usize,
        shares: Vec<Vec<u8>>,
    ) -> Result<(), String> {
        if shares.is_empty() {
            return Ok(());
        }
        let batch_size = shares.len();
        if batch_size > MAX_BATCH_ELEMENTS {
            return Err(format!(
                "batch_open_shares has {batch_size} elements (max {MAX_BATCH_ELEMENTS})"
            ));
        }
        let mut reg = self.batch.lock();
        let type_key = type_key.to_owned();
        let key = (seq, type_key.clone(), batch_size);
        if self.batch_completed_order.lock().contains(&key) {
            return Ok(());
        }
        if reg.get(&key).is_some_and(|entry| entry.results.is_some()) {
            return Ok(());
        }
        if reg
            .get(&key)
            .is_none_or(|entry| !entry.party_ids.contains(&sender_party_id))
        {
            let creates_entry = !reg.contains_key(&key);
            enforce_batch_retention_budget(
                &reg,
                sender_party_id,
                batch_size,
                &shares,
                creates_entry,
            )?;
        }
        let entry = reg
            .entry(key)
            .or_insert_with(|| BatchOpenAccumulator::new(batch_size));
        if let Some(pos) = entry.party_ids.iter().position(|id| *id == sender_party_id) {
            let existing: Vec<_> = entry
                .shares_per_position
                .iter()
                .filter_map(|shares_at_pos| shares_at_pos.get(pos).cloned())
                .collect();
            if existing == shares {
                return Ok(());
            }
            return Err(format!(
                "conflicting batch_open_shares payload for sequence {seq}, type '{type_key}', party {sender_party_id}"
            ));
        }
        for (pos, share_bytes) in shares.into_iter().enumerate() {
            entry.shares_per_position[pos].push(share_bytes);
        }
        entry.party_ids.push(sender_party_id);
        drop(reg);
        self.batch_notify.notify_waiters();
        Ok(())
    }

    pub(crate) fn insert_batch_next(
        &self,
        type_key: &str,
        sender_party_id: usize,
        shares: Vec<Vec<u8>>,
    ) -> Result<usize, String> {
        if shares.is_empty() {
            return Ok(0);
        }
        let batch_size = shares.len();
        if batch_size > MAX_BATCH_ELEMENTS {
            return Err(format!(
                "batch_open_shares has {batch_size} elements (max {MAX_BATCH_ELEMENTS})"
            ));
        }
        let type_key = type_key.to_owned();
        let mut reg = self.batch.lock();
        let seq = self.allocate_batch_sequence(sender_party_id, &type_key, batch_size)?;
        let key = (seq, type_key, batch_size);
        let creates_entry = !reg.contains_key(&key);
        enforce_batch_retention_budget(&reg, sender_party_id, batch_size, &shares, creates_entry)?;
        let entry = reg
            .entry(key)
            .or_insert_with(|| BatchOpenAccumulator::new(batch_size));
        for (pos, share_bytes) in shares.into_iter().enumerate() {
            entry.shares_per_position[pos].push(share_bytes);
        }
        entry.party_ids.push(sender_party_id);
        drop(reg);
        self.batch_notify.notify_waiters();
        Ok(seq)
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
            None,
            required,
            reconstruct_one,
        )
    }

    pub(crate) fn batch_open_at_wait<R>(
        &self,
        party_id: usize,
        type_key: &str,
        sequence: usize,
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
                    handle.block_on(self.batch_open_at_async(
                        party_id,
                        type_key.to_owned(),
                        Some(sequence),
                        shares,
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
            Some(sequence),
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
        self.batch_open_at_async(party_id, type_key, None, &shares, required, reconstruct_one)
            .await
    }

    pub(crate) async fn batch_open_at_async<R>(
        &self,
        party_id: usize,
        type_key: String,
        sequence: Option<usize>,
        shares: &[Vec<u8>],
        required: usize,
        reconstruct_one: R,
    ) -> Result<Vec<ClearShareValue>, String>
    where
        R: Fn(&[Vec<u8>], usize) -> Result<ClearShareValue, String>,
    {
        let batch_size = shares.len();
        let mut my_sequence: Option<usize> = None;
        let deadline = tokio::time::Instant::now() + open_registry_wait_timeout();

        loop {
            let notified = self.batch_notify.notified();
            let mut inserted_local = false;

            {
                let mut reg = self.batch.lock();

                if my_sequence.is_none() {
                    let seq = match sequence {
                        Some(seq) => seq,
                        None => self.allocate_batch_sequence(party_id, &type_key, batch_size)?,
                    };
                    let key = (seq, type_key.clone(), batch_size);
                    if let Some(results) = reg
                        .get(&key)
                        .and_then(|entry| entry.results.as_ref())
                        .cloned()
                    {
                        return Ok(results);
                    }
                    let creates_entry = !reg.contains_key(&key);
                    if reg
                        .get(&key)
                        .is_none_or(|entry| !entry.party_ids.contains(&party_id))
                    {
                        enforce_batch_retention_budget(
                            &reg,
                            party_id,
                            batch_size,
                            shares,
                            creates_entry,
                        )?;
                    }
                    let entry = reg
                        .entry(key)
                        .or_insert_with(|| BatchOpenAccumulator::new(batch_size));
                    if let Some(pos) = entry.party_ids.iter().position(|id| *id == party_id) {
                        let existing_matches =
                            entry.shares_per_position.iter().zip(shares).all(
                                |(shares_at_pos, share)| shares_at_pos.get(pos) == Some(share),
                            );
                        if !existing_matches || entry.shares_per_position.len() != shares.len() {
                            return Err(format!(
                                "conflicting local batch_open_shares payload for sequence {}, type '{}'",
                                seq, type_key
                            ));
                        }
                    } else {
                        for (pos, share_bytes) in shares.iter().enumerate() {
                            entry.shares_per_position[pos].push(share_bytes.clone());
                        }
                        entry.party_ids.push(party_id);
                        inserted_local = true;
                    }
                    my_sequence = Some(seq);
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
                    compact_completed_batch_entry(entry);
                    self.record_completed_batch(key, &mut reg);
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

    /// Wait for one already-inserted batch and return its authenticated party
    /// IDs plus raw contributions for every position. Callers can reconstruct
    /// values whose representation is not `ClearShareValue`, such as group
    /// points used by batched exponent opening.
    pub(crate) async fn batch_collect_at_async(
        &self,
        party_id: usize,
        type_key: String,
        sequence: usize,
        shares: Vec<Vec<u8>>,
        required: usize,
    ) -> Result<(Vec<usize>, Vec<Vec<Vec<u8>>>), String> {
        if shares.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        if required == 0 {
            return Err("batch collection requires at least one contribution".to_string());
        }

        let batch_size = shares.len();
        let deadline = tokio::time::Instant::now() + open_registry_wait_timeout();
        loop {
            let notified = self.batch_notify.notified();
            let current_count = {
                let mut reg = self.batch.lock();
                let key = (sequence, type_key.clone(), batch_size);
                let entry = reg.get(&key).ok_or_else(|| {
                    Self::missing_batch_entry_error(sequence, &type_key, batch_size)
                })?;
                let local_position = entry
                    .party_ids
                    .iter()
                    .position(|id| *id == party_id)
                    .ok_or_else(|| {
                        format!(
                            "batch collection sequence {sequence}, type '{type_key}' is missing local party {party_id}"
                        )
                    })?;
                let local: Vec<_> = entry
                    .shares_per_position
                    .iter()
                    .filter_map(|position| position.get(local_position).cloned())
                    .collect();
                if local != shares {
                    return Err(format!(
                        "conflicting local batch collection payload for sequence {sequence}, type '{type_key}'"
                    ));
                }
                if entry.party_ids.len() >= required {
                    let party_ids = entry.party_ids.iter().take(required).copied().collect();
                    let contributions = entry
                        .shares_per_position
                        .iter()
                        .map(|position| position.iter().take(required).cloned().collect())
                        .collect();
                    reg.remove(&key);
                    self.record_completed_batch(key, &mut reg);
                    drop(reg);
                    self.batch_notify.notify_waiters();
                    return Ok((party_ids, contributions));
                }
                entry.party_ids.len()
            };

            if tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "Timeout waiting for raw batch contributions ({current_count}/{required})"
                ));
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
        sequence: Option<usize>,
        required: usize,
        reconstruct_one: R,
    ) -> Result<Vec<ClearShareValue>, String>
    where
        R: Fn(&[Vec<u8>], usize) -> Result<ClearShareValue, String>,
    {
        let batch_size = shares.len();
        let mut my_sequence: Option<usize> = None;
        let deadline = Instant::now() + open_registry_wait_timeout();

        loop {
            let mut reg = self.batch.lock();

            if my_sequence.is_none() {
                let seq = match sequence {
                    Some(seq) => seq,
                    None => self.allocate_batch_sequence(party_id, &type_key, batch_size)?,
                };
                let key = (seq, type_key.clone(), batch_size);
                if let Some(results) = reg
                    .get(&key)
                    .and_then(|entry| entry.results.as_ref())
                    .cloned()
                {
                    return Ok(results);
                }
                let creates_entry = !reg.contains_key(&key);
                if reg
                    .get(&key)
                    .is_none_or(|entry| !entry.party_ids.contains(&party_id))
                {
                    enforce_batch_retention_budget(
                        &reg,
                        party_id,
                        batch_size,
                        shares,
                        creates_entry,
                    )?;
                }
                let entry = reg
                    .entry(key)
                    .or_insert_with(|| BatchOpenAccumulator::new(batch_size));
                if let Some(pos) = entry.party_ids.iter().position(|id| *id == party_id) {
                    let existing: Vec<_> = entry
                        .shares_per_position
                        .iter()
                        .filter_map(|shares_at_pos| shares_at_pos.get(pos).cloned())
                        .collect();
                    if existing.iter().map(Vec::as_slice).collect::<Vec<_>>()
                        != shares.iter().map(Vec::as_slice).collect::<Vec<_>>()
                    {
                        return Err(format!(
                            "conflicting local batch_open_shares payload for sequence {}, type '{}'",
                            seq, type_key
                        ));
                    }
                } else {
                    for (pos, share_bytes) in shares.iter().enumerate() {
                        entry.shares_per_position[pos].push(share_bytes.clone());
                    }
                    entry.party_ids.push(party_id);
                }
                my_sequence = Some(seq);
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
                compact_completed_batch_entry(entry);
                self.record_completed_batch(key, &mut reg);
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
