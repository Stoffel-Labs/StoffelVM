//! Local batching for secret-share reveal operations.
//!
//! The VM queues secret-to-clear register moves here so a backend can open
//! multiple shares with fewer protocol round trips.

use crate::net::mpc_engine::MpcEngine;
use crate::reveal_destination::{FrameDepth, RevealDestination};
use rustc_hash::FxHashMap;
use stoffel_vm_types::core_types::{ShareData, ShareDataFormat, ShareType, Value};

pub(crate) type RevealBatchResult<T> = Result<T, RevealBatchError>;

#[derive(Debug, thiserror::Error)]
pub(crate) enum RevealBatchError {
    #[error("Batch reveal for {share_type:?} failed: {reason}")]
    Backend {
        share_type: ShareType,
        reason: String,
    },
    #[error("Batch reveal count mismatch for {share_type:?}: got {actual}, expected {expected}")]
    CountMismatch {
        share_type: ShareType,
        actual: usize,
        expected: usize,
    },
    #[error("Missing batched reveal result at index {index}")]
    MissingResult { index: usize },
}

#[derive(Clone)]
struct QueuedReveal {
    destination: RevealDestination,
    share_type: ShareType,
    share_data: ShareData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RevealedRegister {
    destination: RevealDestination,
    value: Value,
}

impl RevealedRegister {
    #[cfg(test)]
    pub(crate) const fn destination(&self) -> RevealDestination {
        self.destination
    }

    #[cfg(test)]
    pub(crate) const fn register_index(&self) -> usize {
        self.destination.register().index()
    }

    #[cfg(test)]
    pub(crate) fn value(&self) -> &Value {
        &self.value
    }

    pub(crate) fn into_parts(self) -> (RevealDestination, Value) {
        (self.destination, self.value)
    }
}

pub(crate) struct RevealBatcher {
    pending: Vec<QueuedReveal>,
    index: Option<Box<RevealBatchIndex>>,
    enabled: bool,
    max_pending: usize,
}

#[derive(Default)]
struct RevealBatchIndex {
    by_destination: FxHashMap<RevealDestination, usize>,
    by_frame: FxHashMap<FrameDepth, usize>,
}

impl RevealBatchIndex {
    fn insert(&mut self, destination: RevealDestination, index: usize) {
        self.by_destination.insert(destination, index);
        *self.by_frame.entry(destination.frame_depth()).or_insert(0) += 1;
    }

    fn decrement_frame_count(&mut self, frame_depth: FrameDepth) {
        let should_remove = if let Some(count) = self.by_frame.get_mut(&frame_depth) {
            *count = count.saturating_sub(1);
            *count == 0
        } else {
            false
        };

        if should_remove {
            self.by_frame.remove(&frame_depth);
        }
    }
}

impl Default for RevealBatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl RevealBatcher {
    pub(crate) fn new() -> Self {
        Self {
            pending: Vec::new(),
            index: None,
            enabled: true,
            max_pending: 1024,
        }
    }

    #[inline]
    pub(crate) fn is_enabled(&self) -> bool {
        self.enabled
    }

    #[inline]
    pub(crate) fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    pub(crate) fn queue(&mut self, destination: RevealDestination, ty: ShareType, data: ShareData) {
        if let Some(index) = self.index.as_ref() {
            if let Some(&pending_index) = index.by_destination.get(&destination) {
                self.pending[pending_index] = QueuedReveal {
                    destination,
                    share_type: ty,
                    share_data: data,
                };
                return;
            }
        }

        let pending_index = self.pending.len();
        self.pending.push(QueuedReveal {
            destination,
            share_type: ty,
            share_data: data,
        });
        self.index_mut().insert(destination, pending_index);
    }

    #[inline]
    pub(crate) fn has_pending_frame(&self, frame_depth: FrameDepth) -> bool {
        self.index
            .as_ref()
            .is_some_and(|index| index.by_frame.contains_key(&frame_depth))
    }

    #[inline]
    pub(crate) fn has_pending_destination(&self, destination: RevealDestination) -> bool {
        self.index
            .as_ref()
            .is_some_and(|index| index.by_destination.contains_key(&destination))
    }

    pub(crate) fn cancel_destination(&mut self, destination: RevealDestination) {
        if self.pending.is_empty() {
            return;
        }

        let Some(index) = self.index.as_mut() else {
            return;
        };
        let Some(pending_index) = index.by_destination.remove(&destination) else {
            return;
        };

        let removed = self.pending.remove(pending_index);
        index.decrement_frame_count(removed.destination.frame_depth());
        if self.pending.is_empty() {
            self.index = None;
            return;
        }
        self.reindex_from(pending_index);
    }

    pub(crate) fn clear_frame(&mut self, frame_depth: FrameDepth) {
        if !self.has_pending_frame(frame_depth) {
            return;
        }

        self.pending
            .retain(|queued| queued.destination.frame_depth() != frame_depth);
        self.rebuild_indices();
    }

    pub(crate) fn clear_frames_at_or_above(&mut self, depth: FrameDepth) {
        self.pending
            .retain(|queued| queued.destination.frame_depth() < depth);
        self.rebuild_indices();
    }

    pub(crate) fn clear_all(&mut self) {
        self.pending.clear();
        self.index = None;
    }

    #[inline]
    pub(crate) fn should_auto_flush(&self, frame_depth: FrameDepth) -> bool {
        self.index
            .as_ref()
            .and_then(|index| index.by_frame.get(&frame_depth).copied())
            .unwrap_or_default()
            >= self.max_pending
    }

    pub(crate) fn flush(
        &mut self,
        frame_depth: FrameDepth,
        engine: &dyn MpcEngine,
    ) -> RevealBatchResult<Vec<RevealedRegister>> {
        let selected_indices: Vec<usize> = self
            .pending
            .iter()
            .enumerate()
            .filter_map(|(idx, queued)| {
                (queued.destination.frame_depth() == frame_depth).then_some(idx)
            })
            .collect();

        if selected_indices.is_empty() {
            return Ok(vec![]);
        }

        // Group by share type and representation so mixed queues do not decode
        // or open under the wrong backend payload shape.
        let mut grouped_indices: Vec<((ShareType, ShareDataFormat), Vec<usize>)> = Vec::new();
        for &idx in &selected_indices {
            let queued = &self.pending[idx];
            let group_key = (queued.share_type, queued.share_data.format());
            if let Some((_, indices)) = grouped_indices
                .iter_mut()
                .find(|(existing_key, _)| *existing_key == group_key)
            {
                indices.push(idx);
            } else {
                grouped_indices.push((group_key, vec![idx]));
            }
        }

        let mut revealed_by_index: Vec<Option<Value>> = vec![None; self.pending.len()];
        for ((share_type, _format), indices) in grouped_indices {
            let shares: Vec<Vec<u8>> = indices
                .iter()
                .map(|idx| self.pending[*idx].share_data.as_bytes().to_vec())
                .collect();
            let revealed = engine
                .batch_open_shares(share_type, &shares)
                .map_err(|reason| RevealBatchError::Backend {
                    share_type,
                    reason: reason.to_string(),
                })?;
            if revealed.len() != indices.len() {
                return Err(RevealBatchError::CountMismatch {
                    share_type,
                    actual: revealed.len(),
                    expected: indices.len(),
                });
            }
            for (pos, value) in revealed.into_iter().enumerate() {
                revealed_by_index[indices[pos]] = Some(value.into_vm_value());
            }
        }

        let mut results = Vec::with_capacity(selected_indices.len());
        for idx in selected_indices {
            let queued = &self.pending[idx];
            let value = revealed_by_index[idx]
                .take()
                .ok_or(RevealBatchError::MissingResult { index: idx })?;
            results.push(RevealedRegister {
                destination: queued.destination,
                value,
            });
        }

        self.clear_frame(frame_depth);
        Ok(results)
    }

    fn index_mut(&mut self) -> &mut RevealBatchIndex {
        self.index
            .get_or_insert_with(|| Box::new(RevealBatchIndex::default()))
    }

    fn rebuild_indices(&mut self) {
        if self.pending.is_empty() {
            self.index = None;
            return;
        }

        let mut batch_index = RevealBatchIndex::default();
        for pending_index in 0..self.pending.len() {
            let destination = self.pending[pending_index].destination;
            batch_index.insert(destination, pending_index);
        }
        self.index = Some(Box::new(batch_index));
    }

    fn reindex_from(&mut self, start: usize) {
        let Some(batch_index) = self.index.as_mut() else {
            return;
        };

        for pending_index in start..self.pending.len() {
            batch_index
                .by_destination
                .insert(self.pending[pending_index].destination, pending_index);
        }
    }
}
