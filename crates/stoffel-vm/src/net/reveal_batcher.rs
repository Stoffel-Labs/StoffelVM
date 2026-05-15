//! Local batching for secret-share reveal operations.
//!
//! The VM queues secret-to-clear register moves here so a backend can open
//! multiple shares with fewer protocol round trips.

use crate::net::mpc_engine::MpcEngine;
use crate::reveal_destination::{FrameDepth, RevealDestination};
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
    enabled: bool,
    max_pending: usize,
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
            enabled: true,
            max_pending: 1024,
        }
    }

    #[inline]
    pub(crate) fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub(crate) fn queue(&mut self, destination: RevealDestination, ty: ShareType, data: ShareData) {
        self.cancel_destination(destination);
        self.pending.push(QueuedReveal {
            destination,
            share_type: ty,
            share_data: data,
        });
    }

    #[inline]
    pub(crate) fn has_pending_frame(&self, frame_depth: FrameDepth) -> bool {
        self.pending
            .iter()
            .any(|queued| queued.destination.frame_depth() == frame_depth)
    }

    #[inline]
    pub(crate) fn has_pending_destination(&self, destination: RevealDestination) -> bool {
        self.pending
            .iter()
            .any(|queued| queued.destination == destination)
    }

    pub(crate) fn cancel_destination(&mut self, destination: RevealDestination) {
        self.pending
            .retain(|queued| queued.destination != destination);
    }

    pub(crate) fn clear_frame(&mut self, frame_depth: FrameDepth) {
        self.pending
            .retain(|queued| queued.destination.frame_depth() != frame_depth);
    }

    pub(crate) fn clear_frames_at_or_above(&mut self, depth: FrameDepth) {
        self.pending
            .retain(|queued| queued.destination.frame_depth() < depth);
    }

    pub(crate) fn clear_all(&mut self) {
        self.pending.clear();
    }

    #[inline]
    pub(crate) fn should_auto_flush(&self, frame_depth: FrameDepth) -> bool {
        self.pending
            .iter()
            .filter(|queued| queued.destination.frame_depth() == frame_depth)
            .count()
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
}
