//! Lightweight server metrics counters and immutable snapshots.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerMetricsSnapshot {
    pub connected_peers: u64,
    pub connected_clients: u64,
    pub computations_completed: u64,
    pub computations_failed: u64,
    pub preprocessing_triples_remaining: u64,
    pub preprocessing_random_shares_remaining: u64,
    pub computation_latency_ms: u64,
    pub computation_latency_count: u64,
    pub computation_latency_total_ms: u64,
    pub computation_latency_max_ms: u64,
    pub consensus_latency_ms: u64,
    pub consensus_latency_count: u64,
    pub consensus_latency_total_ms: u64,
    pub consensus_latency_max_ms: u64,
}

impl ServerMetricsSnapshot {
    pub fn computation_latency_average_ms(&self) -> Option<u64> {
        average(
            self.computation_latency_total_ms,
            self.computation_latency_count,
        )
    }

    pub fn consensus_latency_average_ms(&self) -> Option<u64> {
        average(
            self.consensus_latency_total_ms,
            self.consensus_latency_count,
        )
    }

    pub fn computation_count(&self) -> u64 {
        self.computations_completed
            .saturating_add(self.computations_failed)
    }
}

#[derive(Debug, Default)]
pub struct ServerMetrics {
    connected_peers: AtomicU64,
    connected_clients: AtomicU64,
    computations_completed: AtomicU64,
    computations_failed: AtomicU64,
    preprocessing_triples_remaining: AtomicU64,
    preprocessing_random_shares_remaining: AtomicU64,
    computation_latency_ms: AtomicU64,
    computation_latency_count: AtomicU64,
    computation_latency_total_ms: AtomicU64,
    computation_latency_max_ms: AtomicU64,
    consensus_latency_ms: AtomicU64,
    consensus_latency_count: AtomicU64,
    consensus_latency_total_ms: AtomicU64,
    consensus_latency_max_ms: AtomicU64,
}

impl ServerMetrics {
    pub fn snapshot(&self) -> ServerMetricsSnapshot {
        ServerMetricsSnapshot {
            connected_peers: self.connected_peers(),
            connected_clients: self.connected_clients(),
            computations_completed: self.computations_completed(),
            computations_failed: self.computations_failed(),
            preprocessing_triples_remaining: self.preprocessing_triples_remaining(),
            preprocessing_random_shares_remaining: self.preprocessing_random_shares_remaining(),
            computation_latency_ms: self.computation_latency_ms(),
            computation_latency_count: self.computation_latency_count(),
            computation_latency_total_ms: self.computation_latency_total_ms(),
            computation_latency_max_ms: self.computation_latency_max_ms(),
            consensus_latency_ms: self.consensus_latency_ms(),
            consensus_latency_count: self.consensus_latency_count(),
            consensus_latency_total_ms: self.consensus_latency_total_ms(),
            consensus_latency_max_ms: self.consensus_latency_max_ms(),
        }
    }

    pub fn connected_peers(&self) -> u64 {
        self.connected_peers.load(Ordering::Relaxed)
    }

    pub fn connected_clients(&self) -> u64 {
        self.connected_clients.load(Ordering::Relaxed)
    }

    pub fn computations_completed(&self) -> u64 {
        self.computations_completed.load(Ordering::Relaxed)
    }

    pub fn computations_failed(&self) -> u64 {
        self.computations_failed.load(Ordering::Relaxed)
    }

    pub fn preprocessing_triples_remaining(&self) -> u64 {
        self.preprocessing_triples_remaining.load(Ordering::Relaxed)
    }

    pub fn preprocessing_random_shares_remaining(&self) -> u64 {
        self.preprocessing_random_shares_remaining
            .load(Ordering::Relaxed)
    }

    pub fn computation_latency_ms(&self) -> u64 {
        self.computation_latency_ms.load(Ordering::Relaxed)
    }

    pub fn computation_latency_count(&self) -> u64 {
        self.computation_latency_count.load(Ordering::Relaxed)
    }

    pub fn computation_latency_total_ms(&self) -> u64 {
        self.computation_latency_total_ms.load(Ordering::Relaxed)
    }

    pub fn computation_latency_max_ms(&self) -> u64 {
        self.computation_latency_max_ms.load(Ordering::Relaxed)
    }

    pub fn computation_latency_average_ms(&self) -> Option<u64> {
        average(
            self.computation_latency_total_ms(),
            self.computation_latency_count(),
        )
    }

    pub fn consensus_latency_ms(&self) -> u64 {
        self.consensus_latency_ms.load(Ordering::Relaxed)
    }

    pub fn consensus_latency_count(&self) -> u64 {
        self.consensus_latency_count.load(Ordering::Relaxed)
    }

    pub fn consensus_latency_total_ms(&self) -> u64 {
        self.consensus_latency_total_ms.load(Ordering::Relaxed)
    }

    pub fn consensus_latency_max_ms(&self) -> u64 {
        self.consensus_latency_max_ms.load(Ordering::Relaxed)
    }

    pub fn consensus_latency_average_ms(&self) -> Option<u64> {
        average(
            self.consensus_latency_total_ms(),
            self.consensus_latency_count(),
        )
    }

    pub fn record_connected_peers(&self, value: u64) {
        self.connected_peers.store(value, Ordering::Relaxed);
    }

    pub fn record_connected_clients(&self, value: u64) {
        self.connected_clients.store(value, Ordering::Relaxed);
    }

    pub fn record_preprocessing_triples_remaining(&self, value: u64) {
        self.preprocessing_triples_remaining
            .store(value, Ordering::Relaxed);
    }

    pub fn record_preprocessing_random_shares_remaining(&self, value: u64) {
        self.preprocessing_random_shares_remaining
            .store(value, Ordering::Relaxed);
    }

    pub fn record_preprocessing_remaining(&self, triples: u64, random_shares: u64) {
        self.record_preprocessing_triples_remaining(triples);
        self.record_preprocessing_random_shares_remaining(random_shares);
    }

    pub fn record_computation_latency_ms(&self, value: u64) {
        self.computation_latency_ms.store(value, Ordering::Relaxed);
        self.computation_latency_count
            .fetch_add(1, Ordering::Relaxed);
        saturating_fetch_add(&self.computation_latency_total_ms, value);
        self.computation_latency_max_ms
            .fetch_max(value, Ordering::Relaxed);
    }

    pub fn record_computation_latency(&self, duration: Duration) {
        self.record_computation_latency_ms(duration_to_millis(duration));
    }

    pub fn record_consensus_latency_ms(&self, value: u64) {
        self.consensus_latency_ms.store(value, Ordering::Relaxed);
        self.consensus_latency_count.fetch_add(1, Ordering::Relaxed);
        saturating_fetch_add(&self.consensus_latency_total_ms, value);
        self.consensus_latency_max_ms
            .fetch_max(value, Ordering::Relaxed);
    }

    pub fn record_consensus_latency(&self, duration: Duration) {
        self.record_consensus_latency_ms(duration_to_millis(duration));
    }

    pub fn increment_computations_completed(&self) -> u64 {
        self.computations_completed.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn increment_computations_failed(&self) -> u64 {
        self.computations_failed.fetch_add(1, Ordering::Relaxed) + 1
    }
}

fn average(total: u64, count: u64) -> Option<u64> {
    (count > 0).then_some(total / count)
}

fn duration_to_millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

fn saturating_fetch_add(value: &AtomicU64, increment: u64) {
    let mut current = value.load(Ordering::Relaxed);
    loop {
        let updated = current.saturating_add(increment);
        match value.compare_exchange_weak(current, updated, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}
