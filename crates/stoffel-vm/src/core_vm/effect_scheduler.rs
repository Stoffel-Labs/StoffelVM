use crate::error::VmResult;
use crate::net::mpc_engine::AsyncMpcEngine;
use crate::vm_state::{CallStackCheckpoint, VMState, VmEffectKind, VmExecutionBudget, VmRunSlice};
use std::time::{Duration, Instant};
use stoffel_vm_types::core_types::Value;

// A 32K slice remains short compared with online MPC effects while reducing
// executor wakeups for local loop-heavy bytecode. Deployments that need tighter
// cooperative latency can override it with STOFFEL_VM_LOCAL_INSTRUCTION_BUDGET.
pub(super) const DEFAULT_LOCAL_INSTRUCTION_BUDGET: usize = 32_768;
pub(super) const DEFAULT_COMPLETED_EFFECT_BUDGET: usize = 64;

/// Observable evidence that one VM invocation used the cooperative async
/// scheduler instead of monopolising an executor thread.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VmCooperativeExecutionMetrics {
    /// Number of times local instruction execution exhausted its fair-use
    /// budget and explicitly yielded to Tokio.
    pub instruction_budget_yields: u64,
    /// Number of online MPC effects handed to the async engine. This is a VM
    /// scheduling boundary, but the engine future may complete immediately and
    /// therefore does not by itself prove that Tokio scheduled another task.
    pub online_effect_yields: u64,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct AsyncEffectScheduler {
    local_budget: VmExecutionBudget,
}

impl Default for AsyncEffectScheduler {
    fn default() -> Self {
        let local_instruction_budget = std::env::var("STOFFEL_VM_LOCAL_INSTRUCTION_BUDGET")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_LOCAL_INSTRUCTION_BUDGET);
        Self::new(local_instruction_budget)
    }
}

impl AsyncEffectScheduler {
    pub(crate) const fn new(local_instruction_budget: usize) -> Self {
        Self {
            local_budget: VmExecutionBudget::max_instructions(local_instruction_budget),
        }
    }

    pub(crate) async fn execute_to_depth_with_metrics<E: AsyncMpcEngine + ?Sized>(
        self,
        state: &mut VMState,
        checkpoint: CallStackCheckpoint,
        engine: &E,
    ) -> VmResult<(Value, VmCooperativeExecutionMetrics)> {
        let mut engine_identity_checked = false;
        let mut progress = AsyncMpcProgress::from_env();
        let mut completed_effects_since_yield = 0usize;

        loop {
            match state.run_until_effect_or_budget_to_depth(checkpoint, self.local_budget)? {
                VmRunSlice::Complete(value) => {
                    progress.report_final();
                    return Ok((value, progress.cooperative_metrics()));
                }
                VmRunSlice::BudgetExhausted => {
                    completed_effects_since_yield = 0;
                    progress.record_instruction_budget_yield();
                    tokio::task::yield_now().await;
                }
                VmRunSlice::Yield(effect) => {
                    if !engine_identity_checked {
                        state.ensure_async_engine_matches(engine)?;
                        engine_identity_checked = true;
                    }
                    let summary = effect.summary();
                    progress.record_effect(summary);
                    let effect_started_at = Instant::now();
                    let completed = if let Some(interval) = progress.effect_wait_interval() {
                        let mut effect_future = Box::pin(effect.execute(engine));
                        let mut next_report = Box::pin(tokio::time::sleep(interval));
                        loop {
                            tokio::select! {
                                completed = &mut effect_future => break completed?,
                                _ = &mut next_report => {
                                    progress.report_waiting_effect(summary, effect_started_at.elapsed());
                                    next_report = Box::pin(tokio::time::sleep(interval));
                                }
                            }
                        }
                    } else {
                        effect.execute(engine).await?
                    };
                    progress.record_effect_completion(summary, effect_started_at.elapsed());
                    state.apply_completed_vm_effect(completed)?;

                    // Cached or preprocessed effects may complete on their
                    // first poll. A fixed completed-effect budget is enough to
                    // bound executor monopolization without tracking the poll
                    // history of every protocol future.
                    completed_effects_since_yield = completed_effects_since_yield.saturating_add(1);
                    if completed_effects_since_yield >= DEFAULT_COMPLETED_EFFECT_BUDGET {
                        completed_effects_since_yield = 0;
                        tokio::task::yield_now().await;
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
struct AsyncMpcProgress {
    interval: Option<Duration>,
    effect_wait_interval: Option<Duration>,
    profile_enabled: bool,
    started_at: Instant,
    last_report_at: Instant,
    instruction_budget_yields: u64,
    effects: u64,
    effect_time: Duration,
    slowest_effect: Option<(VmEffectKind, usize, Duration)>,
    inputs: u64,
    input_time: Duration,
    multiplies: u64,
    multiply_time: Duration,
    boolean_bits: u64,
    boolean_bit_time: Duration,
    opens: u64,
    open_time: Duration,
    builtin_inputs: u64,
    builtin_input_time: Duration,
    builtin_muls: u64,
    builtin_mul_time: Duration,
    builtin_batch_muls: u64,
    builtin_batch_mul_items: u64,
    builtin_batch_mul_item_buckets: [u64; 10],
    builtin_batch_mul_time: Duration,
    builtin_opens: u64,
    builtin_open_time: Duration,
    builtin_batch_opens: u64,
    builtin_batch_open_items: u64,
    builtin_batch_open_time: Duration,
    builtin_other: u64,
    builtin_other_time: Duration,
}

impl AsyncMpcProgress {
    fn from_env() -> Self {
        let now = Instant::now();
        let interval = std::env::var("STOFFEL_VM_MPC_PROGRESS_INTERVAL_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .map(Duration::from_secs);
        let effect_wait_interval = std::env::var("STOFFEL_VM_MPC_EFFECT_TRACE_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .map(Duration::from_secs);
        let profile_enabled = std::env::var("STOFFEL_VM_MPC_PROFILE")
            .ok()
            .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "on"));
        Self {
            interval,
            effect_wait_interval,
            profile_enabled,
            started_at: now,
            last_report_at: now,
            instruction_budget_yields: 0,
            effects: 0,
            effect_time: Duration::ZERO,
            slowest_effect: None,
            inputs: 0,
            input_time: Duration::ZERO,
            multiplies: 0,
            multiply_time: Duration::ZERO,
            boolean_bits: 0,
            boolean_bit_time: Duration::ZERO,
            opens: 0,
            open_time: Duration::ZERO,
            builtin_inputs: 0,
            builtin_input_time: Duration::ZERO,
            builtin_muls: 0,
            builtin_mul_time: Duration::ZERO,
            builtin_batch_muls: 0,
            builtin_batch_mul_items: 0,
            builtin_batch_mul_item_buckets: [0; 10],
            builtin_batch_mul_time: Duration::ZERO,
            builtin_opens: 0,
            builtin_open_time: Duration::ZERO,
            builtin_batch_opens: 0,
            builtin_batch_open_items: 0,
            builtin_batch_open_time: Duration::ZERO,
            builtin_other: 0,
            builtin_other_time: Duration::ZERO,
        }
    }

    fn record_instruction_budget_yield(&mut self) {
        self.instruction_budget_yields = self.instruction_budget_yields.saturating_add(1);
        self.report_if_due();
    }

    fn cooperative_metrics(&self) -> VmCooperativeExecutionMetrics {
        VmCooperativeExecutionMetrics {
            instruction_budget_yields: self.instruction_budget_yields,
            online_effect_yields: self.effects,
        }
    }

    fn record_effect(&mut self, summary: crate::vm_state::VmEffectSummary) {
        self.effects = self.effects.saturating_add(1);
        let items = u64::try_from(summary.items).unwrap_or(u64::MAX);
        match summary.kind {
            VmEffectKind::Input => self.inputs = self.inputs.saturating_add(1),
            VmEffectKind::Multiply => self.multiplies = self.multiplies.saturating_add(1),
            VmEffectKind::BooleanBit => self.boolean_bits = self.boolean_bits.saturating_add(1),
            VmEffectKind::Open => self.opens = self.opens.saturating_add(1),
            VmEffectKind::BuiltinInput => {
                self.builtin_inputs = self.builtin_inputs.saturating_add(1)
            }
            VmEffectKind::BuiltinMul => self.builtin_muls = self.builtin_muls.saturating_add(1),
            VmEffectKind::BuiltinBatchMul => {
                self.builtin_batch_muls = self.builtin_batch_muls.saturating_add(1);
                self.builtin_batch_mul_items = self.builtin_batch_mul_items.saturating_add(items);
                let bucket = match summary.items {
                    0 | 1 => 0,
                    2 => 1,
                    3 | 4 => 2,
                    5..=8 => 3,
                    9..=16 => 4,
                    17..=32 => 5,
                    33..=64 => 6,
                    65..=128 => 7,
                    129..=256 => 8,
                    _ => 9,
                };
                self.builtin_batch_mul_item_buckets[bucket] =
                    self.builtin_batch_mul_item_buckets[bucket].saturating_add(1);
            }
            VmEffectKind::BuiltinOpen => self.builtin_opens = self.builtin_opens.saturating_add(1),
            VmEffectKind::BuiltinBatchOpen => {
                self.builtin_batch_opens = self.builtin_batch_opens.saturating_add(1);
                self.builtin_batch_open_items = self.builtin_batch_open_items.saturating_add(items);
            }
            VmEffectKind::BuiltinOther => self.builtin_other = self.builtin_other.saturating_add(1),
        }
        self.report_if_due();
    }

    fn record_effect_completion(
        &mut self,
        summary: crate::vm_state::VmEffectSummary,
        elapsed: Duration,
    ) {
        self.effect_time += elapsed;
        match summary.kind {
            VmEffectKind::Input => self.input_time += elapsed,
            VmEffectKind::Multiply => self.multiply_time += elapsed,
            VmEffectKind::BooleanBit => self.boolean_bit_time += elapsed,
            VmEffectKind::Open => self.open_time += elapsed,
            VmEffectKind::BuiltinInput => self.builtin_input_time += elapsed,
            VmEffectKind::BuiltinMul => self.builtin_mul_time += elapsed,
            VmEffectKind::BuiltinBatchMul => self.builtin_batch_mul_time += elapsed,
            VmEffectKind::BuiltinOpen => self.builtin_open_time += elapsed,
            VmEffectKind::BuiltinBatchOpen => self.builtin_batch_open_time += elapsed,
            VmEffectKind::BuiltinOther => self.builtin_other_time += elapsed,
        }

        let should_replace = self
            .slowest_effect
            .as_ref()
            .is_none_or(|(_, _, slowest)| elapsed > *slowest);
        if should_replace {
            self.slowest_effect = Some((summary.kind, summary.items, elapsed));
        }
    }

    fn report_if_due(&mut self) {
        let Some(interval) = self.interval else {
            return;
        };
        if self.last_report_at.elapsed() >= interval {
            self.report("progress");
            self.last_report_at = Instant::now();
        }
    }

    fn effect_wait_interval(&self) -> Option<Duration> {
        self.effect_wait_interval
    }

    fn report_waiting_effect(&self, summary: crate::vm_state::VmEffectSummary, elapsed: Duration) {
        eprintln!(
            "[vm async mpc waiting] kind={:?} items={} elapsed={:.1}s effects_completed={} batch_mul_items_completed={}",
            summary.kind,
            summary.items,
            elapsed.as_secs_f64(),
            self.effects.saturating_sub(1),
            self.builtin_batch_mul_items,
        );
    }

    fn report_final(&self) {
        if self.interval.is_some() || self.profile_enabled {
            self.report("complete");
            if self.profile_enabled {
                self.report_profile();
            }
        }
    }

    fn report(&self, label: &str) {
        let elapsed = self.started_at.elapsed().as_secs_f64();
        let effect_rate = if elapsed > 0.0 {
            self.effects as f64 / elapsed
        } else {
            0.0
        };
        eprintln!(
            "[vm async mpc {label}] elapsed={:.1}s effects={} rate={:.2}/s instruction_budget_yields={} input={} mul={} bool={} open={} builtin_input={} builtin_mul={} batch_mul={} batch_mul_items={} builtin_open={} batch_open={} batch_open_items={} builtin_other={}",
            elapsed,
            self.effects,
            effect_rate,
            self.instruction_budget_yields,
            self.inputs,
            self.multiplies,
            self.boolean_bits,
            self.opens,
            self.builtin_inputs,
            self.builtin_muls,
            self.builtin_batch_muls,
            self.builtin_batch_mul_items,
            self.builtin_opens,
            self.builtin_batch_opens,
            self.builtin_batch_open_items,
            self.builtin_other,
        );
    }

    fn report_profile(&self) {
        let slowest = self
            .slowest_effect
            .map(|(kind, items, elapsed)| {
                format!(
                    "{kind:?}/items={items}/elapsed={:.3}s",
                    elapsed.as_secs_f64()
                )
            })
            .unwrap_or_else(|| "none".to_owned());

        eprintln!(
            "[vm async mpc profile] effect_time={:.3}s input_time={:.3}s mul_time={:.3}s bool_time={:.3}s open_time={:.3}s builtin_input_time={:.3}s builtin_mul_time={:.3}s batch_mul_time={:.3}s builtin_open_time={:.3}s batch_open_time={:.3}s builtin_other_time={:.3}s slowest={}",
            self.effect_time.as_secs_f64(),
            self.input_time.as_secs_f64(),
            self.multiply_time.as_secs_f64(),
            self.boolean_bit_time.as_secs_f64(),
            self.open_time.as_secs_f64(),
            self.builtin_input_time.as_secs_f64(),
            self.builtin_mul_time.as_secs_f64(),
            self.builtin_batch_mul_time.as_secs_f64(),
            self.builtin_open_time.as_secs_f64(),
            self.builtin_batch_open_time.as_secs_f64(),
            self.builtin_other_time.as_secs_f64(),
            slowest,
        );
        eprintln!(
            "[vm async mpc profile batch_mul_items] calls_by_items=1:{} 2:{} 3-4:{} 5-8:{} 9-16:{} 17-32:{} 33-64:{} 65-128:{} 129-256:{} >256:{}",
            self.builtin_batch_mul_item_buckets[0],
            self.builtin_batch_mul_item_buckets[1],
            self.builtin_batch_mul_item_buckets[2],
            self.builtin_batch_mul_item_buckets[3],
            self.builtin_batch_mul_item_buckets[4],
            self.builtin_batch_mul_item_buckets[5],
            self.builtin_batch_mul_item_buckets[6],
            self.builtin_batch_mul_item_buckets[7],
            self.builtin_batch_mul_item_buckets[8],
            self.builtin_batch_mul_item_buckets[9],
        );
    }
}
