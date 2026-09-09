//! Interprocedural preprocessing-demand analysis.
//!
//! StoffelLang programs consume MPC preprocessing material (Beaver triples,
//! random bits/ints) as they execute. The runtime needs an accurate up-front
//! estimate so it can pre-generate exactly that much material. A naive
//! intraprocedural count massively undercounts: it cannot see that a helper
//! containing one secret multiplication is called inside `for i in 0..10`
//! (×10), nor that `Share.batch_mul(a, b)` consumes `len(a)` triples when `a`'s
//! length is determined by a caller.
//!
//! This module performs a small abstract interpretation over the AST, threading
//! two abstract domains through a pure (side-effect-free) evaluator:
//!
//! * [`Len`] — the statically known length of a list-typed value (for sizing
//!   `batch_mul`, folding `.len()`, and counting list-iteration loops).
//! * [`Secrecy`] — whether a value is secret, clear, or unknown (to recognise
//!   the secret×secret operations that actually consume a triple).
//!
//! The result is a [`PreprocessingDemand`] (reused verbatim from
//! `stoffel-vm-types`) describing the total material one program run consumes.
//! When a path cannot be sized statically (recursion, runtime-sized batches,
//! data-dependent loops) the analysis sets `dynamic = true` rather than silently
//! undercounting.

use std::collections::HashMap;

use crate::ast::{AstNode, Parameter, Value};
use stoffel_vm_types::compiled_binary::{MpcBackend, PreprocessingDemand};
use stoffel_vm_types::core_types::DEFAULT_FIXED_POINT_FRACTIONAL_BITS;

/// Statically known list shape of a value: its length and, recursively, the
/// shape of its elements (so nested lists like `list[list[secret bool]]` can be
/// sized — e.g. an AES state of 16 bytes, each 8 bits).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Len {
    /// A list of exactly `len` elements, each having element shape `elem`.
    Known { len: usize, elem: Box<Len> },
    /// Not a list, or a length only known at runtime.
    Unknown,
}

impl Len {
    /// A list of `len` elements whose own shapes are unknown (a flat list).
    fn flat(len: usize) -> Len {
        Len::Known {
            len,
            elem: Box::new(Len::Unknown),
        }
    }

    /// The outer element count, if statically known.
    fn count(&self) -> Option<usize> {
        match self {
            Len::Known { len, .. } => Some(*len),
            Len::Unknown => None,
        }
    }

    /// The shape of this list's elements (`Unknown` if not a known list).
    fn element(&self) -> Len {
        match self {
            Len::Known { elem, .. } => (**elem).clone(),
            Len::Unknown => Len::Unknown,
        }
    }
}

/// Whether a value (or, for lists, its elements) is secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Secrecy {
    Secret,
    Clear,
    Unknown,
}

impl Secrecy {
    /// Result secrecy of an arithmetic combination of two operands: secret if
    /// either side is secret, clear if both are clear, otherwise unknown.
    fn join_arith(self, other: Secrecy) -> Secrecy {
        match (self, other) {
            (Secrecy::Secret, _) | (_, Secrecy::Secret) => Secrecy::Secret,
            (Secrecy::Clear, Secrecy::Clear) => Secrecy::Clear,
            _ => Secrecy::Unknown,
        }
    }

    /// Merge secrecy across two control-flow branches that may both reach a use.
    fn merge_branch(self, other: Secrecy) -> Secrecy {
        if self == other {
            self
        } else {
            Secrecy::Unknown
        }
    }
}

impl std::hash::Hash for Secrecy {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        (*self as u8).hash(state);
    }
}

/// The abstract value an expression evaluates to: its list shape, its secrecy,
/// and — for clear integers — its constant value (used for loop bounds).
#[derive(Debug, Clone)]
struct AbstractValue {
    len: Len,
    secrecy: Secrecy,
    /// Statically known clear integer value, if any.
    int: Option<u64>,
    /// Fractional bits of a secret fixed-point value, for `/` truncation cost.
    frac_bits: Option<usize>,
}

impl AbstractValue {
    fn unknown() -> Self {
        AbstractValue {
            len: Len::Unknown,
            secrecy: Secrecy::Unknown,
            int: None,
            frac_bits: None,
        }
    }

    fn clear_int(value: u64) -> Self {
        AbstractValue {
            len: Len::Unknown,
            secrecy: Secrecy::Clear,
            int: Some(value),
            frac_bits: None,
        }
    }

    fn clear() -> Self {
        AbstractValue {
            len: Len::Unknown,
            secrecy: Secrecy::Clear,
            int: None,
            frac_bits: None,
        }
    }

    fn secret() -> Self {
        AbstractValue {
            len: Len::Unknown,
            secrecy: Secrecy::Secret,
            int: None,
            frac_bits: None,
        }
    }
}

/// Per-scope binding of variable names to their abstract values.
type Env = HashMap<String, AbstractValue>;

/// Result of analysing a function body: the demand it incurs and the abstract
/// value it returns.
#[derive(Debug, Clone)]
struct CallResult {
    demand: PreprocessingDemand,
    ret: AbstractValue,
}

/// Hashable form of [`Len`], used in memo / call-shape keys.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum LenKey {
    Known { len: usize, elem: Box<LenKey> },
    Unknown,
}

impl From<&Len> for LenKey {
    fn from(len: &Len) -> Self {
        match len {
            Len::Known { len, elem } => LenKey::Known {
                len: *len,
                elem: Box::new(LenKey::from(elem.as_ref())),
            },
            Len::Unknown => LenKey::Unknown,
        }
    }
}

/// A memoisation / call-stack key: the function plus the abstract shape of its
/// arguments. Two calls with the same name, argument lengths, and argument
/// secrecy incur identical demand, so we analyse each shape only once.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CallKey {
    name: String,
    arg_lens: Vec<LenKey>,
    arg_secrecy: Vec<Secrecy>,
    arg_ints: Vec<Option<u64>>,
}

/// A user-defined function the planner can analyse.
struct FunctionInfo<'a> {
    parameters: &'a [Parameter],
    body: &'a AstNode,
}

/// The interprocedural planner. Holds the program's user functions plus a memo
/// table keyed on call shape.
struct Planner<'a> {
    functions: HashMap<String, &'a FunctionInfo<'a>>,
    memo: HashMap<CallKey, CallResult>,
    mpc_backend: MpcBackend,
}

/// Compute the total preprocessing demand of `program` (the top-level AST, a
/// `Block` of definitions). Returns the element-wise maximum over every
/// top-level function's demand, so whichever entry the runtime selects is
/// covered.
pub fn plan_preprocessing_demand(program: &AstNode) -> PreprocessingDemand {
    plan_preprocessing_demand_for_backend(program, MpcBackend::default())
}

/// Compute preprocessing demand using the material pools consumed by
/// `mpc_backend`. Random integer generation is backed by PRandInt under
/// HoneyBadger, while AVSS currently implements it using ordinary random field
/// shares.
pub fn plan_preprocessing_demand_for_backend(
    program: &AstNode,
    mpc_backend: MpcBackend,
) -> PreprocessingDemand {
    // The analysis recurses through the program's call graph, which for large
    // straight-line circuits (e.g. the AES S-box and its callers) can nest many
    // frames deep. Run it on a dedicated thread with a generous stack so the
    // recursion never overflows the (smaller) default/main stack. `std::thread::
    // scope` lets the worker borrow `program` without `'static`.
    const ANALYSIS_STACK_SIZE: usize = 256 * 1024 * 1024;
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("preprocessing-demand-analysis".to_string())
            .stack_size(ANALYSIS_STACK_SIZE)
            .spawn_scoped(scope, || {
                plan_preprocessing_demand_inner(program, mpc_backend)
            })
            .expect("failed to spawn preprocessing-demand analysis thread")
            .join()
            .expect("preprocessing-demand analysis thread panicked")
    })
}

fn plan_preprocessing_demand_inner(
    program: &AstNode,
    mpc_backend: MpcBackend,
) -> PreprocessingDemand {
    let mut infos: Vec<(String, FunctionInfo)> = Vec::new();
    collect_functions(program, &mut infos);

    let functions: HashMap<String, &FunctionInfo> = infos
        .iter()
        .map(|(name, info)| (name.clone(), info))
        .collect();

    let mut planner = Planner {
        functions,
        memo: HashMap::new(),
        mpc_backend,
    };

    // Program entries are the functions the runtime can actually invoke as a
    // top-level entry point: the conventional entry `main` (which may take
    // client-supplied arguments, whose lengths are unknown but whose secrecy
    // follows their type), plus any zero-parameter function (another possible
    // entry). An *arbitrary* parameter-taking helper is NOT an entry — the
    // runtime cannot supply its (often secret-list) arguments — so analysing it
    // speculatively with unknown-length args would only pollute the estimate
    // with spurious `dynamic` flags. Helpers are instead analysed precisely via
    // the concrete calls their entry makes. If nothing qualifies, fall back to
    // analysing every function so we never emit an empty estimate.
    let entries: Vec<&(String, FunctionInfo)> = {
        let selected: Vec<&(String, FunctionInfo)> = infos
            .iter()
            .filter(|(name, info)| name == "main" || info.parameters.is_empty())
            .collect();
        if selected.is_empty() {
            infos.iter().collect()
        } else {
            selected
        }
    };

    let mut total = PreprocessingDemand::default();
    for (name, info) in entries {
        let result = planner.analyze_entry(name, info);
        total = max_demand(total, result.demand);
    }
    total
}

/// Walk `node` collecting every top-level function definition (recursing into
/// the outer `Block`, but not into function bodies).
fn collect_functions<'a>(node: &'a AstNode, out: &mut Vec<(String, FunctionInfo<'a>)>) {
    match node {
        AstNode::Block(statements) => {
            for statement in statements {
                collect_functions(statement, out);
            }
        }
        AstNode::FunctionDefinition {
            name: Some(name),
            parameters,
            body,
            pragmas,
            ..
        } => {
            // Builtins have no analysable StoffelLang body.
            let is_builtin = pragmas.iter().any(|pragma| match pragma {
                crate::ast::Pragma::Simple(n, _) | crate::ast::Pragma::KeyValue(n, _, _) => {
                    n == "builtin"
                }
            });
            if !is_builtin {
                out.push((
                    name.clone(),
                    FunctionInfo {
                        parameters: parameters.as_slice(),
                        body,
                    },
                ));
            }
        }
        _ => {}
    }
}

/// Element-wise maximum of two demands (`dynamic` is OR'd).
fn max_demand(a: PreprocessingDemand, b: PreprocessingDemand) -> PreprocessingDemand {
    PreprocessingDemand {
        triples: a.triples.max(b.triples),
        randoms: a.randoms.max(b.randoms),
        prandbits: a.prandbits.max(b.prandbits),
        prandints: a.prandints.max(b.prandints),
        dynamic: a.dynamic || b.dynamic,
    }
}

impl<'a> Planner<'a> {
    /// Analyse a top-level function as a program entry. Its parameters' lengths
    /// are unknown (a caller would supply them) but their secrecy follows their
    /// type annotation.
    fn analyze_entry(&mut self, name: &str, info: &FunctionInfo<'a>) -> CallResult {
        let arg_lens: Vec<Len> = info.parameters.iter().map(|_| Len::Unknown).collect();
        let arg_secrecy: Vec<Secrecy> = info.parameters.iter().map(param_element_secrecy).collect();
        let arg_ints = vec![None; info.parameters.len()];
        let mut call_stack = Vec::new();
        self.analyze_call(
            name,
            info,
            &arg_lens,
            &arg_secrecy,
            &arg_ints,
            &mut call_stack,
        )
    }

    /// Analyse one call of `name` with the given argument shapes, memoised on
    /// `(name, arg_lens, arg_secrecy, arg_ints)`. Constant clear-integer arguments
    /// are part of the call shape because helpers commonly use them as loop bounds.
    /// Recursion (the same name already on the call stack) yields a `dynamic` floor.
    fn analyze_call(
        &mut self,
        name: &str,
        info: &FunctionInfo<'a>,
        arg_lens: &[Len],
        arg_secrecy: &[Secrecy],
        arg_ints: &[Option<u64>],
        call_stack: &mut Vec<String>,
    ) -> CallResult {
        let key = CallKey {
            name: name.to_string(),
            arg_lens: arg_lens.iter().map(LenKey::from).collect(),
            arg_secrecy: arg_secrecy.to_vec(),
            arg_ints: arg_ints.to_vec(),
        };
        if let Some(cached) = self.memo.get(&key) {
            return cached.clone();
        }

        // Recursion: we cannot bound the depth statically, so flag dynamic.
        if call_stack.iter().any(|frame| frame == name) {
            return CallResult {
                demand: PreprocessingDemand {
                    dynamic: true,
                    ..Default::default()
                },
                ret: AbstractValue::unknown(),
            };
        }

        // Seed the parameter environment from the call-site argument shapes and
        // the parameters' declared element secrecy.
        let mut env = Env::new();
        for (index, param) in info.parameters.iter().enumerate() {
            let len = arg_lens.get(index).cloned().unwrap_or(Len::Unknown);
            let secrecy = arg_secrecy
                .get(index)
                .copied()
                .unwrap_or_else(|| param_element_secrecy(param));
            env.insert(
                param.name.clone(),
                AbstractValue {
                    len,
                    secrecy,
                    int: arg_ints.get(index).copied().flatten(),
                    frac_bits: param_frac_bits(param),
                },
            );
        }

        call_stack.push(name.to_string());
        let mut demand = PreprocessingDemand::default();
        let mut ret: Option<AbstractValue> = None;
        self.eval_block_like(info.body, &mut env, &mut demand, &mut ret, call_stack);
        call_stack.pop();

        let result = CallResult {
            demand,
            ret: ret.unwrap_or_else(AbstractValue::unknown),
        };
        self.memo.insert(key, result.clone());
        result
    }

    /// Evaluate a statement or block for its side effects on `env`, `demand`,
    /// and (via `Return`) the function's `ret` value.
    fn eval_block_like(
        &mut self,
        node: &AstNode,
        env: &mut Env,
        demand: &mut PreprocessingDemand,
        ret: &mut Option<AbstractValue>,
        call_stack: &mut Vec<String>,
    ) {
        match node {
            AstNode::Block(statements) => {
                for statement in statements {
                    self.eval_block_like(statement, env, demand, ret, call_stack);
                }
            }
            AstNode::VariableDeclaration {
                name,
                value,
                type_annotation,
                is_secret,
                ..
            } => {
                let mut value = match value {
                    Some(value) => self.eval_expr(value, env, demand, call_stack),
                    None => AbstractValue::unknown(),
                };
                // A declared `secret` / `list[secret ...]` type pins the element
                // secrecy even when the initialiser is an empty (or otherwise
                // secrecy-ambiguous) list literal that will be filled in later.
                let declared_secret = *is_secret
                    || type_annotation
                        .as_deref()
                        .is_some_and(annotation_contains_secret);
                if declared_secret {
                    value.secrecy = Secrecy::Secret;
                }
                env.insert(name.clone(), value);
            }
            AstNode::Assignment { target, value, .. } => {
                let value = self.eval_expr(value, env, demand, call_stack);
                if let AstNode::Identifier(name, _) = target.as_ref() {
                    env.insert(name.clone(), value);
                } else {
                    // Index/field assignment: evaluate the target for any
                    // embedded calls, but it does not rebind a simple name.
                    self.eval_expr(target, env, demand, call_stack);
                }
            }
            AstNode::ForLoop {
                variables,
                iterable,
                body,
                ..
            } => self.eval_for_loop(variables, iterable, body, env, demand, ret, call_stack),
            AstNode::WhileLoop {
                condition, body, ..
            } => self.eval_while_loop(condition, body, env, demand, ret, call_stack),
            AstNode::IfExpression {
                condition,
                then_branch,
                else_branch,
            } => {
                self.eval_expr(condition, env, demand, call_stack);
                self.eval_if_statement(then_branch, else_branch, env, demand, ret, call_stack);
            }
            AstNode::Return { value, .. } => {
                if let Some(value) = value {
                    let value = self.eval_expr(value, env, demand, call_stack);
                    merge_into_ret(ret, Some(value));
                }
            }
            AstNode::DiscardStatement { expression, .. } => {
                self.eval_expr(expression, env, demand, call_stack);
            }
            // Any expression used in statement position (e.g. a bare call).
            other => {
                self.eval_expr(other, env, demand, call_stack);
            }
        }
    }

    /// Evaluate an `if` in statement position, taking the branch-wise maximum of
    /// demand (the runtime must provision for whichever branch executes).
    fn eval_if_statement(
        &mut self,
        then_branch: &AstNode,
        else_branch: &Option<Box<AstNode>>,
        env: &mut Env,
        demand: &mut PreprocessingDemand,
        ret: &mut Option<AbstractValue>,
        call_stack: &mut Vec<String>,
    ) {
        let mut then_env = env.clone();
        let mut then_demand = PreprocessingDemand::default();
        let mut then_ret = ret.clone();
        self.eval_block_like(
            then_branch,
            &mut then_env,
            &mut then_demand,
            &mut then_ret,
            call_stack,
        );

        let (else_env, else_demand, else_ret) = match else_branch {
            Some(else_branch) => {
                let mut else_env = env.clone();
                let mut else_demand = PreprocessingDemand::default();
                let mut else_ret = ret.clone();
                self.eval_block_like(
                    else_branch,
                    &mut else_env,
                    &mut else_demand,
                    &mut else_ret,
                    call_stack,
                );
                (else_env, else_demand, else_ret)
            }
            None => (env.clone(), PreprocessingDemand::default(), ret.clone()),
        };

        // Demand of a conditional is the per-element maximum of its branches.
        add_demand(demand, &max_demand(then_demand, else_demand));

        // The function return value may come from either branch.
        *ret = merge_opt_ret(then_ret, else_ret);

        // Reconcile pre-existing bindings across the two possible branches.
        // Divergent list lengths must become unknown: retaining the pre-`if`
        // length can undercount a later batch/loop (for example, a conditional
        // append inside a counted loop previously left an empty-list length of
        // zero visible to subsequent secret gates).
        let before = env.clone();
        for name in before.keys() {
            if let (Some(then_value), Some(else_value)) = (then_env.get(name), else_env.get(name)) {
                env.insert(
                    name.clone(),
                    merge_value(then_value.clone(), else_value.clone()),
                );
            }
        }
    }

    /// Evaluate a `while` loop. The counted shape codegen emits everywhere —
    /// `v = <known>; while v OP <known>: … ; v = v ± step` (or `v = v * k`) —
    /// gets its trip count inferred and is then treated exactly like a counted
    /// `for` loop (body analysed once, demand scaled, list growth applied
    /// `count` times), so `while`-built programs provision correctly instead of
    /// reporting ZERO demand. Anything non-canonical falls back to
    /// analyse-once + `dynamic`, and — crucially — poisons the lengths of every
    /// list the body grew (`apply_loop_length_growth_unknown`): before this,
    /// the discarded body env left the PRE-loop lengths visible, so a
    /// post-loop `batch_mul` over a `while`-filled list counted len 0 triples
    /// with `dynamic: false` (the all-zero manifests that starved the runtime).
    #[allow(clippy::too_many_arguments)]
    fn eval_while_loop(
        &mut self,
        condition: &AstNode,
        body: &AstNode,
        env: &mut Env,
        demand: &mut PreprocessingDemand,
        ret: &mut Option<AbstractValue>,
        call_stack: &mut Vec<String>,
    ) {
        self.eval_expr(condition, env, demand, call_stack);
        let count = self.while_trip_count(condition, body, env, demand, call_stack);

        let mut body_env = env.clone();
        if count.is_some() {
            if let Some((var, _, _)) = while_condition_parts(condition) {
                // A counted loop is scaled from one symbolic body. Its counter
                // varies between iterations, so do not incorrectly specialize
                // the body to the first value.
                body_env.insert(var.to_string(), AbstractValue::clear());
            }
        }
        let mut body_demand = PreprocessingDemand::default();
        let mut body_ret = ret.clone();
        self.eval_block_like(
            body,
            &mut body_env,
            &mut body_demand,
            &mut body_ret,
            call_stack,
        );
        merge_into_ret(ret, body_ret);

        match count {
            Some(count) => {
                add_demand(demand, &scale_demand(&body_demand, count));
                apply_loop_length_growth(env, &body_env, count);
                // The counter's post-loop value is loop-shape-dependent; keep it
                // conservative (clear, value unknown) rather than stale-at-start.
                if let Some((var, _, _)) = while_condition_parts(condition) {
                    env.insert(var.to_string(), AbstractValue::clear());
                }
            }
            None => {
                add_demand(demand, &body_demand);
                if has_any_material(&body_demand) {
                    demand.dynamic = true;
                }
                apply_loop_length_growth_unknown(env, &body_env);
                if let Some((var, _, _)) = while_condition_parts(condition) {
                    env.insert(var.to_string(), AbstractValue::clear());
                }
            }
        }
    }

    /// Infer the trip count of the canonical counted `while` shape, or `None`.
    /// Requirements: condition `v < | <= | > | >= <bound>` with `v` a tracked
    /// int and `<bound>` foldable; EXACTLY one assignment to `v` anywhere in
    /// the body, at the body's top level, of shape `v = v + s`, `v = v - s`
    /// (`s` a positive literal, direction matching the comparison) or
    /// `v = v * k` (`k >= 2`, ascending).
    fn while_trip_count(
        &mut self,
        condition: &AstNode,
        body: &AstNode,
        env: &mut Env,
        demand: &mut PreprocessingDemand,
        call_stack: &mut Vec<String>,
    ) -> Option<u64> {
        let (var, cmp, bound_expr) = while_condition_parts(condition)?;
        let start = env.get(var)?.int?;
        let _ = &demand;
        let bound = {
            let mut scratch = PreprocessingDemand::default();
            self.eval_expr(bound_expr, env, &mut scratch, call_stack)
                .int?
        };
        let step = while_step(body, var)?;

        match (cmp, step) {
            ("<", WhileStep::Add(s)) if bound > start => Some((bound - start).div_ceil(s)),
            ("<", WhileStep::Add(_)) => Some(0),
            ("<=", WhileStep::Add(s)) if bound >= start => Some((bound - start) / s + 1),
            ("<=", WhileStep::Add(_)) => Some(0),
            (">", WhileStep::Sub(s)) if start > bound => Some((start - bound).div_ceil(s)),
            (">", WhileStep::Sub(_)) => Some(0),
            (">=", WhileStep::Sub(s)) if start >= bound => Some((start - bound) / s + 1),
            (">=", WhileStep::Sub(_)) => Some(0),
            ("<", WhileStep::Mul(k)) if start >= 1 && k >= 2 => {
                let mut v = start;
                let mut c = 0u64;
                while v < bound && c < 64 {
                    v = v.saturating_mul(k);
                    c += 1;
                }
                (c < 64).then_some(c)
            }
            _ => None,
        }
    }

    /// Evaluate a `for` loop: count its iterations when statically known,
    /// multiply the body demand by that count, and bind the loop variable.
    #[allow(clippy::too_many_arguments)]
    fn eval_for_loop(
        &mut self,
        variables: &[String],
        iterable: &AstNode,
        body: &AstNode,
        env: &mut Env,
        demand: &mut PreprocessingDemand,
        ret: &mut Option<AbstractValue>,
        call_stack: &mut Vec<String>,
    ) {
        // Determine iteration count and the loop variable's abstract value.
        let (count, loop_var_value): (Option<u64>, AbstractValue) = match iterable {
            AstNode::BinaryOperation {
                op, left, right, ..
            } if op == ".." => {
                // Evaluate bounds for any embedded calls, then fold.
                let start = self.eval_expr(left, env, demand, call_stack);
                let end = self.eval_expr(right, env, demand, call_stack);
                let count = match (start.int, end.int) {
                    (Some(a), Some(b)) if b >= a => Some(b - a),
                    _ => None,
                };
                // Range loop variable is a clear int (value unknown in general).
                (count, AbstractValue::clear())
            }
            _ => {
                // `for x in <list>`: the count is the list length; bind `x` to
                // the collection's element shape and secrecy.
                let collection = self.eval_expr(iterable, env, demand, call_stack);
                let count = collection.len.count().map(|n| n as u64);
                let element = AbstractValue {
                    len: collection.len.element(),
                    secrecy: collection.secrecy,
                    int: None,
                    frac_bits: None,
                };
                (count, element)
            }
        };

        // Bind the loop variable(s) before analysing the body. (Only single-var
        // loops are supported by codegen; bind the first, leave the rest
        // unknown.)
        let mut body_env = env.clone();
        if let Some(first) = variables.first() {
            body_env.insert(first.clone(), loop_var_value);
        }
        for extra in variables.iter().skip(1) {
            body_env.insert(extra.clone(), AbstractValue::unknown());
        }

        let mut body_demand = PreprocessingDemand::default();
        let mut body_ret = ret.clone();
        self.eval_block_like(
            body,
            &mut body_env,
            &mut body_demand,
            &mut body_ret,
            call_stack,
        );
        // A `return` reached inside the loop body contributes to the function's
        // return value.
        merge_into_ret(ret, body_ret);

        match count {
            Some(count) => {
                add_demand(demand, &scale_demand(&body_demand, count));
                // Apply the per-iteration list-length growth `count` times. A
                // list appended to once per iteration ends at `start + count`.
                // (This composes across nested loops: the inner loop writes its
                // scaled growth into the outer loop's body env, which the outer
                // loop then scales again.)
                apply_loop_length_growth(env, &body_env, count);
            }
            None => {
                // Unknown iteration count: provision one iteration and flag the
                // estimate dynamic so the runtime keeps headroom. Any list grown
                // by an unbounded loop now has an unknown length.
                add_demand(demand, &body_demand);
                if has_any_material(&body_demand) {
                    demand.dynamic = true;
                }
                apply_loop_length_growth_unknown(env, &body_env);
            }
        }
    }

    /// Evaluate an expression for its abstract value, accumulating any demand it
    /// incurs into `demand`.
    fn eval_expr(
        &mut self,
        node: &AstNode,
        env: &mut Env,
        demand: &mut PreprocessingDemand,
        call_stack: &mut Vec<String>,
    ) -> AbstractValue {
        match node {
            AstNode::Literal { value, .. } => match value {
                Value::Int { value, .. } => u64::try_from(*value)
                    .map(AbstractValue::clear_int)
                    .unwrap_or_else(|_| AbstractValue::clear()),
                _ => AbstractValue::clear(),
            },
            AstNode::Identifier(name, _) => env
                .get(name)
                .cloned()
                .unwrap_or_else(AbstractValue::unknown),
            AstNode::ListLiteral { elements, .. } => {
                let mut secrecy = Secrecy::Clear;
                let mut element_shape: Option<Len> = None;
                for element in elements {
                    let value = self.eval_expr(element, env, demand, call_stack);
                    if value.secrecy == Secrecy::Secret {
                        secrecy = Secrecy::Secret;
                    } else if value.secrecy == Secrecy::Unknown && secrecy != Secrecy::Secret {
                        secrecy = Secrecy::Unknown;
                    }
                    // Track the elements' shared shape so nested lists are sized.
                    element_shape = Some(match element_shape {
                        Some(existing) if existing == value.len => existing,
                        Some(_) => Len::Unknown,
                        None => value.len,
                    });
                }
                AbstractValue {
                    len: Len::Known {
                        len: elements.len(),
                        elem: Box::new(element_shape.unwrap_or(Len::Unknown)),
                    },
                    secrecy,
                    int: None,
                    frac_bits: None,
                }
            }
            AstNode::BinaryOperation {
                op, left, right, ..
            } => self.eval_binary_operation(op, left, right, env, demand, call_stack),
            AstNode::UnaryOperation { operand, .. } => {
                // `not` and other unary ops are free; propagate operand secrecy.
                let value = self.eval_expr(operand, env, demand, call_stack);
                AbstractValue {
                    len: Len::Unknown,
                    secrecy: value.secrecy,
                    int: None,
                    frac_bits: value.frac_bits,
                }
            }
            AstNode::FunctionCall {
                function,
                arguments,
                ..
            } => self.eval_function_call(function, arguments, env, demand, call_stack),
            AstNode::IndexAccess { base, index, .. } => {
                let base = self.eval_expr(base, env, demand, call_stack);
                self.eval_expr(index, env, demand, call_stack);
                // An element of a list inherits the list's element shape and
                // secrecy (so `state[i]` on a list of 8-bit bytes is a byte of
                // length 8).
                AbstractValue {
                    len: base.len.element(),
                    secrecy: base.secrecy,
                    int: None,
                    frac_bits: None,
                }
            }
            AstNode::FieldAccess { object, .. } => {
                self.eval_expr(object, env, demand, call_stack);
                AbstractValue::unknown()
            }
            AstNode::IfExpression {
                condition,
                then_branch,
                else_branch,
            } => {
                self.eval_expr(condition, env, demand, call_stack);
                let (then_demand, then_value) = self.eval_expr_branch(then_branch, env, call_stack);
                let (else_demand, else_value) = match else_branch {
                    Some(else_branch) => self.eval_expr_branch(else_branch, env, call_stack),
                    None => (PreprocessingDemand::default(), AbstractValue::unknown()),
                };
                add_demand(demand, &max_demand(then_demand, else_demand));
                merge_value(then_value, else_value)
            }
            AstNode::Block(statements) => {
                // An expression block: last expression is its value.
                let mut last = AbstractValue::unknown();
                for statement in statements {
                    last = self.eval_expr(statement, env, demand, call_stack);
                }
                last
            }
            AstNode::TupleLiteral(elements) | AstNode::SetLiteral(elements) => {
                for element in elements {
                    self.eval_expr(element, env, demand, call_stack);
                }
                AbstractValue::unknown()
            }
            AstNode::Return { value, .. } => match value {
                Some(value) => self.eval_expr(value, env, demand, call_stack),
                None => AbstractValue::unknown(),
            },
            // Any construct we do not specifically model: descend into its
            // children so embedded calls/ops are still counted, and report an
            // unknown value.
            _ => {
                for child in child_expressions(node) {
                    self.eval_expr(child, env, demand, call_stack);
                }
                AbstractValue::unknown()
            }
        }
    }

    /// Evaluate a branch of an `if`-expression in isolation, returning the
    /// branch's demand and value so the caller can take the per-branch maximum.
    fn eval_expr_branch(
        &mut self,
        node: &AstNode,
        env: &mut Env,
        call_stack: &mut Vec<String>,
    ) -> (PreprocessingDemand, AbstractValue) {
        let mut branch_demand = PreprocessingDemand::default();
        let mut branch_env = env.clone();
        let value = self.eval_expr(node, &mut branch_env, &mut branch_demand, call_stack);
        (branch_demand, value)
    }

    fn eval_binary_operation(
        &mut self,
        op: &str,
        left: &AstNode,
        right: &AstNode,
        env: &mut Env,
        demand: &mut PreprocessingDemand,
        call_stack: &mut Vec<String>,
    ) -> AbstractValue {
        let left_value = self.eval_expr(left, env, demand, call_stack);
        let right_value = self.eval_expr(right, env, demand, call_stack);

        match op {
            // secret * secret consumes one Beaver triple. secret*public is free.
            // Secret-bool `and`/`or`/`xor` are each one multiplication over the
            // prime field (`a xor b = a + b - 2ab`), so they cost one triple too.
            "*" | "and" | "or" | "xor"
                if left_value.secrecy == Secrecy::Secret
                    && right_value.secrecy == Secrecy::Secret =>
            {
                demand.add(1, 0, 0, 0);
            }
            // Field access through a user-defined object is not yet represented
            // in the abstract-value environment.  The type checker has already
            // accepted these boolean operators, so an unknown operand may be a
            // secret boolean (for example `share.bits[i]`).  Provision one
            // conservative gate and mark the estimate dynamic rather than
            // emitting an all-zero manifest that can starve the runtime.
            "and" | "or" | "xor"
                if left_value.secrecy != Secrecy::Clear
                    || right_value.secrecy != Secrecy::Clear =>
            {
                demand.add(1, 0, 0, 0);
                demand.dynamic = true;
            }
            // secret fixed-point division runs the truncation protocol: `f`
            // random bits + 1 random int, where `f` is the left operand's
            // fractional-bit count.
            "/" if left_value.secrecy == Secrecy::Secret => {
                let f = left_value
                    .frac_bits
                    .unwrap_or(DEFAULT_FIXED_POINT_FRACTIONAL_BITS) as u64;
                demand.add(0, 0, f, 1);
            }
            _ => {}
        }

        // Fold constant integer arithmetic for loop-bound evaluation.
        let int = match (op, left_value.int, right_value.int) {
            ("+", Some(a), Some(b)) => a.checked_add(b),
            ("-", Some(a), Some(b)) => a.checked_sub(b),
            ("*", Some(a), Some(b)) => a.checked_mul(b),
            ("/", Some(a), Some(b)) if b != 0 => Some(a / b),
            ("mod" | "%", Some(a), Some(b)) if b != 0 => Some(a % b),
            _ => None,
        };

        AbstractValue {
            len: Len::Unknown,
            secrecy: left_value.secrecy.join_arith(right_value.secrecy),
            int,
            frac_bits: left_value.frac_bits.or(right_value.frac_bits),
        }
    }

    fn eval_function_call(
        &mut self,
        function: &AstNode,
        arguments: &[AstNode],
        env: &mut Env,
        demand: &mut PreprocessingDemand,
        call_stack: &mut Vec<String>,
    ) -> AbstractValue {
        let AstNode::Identifier(raw_name, _) = function else {
            // Indirect call: evaluate the callee and arguments for embedded
            // demand; result unknown.
            self.eval_expr(function, env, demand, call_stack);
            for argument in arguments {
                self.eval_expr(argument, env, demand, call_stack);
            }
            return AbstractValue::unknown();
        };

        // Map source-level builtin aliases to their VM symbol, mirroring codegen.
        let name = crate::builtin_registry::builtin_registry()
            .vm_symbol_for_call(raw_name)
            .unwrap_or(raw_name.as_str())
            .to_string();

        // Pre-evaluate argument abstract values (also accumulates embedded
        // demand from nested calls/ops).
        let arg_values: Vec<AbstractValue> = arguments
            .iter()
            .map(|argument| self.eval_expr(argument, env, demand, call_stack))
            .collect();

        match name.as_str() {
            // --- Operations that consume preprocessing material ---------------
            // Semantic overload resolution lowers the Share VM primitive to
            // its unqualified bytecode symbol (`mul`) while some compiler
            // paths retain the source-qualified spelling. Count both.
            "Share.mul" | "mul" => {
                demand.add(1, 0, 0, 0);
                AbstractValue::secret()
            }
            "Share.batch_mul" | "batch_mul" => {
                let input_len = arg_values
                    .first()
                    .map(|value| value.len.clone())
                    .unwrap_or(Len::Unknown);
                match input_len.count() {
                    Some(len) => demand.add(len as u64, 0, 0, 0),
                    None => {
                        // Runtime-sized batch: provision one and flag dynamic.
                        demand.add(1, 0, 0, 0);
                        demand.dynamic = true;
                    }
                }
                // Result is a list of secret shares, same length as the inputs.
                AbstractValue {
                    len: input_len,
                    secrecy: Secrecy::Secret,
                    int: None,
                    frac_bits: None,
                }
            }

            // --- Length / iteration builtins ---------------------------------
            "len" | "array_length" => {
                match arg_values.first().and_then(|value| value.len.count()) {
                    Some(len) => AbstractValue::clear_int(len as u64),
                    None => AbstractValue::clear(),
                }
            }

            // --- List mutators: update the tracked length of the receiver -----
            // The appended/inserted element is the call's last argument; its
            // shape and secrecy are folded into the receiver list.
            "append" | "array_push" | "insert" => {
                let element = arg_values.last();
                let element_secrecy = element.map(|value| value.secrecy);
                let element_shape = element.map(|value| value.len.clone());
                self.list_grow(arguments.first(), 1, element_secrecy, element_shape, env);
                AbstractValue::clear()
            }
            "extend" => {
                let element_secrecy = arg_values.get(1).map(|value| value.secrecy);
                match arg_values.get(1).and_then(|value| value.len.count()) {
                    Some(n) => self.list_grow(
                        arguments.first(),
                        n,
                        element_secrecy,
                        arg_values.get(1).map(|value| value.len.element()),
                        env,
                    ),
                    None => self.list_make_unknown(arguments.first(), env),
                }
                AbstractValue::clear()
            }

            // `copy` creates a distinct list object but preserves the complete
            // abstract value shape. The O3 multiply batcher seeds each fused
            // operand accumulator with `copy(first_operand)` and then extends
            // it; losing the seed length here makes an otherwise fully static
            // `Share.batch_mul` appear runtime-sized, forcing online top-ups.
            "copy" => arg_values
                .first()
                .cloned()
                .unwrap_or_else(AbstractValue::unknown),

            // --- List/object constructors ------------------------------------
            "create_array" => AbstractValue {
                len: Len::flat(0),
                secrecy: Secrecy::Unknown,
                int: None,
                frac_bits: None,
            },
            "create_object"
            | "set_field"
            | "print"
            | "to_string"
            | "assert"
            | "ClientStore.get_number_clients"
            | "Mpc.has_capability"
            | "MpcOutput.send_to_client"
            | "Share.send_to_client" => AbstractValue::clear(),
            "get_field" => arg_values
                .first()
                .map(|collection| AbstractValue {
                    len: collection.len.element(),
                    secrecy: collection.secrecy,
                    int: None,
                    frac_bits: collection.frac_bits,
                })
                .unwrap_or_else(AbstractValue::unknown),
            "slice" => {
                let source = arg_values.first();
                let len = match (
                    arg_values.get(1).and_then(|value| value.int),
                    arg_values.get(2).and_then(|value| value.int),
                ) {
                    (Some(start), Some(end)) if end >= start => Len::Known {
                        len: (end - start) as usize,
                        elem: Box::new(
                            source
                                .map(|value| value.len.element())
                                .unwrap_or(Len::Unknown),
                        ),
                    },
                    _ => Len::Unknown,
                };
                AbstractValue {
                    len,
                    secrecy: source
                        .map(|value| value.secrecy)
                        .unwrap_or(Secrecy::Unknown),
                    int: None,
                    frac_bits: source.and_then(|value| value.frac_bits),
                }
            }
            "contains" => AbstractValue::clear(),

            // --- Client input: a secret scalar share -------------------------
            "ClientStore.take_share"
            | "ClientStore.take_share_bool"
            | "ClientStore.take_share_fixed"
            | "ClientStore.sum_shares"
            | "ClientStore.sum_shares_bool"
            | "ClientStore.sum_shares_fixed" => AbstractValue::secret(),

            // --- Operations that consume random preprocessing material -------
            // random_field always uses the random-share pool. A typed
            // `Share.random()` is lowered to random_int(bit_length), whose
            // backing pool depends on the selected runtime backend.
            "Share.random_field" => {
                demand.add(0, 1, 0, 0);
                AbstractValue::secret()
            }
            "Share.random" | "Share.random_int" => {
                match self.mpc_backend {
                    MpcBackend::HoneyBadger => demand.add(0, 0, 0, 1),
                    MpcBackend::Avss => demand.add(0, 1, 0, 0),
                }
                AbstractValue::secret()
            }

            // --- Free MPC builtins (secrecy effects only, no demand) ---------
            "Share.add" | "Share.sub" | "Share.mul_scalar" | "Share.add_constant"
            | "Share.add_scalar" => AbstractValue::secret(),
            "Share.from_field"
            | "Share.from_clear"
            | "Share.from_clear_int"
            | "Share.from_clear_uint"
            | "Share.from_clear_fixed" => AbstractValue::secret(),
            "Share.open" => AbstractValue::clear(),

            // --- User functions: recurse with the call's argument shapes -----
            _ => {
                if let Some(info) = self.functions.get(name.as_str()).copied() {
                    let arg_lens: Vec<Len> =
                        arg_values.iter().map(|value| value.len.clone()).collect();
                    let arg_secrecy: Vec<Secrecy> =
                        arg_values.iter().map(|value| value.secrecy).collect();
                    let arg_ints: Vec<Option<u64>> =
                        arg_values.iter().map(|value| value.int).collect();
                    let result = self.analyze_call(
                        &name,
                        info,
                        &arg_lens,
                        &arg_secrecy,
                        &arg_ints,
                        call_stack,
                    );
                    add_demand(demand, &result.demand);
                    result.ret
                } else {
                    // Unknown function with no analysable body. We have already
                    // counted demand inside its arguments; its own body is
                    // opaque, so report unknown (do not over-count).
                    AbstractValue::unknown()
                }
            }
        }
    }

    /// Grow the tracked length of the list variable named by `receiver` by `n`
    /// (when its current length is statically known), recording the appended
    /// element's shape (so the receiver becomes a list-of-known-shape) and
    /// folding the element's secrecy into the list's element secrecy.
    fn list_grow(
        &self,
        receiver: Option<&AstNode>,
        n: usize,
        element_secrecy: Option<Secrecy>,
        element_shape: Option<Len>,
        env: &mut Env,
    ) {
        if let Some(AstNode::Identifier(name, _)) = receiver {
            if let Some(value) = env.get_mut(name) {
                value.len = match &value.len {
                    Len::Known { len, elem } => {
                        // Keep the element shape if it agrees with the appended
                        // element's shape; otherwise the list is ragged.
                        let new_elem = match (element_shape, elem.as_ref()) {
                            (Some(appended), _) if *len == 0 => appended,
                            (Some(appended), existing) if appended == *existing => appended,
                            (Some(_), _) => Len::Unknown,
                            (None, existing) => existing.clone(),
                        };
                        Len::Known {
                            len: len + n,
                            elem: Box::new(new_elem),
                        }
                    }
                    Len::Unknown => Len::Unknown,
                };
                if let Some(element_secrecy) = element_secrecy {
                    // A list that has held a secret element has secret elements.
                    value.secrecy = match (value.secrecy, element_secrecy) {
                        (Secrecy::Secret, _) | (_, Secrecy::Secret) => Secrecy::Secret,
                        (Secrecy::Clear, Secrecy::Clear) => Secrecy::Clear,
                        _ => Secrecy::Unknown,
                    };
                }
            }
        }
    }

    /// Mark the list variable named by `receiver` as having unknown length.
    fn list_make_unknown(&self, receiver: Option<&AstNode>, env: &mut Env) {
        if let Some(AstNode::Identifier(name, _)) = receiver {
            if let Some(value) = env.get_mut(name) {
                value.len = Len::Unknown;
            }
        }
    }
}

/// Fold a freshly observed return value into a function's accumulating return
/// value. The first `return` seeds it exactly (so a known length is preserved);
/// subsequent returns merge per-element.
fn merge_into_ret(ret: &mut Option<AbstractValue>, value: Option<AbstractValue>) {
    *ret = merge_opt_ret(ret.clone(), value);
}

/// Combine two optional return values: `None` is "no return on this path".
fn merge_opt_ret(a: Option<AbstractValue>, b: Option<AbstractValue>) -> Option<AbstractValue> {
    match (a, b) {
        (Some(a), Some(b)) => Some(merge_value(a, b)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

/// Merge two abstract values that may both flow to the same use (e.g. two `if`
/// branches or two `return`s).
fn merge_value(a: AbstractValue, b: AbstractValue) -> AbstractValue {
    let len = if a.len == b.len { a.len } else { Len::Unknown };
    let int = match (a.int, b.int) {
        (Some(x), Some(y)) if x == y => Some(x),
        _ => None,
    };
    AbstractValue {
        len,
        secrecy: a.secrecy.merge_branch(b.secrecy),
        int,
        frac_bits: if a.frac_bits == b.frac_bits {
            a.frac_bits
        } else {
            None
        },
    }
}

/// One canonical `while` counter step, extracted from the body's top level.
#[derive(Clone, Copy)]
enum WhileStep {
    Add(u64),
    Sub(u64),
    Mul(u64),
}

/// `(var, cmp, bound_expr)` of a `while v OP bound:` condition, if that shape.
fn while_condition_parts(condition: &AstNode) -> Option<(&str, &str, &AstNode)> {
    if let AstNode::BinaryOperation {
        op, left, right, ..
    } = condition
    {
        if matches!(op.as_str(), "<" | "<=" | ">" | ">=") {
            if let AstNode::Identifier(name, _) = left.as_ref() {
                return Some((name.as_str(), op.as_str(), right));
            }
        }
    }
    None
}

/// The single counter-step assignment for `var` in `body`, or `None` when the
/// body assigns `var` zero times, more than once, somewhere nested, or in a
/// non-`v = v ± lit` / `v = v * lit` shape.
fn while_step(body: &AstNode, var: &str) -> Option<WhileStep> {
    fn count_assignments(node: &AstNode, var: &str, n: &mut usize) {
        if let AstNode::Assignment { target, .. } = node {
            if matches!(target.as_ref(), AstNode::Identifier(name, _) if name == var) {
                *n += 1;
            }
        }
        crate::optimizations::for_each_child(node, &mut |child| count_assignments(child, var, n));
    }

    let statements = match body {
        AstNode::Block(statements) => statements.as_slice(),
        other => std::slice::from_ref(other),
    };

    let mut total = 0usize;
    for statement in statements {
        count_assignments(statement, var, &mut total);
    }
    if total != 1 {
        return None;
    }

    for statement in statements {
        let AstNode::Assignment { target, value, .. } = statement else {
            continue;
        };
        if !matches!(target.as_ref(), AstNode::Identifier(name, _) if name == var) {
            continue;
        }
        let AstNode::BinaryOperation {
            op, left, right, ..
        } = value.as_ref()
        else {
            return None;
        };
        let lit = |node: &AstNode| -> Option<u64> {
            if let AstNode::Literal {
                value: Value::Int { value, .. },
                ..
            } = node
            {
                u64::try_from(*value).ok()
            } else {
                None
            }
        };
        let var_side = |node: &AstNode| -> bool {
            matches!(node, AstNode::Identifier(name, _) if name == var)
        };
        return match op.as_str() {
            "+" if var_side(left) => lit(right).filter(|s| *s > 0).map(WhileStep::Add),
            "+" if var_side(right) => lit(left).filter(|s| *s > 0).map(WhileStep::Add),
            "-" if var_side(left) => lit(right).filter(|s| *s > 0).map(WhileStep::Sub),
            "*" if var_side(left) => lit(right).filter(|k| *k >= 2).map(WhileStep::Mul),
            "*" if var_side(right) => lit(left).filter(|k| *k >= 2).map(WhileStep::Mul),
            _ => None,
        };
    }
    None
}

/// Add `addend` into `target` (saturating), preserving/propagating `dynamic`.
fn add_demand(target: &mut PreprocessingDemand, addend: &PreprocessingDemand) {
    target.add(
        addend.triples,
        addend.randoms,
        addend.prandbits,
        addend.prandints,
    );
    target.dynamic |= addend.dynamic;
}

/// Multiply a demand by an iteration count (saturating).
fn scale_demand(demand: &PreprocessingDemand, count: u64) -> PreprocessingDemand {
    PreprocessingDemand {
        triples: demand.triples.saturating_mul(count),
        randoms: demand.randoms.saturating_mul(count),
        prandbits: demand.prandbits.saturating_mul(count),
        prandints: demand.prandints.saturating_mul(count),
        dynamic: demand.dynamic,
    }
}

/// Propagate the list-length effects of one symbolic loop iteration back into
/// the enclosing `env`, scaled by the loop's iteration `count`. For each list
/// variable visible before the loop, the body's net per-iteration length change
/// is multiplied by `count` and applied to the pre-loop length. New bindings
/// introduced inside the loop body are loop-local and not propagated.
fn apply_loop_length_growth(env: &mut Env, body_env: &Env, count: u64) {
    for (name, before) in env.clone().iter() {
        let Some(after) = body_env.get(name) else {
            continue;
        };
        let new_len = match (&before.len, &after.len) {
            (
                Len::Known { len: start, .. },
                Len::Known {
                    len: end,
                    elem: end_elem,
                },
            ) => {
                let delta = *end as i128 - *start as i128;
                let total = *start as i128 + delta * count as i128;
                if total >= 0 {
                    // Preserve the per-iteration element shape (e.g. each
                    // appended byte stays length 8).
                    Len::Known {
                        len: total as usize,
                        elem: end_elem.clone(),
                    }
                } else {
                    Len::Unknown
                }
            }
            // The body made the length unknown (or it always was): stays unknown.
            (_, Len::Unknown) => Len::Unknown,
            // The list did not exist with a known length before but does now:
            // we cannot scale it reliably, so treat as unknown.
            (Len::Unknown, Len::Known { .. }) => Len::Unknown,
        };
        if let Some(slot) = env.get_mut(name) {
            slot.len = new_len;
        }
    }
}

/// After an unbounded loop, any list whose length the body changed is no longer
/// statically known.
fn apply_loop_length_growth_unknown(env: &mut Env, body_env: &Env) {
    for (name, before) in env.clone().iter() {
        let Some(after) = body_env.get(name) else {
            continue;
        };
        if before.len != after.len {
            if let Some(slot) = env.get_mut(name) {
                slot.len = Len::Unknown;
            }
        }
    }
}

/// Whether a demand carries any preprocessing material at all.
fn has_any_material(demand: &PreprocessingDemand) -> bool {
    demand.triples > 0 || demand.randoms > 0 || demand.prandbits > 0 || demand.prandints > 0
}

/// Element secrecy of a parameter, derived from its type annotation. A
/// `secret T` (scalar) or `list[secret T]` / nested-list-of-secret parameter has
/// secret elements; otherwise its elements are clear.
fn param_element_secrecy(param: &Parameter) -> Secrecy {
    if param.is_secret {
        return Secrecy::Secret;
    }
    match param.type_annotation.as_deref() {
        Some(annotation) => {
            if annotation_contains_secret(annotation) {
                Secrecy::Secret
            } else {
                Secrecy::Clear
            }
        }
        None => Secrecy::Unknown,
    }
}

/// Whether a type annotation wraps a `secret` anywhere (through `list[...]`
/// nesting), i.e. its scalar leaf is secret.
fn annotation_contains_secret(annotation: &AstNode) -> bool {
    match annotation {
        AstNode::SecretType(_) => true,
        AstNode::ListType(inner) => annotation_contains_secret(inner),
        _ => false,
    }
}

/// Fractional-bit count of a parameter whose leaf type is a secret fixed-point,
/// used to size the `/` truncation cost.
///
/// The AES examples operate over secret booleans, never secret fixed-point
/// division, so a precise per-parameter fractional-bit count is not needed here.
/// Returning `None` makes `/` fall back to the project default, matching the
/// previous codegen behaviour for fixed-point division.
fn param_frac_bits(_param: &Parameter) -> Option<usize> {
    None
}

/// Direct child expressions of a node, for conservative descent into constructs
/// the planner does not model explicitly.
fn child_expressions(node: &AstNode) -> Vec<&AstNode> {
    match node {
        AstNode::Assignment { target, value, .. } => vec![target, value],
        AstNode::BinaryOperation { left, right, .. } => vec![left, right],
        AstNode::UnaryOperation { operand, .. } => vec![operand],
        AstNode::FunctionCall {
            function,
            arguments,
            ..
        } => std::iter::once(function.as_ref())
            .chain(arguments.iter())
            .collect(),
        AstNode::IndexAccess { base, index, .. } => vec![base, index],
        AstNode::FieldAccess { object, .. } => vec![object],
        AstNode::ListLiteral { elements, .. } => elements.iter().collect(),
        AstNode::TupleLiteral(elements) | AstNode::SetLiteral(elements) => {
            elements.iter().collect()
        }
        AstNode::Return {
            value: Some(value), ..
        } => vec![value.as_ref()],
        AstNode::DiscardStatement { expression, .. } => vec![expression],
        AstNode::Block(statements) => statements.iter().collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::{compile, CompilerOptions};
    use stoffel_vm_types::compiled_binary::MpcBackend;

    fn demand_for(src: &str) -> PreprocessingDemand {
        // Compile on a dedicated large-stack thread. The compiler's parser /
        // semantic / codegen passes recurse over the AST, and the bundled AES
        // examples are large enough to exceed the test harness's small default
        // stack. (Production callers run on the main thread, whose default stack
        // is ample.)
        let src = src.to_string();
        std::thread::Builder::new()
            .stack_size(256 * 1024 * 1024)
            .spawn(move || {
                // Mirror the example/bindgen compile path, which emits the
                // manifest with optimization disabled. (The optimizer would
                // otherwise hoist/rewrite loop-invariant secret ops, changing
                // the consumed count.)
                let options = CompilerOptions {
                    optimize: false,
                    optimization_level: 0,
                    print_ir: false,
                    mpc_backend: MpcBackend::HoneyBadger,
                    mpc_curve: Default::default(),
                    ..Default::default()
                };
                let program = compile(&src, "t.stfl", &options).expect("compile should succeed");
                program.client_io_manifest.preprocessing_demand
            })
            .expect("failed to spawn compile thread")
            .join()
            .expect("compile thread panicked")
    }

    /// Counted `while` loops (the only loop shape StoffelDB's codegen emits)
    /// must provision like counted `for` loops — this exact shape used to
    /// report ZERO demand with `dynamic: false` (the stale pre-loop list
    /// length made the post-loop `batch_mul` count len 0), starving the
    /// runtime preprocessing pool.
    #[test]
    fn counted_while_batch_mul_provisions_like_for() {
        let src = r#"
def main() -> int64:
  var xs: list[Share] = []
  var ys: list[Share] = []
  var i = 0
  while i < 16:
    xs.append(ClientStore.take_share(0, i))
    ys.append(ClientStore.take_share(1, i))
    i = i + 1
  var products = Share.batch_mul(xs, ys)
  return 0
"#;
        let demand = demand_for(src);
        assert_eq!(demand.triples, 16);
        assert!(!demand.dynamic);
    }

    /// Descending counted `while` (`i = N-1; while i >= 0: … i = i - 1`) — the
    /// restoring-divide loop shape.
    #[test]
    fn descending_while_counts_iterations() {
        let src = r#"
def main() -> int64:
  var xs: list[Share] = []
  var ys: list[Share] = []
  var j = 0
  while j < 4:
    xs.append(ClientStore.take_share(0, j))
    ys.append(ClientStore.take_share(1, j))
    j = j + 1
  var i = 7
  while i >= 0:
    var p = Share.batch_mul(xs, ys)
    i = i - 1
  return 0
"#;
        let demand = demand_for(src);
        // 8 iterations x 4-element batch_mul, plus nothing else.
        assert_eq!(demand.triples, 32);
        assert!(!demand.dynamic);
    }

    /// A non-canonical `while` (data-dependent bound) must flag `dynamic` AND
    /// poison the lengths of lists it grew, so a post-loop batch op cannot
    /// count a stale zero length as "known".
    #[test]
    fn unknown_while_flags_dynamic_via_poisoned_length() {
        let src = r#"
def main(n: int64) -> int64:
  var xs: list[Share] = []
  var ys: list[Share] = []
  var i = 0
  while i < n:
    xs.append(ClientStore.take_share(0, i))
    ys.append(ClientStore.take_share(1, i))
    i = i + 1
  var products = Share.batch_mul(xs, ys)
  return 0
"#;
        let demand = demand_for(src);
        assert!(demand.dynamic, "runtime-bounded while must flag dynamic");
        assert!(
            demand.triples >= 1,
            "unknown batch must provision at least one"
        );
    }

    #[test]
    fn conditional_append_does_not_leave_a_stale_zero_length() {
        let src = r#"
def fold(bits: list[secret bool]) -> secret bool:
  var acc: secret bool = Share.from_clear_int(1, 1)
  var i = 0
  while i < bits.len():
    acc = acc and bits[i]
    i += 1
  return acc

def main() -> int64:
  var bits: list[secret bool] = []
  var i = 0
  while i < 8:
    var bit: secret bool = ClientStore.take_share_bool(0, i)
    if i < 4:
      bits.append(bit)
    i += 1
  var result: secret bool = fold(bits)
  return 0
"#;
        let demand = demand_for(src);
        assert!(
            demand.dynamic,
            "conditional list growth cannot be sized exactly"
        );
        assert!(
            demand.triples >= 1,
            "a later secret fold must retain a preprocessing floor"
        );
    }

    #[test]
    fn dynamic_outer_loop_preserves_first_iteration_bound_for_nested_loop() {
        let src = r#"
def main() -> int64:
  var width = 16
  while width > 1:
    var j = 0
    while j < width / 2:
      discard Share.random_field()
      j += 1
    width = width / 2
  return 0
"#;
        let demand = demand_for(src);
        assert_eq!(
            demand.randoms, 8,
            "the first outer iteration has a statically visible inner width"
        );
        assert!(demand.dynamic, "the shrinking outer loop remains dynamic");
    }

    #[test]
    fn batch_mul_over_known_literal_list() {
        let src = r#"
def main() -> int64:
  var xs: list[secret bool] = []
  for i in 0..5:
    xs.append(ClientStore.take_share_bool(0, i))
  var ys: list[secret bool] = []
  for j in 0..5:
    ys.append(ClientStore.take_share_bool(1, j))
  var products = Share.batch_mul(xs, ys)
  return 0
"#;
        let demand = demand_for(src);
        assert_eq!(demand.triples, 5);
        assert!(!demand.dynamic);
    }

    #[test]
    fn copy_extend_and_slice_preserve_static_batch_lengths() {
        let src = r#"
def main() -> int64:
  var xs: list[secret bool] = []
  var ys: list[secret bool] = []
  for i in 0..4:
    xs.append(ClientStore.take_share_bool(0, i))
    ys.append(ClientStore.take_share_bool(1, i))
  var lefts = copy(xs)
  var rights = copy(ys)
  lefts.extend(xs)
  rights.extend(ys)
  var products = Share.batch_mul(lefts, rights)
  var first = slice(products, 0, 4)
  var first_copy = copy(first)
  var products2 = Share.batch_mul(first_copy, first)
  return 0
"#;
        let demand = demand_for(src);
        assert_eq!(demand.triples, 12, "8-element batch plus 4-element batch");
        assert!(
            !demand.dynamic,
            "shape-preserving list plumbing must not force online top-ups"
        );
    }

    #[test]
    fn secret_xor_helper_in_literal_loop() {
        let src = r#"
def gate(a: secret bool, b: secret bool) -> secret bool:
  return a xor b

def main() -> int64:
  var a: secret bool = ClientStore.take_share_bool(0, 0)
  var b: secret bool = ClientStore.take_share_bool(0, 1)
  for i in 0..10:
    var c: secret bool = gate(a, b)
  return 0
"#;
        let demand = demand_for(src);
        assert_eq!(demand.triples, 10);
        assert!(!demand.dynamic);
    }

    #[test]
    fn secret_boolean_fields_get_a_conservative_dynamic_floor() {
        let src = r#"
object bit_vector:
  bits: list[secret bool]
  length: int64

def XOR(a: bit_vector, b: bit_vector) -> bit_vector:
  var result: bit_vector
  result.length = a.length
  for i in 0..result.length:
    result.bits.append(a.bits[i] xor b.bits[i])
  return result

def main(a: list[secret bool], b: list[secret bool]) -> None:
  var left: bit_vector
  left.bits = a
  left.length = len(a)
  var right: bit_vector
  right.bits = b
  right.length = len(b)
  var result = XOR(left, right)
"#;
        let demand = demand_for(src);
        assert_eq!(demand.triples, 1);
        assert!(
            demand.dynamic,
            "untracked object-field lengths must retain runtime headroom"
        );
    }

    #[test]
    fn zero_argument_wrapper_propagates_parameterized_object_field_demand() {
        let src = r#"
object bit_vector:
  bits: list[secret bool]
  length: int64

def XOR(a: bit_vector, b: bit_vector) -> bit_vector:
  var result: bit_vector
  result.length = a.length
  for i in 0..result.length:
    result.bits.append(a.bits[i] xor b.bits[i])
  return result

def parameterized(a: list[secret bool], b: list[secret bool]) -> None:
  var left: bit_vector
  left.bits = a
  left.length = len(a)
  var right: bit_vector
  right.bits = b
  right.length = len(b)
  var result = XOR(left, right)

def main() -> None:
  parameterized(
    [Share.from_clear_int(0, 1), Share.from_clear_int(1, 1)],
    [Share.from_clear_int(1, 1), Share.from_clear_int(0, 1)],
  )
"#;
        let demand = demand_for(src);
        assert_eq!(demand.triples, 1);
        assert!(demand.dynamic);
    }

    #[test]
    fn bitwise_share_catalog_wrapper_has_preprocessing_floor() {
        let original = include_str!("../examples/mpc_bitwise_share/main.stfl");
        let renamed = original.replacen("def main(", "def __example_parameterized_main(", 1);
        let source = format!(
            "{renamed}\n\
             def __standing_example_main() -> None:\n  \
             __example_parameterized_main(\
             [Share.from_clear_int(0, 1), Share.from_clear_int(1, 1), Share.from_clear_int(0, 1), Share.from_clear_int(1, 1)], \
             [Share.from_clear_int(1, 1), Share.from_clear_int(0, 1), Share.from_clear_int(1, 1), Share.from_clear_int(0, 1)])\n"
        );
        let demand = demand_for(&source);
        assert!(demand.triples >= 4, "observed demand: {demand:?}");
        assert!(demand.dynamic);
    }

    #[test]
    fn len_loop_over_literal_list() {
        let src = r#"
def helper(xs: list[secret bool], ys: list[secret bool]) -> int64:
  for i in 0..xs.len():
    var c: secret bool = xs[i] and ys[i]
  return 0

def main() -> int64:
  var xs: list[secret bool] = []
  for i in 0..7:
    xs.append(ClientStore.take_share_bool(0, i))
  var ys: list[secret bool] = []
  for j in 0..7:
    ys.append(ClientStore.take_share_bool(1, j))
  var n = helper(xs, ys)
  return 0
"#;
        let demand = demand_for(src);
        assert_eq!(demand.triples, 7);
        assert!(!demand.dynamic);
    }

    #[test]
    fn recursion_is_dynamic() {
        let src = r#"
def recurse(n: int64, a: secret bool, b: secret bool) -> secret bool:
  if n == 0:
    return a
  var c: secret bool = a and b
  return recurse(n - 1, c, b)

def main() -> int64:
  var a: secret bool = ClientStore.take_share_bool(0, 0)
  var b: secret bool = ClientStore.take_share_bool(0, 1)
  var r: secret bool = recurse(3, a, b)
  return 0
"#;
        let demand = demand_for(src);
        assert!(demand.dynamic);
    }

    #[test]
    fn if_takes_branch_maximum() {
        let src = r#"
def pick(flag: int64, a: secret bool, b: secret bool) -> secret bool:
  if flag == 0:
    var c: secret bool = a and b
    var d: secret bool = a xor b
    return c
  else:
    var e: secret bool = a or b
    return e

def main() -> int64:
  var a: secret bool = ClientStore.take_share_bool(0, 0)
  var b: secret bool = ClientStore.take_share_bool(0, 1)
  var r: secret bool = pick(1, a, b)
  return 0
"#;
        let demand = demand_for(src);
        // then-branch needs 2 triples (and + xor), else-branch 1 (or); max = 2.
        assert_eq!(demand.triples, 2);
        assert!(!demand.dynamic);
    }

    #[test]
    fn retrying_random_bit_counts_its_multiplication() {
        let src = r#"
def random_bit() -> secret bool:
  while True:
    var r = Share.random_field()
    var squared = Share.open_field(Share.mul(r, r))
    if Field.is_zero(squared):
      continue
    return Share.retag(r, 1)

def main() -> bool:
  return random_bit().reveal()
"#;
        let demand = demand_for(src);
        assert_eq!(demand.triples, 1);
        assert_eq!(demand.randoms, 1);
        assert!(demand.dynamic);
    }

    #[test]
    fn literal_integer_arguments_bound_helper_loops() {
        let src = r#"
def random_bit() -> Share:
  while True:
    var r = Share.random_field()
    var squared = Share.open_field(Share.mul(r, r))
    if Field.is_zero(squared):
      continue
    return Share.retag(r, 1)

def make_bits(l: int64, kappa: int64) -> int64:
  var i = 0
  while i < l + kappa:
    discard random_bit()
    i = i + 1
  return i

def main() -> int64:
  return make_bits(8, 8)
"#;
        let demand = demand_for(src);
        assert_eq!(demand.triples, 16);
        assert_eq!(demand.randoms, 16);
        // random_bit retries with a data-dependent loop, so its one-attempt
        // floor remains dynamic even though the outer helper loop is exact.
        assert!(demand.dynamic);
    }

    #[test]
    fn receiver_style_share_multiplication_counts_a_triple() {
        let src = r#"
def main() -> int64:
  var score = Share.from_clear_int(7, 64)
  score = score.mul(Share.from_clear_int(1, 64))
  return score.open()
"#;
        let demand = demand_for(src);
        assert_eq!(demand.triples, 1);
    }

    /// Compile each bundled AES-128 example via the real example/bindgen compile
    /// path and assert its preprocessing demand is an exact, non-dynamic count.
    /// Run with `--nocapture` to see the emitted triple counts.
    #[test]
    fn aes_examples_have_exact_static_demand() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let examples = [
            "mpc_aes128_ctr_client_io",
            "mpc_aes128_cbc_client_io",
            "mpc_aes128_transcipher",
            "mpc_aes128_secure_decrypt",
        ];
        for example in examples {
            let path = format!("{manifest_dir}/examples/{example}/main.stfl");
            let source = match std::fs::read_to_string(&path) {
                Ok(source) => source,
                Err(_) => {
                    // The example is not present in this checkout; skip it.
                    eprintln!("skipping {example}: {path} not found");
                    continue;
                }
            };
            let demand = demand_for(&source);
            println!(
                "{example}: triples={} randoms={} prandbits={} prandints={} dynamic={}",
                demand.triples, demand.randoms, demand.prandbits, demand.prandints, demand.dynamic,
            );
            assert!(
                !demand.dynamic,
                "{example} demand should be statically exact (dynamic == false)"
            );
            assert!(
                demand.triples > 0,
                "{example} should consume some preprocessing triples"
            );
        }
    }
}
