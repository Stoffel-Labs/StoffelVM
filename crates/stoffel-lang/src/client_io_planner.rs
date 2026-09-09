//! Interprocedural client-I/O inference over the checked AST.
//!
//! Input planning propagates concrete slots/ordinals through relevant helpers.
//! Output planning tracks share tags, exact scalar widths, aggregate identities,
//! aliases, and mutations through helper calls. Static loops are enumerated;
//! runtime loop backedges are joined to a bounded fixed point. Unprovable output
//! domains or batch lengths produce source diagnostics instead of guessed tags.
//! The proven output contract replaces codegen's local guesses after lowering.

use std::collections::{BTreeSet, HashMap, HashSet};

use crate::ast::{AstNode, Parameter, Pragma, Value};
use crate::errors::{CompilerError, SourceLocation};
use crate::symbol_table::SymbolType;
use stoffel_vm_types::compiled_binary::{
    ClientIoManifest, ClientIoSchema, DynamicClientInputSchema,
};
use stoffel_vm_types::core_types::ShareType;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
struct AbstractValue {
    list_depth: usize,
    opaque: bool,
    float: bool,
    share: Option<ShareType>,
    aggregate: Option<usize>,
    int: Option<i128>,
    list_len: Option<usize>,
    runtime_client_count: bool,
    dynamic_client_slot_start: Option<u64>,
}

impl AbstractValue {
    fn int(value: i128) -> Self {
        Self {
            list_depth: 0,
            opaque: false,
            float: false,
            share: None,
            aggregate: None,
            int: Some(value),
            list_len: None,
            runtime_client_count: false,
            dynamic_client_slot_start: None,
        }
    }

    fn list(len: usize) -> Self {
        Self {
            list_depth: 1,
            opaque: false,
            float: false,
            share: None,
            aggregate: None,
            int: None,
            list_len: Some(len),
            runtime_client_count: false,
            dynamic_client_slot_start: None,
        }
    }
}

type Env = HashMap<String, AbstractValue>;
type InferredInputs = HashMap<u64, Vec<Option<ShareType>>>;
type InferredDynamicInputs = HashMap<u64, Vec<Option<ShareType>>>;
type InferredOutputCounts = HashMap<u64, usize>;
type InferredOutputs = HashMap<u64, Vec<Option<ShareType>>>;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Aggregate {
    Unknown,
    Closure(String),
    List(Vec<AbstractValue>),
    Object(HashMap<String, AbstractValue>),
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum Control {
    #[default]
    Next,
    Return,
    Break,
    Continue,
}

struct FunctionInfo<'a> {
    parameters: &'a [Parameter],
    body: &'a AstNode,
    is_entry: bool,
    returns_list: bool,
    return_type: Option<SymbolType>,
}

struct LoopSnapshot {
    env: Env,
    heap: Vec<Aggregate>,
    offsets: HashMap<u64, BTreeSet<usize>>,
}

#[derive(Default)]
struct LoopFrame {
    breaks: Vec<LoopSnapshot>,
    continues: Vec<LoopSnapshot>,
}

struct Planner<'a> {
    functions: HashMap<String, FunctionInfo<'a>>,
    relevant: HashSet<String>,
    domain_sensitive: HashSet<String>,
    inputs: InferredInputs,
    dynamic_inputs: InferredDynamicInputs,
    output_counts: InferredOutputCounts,
    call_stack: Vec<(String, Vec<AbstractValue>)>,
    scalar_cache: HashMap<(String, Vec<AbstractValue>), AbstractValue>,
    heap: Vec<Aggregate>,
    uncertain_lengths: HashSet<usize>,
    aggregate_aliases: HashMap<usize, BTreeSet<usize>>,
    outputs: InferredOutputs,
    output_offsets: HashMap<u64, BTreeSet<usize>>,
    object_types: HashMap<String, Vec<crate::ast::FieldDefinition>>,
    errors: Vec<CompilerError>,
    output_locations: HashMap<u64, SourceLocation>,
    control: Control,
    loops: Vec<LoopFrame>,
    returns: Vec<AbstractValue>,
    steps: usize,
    needs_output_shapes: bool,
}

const MAX_STATIC_LOOP_ITERATIONS: usize = 1_000_000;

/// Add interprocedurally inferred client inputs to an already generated
/// manifest. Existing output schemas and directly inferred input types remain
/// intact.
pub(crate) fn merge_inferred_client_inputs(program: &AstNode, manifest: &mut ClientIoManifest) {
    let (inputs, dynamic_inputs, output_counts) = infer_client_io(program);
    for (client_slot, inferred) in inputs {
        let schema = match manifest
            .clients
            .iter_mut()
            .find(|schema| schema.client_slot == client_slot)
        {
            Some(schema) => schema,
            None => {
                manifest.clients.push(ClientIoSchema {
                    client_slot,
                    inputs: Vec::new(),
                    outputs: Vec::new(),
                });
                manifest
                    .clients
                    .last_mut()
                    .expect("client schema was pushed")
            }
        };
        let directly_inferred_len = schema.inputs.len();
        if schema.inputs.len() < inferred.len() {
            schema
                .inputs
                .resize_with(inferred.len(), ShareType::default_secret_int);
        }
        for (ordinal, share_type) in inferred.into_iter().enumerate() {
            if let Some(share_type) = share_type {
                // Direct codegen has semantic annotations and is authoritative
                // for every ordinal it already found. The concrete planner only
                // fills ordinals discovered through helper-call propagation;
                // otherwise its builtin defaults would erase precise types such
                // as an annotated `secret fix32`.
                if ordinal >= directly_inferred_len {
                    schema.inputs[ordinal] = share_type;
                }
            }
        }
    }
    manifest
        .clients
        .sort_unstable_by_key(|schema| schema.client_slot);

    for (first_client_slot, inferred) in dynamic_inputs {
        let schema = match manifest
            .dynamic_client_inputs
            .iter_mut()
            .find(|schema| schema.first_client_slot == first_client_slot)
        {
            Some(schema) => schema,
            None => {
                manifest
                    .dynamic_client_inputs
                    .push(DynamicClientInputSchema {
                        first_client_slot,
                        inputs: Vec::new(),
                    });
                manifest
                    .dynamic_client_inputs
                    .last_mut()
                    .expect("dynamic client input schema was pushed")
            }
        };
        if schema.inputs.len() < inferred.len() {
            schema
                .inputs
                .resize_with(inferred.len(), ShareType::default_secret_int);
        }
        for (ordinal, share_type) in inferred.into_iter().enumerate() {
            if let Some(share_type) = share_type {
                schema.inputs[ordinal] = share_type;
            }
        }
    }
    manifest
        .dynamic_client_inputs
        .sort_unstable_by_key(|schema| schema.first_client_slot);

    // Codegen visits a loop body once, so a `send_to_client` inside a bounded
    // loop contributes only one schema output even though the VM captures one
    // output per iteration. The concrete walk below enumerates bounded loops
    // and user-function calls. Extend the direct type pattern to the inferred
    // cardinality; the standing runner can then submit the complete ordered
    // batch once, matching the coordinator contract.
    for (client_slot, inferred_count) in output_counts {
        let schema = match manifest
            .clients
            .iter_mut()
            .find(|schema| schema.client_slot == client_slot)
        {
            Some(schema) => schema,
            None => {
                manifest.clients.push(ClientIoSchema {
                    client_slot,
                    inputs: Vec::new(),
                    outputs: Vec::new(),
                });
                manifest
                    .clients
                    .last_mut()
                    .expect("client schema was pushed")
            }
        };
        if schema.outputs.len() < inferred_count {
            let pattern = if schema.outputs.is_empty() {
                vec![ShareType::default_secret_int()]
            } else {
                schema.outputs.clone()
            };
            while schema.outputs.len() < inferred_count {
                let next = pattern[schema.outputs.len() % pattern.len()];
                schema.outputs.push(next);
            }
        }
    }
    manifest
        .clients
        .sort_unstable_by_key(|schema| schema.client_slot);
}

fn infer_client_io(
    program: &AstNode,
) -> (InferredInputs, InferredDynamicInputs, InferredOutputCounts) {
    let planner = plan_client_io(program, &[], false);
    (
        planner.inputs,
        planner.dynamic_inputs,
        planner.output_counts,
    )
}

fn plan_client_io<'a>(
    program: &'a AstNode,
    entry_points: &[String],
    infer_output_shapes: bool,
) -> Planner<'a> {
    let mut functions = HashMap::new();
    collect_functions(program, &mut functions);

    let mut direct_client_readers = HashSet::new();
    let mut callees: HashMap<String, HashSet<String>> = HashMap::new();
    for (name, info) in &functions {
        let mut calls = HashSet::new();
        let mut reads_client = false;
        collect_calls(info.body, &mut calls, &mut reads_client);
        if reads_client {
            direct_client_readers.insert(name.clone());
        }
        callees.insert(name.clone(), calls);
    }

    // Fixed-point reachability over the call graph lets the interpreter skip
    // large unrelated circuits (notably AES itself) and visit only helpers that
    // can eventually read from ClientStore.
    let mut domain_sensitive = HashSet::new();
    for (name, info) in &functions {
        if info.parameters.iter().any(|p| p.type_annotation.as_deref().map(SymbolType::from_ast).is_some_and(|ty| matches!(ty.underlying_type(), SymbolType::Object(n) | SymbolType::TypeName(n) if n == "Share")))
            || callees[name].iter().any(|callee| matches!(callee.as_str(), "Share.from_field" | "Share.random_field" | "Share.add_field" | "Share.mul_field" | "add_field" | "mul_field" | "Share.from_clear_int" | "Share.from_clear_uint" | "Share.from_clear_fixed" | "Share.retag" | "retag" | "Share.mul_scalar" | "mul_scalar" | "Share.add_constant" | "add_constant" | "Share.add_scalar" | "add_scalar")) {
            domain_sensitive.insert(name.clone());
        }
    }
    loop {
        let before = domain_sensitive.len();
        for (caller, calls) in &callees {
            if calls.iter().any(|callee| domain_sensitive.contains(callee)) {
                domain_sensitive.insert(caller.clone());
            }
        }
        if before == domain_sensitive.len() {
            break;
        }
    }
    let mut relevant = direct_client_readers;
    loop {
        let before = relevant.len();
        for (caller, calls) in &callees {
            if calls.iter().any(|callee| relevant.contains(callee)) {
                relevant.insert(caller.clone());
            }
        }
        if relevant.len() == before {
            break;
        }
    }

    let entries = functions
        .iter()
        .filter_map(|(name, info)| {
            (name == "main" || info.is_entry || entry_points.contains(name)).then_some(name.clone())
        })
        .collect::<Vec<_>>();

    let mut needs_output_shapes = false;
    fn has_outputs(node: &AstNode, found: &mut bool) {
        match node {
            AstNode::FunctionDefinition { body, .. } => has_outputs(body, found),
            AstNode::FunctionCall { function, .. } if matches!(function.as_ref(), AstNode::Identifier(name, _) if is_client_output_call(name)) => {
                *found = true
            }
            _ => {}
        }
        crate::optimizations::for_each_child(node, &mut |child| has_outputs(child, found));
    }
    if infer_output_shapes {
        has_outputs(program, &mut needs_output_shapes);
    }
    fn collect_objects(
        node: &AstNode,
        out: &mut HashMap<String, Vec<crate::ast::FieldDefinition>>,
    ) {
        if let AstNode::ObjectDefinition { name, fields, .. } = node {
            out.insert(name.clone(), fields.clone());
        }
        if let AstNode::FunctionDefinition { body, .. } = node {
            collect_objects(body, out);
        }
        crate::optimizations::for_each_child(node, &mut |child| collect_objects(child, out));
    }
    let mut object_types = HashMap::new();
    collect_objects(program, &mut object_types);
    let mut planner = Planner {
        functions,
        relevant,
        domain_sensitive,
        inputs: HashMap::new(),
        dynamic_inputs: HashMap::new(),
        output_counts: HashMap::new(),
        call_stack: Vec::new(),
        scalar_cache: HashMap::new(),
        heap: Vec::new(),
        uncertain_lengths: HashSet::new(),
        aggregate_aliases: HashMap::new(),
        outputs: HashMap::new(),
        output_offsets: HashMap::new(),
        object_types,
        errors: Vec::new(),
        output_locations: HashMap::new(),
        control: Control::Next,
        loops: Vec::new(),
        returns: Vec::new(),
        steps: 0,
        needs_output_shapes,
    };

    // Top-level executable statements are an entry form too. Function
    // definitions are scope declarations and are skipped by `visit`.
    planner.visit(program, &mut Env::new());
    for entry in entries {
        planner.output_offsets.clear();
        planner.visit_user_call(&entry, &[], &Env::new());
    }
    planner
}

/// Resolve output domains from actual calls before optimization erases source
/// structure. Unknown domains are errors, never an implicit integer encoding.
pub(crate) fn infer_output_domains(
    program: &AstNode,
    entry_points: &[String],
) -> Result<HashMap<u64, Vec<ShareType>>, Vec<CompilerError>> {
    let mut planner = plan_client_io(program, entry_points, true);
    let mut outputs = HashMap::new();
    for (slot, values) in planner.outputs {
        if let Some(types) = values.into_iter().collect::<Option<Vec<_>>>() {
            outputs.insert(slot, types);
        } else {
            planner.errors.push(CompilerError::type_error(
                "Cannot infer a single share domain for this client output",
                planner.output_locations.get(&slot).cloned().unwrap_or_default())
                .with_hint("Use an explicit Share constructor or a secret scalar type; every possible value at an output position must have the same domain and precision"));
        }
    }
    if planner.errors.is_empty() {
        Ok(outputs)
    } else {
        Err(planner.errors)
    }
}

pub(crate) fn apply_output_domains(
    outputs: HashMap<u64, Vec<ShareType>>,
    manifest: &mut ClientIoManifest,
) {
    for schema in &mut manifest.clients {
        schema.outputs.clear();
    }
    for (slot, outputs) in outputs {
        if let Some(schema) = manifest.clients.iter_mut().find(|s| s.client_slot == slot) {
            schema.outputs = outputs;
        } else {
            manifest.clients.push(ClientIoSchema {
                client_slot: slot,
                inputs: Vec::new(),
                outputs,
            });
        }
    }
    manifest.clients.sort_unstable_by_key(|s| s.client_slot);
}

fn collect_functions<'a>(node: &'a AstNode, out: &mut HashMap<String, FunctionInfo<'a>>) {
    match node {
        AstNode::FunctionDefinition {
            name: Some(name),
            parameters,
            return_type,
            body,
            pragmas,
            ..
        } => {
            out.insert(
                name.clone(),
                FunctionInfo {
                    parameters,
                    body,
                    is_entry: pragmas
                        .iter()
                        .any(|pragma| matches!(pragma, Pragma::Simple(name, _) if name == "entry")),
                    returns_list: return_type.as_deref().is_some_and(is_list_return_type),
                    return_type: return_type.as_deref().map(SymbolType::from_ast),
                },
            );
            collect_functions(body, out);
        }
        AstNode::Block(nodes) => {
            for node in nodes {
                collect_functions(node, out);
            }
        }
        _ => {}
    }
}

fn collect_calls(node: &AstNode, calls: &mut HashSet<String>, reads_client: &mut bool) {
    if let AstNode::FunctionCall {
        function,
        arguments,
        ..
    }
    | AstNode::CommandCall {
        command: function,
        arguments,
        ..
    } = node
    {
        if let AstNode::Identifier(name, _) = function.as_ref() {
            if is_client_input_call(name) || is_client_output_call(name) {
                *reads_client = true;
            } else {
                calls.insert(name.clone());
                if matches!(
                    name.as_str(),
                    "create_closure" | "create_closure_with_upvalue"
                ) {
                    if let Some(AstNode::Literal {
                        value: Value::String(target),
                        ..
                    }) = arguments.first()
                    {
                        calls.insert(target.clone());
                    }
                }
            }
        }
    }
    crate::optimizations::for_each_child(node, &mut |child| {
        collect_calls(child, calls, reads_client)
    });
}

impl Planner<'_> {
    fn visit(&mut self, node: &AstNode, env: &mut Env) -> AbstractValue {
        self.steps += 1;
        if self.steps > 5_000_000 {
            if self.steps == 5_000_001 && self.needs_output_shapes {
                self.errors.push(CompilerError::type_error("Share-domain inference exceeded its analysis budget", node.location()).with_hint("Simplify the output-producing loop or split the entrypoint into smaller computations"));
            }
            return AbstractValue {
                opaque: true,
                ..AbstractValue::default()
            };
        }
        match node {
            AstNode::Literal { value, .. } => match value {
                Value::Int { value, .. } => i128::try_from(*value)
                    .map(AbstractValue::int)
                    .unwrap_or_default(),
                Value::Float(_) => AbstractValue {
                    float: true,
                    ..AbstractValue::default()
                },
                Value::Bool(value) => AbstractValue::int(i128::from(*value)),
                _ => AbstractValue::default(),
            },
            AstNode::Identifier(name, _) => env.get(name).copied().unwrap_or_default(),
            AstNode::VariableDeclaration {
                name,
                value,
                type_annotation,
                ..
            } => {
                let has_initializer = value.is_some();
                let mut value = value
                    .as_deref()
                    .map(|value| self.visit(value, env))
                    .unwrap_or_default();
                if let Some(ty) = type_annotation.as_deref().map(SymbolType::from_ast) {
                    value = self.apply_type(value, &ty);
                    if !has_initializer {
                        value = self.default_value(&ty, 0);
                    }
                }
                env.insert(name.clone(), value);
                value
            }
            AstNode::Assignment { target, value, .. } => {
                let value = self.visit(value, env);
                if let AstNode::Identifier(name, _) = target.as_ref() {
                    env.insert(name.clone(), value);
                } else {
                    self.assign_aggregate(target, value, env);
                }
                value
            }
            AstNode::BinaryOperation {
                op, left, right, ..
            } => {
                let left = self.visit(left, env);
                let right = self.visit(right, env);
                if op == "*" {
                    if let Some(result) = self
                        .repeat_list(left, right)
                        .or_else(|| self.repeat_list(right, left))
                    {
                        return result;
                    }
                }
                if op == "+" {
                    if let (Some(Aggregate::List(a)), Some(Aggregate::List(b))) = (
                        left.aggregate.and_then(|id| self.heap.get(id)),
                        right.aggregate.and_then(|id| self.heap.get(id)),
                    ) {
                        return self.list(a.iter().chain(b).copied().collect());
                    }
                }
                AbstractValue {
                    share: if (left.opaque && left.share.is_none())
                        || (right.opaque && right.share.is_none())
                    {
                        None
                    } else {
                        promoted_scalar_domain(
                            arithmetic_domain(op, left.share, right.share),
                            matches!(op.as_str(), "+" | "-" | "*" | "/")
                                && (left.float || right.float),
                        )
                    },
                    opaque: left.opaque
                        || right.opaque
                        || left.share.is_some()
                        || right.share.is_some(),
                    float: left.float || right.float,
                    int: eval_binary(op, left.int, right.int),
                    list_len: None,
                    ..AbstractValue::default()
                }
            }
            AstNode::UnaryOperation { op, operand, .. } => {
                let value = self.visit(operand, env);
                let int = match (op.as_str(), value.int) {
                    ("-", Some(value)) => value.checked_neg(),
                    ("+", value) => value,
                    ("not", Some(value)) => Some(i128::from(value == 0)),
                    ("~", Some(value)) => Some(!value),
                    _ => None,
                };
                AbstractValue {
                    share: value.share,
                    opaque: value.opaque,
                    float: value.float,
                    int,
                    list_len: None,
                    ..AbstractValue::default()
                }
            }
            AstNode::Block(nodes) => {
                let mut value = AbstractValue::default();
                for node in nodes {
                    if self.control != Control::Next {
                        break;
                    }
                    if !matches!(node, AstNode::FunctionDefinition { .. }) {
                        value = self.visit(node, env);
                    }
                }
                value
            }
            AstNode::FunctionDefinition { .. } => AbstractValue::default(),
            AstNode::FunctionCall {
                function,
                arguments,
                resolved_return_type,
                location,
            } => self.visit_call(
                function,
                arguments,
                resolved_return_type.as_ref(),
                env,
                location,
            ),
            AstNode::CommandCall {
                command: function,
                arguments,
                location,
                ..
            } => self.visit_call(function, arguments, None, env, location),
            AstNode::NamedArgument { value, .. } => self.visit(value, env),
            AstNode::ForLoop {
                variables,
                iterable,
                body,
                ..
            } => {
                self.visit_for(variables, iterable, body, env);
                AbstractValue::default()
            }
            AstNode::WhileLoop {
                condition, body, ..
            } => {
                self.visit_while(condition, body, env);
                AbstractValue::default()
            }
            AstNode::IfExpression {
                condition,
                then_branch,
                else_branch,
            } => {
                if let Some(value) = self.visit(condition, env).int {
                    return if value != 0 {
                        self.visit(then_branch, env)
                    } else {
                        else_branch
                            .as_deref()
                            .map(|b| self.visit(b, env))
                            .unwrap_or_default()
                    };
                }
                let original = env.clone();
                let heap_before = self.heap.clone();
                let outputs_before = self.output_counts.clone();
                let types_before = self.outputs.clone();
                let offsets_before = self.output_offsets.clone();
                let mut then_env = original.clone();
                let then_value = self.visit(then_branch, &mut then_env);
                let then_control = self.control;
                let then_heap = self.heap.clone();
                let then_outputs = self.output_counts.clone();
                let then_types = self.outputs.clone();
                let then_offsets = self.output_offsets.clone();
                self.output_counts.clone_from(&outputs_before);
                self.outputs.clone_from(&types_before);
                self.output_offsets.clone_from(&offsets_before);
                self.heap[..heap_before.len()].clone_from_slice(&heap_before);
                self.control = Control::Next;
                let mut else_env = original.clone();
                let else_value = else_branch
                    .as_deref()
                    .map(|branch| self.visit(branch, &mut else_env))
                    .unwrap_or_default();
                let else_control = self.control;
                let else_outputs = self.output_counts.clone();
                let else_types = self.outputs.clone();
                merge_branch_output_counts(
                    &mut self.output_counts,
                    &outputs_before,
                    &then_outputs,
                    &else_outputs,
                );
                self.outputs = merge_output_types(&then_types, &else_types);
                let else_offsets = self.output_offsets.clone();
                if then_control == Control::Next && else_control == Control::Next {
                    self.output_offsets = merge_offsets(&then_offsets, &else_offsets);
                } else if then_control == Control::Next {
                    self.output_offsets = then_offsets;
                } else {
                    self.output_offsets = else_offsets;
                }
                for (id, then) in then_heap.iter().enumerate().take(heap_before.len()) {
                    if different_list_lengths(then, &self.heap[id]) {
                        self.uncertain_lengths.insert(id);
                    }
                    self.heap[id] = self.join_aggregate(then, &self.heap[id].clone());
                }
                match (then_control, else_control) {
                    (Control::Next, Control::Next) => {
                        self.merge_env(env, &then_env, &else_env);
                        self.control = Control::Next;
                    }
                    (Control::Next, _) => {
                        *env = then_env;
                        self.control = Control::Next;
                    }
                    (_, Control::Next) => {
                        *env = else_env;
                        self.control = Control::Next;
                    }
                    (a, b) => {
                        self.control = if a == b { a } else { Control::Return };
                    }
                }
                self.join_value(then_value, else_value)
            }
            AstNode::ListLiteral { elements, .. }
            | AstNode::TupleLiteral(elements)
            | AstNode::SetLiteral(elements) => {
                let values = elements
                    .iter()
                    .map(|element| self.visit(element, env))
                    .collect();
                self.list(values)
            }
            AstNode::DictLiteral { pairs, .. } => {
                for (key, value) in pairs {
                    self.visit(key, env);
                    self.visit(value, env);
                }
                AbstractValue::default()
            }
            AstNode::Return { value, .. } | AstNode::Yield(value) => {
                let value = value
                    .as_deref()
                    .map(|value| self.visit(value, env))
                    .unwrap_or_default();
                self.returns.push(value);
                self.control = Control::Return;
                value
            }
            AstNode::DiscardStatement { expression, .. } => self.visit(expression, env),
            AstNode::IndexAccess { base, index, .. } => {
                let base = self.visit(base, env);
                let index = self
                    .visit(index, env)
                    .int
                    .and_then(|n| usize::try_from(n).ok());
                if let Some(Aggregate::List(values)) =
                    base.aggregate.and_then(|id| self.heap.get(id)).cloned()
                {
                    if let Some(index) = index {
                        return values.get(index).copied().unwrap_or_default();
                    }
                    return values
                        .into_iter()
                        .reduce(|a, b| self.join_value(a, b))
                        .unwrap_or_default();
                }
                AbstractValue {
                    list_depth: base.list_depth.saturating_sub(1),
                    opaque: base.opaque || base.aggregate.is_some(),
                    share: if base.aggregate.is_none() {
                        base.share
                    } else {
                        None
                    },
                    ..AbstractValue::default()
                }
            }
            AstNode::FieldAccess {
                object, field_name, ..
            } => {
                let object = self.visit(object, env);
                if let Some(Aggregate::Object(fields)) =
                    object.aggregate.and_then(|id| self.heap.get(id))
                {
                    return fields.get(field_name).copied().unwrap_or_default();
                }
                AbstractValue {
                    opaque: true,
                    ..AbstractValue::default()
                }
            }
            AstNode::TryCatch {
                try_block,
                catch_clauses,
                finally_block,
                ..
            } => {
                self.visit(try_block, env);
                for clause in catch_clauses {
                    self.visit(&clause.body, env);
                }
                if let Some(finally_block) = finally_block {
                    self.visit(finally_block, env);
                }
                AbstractValue::default()
            }
            // Type and declaration nodes do not execute client reads.
            AstNode::Break => {
                let snapshot = self.loop_snapshot(env);
                if let Some(frame) = self.loops.last_mut() {
                    frame.breaks.push(snapshot);
                }
                self.control = Control::Break;
                AbstractValue::default()
            }
            AstNode::Continue => {
                let snapshot = self.loop_snapshot(env);
                if let Some(frame) = self.loops.last_mut() {
                    frame.continues.push(snapshot);
                }
                self.control = Control::Continue;
                AbstractValue::default()
            }
            AstNode::TypeAlias { .. }
            | AstNode::BuiltinTypeDefinition { .. }
            | AstNode::BuiltinObjectDefinition { .. }
            | AstNode::ObjectDefinition { .. }
            | AstNode::EnumDefinition { .. }
            | AstNode::SecretType(_)
            | AstNode::FunctionType { .. }
            | AstNode::TupleType(_)
            | AstNode::ListType(_)
            | AstNode::DictType { .. }
            | AstNode::GenericType { .. }
            | AstNode::Import { .. } => AbstractValue::default(),
        }
    }

    fn visit_call(
        &mut self,
        function: &AstNode,
        arguments: &[AstNode],
        resolved_return_type: Option<&SymbolType>,
        env: &mut Env,
        location: &SourceLocation,
    ) -> AbstractValue {
        let argument_values = arguments
            .iter()
            .map(|argument| self.visit(argument, env))
            .collect::<Vec<_>>();
        let AstNode::Identifier(name, _) = function else {
            self.visit(function, env);
            return AbstractValue::default();
        };

        if matches!(
            name.as_str(),
            "create_closure" | "create_closure_with_upvalue"
        ) {
            if let Some(AstNode::Literal {
                value: Value::String(target),
                ..
            }) = arguments.first()
            {
                let id = self.heap.len();
                self.heap.push(Aggregate::Closure(target.clone()));
                return AbstractValue {
                    aggregate: Some(id),
                    ..AbstractValue::default()
                };
            }
        }
        if matches!(name.as_str(), "call_closure" | "call_closure_with_arg") {
            if let Some(Aggregate::Closure(target)) = argument_values
                .first()
                .and_then(|v| v.aggregate)
                .and_then(|id| self.heap.get(id))
                .cloned()
            {
                if self.functions.contains_key(&target) {
                    return self.visit_user_call(&target, &argument_values[1..], env);
                }
            }
            if self.needs_output_shapes {
                self.errors.push(CompilerError::type_error("Cannot infer the target of this closure call for client I/O", location.clone())
                    .with_hint("Use a statically named closure target or a direct helper call for output-producing computations"));
            }
            return AbstractValue {
                opaque: true,
                ..AbstractValue::default()
            };
        }
        if matches!(name.as_str(), "Share.batch_mul" | "batch_mul") {
            if let (Some(Aggregate::List(a)), Some(Aggregate::List(b))) = (
                argument_values
                    .first()
                    .and_then(|v| v.aggregate)
                    .and_then(|id| self.heap.get(id))
                    .cloned(),
                argument_values
                    .get(1)
                    .and_then(|v| v.aggregate)
                    .and_then(|id| self.heap.get(id))
                    .cloned(),
            ) {
                return self.list(
                    a.iter()
                        .zip(b)
                        .map(|(a, b)| AbstractValue {
                            share: arithmetic_domain("*", a.share, b.share),
                            ..AbstractValue::default()
                        })
                        .collect(),
                );
            }
        }
        if name == "ClientStore.get_number_clients" {
            return AbstractValue {
                runtime_client_count: true,
                ..AbstractValue::default()
            };
        } else if is_client_input_sum_call(name) {
            self.record_client_input_sum(name, &argument_values, resolved_return_type);
        } else if is_client_input_call(name) {
            self.record_client_input(name, &argument_values, resolved_return_type);
        } else if is_client_output_call(name) {
            self.record_client_output(name, &argument_values);
            if self.needs_output_shapes {
                self.record_output_domains(name, &argument_values, location);
            }
        } else if matches!(name.as_str(), "len" | "array_length") {
            return AbstractValue {
                int: argument_values
                    .first()
                    .and_then(|value| self.list_length(*value))
                    .and_then(|len| i128::try_from(len).ok()),
                list_len: None,
                ..AbstractValue::default()
            };
        } else if matches!(name.as_str(), "append" | "array_push" | "insert") {
            if let Some(AstNode::Identifier(receiver, _)) = arguments.first() {
                if let Some(value) = env.get_mut(receiver) {
                    value.list_len = value.list_len.and_then(|len| len.checked_add(1));
                }
            }
        } else if name == "extend" {
            if let Some(AstNode::Identifier(receiver, _)) = arguments.first() {
                let extension_len = argument_values.get(1).and_then(|value| value.list_len);
                if let Some(value) = env.get_mut(receiver) {
                    value.list_len = value
                        .list_len
                        .zip(extension_len)
                        .and_then(|(left, right)| left.checked_add(right));
                }
            }
        } else if self.relevant.contains(name)
            || self.functions.get(name).is_some_and(|info| {
                self.needs_output_shapes
                    && (self.domain_sensitive.contains(name)
                        || info.parameters.iter().zip(&argument_values).any(
                            |(parameter, value)| {
                                value.aggregate.is_some()
                                || (value.opaque && value.share.is_none())
                                || parameter
                                    .type_annotation
                                    .as_deref()
                                    .map(SymbolType::from_ast)
                                    .and_then(|ty| {
                                        crate::codegen::share_type_for_secret_scalar_symbol_type(
                                            &ty,
                                        )
                                    })
                                    .is_some_and(|expected| {
                                        value.share.is_some_and(|actual| actual != expected)
                                    })
                            },
                        )
                        || info.returns_list
                        || info.return_type.as_ref().is_none_or(|ty| {
                            crate::codegen::share_type_for_secret_scalar_symbol_type(ty).is_none()
                        }))
            })
        {
            return self.visit_user_call(name, &argument_values, env);
        }
        if let Some(id) = argument_values.first().and_then(|v| v.aggregate) {
            match name.as_str() {
                "append" | "array_push" => {
                    if let (Some(Aggregate::List(values)), Some(value)) =
                        (self.heap.get_mut(id), argument_values.get(1))
                    {
                        values.push(*value);
                    }
                }
                "insert" => {
                    if let (Some(Aggregate::List(values)), Some(index), Some(value)) = (
                        self.heap.get_mut(id),
                        argument_values
                            .get(1)
                            .and_then(|v| v.int)
                            .and_then(|v| usize::try_from(v).ok()),
                        argument_values.get(2),
                    ) {
                        if index <= values.len() {
                            values.insert(index, *value);
                        }
                    }
                }
                "copy" => {
                    if let Some(Aggregate::List(values)) = self.heap.get(id).cloned() {
                        let value = self.list(values);
                        if self.uncertain_lengths.contains(&id) {
                            self.uncertain_lengths.insert(value.aggregate.unwrap());
                        }
                        return value;
                    }
                }
                "reverse" => {
                    if let Some(Aggregate::List(values)) = self.heap.get_mut(id) {
                        values.reverse();
                    }
                }
                "clear" => {
                    if let Some(Aggregate::List(values)) = self.heap.get_mut(id) {
                        values.clear();
                        self.uncertain_lengths.remove(&id);
                    }
                }
                "pop" => {
                    if let Some(Aggregate::List(values)) = self.heap.get(id).cloned() {
                        let index = argument_values.get(1).map(|v| v.int).unwrap_or(Some(-1));
                        let Some(index) = index else {
                            let joined = values
                                .iter()
                                .copied()
                                .reduce(|a, b| self.join_value(a, b))
                                .unwrap_or_default();
                            self.write_heap(
                                id,
                                Aggregate::List(vec![joined; values.len().saturating_sub(1)]),
                            );
                            return joined;
                        };
                        let index = if index < 0 {
                            index + values.len() as i128
                        } else {
                            index
                        };
                        if let Ok(index) = usize::try_from(index) {
                            if index < values.len() {
                                let mut values = values;
                                let result = values.remove(index);
                                self.write_heap(id, Aggregate::List(values));
                                return result;
                            }
                        }
                        // Invalid/unknown index cannot establish a domain.
                        return AbstractValue {
                            opaque: true,
                            ..AbstractValue::default()
                        };
                    }
                }
                "sort" | "remove" => {
                    if let Some(Aggregate::List(values)) = self.heap.get(id).cloned() {
                        let joined = values
                            .iter()
                            .copied()
                            .reduce(|a, b| self.join_value(a, b))
                            .unwrap_or_default();
                        self.heap[id] = Aggregate::List(vec![
                            joined;
                            values.len().saturating_sub(
                                usize::from(name == "remove")
                            )
                        ]);
                    }
                }
                "extend" => {
                    let extension = argument_values
                        .get(1)
                        .and_then(|v| v.aggregate)
                        .and_then(|id| self.heap.get(id))
                        .cloned();
                    if let (Some(Aggregate::List(values)), Some(Aggregate::List(extension))) =
                        (self.heap.get_mut(id), extension)
                    {
                        values.extend(extension);
                    }
                }
                _ => {}
            }
            if matches!(
                name.as_str(),
                "append"
                    | "array_push"
                    | "insert"
                    | "extend"
                    | "reverse"
                    | "clear"
                    | "sort"
                    | "remove"
            ) {
                self.write_heap(id, self.heap[id].clone());
            }
        }
        if self.object_types.contains_key(name) {
            let value = self.default_value(&SymbolType::Object(name.clone()), 0);
            if let Some(Aggregate::Object(fields)) =
                value.aggregate.and_then(|id| self.heap.get_mut(id))
            {
                for (arg, value) in arguments.iter().zip(&argument_values) {
                    if let AstNode::NamedArgument { name, .. } = arg {
                        fields.insert(name.clone(), *value);
                    }
                }
            }
            return value;
        }
        self.builtin_value(name, &argument_values, resolved_return_type)
    }

    fn visit_user_call(
        &mut self,
        name: &str,
        arguments: &[AbstractValue],
        _caller_env: &Env,
    ) -> AbstractValue {
        let cacheable =
            !self.relevant.contains(name) && arguments.iter().all(|a| a.aggregate.is_none());
        let cache_key = (name.to_owned(), arguments.to_vec());
        if cacheable {
            if let Some(value) = self.scalar_cache.get(&cache_key) {
                return *value;
            }
        }
        if self.call_stack.len() >= 64
            || self
                .call_stack
                .iter()
                .any(|(active, values)| active == name && values == arguments)
        {
            if self.domain_sensitive.contains(name) {
                return AbstractValue {
                    opaque: true,
                    ..AbstractValue::default()
                };
            }
            return self
                .functions
                .get(name)
                .and_then(|info| info.return_type.as_ref())
                .map(|ty| self.typed_value(ty))
                .unwrap_or_default();
        }
        let Some(info) = self.functions.get(name) else {
            return AbstractValue::default();
        };
        let parameters = info.parameters;
        let body = info.body;
        let return_type = info.return_type.clone();
        let mut env = Env::new();
        for (index, parameter) in parameters.iter().enumerate() {
            let value = arguments.get(index).copied().unwrap_or_else(|| {
                parameter
                    .type_annotation
                    .as_deref()
                    .map(SymbolType::from_ast)
                    .map(|ty| self.typed_value(&ty))
                    .unwrap_or_default()
            });
            let value = parameter
                .type_annotation
                .as_deref()
                .map(SymbolType::from_ast)
                .map(|ty| self.apply_type(value, &ty))
                .unwrap_or(value);
            env.insert(parameter.name.clone(), value);
        }
        let saved_control = self.control;
        let saved_returns = std::mem::take(&mut self.returns);
        self.control = Control::Next;
        self.call_stack.push((name.to_string(), arguments.to_vec()));
        let last = self.visit(body, &mut env);
        self.call_stack.pop();
        let returns = std::mem::replace(&mut self.returns, saved_returns);
        self.control = saved_control;
        let value = returns
            .into_iter()
            .reduce(|a, b| self.join_value(a, b))
            .unwrap_or(last);
        let value = return_type
            .as_ref()
            .map(|ty| self.apply_type(value, ty))
            .unwrap_or(value);
        if cacheable && value.aggregate.is_none() {
            self.scalar_cache.insert(cache_key, value);
        }
        value
    }

    fn record_client_input(
        &mut self,
        name: &str,
        arguments: &[AbstractValue],
        resolved_return_type: Option<&SymbolType>,
    ) {
        let Some(ordinal) = arguments
            .get(1)
            .and_then(|value| value.int)
            .and_then(|value| usize::try_from(value).ok())
        else {
            return;
        };
        let share_type = resolved_return_type
            .and_then(crate::codegen::share_type_for_secret_scalar_symbol_type)
            .unwrap_or_else(|| match name {
                "ClientStore.take_share_fixed" => ShareType::default_secret_fixed_point(),
                "ClientStore.take_share_bool" => ShareType::boolean(),
                _ => ShareType::default_secret_int(),
            });
        let Some(client) = arguments.first() else {
            return;
        };
        let inputs =
            if let Some(client_slot) = client.int.and_then(|value| u64::try_from(value).ok()) {
                self.inputs.entry(client_slot).or_default()
            } else if let Some(first_client_slot) = client.dynamic_client_slot_start {
                self.dynamic_inputs.entry(first_client_slot).or_default()
            } else {
                return;
            };
        if inputs.len() <= ordinal {
            inputs.resize(ordinal + 1, None);
        }
        inputs[ordinal] = Some(share_type);
    }

    fn record_client_input_sum(
        &mut self,
        name: &str,
        arguments: &[AbstractValue],
        resolved_return_type: Option<&SymbolType>,
    ) {
        let Some(ordinal) = arguments
            .first()
            .and_then(|value| value.int)
            .and_then(|value| usize::try_from(value).ok())
        else {
            return;
        };
        let Some(client_count) = arguments.get(1) else {
            return;
        };
        let share_type = resolved_return_type
            .and_then(crate::codegen::share_type_for_secret_scalar_symbol_type)
            .unwrap_or_else(|| match name {
                "ClientStore.sum_shares_bool" => ShareType::boolean(),
                "ClientStore.sum_shares_fixed" => ShareType::default_secret_fixed_point(),
                _ => ShareType::default_secret_int(),
            });

        if client_count.runtime_client_count {
            let inputs = self.dynamic_inputs.entry(0).or_default();
            if inputs.len() <= ordinal {
                inputs.resize(ordinal + 1, None);
            }
            inputs[ordinal] = Some(share_type);
            return;
        }

        let Some(client_count) = client_count
            .int
            .and_then(|value| usize::try_from(value).ok())
        else {
            return;
        };
        for client_slot in 0..client_count.max(1) {
            let inputs = self.inputs.entry(client_slot as u64).or_default();
            if inputs.len() <= ordinal {
                inputs.resize(ordinal + 1, None);
            }
            inputs[ordinal] = Some(share_type);
        }
    }

    fn record_client_output(&mut self, name: &str, arguments: &[AbstractValue]) {
        let (slot_argument, width) = match name {
            "send_to_client" | "Share.send_to_client" => (arguments.get(1), 1),
            "MpcOutput.send_to_client" => (
                arguments.first(),
                arguments
                    .get(1)
                    .and_then(|value| value.list_len)
                    .unwrap_or(1),
            ),
            _ => return,
        };
        let Some(client_slot) = slot_argument
            .and_then(|value| value.int)
            .and_then(|value| u64::try_from(value).ok())
        else {
            return;
        };
        let count = self.output_counts.entry(client_slot).or_default();
        *count = count.saturating_add(width);
    }

    fn visit_for(
        &mut self,
        variables: &[String],
        iterable: &AstNode,
        body: &AstNode,
        env: &mut Env,
    ) {
        let mut names = HashSet::new();
        fn declarations(node: &AstNode, names: &mut HashSet<String>) {
            if let AstNode::VariableDeclaration { name, .. } = node {
                names.insert(name.clone());
            }
            crate::optimizations::for_each_child(node, &mut |child| declarations(child, names));
        }
        declarations(body, &mut names);
        names.extend(variables.iter().cloned());
        let bindings: Vec<_> = names
            .into_iter()
            .map(|name| {
                let value = env.get(&name).copied();
                (name, value)
            })
            .collect();
        self.loops.push(LoopFrame::default());
        self.visit_for_inner(variables, iterable, body, env);
        self.finish_loop(env);
        for (name, value) in bindings {
            if let Some(value) = value {
                env.insert(name, value);
            } else {
                env.remove(&name);
            }
        }
    }

    fn visit_for_inner(
        &mut self,
        variables: &[String],
        iterable: &AstNode,
        body: &AstNode,
        env: &mut Env,
    ) {
        if let AstNode::BinaryOperation {
            op, left, right, ..
        } = iterable
        {
            if op == ".." {
                let start = self.visit(left, env).int;
                let end = self.visit(right, env).int;
                if let (Some(start), Some(end)) = (start, end) {
                    let count = end.saturating_sub(start);
                    if count >= 0
                        && usize::try_from(count).is_ok_and(|n| n <= MAX_STATIC_LOOP_ITERATIONS)
                    {
                        for value in start..end {
                            if let Some(variable) = variables.first() {
                                env.insert(variable.clone(), AbstractValue::int(value));
                            }
                            self.visit(body, env);
                            self.merge_continues(env);
                            match self.control {
                                Control::Return => return,
                                Control::Break => {
                                    self.control = Control::Next;
                                    return;
                                }
                                Control::Continue => self.control = Control::Next,
                                Control::Next => {}
                            }
                        }
                        return;
                    }
                }
            }
        }

        // Enumerate known lists; otherwise join all possible backedges.
        let iterable_value = self.visit(iterable, env);
        if let Some(Aggregate::List(values)) = iterable_value
            .aggregate
            .filter(|id| !self.uncertain_lengths.contains(id))
            .and_then(|id| self.heap.get(id))
            .cloned()
        {
            for value in values {
                if let Some(variable) = variables.first() {
                    env.insert(variable.clone(), value);
                }
                self.visit(body, env);
                self.merge_continues(env);
                match self.control {
                    Control::Return => return,
                    Control::Break => {
                        self.control = Control::Next;
                        return;
                    }
                    Control::Continue => self.control = Control::Next,
                    Control::Next => {}
                }
            }
            return;
        }
        let element = if let Some(Aggregate::List(values)) = iterable_value
            .aggregate
            .and_then(|id| self.heap.get(id))
            .cloned()
        {
            values
                .into_iter()
                .reduce(|a, b| self.join_value(a, b))
                .unwrap_or_default()
        } else {
            AbstractValue {
                aggregate: None,
                list_depth: iterable_value.list_depth.saturating_sub(1),
                list_len: None,
                opaque: iterable_value.opaque || iterable_value.aggregate.is_some(),
                ..iterable_value
            }
        };
        let setup = variables
            .iter()
            .map(|name| (name.clone(), element))
            .collect::<Vec<_>>();
        self.visit_dynamic_loop(body, env, &setup, None, iterable.location());
    }

    fn visit_while(&mut self, condition: &AstNode, body: &AstNode, env: &mut Env) {
        self.loops.push(LoopFrame::default());
        self.visit_while_inner(condition, body, env);
        self.finish_loop(env);
    }

    fn visit_while_inner(&mut self, condition: &AstNode, body: &AstNode, env: &mut Env) {
        for _ in 0..MAX_STATIC_LOOP_ITERATIONS {
            let dynamic_client_counter = dynamic_client_loop_counter(condition, env);
            match self.visit(condition, env).int {
                Some(0) => return,
                Some(_) => {
                    let returns_before = self.returns.len();
                    self.visit(body, env);
                    self.merge_continues(env);
                    let always_true = matches!(
                        condition,
                        AstNode::Literal {
                            value: Value::Bool(true),
                            ..
                        }
                    );
                    if self.needs_output_shapes
                        && self.control == Control::Next
                        && (self.returns.len() > returns_before
                            || (always_true
                                && self
                                    .loops
                                    .last()
                                    .is_some_and(|frame| !frame.breaks.is_empty())))
                    {
                        // A retry path and a return path coexist. Interpret the
                        // remaining backedges abstractly instead of retrying a
                        // runtime-random condition a million times.
                        self.visit_dynamic_loop(
                            body,
                            env,
                            &[],
                            Some(condition),
                            condition.location(),
                        );
                        self.control = if always_true {
                            Control::Return
                        } else {
                            Control::Next
                        };
                        return;
                    }
                    match self.control {
                        Control::Return => return,
                        Control::Break => {
                            self.control = Control::Next;
                            return;
                        }
                        Control::Continue => self.control = Control::Next,
                        Control::Next => {}
                    }
                }
                None => {
                    let mut setup = Vec::new();
                    // Runtime client counters represent a range of slots, not
                    // a literal first slot in the manifest.
                    if let Some((counter, first_client_slot)) = dynamic_client_counter {
                        setup.push((
                            counter,
                            AbstractValue {
                                dynamic_client_slot_start: Some(first_client_slot),
                                ..AbstractValue::default()
                            },
                        ));
                    } else if let AstNode::BinaryOperation { left, right, .. } = condition {
                        for operand in [left, right] {
                            if let AstNode::Identifier(name, _) = operand.as_ref() {
                                let mut value = env.get(name).copied().unwrap_or_default();
                                value.int = None;
                                setup.push((name.clone(), value));
                            }
                        }
                    }
                    self.visit_dynamic_loop(
                        body,
                        env,
                        &setup,
                        Some(condition),
                        condition.location(),
                    );
                    return;
                }
            }
        }
        if self.needs_output_shapes {
            self.errors.push(
                CompilerError::type_error(
                    "Cannot prove share domains across this loop",
                    condition.location(),
                )
                .with_hint("The loop exceeded the static iteration limit"),
            );
        }
    }
}

impl Planner<'_> {
    /// Join the zero-iteration path and every reachable backedge until the
    /// abstract state stabilizes. A single body visit misses delayed domain
    /// changes (for example `result = previous; previous = new_domain`).
    fn visit_dynamic_loop(
        &mut self,
        body: &AstNode,
        env: &mut Env,
        setup: &[(String, AbstractValue)],
        condition: Option<&AstNode>,
        location: SourceLocation,
    ) {
        let counts_before = self.output_counts.clone();
        let initial = self.loop_snapshot(env);
        let returns_before = self.returns.len();
        for iteration in 0..64 {
            for (name, value) in setup {
                env.insert(name.clone(), *value);
            }
            let header = self.loop_snapshot(env);
            let uncertain_before = self.uncertain_lengths.clone();
            self.control = Control::Next;
            if iteration > 0 {
                if let Some(condition) = condition {
                    self.visit(condition, env);
                }
            }
            self.visit(body, env);
            self.merge_continues(env);
            let backedge = matches!(self.control, Control::Next | Control::Continue);
            if self.output_counts != counts_before {
                self.errors.push(CompilerError::type_error(
                    "Cannot infer the client-output count of a runtime-bounded loop", location,
                ).with_hint("Use a statically bounded output loop so the client manifest describes the complete batch"));
                self.control = Control::Next;
                return;
            }
            self.merge_loop_state(env, &header.env, &header.heap);
            self.output_offsets = merge_offsets(&header.offsets, &self.output_offsets);
            self.control = Control::Next;
            if !self.needs_output_shapes
                || !backedge
                || (*env == header.env
                    && self.heap == header.heap
                    && self.uncertain_lengths == uncertain_before)
            {
                return;
            }
        }
        // Growing runtime collections need not prevent unrelated code from
        // compiling. Widen changing facts to unknown; any output that depends
        // on them will receive the normal domain/length diagnostic at its use.
        let unknown = AbstractValue {
            opaque: true,
            ..AbstractValue::default()
        };
        for (name, value) in env.iter_mut() {
            if initial.env.get(name) != Some(value) {
                *value = unknown;
            }
        }
        for (id, value) in self.heap.iter_mut().enumerate() {
            if initial.heap.get(id) != Some(value) {
                *value = Aggregate::Unknown;
                self.uncertain_lengths.insert(id);
            }
        }
        self.returns[returns_before..].fill(unknown);
    }

    fn loop_snapshot(&self, env: &Env) -> LoopSnapshot {
        LoopSnapshot {
            env: env.clone(),
            heap: self.heap.clone(),
            offsets: self.output_offsets.clone(),
        }
    }

    fn merge_snapshot(&mut self, env: &mut Env, snapshot: LoopSnapshot) {
        self.merge_loop_state(env, &snapshot.env, &snapshot.heap);
        self.output_offsets = merge_offsets(&self.output_offsets, &snapshot.offsets);
    }

    fn merge_continues(&mut self, env: &mut Env) {
        let snapshots = self
            .loops
            .last_mut()
            .map(|frame| std::mem::take(&mut frame.continues))
            .unwrap_or_default();
        if self.needs_output_shapes
            && !snapshots.is_empty()
            && matches!(self.control, Control::Return | Control::Break)
        {
            self.control = Control::Next;
        }
        for snapshot in snapshots {
            self.merge_snapshot(env, snapshot);
        }
    }

    fn finish_loop(&mut self, env: &mut Env) {
        let Some(frame) = self.loops.pop() else {
            return;
        };
        if !frame.breaks.is_empty() {
            self.control = Control::Next;
        }
        for snapshot in frame.breaks.into_iter().chain(frame.continues) {
            self.merge_snapshot(env, snapshot);
        }
    }

    fn referents(&self, id: usize) -> BTreeSet<usize> {
        self.aggregate_aliases
            .get(&id)
            .cloned()
            .unwrap_or_else(|| BTreeSet::from([id]))
    }

    fn write_heap(&mut self, id: usize, value: Aggregate) {
        let refs = self.referents(id);
        for referent in &refs {
            let next = if refs.len() == 1 {
                value.clone()
            } else {
                if different_list_lengths(&self.heap[*referent], &value) {
                    self.uncertain_lengths.insert(*referent);
                }
                self.join_aggregate(&self.heap[*referent].clone(), &value)
            };
            self.heap[*referent] = next;
        }
        // Cached joins must reflect later writes through either the merged
        // reference or one of its original aliases.
        for (proxy, sources) in self.aggregate_aliases.clone() {
            if !sources.is_disjoint(&refs) {
                let mut values = sources
                    .iter()
                    .map(|source| self.heap[*source].clone())
                    .collect::<Vec<_>>()
                    .into_iter();
                if let Some(mut joined) = values.next() {
                    for value in values {
                        if different_list_lengths(&joined, &value) {
                            self.uncertain_lengths.insert(proxy);
                        }
                        joined = self.join_aggregate(&joined, &value);
                    }
                    self.heap[proxy] = joined;
                }
            }
        }
    }

    fn list_length(&self, value: AbstractValue) -> Option<usize> {
        if let Some(id) = value.aggregate {
            if self.uncertain_lengths.contains(&id) {
                return None;
            }
            if let Some(Aggregate::List(values)) = self.heap.get(id) {
                return Some(values.len());
            }
        }
        value.list_len
    }

    fn default_value(&mut self, ty: &SymbolType, depth: usize) -> AbstractValue {
        if depth > 64 {
            return AbstractValue {
                opaque: true,
                ..AbstractValue::default()
            };
        }
        match ty.underlying_type() {
            SymbolType::List(_) => self.list(Vec::new()),
            SymbolType::Object(name) | SymbolType::TypeName(name) => {
                if let Some(fields) = self.object_types.get(name).cloned() {
                    let fields = fields
                        .into_iter()
                        .map(|f| {
                            (
                                f.name,
                                self.default_value(
                                    &SymbolType::from_ast(&f.type_annotation),
                                    depth + 1,
                                ),
                            )
                        })
                        .collect();
                    let id = self.heap.len();
                    self.heap.push(Aggregate::Object(fields));
                    AbstractValue {
                        aggregate: Some(id),
                        ..AbstractValue::default()
                    }
                } else {
                    self.typed_value(ty)
                }
            }
            _ => self.typed_value(ty),
        }
    }

    fn merge_loop_state(&mut self, env: &mut Env, original: &Env, heap_before: &[Aggregate]) {
        for (id, before) in heap_before.iter().enumerate() {
            if different_list_lengths(before, &self.heap[id]) {
                self.uncertain_lengths.insert(id);
            }
            self.heap[id] = self.join_aggregate(before, &self.heap[id].clone());
        }
        let after = env.clone();
        self.merge_env(env, original, &after);
    }

    fn list(&mut self, values: Vec<AbstractValue>) -> AbstractValue {
        let len = values.len();
        let list_depth = 1 + values.iter().map(|v| v.list_depth).max().unwrap_or(0);
        let id = self.heap.len();
        self.heap.push(Aggregate::List(values));
        AbstractValue {
            aggregate: Some(id),
            list_depth,
            ..AbstractValue::list(len)
        }
    }

    fn apply_type(&mut self, mut value: AbstractValue, ty: &SymbolType) -> AbstractValue {
        match ty.underlying_type() {
            SymbolType::List(inner) => {
                if let Some(id) = value.aggregate {
                    if let Some(Aggregate::List(elements)) = self.heap.get(id).cloned() {
                        let elements = elements
                            .into_iter()
                            .map(|v| self.apply_type(v, inner))
                            .collect();
                        self.heap[id] = Aggregate::List(elements);
                    }
                }
                let typed = self.typed_value(inner);
                value.list_depth = typed.list_depth + 1;
                if !value.opaque {
                    value.share = value.share.or(typed.share);
                }
                value.opaque |= typed.opaque;
            }
            _ => {
                let typed = self.typed_value(ty);
                if !value.opaque {
                    value.share = value.share.or(typed.share);
                }
                value.opaque |= typed.opaque;
                value.float |= typed.float;
            }
        }
        value
    }

    fn typed_value(&self, ty: &SymbolType) -> AbstractValue {
        match ty.underlying_type() {
            SymbolType::List(inner) => {
                let mut value = self.typed_value(inner);
                value.list_depth += 1;
                value
            }
            _ => AbstractValue {
                opaque: matches!(ty.underlying_type(), SymbolType::Object(n) | SymbolType::TypeName(n) if n == "Share"),
                float: !ty.is_secret()
                    && matches!(ty, SymbolType::Float | SymbolType::Fixed { .. }),
                share: crate::codegen::share_type_for_secret_scalar_symbol_type(ty),
                ..AbstractValue::default()
            },
        }
    }

    fn join_value(&mut self, a: AbstractValue, b: AbstractValue) -> AbstractValue {
        if a == b {
            return a;
        }
        let aggregate = match (a.aggregate, b.aggregate) {
            (Some(a), Some(b)) if a == b => Some(a),
            (Some(a), Some(b)) => {
                let value = self.join_aggregate(&self.heap[a].clone(), &self.heap[b].clone());
                let id = self.heap.len();
                if self.uncertain_lengths.contains(&a)
                    || self.uncertain_lengths.contains(&b)
                    || different_list_lengths(&self.heap[a], &self.heap[b])
                {
                    self.uncertain_lengths.insert(id);
                }
                self.heap.push(value);
                let mut refs = self.referents(a);
                refs.extend(self.referents(b));
                self.aggregate_aliases.insert(id, refs);
                Some(id)
            }
            _ => None,
        };
        AbstractValue {
            list_depth: a.list_depth.max(b.list_depth),
            opaque: a.opaque || b.opaque || a.share.is_some() || b.share.is_some(),
            float: a.float || b.float,
            share: if a.share == b.share { a.share } else { None },
            aggregate,
            int: if a.int == b.int { a.int } else { None },
            list_len: if a.list_len == b.list_len {
                a.list_len
            } else {
                None
            },
            runtime_client_count: a.runtime_client_count && b.runtime_client_count,
            dynamic_client_slot_start: if a.dynamic_client_slot_start == b.dynamic_client_slot_start
            {
                a.dynamic_client_slot_start
            } else {
                None
            },
        }
    }

    fn join_aggregate(&mut self, a: &Aggregate, b: &Aggregate) -> Aggregate {
        match (a, b) {
            (Aggregate::Closure(a), Aggregate::Closure(b)) if a == b => {
                Aggregate::Closure(a.clone())
            }
            (Aggregate::List(a), Aggregate::List(b)) => Aggregate::List(
                (0..a.len().max(b.len()))
                    .map(|i| {
                        self.join_value(
                            a.get(i).copied().unwrap_or_default(),
                            b.get(i).copied().unwrap_or_default(),
                        )
                    })
                    .collect(),
            ),
            (Aggregate::Object(a), Aggregate::Object(b)) => Aggregate::Object(
                a.keys()
                    .chain(b.keys())
                    .map(|key| {
                        (
                            key.clone(),
                            self.join_value(
                                a.get(key).copied().unwrap_or_default(),
                                b.get(key).copied().unwrap_or_default(),
                            ),
                        )
                    })
                    .collect(),
            ),
            _ => Aggregate::Unknown,
        }
    }

    fn merge_env(&mut self, target: &mut Env, a: &Env, b: &Env) {
        target.clear();
        for key in a.keys().chain(b.keys()) {
            target.insert(
                key.clone(),
                self.join_value(
                    a.get(key).copied().unwrap_or_default(),
                    b.get(key).copied().unwrap_or_default(),
                ),
            );
        }
    }

    fn repeat_list(&mut self, list: AbstractValue, count: AbstractValue) -> Option<AbstractValue> {
        let Aggregate::List(values) = self.heap.get(list.aggregate?)?.clone() else {
            return None;
        };
        let count = usize::try_from(count.int?.max(0)).ok()?;
        if values.len().checked_mul(count)? > MAX_STATIC_LOOP_ITERATIONS {
            return None;
        }
        Some(self.list(values.repeat(count)))
    }

    fn assign_aggregate(&mut self, target: &AstNode, value: AbstractValue, env: &mut Env) {
        match target {
            AstNode::FieldAccess {
                object, field_name, ..
            } => {
                let object = self.visit(object, env);
                if let Some(Aggregate::Object(fields)) =
                    object.aggregate.and_then(|id| self.heap.get_mut(id))
                {
                    fields.insert(field_name.clone(), value);
                    let id = object.aggregate.unwrap();
                    self.write_heap(id, self.heap[id].clone());
                }
            }
            AstNode::IndexAccess { base, index, .. } => {
                let base = self.visit(base, env);
                let index = self
                    .visit(index, env)
                    .int
                    .and_then(|i| usize::try_from(i).ok());
                if let Some(Aggregate::List(values)) =
                    base.aggregate.and_then(|id| self.heap.get(id)).cloned()
                {
                    let values = values
                        .into_iter()
                        .enumerate()
                        .map(|(i, old)| {
                            if index == Some(i) {
                                value
                            } else if index.is_none() {
                                self.join_value(old, value)
                            } else {
                                old
                            }
                        })
                        .collect();
                    self.write_heap(base.aggregate.unwrap(), Aggregate::List(values));
                }
            }
            _ => {
                self.visit(target, env);
            }
        }
    }

    fn builtin_value(
        &self,
        name: &str,
        args: &[AbstractValue],
        ty: Option<&SymbolType>,
    ) -> AbstractValue {
        let qualified;
        let name = if !name.contains('.') && args.first().is_some_and(|v| v.share.is_some()) {
            qualified = format!("Share.{name}");
            qualified.as_str()
        } else {
            name
        };
        let width = |index: usize| {
            args.get(index)
                .and_then(|a| a.int)
                .and_then(|n| usize::try_from(n).ok())
        };
        let first = args.first().and_then(|v| v.share);
        let share = match name {
            "Share.from_field" | "Share.random_field" | "Share.add_field" | "Share.mul_field"
            | "add_field" | "mul_field" => Some(ShareType::SecretField),
            "Share.from_clear_int" | "Share.random_int" | "Share.retag" => {
                width(if name == "Share.random_int" { 0 } else { 1 })
                    .and_then(|n| ShareType::try_secret_int(n).ok())
            }
            "Share.from_clear_uint" => width(1).and_then(|n| ShareType::try_secret_uint(n).ok()),
            "Share.from_clear_fixed" => width(1)
                .zip(width(2))
                .and_then(|(k, f)| ShareType::try_secret_fixed_point_from_bits(k, f).ok()),
            "Share.from_clear" => Some(ShareType::default_secret_int()),
            "Share.neg" => first,
            "Share.add_constant" | "Share.add_scalar" | "Share.mul_scalar" => {
                promoted_scalar_domain(first, args.get(1).is_some_and(|v| v.float))
            }
            "Share.add" | "Share.sub" | "Share.mul" => {
                if args.iter().any(|a| a.opaque && a.share.is_none()) {
                    None
                } else {
                    arithmetic_domain("+", first, args.get(1).and_then(|v| v.share))
                }
            }
            "ClientStore.take_share_bool" | "ClientStore.sum_shares_bool" => {
                Some(ShareType::boolean())
            }
            "ClientStore.take_share_fixed" | "ClientStore.sum_shares_fixed" => {
                Some(ShareType::default_secret_fixed_point())
            }
            "ClientStore.take_share" | "ClientStore.sum_shares" | "Share.random" => {
                Some(ShareType::default_secret_int())
            }
            _ => None,
        };
        let typed = ty.map(|ty| self.typed_value(ty)).unwrap_or_default();
        let share = if is_client_input_call(name) || name == "Share.random" {
            typed.share.or(share)
        } else {
            share.or(typed.share.filter(|_| !args.iter().any(|a| a.opaque)))
        };
        AbstractValue { share, ..typed }
    }

    fn record_output_domains(
        &mut self,
        name: &str,
        args: &[AbstractValue],
        location: &SourceLocation,
    ) {
        let (slot, value) = if name == "MpcOutput.send_to_client" {
            (args.first(), args.get(1))
        } else {
            (args.get(1), args.first())
        };
        let Some(slot) = slot.and_then(|a| a.int).and_then(|n| u64::try_from(n).ok()) else {
            return;
        };
        let Some(value) = value else {
            return;
        };
        if value.list_depth > 0
            && (value.aggregate.is_none()
                || value
                    .aggregate
                    .is_some_and(|id| self.uncertain_lengths.contains(&id)))
        {
            self.errors.push(CompilerError::type_error("Cannot infer the number of shares in this client output", location.clone())
                .with_hint("Build the output list with a statically known length, or send known individual shares"));
            return;
        }
        let types = if let Some(Aggregate::List(values)) =
            value.aggregate.and_then(|id| self.heap.get(id))
        {
            values
                .iter()
                .map(|v| if v.list_depth == 0 { v.share } else { None })
                .collect::<Vec<_>>()
        } else {
            vec![value.share]
        };
        self.output_locations.insert(slot, location.clone());
        let offsets = self
            .output_offsets
            .entry(slot)
            .or_insert_with(|| BTreeSet::from([0]));
        let outputs = self.outputs.entry(slot).or_default();
        for start in offsets.iter().copied() {
            for (index, ty) in types.iter().enumerate() {
                let index = start + index;
                if index >= outputs.len() {
                    outputs.resize(index + 1, None);
                    outputs[index] = *ty;
                } else if outputs[index] != *ty {
                    outputs[index] = None;
                }
            }
        }
        *offsets = offsets.iter().map(|offset| offset + types.len()).collect();
    }
}

fn different_list_lengths(a: &Aggregate, b: &Aggregate) -> bool {
    matches!((a, b), (Aggregate::List(a), Aggregate::List(b)) if a.len() != b.len())
}

fn promoted_scalar_domain(share: Option<ShareType>, float: bool) -> Option<ShareType> {
    if !float {
        return share;
    }
    match share {
        Some(ShareType::SecretField) => None,
        Some(ty @ ShareType::SecretFixedPoint { .. }) => Some(ty),
        Some(_) => Some(ShareType::default_secret_fixed_point()),
        None => None,
    }
}

fn arithmetic_domain(op: &str, a: Option<ShareType>, b: Option<ShareType>) -> Option<ShareType> {
    if matches!(op, "==" | "!=" | "<" | "<=" | ">" | ">=") && (a.is_some() || b.is_some()) {
        return Some(ShareType::boolean());
    }
    match (a, b) {
        (Some(a), Some(b)) if a == b => Some(a),
        (Some(a), None) | (None, Some(a)) => Some(a),
        // Runtime share/share arithmetic requires matching domains and widths.
        _ => None,
    }
}

fn merge_offsets(
    a: &HashMap<u64, BTreeSet<usize>>,
    b: &HashMap<u64, BTreeSet<usize>>,
) -> HashMap<u64, BTreeSet<usize>> {
    a.keys()
        .chain(b.keys())
        .map(|slot| {
            let zero = BTreeSet::from([0]);
            (
                *slot,
                a.get(slot)
                    .unwrap_or(&zero)
                    .union(b.get(slot).unwrap_or(&zero))
                    .copied()
                    .collect(),
            )
        })
        .collect()
}

fn merge_output_types(a: &InferredOutputs, b: &InferredOutputs) -> InferredOutputs {
    a.keys()
        .chain(b.keys())
        .map(|slot| {
            let a = a.get(slot).map(Vec::as_slice).unwrap_or_default();
            let b = b.get(slot).map(Vec::as_slice).unwrap_or_default();
            let types = (0..a.len().max(b.len()))
                .map(|i| match (a.get(i), b.get(i)) {
                    (Some(a), Some(b)) if a == b => *a,
                    (Some(a), None) | (None, Some(a)) => *a,
                    _ => None,
                })
                .collect();
            (*slot, types)
        })
        .collect()
}

fn dynamic_client_loop_counter(condition: &AstNode, env: &Env) -> Option<(String, u64)> {
    let AstNode::BinaryOperation {
        op, left, right, ..
    } = condition
    else {
        return None;
    };
    if op != "<" {
        return None;
    }
    let AstNode::Identifier(counter, _) = left.as_ref() else {
        return None;
    };
    let AstNode::Identifier(client_count, _) = right.as_ref() else {
        return None;
    };
    if !env
        .get(client_count)
        .is_some_and(|value| value.runtime_client_count)
    {
        return None;
    }
    let first_client_slot = env
        .get(counter)
        .and_then(|value| value.int)
        .and_then(|value| u64::try_from(value).ok())?;
    Some((counter.clone(), first_client_slot))
}

fn is_list_return_type(node: &AstNode) -> bool {
    match node {
        AstNode::ListType(_) => true,
        AstNode::SecretType(inner) => is_list_return_type(inner),
        _ => false,
    }
}

fn is_client_input_call(name: &str) -> bool {
    matches!(
        name,
        "ClientStore.take_share"
            | "ClientStore.take_share_fixed"
            | "ClientStore.take_share_bool"
            | "ClientStore.sum_shares"
            | "ClientStore.sum_shares_bool"
            | "ClientStore.sum_shares_fixed"
    )
}

fn is_client_input_sum_call(name: &str) -> bool {
    matches!(
        name,
        "ClientStore.sum_shares" | "ClientStore.sum_shares_bool" | "ClientStore.sum_shares_fixed"
    )
}

fn is_client_output_call(name: &str) -> bool {
    matches!(
        name,
        "send_to_client" | "Share.send_to_client" | "MpcOutput.send_to_client"
    )
}

fn eval_binary(op: &str, left: Option<i128>, right: Option<i128>) -> Option<i128> {
    let (left, right) = (left?, right?);
    match op {
        "+" => left.checked_add(right),
        "-" => left.checked_sub(right),
        "*" => left.checked_mul(right),
        "/" => left.checked_div(right),
        "%" => left.checked_rem(right),
        "<<" => u32::try_from(right).ok().and_then(|n| left.checked_shl(n)),
        ">>" => u32::try_from(right).ok().and_then(|n| left.checked_shr(n)),
        "&" => Some(left & right),
        "|" => Some(left | right),
        "^" => Some(left ^ right),
        "==" => Some(i128::from(left == right)),
        "!=" => Some(i128::from(left != right)),
        "<" => Some(i128::from(left < right)),
        "<=" => Some(i128::from(left <= right)),
        ">" => Some(i128::from(left > right)),
        ">=" => Some(i128::from(left >= right)),
        "and" => Some(i128::from(left != 0 && right != 0)),
        "or" => Some(i128::from(left != 0 || right != 0)),
        _ => None,
    }
}

fn merge_branch_output_counts(
    target: &mut HashMap<u64, usize>,
    base: &HashMap<u64, usize>,
    left: &HashMap<u64, usize>,
    right: &HashMap<u64, usize>,
) {
    let slots = base
        .keys()
        .chain(left.keys())
        .chain(right.keys())
        .copied()
        .collect::<HashSet<_>>();
    target.clear();
    for slot in slots {
        let base_count = base.get(&slot).copied().unwrap_or(0);
        let left_delta = left
            .get(&slot)
            .copied()
            .unwrap_or(base_count)
            .saturating_sub(base_count);
        let right_delta = right
            .get(&slot)
            .copied()
            .unwrap_or(base_count)
            .saturating_sub(base_count);
        let count = base_count.saturating_add(left_delta.max(right_delta));
        if count > 0 {
            target.insert(slot, count);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::compiler::{compile, CompilerOptions};
    use stoffel_vm_types::core_types::ShareType;

    #[test]
    fn follows_literal_integer_arguments_through_nested_client_input_helpers() {
        let source = r#"
def take_byte(client: int64, byte_index: int64) -> list[secret bool]:
  var bits: list[secret bool] = []
  for bit_index in 0..8:
    bits.append(ClientStore.take_share_bool(client, byte_index * 8 + bit_index))
  return bits

def take_block(client: int64, block_index: int64) -> list[list[secret bool]]:
  var block: list[list[secret bool]] = []
  for byte_index in 0..2:
    block.append(take_byte(client, block_index * 2 + byte_index))
  return block

def main() -> int64:
  var left = take_block(0, 0)
  var right = take_block(1, 0)
  return 0
"#;
        let program = compile(source, "client_helpers.stfl", &CompilerOptions::default())
            .expect("program should compile");
        assert_eq!(program.client_io_manifest.clients.len(), 2);
        for schema in &program.client_io_manifest.clients {
            assert_eq!(schema.inputs, vec![ShareType::boolean(); 16]);
        }
    }

    #[test]
    fn executes_clear_bounded_while_loops_in_client_input_helpers() {
        let source = r#"
def take_values(client: int64, width: int64) -> list[secret fix64]:
  var values: list[secret fix64] = []
  var i: int64 = 0
  while i < width:
    values.append(ClientStore.take_share_fixed(client, i))
    i += 1
  return values

def main() -> int64:
  var values = take_values(2, 4)
  return 0
"#;
        let program = compile(source, "client_while.stfl", &CompilerOptions::default())
            .expect("program should compile");
        let schema = &program.client_io_manifest.clients[0];
        assert_eq!(schema.client_slot, 2);
        assert_eq!(
            schema.inputs,
            vec![ShareType::default_secret_fixed_point(); 4]
        );
    }

    #[test]
    fn plain_take_share_does_not_erase_an_explicit_boolean_annotation() {
        let source = r#"
def main() -> int64:
  var bits: list[secret bool] = []
  var i: int64 = 0
  while i < 4:
    var bit: secret bool = ClientStore.take_share(0, i)
    bits.append(bit)
    i += 1
  return 0
"#;
        let program = compile(
            source,
            "annotated_bool_inputs.stfl",
            &CompilerOptions::default(),
        )
        .expect("program should compile");
        let schema = &program.client_io_manifest.clients[0];
        assert_eq!(schema.client_slot, 0);
        assert_eq!(schema.inputs, vec![ShareType::boolean(); 4]);
    }

    #[test]
    fn dynamic_client_loop_records_a_runtime_input_template_without_inventing_a_slot() {
        let source = r#"
def main() -> int64:
  var clients = ClientStore.get_number_clients()
  var client = 1
  while client < clients:
    discard ClientStore.take_share_fixed(client, 0)
    client += 1
  discard ClientStore.take_share_fixed(0, 0)
  return 0
"#;
        let program = compile(source, "dynamic_clients.stfl", &CompilerOptions::default())
            .expect("program should compile");
        assert_eq!(program.client_io_manifest.clients.len(), 1);
        assert_eq!(program.client_io_manifest.clients[0].client_slot, 0);
        assert_eq!(program.client_io_manifest.dynamic_client_inputs.len(), 1);
        assert_eq!(
            program.client_io_manifest.dynamic_client_inputs[0].first_client_slot,
            1
        );
        assert_eq!(
            program.client_io_manifest.dynamic_client_inputs[0].inputs,
            vec![ShareType::default_secret_fixed_point()]
        );
    }

    #[test]
    fn dynamic_client_template_collects_each_statically_bounded_input_ordinal() {
        let source = r#"
def main() -> int64:
  var clients = ClientStore.get_number_clients()
  var ordinal = 0
  while ordinal < 4:
    var client = 0
    while client < clients:
      discard ClientStore.take_share_fixed(client, ordinal)
      client += 1
    ordinal += 1
  return 0
"#;
        let program = compile(
            source,
            "dynamic_client_inputs.stfl",
            &CompilerOptions::default(),
        )
        .expect("program should compile");
        assert!(program.client_io_manifest.clients.is_empty());
        assert_eq!(program.client_io_manifest.dynamic_client_inputs.len(), 1);
        let schema = &program.client_io_manifest.dynamic_client_inputs[0];
        assert_eq!(schema.first_client_slot, 0);
        assert_eq!(
            schema.inputs,
            vec![ShareType::default_secret_fixed_point(); 4]
        );
    }

    #[test]
    fn bounded_output_loop_records_every_output_share() {
        let source = r#"
def main() -> None:
  var value: secret int64 = Share.from_clear_int(7, 64)
  var i: int64 = 0
  while i < 4:
    value.send_to_client(0)
    i += 1
"#;
        let program = compile(
            source,
            "looped_client_outputs.stfl",
            &CompilerOptions::default(),
        )
        .expect("program should compile");
        let schema = &program.client_io_manifest.clients[0];
        assert_eq!(schema.client_slot, 0);
        assert_eq!(schema.outputs, vec![ShareType::default_secret_int(); 4]);
    }

    #[test]
    fn output_loop_uses_length_of_append_built_list() {
        let source = r#"
def main() -> None:
  var values: list[secret int64] = []
  var i: int64 = 0
  while i < 8:
    values.append(ClientStore.take_share(0, i))
    i += 1
  for j in 0..values.len():
    values[j].send_to_client(0)
"#;
        let program = compile(source, "list_output_loop.stfl", &CompilerOptions::default())
            .expect("program should compile");
        let schema = &program.client_io_manifest.clients[0];
        assert_eq!(schema.inputs.len(), 8);
        assert_eq!(schema.outputs.len(), 8);
    }

    #[test]
    fn output_loop_uses_length_returned_by_list_building_helper() {
        let source = r#"
def histogram(bounds: list[int64]) -> list[Share]:
  var out: list[Share] = []
  var b = 0
  while b < (len(bounds) - 1):
    out.append(Share.from_clear_int(b, 64))
    b += 1
  return out

def main() -> None:
  var h = histogram([0, 10, 20, 30])
  var client = 0
  while client < 5:
    var b = 0
    while b < len(h):
      h[b].send_to_client(client)
      b += 1
    client += 1
"#;
        let program = compile(
            source,
            "helper_list_output_loop.stfl",
            &CompilerOptions::default(),
        )
        .expect("program should compile");
        assert_eq!(program.client_io_manifest.clients.len(), 5);
        for (client_slot, schema) in program.client_io_manifest.clients.iter().enumerate() {
            assert_eq!(schema.client_slot, client_slot as u64);
            assert_eq!(schema.outputs.len(), 3);
        }
    }
}
