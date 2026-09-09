//! Interprocedural inference for client inputs whose slot or ordinal is passed
//! through a user-defined helper.
//!
//! Code generation records direct `ClientStore.take_share*` calls while each
//! function is compiled. That is enough for literal arguments and locally
//! bounded loops, but a helper such as `take_byte(client, byte_index)` is
//! compiled before any particular call-site values are known. This small
//! concrete interpreter follows only the client-input-relevant part of the
//! call graph from the program entry, propagates clear integer arguments, and
//! enumerates statically bounded loops. Its findings are merged with (rather
//! than replacing) codegen's manifest.

use std::collections::{HashMap, HashSet};

use crate::ast::{AstNode, Parameter, Pragma, Value};
use crate::symbol_table::SymbolType;
use stoffel_vm_types::compiled_binary::{
    ClientIoManifest, ClientIoSchema, DynamicClientInputSchema,
};
use stoffel_vm_types::core_types::ShareType;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct AbstractValue {
    int: Option<i128>,
    list_len: Option<usize>,
    runtime_client_count: bool,
    dynamic_client_slot_start: Option<u64>,
}

impl AbstractValue {
    fn int(value: i128) -> Self {
        Self {
            int: Some(value),
            list_len: None,
            runtime_client_count: false,
            dynamic_client_slot_start: None,
        }
    }

    fn list(len: usize) -> Self {
        Self {
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

struct FunctionInfo<'a> {
    parameters: &'a [Parameter],
    body: &'a AstNode,
    is_entry: bool,
    returns_list: bool,
}

struct Planner<'a> {
    functions: HashMap<String, FunctionInfo<'a>>,
    relevant: HashSet<String>,
    inputs: InferredInputs,
    dynamic_inputs: InferredDynamicInputs,
    output_counts: InferredOutputCounts,
    call_stack: Vec<String>,
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
        .filter_map(|(name, info)| (name == "main" || info.is_entry).then_some(name.clone()))
        .collect::<Vec<_>>();

    let mut planner = Planner {
        functions,
        relevant,
        inputs: HashMap::new(),
        dynamic_inputs: HashMap::new(),
        output_counts: HashMap::new(),
        call_stack: Vec::new(),
    };

    // Top-level executable statements are an entry form too. Function
    // definitions are scope declarations and are skipped by `visit`.
    planner.visit(program, &mut Env::new());
    for entry in entries {
        planner.visit_user_call(&entry, &[], &Env::new());
    }
    (
        planner.inputs,
        planner.dynamic_inputs,
        planner.output_counts,
    )
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
                },
            );
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
    if let AstNode::FunctionCall { function, .. }
    | AstNode::CommandCall {
        command: function, ..
    } = node
    {
        if let AstNode::Identifier(name, _) = function.as_ref() {
            if is_client_input_call(name) || is_client_output_call(name) {
                *reads_client = true;
            } else {
                calls.insert(name.clone());
            }
        }
    }
    crate::optimizations::for_each_child(node, &mut |child| {
        collect_calls(child, calls, reads_client)
    });
}

impl Planner<'_> {
    fn visit(&mut self, node: &AstNode, env: &mut Env) -> AbstractValue {
        match node {
            AstNode::Literal { value, .. } => match value {
                Value::Int { value, .. } => i128::try_from(*value)
                    .map(AbstractValue::int)
                    .unwrap_or_default(),
                _ => AbstractValue::default(),
            },
            AstNode::Identifier(name, _) => env.get(name).copied().unwrap_or_default(),
            AstNode::VariableDeclaration { name, value, .. } => {
                let value = value
                    .as_deref()
                    .map(|value| self.visit(value, env))
                    .unwrap_or_default();
                env.insert(name.clone(), value);
                value
            }
            AstNode::Assignment { target, value, .. } => {
                let value = self.visit(value, env);
                if let AstNode::Identifier(name, _) = target.as_ref() {
                    env.insert(name.clone(), value);
                } else {
                    self.visit(target, env);
                }
                value
            }
            AstNode::BinaryOperation {
                op, left, right, ..
            } => {
                let left = self.visit(left, env);
                let right = self.visit(right, env);
                AbstractValue {
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
                    int,
                    list_len: None,
                    ..AbstractValue::default()
                }
            }
            AstNode::Block(nodes) => {
                let mut value = AbstractValue::default();
                for node in nodes {
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
                ..
            } => self.visit_call(function, arguments, resolved_return_type.as_ref(), env),
            AstNode::CommandCall {
                command: function,
                arguments,
                ..
            } => self.visit_call(function, arguments, None, env),
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
                self.visit(condition, env);
                let original = env.clone();
                let outputs_before = self.output_counts.clone();
                let mut then_env = original.clone();
                let then_value = self.visit(then_branch, &mut then_env);
                let then_outputs = self.output_counts.clone();
                self.output_counts.clone_from(&outputs_before);
                let mut else_env = original.clone();
                let else_value = else_branch
                    .as_deref()
                    .map(|branch| self.visit(branch, &mut else_env))
                    .unwrap_or_default();
                let else_outputs = self.output_counts.clone();
                merge_branch_output_counts(
                    &mut self.output_counts,
                    &outputs_before,
                    &then_outputs,
                    &else_outputs,
                );
                merge_branch_env(env, &then_env, &else_env);
                if then_value == else_value {
                    then_value
                } else {
                    AbstractValue::default()
                }
            }
            AstNode::ListLiteral { elements, .. }
            | AstNode::TupleLiteral(elements)
            | AstNode::SetLiteral(elements) => {
                for element in elements {
                    self.visit(element, env);
                }
                AbstractValue::list(elements.len())
            }
            AstNode::DictLiteral { pairs, .. } => {
                for (key, value) in pairs {
                    self.visit(key, env);
                    self.visit(value, env);
                }
                AbstractValue::default()
            }
            AstNode::Return { value, .. } | AstNode::Yield(value) => value
                .as_deref()
                .map(|value| self.visit(value, env))
                .unwrap_or_default(),
            AstNode::DiscardStatement { expression, .. } => self.visit(expression, env),
            AstNode::IndexAccess { base, index, .. } => {
                self.visit(base, env);
                self.visit(index, env);
                AbstractValue::default()
            }
            AstNode::FieldAccess { object, .. } => {
                self.visit(object, env);
                AbstractValue::default()
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
            AstNode::Break
            | AstNode::Continue
            | AstNode::TypeAlias { .. }
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
    ) -> AbstractValue {
        let argument_values = arguments
            .iter()
            .map(|argument| self.visit(argument, env))
            .collect::<Vec<_>>();
        let AstNode::Identifier(name, _) = function else {
            self.visit(function, env);
            return AbstractValue::default();
        };

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
        } else if matches!(name.as_str(), "len" | "array_length") {
            return AbstractValue {
                int: argument_values
                    .first()
                    .and_then(|value| value.list_len)
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
            || self
                .functions
                .get(name)
                .is_some_and(|info| info.returns_list)
        {
            return self.visit_user_call(name, &argument_values, env);
        }
        AbstractValue::default()
    }

    fn visit_user_call(
        &mut self,
        name: &str,
        arguments: &[AbstractValue],
        _caller_env: &Env,
    ) -> AbstractValue {
        if self.call_stack.iter().any(|active| active == name) {
            return AbstractValue::default();
        }
        let Some(info) = self.functions.get(name) else {
            return AbstractValue::default();
        };
        let parameters = info.parameters;
        let body = info.body;
        let mut env = Env::new();
        for (parameter, value) in parameters.iter().zip(arguments.iter().copied()) {
            env.insert(parameter.name.clone(), value);
        }
        self.call_stack.push(name.to_string());
        let value = self.visit(body, &mut env);
        self.call_stack.pop();
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
                        }
                        return;
                    }
                }
            }
        }

        // Conservatively inspect one iteration when the range/list is not
        // statically enumerable. Direct codegen inference remains responsible
        // for any locally known loop bounds in this case.
        self.visit(iterable, env);
        for variable in variables {
            env.insert(variable.clone(), AbstractValue::default());
        }
        self.visit(body, env);
    }

    fn visit_while(&mut self, condition: &AstNode, body: &AstNode, env: &mut Env) {
        for _ in 0..MAX_STATIC_LOOP_ITERATIONS {
            let dynamic_client_counter = dynamic_client_loop_counter(condition, env);
            match self.visit(condition, env).int {
                Some(0) => return,
                Some(_) => {
                    self.visit(body, env);
                }
                None => {
                    // The condition is dynamic. One conservative body visit can
                    // still resolve literal client slots and ordinals. A loop
                    // counter in the condition is not a literal, though: its
                    // current value represents an unknown runtime range and
                    // must not invent a client schema for the first iteration.
                    if let Some((counter, first_client_slot)) = dynamic_client_counter {
                        env.insert(
                            counter,
                            AbstractValue {
                                dynamic_client_slot_start: Some(first_client_slot),
                                ..AbstractValue::default()
                            },
                        );
                    } else if let AstNode::BinaryOperation { left, right, .. } = condition {
                        if let AstNode::Identifier(name, _) = left.as_ref() {
                            env.insert(name.clone(), AbstractValue::default());
                        }
                        if let AstNode::Identifier(name, _) = right.as_ref() {
                            env.insert(name.clone(), AbstractValue::default());
                        }
                    }
                    self.visit(body, env);
                    return;
                }
            }
        }
    }
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

fn merge_branch_env(target: &mut Env, left: &Env, right: &Env) {
    let keys = left
        .keys()
        .chain(right.keys())
        .cloned()
        .collect::<HashSet<_>>();
    target.clear();
    for key in keys {
        if let (Some(left), Some(right)) = (left.get(&key), right.get(&key)) {
            if left == right {
                target.insert(key, *left);
            }
        }
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
