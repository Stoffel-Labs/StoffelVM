//! Forward must-analysis of initialization, before any AST optimization.
//!
//! Object identities preserve aliases. Joins keep every possible referent and
//! only retain facts true on both paths; only a unique referent admits a strong
//! field update. Abrupt exits never contribute to a following statement.
use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::ast::{AstNode, FieldDefinition, Value};
use crate::errors::CompilerError;
use crate::symbol_table::SymbolType;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Fact {
    Missing,
    Ready,
    Objects(BTreeSet<usize>),
}

impl Fact {
    fn join(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Missing, _) | (_, Self::Missing) => Self::Missing,
            (Self::Ready, Self::Ready) => Self::Ready,
            (Self::Objects(a), Self::Objects(b)) => Self::Objects(a.union(b).copied().collect()),
            // Ready denotes a fully initialized value with no local identity.
            (Self::Objects(ids), Self::Ready) | (Self::Ready, Self::Objects(ids)) => {
                Self::Objects(ids.iter().copied().chain([usize::MAX]).collect())
            }
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct State {
    vars: BTreeMap<String, Fact>,
    heap: BTreeMap<usize, BTreeMap<String, Fact>>,
}

impl State {
    fn join(&self, other: &Self) -> Self {
        let mut out = self.clone();
        for name in self.vars.keys().chain(other.vars.keys()) {
            out.vars.insert(
                name.clone(),
                self.vars
                    .get(name)
                    .unwrap_or(&Fact::Missing)
                    .join(other.vars.get(name).unwrap_or(&Fact::Missing)),
            );
        }
        for (id, fields) in &other.heap {
            let dest = out.heap.entry(*id).or_insert_with(|| fields.clone());
            for (field, fact) in fields {
                dest.entry(field.clone())
                    .and_modify(|old| *old = old.join(fact))
                    .or_insert_with(|| fact.clone());
            }
        }
        out
    }

    fn canonical(&self) -> Self {
        fn fact(value: &Fact, ids: &mut BTreeMap<usize, usize>, queue: &mut Vec<usize>) -> Fact {
            if let Fact::Objects(refs) = value {
                Fact::Objects(
                    refs.iter()
                        .map(|id| {
                            if let Some(mapped) = ids.get(id) {
                                *mapped
                            } else {
                                let mapped = ids.len();
                                ids.insert(*id, mapped);
                                queue.push(*id);
                                mapped
                            }
                        })
                        .collect(),
                )
            } else {
                value.clone()
            }
        }
        let mut ids = BTreeMap::new();
        let mut queue = Vec::new();
        let vars = self
            .vars
            .iter()
            .map(|(name, value)| (name.clone(), fact(value, &mut ids, &mut queue)))
            .collect();
        let mut heap = BTreeMap::new();
        let mut cursor = 0;
        while cursor < queue.len() {
            let id = queue[cursor];
            cursor += 1;
            if let Some(fields) = self.heap.get(&id) {
                let fields = fields
                    .iter()
                    .map(|(name, value)| (name.clone(), fact(value, &mut ids, &mut queue)))
                    .collect();
                heap.insert(ids[&id], fields);
            }
        }
        Self { vars, heap }
    }

    fn missing(&self, fact: &Fact, path: &str, seen: &mut BTreeSet<usize>) -> Option<String> {
        match fact {
            Fact::Missing => Some(path.to_owned()),
            Fact::Ready => None,
            Fact::Objects(ids) => {
                for id in ids {
                    if !seen.insert(*id) {
                        continue;
                    }
                    if let Some(fields) = self.heap.get(id) {
                        for (name, value) in fields {
                            if let Some(path) = self.missing(value, &format!("{path}.{name}"), seen)
                            {
                                return Some(path);
                            }
                        }
                    }
                }
                None
            }
        }
    }
}

#[derive(Default)]
struct Flow {
    next: Option<State>,
    breaks: Vec<State>,
    continues: Vec<State>,
    returns: Vec<State>,
}

struct Checker<'a> {
    objects: HashMap<String, Vec<FieldDefinition>>,
    aliases: HashMap<String, SymbolType>,
    functions: Vec<&'a AstNode>,
    next_id: usize,
    errors: Vec<CompilerError>,
    calls: Vec<String>,
}

pub(crate) fn check(node: &AstNode) -> Vec<CompilerError> {
    let mut checker = Checker {
        objects: HashMap::new(),
        aliases: HashMap::new(),
        functions: Vec::new(),
        next_id: 0,
        errors: Vec::new(),
        calls: Vec::new(),
    };
    checker.collect(node);
    let mut top = State::default();
    declare_locals(node, &mut top);
    checker.statement(node, top);
    for function in checker.functions.clone() {
        if let AstNode::FunctionDefinition {
            parameters, body, ..
        } = function
        {
            let mut state = State::default();
            declare_locals(body, &mut state);
            for parameter in parameters {
                state.vars.insert(parameter.name.clone(), Fact::Ready);
                if let Some(default) = &parameter.default_value {
                    let fact = checker.expression(default, &mut state);
                    checker.require(&fact, default, &state);
                }
            }
            checker.statement(body, state);
        }
    }
    checker.errors.sort_by_key(|e| {
        (
            e.location.file.clone(),
            e.location.line,
            e.location.column,
            e.message.clone(),
        )
    });
    checker
        .errors
        .dedup_by(|a, b| a.location == b.location && a.message == b.message);
    checker.errors
}

impl<'a> Checker<'a> {
    fn collect(&mut self, node: &'a AstNode) {
        match node {
            AstNode::ObjectDefinition { name, fields, .. } => {
                self.objects.insert(name.clone(), fields.clone());
            }
            AstNode::TypeAlias {
                name, target_type, ..
            } => {
                self.aliases
                    .insert(name.clone(), SymbolType::from_ast(target_type));
            }
            AstNode::FunctionDefinition { body, .. } => {
                self.functions.push(node);
                self.collect(body);
            }
            AstNode::Block(nodes) => {
                for node in nodes {
                    self.collect(node);
                }
            }
            AstNode::IfExpression {
                then_branch,
                else_branch,
                ..
            } => {
                self.collect(then_branch);
                if let Some(branch) = else_branch {
                    self.collect(branch);
                }
            }
            AstNode::WhileLoop { body, .. } | AstNode::ForLoop { body, .. } => self.collect(body),
            _ => {}
        }
    }

    fn resolve(&self, ty: SymbolType, depth: usize) -> SymbolType {
        if depth > 64 {
            return ty;
        }
        match &ty {
            SymbolType::TypeName(name) | SymbolType::Object(name) => self
                .aliases
                .get(name)
                .map(|ty| self.resolve(ty.clone(), depth + 1))
                .unwrap_or(ty),
            SymbolType::Secret(inner) => {
                SymbolType::Secret(Box::new(self.resolve(*inner.clone(), depth + 1)))
            }
            _ => ty,
        }
    }

    fn default_value(
        &mut self,
        ty: SymbolType,
        field: bool,
        state: &mut State,
        depth: usize,
    ) -> Fact {
        if depth > 64 {
            return Fact::Missing;
        }
        let ty = self.resolve(ty, 0);
        if matches!(ty.underlying_type(), SymbolType::List(_)) {
            return Fact::Ready;
        }
        if let SymbolType::Object(name) | SymbolType::TypeName(name) = ty.underlying_type() {
            if let Some(fields) = self.objects.get(name).cloned() {
                let id = self.next_id;
                self.next_id += 1;
                let mut values = BTreeMap::new();
                for field in fields {
                    values.insert(
                        field.name,
                        self.default_value(
                            SymbolType::from_ast(&field.type_annotation),
                            true,
                            state,
                            depth + 1,
                        ),
                    );
                }
                state.heap.insert(id, values);
                return Fact::Objects(BTreeSet::from([id]));
            }
        }
        if !field
            && (crate::codegen::share_type_for_secret_scalar_symbol_type(&ty).is_some()
                || matches!(ty, SymbolType::Void | SymbolType::Nil))
        {
            Fact::Ready
        } else {
            Fact::Missing
        }
    }

    fn require(&mut self, fact: &Fact, node: &AstNode, state: &State) {
        let path = match node {
            AstNode::Identifier(name, _) => crate::scope_bindings::source_name(name).to_owned(),
            AstNode::FieldAccess {
                object, field_name, ..
            } => format!("{}.{}", display_path(object), field_name),
            _ => "value".to_owned(),
        };
        if let Some(path) = state.missing(fact, &path, &mut BTreeSet::new()) {
            self.errors.push(CompilerError::semantic_error(
                format!("'{path}' may be read before it is initialized"), node.location())
                .with_hint("Assign this value on every path that reaches this use; initialize all object fields before passing or returning the object"));
        }
    }

    fn read(&mut self, node: &AstNode, state: &mut State) -> Fact {
        let fact = self.expression(node, state);
        self.require(&fact, node, state);
        fact
    }

    fn expression(&mut self, node: &AstNode, state: &mut State) -> Fact {
        match node {
            AstNode::Identifier(name, _) => state.vars.get(name).cloned().unwrap_or(Fact::Ready),
            AstNode::FieldAccess {
                object, field_name, ..
            } => {
                let base = self.expression(object, state);
                if let Fact::Objects(ids) = base {
                    ids.iter()
                        .map(|id| {
                            state
                                .heap
                                .get(id)
                                .and_then(|fields| fields.get(field_name))
                                .cloned()
                                .unwrap_or({
                                    // The sentinel is a complete object from
                                    // outside the tracked local heap.
                                    if *id == usize::MAX {
                                        Fact::Ready
                                    } else {
                                        Fact::Missing
                                    }
                                })
                        })
                        .reduce(|a, b| a.join(&b))
                        .unwrap_or(Fact::Missing)
                } else {
                    self.require(&base, object, state);
                    base
                }
            }
            AstNode::FunctionCall {
                function,
                arguments,
                ..
            }
            | AstNode::CommandCall {
                command: function,
                arguments,
                ..
            } => {
                if let AstNode::Identifier(name, _) = function.as_ref() {
                    if self.objects.contains_key(name) {
                        let object =
                            self.default_value(SymbolType::Object(name.clone()), false, state, 0);
                        for arg in arguments {
                            if let AstNode::NamedArgument { name, value, .. } = arg {
                                let fact = self.expression(value, state);
                                if fact == Fact::Missing {
                                    self.require(&fact, value, state);
                                }
                                self.write_field(&object, name, fact, state);
                            } else {
                                self.read(arg, state);
                            }
                        }
                        return object;
                    }
                }
                if !matches!(function.as_ref(), AstNode::Identifier(_, _)) {
                    self.read(function, state);
                }
                let values: Vec<_> = arguments
                    .iter()
                    .map(|argument| self.expression(argument, state))
                    .collect();
                for (argument, value) in arguments.iter().zip(&values) {
                    if *value == Fact::Missing {
                        self.require(value, argument, state);
                    }
                }
                let partial = values
                    .iter()
                    .any(|v| state.missing(v, "value", &mut BTreeSet::new()).is_some());
                if partial {
                    if let AstNode::Identifier(name, _) = function.as_ref() {
                        let definition = self.functions.iter().rev().copied().find(|f| matches!(f, AstNode::FunctionDefinition { name: Some(n), .. } if n == name));
                        if let Some(AstNode::FunctionDefinition {
                            parameters, body, ..
                        }) = definition
                        {
                            if !self.calls.contains(name) && self.calls.len() < 64 {
                                let mut callee = State {
                                    vars: BTreeMap::new(),
                                    heap: state.heap.clone(),
                                };
                                declare_locals(body, &mut callee);
                                for (param, value) in parameters.iter().zip(&values) {
                                    callee.vars.insert(param.name.clone(), value.clone());
                                }
                                self.calls.push(name.clone());
                                let flow = self.statement(body, callee);
                                self.calls.pop();
                                if let Some(after) = flow
                                    .returns
                                    .into_iter()
                                    .fold(flow.next, |a, b| join_optional(a, Some(b)))
                                {
                                    state.heap = after.heap;
                                }
                                return Fact::Ready;
                            }
                        }
                    }
                }
                for (argument, value) in arguments.iter().zip(&values) {
                    self.require(value, argument, state);
                }
                Fact::Ready
            }
            AstNode::NamedArgument { value, .. } => self.expression(value, state),
            AstNode::BinaryOperation { left, right, .. } => {
                // Boolean and/or are eager VM operations, just like arithmetic.
                self.read(left, state);
                self.read(right, state);
                Fact::Ready
            }
            AstNode::UnaryOperation { operand, .. } => {
                self.read(operand, state);
                Fact::Ready
            }
            AstNode::IndexAccess { base, index, .. } => {
                self.read(base, state);
                self.read(index, state);
                Fact::Ready
            }
            AstNode::ListLiteral { elements, .. }
            | AstNode::TupleLiteral(elements)
            | AstNode::SetLiteral(elements) => {
                for element in elements {
                    self.read(element, state);
                }
                Fact::Ready
            }
            AstNode::DictLiteral { pairs, .. } => {
                for (key, value) in pairs {
                    self.read(key, state);
                    self.read(value, state);
                }
                Fact::Ready
            }
            AstNode::IfExpression { .. } | AstNode::Block(_) => {
                let flow = self.statement(node, state.clone());
                if let Some(next) = flow.next {
                    *state = next;
                }
                Fact::Ready
            }
            _ => Fact::Ready,
        }
    }

    fn write_field(&self, object: &Fact, name: &str, value: Fact, state: &mut State) {
        if let Fact::Objects(ids) = object {
            for id in ids {
                if let Some(fields) = state.heap.get_mut(id) {
                    let next = if ids.len() == 1 {
                        value.clone()
                    } else {
                        fields.get(name).unwrap_or(&Fact::Missing).join(&value)
                    };
                    fields.insert(name.to_owned(), next);
                }
            }
        }
    }

    fn statement(&mut self, node: &AstNode, mut state: State) -> Flow {
        match node {
            AstNode::Block(nodes) => {
                let mut flow = Flow {
                    next: Some(state),
                    ..Flow::default()
                };
                for node in nodes {
                    let Some(next) = flow.next.take() else {
                        break;
                    };
                    let step = self.statement(node, next);
                    flow.next = step.next;
                    flow.breaks.extend(step.breaks);
                    flow.continues.extend(step.continues);
                    flow.returns.extend(step.returns);
                }
                return flow;
            }
            AstNode::VariableDeclaration {
                name,
                type_annotation,
                value,
                is_secret,
                ..
            } => {
                let fact = if let Some(value) = value {
                    let fact = self.expression(value, &mut state);
                    if fact == Fact::Missing {
                        self.require(&fact, value, &state);
                    }
                    fact
                } else {
                    let mut ty = type_annotation
                        .as_deref()
                        .map(SymbolType::from_ast)
                        .unwrap_or(SymbolType::Unknown);
                    if *is_secret && !ty.is_secret() {
                        ty = SymbolType::Secret(Box::new(ty));
                    }
                    self.default_value(ty, false, &mut state, 0)
                };
                state.vars.insert(name.clone(), fact);
            }
            AstNode::Assignment { target, value, .. } => {
                let fact = self.expression(value, &mut state);
                if fact == Fact::Missing {
                    self.require(&fact, value, &state);
                }
                match target.as_ref() {
                    AstNode::Identifier(name, _) => {
                        state.vars.insert(name.clone(), fact);
                    }
                    AstNode::FieldAccess {
                        object, field_name, ..
                    } => {
                        let base = self.expression(object, &mut state);
                        if base == Fact::Missing {
                            self.require(&base, object, &state);
                        }
                        self.require(&fact, value, &state);
                        self.write_field(&base, field_name, fact, &mut state);
                    }
                    _ => {
                        self.read(target, &mut state);
                        self.require(&fact, value, &state);
                    }
                }
            }
            AstNode::IfExpression {
                condition,
                then_branch,
                else_branch,
            } => {
                self.read(condition, &mut state);
                if let Some(value) = constant_bool(condition) {
                    return if value {
                        self.statement(then_branch, state)
                    } else if let Some(other) = else_branch {
                        self.statement(other, state)
                    } else {
                        Flow {
                            next: Some(state),
                            ..Flow::default()
                        }
                    };
                }
                let mut left = self.statement(then_branch, state.clone());
                let right = else_branch
                    .as_deref()
                    .map(|n| self.statement(n, state.clone()))
                    .unwrap_or(Flow {
                        next: Some(state),
                        ..Flow::default()
                    });
                left.next = join_optional(left.next, right.next);
                left.breaks.extend(right.breaks);
                left.continues.extend(right.continues);
                left.returns.extend(right.returns);
                return left;
            }
            AstNode::WhileLoop {
                condition, body, ..
            } => {
                self.read(condition, &mut state);
                if constant_bool(condition) == Some(false) {
                    return Flow {
                        next: Some(state),
                        ..Flow::default()
                    };
                }
                return self.loop_body(node, body, Some(condition), state, &[]);
            }
            AstNode::ForLoop {
                variables,
                iterable,
                body,
                ..
            } => {
                self.read(iterable, &mut state);
                return self.loop_body(node, body, None, state, variables);
            }
            AstNode::Return { value, .. } | AstNode::Yield(value) => {
                if let Some(value) = value {
                    self.read(value, &mut state);
                }
                return Flow {
                    returns: vec![state],
                    ..Flow::default()
                };
            }
            AstNode::Break => {
                return Flow {
                    breaks: vec![state],
                    ..Flow::default()
                }
            }
            AstNode::Continue => {
                return Flow {
                    continues: vec![state],
                    ..Flow::default()
                }
            }
            AstNode::FunctionDefinition { .. }
            | AstNode::ObjectDefinition { .. }
            | AstNode::TypeAlias { .. }
            | AstNode::BuiltinTypeDefinition { .. }
            | AstNode::BuiltinObjectDefinition { .. }
            | AstNode::EnumDefinition { .. }
            | AstNode::Import { .. } => {}
            AstNode::DiscardStatement { expression, .. } => {
                self.read(expression, &mut state);
            }
            _ => {
                self.read(node, &mut state);
            }
        }
        Flow {
            next: Some(state),
            ..Flow::default()
        }
    }

    fn loop_body(
        &mut self,
        node: &AstNode,
        body: &AstNode,
        condition: Option<&AstNode>,
        initial: State,
        variables: &[String],
    ) -> Flow {
        let mut header = initial.clone();
        let mut exits = if condition.and_then(constant_bool) == Some(true) {
            None
        } else {
            Some(initial.clone())
        };
        let mut returns = Vec::new();
        for _ in 0..64 {
            let mut iteration = header.clone();
            for variable in variables {
                iteration.vars.insert(variable.clone(), Fact::Ready);
            }
            if let Some(condition) = condition {
                self.read(condition, &mut iteration);
            }
            let mut flow = self.statement(body, iteration);
            if !variables.is_empty() {
                let mut locals = State::default();
                declare_locals(body, &mut locals);
                for name in variables {
                    locals.vars.insert(name.clone(), Fact::Missing);
                }
                for next in flow
                    .next
                    .iter_mut()
                    .chain(flow.breaks.iter_mut())
                    .chain(flow.continues.iter_mut())
                    .chain(flow.returns.iter_mut())
                {
                    for name in locals.vars.keys() {
                        if let Some(value) = header.vars.get(name) {
                            next.vars.insert(name.clone(), value.clone());
                        } else {
                            next.vars.remove(name);
                        }
                    }
                }
            }
            returns.extend(flow.returns);
            for exit in flow.breaks {
                exits = join_optional(exits, Some(exit));
            }
            let back = flow
                .continues
                .into_iter()
                .fold(flow.next, |a, b| join_optional(a, Some(b)));
            let Some(back) = back else {
                return Flow {
                    next: exits,
                    returns,
                    ..Flow::default()
                };
            };
            if condition.and_then(constant_bool) != Some(true) {
                exits = join_optional(exits, Some(back.clone()));
            }
            let next = initial.join(&back);
            if next.canonical() == header.canonical() {
                return Flow {
                    next: exits,
                    returns,
                    ..Flow::default()
                };
            }
            header = next;
        }
        self.errors.push(CompilerError::semantic_error("Cannot prove definite assignment across this loop", node.location())
            .with_hint("Initialize values and object fields before the loop, or construct complete objects in each iteration"));
        Flow {
            next: exits,
            returns,
            ..Flow::default()
        }
    }
}

fn join_optional(a: Option<State>, b: Option<State>) -> Option<State> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.join(&b)),
        (a, b) => a.or(b),
    }
}

fn constant_bool(node: &AstNode) -> Option<bool> {
    match node {
        AstNode::Literal {
            value: Value::Bool(value),
            ..
        } => Some(*value),
        AstNode::UnaryOperation { op, operand, .. } if op == "not" => {
            constant_bool(operand).map(|v| !v)
        }
        _ => None,
    }
}

fn display_path(node: &AstNode) -> String {
    match node {
        AstNode::Identifier(name, _) => crate::scope_bindings::source_name(name).to_owned(),
        AstNode::FieldAccess {
            object, field_name, ..
        } => format!("{}.{}", display_path(object), field_name),
        _ => "value".to_owned(),
    }
}

fn declare_locals(node: &AstNode, state: &mut State) {
    if matches!(node, AstNode::FunctionDefinition { .. }) {
        return;
    }
    if let AstNode::VariableDeclaration { name, .. } = node {
        state.vars.insert(name.clone(), Fact::Missing);
    }
    crate::optimizations::for_each_child(node, &mut |child| declare_locals(child, state));
}
