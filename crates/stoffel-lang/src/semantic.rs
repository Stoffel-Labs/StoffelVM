use std::collections::{HashMap, HashSet};

use crate::ast::{AstNode, Pragma, Value};
use crate::builtin_registry::BuiltinParameterInfo;
use crate::errors::{CompilerError, ErrorReporter, SourceLocation};
use crate::suggestions::{
    suggest_from_symbols, suggest_function_from_symbols, suggest_method_to_function,
};
use crate::symbol_table::{
    SymbolDeclarationError, SymbolInfo, SymbolKind, SymbolTable, SymbolType, UserObjectInfo,
};

/// Performs semantic analysis (symbol checking, type checking) on the AST.
pub struct SemanticAnalyzer<'a> {
    symbol_table: SymbolTable,
    error_reporter: &'a mut ErrorReporter,
    current_function_return_type: Option<SymbolType>, // Track expected return type
    /// Imported symbols from other modules, keyed by their qualified name
    imported_symbols: HashMap<String, SymbolInfo>,
    /// Number of enclosing loops at the current analysis point (for break/continue)
    loop_depth: usize,
    function_scope: Option<usize>,
    /// Parameter names, default-value expressions, and variadic flags of
    /// user-defined functions, used to resolve named arguments, inject
    /// defaults, and pack *args at call sites.
    function_signatures: HashMap<String, Vec<(String, Option<AstNode>, bool)>>,
    /// Enum member values by enum name; enums lower to int64 constants.
    enum_members: HashMap<String, HashMap<String, i64>>,
}

#[derive(Debug, Clone)]
struct CallParameterInfo {
    ty: SymbolType,
    has_default: bool,
    is_variadic: bool,
}

#[derive(Debug, Clone)]
struct InferenceConstraint {
    ty: SymbolType,
    location: SourceLocation,
    reason: String,
}

#[derive(Debug, Clone)]
struct LocalInference {
    location: SourceLocation,
    explicit: bool,
    constraints: Vec<InferenceConstraint>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticError;

impl<'a> SemanticAnalyzer<'a> {
    pub fn new(error_reporter: &'a mut ErrorReporter, _filename: &'a str) -> Self {
        SemanticAnalyzer {
            symbol_table: SymbolTable::new(),
            error_reporter,
            current_function_return_type: None,
            imported_symbols: HashMap::new(),
            loop_depth: 0,
            function_scope: None,
            function_signatures: HashMap::new(),
            enum_members: HashMap::new(),
        }
    }

    /// Creates a new analyzer with pre-populated imported symbols.
    pub fn with_imports(
        error_reporter: &'a mut ErrorReporter,
        _filename: &'a str,
        imported_symbols: HashMap<String, SymbolInfo>,
    ) -> Self {
        SemanticAnalyzer {
            symbol_table: SymbolTable::new(),
            error_reporter,
            current_function_return_type: None,
            imported_symbols,
            loop_depth: 0,
            function_scope: None,
            function_signatures: HashMap::new(),
            enum_members: HashMap::new(),
        }
    }

    pub(crate) fn import_function_signature(
        &mut self,
        name: String,
        parameters: &[crate::ast::Parameter],
    ) {
        self.function_signatures.insert(
            name,
            parameters
                .iter()
                .map(|p| {
                    (
                        p.name.clone(),
                        p.default_value.as_deref().cloned(),
                        p.is_variadic,
                    )
                })
                .collect(),
        );
    }

    /// Adds imported symbols to the global scope.
    fn register_imported_symbols(&mut self, node: &AstNode) {
        let mut counts = HashMap::new();
        for name in self.imported_symbols.keys() {
            *counts
                .entry(name.rsplit('.').next().unwrap_or(name))
                .or_insert(0usize) += 1;
        }
        let local_names: HashSet<_> = if let AstNode::Block(nodes) = node {
            nodes
                .iter()
                .filter_map(|n| match n {
                    AstNode::FunctionDefinition {
                        name: Some(name), ..
                    } => Some(name.as_str()),
                    _ => None,
                })
                .collect()
        } else {
            HashSet::new()
        };
        for (name, info) in &self.imported_symbols {
            // Add the simple name (without module prefix) for convenience
            // This allows calling `add(a, b)` instead of `utils.math.add(a, b)`
            let simple_name = name.rsplit('.').next().unwrap_or(name);
            if name != simple_name
                && counts.get(simple_name) == Some(&1)
                && !local_names.contains(simple_name)
            {
                if let Some(signature) = self.function_signatures.get(name).cloned() {
                    self.function_signatures
                        .insert(simple_name.to_owned(), signature);
                }
                self.symbol_table.declare_symbol(SymbolInfo {
                    name: simple_name.to_string(),
                    kind: info.kind.clone(),
                    symbol_type: info.symbol_type.clone(),
                    is_secret: info.is_secret,
                    defined_at: info.defined_at.clone(),
                });
            }
            // Also add the qualified name for explicit module.func() calls
            self.symbol_table.declare_symbol(info.clone());
        }
    }

    fn int_literal_value(node: &AstNode) -> Option<i128> {
        if let AstNode::Literal {
            value: Value::Int { value, .. },
            ..
        } = node
        {
            if *value <= i128::MAX as u128 {
                Some(*value as i128)
            } else {
                None
            }
        } else {
            None
        }
    }

    fn untyped_int_literal_value(node: &AstNode) -> Option<i128> {
        match node {
            AstNode::Literal {
                value: Value::Int { value, kind: None },
                ..
            } if *value <= i128::MAX as u128 => Some(*value as i128),
            AstNode::UnaryOperation { op, operand, .. } if op == "-" => {
                Self::untyped_int_literal_value(operand).map(|value| -value)
            }
            _ => None,
        }
    }

    fn int_literal_bool_value(node: &AstNode) -> Option<bool> {
        match Self::int_literal_value(node)? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    fn bool_literal_from_int(node: AstNode) -> AstNode {
        if let AstNode::Literal { location, .. } = &node {
            if let Some(value) = Self::int_literal_bool_value(&node) {
                return AstNode::Literal {
                    value: Value::Bool(value),
                    location: location.clone(),
                };
            }
        }
        node
    }

    /// Maps a call's arguments onto a user function's parameter list:
    /// positional arguments fill slots left to right, named arguments fill
    /// their parameter's slot, and remaining slots take declared defaults.
    fn resolve_call_arguments(
        &mut self,
        mut arguments: Vec<AstNode>,
        signature: &[(String, Option<AstNode>, bool)],
        function_name: &str,
        location: &SourceLocation,
    ) -> Result<Vec<AstNode>, ()> {
        let is_variadic = signature.last().is_some_and(|(_, _, variadic)| *variadic);

        // Pack extra positional arguments into a list for a trailing *args.
        if is_variadic {
            if arguments
                .iter()
                .any(|arg| matches!(arg, AstNode::NamedArgument { .. }))
            {
                self.error_reporter.add_error(CompilerError::semantic_error(
                    format!(
                        "Named arguments cannot be combined with the variadic function '{}'",
                        function_name
                    ),
                    location.clone(),
                ));
                return Err(());
            }
            let fixed = signature.len() - 1;
            if arguments.len() < fixed {
                self.error_reporter.add_error(CompilerError::semantic_error(
                    format!(
                        "Function '{}' expects at least {} argument(s), but {} were provided",
                        function_name,
                        fixed,
                        arguments.len()
                    ),
                    location.clone(),
                ));
                return Err(());
            }
            let extras = arguments.split_off(fixed);
            arguments.push(AstNode::ListLiteral {
                elements: extras,
                location: location.clone(),
            });
            return Ok(arguments);
        }

        let has_named = arguments
            .iter()
            .any(|arg| matches!(arg, AstNode::NamedArgument { .. }));
        let has_defaults = signature.iter().any(|(_, default, _)| default.is_some());
        if !has_named && !has_defaults {
            return Ok(arguments);
        }
        if !has_named && arguments.len() > signature.len() {
            // Let the regular arity check report this.
            return Ok(arguments);
        }

        let mut slots: Vec<Option<AstNode>> = vec![None; signature.len()];
        let mut next_positional = 0usize;
        let mut seen_named = false;
        for arg in arguments {
            match arg {
                AstNode::NamedArgument {
                    name,
                    value,
                    location: arg_loc,
                } => {
                    seen_named = true;
                    let Some(index) = signature.iter().position(|(param, _, _)| *param == name)
                    else {
                        self.error_reporter.add_error(CompilerError::semantic_error(
                            format!(
                                "Function '{}' has no parameter named '{}'",
                                function_name, name
                            ),
                            arg_loc,
                        ));
                        return Err(());
                    };
                    if slots[index].is_some() {
                        self.error_reporter.add_error(CompilerError::semantic_error(
                            format!("Argument '{}' provided more than once", name),
                            arg_loc,
                        ));
                        return Err(());
                    }
                    slots[index] = Some(*value);
                }
                positional => {
                    if seen_named {
                        self.error_reporter.add_error(CompilerError::semantic_error(
                            "Positional arguments must come before named arguments",
                            positional.location(),
                        ));
                        return Err(());
                    }
                    if next_positional >= slots.len() {
                        self.error_reporter.add_error(CompilerError::semantic_error(
                            format!(
                                "Function '{}' expects {} argument(s), but more were provided",
                                function_name,
                                signature.len()
                            ),
                            positional.location(),
                        ));
                        return Err(());
                    }
                    slots[next_positional] = Some(positional);
                    next_positional += 1;
                }
            }
        }

        let mut resolved = Vec::with_capacity(slots.len());
        for (slot, (param_name, default, _)) in slots.into_iter().zip(signature.iter()) {
            match (slot, default) {
                (Some(arg), _) => resolved.push(arg),
                (None, Some(default)) => resolved.push(default.clone()),
                (None, None) => {
                    self.error_reporter.add_error(CompilerError::semantic_error(
                        format!(
                            "Missing argument '{}' in call to '{}'",
                            param_name, function_name
                        ),
                        location.clone(),
                    ));
                    return Err(());
                }
            }
        }
        Ok(resolved)
    }

    /// Conservative control-flow check: does every path through `node`
    /// execute a return statement? Loops are assumed to possibly not run.
    fn node_always_returns(node: &AstNode) -> bool {
        match node {
            AstNode::Return { .. } => true,
            AstNode::Block(statements) => statements.iter().any(Self::node_always_returns),
            AstNode::IfExpression {
                then_branch,
                else_branch: Some(else_branch),
                ..
            } => Self::node_always_returns(then_branch) && Self::node_always_returns(else_branch),
            AstNode::IfExpression { .. } => false,
            // A `while true:` (or any constant-true condition) never falls through
            // unless something `break`s out of it. With no escaping break the loop
            // diverges, so the function returns (or loops forever) on this path and
            // needs no trailing return — e.g. `while true: ... return x`.
            AstNode::WhileLoop {
                condition, body, ..
            } => Self::is_const_true(condition) && !Self::contains_escaping_break(body),
            _ => false,
        }
    }

    /// True for a literal `true`/`True` condition.
    fn is_const_true(node: &AstNode) -> bool {
        matches!(
            node,
            AstNode::Literal {
                value: crate::ast::Value::Bool(true),
                ..
            }
        )
    }

    /// Whether `node` contains a `break` that would exit the *current* loop.
    /// Breaks inside a nested loop target that inner loop, so nested
    /// `WhileLoop`/`ForLoop` bodies are not descended into. Pure-expression and
    /// leaf nodes cannot hold statements, so they contribute no break.
    fn contains_escaping_break(node: &AstNode) -> bool {
        match node {
            AstNode::Break => true,
            AstNode::WhileLoop { .. } | AstNode::ForLoop { .. } => false,
            AstNode::Block(statements) => statements.iter().any(Self::contains_escaping_break),
            AstNode::IfExpression {
                then_branch,
                else_branch,
                ..
            } => {
                Self::contains_escaping_break(then_branch)
                    || else_branch
                        .as_ref()
                        .is_some_and(|branch| Self::contains_escaping_break(branch))
            }
            AstNode::TryCatch {
                try_block,
                catch_clauses,
                finally_block,
                ..
            } => {
                Self::contains_escaping_break(try_block)
                    || catch_clauses
                        .iter()
                        .any(|clause| Self::contains_escaping_break(&clause.body))
                    || finally_block
                        .as_ref()
                        .is_some_and(|block| Self::contains_escaping_break(block))
            }
            _ => false,
        }
    }

    fn int_kind_for_symbol_type(ty: &SymbolType) -> Option<crate::ast::IntKind> {
        use crate::ast::{IntKind, IntWidth};
        match ty.underlying_type() {
            SymbolType::Int8 => Some(IntKind::Signed(IntWidth::W8)),
            SymbolType::Int16 => Some(IntKind::Signed(IntWidth::W16)),
            SymbolType::Int32 => Some(IntKind::Signed(IntWidth::W32)),
            SymbolType::Int64 => Some(IntKind::Signed(IntWidth::W64)),
            SymbolType::UInt8 => Some(IntKind::Unsigned(IntWidth::W8)),
            SymbolType::UInt16 => Some(IntKind::Unsigned(IntWidth::W16)),
            SymbolType::UInt32 => Some(IntKind::Unsigned(IntWidth::W32)),
            SymbolType::UInt64 => Some(IntKind::Unsigned(IntWidth::W64)),
            _ => None,
        }
    }

    /// Rewrites an untyped integer literal (or unary minus of one) so codegen
    /// emits a constant of the expected width instead of defaulting to I64.
    fn sized_int_literal_from_int(node: AstNode, expected_type: &SymbolType) -> AstNode {
        let Some(kind) = Self::int_kind_for_symbol_type(expected_type) else {
            return node;
        };
        match node {
            AstNode::Literal {
                value: Value::Int { value, kind: None },
                location,
            } => AstNode::Literal {
                value: Value::Int {
                    value,
                    kind: Some(kind),
                },
                location,
            },
            AstNode::UnaryOperation {
                op,
                operand,
                location,
            } if op == "-" => AstNode::UnaryOperation {
                op,
                operand: Box::new(Self::sized_int_literal_from_int(*operand, expected_type)),
                location,
            },
            other => other,
        }
    }

    /// True when the node is an untyped integer literal (optionally wrapped in
    /// unary minus) that can adopt any integer width from context.
    fn is_untyped_int_literal(node: &AstNode) -> bool {
        match node {
            AstNode::Literal {
                value: Value::Int { kind: None, .. },
                ..
            } => true,
            AstNode::UnaryOperation { op, operand, .. } if op == "-" => {
                Self::is_untyped_int_literal(operand)
            }
            _ => false,
        }
    }

    fn expression_can_refine_to_expected(expr: &AstNode, expected_type: &SymbolType) -> bool {
        match expr {
            AstNode::Literal {
                value: Value::String(_),
                ..
            } => expected_type.underlying_type() == &SymbolType::String,
            AstNode::Literal {
                value: Value::Bool(_),
                ..
            } => expected_type.underlying_type() == &SymbolType::Bool,
            AstNode::Literal {
                value: Value::Nil, ..
            } => expected_type.underlying_type() == &SymbolType::Nil,
            AstNode::Literal {
                value: Value::Int { kind: None, .. },
                ..
            } => {
                if expected_type.underlying_type() == &SymbolType::Bool {
                    return Self::int_literal_bool_value(expr).is_some();
                }
                if expected_type.underlying_type().is_integer() {
                    return Self::untyped_int_literal_value(expr)
                        .is_some_and(|value| expected_type.fits_literal_i128(value));
                }
                Self::is_clear_real_type(expected_type)
                    && Self::untyped_int_literal_value(expr).is_some()
            }
            AstNode::UnaryOperation { op, operand, .. } if op == "-" => {
                if expected_type.underlying_type().is_integer() {
                    return Self::untyped_int_literal_value(expr)
                        .is_some_and(|value| expected_type.fits_literal_i128(value));
                }
                // Negated int literals (-3) and negated float literals (-1.5)
                // both adopt a clear real (float/fix64) context.
                Self::is_clear_real_type(expected_type)
                    && (Self::untyped_int_literal_value(expr).is_some()
                        || matches!(
                            operand.as_ref(),
                            AstNode::Literal {
                                value: Value::Float(_),
                                ..
                            }
                        ))
            }
            AstNode::Literal {
                value: Value::Float(_),
                ..
            } => Self::is_clear_real_type(expected_type),
            AstNode::BinaryOperation {
                op, left, right, ..
            } if Self::binary_operand_context_type(op, expected_type).is_some() => {
                Self::expression_can_refine_to_expected(left, expected_type)
                    && Self::expression_can_refine_to_expected(right, expected_type)
            }
            AstNode::ListLiteral { elements, .. } => {
                if let SymbolType::List(element_type) = expected_type.underlying_type() {
                    elements.iter().all(|element| {
                        Self::expression_can_refine_to_expected(element, element_type)
                    })
                } else {
                    false
                }
            }
            AstNode::DictLiteral { pairs, .. } => {
                if let SymbolType::Dict(key_type, value_type) = expected_type.underlying_type() {
                    pairs.iter().all(|(key, value)| {
                        Self::expression_can_refine_to_expected(key, key_type)
                            && Self::expression_can_refine_to_expected(value, value_type)
                    })
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    fn float_literal_from_int(node: AstNode) -> AstNode {
        if let AstNode::Literal { location, .. } = &node {
            if let Some(value) = Self::int_literal_value(&node) {
                return AstNode::Literal {
                    value: Value::Float((value as f64).to_bits()),
                    location: location.clone(),
                };
            }
        }
        node
    }

    fn is_clear_real_type(ty: &SymbolType) -> bool {
        matches!(
            ty.underlying_type(),
            SymbolType::Float | SymbolType::Fixed { .. }
        )
    }

    fn is_arithmetic_op(op: &str) -> bool {
        matches!(op, "+" | "-" | "*" | "/" | "%" | "mod")
    }

    fn is_boolean_logic_op(op: &str) -> bool {
        matches!(op, "and" | "or" | "xor")
    }

    fn is_clear_numeric_type(ty: &SymbolType) -> bool {
        ty.is_integer() || Self::is_clear_real_type(ty)
    }

    fn is_clear_primitive_type(ty: &SymbolType) -> bool {
        matches!(
            ty.underlying_type(),
            SymbolType::String | SymbolType::Bool | SymbolType::Nil
        ) || Self::is_clear_numeric_type(ty)
    }

    fn binary_operand_context_type<'b>(
        op: &str,
        expected_type: &'b SymbolType,
    ) -> Option<&'b SymbolType> {
        let expected_under = expected_type.underlying_type();
        if Self::is_arithmetic_op(op) && Self::is_clear_numeric_type(expected_under) {
            return Some(expected_type);
        }
        if op == "+" && expected_under == &SymbolType::String {
            return Some(expected_type);
        }
        if Self::is_boolean_logic_op(op) && expected_under == &SymbolType::Bool {
            return Some(expected_type);
        }
        None
    }

    /// Checks if two types are compatible, allowing Unknown to match any type.
    /// This enables type refinement where a concrete type annotation can refine
    /// an Unknown type from inference (e.g., `List[float]` refines `List[<unknown>]`).
    fn types_compatible(src: &SymbolType, dst: &SymbolType) -> bool {
        // Unknown is compatible with anything
        if *src == SymbolType::Unknown || *dst == SymbolType::Unknown {
            return true;
        }

        if Self::requires_explicit_reveal(src, dst) {
            return false;
        }

        if Self::share_to_secret_compatible(src, dst) {
            return true;
        }
        if Self::secret_to_share_compatible(src, dst) {
            return true;
        }

        match (src.underlying_type(), dst.underlying_type()) {
            // List types: compatible if element types are compatible
            (SymbolType::List(src_elem), SymbolType::List(dst_elem)) => {
                Self::types_compatible(src_elem, dst_elem)
            }
            // Dict types: compatible if both key and value types are compatible
            (SymbolType::Dict(src_k, src_v), SymbolType::Dict(dst_k, dst_v)) => {
                Self::types_compatible(src_k, dst_k) && Self::types_compatible(src_v, dst_v)
            }
            // Generic types: compatible if name matches and all params are compatible
            (
                SymbolType::Generic(src_name, src_params),
                SymbolType::Generic(dst_name, dst_params),
            ) => {
                src_name == dst_name
                    && src_params.len() == dst_params.len()
                    && src_params
                        .iter()
                        .zip(dst_params.iter())
                        .all(|(s, d)| Self::types_compatible(s, d))
            }
            // User object annotations parse as TypeName, while constructors
            // and inferred values carry Object.
            (SymbolType::TypeName(src_name), SymbolType::Object(dst_name))
            | (SymbolType::Object(src_name), SymbolType::TypeName(dst_name)) => {
                src_name == dst_name
            }
            // Secret types: compare underlying types
            (SymbolType::Secret(src_inner), SymbolType::Secret(dst_inner)) => {
                Self::types_compatible(src_inner, dst_inner)
            }
            // Type variables are resolved per call by `check_generic_compat`.
            // Outside that context they behave like placeholders.
            (SymbolType::TypeVar(_), _) | (_, SymbolType::TypeVar(_)) => true,
            // For all other types, require exact match
            (s, d) => s == d,
        }
    }

    fn is_share_alias_type(ty: &SymbolType) -> bool {
        matches!(
            ty.underlying_type(),
            SymbolType::Object(name) | SymbolType::TypeName(name) if name == "Share"
        )
    }

    fn share_to_secret_compatible(src: &SymbolType, dst: &SymbolType) -> bool {
        Self::is_share_alias_type(src) && matches!(dst, SymbolType::Secret(_))
    }

    fn secret_to_share_compatible(src: &SymbolType, dst: &SymbolType) -> bool {
        matches!(src, SymbolType::Secret(_)) && Self::is_share_alias_type(dst)
    }

    fn is_secret_or_share_value(ty: &SymbolType) -> bool {
        ty.is_secret() || Self::is_share_alias_type(ty)
    }

    fn builtin_parameter_info_to_call_parameter(info: &BuiltinParameterInfo) -> CallParameterInfo {
        CallParameterInfo {
            ty: info.ty.clone(),
            has_default: info.has_default,
            is_variadic: info.is_variadic,
        }
    }

    fn fixed_parameter_info(parameters: &[SymbolType]) -> Vec<CallParameterInfo> {
        parameters
            .iter()
            .cloned()
            .map(|ty| CallParameterInfo {
                ty,
                has_default: false,
                is_variadic: false,
            })
            .collect()
    }

    fn builtin_call_parameters(
        &self,
        function_name: &str,
        fallback: &[SymbolType],
        is_builtin_call: bool,
    ) -> Vec<CallParameterInfo> {
        if is_builtin_call {
            let registry = crate::builtin_registry::builtin_registry();
            if let Some(function) = registry.functions.get(function_name) {
                return function
                    .parameter_details
                    .iter()
                    .map(Self::builtin_parameter_info_to_call_parameter)
                    .collect();
            }

            if let Some((object_name, method_name)) = function_name.split_once('.') {
                if let Some(method) = registry
                    .objects
                    .get(object_name)
                    .and_then(|object| object.methods.get(method_name))
                {
                    return method
                        .parameter_details
                        .iter()
                        .map(Self::builtin_parameter_info_to_call_parameter)
                        .collect();
                }
            }
        }

        Self::fixed_parameter_info(fallback)
    }

    fn minimum_argument_count(parameters: &[CallParameterInfo]) -> usize {
        parameters
            .iter()
            .filter(|parameter| !parameter.has_default && !parameter.is_variadic)
            .count()
    }

    fn has_variadic_parameter(parameters: &[CallParameterInfo]) -> bool {
        parameters.iter().any(|parameter| parameter.is_variadic)
    }

    fn expected_argument_type_for_index(
        parameters: &[CallParameterInfo],
        index: usize,
    ) -> Option<&SymbolType> {
        parameters
            .get(index)
            .map(|parameter| &parameter.ty)
            .or_else(|| {
                parameters
                    .iter()
                    .find(|parameter| parameter.is_variadic)
                    .map(|parameter| &parameter.ty)
            })
    }

    fn bind_type_vars_from_expected_return(
        pattern: &SymbolType,
        expected: &SymbolType,
        bindings: &mut HashMap<String, SymbolType>,
    ) {
        match (pattern, expected) {
            (SymbolType::TypeVar(name), expected) if *expected != SymbolType::Unknown => {
                bindings
                    .entry(name.clone())
                    .or_insert_with(|| expected.clone());
            }
            (SymbolType::Secret(pattern_inner), SymbolType::Secret(expected_inner))
            | (SymbolType::List(pattern_inner), SymbolType::List(expected_inner)) => {
                Self::bind_type_vars_from_expected_return(pattern_inner, expected_inner, bindings);
            }
            (
                SymbolType::Dict(pattern_key, pattern_value),
                SymbolType::Dict(expected_key, expected_value),
            ) => {
                Self::bind_type_vars_from_expected_return(pattern_key, expected_key, bindings);
                Self::bind_type_vars_from_expected_return(pattern_value, expected_value, bindings);
            }
            (
                SymbolType::Generic(pattern_name, pattern_params),
                SymbolType::Generic(expected_name, expected_params),
            ) if pattern_name == expected_name && pattern_params.len() == expected_params.len() => {
                for (pattern_param, expected_param) in pattern_params.iter().zip(expected_params) {
                    Self::bind_type_vars_from_expected_return(
                        pattern_param,
                        expected_param,
                        bindings,
                    );
                }
            }
            _ => {}
        }
    }

    fn call_signature_and_return(
        &self,
        function: &AstNode,
        arguments: &[AstNode],
    ) -> Option<(String, Vec<CallParameterInfo>, SymbolType)> {
        let (function_name, params, return_type, is_builtin) = match function {
            AstNode::Identifier(name, _) => {
                if let Some((object_name, method_name)) = name
                    .split_once('.')
                    .filter(|_| !self.imported_symbols.contains_key(name))
                {
                    let method = self
                        .symbol_table
                        .lookup_builtin_method(object_name, method_name)?;
                    let call_name = if crate::builtin_registry::builtin_registry()
                        .is_receiver_bound_method(object_name, method_name)
                    {
                        method_name.to_string()
                    } else {
                        name.clone()
                    };
                    (
                        call_name,
                        method.parameters.clone(),
                        method.return_type.clone(),
                        true,
                    )
                } else if let Some(info) = self.symbol_table.lookup_symbol(name) {
                    match &info.kind {
                        SymbolKind::Function {
                            parameters,
                            return_type,
                        } => (name.clone(), parameters.clone(), return_type.clone(), false),
                        SymbolKind::BuiltinFunction {
                            parameters,
                            return_type,
                        } => (name.clone(), parameters.clone(), return_type.clone(), true),
                        _ => return None,
                    }
                } else {
                    let first_arg = arguments.first()?;
                    let receiver_type = self.inference_expr_type(first_arg, &HashMap::new());
                    let method = self
                        .symbol_table
                        .lookup_builtin_method_for_receiver(&receiver_type, name)?;
                    (
                        name.clone(),
                        method.parameters.clone(),
                        method.return_type.clone(),
                        true,
                    )
                }
            }
            AstNode::FieldAccess {
                object, field_name, ..
            } => {
                let AstNode::Identifier(object_name, _) = object.as_ref() else {
                    return None;
                };
                let qualified_name = format!("{}.{}", object_name, field_name);
                let info = self.symbol_table.lookup_symbol(&qualified_name)?;
                match &info.kind {
                    SymbolKind::Function {
                        parameters,
                        return_type,
                    } => (
                        qualified_name,
                        parameters.clone(),
                        return_type.clone(),
                        false,
                    ),
                    SymbolKind::BuiltinFunction {
                        parameters,
                        return_type,
                    } => (
                        qualified_name,
                        parameters.clone(),
                        return_type.clone(),
                        true,
                    ),
                    _ => return None,
                }
            }
            _ => return None,
        };

        let call_parameters = self.builtin_call_parameters(&function_name, &params, is_builtin);
        Some((function_name, call_parameters, return_type))
    }

    fn contextualize_expression_with_expected(
        &self,
        expr: AstNode,
        expected_type: &SymbolType,
    ) -> AstNode {
        if *expected_type == SymbolType::Unknown {
            return expr;
        }

        match expr {
            AstNode::FunctionCall {
                function,
                arguments,
                location,
                resolved_return_type,
            } => {
                let mut arguments = arguments;
                if let Some((_function_name, call_parameters, return_type)) =
                    self.call_signature_and_return(&function, &arguments)
                {
                    let mut bindings = HashMap::new();
                    Self::bind_type_vars_from_expected_return(
                        &return_type,
                        expected_type,
                        &mut bindings,
                    );
                    if !bindings.is_empty() {
                        for (idx, argument) in arguments.iter_mut().enumerate() {
                            if let Some(parameter_type) =
                                Self::expected_argument_type_for_index(&call_parameters, idx)
                            {
                                let expected_argument_type =
                                    Self::substitute_type_vars(parameter_type, &bindings);
                                if !Self::contains_type_var(&expected_argument_type) {
                                    let contextualized = self
                                        .contextualize_expression_with_expected(
                                            argument.clone(),
                                            &expected_argument_type,
                                        );
                                    let (refined, _) = Self::refine_expression_type_with_expected(
                                        contextualized,
                                        &SymbolType::Unknown,
                                        &expected_argument_type,
                                    );
                                    *argument = refined;
                                }
                            }
                        }
                    }
                }

                let (refined, _) = Self::refine_expression_type_with_expected(
                    AstNode::FunctionCall {
                        function,
                        arguments,
                        location,
                        resolved_return_type,
                    },
                    &SymbolType::Unknown,
                    expected_type,
                );
                refined
            }
            AstNode::CommandCall {
                command,
                arguments,
                location,
                resolved_return_type,
            } => {
                let mut arguments = arguments;
                if let Some((_function_name, call_parameters, return_type)) =
                    self.call_signature_and_return(&command, &arguments)
                {
                    let mut bindings = HashMap::new();
                    Self::bind_type_vars_from_expected_return(
                        &return_type,
                        expected_type,
                        &mut bindings,
                    );
                    if !bindings.is_empty() {
                        for (idx, argument) in arguments.iter_mut().enumerate() {
                            if let Some(parameter_type) =
                                Self::expected_argument_type_for_index(&call_parameters, idx)
                            {
                                let expected_argument_type =
                                    Self::substitute_type_vars(parameter_type, &bindings);
                                if !Self::contains_type_var(&expected_argument_type) {
                                    let contextualized = self
                                        .contextualize_expression_with_expected(
                                            argument.clone(),
                                            &expected_argument_type,
                                        );
                                    let (refined, _) = Self::refine_expression_type_with_expected(
                                        contextualized,
                                        &SymbolType::Unknown,
                                        &expected_argument_type,
                                    );
                                    *argument = refined;
                                }
                            }
                        }
                    }
                }

                let (refined, _) = Self::refine_expression_type_with_expected(
                    AstNode::CommandCall {
                        command,
                        arguments,
                        location,
                        resolved_return_type,
                    },
                    &SymbolType::Unknown,
                    expected_type,
                );
                refined
            }
            AstNode::ListLiteral { elements, location } => {
                let elements = if let SymbolType::List(element_type) = expected_type {
                    elements
                        .into_iter()
                        .map(|element| {
                            self.contextualize_expression_with_expected(element, element_type)
                        })
                        .collect()
                } else {
                    elements
                };
                AstNode::ListLiteral { elements, location }
            }
            AstNode::DictLiteral { pairs, location } => {
                let pairs = if let SymbolType::Dict(key_type, value_type) = expected_type {
                    pairs
                        .into_iter()
                        .map(|(key, value)| {
                            (
                                self.contextualize_expression_with_expected(key, key_type),
                                self.contextualize_expression_with_expected(value, value_type),
                            )
                        })
                        .collect()
                } else {
                    pairs
                };
                AstNode::DictLiteral { pairs, location }
            }
            AstNode::UnaryOperation {
                op,
                operand,
                location,
            } if (op == "-"
                && Self::is_clear_numeric_type(expected_type.underlying_type())
                && !matches!(
                    expected_type.underlying_type(),
                    SymbolType::UInt8
                        | SymbolType::UInt16
                        | SymbolType::UInt32
                        | SymbolType::UInt64
                ))
                || (op == "not" && Self::is_clear_primitive_type(expected_type)) =>
            {
                let operand = self.contextualize_expression_with_expected(*operand, expected_type);
                let (operand, _) = Self::refine_expression_type_with_expected(
                    operand,
                    &SymbolType::Unknown,
                    expected_type,
                );
                AstNode::UnaryOperation {
                    op,
                    operand: Box::new(operand),
                    location,
                }
            }
            AstNode::BinaryOperation {
                op,
                left,
                right,
                location,
            } if Self::binary_operand_context_type(&op, expected_type).is_some() => {
                let operand_expected =
                    Self::binary_operand_context_type(&op, expected_type).unwrap_or(expected_type);
                let left = self.contextualize_expression_with_expected(*left, operand_expected);
                let right = self.contextualize_expression_with_expected(*right, operand_expected);
                let (left, _) = Self::refine_expression_type_with_expected(
                    left,
                    &SymbolType::Unknown,
                    operand_expected,
                );
                let (right, _) = Self::refine_expression_type_with_expected(
                    right,
                    &SymbolType::Unknown,
                    operand_expected,
                );

                AstNode::BinaryOperation {
                    op,
                    left: Box::new(left),
                    right: Box::new(right),
                    location,
                }
            }
            other => other,
        }
    }

    fn is_typed_assignment_target(node: &AstNode) -> bool {
        matches!(
            node,
            AstNode::Identifier(_, _) | AstNode::FieldAccess { .. } | AstNode::IndexAccess { .. }
        )
    }

    fn share_expr_can_initialize_secret(expr: Option<&AstNode>, dst: &SymbolType) -> bool {
        let Some(AstNode::FunctionCall { function, .. }) = expr else {
            return false;
        };
        let AstNode::Identifier(name, _) = function.as_ref() else {
            return false;
        };

        match name.as_str() {
            "Share.random" => Self::share_random_expected_type(dst),
            "ClientStore.take_share"
            | "Share.from_clear"
            | "Share.from_clear_int"
            | "Share.from_clear_uint" => dst.is_secret() && dst.is_integer(),
            "ClientStore.take_share_fixed" | "Share.from_clear_fixed" => matches!(
                dst,
                SymbolType::Secret(inner)
                    if matches!(inner.underlying_type(), SymbolType::Fixed { .. })
            ),
            _ => false,
        }
    }

    fn share_random_expected_type(ty: &SymbolType) -> bool {
        ty.is_secret() && (ty.is_integer() || ty.underlying_type() == &SymbolType::Bool)
    }

    fn is_unrefined_share_random_call(node: &AstNode) -> bool {
        matches!(
            node,
            AstNode::FunctionCall {
                function,
                resolved_return_type,
                ..
            } if matches!(function.as_ref(), AstNode::Identifier(name, _) if name == "Share.random")
                && !resolved_return_type
                    .as_ref()
                    .is_some_and(Self::share_random_expected_type)
        )
    }

    fn contains_unrefined_share_random_call(node: &AstNode) -> bool {
        if Self::is_unrefined_share_random_call(node) {
            return true;
        }
        match node {
            AstNode::FunctionCall { arguments, .. } | AstNode::CommandCall { arguments, .. } => {
                arguments
                    .iter()
                    .any(Self::contains_unrefined_share_random_call)
            }
            AstNode::NamedArgument { value, .. } => {
                Self::contains_unrefined_share_random_call(value)
            }
            AstNode::ListLiteral { elements, .. }
            | AstNode::TupleLiteral(elements)
            | AstNode::SetLiteral(elements) => elements
                .iter()
                .any(Self::contains_unrefined_share_random_call),
            AstNode::DictLiteral { pairs, .. } => pairs.iter().any(|(key, value)| {
                Self::contains_unrefined_share_random_call(key)
                    || Self::contains_unrefined_share_random_call(value)
            }),
            AstNode::Assignment { target, value, .. } => {
                Self::contains_unrefined_share_random_call(target)
                    || Self::contains_unrefined_share_random_call(value)
            }
            AstNode::VariableDeclaration { value, .. } | AstNode::Return { value, .. } => value
                .as_deref()
                .is_some_and(Self::contains_unrefined_share_random_call),
            AstNode::BinaryOperation { left, right, .. } => {
                Self::contains_unrefined_share_random_call(left)
                    || Self::contains_unrefined_share_random_call(right)
            }
            AstNode::UnaryOperation { operand, .. } => {
                Self::contains_unrefined_share_random_call(operand)
            }
            AstNode::IfExpression {
                condition,
                then_branch,
                else_branch,
            } => {
                Self::contains_unrefined_share_random_call(condition)
                    || Self::contains_unrefined_share_random_call(then_branch)
                    || else_branch
                        .as_deref()
                        .is_some_and(Self::contains_unrefined_share_random_call)
            }
            AstNode::WhileLoop {
                condition, body, ..
            } => {
                Self::contains_unrefined_share_random_call(condition)
                    || Self::contains_unrefined_share_random_call(body)
            }
            AstNode::Block(statements) => statements
                .iter()
                .any(Self::contains_unrefined_share_random_call),
            AstNode::FieldAccess { object, .. } => {
                Self::contains_unrefined_share_random_call(object)
            }
            AstNode::IndexAccess { base, index, .. } => {
                Self::contains_unrefined_share_random_call(base)
                    || Self::contains_unrefined_share_random_call(index)
            }
            _ => false,
        }
    }

    fn requires_explicit_reveal(src: &SymbolType, dst: &SymbolType) -> bool {
        matches!(src, SymbolType::Secret(_))
            && !matches!(dst, SymbolType::Secret(_) | SymbolType::Unknown)
            && !Self::is_share_alias_type(dst)
    }

    fn substitute_type_vars(ty: &SymbolType, bindings: &HashMap<String, SymbolType>) -> SymbolType {
        match ty {
            SymbolType::TypeVar(name) => bindings.get(name).cloned().unwrap_or(SymbolType::Unknown),
            SymbolType::Secret(inner) => {
                SymbolType::Secret(Box::new(Self::substitute_type_vars(inner, bindings)))
            }
            SymbolType::List(elem) => {
                SymbolType::List(Box::new(Self::substitute_type_vars(elem, bindings)))
            }
            SymbolType::Dict(key, value) => SymbolType::Dict(
                Box::new(Self::substitute_type_vars(key, bindings)),
                Box::new(Self::substitute_type_vars(value, bindings)),
            ),
            SymbolType::Generic(name, params) => SymbolType::Generic(
                name.clone(),
                params
                    .iter()
                    .map(|param| Self::substitute_type_vars(param, bindings))
                    .collect(),
            ),
            _ => ty.clone(),
        }
    }

    fn refine_type_with_expected(inferred: &SymbolType, expected: &SymbolType) -> SymbolType {
        match (inferred, expected) {
            (SymbolType::Unknown, expected) | (SymbolType::TypeVar(_), expected) => {
                expected.clone()
            }
            (SymbolType::List(inferred_elem), SymbolType::List(expected_elem)) => {
                SymbolType::List(Box::new(Self::refine_type_with_expected(
                    inferred_elem,
                    expected_elem,
                )))
            }
            (
                SymbolType::Dict(inferred_key, inferred_value),
                SymbolType::Dict(expected_key, expected_value),
            ) => SymbolType::Dict(
                Box::new(Self::refine_type_with_expected(inferred_key, expected_key)),
                Box::new(Self::refine_type_with_expected(
                    inferred_value,
                    expected_value,
                )),
            ),
            (SymbolType::Secret(inferred_inner), SymbolType::Secret(expected_inner)) => {
                SymbolType::Secret(Box::new(Self::refine_type_with_expected(
                    inferred_inner,
                    expected_inner,
                )))
            }
            (inferred, expected) if inferred.is_integer() && Self::is_clear_real_type(expected) => {
                expected.clone()
            }
            (
                SymbolType::Generic(inferred_name, inferred_params),
                SymbolType::Generic(expected_name, expected_params),
            ) if inferred_name == expected_name
                && inferred_params.len() == expected_params.len() =>
            {
                SymbolType::Generic(
                    inferred_name.clone(),
                    inferred_params
                        .iter()
                        .zip(expected_params.iter())
                        .map(|(inferred, expected)| {
                            Self::refine_type_with_expected(inferred, expected)
                        })
                        .collect(),
                )
            }
            _ => inferred.clone(),
        }
    }

    fn refine_expression_type_with_expected(
        expr: AstNode,
        inferred_type: &SymbolType,
        expected_type: &SymbolType,
    ) -> (AstNode, SymbolType) {
        let refined_type = match (&expr, inferred_type, expected_type) {
            (AstNode::Literal { .. }, _, expected)
                if expected.underlying_type() == &SymbolType::Bool
                    && Self::int_literal_bool_value(&expr).is_some() =>
            {
                expected.clone()
            }
            (AstNode::Literal { .. }, inferred, expected)
                if inferred.is_integer()
                    && Self::is_clear_real_type(expected)
                    && Self::int_literal_value(&expr).is_some() =>
            {
                expected.clone()
            }
            (node, inferred, expected)
                if inferred.is_integer()
                    && expected.underlying_type().is_integer()
                    && Self::is_untyped_int_literal(node) =>
            {
                expected.clone()
            }
            (
                AstNode::Literal {
                    value: Value::Float(_),
                    ..
                },
                _,
                expected,
            ) if Self::is_clear_real_type(expected) => expected.clone(),
            (AstNode::UnaryOperation { op, .. }, inferred, expected)
                if op == "-"
                    && Self::is_clear_numeric_type(inferred)
                    && Self::is_clear_numeric_type(expected)
                    && !matches!(
                        expected.underlying_type(),
                        SymbolType::UInt8
                            | SymbolType::UInt16
                            | SymbolType::UInt32
                            | SymbolType::UInt64
                    ) =>
            {
                expected.clone()
            }
            (AstNode::UnaryOperation { op, .. }, inferred, expected)
                if op == "not"
                    && Self::is_clear_primitive_type(inferred)
                    && Self::is_clear_primitive_type(expected) =>
            {
                expected.clone()
            }
            (AstNode::BinaryOperation { op, .. }, inferred, expected)
                if Self::binary_operand_context_type(op, expected).is_some()
                    && Self::is_clear_primitive_type(inferred) =>
            {
                expected.clone()
            }
            (AstNode::ListLiteral { .. }, inferred, expected)
                if matches!(expected.underlying_type(), SymbolType::List(_))
                    && (Self::types_compatible(inferred, expected)
                        || Self::expression_can_refine_to_expected(&expr, expected)) =>
            {
                expected.clone()
            }
            (AstNode::DictLiteral { .. }, inferred, expected)
                if matches!(expected.underlying_type(), SymbolType::Dict(_, _))
                    && (Self::types_compatible(inferred, expected)
                        || Self::expression_can_refine_to_expected(&expr, expected)) =>
            {
                expected.clone()
            }
            (AstNode::FunctionCall { function, .. }, inferred, expected)
                if (Self::is_share_alias_type(inferred)
                    || matches!(function.as_ref(), AstNode::Identifier(name, _) if name == "Share.random"))
                    && Self::share_expr_can_initialize_secret(Some(&expr), expected) =>
            {
                expected.clone()
            }
            _ => Self::refine_type_with_expected(inferred_type, expected_type),
        };

        let refined_expr = match expr {
            // Fold a negated float literal into a single negative literal so
            // later phases see an ordinary literal of the refined type
            // (e.g. -1.5 inside a list[fix64] literal).
            AstNode::UnaryOperation {
                op,
                operand,
                location,
            } if op == "-"
                && matches!(
                    operand.as_ref(),
                    AstNode::Literal {
                        value: Value::Float(_),
                        ..
                    }
                ) =>
            {
                if let AstNode::Literal {
                    value: Value::Float(bits),
                    ..
                } = operand.as_ref()
                {
                    AstNode::Literal {
                        value: Value::Float((-f64::from_bits(*bits)).to_bits()),
                        location,
                    }
                } else {
                    unreachable!("guarded by matches! above")
                }
            }
            AstNode::FunctionCall {
                function,
                arguments,
                location,
                ..
            } => AstNode::FunctionCall {
                function,
                arguments,
                location,
                resolved_return_type: Some(refined_type.clone()),
            },
            AstNode::CommandCall {
                command,
                arguments,
                location,
                ..
            } => AstNode::CommandCall {
                command,
                arguments,
                location,
                resolved_return_type: Some(refined_type.clone()),
            },
            AstNode::ListLiteral { elements, location } => {
                let elements = if let SymbolType::List(expected_elem) = expected_type {
                    elements
                        .into_iter()
                        .map(|element| {
                            let (refined_element, _) = Self::refine_expression_type_with_expected(
                                element,
                                &SymbolType::Unknown,
                                expected_elem,
                            );
                            refined_element
                        })
                        .collect()
                } else {
                    elements
                };
                AstNode::ListLiteral { elements, location }
            }
            AstNode::DictLiteral { pairs, location } => {
                let pairs = if let SymbolType::Dict(expected_key, expected_value) = expected_type {
                    pairs
                        .into_iter()
                        .map(|(key, value)| {
                            let (refined_key, _) = Self::refine_expression_type_with_expected(
                                key,
                                &SymbolType::Unknown,
                                expected_key,
                            );
                            let (refined_value, _) = Self::refine_expression_type_with_expected(
                                value,
                                &SymbolType::Unknown,
                                expected_value,
                            );
                            (refined_key, refined_value)
                        })
                        .collect()
                } else {
                    pairs
                };
                AstNode::DictLiteral { pairs, location }
            }
            AstNode::UnaryOperation {
                op,
                operand,
                location,
            } if (op == "-"
                && Self::is_clear_numeric_type(expected_type.underlying_type())
                && !matches!(
                    expected_type.underlying_type(),
                    SymbolType::UInt8
                        | SymbolType::UInt16
                        | SymbolType::UInt32
                        | SymbolType::UInt64
                ))
                || (op == "not" && Self::is_clear_primitive_type(expected_type)) =>
            {
                let operand_inferred =
                    Self::refine_type_with_expected(inferred_type, expected_type);
                let (refined_operand, _) = Self::refine_expression_type_with_expected(
                    *operand,
                    &operand_inferred,
                    expected_type,
                );
                AstNode::UnaryOperation {
                    op,
                    operand: Box::new(refined_operand),
                    location,
                }
            }
            AstNode::BinaryOperation {
                op,
                left,
                right,
                location,
            } if Self::binary_operand_context_type(&op, expected_type).is_some() => {
                let operand_expected =
                    Self::binary_operand_context_type(&op, expected_type).unwrap_or(expected_type);
                let (refined_left, _) = Self::refine_expression_type_with_expected(
                    *left,
                    &SymbolType::Unknown,
                    operand_expected,
                );
                let (refined_right, _) = Self::refine_expression_type_with_expected(
                    *right,
                    &SymbolType::Unknown,
                    operand_expected,
                );
                AstNode::BinaryOperation {
                    op,
                    left: Box::new(refined_left),
                    right: Box::new(refined_right),
                    location,
                }
            }
            other if expected_type.underlying_type() == &SymbolType::Bool => {
                Self::bool_literal_from_int(other)
            }
            other if Self::is_clear_real_type(expected_type) => Self::float_literal_from_int(other),
            other if expected_type.underlying_type().is_integer() => {
                Self::sized_int_literal_from_int(other, expected_type)
            }
            other => other,
        };

        (refined_expr, refined_type)
    }

    fn contains_type_var(ty: &SymbolType) -> bool {
        match ty {
            SymbolType::TypeVar(_) => true,
            SymbolType::Secret(inner) | SymbolType::List(inner) => Self::contains_type_var(inner),
            SymbolType::Dict(key, value) => {
                Self::contains_type_var(key) || Self::contains_type_var(value)
            }
            SymbolType::Generic(_, params) => params.iter().any(Self::contains_type_var),
            _ => false,
        }
    }

    fn refine_argument_with_expected(
        argument: &mut AstNode,
        argument_type: &mut SymbolType,
        expected_type: &SymbolType,
    ) {
        if Self::contains_type_var(expected_type) {
            return;
        }
        let (refined_arg, refined_type) = Self::refine_expression_type_with_expected(
            argument.clone(),
            argument_type,
            expected_type,
        );
        *argument = refined_arg;
        *argument_type = refined_type;
    }

    fn type_annotation_for_inferred_type(
        ty: &SymbolType,
        location: SourceLocation,
    ) -> Option<AstNode> {
        match ty {
            SymbolType::Int64 => Some(AstNode::Identifier("int64".to_string(), location)),
            SymbolType::Int32 => Some(AstNode::Identifier("int32".to_string(), location)),
            SymbolType::Int16 => Some(AstNode::Identifier("int16".to_string(), location)),
            SymbolType::Int8 => Some(AstNode::Identifier("int8".to_string(), location)),
            SymbolType::UInt64 => Some(AstNode::Identifier("uint64".to_string(), location)),
            SymbolType::UInt32 => Some(AstNode::Identifier("uint32".to_string(), location)),
            SymbolType::UInt16 => Some(AstNode::Identifier("uint16".to_string(), location)),
            SymbolType::UInt8 => Some(AstNode::Identifier("uint8".to_string(), location)),
            SymbolType::Float => Some(AstNode::Identifier("float".to_string(), location)),
            SymbolType::Fixed { bits } => {
                Some(AstNode::Identifier(format!("fixed{bits}"), location))
            }
            SymbolType::String => Some(AstNode::Identifier("string".to_string(), location)),
            SymbolType::Bool => Some(AstNode::Identifier("bool".to_string(), location)),
            SymbolType::Nil => Some(AstNode::Identifier("None".to_string(), location)),
            SymbolType::Void | SymbolType::Unknown | SymbolType::TypeVar(_) => None,
            SymbolType::Secret(inner) => Self::type_annotation_for_inferred_type(inner, location)
                .map(|inner| AstNode::SecretType(Box::new(inner))),
            SymbolType::List(elem) => Self::type_annotation_for_inferred_type(elem, location)
                .map(|elem| AstNode::ListType(Box::new(elem))),
            SymbolType::Dict(key, value) => {
                let key_type = Self::type_annotation_for_inferred_type(key, location.clone())?;
                let value_type = Self::type_annotation_for_inferred_type(value, location.clone())?;
                Some(AstNode::DictType {
                    key_type: Box::new(key_type),
                    value_type: Box::new(value_type),
                    location,
                })
            }
            SymbolType::TypeName(name) | SymbolType::Object(name) => {
                Some(AstNode::Identifier(name.clone(), location))
            }
            SymbolType::Generic(name, params) => {
                let mut type_params = Vec::with_capacity(params.len());
                for param in params {
                    type_params.push(Self::type_annotation_for_inferred_type(
                        param,
                        location.clone(),
                    )?);
                }
                Some(AstNode::GenericType {
                    base_name: name.clone(),
                    type_params,
                    location,
                })
            }
        }
    }

    fn is_concrete_inference_type(ty: &SymbolType) -> bool {
        !matches!(
            ty,
            SymbolType::Unknown | SymbolType::Void | SymbolType::TypeVar(_)
        ) && !Self::contains_type_var(ty)
    }

    fn weak_literal_type(node: &AstNode, ty: &SymbolType) -> bool {
        Self::is_untyped_int_literal(node)
            || matches!(ty, SymbolType::Unknown)
            || matches!(node, AstNode::ListLiteral { elements, .. } if elements.is_empty())
            || matches!(node, AstNode::DictLiteral { pairs, .. } if pairs.is_empty())
    }

    fn add_inference_constraint(
        locals: &mut HashMap<String, LocalInference>,
        name: &str,
        ty: SymbolType,
        location: SourceLocation,
        reason: impl Into<String>,
    ) -> bool {
        if !Self::is_concrete_inference_type(&ty) {
            return false;
        }
        let Some(local) = locals.get_mut(name) else {
            return false;
        };
        if local.explicit {
            return false;
        }
        let reason = reason.into();
        if local
            .constraints
            .iter()
            .any(|constraint| constraint.ty == ty && constraint.reason == reason)
        {
            return false;
        }
        local.constraints.push(InferenceConstraint {
            ty,
            location,
            reason,
        });
        true
    }

    fn resolved_local_types(
        &mut self,
        locals: &HashMap<String, LocalInference>,
    ) -> Result<HashMap<String, SymbolType>, ()> {
        let mut resolved = HashMap::new();
        for (name, local) in locals {
            if local.explicit {
                continue;
            }
            let mut chosen: Option<&InferenceConstraint> = None;
            for constraint in &local.constraints {
                let Some(previous) = chosen else {
                    chosen = Some(constraint);
                    continue;
                };
                if previous.ty == constraint.ty
                    || Self::types_compatible(&constraint.ty, &previous.ty)
                {
                    continue;
                }
                // A secret share absorbs a clear numeric scalar: `secret * 2.5`
                // keeps the variable a share, with the MPC runtime handling the
                // mixed-type scalar op. So a share/secret constraint wins over a
                // clear-numeric one rather than conflicting (in either order).
                let prev_share = Self::is_share_alias_type(&previous.ty) || previous.ty.is_secret();
                let cur_share =
                    Self::is_share_alias_type(&constraint.ty) || constraint.ty.is_secret();
                let prev_num = Self::is_clear_numeric_type(previous.ty.underlying_type());
                let cur_num = Self::is_clear_numeric_type(constraint.ty.underlying_type());
                if prev_share && cur_num && !cur_share {
                    continue;
                }
                if cur_share && prev_num && !prev_share {
                    chosen = Some(constraint);
                    continue;
                }
                self.error_reporter.add_error(
                    CompilerError::type_error(
                        format!(
                            "Cannot infer a single type for variable '{}': {} requires '{}', but {} requires '{}'",
                            name,
                            previous.reason,
                            declared_type_to_string(&previous.ty),
                            constraint.reason,
                            declared_type_to_string(&constraint.ty)
                        ),
                        constraint.location.clone(),
                    )
                    .with_hint(format!(
                        "Add an explicit type annotation to '{}' to choose the intended type; declaration is at {}",
                        name, local.location
                    )),
                );
                return Err(());
            }
            if let Some(chosen) = chosen {
                resolved.insert(name.clone(), chosen.ty.clone());
            }
        }
        Ok(resolved)
    }

    fn infer_function_body_types(
        &mut self,
        body: AstNode,
        return_type: &SymbolType,
    ) -> Result<AstNode, ()> {
        let mut locals = HashMap::new();
        Self::collect_local_declarations(&body, &mut locals);

        let mut env = HashMap::new();
        for (name, local) in &locals {
            if local.explicit {
                if let Some(constraint) = local.constraints.first() {
                    env.insert(name.clone(), constraint.ty.clone());
                }
            }
        }

        let mut changed = true;
        while changed {
            changed = false;
            let resolved = self.resolved_local_types(&locals)?;
            for (name, ty) in resolved {
                if env.get(&name) != Some(&ty) {
                    env.insert(name, ty);
                    changed = true;
                }
            }
            changed |= self.collect_inference_constraints(&body, return_type, &env, &mut locals);
        }

        let resolved = self.resolved_local_types(&locals)?;
        Ok(Self::apply_inferred_types(body, &resolved))
    }

    fn collect_local_declarations(node: &AstNode, locals: &mut HashMap<String, LocalInference>) {
        match node {
            AstNode::VariableDeclaration {
                name,
                type_annotation,
                location,
                ..
            } => {
                let mut constraints = Vec::new();
                if let Some(annotation) = type_annotation {
                    constraints.push(InferenceConstraint {
                        ty: SymbolType::from_ast(annotation),
                        location: annotation.location(),
                        reason: "explicit annotation".to_string(),
                    });
                }
                locals.entry(name.clone()).or_insert(LocalInference {
                    location: location.clone(),
                    explicit: type_annotation.is_some(),
                    constraints,
                });
            }
            AstNode::Block(statements)
            | AstNode::TupleLiteral(statements)
            | AstNode::SetLiteral(statements) => {
                for stmt in statements {
                    Self::collect_local_declarations(stmt, locals);
                }
            }
            AstNode::IfExpression {
                condition,
                then_branch,
                else_branch,
            } => {
                Self::collect_local_declarations(condition, locals);
                Self::collect_local_declarations(then_branch, locals);
                if let Some(else_branch) = else_branch {
                    Self::collect_local_declarations(else_branch, locals);
                }
            }
            AstNode::WhileLoop {
                condition, body, ..
            } => {
                Self::collect_local_declarations(condition, locals);
                Self::collect_local_declarations(body, locals);
            }
            AstNode::ForLoop { iterable, body, .. } => {
                Self::collect_local_declarations(iterable, locals);
                Self::collect_local_declarations(body, locals);
            }
            AstNode::Assignment { target, value, .. } => {
                Self::collect_local_declarations(target, locals);
                Self::collect_local_declarations(value, locals);
            }
            AstNode::Return { value, .. } | AstNode::Yield(value) => {
                if let Some(value) = value {
                    Self::collect_local_declarations(value, locals);
                }
            }
            AstNode::BinaryOperation { left, right, .. } => {
                Self::collect_local_declarations(left, locals);
                Self::collect_local_declarations(right, locals);
            }
            AstNode::UnaryOperation { operand, .. } => {
                Self::collect_local_declarations(operand, locals);
            }
            AstNode::FunctionCall {
                function,
                arguments,
                ..
            } => {
                Self::collect_local_declarations(function, locals);
                for arg in arguments {
                    Self::collect_local_declarations(arg, locals);
                }
            }
            AstNode::NamedArgument { value, .. } => {
                Self::collect_local_declarations(value, locals);
            }
            AstNode::DiscardStatement { expression, .. } => {
                Self::collect_local_declarations(expression, locals);
            }
            AstNode::CommandCall {
                command, arguments, ..
            } => {
                Self::collect_local_declarations(command, locals);
                for arg in arguments {
                    Self::collect_local_declarations(arg, locals);
                }
            }
            AstNode::FieldAccess { object, .. } => {
                Self::collect_local_declarations(object, locals);
            }
            AstNode::IndexAccess { base, index, .. } => {
                Self::collect_local_declarations(base, locals);
                Self::collect_local_declarations(index, locals);
            }
            AstNode::ListLiteral { elements, .. } => {
                for element in elements {
                    Self::collect_local_declarations(element, locals);
                }
            }
            AstNode::DictLiteral { pairs, .. } => {
                for (key, value) in pairs {
                    Self::collect_local_declarations(key, locals);
                    Self::collect_local_declarations(value, locals);
                }
            }
            AstNode::FunctionDefinition { .. } => {}
            _ => {}
        }
    }

    fn collect_inference_constraints(
        &self,
        node: &AstNode,
        return_type: &SymbolType,
        env: &HashMap<String, SymbolType>,
        locals: &mut HashMap<String, LocalInference>,
    ) -> bool {
        let mut changed = false;
        match node {
            AstNode::VariableDeclaration {
                name,
                type_annotation,
                value,
                location,
                is_secret,
                ..
            } => {
                if let Some(value) = value.as_deref() {
                    let value_type = self.inference_expr_type(value, env);
                    if let Some(annotation) = type_annotation {
                        let mut expected =
                            self.resolve_type_aliases(&SymbolType::from_ast(annotation));
                        if expected.is_secret() || *is_secret {
                            expected = expected.with_secret_modifier();
                        }
                        changed |= self.apply_expected_inference(
                            value,
                            &expected,
                            value.location(),
                            format!("initializer for '{}'", name),
                            env,
                            locals,
                        );
                    } else if !Self::weak_literal_type(value, &value_type)
                        && Self::is_concrete_inference_type(&value_type)
                    {
                        let mut inferred = value_type;
                        if inferred.is_secret() || *is_secret {
                            inferred = inferred.with_secret_modifier();
                        }
                        changed |= Self::add_inference_constraint(
                            locals,
                            name,
                            inferred,
                            location.clone(),
                            "initializer",
                        );
                    }
                    changed |= self.collect_inference_constraints(value, return_type, env, locals);
                }
            }
            AstNode::Assignment {
                target,
                value,
                location,
            } => {
                let target_type = self.inference_expr_type(target, env);
                let value_type = self.inference_expr_type(value, env);
                if Self::is_concrete_inference_type(&target_type) {
                    changed |= self.apply_expected_inference(
                        value,
                        &target_type,
                        location.clone(),
                        "assignment target".to_string(),
                        env,
                        locals,
                    );
                }
                if Self::is_concrete_inference_type(&value_type) {
                    changed |= self.apply_expected_inference(
                        target,
                        &value_type,
                        location.clone(),
                        "assigned value".to_string(),
                        env,
                        locals,
                    );
                }
                changed |= self.collect_inference_constraints(target, return_type, env, locals);
                changed |= self.collect_inference_constraints(value, return_type, env, locals);
            }
            AstNode::Return { value, location } => {
                if let Some(value) = value.as_deref() {
                    let expected = match return_type {
                        SymbolType::Secret(inner) => inner.as_ref(),
                        _ => return_type,
                    };
                    changed |= self.apply_expected_inference(
                        value,
                        expected,
                        location.clone(),
                        "function return type".to_string(),
                        env,
                        locals,
                    );
                    changed |= self.collect_inference_constraints(value, return_type, env, locals);
                }
            }
            AstNode::BinaryOperation {
                op,
                left,
                right,
                location,
            } => {
                let left_type = self.inference_expr_type(left, env);
                let right_type = self.inference_expr_type(right, env);
                if op == "in" {
                    match right_type.underlying_type() {
                        SymbolType::List(element_type) => {
                            changed |= self.apply_expected_inference(
                                left,
                                element_type,
                                location.clone(),
                                "membership element type".to_string(),
                                env,
                                locals,
                            );
                        }
                        SymbolType::Dict(key_type, _) => {
                            changed |= self.apply_expected_inference(
                                left,
                                key_type,
                                location.clone(),
                                "membership key type".to_string(),
                                env,
                                locals,
                            );
                        }
                        SymbolType::String => {
                            changed |= self.apply_expected_inference(
                                left,
                                &SymbolType::String,
                                location.clone(),
                                "string membership value".to_string(),
                                env,
                                locals,
                            );
                        }
                        _ => {}
                    }
                }
                if matches!(
                    op.as_str(),
                    "+" | "-"
                        | "*"
                        | "/"
                        | "%"
                        | "mod"
                        | "shl"
                        | "shr"
                        | "and"
                        | "or"
                        | "xor"
                        | "=="
                        | "!="
                        | "<"
                        | "<="
                        | ">"
                        | ">="
                ) {
                    // Don't propagate a clear numeric type across the operator onto
                    // a share/secret operand: a secret share multiplied by a
                    // fixed-point/float scalar (e.g. `secret * 2.5`) keeps the share
                    // typed as a share — the MPC runtime handles the mixed-type
                    // scalar op — so forcing it to `float` here would wrongly
                    // conflict with its share type.
                    let right_is_share =
                        Self::is_share_alias_type(&right_type) || right_type.is_secret();
                    let left_is_share =
                        Self::is_share_alias_type(&left_type) || left_type.is_secret();
                    if !right_is_share
                        && Self::is_concrete_inference_type(&left_type)
                        && (Self::is_clear_numeric_type(left_type.underlying_type())
                            || matches!(
                                left_type.underlying_type(),
                                SymbolType::Bool | SymbolType::String
                            ))
                    {
                        changed |= self.apply_expected_inference(
                            right,
                            left_type.underlying_type(),
                            location.clone(),
                            format!("left operand of '{}'", op),
                            env,
                            locals,
                        );
                    }
                    if !left_is_share
                        && Self::is_concrete_inference_type(&right_type)
                        && (Self::is_clear_numeric_type(right_type.underlying_type())
                            || matches!(
                                right_type.underlying_type(),
                                SymbolType::Bool | SymbolType::String
                            ))
                    {
                        changed |= self.apply_expected_inference(
                            left,
                            right_type.underlying_type(),
                            location.clone(),
                            format!("right operand of '{}'", op),
                            env,
                            locals,
                        );
                    }
                }
                changed |= self.collect_inference_constraints(left, return_type, env, locals);
                changed |= self.collect_inference_constraints(right, return_type, env, locals);
            }
            AstNode::UnaryOperation {
                op,
                operand,
                location,
            } => {
                if op == "not" {
                    changed |= self.apply_expected_inference(
                        operand,
                        &SymbolType::Bool,
                        location.clone(),
                        "operand of 'not'".to_string(),
                        env,
                        locals,
                    );
                }
                changed |= self.collect_inference_constraints(operand, return_type, env, locals);
            }
            AstNode::FunctionCall {
                function,
                arguments,
                location,
                ..
            } => {
                if let Some((function_name, params, is_builtin)) =
                    self.inference_call_signature(function, arguments, env)
                {
                    let call_parameters =
                        self.builtin_call_parameters(&function_name, &params, is_builtin);
                    for (idx, arg) in arguments.iter().enumerate() {
                        if let Some(expected) =
                            Self::expected_argument_type_for_index(&call_parameters, idx)
                        {
                            changed |= self.apply_expected_inference(
                                arg,
                                expected,
                                arg.location(),
                                format!("argument {} of '{}'", idx + 1, function_name),
                                env,
                                locals,
                            );
                        }
                    }
                } else {
                    changed |=
                        self.collect_inference_constraints(function, return_type, env, locals);
                }
                for arg in arguments {
                    changed |= self.collect_inference_constraints(arg, return_type, env, locals);
                }
                let _ = location;
            }
            AstNode::CommandCall {
                command, arguments, ..
            } => {
                if let Some((function_name, params, is_builtin)) =
                    self.inference_call_signature(command, arguments, env)
                {
                    let call_parameters =
                        self.builtin_call_parameters(&function_name, &params, is_builtin);
                    for (idx, arg) in arguments.iter().enumerate() {
                        if let Some(expected) =
                            Self::expected_argument_type_for_index(&call_parameters, idx)
                        {
                            changed |= self.apply_expected_inference(
                                arg,
                                expected,
                                arg.location(),
                                format!("argument {} of '{}'", idx + 1, function_name),
                                env,
                                locals,
                            );
                        }
                    }
                } else {
                    changed |=
                        self.collect_inference_constraints(command, return_type, env, locals);
                }
                for arg in arguments {
                    changed |= self.collect_inference_constraints(arg, return_type, env, locals);
                }
            }
            AstNode::ListLiteral { elements, .. } => {
                let element_type = elements
                    .iter()
                    .map(|element| self.inference_expr_type(element, env))
                    .find(Self::is_concrete_inference_type);
                if let Some(element_type) = element_type {
                    for element in elements {
                        changed |= self.apply_expected_inference(
                            element,
                            &element_type,
                            element.location(),
                            "list element type".to_string(),
                            env,
                            locals,
                        );
                    }
                }
                for element in elements {
                    changed |=
                        self.collect_inference_constraints(element, return_type, env, locals);
                }
            }
            AstNode::DictLiteral { pairs, .. } => {
                let key_type = pairs
                    .iter()
                    .map(|(key, _)| self.inference_expr_type(key, env))
                    .find(Self::is_concrete_inference_type);
                let value_type = pairs
                    .iter()
                    .map(|(_, value)| self.inference_expr_type(value, env))
                    .find(Self::is_concrete_inference_type);
                for (key, value) in pairs {
                    if let Some(key_type) = &key_type {
                        changed |= self.apply_expected_inference(
                            key,
                            key_type,
                            key.location(),
                            "dict key type".to_string(),
                            env,
                            locals,
                        );
                    }
                    if let Some(value_type) = &value_type {
                        changed |= self.apply_expected_inference(
                            value,
                            value_type,
                            value.location(),
                            "dict value type".to_string(),
                            env,
                            locals,
                        );
                    }
                    changed |= self.collect_inference_constraints(key, return_type, env, locals);
                    changed |= self.collect_inference_constraints(value, return_type, env, locals);
                }
            }
            AstNode::IndexAccess { base, index, .. } => {
                let base_type = self.inference_expr_type(base, env);
                match base_type.underlying_type() {
                    SymbolType::List(_) | SymbolType::String => {
                        changed |= self.apply_expected_inference(
                            index,
                            &SymbolType::Int64,
                            index.location(),
                            "list/string index".to_string(),
                            env,
                            locals,
                        );
                    }
                    SymbolType::Dict(key, _) => {
                        changed |= self.apply_expected_inference(
                            index,
                            key,
                            index.location(),
                            "dict key type".to_string(),
                            env,
                            locals,
                        );
                    }
                    _ => {}
                }
                changed |= self.collect_inference_constraints(base, return_type, env, locals);
                changed |= self.collect_inference_constraints(index, return_type, env, locals);
            }
            AstNode::Block(statements)
            | AstNode::TupleLiteral(statements)
            | AstNode::SetLiteral(statements) => {
                for stmt in statements {
                    changed |= self.collect_inference_constraints(stmt, return_type, env, locals);
                }
            }
            AstNode::IfExpression {
                condition,
                then_branch,
                else_branch,
            } => {
                changed |= self.apply_expected_inference(
                    condition,
                    &SymbolType::Bool,
                    condition.location(),
                    "if condition".to_string(),
                    env,
                    locals,
                );
                changed |= self.collect_inference_constraints(condition, return_type, env, locals);
                changed |=
                    self.collect_inference_constraints(then_branch, return_type, env, locals);
                if let Some(else_branch) = else_branch {
                    changed |=
                        self.collect_inference_constraints(else_branch, return_type, env, locals);
                }
            }
            AstNode::WhileLoop {
                condition, body, ..
            } => {
                changed |= self.apply_expected_inference(
                    condition,
                    &SymbolType::Bool,
                    condition.location(),
                    "while condition".to_string(),
                    env,
                    locals,
                );
                changed |= self.collect_inference_constraints(condition, return_type, env, locals);
                changed |= self.collect_inference_constraints(body, return_type, env, locals);
            }
            AstNode::ForLoop { iterable, body, .. } => {
                changed |= self.collect_inference_constraints(iterable, return_type, env, locals);
                changed |= self.collect_inference_constraints(body, return_type, env, locals);
            }
            AstNode::NamedArgument { value, .. } => {
                changed |= self.collect_inference_constraints(value, return_type, env, locals);
            }
            AstNode::DiscardStatement { expression, .. } => {
                changed |= self.collect_inference_constraints(expression, return_type, env, locals);
            }
            AstNode::FieldAccess { object, .. } => {
                changed |= self.collect_inference_constraints(object, return_type, env, locals);
            }
            AstNode::FunctionDefinition { .. } => {}
            _ => {}
        }
        changed
    }

    fn apply_expected_inference(
        &self,
        expr: &AstNode,
        expected: &SymbolType,
        location: SourceLocation,
        reason: String,
        env: &HashMap<String, SymbolType>,
        locals: &mut HashMap<String, LocalInference>,
    ) -> bool {
        if !Self::is_concrete_inference_type(expected) || Self::contains_type_var(expected) {
            return false;
        }
        match expr {
            AstNode::Identifier(name, _) => {
                Self::add_inference_constraint(locals, name, expected.clone(), location, reason)
            }
            AstNode::ListLiteral { elements, .. } => {
                if let SymbolType::List(element_type) = expected.underlying_type() {
                    let mut changed = false;
                    for element in elements {
                        changed |= self.apply_expected_inference(
                            element,
                            element_type,
                            element.location(),
                            reason.clone(),
                            env,
                            locals,
                        );
                    }
                    changed
                } else {
                    false
                }
            }
            AstNode::DictLiteral { pairs, .. } => {
                if let SymbolType::Dict(key_type, value_type) = expected.underlying_type() {
                    let mut changed = false;
                    for (key, value) in pairs {
                        changed |= self.apply_expected_inference(
                            key,
                            key_type,
                            key.location(),
                            reason.clone(),
                            env,
                            locals,
                        );
                        changed |= self.apply_expected_inference(
                            value,
                            value_type,
                            value.location(),
                            reason.clone(),
                            env,
                            locals,
                        );
                    }
                    changed
                } else {
                    false
                }
            }
            AstNode::BinaryOperation {
                op,
                left,
                right,
                location,
            } if matches!(
                op.as_str(),
                "+" | "-" | "*" | "/" | "%" | "mod" | "shl" | "shr" | "and" | "or" | "xor"
            ) =>
            {
                let mut changed = false;
                changed |= self.apply_expected_inference(
                    left,
                    expected,
                    location.clone(),
                    reason.clone(),
                    env,
                    locals,
                );
                changed |= self.apply_expected_inference(
                    right,
                    expected,
                    location.clone(),
                    reason,
                    env,
                    locals,
                );
                changed
            }
            AstNode::UnaryOperation { op, operand, .. } if op == "-" || op == "not" => {
                self.apply_expected_inference(operand, expected, location, reason, env, locals)
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
                let mut changed = false;
                if let Some((function_name, params, is_builtin)) =
                    self.inference_call_signature(function, arguments, env)
                {
                    let call_parameters =
                        self.builtin_call_parameters(&function_name, &params, is_builtin);
                    for (idx, arg) in arguments.iter().enumerate() {
                        if let Some(expected) =
                            Self::expected_argument_type_for_index(&call_parameters, idx)
                        {
                            changed |= self.apply_expected_inference(
                                arg,
                                expected,
                                arg.location(),
                                format!("argument {} of '{}'", idx + 1, function_name),
                                env,
                                locals,
                            );
                        }
                    }
                }
                changed
            }
            _ => false,
        }
    }

    fn inference_expr_type(&self, expr: &AstNode, env: &HashMap<String, SymbolType>) -> SymbolType {
        match expr {
            AstNode::Literal { value, .. } => match value {
                Value::Int {
                    kind: Some(kind), ..
                } => match kind {
                    crate::ast::IntKind::Signed(width) => match width {
                        crate::ast::IntWidth::W8 => SymbolType::Int8,
                        crate::ast::IntWidth::W16 => SymbolType::Int16,
                        crate::ast::IntWidth::W32 => SymbolType::Int32,
                        crate::ast::IntWidth::W64 => SymbolType::Int64,
                    },
                    crate::ast::IntKind::Unsigned(width) => match width {
                        crate::ast::IntWidth::W8 => SymbolType::UInt8,
                        crate::ast::IntWidth::W16 => SymbolType::UInt16,
                        crate::ast::IntWidth::W32 => SymbolType::UInt32,
                        crate::ast::IntWidth::W64 => SymbolType::UInt64,
                    },
                },
                Value::Int { kind: None, .. } => SymbolType::Unknown,
                Value::Float(_) => SymbolType::Float,
                Value::String(_) => SymbolType::String,
                Value::Bool(_) => SymbolType::Bool,
                Value::Nil => SymbolType::Nil,
            },
            AstNode::Identifier(name, _)
                if self
                    .symbol_table
                    .lookup_symbol(name)
                    .is_some_and(|info| matches!(info.kind, SymbolKind::BuiltinObject { .. })) =>
            {
                SymbolType::Unknown
            }
            AstNode::Identifier(name, _) => env
                .get(name)
                .cloned()
                .or_else(|| {
                    self.symbol_table
                        .lookup_symbol(name)
                        .map(|info| info.symbol_type.clone())
                })
                .unwrap_or(SymbolType::Unknown),
            AstNode::VariableDeclaration {
                type_annotation,
                value,
                is_secret,
                ..
            } => {
                if let Some(annotation) = type_annotation {
                    let mut ty = self.resolve_type_aliases(&SymbolType::from_ast(annotation));
                    if ty.is_secret() || *is_secret {
                        ty = ty.with_secret_modifier();
                    }
                    ty
                } else {
                    value
                        .as_deref()
                        .map(|value| self.inference_expr_type(value, env))
                        .unwrap_or(SymbolType::Unknown)
                }
            }
            AstNode::UnaryOperation { op, operand, .. } => {
                if op == "not" {
                    SymbolType::Bool
                } else {
                    self.inference_expr_type(operand, env)
                }
            }
            AstNode::BinaryOperation {
                op, left, right, ..
            } => {
                let left_type = self.inference_expr_type(left, env);
                let right_type = self.inference_expr_type(right, env);
                if matches!(op.as_str(), "==" | "!=" | "<" | "<=" | ">" | ">=" | "in") {
                    return SymbolType::Bool;
                }
                if op == "*"
                    && (matches!(left_type.underlying_type(), SymbolType::List(_))
                        || matches!(right_type.underlying_type(), SymbolType::List(_)))
                {
                    let clear_int = |ty: &SymbolType, node: &AstNode| {
                        !ty.is_secret()
                            && (ty.is_integer() || Self::untyped_int_literal_value(node).is_some())
                    };
                    return if matches!(left_type.underlying_type(), SymbolType::List(_))
                        && clear_int(&right_type, right)
                    {
                        left_type
                    } else if matches!(right_type.underlying_type(), SymbolType::List(_))
                        && clear_int(&left_type, left)
                    {
                        right_type
                    } else {
                        SymbolType::Unknown
                    };
                }
                if op == "+" && left_type == SymbolType::String && right_type == SymbolType::String
                {
                    return SymbolType::String;
                }
                if matches!(
                    op.as_str(),
                    "+" | "-" | "*" | "/" | "%" | "mod" | "shl" | "shr" | "and" | "or" | "xor"
                ) {
                    // A share/secret operand makes the whole arithmetic
                    // expression a share/secret (the MPC runtime handles mixed
                    // `share <op> scalar` cases, e.g. `secret * 2.5`), so it wins
                    // over a clear numeric operand regardless of order.
                    if Self::is_share_alias_type(&left_type) || left_type.is_secret() {
                        return left_type;
                    }
                    if Self::is_share_alias_type(&right_type) || right_type.is_secret() {
                        return right_type;
                    }
                    if Self::is_concrete_inference_type(&left_type)
                        && (right_type == SymbolType::Unknown || left_type == right_type)
                    {
                        return left_type;
                    }
                    if Self::is_concrete_inference_type(&right_type) {
                        return right_type;
                    }
                }
                SymbolType::Unknown
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
            } => self
                .inference_call_signature(function, arguments, env)
                .map(|(_, _, _)| self.inference_call_return_type(function, env))
                .unwrap_or(SymbolType::Unknown),
            AstNode::ListLiteral { elements, .. } => {
                let element_type = elements
                    .iter()
                    .map(|element| self.inference_expr_type(element, env))
                    .find(Self::is_concrete_inference_type)
                    .unwrap_or(SymbolType::Unknown);
                SymbolType::List(Box::new(element_type))
            }
            AstNode::DictLiteral { pairs, .. } => {
                let key_type = pairs
                    .iter()
                    .map(|(key, _)| self.inference_expr_type(key, env))
                    .find(Self::is_concrete_inference_type)
                    .unwrap_or(SymbolType::Unknown);
                let value_type = pairs
                    .iter()
                    .map(|(_, value)| self.inference_expr_type(value, env))
                    .find(Self::is_concrete_inference_type)
                    .unwrap_or(SymbolType::Unknown);
                SymbolType::Dict(Box::new(key_type), Box::new(value_type))
            }
            AstNode::IndexAccess { base, .. } => {
                match self.inference_expr_type(base, env).underlying_type() {
                    SymbolType::List(elem) => elem.as_ref().clone(),
                    SymbolType::Dict(_, value) => value.as_ref().clone(),
                    SymbolType::String => SymbolType::String,
                    _ => SymbolType::Unknown,
                }
            }
            AstNode::NamedArgument { value, .. } => self.inference_expr_type(value, env),
            AstNode::FieldAccess {
                object, field_name, ..
            } => {
                let object_type = self.inference_expr_type(object, env);
                match object_type.underlying_type() {
                    SymbolType::Object(name) | SymbolType::TypeName(name) => self
                        .symbol_table
                        .lookup_user_object(name)
                        .and_then(|info| info.fields.get(field_name))
                        .cloned()
                        .unwrap_or(SymbolType::Unknown),
                    _ => SymbolType::Unknown,
                }
            }
            _ => SymbolType::Unknown,
        }
    }

    fn inference_call_signature(
        &self,
        function: &AstNode,
        arguments: &[AstNode],
        env: &HashMap<String, SymbolType>,
    ) -> Option<(String, Vec<SymbolType>, bool)> {
        match function {
            AstNode::Identifier(name, _) => {
                if let Some((object_name, method_name)) = name
                    .split_once('.')
                    .filter(|_| !self.imported_symbols.contains_key(name))
                {
                    let method = self
                        .symbol_table
                        .lookup_builtin_method(object_name, method_name)?;
                    let call_name = if crate::builtin_registry::builtin_registry()
                        .is_receiver_bound_method(object_name, method_name)
                    {
                        method_name.to_string()
                    } else {
                        name.clone()
                    };
                    return Some((call_name, method.parameters.clone(), true));
                }
                if let Some(info) = self.symbol_table.lookup_symbol(name) {
                    return match &info.kind {
                        SymbolKind::Function { parameters, .. } => {
                            Some((name.clone(), parameters.clone(), false))
                        }
                        SymbolKind::BuiltinFunction { parameters, .. } => {
                            Some((name.clone(), parameters.clone(), true))
                        }
                        _ => None,
                    };
                }
                if let Some(first_arg) = arguments.first() {
                    let receiver_type = self.inference_expr_type(first_arg, env);
                    if let Some(method) = self
                        .symbol_table
                        .lookup_builtin_method_for_receiver(&receiver_type, name)
                    {
                        return Some((name.clone(), method.parameters.clone(), true));
                    }
                }
                None
            }
            AstNode::FieldAccess {
                object, field_name, ..
            } => {
                if let AstNode::Identifier(object_name, _) = object.as_ref() {
                    let qualified_name = format!("{}.{}", object_name, field_name);
                    if let Some(info) = self.symbol_table.lookup_symbol(&qualified_name) {
                        return match &info.kind {
                            SymbolKind::Function { parameters, .. } => {
                                Some((qualified_name, parameters.clone(), false))
                            }
                            SymbolKind::BuiltinFunction { parameters, .. } => {
                                Some((qualified_name, parameters.clone(), true))
                            }
                            _ => None,
                        };
                    }
                }
                None
            }
            _ => None,
        }
    }

    fn inference_call_return_type(
        &self,
        function: &AstNode,
        env: &HashMap<String, SymbolType>,
    ) -> SymbolType {
        match function {
            AstNode::Identifier(name, _) => {
                if let Some((object_name, method_name)) = name
                    .split_once('.')
                    .filter(|_| !self.imported_symbols.contains_key(name))
                {
                    return self
                        .symbol_table
                        .lookup_builtin_method(object_name, method_name)
                        .map(|method| method.return_type.clone())
                        .unwrap_or(SymbolType::Unknown);
                }
                self.symbol_table
                    .lookup_symbol(name)
                    .map(|info| info.symbol_type.clone())
                    .unwrap_or_else(|| env.get(name).cloned().unwrap_or(SymbolType::Unknown))
            }
            AstNode::FieldAccess {
                object, field_name, ..
            } => {
                if let AstNode::Identifier(object_name, _) = object.as_ref() {
                    let qualified_name = format!("{}.{}", object_name, field_name);
                    return self
                        .symbol_table
                        .lookup_symbol(&qualified_name)
                        .map(|info| info.symbol_type.clone())
                        .unwrap_or(SymbolType::Unknown);
                }
                SymbolType::Unknown
            }
            _ => SymbolType::Unknown,
        }
    }

    fn apply_inferred_types(node: AstNode, resolved: &HashMap<String, SymbolType>) -> AstNode {
        match node {
            AstNode::VariableDeclaration {
                name,
                type_annotation,
                value,
                is_mutable,
                is_secret,
                location,
            } => {
                let inferred = type_annotation.or_else(|| {
                    resolved.get(&name).and_then(|ty| {
                        Self::type_annotation_for_inferred_type(ty, location.clone()).map(Box::new)
                    })
                });
                let expected = resolved.get(&name).cloned();
                let value = value.map(|value| {
                    let value = Self::apply_inferred_types(*value, resolved);
                    if let Some(expected) = expected.as_ref() {
                        let (value, _) = Self::refine_expression_type_with_expected(
                            value,
                            &SymbolType::Unknown,
                            expected,
                        );
                        Box::new(value)
                    } else {
                        Box::new(value)
                    }
                });
                AstNode::VariableDeclaration {
                    name,
                    type_annotation: inferred,
                    value,
                    is_mutable,
                    is_secret,
                    location,
                }
            }
            AstNode::Assignment {
                target,
                value,
                location,
            } => AstNode::Assignment {
                target: Box::new(Self::apply_inferred_types(*target, resolved)),
                value: Box::new(Self::apply_inferred_types(*value, resolved)),
                location,
            },
            AstNode::BinaryOperation {
                op,
                left,
                right,
                location,
            } => AstNode::BinaryOperation {
                op,
                left: Box::new(Self::apply_inferred_types(*left, resolved)),
                right: Box::new(Self::apply_inferred_types(*right, resolved)),
                location,
            },
            AstNode::UnaryOperation {
                op,
                operand,
                location,
            } => AstNode::UnaryOperation {
                op,
                operand: Box::new(Self::apply_inferred_types(*operand, resolved)),
                location,
            },
            AstNode::FunctionCall {
                function,
                arguments,
                location,
                resolved_return_type,
            } => AstNode::FunctionCall {
                function: Box::new(Self::apply_inferred_types(*function, resolved)),
                arguments: arguments
                    .into_iter()
                    .map(|arg| Self::apply_inferred_types(arg, resolved))
                    .collect(),
                location,
                resolved_return_type,
            },
            AstNode::CommandCall {
                command,
                arguments,
                location,
                resolved_return_type,
            } => AstNode::CommandCall {
                command: Box::new(Self::apply_inferred_types(*command, resolved)),
                arguments: arguments
                    .into_iter()
                    .map(|arg| Self::apply_inferred_types(arg, resolved))
                    .collect(),
                location,
                resolved_return_type,
            },
            AstNode::NamedArgument {
                name,
                value,
                location,
            } => AstNode::NamedArgument {
                name,
                value: Box::new(Self::apply_inferred_types(*value, resolved)),
                location,
            },
            AstNode::IfExpression {
                condition,
                then_branch,
                else_branch,
            } => AstNode::IfExpression {
                condition: Box::new(Self::apply_inferred_types(*condition, resolved)),
                then_branch: Box::new(Self::apply_inferred_types(*then_branch, resolved)),
                else_branch: else_branch
                    .map(|branch| Box::new(Self::apply_inferred_types(*branch, resolved))),
            },
            AstNode::WhileLoop {
                condition,
                body,
                location,
            } => AstNode::WhileLoop {
                condition: Box::new(Self::apply_inferred_types(*condition, resolved)),
                body: Box::new(Self::apply_inferred_types(*body, resolved)),
                location,
            },
            AstNode::ForLoop {
                variables,
                iterable,
                body,
                location,
            } => AstNode::ForLoop {
                variables,
                iterable: Box::new(Self::apply_inferred_types(*iterable, resolved)),
                body: Box::new(Self::apply_inferred_types(*body, resolved)),
                location,
            },
            AstNode::Block(statements) => AstNode::Block(
                statements
                    .into_iter()
                    .map(|stmt| Self::apply_inferred_types(stmt, resolved))
                    .collect(),
            ),
            AstNode::Return { value, location } => AstNode::Return {
                value: value.map(|value| Box::new(Self::apply_inferred_types(*value, resolved))),
                location,
            },
            AstNode::Yield(value) => AstNode::Yield(
                value.map(|value| Box::new(Self::apply_inferred_types(*value, resolved))),
            ),
            AstNode::FieldAccess {
                object,
                field_name,
                location,
            } => AstNode::FieldAccess {
                object: Box::new(Self::apply_inferred_types(*object, resolved)),
                field_name,
                location,
            },
            AstNode::IndexAccess {
                base,
                index,
                location,
            } => AstNode::IndexAccess {
                base: Box::new(Self::apply_inferred_types(*base, resolved)),
                index: Box::new(Self::apply_inferred_types(*index, resolved)),
                location,
            },
            AstNode::ListLiteral { elements, location } => AstNode::ListLiteral {
                elements: elements
                    .into_iter()
                    .map(|element| Self::apply_inferred_types(element, resolved))
                    .collect(),
                location,
            },
            AstNode::TupleLiteral(elements) => AstNode::TupleLiteral(
                elements
                    .into_iter()
                    .map(|element| Self::apply_inferred_types(element, resolved))
                    .collect(),
            ),
            AstNode::SetLiteral(elements) => AstNode::SetLiteral(
                elements
                    .into_iter()
                    .map(|element| Self::apply_inferred_types(element, resolved))
                    .collect(),
            ),
            AstNode::DictLiteral { pairs, location } => AstNode::DictLiteral {
                pairs: pairs
                    .into_iter()
                    .map(|(key, value)| {
                        (
                            Self::apply_inferred_types(key, resolved),
                            Self::apply_inferred_types(value, resolved),
                        )
                    })
                    .collect(),
                location,
            },
            AstNode::DiscardStatement {
                expression,
                location,
            } => AstNode::DiscardStatement {
                expression: Box::new(Self::apply_inferred_types(*expression, resolved)),
                location,
            },
            other => other,
        }
    }

    fn check_generic_compat(
        &mut self,
        src_node: Option<&AstNode>,
        src_type: &SymbolType,
        dst_type: &SymbolType,
        bindings: &mut HashMap<String, SymbolType>,
        location: SourceLocation,
    ) -> Result<(), ()> {
        match dst_type {
            SymbolType::TypeVar(name) => {
                if let Some(bound) = bindings.get(name).cloned() {
                    self.check_integer_compat(src_node, src_type, &bound, location)
                } else {
                    bindings.insert(name.clone(), src_type.clone());
                    Ok(())
                }
            }
            SymbolType::Secret(dst_inner) => {
                if let SymbolType::Secret(src_inner) = src_type.underlying_type() {
                    self.check_generic_compat(src_node, src_inner, dst_inner, bindings, location)
                } else {
                    self.check_integer_compat(src_node, src_type, dst_type, location)
                }
            }
            SymbolType::List(dst_elem) => {
                if let SymbolType::List(src_elem) = src_type.underlying_type() {
                    self.check_generic_compat(src_node, src_elem, dst_elem, bindings, location)
                } else {
                    self.check_integer_compat(src_node, src_type, dst_type, location)
                }
            }
            SymbolType::Dict(dst_key, dst_value) => {
                if let SymbolType::Dict(src_key, src_value) = src_type.underlying_type() {
                    self.check_generic_compat(
                        src_node,
                        src_key,
                        dst_key,
                        bindings,
                        location.clone(),
                    )?;
                    self.check_generic_compat(src_node, src_value, dst_value, bindings, location)
                } else {
                    self.check_integer_compat(src_node, src_type, dst_type, location)
                }
            }
            SymbolType::Generic(dst_name, dst_params) => {
                if let SymbolType::Generic(src_name, src_params) = src_type.underlying_type() {
                    if src_name == dst_name && src_params.len() == dst_params.len() {
                        for (src_param, dst_param) in src_params.iter().zip(dst_params.iter()) {
                            self.check_generic_compat(
                                src_node,
                                src_param,
                                dst_param,
                                bindings,
                                location.clone(),
                            )?;
                        }
                        Ok(())
                    } else {
                        self.check_integer_compat(src_node, src_type, dst_type, location)
                    }
                } else {
                    self.check_integer_compat(src_node, src_type, dst_type, location)
                }
            }
            _ => self.check_integer_compat(src_node, src_type, dst_type, location),
        }
    }

    fn check_integer_compat(
        &mut self,
        src_node: Option<&AstNode>,
        src_type: &SymbolType,
        dst_type: &SymbolType,
        location: crate::errors::SourceLocation,
    ) -> Result<(), ()> {
        if Self::requires_explicit_reveal(src_type, dst_type) {
            self.error_reporter.add_error(
                CompilerError::type_error(
                    format!(
                        "Cannot implicitly reveal '{}' as '{}'",
                        declared_type_to_string(src_type),
                        declared_type_to_string(dst_type)
                    ),
                    location,
                )
                .with_hint("Call .reveal() to explicitly reveal a secret value"),
            );
            return Err(());
        }

        // Numeric bool literals are accepted only for the bit values bool can represent.
        if dst_type.underlying_type() == &SymbolType::Bool {
            if let Some(val) = src_node.and_then(Self::int_literal_value) {
                if val == 0 || val == 1 {
                    return Ok(());
                }
                self.error_reporter.add_error(CompilerError::type_error(
                    format!(
                        "Integer literal {} cannot initialize 'bool' (allowed values are 0 or 1)",
                        val
                    ),
                    location,
                ));
                return Err(());
            }
        }

        if Self::is_clear_real_type(dst_type)
            && src_node.and_then(Self::int_literal_value).is_some()
        {
            return Ok(());
        }

        // Only enforce special rules if destination is integer
        if dst_type.is_integer() {
            // 1) Literal fits check
            if let Some(val) = src_node.and_then(Self::int_literal_value) {
                if !dst_type.fits_literal_i128(val) {
                    let min = dst_type.min_value_i128().unwrap();
                    let max = dst_type.max_value_i128().unwrap();
                    self.error_reporter.add_error(CompilerError::type_error(
                        format!(
                            "Integer literal {} does not fit in '{}' (allowed range {}..={})",
                            val,
                            declared_type_to_string(dst_type),
                            min,
                            max
                        ),
                        location,
                    ));
                    return Err(());
                }
                return Ok(());
            }
            // 2) Type-to-type compatibility
            if src_type.is_integer() {
                if src_type.underlying_type() == dst_type.underlying_type() {
                    return Ok(());
                }
                if src_type.can_widen_to(dst_type) {
                    return Ok(());
                }
                self.error_reporter.add_error(CompilerError::type_error(
                    format!(
                        "Cannot implicitly convert from '{}' to '{}'",
                        declared_type_to_string(src_type),
                        declared_type_to_string(dst_type)
                    ),
                    location,
                ));
                return Err(());
            }
        }
        // Fallback: check type compatibility (handles Unknown in collections)
        let share_random_in_bad_context = matches!(
            src_node,
            Some(AstNode::FunctionCall { function, .. })
                if matches!(function.as_ref(), AstNode::Identifier(name, _) if name == "Share.random")
                    && !Self::share_random_expected_type(dst_type)
        );
        if Self::is_share_alias_type(src_type) && share_random_in_bad_context {
            self.error_reporter.add_error(CompilerError::type_error(
                format!(
                    "Type mismatch. Expected '{}', found '{}'",
                    declared_type_to_string(dst_type),
                    declared_type_to_string(src_type)
                ),
                location,
            ));
            return Err(());
        }

        if !Self::types_compatible(src_type, dst_type) {
            self.error_reporter.add_error(CompilerError::type_error(
                format!(
                    "Type mismatch. Expected '{}', found '{}'",
                    declared_type_to_string(dst_type),
                    declared_type_to_string(src_type)
                ),
                location,
            ));
            return Err(());
        }
        Ok(())
    }

    fn clear_integer_conversion_error(
        src_node: Option<&AstNode>,
        src_type: &SymbolType,
        dst_type: &SymbolType,
    ) -> bool {
        if !src_type.is_integer() || !dst_type.is_integer() {
            return false;
        }
        if src_type.underlying_type() == dst_type.underlying_type() {
            return false;
        }
        if src_node.and_then(Self::int_literal_value).is_some() {
            return false;
        }
        !src_type.can_widen_to(dst_type)
    }

    fn add_variable_initializer_type_error(
        &mut self,
        name: &str,
        src_type: &SymbolType,
        dst_type: &SymbolType,
        location: SourceLocation,
    ) {
        self.error_reporter.add_error(
            CompilerError::type_error(
                format!(
                    "Cannot initialize variable '{}' of type '{}' with value of type '{}'",
                    name,
                    declared_type_to_string(dst_type),
                    declared_type_to_string(src_type)
                ),
                location,
            )
            .with_hint("Use matching signedness and width for the variable and initializer"),
        );
    }

    fn add_call_argument_type_error(
        &mut self,
        function_name: &str,
        argument_index: usize,
        src_type: &SymbolType,
        dst_type: &SymbolType,
        location: SourceLocation,
    ) {
        self.error_reporter.add_error(
            CompilerError::type_error(
                format!(
                    "Argument {} to function '{}' has type '{}', but parameter expects '{}'",
                    argument_index + 1,
                    function_name,
                    declared_type_to_string(src_type),
                    declared_type_to_string(dst_type)
                ),
                location,
            )
            .with_hint(
                "Use matching signedness and width at the call site or in the function signature",
            ),
        );
    }

    fn assignment_target_description(target: &AstNode) -> String {
        match target {
            AstNode::Identifier(name, _) => format!("'{}'", name),
            AstNode::FieldAccess { field_name, .. } => format!("field '{}'", field_name),
            AstNode::IndexAccess { .. } => "indexed value".to_string(),
            _ => "assignment target".to_string(),
        }
    }

    fn add_assignment_type_error(
        &mut self,
        target: &AstNode,
        src_type: &SymbolType,
        dst_type: &SymbolType,
        location: SourceLocation,
    ) {
        self.error_reporter.add_error(
            CompilerError::type_error(
                format!(
                    "Cannot assign value of type '{}' to {} of type '{}'",
                    declared_type_to_string(src_type),
                    Self::assignment_target_description(target),
                    declared_type_to_string(dst_type)
                ),
                location,
            )
            .with_hint("Use matching signedness and width on both sides of the assignment"),
        );
    }

    fn add_return_type_error(
        &mut self,
        src_type: &SymbolType,
        dst_type: &SymbolType,
        location: SourceLocation,
    ) {
        self.error_reporter.add_error(
            CompilerError::type_error(
                format!(
                    "Cannot return value of type '{}' from function returning '{}'",
                    declared_type_to_string(src_type),
                    declared_type_to_string(dst_type)
                ),
                location,
            )
            .with_hint("Return a value whose signedness and width match the function return type"),
        );
    }

    fn resolve_type_aliases(&self, sym_type: &SymbolType) -> SymbolType {
        self.resolve_type_aliases_inner(sym_type, 0)
    }

    fn resolve_type_aliases_inner(&self, sym_type: &SymbolType, depth: usize) -> SymbolType {
        if depth > 32 {
            return sym_type.clone();
        }

        match sym_type {
            SymbolType::TypeName(name) => {
                if let Some(info) = self.symbol_table.lookup_symbol(name) {
                    if matches!(&info.kind, SymbolKind::Type) {
                        return self.resolve_type_aliases_inner(&info.symbol_type, depth + 1);
                    }
                }
                sym_type.clone()
            }
            SymbolType::Secret(inner) => {
                SymbolType::Secret(Box::new(self.resolve_type_aliases_inner(inner, depth + 1)))
            }
            SymbolType::List(inner) => {
                SymbolType::List(Box::new(self.resolve_type_aliases_inner(inner, depth + 1)))
            }
            SymbolType::Dict(key, value) => SymbolType::Dict(
                Box::new(self.resolve_type_aliases_inner(key, depth + 1)),
                Box::new(self.resolve_type_aliases_inner(value, depth + 1)),
            ),
            SymbolType::Generic(name, params) => SymbolType::Generic(
                name.clone(),
                params
                    .iter()
                    .map(|param| self.resolve_type_aliases_inner(param, depth + 1))
                    .collect(),
            ),
            _ => sym_type.clone(),
        }
    }

    /// Performs semantic analysis (declaration and resolution passes).
    /// Returns the potentially annotated AST or errors.
    pub fn analyze(&mut self, node: AstNode) -> Result<AstNode, SemanticError> {
        // Register any imported symbols before analysis
        self.register_imported_symbols(&node);

        if let AstNode::Block(statements) = &node {
            let has_main = statements.iter().any(|stmt| {
                matches!(stmt,
                AstNode::FunctionDefinition { name: Some(name), .. } if name == "main")
            });
            if has_main {
                if let Some(stmt) = statements
                    .iter()
                    .find(|stmt| Self::is_top_level_execution(stmt))
                {
                    self.error_reporter.add_error(CompilerError::semantic_error(
                        "Cannot mix top-level code with 'def main' entry", stmt.location())
                        .with_hint("Move executable statements and variables into 'def main', or use script-style top-level code without 'def main'"));
                    return Err(SemanticError);
                }
            }
        }

        // Perform the combined analysis traversal
        let (analyzed_node, _node_type) = self.analyze_node(node).map_err(|_| SemanticError)?;
        if !self.symbol_table.errors.is_empty() {
            for (error, location) in &self.symbol_table.errors {
                match error {
                    SymbolDeclarationError::AlreadyDeclared {
                        name,
                        original_location,
                    } => {
                        self.error_reporter.add_error(
                            CompilerError::semantic_error(
                                format!("Symbol '{}' already declared in this scope", name),
                                location.clone(), // Location of the second declaration attempt
                            )
                            .with_hint(format!(
                                "Original declaration was here: {}",
                                original_location
                            )),
                        );
                    } // Handle other symbol table errors if added later
                }
            }
            return Err(SemanticError); // Stop if declaration errors occurred
        }

        if !self.error_reporter.has_errors() {
            for error in crate::definite_assignment::check(&analyzed_node) {
                self.error_reporter.add_error(error);
            }
        }
        if self.error_reporter.has_errors() {
            Err(SemanticError)
        } else {
            Ok(analyzed_node) // Return the analyzed node
        }
    }

    pub(crate) fn is_top_level_execution(node: &AstNode) -> bool {
        !matches!(
            node,
            AstNode::FunctionDefinition { .. }
                | AstNode::ObjectDefinition { .. }
                | AstNode::EnumDefinition { .. }
                | AstNode::TypeAlias { .. }
                | AstNode::BuiltinTypeDefinition { .. }
                | AstNode::BuiltinObjectDefinition { .. }
                | AstNode::Import { .. }
        )
    }

    fn validate_variable_scope(&mut self, name: &str, location: SourceLocation) -> Result<(), ()> {
        if let Some((scope, info)) = self.symbol_table.lookup_symbol_with_scope(name) {
            let imported = scope == 0
                && self.imported_symbols.values().any(|symbol| {
                    symbol.name == info.name || symbol.name.rsplit('.').next() == Some(name)
                });
            if matches!(info.kind, SymbolKind::Variable { .. })
                && (imported || self.function_scope.is_some_and(|boundary| scope < boundary))
            {
                self.error_reporter.add_error(CompilerError::semantic_error(
                    format!("Variable '{}' is outside this function's storage scope; globals and implicit captures are not supported", name), location)
                    .with_hint("Pass the value as a function parameter, or use explicit closure upvalues"));
                return Err(());
            }
        }
        Ok(())
    }

    /// Recursively analyzes a node, handling symbol declaration, resolution, and type checking.
    /// Returns the (potentially modified) node and its determined type.
    fn analyze_node(&mut self, node: AstNode) -> Result<(AstNode, SymbolType), ()> {
        match node {
            // --- Leaf Nodes ---
            AstNode::Literal { value, location } => Ok((
                AstNode::Literal {
                    value: value.clone(),
                    location,
                },
                match value {
                    Value::Int { kind, .. } => match kind {
                        Some(crate::ast::IntKind::Signed(w)) => match w {
                            crate::ast::IntWidth::W8 => SymbolType::Int8,
                            crate::ast::IntWidth::W16 => SymbolType::Int16,
                            crate::ast::IntWidth::W32 => SymbolType::Int32,
                            crate::ast::IntWidth::W64 => SymbolType::Int64,
                        },
                        Some(crate::ast::IntKind::Unsigned(w)) => match w {
                            crate::ast::IntWidth::W8 => SymbolType::UInt8,
                            crate::ast::IntWidth::W16 => SymbolType::UInt16,
                            crate::ast::IntWidth::W32 => SymbolType::UInt32,
                            crate::ast::IntWidth::W64 => SymbolType::UInt64,
                        },
                        None => SymbolType::Int64,
                    },
                    Value::Float(_) => SymbolType::Float,
                    Value::String(_) => SymbolType::String,
                    Value::Bool(_) => SymbolType::Bool,
                    Value::Nil => SymbolType::Nil,
                },
            )),
            AstNode::Identifier(name, location) => {
                // First check for qualified builtin method names (e.g., "ClientStore.take_share")
                // These are valid when used as function identifiers in FunctionCall
                if let Some(dot_pos) = name
                    .find('.')
                    .filter(|_| !self.imported_symbols.contains_key(&name))
                {
                    let obj_name = &name[..dot_pos];
                    let method_name = &name[dot_pos + 1..];

                    if let Some(method_info) = self
                        .symbol_table
                        .lookup_builtin_method(obj_name, method_name)
                    {
                        // Return the method's return type (the identifier is valid as a callable)
                        return Ok((
                            AstNode::Identifier(name.clone(), location.clone()),
                            method_info.return_type.clone(),
                        ));
                    }
                }

                self.validate_variable_scope(&name, location.clone())?;
                if self
                    .symbol_table
                    .lookup_symbol(&name)
                    .is_some_and(|info| matches!(info.kind, SymbolKind::BuiltinObject { .. }))
                {
                    self.error_reporter.add_error(
                        CompilerError::type_error(
                            format!("'{}' is a builtin namespace, not a value", name),
                            location,
                        )
                        .with_hint(format!("Call a method such as '{}.method(...)'", name)),
                    );
                    return Err(());
                }
                // Regular symbol lookup
                if let Some(info) = self.symbol_table.lookup_symbol(name.as_str()) {
                    // TODO: Mark symbol as used (for warnings)
                    // Return the type stored in the symbol table
                    Ok((
                        AstNode::Identifier(name.clone(), location.clone()),
                        info.symbol_type.clone(),
                    ))
                } else {
                    // Check if this looks like a method name that should be a function
                    // The parser transforms obj.method(args) into method(obj, args) via UFCS,
                    // so we catch method-like identifiers here
                    if let Some(suggestion) = suggest_method_to_function(&name, &self.symbol_table)
                    {
                        self.error_reporter.add_error(
                            CompilerError::semantic_error(
                                format!("'{}' is not a valid function name", name),
                                location.clone(),
                            )
                            .with_hint(format!(
                                "Stoffel-Lang uses functions instead of methods. Use {} instead",
                                suggestion
                            )),
                        );
                    } else {
                        // Semantic-aware suggestion using actual symbols in scope
                        let mut error = CompilerError::semantic_error(
                            format!("Use of undeclared identifier '{}'", name),
                            location.clone(),
                        );
                        if let Some(suggestion) = suggest_from_symbols(&name, &self.symbol_table) {
                            error = error.with_hint(format!("Did you mean '{}'?", suggestion));
                        }
                        self.error_reporter.add_error(error);
                    }
                    Err(())
                }
            }

            AstNode::UnaryOperation {
                op,
                operand,
                location,
            } => {
                let (checked_operand, operand_ty) = self.analyze_node(*operand)?;
                let operand_under = operand_ty.underlying_type().clone();

                let result_ty = match op.as_str() {
                    "-" => {
                        if operand_under.is_integer() && !operand_under.is_signed() {
                            self.error_reporter.add_error(CompilerError::type_error(
                                format!(
                                    "Unary '-' requires a signed numeric operand, found '{}'",
                                    declared_type_to_string(&operand_ty)
                                ),
                                location.clone(),
                            ));
                            return Err(());
                        }

                        if (operand_under.is_integer() && operand_under.is_signed())
                            || Self::is_clear_real_type(&operand_under)
                            || operand_under == SymbolType::Unknown
                        {
                            operand_ty.clone()
                        } else {
                            self.error_reporter.add_error(CompilerError::type_error(
                                format!(
                                    "Unary '-' requires a numeric operand, found '{}'",
                                    declared_type_to_string(&operand_ty)
                                ),
                                location.clone(),
                            ));
                            return Err(());
                        }
                    }
                    "not" => {
                        if operand_under == SymbolType::Bool || operand_under == SymbolType::Unknown
                        {
                            if operand_ty.is_secret() {
                                SymbolType::Secret(Box::new(SymbolType::Bool))
                            } else {
                                SymbolType::Bool
                            }
                        } else if operand_under.is_integer() {
                            // Nim-style: on clear integers 'not' is the bitwise
                            // complement, preserving the operand's width.
                            if operand_ty.is_secret() {
                                self.error_reporter.add_error(CompilerError::semantic_error(
                                    "Bitwise 'not' is not supported on secret integers (only secret bool)",
                                    location.clone(),
                                ));
                                return Err(());
                            }
                            operand_under.clone()
                        } else {
                            self.error_reporter.add_error(CompilerError::type_error(
                                format!(
                                    "Unary 'not' requires a bool or integer operand, found '{}'",
                                    declared_type_to_string(&operand_ty)
                                ),
                                location.clone(),
                            ));
                            return Err(());
                        }
                    }
                    _ => {
                        self.error_reporter.add_error(CompilerError::semantic_error(
                            format!("Unsupported unary operator '{}'", op),
                            location.clone(),
                        ));
                        return Err(());
                    }
                };

                Ok((
                    AstNode::UnaryOperation {
                        op,
                        operand: Box::new(checked_operand),
                        location,
                    },
                    result_ty,
                ))
            }

            // --- Declarations and Statements ---
            AstNode::Assignment {
                target,
                value,
                location,
            } => {
                // Analyze target first so its static type can contextualize the value.
                let (checked_target, target_type) = self.analyze_node(*target)?;
                let value = if Self::is_typed_assignment_target(&checked_target)
                    && target_type != SymbolType::Unknown
                {
                    self.contextualize_expression_with_expected(*value, &target_type)
                } else {
                    *value
                };
                let (checked_value, value_type) = self.analyze_node(value)?;
                let (checked_value, value_type) =
                    if Self::is_typed_assignment_target(&checked_target)
                        && target_type != SymbolType::Unknown
                    {
                        Self::refine_expression_type_with_expected(
                            checked_value,
                            &value_type,
                            &target_type,
                        )
                    } else {
                        (checked_value, value_type)
                    };

                if Self::contains_unrefined_share_random_call(&checked_value) {
                    self.error_reporter.add_error(
                        CompilerError::type_error(
                            "Share.random() requires an expected secret integer type".to_string(),
                            location.clone(),
                        )
                        .with_hint(
                            "Add a typed secret integer context such as 'var s: secret int64 = Share.random()'",
                        ),
                    );
                    return Err(());
                }

                // Type check assignments when the target has a known static type.
                let loc = location.clone();
                if Self::is_typed_assignment_target(&checked_target)
                    && target_type != SymbolType::Unknown
                {
                    // Enforce integer compatibility (includes literal range check)
                    if Self::clear_integer_conversion_error(
                        Some(&checked_value),
                        &value_type,
                        &target_type,
                    ) {
                        self.add_assignment_type_error(
                            &checked_target,
                            &value_type,
                            &target_type,
                            loc.clone(),
                        );
                        return Err(());
                    }

                    if self
                        .check_integer_compat(
                            Some(&checked_value),
                            &value_type,
                            &target_type,
                            loc.clone(),
                        )
                        .is_err()
                    {
                        return Err(());
                    }
                    Ok((
                        AstNode::Assignment {
                            target: Box::new(checked_target),
                            value: Box::new(checked_value),
                            location,
                        },
                        SymbolType::Void,
                    ))
                } else {
                    // For non-identifier targets, keep previous basic behavior (no type enforcement yet)
                    Ok((
                        AstNode::Assignment {
                            target: Box::new(checked_target),
                            value: Box::new(checked_value),
                            location,
                        },
                        SymbolType::Void,
                    ))
                }
            }

            AstNode::VariableDeclaration {
                name,
                type_annotation,
                value,
                is_mutable,
                is_secret,
                location,
            } => {
                if let Some(annotation) = type_annotation.as_ref() {
                    self.validate_namespace_annotation(annotation)?;
                    self.validate_type_annotation(
                        &SymbolType::from_ast(annotation),
                        annotation.location(),
                    )?;
                }
                // 1. Analyze the value expression first (if it exists)
                let mut checked_value_node = None;
                let mut value_type = if let Some(val_expr) = value {
                    let val_expr = if let Some(type_node) = type_annotation.as_ref() {
                        let expected = self.resolve_type_aliases(&SymbolType::from_ast(type_node));
                        self.contextualize_expression_with_expected(*val_expr, &expected)
                    } else {
                        *val_expr
                    };
                    let (checked_val, val_type) = self.analyze_node(val_expr)?;

                    checked_value_node = Some(Box::new(checked_val));
                    val_type
                } else {
                    SymbolType::Unknown // No value provided
                };

                // 2. Determine the declared type (from annotation or inferred from value)
                let declared_type = type_annotation
                    .as_ref()
                    .map(|tn| SymbolType::from_ast(tn))
                    .unwrap_or_else(|| value_type.clone()); // Infer if no annotation

                // Validate the type annotation if present - ensure it refers to an actual type
                if let Some(tn) = &type_annotation {
                    self.validate_type_annotation(&declared_type, tn.location())?;
                }

                let declared_type = self.resolve_type_aliases(&declared_type);

                if type_annotation.is_some() {
                    if let Some(checked_val) = checked_value_node.take() {
                        let (refined_value, refined_type) =
                            Self::refine_expression_type_with_expected(
                                *checked_val,
                                &value_type,
                                &declared_type,
                            );
                        checked_value_node = Some(Box::new(refined_value));
                        value_type = refined_type;
                    }
                }

                if checked_value_node
                    .as_deref()
                    .is_some_and(Self::contains_unrefined_share_random_call)
                {
                    self.error_reporter.add_error(
                        CompilerError::type_error(
                            "Share.random() requires an expected secret integer type".to_string(),
                            location.clone(),
                        )
                        .with_hint(
                            "Add a type annotation such as 'var s: secret int64 = Share.random()'",
                        ),
                    );
                    return Err(());
                }

                // 3. Check for type consistency (with integer width/range rules)
                if type_annotation.is_some() && value_type != SymbolType::Unknown {
                    let initializer_has_type_error = if Self::clear_integer_conversion_error(
                        checked_value_node.as_deref(),
                        &value_type,
                        &declared_type,
                    ) {
                        self.add_variable_initializer_type_error(
                            &name,
                            &value_type,
                            &declared_type,
                            location.clone(),
                        );
                        true
                    } else {
                        self.check_integer_compat(
                            checked_value_node.as_deref(),
                            &value_type,
                            &declared_type,
                            location.clone(),
                        )
                        .is_err()
                    };

                    if initializer_has_type_error {
                        // Keep the declared symbol available with its annotation so later
                        // statements do not cascade into undeclared-identifier errors.
                    }
                }

                // 4. Handle 'secret' keyword and type secrecy
                let final_type = if declared_type.is_secret() || is_secret {
                    declared_type.with_secret_modifier()
                } else {
                    declared_type
                };
                let calculated_is_secret = final_type.is_secret();

                // Preserve the resolved type for default initialization and
                // downstream analyses; source spans still identify the annotation.
                let type_annotation = Self::type_annotation_for_inferred_type(
                    &final_type,
                    type_annotation
                        .as_deref()
                        .map(AstNode::location)
                        .unwrap_or_else(|| location.clone()),
                )
                .map(Box::new)
                .or(type_annotation);
                // 5. Declare the symbol in the current scope
                let info = SymbolInfo {
                    name: name.clone(),
                    kind: SymbolKind::Variable { is_mutable },
                    symbol_type: final_type,
                    is_secret: is_secret || calculated_is_secret,
                    defined_at: location.clone(),
                };
                self.symbol_table.declare_symbol(info); // Errors are collected internally

                // 6. Reconstruct the node with the checked value
                let reconstructed_node = AstNode::VariableDeclaration {
                    name,
                    type_annotation, // Keep original annotation node
                    value: checked_value_node,
                    is_mutable,
                    is_secret,
                    location,
                };
                Ok((reconstructed_node, SymbolType::Void)) // Declaration is a statement
            }

            AstNode::FunctionDefinition {
                name,
                type_params,
                parameters,
                return_type,
                body,
                is_secret,
                pragmas,
                location,
                node_id,
            } => {
                let func_name = name.as_ref().cloned().unwrap_or_else(|| {
                    format!("<anonymous_{}:{}>", location.line, location.column)
                });

                // 1. Determine parameter and return types for symbol table entry
                let param_types: Vec<SymbolType> = parameters
                    .iter()
                    .map(|p| {
                        let param_type = p
                            .type_annotation
                            .as_ref()
                            .map(|tn| SymbolType::from_ast_with_type_params(tn, &type_params))
                            .unwrap_or(SymbolType::Unknown);
                        let param_type = self.resolve_type_aliases(&param_type);
                        if p.is_variadic {
                            // *args receives the packed extras as a list.
                            SymbolType::List(Box::new(param_type))
                        } else {
                            param_type
                        }
                    })
                    .collect();

                let ret_type_annotation = return_type
                    .as_ref()
                    .map(|rt| SymbolType::from_ast_with_type_params(rt, &type_params))
                    .unwrap_or(SymbolType::Void); // None or '-> nil' means Void
                let ret_type_annotation = self.resolve_type_aliases(&ret_type_annotation);

                // Handle 'secret proc' and secret return type annotation
                let final_return_type = if ret_type_annotation.is_secret() || is_secret {
                    ret_type_annotation.with_secret_modifier()
                } else {
                    ret_type_annotation
                };

                // Validate parameter types - ensure they refer to actual types, not functions
                for (param, param_type) in parameters.iter().zip(param_types.iter()) {
                    if let Some(annotation) = &param.type_annotation {
                        self.validate_namespace_annotation(annotation)?;
                    }
                    let param_loc = param
                        .type_annotation
                        .as_ref()
                        .map_or_else(|| location.clone(), |n| n.location());
                    self.validate_type_annotation(param_type, param_loc)?;
                }

                // Validate return type
                if let Some(rt_node) = &return_type {
                    self.validate_namespace_annotation(rt_node)?;
                    self.validate_type_annotation(&final_return_type, rt_node.location())?;
                }

                // Check for pragmas like 'builtin'
                let mut is_builtin = false;
                for pragma in &pragmas {
                    if matches!(
                        pragma,
                        Pragma::Simple(pragma_name, _) | Pragma::KeyValue(pragma_name, _, _)
                            if pragma_name == "builtin"
                    ) {
                        is_builtin = true;
                        break;
                    }
                }

                if !is_builtin {
                    if let Some(position) = parameters.iter().position(|param| param.is_variadic) {
                        if position + 1 != parameters.len() {
                            self.error_reporter.add_error(CompilerError::semantic_error(
                                "A variadic parameter (*args) must be the last parameter",
                                location.clone(),
                            ));
                            return Err(());
                        }
                        if parameters[position].default_value.is_some() {
                            self.error_reporter.add_error(CompilerError::semantic_error(
                                "A variadic parameter cannot have a default value",
                                location.clone(),
                            ));
                            return Err(());
                        }
                    }
                    // Defaults are injected at call sites, so they must not
                    // depend on caller or callee scope: literals only.
                    if let Some(param) = parameters.iter().find(|param| {
                        param
                            .default_value
                            .as_deref()
                            .is_some_and(|value| !matches!(value, AstNode::Literal { .. }))
                    }) {
                        self.error_reporter.add_error(CompilerError::semantic_error(
                            format!(
                                "Default value for parameter '{}' must be a literal",
                                param.name
                            ),
                            param
                                .type_annotation
                                .as_ref()
                                .map_or_else(|| location.clone(), |node| node.location()),
                        ));
                        return Err(());
                    }
                    let mut seen_default = false;
                    for param in parameters.iter() {
                        if param.default_value.is_some() {
                            seen_default = true;
                        } else if seen_default {
                            self.error_reporter.add_error(CompilerError::semantic_error(
                                format!(
                                    "Parameter '{}' without a default follows a parameter with one",
                                    param.name
                                ),
                                location.clone(),
                            ));
                            return Err(());
                        }
                    }
                    self.function_signatures.insert(
                        func_name.clone(),
                        parameters
                            .iter()
                            .map(|param| {
                                (
                                    param.name.clone(),
                                    param.default_value.as_deref().cloned(),
                                    param.is_variadic,
                                )
                            })
                            .collect(),
                    );
                }

                // 2. Declare the function symbol in the *current* (outer) scope
                //    (Unless it's a builtin, builtins are pre-declared)
                if !is_builtin {
                    let info = SymbolInfo {
                        name: func_name.clone(),
                        kind: SymbolKind::Function {
                            parameters: param_types.clone(),
                            return_type: final_return_type.clone(),
                        },
                        symbol_type: final_return_type.clone(), // Type of symbol is its return type
                        is_secret: is_secret || final_return_type.is_secret(),
                        defined_at: location.clone(),
                    };
                    self.symbol_table.declare_symbol(info);
                }

                // 3. Analyze function body in a new scope (if not builtin)
                let checked_body = if !is_builtin {
                    self.symbol_table.enter_scope();
                    let previous_function_scope = self
                        .function_scope
                        .replace(self.symbol_table.current_scope_id());
                    let previous_loop_depth = std::mem::replace(&mut self.loop_depth, 0);
                    let previous_return_type = self
                        .current_function_return_type
                        .replace(final_return_type.clone());

                    let body_result: Result<AstNode, ()> = (|| {
                        // Declare parameters within the function's scope
                        for (param, param_type) in parameters.iter().zip(param_types.iter()) {
                            let param_info = SymbolInfo {
                                name: param.name.clone(),
                                kind: SymbolKind::Variable { is_mutable: false }, // Params are immutable
                                symbol_type: param_type.clone(),
                                is_secret: param_type.is_secret(),
                                defined_at: param
                                    .type_annotation
                                    .as_ref()
                                    .map_or_else(|| location.clone(), |n| n.location()),
                            };
                            self.symbol_table.declare_symbol(param_info);
                        }

                        let body =
                            Box::new(self.infer_function_body_types(*body, &final_return_type)?);

                        // Recursively analyze the body
                        let errors_before_body = self.error_reporter.error_count();
                        let (checked_body_node, _body_type) = self.analyze_node(*body)?;
                        let body_has_errors =
                            self.error_reporter.error_count() > errors_before_body;

                        // Every path through a value-returning function must return.
                        let needs_return = !matches!(
                            final_return_type.underlying_type(),
                            SymbolType::Void | SymbolType::Nil | SymbolType::Unknown
                        );
                        if !body_has_errors
                            && needs_return
                            && !Self::node_always_returns(&checked_body_node)
                        {
                            self.error_reporter.add_error(
                            CompilerError::semantic_error(
                                format!(
                                    "Function '{}' declares return type '{}' but not all paths return a value",
                                    func_name,
                                    declared_type_to_string(&final_return_type)
                                ),
                                location.clone(),
                            )
                            .with_hint("Add a return statement at the end of the function or to every branch"),
                        );
                            return Err(());
                        }

                        Ok(checked_body_node)
                    })();
                    self.current_function_return_type = previous_return_type;
                    self.function_scope = previous_function_scope;
                    self.loop_depth = previous_loop_depth;
                    self.symbol_table.exit_scope();
                    Box::new(body_result?)
                } else {
                    body // Keep original body for builtins (it's not analyzed)
                };

                // Keep aliases resolved at function boundaries as well as in
                // locals, so downstream domain analysis sees the same types.
                let mut parameters = parameters;
                for parameter in &mut parameters {
                    if let Some(annotation) = parameter.type_annotation.as_deref() {
                        let mut ty = self.resolve_type_aliases(&SymbolType::from_ast(annotation));
                        if parameter.is_secret && !ty.is_secret() {
                            ty = ty.with_secret_modifier();
                        }
                        if let Some(resolved) =
                            Self::type_annotation_for_inferred_type(&ty, annotation.location())
                        {
                            parameter.type_annotation = Some(Box::new(resolved));
                        }
                    }
                }
                let return_type = return_type.map(|annotation| {
                    let ty = self.resolve_type_aliases(&SymbolType::from_ast(&annotation));
                    Self::type_annotation_for_inferred_type(&ty, annotation.location())
                        .map(Box::new)
                        .unwrap_or(annotation)
                });
                // 4. Reconstruct the node
                let reconstructed_node = AstNode::FunctionDefinition {
                    name,
                    type_params,
                    parameters,
                    return_type,
                    body: checked_body,
                    is_secret,
                    pragmas,
                    location,
                    node_id,
                };
                Ok((reconstructed_node, SymbolType::Void)) // Definition is a statement
            }

            AstNode::ObjectDefinition {
                name,
                base_type,
                fields,
                is_secret,
                location,
            } => {
                // 1. Register the object type in the symbol table
                let object_type = SymbolType::Object(name.clone());

                // Build field type map for the object
                let mut field_types: std::collections::HashMap<String, SymbolType> =
                    std::collections::HashMap::new();

                if let Some(base_node) = &base_type {
                    let base_type_symbol = SymbolType::from_ast(base_node);
                    self.validate_namespace_annotation(base_node)?;
                    self.validate_type_annotation(&base_type_symbol, base_node.location())?;
                    let base_type_symbol = self.resolve_type_aliases(&base_type_symbol);

                    let base_name = match base_type_symbol.underlying_type() {
                        SymbolType::Object(name) | SymbolType::TypeName(name) => Some(name),
                        _ => None,
                    };

                    if let Some(base_name) = base_name {
                        if let Some(base_info) = self.symbol_table.lookup_user_object(base_name) {
                            field_types.extend(base_info.fields.clone());
                        }
                    }
                }

                for field in &fields {
                    let mut field_type = SymbolType::from_ast(&field.type_annotation);
                    // Apply the `secret` modifier from field definition
                    if field.is_secret && !field_type.is_secret() {
                        field_type = field_type.with_secret_modifier();
                    }
                    // Validate field type refers to a valid type
                    self.validate_namespace_annotation(&field.type_annotation)?;
                    self.validate_type_annotation(&field_type, field.type_annotation.location())?;
                    field_type = self.resolve_type_aliases(&field_type);
                    field_types.insert(field.name.clone(), field_type);
                }

                self.symbol_table.register_user_object(UserObjectInfo {
                    name: name.clone(),
                    fields: field_types.clone(),
                });

                // Declare the object type as a type symbol
                let info = SymbolInfo {
                    name: name.clone(),
                    kind: SymbolKind::Type, // User-defined type
                    symbol_type: object_type.clone(),
                    is_secret,
                    defined_at: location.clone(),
                };
                self.symbol_table.declare_symbol(info);

                // Materialize inherited fields and resolved aliases for defaults
                // and the initialization checker, using the same object layout.
                let mut resolved_fields = Vec::new();
                for (field_name, ty) in &field_types {
                    let field_location = fields
                        .iter()
                        .find(|f| &f.name == field_name)
                        .map(|f| f.type_annotation.location())
                        .unwrap_or_else(|| location.clone());
                    if let Some(annotation) =
                        Self::type_annotation_for_inferred_type(ty, field_location)
                    {
                        resolved_fields.push(crate::ast::FieldDefinition {
                            name: field_name.clone(),
                            type_annotation: Box::new(annotation),
                            is_secret: ty.is_secret(),
                        });
                    }
                }
                resolved_fields.sort_by(|a, b| a.name.cmp(&b.name));
                let fields = resolved_fields;
                Ok((
                    AstNode::ObjectDefinition {
                        name,
                        base_type,
                        fields,
                        is_secret,
                        location,
                    },
                    SymbolType::Void,
                ))
            }

            AstNode::TypeAlias {
                name,
                target_type,
                is_secret,
                location,
            } => {
                let mut alias_type = SymbolType::from_ast(&target_type);
                if is_secret && !alias_type.is_secret() {
                    alias_type = alias_type.with_secret_modifier();
                }

                self.validate_namespace_annotation(&target_type)?;
                self.validate_type_annotation(&alias_type, target_type.location())?;
                alias_type = self.resolve_type_aliases(&alias_type);

                let info = SymbolInfo {
                    name: name.clone(),
                    kind: SymbolKind::Type,
                    symbol_type: alias_type,
                    is_secret,
                    defined_at: location.clone(),
                };
                self.symbol_table.declare_symbol(info);

                Ok((
                    AstNode::TypeAlias {
                        name,
                        target_type,
                        is_secret,
                        location,
                    },
                    SymbolType::Void,
                ))
            }

            AstNode::BuiltinTypeDefinition {
                name,
                target_type,
                is_opaque_object,
                location,
            } => Ok((
                AstNode::BuiltinTypeDefinition {
                    name,
                    target_type,
                    is_opaque_object,
                    location,
                },
                SymbolType::Void,
            )),

            AstNode::BuiltinObjectDefinition {
                name,
                methods,
                location,
            } => Ok((
                AstNode::BuiltinObjectDefinition {
                    name,
                    methods,
                    location,
                },
                SymbolType::Void,
            )),

            // --- Expressions and Control Flow ---
            AstNode::IfExpression {
                condition,
                then_branch,
                else_branch,
            } => {
                // Analyze condition and enforce that branching on secret is not supported
                let (checked_condition, cond_type) = self.analyze_node(*condition)?;
                if cond_type.is_secret() {
                    self.error_reporter.add_error(CompilerError::semantic_error(
                        "Branching with secret values isn't supported yet (secret condition in 'if')",
                        checked_condition.location(),
                    ));
                    return Err(());
                }
                // Optional: ensure condition is bool (underlying type)
                if cond_type.underlying_type() != &SymbolType::Bool {
                    self.error_reporter.add_error(CompilerError::type_error(
                        "If-condition must be of type 'bool'",
                        checked_condition.location(),
                    ));
                    return Err(());
                }

                // Analyze branches
                let (checked_then, _then_ty) = self.analyze_node(*then_branch)?;
                let checked_else = if let Some(eb) = else_branch {
                    let (c_eb, _else_ty) = self.analyze_node(*eb)?;
                    Some(Box::new(c_eb))
                } else {
                    None
                };

                Ok((
                    AstNode::IfExpression {
                        condition: Box::new(checked_condition),
                        then_branch: Box::new(checked_then),
                        else_branch: checked_else,
                    },
                    SymbolType::Unknown,
                ))
            }
            AstNode::WhileLoop {
                condition,
                body,
                location,
            } => {
                // Analyze condition and error if it's secret
                let (checked_condition, cond_type) = self.analyze_node(*condition)?;
                if cond_type.is_secret() {
                    self.error_reporter.add_error(CompilerError::semantic_error(
                        "Branching with secret values isn't supported yet (secret condition in 'while')",
                        checked_condition.location(),
                    ));
                    return Err(());
                }
                if cond_type.underlying_type() != &SymbolType::Bool {
                    self.error_reporter.add_error(CompilerError::type_error(
                        "While-condition must be of type 'bool'",
                        checked_condition.location(),
                    ));
                    return Err(());
                }
                self.loop_depth += 1;
                let body_result = self.analyze_node(*body);
                self.loop_depth -= 1;
                let (checked_body, _body_ty) = body_result?;
                Ok((
                    AstNode::WhileLoop {
                        condition: Box::new(checked_condition),
                        body: Box::new(checked_body),
                        location,
                    },
                    SymbolType::Void,
                ))
            }
            AstNode::EnumDefinition {
                name,
                members,
                is_secret,
                location,
            } => {
                let mut values = HashMap::new();
                let mut next_value: i64 = 0;
                for member in &members {
                    let value = match member.value.as_deref() {
                        Some(node) => match Self::int_literal_value(node) {
                            Some(v) => i64::try_from(v).map_err(|_| {
                                self.error_reporter.add_error(CompilerError::semantic_error(
                                    format!(
                                        "Enum member '{}' value does not fit in int64",
                                        member.name
                                    ),
                                    location.clone(),
                                ));
                            })?,
                            None => {
                                self.error_reporter.add_error(CompilerError::semantic_error(
                                    format!(
                                        "Enum member '{}' must use an integer literal value",
                                        member.name
                                    ),
                                    location.clone(),
                                ));
                                return Err(());
                            }
                        },
                        None => next_value,
                    };
                    if values.insert(member.name.clone(), value).is_some() {
                        self.error_reporter.add_error(CompilerError::semantic_error(
                            format!("Duplicate enum member '{}'", member.name),
                            location.clone(),
                        ));
                        return Err(());
                    }
                    next_value = value.saturating_add(1);
                }
                self.enum_members.insert(name.clone(), values);

                // The enum name doubles as a type alias for int64.
                self.symbol_table.declare_symbol(SymbolInfo {
                    name: name.clone(),
                    kind: SymbolKind::Type,
                    symbol_type: SymbolType::Int64,
                    is_secret: false,
                    defined_at: location.clone(),
                });

                Ok((
                    AstNode::EnumDefinition {
                        name,
                        members,
                        is_secret,
                        location,
                    },
                    SymbolType::Void,
                ))
            }
            AstNode::Break => {
                if self.loop_depth == 0 {
                    self.error_reporter.add_error(CompilerError::semantic_error(
                        "'break' outside of a loop",
                        SourceLocation::default(),
                    ));
                    return Err(());
                }
                Ok((AstNode::Break, SymbolType::Void))
            }
            AstNode::Continue => {
                if self.loop_depth == 0 {
                    self.error_reporter.add_error(CompilerError::semantic_error(
                        "'continue' outside of a loop",
                        SourceLocation::default(),
                    ));
                    return Err(());
                }
                Ok((AstNode::Continue, SymbolType::Void))
            }
            AstNode::Block(statements) => {
                // Blocks don't create scopes by default in this design.
                // Scopes are handled by functions, loops (if needed), etc.
                let mut checked_statements = Vec::new();
                let mut last_type = SymbolType::Void; // Default for empty block
                                                      // Important: continue analyzing all statements even if some have errors
                for stmt in statements {
                    match self.analyze_node(stmt) {
                        Ok((checked_stmt, stmt_type)) => {
                            last_type = stmt_type; // Type of block is type of last successful statement
                            checked_statements.push(checked_stmt);
                        }
                        Err(()) => {
                            // Preserve the original statement to keep AST shape and continue
                            // We purposely do not update last_type here.
                            // Note: We cannot reconstruct the original `stmt` here because it's moved by match,
                            // so we push a placeholder no-op statement to maintain block length.
                            // If a proper NoOp node exists, prefer that; otherwise use an empty literal.
                            checked_statements.push(AstNode::Literal {
                                value: Value::Nil,
                                location: SourceLocation::default(),
                            });
                        }
                    }
                }
                Ok((AstNode::Block(checked_statements), last_type))
            }

            AstNode::ForLoop {
                variables,
                iterable,
                body,
                location,
            } => {
                // Support single variable iteration over ranges or collections
                if variables.len() != 1 {
                    self.error_reporter.add_error(CompilerError::semantic_error(
                        "For-loop with multiple variables not supported yet",
                        location.clone(),
                    ));
                    return Err(());
                }

                // Analyze iterable to determine its type
                let (checked_iterable, iter_type) = self.analyze_node(*iterable)?;

                // Determine the loop variable type based on the iterable
                let (loop_var_type, is_secret) = match &checked_iterable {
                    // Range iteration: for i in a..b
                    AstNode::BinaryOperation { op, .. } if op == ".." => (SymbolType::Int64, false),
                    // Collection iteration: infer element type from iterable type
                    _ => {
                        match iter_type.underlying_type() {
                            SymbolType::List(elem_type) => {
                                // Derive secrecy from the element (loop variable) type,
                                // not from the iterable's top-level type.
                                let elem_ty = elem_type.as_ref().clone();
                                let is_secret = elem_ty.is_secret();
                                (elem_ty, is_secret)
                            }
                            SymbolType::String => {
                                // Iterating over a string yields characters (as strings)
                                (SymbolType::String, false)
                            }
                            _ => {
                                self.error_reporter.add_error(CompilerError::semantic_error(
                                    format!(
                                        "Cannot iterate over type '{}'; expected a range (a..b) or a List",
                                        declared_type_to_string(&iter_type)
                                    ),
                                    checked_iterable.location(),
                                ));
                                return Err(());
                            }
                        }
                    }
                };

                // Enter loop scope and declare the loop variable with inferred type
                self.symbol_table.enter_scope();
                let var_name = variables[0].clone();
                let var_info = SymbolInfo {
                    name: var_name.clone(),
                    kind: SymbolKind::Variable { is_mutable: false },
                    symbol_type: loop_var_type,
                    is_secret,
                    defined_at: location.clone(),
                };
                self.symbol_table.declare_symbol(var_info);

                // Analyze body within scope
                self.loop_depth += 1;
                let body_result = self.analyze_node(*body);
                self.loop_depth -= 1;
                let (checked_body, _body_type) = match body_result {
                    Ok(result) => result,
                    Err(()) => {
                        self.symbol_table.exit_scope();
                        return Err(());
                    }
                };

                // Exit loop scope
                self.symbol_table.exit_scope();

                let (var_name, checked_body) =
                    crate::scope_bindings::for_scope(var_name, checked_body, &location);
                Ok((
                    AstNode::ForLoop {
                        variables: vec![var_name],
                        iterable: Box::new(checked_iterable),
                        body: Box::new(checked_body),
                        location,
                    },
                    SymbolType::Void,
                ))
            }

            AstNode::Return {
                value: ref maybe_expr,
                location: ref ret_loc,
            } => {
                let expected_ret = self.current_function_return_type.clone();
                let (mut checked_expr_node, mut return_value_type) = match maybe_expr {
                    Some(expr) => {
                        let expr = if let Some(expected) = expected_ret.as_ref() {
                            self.contextualize_expression_with_expected(*expr.clone(), expected)
                        } else {
                            *expr.clone()
                        };
                        let (checked_expr, expr_type) = self.analyze_node(expr)?;
                        (Some(Box::new(checked_expr)), expr_type)
                    }
                    None => (None, SymbolType::Void),
                };

                match expected_ret {
                    Some(expected) => {
                        if let Some(checked_expr) = checked_expr_node.take() {
                            let (refined_expr, refined_type) =
                                Self::refine_expression_type_with_expected(
                                    *checked_expr,
                                    &return_value_type,
                                    &expected,
                                );
                            checked_expr_node = Some(Box::new(refined_expr));
                            return_value_type = refined_type;
                        }
                        // Integer-aware compatibility (includes literal range check)
                        let loc = node.location();
                        if checked_expr_node
                            .as_deref()
                            .is_some_and(Self::contains_unrefined_share_random_call)
                        {
                            self.error_reporter.add_error(
                                CompilerError::type_error(
                                    "Share.random() requires an expected secret integer type"
                                        .to_string(),
                                    loc.clone(),
                                )
                                .with_hint(
                                    "Add a typed secret integer context such as 'var s: secret int64 = Share.random()'",
                                ),
                            );
                            return Err(());
                        }
                        if Self::clear_integer_conversion_error(
                            checked_expr_node.as_deref(),
                            &return_value_type,
                            &expected,
                        ) {
                            self.add_return_type_error(&return_value_type, &expected, loc);
                            return Err(());
                        }

                        if self
                            .check_integer_compat(
                                checked_expr_node.as_deref(),
                                &return_value_type,
                                &expected,
                                loc,
                            )
                            .is_err()
                        {
                            return Err(());
                        }
                        // TODO: Check secrecy compatibility (cannot return clear from secret context, etc.)
                    }
                    None => {
                        self.error_reporter.add_error(CompilerError::semantic_error(
                            "'return' statement outside of function",
                            node.location(),
                        ));
                        return Err(());
                    }
                }
                Ok((
                    AstNode::Return {
                        value: checked_expr_node,
                        location: ret_loc.clone(),
                    },
                    SymbolType::Void,
                )) // Return is a statement
            }

            AstNode::FunctionCall {
                function,
                arguments,
                location,
                resolved_return_type: contextual_return_type,
            } => {
                // 1. Preserve simple call targets for call resolution. Unqualified
                // receiver-bound methods like `open(s)` cannot be validated until
                // the arguments have been analyzed.
                let checked_function_node = match *function {
                    AstNode::Identifier(name, location) => AstNode::Identifier(name, location),
                    other => {
                        let (checked, _function_expr_type) = self.analyze_node(other)?;
                        checked
                    }
                };

                if let AstNode::Identifier(name, loc) = &checked_function_node {
                    let object_info = self.symbol_table.lookup_symbol(name).and_then(|info| {
                        if matches!(&info.kind, SymbolKind::Type)
                            && matches!(&info.symbol_type, SymbolType::Object(_))
                        {
                            self.symbol_table.lookup_user_object(name).cloned()
                        } else {
                            None
                        }
                    });

                    if let Some(object_info) = object_info {
                        let mut checked_arguments = Vec::with_capacity(arguments.len());
                        let mut seen_fields = std::collections::HashSet::new();

                        for arg_node in arguments {
                            match arg_node {
                                AstNode::NamedArgument {
                                    name: field_name,
                                    value,
                                    location: arg_loc,
                                } => {
                                    if !seen_fields.insert(field_name.clone()) {
                                        self.error_reporter.add_error(
                                            CompilerError::semantic_error(
                                                format!(
                                                    "Duplicate field '{}' in constructor for '{}'",
                                                    field_name, object_info.name
                                                ),
                                                arg_loc,
                                            ),
                                        );
                                        return Err(());
                                    }

                                    let field_type =
                                        match object_info.fields.get(&field_name).cloned() {
                                            Some(field_type) => field_type,
                                            None => {
                                                self.error_reporter.add_error(
                                                    CompilerError::semantic_error(
                                                        format!(
                                                            "Unknown field '{}' for object '{}'",
                                                            field_name, object_info.name
                                                        ),
                                                        arg_loc,
                                                    ),
                                                );
                                                return Err(());
                                            }
                                        };

                                    let (checked_value, value_type) = self.analyze_node(*value)?;
                                    let (checked_value, value_type) =
                                        Self::refine_expression_type_with_expected(
                                            checked_value,
                                            &value_type,
                                            &field_type,
                                        );
                                    if self
                                        .check_integer_compat(
                                            Some(&checked_value),
                                            &value_type,
                                            &field_type,
                                            checked_value.location(),
                                        )
                                        .is_err()
                                    {
                                        return Err(());
                                    }

                                    checked_arguments.push(AstNode::NamedArgument {
                                        name: field_name,
                                        value: Box::new(checked_value),
                                        location: arg_loc,
                                    });
                                }
                                other => {
                                    self.error_reporter.add_error(
                                        CompilerError::semantic_error(
                                            format!(
                                                "Constructor for '{}' expects named field arguments",
                                                object_info.name
                                            ),
                                            other.location(),
                                        )
                                        .with_hint(format!(
                                            "Use {}(field: value) syntax",
                                            object_info.name
                                        )),
                                    );
                                    return Err(());
                                }
                            }
                        }

                        let object_type = SymbolType::Object(object_info.name);
                        return Ok((
                            AstNode::FunctionCall {
                                function: Box::new(AstNode::Identifier(name.clone(), loc.clone())),
                                arguments: checked_arguments,
                                location,
                                resolved_return_type: Some(object_type.clone()),
                            },
                            object_type,
                        ));
                    }
                }

                // 2. For user-defined functions, resolve named arguments and
                // inject default values so the call becomes plain positional.
                let arguments = if let AstNode::Identifier(name, _) = &checked_function_node {
                    match self.function_signatures.get(name).cloned() {
                        Some(signature) => {
                            self.resolve_call_arguments(arguments, &signature, name, &location)?
                        }
                        None => arguments,
                    }
                } else {
                    arguments
                };

                // Analyze arguments
                let mut checked_arguments = Vec::with_capacity(arguments.len());
                let mut argument_types = Vec::with_capacity(arguments.len());
                for arg_node in arguments {
                    if let AstNode::NamedArgument { location, .. } = &arg_node {
                        self.error_reporter.add_error(CompilerError::semantic_error(
                            "Named arguments are only supported for object constructors and user-defined functions",
                            location.clone(),
                        ));
                        return Err(());
                    }
                    let (checked_arg, arg_type) = self.analyze_node(arg_node)?;
                    checked_arguments.push(checked_arg);
                    argument_types.push(arg_type);
                }

                // 3. Determine the actual function symbol and its type
                let (function_name, expected_param_types, return_type, is_builtin_call) =
                    match &checked_function_node {
                        AstNode::Identifier(name, loc) => {
                            // Check if this is a qualified builtin object method call (e.g., "ClientStore.take_share")
                            if let Some(dot_pos) = name
                                .find('.')
                                .filter(|_| !self.imported_symbols.contains_key(name))
                            {
                                let obj_name = &name[..dot_pos];
                                let method_name = &name[dot_pos + 1..];

                                if let Some(method_info) = self
                                    .symbol_table
                                    .lookup_builtin_method(obj_name, method_name)
                                {
                                    let call_name = if crate::builtin_registry::builtin_registry()
                                        .is_receiver_bound_method(obj_name, method_name)
                                    {
                                        method_name.to_string()
                                    } else {
                                        name.clone()
                                    };
                                    (
                                        call_name,
                                        method_info.parameters.clone(),
                                        method_info.return_type.clone(),
                                        true,
                                    )
                                } else {
                                    self.error_reporter.add_error(CompilerError::semantic_error(
                                        format!(
                                            "Unknown method '{}' on builtin object '{}'",
                                            method_name, obj_name
                                        ),
                                        loc.clone(),
                                    ));
                                    return Err(());
                                }
                            } else if let Some(info) = self.symbol_table.lookup_symbol(name) {
                                // Regular function lookup
                                match &info.kind {
                                    SymbolKind::Function {
                                        parameters,
                                        return_type,
                                    } => (
                                        name.clone(),
                                        parameters.clone(),
                                        return_type.clone(),
                                        false,
                                    ),
                                    SymbolKind::BuiltinFunction {
                                        parameters,
                                        return_type,
                                    } => (
                                        name.clone(),
                                        parameters.clone(),
                                        return_type.clone(),
                                        true,
                                    ),
                                    _ => {
                                        self.error_reporter.add_error(CompilerError::type_error(
                                            format!("'{}' is not a function", name),
                                            loc.clone(),
                                        ));
                                        return Err(());
                                    }
                                }
                            } else if let Some(receiver_type) = argument_types.first() {
                                if let Some(method_info) = self
                                    .symbol_table
                                    .lookup_builtin_method_for_receiver(receiver_type, name)
                                {
                                    (
                                        name.clone(),
                                        method_info.parameters.clone(),
                                        method_info.return_type.clone(),
                                        true,
                                    )
                                } else if let Some(suggestion) =
                                    suggest_method_to_function(name, &self.symbol_table)
                                {
                                    self.error_reporter.add_error(
                                        CompilerError::semantic_error(
                                            format!("Method '.{}()' is not supported", name),
                                            loc.clone(),
                                        )
                                        .with_hint(format!("Use {} instead", suggestion)),
                                    );
                                    return Err(());
                                } else {
                                    // Semantic-aware suggestion using actual functions in scope
                                    let mut error = CompilerError::semantic_error(
                                        format!("Use of undeclared function '{}'", name),
                                        loc.clone(),
                                    );
                                    if let Some(suggestion) =
                                        suggest_function_from_symbols(name, &self.symbol_table)
                                    {
                                        error = error
                                            .with_hint(format!("Did you mean '{}'?", suggestion));
                                    }
                                    self.error_reporter.add_error(error);
                                    return Err(());
                                }
                            } else {
                                // Semantic-aware suggestion using actual functions in scope
                                if let Some(suggestion) =
                                    suggest_method_to_function(name, &self.symbol_table)
                                {
                                    self.error_reporter.add_error(
                                        CompilerError::semantic_error(
                                            format!("Method '.{}()' is not supported", name),
                                            loc.clone(),
                                        )
                                        .with_hint(format!("Use {} instead", suggestion)),
                                    );
                                    return Err(());
                                }
                                let mut error = CompilerError::semantic_error(
                                    format!("Use of undeclared function '{}'", name),
                                    loc.clone(),
                                );
                                if let Some(suggestion) =
                                    suggest_function_from_symbols(name, &self.symbol_table)
                                {
                                    error =
                                        error.with_hint(format!("Did you mean '{}'?", suggestion));
                                }
                                self.error_reporter.add_error(error);
                                return Err(());
                            }
                        }
                        // Handle field access: could be a qualified function call (module.func)
                        // or an unsupported method-style call (obj.method)
                        AstNode::FieldAccess {
                            object,
                            field_name,
                            location: field_loc,
                        } => {
                            // Try to resolve as a qualified function call (e.g., module.func)
                            if let AstNode::Identifier(obj_name, _) = object.as_ref() {
                                let qualified_name = format!("{}.{}", obj_name, field_name);
                                if let Some(info) = self.symbol_table.lookup_symbol(&qualified_name)
                                {
                                    match &info.kind {
                                        SymbolKind::Function {
                                            parameters,
                                            return_type,
                                        } => (
                                            qualified_name,
                                            parameters.clone(),
                                            return_type.clone(),
                                            false,
                                        ),
                                        SymbolKind::BuiltinFunction {
                                            parameters,
                                            return_type,
                                        } => (
                                            qualified_name,
                                            parameters.clone(),
                                            return_type.clone(),
                                            true,
                                        ),
                                        _ => {
                                            self.error_reporter.add_error(
                                                CompilerError::type_error(
                                                    format!(
                                                        "'{}' is not a function",
                                                        qualified_name
                                                    ),
                                                    field_loc.clone(),
                                                ),
                                            );
                                            return Err(());
                                        }
                                    }
                                } else if let Some(suggestion) =
                                    suggest_method_to_function(field_name, &self.symbol_table)
                                {
                                    self.error_reporter.add_error(
                                        CompilerError::semantic_error(
                                            format!("Method '.{}()' is not supported", field_name),
                                            field_loc.clone(),
                                        )
                                        .with_hint(format!("Use {} instead", suggestion)),
                                    );
                                    return Err(());
                                } else {
                                    self.error_reporter.add_error(CompilerError::type_error(
                                    format!("Method calls like '.{}()' are not supported", field_name),
                                    field_loc.clone(),
                                ).with_hint("Stoffel-Lang uses functions instead of methods. Try using a function call."));
                                    return Err(());
                                }
                            } else {
                                // Object is not a simple identifier — unsupported method call
                                if let Some(suggestion) =
                                    suggest_method_to_function(field_name, &self.symbol_table)
                                {
                                    self.error_reporter.add_error(
                                        CompilerError::semantic_error(
                                            format!("Method '.{}()' is not supported", field_name),
                                            field_loc.clone(),
                                        )
                                        .with_hint(format!("Use {} instead", suggestion)),
                                    );
                                } else {
                                    self.error_reporter.add_error(CompilerError::type_error(
                                    format!("Method calls like '.{}()' are not supported", field_name),
                                    field_loc.clone(),
                                ).with_hint("Stoffel-Lang uses functions instead of methods. Try using a function call."));
                                }
                                return Err(());
                            }
                        }
                        // Other non-callable expressions
                        _ => {
                            self.error_reporter.add_error(CompilerError::type_error(
                                "Expression is not callable",
                                checked_function_node.location(),
                            ));
                            return Err(());
                        }
                    };

                if is_builtin_call
                    && matches!(
                        function_name.as_str(),
                        "mul_scalar"
                            | "add_constant"
                            | "add_scalar"
                            | "Share.mul_scalar"
                            | "Share.add_constant"
                            | "Share.add_scalar"
                    )
                {
                    if let Some(ty) = argument_types.get(1) {
                        if ty.is_secret() || !Self::is_clear_numeric_type(ty) {
                            self.error_reporter.add_error(CompilerError::type_error(
                                format!(
                                    "'{}' requires a clear numeric scalar, found '{}'",
                                    function_name, ty
                                ),
                                checked_arguments[1].location(),
                            ));
                            return Err(());
                        }
                    }
                }
                // 4. Validate argument count
                let mut call_parameters = self.builtin_call_parameters(
                    &function_name,
                    &expected_param_types,
                    is_builtin_call,
                );
                // `len` is Pythonic: it accepts a string as well as a list[T].
                if is_builtin_call
                    && function_name == "len"
                    && argument_types.len() == 1
                    && matches!(argument_types[0].underlying_type(), SymbolType::String)
                {
                    call_parameters = vec![CallParameterInfo {
                        ty: SymbolType::String,
                        has_default: false,
                        is_variadic: false,
                    }];
                }
                let min_args = Self::minimum_argument_count(&call_parameters);
                let has_variadic = Self::has_variadic_parameter(&call_parameters);
                let max_args = if has_variadic {
                    None
                } else {
                    Some(call_parameters.len())
                };
                if argument_types.len() < min_args
                    || max_args.is_some_and(|max_args| argument_types.len() > max_args)
                {
                    let expected = match max_args {
                        Some(max_args) if min_args == max_args => min_args.to_string(),
                        Some(max_args) => format!("{min_args} to {max_args}"),
                        None => format!("at least {min_args}"),
                    };
                    self.error_reporter.add_error(CompilerError::semantic_error(
                        format!(
                            "Function '{}' expects {} argument(s), but {} were provided",
                            function_name,
                            expected,
                            argument_types.len()
                        ),
                        location.clone(),
                    ));
                    return Err(());
                }

                // 5. Validate arguments, binding any function-level type parameters per call
                let mut generic_bindings = HashMap::new();
                for idx in 0..argument_types.len() {
                    let expected_ty = Self::expected_argument_type_for_index(&call_parameters, idx)
                        .unwrap_or(&SymbolType::Unknown);
                    let mut arg_loc = checked_arguments[idx].location();
                    if arg_loc.line == 0 {
                        arg_loc = location.clone();
                    }

                    let expected_after_bindings =
                        Self::substitute_type_vars(expected_ty, &generic_bindings);
                    Self::refine_argument_with_expected(
                        &mut checked_arguments[idx],
                        &mut argument_types[idx],
                        &expected_after_bindings,
                    );

                    if Self::contains_unrefined_share_random_call(&checked_arguments[idx]) {
                        self.error_reporter.add_error(
                            CompilerError::type_error(
                                "Share.random() requires an expected secret integer type"
                                    .to_string(),
                                arg_loc,
                            )
                            .with_hint(
                                "Assign it to a typed secret integer before passing it, such as 'var s: secret int64 = Share.random()'",
                            ),
                        );
                        return Err(());
                    }

                    if is_builtin_call
                        && idx == 0
                        && expected_ty.is_secret()
                        && !Self::is_secret_or_share_value(&argument_types[idx])
                    {
                        self.error_reporter.add_error(CompilerError::type_error(
                            format!(
                                "Expected secret value, found '{}'",
                                declared_type_to_string(&argument_types[idx])
                            ),
                            arg_loc,
                        ));
                        return Err(());
                    }

                    if Self::clear_integer_conversion_error(
                        Some(&checked_arguments[idx]),
                        &argument_types[idx],
                        expected_ty,
                    ) {
                        self.add_call_argument_type_error(
                            &function_name,
                            idx,
                            &argument_types[idx],
                            expected_ty,
                            arg_loc,
                        );
                        return Err(());
                    }

                    if self
                        .check_generic_compat(
                            Some(&checked_arguments[idx]),
                            &argument_types[idx],
                            expected_ty,
                            &mut generic_bindings,
                            arg_loc,
                        )
                        .is_err()
                    {
                        return Err(());
                    }
                }

                // 6. Reconstruct the node with checked parts and resolved return type
                let resolved_function_node = match &checked_function_node {
                    AstNode::Identifier(_, loc) => {
                        AstNode::Identifier(function_name.clone(), loc.clone())
                    }
                    AstNode::FieldAccess { location, .. } => {
                        AstNode::Identifier(function_name.clone(), location.clone())
                    }
                    _ => checked_function_node,
                };
                let resolved_return_type =
                    Self::substitute_type_vars(&return_type, &generic_bindings);
                let resolved_return_type = if function_name == "Share.random"
                    && contextual_return_type
                        .as_ref()
                        .is_some_and(Self::share_random_expected_type)
                {
                    contextual_return_type.unwrap()
                } else {
                    resolved_return_type
                };
                let reconstructed_node = AstNode::FunctionCall {
                    function: Box::new(resolved_function_node),
                    arguments: checked_arguments,
                    location,
                    resolved_return_type: Some(resolved_return_type.clone()), // Store the resolved type
                };

                Ok((reconstructed_node, resolved_return_type)) // Type of the call is the function's return type
            }

            AstNode::CommandCall {
                command,
                arguments,
                location,
                resolved_return_type: _,
            } => {
                // 1. Analyze the command expression (usually an identifier)
                let (checked_command_node, _command_expr_type) = self.analyze_node(*command)?;

                // 2. Analyze arguments
                let mut checked_arguments = Vec::with_capacity(arguments.len());
                let mut argument_types = Vec::with_capacity(arguments.len());
                for arg_node in arguments {
                    let (checked_arg, arg_type) = self.analyze_node(arg_node)?;
                    checked_arguments.push(checked_arg);
                    argument_types.push(arg_type);
                }

                // 3. Determine the actual function symbol and its type from the command
                let (function_name, function_info) = match &checked_command_node {
                    AstNode::Identifier(name, loc) => {
                        if let Some(info) = self.symbol_table.lookup_symbol(name) {
                            (name.clone(), info.clone())
                        } else {
                            let mut error = CompilerError::semantic_error(
                                format!("Use of undeclared function '{}' in command call", name),
                                loc.clone(),
                            );
                            if let Some(suggestion) =
                                suggest_function_from_symbols(name, &self.symbol_table)
                            {
                                error = error.with_hint(format!("Did you mean '{}'?", suggestion));
                            }
                            self.error_reporter.add_error(error);
                            return Err(());
                        }
                    }
                    _ => {
                        self.error_reporter.add_error(CompilerError::type_error(
                            "Command expression is not callable",
                            checked_command_node.location(),
                        ));
                        return Err(());
                    }
                };

                // 4. Check if the symbol is a function and validate arguments (similar to FunctionCall)
                let (expected_param_types, return_type, is_builtin_call) = match &function_info.kind
                {
                    SymbolKind::Function {
                        parameters,
                        return_type,
                    } => (parameters.clone(), return_type.clone(), false),
                    SymbolKind::BuiltinFunction {
                        parameters,
                        return_type,
                    } => (parameters.clone(), return_type.clone(), true),
                    _ => {
                        self.error_reporter.add_error(CompilerError::type_error(
                            format!(
                                "'{}' is not a function (used in command call)",
                                function_name
                            ),
                            checked_command_node.location(),
                        ));
                        return Err(());
                    }
                };

                let call_parameters = self.builtin_call_parameters(
                    &function_name,
                    &expected_param_types,
                    is_builtin_call,
                );
                let min_args = Self::minimum_argument_count(&call_parameters);
                let has_variadic = Self::has_variadic_parameter(&call_parameters);
                let max_args = if has_variadic {
                    None
                } else {
                    Some(call_parameters.len())
                };
                if argument_types.len() < min_args
                    || max_args.is_some_and(|max_args| argument_types.len() > max_args)
                {
                    let expected = match max_args {
                        Some(max_args) if min_args == max_args => min_args.to_string(),
                        Some(max_args) => format!("{min_args} to {max_args}"),
                        None => format!("at least {min_args}"),
                    };
                    self.error_reporter.add_error(CompilerError::semantic_error(
                        format!(
                            "Function '{}' expects {} argument(s), but {} were provided",
                            function_name,
                            expected,
                            argument_types.len()
                        ),
                        location.clone(),
                    ));
                    return Err(());
                }

                // 5. Validate arguments, binding any function-level type parameters per call
                let mut generic_bindings = HashMap::new();
                for idx in 0..argument_types.len() {
                    let expected_ty = Self::expected_argument_type_for_index(&call_parameters, idx)
                        .unwrap_or(&SymbolType::Unknown);
                    let arg_loc = checked_arguments[idx].location();
                    let expected_after_bindings =
                        Self::substitute_type_vars(expected_ty, &generic_bindings);
                    Self::refine_argument_with_expected(
                        &mut checked_arguments[idx],
                        &mut argument_types[idx],
                        &expected_after_bindings,
                    );

                    if Self::contains_unrefined_share_random_call(&checked_arguments[idx]) {
                        self.error_reporter.add_error(
                            CompilerError::type_error(
                                "Share.random() requires an expected secret integer type"
                                    .to_string(),
                                arg_loc.clone(),
                            )
                            .with_hint(
                                "Assign it to a typed secret integer before passing it, such as 'var s: secret int64 = Share.random()'",
                            ),
                        );
                        return Err(());
                    }

                    if self
                        .check_generic_compat(
                            Some(&checked_arguments[idx]),
                            &argument_types[idx],
                            expected_ty,
                            &mut generic_bindings,
                            arg_loc,
                        )
                        .is_err()
                    {
                        return Err(());
                    }
                }

                // 6. Reconstruct the node with checked parts and resolved return type
                let resolved_return_type =
                    Self::substitute_type_vars(&return_type, &generic_bindings);
                let reconstructed_node = AstNode::CommandCall {
                    command: Box::new(checked_command_node),
                    arguments: checked_arguments,
                    location,
                    resolved_return_type: Some(resolved_return_type.clone()), // Store the resolved type
                };
                Ok((reconstructed_node, resolved_return_type)) // Type of the call is the function's return type
            }

            // --- Binary operations (comparisons etc.) ---
            AstNode::BinaryOperation {
                op,
                left,
                right,
                location,
            } => {
                // Analyze both sides first
                let (checked_left, left_ty) = self.analyze_node(*left)?;
                let (checked_right, right_ty) = self.analyze_node(*right)?;

                // Helper: are these comparison operators?
                let is_cmp = matches!(op.as_str(), "==" | "!=" | "<" | "<=" | ">" | ">=");

                if is_cmp {
                    // Validate operand types. Equality also supports booleans.
                    let l_under = left_ty.underlying_type().clone();
                    let r_under = right_ty.underlying_type().clone();
                    if matches!(op.as_str(), "==" | "!=") {
                        if let (SymbolType::List(left_elem), SymbolType::List(right_elem)) =
                            (&l_under, &r_under)
                        {
                            if !Self::types_compatible(left_elem, right_elem) {
                                self.error_reporter.add_error(CompilerError::type_error(
                                    format!(
                                        "Cannot compare lists with incompatible element types '{}' and '{}'",
                                        declared_type_to_string(left_elem),
                                        declared_type_to_string(right_elem)
                                    ),
                                    location.clone(),
                                ));
                                return Err(());
                            }

                            return Ok((
                                AstNode::BinaryOperation {
                                    op,
                                    left: Box::new(checked_left),
                                    right: Box::new(checked_right),
                                    location,
                                },
                                SymbolType::Bool,
                            ));
                        }
                    }

                    let is_left_numeric = Self::is_clear_numeric_type(&l_under);
                    let is_right_numeric = Self::is_clear_numeric_type(&r_under);
                    let is_same_clear_comparable = l_under == r_under
                        && matches!(l_under, SymbolType::Bool | SymbolType::String);

                    if (!is_left_numeric || !is_right_numeric)
                        && !is_same_clear_comparable
                        && !matches!(l_under, SymbolType::Unknown)
                        && !matches!(r_under, SymbolType::Unknown)
                    {
                        // If both are known and not numeric, error out
                        let err_loc = match (&checked_left, &checked_right) {
                            (l, _) if !is_left_numeric => l.location(),
                            (_, r) => r.location(),
                        };
                        self.error_reporter.add_error(CompilerError::type_error(
                            format!("Operands to '{}' must be numeric (ints or float), or matching bool/string values, found '{}' and '{}'",
                                    op,
                                    declared_type_to_string(&left_ty),
                                    declared_type_to_string(&right_ty)),
                            err_loc,
                        ).with_hint("Cast or adjust operand types to be comparable"));
                        return Err(());
                    }

                    // Result type of comparison:
                    // - public bool when both operands are public
                    // - secret bool when any operand is secret
                    let result_ty = if left_ty.is_secret() || right_ty.is_secret() {
                        SymbolType::Secret(Box::new(SymbolType::Bool))
                    } else {
                        SymbolType::Bool
                    };

                    return Ok((
                        AstNode::BinaryOperation {
                            op,
                            left: Box::new(checked_left),
                            right: Box::new(checked_right),
                            location,
                        },
                        result_ty,
                    ));
                }

                if matches!(op.as_str(), "and" | "or" | "xor") {
                    let l_under = left_ty.underlying_type().clone();
                    let r_under = right_ty.underlying_type().clone();

                    // Nim-style: on integers these are bitwise operators.
                    if l_under.is_integer() && r_under.is_integer() {
                        if l_under != r_under {
                            self.error_reporter.add_error(CompilerError::type_error(
                                format!(
                                    "Bitwise '{}' requires matching integer types, found '{}' and '{}'",
                                    op,
                                    declared_type_to_string(&left_ty),
                                    declared_type_to_string(&right_ty)
                                ),
                                location.clone(),
                            ));
                            return Err(());
                        }
                        if left_ty.is_secret() || right_ty.is_secret() {
                            self.error_reporter.add_error(CompilerError::semantic_error(
                                format!(
                                    "Bitwise '{}' is not supported on secret integers (only secret bool)",
                                    op
                                ),
                                location.clone(),
                            ));
                            return Err(());
                        }
                        return Ok((
                            AstNode::BinaryOperation {
                                op,
                                left: Box::new(checked_left),
                                right: Box::new(checked_right),
                                location,
                            },
                            l_under,
                        ));
                    }

                    let both_bool = l_under == SymbolType::Bool && r_under == SymbolType::Bool;
                    let both_unknown_or_bool =
                        matches!(l_under, SymbolType::Unknown | SymbolType::Bool)
                            && matches!(r_under, SymbolType::Unknown | SymbolType::Bool);

                    if !both_unknown_or_bool {
                        self.error_reporter.add_error(CompilerError::type_error(
                            format!(
                                "Operands to '{}' must both be bool (or matching integers for bitwise use), found '{}' and '{}'",
                                op,
                                declared_type_to_string(&left_ty),
                                declared_type_to_string(&right_ty)
                            ),
                            location.clone(),
                        ));
                        return Err(());
                    }

                    let result_ty = if left_ty.is_secret() || right_ty.is_secret() {
                        SymbolType::Secret(Box::new(SymbolType::Bool))
                    } else if both_bool || both_unknown_or_bool {
                        SymbolType::Bool
                    } else {
                        SymbolType::Unknown
                    };

                    return Ok((
                        AstNode::BinaryOperation {
                            op,
                            left: Box::new(checked_left),
                            right: Box::new(checked_right),
                            location,
                        },
                        result_ty,
                    ));
                }

                if op == "+" {
                    if let (SymbolType::String, SymbolType::String) =
                        (left_ty.underlying_type(), right_ty.underlying_type())
                    {
                        return Ok((
                            AstNode::BinaryOperation {
                                op,
                                left: Box::new(checked_left),
                                right: Box::new(checked_right),
                                location,
                            },
                            SymbolType::String,
                        ));
                    }

                    if let (SymbolType::List(left_elem), SymbolType::List(right_elem)) =
                        (left_ty.underlying_type(), right_ty.underlying_type())
                    {
                        if !Self::types_compatible(left_elem, right_elem) {
                            self.error_reporter.add_error(CompilerError::type_error(
                                format!(
                                    "Cannot concatenate lists with incompatible element types '{}' and '{}'",
                                    declared_type_to_string(left_elem),
                                    declared_type_to_string(right_elem)
                                ),
                                location.clone(),
                            ));
                            return Err(());
                        }

                        return Ok((
                            AstNode::BinaryOperation {
                                op,
                                left: Box::new(checked_left),
                                right: Box::new(checked_right),
                                location,
                            },
                            left_ty.clone(),
                        ));
                    }
                }

                if op == "*" {
                    let left_is_list = matches!(left_ty.underlying_type(), SymbolType::List(_));
                    let right_is_list = matches!(right_ty.underlying_type(), SymbolType::List(_));
                    let left_is_int = left_ty.is_integer() && !left_ty.is_secret();
                    let right_is_int = right_ty.is_integer() && !right_ty.is_secret();
                    if (left_is_list || right_is_list)
                        && !(left_is_list && right_is_int || left_is_int && right_is_list)
                    {
                        self.error_reporter.add_error(CompilerError::type_error(
                            format!("List repetition requires a clear integer count, found '{}' and '{}'", left_ty, right_ty), location.clone())
                            .with_hint("Use list * clear_integer; for a field element and a Share, use Share.mul_field(share, field_bytes)"));
                        return Err(());
                    }

                    if left_is_list && right_is_int {
                        return Ok((
                            AstNode::BinaryOperation {
                                op,
                                left: Box::new(checked_left),
                                right: Box::new(checked_right),
                                location,
                            },
                            left_ty.clone(),
                        ));
                    }

                    if left_is_int && right_is_list {
                        return Ok((
                            AstNode::BinaryOperation {
                                op,
                                left: Box::new(checked_left),
                                right: Box::new(checked_right),
                                location,
                            },
                            right_ty.clone(),
                        ));
                    }
                }

                if op == "in" {
                    let container_under = right_ty.underlying_type().clone();
                    let container_ok = matches!(
                        container_under,
                        SymbolType::List(_)
                            | SymbolType::Dict(_, _)
                            | SymbolType::String
                            | SymbolType::Unknown
                    );
                    if !container_ok {
                        self.error_reporter.add_error(CompilerError::type_error(
                            format!(
                                "Right side of 'in' must be a list, dict, or string, found '{}'",
                                declared_type_to_string(&right_ty)
                            ),
                            location.clone(),
                        ));
                        return Err(());
                    }
                    if left_ty.is_secret() || right_ty.is_secret() {
                        self.error_reporter.add_error(CompilerError::semantic_error(
                            "'in' is not supported on secret values",
                            location.clone(),
                        ));
                        return Err(());
                    }
                    return Ok((
                        AstNode::BinaryOperation {
                            op,
                            left: Box::new(checked_left),
                            right: Box::new(checked_right),
                            location,
                        },
                        SymbolType::Bool,
                    ));
                }

                if matches!(op.as_str(), "shl" | "shr") {
                    let l_under = left_ty.underlying_type().clone();
                    let r_under = right_ty.underlying_type().clone();
                    let left_ok = l_under.is_integer() || matches!(l_under, SymbolType::Unknown);
                    let right_ok = r_under.is_integer() || matches!(r_under, SymbolType::Unknown);
                    if !left_ok || !right_ok {
                        self.error_reporter.add_error(CompilerError::type_error(
                            format!(
                                "Operands to '{}' must be integers, found '{}' and '{}'",
                                op,
                                declared_type_to_string(&left_ty),
                                declared_type_to_string(&right_ty)
                            ),
                            location.clone(),
                        ));
                        return Err(());
                    }
                    if left_ty.is_secret() || right_ty.is_secret() {
                        self.error_reporter.add_error(CompilerError::semantic_error(
                            format!("'{}' is not supported on secret values", op),
                            location.clone(),
                        ));
                        return Err(());
                    }
                    if l_under.is_integer() && r_under.is_integer() && l_under != r_under {
                        self.error_reporter.add_error(CompilerError::type_error(
                            format!(
                                "'{}' requires matching integer types, found '{}' and '{}'",
                                op,
                                declared_type_to_string(&left_ty),
                                declared_type_to_string(&right_ty)
                            ),
                            location.clone(),
                        ));
                        return Err(());
                    }
                    return Ok((
                        AstNode::BinaryOperation {
                            op,
                            left: Box::new(checked_left),
                            right: Box::new(checked_right),
                            location,
                        },
                        l_under,
                    ));
                }

                if matches!(op.as_str(), "+" | "-" | "*" | "/" | "%" | "mod") {
                    let mut checked_left = checked_left;
                    let mut checked_right = checked_right;
                    let mut left_ty = left_ty;
                    let mut right_ty = right_ty;

                    // Untyped integer literals adopt the width of the other side
                    // (e.g. `a32 + 1` treats 1 as int32, `f + 1` treats 1 as float).
                    if Self::is_untyped_int_literal(&checked_left)
                        && Self::is_clear_numeric_type(right_ty.underlying_type())
                    {
                        Self::refine_argument_with_expected(
                            &mut checked_left,
                            &mut left_ty,
                            right_ty.underlying_type(),
                        );
                    } else if Self::is_untyped_int_literal(&checked_right)
                        && Self::is_clear_numeric_type(left_ty.underlying_type())
                    {
                        Self::refine_argument_with_expected(
                            &mut checked_right,
                            &mut right_ty,
                            left_ty.underlying_type(),
                        );
                    }

                    let l_under = left_ty.underlying_type().clone();
                    let r_under = right_ty.underlying_type().clone();
                    let result_secret = left_ty.is_secret() || right_ty.is_secret();
                    let wrap = |ty: SymbolType| {
                        if result_secret {
                            SymbolType::Secret(Box::new(ty))
                        } else {
                            ty
                        }
                    };
                    let rebuild = |left: AstNode, right: AstNode| AstNode::BinaryOperation {
                        op: op.clone(),
                        left: Box::new(left),
                        right: Box::new(right),
                        location: location.clone(),
                    };

                    let unknown_involved = matches!(l_under, SymbolType::Unknown)
                        || matches!(r_under, SymbolType::Unknown);
                    if unknown_involved {
                        return Ok((rebuild(checked_left, checked_right), SymbolType::Unknown));
                    }

                    // Opaque Share values support arithmetic via the MPC runtime;
                    // the result is a Share (refined by annotations downstream).
                    let l_share = Self::is_share_alias_type(&left_ty);
                    let r_share = Self::is_share_alias_type(&right_ty);
                    if l_share || r_share {
                        let left_share = l_share || left_ty.is_secret();
                        let right_share = r_share || right_ty.is_secret();
                        let clear_int = |ty: &SymbolType| ty.is_integer() && !ty.is_secret();
                        let clear_real =
                            |ty: &SymbolType| Self::is_clear_real_type(ty) && !ty.is_secret();
                        let supported = match op.as_str() {
                            "+" | "-" => {
                                (left_share && right_share)
                                    || (left_share && clear_int(&right_ty))
                                    || (clear_int(&left_ty) && right_share)
                            }
                            "*" => {
                                (left_share && right_share)
                                    || (left_share
                                        && (clear_int(&right_ty) || clear_real(&right_ty)))
                                    || ((clear_int(&left_ty) || clear_real(&left_ty))
                                        && right_share)
                            }
                            "/" => left_share && (clear_int(&right_ty) || clear_real(&right_ty)),
                            _ => false,
                        };
                        if !supported {
                            self.error_reporter.add_error(CompilerError::type_error(
                                format!("Unsupported Share arithmetic: '{}' {} '{}'", left_ty, op, right_ty), location.clone())
                                .with_hint("Use supported Share/scalar arithmetic; use Share.add_field or Share.mul_field for field bytes"));
                            return Err(());
                        }
                        let result_ty = if l_share {
                            left_ty.clone()
                        } else {
                            right_ty.clone()
                        };
                        return Ok((rebuild(checked_left, checked_right), result_ty));
                    }

                    let both_numeric = Self::is_clear_numeric_type(&l_under)
                        && Self::is_clear_numeric_type(&r_under);
                    let left_secret_bool = left_ty.is_secret() && l_under == SymbolType::Bool;
                    let right_secret_bool = right_ty.is_secret() && r_under == SymbolType::Bool;
                    let left_bool_share_operand = left_secret_bool
                        || (right_secret_bool
                            && Self::is_untyped_int_literal(&checked_left)
                            && Self::int_literal_bool_value(&checked_left).is_some());
                    let right_bool_share_operand = right_secret_bool
                        || (left_secret_bool
                            && Self::is_untyped_int_literal(&checked_right)
                            && Self::int_literal_bool_value(&checked_right).is_some());
                    if matches!(op.as_str(), "+" | "-" | "*")
                        && (left_secret_bool || right_secret_bool)
                        && left_bool_share_operand
                        && right_bool_share_operand
                    {
                        return Ok((
                            rebuild(checked_left, checked_right),
                            SymbolType::Secret(Box::new(SymbolType::Bool)),
                        ));
                    }

                    if both_numeric {
                        // Same type: fine.
                        if l_under == r_under {
                            let result = wrap(l_under);
                            return Ok((rebuild(checked_left, checked_right), result));
                        }
                        // Fixed-point and float share a runtime representation.
                        let fixed_float_mix = (matches!(l_under, SymbolType::Fixed { .. })
                            && r_under == SymbolType::Float)
                            || (l_under == SymbolType::Float
                                && matches!(r_under, SymbolType::Fixed { .. }));
                        if fixed_float_mix {
                            let result_under = if matches!(l_under, SymbolType::Fixed { .. }) {
                                l_under
                            } else {
                                r_under
                            };
                            return Ok((rebuild(checked_left, checked_right), wrap(result_under)));
                        }
                        // int64 <-> float/fixed coercion is supported by the VM
                        // (clear fixed-point values share the float representation).
                        let i64_real_mix = (l_under == SymbolType::Int64
                            && Self::is_clear_real_type(&r_under))
                            || (Self::is_clear_real_type(&l_under) && r_under == SymbolType::Int64);
                        if i64_real_mix {
                            let result_under = if Self::is_clear_real_type(&l_under) {
                                l_under
                            } else {
                                r_under
                            };
                            return Ok((rebuild(checked_left, checked_right), wrap(result_under)));
                        }
                        let hint = if l_under.is_integer() && r_under.is_integer() {
                            "Give both operands the same width, e.g. with literal suffixes like 10i32"
                        } else {
                            "Convert the integer operand explicitly or use matching numeric types"
                        };
                        self.error_reporter.add_error(
                            CompilerError::type_error(
                                format!(
                                    "Arithmetic '{}' requires matching numeric types, found '{}' and '{}'",
                                    op,
                                    declared_type_to_string(&left_ty),
                                    declared_type_to_string(&right_ty)
                                ),
                                location.clone(),
                            )
                            .with_hint(hint),
                        );
                        return Err(());
                    }

                    // Non-numeric operands (bools, strings outside of string+string,
                    // lists outside of concat/repeat, objects, nil).
                    self.error_reporter.add_error(CompilerError::type_error(
                        format!(
                            "Operands to '{}' must be numeric, found '{}' and '{}'",
                            op,
                            declared_type_to_string(&left_ty),
                            declared_type_to_string(&right_ty)
                        ),
                        location.clone(),
                    ));
                    return Err(());
                }

                // For other binary ops we don't handle here; pass through as Unknown type.
                Ok((
                    AstNode::BinaryOperation {
                        op,
                        left: Box::new(checked_left),
                        right: Box::new(checked_right),
                        location,
                    },
                    SymbolType::Unknown,
                ))
            }

            // --- Collection Literals and Access ---
            AstNode::ListLiteral { elements, location } => {
                let mut analyzed = Vec::with_capacity(elements.len());
                for elem in elements {
                    analyzed.push(self.analyze_node(elem)?);
                }

                // The element type is set by the first element that is not an
                // untyped integer literal (literals adapt to their context,
                // e.g. [0, local] where local is a float).
                let element_type_entry = analyzed
                    .iter()
                    .find(|(node, ty)| {
                        !matches!(ty, SymbolType::Unknown) && !Self::is_untyped_int_literal(node)
                    })
                    .or_else(|| {
                        analyzed
                            .iter()
                            .find(|(_, ty)| !matches!(ty, SymbolType::Unknown))
                    });
                let element_type_from_untyped_literal =
                    element_type_entry.is_some_and(|(node, _)| Self::is_untyped_int_literal(node));
                let element_type = element_type_entry
                    .map(|(_, ty)| ty.clone())
                    .unwrap_or(SymbolType::Unknown);

                let mut checked_elements = Vec::with_capacity(analyzed.len());
                for (mut checked_elem, mut elem_ty) in analyzed {
                    if !(matches!(element_type, SymbolType::Unknown)
                        || matches!(elem_ty, SymbolType::Unknown)
                        || element_type_from_untyped_literal
                            && Self::is_untyped_int_literal(&checked_elem))
                    {
                        Self::refine_argument_with_expected(
                            &mut checked_elem,
                            &mut elem_ty,
                            &element_type,
                        );
                        if !Self::types_compatible(&elem_ty, &element_type) {
                            self.error_reporter.add_error(
                                CompilerError::type_error(
                                    format!(
                                        "List elements must share one type: expected '{}', found '{}'",
                                        declared_type_to_string(&element_type),
                                        declared_type_to_string(&elem_ty)
                                    ),
                                    checked_elem.location(),
                                )
                                .with_hint("Use a single element type, or model mixed data with an object"),
                            );
                            return Err(());
                        }
                    }
                    checked_elements.push(checked_elem);
                }

                Ok((
                    AstNode::ListLiteral {
                        elements: checked_elements,
                        location,
                    },
                    SymbolType::List(Box::new(element_type)),
                ))
            }

            AstNode::DictLiteral { pairs, location } => {
                let mut checked_pairs = Vec::with_capacity(pairs.len());
                let mut key_type = SymbolType::Unknown;
                let mut value_type = SymbolType::Unknown;
                let mut key_type_from_untyped_literal = false;
                let mut value_type_from_untyped_literal = false;

                for (key, value) in pairs {
                    let (mut checked_key, mut key_ty) = self.analyze_node(key)?;
                    let (mut checked_value, mut val_ty) = self.analyze_node(value)?;
                    // Infer types from first pair; later pairs must agree.
                    if matches!(key_type, SymbolType::Unknown) {
                        key_type = key_ty.clone();
                        key_type_from_untyped_literal = Self::is_untyped_int_literal(&checked_key);
                    } else if !(matches!(key_ty, SymbolType::Unknown)
                        || key_type_from_untyped_literal
                            && Self::is_untyped_int_literal(&checked_key))
                    {
                        Self::refine_argument_with_expected(
                            &mut checked_key,
                            &mut key_ty,
                            &key_type,
                        );
                        if !Self::types_compatible(&key_ty, &key_type) {
                            self.error_reporter.add_error(CompilerError::type_error(
                                format!(
                                    "Dict keys must share one type: expected '{}', found '{}'",
                                    declared_type_to_string(&key_type),
                                    declared_type_to_string(&key_ty)
                                ),
                                checked_key.location(),
                            ));
                            return Err(());
                        }
                    }
                    if matches!(value_type, SymbolType::Unknown) {
                        value_type = val_ty.clone();
                        value_type_from_untyped_literal =
                            Self::is_untyped_int_literal(&checked_value);
                    } else if !(matches!(val_ty, SymbolType::Unknown)
                        || value_type_from_untyped_literal
                            && Self::is_untyped_int_literal(&checked_value))
                    {
                        Self::refine_argument_with_expected(
                            &mut checked_value,
                            &mut val_ty,
                            &value_type,
                        );
                        if !Self::types_compatible(&val_ty, &value_type) {
                            self.error_reporter.add_error(CompilerError::type_error(
                                format!(
                                    "Dict values must share one type: expected '{}', found '{}'",
                                    declared_type_to_string(&value_type),
                                    declared_type_to_string(&val_ty)
                                ),
                                checked_value.location(),
                            ));
                            return Err(());
                        }
                    }
                    checked_pairs.push((checked_key, checked_value));
                }

                Ok((
                    AstNode::DictLiteral {
                        pairs: checked_pairs,
                        location,
                    },
                    SymbolType::Dict(Box::new(key_type), Box::new(value_type)),
                ))
            }

            AstNode::IndexAccess {
                base,
                index,
                location,
            } => {
                let (checked_base, base_type) = self.analyze_node(*base)?;
                let (checked_index, index_type) = self.analyze_node(*index)?;

                // Determine element type based on base type
                let element_type = match base_type.underlying_type() {
                    SymbolType::List(elem) => elem.as_ref().clone(),
                    SymbolType::String => SymbolType::String, // String indexing returns string (single char)
                    SymbolType::Dict(_, val) => val.as_ref().clone(),
                    _ => SymbolType::Unknown, // Allow dynamic access for unknown types
                };

                // Validate the index type: integers for lists/strings, the key
                // type for dicts. Secret indices are never allowed.
                if index_type.is_secret() {
                    self.error_reporter.add_error(CompilerError::semantic_error(
                        "Cannot index with a secret value",
                        checked_index.location(),
                    ));
                    return Err(());
                }
                match base_type.underlying_type() {
                    SymbolType::List(_) | SymbolType::String => {
                        let idx_under = index_type.underlying_type();
                        if !idx_under.is_integer() && !matches!(idx_under, SymbolType::Unknown) {
                            self.error_reporter.add_error(CompilerError::type_error(
                                format!(
                                    "Index must be an integer, found '{}'",
                                    declared_type_to_string(&index_type)
                                ),
                                checked_index.location(),
                            ));
                            return Err(());
                        }
                    }
                    SymbolType::Dict(key_ty, _)
                        if !Self::types_compatible(index_type.underlying_type(), key_ty) =>
                    {
                        self.error_reporter.add_error(CompilerError::type_error(
                            format!(
                                "Dict key must be '{}', found '{}'",
                                declared_type_to_string(key_ty),
                                declared_type_to_string(&index_type)
                            ),
                            checked_index.location(),
                        ));
                        return Err(());
                    }
                    _ => {}
                }

                Ok((
                    AstNode::IndexAccess {
                        base: Box::new(checked_base),
                        index: Box::new(checked_index),
                        location,
                    },
                    element_type,
                ))
            }

            AstNode::FieldAccess {
                object,
                field_name,
                location,
            } => {
                if let AstNode::Identifier(object_name, _) = object.as_ref() {
                    let qualified_name = format!("{}.{}", object_name, field_name);
                    self.validate_variable_scope(&qualified_name, location.clone())?;
                    if let Some(info) = self.symbol_table.lookup_symbol(&qualified_name) {
                        return Ok((
                            AstNode::FieldAccess {
                                object,
                                field_name,
                                location,
                            },
                            info.symbol_type.clone(),
                        ));
                    }
                }

                // Enum member access (Color.Red) lowers to its int64 constant.
                if let AstNode::Identifier(object_name, _) = object.as_ref() {
                    if let Some(members) = self.enum_members.get(object_name) {
                        let Some(value) = members.get(&field_name).copied() else {
                            self.error_reporter.add_error(CompilerError::semantic_error(
                                format!("Enum '{}' has no member '{}'", object_name, field_name),
                                location.clone(),
                            ));
                            return Err(());
                        };
                        return Ok((
                            AstNode::Literal {
                                value: Value::Int {
                                    value: value as u128,
                                    kind: Some(crate::ast::IntKind::Signed(
                                        crate::ast::IntWidth::W64,
                                    )),
                                },
                                location,
                            },
                            SymbolType::Int64,
                        ));
                    }
                }

                let (checked_object, object_type) = self.analyze_node(*object)?;

                // Check if this looks like a method call attempt on a list or primitive type
                // and provide helpful suggestions
                let is_builtin_type = matches!(
                    object_type.underlying_type(),
                    SymbolType::List(_)
                        | SymbolType::Int64
                        | SymbolType::Int32
                        | SymbolType::Int16
                        | SymbolType::Int8
                        | SymbolType::Float
                        | SymbolType::Fixed { .. }
                        | SymbolType::String
                        | SymbolType::Bool
                );

                if is_builtin_type {
                    // Check if this is a common method name that should be a function
                    if let Some(suggestion) =
                        suggest_method_to_function(&field_name, &self.symbol_table)
                    {
                        self.error_reporter.add_error(
                            CompilerError::semantic_error(
                                format!("Method '.{}' is not supported on this type", field_name),
                                location.clone(),
                            )
                            .with_hint(format!("Use {} instead", suggestion)),
                        );
                        return Err(());
                    }
                }

                let field_type = match object_type.underlying_type() {
                    SymbolType::Object(object_name) => {
                        if let Some(object_info) = self.symbol_table.lookup_user_object(object_name)
                        {
                            match object_info.fields.get(&field_name) {
                                Some(field_type) => field_type.clone(),
                                None => {
                                    self.error_reporter.add_error(CompilerError::semantic_error(
                                        format!(
                                            "Unknown field '{}' for object '{}'",
                                            field_name, object_name
                                        ),
                                        location.clone(),
                                    ));
                                    return Err(());
                                }
                            }
                        } else {
                            SymbolType::Unknown
                        }
                    }
                    _ => SymbolType::Unknown,
                };

                Ok((
                    AstNode::FieldAccess {
                        object: Box::new(checked_object),
                        field_name,
                        location,
                    },
                    field_type,
                ))
            }

            AstNode::DiscardStatement {
                expression,
                location,
            } => {
                let (checked_expr, _expr_type) = self.analyze_node(*expression)?;
                Ok((
                    AstNode::DiscardStatement {
                        expression: Box::new(checked_expr),
                        location,
                    },
                    SymbolType::Void,
                ))
            }

            // Fallback for unhandled nodes
            _ => {
                // For now, just return the node as is with Unknown type.
                Ok((node, SymbolType::Unknown))
            }
        }
    }

    // --- Helper Functions ---

    /// Walk the annotation before type conversion loses nested source spans.
    fn validate_namespace_annotation(&mut self, node: &AstNode) -> Result<(), ()> {
        match node {
            AstNode::SecretType(inner) | AstNode::ListType(inner) => {
                self.validate_namespace_annotation(inner)
            }
            AstNode::TupleType(items) => {
                for item in items {
                    self.validate_namespace_annotation(item)?;
                }
                Ok(())
            }
            AstNode::DictType {
                key_type,
                value_type,
                ..
            } => {
                self.validate_namespace_annotation(key_type)?;
                self.validate_namespace_annotation(value_type)
            }
            AstNode::FunctionType {
                parameter_types,
                return_type,
                ..
            } => {
                for parameter in parameter_types {
                    self.validate_namespace_annotation(parameter)?;
                }
                self.validate_namespace_annotation(return_type)
            }
            AstNode::GenericType {
                base_name,
                type_params,
                location,
            } => {
                if crate::builtin_registry::builtin_registry()
                    .objects
                    .contains_key(base_name)
                {
                    self.validate_type_annotation(
                        &SymbolType::TypeName(base_name.clone()),
                        location.clone(),
                    )?;
                }
                for parameter in type_params {
                    self.validate_namespace_annotation(parameter)?;
                }
                Ok(())
            }
            AstNode::Identifier(name, location)
                if crate::builtin_registry::builtin_registry()
                    .objects
                    .contains_key(name) =>
            {
                self.validate_type_annotation(&SymbolType::TypeName(name.clone()), location.clone())
            }
            _ => Ok(()),
        }
    }

    /// Validates that a SymbolType doesn't contain invalid type references.
    /// Returns an error if a TypeName refers to a function or undeclared identifier.
    fn validate_type_annotation(
        &mut self,
        sym_type: &SymbolType,
        location: SourceLocation,
    ) -> Result<(), ()> {
        if let SymbolType::TypeName(name) | SymbolType::Object(name) = sym_type {
            let registry = crate::builtin_registry::builtin_registry();
            if registry.objects.contains_key(name) && !registry.object_type_names.contains(name) {
                let hint = match name.as_str() {
                    "Field" => "Field elements are represented as 'bytes'",
                    "Bytes" => "Use 'bytes' (list[uint8]) for byte values",
                    _ => "Use this namespace only to call its builtin methods",
                };
                self.error_reporter.add_error(
                    CompilerError::type_error(
                        format!("'{}' is a builtin namespace, not a type", name),
                        location,
                    )
                    .with_hint(hint),
                );
                return Err(());
            }
        }
        match sym_type {
            SymbolType::TypeName(name) => {
                // Check if the name refers to something in the symbol table
                if let Some(info) = self.symbol_table.lookup_symbol(name) {
                    match &info.kind {
                        SymbolKind::Type => Ok(()), // Valid type reference
                        SymbolKind::Function { .. } | SymbolKind::BuiltinFunction { .. } => {
                            self.error_reporter.add_error(
                                CompilerError::type_error(
                                    format!("'{}' is a function, not a type", name),
                                    location,
                                ).with_hint(format!("'{}' is defined as a function. To use a custom type, define it with 'type' or 'object' (type aliases not yet supported)", name))
                            );
                            Err(())
                        }
                        SymbolKind::Variable { .. } => {
                            self.error_reporter.add_error(
                                CompilerError::type_error(
                                    format!("'{}' is a variable, not a type", name),
                                    location,
                                )
                                .with_hint("Variable names cannot be used as types"),
                            );
                            Err(())
                        }
                        SymbolKind::BuiltinObject { .. } => {
                            // Namespace-only names were rejected above; Share remains a value type.
                            Ok(())
                        }
                        SymbolKind::Module => {
                            self.error_reporter.add_error(CompilerError::type_error(
                                format!("'{}' is a module, not a type", name),
                                location,
                            ));
                            Err(())
                        }
                    }
                } else {
                    // Not found in symbol table - undefined type
                    let mut error =
                        CompilerError::type_error(format!("Undefined type '{}'", name), location);
                    // Try to suggest a similar type name
                    if let Some(suggestion) = suggest_from_symbols(name, &self.symbol_table) {
                        error = error.with_hint(format!("Did you mean '{}'?", suggestion));
                    }
                    self.error_reporter.add_error(error);
                    Err(())
                }
            }
            SymbolType::TypeVar(_) => Ok(()),
            // Recursively validate nested types
            SymbolType::List(elem) => self.validate_type_annotation(elem, location),
            SymbolType::Dict(key, val) => {
                self.validate_type_annotation(key, location.clone())?;
                self.validate_type_annotation(val, location)
            }
            SymbolType::Secret(inner) => {
                if inner.underlying_type() == &SymbolType::Float {
                    self.error_reporter.add_error(
                        CompilerError::type_error(
                            "secret float64 is not supported by the current MPC protocol"
                                .to_string(),
                            location,
                        )
                        .with_hint(
                            "Use 'secret fix64' for MPC fixed-point values; the pinned mpc-protocols crate exposes SecretFixedPoint but no SecretFloat type.",
                        ),
                    );
                    return Err(());
                }
                self.validate_type_annotation(inner, location)
            }
            SymbolType::Generic(name, params) => {
                // Validate the base name as a TypeName
                self.validate_type_annotation(
                    &SymbolType::TypeName(name.clone()),
                    location.clone(),
                )?;
                // Validate each type parameter
                for param in params {
                    self.validate_type_annotation(param, location.clone())?;
                }
                Ok(())
            }
            // All other types are primitives or Unknown - valid
            _ => Ok(()),
        }
    }
}

// Helper to get a string representation of a SymbolType for error messages
// TODO: Move this into SymbolType impl or a dedicated formatter module
fn declared_type_to_string(sym_type: &SymbolType) -> String {
    match sym_type {
        // Signed integers
        SymbolType::Int64 => "int64".to_string(),
        SymbolType::Int32 => "int32".to_string(),
        SymbolType::Int16 => "int16".to_string(),
        SymbolType::Int8 => "int8".to_string(),
        // Unsigned integers
        SymbolType::UInt64 => "uint64".to_string(),
        SymbolType::UInt32 => "uint32".to_string(),
        SymbolType::UInt16 => "uint16".to_string(),
        SymbolType::UInt8 => "uint8".to_string(),
        SymbolType::Float => "float".to_string(),
        SymbolType::Fixed { bits } => format!("fix{bits}"),
        SymbolType::String => "string".to_string(),
        SymbolType::Bool => "bool".to_string(),
        SymbolType::Nil => "None".to_string(),
        SymbolType::Void => "void".to_string(),
        SymbolType::Secret(inner) => format!("secret {}", declared_type_to_string(inner)),
        SymbolType::TypeName(name) => name.clone(),
        SymbolType::TypeVar(name) => name.clone(),
        SymbolType::Unknown => "<unknown>".to_string(),
        // Collection types
        SymbolType::List(elem) => format!("list[{}]", declared_type_to_string(elem)),
        SymbolType::Dict(key, val) => format!(
            "dict[{}, {}]",
            declared_type_to_string(key),
            declared_type_to_string(val)
        ),
        SymbolType::Object(name) => name.clone(),
        SymbolType::Generic(name, params) => {
            let params_str: Vec<String> = params.iter().map(declared_type_to_string).collect();
            format!("{}[{}]", name, params_str.join(", "))
        }
    }
}

/// Public entry point for semantic analysis
pub fn analyze(
    ast: AstNode,
    error_reporter: &mut ErrorReporter,
    filename: &str,
) -> Result<AstNode, SemanticError> {
    let mut analyzer = SemanticAnalyzer::new(error_reporter, filename);
    analyzer.analyze(ast)
}

/// Analyzes an AST with pre-imported symbols from other modules.
pub fn analyze_with_imports(
    ast: AstNode,
    error_reporter: &mut ErrorReporter,
    filename: &str,
    imported_symbols: HashMap<String, SymbolInfo>,
) -> Result<AstNode, SemanticError> {
    let mut analyzer = SemanticAnalyzer::with_imports(error_reporter, filename, imported_symbols);
    analyzer.analyze(ast)
}
