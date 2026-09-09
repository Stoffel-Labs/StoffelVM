use crate::ast::AstNode;
use std::collections::HashSet;

fn dotted_name(node: &AstNode) -> Option<String> {
    match node {
        AstNode::Identifier(name, _) => Some(name.clone()),
        AstNode::FieldAccess {
            object, field_name, ..
        } => dotted_name(object).map(|prefix| format!("{prefix}.{field_name}")),
        _ => None,
    }
}

/// Checks if a name is a builtin object that uses qualified method names
fn is_builtin_object(name: &str) -> bool {
    crate::builtin_registry::builtin_registry()
        .objects
        .contains_key(name)
}

/// Transforms the AST to support Uniform Function Call Syntax (UFCS)
/// This allows for multiple calling styles:
/// 1. Traditional method call: obj.method(arg1, arg2)
/// 2. Function call with object as first argument: method(obj, arg1, arg2)
/// 3. Command-style call: obj method arg1 arg2 (without parentheses)
/// 4. Infix operator style: arg1.op(arg2) equivalent to op(arg1, arg2)
///
/// Special handling for builtin objects (like ClientStore):
/// - ClientStore.method(args) is transformed to call "ClientStore.method" directly
/// - The object is NOT prepended as an argument (VM doesn't expect it)
pub fn transform_ufcs(node: AstNode) -> AstNode {
    transform_ufcs_with_module_prefixes(node, &HashSet::new())
}

/// Transforms UFCS while preserving calls through known module prefixes.
pub fn transform_ufcs_with_module_prefixes(
    node: AstNode,
    module_prefixes: &HashSet<String>,
) -> AstNode {
    match node {
        AstNode::FunctionCall {
            function,
            arguments,
            location,
            resolved_return_type,
        } => {
            // A namespace can itself contain dots (`pkg.tools`). Resolve the
            // entire module prefix before considering receiver-style UFCS.
            if let Some(name) = dotted_name(&function) {
                if name
                    .rsplit_once('.')
                    .is_some_and(|(prefix, _)| module_prefixes.contains(prefix))
                {
                    return AstNode::FunctionCall {
                        function: Box::new(AstNode::Identifier(name, function.location())),
                        arguments: arguments
                            .into_iter()
                            .map(|arg| transform_ufcs_with_module_prefixes(arg, module_prefixes))
                            .collect(),
                        location,
                        resolved_return_type,
                    };
                }
            }
            // Style 1: Transform obj.method(arg1, arg2)
            if let AstNode::FieldAccess {
                object,
                field_name,
                location: fa_location,
            } = *function
            {
                // Check if this is a builtin object method call
                if let AstNode::Identifier(obj_name, _) = &*object {
                    if is_builtin_object(obj_name) {
                        // For builtin objects, use qualified method name and don't prepend object
                        let qualified_name = format!("{}.{}", obj_name, field_name);
                        return AstNode::FunctionCall {
                            function: Box::new(AstNode::Identifier(
                                qualified_name,
                                fa_location.clone(),
                            )),
                            arguments: arguments
                                .into_iter()
                                .map(|arg| {
                                    transform_ufcs_with_module_prefixes(arg, module_prefixes)
                                })
                                .collect(),
                            location: fa_location,
                            resolved_return_type,
                        };
                    }
                }

                // For regular objects, use standard UFCS: prepend object as first argument
                let mut new_args = vec![transform_ufcs_with_module_prefixes(
                    *object,
                    module_prefixes,
                )];
                new_args.extend(
                    arguments
                        .into_iter()
                        .map(|arg| transform_ufcs_with_module_prefixes(arg, module_prefixes)),
                );
                return AstNode::FunctionCall {
                    function: Box::new(AstNode::Identifier(field_name, location)),
                    arguments: new_args,
                    location: fa_location,
                    resolved_return_type,
                };
            }
            // Recursively transform arguments and the function expression itself
            AstNode::FunctionCall {
                function: Box::new(transform_ufcs_with_module_prefixes(
                    *function,
                    module_prefixes,
                )),
                arguments: arguments
                    .into_iter()
                    .map(|arg| transform_ufcs_with_module_prefixes(arg, module_prefixes))
                    .collect(),
                location,
                resolved_return_type,
            }
        }
        // Style 3: Transform command-style calls: obj method arg1 arg2
        AstNode::CommandCall {
            command,
            arguments,
            location,
            resolved_return_type,
        } => {
            // If the command is an identifier, transform to a regular function call
            // with the first argument as the object
            if !arguments.is_empty() {
                let first_arg =
                    transform_ufcs_with_module_prefixes(arguments[0].clone(), module_prefixes);
                let remaining_args = arguments
                    .into_iter()
                    .skip(1)
                    .map(|arg| transform_ufcs_with_module_prefixes(arg, module_prefixes))
                    .collect::<Vec<_>>();

                let mut new_args = vec![first_arg];
                new_args.extend(remaining_args);

                return AstNode::FunctionCall {
                    function: Box::new(transform_ufcs_with_module_prefixes(
                        *command,
                        module_prefixes,
                    )),
                    arguments: new_args,
                    location,
                    resolved_return_type, // Pass the resolved type along
                };
            }
            // If no arguments, just transform the command part
            AstNode::CommandCall {
                command: Box::new(transform_ufcs_with_module_prefixes(
                    *command,
                    module_prefixes,
                )),
                arguments: arguments
                    .into_iter()
                    .map(|arg| transform_ufcs_with_module_prefixes(arg, module_prefixes))
                    .collect(),
                location,
                resolved_return_type, // Keep type even if no args
            }
        }
        AstNode::FieldAccess {
            object,
            field_name,
            location,
        } => {
            // Style 4: Transform infix operator calls: a.op(b) into op(a, b)
            // Check if this field access is followed by a function call (handled in FunctionCall case)
            // Otherwise, leave it as is
            AstNode::FieldAccess {
                object: Box::new(transform_ufcs_with_module_prefixes(
                    *object,
                    module_prefixes,
                )),
                field_name,
                location,
            }
        }
        // Recursively transform other node types
        AstNode::VariableDeclaration {
            name,
            type_annotation,
            value,
            is_mutable,
            is_secret,
            location,
        } => AstNode::VariableDeclaration {
            name,
            type_annotation,
            value: value
                .map(|v| Box::new(transform_ufcs_with_module_prefixes(*v, module_prefixes))),
            is_mutable,
            is_secret,
            location,
        },
        AstNode::Assignment {
            target,
            value,
            location,
        } => AstNode::Assignment {
            target: Box::new(transform_ufcs_with_module_prefixes(
                *target,
                module_prefixes,
            )),
            value: Box::new(transform_ufcs_with_module_prefixes(*value, module_prefixes)),
            location,
        },
        AstNode::Block(nodes) => AstNode::Block(
            nodes
                .into_iter()
                .map(|node| transform_ufcs_with_module_prefixes(node, module_prefixes))
                .collect(),
        ),
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
        } => AstNode::FunctionDefinition {
            name,
            type_params,
            parameters,
            return_type,
            body: Box::new(transform_ufcs_with_module_prefixes(*body, module_prefixes)),
            is_secret,
            pragmas,
            location,
            node_id,
        },
        AstNode::BuiltinObjectDefinition {
            name,
            methods,
            location,
        } => AstNode::BuiltinObjectDefinition {
            name,
            methods: methods
                .into_iter()
                .map(|method| transform_ufcs_with_module_prefixes(method, module_prefixes))
                .collect(),
            location,
        },
        AstNode::IfExpression {
            condition,
            then_branch,
            else_branch,
        } => AstNode::IfExpression {
            condition: Box::new(transform_ufcs_with_module_prefixes(
                *condition,
                module_prefixes,
            )),
            then_branch: Box::new(transform_ufcs_with_module_prefixes(
                *then_branch,
                module_prefixes,
            )),
            else_branch: else_branch
                .map(|e| Box::new(transform_ufcs_with_module_prefixes(*e, module_prefixes))),
        },
        AstNode::WhileLoop {
            condition,
            body,
            location,
        } => AstNode::WhileLoop {
            condition: Box::new(transform_ufcs_with_module_prefixes(
                *condition,
                module_prefixes,
            )),
            body: Box::new(transform_ufcs_with_module_prefixes(*body, module_prefixes)),
            location,
        },
        AstNode::ForLoop {
            variables,
            iterable,
            body,
            location,
        } => AstNode::ForLoop {
            variables,
            iterable: Box::new(transform_ufcs_with_module_prefixes(
                *iterable,
                module_prefixes,
            )),
            body: Box::new(transform_ufcs_with_module_prefixes(*body, module_prefixes)),
            location,
        },
        AstNode::Return { value, location } => AstNode::Return {
            value: value
                .map(|v| Box::new(transform_ufcs_with_module_prefixes(*v, module_prefixes))),
            location,
        },
        AstNode::BinaryOperation {
            op,
            left,
            right,
            location,
        } => AstNode::BinaryOperation {
            op,
            left: Box::new(transform_ufcs_with_module_prefixes(*left, module_prefixes)),
            right: Box::new(transform_ufcs_with_module_prefixes(*right, module_prefixes)),
            location,
        },
        AstNode::UnaryOperation {
            op,
            operand,
            location,
        } => AstNode::UnaryOperation {
            op,
            operand: Box::new(transform_ufcs_with_module_prefixes(
                *operand,
                module_prefixes,
            )),
            location,
        },
        AstNode::DiscardStatement {
            expression,
            location,
        } => AstNode::DiscardStatement {
            expression: Box::new(transform_ufcs_with_module_prefixes(
                *expression,
                module_prefixes,
            )),
            location,
        },
        AstNode::NamedArgument {
            name,
            value,
            location,
        } => AstNode::NamedArgument {
            name,
            value: Box::new(transform_ufcs_with_module_prefixes(*value, module_prefixes)),
            location,
        },
        AstNode::IndexAccess {
            base,
            index,
            location,
        } => AstNode::IndexAccess {
            base: Box::new(transform_ufcs_with_module_prefixes(*base, module_prefixes)),
            index: Box::new(transform_ufcs_with_module_prefixes(*index, module_prefixes)),
            location,
        },
        AstNode::ListLiteral { elements, location } => AstNode::ListLiteral {
            elements: elements
                .into_iter()
                .map(|element| transform_ufcs_with_module_prefixes(element, module_prefixes))
                .collect(),
            location,
        },
        AstNode::TupleLiteral(elements) => AstNode::TupleLiteral(
            elements
                .into_iter()
                .map(|element| transform_ufcs_with_module_prefixes(element, module_prefixes))
                .collect(),
        ),
        AstNode::SetLiteral(elements) => AstNode::SetLiteral(
            elements
                .into_iter()
                .map(|element| transform_ufcs_with_module_prefixes(element, module_prefixes))
                .collect(),
        ),
        AstNode::DictLiteral { pairs, location } => AstNode::DictLiteral {
            pairs: pairs
                .into_iter()
                .map(|(key, value)| {
                    (
                        transform_ufcs_with_module_prefixes(key, module_prefixes),
                        transform_ufcs_with_module_prefixes(value, module_prefixes),
                    )
                })
                .collect(),
            location,
        },
        _ => node,
    }
}
