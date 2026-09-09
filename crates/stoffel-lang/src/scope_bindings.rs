//! Give for-loop locals distinct identities before name-based optimization.
//! Blocks/while loops share their surrounding scope; for loops introduce one.
use crate::ast::AstNode;
use crate::errors::SourceLocation;
use std::collections::HashMap;

pub(crate) fn for_scope(
    variable: String,
    body: AstNode,
    location: &SourceLocation,
) -> (String, AstNode) {
    // '$' cannot appear in a source identifier, so generated names cannot collide.
    let suffix = format!("$for{}_{}", location.line, location.column);
    let renamed = format!("{variable}{suffix}");
    let mut names = HashMap::from([(variable, renamed.clone())]);
    (renamed, rename(body, &mut names, &suffix))
}

fn rename(mut node: AstNode, names: &mut HashMap<String, String>, suffix: &str) -> AstNode {
    match &mut node {
        AstNode::Identifier(name, _) => {
            if let Some(renamed) = names.get(name) {
                *name = renamed.clone();
            }
            node
        }
        AstNode::VariableDeclaration { name, value, .. } => {
            if let Some(value) = value {
                **value = rename(*value.clone(), names, suffix);
            }
            // Nested loops have already resolved their own local bindings.
            if !name.contains('$') {
                let renamed = format!("{name}{suffix}");
                names.insert(name.clone(), renamed.clone());
                *name = renamed;
            }
            node
        }
        AstNode::FunctionDefinition { .. } => node,
        AstNode::ForLoop { iterable, body, .. } => {
            **iterable = rename(*iterable.clone(), names, suffix);
            **body = rename(*body.clone(), &mut names.clone(), suffix);
            node
        }
        AstNode::FunctionCall { arguments, .. } | AstNode::CommandCall { arguments, .. } => {
            // Semantic call resolution has identified a function, not a variable
            // read, even when a local has the same spelling as a builtin.
            for argument in arguments {
                *argument = rename(argument.clone(), names, suffix);
            }
            node
        }
        _ => crate::optimizations::map_children(node, &mut |child| rename(child, names, suffix)),
    }
}

pub(crate) fn source_name(name: &str) -> &str {
    name.split('$').next().unwrap_or(name)
}
