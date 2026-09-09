use crate::errors::SourceLocation;
use crate::symbol_table::SymbolType;

#[derive(Debug, Clone, PartialEq, Hash)]
pub enum IntWidth {
    W8,
    W16,
    W32,
    W64,
}

#[derive(Debug, Clone, PartialEq, Hash)]
pub enum IntKind {
    Signed(IntWidth),
    Unsigned(IntWidth),
}

#[derive(Debug, Clone, PartialEq, Hash)]
pub enum Value {
    Int { value: u128, kind: Option<IntKind> },
    Float(u64),
    String(String),
    Bool(bool),
    Nil,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Parameter {
    pub name: String,
    pub type_annotation: Option<Box<AstNode>>,
    pub default_value: Option<Box<AstNode>>,
    pub is_secret: bool,
    pub is_variadic: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Pragma {
    Simple(String, SourceLocation),
    KeyValue(String, Box<AstNode>, SourceLocation),
}

#[derive(Debug, Clone, PartialEq)]
pub struct FieldDefinition {
    pub name: String,
    pub type_annotation: Box<AstNode>,
    pub is_secret: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EnumMember {
    pub name: String,
    pub value: Option<Box<AstNode>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AstNode {
    Literal {
        value: Value,
        location: SourceLocation,
    },
    Identifier(String, SourceLocation),
    Assignment {
        target: Box<AstNode>,
        value: Box<AstNode>,
        location: SourceLocation,
    },
    VariableDeclaration {
        name: String,
        type_annotation: Option<Box<AstNode>>,
        value: Option<Box<AstNode>>,
        is_mutable: bool,
        is_secret: bool,
        location: SourceLocation,
    },
    BinaryOperation {
        op: String,
        left: Box<AstNode>,
        right: Box<AstNode>,
        location: SourceLocation,
    },
    UnaryOperation {
        op: String,
        operand: Box<AstNode>,
        location: SourceLocation,
    },
    FunctionCall {
        function: Box<AstNode>,
        arguments: Vec<AstNode>,
        location: SourceLocation,
        resolved_return_type: Option<SymbolType>,
    },
    NamedArgument {
        name: String,
        value: Box<AstNode>,
        location: SourceLocation,
    },
    FunctionDefinition {
        name: Option<String>,
        type_params: Vec<String>,
        parameters: Vec<Parameter>,
        return_type: Option<Box<AstNode>>,
        body: Box<AstNode>,
        is_secret: bool,
        pragmas: Vec<Pragma>,
        location: SourceLocation,
        node_id: usize,
    },
    IfExpression {
        condition: Box<AstNode>,
        then_branch: Box<AstNode>,
        else_branch: Option<Box<AstNode>>,
    },
    WhileLoop {
        condition: Box<AstNode>,
        body: Box<AstNode>,
        location: SourceLocation,
    },
    Block(Vec<AstNode>),
    Return {
        value: Option<Box<AstNode>>,
        location: SourceLocation,
    },
    Yield(Option<Box<AstNode>>),
    Break,
    Continue,
    FieldAccess {
        object: Box<AstNode>,
        field_name: String,
        location: SourceLocation,
    },
    IndexAccess {
        base: Box<AstNode>,
        index: Box<AstNode>,
        location: SourceLocation,
    },
    ListLiteral {
        elements: Vec<AstNode>,
        location: SourceLocation,
    },
    TupleLiteral(Vec<AstNode>),
    SetLiteral(Vec<AstNode>),
    DictLiteral {
        pairs: Vec<(AstNode, AstNode)>,
        location: SourceLocation,
    },
    TypeAlias {
        name: String,
        target_type: Box<AstNode>,
        is_secret: bool,
        location: SourceLocation,
    },
    BuiltinTypeDefinition {
        name: String,
        target_type: Option<Box<AstNode>>,
        is_opaque_object: bool,
        location: SourceLocation,
    },
    BuiltinObjectDefinition {
        name: String,
        methods: Vec<AstNode>,
        location: SourceLocation,
    },
    ObjectDefinition {
        name: String,
        base_type: Option<Box<AstNode>>,
        fields: Vec<FieldDefinition>,
        is_secret: bool,
        location: SourceLocation,
    },
    EnumDefinition {
        name: String,
        members: Vec<EnumMember>,
        is_secret: bool,
        location: SourceLocation,
    },
    SecretType(Box<AstNode>),
    FunctionType {
        parameter_types: Vec<AstNode>,
        return_type: Box<AstNode>,
        location: SourceLocation,
    },
    TupleType(Vec<AstNode>),
    ListType(Box<AstNode>),
    DictType {
        key_type: Box<AstNode>,
        value_type: Box<AstNode>,
        location: SourceLocation,
    },
    GenericType {
        base_name: String,
        type_params: Vec<AstNode>,
        location: SourceLocation,
    },
    ForLoop {
        variables: Vec<String>,
        iterable: Box<AstNode>,
        body: Box<AstNode>,
        location: SourceLocation,
    },
    TryCatch {
        try_block: Box<AstNode>,
        catch_clauses: Vec<CatchClause>,
        finally_block: Option<Box<AstNode>>,
        location: SourceLocation,
    },
    Import {
        module_path: Vec<String>,
        raw_path: Option<String>,
        alias: Option<String>,
        imported_items: Option<Vec<String>>,
        location: SourceLocation,
    },
    CommandCall {
        command: Box<AstNode>,
        arguments: Vec<AstNode>,
        location: SourceLocation,
        resolved_return_type: Option<SymbolType>,
    },
    DiscardStatement {
        expression: Box<AstNode>,
        location: SourceLocation,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct CatchClause {
    pub exception_type: Option<Box<AstNode>>,
    pub variable_name: Option<String>,
    pub body: Box<AstNode>,
    pub location: SourceLocation,
}

impl AstNode {
    pub fn is_type_node(&self) -> bool {
        matches!(
            self,
            AstNode::Identifier(_, _)
                | AstNode::TypeAlias { .. }
                | AstNode::BuiltinTypeDefinition { .. }
                | AstNode::BuiltinObjectDefinition { .. }
                | AstNode::ObjectDefinition { .. }
                | AstNode::EnumDefinition { .. }
                | AstNode::FunctionType { .. }
                | AstNode::TupleType(_)
                | AstNode::SecretType(_)
                | AstNode::ListType(_)
                | AstNode::DictType { .. }
                | AstNode::GenericType { .. }
                | AstNode::FieldAccess { .. }
        )
    }

    pub fn is_expression(&self) -> bool {
        match self {
            AstNode::Literal { .. } | AstNode::Identifier(_, _) => true,
            AstNode::BinaryOperation { .. } | AstNode::UnaryOperation { .. } => true,
            AstNode::FunctionCall { .. } | AstNode::CommandCall { .. } => true,
            AstNode::FieldAccess { .. } | AstNode::IndexAccess { .. } => true,
            AstNode::ListLiteral { .. } | AstNode::TupleLiteral(_) => true,
            AstNode::SetLiteral(_) | AstNode::DictLiteral { .. } => true,
            AstNode::IfExpression { .. } => true,
            AstNode::Block(nodes) => nodes.last().is_some_and(|n| n.is_expression()),
            AstNode::Assignment { .. } | AstNode::VariableDeclaration { .. } => false,
            AstNode::WhileLoop { .. } | AstNode::ForLoop { .. } => false,
            AstNode::Return { .. } | AstNode::Yield(_) | AstNode::Break | AstNode::Continue => {
                false
            }
            AstNode::FunctionDefinition { .. } | AstNode::TypeAlias { .. } => false,
            AstNode::BuiltinTypeDefinition { .. } | AstNode::BuiltinObjectDefinition { .. } => {
                false
            }
            AstNode::Import { .. } => false,
            AstNode::ObjectDefinition { .. } | AstNode::EnumDefinition { .. } => false,
            AstNode::TryCatch { .. } => false,
            AstNode::NamedArgument { .. } => false,
            AstNode::FunctionType { .. }
            | AstNode::TupleType(_)
            | AstNode::ListType(_)
            | AstNode::DictType { .. }
            | AstNode::GenericType { .. } => false,
            AstNode::DiscardStatement { .. } => false,
            &AstNode::SecretType(_) => todo!(),
        }
    }

    pub fn location(&self) -> SourceLocation {
        match self {
            AstNode::Identifier(_, loc) => loc.clone(),
            AstNode::SecretType(inner) | AstNode::ListType(inner) => inner.location(),
            AstNode::TupleType(nodes) => nodes.first().map(AstNode::location).unwrap_or_default(),
            AstNode::Assignment { location: loc, .. } => loc.clone(),
            AstNode::VariableDeclaration { location: loc, .. } => loc.clone(),
            AstNode::BinaryOperation { location: loc, .. } => loc.clone(),
            AstNode::UnaryOperation { location: loc, .. } => loc.clone(),
            AstNode::FunctionCall { location: loc, .. } => loc.clone(),
            AstNode::NamedArgument { location: loc, .. } => loc.clone(),
            AstNode::FunctionDefinition { location: loc, .. } => loc.clone(),
            AstNode::WhileLoop { location: loc, .. } => loc.clone(),
            AstNode::FieldAccess { location: loc, .. } => loc.clone(),
            AstNode::IndexAccess { location: loc, .. } => loc.clone(),
            AstNode::TypeAlias { location: loc, .. } => loc.clone(),
            AstNode::BuiltinTypeDefinition { location: loc, .. } => loc.clone(),
            AstNode::BuiltinObjectDefinition { location: loc, .. } => loc.clone(),
            AstNode::ObjectDefinition { location: loc, .. } => loc.clone(),
            AstNode::EnumDefinition { location: loc, .. } => loc.clone(),
            AstNode::FunctionType { location: loc, .. } => loc.clone(),
            AstNode::DictType { location: loc, .. } => loc.clone(),
            AstNode::GenericType { location: loc, .. } => loc.clone(),
            AstNode::ForLoop { location: loc, .. } => loc.clone(),
            AstNode::TryCatch { location: loc, .. } => loc.clone(),
            AstNode::Import { location: loc, .. } => loc.clone(),
            AstNode::CommandCall { location: loc, .. } => loc.clone(),
            AstNode::DiscardStatement { location: loc, .. } => loc.clone(),
            AstNode::Literal { location: loc, .. } => loc.clone(),
            AstNode::ListLiteral { location: loc, .. } => loc.clone(),
            AstNode::DictLiteral { location: loc, .. } => loc.clone(),
            AstNode::IfExpression { condition, .. } => condition.location(),
            AstNode::Block(nodes) => nodes
                .first()
                .map_or_else(SourceLocation::default, AstNode::location),
            AstNode::Return {
                value: Some(expr),
                location: _,
            } => expr.location(),
            AstNode::Return {
                value: None,
                location,
            } => location.clone(),
            _ => SourceLocation::default(),
        }
    }
}
