use crate::ast::AstNode;
use crate::errors::SourceLocation;
use std::collections::HashMap;
use std::fmt;

/// Represents the kind of a symbol (variable, function, type, etc.)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SymbolKind {
    Variable {
        is_mutable: bool,
    },
    Function {
        parameters: Vec<SymbolType>,
        return_type: SymbolType,
    }, // Simplified for now
    Type,
    BuiltinFunction {
        parameters: Vec<SymbolType>,
        return_type: SymbolType,
    },
    Module,
    /// A builtin object type (like ClientStore) - the name refers to the BuiltinObjectInfo
    BuiltinObject {
        object_type_name: String,
    },
    // Add more kinds as needed (e.g., EnumMember, Field)
}

/// Information about a method on a builtin object
#[derive(Debug, Clone)]
pub struct ObjectMethodInfo {
    /// Parameters for the method (excludes the implicit receiver/self)
    pub parameters: Vec<SymbolType>,
    pub parameter_details: Vec<crate::builtin_registry::BuiltinParameterInfo>,
    /// Return type of the method
    pub return_type: SymbolType,
    /// The qualified name used in bytecode (e.g., "ClientStore.take_share")
    pub qualified_name: String,
}

/// Information about a builtin object type (like ClientStore)
#[derive(Debug, Clone)]
pub struct BuiltinObjectInfo {
    /// The name of the object type
    pub name: String,
    /// Methods available on this object type
    pub methods: HashMap<String, ObjectMethodInfo>,
}

/// Information about a user-defined object type.
#[derive(Debug, Clone)]
pub struct UserObjectInfo {
    /// The name of the object type
    pub name: String,
    /// Field types keyed by field name, including inherited fields.
    pub fields: HashMap<String, SymbolType>,
}

/// Represents the type of a symbol (primitive or user-defined)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SymbolType {
    // Signed integers
    Int64,
    Int32,
    Int16,
    Int8,
    // Unsigned integers
    UInt64,
    UInt32,
    UInt16,
    UInt8,
    Float,
    Fixed { bits: u8 },
    String,
    Bool,
    Nil,
    Void, // For functions returning nothing
    Secret(Box<SymbolType>),
    TypeName(String), // For user-defined types
    TypeVar(String),  // Declared generic type parameter
    Unknown,          // Placeholder during analysis
    // Collection types
    List(Box<SymbolType>),                  // List[T]
    Dict(Box<SymbolType>, Box<SymbolType>), // Dict[K, V]
    Object(String),                         // Named object type
    Generic(String, Vec<SymbolType>),       // Generic type: Name[T1, T2, ...]
}

impl SymbolType {
    /// Checks if the type is secret.
    pub fn is_secret(&self) -> bool {
        matches!(self, SymbolType::Secret(_))
    }

    /// Checks if the type *contains* a secret leaf anywhere — a scalar
    /// `Secret(_)`, a runtime `Share` object handle (which carries secret shares
    /// even though it is a clear object handle, see `with_secret_modifier`), or
    /// either nested inside a `List`/`Dict`/`Generic` element type. This is
    /// distinct from `is_secret()` (which is scalar-`Secret(_)`-only and gates
    /// secret-register allocation): a `list[Share]` / `list[secret bool]` is NOT
    /// a secret scalar, but it *carries* secret shares, so an operation producing
    /// one (e.g. `Share.batch_mul`) still costs an MPC round. Used only by the
    /// round-batching optimizer to classify batched multiplies.
    pub fn contains_secret(&self) -> bool {
        match self {
            SymbolType::Secret(_) => true,
            SymbolType::Object(name) => name == "Share",
            SymbolType::List(inner) => inner.contains_secret(),
            SymbolType::Dict(k, v) => k.contains_secret() || v.contains_secret(),
            SymbolType::Generic(_, args) => args.iter().any(|t| t.contains_secret()),
            _ => false,
        }
    }

    /// Gets the underlying type if secret.
    pub fn underlying_type(&self) -> &SymbolType {
        match self {
            SymbolType::Secret(t) => t.underlying_type(),
            _ => self,
        }
    }

    /// Applies the source-level `secret` modifier to a type.
    ///
    /// Runtime object values such as `Share` are already handles to typed VM
    /// objects. They must not be reclassified as secret scalar registers.
    pub fn with_secret_modifier(&self) -> SymbolType {
        let underlying = self.underlying_type().clone();
        if matches!(underlying, SymbolType::Object(_)) {
            underlying
        } else {
            SymbolType::Secret(Box::new(underlying))
        }
    }

    /// Returns true when this type should be stored in the VM's secret register
    /// bank. Object handles are clear typed values even when they represent
    /// secret-bearing objects.
    pub fn uses_secret_register(&self) -> bool {
        self.is_secret() && !matches!(self.underlying_type(), SymbolType::Object(_))
    }

    /// Returns true if this is any integer type (signed or unsigned).
    pub fn is_integer(&self) -> bool {
        matches!(
            self.underlying_type(),
            SymbolType::Int64
                | SymbolType::Int32
                | SymbolType::Int16
                | SymbolType::Int8
                | SymbolType::UInt64
                | SymbolType::UInt32
                | SymbolType::UInt16
                | SymbolType::UInt8
        )
    }

    /// Returns true if integer and signed; false if integer and unsigned; otherwise false.
    pub fn is_signed(&self) -> bool {
        match self.underlying_type() {
            SymbolType::Int64 | SymbolType::Int32 | SymbolType::Int16 | SymbolType::Int8 => true,
            SymbolType::UInt64 | SymbolType::UInt32 | SymbolType::UInt16 | SymbolType::UInt8 => {
                false
            }
            _ => false,
        }
    }

    /// Returns bit width for integer types.
    pub fn bit_width(&self) -> Option<u8> {
        match self.underlying_type() {
            SymbolType::Int64 | SymbolType::UInt64 => Some(64),
            SymbolType::Int32 | SymbolType::UInt32 => Some(32),
            SymbolType::Int16 | SymbolType::UInt16 => Some(16),
            SymbolType::Int8 | SymbolType::UInt8 => Some(8),
            _ => None,
        }
    }

    /// Returns bit width for fixed-point types.
    pub fn fixed_bit_width(&self) -> Option<u8> {
        match self.underlying_type() {
            SymbolType::Fixed { bits } => Some(*bits),
            _ => None,
        }
    }

    /// Returns the inclusive min value for this integer type as i128.
    pub fn min_value_i128(&self) -> Option<i128> {
        if !self.is_integer() {
            return None;
        }
        let bits_u8 = self.bit_width().unwrap();
        let bits: u32 = bits_u8 as u32;
        if self.is_signed() {
            Some(-(1i128 << (bits - 1)))
        } else {
            Some(0)
        }
    }

    /// Returns the inclusive max value for this integer type as i128.
    pub fn max_value_i128(&self) -> Option<i128> {
        if !self.is_integer() {
            return None;
        }
        let bits_u8 = self.bit_width().unwrap();
        let bits: u32 = bits_u8 as u32;
        if self.is_signed() {
            Some((1i128 << (bits - 1)) - 1)
        } else {
            Some((1i128 << bits) - 1)
        }
    }

    /// Checks if a literal value fits within this integer type.
    pub fn fits_literal_i128(&self, value: i128) -> bool {
        match (self.min_value_i128(), self.max_value_i128()) {
            (Some(min), Some(max)) => value >= min && value <= max,
            _ => false,
        }
    }

    /// Gets the element type for list types.
    pub fn element_type(&self) -> Option<&SymbolType> {
        match self.underlying_type() {
            SymbolType::List(elem) => Some(elem),
            _ => None,
        }
    }

    /// Checks if the type is indexable (list, string, dict).
    pub fn is_indexable(&self) -> bool {
        matches!(
            self.underlying_type(),
            SymbolType::List(_) | SymbolType::String | SymbolType::Dict(_, _)
        )
    }

    /// Checks if the type is a collection (list or dict).
    pub fn is_collection(&self) -> bool {
        matches!(
            self.underlying_type(),
            SymbolType::List(_) | SymbolType::Dict(_, _)
        )
    }

    /// Returns true if converting any value of `self` to `target` is safe (implicit widening).
    /// Conservative: allows signed->signed widening, unsigned->unsigned widening,
    /// and unsigned->signed only if target bit width > source bit width.
    pub fn can_widen_to(&self, target: &SymbolType) -> bool {
        let src = self.underlying_type();
        let dst = target.underlying_type();
        if !src.is_integer() || !dst.is_integer() {
            return false;
        }
        let src_bits = src.bit_width().unwrap();
        let dst_bits = dst.bit_width().unwrap();
        match (src.is_signed(), dst.is_signed()) {
            (true, true) => src_bits <= dst_bits,
            (false, false) => src_bits <= dst_bits,
            (false, true) => src_bits < dst_bits, // e.g., u8 -> i16 (ok), u8 -> i8 (not safe for all values)
            (true, false) => false,               // signed to unsigned not always safe
        }
    }

    /// Creates a SymbolType from an AST node representing a type annotation.
    /// This is a simplified version.
    pub fn from_ast(node: &AstNode) -> Self {
        Self::from_ast_with_type_params(node, &[])
    }

    pub fn from_ast_with_type_params(node: &AstNode, type_params: &[String]) -> Self {
        match node {
            AstNode::Identifier(name, _) => match name.as_str() {
                // Signed ints (aliases)
                "i64" | "int64" | "int" => SymbolType::Int64,
                "i32" | "int32" => SymbolType::Int32,
                "i16" | "int16" => SymbolType::Int16,
                "i8" | "int8" => SymbolType::Int8,
                // Unsigned ints (aliases)
                "u64" | "uint64" => SymbolType::UInt64,
                "u32" | "uint32" => SymbolType::UInt32,
                "u16" | "uint16" => SymbolType::UInt16,
                "u8" | "uint8" => SymbolType::UInt8,
                // Other primitives
                "float" | "float64" | "f64" => SymbolType::Float,
                "fixed" | "fixed64" | "fix64" => SymbolType::Fixed { bits: 64 },
                "fixed32" | "fix32" => SymbolType::Fixed { bits: 32 },
                "string" => SymbolType::String,
                "bool" => SymbolType::Bool,
                "bytes" | "ByteArray" => SymbolType::List(Box::new(SymbolType::UInt8)),
                "void" => SymbolType::Void, // Assuming 'void' keyword exists or is inferred
                "None" => SymbolType::Nil,
                _ if type_params.iter().any(|param| param == name) => {
                    SymbolType::TypeVar(name.clone())
                }
                _ => crate::builtin_registry::resolve_builtin_type_name(name)
                    .unwrap_or_else(|| SymbolType::TypeName(name.clone())),
            },
            AstNode::SecretType(inner_node) => SymbolType::Secret(Box::new(
                SymbolType::from_ast_with_type_params(inner_node, type_params),
            )),
            AstNode::ListType(element_type) => SymbolType::List(Box::new(
                SymbolType::from_ast_with_type_params(element_type, type_params),
            )),
            AstNode::DictType {
                key_type,
                value_type,
                ..
            } => SymbolType::Dict(
                Box::new(SymbolType::from_ast_with_type_params(key_type, type_params)),
                Box::new(SymbolType::from_ast_with_type_params(
                    value_type,
                    type_params,
                )),
            ),
            AstNode::GenericType {
                base_name,
                type_params: generic_args,
                ..
            } => {
                let params: Vec<SymbolType> = generic_args
                    .iter()
                    .map(|node| SymbolType::from_ast_with_type_params(node, type_params))
                    .collect();
                SymbolType::Generic(base_name.clone(), params)
            }
            _ => SymbolType::Unknown, // Cannot determine type from this node
        }
    }
}

impl fmt::Display for SymbolType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SymbolType::Int64 => write!(f, "int64"),
            SymbolType::Int32 => write!(f, "int32"),
            SymbolType::Int16 => write!(f, "int16"),
            SymbolType::Int8 => write!(f, "int8"),
            SymbolType::UInt64 => write!(f, "uint64"),
            SymbolType::UInt32 => write!(f, "uint32"),
            SymbolType::UInt16 => write!(f, "uint16"),
            SymbolType::UInt8 => write!(f, "uint8"),
            SymbolType::Float => write!(f, "float"),
            SymbolType::Fixed { bits } => write!(f, "fix{bits}"),
            SymbolType::String => write!(f, "string"),
            SymbolType::Bool => write!(f, "bool"),
            SymbolType::Nil => write!(f, "None"),
            SymbolType::Void => write!(f, "void"),
            SymbolType::Secret(inner) => write!(f, "secret {}", inner),
            SymbolType::TypeName(name) => write!(f, "{}", name),
            SymbolType::TypeVar(name) => write!(f, "{}", name),
            SymbolType::Unknown => write!(f, "<unknown>"),
            SymbolType::List(elem) => write!(f, "list[{}]", elem),
            SymbolType::Dict(key, val) => write!(f, "dict[{}, {}]", key, val),
            SymbolType::Object(name) => write!(f, "{}", name),
            SymbolType::Generic(name, params) => {
                write!(f, "{}[", name)?;
                for (i, param) in params.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", param)?;
                }
                write!(f, "]")
            }
        }
    }
}

/// Information stored for each symbol in the table.
#[derive(Debug, Clone)]
pub struct SymbolInfo {
    pub name: String,
    pub kind: SymbolKind,
    pub symbol_type: SymbolType, // Resolved type
    pub is_secret: bool,         // Can be derived from symbol_type, but useful for quick checks.
    pub defined_at: SourceLocation,
    // pub scope_level: usize, // Could be useful for debugging
    // pub used: bool, // For unused variable warnings
}

/// Error type for symbol declaration issues within a scope.
#[derive(Debug, Clone)]
pub enum SymbolDeclarationError {
    AlreadyDeclared {
        name: String,
        original_location: SourceLocation, // Location of the first declaration
    },
}

/// Represents a single scope (e.g., global, function, block).
#[derive(Debug, Clone, Default)]
pub struct Scope {
    symbols: HashMap<String, SymbolInfo>,
    parent_scope_id: Option<usize>, // ID of the enclosing scope
                                    // pub children_scope_ids: Vec<usize>, // For debugging/visualization
}

impl Scope {
    fn new(parent_scope_id: Option<usize>) -> Self {
        Scope {
            symbols: HashMap::new(),
            parent_scope_id,
            // children_scope_ids: Vec::new(),
        }
    }

    /// Declares a symbol in this scope. Returns error if already declared.
    fn declare(&mut self, info: SymbolInfo) -> Result<(), SymbolDeclarationError> {
        if let Some(existing_info) = self.symbols.get(&info.name) {
            if matches!(existing_info.kind, SymbolKind::BuiltinFunction { .. }) {
                self.symbols.insert(info.name.clone(), info);
                return Ok(());
            }

            Err(SymbolDeclarationError::AlreadyDeclared {
                name: info.name.clone(),
                original_location: existing_info.defined_at.clone(),
            })
        } else {
            // Store the new symbol
            self.symbols.insert(info.name.clone(), info);
            Ok(())
        }
    }

    /// Looks up a symbol only in this specific scope.
    fn lookup_local(&self, name: &str) -> Option<&SymbolInfo> {
        self.symbols.get(name)
    }
}

/// The main Symbol Table structure, managing multiple scopes.
#[derive(Debug)]
pub struct SymbolTable {
    scopes: Vec<Scope>,                                        // Stores all scopes
    current_scope_id: usize,                                   // ID of the currently active scope
    next_scope_id: usize, // Counter for assigning unique scope IDs
    pub errors: Vec<(SymbolDeclarationError, SourceLocation)>, // Store error and location of the failed declaration
    /// Registry of builtin object types (like ClientStore)
    pub builtin_objects: HashMap<String, BuiltinObjectInfo>,
    /// Registry of user-defined object types.
    pub user_objects: HashMap<String, UserObjectInfo>,
    /// Method-to-function suggestions for common method names that should be functions.
    /// Maps method name (e.g., "length") to suggestion string (e.g., "array_length(arr)").
    method_suggestions: HashMap<String, String>,
}

impl Default for SymbolTable {
    fn default() -> Self {
        Self::new()
    }
}

impl SymbolTable {
    pub fn new() -> Self {
        let mut table = SymbolTable {
            scopes: Vec::new(),
            current_scope_id: 0,
            next_scope_id: 1, // 0 is global scope
            errors: Vec::new(),
            builtin_objects: HashMap::new(),
            user_objects: HashMap::new(),
            method_suggestions: HashMap::new(),
        };
        // Create the global scope (ID 0)
        table.scopes.push(Scope::new(None));
        table.add_builtins();
        table
    }

    /// Looks up a method suggestion for when users try to use method syntax.
    /// Returns a suggestion string if the method name has a known function equivalent.
    pub fn get_method_suggestion(&self, method_name: &str) -> Option<&String> {
        self.method_suggestions.get(method_name)
    }

    /// Looks up a builtin object type by name
    pub fn lookup_builtin_object(&self, name: &str) -> Option<&BuiltinObjectInfo> {
        self.builtin_objects.get(name)
    }

    /// Registers a user-defined object type for constructor and field checks.
    pub fn register_user_object(&mut self, info: UserObjectInfo) {
        self.user_objects.insert(info.name.clone(), info);
    }

    /// Looks up a user-defined object type by name.
    pub fn lookup_user_object(&self, name: &str) -> Option<&UserObjectInfo> {
        self.user_objects.get(name)
    }

    /// Looks up a method on a builtin object type
    pub fn lookup_builtin_method(
        &self,
        object_name: &str,
        method_name: &str,
    ) -> Option<&ObjectMethodInfo> {
        self.builtin_objects
            .get(object_name)
            .and_then(|obj| obj.methods.get(method_name))
    }

    /// Looks up a builtin method by receiver type and source method name.
    ///
    /// A method is receiver-bound when its first declared parameter is the
    /// object type that owns the method, e.g. `Share.open(share: Share)`.
    pub fn lookup_builtin_method_for_receiver(
        &self,
        receiver_type: &SymbolType,
        method_name: &str,
    ) -> Option<&ObjectMethodInfo> {
        let receiver_name = match receiver_type.underlying_type() {
            SymbolType::Object(receiver_name) => receiver_name.as_str(),
            _ if receiver_type.is_secret() => "Share",
            _ => return None,
        };

        let method = self.lookup_builtin_method(receiver_name, method_name)?;
        let first_param = method.parameters.first()?;

        match first_param.underlying_type() {
            SymbolType::Object(param_name) if param_name == receiver_name => Some(method),
            _ => None,
        }
    }

    fn declare_global_builtin(&mut self, info: SymbolInfo) {
        let location = info.defined_at.clone();
        if let Err(e) = self.scopes[0].declare(info) {
            self.errors.push((e, location));
        }
    }

    /// Adds built-in functions and types to the global scope.
    fn add_builtins(&mut self) {
        let registry = crate::builtin_registry::builtin_registry();

        for type_name in &registry.type_names {
            if registry.objects.contains_key(type_name) {
                continue;
            }

            self.declare_global_builtin(SymbolInfo {
                name: type_name.clone(),
                kind: SymbolKind::Type,
                symbol_type: registry
                    .resolve_type_name(type_name)
                    .unwrap_or(SymbolType::Unknown),
                is_secret: false,
                defined_at: SourceLocation::default(),
            });
        }

        for (name, function) in &registry.functions {
            self.declare_global_builtin(SymbolInfo {
                name: name.clone(),
                kind: SymbolKind::BuiltinFunction {
                    parameters: function.parameters.clone(),
                    return_type: function.return_type.clone(),
                },
                symbol_type: function.return_type.clone(),
                is_secret: function.return_type.is_secret(),
                defined_at: SourceLocation::default(),
            });
        }

        for (name, object) in &registry.objects {
            self.builtin_objects.insert(name.clone(), object.clone());
            self.declare_global_builtin(SymbolInfo {
                name: name.clone(),
                kind: SymbolKind::BuiltinObject {
                    object_type_name: name.clone(),
                },
                symbol_type: SymbolType::Object(name.clone()),
                is_secret: false,
                defined_at: SourceLocation::default(),
            });
        }

        // Note: Method-to-function suggestions are kept for methods that don't have
        // direct function aliases (like pop, get, set) or have different semantics
        self.method_suggestions
            .insert("pop".to_string(), "array_pop(arr)".to_string());
        self.method_suggestions
            .insert("get".to_string(), "arr[index]".to_string());
        self.method_suggestions
            .insert("set".to_string(), "arr[index] = value".to_string());
        self.method_suggestions.insert(
            "open".to_string(),
            "Share.open(value) or value.reveal()".to_string(),
        );
    }

    /// Enters a new scope nested within the current one.
    pub fn enter_scope(&mut self) {
        let new_scope_id = self.next_scope_id;
        self.next_scope_id += 1;
        let new_scope = Scope::new(Some(self.current_scope_id));
        self.scopes.push(new_scope);
        // Update parent's children list (if needed for debugging)
        // if let Some(parent_scope) = self.scopes.get_mut(self.current_scope_id) {
        //     parent_scope.children_scope_ids.push(new_scope_id);
        // }
        self.current_scope_id = new_scope_id;
    }

    /// Exits the current scope and returns to the parent scope.
    /// Panics if trying to exit the global scope.
    pub fn exit_scope(&mut self) {
        let current_scope = self
            .scopes
            .get(self.current_scope_id)
            .expect("Internal error: Current scope ID invalid");
        self.current_scope_id = current_scope
            .parent_scope_id
            .expect("Cannot exit the global scope");
    }

    /// Declares a symbol in the current scope.
    pub fn declare_symbol(&mut self, info: SymbolInfo) {
        let current_scope = self
            .scopes
            .get_mut(self.current_scope_id)
            .expect("Internal error: Current scope ID invalid during declaration");
        let location = info.defined_at.clone(); // Get location before moving info
        if let Err(e) = current_scope.declare(info) {
            self.errors.push((e, location)); // Store error and location of failed declaration
        }
    }

    /// Looks up a symbol starting from the current scope and walking up the chain.
    pub fn lookup_symbol(&self, name: &str) -> Option<&SymbolInfo> {
        let mut scope_id_to_check = Some(self.current_scope_id);
        while let Some(id) = scope_id_to_check {
            let scope = self
                .scopes
                .get(id)
                .expect("Internal error: Invalid scope ID during lookup");
            if let Some(info) = scope.lookup_local(name) {
                return Some(info);
            }
            scope_id_to_check = scope.parent_scope_id;
        }
        None // Not found in any scope
    }

    /// Returns all visible symbol names from current scope up the chain.
    /// Handles shadowing (inner scope symbols take precedence over outer).
    pub fn get_visible_symbol_names(&self) -> Vec<String> {
        let mut symbols = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut scope_id = Some(self.current_scope_id);

        while let Some(id) = scope_id {
            let scope = &self.scopes[id];
            for name in scope.symbols.keys() {
                if !seen.contains(name) {
                    seen.insert(name.clone());
                    symbols.push(name.clone());
                }
            }
            scope_id = scope.parent_scope_id;
        }
        symbols
    }

    /// Returns all callable symbol names (functions + builtins + object methods).
    pub fn get_callable_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .get_visible_symbol_names()
            .into_iter()
            .filter(|name| {
                self.lookup_symbol(name)
                    .map(|info| {
                        matches!(
                            info.kind,
                            SymbolKind::Function { .. } | SymbolKind::BuiltinFunction { .. }
                        )
                    })
                    .unwrap_or(false)
            })
            .collect();

        // Add builtin object methods as "Object.method"
        for (obj_name, obj_info) in &self.builtin_objects {
            for method_name in obj_info.methods.keys() {
                names.push(format!("{}.{}", obj_name, method_name));
            }
        }
        names
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::SourceLocation;

    fn make_loc() -> SourceLocation {
        SourceLocation::default()
    }

    fn make_variable(name: &str, symbol_type: SymbolType) -> SymbolInfo {
        SymbolInfo {
            name: name.to_string(),
            kind: SymbolKind::Variable { is_mutable: false },
            symbol_type,
            is_secret: false,
            defined_at: make_loc(),
        }
    }

    fn make_function(name: &str, params: Vec<SymbolType>, return_type: SymbolType) -> SymbolInfo {
        SymbolInfo {
            name: name.to_string(),
            kind: SymbolKind::Function {
                parameters: params,
                return_type,
            },
            symbol_type: SymbolType::Void,
            is_secret: false,
            defined_at: make_loc(),
        }
    }

    // ===========================================
    // Tests for get_visible_symbol_names
    // ===========================================

    #[test]
    fn test_get_visible_symbols_empty_scope() {
        let table = SymbolTable::new();
        // New table has builtins but no user symbols at global scope
        let symbols = table.get_visible_symbol_names();
        // Should include public builtin functions like "print" and "append".
        assert!(symbols.contains(&"print".to_string()));
        assert!(symbols.contains(&"append".to_string()));
    }

    #[test]
    fn test_get_visible_symbols_single_scope() {
        let mut table = SymbolTable::new();
        table.declare_symbol(make_variable("counter", SymbolType::Int64));
        table.declare_symbol(make_variable("total", SymbolType::Int64));

        let symbols = table.get_visible_symbol_names();
        assert!(symbols.contains(&"counter".to_string()));
        assert!(symbols.contains(&"total".to_string()));
    }

    #[test]
    fn test_get_visible_symbols_nested_scopes() {
        let mut table = SymbolTable::new();

        // Global scope
        table.declare_symbol(make_variable("global_var", SymbolType::Int64));

        // Enter function scope
        table.enter_scope();
        table.declare_symbol(make_variable("local_var", SymbolType::Int64));

        let symbols = table.get_visible_symbol_names();

        // Should see both global and local
        assert!(symbols.contains(&"global_var".to_string()));
        assert!(symbols.contains(&"local_var".to_string()));
    }

    #[test]
    fn test_get_visible_symbols_shadowing() {
        let mut table = SymbolTable::new();

        // Global scope - declare 'x'
        table.declare_symbol(make_variable("x", SymbolType::Int64));
        table.declare_symbol(make_variable("y", SymbolType::Int64));

        // Enter inner scope - shadow 'x'
        table.enter_scope();
        table.declare_symbol(make_variable("x", SymbolType::String)); // shadows outer x
        table.declare_symbol(make_variable("z", SymbolType::Int64));

        let symbols = table.get_visible_symbol_names();

        // Should see x, y, z (x only once due to shadowing)
        let x_count = symbols.iter().filter(|s| *s == "x").count();
        assert_eq!(x_count, 1, "Shadowed variable should appear only once");
        assert!(symbols.contains(&"y".to_string()));
        assert!(symbols.contains(&"z".to_string()));
    }

    #[test]
    fn test_get_visible_symbols_after_exit_scope() {
        let mut table = SymbolTable::new();

        table.declare_symbol(make_variable("global_var", SymbolType::Int64));

        table.enter_scope();
        table.declare_symbol(make_variable("local_var", SymbolType::Int64));
        table.exit_scope();

        let symbols = table.get_visible_symbol_names();

        // After exiting scope, local_var should not be visible
        assert!(symbols.contains(&"global_var".to_string()));
        assert!(!symbols.contains(&"local_var".to_string()));
    }

    // ===========================================
    // Tests for get_callable_names
    // ===========================================

    #[test]
    fn test_get_callable_names_includes_builtins() {
        let table = SymbolTable::new();
        let callables = table.get_callable_names();

        // Should include builtin functions
        assert!(callables.contains(&"print".to_string()));
        assert!(callables.contains(&"append".to_string()));
        assert!(callables.contains(&"len".to_string()));
    }

    #[test]
    fn test_get_callable_names_includes_user_functions() {
        let mut table = SymbolTable::new();
        table.declare_symbol(make_function(
            "calculate",
            vec![SymbolType::Int64],
            SymbolType::Int64,
        ));
        table.declare_symbol(make_function(
            "process",
            vec![SymbolType::String],
            SymbolType::Void,
        ));

        let callables = table.get_callable_names();

        assert!(callables.contains(&"calculate".to_string()));
        assert!(callables.contains(&"process".to_string()));
    }

    #[test]
    fn test_get_callable_names_excludes_variables() {
        let mut table = SymbolTable::new();
        table.declare_symbol(make_variable("my_var", SymbolType::Int64));
        table.declare_symbol(make_function("my_func", vec![], SymbolType::Void));

        let callables = table.get_callable_names();

        assert!(!callables.contains(&"my_var".to_string()));
        assert!(callables.contains(&"my_func".to_string()));
    }

    #[test]
    fn test_get_callable_names_includes_builtin_object_methods() {
        let table = SymbolTable::new();
        let callables = table.get_callable_names();

        // Should include builtin object methods as "Object.method"
        assert!(callables.contains(&"Share.open".to_string()));
        assert!(callables.contains(&"Share.mul".to_string()));
        assert!(callables.contains(&"ClientStore.take_share".to_string()));
        assert!(callables.contains(&"Mpc.party_id".to_string()));
    }

    #[test]
    fn test_get_callable_names_nested_scope_functions() {
        let mut table = SymbolTable::new();

        // Global function
        table.declare_symbol(make_function("global_func", vec![], SymbolType::Void));

        // Enter scope and declare local function
        table.enter_scope();
        table.declare_symbol(make_function("local_func", vec![], SymbolType::Void));

        let callables = table.get_callable_names();

        // Should see both
        assert!(callables.contains(&"global_func".to_string()));
        assert!(callables.contains(&"local_func".to_string()));
    }

    // ===========================================
    // Tests for builtin objects
    // ===========================================

    #[test]
    fn test_builtin_objects_registered() {
        let table = SymbolTable::new();

        // All builtin objects should be registered
        assert!(table.builtin_objects.contains_key("ClientStore"));
        assert!(table.builtin_objects.contains_key("Share"));
        assert!(table.builtin_objects.contains_key("Mpc"));
        assert!(table.builtin_objects.contains_key("MpcOutput"));
        assert!(table.builtin_objects.contains_key("Rbc"));
        assert!(table.builtin_objects.contains_key("Bytes"));
        assert!(table.builtin_objects.contains_key("Crypto"));
        assert!(table.builtin_objects.contains_key("Avss"));
    }

    #[test]
    fn test_builtin_objects_as_symbols() {
        let table = SymbolTable::new();

        // Builtin objects should be declared as symbols in global scope
        let client_store = table.lookup_symbol("ClientStore");
        assert!(client_store.is_some());
        let info = client_store.unwrap();
        assert!(matches!(info.kind, SymbolKind::BuiltinObject { .. }));
        assert_eq!(
            info.symbol_type,
            SymbolType::Object("ClientStore".to_string())
        );

        let share = table.lookup_symbol("Share");
        assert!(share.is_some());
        assert!(matches!(
            share.unwrap().kind,
            SymbolKind::BuiltinObject { .. }
        ));

        let mpc = table.lookup_symbol("Mpc");
        assert!(mpc.is_some());
        assert!(matches!(
            mpc.unwrap().kind,
            SymbolKind::BuiltinObject { .. }
        ));
    }

    #[test]
    fn test_lookup_builtin_object() {
        let table = SymbolTable::new();

        let client_store = table.lookup_builtin_object("ClientStore");
        assert!(client_store.is_some());
        let obj_info = client_store.unwrap();
        assert!(!obj_info.methods.is_empty());

        // Non-existent object should return None
        assert!(table.lookup_builtin_object("NonExistent").is_none());
    }

    // ===========================================
    // Tests for builtin object methods
    // ===========================================

    #[test]
    fn test_lookup_builtin_method_client_store() {
        let table = SymbolTable::new();

        // Test take_share method
        let take_share = table.lookup_builtin_method("ClientStore", "take_share");
        assert!(take_share.is_some());
        let method = take_share.unwrap();
        assert_eq!(method.parameters.len(), 2);
        assert_eq!(method.parameters[0], SymbolType::Int64);
        assert_eq!(method.parameters[1], SymbolType::Int64);
        assert_eq!(method.return_type, SymbolType::Object("Share".to_string()));
        assert_eq!(method.qualified_name, "ClientStore.take_share");

        // Test take_share_fixed method
        let take_share_fixed = table.lookup_builtin_method("ClientStore", "take_share_fixed");
        assert!(take_share_fixed.is_some());
        let method = take_share_fixed.unwrap();
        assert_eq!(method.return_type, SymbolType::Object("Share".to_string()));

        // Test get_number_clients method
        let get_number_clients = table.lookup_builtin_method("ClientStore", "get_number_clients");
        assert!(get_number_clients.is_some());
        let method = get_number_clients.unwrap();
        assert!(method.parameters.is_empty());
        assert_eq!(method.return_type, SymbolType::Int64);

        let get_number_input_clients =
            table.lookup_builtin_method("ClientStore", "get_number_input_clients");
        assert!(get_number_input_clients.is_some());
        let method = get_number_input_clients.unwrap();
        assert!(method.parameters.is_empty());
        assert_eq!(method.return_type, SymbolType::Int64);

        let get_number_output_clients =
            table.lookup_builtin_method("ClientStore", "get_number_output_clients");
        assert!(get_number_output_clients.is_some());
        let method = get_number_output_clients.unwrap();
        assert!(method.parameters.is_empty());
        assert_eq!(method.return_type, SymbolType::Int64);
    }

    #[test]
    fn test_lookup_builtin_method_share() {
        let table = SymbolTable::new();

        // Test from_clear method
        let from_clear = table.lookup_builtin_method("Share", "from_clear");
        assert!(from_clear.is_some());
        let method = from_clear.unwrap();
        assert_eq!(method.parameters.len(), 1);
        assert_eq!(method.parameters[0], SymbolType::Int64);
        assert_eq!(method.return_type, SymbolType::Object("Share".to_string()));

        // Test add method
        let add = table.lookup_builtin_method("Share", "add");
        assert!(add.is_some());
        let method = add.unwrap();
        assert_eq!(method.parameters.len(), 2);
        assert_eq!(
            method.parameters[0],
            SymbolType::Object("Share".to_string())
        );
        assert_eq!(
            method.parameters[1],
            SymbolType::Object("Share".to_string())
        );
        assert_eq!(method.return_type, SymbolType::Object("Share".to_string()));

        // Test mul method (network operation)
        let mul = table.lookup_builtin_method("Share", "mul");
        assert!(mul.is_some());
        assert_eq!(mul.unwrap().qualified_name, "Share.mul");

        // Test open method
        let open = table.lookup_builtin_method("Share", "open");
        assert!(open.is_some());
        let method = open.unwrap();
        assert_eq!(method.parameters.len(), 1);
        assert_eq!(method.return_type, SymbolType::Int64);
    }

    #[test]
    fn test_lookup_builtin_method_mpc() {
        let table = SymbolTable::new();

        // Test party_id method
        let party_id = table.lookup_builtin_method("Mpc", "party_id");
        assert!(party_id.is_some());
        let method = party_id.unwrap();
        assert!(method.parameters.is_empty());
        assert_eq!(method.return_type, SymbolType::Int64);

        // Test n_parties method
        let n_parties = table.lookup_builtin_method("Mpc", "n_parties");
        assert!(n_parties.is_some());

        // Test threshold method
        let threshold = table.lookup_builtin_method("Mpc", "threshold");
        assert!(threshold.is_some());

        // Test is_ready method
        let is_ready = table.lookup_builtin_method("Mpc", "is_ready");
        assert!(is_ready.is_some());
        assert_eq!(is_ready.unwrap().return_type, SymbolType::Bool);
    }

    #[test]
    fn test_lookup_builtin_method_rbc() {
        let table = SymbolTable::new();

        // Test broadcast method
        let broadcast = table.lookup_builtin_method("Rbc", "broadcast");
        assert!(broadcast.is_some());
        let method = broadcast.unwrap();
        assert_eq!(method.parameters.len(), 1);
        assert_eq!(method.parameters[0], SymbolType::String);
        assert_eq!(method.return_type, SymbolType::Int64);

        // Test receive method
        let receive = table.lookup_builtin_method("Rbc", "receive");
        assert!(receive.is_some());
        let method = receive.unwrap();
        assert_eq!(method.parameters.len(), 2);
        assert_eq!(method.return_type, SymbolType::String);
    }

    #[test]
    fn test_lookup_builtin_method_bytes_crypto_avss() {
        let table = SymbolTable::new();

        let bytes = SymbolType::List(Box::new(SymbolType::UInt8));

        let from_string = table.lookup_builtin_method("Bytes", "from_string");
        assert!(from_string.is_some());
        let method = from_string.unwrap();
        assert_eq!(method.parameters.len(), 1);
        assert_eq!(method.parameters[0], SymbolType::String);
        assert_eq!(method.return_type, bytes);

        let hash_to_field = table.lookup_builtin_method("Crypto", "hash_to_field");
        assert!(hash_to_field.is_some());
        let method = hash_to_field.unwrap();
        assert_eq!(method.parameters.len(), 2);
        assert_eq!(method.parameters[1], SymbolType::String);

        let is_avss_share = table.lookup_builtin_method("Avss", "is_avss_share");
        assert!(is_avss_share.is_some());
        assert_eq!(is_avss_share.unwrap().return_type, SymbolType::Bool);
    }

    #[test]
    fn test_lookup_nonexistent_method() {
        let table = SymbolTable::new();

        // Non-existent method on existing object
        assert!(table
            .lookup_builtin_method("ClientStore", "nonexistent")
            .is_none());

        // Method on non-existent object
        assert!(table
            .lookup_builtin_method("NonExistent", "method")
            .is_none());
    }

    // ===========================================
    // Tests for SymbolType::Object
    // ===========================================

    #[test]
    fn test_symbol_type_object_equality() {
        let obj1 = SymbolType::Object("Share".to_string());
        let obj2 = SymbolType::Object("Share".to_string());
        let obj3 = SymbolType::Object("ClientStore".to_string());

        assert_eq!(obj1, obj2);
        assert_ne!(obj1, obj3);
    }

    #[test]
    fn test_symbol_type_object_in_secret() {
        let secret_share = SymbolType::Secret(Box::new(SymbolType::Object("Share".to_string())));

        assert!(secret_share.is_secret());
        assert_eq!(
            *secret_share.underlying_type(),
            SymbolType::Object("Share".to_string())
        );
    }

    #[test]
    fn test_symbol_type_object_not_integer() {
        let obj = SymbolType::Object("Share".to_string());
        assert!(!obj.is_integer());
        assert!(!obj.is_signed());
        assert!(obj.bit_width().is_none());
    }

    // ===========================================
    // Tests for SymbolKind::BuiltinObject
    // ===========================================

    #[test]
    fn test_symbol_kind_builtin_object() {
        let table = SymbolTable::new();

        let share_symbol = table.lookup_symbol("Share").unwrap();
        match &share_symbol.kind {
            SymbolKind::BuiltinObject { object_type_name } => {
                assert_eq!(object_type_name, "Share");
            }
            _ => panic!("Expected BuiltinObject kind"),
        }
    }

    #[test]
    fn test_builtin_object_not_callable_directly() {
        let table = SymbolTable::new();
        let callables = table.get_callable_names();

        // Builtin objects themselves should not be in callable names
        // (only their methods should be)
        assert!(!callables.contains(&"ClientStore".to_string()));
        assert!(!callables.contains(&"Share".to_string()));
        assert!(!callables.contains(&"Mpc".to_string()));
    }

    // ===========================================
    // Tests for object method count and listing
    // ===========================================

    #[test]
    fn test_share_has_all_methods() {
        let table = SymbolTable::new();
        let share = table.lookup_builtin_object("Share").unwrap();

        // Share should have these methods
        let expected_methods = [
            "from_clear",
            "from_clear_int",
            "from_clear_uint",
            "from_clear_fixed",
            "add",
            "sub",
            "neg",
            "add_constant",
            "add_scalar",
            "mul_scalar",
            "mul",
            "batch_mul",
            "open",
            "open_fixed",
            "send_to_client",
            "interpolate_local",
            "get_type",
            "get_party_id",
            "batch_open",
            "batch_open_fixed",
            "open_exp",
            "random",
            "random_int",
            "get_commitment",
            "commitment_count",
            "has_commitments",
            "mul_field",
            "add_field",
            "retag",
            "open_field",
            "open_exp_custom",
        ];

        for method_name in expected_methods {
            assert!(
                share.methods.contains_key(method_name),
                "Share should have method '{}'",
                method_name
            );
        }
    }

    #[test]
    fn test_field_has_all_methods() {
        let table = SymbolTable::new();
        let field = table.lookup_builtin_object("Field").unwrap();

        let expected_methods = [
            "from_int", "zero", "one", "is_zero", "eq", "add", "sub", "mul", "neg", "inverse",
            "sqrt",
        ];

        for method_name in expected_methods {
            assert!(
                field.methods.contains_key(method_name),
                "Field should have method '{}'",
                method_name
            );
        }
        assert_eq!(field.methods.len(), expected_methods.len());
    }

    #[test]
    fn test_client_store_has_all_methods() {
        let table = SymbolTable::new();
        let client_store = table.lookup_builtin_object("ClientStore").unwrap();

        let expected_methods = [
            "take_share",
            "take_share_bool",
            "take_share_fixed",
            "sum_shares",
            "sum_shares_bool",
            "sum_shares_fixed",
            "get_number_clients",
            "get_number_input_clients",
            "get_number_output_clients",
        ];

        for method_name in expected_methods {
            assert!(
                client_store.methods.contains_key(method_name),
                "ClientStore should have method '{}'",
                method_name
            );
        }
        assert_eq!(client_store.methods.len(), expected_methods.len());
    }

    #[test]
    fn test_mpc_has_all_methods() {
        let table = SymbolTable::new();
        let mpc = table.lookup_builtin_object("Mpc").unwrap();

        let expected_methods = [
            "party_id",
            "n_parties",
            "threshold",
            "is_ready",
            "instance_id",
            "protocol_name",
            "curve",
            "field",
            "has_capability",
            "capabilities",
            "rand",
            "rand_int",
        ];

        for method_name in expected_methods {
            assert!(
                mpc.methods.contains_key(method_name),
                "Mpc should have method '{}'",
                method_name
            );
        }
        assert_eq!(mpc.methods.len(), expected_methods.len());
    }

    // ===========================================
    // Tests for method suggestions related to objects
    // ===========================================

    #[test]
    fn test_method_suggestion_open() {
        let table = SymbolTable::new();

        // "open" should suggest Share.open
        let suggestion = table.get_method_suggestion("open");
        assert!(suggestion.is_some());
        assert!(suggestion.unwrap().contains("Share.open"));
    }

    #[test]
    fn test_method_suggestion_reveal() {
        let table = SymbolTable::new();

        // "reveal" is a real builtin now, not an unsupported-method suggestion.
        let suggestion = table.get_method_suggestion("reveal");
        assert!(suggestion.is_none());
    }

    // ===========================================
    // Tests for object variables
    // ===========================================

    #[test]
    fn test_declare_object_typed_variable() {
        let mut table = SymbolTable::new();

        let share_var = SymbolInfo {
            name: "my_share".to_string(),
            kind: SymbolKind::Variable { is_mutable: false },
            symbol_type: SymbolType::Object("Share".to_string()),
            is_secret: false,
            defined_at: make_loc(),
        };
        table.declare_symbol(share_var);

        let looked_up = table.lookup_symbol("my_share");
        assert!(looked_up.is_some());
        assert_eq!(
            looked_up.unwrap().symbol_type,
            SymbolType::Object("Share".to_string())
        );
    }

    #[test]
    fn test_declare_secret_object_variable() {
        let mut table = SymbolTable::new();

        let secret_share_var = SymbolInfo {
            name: "secret_share".to_string(),
            kind: SymbolKind::Variable { is_mutable: true },
            symbol_type: SymbolType::Secret(Box::new(SymbolType::Object("Share".to_string()))),
            is_secret: true,
            defined_at: make_loc(),
        };
        table.declare_symbol(secret_share_var);

        let looked_up = table.lookup_symbol("secret_share").unwrap();
        assert!(looked_up.is_secret);
        assert!(looked_up.symbol_type.is_secret());
    }

    // ===========================================
    // Tests for List of objects
    // ===========================================

    #[test]
    fn test_list_of_objects_type() {
        // Check interpolate_local accepts Share arrays.
        let table = SymbolTable::new();
        let interpolate = table
            .lookup_builtin_method("Share", "interpolate_local")
            .unwrap();

        assert_eq!(interpolate.parameters.len(), 1);
        assert_eq!(
            interpolate.parameters[0],
            SymbolType::List(Box::new(SymbolType::Object("Share".to_string())))
        );
    }

    #[test]
    fn test_batch_open_returns_list() {
        let table = SymbolTable::new();
        let batch_open = table.lookup_builtin_method("Share", "batch_open").unwrap();

        // batch_open should return a list
        match &batch_open.return_type {
            SymbolType::List(_) => (),
            _ => panic!("batch_open should return a List type"),
        }

        let batch_open_fixed = table
            .lookup_builtin_method("Share", "batch_open_fixed")
            .unwrap();
        assert_eq!(
            batch_open_fixed.parameters,
            vec![SymbolType::List(Box::new(SymbolType::Object(
                "Share".to_string()
            )))]
        );
        assert_eq!(
            batch_open_fixed.return_type,
            SymbolType::List(Box::new(SymbolType::TypeVar("T".to_string())))
        );
    }
}
