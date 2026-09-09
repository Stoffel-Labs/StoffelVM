//! Module resolution and dependency graph management for multi-file compilation.
//!
//! This module handles:
//! - Converting module paths (e.g., `utils.math`) to file paths (e.g., `./utils/math.stfl`)
//! - Building the dependency graph from import statements
//! - Detecting circular dependencies
//! - Providing topological sort for compilation order

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

use crate::ast::AstNode;
use crate::errors::{CompilerError, SourceLocation};
use crate::lexer;
use crate::parser;

/// Represents a module path like `utils.math` as a vector of components.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModulePath {
    pub components: Vec<String>,
}

impl ModulePath {
    /// Creates a new ModulePath from a vector of components.
    pub fn new(components: Vec<String>) -> Self {
        Self { components }
    }

    /// Converts the module path to a file path relative to a base directory.
    /// For example, `utils.math` becomes `<base>/utils/math.stfl`.
    pub fn to_file_path(&self, base_dir: &Path) -> PathBuf {
        let mut path = base_dir.to_path_buf();

        // Add all components except the last as directories
        for component in &self.components[..self.components.len().saturating_sub(1)] {
            path.push(component);
        }

        // Add the last component with .stfl extension
        if let Some(last) = self.components.last() {
            path.push(format!("{}.stfl", last));
        }

        path
    }

    /// Returns a string representation of the module path (e.g., "utils.math").
    pub fn as_string(&self) -> String {
        self.components.join(".")
    }
}

impl std::fmt::Display for ModulePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_string())
    }
}

pub fn is_std_module_path(module_path: &ModulePath) -> bool {
    module_path
        .components
        .first()
        .map(|component| component == "std")
        .unwrap_or(false)
}

/// Information about an import statement.
#[derive(Debug, Clone)]
pub struct ImportInfo {
    pub module_path: ModulePath,
    pub raw_path: Option<String>,
    pub alias: Option<String>,
    pub location: SourceLocation,
    pub resolved_module_key: Option<String>,
    /// An exported member selected by `import module.member [as alias]`.
    pub imported_item: Option<String>,
}

impl ImportInfo {
    pub(crate) fn binding_for_export(&self, name: &str) -> Option<String> {
        if let Some(item) = &self.imported_item {
            (item == name).then(|| self.alias.clone().unwrap_or_else(|| item.clone()))
        } else {
            let prefix = self
                .alias
                .clone()
                .unwrap_or_else(|| self.module_path.as_string());
            Some(format!("{prefix}.{name}"))
        }
    }
}

/// A resolved module with its source, AST, and dependencies.
#[derive(Debug)]
pub struct ResolvedModule {
    /// The module path (e.g., utils.math)
    pub module_path: ModulePath,
    /// The absolute file path
    pub file_path: PathBuf,
    /// The source code
    pub source: String,
    /// Parsed AST
    pub ast: AstNode,
    /// List of imports found in this module
    pub imports: Vec<ImportInfo>,
}

/// Dependency graph for modules.
#[derive(Debug, Default)]
pub struct DependencyGraph {
    /// Adjacency list: module path -> list of modules it imports
    edges: HashMap<String, Vec<String>>,
    /// All known modules
    modules: HashSet<String>,
}

impl DependencyGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a module to the graph.
    pub fn add_module(&mut self, module: &str) {
        self.modules.insert(module.to_string());
        self.edges.entry(module.to_string()).or_default();
    }

    /// Adds a dependency edge: `from` imports `to`.
    pub fn add_edge(&mut self, from: &str, to: &str) {
        self.modules.insert(from.to_string());
        self.modules.insert(to.to_string());
        self.edges
            .entry(from.to_string())
            .or_default()
            .push(to.to_string());
    }

    /// Performs topological sort using Kahn's algorithm.
    /// Returns modules in compilation order (dependencies first).
    /// Returns an error if a cycle is detected.
    pub fn topological_sort(&self) -> Result<Vec<String>, Vec<String>> {
        // Build reverse adjacency list: for each module, who depends on it
        // Original edges: A -> B means A imports B
        // For compilation order, B must come before A
        // So we need reverse edges for Kahn's algorithm
        let mut reverse_edges: HashMap<&str, Vec<&str>> = HashMap::new();
        for module in &self.modules {
            reverse_edges.insert(module.as_str(), Vec::new());
        }

        for (from, deps) in &self.edges {
            for dep in deps {
                reverse_edges
                    .entry(dep.as_str())
                    .or_default()
                    .push(from.as_str());
            }
        }

        // Calculate in-degrees based on original edges
        // A module's in-degree = number of modules it imports (dependencies)
        let mut in_degree: HashMap<&str, usize> = HashMap::new();
        for module in &self.modules {
            in_degree.insert(module.as_str(), 0);
        }

        // Calculate in-degree as number of imports (dependencies this module has)
        for module in &self.modules {
            let num_deps = self
                .edges
                .get(module.as_str())
                .map(|d| d.len())
                .unwrap_or(0);
            in_degree.insert(module.as_str(), num_deps);
        }

        // Find nodes with no dependencies (in-degree 0)
        let mut queue: VecDeque<&str> = VecDeque::new();
        for (module, &degree) in &in_degree {
            if degree == 0 {
                queue.push_back(module);
            }
        }

        let mut result: Vec<String> = Vec::new();

        while let Some(module) = queue.pop_front() {
            result.push(module.to_string());

            // For each module that depends on this one, reduce its in-degree
            if let Some(dependents) = reverse_edges.get(module) {
                for dependent in dependents {
                    if let Some(degree) = in_degree.get_mut(*dependent) {
                        *degree -= 1;
                        if *degree == 0 {
                            queue.push_back(dependent);
                        }
                    }
                }
            }
        }

        // Check for cycle
        if result.len() != self.modules.len() {
            // There's a cycle - find it
            let cycle = self
                .find_cycle()
                .unwrap_or_else(|| vec!["<unknown>".to_string()]);
            return Err(cycle);
        }

        Ok(result)
    }

    /// Finds a cycle in the graph using DFS.
    /// Returns the cycle path if found.
    fn find_cycle(&self) -> Option<Vec<String>> {
        #[derive(Clone, Copy, PartialEq)]
        enum State {
            White,
            Gray,
            Black,
        }

        let mut state: HashMap<&str, State> = HashMap::new();
        let mut parent: HashMap<&str, &str> = HashMap::new();

        for module in &self.modules {
            state.insert(module.as_str(), State::White);
        }

        fn dfs<'a>(
            node: &'a str,
            edges: &'a HashMap<String, Vec<String>>,
            state: &mut HashMap<&'a str, State>,
            parent: &mut HashMap<&'a str, &'a str>,
        ) -> Option<&'a str> {
            state.insert(node, State::Gray);

            if let Some(deps) = edges.get(node) {
                for dep in deps {
                    match state.get(dep.as_str()) {
                        Some(State::Gray) => return Some(dep.as_str()), // Back edge = cycle
                        Some(State::Black) => continue,
                        _ => {
                            parent.insert(dep.as_str(), node);
                            if let Some(cycle_node) = dfs(dep.as_str(), edges, state, parent) {
                                return Some(cycle_node);
                            }
                        }
                    }
                }
            }

            state.insert(node, State::Black);
            None
        }

        for module in &self.modules {
            if state.get(module.as_str()) == Some(&State::White) {
                if let Some(cycle_start) =
                    dfs(module.as_str(), &self.edges, &mut state, &mut parent)
                {
                    // Reconstruct cycle path
                    let mut cycle = vec![cycle_start.to_string()];
                    let mut current = parent.get(cycle_start);
                    while let Some(&node) = current {
                        cycle.push(node.to_string());
                        if node == cycle_start {
                            break;
                        }
                        current = parent.get(node);
                    }
                    cycle.reverse();
                    return Some(cycle);
                }
            }
        }

        None
    }
}

/// The module resolver handles discovering and parsing all modules.
pub struct ModuleResolver {
    /// Resolved modules indexed by their module path string
    pub resolved_modules: HashMap<String, ResolvedModule>,
    /// The dependency graph
    pub dependency_graph: DependencyGraph,
    /// Errors encountered during resolution
    pub errors: Vec<CompilerError>,
    /// Modules currently being resolved (for cycle detection)
    resolving_modules: HashSet<String>,
    /// File identity is independent of the spelling/alias at each import site.
    file_keys: HashMap<PathBuf, String>,
}

impl ModuleResolver {
    pub fn new() -> Self {
        Self {
            resolved_modules: HashMap::new(),
            dependency_graph: DependencyGraph::new(),
            errors: Vec::new(),
            resolving_modules: HashSet::new(),
            file_keys: HashMap::new(),
        }
    }

    fn key_for_file(&mut self, file: &Path, preferred: String) -> String {
        let canonical = file.canonicalize().unwrap_or_else(|_| file.to_path_buf());
        if let Some(key) = self.file_keys.get(&canonical) {
            return key.clone();
        }
        let key = if self.file_keys.values().any(|key| key == &preferred) {
            canonical.to_string_lossy().into_owned()
        } else {
            preferred
        };
        self.file_keys.insert(canonical, key.clone());
        key
    }

    /// Resolves all modules starting from an entry file.
    /// Returns the module path of the entry file.
    pub fn resolve_all(&mut self, entry_file: &Path) -> Result<String, Vec<CompilerError>> {
        let entry_file = entry_file.canonicalize().map_err(|e| {
            vec![CompilerError::syntax_error(
                format!("Cannot find entry file '{}': {}", entry_file.display(), e),
                SourceLocation::default(),
            )]
        })?;

        // Create module path for entry file (just the filename without extension)
        let entry_module_name = entry_file
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("main")
            .to_string();

        let entry_module_name = self.key_for_file(&entry_file, entry_module_name);
        // Start resolving from the entry file
        let _ = self.resolve_module_from_file(
            &entry_file,
            ModulePath::new(vec![entry_module_name.clone()]),
            entry_module_name.clone(),
        );

        if !self.errors.is_empty() {
            return Err(self.errors.clone());
        }

        Ok(entry_module_name)
    }

    /// Recursively resolves a module and its dependencies.
    fn resolve_module_from_file(
        &mut self,
        file_path: &Path,
        module_path: ModulePath,
        module_key: String,
    ) -> Result<(), ()> {
        // Skip if already resolved
        if self.resolved_modules.contains_key(&module_key) {
            return Ok(());
        }

        // Check for circular dependency
        if self.resolving_modules.contains(&module_key) {
            // Build cycle path from currently resolving modules
            let cycle: Vec<String> = self.resolving_modules.iter().cloned().collect();
            self.errors.push(
                CompilerError::syntax_error(
                    format!("Circular import detected involving '{}'", module_key),
                    SourceLocation::default(),
                )
                .with_hint(format!(
                    "Import cycle: {} -> {}",
                    cycle.join(" -> "),
                    module_key
                )),
            );
            return Err(());
        }

        // Mark this module as being resolved
        self.resolving_modules.insert(module_key.clone());

        // Read the source file
        let source = match fs::read_to_string(file_path) {
            Ok(s) => s,
            Err(e) => {
                self.errors.push(CompilerError::syntax_error(
                    format!(
                        "Cannot read module '{}' from '{}': {}",
                        module_key,
                        file_path.display(),
                        e
                    ),
                    SourceLocation::default(),
                ));
                return Err(());
            }
        };

        // Tokenize
        let filename = file_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&module_key);

        let tokens = match lexer::tokenize(&source, filename) {
            Ok(t) => t,
            Err(e) => {
                self.errors.push(e);
                return Err(());
            }
        };

        // Parse
        let ast = match parser::parse(&tokens, filename) {
            Ok(a) => a,
            Err(e) => {
                self.errors.push(e);
                return Err(());
            }
        };

        // Extract imports from the AST
        let mut imports = Self::collect_imports(&ast);

        // Add this module to the graph
        self.dependency_graph.add_module(&module_key);

        // Get the directory containing this file for resolving relative imports
        let base_dir = file_path.parent().unwrap_or(Path::new("."));

        // Process each import
        for import_info in &mut imports {
            if is_std_module_path(&import_info.module_path) {
                continue;
            }

            let mut imported_module_path = import_info.module_path.clone();
            let mut imported_file_path = if let Some(raw_path) = &import_info.raw_path {
                base_dir.join(raw_path)
            } else {
                import_info.module_path.to_file_path(base_dir)
            };

            // A real nested module takes precedence. Otherwise the final
            // component may name an export of the parent .stfl file.
            if !imported_file_path.exists()
                && import_info.raw_path.is_none()
                && imported_module_path.components.len() > 1
            {
                let item = imported_module_path.components.pop().unwrap();
                let parent_file = imported_module_path.to_file_path(base_dir);
                if parent_file.is_file() {
                    imported_file_path = parent_file;
                    import_info.imported_item = Some(item);
                } else {
                    imported_module_path = import_info.module_path.clone();
                }
            }

            let imported_module_key =
                if import_info.raw_path.is_some() && imported_file_path.exists() {
                    imported_file_path
                        .canonicalize()
                        .map(|path| path.to_string_lossy().into_owned())
                        .unwrap_or_else(|_| imported_file_path.to_string_lossy().into_owned())
                } else {
                    imported_module_path.as_string()
                };
            let imported_module_key = self.key_for_file(&imported_file_path, imported_module_key);
            import_info.resolved_module_key = Some(imported_module_key.clone());

            // Add edge in dependency graph
            self.dependency_graph
                .add_edge(&module_key, &imported_module_key);

            // Check if file exists
            if !imported_file_path.exists() {
                self.errors.push(
                    CompilerError::syntax_error(
                        format!(
                            "Module '{}' not found. Expected file at '{}'",
                            imported_module_key,
                            imported_file_path.display()
                        ),
                        import_info.location.clone(),
                    )
                    .with_hint("Check that the module path is correct and the file exists"),
                );
                continue;
            }

            // Recursively resolve the imported module
            let _ = self.resolve_module_from_file(
                &imported_file_path,
                imported_module_path,
                imported_module_key,
            );
        }

        // Mark this module as no longer being resolved
        self.resolving_modules.remove(&module_key);

        // Store the resolved module
        self.resolved_modules.insert(
            module_key,
            ResolvedModule {
                module_path,
                file_path: file_path.to_path_buf(),
                source,
                ast,
                imports,
            },
        );

        Ok(())
    }

    /// Extracts all import statements from an AST.
    fn collect_imports(ast: &AstNode) -> Vec<ImportInfo> {
        let mut imports = Vec::new();
        Self::collect_imports_recursive(ast, &mut imports);
        imports
    }

    fn collect_imports_recursive(node: &AstNode, imports: &mut Vec<ImportInfo>) {
        match node {
            AstNode::Import {
                module_path,
                raw_path,
                alias,
                location,
                ..
            } => {
                imports.push(ImportInfo {
                    module_path: ModulePath::new(module_path.clone()),
                    raw_path: raw_path.clone(),
                    alias: alias.clone(),
                    location: location.clone(),
                    resolved_module_key: None,
                    imported_item: None,
                });
            }
            AstNode::Block(statements) => {
                for stmt in statements {
                    Self::collect_imports_recursive(stmt, imports);
                }
            }
            // Imports should only be at the top level, but we check blocks just in case
            _ => {}
        }
    }

    /// Returns the compilation order (dependencies first).
    pub fn get_compilation_order(&self) -> Result<Vec<String>, CompilerError> {
        match self.dependency_graph.topological_sort() {
            Ok(order) => Ok(order),
            Err(cycle) => {
                let cycle_str = cycle.join(" -> ");
                Err(CompilerError::syntax_error(
                    format!("Circular import detected: {}", cycle_str),
                    SourceLocation::default(),
                )
                .with_hint("Break the cycle by refactoring shared code into a separate module"))
            }
        }
    }
}

impl Default for ModuleResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== ModulePath Tests ====================

    #[test]
    fn test_module_path_to_file_path() {
        let path = ModulePath::new(vec!["utils".to_string(), "math".to_string()]);
        let base = Path::new("/project/src");
        let file_path = path.to_file_path(base);
        assert_eq!(file_path, PathBuf::from("/project/src/utils/math.stfl"));
    }

    #[test]
    fn test_single_component_path() {
        let path = ModulePath::new(vec!["helpers".to_string()]);
        let base = Path::new("/project");
        let file_path = path.to_file_path(base);
        assert_eq!(file_path, PathBuf::from("/project/helpers.stfl"));
    }

    #[test]
    fn test_three_component_path() {
        let path = ModulePath::new(vec![
            "lib".to_string(),
            "utils".to_string(),
            "strings".to_string(),
        ]);
        let base = Path::new("/project");
        let file_path = path.to_file_path(base);
        assert_eq!(file_path, PathBuf::from("/project/lib/utils/strings.stfl"));
    }

    #[test]
    fn test_module_path_as_string() {
        let path = ModulePath::new(vec!["utils".to_string(), "math".to_string()]);
        assert_eq!(path.as_string(), "utils.math");
    }

    #[test]
    fn test_module_path_display() {
        let path = ModulePath::new(vec!["a".to_string(), "b".to_string(), "c".to_string()]);
        assert_eq!(format!("{}", path), "a.b.c");
    }

    // ==================== DependencyGraph Tests ====================

    #[test]
    fn test_dependency_graph_topological_sort() {
        let mut graph = DependencyGraph::new();
        graph.add_module("main");
        graph.add_module("utils");
        graph.add_module("helpers");
        // main imports utils, utils imports helpers
        graph.add_edge("main", "utils");
        graph.add_edge("utils", "helpers");

        let order = graph.topological_sort().unwrap();

        // helpers should come before utils (since utils depends on helpers)
        // utils should come before main (since main depends on utils)
        let helpers_pos = order.iter().position(|x| x == "helpers").unwrap();
        let utils_pos = order.iter().position(|x| x == "utils").unwrap();
        let main_pos = order.iter().position(|x| x == "main").unwrap();

        assert!(
            helpers_pos < utils_pos,
            "helpers should be compiled before utils"
        );
        assert!(utils_pos < main_pos, "utils should be compiled before main");
    }

    #[test]
    fn test_dependency_graph_cycle_detection() {
        let mut graph = DependencyGraph::new();
        graph.add_module("a");
        graph.add_module("b");
        graph.add_edge("a", "b");
        graph.add_edge("b", "a");

        let result = graph.topological_sort();
        assert!(result.is_err());
    }

    #[test]
    fn test_dependency_graph_diamond_pattern() {
        // Diamond pattern: A imports B and C, both B and C import D
        //       A
        //      / \
        //     B   C
        //      \ /
        //       D
        let mut graph = DependencyGraph::new();
        graph.add_module("a");
        graph.add_module("b");
        graph.add_module("c");
        graph.add_module("d");
        graph.add_edge("a", "b");
        graph.add_edge("a", "c");
        graph.add_edge("b", "d");
        graph.add_edge("c", "d");

        let order = graph.topological_sort().unwrap();

        // D must come before B and C
        // B and C must come before A
        let d_pos = order.iter().position(|x| x == "d").unwrap();
        let b_pos = order.iter().position(|x| x == "b").unwrap();
        let c_pos = order.iter().position(|x| x == "c").unwrap();
        let a_pos = order.iter().position(|x| x == "a").unwrap();

        assert!(d_pos < b_pos, "d should be compiled before b");
        assert!(d_pos < c_pos, "d should be compiled before c");
        assert!(b_pos < a_pos, "b should be compiled before a");
        assert!(c_pos < a_pos, "c should be compiled before a");
    }

    #[test]
    fn test_dependency_graph_three_node_cycle() {
        // A -> B -> C -> A
        let mut graph = DependencyGraph::new();
        graph.add_module("a");
        graph.add_module("b");
        graph.add_module("c");
        graph.add_edge("a", "b");
        graph.add_edge("b", "c");
        graph.add_edge("c", "a");

        let result = graph.topological_sort();
        assert!(result.is_err(), "Should detect 3-node cycle");
    }

    #[test]
    fn test_dependency_graph_self_cycle() {
        // A imports itself
        let mut graph = DependencyGraph::new();
        graph.add_module("a");
        graph.add_edge("a", "a");

        let result = graph.topological_sort();
        assert!(result.is_err(), "Should detect self-import cycle");
    }

    #[test]
    fn test_dependency_graph_no_dependencies() {
        let mut graph = DependencyGraph::new();
        graph.add_module("a");
        graph.add_module("b");
        graph.add_module("c");
        // No edges - all independent

        let order = graph.topological_sort().unwrap();
        assert_eq!(order.len(), 3);
        // All modules should be present
        assert!(order.contains(&"a".to_string()));
        assert!(order.contains(&"b".to_string()));
        assert!(order.contains(&"c".to_string()));
    }

    #[test]
    fn test_dependency_graph_single_module() {
        let mut graph = DependencyGraph::new();
        graph.add_module("main");

        let order = graph.topological_sort().unwrap();
        assert_eq!(order, vec!["main".to_string()]);
    }

    #[test]
    fn test_dependency_graph_multiple_roots() {
        // Two independent dependency trees
        // A -> B    C -> D
        let mut graph = DependencyGraph::new();
        graph.add_module("a");
        graph.add_module("b");
        graph.add_module("c");
        graph.add_module("d");
        graph.add_edge("a", "b");
        graph.add_edge("c", "d");

        let order = graph.topological_sort().unwrap();

        let b_pos = order.iter().position(|x| x == "b").unwrap();
        let a_pos = order.iter().position(|x| x == "a").unwrap();
        let d_pos = order.iter().position(|x| x == "d").unwrap();
        let c_pos = order.iter().position(|x| x == "c").unwrap();

        assert!(b_pos < a_pos, "b should be compiled before a");
        assert!(d_pos < c_pos, "d should be compiled before c");
    }

    #[test]
    fn test_dependency_graph_long_chain() {
        // A -> B -> C -> D -> E
        let mut graph = DependencyGraph::new();
        for module in &["a", "b", "c", "d", "e"] {
            graph.add_module(module);
        }
        graph.add_edge("a", "b");
        graph.add_edge("b", "c");
        graph.add_edge("c", "d");
        graph.add_edge("d", "e");

        let order = graph.topological_sort().unwrap();

        // Verify order: e, d, c, b, a
        let positions: Vec<usize> = ["e", "d", "c", "b", "a"]
            .iter()
            .map(|m| order.iter().position(|x| x == *m).unwrap())
            .collect();

        for i in 0..positions.len() - 1 {
            assert!(
                positions[i] < positions[i + 1],
                "Module at position {} should come before module at position {}",
                i,
                i + 1
            );
        }
    }

    #[test]
    fn test_dependency_graph_partial_cycle() {
        // A -> B -> C -> B (cycle), but A is outside the cycle
        let mut graph = DependencyGraph::new();
        graph.add_module("a");
        graph.add_module("b");
        graph.add_module("c");
        graph.add_edge("a", "b");
        graph.add_edge("b", "c");
        graph.add_edge("c", "b");

        let result = graph.topological_sort();
        assert!(result.is_err(), "Should detect partial cycle");
    }

    // ==================== ImportInfo Tests ====================

    #[test]
    fn test_import_info_creation() {
        let info = ImportInfo {
            module_path: ModulePath::new(vec!["utils".to_string()]),
            raw_path: None,
            alias: Some("u".to_string()),
            location: SourceLocation::default(),
            resolved_module_key: None,
            imported_item: None,
        };
        assert_eq!(info.module_path.as_string(), "utils");
        assert_eq!(info.alias, Some("u".to_string()));
    }

    // ==================== ModuleResolver Tests ====================

    #[test]
    fn test_module_resolver_new() {
        let resolver = ModuleResolver::new();
        assert!(resolver.resolved_modules.is_empty());
        assert!(resolver.errors.is_empty());
    }
}
