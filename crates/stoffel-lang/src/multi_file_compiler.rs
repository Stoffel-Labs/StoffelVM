//! Multi-file compilation orchestration.
//!
//! This module handles compiling projects that span multiple .stfl files.
//! It coordinates:
//! - Module resolution and dependency tracking
//! - Compilation ordering based on dependencies
//! - Symbol table merging for imported modules
//! - Linking compiled modules into a single program

use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::ast::AstNode;
use crate::bytecode::CompiledProgram;
use crate::codegen;
use crate::compiler::CompilerOptions;
use crate::errors::{CompilerError, ErrorReporter, SourceLocation};
use crate::module_resolver::{
    is_std_module_path, ImportInfo, ModulePath, ModuleResolver, ResolvedModule,
};
use crate::optimizations;
use crate::semantic;
use crate::symbol_table::{SymbolInfo, SymbolKind, SymbolType};
use crate::ufcs;

/// Stores exported symbols from a compiled module.
#[derive(Debug, Clone)]
pub struct ModuleExports {
    /// The module path
    pub module_path: ModulePath,
    /// Exported function symbols: name -> (parameter types, return type)
    pub functions: HashMap<String, (Vec<SymbolType>, SymbolType)>,
    /// Exported variable/constant symbols: name -> type
    pub variables: HashMap<String, SymbolType>,
    /// Call-site binding information (names, defaults and variadic packing).
    pub parameters: HashMap<String, Vec<crate::ast::Parameter>>,
}

impl ModuleExports {
    pub fn new(module_path: ModulePath) -> Self {
        Self {
            module_path,
            functions: HashMap::new(),
            variables: HashMap::new(),
            parameters: HashMap::new(),
        }
    }
}

/// Compiled module with its bytecode and exports.
#[derive(Debug)]
pub struct CompiledModule {
    pub module_path: ModulePath,
    pub program: CompiledProgram,
    pub exports: ModuleExports,
    analyzed_ast: AstNode,
}

/// The multi-file compiler orchestrates compilation across multiple modules.
pub struct MultiFileCompiler {
    resolver: ModuleResolver,
    options: CompilerOptions,
    /// Compiled modules indexed by module path string
    compiled_modules: HashMap<String, CompiledModule>,
}

impl MultiFileCompiler {
    pub fn new(options: CompilerOptions) -> Self {
        Self {
            resolver: ModuleResolver::new(),
            options,
            compiled_modules: HashMap::new(),
        }
    }

    /// Compiles a project starting from an entry file.
    /// Returns a combined CompiledProgram containing all modules.
    pub fn compile_project(
        &mut self,
        entry_file: &Path,
    ) -> Result<CompiledProgram, Vec<CompilerError>> {
        // Phase 1: Resolve all modules and build dependency graph
        let entry_module = self.resolver.resolve_all(entry_file)?;

        // Phase 2: Get compilation order (dependencies first)
        let compilation_order = self.resolver.get_compilation_order().map_err(|e| vec![e])?;

        // Phase 3: Compile each module in order
        for module_key in &compilation_order {
            if module_key != &entry_module {
                if let Some(resolved) = self.resolver.resolved_modules.get(module_key) {
                    if let AstNode::Block(statements) = &resolved.ast {
                        if let Some(stmt) = statements
                            .iter()
                            .find(|stmt| semantic::SemanticAnalyzer::is_top_level_execution(stmt))
                        {
                            return Err(vec![CompilerError::semantic_error(
                                "Imported modules cannot contain executable top-level code or variables", stmt.location())
                                .with_hint("Move initialization into a function and call it explicitly; pass values as parameters")]);
                        }
                    }
                }
            }
            self.compile_module(module_key, &entry_module)?;
        }

        // Phase 4: Link all modules into a single program, then remove any
        // functions that are not reachable from the entry chunk.
        let mut program = self.link_modules(&entry_module)?;
        let mut nodes = Vec::new();
        let mut roots = self.options.entry_points.clone();
        let mut keys = self.compiled_modules.keys().collect::<Vec<_>>();
        keys.sort();
        for key in keys {
            let names = self.function_bindings(key, &entry_module);
            crate::compiler::collect_literal_closure_targets(
                &self.compiled_modules[key].analyzed_ast,
                &mut roots,
            );
            nodes.push(qualify_analysis(
                self.compiled_modules[key].analyzed_ast.clone(),
                &names,
                key == &entry_module,
            ));
        }
        let outputs = crate::client_io_planner::infer_output_domains(
            &AstNode::Block(nodes),
            &self.options.entry_points,
        )?;
        crate::client_io_planner::apply_output_domains(outputs, &mut program.client_io_manifest);
        program.prune_unreachable_functions_with_roots(roots.iter().map(String::as_str));
        Ok(program)
    }

    fn function_bindings(&self, module_key: &str, entry: &str) -> HashMap<String, String> {
        self.bindings_for_names(
            module_key,
            entry,
            self.compiled_modules[module_key]
                .program
                .function_chunks
                .keys(),
        )
    }

    fn bindings_for_names<'a>(
        &self,
        module_key: &str,
        entry: &str,
        local_names: impl IntoIterator<Item = &'a String>,
    ) -> HashMap<String, String> {
        let mut names = HashMap::new();
        for name in local_names {
            names.insert(
                name.clone(),
                if module_key == entry {
                    name.clone()
                } else {
                    format!("{module_key}.{name}")
                },
            );
        }
        let mut simple_imports: HashMap<String, Vec<String>> = HashMap::new();
        for import in &self.resolver.resolved_modules[module_key].imports {
            if is_std_module_path(&import.module_path) {
                continue;
            }
            let key = import
                .resolved_module_key
                .clone()
                .unwrap_or_else(|| import.module_path.as_string());
            if let Some(dependency) = self.compiled_modules.get(&key) {
                for name in dependency.exports.functions.keys() {
                    let Some(binding) = import.binding_for_export(name) else {
                        continue;
                    };
                    names.insert(binding, format!("{key}.{name}"));
                    if import.imported_item.is_none() {
                        simple_imports
                            .entry(name.clone())
                            .or_default()
                            .push(format!("{key}.{name}"));
                    }
                }
            }
        }
        for (name, targets) in simple_imports {
            if targets.len() == 1 {
                names.entry(name).or_insert_with(|| targets[0].clone());
            }
        }
        names
    }

    /// Compiles a single module, using exports from already-compiled dependencies.
    fn compile_module(&mut self, module_key: &str, entry: &str) -> Result<(), Vec<CompilerError>> {
        let resolved = self
            .resolver
            .resolved_modules
            .get(module_key)
            .ok_or_else(|| {
                vec![CompilerError::syntax_error(
                    format!(
                        "Internal error: module '{}' not found in resolver",
                        module_key
                    ),
                    SourceLocation::default(),
                )]
            })?;

        // Collect imports for this module
        let imported_symbols = self.collect_imported_symbols(&resolved.imports)?;

        // Compile the module with imported symbols
        let (program, exports, analyzed_ast) =
            self.compile_single_module(resolved, &imported_symbols, module_key, entry)?;

        // Store the compiled module
        self.compiled_modules.insert(
            module_key.to_string(),
            CompiledModule {
                module_path: resolved.module_path.clone(),
                program,
                exports,
                analyzed_ast,
            },
        );

        Ok(())
    }

    /// Collects all symbols that should be available from imports.
    fn collect_imported_symbols(
        &self,
        imports: &[ImportInfo],
    ) -> Result<HashMap<String, SymbolInfo>, Vec<CompilerError>> {
        let mut symbols = HashMap::new();
        let mut bindings = HashMap::new();

        for import in imports {
            if is_std_module_path(&import.module_path) {
                continue;
            }

            let module_key = import
                .resolved_module_key
                .as_ref()
                .cloned()
                .unwrap_or_else(|| import.module_path.as_string());

            let compiled = self.compiled_modules.get(&module_key).ok_or_else(|| {
                vec![CompilerError::syntax_error(
                    format!("Module '{}' not yet compiled (internal error)", module_key),
                    import.location.clone(),
                )]
            })?;

            let binding = import.alias.clone().unwrap_or_else(|| {
                import
                    .imported_item
                    .clone()
                    .unwrap_or_else(|| import.module_path.as_string())
            });
            let target = (module_key.clone(), import.imported_item.clone());
            if let Some(previous) = bindings.insert(binding.clone(), target.clone()) {
                if previous != target {
                    return Err(vec![CompilerError::semantic_error(
                        format!("Import binding '{binding}' refers to more than one target"),
                        import.location.clone(),
                    )
                    .with_hint("Give the imports distinct aliases")]);
                }
            }
            if let Some(item) = &import.imported_item {
                if !compiled.exports.functions.contains_key(item)
                    && !compiled.exports.variables.contains_key(item)
                {
                    return Err(vec![CompilerError::semantic_error(
                        format!("Module '{module_key}' has no exported function or value named '{item}'"),
                        import.location.clone(),
                    ).with_hint("Check the exported name in the imported .stfl file")]);
                }
            }

            // Add function exports
            for (name, (params, ret_type)) in &compiled.exports.functions {
                let Some(qualified_name) = import.binding_for_export(name) else {
                    continue;
                };
                symbols.insert(
                    qualified_name.clone(),
                    SymbolInfo {
                        name: qualified_name,
                        kind: SymbolKind::Function {
                            parameters: params.clone(),
                            return_type: ret_type.clone(),
                        },
                        symbol_type: ret_type.clone(),
                        is_secret: ret_type.is_secret(),
                        defined_at: import.location.clone(),
                    },
                );
            }

            // Add variable exports
            for (name, var_type) in &compiled.exports.variables {
                let Some(qualified_name) = import.binding_for_export(name) else {
                    continue;
                };
                symbols.insert(
                    qualified_name.clone(),
                    SymbolInfo {
                        name: qualified_name,
                        kind: SymbolKind::Variable { is_mutable: false },
                        symbol_type: var_type.clone(),
                        is_secret: var_type.is_secret(),
                        defined_at: import.location.clone(),
                    },
                );
            }
        }

        Ok(symbols)
    }

    /// Compiles a single module with access to imported symbols.
    fn compile_single_module(
        &self,
        resolved: &ResolvedModule,
        imported_symbols: &HashMap<String, SymbolInfo>,
        module_key: &str,
        entry: &str,
    ) -> Result<(CompiledProgram, ModuleExports, AstNode), Vec<CompilerError>> {
        let mut error_reporter = ErrorReporter::new();

        // An explicit member alias cannot silently replace a local declaration.
        if let AstNode::Block(nodes) = &resolved.ast {
            for import in &resolved.imports {
                if let Some(item) = &import.imported_item {
                    let binding = import.alias.as_ref().unwrap_or(item);
                    if nodes.iter().any(|node| match node {
                        AstNode::FunctionDefinition {
                            name: Some(name), ..
                        }
                        | AstNode::VariableDeclaration { name, .. }
                        | AstNode::ObjectDefinition { name, .. }
                        | AstNode::TypeAlias { name, .. }
                        | AstNode::EnumDefinition { name, .. } => name == binding,
                        _ => false,
                    }) {
                        return Err(vec![CompilerError::semantic_error(
                            format!(
                                "Import binding '{binding}' conflicts with a local declaration"
                            ),
                            import.location.clone(),
                        )
                        .with_hint(
                            "Choose a distinct import alias or rename the local declaration",
                        )]);
                    }
                }
            }
        }
        let ast = resolved.ast.clone();

        // Apply UFCS transformation, preserving known module-qualified calls.
        let module_prefixes = Self::module_prefixes_for_imports(&resolved.imports);
        let transformed_ast = ufcs::transform_ufcs_with_module_prefixes(ast, &module_prefixes);

        // Semantic analysis with imported symbols
        let analyzed_ast = self.analyze_with_imports(
            transformed_ast,
            imported_symbols,
            &resolved.imports,
            &mut error_reporter,
            &resolved.file_path.to_string_lossy(),
        )?;

        if error_reporter.has_errors() {
            return Err(error_reporter.get_all().into_iter().cloned().collect());
        }

        let mut local_names = Vec::new();
        collect_function_names(&analyzed_ast, &mut local_names);
        let bindings = self.bindings_for_names(module_key, entry, local_names.iter());
        let analyzed_ast = qualify_closure_targets(analyzed_ast, &bindings);
        let source_ast = analyzed_ast.clone();
        let analyzed_ast = optimizations::lower_semantic_client_reductions(analyzed_ast);

        // Apply optimizations
        let optimized_ast = if self.options.optimize {
            optimizations::optimize_all_with_budgets(
                analyzed_ast,
                self.options.optimization_level,
                self.options.opt_budgets(),
            )
        } else {
            analyzed_ast
        };

        // Extract exports before code generation
        let exports = self.extract_exports(&optimized_ast, &resolved.module_path);

        // Code generation
        let codegen_opt_level = if self.options.optimize {
            self.options.optimization_level
        } else {
            0
        };
        let mut program = codegen::generate_bytecode_with_opt_level_and_backend(
            &optimized_ast,
            codegen_opt_level,
            self.options.mpc_backend,
        )
        .map_err(|e| vec![e])?;
        program.client_io_manifest.mpc_backend = self.options.mpc_backend;
        program.client_io_manifest.mpc_curve = self.options.mpc_curve;

        Ok((program, exports, source_ast))
    }

    /// Performs semantic analysis with imported symbols pre-populated.
    fn analyze_with_imports(
        &self,
        ast: AstNode,
        imported_symbols: &HashMap<String, SymbolInfo>,
        imports: &[ImportInfo],
        error_reporter: &mut ErrorReporter,
        filename: &str,
    ) -> Result<AstNode, Vec<CompilerError>> {
        let mut analyzer = semantic::SemanticAnalyzer::with_imports(
            error_reporter,
            filename,
            imported_symbols.clone(),
        );
        for import in imports {
            if let Some(compiled) = import
                .resolved_module_key
                .as_ref()
                .and_then(|key| self.compiled_modules.get(key))
            {
                for (name, parameters) in &compiled.exports.parameters {
                    if let Some(binding) = import.binding_for_export(name) {
                        analyzer.import_function_signature(binding, parameters);
                    }
                }
            }
        }
        analyzer
            .analyze(ast)
            .map_err(|_| error_reporter.get_all().into_iter().cloned().collect())
    }

    fn module_prefixes_for_imports(imports: &[ImportInfo]) -> HashSet<String> {
        imports
            .iter()
            .filter(|import| {
                !is_std_module_path(&import.module_path) && import.imported_item.is_none()
            })
            .map(|import| {
                import
                    .alias
                    .clone()
                    .unwrap_or_else(|| import.module_path.as_string())
            })
            .collect()
    }

    /// Extracts exported symbols from a compiled AST.
    fn extract_exports(&self, ast: &AstNode, module_path: &ModulePath) -> ModuleExports {
        let mut exports = ModuleExports::new(module_path.clone());
        self.extract_exports_recursive(ast, &mut exports);
        exports
    }

    fn extract_exports_recursive(&self, node: &AstNode, exports: &mut ModuleExports) {
        match node {
            AstNode::Block(statements) => {
                for stmt in statements {
                    self.extract_exports_recursive(stmt, exports);
                }
            }
            AstNode::FunctionDefinition {
                name: Some(name),
                type_params,
                parameters,
                return_type,
                ..
            } => {
                // All top-level functions are exported
                let param_types: Vec<SymbolType> = parameters
                    .iter()
                    .map(|p| {
                        let ty = p
                            .type_annotation
                            .as_ref()
                            .map(|t| SymbolType::from_ast_with_type_params(t, type_params))
                            .unwrap_or(SymbolType::Unknown);
                        if p.is_variadic {
                            SymbolType::List(Box::new(ty))
                        } else {
                            ty
                        }
                    })
                    .collect();

                let ret_type = return_type
                    .as_ref()
                    .map(|t| SymbolType::from_ast_with_type_params(t, type_params))
                    .unwrap_or(SymbolType::Void);

                exports
                    .functions
                    .insert(name.clone(), (param_types, ret_type));
                exports.parameters.insert(name.clone(), parameters.clone());
            }
            AstNode::VariableDeclaration {
                name,
                type_annotation,
                is_secret,
                ..
            } => {
                // Export top-level variables
                let var_type = type_annotation
                    .as_ref()
                    .map(|t| SymbolType::from_ast(t))
                    .unwrap_or(SymbolType::Unknown);

                let final_type = if *is_secret {
                    SymbolType::Secret(Box::new(var_type))
                } else {
                    var_type
                };

                exports.variables.insert(name.clone(), final_type);
            }
            _ => {}
        }
    }

    /// Links all compiled modules into a single program.
    fn link_modules(&self, entry_module: &str) -> Result<CompiledProgram, Vec<CompilerError>> {
        // Get the entry module's compiled program
        let entry = self.compiled_modules.get(entry_module).ok_or_else(|| {
            vec![CompilerError::syntax_error(
                format!("Entry module '{}' not found", entry_module),
                SourceLocation::default(),
            )]
        })?;

        // Start with the entry module's program
        let mut linked = entry.program.clone();

        // Resolve CALL names in their defining module. The same bindings drive
        // domain inference, so aliases and identically named private helpers
        // cannot make metadata describe a different function from the VM call.
        let names = self.function_bindings(entry_module, entry_module);
        qualify_chunk(&mut linked.main_chunk, &names);
        for chunk in linked.function_chunks.values_mut() {
            qualify_chunk(chunk, &names);
        }
        let mut keys = self.compiled_modules.keys().collect::<Vec<_>>();
        keys.sort();
        for module_key in keys {
            if module_key == entry_module {
                continue;
            }
            let compiled = &self.compiled_modules[module_key];
            let names = self.function_bindings(module_key, entry_module);
            for (func_name, chunk) in &compiled.program.function_chunks {
                let mut chunk = chunk.clone();
                qualify_chunk(&mut chunk, &names);
                linked
                    .function_chunks
                    .insert(format!("{module_key}.{func_name}"), chunk);
            }
        }

        Ok(linked)
    }
}

fn collect_function_names(node: &AstNode, names: &mut Vec<String>) {
    if let AstNode::FunctionDefinition { name, body, .. } = node {
        if let Some(name) = name {
            names.push(name.clone());
        }
        collect_function_names(body, names);
    }
    optimizations::for_each_child(node, &mut |child| collect_function_names(child, names));
}

fn qualify_closure_targets(mut node: AstNode, names: &HashMap<String, String>) -> AstNode {
    if let AstNode::FunctionDefinition { body, .. } = &mut node {
        **body = qualify_closure_targets(*body.clone(), names);
        return node;
    }
    if let AstNode::FunctionCall {
        function,
        arguments,
        ..
    } = &mut node
    {
        if matches!(function.as_ref(), AstNode::Identifier(name, _) if name == "create_closure" || name == "create_closure_with_upvalue")
        {
            if let Some(AstNode::Literal {
                value: crate::ast::Value::String(target),
                ..
            }) = arguments.first_mut()
            {
                if let Some(qualified) = names.get(target) {
                    *target = qualified.clone();
                }
            }
        }
    }
    optimizations::map_children(node, &mut |child| qualify_closure_targets(child, names))
}

fn qualify_chunk(chunk: &mut crate::bytecode::BytecodeChunk, names: &HashMap<String, String>) {
    for instruction in &mut chunk.instructions {
        if let crate::bytecode::Instruction::CALL(name) = instruction {
            if let Some(qualified) = names.get(name) {
                *name = qualified.clone();
            }
        }
    }
}

fn qualify_analysis(mut node: AstNode, names: &HashMap<String, String>, entry: bool) -> AstNode {
    match &mut node {
        AstNode::FunctionDefinition {
            name,
            body,
            pragmas,
            ..
        } => {
            if let Some(qualified) = name.as_ref().and_then(|name| names.get(name)) {
                *name = Some(qualified.clone());
            }
            if !entry {
                pragmas.retain(|p| !matches!(p, crate::ast::Pragma::Simple(n, _) if n == "entry"));
            }
            **body = qualify_analysis(*body.clone(), names, entry);
            return node;
        }
        AstNode::FunctionCall { function, .. }
        | AstNode::CommandCall {
            command: function, ..
        } => {
            if let AstNode::Identifier(name, _) = function.as_mut() {
                if let Some(qualified) = names.get(name) {
                    *name = qualified.clone();
                }
            }
        }
        _ => {}
    }
    optimizations::map_children(node, &mut |child| qualify_analysis(child, names, entry))
}

/// Checks if a source string contains import statements.
/// Used to determine whether to use single-file or multi-file compilation.
pub fn has_imports(source: &str) -> bool {
    // Simple heuristic: check for "import " at the start of a line
    source.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with("import ")
    })
}

/// Compiles a project, automatically choosing single-file or multi-file mode.
pub fn compile_project(
    entry_file: &Path,
    options: &CompilerOptions,
) -> Result<CompiledProgram, Vec<CompilerError>> {
    let mut compiler = MultiFileCompiler::new(options.clone());
    compiler.compile_project(entry_file)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== has_imports Tests ====================

    #[test]
    fn test_has_imports_basic() {
        assert!(has_imports(
            "import utils.math\ndef main() -> int64:\n  return 0"
        ));
    }

    #[test]
    fn test_has_imports_with_leading_whitespace() {
        assert!(has_imports("  import utils\n"));
    }

    #[test]
    fn test_has_imports_no_imports() {
        assert!(!has_imports("def main() -> int64:\n  return 0"));
    }

    #[test]
    fn test_has_imports_comment_not_counted() {
        // Comments starting with # are not imports
        assert!(!has_imports(
            "# import is a keyword\ndef main() -> int64:\n  return 0"
        ));
    }

    #[test]
    fn test_has_imports_multiple_imports() {
        let source = r#"
import utils.math
import utils.strings
import helpers

def main() -> int64:
  return 0
"#;
        assert!(has_imports(source));
    }

    #[test]
    fn test_has_imports_import_with_alias() {
        assert!(has_imports(
            "import utils.math as m\ndef main() -> int64:\n  return 0"
        ));
    }

    #[test]
    fn test_has_imports_import_in_middle_of_file() {
        let source = r#"
# This is a comment

import utils.math

def main() -> int64:
  return 0
"#;
        assert!(has_imports(source));
    }

    #[test]
    fn test_has_imports_empty_source() {
        assert!(!has_imports(""));
    }

    #[test]
    fn test_has_imports_only_whitespace() {
        assert!(!has_imports("   \n\n   \n"));
    }

    #[test]
    fn test_has_imports_import_word_in_string_not_counted() {
        // "import" inside a string literal shouldn't trigger detection
        // Note: This is a limitation - the current implementation might give false positives
        // if "import " appears at the start of a line inside a multi-line string
        assert!(!has_imports(
            "var s = \"import something\"\ndef main() -> int64:\n  return 0"
        ));
    }

    // ==================== ModuleExports Tests ====================

    #[test]
    fn test_module_exports_new() {
        let path = ModulePath::new(vec!["utils".to_string()]);
        let exports = ModuleExports::new(path.clone());
        assert!(exports.functions.is_empty());
        assert!(exports.variables.is_empty());
        assert_eq!(exports.module_path.as_string(), "utils");
    }

    // ==================== MultiFileCompiler Tests ====================

    #[test]
    fn test_multi_file_compiler_new() {
        let options = CompilerOptions::default();
        let compiler = MultiFileCompiler::new(options);
        assert!(compiler.compiled_modules.is_empty());
    }
}
