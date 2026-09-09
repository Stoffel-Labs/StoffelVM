use std::path::Path;

use crate::ast::{AstNode, Value};
use crate::bytecode::CompiledProgram;
use crate::codegen;
use crate::errors::{CompilerError, ErrorReporter};
use crate::lexer;
use crate::multi_file_compiler;
use crate::optimizations;
use crate::parser;
use crate::semantic;
use crate::ufcs;
use stoffel_vm_types::compiled_binary::{MpcBackend, MpcCurve};

/// Options to configure the compilation process.
#[derive(Debug, Clone, Default)]
pub struct CompilerOptions {
    /// Enable or disable optimization passes.
    pub optimize: bool,
    /// Set the optimization level (0-3).
    pub optimization_level: u8,
    /// Print intermediate representations (Tokens, AST) for debugging.
    pub print_ir: bool,
    /// MPC backend expected by the coordinator when running the emitted binary.
    pub mpc_backend: MpcBackend,
    /// MPC curve expected by AVSS when running the emitted binary.
    pub mpc_curve: MpcCurve,
    /// Additional function chunks that should be preserved as executable entrypoints.
    pub entry_points: Vec<String>,
    /// Override for the inliner blowup budget (`None` = compiler default).
    ///
    /// These budget overrides are threaded explicitly (rather than read from
    /// process-global environment variables inside the optimizer) so that
    /// compilation is hermetic: in a process that compiles more than once, a
    /// budget chosen for one compile never leaks into another.
    pub inline_budget: Option<usize>,
    /// Override for the global loop-unroll blowup budget (`None` = default).
    pub unroll_budget: Option<usize>,
    /// Override for the per-loop unroll expansion cap (`None` = default).
    pub unroll_max_expansion: Option<usize>,
    // Add more options as needed: output_path, target_platform, etc.
}

impl CompilerOptions {
    /// The optimizer expansion budgets carried by these options.
    pub fn opt_budgets(&self) -> optimizations::OptBudgets {
        optimizations::OptBudgets {
            inline: self.inline_budget,
            unroll: self.unroll_budget,
            unroll_max_expansion: self.unroll_max_expansion,
        }
    }
}

/// Compiles the given source code string.
///
/// This function orchestrates the different phases of the compiler:
/// Lexing, Parsing, AST Transformations (like UFCS), Semantic Analysis, and Code Generation.
///
/// # Arguments
///
/// * `source` - The source code to compile.
/// * `filename` - The name of the source file (used for error reporting).
/// * `options` - Configuration for the compilation process.
///
/// # Returns
///
/// * `Ok(CompiledProgram)` - If compilation is successful.
/// * `Err(Vec<CompilerError>)` - If any errors occur during compilation.
pub fn compile(
    source: &str,
    filename: &str,
    options: &CompilerOptions,
) -> Result<CompiledProgram, Vec<CompilerError>> {
    let mut error_reporter = ErrorReporter::new();

    // 1. Lexing
    let tokens = match lexer::tokenize(source, filename) {
        Ok(t) => t,
        Err(e) => {
            error_reporter.add_error(e);
            // Cannot proceed without tokens
            return Err(error_reporter.get_all().into_iter().cloned().collect());
        }
    };
    if options.print_ir {
        println!("--- Tokens ---");
        println!("{:?}", tokens);
        println!("--------------");
    }

    // 2. Parsing
    let parse_output = parser::parse_recovering(&tokens, filename);
    for error in parse_output.errors {
        error_reporter.add_error(error);
    }
    let ast_root = parse_output.ast;
    if options.print_ir {
        println!("--- Initial AST ---");
        println!("{:#?}", ast_root);
        println!("-------------------");
    }

    // 3. UFCS Transformation (AST Pass)
    let transformed_ast = ufcs::transform_ufcs(ast_root);
    if options.print_ir {
        println!("--- Transformed AST (UFCS) ---");
        println!("{:#?}", transformed_ast);
        println!("------------------------------");
    }

    // 4. Semantic Analysis (Symbol Table, Type Checking)
    let analyzed_ast = match semantic::analyze(transformed_ast, &mut error_reporter, filename) {
        Ok(ast) => ast,
        Err(_) => {
            // Errors were already added to the reporter by the analyzer
            // Stop compilation if semantic errors occurred
            return Err(error_reporter.get_all().into_iter().cloned().collect());
        }
    };
    if error_reporter.has_errors() {
        return Err(error_reporter.get_all().into_iter().cloned().collect());
    }
    if options.print_ir {
        println!("--- Analyzed AST (Semantic Check) ---");
        println!("{:#?}", analyzed_ast);
        println!("-------------------------------------");
    }

    // Lower semantically proven VM-native reductions even when general
    // optimization is disabled. This is a backend-aware lowering, not an
    // optional source-level performance tweak developers must remember.
    let analyzed_ast = optimizations::lower_semantic_client_reductions(analyzed_ast);

    // 5. Optimization Passes
    let optimized_ast = if options.optimize {
        let ast = optimizations::optimize_all_with_budgets(
            analyzed_ast,
            options.optimization_level,
            options.opt_budgets(),
        );
        if options.print_ir {
            println!("--- Optimized AST (full optimize_all pipeline) ---");
            println!("{:#?}", ast);
            println!("----------------------------------------------------");
        }
        ast
    } else {
        analyzed_ast
    };

    // 6. Code Generation
    let codegen_opt_level = if options.optimize {
        options.optimization_level
    } else {
        0
    };
    let mut compiled_program = match codegen::generate_bytecode_with_opt_level_and_backend(
        &optimized_ast,
        codegen_opt_level,
        options.mpc_backend,
    ) {
        Ok(program) => program,
        Err(e) => {
            error_reporter.add_error(e);
            // Stop if codegen fails
            return Err(error_reporter.get_all().into_iter().cloned().collect());
        }
    };
    let mut executable_roots = options.entry_points.clone();
    collect_literal_closure_targets(&optimized_ast, &mut executable_roots);
    executable_roots.sort();
    executable_roots.dedup();
    compiled_program
        .prune_unreachable_functions_with_roots(executable_roots.iter().map(String::as_str));
    compiled_program.client_io_manifest.mpc_backend = options.mpc_backend;
    compiled_program.client_io_manifest.mpc_curve = options.mpc_curve;

    if error_reporter.has_errors() {
        Err(error_reporter.get_all().into_iter().cloned().collect())
    } else {
        Ok(compiled_program)
    }
}

/// A closure target is a dynamic VM call edge even though the source names it
/// with a string literal. Preserve those functions when pruning ordinary
/// instruction-level call graph dead code.
fn collect_literal_closure_targets(node: &AstNode, roots: &mut Vec<String>) {
    if let AstNode::FunctionDefinition { body, .. } = node {
        collect_literal_closure_targets(body, roots);
        return;
    }
    if let AstNode::FunctionCall {
        function,
        arguments,
        ..
    } = node
    {
        let is_closure_constructor = matches!(
            function.as_ref(),
            AstNode::Identifier(name, _)
                if name == "create_closure" || name == "create_closure_with_upvalue"
        );
        if is_closure_constructor {
            if let Some(AstNode::Literal {
                value: Value::String(target),
                ..
            }) = arguments.first()
            {
                roots.push(target.clone());
            }
        }
    }
    optimizations::for_each_child(node, &mut |child| {
        collect_literal_closure_targets(child, roots)
    });
}

/// Compiles a project from a file path.
///
/// This function automatically detects whether the source file contains imports
/// and uses multi-file compilation if needed. For single-file programs without
/// imports, it falls back to the standard compilation path.
///
/// # Arguments
///
/// * `file_path` - Path to the entry source file.
/// * `source` - The source code of the entry file.
/// * `options` - Configuration for the compilation process.
///
/// # Returns
///
/// * `Ok(CompiledProgram)` - If compilation is successful.
/// * `Err(Vec<CompilerError>)` - If any errors occur during compilation.
pub fn compile_file(
    file_path: &Path,
    source: &str,
    options: &CompilerOptions,
) -> Result<CompiledProgram, Vec<CompilerError>> {
    // Check if the source contains import statements
    if multi_file_compiler::has_imports(source) {
        // Use multi-file compilation
        multi_file_compiler::compile_project(file_path, options)
    } else {
        // Use single-file compilation
        let filename = file_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown.stfl");
        compile(source, filename, options)
    }
}
