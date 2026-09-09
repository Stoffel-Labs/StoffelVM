//! Stoffel-Lang Compiler Library
//!
//! This library provides the core compilation functionality for the Stoffel programming language.
//! It can be used as a standalone compiler or integrated into other tools.

#![allow(clippy::result_large_err)]

pub mod ast;
pub mod binary_converter;
pub mod builtin_registry;
pub mod bytecode;
mod client_io_planner;
pub mod codegen;
pub mod compiler;
pub mod core_types;
mod definite_assignment;
pub mod errors;
pub mod ffi;
pub mod lexer;
pub mod module_resolver;
pub mod multi_file_compiler;
pub mod optimizations;
pub mod parser;
pub mod preprocessing_planner;
pub mod register_allocator;
mod scope_bindings;
pub mod semantic;
pub mod suggestions;
pub mod symbol_table;
pub mod ufcs;

pub use stoffel_vm_types;

// Re-export the main compiler functions and types for easy access
pub use binary_converter::{convert_to_binary, save_to_file};
pub use bytecode::{CompiledProgram, Constant};
pub use compiler::{compile, compile_file, CompilerOptions};
pub use errors::{CompilerError, ErrorReporter};

/// Get the compiler version
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
