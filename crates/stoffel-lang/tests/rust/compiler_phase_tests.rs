//! Integration tests that run the full compiler phases
//!
//! These tests exercise the lexer, parser, UFCS transformer, and semantic analyzer
//! as a unit, testing real code snippets rather than manually constructed ASTs.

use stoffel_vm_types::compiled_binary::{FunctionType, MpcBackend, MpcCurve};
use stoffel_vm_types::core_types::{ShareType, Value};
use stoffel_vm_types::instructions::Instruction;
use stoffel_vm_types::registers::DEFAULT_SECRET_REGISTER_START;
use stoffellang::ast::AstNode;
use stoffellang::bytecode::Constant;
use stoffellang::compiler::{compile, CompilerOptions};
use stoffellang::convert_to_binary;
use stoffellang::errors::{CompilerError, ErrorReporter};
use stoffellang::lexer::tokenize;
use stoffellang::parser::parse;
use stoffellang::semantic::analyze;
use stoffellang::symbol_table::SymbolType;
use stoffellang::ufcs::transform_ufcs;

// ===========================================
// Helper functions
// ===========================================

fn default_options() -> CompilerOptions {
    CompilerOptions {
        optimize: false,
        optimization_level: 0,
        print_ir: false,
        mpc_backend: MpcBackend::HoneyBadger,
        mpc_curve: MpcCurve::default(),
        ..Default::default()
    }
}

/// Runs lexer + parser and returns success/failure
fn parse_source(source: &str) -> Result<(), String> {
    let tokens = tokenize(source, "test.stfl").map_err(|e| e.message)?;
    parse(&tokens, "test.stfl").map_err(|e| e.message)?;
    Ok(())
}

/// Runs full semantic analysis pipeline and returns success/failure
fn analyze_source(source: &str) -> Result<(), Vec<String>> {
    let tokens = tokenize(source, "test.stfl").map_err(|e| vec![e.message])?;
    let ast = parse(&tokens, "test.stfl").map_err(|e| vec![e.message])?;
    let transformed = transform_ufcs(ast);
    let mut reporter = ErrorReporter::new();
    analyze(transformed, &mut reporter, "test.stfl").map_err(|_| {
        reporter
            .get_all()
            .iter()
            .map(|e| e.message.clone())
            .collect::<Vec<_>>()
    })?;
    Ok(())
}

fn analyze_source_errors(source: &str) -> Vec<CompilerError> {
    let tokens = tokenize(source, "test.stfl").expect("test source should lex");
    let ast = parse(&tokens, "test.stfl").expect("test source should parse");
    let transformed = transform_ufcs(ast);
    let mut reporter = ErrorReporter::new();
    analyze(transformed, &mut reporter, "test.stfl").expect_err("test source should fail");
    reporter.get_all().into_iter().cloned().collect()
}

fn analyze_source_ast(source: &str) -> Result<AstNode, Vec<String>> {
    let tokens = tokenize(source, "test.stfl").map_err(|e| vec![e.message])?;
    let ast = parse(&tokens, "test.stfl").map_err(|e| vec![e.message])?;
    let transformed = transform_ufcs(ast);
    let mut reporter = ErrorReporter::new();
    analyze(transformed, &mut reporter, "test.stfl").map_err(|_| {
        reporter
            .get_all()
            .iter()
            .map(|e| e.message.clone())
            .collect::<Vec<_>>()
    })
}

fn collect_call_return_types(node: &AstNode, function_name: &str, out: &mut Vec<SymbolType>) {
    match node {
        AstNode::Block(statements) => {
            for statement in statements {
                collect_call_return_types(statement, function_name, out);
            }
        }
        AstNode::VariableDeclaration {
            value: Some(value), ..
        } => {
            collect_call_return_types(value, function_name, out);
        }
        AstNode::VariableDeclaration { value: None, .. } => {}
        AstNode::Assignment { target, value, .. } => {
            collect_call_return_types(target, function_name, out);
            collect_call_return_types(value, function_name, out);
        }
        AstNode::FunctionCall {
            function,
            arguments,
            resolved_return_type,
            ..
        } => {
            if matches!(function.as_ref(), AstNode::Identifier(name, _) if name == function_name) {
                out.push(resolved_return_type.clone().unwrap_or(SymbolType::Unknown));
            }
            collect_call_return_types(function, function_name, out);
            for argument in arguments {
                collect_call_return_types(argument, function_name, out);
            }
        }
        AstNode::CommandCall {
            command, arguments, ..
        } => {
            collect_call_return_types(command, function_name, out);
            for argument in arguments {
                collect_call_return_types(argument, function_name, out);
            }
        }
        AstNode::FunctionDefinition { body, .. } => {
            collect_call_return_types(body, function_name, out);
        }
        AstNode::Return { value, .. } | AstNode::Yield(value) => {
            if let Some(value) = value {
                collect_call_return_types(value, function_name, out);
            }
        }
        AstNode::IfExpression {
            condition,
            then_branch,
            else_branch,
        } => {
            collect_call_return_types(condition, function_name, out);
            collect_call_return_types(then_branch, function_name, out);
            if let Some(else_branch) = else_branch {
                collect_call_return_types(else_branch, function_name, out);
            }
        }
        AstNode::WhileLoop {
            condition, body, ..
        } => {
            collect_call_return_types(condition, function_name, out);
            collect_call_return_types(body, function_name, out);
        }
        AstNode::ForLoop { iterable, body, .. } => {
            collect_call_return_types(iterable, function_name, out);
            collect_call_return_types(body, function_name, out);
        }
        AstNode::BinaryOperation { left, right, .. } => {
            collect_call_return_types(left, function_name, out);
            collect_call_return_types(right, function_name, out);
        }
        AstNode::UnaryOperation { operand, .. } => {
            collect_call_return_types(operand, function_name, out);
        }
        AstNode::FieldAccess { object, .. } => {
            collect_call_return_types(object, function_name, out);
        }
        AstNode::IndexAccess { base, index, .. } => {
            collect_call_return_types(base, function_name, out);
            collect_call_return_types(index, function_name, out);
        }
        AstNode::ListLiteral { elements, .. }
        | AstNode::TupleLiteral(elements)
        | AstNode::SetLiteral(elements) => {
            for element in elements {
                collect_call_return_types(element, function_name, out);
            }
        }
        AstNode::DictLiteral { pairs, .. } => {
            for (key, value) in pairs {
                collect_call_return_types(key, function_name, out);
                collect_call_return_types(value, function_name, out);
            }
        }
        AstNode::NamedArgument { value, .. }
        | AstNode::DiscardStatement {
            expression: value, ..
        } => {
            collect_call_return_types(value, function_name, out);
        }
        _ => {}
    }
}

fn list_of(element_type: SymbolType) -> SymbolType {
    SymbolType::List(Box::new(element_type))
}

/// Runs full compilation and returns success/failure
fn compile_source(source: &str) -> Result<(), Vec<String>> {
    compile(source, "test.stfl", &default_options())
        .map(|_| ())
        .map_err(|errors| errors.iter().map(|e| e.message.clone()).collect())
}

fn compile_source_errors(source: &str) -> Vec<CompilerError> {
    compile(source, "test.stfl", &default_options()).expect_err("test source should fail")
}

fn assert_client_io_manifest(source: &str, expected: &[(u64, Vec<ShareType>, Vec<ShareType>)]) {
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let binary = convert_to_binary(&program);

    assert_eq!(binary.client_io_manifest.clients.len(), expected.len());
    for (schema, (client_slot, inputs, outputs)) in
        binary.client_io_manifest.clients.iter().zip(expected)
    {
        assert_eq!(schema.client_slot, *client_slot);
        assert_eq!(&schema.inputs, inputs);
        assert_eq!(&schema.outputs, outputs);
    }
}

fn instruction_registers(instruction: &Instruction) -> Vec<usize> {
    match instruction {
        Instruction::LD(reg, _)
        | Instruction::LDI(reg, _)
        | Instruction::RET(reg)
        | Instruction::PUSHARG(reg) => vec![*reg],
        Instruction::LDS(reg, _) | Instruction::STS(_, reg) => vec![*reg],
        Instruction::MOV(dest, src) | Instruction::NOT(dest, src) | Instruction::CMP(dest, src) => {
            vec![*dest, *src]
        }
        Instruction::ADD(dest, left, right)
        | Instruction::SUB(dest, left, right)
        | Instruction::MUL(dest, left, right)
        | Instruction::DIV(dest, left, right)
        | Instruction::MOD(dest, left, right)
        | Instruction::AND(dest, left, right)
        | Instruction::OR(dest, left, right)
        | Instruction::XOR(dest, left, right)
        | Instruction::SHL(dest, left, right)
        | Instruction::SHR(dest, left, right) => vec![*dest, *left, *right],
        Instruction::NOP
        | Instruction::JMP(_)
        | Instruction::JMPEQ(_)
        | Instruction::JMPNEQ(_)
        | Instruction::JMPLT(_)
        | Instruction::JMPGT(_)
        | Instruction::CALL(_) => Vec::new(),
    }
}

fn collect_call_names(instructions: &[Instruction]) -> Vec<String> {
    instructions
        .iter()
        .filter_map(|instruction| match instruction {
            Instruction::CALL(name) => Some(name.clone()),
            _ => None,
        })
        .collect()
}

fn assert_no_unit_moves_into_secret_register(instructions: &[Instruction]) {
    let mut unit_registers = std::collections::HashSet::new();

    for instruction in instructions {
        match instruction {
            Instruction::LDI(register, Value::Unit) => {
                unit_registers.insert(*register);
            }
            Instruction::LDI(register, _) => {
                unit_registers.remove(register);
            }
            Instruction::MOV(dest, src)
                if *dest >= DEFAULT_SECRET_REGISTER_START && unit_registers.contains(src) =>
            {
                panic!(
                    "unit value from r{src} was moved into secret register r{dest}: {instructions:?}"
                );
            }
            Instruction::MOV(dest, src) => {
                if unit_registers.contains(src) {
                    unit_registers.insert(*dest);
                } else {
                    unit_registers.remove(dest);
                }
            }
            _ => {}
        }
    }
}

/// Checks if compilation produces an error containing the given substring
fn expect_error_containing(source: &str, expected_substring: &str) -> bool {
    match compile(source, "test.stfl", &default_options()) {
        Ok(_) => false,
        Err(errors) => errors
            .iter()
            .any(|e| e.message.contains(expected_substring)),
    }
}

// ===========================================
// Lexer Phase Tests
// ===========================================

#[test]
fn test_lexer_valid_identifiers() {
    let source = "var myVar = 42\nvar _private = 1\nvar camelCase = 2";
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_lexer_valid_literals() {
    let source = r#"
var a = 42
var b = 3.14
var c = "hello"
var d = True
var e = False
"#;
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_lexer_valid_operators() {
    let source = r#"
var a = 1 + 2
var b = 3 - 4
var c = 5 * 6
var d = 7 / 8
var e = 9 % 10
var f = a == b
var g = a != b
var h = a < b
var i = a > b
var j = a <= b
var k = a >= b
"#;
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_lexer_hex_literals() {
    let source = "var x = 0xFF\nvar y = 0x1A2B";
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_lexer_binary_literals() {
    let source = "var x = 0b1010\nvar y = 0b11110000";
    assert!(parse_source(source).is_ok());
}

// ===========================================
// Parser Phase Tests - Object Syntax
// ===========================================

#[test]
fn test_parser_field_access() {
    let source = "var x = obj.field";
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_method_call() {
    let source = "var x = obj.method(1, 2)";
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_chained_method_calls() {
    let source = "var x = a.first().second().third()";
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_builtin_object_calls() {
    let source = r#"
var share = ClientStore.take_share(0, 0)
var id = Mpc.party_id()
var n = Mpc.n_parties()
"#;
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_field_access_in_expressions() {
    let source = "var sum = a.x + b.y * c.z";
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_index_and_field_combined() {
    let source = r#"
var x = arr[0].field
var y = obj.array[1]
"#;
    assert!(parse_source(source).is_ok());
}

// ===========================================
// Parser Phase Tests - Functions
// ===========================================

#[test]
fn test_parser_function_definition() {
    let source = r#"
def add(a: int64, b: int64) -> int64:
  return a + b
"#;
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_function_no_return_type() {
    let source = r#"
def greet(name: string):
  print(name)
"#;
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_function_no_params() {
    let source = r#"
def get_value() -> int64:
  return 42
"#;
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_function_with_secret_types() {
    let source = r#"
def compute(x: secret int64) -> secret int64:
  return x * 2
"#;
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_secret_function_modifier_is_rejected() {
    let source = r#"
secret def compute(x: int64) -> int64:
  return x * 2
"#;
    assert!(expect_error_containing(
        source,
        "The 'secret' descriptor is only valid in type annotations"
    ));
}

// ===========================================
// Parser Phase Tests - Control Flow
// ===========================================

#[test]
fn test_parser_if_statement() {
    let source = r#"
if x > 0:
  print("positive")
"#;
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_if_else() {
    let source = r#"
if x > 0:
  print("positive")
else:
  print("non-positive")
"#;
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_if_elif_else() {
    let source = r#"
if x > 0:
  print("positive")
elif x < 0:
  print("negative")
else:
  print("zero")
"#;
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_rejects_symbolic_and_in_if_condition() {
    let source = r#"
def main(a: bool, b: bool):
  if a == b && b == a:
    print("does not compile")
"#;
    let error = parse_source(source).expect_err("symbolic boolean operator should be rejected");
    assert!(
        error.contains("Unsupported boolean operator '&&'. Use 'and' instead."),
        "expected pythonic boolean operator guidance, got: {error}"
    );
}

#[test]
fn test_parser_rejects_parenthesized_symbolic_and_in_if_condition() {
    let source = r#"
def main(a: bool, b: bool):
  if (a == b) && (b == a):
    print("does not compile")
"#;
    let error = parse_source(source).expect_err("symbolic boolean operator should be rejected");
    assert!(
        error.contains("Unsupported boolean operator '&&'. Use 'and' instead."),
        "expected pythonic boolean operator guidance, got: {error}"
    );
}

#[test]
fn test_parser_rejects_symbolic_or_in_if_condition() {
    let source = r#"
def main(a: bool, b: bool):
  if a == b || b == a:
    print("does not compile")
"#;
    let error = parse_source(source).expect_err("symbolic boolean operator should be rejected");
    assert!(
        error.contains("Unsupported boolean operator '||'. Use 'or' instead."),
        "expected pythonic boolean operator guidance, got: {error}"
    );
}

#[test]
fn test_parser_while_loop() {
    let source = r#"
while x > 0:
  x = x - 1
"#;
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_for_loop() {
    // For loop syntax requires a range with ".." operator (no spaces around it)
    let source = r#"
for i in 0..10:
  print(i)
"#;
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_for_loop_list_iteration() {
    // For loop can iterate over a list variable
    let source = r#"
var items = [1, 2, 3]
for item in items:
  print(item)
"#;
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_for_loop_list_literal() {
    // For loop can iterate directly over a list literal
    let source = r#"
for x in [10, 20, 30]:
  print(x)
"#;
    assert!(parse_source(source).is_ok());
}

// ===========================================
// Parser Phase Tests - Declarations
// ===========================================

#[test]
fn test_parser_variable_declaration() {
    let source = "var x = 42";
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_typed_variable() {
    let source = "var x: int64 = 42";
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_secret_variable_modifier_is_rejected() {
    let source = "secret var x = 42";
    assert!(expect_error_containing(
        source,
        "The 'secret' descriptor is only valid in type annotations"
    ));
}

#[test]
fn test_parser_secret_typed_variable() {
    let source = "var x: secret int64 = 42";
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_secret_field_modifier_is_rejected() {
    let source = r#"
object SecretRecord:
  secret value: int64
"#;
    assert!(expect_error_containing(
        source,
        "The 'secret' descriptor is only valid in type annotations"
    ));
}

#[test]
fn test_parser_array_literal() {
    let source = "var arr = [1, 2, 3, 4, 5]";
    assert!(parse_source(source).is_ok());
}

// ===========================================
// Semantic Analysis Tests - Valid Programs
// ===========================================

#[test]
fn test_semantic_simple_program() {
    let source = r#"
var x = 10
var y = 20
var z = x + y
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_function_call() {
    let source = r#"
def double(n: int64) -> int64:
  return n * 2

var result = double(21)
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_builtin_print() {
    // print is a statement, test in proper context
    let source = r#"
var msg = "Hello, World!"
print(msg)
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_builtin_print_accepts_multiple_mixed_arguments() {
    let source = r#"
var label = "answer"
var value = 42
print(label, "=", value, True)
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_builtin_print_rejects_untyped_share_random_argument() {
    let source = r#"
print("random", Share.random())
"#;
    let errors = analyze_source_errors(source);
    assert!(
        errors.iter().any(|error| error
            .message
            .contains("Share.random() requires an expected secret integer type")),
        "expected untyped Share.random() error, got: {errors:?}"
    );
}

#[test]
fn test_semantic_array_operations() {
    let source = r#"
var arr = []
arr.append(1)
var arr_len = len(arr)
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_generic_function_binds_type_parameter() {
    let source = r#"
def identity[T](value: T) -> T:
  return value

var number: int64 = identity(42)
var label: string = identity("ok")
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_generic_return_type_is_substituted_in_analyzed_ast() {
    let source = r#"
def identity[T](value: T) -> T:
  return value

var number: int64 = identity(42)
var label: string = identity("ok")
"#;
    let analyzed = analyze_source_ast(source).expect("semantic analysis succeeds");
    let mut return_types = Vec::new();
    collect_call_return_types(&analyzed, "identity", &mut return_types);

    assert_eq!(return_types, vec![SymbolType::Int64, SymbolType::String]);
}

#[test]
fn test_semantic_generic_list_element_return_type_is_substituted() {
    let source = r#"
def first[T](items: list[T]) -> T:
  return items[0]

var number: int64 = first([1, 2])
var label: string = first(["a", "b"])
"#;
    let analyzed = analyze_source_ast(source).expect("semantic analysis succeeds");
    let mut return_types = Vec::new();
    collect_call_return_types(&analyzed, "first", &mut return_types);

    assert_eq!(return_types, vec![SymbolType::Int64, SymbolType::String]);
}

#[test]
fn test_semantic_generic_type_parameter_can_bind_to_list() {
    let source = r#"
def first[T](items: list[T]) -> T:
  return items[0]

var rows: list[list[int64]] = [[1, 2], [3, 4]]
var row: list[int64] = first(rows)
"#;
    let analyzed = analyze_source_ast(source).expect("semantic analysis succeeds");
    let mut return_types = Vec::new();
    collect_call_return_types(&analyzed, "first", &mut return_types);

    assert_eq!(
        return_types,
        vec![SymbolType::List(Box::new(SymbolType::Int64))]
    );
}

#[test]
fn test_semantic_nested_list_generic_substitution() {
    let source = r#"
def first_row[T](rows: list[list[T]]) -> list[T]:
  return rows[0]

var rows: list[list[int64]] = [[1, 2], [3, 4]]
var row: list[int64] = first_row(rows)
"#;
    let analyzed = analyze_source_ast(source).expect("semantic analysis succeeds");
    let mut return_types = Vec::new();
    collect_call_return_types(&analyzed, "first_row", &mut return_types);

    assert_eq!(return_types, vec![list_of(SymbolType::Int64)]);
}

#[test]
fn test_semantic_nested_list_generic_can_bind_t_to_list() {
    let source = r#"
def first_row[T](rows: list[list[T]]) -> list[T]:
  return rows[0]

var rows: list[list[list[int64]]] = [[[1, 2]], [[3, 4]]]
var row: list[list[int64]] = first_row(rows)
"#;
    let analyzed = analyze_source_ast(source).expect("semantic analysis succeeds");
    let mut return_types = Vec::new();
    collect_call_return_types(&analyzed, "first_row", &mut return_types);

    assert_eq!(return_types, vec![list_of(list_of(SymbolType::Int64))]);
}

#[test]
fn test_semantic_nested_list_generic_can_bind_t_to_nested_list() {
    let source = r#"
def first_row[T](rows: list[list[T]]) -> list[T]:
  return rows[0]

var rows: list[list[list[list[int64]]]] = [[[[1, 2]]], [[[3, 4]]]]
var row: list[list[list[int64]]] = first_row(rows)
"#;
    let analyzed = analyze_source_ast(source).expect("semantic analysis succeeds");
    let mut return_types = Vec::new();
    collect_call_return_types(&analyzed, "first_row", &mut return_types);

    assert_eq!(
        return_types,
        vec![list_of(list_of(list_of(SymbolType::Int64)))]
    );
}

#[test]
fn test_semantic_nested_list_generic_binding_is_consistent_when_t_is_list() {
    let source = r#"
def choose_nested[T](left: list[list[T]], right: list[T]) -> list[T]:
  return right

var left: list[list[list[int64]]] = [[[1]], [[2]]]
var right: list[list[int64]] = [[3], [4]]
var selected: list[list[int64]] = choose_nested(left, right)
"#;
    let analyzed = analyze_source_ast(source).expect("semantic analysis succeeds");
    let mut return_types = Vec::new();
    collect_call_return_types(&analyzed, "choose_nested", &mut return_types);

    assert_eq!(return_types, vec![list_of(list_of(SymbolType::Int64))]);
}

#[test]
fn test_semantic_return_only_generic_is_refined_from_assignment_type() {
    let source = r#"
var s1 = Share.from_clear(10)
var s2 = Share.from_clear(20)
var shares: list[Share] = [s1, s2]
var opened_ints: list[int64] = Share.batch_open_fixed(shares)
var opened_fixed: list[fix64] = Share.batch_open_fixed(shares)
"#;
    let analyzed = analyze_source_ast(source).expect("semantic analysis succeeds");
    let mut return_types = Vec::new();
    collect_call_return_types(&analyzed, "Share.batch_open_fixed", &mut return_types);

    assert_eq!(
        return_types,
        vec![
            list_of(SymbolType::Int64),
            list_of(SymbolType::Fixed { bits: 64 }),
        ]
    );
}

#[test]
fn test_fix64_type_alias_resolves_to_fixed_point_type() {
    let source = r#"
def identity(x: fix64) -> fix64:
  return x

def main(x: fix64) -> list[fix64]:
  var y: fix64 = identity(x)
  return [y]
"#;
    let analyzed = analyze_source_ast(source).expect("fix64 should resolve as a primitive type");
    let mut return_types = Vec::new();
    collect_call_return_types(&analyzed, "identity", &mut return_types);

    assert_eq!(return_types, vec![SymbolType::Fixed { bits: 64 }]);

    let program = compile(source, "test.stfl", &default_options())
        .expect("fix64 annotations should compile through bytecode generation");
    assert_eq!(
        program.main_chunk.return_type,
        FunctionType::List(Box::new(FunctionType::fix64()))
    );
}

#[test]
fn test_float64_and_fix64_have_distinct_function_metadata() {
    let source = r#"
def floating(x: float64) -> float64:
  return x

def fixed_point(x: fix64) -> fix64:
  return x
"#;

    let program = compile(source, "test.stfl", &default_options())
        .expect("float64 and fix64 functions should compile");

    let floating = program
        .function_chunks
        .get("floating")
        .expect("floating function should be emitted");
    assert_eq!(floating.parameter_types, vec![FunctionType::Float]);
    assert_eq!(floating.return_type, FunctionType::Float);

    let fixed_point = program
        .function_chunks
        .get("fixed_point")
        .expect("fixed_point function should be emitted");
    assert_eq!(fixed_point.parameter_types, vec![FunctionType::fix64()]);
    assert_eq!(fixed_point.return_type, FunctionType::fix64());
}

#[test]
fn test_secret_fix64_uses_secret_fixed_point_metadata_and_manifest() {
    let source = r#"
def main(value: secret fix64) -> None:
  value.send_to_client(0)
"#;
    let program = compile(source, "test.stfl", &default_options())
        .expect("secret fix64 should compile as SecretFixedPoint");

    assert_eq!(
        program.main_chunk.parameter_types,
        vec![FunctionType::Secret(Box::new(FunctionType::fix64()))]
    );
    assert_eq!(
        program.client_io_manifest.clients[0].outputs,
        vec![ShareType::default_secret_fixed_point()]
    );
}

#[test]
fn test_fix32_and_fix64_have_distinct_function_metadata() {
    let source = r#"
def fixed32_value(x: fix32) -> fixed32:
  return x

def fixed64_value(x: fix64) -> fixed64:
  return x
"#;

    let program = compile(source, "test.stfl", &default_options())
        .expect("fix32 and fix64 functions should compile");

    let fixed32_value = program
        .function_chunks
        .get("fixed32_value")
        .expect("fixed32 function should be emitted");
    assert_eq!(fixed32_value.parameter_types, vec![FunctionType::fix32()]);
    assert_eq!(fixed32_value.return_type, FunctionType::fix32());

    let fixed64_value = program
        .function_chunks
        .get("fixed64_value")
        .expect("fixed64 function should be emitted");
    assert_eq!(fixed64_value.parameter_types, vec![FunctionType::fix64()]);
    assert_eq!(fixed64_value.return_type, FunctionType::fix64());
}

#[test]
fn test_secret_fix32_uses_32_bit_fixed_point_manifest() {
    let source = r#"
def main(value: secret fix32) -> None:
  value.send_to_client(0)
"#;
    let program = compile(source, "test.stfl", &default_options())
        .expect("secret fix32 should compile as a 32-bit SecretFixedPoint");

    assert_eq!(
        program.main_chunk.parameter_types,
        vec![FunctionType::Secret(Box::new(FunctionType::fix32()))]
    );
    assert_eq!(
        program.client_io_manifest.clients[0].outputs,
        vec![ShareType::secret_fixed_point_from_bits(32, 16)]
    );
}

#[test]
fn test_secret_fix32_client_input_annotation_sets_manifest_precision() {
    let source = r#"
def main() -> None:
  var value: secret fix32 = ClientStore.take_share_fixed(0, 0)
  value.send_to_client(0)
"#;
    let program = compile(source, "test.stfl", &default_options())
        .expect("secret fix32 client input should compile");

    let expected = ShareType::secret_fixed_point_from_bits(32, 16);
    assert_eq!(program.client_io_manifest.clients[0].inputs, vec![expected]);
    assert_eq!(
        program.client_io_manifest.clients[0].outputs,
        vec![expected]
    );
}

#[test]
fn test_secret_float64_is_rejected_until_protocol_support_exists() {
    for ty in ["float", "float64", "f64"] {
        let source = format!(
            r#"
def main(value: secret {ty}) -> {ty}:
  return reveal(value)
"#
        );
        let errors = compile(&source, "test.stfl", &default_options())
            .expect_err("secret floating point should not compile without protocol support");
        assert!(
            errors
                .iter()
                .any(|error| error.message.contains("secret float64 is not supported")),
            "expected secret float64 support error for {ty}, got {errors:?}"
        );
    }
}

#[test]
fn test_negative_decimal_literals_compile_to_real_values() {
    let source = r#"
def main() -> float64:
  return -0.125
"#;

    let program = compile(source, "test.stfl", &default_options())
        .expect("negative decimal literals should compile");

    // Negated float literals are folded into a single negative constant
    // (no runtime 0.0 - x subtraction).
    assert!(
        program
            .main_chunk
            .constants
            .iter()
            .any(|constant| matches!(constant, Constant::Float(value) if value.0 == -0.125)),
        "negated decimal literal should fold to the f64 constant -0.125"
    );
}

#[test]
fn test_unary_minus_compiles_for_signed_integer_float_and_fixed_values() {
    let source = r#"
def negate_int(x: int64) -> int64:
  return -x

def negate_float(x: float64) -> float64:
  return -x

def negate_fixed(x: fix64) -> fix64:
  return -x

def main() -> fix64:
  var int_value: int64 = -7
  var float_value: float64 = negate_float(-0.25)
  var fixed_value: fix64 = negate_fixed(-1.5)
  return fixed_value
"#;

    let mut options = default_options();
    options.entry_points = vec!["negate_int".to_owned()];
    let program = compile(source, "test.stfl", &options)
        .expect("unary minus should compile for signed integer, float64, and fix64");

    assert_eq!(program.main_chunk.return_type, FunctionType::fix64());
    let negate_int = program
        .function_chunks
        .get("negate_int")
        .expect("negate_int should compile");
    assert_eq!(negate_int.return_type, FunctionType::int64());
    let negate_float = program
        .function_chunks
        .get("negate_float")
        .expect("negate_float should compile");
    assert_eq!(negate_float.return_type, FunctionType::Float);
    let negate_fixed = program
        .function_chunks
        .get("negate_fixed")
        .expect("negate_fixed should compile");
    assert_eq!(negate_fixed.return_type, FunctionType::fix64());
}

#[test]
fn test_fixed_point_annotation_context_refines_decimal_binary_literals() {
    let source = r#"
def take_fixed(x: fix64) -> fix64:
  return x

def main() -> fix64:
  var x: fix64 = 1-0.0001
  var y: fix64 = 2 * (1-0.0001)
  var z: fix64 = take_fixed(1-0.0001)
  print(1-0.0001)
  return x + y + z
"#;

    let program = compile(source, "test.stfl", &default_options())
        .expect("fix64 initializer context should refine decimal literal arithmetic");
    assert_eq!(program.main_chunk.return_type, FunctionType::fix64());
}

#[test]
fn test_primitive_annotation_context_refines_integer_binary_literals() {
    let cases = [
        (
            "int8",
            FunctionType::Int {
                signed: true,
                bits: 8,
            },
        ),
        (
            "int16",
            FunctionType::Int {
                signed: true,
                bits: 16,
            },
        ),
        (
            "int32",
            FunctionType::Int {
                signed: true,
                bits: 32,
            },
        ),
        (
            "int64",
            FunctionType::Int {
                signed: true,
                bits: 64,
            },
        ),
        (
            "uint8",
            FunctionType::Int {
                signed: false,
                bits: 8,
            },
        ),
        (
            "uint16",
            FunctionType::Int {
                signed: false,
                bits: 16,
            },
        ),
        (
            "uint32",
            FunctionType::Int {
                signed: false,
                bits: 32,
            },
        ),
        (
            "uint64",
            FunctionType::Int {
                signed: false,
                bits: 64,
            },
        ),
    ];

    for (ty, expected_return) in cases {
        let source = format!(
            r#"
def take(value: {ty}) -> {ty}:
  return value

def main() -> {ty}:
  var local: {ty} = 1 + 2
  var nested: {ty} = 3 * (4 + 5)
  return take(6 + 7) + local + nested
"#
        );

        let program = compile(&source, "test.stfl", &default_options())
            .unwrap_or_else(|errors| panic!("{ty} primitive context should compile: {errors:?}"));
        assert_eq!(program.main_chunk.return_type, expected_return, "{ty}");
    }
}

#[test]
fn test_primitive_annotation_context_refines_real_binary_literals() {
    let cases = [
        ("float64", FunctionType::Float),
        ("fix32", FunctionType::Fixed { bits: 32 }),
        ("fix64", FunctionType::Fixed { bits: 64 }),
    ];

    for (ty, expected_return) in cases {
        let source = format!(
            r#"
def take(value: {ty}) -> {ty}:
  return value

def main() -> {ty}:
  var local: {ty} = 1 - 0.0001
  var nested: {ty} = 2 * (1 - 0.0001)
  return take(3 - 0.0001) + local + nested
"#
        );

        let program = compile(&source, "test.stfl", &default_options())
            .unwrap_or_else(|errors| panic!("{ty} primitive context should compile: {errors:?}"));
        assert_eq!(program.main_chunk.return_type, expected_return, "{ty}");
    }
}

#[test]
fn test_primitive_annotation_context_refines_bool_and_string_expressions() {
    let source = r#"
def take_bool(value: bool) -> bool:
  return value

def take_string(value: string) -> string:
  return value

def main() -> string:
  var flag: bool = 1 and not 0
  var also_flag: bool = take_bool(1 xor 0)
  var message: string = "sto" + "ffel"
  return take_string(message + "vm")
"#;

    let program = compile(source, "test.stfl", &default_options())
        .expect("bool and string primitive expression contexts should compile");
    assert_eq!(program.main_chunk.return_type, FunctionType::String);
}

#[test]
fn test_unary_minus_rejects_unsigned_integer_values() {
    let source = r#"
def main(x: uint64) -> int64:
  return -x
"#;

    assert!(expect_error_containing(
        source,
        "Unary '-' requires a signed numeric operand"
    ));
}

#[test]
fn test_int_literal_return_refines_to_fixed_point_return_type() {
    let source = r#"
def main(x: float64) -> float64:
  if x < 0.1:
    return 0
  return x
"#;

    let program = compile(source, "test.stfl", &default_options())
        .expect("integer literals should be valid float64 return values");

    assert_eq!(program.main_chunk.return_type, FunctionType::Float);
    assert!(
        program
            .main_chunk
            .constants
            .iter()
            .any(|constant| matches!(constant, Constant::Float(value) if value.0 == 0.0)),
        "return 0 should be refined to a float constant"
    );
}

#[test]
fn test_int_literals_refine_to_fixed_point_annotation_contexts() {
    let source = r#"
def take_float(x: float64) -> float64:
  return x

def main() -> list[float64]:
  var local: float64 = 1
  var values: list[float64] = [0, local, take_float(2)]
  return values
"#;

    let program = compile(source, "test.stfl", &default_options())
        .expect("integer literals should refine in float64 annotation contexts");

    assert_eq!(
        program.main_chunk.return_type,
        FunctionType::List(Box::new(FunctionType::Float))
    );
}

#[test]
fn test_int_literals_refine_to_integer_container_annotation_contexts() {
    let source = r#"
def main() -> int32:
  var values: list[int32] = [1, 2]
  var lookup: dict[string, int32] = {"one": 1}
  return values[0] + lookup["one"]
"#;

    let program = compile(source, "test.stfl", &default_options())
        .expect("integer literals should refine in list and dict annotation contexts");

    assert_eq!(
        program.main_chunk.return_type,
        FunctionType::Int {
            signed: true,
            bits: 32
        }
    );
}

#[test]
fn test_membership_infers_candidate_type_from_container() {
    let source = r#"
def main() -> bool:
  var values: list[int32] = [1, 2]
  var needle = 1
  return needle in values
"#;

    compile(source, "test.stfl", &default_options())
        .expect("'in' should infer the candidate type from the container element type");
}

#[test]
fn test_discard_statement_participates_in_call_argument_inference() {
    let source = r#"
def take_i32(value: int32):
  return

def main():
  var value = 1
  discard take_i32(value)
"#;

    compile(source, "test.stfl", &default_options())
        .expect("discarded calls should still infer argument types");
}

#[test]
fn test_integer_container_context_does_not_narrow_typed_values() {
    let source = r#"
def main() -> int64:
  var explicit: int64 = 1
  var values: list[int32] = [explicit]
  return 0
"#;

    assert!(expect_error_containing(source, "Type mismatch"));
}

#[test]
fn test_semantic_return_only_generic_is_refined_from_index_assignment_type() {
    let source = r#"
var s1 = Share.from_clear(10)
var s2 = Share.from_clear(20)
var shares: list[Share] = [s1, s2]
var opened: list[list[fix64]]
opened[0] = Share.batch_open_fixed(shares)
"#;
    let analyzed = analyze_source_ast(source).expect("semantic analysis succeeds");
    let mut return_types = Vec::new();
    collect_call_return_types(&analyzed, "Share.batch_open_fixed", &mut return_types);

    assert_eq!(return_types, vec![list_of(SymbolType::Fixed { bits: 64 })]);
}

#[test]
fn test_semantic_return_only_generic_is_refined_from_function_return_type() {
    let source = r#"
def open_as_fixed(shares: list[Share]) -> list[fix64]:
  return Share.batch_open_fixed(shares)

var s1 = Share.from_clear(10)
var s2 = Share.from_clear(20)
var shares: list[Share] = [s1, s2]
var opened: list[fix64] = open_as_fixed(shares)
"#;
    let analyzed = analyze_source_ast(source).expect("semantic analysis succeeds");
    let mut return_types = Vec::new();
    collect_call_return_types(&analyzed, "Share.batch_open_fixed", &mut return_types);

    assert_eq!(return_types, vec![list_of(SymbolType::Fixed { bits: 64 })]);
}

#[test]
fn test_compile_batch_open_fixed_generic_alias_lowers_to_vm_batch_open() {
    let source = r#"
def main() -> int64:
  var s1 = Share.from_clear(10)
  var s2 = Share.from_clear(20)
  var shares: list[Share] = [s1, s2]
  var opened: list[int64] = Share.batch_open_fixed(shares)
  return opened[0]
"#;
    let program = compile(source, "test.stfl", &default_options())
        .expect("batch_open_fixed should compile with contextual return type");
    let call_names = collect_call_names(&program.main_chunk.instructions);

    assert!(
        call_names.iter().any(|name| name == "Share.batch_open"),
        "batch_open_fixed should lower to VM Share.batch_open, got {call_names:?}"
    );
    assert!(
        call_names
            .iter()
            .all(|name| !name.contains('[') && !name.contains("unknown")),
        "generic source types must not leak into VM call names: {call_names:?}"
    );
}

#[test]
fn test_compile_share_reveal_method_lowers_to_vm_open() {
    let source = r#"
var share = ClientStore.take_share(0, 0)
var revealed: uint64 = share.reveal()
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let call_names = collect_call_names(&program.main_chunk.instructions);
    assert!(
        call_names.iter().any(|name| name == "Share.open"),
        "Share reveal method should lower to VM Share.open, got {call_names:?}"
    );
}

#[test]
fn test_compile_secret_uint64_reveal_method_lowers_to_vm_open() {
    let source = r#"
var share: secret uint64 = ClientStore.take_share(0, 0)
var revealed: uint64 = share.reveal()
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let call_names = collect_call_names(&program.main_chunk.instructions);
    assert!(
        call_names.iter().any(|name| name == "Share.open"),
        "secret uint64 reveal method should lower to VM Share.open, got {call_names:?}"
    );
}

#[test]
fn test_compile_share_random_contextual_secret_int64_lowers_to_typed_random() {
    let source = r#"
def main() -> secret int64:
  var s: secret int64 = Share.random()
  return s
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let call_names = collect_call_names(&program.main_chunk.instructions);
    assert!(
        call_names.iter().any(|name| name == "Share.random_int"),
        "typed Share.random should lower to VM Share.random_int, got {call_names:?}"
    );
}

#[test]
fn test_compile_parenthesized_share_random_reveal_uses_int64_context() {
    let source = r#"
def main() -> int64:
  var x: int64 = (Share.random().reveal())
  return x
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let call_names = collect_call_names(&program.main_chunk.instructions);
    assert!(
        call_names.iter().any(|name| name == "Share.random_int"),
        "reveal result context should refine nested Share.random, got {call_names:?}"
    );
    assert!(
        call_names.iter().any(|name| name == "Share.open"),
        "Share.random().reveal() should lower reveal to VM Share.open, got {call_names:?}"
    );
    assert!(
        call_names.iter().all(|name| name != "Share.random"),
        "contextualized nested Share.random must not leave raw Share.random calls, got {call_names:?}"
    );
}

#[test]
fn test_compile_context_refines_nested_generic_reveal_return() {
    let source = r#"
def identity_secret(value: secret int64) -> secret int64:
  return value

def main() -> int64:
  var x: int64 = reveal(identity_secret(Share.random()))
  return x
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let call_names = collect_call_names(&program.main_chunk.instructions);
    assert!(
        call_names.iter().any(|name| name == "Share.random_int"),
        "generic reveal return context should refine nested Share.random, got {call_names:?}"
    );
    assert!(
        call_names.iter().all(|name| name != "Share.random"),
        "contextualized nested Share.random must not leave raw Share.random calls, got {call_names:?}"
    );
}

#[test]
fn test_compile_share_random_contextual_secret_bool_lowers_to_one_bit_random() {
    let source = r#"
def main() -> secret bool:
  var test: secret bool = Share.random()
  return test
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let instructions = &program.main_chunk.instructions;
    let call_names = collect_call_names(instructions);
    assert!(
        call_names.iter().any(|name| name == "Share.random_int"),
        "secret bool Share.random should lower to VM Share.random_int, got {call_names:?}"
    );
    assert!(
        call_names.iter().all(|name| name != "Share.random"),
        "typed secret bool context must not leave raw Share.random calls, got {call_names:?}"
    );
    assert!(
        instructions
            .iter()
            .any(|instruction| matches!(instruction, Instruction::LDI(_, Value::I64(1)))),
        "secret bool Share.random should request a 1-bit random int, got {instructions:?}"
    );
}

#[test]
fn test_compile_secret_bool_literal_initializer_lowers_to_typed_share() {
    let source = r#"
def main() -> secret bool:
  var acc: secret bool = 1
  return acc
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let instructions = &program.main_chunk.instructions;
    let call_names = collect_call_names(instructions);
    assert!(
        call_names.iter().any(|name| name == "Share.from_clear_int"),
        "secret bool literal initializer should lower to typed clear-to-share, got {call_names:?}"
    );
    assert!(
        instructions
            .iter()
            .any(|instruction| matches!(instruction, Instruction::LDI(_, Value::I64(1)))),
        "secret bool literal initializer should request a 1-bit share, got {instructions:?}"
    );
}

#[test]
fn test_compile_secret_bool_share_arithmetic_operators() {
    let source = r#"
def main(a: secret bool, b: secret bool) -> secret bool:
  var acc: secret bool = 1
  acc *= (1 - a)
  return acc * b
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let instructions = &program.main_chunk.instructions;
    assert!(
        instructions
            .iter()
            .any(|instruction| matches!(instruction, Instruction::SUB(_, _, _))),
        "secret bool share subtraction should lower to SUB, got {instructions:?}"
    );
    assert!(
        instructions
            .iter()
            .any(|instruction| matches!(instruction, Instruction::MUL(_, _, _))),
        "secret bool share multiplication should lower to MUL, got {instructions:?}"
    );
}

#[test]
fn test_compile_secret_uint_literal_initializer_lowers_to_typed_share() {
    let source = r#"
def main() -> secret uint8:
  var acc: secret uint8 = 1
  return acc
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let instructions = &program.main_chunk.instructions;
    let call_names = collect_call_names(instructions);
    assert!(
        call_names
            .iter()
            .any(|name| name == "Share.from_clear_uint"),
        "secret uint literal initializer should lower to typed clear-to-share, got {call_names:?}"
    );
    assert!(
        instructions
            .iter()
            .any(|instruction| matches!(instruction, Instruction::LDI(_, Value::I64(8)))),
        "secret uint8 literal initializer should request an 8-bit share, got {instructions:?}"
    );
}

#[test]
fn test_compile_share_random_contextual_secret_uint8_lowers_to_typed_random() {
    let source = r#"
def main() -> secret uint8:
  var s: secret uint8 = Share.random()
  return s
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let call_names = collect_call_names(&program.main_chunk.instructions);
    assert!(
        call_names.iter().any(|name| name == "Share.random_int"),
        "typed Share.random should lower to VM Share.random_int, got {call_names:?}"
    );
}

#[test]
fn test_compile_explicit_share_random_int_can_initialize_secret_int64() {
    let source = r#"
def main() -> secret int64:
  var s: secret int64 = Share.random_int(31)
  return s
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let call_names = collect_call_names(&program.main_chunk.instructions);
    assert!(
        call_names.iter().any(|name| name == "Share.random_int"),
        "explicit Share.random_int should lower to VM Share.random_int, got {call_names:?}"
    );
}

#[test]
fn test_compile_share_random_in_secret_int_list_index_assignment() {
    let source = r#"
def main() -> secret int64:
  var values: list[secret int64]
  values[0] = Share.random()
  return values[0]
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let call_names = collect_call_names(&program.main_chunk.instructions);
    assert!(
        call_names.iter().any(|name| name == "Share.random_int"),
        "indexed assignment context should lower Share.random to VM Share.random_int, got {call_names:?}"
    );
}

#[test]
fn test_compile_share_random_untyped_requires_secret_integer_context() {
    let source = r#"
var s = Share.random()
"#;
    assert!(expect_error_containing(
        source,
        "Share.random() requires an expected secret integer type"
    ));
}

#[test]
fn test_compile_share_random_in_secret_int_list_append_lowers_to_typed_random() {
    let source = r#"
def main() -> secret int64:
  var values: list[secret int64]
  values.append(Share.random())
  return values[0]
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let call_names = collect_call_names(&program.main_chunk.instructions);
    assert!(
        call_names.iter().any(|name| name == "Share.random_int"),
        "Share.random in list append should lower to VM Share.random_int, got {call_names:?}"
    );
    assert!(
        call_names.iter().all(|name| name != "Share.random"),
        "typed list append context must not leave raw Share.random calls, got {call_names:?}"
    );
}

#[test]
fn test_compile_context_refines_share_random_in_secret_int_function_argument() {
    let source = r#"
def id_secret(value: secret int64) -> secret int64:
  return value

def main() -> secret int64:
  return id_secret(Share.random())
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let call_names = collect_call_names(&program.main_chunk.instructions);
    assert!(
        call_names.iter().any(|name| name == "Share.random_int"),
        "secret int64 function parameter should contextualize Share.random, got {call_names:?}"
    );
    assert!(
        call_names.iter().all(|name| name != "Share.random"),
        "typed function argument context must not leave raw Share.random calls, got {call_names:?}"
    );
}

#[test]
fn test_compile_context_refines_share_random_in_secret_int_list_literal() {
    let source = r#"
def main() -> secret int64:
  var values: list[secret int64] = [Share.random()]
  return values[0]
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let call_names = collect_call_names(&program.main_chunk.instructions);
    assert!(
        call_names.iter().any(|name| name == "Share.random_int"),
        "secret int64 list literal should contextualize Share.random, got {call_names:?}"
    );
    assert!(
        call_names.iter().all(|name| name != "Share.random"),
        "typed list literal context must not leave raw Share.random calls, got {call_names:?}"
    );
}

#[test]
fn test_compile_context_refines_empty_list_literal_in_function_argument() {
    let source = r#"
def count(values: list[int64]) -> int64:
  return 0

def main() -> int64:
  return count([])
"#;
    assert!(compile(source, "test.stfl", &default_options()).is_ok());
}

#[test]
fn test_compile_share_random_share_annotation_is_rejected() {
    let source = r#"
var s: Share = Share.random()
"#;
    assert!(expect_error_containing(
        source,
        "Share.random() requires an expected secret integer type"
    ));
}

#[test]
fn test_compile_share_random_rejects_secret_float_context() {
    let source = r#"
var s: secret float = Share.random()
"#;
    assert!(expect_error_containing(
        source,
        "secret float64 is not supported"
    ));
}

#[test]
fn test_compile_additive_share_program_uses_contextual_share_random() {
    let source = r#"
object AdditiveShare:
  player: int64
  share: secret int64

def main(a: secret int64, b: secret int64) -> secret int64:
  var s: secret int64 = Share.random()
  var acc: secret int64

  var additive_shares: list[AdditiveShare]

  for i in 0..ClientStore.get_number_clients():
    var additive_share: AdditiveShare
    additive_share.player = i
    var sub_share: secret int64 = 0
    if i == ClientStore.get_number_clients()-1:
      sub_share = s - acc
    else:
      sub_share = Share.random()
      acc += sub_share
    MpcOutput.send_to_client(i, sub_share)
    additive_share.share = sub_share
    additive_shares.append(additive_share)

  for i in additive_shares:
    var sub_share: secret int64 = ClientStore.take_share(i.player, 0)
    var acc: secret int64 = 0
    if i.share.reveal() == sub_share.reveal():
      print("additive shares match")
      acc += sub_share

    print(s.reveal())
    print(acc.reveal())

  return s
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let call_names = collect_call_names(&program.main_chunk.instructions);
    assert!(
        call_names.iter().any(|name| name == "Share.random_int"),
        "additive share program should use typed random, got {call_names:?}"
    );
    assert_no_unit_moves_into_secret_register(&program.main_chunk.instructions);
}

#[test]
fn test_semantic_secret_uint64_requires_explicit_reveal() {
    let source = r#"
var share: secret uint64 = ClientStore.take_share(0, 0)
var revealed: uint64 = share
"#;
    let errors = analyze_source(source).expect_err("implicit reveal should fail");
    assert!(
        errors
            .iter()
            .any(|message| message.contains("Cannot implicitly reveal")),
        "expected implicit reveal rejection, got {errors:?}"
    );
}

#[test]
fn test_semantic_reveal_method_rejects_public_int_receiver() {
    let source = r#"
def main(b: bool, bi: int64) -> bool:
  var bit: bool = b
  var bit_as_int: int64 = bi
  var tmp: int64

  tmp = bit * bit_as_int
  print(tmp)
  print(tmp.reveal())
  return bit
"#;
    let errors = analyze_source(source).expect_err("reveal on public int should fail");
    assert!(
        errors
            .iter()
            .any(|message| message.contains("secret") || message.contains("reveal")),
        "expected reveal-on-public-int rejection, got {errors:?}"
    );
}

#[test]
fn test_semantic_reveal_function_rejects_public_int_argument() {
    let source = r#"
def main(bi: int64) -> None:
  var tmp: int64 = bi
  print(reveal(tmp))
"#;
    let errors = analyze_source(source).expect_err("reveal on public int should fail");
    assert!(
        errors
            .iter()
            .any(|message| message.contains("Expected secret value")),
        "expected reveal-on-public-int rejection, got {errors:?}"
    );
}

#[test]
fn test_compile_reveal_method_inside_list_literal() {
    let source = r#"
var share: secret uint64 = ClientStore.take_share(0, 0)
var revealed: list[uint64] = [share.reveal()]
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_semantic_nested_list_generic_rejects_inconsistent_t_list_binding() {
    let source = r#"
def choose_nested[T](left: list[list[T]], right: list[T]) -> list[T]:
  return right

var left: list[list[list[int64]]] = [[[1]], [[2]]]
var right: list[int64] = [3, 4]
var selected = choose_nested(left, right)
"#;
    let errors =
        analyze_source(source).expect_err("inconsistent nested generic binding should fail");
    assert!(
        errors.iter().any(|error| error.contains("Type mismatch")),
        "expected type mismatch error, got {errors:?}"
    );
}

#[test]
fn test_semantic_nested_list_generic_rejects_inconsistent_t_element_binding() {
    let source = r#"
def pair_rows[T](left: list[list[T]], right: list[list[T]]) -> list[T]:
  return left[0]

var left: list[list[int64]] = [[1], [2]]
var right: list[list[string]] = [["bad"]]
var selected = pair_rows(left, right)
"#;
    let errors = analyze_source(source)
        .expect_err("inconsistent nested generic element binding should fail");
    assert!(
        errors.iter().any(|error| error.contains("Type mismatch")),
        "expected type mismatch error, got {errors:?}"
    );
}

#[test]
fn test_semantic_nested_list_append_accepts_matching_nested_element() {
    let source = r#"
var rows: list[list[int64]] = []
rows.append([1, 2])

var cubes: list[list[list[int64]]] = []
cubes.append([[1], [2]])
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_nested_list_append_rejects_wrong_nested_element_shape() {
    let source = r#"
var rows: list[list[int64]] = []
rows.append(1)
"#;
    assert!(expect_error_containing(source, "Type mismatch"));
}

#[test]
fn test_semantic_nested_list_append_rejects_wrong_nested_element_type() {
    let source = r#"
var rows: list[list[int64]] = []
rows.append(["bad"])
"#;
    assert!(expect_error_containing(source, "Type mismatch"));
}

#[test]
fn test_semantic_builtin_default_parameter_supports_optional_pop_index() {
    let source = r#"
var items: list[int64] = [1, 2, 3]
var last: int64 = items.pop()
var first: int64 = items.pop(0)
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_builtin_default_parameter_rejects_too_many_pop_args() {
    let source = r#"
var items: list[int64] = [1, 2, 3]
var bad: int64 = items.pop(0, 1)
"#;
    assert!(expect_error_containing(
        source,
        "Function 'pop' expects 1 to 2 argument(s)"
    ));
}

#[test]
fn test_semantic_builtin_variadic_parameter_supports_print_args() {
    let source = r#"
print()
print(1, "two", 3)
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_user_function_default_parameters_are_supported() {
    let source = r#"
def f(x: int64, bonus: int64 = 5) -> int64:
  return x + bonus

def main() -> int64:
  return f(10) + f(10, 1)
"#;
    compile(source, "test.stfl", &default_options())
        .expect("literal default parameters should compile for user functions");
}

#[test]
fn test_semantic_user_function_named_arguments_are_supported() {
    let source = r#"
def sub(a: int64, b: int64) -> int64:
  return a - b

def main() -> int64:
  return sub(b: 3, a: 10)
"#;
    compile(source, "test.stfl", &default_options())
        .expect("named arguments should compile for user functions");
}

#[test]
fn test_semantic_user_function_unknown_named_argument_is_rejected() {
    let source = r#"
def sub(a: int64, b: int64) -> int64:
  return a - b

def main() -> int64:
  return sub(a: 10, c: 3)
"#;
    assert!(expect_error_containing(
        source,
        "has no parameter named 'c'"
    ));
}

#[test]
fn test_semantic_user_function_non_literal_default_is_rejected() {
    let source = r#"
var base: int64 = 10

def f(x: int64 = base) -> int64:
  return x
"#;
    assert!(expect_error_containing(source, "must be a literal"));
}

#[test]
fn test_semantic_user_function_variadic_is_supported() {
    let source = r#"
def total(*xs) -> int64:
  var sum = 0
  for x in xs:
    sum += x
  return sum

def main() -> int64:
  return total(1, 2, 3) + total()
"#;
    compile(source, "test.stfl", &default_options())
        .expect("user-function *args should compile, packing extras into a list");
}

#[test]
fn test_semantic_variadic_must_be_last_parameter() {
    let source = r#"
def f(*xs, y: int64) -> int64:
  return y
"#;
    assert!(expect_error_containing(
        source,
        "must be the last parameter"
    ));
}

#[test]
fn test_semantic_variable_index_access_for_lists_and_strings() {
    let source = r#"
def at[T](items: list[T], index: int64) -> T:
  return items[index]

var index: int64 = 1
var items: list[int64] = [10, 20, 30]
var item: int64 = at(items, index)

var rows: list[list[int64]] = [[1, 2], [3, 4]]
var row: list[int64] = at(rows, index)

var text: string = "abc"
var letter: string = text[index]
"#;
    let analyzed = analyze_source_ast(source).expect("semantic analysis succeeds");
    let mut return_types = Vec::new();
    collect_call_return_types(&analyzed, "at", &mut return_types);

    assert_eq!(
        return_types,
        vec![SymbolType::Int64, list_of(SymbolType::Int64)]
    );
}

#[test]
fn test_compile_variable_index_access_lowers_to_get_field() {
    let source = r#"
def at[T](items: list[T], index: int64) -> T:
  return items[index]

def main() -> int64:
  var index: int64 = 1
  var items: list[int64] = [10, 20, 30]
  var nested: list[list[int64]] = [[1, 2], [3, 4]]
  var row: list[int64] = nested[index]
  return at(items, index) + row[index]
"#;
    let program = compile(source, "test.stfl", &default_options())
        .expect("variable index access should compile");

    let at_chunk = program
        .function_chunks
        .get("at")
        .expect("generic index helper should be emitted");
    let at_calls = collect_call_names(&at_chunk.instructions);
    assert!(
        at_calls.iter().any(|name| name == "get_field"),
        "items[index] should lower to VM get_field, got {at_calls:?}"
    );

    let entry_calls = collect_call_names(&program.main_chunk.instructions);
    assert!(
        entry_calls.iter().any(|name| name == "get_field"),
        "nested[index] should lower to VM get_field, got {entry_calls:?}"
    );
    assert!(
        entry_calls.iter().any(|name| name == "at"),
        "entry bytecode should call generic at helper, got {entry_calls:?}"
    );
}

#[test]
fn test_compile_local_nested_generics_example_bytecode_shape() {
    let source = include_str!("../../examples/local_nested_generics/main.stfl");
    let program = compile(
        source,
        "examples/local_nested_generics/main.stfl",
        &default_options(),
    )
    .expect("local nested generics example should compile");

    assert!(
        program.function_chunks.contains_key("first_row"),
        "generic helper should be emitted as a VM function"
    );
    assert!(
        program.function_chunks.contains_key("first_cell"),
        "generic helper should be emitted as a VM function"
    );
    assert!(
        program.function_chunks.contains_key("choose_nested"),
        "generic helper should be emitted as a VM function"
    );
    assert!(
        program.function_chunks.contains_key("at"),
        "generic index helper should be emitted as a VM function"
    );

    let call_names = collect_call_names(&program.main_chunk.instructions);

    assert!(
        call_names.iter().any(|name| name == "first_row"),
        "entry bytecode should call first_row, got {call_names:?}"
    );
    assert!(
        call_names.iter().any(|name| name == "first_cell"),
        "entry bytecode should call first_cell, got {call_names:?}"
    );
    assert!(
        call_names.iter().any(|name| name == "choose_nested"),
        "entry bytecode should call choose_nested, got {call_names:?}"
    );
    assert!(
        call_names.iter().any(|name| name == "at"),
        "entry bytecode should call generic at helper, got {call_names:?}"
    );
    assert!(
        call_names.iter().any(|name| name == "append"),
        "list method syntax should lower to VM append, got {call_names:?}"
    );
    assert!(
        call_names.iter().any(|name| name == "len"),
        "list len method syntax should lower to VM len, got {call_names:?}"
    );
    assert!(
        call_names
            .iter()
            .all(|name| !name.contains('[') && !name.contains("unknown")),
        "generic source types must not leak into VM call names: {call_names:?}"
    );
}

#[test]
fn test_compile_matrix_average_fixed_point_uses_nested_generic_bytecode() {
    let source = include_str!("../stfl/matrix_average_fixed_point.stfl");
    let program = compile(
        source,
        "tests/stfl/matrix_average_fixed_point.stfl",
        &default_options(),
    )
    .expect("matrix average fixed-point fixture should compile");

    for helper in [
        "matrix_get",
        "matrix_row",
        "append_matrix_row",
        "reshape_2x3",
    ] {
        assert!(
            program.function_chunks.contains_key(helper),
            "expected helper function '{helper}' to be emitted"
        );
    }

    let average_chunk = program
        .function_chunks
        .get("federated_average_2x3")
        .expect("average helper should be emitted");
    let average_calls = collect_call_names(&average_chunk.instructions);

    assert!(
        !average_calls
            .iter()
            .any(|name| name == "load_client_matrix_2x3"),
        "average bytecode should not rebuild full client matrices per element, got {average_calls:?}"
    );
    assert!(
        average_calls
            .iter()
            .any(|name| name == "ClientStore.sum_shares_fixed"),
        "average bytecode should use the semantic fixed-point client reduction, got {average_calls:?}"
    );
    assert!(
        average_calls.iter().any(|name| name == "Share.batch_open"),
        "average bytecode should batch-open all flat sums before clear division, got {average_calls:?}"
    );
    assert!(
        average_calls.iter().any(|name| name == "reshape_2x3"),
        "average bytecode should reshape flat averages into a matrix, got {average_calls:?}"
    );
    assert!(
        average_calls.iter().any(|name| name == "append"),
        "row construction should lower .append() to VM append, got {average_calls:?}"
    );
    assert!(
        average_calls
            .iter()
            .all(|name| !name.contains('[') && !name.contains("unknown")),
        "generic source types must not leak into VM call names: {average_calls:?}"
    );

    let main_calls = collect_call_names(&program.main_chunk.instructions);
    assert!(
        main_calls.iter().any(|name| name == "matrix_get"),
        "main bytecode should call matrix_get with T = float, got {main_calls:?}"
    );
    assert!(
        main_calls.iter().any(|name| name == "matrix_row"),
        "main bytecode should call matrix_row with T = float, got {main_calls:?}"
    );
}

#[test]
fn test_semantic_generic_binding_is_consistent_across_parameters() {
    let source = r#"
def choose[T](left: T, right: T) -> T:
  return left

var value = choose(1, "bad")
"#;
    let errors = analyze_source(source).expect_err("mixed generic binding should fail");
    assert!(
        errors.iter().any(|error| error.contains("Type mismatch")),
        "expected type mismatch error, got {errors:?}"
    );
}

#[test]
fn test_semantic_generic_append_rejects_wrong_element_type() {
    let source = r#"
var items: list[int64] = []
items.append("bad")
"#;
    assert!(expect_error_containing(source, "Type mismatch"));
}

#[test]
fn test_semantic_unknown_is_not_a_source_type() {
    let source = r#"
var value: unknown = 1
"#;
    assert!(expect_error_containing(source, "Undefined type 'unknown'"));
}

#[test]
fn test_semantic_nested_function_calls() {
    let source = r#"
def inner(x: int64) -> int64:
  return x + 1

def outer(x: int64) -> int64:
  return inner(x) * 2

var result = outer(5)
"#;
    assert!(analyze_source(source).is_ok());
}

// ===========================================
// Semantic Analysis Tests - Object Methods
// ===========================================

#[test]
fn test_semantic_client_store_take_share() {
    let source = r#"
var share = ClientStore.take_share(0, 0)
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_mpc_methods() {
    let source = r#"
var party = Mpc.party_id()
var total = Mpc.n_parties()
var thresh = Mpc.threshold()
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_share_operations() {
    let source = r#"
var s1 = Share.from_clear(10)
var s2 = Share.from_clear(20)
var sum = Share.add(s1, s2)
"#;
    assert!(analyze_source(source).is_ok());
}

// ===========================================
// Semantic Analysis Tests - Error Detection
// ===========================================

#[test]
fn test_semantic_error_undefined_variable() {
    let source = "var x = undefined_var + 1";
    assert!(expect_error_containing(source, "undefined_var"));
}

#[test]
fn test_semantic_error_undefined_function() {
    let source = "var x = undefined_function(42)";
    assert!(expect_error_containing(source, "undefined_function"));
}

#[test]
fn test_semantic_error_duplicate_variable() {
    let source = r#"
var x = 10
var x = 20
"#;
    let result = analyze_source(source);
    assert!(result.is_err(), "Should detect duplicate variable");
}

#[test]
fn test_semantic_error_wrong_argument_count() {
    let source = r#"
def foo(a: int64, b: int64) -> int64:
  return a + b

var x = foo(1)
"#;
    assert!(expect_error_containing(source, "argument"));
}

#[test]
fn test_semantic_error_literal_condition_has_source_location() {
    let source = "def main():\n  if 123:\n    var value = 1\n";
    let errors = analyze_source_errors(source);
    let error = errors
        .iter()
        .find(|error| error.message.contains("If-condition"))
        .expect("expected if-condition error");

    assert_eq!(error.location.file, "test.stfl");
    assert_eq!(error.location.line, 2);
    assert_eq!(error.location.column, 6);
}

#[test]
fn test_semantic_error_empty_list_condition_has_source_location() {
    let source = "def main():\n  if []:\n    var value = 1\n";
    let errors = analyze_source_errors(source);
    let error = errors
        .iter()
        .find(|error| error.message.contains("If-condition"))
        .expect("expected if-condition error");

    assert_eq!(error.location.file, "test.stfl");
    assert_eq!(error.location.line, 2);
    assert_eq!(error.location.column, 6);
}

#[test]
fn test_compile_recovers_from_capitalized_list_and_reports_later_errors() {
    let source = r#"
def main():
  var xs: List[int64] = []
  var a: int64 = "nope"
  if []:
    var value = 1
"#;
    let errors = compile_source_errors(source);
    let messages = errors
        .iter()
        .map(|error| error.message.as_str())
        .collect::<Vec<_>>();

    assert!(
        messages
            .iter()
            .any(|message| message.contains("Unknown generic type: List")),
        "expected recoverable parse error, got {messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|message| message.contains("Expected 'int64', found 'string'")),
        "expected later type mismatch, got {messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|message| message.contains("If-condition must be of type 'bool'")),
        "expected later if-condition error, got {messages:?}"
    );
}

#[test]
fn test_compile_recovers_at_statement_boundary_after_missing_expression() {
    let source = r#"
def main():
  var broken =
  var a: int64 = "nope"
  if 123:
    var value = 1
  var ok = 1
  unknown_call(ok)
"#;
    let errors = compile_source_errors(source);
    let messages = errors
        .iter()
        .map(|error| error.message.as_str())
        .collect::<Vec<_>>();

    assert!(
        messages
            .iter()
            .any(|message| message.contains("Expected expression, found Newline")),
        "expected missing expression parse error, got {messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|message| message.contains("Expected 'int64', found 'string'")),
        "expected next statement type mismatch, got {messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|message| message.contains("If-condition must be of type 'bool'")),
        "expected later if-condition error, got {messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|message| message.contains("unknown_call")),
        "expected later unknown function error, got {messages:?}"
    );
}

// ===========================================
// Semantic Analysis Tests - Type Checking
// ===========================================

#[test]
fn test_compile_bool_accepts_zero_and_one_literals() {
    let source = r#"
def takes_bool(value: bool) -> bool:
  return value

def main() -> bool:
  var false_bit: bool = 0
  var true_bit: bool = 1
  var passed_bit: bool = takes_bool(1)
  return passed_bit
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_bool_integer_literal_lowers_to_bool_constant() {
    let source = r#"
def main() -> bool:
  var bit: bool = 1
  return bit
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");

    assert!(
        program
            .main_chunk
            .instructions
            .iter()
            .any(|instruction| matches!(instruction, Instruction::LDI(_, Value::Bool(true)))),
        "expected integer bool initializer to lower to Bool(true), got {:?}",
        program.main_chunk.instructions
    );
}

#[test]
fn test_compile_bool_rejects_integer_literal_outside_bit_range() {
    let source = r#"
def main() -> bool:
  var bit: bool = 2
  return bit
"#;
    let errors = compile_source_errors(source);
    let messages = errors
        .iter()
        .map(|error| error.message.as_str())
        .collect::<Vec<_>>();

    assert!(
        messages.iter().any(|message| message
            .contains("Integer literal 2 cannot initialize 'bool' (allowed values are 0 or 1)")),
        "expected bool literal range error, got {messages:?}"
    );
}

#[test]
fn test_semantic_secret_assignment_valid() {
    let source = r#"
var share: Share = ClientStore.take_share(0, 0)
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_share_can_assign_to_secret_int() {
    let source = r#"
var share: secret int64 = ClientStore.take_share(0, 0)
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_share_can_flow_to_secret_int_parameter() {
    let source = r#"
def process(value: secret int64) -> secret int64:
  return value

var share = ClientStore.take_share(0, 0)
var processed = process(share)
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_share_can_initialize_secret_int_list() {
    let source = r#"
var first = ClientStore.take_share(0, 0)
var second = ClientStore.take_share(0, 1)
var shares: list[secret int64] = [first, second]
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_secret_in_function() {
    let source = r#"
def process(s: secret int64) -> secret int64:
  return s * 2
"#;
    assert!(analyze_source(source).is_ok());
}

// ===========================================
// Semantic Phase Tests - List Iteration
// ===========================================

#[test]
fn test_semantic_for_loop_list_iteration() {
    let source = r#"
var items: list[int64] = [1, 2, 3]
var sum = 0
for item in items:
  sum = sum + item
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_for_loop_list_literal() {
    let source = r#"
var total = 0
for x in [10, 20, 30]:
  total = total + x
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_for_loop_element_type_inferred() {
    // The loop variable should have the same type as list elements
    let source = r#"
var numbers: list[int64] = [1, 2, 3]
var total = 0
for n in numbers:
  total = total + n
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_for_loop_range_still_works() {
    // Ensure range-based iteration still works
    let source = r#"
var sum = 0
for i in 0..10:
  sum = sum + i
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_error_iterate_non_iterable() {
    // Cannot iterate over a non-iterable type
    let source = r#"
var x = 42
for item in x:
  print(item)
"#;
    assert!(analyze_source(source).is_err());
}

// ===========================================
// Semantic Phase Tests - String Iteration
// ===========================================

#[test]
fn test_semantic_for_loop_string_iteration() {
    // Iterate over characters in a string
    let source = r#"
var text = "hello"
for ch in text:
  print(ch)
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_for_loop_string_literal() {
    // Iterate directly over a string literal
    let source = r#"
for ch in "world":
  print(ch)
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_for_loop_string_element_is_string() {
    // The loop variable should be a string (character)
    // so we can concatenate it with another string
    let source = r#"
var text = "abc"
var result = ""
for ch in text:
  result = result + ch
"#;
    assert!(analyze_source(source).is_ok());
}

// ===========================================
// Full Compilation Tests - Valid Programs
// ===========================================

#[test]
fn test_compile_hello_world() {
    let source = r#"
print("Hello, World!")
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_arithmetic() {
    let source = r#"
var a = 10
var b = 20
var sum = a + b
var diff = a - b
var prod = a * b
var quot = b / a
print(sum)
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_function_definition_and_call() {
    let source = r#"
def double(n: int64) -> int64:
  return n * 2

var result = double(5)
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_conditionals() {
    let source = r#"
var x = 10
if x > 5:
  print("big")
else:
  print("small")
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_loops() {
    let source = r#"
var i = 0
while i < 10:
  i = i + 1
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_arrays() {
    let source = r#"
var arr = []
arr.append(10)
arr.append(20)
var first = arr[0]
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_for_loop_list_iteration() {
    let source = r#"
var items: list[int64] = [1, 2, 3, 4, 5]
var total = 0
for item in items:
  total = total + item
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_for_loop_list_literal() {
    let source = r#"
var sum = 0
for x in [10, 20, 30]:
  sum = sum + x
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_for_loop_range() {
    let source = r#"
var sum = 0
for i in 0..5:
  sum = sum + i
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_for_loop_nested_with_list() {
    let source = r#"
var matrix: list[int64] = [1, 2, 3]
var total = 0
for i in 0..3:
  for val in matrix:
    total = total + val
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_for_loop_string_iteration() {
    let source = r#"
var text = "hello"
for ch in text:
  print(ch)
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_for_loop_string_literal() {
    let source = r#"
for ch in "world":
  print(ch)
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_for_loop_string_concatenation() {
    let source = r#"
var text = "abc"
var result = ""
for ch in text:
  result = result + ch
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_type_builtin_and_boolean_ops() {
    let source = r#"
var name = type("invoice")
var accepted = (name == "string") and not False
if accepted or False:
  print(name)
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_clear_collection_loops_stay_in_clear_registers() {
    let source = r#"
var total = 0
for value in [3, 4, 5]:
  total += value
for ch in "risk":
  discard ch
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let max_register = program
        .main_chunk
        .instructions
        .iter()
        .flat_map(instruction_registers)
        .max()
        .unwrap_or(0);

    assert!(
        max_register < DEFAULT_SECRET_REGISTER_START,
        "clear collection loops should not allocate secret registers; max register was {max_register}"
    );
}

#[test]
fn test_binary_preserves_function_parameter_names_and_upvalues() {
    let source = r#"
def increment_counter(amount: int64) -> int64:
  var saved_amount = amount
  var current = get_upvalue("start")
  var updated = current + saved_amount
  discard set_upvalue("start", updated)
  return updated

def create_counter(start: int64) -> Closure:
  return create_closure_with_upvalue("increment_counter", "start")

def main() -> int64:
  var counter = create_counter(10)
  return call_closure_with_arg(counter, 5)
"#;
    let mut options = default_options();
    options.entry_points = vec!["increment_counter".to_owned()];
    let program = compile(source, "test.stfl", &options).expect("program compiles");
    let binary = convert_to_binary(&program);

    let create_counter = binary
        .functions
        .iter()
        .find(|function| function.name == "create_counter")
        .expect("create_counter function exists");
    assert_eq!(create_counter.parameters, vec!["start".to_string()]);

    let increment_counter = binary
        .functions
        .iter()
        .find(|function| function.name == "increment_counter")
        .expect("increment_counter function exists");
    assert_eq!(increment_counter.parameters, vec!["amount".to_string()]);
    assert_eq!(increment_counter.upvalues, vec!["start".to_string()]);
}

#[test]
fn test_def_main_with_return_type_is_entry_chunk() {
    let source = r#"
def main() -> int64:
  return 42
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");

    assert!(
        !program
            .main_chunk
            .instructions
            .iter()
            .any(|instruction| matches!(instruction, Instruction::CALL(name) if name == "main")),
        "def main should be promoted to the entry chunk, not called through a wrapper"
    );
    assert!(
        !program.function_chunks.contains_key("main"),
        "entry def main should not also be emitted as a normal function"
    );
}

#[test]
fn test_def_main_prunes_unreachable_function_chunks() {
    let source = r#"
def live() -> int64:
  return 7

def dead() -> int64:
  return 9

def main() -> int64:
  return live()
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");

    assert!(
        program.function_chunks.contains_key("live"),
        "reachable callees should remain callable"
    );
    assert!(
        !program.function_chunks.contains_key("dead"),
        "unreachable sibling functions should be pruned from executable output"
    );
}

#[test]
fn test_dce_preserves_explicit_extra_entrypoint() {
    let source = r#"
def encrypt() -> int64:
  return 1

def decrypt() -> int64:
  return 2

def dead() -> int64:
  return 3

def main() -> int64:
  return encrypt()
"#;
    let mut options = default_options();
    options.entry_points = vec!["decrypt".to_owned()];
    let program = compile(source, "test.stfl", &options).expect("program compiles");

    assert!(program.function_chunks.contains_key("encrypt"));
    assert!(program.function_chunks.contains_key("decrypt"));
    assert!(!program.function_chunks.contains_key("dead"));
}

#[test]
fn test_dce_preserves_literal_closure_targets() {
    let source = r#"
def callback() -> int64:
  return 7

def dead() -> int64:
  return 9

def main() -> int64:
  var closure = create_closure("callback")
  return call_closure(closure)
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");

    assert!(
        program.function_chunks.contains_key("callback"),
        "string-literal closure targets are executable call-graph roots"
    );
    assert!(!program.function_chunks.contains_key("dead"));
}

#[test]
fn test_no_entry_library_style_compile_keeps_function_chunks() {
    let source = r#"
def first() -> int64:
  return 1

def second() -> int64:
  return 2
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");

    assert!(
        program.main_chunk.instructions.is_empty(),
        "source has no executable entry chunk"
    );
    assert!(program.function_chunks.contains_key("first"));
    assert!(program.function_chunks.contains_key("second"));
}

#[test]
fn test_main_keyword_entry_form_is_rejected() {
    let source = r#"
main main() -> int64:
  return 42
"#;

    assert!(expect_error_containing(
        source,
        "The 'main <name>(...)' entry form is no longer supported"
    ));
}

// ===========================================
// Full Compilation Tests - Builtin Objects
// ===========================================

#[test]
fn test_compile_client_store() {
    let source = r#"
var share = ClientStore.take_share(0, 0)
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_client_io_manifest_in_stflb_binary() {
    let source = r#"
def main() -> int64:
  var left = ClientStore.take_share(0, 0)
  var right = ClientStore.take_share_fixed(0, 1)
  MpcOutput.send_to_client(0, [left, right])
  return 0
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let binary = convert_to_binary(&program);

    assert_eq!(binary.client_io_manifest.clients.len(), 1);
    let schema = &binary.client_io_manifest.clients[0];
    assert_eq!(schema.client_slot, 0);
    assert_eq!(
        schema.inputs,
        vec![
            ShareType::default_secret_int(),
            ShareType::default_secret_fixed_point()
        ]
    );
    assert_eq!(
        schema.outputs,
        vec![
            ShareType::default_secret_int(),
            ShareType::default_secret_fixed_point()
        ]
    );
}

#[test]
fn test_compile_client_io_manifest_tracks_output_list_variables() {
    let source = r#"
def main() -> int64:
  var left = ClientStore.take_share(0, 0)
  var right = ClientStore.take_share_fixed(0, 1)
  var outputs = [left, right]
  MpcOutput.send_to_client(0, outputs)
  return 0
"#;
    let program = compile(source, "test.stfl", &default_options()).expect("program compiles");
    let binary = convert_to_binary(&program);
    let schema = &binary.client_io_manifest.clients[0];

    assert_eq!(
        schema.outputs,
        vec![
            ShareType::default_secret_int(),
            ShareType::default_secret_fixed_point()
        ]
    );
}

#[test]
fn test_compile_client_io_manifest_tracks_multiple_literal_clients() {
    let source = r#"
def main() -> int64:
  var client0_score = ClientStore.take_share(0, 0)
  var client1_weight = ClientStore.take_share_fixed(1, 0)
  MpcOutput.send_to_client(0, [client0_score])
  MpcOutput.send_to_client(1, [client1_weight])
  return 0
"#;
    assert_client_io_manifest(
        source,
        &[
            (
                0,
                vec![ShareType::default_secret_int()],
                vec![ShareType::default_secret_int()],
            ),
            (
                1,
                vec![ShareType::default_secret_fixed_point()],
                vec![ShareType::default_secret_fixed_point()],
            ),
        ],
    );
}

#[test]
fn test_compile_client_io_manifest_tracks_sparse_input_ordinals() {
    let source = r#"
def main() -> int64:
  var first = ClientStore.take_share(2, 0)
  var third = ClientStore.take_share_fixed(2, 2)
  MpcOutput.send_to_client(2, [first, third])
  return 0
"#;
    assert_client_io_manifest(
        source,
        &[(
            2,
            vec![
                ShareType::default_secret_int(),
                ShareType::default_secret_int(),
                ShareType::default_secret_fixed_point(),
            ],
            vec![
                ShareType::default_secret_int(),
                ShareType::default_secret_fixed_point(),
            ],
        )],
    );
}

#[test]
fn test_compile_client_io_manifest_tracks_appended_output_lists() {
    let source = r#"
def main() -> int64:
  var fixed_value = ClientStore.take_share_fixed(0, 0)
  var int_value = ClientStore.take_share(0, 1)
  var outputs: list[Share] = []
  outputs.append(fixed_value)
  outputs.append(int_value)
  MpcOutput.send_to_client(0, outputs)
  return 0
"#;
    assert_client_io_manifest(
        source,
        &[(
            0,
            vec![
                ShareType::default_secret_fixed_point(),
                ShareType::default_secret_int(),
            ],
            vec![
                ShareType::default_secret_fixed_point(),
                ShareType::default_secret_int(),
            ],
        )],
    );
}

#[test]
fn test_compile_client_io_manifest_preserves_nested_boolean_element_outputs() {
    let source = r#"
def send_block(block: list[list[secret bool]]) -> int64:
  var outputs: list[secret bool] = []
  for byte_index in 0..2:
    for bit_index in 0..8:
      outputs.append(block[byte_index][bit_index])
  MpcOutput.send_to_client(0, outputs)
  return 16

def main(block: list[list[secret bool]]) -> int64:
  return send_block(block)
"#;

    assert_client_io_manifest(source, &[(0, vec![], vec![ShareType::boolean(); 16])]);
}

#[test]
fn test_compile_client_io_manifest_tracks_generic_helper_share_output() {
    let source = r#"
def normalize(value: Share) -> Share:
  return value.add_constant(1)

def main() -> int64:
  var input = ClientStore.take_share(0, 0)
  var output = normalize(input)
  var outputs: list[Share] = []
  outputs.append(output)
  MpcOutput.send_to_client(0, outputs)
  return 0
"#;
    assert_client_io_manifest(
        source,
        &[(
            0,
            vec![ShareType::default_secret_int()],
            vec![ShareType::default_secret_int()],
        )],
    );
}

#[test]
fn test_compile_client_io_manifest_tracks_direct_share_send_to_client() {
    let source = r#"
def main() -> int64:
  var fixed_value = ClientStore.take_share_fixed(0, 0)
  var int_value = ClientStore.take_share(1, 0)
  fixed_value.send_to_client(0)
  int_value.send_to_client(1)
  return 0
"#;
    assert_client_io_manifest(
        source,
        &[
            (
                0,
                vec![ShareType::default_secret_fixed_point()],
                vec![ShareType::default_secret_fixed_point()],
            ),
            (
                1,
                vec![ShareType::default_secret_int()],
                vec![ShareType::default_secret_int()],
            ),
        ],
    );
}

#[test]
fn test_compile_client_io_manifest_tracks_static_loop_literal_bound_inputs_and_outputs() {
    let source = r#"
def main() -> int64:
  var outputs: list[Share] = []
  var element_index: int64 = 0
  while element_index < 3:
    var value = ClientStore.take_share_fixed(0, element_index)
    outputs.append(value)
    element_index = element_index + 1
  MpcOutput.send_to_client(0, outputs)
  return 0
"#;
    assert_client_io_manifest(
        source,
        &[(
            0,
            vec![ShareType::default_secret_fixed_point(); 3],
            vec![ShareType::default_secret_fixed_point(); 3],
        )],
    );
}

#[test]
fn test_compile_mpc_output_send_to_client_accepts_single_secret_share() {
    let source = r#"
def main() -> int64:
  var share: secret int64 = ClientStore.take_share(0, 0)
  MpcOutput.send_to_client(0, share)
  return 0
"#;
    assert_client_io_manifest(
        source,
        &[(
            0,
            vec![ShareType::default_secret_int()],
            vec![ShareType::default_secret_int()],
        )],
    );
}

#[test]
fn test_compile_client_io_manifest_tracks_static_loop_fixed_client_io() {
    let source = include_str!("../../examples/mpc_client_federated_average/main.stfl");
    let program = compile(
        source,
        "mpc_client_federated_average.stfl",
        &default_options(),
    )
    .expect("program compiles");
    let binary = convert_to_binary(&program);

    assert_eq!(binary.client_io_manifest.clients.len(), 2);
    let schema = &binary.client_io_manifest.clients[0];
    assert_eq!(schema.client_slot, 0);
    assert_eq!(
        schema.inputs,
        vec![ShareType::default_secret_fixed_point(); 6]
    );
    assert_eq!(
        schema.outputs,
        vec![ShareType::default_secret_fixed_point(); 6]
    );
    let schema = &binary.client_io_manifest.clients[1];
    assert_eq!(schema.client_slot, 1);
    assert_eq!(
        schema.inputs,
        vec![ShareType::default_secret_fixed_point(); 6]
    );
    assert!(schema.outputs.is_empty());
}

#[test]
fn test_compile_records_mpc_backend_in_stflb_binary() {
    let source = r#"
def main() -> int64:
  return 0
"#;
    let mut options = default_options();
    options.mpc_backend = MpcBackend::Avss;

    let program = compile(source, "test.stfl", &options).expect("program compiles");
    let binary = convert_to_binary(&program);

    assert_eq!(binary.client_io_manifest.mpc_backend, MpcBackend::Avss);
}

#[test]
fn test_compile_mpc_operations() {
    let source = r#"
var my_id = Mpc.party_id()
var parties = Mpc.n_parties()
if my_id == 0:
  print("I am the leader")
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_share_creation() {
    let source = r#"
var s = Share.from_clear(42)
"#;
    assert!(compile_source(source).is_ok());
}

// ===========================================
// Full Compilation Tests - Complex Programs
// ===========================================

#[test]
fn test_compile_nested_conditionals() {
    let source = r#"
var x = 10
var y = 20
if x > 5:
  if y > 15:
    print("both big")
  else:
    print("x big, y small")
else:
  print("x small")
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_multiple_functions() {
    let source = r#"
def add(a: int64, b: int64) -> int64:
  return a + b

def multiply(a: int64, b: int64) -> int64:
  return a * b

var sum = add(3, 4)
var prod = multiply(sum, 2)
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_recursive_function() {
    let source = r#"
def fib(n: int64) -> int64:
  if n <= 1:
    return n
  return fib(n - 1) + fib(n - 2)

var result = fib(10)
"#;
    assert!(compile_source(source).is_ok());
}

// ===========================================
// Syntax Error Tests
// ===========================================

#[test]
fn test_syntax_error_unclosed_paren() {
    let source = "var x = (1 + 2";
    assert!(compile_source(source).is_err());
}

#[test]
fn test_syntax_error_missing_expression() {
    let source = "var x =";
    assert!(compile_source(source).is_err());
}

#[test]
fn test_syntax_error_invalid_field_access() {
    let source = "var x = obj.";
    assert!(compile_source(source).is_err());
}

// ===========================================
// Edge Cases
// ===========================================

#[test]
fn test_empty_program() {
    let source = "";
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_only_comments() {
    let source = r#"
# This is a comment
# Another comment
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_deeply_nested_expressions() {
    let source = "var x = ((((1 + 2) * 3) - 4) / 5)";
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_long_identifier() {
    let source = "var this_is_a_very_long_variable_name_that_should_still_work = 42";
    assert!(compile_source(source).is_ok());
}

// ===========================================
// UFCS Transformation Tests
// ===========================================

#[test]
fn test_ufcs_builtin_object_preserved() {
    let source = "var s = ClientStore.take_share(0, 0)";
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_ufcs_share_methods() {
    let source = r#"
var s1 = Share.from_clear(10)
var s2 = Share.from_clear(20)
var result = Share.add(s1, s2)
"#;
    assert!(compile_source(source).is_ok());
}

// ===========================================
// Import Syntax Tests (Parser Only)
// ===========================================

#[test]
fn test_import_syntax() {
    let source = "import foo.bar";
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_import_with_alias() {
    let source = "import foo.bar as baz";
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_multiple_imports() {
    let source = r#"
import module1
import module2.submodule
import module3 as m3
"#;
    assert!(parse_source(source).is_ok());
}

// ===========================================
// Compound Assignment Operator Tests - Lexer
// ===========================================

#[test]
fn test_lexer_compound_plus_equals() {
    let source = "var x = 10\nx += 5";
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_lexer_compound_minus_equals() {
    let source = "var x = 10\nx -= 5";
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_lexer_compound_times_equals() {
    let source = "var x = 10\nx *= 5";
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_lexer_compound_divide_equals() {
    let source = "var x = 10\nx /= 5";
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_lexer_compound_modulo_equals() {
    let source = "var x = 10\nx %= 3";
    assert!(parse_source(source).is_ok());
}

// ===========================================
// Compound Assignment Operator Tests - Parser
// ===========================================

#[test]
fn test_parser_compound_assignment_simple_variable() {
    let source = r#"
var x = 10
x += 5
"#;
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_compound_assignment_with_expression() {
    let source = r#"
var x = 10
var y = 3
x += y * 2
"#;
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_compound_assignment_in_loop() {
    let source = r#"
var sum = 0
for i in 0..10:
  sum += i
"#;
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_compound_assignment_array_element() {
    let source = r#"
var arr = [1, 2, 3]
arr[0] += 10
"#;
    assert!(parse_source(source).is_ok());
}

#[test]
fn test_parser_compound_all_operators() {
    let source = r#"
var a = 100
a += 10
a -= 5
a *= 2
a /= 10
a %= 7
"#;
    assert!(parse_source(source).is_ok());
}

// ===========================================
// Compound Assignment - Semantic Analysis
// ===========================================

#[test]
fn test_semantic_compound_plus_equals() {
    let source = r#"
var x = 10
x += 5
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_compound_minus_equals() {
    let source = r#"
var x = 10
x -= 3
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_compound_times_equals() {
    let source = r#"
var x = 10
x *= 2
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_compound_divide_equals() {
    let source = r#"
var x = 10
x /= 2
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_compound_modulo_equals() {
    let source = r#"
var x = 10
x %= 3
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_compound_assignment_in_function() {
    let source = r#"
def accumulate(n: int64) -> int64:
  var sum = 0
  for i in 0..n:
    sum += i
  return sum

var result = accumulate(10)
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_compound_assignment_with_expression_rhs() {
    let source = r#"
var x = 100
var y = 10
x += y * 2 + 5
"#;
    assert!(analyze_source(source).is_ok());
}

#[test]
fn test_semantic_compound_error_undefined_variable() {
    let source = r#"
undefined_var += 5
"#;
    assert!(analyze_source(source).is_err());
}

// ===========================================
// Compound Assignment - Full Compilation
// ===========================================
// Note: We avoid using print() with integer variables directly
// due to a pre-existing type inference issue where print expects String.
// Instead, we verify compilation succeeds by checking the final value.

#[test]
fn test_compile_compound_plus_equals() {
    let source = r#"
var x = 10
x += 5
var result = x
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_compound_minus_equals() {
    let source = r#"
var x = 10
x -= 3
var result = x
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_compound_times_equals() {
    let source = r#"
var x = 10
x *= 2
var result = x
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_compound_divide_equals() {
    let source = r#"
var x = 10
x /= 2
var result = x
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_compound_modulo_equals() {
    let source = r#"
var x = 10
x %= 3
var result = x
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_compound_assignment_accumulator() {
    let source = r#"
var sum = 0
for i in 1..11:
  sum += i
var result = sum
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_compound_assignment_factorial_style() {
    let source = r#"
var result = 1
for i in 1..6:
  result *= i
var final = result
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_compound_assignment_countdown() {
    let source = r#"
var count = 100
while count > 0:
  count -= 10
var final = count
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_compound_assignment_in_nested_loops() {
    let source = r#"
var total = 0
for i in 0..3:
  for j in 0..3:
    total += i * j
var result = total
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_compound_assignment_mixed_operations() {
    let source = r#"
var x = 100
x += 50
x -= 30
x *= 2
x /= 4
var result = x
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_compound_assignment_with_function_call() {
    let source = r#"
def double(n: int64) -> int64:
  return n * 2

var x = 10
x += double(5)
var result = x
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_compile_compound_assignment_array_element() {
    let source = r#"
var arr = [10, 20, 30]
arr[0] += 5
arr[1] -= 10
arr[2] *= 2
var a = arr[0]
var b = arr[1]
var c = arr[2]
"#;
    assert!(compile_source(source).is_ok());
}

// ===========================================
// Pythonic Array Syntax Tests
// ===========================================

#[test]
fn test_empty_array_literal() {
    // Empty array literal [] is now supported (type inferred from context)
    let source = r#"
var items: list[int64] = []
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_list_constructor_reserves_capacity_with_contextual_element_type() {
    let source = r#"
var items: list[uint8] = list(64)
items[0] = 7
items[63] = 9
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_array_literal_with_elements() {
    let source = r#"
var items = [1, 2, 3, 4, 5]
var first = items[0]
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_array_append_method() {
    // Pythonic .append() method syntax
    let source = r#"
var items: list[int64] = []
items.append(1)
items.append(2)
items.append(3)
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_array_push_method() {
    // JavaScript-style .push() is intentionally not part of the Python-shaped surface.
    let source = r#"
var items = [1, 2]
items.push(3)
items.push(4)
"#;
    assert!(compile_source(source).is_err());
}

#[test]
fn test_array_length_method() {
    // Pythonic .len() method syntax
    let source = r#"
var items = [1, 2, 3, 4, 5]
var n = items.len()
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_array_len_method() {
    // Python-style .len() or len(arr) syntax
    let source = r#"
var items = [1, 2, 3, 4, 5]
var n = len(items)
var m = items.len()
"#;
    assert!(compile_source(source).is_ok());
}

#[test]
fn test_pythonic_array_loop() {
    // Complete Pythonic array workflow
    let source = r#"
var result: list[int64] = []
for i in 1..6:
  result.append(i * 10)
var n = result.len()
"#;
    assert!(compile_source(source).is_ok());
}

// ===========================================
// Audit regression tests (elif order, break/continue, bitwise, literals)
// ===========================================

/// elif chains must evaluate conditions in source order. The parser used to
/// fold elif clauses so the *first elif* became the outermost condition,
/// silently reordering overlapping conditions (e.g. x < 0 vs x < 10).
#[test]
fn test_elif_chain_preserves_source_order() {
    let source = r#"
def classify(x: int64) -> int64:
  if x < 0:
    return -1
  elif x < 10:
    return 1
  else:
    return 2

def main() -> int64:
  return classify(-5)
"#;
    let tokens = tokenize(source, "test.stfl").expect("lexes");
    let ast = parse(&tokens, "test.stfl").expect("parses");

    fn find_if(node: &AstNode) -> Option<&AstNode> {
        match node {
            AstNode::IfExpression { .. } => Some(node),
            AstNode::Block(nodes) => nodes.iter().find_map(find_if),
            AstNode::FunctionDefinition { body, .. } => find_if(body),
            _ => None,
        }
    }

    let if_node = find_if(&ast).expect("function contains an if");
    let AstNode::IfExpression { condition, .. } = if_node else {
        unreachable!()
    };
    // The OUTERMOST condition must be the first written one: x < 0.
    let AstNode::BinaryOperation { op, right, .. } = condition.as_ref() else {
        panic!("expected comparison condition, got {:?}", condition);
    };
    assert_eq!(op, "<");
    match right.as_ref() {
        AstNode::Literal {
            value: stoffellang::ast::Value::Int { value, .. },
            ..
        } => assert_eq!(*value, 0, "outer condition must compare against 0, not 10"),
        other => panic!(
            "expected integer literal in outer condition, got {:?}",
            other
        ),
    }
}

#[test]
fn test_break_and_continue_compile_inside_loops() {
    let source = r#"
def main() -> int64:
  var n = 0
  while True:
    n += 1
    if n == 5:
      break
  var sum = 0
  for i in 0..10:
    if i % 2 == 1:
      continue
    sum += i
  return n + sum
"#;
    let program = compile(source, "test.stfl", &default_options())
        .expect("break/continue should compile inside loops");
    assert!(!program.main_chunk.instructions.is_empty());
}

#[test]
fn test_break_outside_loop_is_rejected() {
    let source = r#"
def main() -> int64:
  break
  return 1
"#;
    assert!(expect_error_containing(source, "'break' outside of a loop"));
}

#[test]
fn test_continue_outside_loop_is_rejected() {
    let source = r#"
def main() -> int64:
  continue
  return 1
"#;
    assert!(expect_error_containing(
        source,
        "'continue' outside of a loop"
    ));
}

#[test]
fn test_pass_statement_compiles_as_noop() {
    let source = r#"
def main() -> int64:
  if True:
    pass
  return 1
"#;
    compile(source, "test.stfl", &default_options()).expect("pass should compile");
}

#[test]
fn test_exponent_float_literals() {
    let source = r#"
def main() -> float64:
  var a = 1e3
  var b = 2.5e-2
  var c = 4E+6
  return a + b + c
"#;
    let program = compile(source, "test.stfl", &default_options())
        .expect("exponent float literals should compile");
    assert!(
        program
            .main_chunk
            .constants
            .iter()
            .any(|constant| matches!(constant, Constant::Float(value) if value.0 == 1000.0)),
        "1e3 should lex as the float 1000.0"
    );
}

#[test]
fn test_bitwise_keywords_on_matching_integers() {
    let source = r#"
def main() -> int64:
  var a = 12
  var b = 10
  var c = a xor b
  var d = a and b
  var e = a or b
  var f = a shl 2
  var g = a shr 1
  return c + d + e + f + g
"#;
    compile(source, "test.stfl", &default_options())
        .expect("bitwise keywords should work on matching integers");
}

#[test]
fn test_bitwise_on_mixed_integer_widths_is_rejected() {
    let source = r#"
def main() -> int64:
  var a: int32 = 1i32
  var b: int64 = 2i64
  var c = a xor b
  return 0
"#;
    assert!(expect_error_containing(
        source,
        "requires matching integer types"
    ));
}

#[test]
fn test_unary_minus_on_sized_integers_uses_matching_width() {
    let source = r#"
def main() -> int64:
  var a32: int32 = 17i32
  var b32 = -a32
  var a16: int16 = 5i16
  var b16 = -a16
  return 0
"#;
    let program = compile(source, "test.stfl", &default_options())
        .expect("unary minus on sized ints should compile");
    assert!(
        program
            .main_chunk
            .constants
            .iter()
            .any(|constant| matches!(constant, Constant::I32(0))),
        "negating an int32 must use an I32 zero, not I64"
    );
}

#[test]
fn test_string_concat_types_as_string() {
    let source = r#"
def main() -> int64:
  var a = "Hello, "
  var b = "Stoffel"
  var c = a + b
  return len(c)
"#;
    compile(source, "test.stfl", &default_options())
        .expect("string concatenation and len(string) should compile");
}

#[test]
fn test_targeted_errors_for_unsupported_python_syntax() {
    let cases: [(&str, &str); 3] = [
        (
            "def main() -> int64:\n  try:\n    var x = 1\n  except:\n    var y = 2\n  return 1\n",
            "no exception handling",
        ),
        (
            "def main() -> int64:\n  var f = lambda x: x + 1\n  return 1\n",
            "no anonymous functions",
        ),
        (
            "def main() -> int64:\n  var a, b = 1, 2\n  return a\n",
            "Tuple unpacking is not supported",
        ),
    ];
    for (source, expected) in cases {
        assert!(
            expect_error_containing(source, expected),
            "expected error containing '{}' for source:\n{}",
            expected,
            source
        );
    }
}

#[test]
fn test_mixed_width_arithmetic_is_rejected() {
    let source = r#"
def main() -> int64:
  var a: int32 = 5i32
  var b: int64 = 10i64
  var c = a + b
  return 0
"#;
    assert!(expect_error_containing(
        source,
        "requires matching numeric types"
    ));
}

#[test]
fn test_untyped_literal_adopts_sized_operand_width() {
    let source = r#"
def main() -> int64:
  var a: int32 = 5i32
  var b = a + 1
  var c: int8 = 100i8
  var d = c % 7
  return 0
"#;
    let program = compile(source, "test.stfl", &default_options())
        .expect("untyped literals should adopt the other operand's width");
    assert!(
        program
            .main_chunk
            .constants
            .iter()
            .any(|constant| matches!(constant, Constant::I32(1))),
        "literal 1 should become an I32 constant next to an int32 operand"
    );
}

#[test]
fn test_uint64_arithmetic_does_not_infer_int64() {
    let source = r#"
def reduce(x: uint64, modulus: uint64) -> uint64:
  var old_r: uint64 = x % modulus
  var r: uint64 = modulus
  var q = old_r / r
  var temp_r: uint64 = old_r - q * r
  return temp_r

def main(x: uint64, modulus: uint64) -> uint64:
  var result = reduce(x, modulus)
  return result
"#;
    compile(source, "test.stfl", &default_options())
        .expect("uint64 arithmetic should remain uint64 throughout inference");
}

#[test]
fn test_uint64_arguments_do_not_rewrite_int64_function_signature() {
    let source = r#"
def signed_identity(x: int64) -> int64:
  return x

def main(x: uint64) -> int64:
  return signed_identity(x)
"#;
    let errors = analyze_source_errors(source);
    assert!(
        errors.iter().any(|error| error
            .message
            .contains("Argument 1 to function 'signed_identity' has type 'uint64', but parameter expects 'int64'")),
        "expected uint64-to-int64 argument error, got {errors:?}"
    );
    assert!(
        !errors.iter().any(|error| error
            .message
            .contains("declares return type 'uint64'")),
        "argument refinement should not rewrite signed_identity's declared return type, got {errors:?}"
    );
}

#[test]
fn test_uint64_call_into_int64_inverse_reports_only_argument_mismatch() {
    let source = r#"
def multiplicative_inverse(x: int64, modulus: int64) -> int64:
  if modulus == 0:
    return 0

  x = x % modulus
  var old_r: int64 = x
  var r: int64 = modulus
  var old_s: int64 = 1
  var s: int64 = 0

  while r != 0:
    var q = old_r / r
    var temp_r: int64 = old_r - q * r
    old_r = r
    r = temp_r
    var temp_s = old_r - q * r
    old_s = s
    s = temp_s

  if old_r != 1:
    return 0

  if old_s < 0:
    old_s += modulus
  return old_s

def main(x: uint64, modulus: uint64):
  var inv = multiplicative_inverse(x, modulus)
"#;
    let errors = analyze_source_errors(source);
    assert_eq!(
        errors.len(),
        1,
        "reported inverse should fail with one root-cause error, got {errors:?}"
    );
    assert!(
        errors[0]
            .message
            .contains("Argument 1 to function 'multiplicative_inverse' has type 'uint64', but parameter expects 'int64'"),
        "expected call-site uint64-to-int64 mismatch, got {errors:?}"
    );
}

#[test]
fn test_uint64_inverse_with_int64_locals_reports_type_roots_without_cascade() {
    let source = r#"
def multiplicative_inverse(x: uint64, modulus: uint64) -> uint64:
  if modulus == 0:
    return 0

  x = x % modulus
  var old_r: int64 = x
  var r: int64 = modulus
  var old_s: int64 = 1
  var s: int64 = 0

  while r != 0:
    var q = old_r / r
    var temp_r: int64 = old_r - q * r
    old_r = r
    r = temp_r
    var temp_s = old_r - q * r
    old_s = s
    s = temp_s

  if old_r != 1:
    return 0

  if old_s < 0:
    old_s += modulus
  return old_s

def main(x: uint64, modulus: uint64):
  var inv = multiplicative_inverse(x, modulus)
"#;
    let errors = analyze_source_errors(source);
    let messages: Vec<&str> = errors.iter().map(|error| error.message.as_str()).collect();

    assert!(
        messages.contains(
            &"Cannot initialize variable 'old_r' of type 'int64' with value of type 'uint64'"
        ),
        "expected old_r initializer type error, got {errors:?}"
    );
    assert!(
        messages.contains(
            &"Cannot initialize variable 'r' of type 'int64' with value of type 'uint64'"
        ),
        "expected r initializer type error, got {errors:?}"
    );
    assert!(
        messages
            .iter()
            .any(|message| message.contains("Arithmetic '+' requires matching numeric types")),
        "expected old_s += modulus mixed numeric type error, got {errors:?}"
    );
    assert!(
        messages.iter().any(|message| message
            .contains("Cannot return value of type 'int64' from function returning 'uint64'")),
        "expected return type mismatch, got {errors:?}"
    );
    assert!(
        !messages
            .iter()
            .any(|message| message.contains("Use of undeclared identifier")),
        "type recovery should suppress undeclared-variable cascades, got {errors:?}"
    );
    assert!(
        !messages
            .iter()
            .any(|message| message.contains("not all paths return a value")),
        "return-path checking should not cascade after body type errors, got {errors:?}"
    );
    assert_eq!(
        errors.len(),
        4,
        "expected only root type errors, got {errors:?}"
    );
}

#[test]
fn test_uint64_inverse_with_inferred_literals_compiles_until_explicit_inv_mismatch() {
    let source = r#"
def multiplicative_inverse(x: uint64, modulus: uint64) -> uint64:
  if modulus == 0:
    return 0

  x = x % modulus
  var old_r = x
  var r = modulus
  var old_s = 1
  var s = 0

  while r != 0:
    var q = old_r / r
    var temp_r = old_r - q * r
    old_r = r
    r = temp_r
    var temp_s = old_r - q * r
    old_s = s
    s = temp_s

  if old_r != 1:
    return 0

  if old_s < 0:
    old_s += modulus
  return old_s

def main(x: uint64, modulus: uint64):
  var inv: int64 = multiplicative_inverse(x, modulus)
  print(inv)
"#;
    let errors = analyze_source_errors(source);
    let messages: Vec<&str> = errors.iter().map(|error| error.message.as_str()).collect();

    assert!(
        messages.contains(
            &"Cannot initialize variable 'inv' of type 'int64' with value of type 'uint64'"
        ),
        "expected inv initializer type error, got {errors:?}"
    );
    assert!(
        !messages
            .iter()
            .any(|message| message.contains("Use of undeclared identifier")),
        "type recovery should suppress undeclared-variable cascades, got {errors:?}"
    );
    assert_eq!(
        errors.len(),
        1,
        "expected only the explicit int64/uint64 mismatch, got {errors:?}"
    );
}

#[test]
fn test_backward_inference_from_return_type_uses_integer_width() {
    let source = r#"
def narrow() -> int32:
  var x = 0
  return x

def main() -> int32:
  return narrow()
"#;
    compile(source, "test.stfl", &default_options())
        .expect("return context should infer the local integer width");
}

#[test]
fn test_backward_inference_from_bool_condition() {
    let source = r#"
def main() -> int64:
  var flag = 1
  if flag:
    return 1
  return 0
"#;
    compile(source, "test.stfl", &default_options())
        .expect("if condition should infer bool for a 0/1 literal local");
}

#[test]
fn test_backward_inference_from_call_argument_for_containers() {
    let source = r#"
def first_name(names: list[string]) -> string:
  return names[0]

def main() -> string:
  var names = []
  names = ["ada"]
  return first_name(names)
"#;
    compile(source, "test.stfl", &default_options())
        .expect("call and assignment context should infer list[string]");
}

#[test]
fn test_backward_inference_conflict_reports_single_variable() {
    let source = r#"
def takes_u64(x: uint64):
  return

def takes_string(x: string):
  return

def main():
  var x = 0
  takes_u64(x)
  takes_string(x)
"#;
    let errors = analyze_source_errors(source);
    assert_eq!(
        errors.len(),
        1,
        "expected one inference conflict, got {errors:?}"
    );
    assert!(
        errors[0]
            .message
            .contains("Cannot infer a single type for variable 'x'"),
        "expected rich inference conflict, got {errors:?}"
    );
}

#[test]
fn test_heterogeneous_list_literal_is_rejected() {
    let source = r#"
def main() -> int64:
  var xs = [1, "two", 3]
  return 0
"#;
    assert!(expect_error_containing(
        source,
        "List elements must share one type"
    ));
}

#[test]
fn test_string_index_into_list_is_rejected() {
    let source = r#"
def main() -> int64:
  var xs: list[int64] = [1, 2, 3]
  var x = xs["zero"]
  return x
"#;
    assert!(expect_error_containing(source, "Index must be an integer"));
}

#[test]
fn test_missing_return_path_is_rejected() {
    let source = r#"
def maybe(x: int64) -> int64:
  if x > 0:
    return 1

def main() -> int64:
  return maybe(1)
"#;
    assert!(expect_error_containing(
        source,
        "not all paths return a value"
    ));
}

#[test]
fn test_all_paths_returning_via_if_else_is_accepted() {
    let source = r#"
def sign(x: int64) -> int64:
  if x < 0:
    return -1
  elif x == 0:
    return 0
  else:
    return 1

def main() -> int64:
  return sign(5)
"#;
    compile(source, "test.stfl", &default_options())
        .expect("if/elif/else with returns on every branch should compile");
}

#[test]
fn test_oversized_integer_literal_is_a_lexer_error() {
    let source = r#"
def main() -> int64:
  var x = 999999999999999999999999999999999999999999
  return 0
"#;
    let result = tokenize(source, "test.stfl");
    assert!(
        result.is_err(),
        "oversized literal should be a lex error, not silently dropped"
    );
    assert!(result.unwrap_err().message.contains("too large"));
}

// ===========================================
// New language features: slices, f-strings, match, enums, comprehensions, in, assert
// ===========================================

#[test]
fn test_slice_syntax_compiles_for_lists_and_strings() {
    let source = r#"
def main() -> int64:
  var xs: list[int64] = [1, 2, 3, 4]
  var ys = xs[1:3]
  var zs = xs[:2]
  var ws = xs[-2:]
  var s = "stoffel"
  var sub = s[1:4]
  return ys.len() + zs.len() + ws.len() + len(sub)
"#;
    compile(source, "test.stfl", &default_options()).expect("slice syntax should compile");
}

#[test]
fn test_fstring_desugars_to_concatenation() {
    let source = r#"
def main() -> string:
  var n = 42
  var who = "Stoffel"
  return f"{who} computes {n}!"
"#;
    let program =
        compile(source, "test.stfl", &default_options()).expect("f-strings should compile");
    assert!(
        program
            .main_chunk
            .constants
            .iter()
            .any(|constant| matches!(constant, Constant::String(s) if s == " computes ")),
        "literal segments should remain string constants"
    );
}

#[test]
fn test_fstring_complex_interpolation_is_rejected() {
    let source = r#"
def main() -> string:
  var n = 1
  return f"{n + 1}"
"#;
    assert!(expect_error_containing(
        source,
        "must be a variable or dotted field access"
    ));
}

#[test]
fn test_match_desugars_to_if_chain() {
    let source = r#"
def classify(x: int64) -> int64:
  match x:
    case 1:
      return 10
    case 2:
      return 20
    case _:
      return 99

def main() -> int64:
  return classify(2)
"#;
    compile(source, "test.stfl", &default_options()).expect("match should compile");
}

#[test]
fn test_match_default_case_must_be_last() {
    let source = r#"
def main() -> int64:
  var x = 1
  match x:
    case _:
      return 0
    case 1:
      return 1
"#;
    assert!(expect_error_containing(source, "must be the last case"));
}

#[test]
fn test_enum_members_lower_to_int_constants() {
    let source = r#"
enum Color:
  Red
  Green
  Blue

enum Status:
  Ok = 200
  NotFound = 404

def main() -> int64:
  var c: Color = Color.Green
  return c + Status.NotFound + Color.Blue
"#;
    compile(source, "test.stfl", &default_options()).expect("enums should compile");
}

#[test]
fn test_enum_unknown_member_is_rejected() {
    let source = r#"
enum Color:
  Red

def main() -> int64:
  return Color.Purple
"#;
    assert!(expect_error_containing(source, "has no member 'Purple'"));
}

#[test]
fn test_list_comprehension_compiles() {
    let source = r#"
def main() -> int64:
  var doubled = [x * 2 for x in range(0, 5)]
  var evens = [x for x in range(0, 10) if x % 2 == 0]
  return doubled.len() + evens.len()
"#;
    compile(source, "test.stfl", &default_options()).expect("comprehensions should compile");
}

#[test]
fn test_in_operator_compiles_for_lists_dicts_strings() {
    let source = r#"
def main() -> int64:
  var xs: list[int64] = [1, 2, 3]
  var d = {"a": 1}
  var hits = 0
  if 2 in xs:
    hits += 1
  if "a" in d:
    hits += 1
  if "off" in "stoffel":
    hits += 1
  return hits
"#;
    compile(source, "test.stfl", &default_options()).expect("'in' should compile");
}

#[test]
fn test_in_operator_rejects_non_container() {
    let source = r#"
def main() -> int64:
  var n = 5
  if 1 in n:
    return 1
  return 0
"#;
    assert!(expect_error_containing(
        source,
        "Right side of 'in' must be a list, dict, or string"
    ));
}

#[test]
fn test_assert_statement_compiles() {
    let source = r#"
def main(x: int64) -> int64:
  assert x > 0
  assert x < 100, "x out of range"
  return x
"#;
    compile(source, "test.stfl", &default_options()).expect("assert should compile");
}

#[test]
fn test_multiline_collection_literals_compile() {
    let source = r#"
def main() -> int64:
  var m: list[list[int64]] = [
    [1, 2, 3],
    [4, 5, 6]
  ]
  var d = {
    "a": 1,
    "b": 2
  }
  var total: int64 = 0
  for row in m:
    for v in row:
      total += v
  return total + d["a"]
"#;
    compile(source, "test.stfl", &default_options())
        .expect("newlines inside brackets should be implicitly joined");
}

#[test]
fn test_negative_float_literal_adopts_fix64_list_context() {
    let source = r#"
def main() -> int64:
  var xs: list[fix64] = [0.5, -1.5, 2.25]
  if xs[1] < 0.0:
    return 1
  return 0
"#;
    compile(source, "test.stfl", &default_options())
        .expect("negated float literals should adopt the fix64 element type");
}

#[test]
fn test_bitwise_not_on_clear_integers_compiles() {
    let source = r#"
def main() -> int64:
  var a: int64 = 12
  var b: int64 = not a
  var c: uint64 = 0u64
  var d: uint64 = not c
  var flag: bool = not (b == a)
  if flag and b == -13 and d == 18446744073709551615u64:
    return 1
  return 0
"#;
    compile(source, "test.stfl", &default_options())
        .expect("'not' should act as bitwise complement on clear integers");
}

#[test]
fn test_bitwise_not_on_secret_integer_rejected() {
    let source = r#"
def main() -> int64:
  var s: secret int64 = Share.from_clear(5)
  var t: secret int64 = not s
  return 0
"#;
    assert!(expect_error_containing(
        source,
        "Bitwise 'not' is not supported on secret integers"
    ));
}

#[test]
fn test_mod_keyword_and_percent_remainder_compile() {
    let source = r#"
def main() -> int64:
  var floored: int64 = -7 mod 3
  var remainder: int64 = -7 % 3
  var precedence: int64 = 1 + 7 mod 3
  if floored == 2 and remainder == -1 and precedence == 2:
    return 1
  return 0
"#;
    compile(source, "test.stfl", &default_options())
        .expect("'mod' (floored) and '%' (remainder) should both compile");
}

#[test]
fn test_secret_fixed_point_division_by_constant_types_to_secret_fixed() {
    let source = r#"
def main() -> fix64:
  var a: secret fix64 = Share.from_clear_fixed(6.0, 64, 16)
  var half: secret fix64 = a / 2.0
  var third: secret fix64 = a / 3
  var blended: secret fix64 = half + third
  return blended.open_fixed()
"#;
    compile(source, "test.stfl", &default_options())
        .expect("secret fix64 divided by a public constant should type to secret fix64");
}

// ===========================================
// Preprocessing-demand emission (planner input)
// ===========================================

/// Compile `source` and return the preprocessing demand the planner reads.
fn demand_of(source: &str) -> stoffel_vm_types::compiled_binary::PreprocessingDemand {
    demand_of_for_backend(source, MpcBackend::HoneyBadger)
}

fn demand_of_for_backend(
    source: &str,
    mpc_backend: MpcBackend,
) -> stoffel_vm_types::compiled_binary::PreprocessingDemand {
    let mut options = default_options();
    options.mpc_backend = mpc_backend;
    let program = compile(source, "test.stfl", &options).expect("program compiles");
    convert_to_binary(&program)
        .client_io_manifest
        .preprocessing_demand
}

#[test]
fn clear_only_program_emits_zero_preprocessing_demand() {
    let demand = demand_of(
        r#"
def main() -> int64:
  var a: int64 = 3
  var b: int64 = 4
  return a + b
"#,
    );
    assert_eq!(demand.triples, 0);
    assert_eq!(demand.randoms, 0);
    assert_eq!(demand.prandbits, 0);
    assert_eq!(demand.prandints, 0);
    assert!(!demand.dynamic);
}

#[test]
fn direct_random_builtins_emit_their_backing_pool_demand() {
    let demand = demand_of(
        r#"
def main() -> int64:
  var field_random = Share.random_field()
  var explicit_int = Share.random_int(31)
  var contextual_int: secret int64 = Share.random()
  return 0
"#,
    );
    assert_eq!(demand.randoms, 1);
    assert_eq!(demand.prandints, 2);
    assert_eq!(demand.triples, 0);
    assert_eq!(demand.prandbits, 0);
    assert!(!demand.dynamic);
}

#[test]
fn literal_loop_scales_direct_random_share_demand() {
    let demand = demand_of(
        r#"
def main() -> int64:
  for i in 0..4:
    var field_random = Share.random_field()
  return 0
"#,
    );
    assert_eq!(demand.randoms, 4);
    assert_eq!(demand.prandints, 0);
    assert!(!demand.dynamic);
}

#[test]
fn avss_random_methods_all_use_random_share_preprocessing() {
    let demand = demand_of_for_backend(
        r#"
def main() -> int64:
  for i in 0..4:
    var field_random = Share.random_field()
    var explicit_int = Share.random_int(31)
    var contextual_int: secret int64 = Share.random()
  return 0
"#,
        MpcBackend::Avss,
    );
    assert_eq!(demand.randoms, 12);
    assert_eq!(demand.prandints, 0);
    assert_eq!(demand.triples, 0);
    assert_eq!(demand.prandbits, 0);
    assert!(!demand.dynamic);
}

#[test]
fn honey_badger_random_methods_use_their_distinct_pools() {
    let demand = demand_of_for_backend(
        r#"
def main() -> int64:
  for i in 0..4:
    var field_random = Share.random_field()
    var explicit_int = Share.random_int(31)
    var contextual_int: secret int64 = Share.random()
  return 0
"#,
        MpcBackend::HoneyBadger,
    );
    assert_eq!(demand.randoms, 4);
    assert_eq!(demand.prandints, 8);
    assert_eq!(demand.triples, 0);
    assert_eq!(demand.prandbits, 0);
    assert!(!demand.dynamic);
}

#[test]
fn secret_multiplication_emits_one_triple() {
    let demand = demand_of(
        r#"
def main() -> int64:
  var a: secret int64 = Share.from_clear(3)
  var b: secret int64 = Share.from_clear(4)
  var c: secret int64 = a * b
  return c.reveal()
"#,
    );
    assert_eq!(demand.triples, 1);
    assert_eq!(demand.prandbits, 0);
    assert_eq!(demand.prandints, 0);
    assert!(!demand.dynamic);
}

#[test]
fn single_secret_division_emits_frac_bits_prandbits_and_one_prandint() {
    // One secure fix64 / constant runs the truncation protocol: f random bits
    // (f = the operand's fractional bits, 16 by default) + 1 random integer.
    let demand = demand_of(
        r#"
def main() -> fix64:
  var a: secret fix64 = Share.from_clear_fixed(6.0, 64, 16)
  var half: secret fix64 = a / 2.0
  return half.open_fixed()
"#,
    );
    assert_eq!(demand.triples, 0);
    assert_eq!(demand.prandbits, 16);
    assert_eq!(demand.prandints, 1);
    assert!(!demand.dynamic);
}

#[test]
fn literal_bounded_loop_multiplies_division_demand_by_iteration_count() {
    // Four iterations of one division each => 4 * (16 prandbits + 1 prandint).
    // The loop bound is a literal range, so the estimate stays static.
    let demand = demand_of(
        r#"
def main() -> fix64:
  var acc: secret fix64 = Share.from_clear_fixed(0.0, 64, 16)
  for i in 0..4:
    var a: secret fix64 = Share.from_clear_fixed(6.0, 64, 16)
    acc = acc + a / 2.0
  return acc.open_fixed()
"#,
    );
    assert_eq!(demand.prandbits, 64);
    assert_eq!(demand.prandints, 4);
    assert_eq!(demand.triples, 0);
    assert!(!demand.dynamic);
}

#[test]
fn runtime_bounded_loop_marks_demand_dynamic() {
    // The while-loop bound (a.len()) is unknown at compile time, so any MPC op
    // inside is dynamic-demand and the planner must keep runtime headroom.
    let demand = demand_of(
        r#"
def secret_dot(a: list[secret int64], b: list[secret int64]) -> secret int64:
  var acc: secret int64 = Share.from_clear(0)
  var i: int64 = 0
  while i < a.len():
    var prod: secret int64 = a[i] * b[i]
    acc = acc + prod
    i += 1
  return acc

def main(a: list[secret int64], b: list[secret int64]) -> int64:
  return secret_dot(a, b).reveal()
"#,
    );
    assert!(demand.dynamic);
}

#[test]
fn optimized_fixed_client_reduction_uses_semantic_bulk_builtin() {
    let source = r#"
def main() -> list[fix64]:
  var num_elements: int64 = 2
  var num_clients: int64 = ClientStore.get_number_clients()
  var sums: list[Share] = []
  var element_index: int64 = 0
  while element_index < num_elements:
    var element_sum: Share = ClientStore.take_share_fixed(0, element_index)
    var client_index: int64 = 1
    while client_index < num_clients:
      var share: Share = ClientStore.take_share_fixed(client_index, element_index)
      element_sum = element_sum.add(share)
      client_index = client_index + 1
    sums.append(element_sum)
    element_index = element_index + 1
  return Share.batch_open_fixed(sums)
"#;
    let options = default_options();
    let program = compile(source, "test.stfl", &options).expect("program compiles");
    let calls = collect_call_names(&program.main_chunk.instructions);
    assert_eq!(
        calls
            .iter()
            .filter(|name| name.as_str() == "ClientStore.sum_shares_fixed")
            .count(),
        1
    );
    assert!(!calls
        .iter()
        .any(|name| name == "ClientStore.take_share_fixed"));
    assert!(!calls.iter().any(|name| name == "add"));

    let dynamic = &program.client_io_manifest.dynamic_client_inputs;
    assert_eq!(dynamic.len(), 1);
    assert_eq!(dynamic[0].first_client_slot, 0);
    assert_eq!(
        dynamic[0].inputs,
        vec![
            ShareType::default_secret_fixed_point(),
            ShareType::default_secret_fixed_point(),
        ]
    );
}

#[test]
fn semantic_client_reduction_uses_bulk_builtin_for_integer_and_boolean_shares() {
    for (read_builtin, sum_builtin, expected_type) in [
        (
            "ClientStore.take_share",
            "ClientStore.sum_shares",
            ShareType::default_secret_int(),
        ),
        (
            "ClientStore.take_share_bool",
            "ClientStore.sum_shares_bool",
            ShareType::boolean(),
        ),
    ] {
        let source = format!(
            r#"
def main() -> Share:
  var num_clients: int64 = ClientStore.get_number_clients()
  var total: Share = {read_builtin}(0, 0)
  var client_index: int64 = 1
  while client_index < num_clients:
    var share: Share = {read_builtin}(client_index, 0)
    total = total.add(share)
    client_index = client_index + 1
  return total
"#
        );
        let program = compile(&source, "test.stfl", &default_options()).expect("program compiles");
        let calls = collect_call_names(&program.main_chunk.instructions);
        assert_eq!(
            calls
                .iter()
                .filter(|name| name.as_str() == sum_builtin)
                .count(),
            1,
            "expected {sum_builtin}, got {calls:?}"
        );
        assert!(
            !calls.iter().any(|name| name == read_builtin),
            "lowered reduction retained {read_builtin}: {calls:?}"
        );
        assert_eq!(
            program.client_io_manifest.dynamic_client_inputs[0].inputs,
            vec![expected_type]
        );

        let static_source = source.replace("ClientStore.get_number_clients()", "2");
        let static_program =
            compile(&static_source, "test.stfl", &default_options()).expect("program compiles");
        assert_eq!(static_program.client_io_manifest.clients.len(), 2);
        assert!(static_program
            .client_io_manifest
            .clients
            .iter()
            .all(|schema| schema.inputs == vec![expected_type]));
    }
}

#[test]
fn semantic_client_reduction_preserves_nondefault_share_metadata() {
    for (type_name, read_builtin, sum_builtin, expected_type) in [
        (
            "uint32",
            "ClientStore.take_share",
            "ClientStore.sum_shares",
            ShareType::secret_uint(32),
        ),
        (
            "fix32",
            "ClientStore.take_share_fixed",
            "ClientStore.sum_shares_fixed",
            ShareType::secret_fixed_point_from_bits(32, 16),
        ),
    ] {
        let source = format!(
            r#"
def main() -> secret {type_name}:
  var num_clients: int64 = ClientStore.get_number_clients()
  var total: secret {type_name} = {read_builtin}(0, 0)
  var client_index: int64 = 1
  while client_index < num_clients:
    var share: secret {type_name} = {read_builtin}(client_index, 0)
    total = total.add(share)
    client_index = client_index + 1
  return total
"#
        );
        let program = compile(&source, "test.stfl", &default_options()).expect("program compiles");
        let calls = collect_call_names(&program.main_chunk.instructions);
        assert!(calls.iter().any(|name| name == sum_builtin));
        assert_eq!(
            program.client_io_manifest.dynamic_client_inputs[0].inputs,
            vec![expected_type]
        );

        let static_source = source.replace("ClientStore.get_number_clients()", "2");
        let static_program =
            compile(&static_source, "test.stfl", &default_options()).expect("program compiles");
        assert_eq!(static_program.client_io_manifest.clients.len(), 2);
        assert!(static_program
            .client_io_manifest
            .clients
            .iter()
            .all(|schema| schema.inputs == vec![expected_type]));
    }
}

#[test]
fn noncanonical_client_reduction_is_not_fused() {
    let source = r#"
def main() -> fix64:
  var num_clients: int64 = ClientStore.get_number_clients()
  var element_sum: Share = ClientStore.take_share_fixed(0, 0)
  var client_index: int64 = 1
  while client_index < num_clients:
    var share: Share = ClientStore.take_share_fixed(client_index, 0)
    element_sum = element_sum.add(share)
    client_index = client_index + 2
  return element_sum.open_fixed()
"#;
    let options = CompilerOptions {
        optimize: true,
        optimization_level: 2,
        ..default_options()
    };
    let program = compile(source, "test.stfl", &options).expect("program compiles");
    let calls = collect_call_names(&program.main_chunk.instructions);
    assert!(!calls
        .iter()
        .any(|name| name == "ClientStore.sum_shares_fixed"));
    assert!(calls
        .iter()
        .any(|name| name == "ClientStore.take_share_fixed"));
}
