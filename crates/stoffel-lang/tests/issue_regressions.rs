//! Cross-phase and developer-facing regressions for STO-970 through STO-973.
use stoffellang::compiler::{compile, compile_file, CompilerOptions};

fn accepts(source: &str) {
    for level in [0, 1, 2, 3] {
        let options = CompilerOptions {
            optimize: level > 0,
            optimization_level: level,
            ..Default::default()
        };
        assert!(
            compile(source, "regression.stfl", &options).is_ok(),
            "{source}\n{:?}",
            compile(source, "regression.stfl", &options).err()
        );
    }
}

fn rejects(source: &str, message: &str) {
    for level in [0, 3] {
        let options = CompilerOptions {
            optimize: level > 0,
            optimization_level: level,
            ..Default::default()
        };
        let errors = compile(source, "regression.stfl", &options).expect_err(source);
        assert!(
            errors.iter().any(|e| e.message.contains(message)),
            "{source}\n{errors:?}"
        );
        assert!(
            errors.iter().all(|e| !e.message.contains("Codegen failed")),
            "{errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|e| e.location.line > 0 && e.location.column > 0),
            "{errors:?}"
        );
    }
}

#[test]
fn repetition_rejects_nonpublic_integer_counts_in_every_expression_shape() {
    for count in [
        "s",
        "Share.from_clear_int(2, 64)",
        "n",
        "1.5",
        "True",
        "[2]",
        "\"x\"",
    ] {
        for expr in [format!("[1] * {count}"), format!("{count} * [1]")] {
            for stmt in [
                format!("discard {expr}"),
                format!("var r = {expr}"),
                format!("var r: list[int64] = {expr}"),
                format!("print({expr})"),
            ] {
                rejects(&format!("def main():\n  var s: Share = Share.from_clear_int(2, 64)\n  var n: secret int64 = 2\n  {stmt}\n"), "repetition requires a clear integer");
            }
        }
    }
}

#[test]
fn bytes_share_original_and_identifier_forms_have_operand_diagnostics() {
    for first in ["s", "Share.from_clear_int(1, 64)"] {
        for annotation in ["", ": Share"] {
            rejects(&format!("def d() -> bytes:\n  return Field.one()\ndef main():\n  var s{annotation} = Share.from_clear_int(3, 64)\n  var eq = {first} + d() * s\n"), "repetition requires a clear integer");
        }
    }
}

#[test]
fn repetition_accepts_clear_integer_widths_empty_lists_and_secret_elements() {
    for ty in [
        "int8", "int16", "int32", "int64", "uint8", "uint16", "uint32", "uint64",
    ] {
        for expr in ["xs * n", "n * xs"] {
            accepts(&format!("def main():\n  var n: {ty} = 2\n  var xs: list[int64] = [1]\n  var r = {expr}\n  print(r[0])\n"));
        }
    }
    for count in ["0", "-1", "3"] {
        accepts(&format!(
            "def main():\n  var r: bytes = [] * {count}\n  print(len(r))\n"
        ));
    }
    accepts("def main():\n  var s: Share = Share.from_clear_int(2, 64)\n  var r = [s] * 2\n  print(len(r))\n");
}

#[test]
fn share_operators_and_scalar_builtins_reject_unsupported_pairs() {
    for expr in [
        "s + \"x\"",
        "s - Field.one()",
        "s / s",
        "s % s",
        "s mod s",
        "2 / s",
        "s + 1.5",
        "Share.mul_scalar(s, Field.one())",
        "s.mul_scalar(\"x\")",
        "Share.add_constant(s, \"x\")",
        "Share.add_scalar(s, n)",
    ] {
        rejects(&format!("def main():\n  var s: Share = Share.from_clear_int(2, 64)\n  var n: secret int64 = 2\n  discard {expr}\n"), if expr.contains("scalar") || expr.contains("constant") { "clear numeric scalar" } else { "Unsupported Share arithmetic" });
    }
    for expr in [
        "s + 2",
        "2 - s",
        "s * s",
        "s * 1.5",
        "1.5 * s",
        "s / 2",
        "Share.mul_scalar(s, 1.5)",
        "Share.add_constant(s, 1.5)",
    ] {
        accepts(&format!(
            "def main():\n  var s: Share = Share.from_clear_int(2, 64)\n  discard {expr}\n"
        ));
    }
}

#[test]
fn builtin_namespaces_are_rejected_in_all_type_positions() {
    for ns in [
        "Field",
        "Bytes",
        "Mpc",
        "ClientStore",
        "LocalStorage",
        "MpcOutput",
        "Crypto",
        "Rbc",
        "Avss",
    ] {
        for source in [
            format!("def main():\n  var x: {ns}\n"),
            format!("def main():\n  var x: {ns} = Field.one()\n"),
            format!("def main():\n  var x: list[{ns}] = []\n"),
            format!("def main():\n  var x: dict[string, {ns}]\n"),
            format!("def f(x: {ns}):\n  print(0)\n"),
            format!("def f() -> {ns}:\n  return Field.one()\n"),
            format!("type Alias = {ns}\ndef main():\n  print(0)\n"),
            format!("object Holder:\n  value: {ns}\ndef main():\n  print(0)\n"),
            format!("def main():\n  var x: secret {ns}\n"),
        ] {
            rejects(&source, "builtin namespace, not a type");
        }
        rejects(
            &format!("def main():\n  var x = {ns}\n"),
            "builtin namespace, not a value",
        );
    }
    accepts("def main():\n  var s: Share = Share.from_clear_int(2, 64)\n  var b: bytes = Field.one()\n  print(Share.get_type(s))\n");
}

#[test]
fn opaque_values_require_initialization_before_use() {
    for ty in ["Share", "Closure", "Object"] {
        rejects(
            &format!("def main():\n  var x: {ty}\n  print(x)\n"),
            "before it is initialized",
        );
    }
}

#[test]
fn globals_and_implicit_captures_never_reach_codegen() {
    for source in [
        "var X: int64 = 255\ndef main():\n  print(X)\n",
        "var X: int64 = 255\ndef main():\n  print(1)\n",
        "def main():\n  print(1)\nvar X: int64 = 255\n",
    ] {
        rejects(source, "Cannot mix top-level code");
    }
    rejects(
        "var X: int64 = 2\ndef f() -> int64:\n  return X\nprint(f())\n",
        "implicit captures are not supported",
    );
    rejects(
        "def main():\n  var x: int64 = 2\n  def f() -> int64:\n    return x\n  print(f())\n",
        "implicit captures are not supported",
    );
    accepts("var X: int64 = 255\nprint(X)\n");
    accepts(
        "def f(x: int64) -> int64:\n  return x\ndef main():\n  var x: int64 = 2\n  print(f(x))\n",
    );
    accepts("def main():\n  var x: int64 = 2\n  def f(x: int64) -> int64:\n    return x\n  print(f(x))\n");
}

#[test]
fn imported_variables_report_a_source_error() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("constants.stfl"), "var X: int64 = 2\n").unwrap();
    for expr in ["X", "constants.X"] {
        let path = dir.path().join("main.stfl");
        let source = format!("import constants\ndef main():\n  print({expr})\n");
        std::fs::write(&path, &source).unwrap();
        let errors = compile_file(&path, &source, &CompilerOptions::default())
            .expect_err("imported globals");
        assert!(
            errors.iter().all(|e| !e.message.contains("Codegen failed")),
            "{errors:?}"
        );
        assert!(errors.iter().any(|e| e.location.line > 0), "{errors:?}");
    }
}

#[test]
fn nested_functions_do_not_inherit_loop_control_context() {
    for keyword in ["break", "continue"] {
        let source =
            format!("def main():\n  while True:\n    def f():\n      {keyword}\n    break\n");
        let errors = compile(&source, "regression.stfl", &CompilerOptions::default()).unwrap_err();
        assert!(errors.iter().any(|e| e.message.contains("outside")));
    }
}

#[test]
fn repetition_return_assignment_and_generic_contexts() {
    rejects(
        "def f(n: secret int64) -> list[int64]:\n  return [1] * n\n",
        "repetition requires a clear integer",
    );
    rejects(
        "def main():\n  var xs: list[int64] = [1]\n  var n: secret int64 = 2\n  xs *= n\n",
        "repetition requires a clear integer",
    );
    accepts("def repeat[T](xs: list[T], n: int64) -> list[T]:\n  return xs * n\ndef main():\n  var xs = repeat([1], 2)\n  xs *= 2\n  print(len(xs))\n");
}

#[test]
fn from_field_signature_and_preprocessing_demand() {
    accepts("def main() -> Share:\n  return Share.from_field(Field.one())\n");
    for expr in [
        "Share.from_field()",
        "Share.from_field(1)",
        "Share.from_field(Field.one(), 1)",
        "Share.from_field(Share.from_clear_int(1, 64))",
    ] {
        let source = format!("def main():\n  discard {expr}\n");
        assert!(
            compile(&source, "regression.stfl", &CompilerOptions::default()).is_err(),
            "{expr}"
        );
    }
    for backend in [
        stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
        stoffel_vm_types::compiled_binary::MpcBackend::Avss,
    ] {
        let options = CompilerOptions {
            mpc_backend: backend,
            ..Default::default()
        };
        let program = compile(
            "def main() -> Share:\n  return Share.from_field(Field.one())\n",
            "regression.stfl",
            &options,
        )
        .unwrap();
        assert_eq!(
            program.client_io_manifest.preprocessing_demand,
            Default::default()
        );
    }
}

#[test]
fn namespace_diagnostics_point_to_nested_type_name() {
    for annotation in [
        "Field",
        "list[Field]",
        "dict[string, list[Field]]",
        "secret Field",
    ] {
        let line = format!("  var x: {annotation}");
        let source = format!("def main():\n{line}\n");
        let errors = compile(&source, "regression.stfl", &CompilerOptions::default()).unwrap_err();
        let error = errors
            .iter()
            .find(|e| e.message.contains("builtin namespace, not a type"))
            .unwrap();
        assert_eq!(error.location.line, 2, "{errors:?}");
        assert_eq!(
            error.location.column,
            line.find("Field").unwrap() + 1,
            "{errors:?}"
        );
    }
}

#[test]
fn field_share_outputs_keep_the_field_domain_in_manifests() {
    use stoffel_vm_types::core_types::ShareType;
    for expression in [
        "Share.from_field(Field.one())",
        "Share.random_field()",
        "Share.add_field(Share.from_clear_int(1, 64), Field.one())",
        "Share.mul_field(Share.from_clear_int(1, 64), Field.one())",
    ] {
        for level in [0, 3] {
            let options = CompilerOptions {
                optimize: level > 0,
                optimization_level: level,
                ..Default::default()
            };
            let source = format!("def main():\n  var s: Share = {expression}\n  discard MpcOutput.send_to_client(0, s)\n");
            let program = compile(&source, "regression.stfl", &options).unwrap();
            assert_eq!(
                program.client_io_manifest.clients[0].outputs,
                vec![ShareType::SecretField],
                "{expression}"
            );
        }
    }
}
