//! Domain inference and definite assignment must agree at every optimization level.
use stoffel_vm_types::core_types::ShareType;
use stoffellang::{compile, compile_file, CompilerOptions};

fn options(level: u8) -> CompilerOptions {
    CompilerOptions {
        optimize: level > 0,
        optimization_level: level,
        ..Default::default()
    }
}
fn accepts(source: &str) {
    for level in 0..=3 {
        compile(source, "flow.stfl", &options(level))
            .unwrap_or_else(|errors| panic!("O{level}: {source}\n{errors:?}"));
    }
}
fn rejects(source: &str, message: &str) {
    for level in 0..=3 {
        let errors = compile(source, "flow.stfl", &options(level)).expect_err(source);
        assert!(
            errors.iter().any(|e| e.message.contains(message)
                && e.location.line > 0
                && e.location.column > 0),
            "O{level}: {source}\n{errors:?}"
        );
    }
}
fn outputs(source: &str, expected: &[ShareType]) {
    for level in 0..=3 {
        let program = compile(source, "flow.stfl", &options(level))
            .unwrap_or_else(|errors| panic!("O{level}: {source}\n{errors:?}"));
        let actual = program
            .client_io_manifest
            .clients
            .iter()
            .find(|c| c.client_slot == 0)
            .map(|c| c.outputs.as_slice())
            .unwrap_or_default();
        assert_eq!(actual, expected, "O{level}: {source}");
    }
}

#[test]
fn late_assignment_and_unused_declarations() {
    for ty in [
        "int64", "uint8", "fix64", "bool", "string", "Share", "Object", "Closure",
    ] {
        accepts(&format!("def main():\n  var x: {ty}\n"));
        rejects(
            &format!("def main():\n  var x: {ty}\n  print(x)\n"),
            "before it is initialized",
        );
    }
    for (ty, value) in [
        ("int64", "7"),
        ("bool", "True"),
        ("string", "\"ready\""),
        ("Share", "Share.from_field(Field.one())"),
    ] {
        accepts(&format!(
            "def main():\n  var x: {ty}\n  x = {value}\n  print(x)\n"
        ));
    }
    rejects(
        "def main():\n  var x: int64\n  x += 1\n",
        "before it is initialized",
    );
    rejects(
        "def main():\n  var x: int64\n  var y = x\n",
        "before it is initialized",
    );
}

#[test]
fn branches_and_early_exits() {
    accepts("def f(flag: bool) -> int64:\n  var x: int64\n  if flag:\n    x = 1\n  else:\n    x = 2\n  return x\n");
    accepts("def f(flag: bool) -> int64:\n  var x: int64\n  if flag:\n    return 1\n  else:\n    x = 2\n  return x\n");
    rejects(
        "def f(flag: bool) -> int64:\n  var x: int64\n  if flag:\n    x = 1\n  return x\n",
        "before it is initialized",
    );
    accepts("def main():\n  var x: int64\n  if True:\n    x = 3\n  print(x)\n");
    rejects(
        "def main():\n  var x: bool\n  discard False and x\n  discard True or x\n",
        "before it is initialized",
    );
}

#[test]
fn loop_zero_iterations_break_continue_and_late_reads() {
    rejects(
        "def f(flag: bool):\n  var x: int64\n  while flag:\n    x = 1\n  print(x)\n",
        "before it is initialized",
    );
    rejects(
        "def main():\n  var x: int64\n  for i in 0..0:\n    x = 1\n  print(x)\n",
        "before it is initialized",
    );
    accepts("def main():\n  var x: int64\n  while True:\n    x = 3\n    break\n  print(x)\n");
    rejects("def f(flag: bool):\n  var x: int64\n  while True:\n    if flag:\n      break\n    x = 3\n    break\n  print(x)\n", "before it is initialized");
    rejects("def f(flag: bool):\n  var x: int64\n  while flag:\n    if flag:\n      continue\n    print(x)\n", "before it is initialized");
}

#[test]
fn object_fields_aliases_and_initializing_helpers() {
    let object = "object Pair:\n  x: int64\n  y: int64\n";
    accepts(&format!("{object}def main():\n  var p: Pair\n  var alias = p\n  alias.x = 1\n  p.y = 2\n  print(p)\n"));
    rejects(
        &format!("{object}def main():\n  var p: Pair\n  p.x = 1\n  print(p)\n"),
        "p.y",
    );
    accepts(&format!("{object}def init(p: Pair):\n  p.x = 1\n  p.y = 2\ndef main():\n  var p: Pair\n  init(p)\n  print(p)\n"));
    rejects(&format!("{object}def init(p: Pair, flag: bool):\n  if flag:\n    p.x = 1\n  p.y = 2\ndef main(flag: bool):\n  var p: Pair\n  init(p, flag)\n  print(p)\n"), "p.x");
    rejects(&format!("{object}def consume(p: Pair):\n  print(p.x)\ndef main():\n  var p: Pair\n  consume(p)\n"), "before it is initialized");
    rejects(
        &format!("{object}def main() -> Pair:\n  var p: Pair\n  p.x = 1\n  return p\n"),
        "p.y",
    );
}

#[test]
fn nested_objects_collections_and_constructor_fields() {
    let object = "object Inner:\n  x: int64\nobject Outer:\n  inner: Inner\n  items: list[int64]\n";
    accepts(&format!(
        "{object}def main():\n  var o: Outer\n  o.inner.x = 1\n  o.items.append(2)\n  print(o)\n"
    ));
    rejects(
        &format!("{object}def main():\n  var o: Outer\n  print(o.inner.x)\n"),
        "o.inner.x",
    );
    rejects(
        &format!("{object}def main():\n  var o: Outer\n  var xs = [o]\n"),
        "o.inner.x",
    );
    accepts("object P:\n  x: int64\ndef main():\n  var p = P(x: 3)\n  print(p.x)\n");
    accepts("def main():\n  var xs: list[int64]\n  var s: secret int64\n  xs.append(1)\n  print(xs)\n  print(s)\n");
}

#[test]
fn helper_domains_widths_and_order() {
    for (constructor, expected) in [
        ("Share.from_field(Field.one())", ShareType::SecretField),
        ("Share.from_clear_int(3, 17)", ShareType::secret_int(17)),
        ("Share.from_clear_uint(3, 9)", ShareType::secret_uint(9)),
        (
            "Share.from_clear_fixed(1.5, 40, 12)",
            ShareType::secret_fixed_point_from_bits(40, 12),
        ),
    ] {
        outputs(&format!("def make() -> Share:\n  return {constructor}\ndef identity(x: Share) -> Share:\n  return x\ndef emit(x: Share):\n  MpcOutput.send_to_client(0, identity(x))\ndef main():\n  emit(make())\n"), &[expected]);
    }
    outputs("def emit(x: Share):\n  MpcOutput.send_to_client(0, x)\ndef main():\n  emit(Share.from_field(Field.one()))\n  emit(Share.from_clear_int(2, 8))\n", &[ShareType::SecretField, ShareType::secret_int(8)]);
}

#[test]
fn branch_domains_reassignment_and_early_return() {
    rejects("def choose(flag: bool) -> Share:\n  if flag:\n    return Share.from_field(Field.one())\n  return Share.from_clear_int(1, 64)\ndef main(flag: bool):\n  MpcOutput.send_to_client(0, choose(flag))\n", "share domain");
    outputs("def choose(flag: bool) -> Share:\n  if flag:\n    return Share.from_field(Field.one())\n  return Share.random_field()\ndef main(flag: bool):\n  MpcOutput.send_to_client(0, choose(flag))\n", &[ShareType::SecretField]);
    outputs("def main():\n  var s = Share.from_clear_int(1, 64)\n  s = Share.from_field(Field.one())\n  MpcOutput.send_to_client(0, s)\n", &[ShareType::SecretField]);
    outputs("def choose(flag: bool) -> Share:\n  if flag:\n    return Share.from_field(Field.one())\n  return Share.from_clear_int(1, 64)\ndef main():\n  MpcOutput.send_to_client(0, choose(True))\n", &[ShareType::SecretField]);
}

#[test]
fn lists_alias_mutation_index_and_helper_returns() {
    outputs("def batch(x: Share) -> list[Share]:\n  var xs: list[Share] = []\n  for i in 0..3:\n    xs.append(x)\n  return xs\ndef main():\n  var xs = batch(Share.from_field(Field.one()))\n  MpcOutput.send_to_client(0, xs)\n", &[ShareType::SecretField; 3]);
    outputs("def main():\n  var xs = [Share.from_clear_int(1, 64)]\n  var ys = xs\n  ys[0] = Share.from_field(Field.one())\n  MpcOutput.send_to_client(0, xs[0])\n", &[ShareType::SecretField]);
    outputs("def main():\n  var xs: list[Share] = []\n  var ys = xs\n  ys.append(Share.from_field(Field.one()))\n  MpcOutput.send_to_client(0, xs)\n", &[ShareType::SecretField]);
    rejects("def main(i: int64):\n  var xs = [Share.from_field(Field.one()), Share.from_clear_int(1, 64)]\n  MpcOutput.send_to_client(0, xs[i])\n", "share domain");
}

#[test]
fn imported_helpers_and_aliases_keep_domains_and_call_targets() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("field.stfl"), "def value() -> Share:\n  return Share.from_field(Field.one())\ndef make() -> Share:\n  return value()\n").unwrap();
    std::fs::write(dir.path().join("integer.stfl"), "def value() -> Share:\n  return Share.from_clear_int(7, 8)\ndef make() -> Share:\n  return value()\n").unwrap();
    let source = "import field as f\nimport integer as i\ndef main():\n  MpcOutput.send_to_client(0, f.make())\n  MpcOutput.send_to_client(0, i.make())\n";
    let path = dir.path().join("main.stfl");
    std::fs::write(&path, source).unwrap();
    for level in 0..=3 {
        let program = compile_file(&path, source, &options(level)).unwrap();
        assert_eq!(
            program.client_io_manifest.clients[0].outputs,
            vec![ShareType::SecretField, ShareType::secret_int(8)]
        );
        for chunk in program.function_chunks.values() {
            for instruction in &chunk.instructions {
                if let stoffel_vm_types::instructions::Instruction::CALL(name) = instruction {
                    if name.ends_with(".value") {
                        assert!(program.function_chunks.contains_key(name), "missing {name}");
                    }
                }
            }
        }
    }
}

#[test]
fn domain_unknown_loops_and_conditional_output_positions() {
    rejects("def main(flag: bool):\n  var s = Share.from_clear_int(1, 64)\n  while flag:\n    s = Share.from_field(Field.one())\n    break\n  MpcOutput.send_to_client(0, s)\n", "share domain");
    rejects("def main(n: int64):\n  var s = Share.from_clear_int(1, 64)\n  for i in 0..n:\n    s = Share.from_field(Field.one())\n  MpcOutput.send_to_client(0, s)\n", "share domain");
    rejects("def main(flag: bool):\n  if flag:\n    MpcOutput.send_to_client(0, Share.from_field(Field.one()))\n  MpcOutput.send_to_client(0, Share.from_clear_int(1, 64))\n", "share domain");
    outputs("def main(flag: bool):\n  if flag:\n    MpcOutput.send_to_client(0, Share.from_field(Field.one()))\n  MpcOutput.send_to_client(0, Share.from_field(Field.one()))\n", &[ShareType::SecretField; 2]);
    rejects("def main(s: Share):\n  var field = Share.from_field(Field.one())\n  MpcOutput.send_to_client(0, Share.add(s, field))\n", "share domain");
}

#[test]
fn constructors_recursion_and_float_precision_through_helpers() {
    outputs("def f(n: int64) -> Share:\n  if n == 0:\n    return Share.from_field(Field.one())\n  return f(n - 1)\ndef main():\n  MpcOutput.send_to_client(0, f(3))\n", &[ShareType::SecretField]);
    rejects("def f(n: int64) -> Share:\n  return f(n)\ndef main(n: int64):\n  MpcOutput.send_to_client(0, f(n))\n", "share domain");
    outputs("def f(x: Share) -> Share:\n  return x.mul_scalar(1.5)\ndef main():\n  MpcOutput.send_to_client(0, f(Share.from_clear_int(1, 8)))\n", &[ShareType::default_secret_fixed_point()]);
    outputs("def f() -> secret int64:\n  return Share.from_field(Field.one())\ndef main():\n  MpcOutput.send_to_client(0, f())\n", &[ShareType::SecretField]);
    outputs("object Holder:\n  value: Share\ndef get(h: Holder) -> Share:\n  return h.value\ndef main():\n  var h: Holder\n  h.value = Share.from_field(Field.one())\n  MpcOutput.send_to_client(0, get(h))\n", &[ShareType::SecretField]);
}

#[test]
fn list_shape_changes_and_scalar_alias_defaults() {
    outputs("def main():\n  var xs: list[Share] = []\n  var alias = xs\n  alias.append(Share.from_field(Field.one()))\n  for i in 0..len(xs):\n    MpcOutput.send_to_client(0, xs[i])\n", &[ShareType::SecretField]);
    outputs("def main():\n  var xs = [Share.from_field(Field.one()), Share.from_clear_int(2, 8)]\n  xs.reverse()\n  MpcOutput.send_to_client(0, xs.pop())\n  MpcOutput.send_to_client(0, xs)\n", &[ShareType::SecretField, ShareType::secret_int(8)]);
    accepts(
        "type Numbers = list[int64]\ndef main():\n  var xs: Numbers\n  xs.append(1)\n  print(xs)\n",
    );
    rejects(
        "type Number = int64\ndef main():\n  var x: Number\n  print(x)\n",
        "before it is initialized",
    );
    rejects(
        "def unused(x: int64):\n  print(1)\ndef main():\n  var x: int64\n  unused(x)\n",
        "before it is initialized",
    );
}

#[test]
fn inherited_fields_and_alias_merges_are_checked() {
    let objects = "object Base:\n  x: int64\nobject Child(Base):\n  y: int64\n";
    rejects(
        &format!("{objects}def main():\n  var c: Child\n  c.y = 1\n  print(c)\n"),
        "c.x",
    );
    accepts(&format!(
        "{objects}def main():\n  var c: Child\n  c.y = 1\n  c.x = 2\n  print(c)\n"
    ));
    rejects("object P:\n  x: int64\ndef main(flag: bool, complete: P):\n  var p: P\n  var alias = p\n  if flag:\n    alias = complete\n  alias.x = 1\n  print(p.x)\n", "p.x");
    rejects("object P:\n  x: int64\ndef main(flag: bool):\n  var a: P\n  var b: P\n  b.x = 1\n  var alias = a\n  if flag:\n    alias = b\n  alias.x = 2\n  print(a.x)\n", "a.x");
}

#[test]
fn loop_local_bindings_do_not_escape() {
    accepts("def main():\n  var x: int64 = 1\n  for i in 0..2:\n    var x: int64\n  print(x)\n");
    outputs("def main():\n  var s = Share.from_field(Field.one())\n  for i in 0..2:\n    var s = Share.from_clear_int(1, 64)\n  MpcOutput.send_to_client(0, s)\n", &[ShareType::SecretField]);
    rejects("def main(flag: bool):\n  var xs: list[Share] = []\n  while flag:\n    xs.append(Share.from_field(Field.one()))\n    break\n  MpcOutput.send_to_client(0, xs)\n", "number of shares");
}

#[test]
fn unknown_pop_index_cannot_invent_an_output_domain() {
    rejects("def main(i: int64):\n  var xs = [Share.from_field(Field.one()), Share.from_clear_int(1, 64)]\n  MpcOutput.send_to_client(0, xs.pop(i))\n", "share domain");
    rejects(
        "def main(xs: list[secret bool]):\n  MpcOutput.send_to_client(0, xs)\n",
        "number of shares",
    );
    rejects("def main():\n  var xs: list[list[secret bool]] = [[Share.from_clear_int(1, 1)]]\n  MpcOutput.send_to_client(0, xs)\n", "share domain");
}

#[test]
fn runtime_output_counts_are_not_silently_truncated() {
    rejects("def main(n: int64):\n  for i in 0..n:\n    MpcOutput.send_to_client(0, Share.from_field(Field.one()))\n", "client-output count");
    rejects("def main(n: int64):\n  var i = 0\n  while i < n:\n    MpcOutput.send_to_client(0, Share.from_field(Field.one()))\n    i += 1\n", "client-output count");
}

#[test]
fn imported_closure_targets_use_their_defining_module() {
    let dir = tempfile::tempdir().unwrap();
    for (module, value) in [("left", 3), ("right", 7)] {
        std::fs::write(dir.path().join(format!("{module}.stfl")), format!("def target() -> int64:\n  return {value}\ndef make() -> Closure:\n  return create_closure(\"target\")\n")).unwrap();
    }
    let source = "import left\nimport right\ndef main() -> int64:\n  var a: int64 = call_closure(left.make())\n  var b: int64 = call_closure(right.make())\n  return a + b\n";
    let path = dir.path().join("main.stfl");
    std::fs::write(&path, source).unwrap();
    for level in 0..=3 {
        let program = compile_file(&path, source, &options(level)).unwrap();
        assert!(program.function_chunks.contains_key("left.target"));
        assert!(program.function_chunks.contains_key("right.target"));
        let strings: Vec<_> = program
            .function_chunks
            .values()
            .flat_map(|c| &c.instructions)
            .filter_map(|i| {
                if let stoffel_vm_types::instructions::Instruction::LDI(
                    _,
                    stoffel_vm_types::core_types::Value::String(s),
                ) = i
                {
                    Some(s.as_str())
                } else {
                    None
                }
            })
            .collect();
        assert!(strings.contains(&"left.target"));
        assert!(strings.contains(&"right.target"));
    }
}

#[test]
fn mutations_through_conditional_aliases_preserve_all_possible_domains() {
    rejects("def main(flag: bool):\n  var a = [Share.from_field(Field.one())]\n  var b = [Share.from_field(Field.one())]\n  var alias = a\n  if flag:\n    alias = b\n  alias[0] = Share.from_clear_int(1, 64)\n  MpcOutput.send_to_client(0, a[0])\n", "share domain");
    rejects("def main(flag: bool):\n  var a = [Share.from_field(Field.one())]\n  var b = [Share.from_field(Field.one())]\n  var alias = a\n  if flag:\n    alias = b\n  a[0] = Share.from_clear_int(1, 64)\n  MpcOutput.send_to_client(0, alias[0])\n", "share domain");
    outputs("def main(flag: bool):\n  var a = [Share.from_field(Field.one())]\n  var b = [Share.from_field(Field.one())]\n  var alias = a\n  if flag:\n    alias = b\n  alias[0] = Share.random_field()\n  MpcOutput.send_to_client(0, a[0])\n", &[ShareType::SecretField]);
}

#[test]
fn fixed_point_comparisons_keep_boolean_output_domains() {
    for op in ["==", "!=", "<", "<=", ">", ">="] {
        outputs(&format!("def main():\n  var x: secret fix64 = 1.5\n  MpcOutput.send_to_client(0, x {op} 0.5)\n"), &[ShareType::boolean()]);
    }
}

#[test]
fn eager_boolean_operands_keep_initializer_side_effects_in_bytecode() {
    use stoffel_vm_types::{core_types::Value, instructions::Instruction};
    for expr in [
        "False and init(p)",
        "init(p) and False",
        "True or init(p)",
        "init(p) or True",
    ] {
        for statement in [
            format!("if {expr}:\n    discard 0"),
            format!("discard {expr}"),
        ] {
            let source = format!("object P:\n  x: int64\ndef init(p: P) -> bool:\n  p.x = 29\n  return True\ndef main() -> int64:\n  var p: P\n  {statement}\n  return p.x\n");
            for level in 0..=3 {
                let program = compile(&source, "flow.stfl", &options(level)).unwrap();
                assert!(
                    std::iter::once(&program.main_chunk)
                        .chain(program.function_chunks.values())
                        .flat_map(|c| &c.instructions)
                        .any(|i| matches!(i, Instruction::LDI(_, Value::I64(29)))),
                    "initializer removed at O{level}: {source}"
                );
            }
        }
    }
}

#[test]
fn typed_helper_boundaries_preserve_constructor_precision() {
    outputs("def f() -> secret fix64:\n  return Share.from_clear_fixed(1.5, 40, 12)\ndef main():\n  MpcOutput.send_to_client(0, f())\n", &[ShareType::secret_fixed_point_from_bits(40, 12)]);
    outputs("def f() -> secret int64:\n  return Share.from_clear_int(3, 17)\ndef main():\n  MpcOutput.send_to_client(0, f())\n", &[ShareType::secret_int(17)]);
    rejects("type S = Share\ndef f(s: S) -> S:\n  return Share.add(s, Share.from_field(Field.one()))\ndef main(s: S):\n  MpcOutput.send_to_client(0, f(s))\n", "share domain");
}

#[test]
fn literal_closure_helpers_contribute_their_output_contract() {
    outputs("def emit():\n  MpcOutput.send_to_client(0, Share.from_field(Field.one()))\ndef main():\n  var c = create_closure(\"emit\")\n  discard call_closure(c)\n", &[ShareType::SecretField]);
    outputs("def make() -> Share:\n  return Share.from_field(Field.one())\ndef main():\n  var c = create_closure(\"make\")\n  var s: Share = call_closure(c)\n  MpcOutput.send_to_client(0, s)\n", &[ShareType::SecretField]);
}

#[test]
fn typed_parameters_do_not_retag_opaque_share_arguments() {
    outputs("def identity(x: secret int64) -> secret int64:\n  return x\ndef main():\n  MpcOutput.send_to_client(0, identity(Share.from_clear_int(1, 17)))\n", &[ShareType::secret_int(17)]);
    outputs("def identity(x: secret fix64) -> secret fix64:\n  return x\ndef main():\n  MpcOutput.send_to_client(0, identity(Share.from_clear_fixed(1.5, 40, 12)))\n", &[ShareType::secret_fixed_point_from_bits(40, 12)]);
    outputs("def first(xs: list[secret int64]) -> secret int64:\n  return xs[0]\ndef main():\n  var xs: list[secret int64] = [Share.from_clear_int(1, 17)]\n  MpcOutput.send_to_client(0, first(xs))\n", &[ShareType::secret_int(17)]);
}

#[test]
fn conditional_loop_exits_keep_share_domain_facts() {
    rejects("def main(flag: bool):\n  var s = Share.from_field(Field.one())\n  for i in 0..2:\n    if flag:\n      s = Share.from_clear_int(1, 64)\n      break\n    s = Share.from_field(Field.one())\n  MpcOutput.send_to_client(0, s)\n", "share domain");
    rejects("def main(flag: bool):\n  var s = Share.from_field(Field.one())\n  var result = s\n  for i in 0..2:\n    result = s\n    if flag:\n      s = Share.from_clear_int(1, 64)\n      continue\n    s = Share.from_field(Field.one())\n  MpcOutput.send_to_client(0, result)\n", "share domain");
    outputs("def main(flag: bool):\n  var s = Share.from_field(Field.one())\n  for i in 0..2:\n    if flag:\n      s = Share.random_field()\n      break\n    s = Share.from_field(Field.one())\n  MpcOutput.send_to_client(0, s)\n", &[ShareType::SecretField]);
}

#[test]
fn runtime_loops_join_domains_from_later_iterations() {
    for header in ["while n > 0:", "for i in 0..n:"] {
        rejects(&format!("def main(n: int64):\n  var s = Share.from_field(Field.one())\n  var result = s\n  {header}\n    result = s\n    s = Share.from_clear_int(1, 64)\n    n -= 1\n  MpcOutput.send_to_client(0, result)\n"), "share domain");
        outputs(&format!("def main(n: int64):\n  var s = Share.from_field(Field.one())\n  var result = s\n  {header}\n    result = s\n    s = Share.random_field()\n    n -= 1\n  MpcOutput.send_to_client(0, result)\n"), &[ShareType::SecretField]);
    }
}

#[test]
fn retry_loops_in_helpers_converge_without_guessing_domains() {
    outputs("def retry(flag: bool) -> Share:\n  while True:\n    if flag:\n      continue\n    return Share.from_field(Field.one())\ndef main(flag: bool):\n  MpcOutput.send_to_client(0, retry(flag))\n", &[ShareType::SecretField]);
    rejects("def retry(flag: bool) -> Share:\n  var s = Share.from_field(Field.one())\n  while True:\n    if flag:\n      s = Share.from_clear_int(1, 64)\n      continue\n    return s\ndef main(flag: bool):\n  MpcOutput.send_to_client(0, retry(flag))\n", "share domain");
}

#[test]
fn runtime_loop_heap_changes_and_growing_collections_are_conservative() {
    rejects("def main(n: int64):\n  var xs = [Share.from_field(Field.one())]\n  var result = xs[0]\n  while n > 0:\n    result = xs[0]\n    xs[0] = Share.from_clear_int(1, 64)\n    n -= 1\n  MpcOutput.send_to_client(0, result)\n", "share domain");
    outputs("def main(n: int64):\n  var xs = [Share.from_field(Field.one())]\n  var result = xs[0]\n  while n > 0:\n    result = xs[0]\n    xs[0] = Share.random_field()\n    n -= 1\n  MpcOutput.send_to_client(0, result)\n", &[ShareType::SecretField]);
    outputs("def main(n: int64):\n  var xs: list[Share] = []\n  for i in 0..n:\n    xs.append(Share.from_field(Field.one()))\n  MpcOutput.send_to_client(0, Share.from_field(Field.one()))\n", &[ShareType::SecretField]);
    rejects("def main(n: int64):\n  var xs: list[Share] = []\n  for i in 0..n:\n    xs.append(Share.from_field(Field.one()))\n  MpcOutput.send_to_client(0, xs)\n", "share");
    rejects("def main(flag: bool):\n  var xs: list[Share] = []\n  if flag:\n    xs.append(Share.from_field(Field.one()))\n  for s in xs:\n    MpcOutput.send_to_client(0, s)\n", "client-output count");
}

#[test]
fn complete_parameter_and_local_aliases_can_be_read_after_joining() {
    accepts("object P:\n  x: int64\ndef select(flag: bool, complete: P) -> int64:\n  var p: P\n  p.x = 1\n  var alias = p\n  if flag:\n    alias = complete\n  return alias.x\n");
    rejects("object P:\n  x: int64\ndef select(flag: bool, complete: P) -> int64:\n  var p: P\n  var alias = p\n  if flag:\n    alias = complete\n  return alias.x\n", "alias.x");
}

#[test]
fn named_default_and_variadic_arguments_keep_dataflow_facts() {
    outputs("def make(bits: int64 = 17) -> Share:\n  return Share.from_clear_int(1, bits)\ndef main():\n  MpcOutput.send_to_client(0, make())\n  MpcOutput.send_to_client(0, make(bits: 9))\n", &[ShareType::secret_int(17), ShareType::secret_int(9)]);
    outputs("def second(*xs: Share) -> Share:\n  return xs[1]\ndef main():\n  MpcOutput.send_to_client(0, second(Share.from_clear_int(1, 8), Share.from_field(Field.one())))\n", &[ShareType::SecretField]);
    accepts("object P:\n  x: int64\ndef init(value: int64, p: P):\n  p.x = value\ndef main() -> int64:\n  var p: P\n  init(p: p, value: 11)\n  return p.x\n");
    rejects("object P:\n  x: int64\ndef consume(*ps: P):\n  print(ps)\ndef main():\n  var p: P\n  consume(p)\n", "p.x");
}
