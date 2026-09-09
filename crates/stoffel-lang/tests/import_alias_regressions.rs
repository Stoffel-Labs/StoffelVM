use stoffellang::{compile_file, CompilerOptions};

fn project(files: &[(&str, &str)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for (name, source) in files {
        let path = dir.path().join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, source).unwrap();
    }
    dir
}

fn compile_project(
    dir: &tempfile::TempDir,
    level: u8,
) -> Result<stoffellang::bytecode::CompiledProgram, Vec<stoffellang::errors::CompilerError>> {
    let path = dir.path().join("main.stfl");
    compile_file(
        &path,
        &std::fs::read_to_string(&path).unwrap(),
        &CompilerOptions {
            optimize: level > 0,
            optimization_level: level,
            ..Default::default()
        },
    )
}

#[test]
fn dotted_function_import_binds_the_alias_directly() {
    let dir = project(&[
        ("utils.stfl", "def private_value() -> int64:\n  return 17\ndef value() -> int64:\n  return private_value()\n"),
        ("main.stfl", "import utils.value as answer\ndef main() -> int64:\n  return answer()\n"),
    ]);
    for level in 0..=3 {
        let program = compile_project(&dir, level).unwrap_or_else(|e| panic!("O{level}: {e:?}"));
        assert!(program.function_chunks.contains_key("utils.value"));
        assert!(program.function_chunks.values().chain([&program.main_chunk]).flat_map(|chunk| &chunk.instructions)
            .any(|i| matches!(i, stoffel_vm_types::instructions::Instruction::CALL(name) if name == "utils.value")));
    }
}

#[test]
fn nested_module_alias_remains_a_module() {
    let dir = project(&[
        ("pkg/utils.stfl", "def value() -> int64:\n  return 23\n"),
        (
            "main.stfl",
            "import pkg.utils as u\ndef main() -> int64:\n  return u.value()\n",
        ),
    ]);
    for level in 0..=3 {
        compile_project(&dir, level).unwrap();
    }
}

#[test]
fn member_imports_support_nested_files_defaults_named_and_variadic_arguments() {
    let dir = project(&[
        ("pkg/tools.stfl", "def make(bits: int64 = 17) -> Share:\n  return Share.from_clear_int(1, bits)\ndef second(*xs: Share) -> Share:\n  return xs[1]\n"),
        ("main.stfl", "import pkg.tools.make as build\nimport pkg.tools.second\ndef main():\n  MpcOutput.send_to_client(0, build())\n  MpcOutput.send_to_client(0, build(bits: 9))\n  MpcOutput.send_to_client(0, second(build(), Share.from_field(Field.one())))\n"),
    ]);
    for level in 0..=3 {
        let program = compile_project(&dir, level).unwrap_or_else(|e| panic!("O{level}: {e:?}"));
        assert_eq!(
            program.client_io_manifest.clients[0].outputs,
            vec![
                stoffel_vm_types::core_types::ShareType::secret_int(17),
                stoffel_vm_types::core_types::ShareType::secret_int(9),
                stoffel_vm_types::core_types::ShareType::SecretField,
            ]
        );
    }
}

#[test]
fn module_import_precedence_and_dotted_qualified_calls_are_preserved() {
    let dir = project(&[
        ("tools.stfl", "def value() -> int64:\n  return 1\n"),
        ("tools/value.stfl", "def marker() -> int64:\n  return 2\n"),
        ("main.stfl", "import tools.value as v\nimport tools.value\ndef main() -> int64:\n  return v.marker() + tools.value.marker()\n"),
    ]);
    for level in 0..=3 {
        compile_project(&dir, level).unwrap();
    }
}

#[test]
fn member_aliases_work_with_closures_and_repeated_imports() {
    let dir = project(&[
        ("tools.stfl", "def value() -> int64:\n  return 17\n"),
        ("main.stfl", "import tools.value as value\nimport tools.value as value\nimport tools.value as other\ndef main() -> int64:\n  var c = create_closure(\"other\")\n  var x: int64 = call_closure(c)\n  return value() + x\n"),
    ]);
    for level in 0..=3 {
        let program = compile_project(&dir, level).unwrap();
        assert!(program.function_chunks.contains_key("tools.value"));
        assert_eq!(
            program
                .function_chunks
                .keys()
                .filter(|n| n.ends_with(".value"))
                .count(),
            1
        );
    }
}

#[test]
fn invalid_member_bindings_get_source_diagnostics() {
    let cases = [
        ("import tools.absent as a\ndef main():\n  discard 0\n", "no exported"),
        ("import tools.value as a\nimport tools.other as a\ndef main():\n  discard 0\n", "more than one target"),
        ("import tools.value as a\ndef a() -> int64:\n  return 0\ndef main() -> int64:\n  return a()\n", "conflicts with a local"),
        ("import tools.value as a\nimport tools as a\ndef main():\n  discard 0\n", "more than one target"),
    ];
    for (source, message) in cases {
        let dir = project(&[
            (
                "tools.stfl",
                "def value() -> int64:\n  return 1\ndef other() -> int64:\n  return 2\n",
            ),
            ("main.stfl", source),
        ]);
        for level in 0..=3 {
            let errors = compile_project(&dir, level).unwrap_err();
            assert!(
                errors.iter().any(|e| e.message.contains(message)
                    && e.location.line > 0
                    && e.location.column > 0),
                "{errors:?}"
            );
        }
    }
}

#[test]
fn selected_import_does_not_expose_sibling_functions_or_the_original_name() {
    for call in ["other()", "value()", "a.other()"] {
        let source = format!("import tools.value as a\ndef main() -> int64:\n  return {call}\n");
        let dir = project(&[
            (
                "tools.stfl",
                "def value() -> int64:\n  return 1\ndef other() -> int64:\n  return 2\n",
            ),
            ("main.stfl", &source),
        ]);
        for level in 0..=3 {
            assert!(compile_project(&dir, level).is_err(), "{call}");
        }
    }
}

#[test]
fn relative_modules_with_same_spelling_have_distinct_file_identities() {
    let dir = project(&[
        ("left/service.stfl", "import helpers.value as selected\ndef run() -> int64:\n  return selected()\n"),
        ("left/helpers.stfl", "def value() -> int64:\n  return 3\n"),
        ("right/service.stfl", "import helpers.value as selected\ndef run() -> int64:\n  return selected()\n"),
        ("right/helpers.stfl", "def value() -> int64:\n  return 8\n"),
        ("main.stfl", "import left.service as l\nimport right.service as r\ndef main() -> int64:\n  return l.run() + r.run()\n"),
    ]);
    for level in 0..=3 {
        let program = compile_project(&dir, level).unwrap();
        assert_eq!(
            program
                .function_chunks
                .keys()
                .filter(|name| name.ends_with(".value"))
                .count(),
            2
        );
    }
}

#[test]
fn alternate_spellings_of_the_same_file_share_one_module() {
    let dir = project(&[
        ("tools.stfl", "def value() -> int64:\n  return 17\n"),
        ("main.stfl", "import tools.value as answer\nimport \"./tools.stfl\" as m\ndef main() -> int64:\n  return answer() + m.value()\n"),
    ]);
    for level in 0..=3 {
        let program = compile_project(&dir, level).unwrap();
        assert_eq!(
            program
                .function_chunks
                .keys()
                .filter(|name| name.ends_with(".value"))
                .count(),
            1
        );
    }
}

#[test]
fn module_aliases_also_keep_default_and_named_argument_bindings() {
    let dir = project(&[
        ("pkg/tools.stfl", "def make(bits: int64 = 17) -> Share:\n  return Share.from_clear_int(1, bits)\n"),
        ("main.stfl", "import pkg.tools as u\ndef main():\n  MpcOutput.send_to_client(0, u.make())\n  MpcOutput.send_to_client(0, u.make(bits: 9))\n  MpcOutput.send_to_client(0, make(bits: 11))\n"),
    ]);
    for level in 0..=3 {
        let program = compile_project(&dir, level).unwrap();
        assert_eq!(
            program.client_io_manifest.clients[0].outputs,
            [17, 9, 11].map(stoffel_vm_types::core_types::ShareType::secret_int)
        );
    }
}

#[test]
fn cycles_through_member_imports_are_reported() {
    let dir = project(&[
        (
            "left.stfl",
            "import right.value as other\ndef value() -> int64:\n  return other()\n",
        ),
        (
            "right.stfl",
            "import left.value as other\ndef value() -> int64:\n  return other()\n",
        ),
        (
            "main.stfl",
            "import left.value as answer\ndef main() -> int64:\n  return answer()\n",
        ),
    ]);
    let errors = compile_project(&dir, 0).unwrap_err();
    assert!(
        errors.iter().any(|e| e.message.contains("Circular")),
        "{errors:?}"
    );
}
