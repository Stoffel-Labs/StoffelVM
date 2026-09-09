use std::fs;
use std::io::{BufRead, BufReader};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::process::{Command as StdCommand, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::Duration;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn local_mpc_guard() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

const LOCAL_MPC_TEST_TIMEOUT_SECS: &str = "120";

/// Overwrites the scaffolded `src/main.stfl` with a deterministic two-argument
/// addition program so named-input run flows have a stable, cleartext-safe
/// `main(a, b)` to exercise. The default `init` template is a no-argument random
/// boolean circuit, which neither accepts named inputs nor runs without an MPC
/// engine, so tests that assert on `--input a=.. --input b=..` results write this
/// program after `init` (and before any `build`).
fn write_addition_program(project_dir: &std::path::Path) {
    fs::write(
        project_dir.join("src/main.stfl"),
        "def main(a: int64, b: int64) -> int64:\n  return a + b\n",
    )
    .unwrap();
}

#[test]
fn cli_exits_cleanly_when_stdout_pipe_closes() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();

    let binary = assert_cmd::cargo::cargo_bin("stoffel");
    let mut child = StdCommand::new(binary)
        .arg("status")
        .arg(temp.path())
        .arg("--verbose")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut first_line = String::new();
    reader.read_line(&mut first_line).unwrap();
    assert!(first_line.starts_with("Project:"));
    drop(reader);

    let status = child.wait().unwrap();
    assert!(
        status.success(),
        "expected closed stdout pipe to exit cleanly, got {status}"
    );
}

#[test]
fn init_creates_default_project() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path().join("hello"))
        .assert()
        .success()
        .stdout(predicate::str::contains("Created Stoffel project"));

    assert!(temp.path().join("hello/Stoffel.toml").exists());
    assert!(temp.path().join("hello/src/main.stfl").exists());
    assert!(temp.path().join("hello/Cargo.toml").exists());
    assert!(temp.path().join("hello/build.rs").exists());
    assert!(temp.path().join("hello/src/main.rs").exists());
    assert!(!temp.path().join("hello/src/stoffel_bindings.rs").exists());
    let program = fs::read_to_string(temp.path().join("hello/src/main.stfl")).unwrap();
    assert!(program.contains("def gate_and(a: secret bool, b: secret bool) -> secret bool"));
    assert!(program.contains("var x: secret bool = Share.random()"));
    assert!(program.contains("return result.reveal()"));
    let cargo_toml = fs::read_to_string(temp.path().join("hello/Cargo.toml")).unwrap();
    assert!(cargo_toml.contains("stoffel-rust-sdk"));
    assert!(cargo_toml.contains("stoffel = { package = \"stoffel-rust-sdk\""));
    assert!(cargo_toml.contains("[build-dependencies]"));
    assert!(cargo_toml.contains("stoffel-bindgen"));
    let build_rs = fs::read_to_string(temp.path().join("hello/build.rs")).unwrap();
    assert!(build_rs.contains("generate_bindings_from_source"));
    assert!(build_rs.contains("src/main.stfl"));
    let main_rs = fs::read_to_string(temp.path().join("hello/src/main.rs")).unwrap();
    assert!(main_rs.contains("mod stoffel_bindings"));
    assert!(main_rs.contains("include!(concat!(env!(\"OUT_DIR\")"));
    assert!(main_rs.contains("stoffel_bindings::ProgramManifest"));
    assert!(!main_rs.contains("with_inputs"));
    let readme = fs::read_to_string(temp.path().join("hello/README.md")).unwrap();
    assert!(readme.contains("stoffel check"));
    assert!(readme.contains("stoffel run"));
    assert!(readme.contains("stoffel dev --once"));
    assert!(!readme.contains("--input a=40 --input b=2"));
    assert!(readme.contains("stoffel build"));
    assert!(readme.contains("cargo build"));
    assert!(readme.contains("cargo run"));
}

#[cfg(unix)]
#[test]
fn init_force_rejects_symlink_project_root() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().unwrap();
    let outside = temp.path().join("outside");
    let linked_project = temp.path().join("linked-project");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("keep.txt"), "keep").unwrap();
    symlink(&outside, &linked_project).unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&linked_project)
        .arg("--force")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "cannot initialize project through symlink",
        ));

    assert_eq!(
        fs::read_to_string(outside.join("keep.txt")).unwrap(),
        "keep"
    );
    assert!(!outside.join("Stoffel.toml").exists());
}

#[test]
#[ignore = "heavy integration test; run with the serial heavy-test command"]
fn init_default_project_builds_with_cargo_and_sdk_bindings() {
    let _guard = local_mpc_guard();
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("hello");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .success();

    let cli_manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let sdk_path = cli_manifest_dir
        .parent()
        .expect("CLI crate lives under crates/")
        .join("stoffel-rust-sdk");
    let crates_dir = sdk_path.parent().expect("SDK crate lives under crates/");
    let bindgen_path = crates_dir.join("stoffel-bindgen");
    let cargo_toml_path = project.join("Cargo.toml");
    let cargo_toml = fs::read_to_string(&cargo_toml_path)
        .unwrap()
        .replace(
            "stoffel = { package = \"stoffel-rust-sdk\", version = \"=0.2.0\" }",
            &format!(
                "stoffel = {{ package = \"stoffel-rust-sdk\", path = \"{}\" }}",
                sdk_path.display()
            ),
        )
        .replace(
            "stoffel-bindgen = \"=0.2.0\"",
            &format!(
                "stoffel-bindgen = {{ path = \"{}\" }}",
                bindgen_path.display()
            ),
        );
    // This fixture builds the in-tree SDK. Cargo does not inherit workspace
    // patches or its lockfile when that SDK is used from a separate project.
    // Carry both over so --offline also works on a fresh CI dependency cache,
    // rather than depending on unrelated registry versions cached locally.
    let workspace = crates_dir
        .parent()
        .expect("crates live under the workspace");
    let workspace_manifest: toml::Value =
        toml::from_str(&fs::read_to_string(workspace.join("Cargo.toml")).unwrap()).unwrap();
    let mut manifest: toml::Value = toml::from_str(&cargo_toml).unwrap();
    if let Some(patches) = workspace_manifest.get("patch") {
        let mut patches = patches.clone();
        for (_, overrides) in patches.as_table_mut().unwrap().iter_mut() {
            for (_, dependency) in overrides.as_table_mut().unwrap().iter_mut() {
                if let Some(path) = dependency.get_mut("path") {
                    *path = toml::Value::String(
                        workspace.join(path.as_str().unwrap()).display().to_string(),
                    );
                }
            }
        }
        manifest
            .as_table_mut()
            .unwrap()
            .insert("patch".to_owned(), patches);
    }
    fs::write(&cargo_toml_path, toml::to_string(&manifest).unwrap()).unwrap();
    fs::copy(workspace.join("Cargo.lock"), project.join("Cargo.lock")).unwrap();

    StdCommand::new("cargo")
        .arg("build")
        .arg("--offline")
        .current_dir(&project)
        .status()
        .expect("cargo build should run")
        .success()
        .then_some(())
        .expect("initialized default project should build with cargo");
}

#[test]
#[ignore = "heavy integration test; run with the serial heavy-test command"]
fn common_command_aliases_work() {
    let _guard = local_mpc_guard();
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("hello");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("new")
        .arg(&project)
        .assert()
        .success()
        .stdout(predicate::str::contains("Created Stoffel project"));
    write_addition_program(&project);

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("doctor")
        .arg(&project)
        .assert()
        .success()
        .stdout(predicate::str::contains("Config: ok"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("exec")
        .arg(&project)
        .args(["--input", "a=1", "--input", "b=2"])
        .assert()
        .success()
        .stdout(predicate::str::contains("3"))
        .stderr(predicate::str::contains("unrecognized subcommand").not());

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("upgrade")
        .arg(&project)
        .arg("--check")
        .assert()
        .success()
        .stdout(predicate::str::contains("Stoffel CLI:"))
        .stderr(predicate::str::contains("unrecognized subcommand").not());
}

#[test]
fn init_help_names_supported_templates_and_aliases() {
    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["init", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Supported templates:"))
        .stdout(predicate::str::contains("python (py)"))
        .stdout(predicate::str::contains("solidity-foundry (foundry)"))
        .stdout(predicate::str::contains("solidity-hardhat (hardhat)"))
        .stdout(predicate::str::contains("typescript").not())
        .stdout(predicate::str::contains("TypeScript").not());
}

#[test]
#[ignore = "heavy integration test; run with the serial heavy-test command"]
fn run_executes_default_secret_bool_circuit_project() {
    let _guard = local_mpc_guard();
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();

    let output = Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args(["run", "--timeout-secs", LOCAL_MPC_TEST_TIMEOUT_SECS])
        .output()
        .expect("stoffel run should execute");
    assert!(
        output.status.success(),
        "default secret bool circuit failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("true") || stdout.contains("false"),
        "expected boolean output, got stdout:\n{stdout}"
    );
}

#[test]
#[ignore = "heavy integration test; run with the serial heavy-test command"]
fn run_accepts_numeric_bits_for_secret_bool_list_inputs() {
    let _guard = local_mpc_guard();
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    fs::write(
        temp.path().join("src/main.stfl"),
        "def main(a: list[secret bool]) -> bool:\n  return a[0].reveal()\n",
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args([
            "run",
            "--input",
            "a=0,1,1,1",
            "--timeout-secs",
            LOCAL_MPC_TEST_TIMEOUT_SECS,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("false"))
        .stderr(predicate::str::contains("expects bool, got i64").not());
}

#[test]
fn build_writes_bytecode_to_target() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args(["build", "--output", "target/debug/app.stflb"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Built"))
        .stdout(predicate::str::contains("Bytecode size:"))
        .stdout(predicate::str::contains("Optimization: O2"));

    assert!(temp.path().join("target/debug/app.stflb").exists());

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args(["build", "--release"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Profile: release"))
        .stdout(predicate::str::contains("Optimization: O3"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args([
            "build",
            "--prod",
            "--output",
            "target/release/prod-alias.stflb",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Profile: release"))
        .stdout(predicate::str::contains("Optimization: O3"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args([
            "compile",
            "--production",
            "--output",
            "target/release/production-alias.stflb",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Profile: release"))
        .stdout(predicate::str::contains("Optimization: O3"));

    let release_artifacts = fs::read_dir(temp.path().join("target/release"))
        .unwrap()
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("stflb"))
        .collect::<Vec<_>>();
    assert!(!release_artifacts.is_empty());
}

#[test]
#[ignore = "heavy integration test; run with the serial heavy-test command"]
fn run_executes_bytecode_file() {
    let _guard = local_mpc_guard();
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    write_addition_program(temp.path());

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args(["build", "--output", "target/debug/app.stflb"])
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args([
            "run",
            "target/debug/app.stflb",
            "--timeout-secs",
            LOCAL_MPC_TEST_TIMEOUT_SECS,
            "--input",
            "a=20",
            "--input",
            "b=22",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("42"));
}

#[test]
#[ignore = "heavy integration test; run with the serial heavy-test command"]
fn run_auto_discovers_built_bytecode() {
    let _guard = local_mpc_guard();
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("app");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .success();
    write_addition_program(&project);

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(&project)
        .arg("build")
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .args([
            "run",
            project.to_str().unwrap(),
            "--timeout-secs",
            LOCAL_MPC_TEST_TIMEOUT_SECS,
            "--input",
            "a=21",
            "--input",
            "b=21",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("42"));
}

#[test]
#[ignore = "heavy integration test; run with the serial heavy-test command"]
fn run_recompiles_when_project_source_is_newer_than_bytecode() {
    let _guard = local_mpc_guard();
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("app");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(&project)
        .assert()
        .success();

    thread::sleep(Duration::from_secs(1));
    fs::write(
        project.join("src/main.stfl"),
        "def main(a: int64, b: int64) -> int64:\n  var sum = a + b\n  var sum2 = sum + b\n  return sum2\n",
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(&project)
        .args([
            "--program-info",
            "--timeout-secs",
            LOCAL_MPC_TEST_TIMEOUT_SECS,
            "--input",
            "a=1",
            "--input",
            "b=2",
        ])
        .assert()
        .success()
        // 5 = MOV a, MOV b, ADD, ADD, RET: the two variable-binding copies the
        // allocator coalesces are now deleted by post-RA self-MOV elimination.
        // Any count far below the ~113-instruction init template proves the
        // stale bytecode was recompiled from the new source.
        .stdout(predicate::str::contains("Instructions: 5"))
        .stdout(predicate::str::contains("5"));
}

#[test]
#[ignore = "heavy integration test; run with the serial heavy-test command"]
fn run_ignores_stray_bytecode_when_project_source_is_newer() {
    let _guard = local_mpc_guard();
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("app");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(&project)
        .assert()
        .success();

    thread::sleep(Duration::from_secs(1));
    fs::write(
        project.join("src/main.stfl"),
        "def main(a: int64, b: int64) -> int64:\n  return 100\n",
    )
    .unwrap();
    fs::copy(
        project.join("target/debug/app.stflb"),
        project.join("target/debug/zzz.stflb"),
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(&project)
        .args([
            "--program-info",
            "--timeout-secs",
            LOCAL_MPC_TEST_TIMEOUT_SECS,
            "--input",
            "a=1",
            "--input",
            "b=2",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Instructions: 4"))
        .stdout(predicate::str::contains("100"))
        .stdout(predicate::str::contains("Instructions: 113").not());
}

#[test]
#[ignore = "heavy integration test; run with the serial heavy-test command"]
fn run_recompiles_when_project_config_is_newer_than_bytecode() {
    let _guard = local_mpc_guard();
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("app");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(&project)
        .assert()
        .success();

    thread::sleep(Duration::from_secs(1));
    let config = fs::read_to_string(project.join("Stoffel.toml")).unwrap();
    fs::write(
        project.join("Stoffel.toml"),
        config.replace("threshold = 1", "threshold = 2"),
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(&project)
        .args([
            "--program-info",
            "--timeout-secs",
            LOCAL_MPC_TEST_TIMEOUT_SECS,
            "--input",
            "a=1",
            "--input",
            "b=2",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid Byzantine threshold"));
}

#[test]
#[ignore = "heavy integration test; run with the serial heavy-test command"]
fn run_folder_compiles_project_when_bytecode_is_missing() {
    let _guard = local_mpc_guard();
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("app.with.dot");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .success();
    write_addition_program(&project);

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(project)
        .args([
            "--program-info",
            "--timeout-secs",
            LOCAL_MPC_TEST_TIMEOUT_SECS,
            "--input",
            "a=21",
            "--input",
            "b=21",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Functions:"))
        .stdout(predicate::str::contains("Instructions:"))
        .stdout(predicate::str::contains("42"));
}

#[test]
#[ignore = "heavy integration test; run with the serial heavy-test command"]
fn run_rejects_non_project_directories_inside_a_project() {
    let _guard = local_mpc_guard();
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    fs::create_dir_all(temp.path().join("target")).unwrap();

    for path in [temp.path().join("src"), temp.path().join("target")] {
        Command::cargo_bin("stoffel")
            .unwrap()
            .arg("run")
            .arg(&path)
            .args([
                "--program-info",
                "--timeout-secs",
                LOCAL_MPC_TEST_TIMEOUT_SECS,
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "expected a project directory containing Stoffel.toml",
            ))
            .stderr(predicate::str::contains("To run the current project, pass"))
            .stdout(predicate::str::contains("Functions:").not());
    }
}

#[test]
#[ignore = "heavy integration test; run with the serial heavy-test command"]
fn dev_once_executes_default_secret_bool_circuit_project() {
    let _guard = local_mpc_guard();
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("app");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("dev")
        .arg(&project)
        .args(["--once", "--timeout-secs", LOCAL_MPC_TEST_TIMEOUT_SECS])
        .assert()
        .success()
        .stdout(predicate::str::contains("true").or(predicate::str::contains("false")));
}

#[test]
#[ignore = "heavy integration test; run with the serial heavy-test command"]
fn dev_once_explains_input_mistakes() {
    let _guard = local_mpc_guard();
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("app");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .success();
    fs::write(
        project.join("src/main.stfl"),
        "def main(a: secret int64, b: secret int64) -> secret int64:\n  return a + b\n",
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("dev")
        .arg(&project)
        .args(["--once", "--timeout-secs", LOCAL_MPC_TEST_TIMEOUT_SECS])
        .assert()
        .failure()
        .stderr(predicate::str::contains("missing input 'a'"))
        .stderr(predicate::str::contains(
            "Pass inputs as: stoffel dev --entry main --input a=<value> --input b=<value>",
        ));

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("dev")
        .arg(&project)
        .args(["--once", "--entry", "", "--input", "a=1", "--input", "b=2"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "entry function name cannot be empty",
        ))
        .stderr(predicate::str::contains("function '' not found").not());

    fs::write(
        project.join("src/main.stfl"),
        "def helper() -> int64:\n  return 1\n",
    )
    .unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("dev")
        .arg(&project)
        .args(["--once"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "entry function 'main' is not declared",
        ))
        .stderr(predicate::str::contains(
            "Available source functions: helper",
        ))
        .stderr(predicate::str::contains("missing input 'a'").not());

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("dev")
        .arg(&project)
        .args(["a=40", "b=2", "--once"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "named inputs must use --input NAME=VALUE",
        ))
        .stderr(predicate::str::contains(
            "Try: stoffel dev --input a=40 --input b=2",
        ));
}

#[test]
fn dev_watch_explains_input_mistakes_before_starting() {
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("app");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .success();
    // Use an input-requiring program so `stoffel dev` (no inputs) reports the
    // missing input and exits BEFORE entering the file watcher; otherwise the
    // default no-argument template would start watching and the test would hang.
    write_addition_program(&project);

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("dev")
        .arg(&project)
        .assert()
        .failure()
        .stderr(predicate::str::contains("missing input 'a'"))
        .stderr(predicate::str::contains(
            "Pass inputs as: stoffel dev --entry main --input a=<value> --input b=<value>",
        ))
        .stdout(predicate::str::contains("Starting Stoffel dev server").not())
        .stdout(predicate::str::contains("Watching for changes").not());
}

#[test]
#[ignore = "heavy integration test; run with the serial heavy-test command"]
fn dev_once_uses_explicit_source_file() {
    let _guard = local_mpc_guard();
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("app");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .success();
    fs::write(
        project.join("src/alt.stfl"),
        "def alt() -> int64:\n  return 99\n",
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("dev")
        .arg(project.join("src/alt.stfl"))
        .args([
            "--once",
            "--entry",
            "alt",
            "--timeout-secs",
            LOCAL_MPC_TEST_TIMEOUT_SECS,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("99"))
        .stderr(predicate::str::contains("function 'alt' not found").not())
        .stderr(predicate::str::contains("missing input 'a'").not());
}

#[test]
fn dev_rejects_non_source_paths_and_invalid_poll_interval() {
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("app");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .success();

    fs::write(project.join("notes.txt"), "not source").unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("dev")
        .arg(project.join("notes.txt"))
        .arg("--once")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "expected a project directory or .stfl source file",
        ));

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(&project)
        .assert()
        .success();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("dev")
        .arg(project.join("target/debug/app.stflb"))
        .arg("--once")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "dev watches project directories or .stfl source files",
        ))
        .stderr(predicate::str::contains("stoffel run"));

    for inner_dir in ["src", "target"] {
        Command::cargo_bin("stoffel")
            .unwrap()
            .arg("dev")
            .arg(project.join(inner_dir))
            .args(["--once", "--input", "a=1", "--input", "b=2"])
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "expected a project directory containing Stoffel.toml",
            ))
            .stderr(predicate::str::contains("To watch this project, pass"))
            .stderr(
                predicate::str::contains("local network timeout must be greater than zero").not(),
            );
    }

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("dev")
        .arg(&project)
        .args(["--poll-ms", "0"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "0 is not valid here; use a positive whole number",
        ));

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("dev")
        .arg(&project)
        .args(["--poll", "0"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "0 is not valid here; use a positive whole number",
        ));
}

#[test]
fn run_help_exposes_mpc_network_flags() {
    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["run", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--parties"))
        .stdout(predicate::str::contains("--threshold"))
        .stdout(predicate::str::contains("--config"))
        .stdout(predicate::str::contains("--network"))
        .stdout(predicate::str::contains("--local"))
        .stdout(predicate::str::contains("--client-input"))
        .stdout(predicate::str::contains(
            "Fixed-point values are scaled automatically",
        ))
        .stdout(predicate::str::contains("--expected-output-clients"))
        .stdout(predicate::str::contains("--expected-clients").not())
        .stdout(predicate::str::contains("--connect-timeout-ms"))
        .stdout(predicate::str::contains("--program-info"))
        .stdout(predicate::str::contains("aliases: --inspect, --info"))
        .stdout(predicate::str::contains("--output").not())
        .stdout(predicate::str::contains("--disassemble").not())
        .stdout(predicate::str::contains("--binary").not());
}

#[test]
fn summary_flag_is_not_part_of_general_build_help() {
    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["check", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--summary").not())
        .stdout(predicate::str::contains("--output").not())
        .stdout(predicate::str::contains("--disassemble").not())
        .stdout(predicate::str::contains("--binary").not())
        .stdout(predicate::str::contains("--release").not())
        .stdout(predicate::str::contains("--optimize").not())
        .stdout(predicate::str::contains("--opt-level").not())
        .stdout(predicate::str::contains("--instance-id").not())
        .stdout(predicate::str::contains(
            "Project directory, source directory, or .stfl source file to validate",
        ))
        .stdout(predicate::str::contains(
            "Override [mpc].backend from Stoffel.toml",
        ))
        .stdout(predicate::str::contains("--print-ir"));

    for command in ["compile", "build"] {
        Command::cargo_bin("stoffel")
            .unwrap()
            .args([command, "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("--summary").not())
            .stdout(predicate::str::contains("--binary").not())
            .stdout(predicate::str::contains("Use -O3, -O 3, or --opt-level 3"))
            .stdout(predicate::str::contains("Accepts `-O3`").not())
            .stdout(predicate::str::contains(
                "Write bytecode to this .stflb file",
            ))
            .stdout(
                predicate::str::contains("alias: --out")
                    .or(predicate::str::contains("aliases: --out")),
            )
            .stdout(predicate::str::contains("aliases: --prod, --production"));
    }
    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["compile", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--disassemble"));
    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["build", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--disassemble").not());

    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["run", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--program-info"))
        .stdout(predicate::str::contains("aliases: --inspect, --info"))
        .stdout(predicate::str::contains("--summary").not())
        .stdout(predicate::str::contains("Use -O3, -O 3, or --opt-level 3"))
        .stdout(predicate::str::contains("Accepts `-O3`").not())
        .stdout(predicate::str::contains("aliases: --prod, --production"))
        .stdout(predicate::str::contains(
            "Do not pass project Stoffel.toml here",
        ))
        .stdout(predicate::str::contains(
            "Function argument value, written as NAME=VALUE",
        ))
        .stdout(predicate::str::contains(
            "aliases: --entrypoint, --function",
        ))
        .stdout(
            predicate::str::contains("alias: --inputs")
                .or(predicate::str::contains("aliases: --inputs")),
        )
        .stdout(
            predicate::str::contains("alias: --client-inputs")
                .or(predicate::str::contains("aliases: --client-inputs")),
        );

    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["run", "--summary"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unexpected argument '--summary'"));
}

#[test]
fn run_rejects_zero_expected_output_clients() {
    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["run", "--expected-output-clients", "0"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "0 is not valid here; use a positive whole number",
        ));
}

#[test]
fn run_rejects_legacy_expected_clients_flag() {
    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["run", "--expected-clients", "1"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "unexpected argument '--expected-clients'",
        ));
}

#[test]
fn run_and_dev_accept_plural_input_aliases() {
    for command in ["run", "dev"] {
        Command::cargo_bin("stoffel")
            .unwrap()
            .args([
                command,
                "--inputs",
                "a=1",
                "--client-inputs",
                "0=2",
                "--entry",
                "",
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "entry function name cannot be empty",
            ))
            .stderr(predicate::str::contains("unexpected argument '--inputs'").not())
            .stderr(predicate::str::contains("unexpected argument '--client-inputs'").not());
    }
}

#[test]
fn run_and_dev_reject_call_syntax_for_entry_names() {
    for command in ["run", "dev"] {
        Command::cargo_bin("stoffel")
            .unwrap()
            .args([command, "--entry", "main()"])
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "entry must be a function name, not a call expression",
            ))
            .stderr(predicate::str::contains("use --entry main"))
            .stderr(predicate::str::contains("could not find Stoffel.toml").not());

        Command::cargo_bin("stoffel")
            .unwrap()
            .args([command, "--entry", "main add"])
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "entry function name cannot contain spaces",
            ))
            .stderr(predicate::str::contains("could not find Stoffel.toml").not());
    }
}

#[test]
fn help_text_uses_foolproof_command_phrasing() {
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Validate source and project MPC settings without writing bytecode",
        ))
        .stdout(predicate::str::contains(
            "Run source or bytecode through MPC execution",
        ))
        .stdout(predicate::str::contains("deploy").not())
        .stdout(predicate::str::contains("publish").not());

    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["init", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("without deleting unrelated files"))
        .stdout(predicate::str::contains("--interactive").not());

    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["clean", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("detected ecosystem caches"))
        .stdout(predicate::str::contains("--release").not());
}

#[test]
fn legacy_planned_commands_explain_current_workflows() {
    for (args, expected) in [
        (
            vec!["deploy"],
            "Build bytecode with `stoffel build`; use `stoffel run --network --config <CONFIG>`",
        ),
        (
            vec!["add", "foo"],
            "Edit project dependency files directly for now",
        ),
        (
            vec!["publish", "--dry-run"],
            "Build artifacts with `stoffel build --release`",
        ),
    ] {
        Command::cargo_bin("stoffel")
            .unwrap()
            .args(args)
            .assert()
            .failure()
            .stderr(predicate::str::contains("not available yet"))
            .stderr(predicate::str::contains(expected))
            .stderr(predicate::str::contains("unrecognized subcommand").not());
    }
}

#[test]
fn typoed_commands_suggest_only_available_commands() {
    for (typo, suggestion) in [
        ("statuz", "stoffel status"),
        ("chek", "stoffel check"),
        ("rn", "stoffel run"),
        ("bulid", "stoffel build"),
    ] {
        Command::cargo_bin("stoffel")
            .unwrap()
            .arg(typo)
            .assert()
            .failure()
            .stderr(predicate::str::contains(format!(
                "Did you mean `{suggestion}`?"
            )))
            .stderr(predicate::str::contains("publish").not())
            .stderr(predicate::str::contains("deploy").not())
            .stderr(predicate::str::contains("add").not());
    }
}

#[test]
#[ignore = "heavy integration test; run with the serial heavy-test command"]
fn common_flag_aliases_work_or_explain_defaults() {
    let _guard = local_mpc_guard();
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    write_addition_program(temp.path());

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(temp.path())
        .args(["--out", "target/debug/alias.stflb"])
        .assert()
        .success()
        .stdout(predicate::str::contains("alias.stflb"));
    assert!(temp.path().join("target/debug/alias.stflb").exists());

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(temp.path())
        .args([
            "--entrypoint",
            "main",
            "--input",
            "a=1",
            "--input",
            "b=2",
            "--timeout-secs",
            LOCAL_MPC_TEST_TIMEOUT_SECS,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("3"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("dev")
        .arg(temp.path())
        .args([
            "--no-watch",
            "--function",
            "main",
            "--input",
            "a=1",
            "--input",
            "b=2",
            "--timeout-secs",
            LOCAL_MPC_TEST_TIMEOUT_SECS,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("3"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("dev")
        .arg(temp.path())
        .arg("--watch")
        .assert()
        .failure()
        .stderr(predicate::str::contains("watches by default"))
        .stderr(predicate::str::contains("--once/--no-watch"));

    fs::create_dir_all(temp.path().join("tests")).unwrap();
    fs::write(
        temp.path().join("tests/selected.stfl"),
        "def main() -> int64:\n  return 7\n",
    )
    .unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("test")
        .arg(temp.path())
        .args(["--name", "selected"])
        .assert()
        .success()
        .stdout(predicate::str::contains("selected.stfl"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("clean")
        .arg(temp.path())
        .arg("--dryrun")
        .assert()
        .success()
        .stdout(predicate::str::contains("Would clean"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("update")
        .arg(temp.path())
        .args(["--dryrun", "--no-self"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Project update:"));
}

#[test]
fn check_rejects_build_only_flags_at_parse_time() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();

    for flag in [
        "--output",
        "--disassemble",
        "--binary",
        "--release",
        "--optimize",
        "--opt-level",
        "--instance-id",
    ] {
        let mut command = Command::cargo_bin("stoffel").unwrap();
        command.arg("check").arg(temp.path()).arg(flag);
        if flag == "--output" {
            command.arg("target/debug/app.stflb");
        }
        if flag == "--opt-level" {
            command.arg("3");
        }
        if flag == "--instance-id" {
            command.arg("0");
        }
        command
            .assert()
            .failure()
            .stderr(predicate::str::contains(format!(
                "unexpected argument '{flag}'"
            )));
    }

    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["check", "--instance-id", "0"])
        .arg(temp.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "unexpected argument '--instance-id'",
        ));
}

#[test]
fn build_rejects_compile_only_disassemble_flag_at_parse_time() {
    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["build", "--disassemble"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "unexpected argument '--disassemble'",
        ));
}

#[test]
fn hidden_legacy_noop_flags_are_rejected() {
    for args in [vec!["compile", "--binary"], vec!["compile", "-b"]] {
        Command::cargo_bin("stoffel")
            .unwrap()
            .args(args)
            .assert()
            .failure()
            .stderr(predicate::str::contains("writes bytecode by default"))
            .stderr(predicate::str::contains("remove -b/--binary"))
            .stderr(predicate::str::contains("unexpected argument").not());
    }

    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["clean", "--release"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unexpected argument"));
}

#[test]
fn opt_level_help_matches_supported_spellings() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();

    for args in [
        vec!["build", "-O3"],
        vec!["build", "-O", "3"],
        vec!["build", "--opt-level", "3"],
    ] {
        Command::cargo_bin("stoffel")
            .unwrap()
            .args(args)
            .arg(temp.path())
            .assert()
            .success()
            .stdout(predicate::str::contains("Optimization: O3 (enabled)"));
    }

    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["compile", "--opt-level", "-O3"])
        .arg(temp.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "use -O3 or --opt-level 3; do not write --opt-level -O3",
        ))
        .stderr(predicate::str::contains("a value is required").not());

    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["compile", "--opt-level", "-03"])
        .arg(temp.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "invalid optimization level '-03'; use 0, 1, 2, or 3",
        ))
        .stderr(predicate::str::contains("unexpected argument '-0'").not());
}

#[test]
#[ignore = "heavy integration test; run with the serial heavy-test command"]
fn run_rejects_build_only_flags_and_honors_program_info() {
    let _guard = local_mpc_guard();
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    write_addition_program(temp.path());

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args(["run", "--output", "target/debug/app.stflb"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unexpected argument '--output'"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args(["run", "--disassemble"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "unexpected argument '--disassemble'",
        ));

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args([
            "run",
            "--program-info",
            "--timeout-secs",
            LOCAL_MPC_TEST_TIMEOUT_SECS,
            "--input",
            "a=1",
            "--input",
            "b=2",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Functions:"))
        .stdout(predicate::str::contains("3"));
}

#[test]
#[ignore = "heavy integration test; run with the serial heavy-test command"]
fn run_validates_entry_and_inputs_before_timeout() {
    let _guard = local_mpc_guard();
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .arg("run")
        .arg(temp.path())
        .args([
            "--entry",
            "missing",
            "--input",
            "a=1",
            "--input",
            "b=2",
            "--timeout-secs",
            LOCAL_MPC_TEST_TIMEOUT_SECS,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "entry function 'missing' is not declared",
        ))
        .stderr(predicate::str::contains(
            "Available source functions: circuit, gate_and, gate_not, gate_or, gate_xor, main",
        ));

    fs::write(
        temp.path().join("src/main.stfl"),
        "def add(a: int64, b: int64) -> int64:\n  return a + b\n",
    )
    .unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .arg("run")
        .arg(temp.path())
        .args(["--input", "a=1", "--input", "b=2"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "entry function 'main' is not declared",
        ))
        .stderr(predicate::str::contains("Available source functions: add"))
        .stderr(predicate::str::contains("Compiler-visible functions").not())
        .stderr(predicate::str::contains("unexpected input 'a'").not());

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .arg("run")
        .arg(temp.path())
        .args(["--entry", "aad", "--input", "a=1", "--input", "b=2"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "entry function 'aad' is not declared",
        ))
        .stderr(predicate::str::contains("Did you mean --entry add?"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    write_addition_program(temp.path());

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .arg("run")
        .arg(temp.path())
        .args(["--entry", "", "--input", "a=1", "--input", "b=2"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "entry function name cannot be empty",
        ))
        .stderr(predicate::str::contains("function '' not found").not());

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .arg("run")
        .arg(temp.path())
        .args([
            "--input",
            "a=1",
            "--input",
            "a=2",
            "--input",
            "b=3",
            "--timeout-secs",
            LOCAL_MPC_TEST_TIMEOUT_SECS,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("duplicate input 'a'"))
        .stderr(predicate::str::contains("--input a=<value>"))
        .stderr(predicate::str::contains("--input b=<value>"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .arg("run")
        .arg(temp.path())
        .args(["--timeout-secs", LOCAL_MPC_TEST_TIMEOUT_SECS])
        .assert()
        .failure()
        .stderr(predicate::str::contains("missing input 'a'"))
        .stderr(predicate::str::contains(
            "Pass inputs as: stoffel run --entry main --input a=<value> --input b=<value>",
        ));

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .arg("run")
        .arg(temp.path())
        .args([
            "--input",
            "a=1",
            "--timeout-secs",
            LOCAL_MPC_TEST_TIMEOUT_SECS,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("missing input 'b'"))
        .stderr(predicate::str::contains("--input b=<value>"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .arg("run")
        .arg(temp.path())
        .args([
            "--input",
            "a=1,b=2",
            "--timeout-secs",
            LOCAL_MPC_TEST_TIMEOUT_SECS,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "looks like multiple inputs in one flag",
        ))
        .stderr(predicate::str::contains("Repeat --input"))
        .stderr(predicate::str::contains("--input b=<value>"))
        .stderr(predicate::str::contains("missing input 'b'").not());

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .arg("run")
        .arg(temp.path())
        .args([
            "--input",
            "a=1=2",
            "--input",
            "b=2",
            "--timeout-secs",
            LOCAL_MPC_TEST_TIMEOUT_SECS,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("has more than one '='"))
        .stderr(predicate::str::contains("--input a=<value>"))
        .stderr(predicate::str::contains("invalid value for input").not());

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .arg("run")
        .arg(temp.path())
        .args([
            "--input",
            "a=",
            "--timeout-secs",
            LOCAL_MPC_TEST_TIMEOUT_SECS,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("input 'a' must include a value"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .arg("run")
        .arg(temp.path())
        .args([
            "--input",
            "a=0x1",
            "--timeout-secs",
            LOCAL_MPC_TEST_TIMEOUT_SECS,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid value for input 'a'"))
        .stderr(predicate::str::contains(
            "hex byte input must contain an even number of digits",
        ));

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .arg("run")
        .arg(temp.path())
        .args([
            "--input",
            "a=1",
            "--input",
            "b=2",
            "--timeout-secs",
            LOCAL_MPC_TEST_TIMEOUT_SECS,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("3"))
        .stderr(predicate::str::contains("invalid value").not());

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .arg("run")
        .arg(temp.path())
        .args(["--input", "a=1", "--input", "b=2", "--timeout-secs", "0"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "0 is not valid here; use a positive whole number",
        ))
        .stderr(predicate::str::contains("local network timeout").not());

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .arg("run")
        .arg(temp.path())
        .args([
            "--client-input",
            "0=",
            "--timeout-secs",
            LOCAL_MPC_TEST_TIMEOUT_SECS,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "client input slot 0 must include a value",
        ));

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .arg("run")
        .arg(temp.path())
        .args([
            "--client-input",
            "0=1,1=2",
            "--timeout-secs",
            LOCAL_MPC_TEST_TIMEOUT_SECS,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "looks like multiple inputs in one flag",
        ))
        .stderr(predicate::str::contains("Repeat --client-input"))
        .stderr(predicate::str::contains("--client-input 1=<value>"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .arg("run")
        .arg(temp.path())
        .args([
            "--client-input",
            "0=1=2",
            "--timeout-secs",
            LOCAL_MPC_TEST_TIMEOUT_SECS,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("has more than one '='"))
        .stderr(predicate::str::contains("--client-input 0=<value>"))
        .stderr(predicate::str::contains("invalid value for client input").not());

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .arg("run")
        .arg(temp.path())
        .args([
            "--client-input",
            "0=0xzz",
            "--timeout-secs",
            LOCAL_MPC_TEST_TIMEOUT_SECS,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "invalid value for client input slot 0",
        ))
        .stderr(predicate::str::contains(
            "hex byte input contains invalid digits 'zz'",
        ));

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .arg("run")
        .arg(temp.path())
        .args([
            "--client-input",
            "-1=2",
            "--timeout-secs",
            LOCAL_MPC_TEST_TIMEOUT_SECS,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid client slot '-1'"))
        .stderr(predicate::str::contains("unexpected argument '-1'").not());

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .arg("run")
        .arg(temp.path())
        .args([
            "--client-input",
            "client=2",
            "--timeout-secs",
            LOCAL_MPC_TEST_TIMEOUT_SECS,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid client slot 'client'"))
        .stderr(predicate::str::contains("use a numeric slot like 0"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .arg("run")
        .arg(temp.path())
        .args(["--timeout-secs", "-1", "--input", "a=1", "--input", "b=2"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid value '-1'"))
        .stderr(predicate::str::contains("unexpected argument '-1'").not());
}

#[test]
fn run_rejects_flat_list_for_nested_list_input() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    fs::write(
        temp.path().join("src/main.stfl"),
        "def main(a: list[list[int64]], a_rows: int64, a_cols: int64) -> int64:\n  return a[0][0]\n",
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .arg("run")
        .arg(temp.path())
        .args([
            "--input",
            "a=1,2,3,4",
            "--input",
            "a_rows=1",
            "--input",
            "a_cols=4",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "input 'a[0]' expects list[int64], got i64",
        ))
        .stderr(predicate::str::contains("--input a=<value>"));
}

#[test]
fn run_explains_positional_input_mistakes() {
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("app");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(&project)
        .args(["a=40", "b=2"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "named inputs must use --input NAME=VALUE",
        ))
        .stderr(predicate::str::contains(
            "Try: stoffel run --input a=40 --input b=2",
        ));

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(&project)
        .args(["run", "a=40", "b=2"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Try: stoffel run --input a=40 --input b=2",
        ));

    fs::write(project.join("network.toml"), "protocol = \"honeybadger\"\n").unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(&project)
        .args([
            "run",
            ".",
            "network.toml",
            "--input",
            "a=40",
            "--input",
            "b=2",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "unexpected TOML config path 'network.toml' after PATH",
        ))
        .stderr(predicate::str::contains(
            "stoffel run <PROJECT> --config network.toml",
        ))
        .stderr(predicate::str::contains("named inputs must use").not());
}

#[test]
fn run_network_requires_config() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .arg("run")
        .arg("--network")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "network execution requires --config",
        ));

    fs::write(
        temp.path().join("network.toml"),
        "protocol = \"honeybadger\"\n",
    )
    .unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args(["run", "--network", "network.toml"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "network config path network.toml was passed as PATH",
        ))
        .stderr(predicate::str::contains(
            "stoffel run <PROJECT> --network --config network.toml",
        ));
}

#[test]
fn run_network_validates_config_path_before_parsing() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    write_addition_program(temp.path());

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(temp.path())
        .args(["--network", "--config", "missing.toml"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("network config")
                .and(predicate::str::contains("does not exist")),
        );

    fs::write(
        temp.path().join("network.toml"),
        "protocol = \"honeybadger\"\nparties = 5\nthreshold = 1\n",
    )
    .unwrap();
    let parent = temp.path().parent().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(parent)
        .arg("run")
        .arg(temp.path())
        .args([
            "--network",
            "--config",
            "network.toml",
            "--input",
            "a=1",
            "--input",
            "b=2",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("missing server address"))
        .stderr(predicate::str::contains("network config network.toml does not exist").not())
        .stderr(predicate::str::contains("Invalid configuration: Invalid configuration").not());

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(temp.path())
        .arg("--network")
        .arg("--config")
        .arg(temp.path().join("src/main.stfl"))
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "network config must be a .toml file",
        ));
}

#[test]
fn run_config_rejects_project_stoffel_toml() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    write_addition_program(temp.path());

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(temp.path())
        .arg("--config")
        .arg(temp.path().join("Stoffel.toml"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("not project Stoffel.toml"));

    let renamed = temp.path().join("project-config.toml");
    fs::copy(temp.path().join("Stoffel.toml"), &renamed).unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(temp.path())
        .arg("--config")
        .arg(&renamed)
        .args(["--input", "a=1", "--input", "b=2"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "looks like a Stoffel project config",
        ))
        .stderr(predicate::str::contains(
            "pass the project path as PATH instead",
        ))
        .stderr(predicate::str::contains("missing field `protocol`").not());
}

#[test]
fn run_rejects_mixed_local_and_network_only_options() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    fs::write(temp.path().join("network.toml"), "not = [valid").unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(temp.path())
        .args(["--local", "--network"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--local and --network select different execution modes",
        ))
        .stderr(predicate::str::contains("cannot be used with").not());

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(temp.path())
        .args(["--local", "--config", "network.toml"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--local cannot be used with --config",
        ))
        .stderr(predicate::str::contains("failed to parse").not());

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(temp.path())
        .args(["--client-id", "0"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--client-id only applies to network execution",
        ))
        .stderr(predicate::str::contains("missing input").not());

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(temp.path())
        .args([
            "--network",
            "--config",
            "network.toml",
            "--runner",
            "stoffel-run",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--runner only applies to local simulation",
        ))
        .stderr(predicate::str::contains("failed to parse").not());
}

#[test]
fn run_dev_and_test_validate_explicit_runner_paths_early() {
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("app");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .success();

    let missing_runner = temp.path().join("missing-stoffel-run");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(&project)
        .arg("--runner")
        .arg(&missing_runner)
        .args(["--input", "a=1", "--input", "b=2"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--runner path"))
        .stderr(predicate::str::contains("does not exist"))
        .stderr(predicate::str::contains("Unsupported SDK operation").not());

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("dev")
        .arg(&project)
        .arg("--once")
        .arg("--runner")
        .arg(&missing_runner)
        .args(["--input", "a=1", "--input", "b=2"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--runner path"))
        .stderr(predicate::str::contains("does not exist"))
        .stderr(predicate::str::contains("Unsupported SDK operation").not());

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("test")
        .arg(&project)
        .arg("--local")
        .arg("--runner")
        .arg(&missing_runner)
        .assert()
        .failure()
        .stderr(predicate::str::contains("--runner path"))
        .stderr(predicate::str::contains("does not exist"))
        .stderr(predicate::str::contains("Unsupported SDK operation").not());

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(&project)
        .arg("--runner")
        .arg(temp.path())
        .args(["--input", "a=1", "--input", "b=2"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--runner path"))
        .stderr(predicate::str::contains("is a directory"))
        .stderr(predicate::str::contains("Permission denied").not());

    #[cfg(unix)]
    {
        let non_executable = temp.path().join("not-executable");
        fs::write(&non_executable, "#!/bin/sh\nexit 0\n").unwrap();
        let mut permissions = fs::metadata(&non_executable).unwrap().permissions();
        permissions.set_mode(0o644);
        fs::set_permissions(&non_executable, permissions).unwrap();

        Command::cargo_bin("stoffel")
            .unwrap()
            .arg("run")
            .arg(&project)
            .arg("--runner")
            .arg(&non_executable)
            .args(["--input", "a=1", "--input", "b=2"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("--runner path"))
            .stderr(predicate::str::contains("is not executable"))
            .stderr(predicate::str::contains("Permission denied").not());
    }
}

#[test]
fn run_network_validates_program_before_parsing_config_contents() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    write_addition_program(temp.path());
    fs::write(temp.path().join("network.toml"), "not = [valid").unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .arg("run")
        .arg(temp.path())
        .args([
            "--network",
            "--config",
            "network.toml",
            "--entry",
            "missing",
            "--input",
            "a=1",
            "--input",
            "b=2",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "entry function 'missing' is not declared",
        ))
        .stderr(predicate::str::contains("Available source functions: main"))
        .stderr(predicate::str::contains("failed to parse").not());

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .arg("run")
        .arg(temp.path())
        .args(["--network", "--config", "network.toml", "--input", "a=1"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("missing input 'b'"))
        .stderr(predicate::str::contains(
            "Pass inputs as: stoffel run --network --entry main",
        ))
        .stderr(predicate::str::contains("failed to parse").not());

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .arg("run")
        .arg(temp.path())
        .args([
            "--network",
            "--config",
            "network.toml",
            "--client-input",
            "0=1",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--client-input and --client-input-file are only used for local ClientStore runs",
        ))
        .stderr(predicate::str::contains("failed to parse").not());
}

#[test]
fn run_network_accepts_network_config_and_attempts_connection() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    write_addition_program(temp.path());
    fs::write(
        temp.path().join("network.toml"),
        r#"
[network]
party_id = 0
bind_address = "127.0.0.1:39200"
expected_parties = 5
expected_clients = 1
consensus_timeout_ms = 1000

[network.peers]
1 = "127.0.0.1:39201"
2 = "127.0.0.1:39202"
3 = "127.0.0.1:39203"
4 = "127.0.0.1:39204"

[mpc]
threshold = 1
protocol = "honeybadger"

[preprocessing]
triples = 1
random_shares = 1
"#,
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args([
            "run",
            "--network",
            "--config",
            "network.toml",
            "--connect-timeout-ms",
            "50",
            "--input",
            "a=1",
            "--input",
            "b=2",
        ])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("failed to connect").or(predicate::str::contains("timed out")),
        );

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args([
            "run",
            "--network",
            "--config",
            "network.toml",
            "--connect-timeout-ms",
            "0",
            "--input",
            "a=1",
            "--input",
            "b=2",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "0 is not valid here; use a positive whole number",
        ))
        .stderr(predicate::str::contains("failed to connect").not());
}

#[test]
fn compile_disassembles_bytecode() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args(["compile", "-O2", "--output", "target/debug/app.stflb"])
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args(["compile", "--disassemble", "target/debug/app.stflb"])
        .assert()
        .success()
        .stdout(predicate::str::contains("main"));

    for args in [
        &[
            "compile",
            "--disassemble",
            "target/debug/app.stflb",
            "--output",
            "target/debug/ignored.stflb",
        ][..],
        &[
            "compile",
            "--disassemble",
            "target/debug/app.stflb",
            "--release",
        ][..],
        &[
            "compile",
            "--disassemble",
            "target/debug/app.stflb",
            "--parties",
            "5",
        ][..],
    ] {
        Command::cargo_bin("stoffel")
            .unwrap()
            .current_dir(temp.path())
            .args(args)
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "--disassemble reads existing bytecode",
            ))
            .stderr(predicate::str::contains("compile options"));
    }
}

#[test]
fn disassemble_rejects_source_files_with_actionable_error() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args(["compile", "--disassemble", "src/main.stfl"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--disassemble requires .stflb bytecode",
        ));

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args(["compile", "--disassemble", "missing.txt"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--disassemble requires .stflb bytecode",
        ));
}

#[test]
fn build_compiles_all_project_sources() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    fs::write(
        temp.path().join("src/second.stfl"),
        "def main() -> int64:\n  return 2\n",
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .arg("build")
        .assert()
        .success();

    let built_files = fs::read_dir(temp.path().join("target/debug"))
        .unwrap()
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("stflb"))
        .collect::<Vec<_>>();
    assert!(built_files.len() >= 2);
    assert!(temp.path().join("target/debug/second.stflb").exists());
}

#[test]
#[ignore = "heavy integration test; run with the serial heavy-test command"]
fn source_and_bytecode_extensions_are_case_insensitive() {
    let _guard = local_mpc_guard();
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    fs::write(
        temp.path().join("src/upper.STFL"),
        "def main() -> int64:\n  return 5\n",
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(temp.path().join("src/upper.STFL"))
        .assert()
        .success()
        .stdout(predicate::str::contains("upper.stflb"));
    assert!(temp.path().join("target/debug/upper.stflb").exists());

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("check")
        .arg(temp.path().join("src/upper.STFL"))
        .assert()
        .success()
        .stdout(predicate::str::contains("upper.STFL"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(temp.path().join("src/upper.STFL"))
        .args(["--timeout-secs", LOCAL_MPC_TEST_TIMEOUT_SECS])
        .assert()
        .success()
        .stdout(predicate::str::contains("5"));

    let upper_bytecode = temp.path().join("target/debug/UPPER_COPY.STFLB");
    fs::copy(
        temp.path().join("target/debug/upper.stflb"),
        &upper_bytecode,
    )
    .unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(&upper_bytecode)
        .args(["--timeout-secs", LOCAL_MPC_TEST_TIMEOUT_SECS])
        .assert()
        .success()
        .stdout(predicate::str::contains("5"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["compile", "--disassemble"])
        .arg(&upper_bytecode)
        .assert()
        .success()
        .stdout(predicate::str::contains(".function main"));
}

#[test]
fn build_preserves_nested_source_paths_to_avoid_artifact_collisions() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    fs::create_dir_all(temp.path().join("src/a")).unwrap();
    fs::create_dir_all(temp.path().join("src/b")).unwrap();
    fs::write(
        temp.path().join("src/a/calc.stfl"),
        "def main() -> int64:\n  return 1\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("src/b/calc.stfl"),
        "def main() -> int64:\n  return 2\n",
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(temp.path())
        .assert()
        .success();

    assert!(temp.path().join("target/debug/a/calc.stflb").exists());
    assert!(temp.path().join("target/debug/b/calc.stflb").exists());
}

#[test]
fn build_and_check_accept_project_folder_paths() {
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("app");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(&project)
        .assert()
        .success()
        .stdout(predicate::str::contains("Built"));
    assert!(project.join("target/debug/app.stflb").exists());

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("check")
        .arg(&project)
        .assert()
        .success()
        .stdout(predicate::str::contains("Checked"));
}

#[test]
fn build_and_check_explain_extra_positional_paths() {
    for command in ["check", "compile", "build"] {
        Command::cargo_bin("stoffel")
            .unwrap()
            .args([command, "src/main.stfl", "extra.stfl"])
            .assert()
            .failure()
            .stderr(predicate::str::contains(format!(
                "stoffel {command} accepts one PATH"
            )))
            .stderr(predicate::str::contains(
                "Use `stoffel ".to_owned() + command + " <PROJECT_DIR>`",
            ))
            .stderr(predicate::str::contains("unexpected argument").not());
    }
}

#[test]
fn build_and_check_do_not_ignore_explicit_empty_source_directories() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    fs::create_dir_all(temp.path().join("empty-src")).unwrap();
    fs::create_dir_all(temp.path().join("more-src")).unwrap();
    fs::write(
        temp.path().join("more-src/extra.stfl"),
        "def main() -> int64:\n  return 7\n",
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(temp.path().join("more-src"))
        .assert()
        .success()
        .stdout(predicate::str::contains("extra.stflb"));

    for command in ["build", "check"] {
        Command::cargo_bin("stoffel")
            .unwrap()
            .arg(command)
            .arg(temp.path().join("empty-src"))
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "no .stfl source files found under",
            ))
            .stderr(predicate::str::contains("pass project directory"))
            .stderr(predicate::str::contains("src/main.stfl").not());
    }
}

#[test]
fn build_output_is_relative_to_project_root() {
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("app");
    let workdir = temp.path().join("work");
    fs::create_dir_all(&workdir).unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(&workdir)
        .arg("build")
        .arg(&project)
        .args(["--output", "target/debug/custom.stflb"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            project
                .join("target/debug/custom.stflb")
                .display()
                .to_string(),
        ));

    assert!(project.join("target/debug/custom.stflb").exists());
    assert!(!workdir.join("target/debug/custom.stflb").exists());
}

#[test]
fn build_missing_configured_source_reports_path() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    fs::remove_file(temp.path().join("src/main.stfl")).unwrap();

    for command in ["build", "check"] {
        Command::cargo_bin("stoffel")
            .unwrap()
            .arg(command)
            .arg(temp.path())
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "configured build.source src/main.stfl does not exist",
            ))
            .stderr(predicate::str::contains("IO error").not());
    }
}

#[test]
fn build_respects_configured_source_directory_paths() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    let config = fs::read_to_string(temp.path().join("Stoffel.toml")).unwrap();
    fs::write(
        temp.path().join("Stoffel.toml"),
        config.replace("source = \"src/main.stfl\"", "source = \"programs\""),
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("check")
        .arg(temp.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "configured build.source programs does not exist",
        ))
        .stderr(predicate::str::contains("src/main.stfl").not());

    fs::create_dir_all(temp.path().join("programs")).unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("check")
        .arg(temp.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "no .stfl source files found under configured build.source programs",
        ))
        .stderr(predicate::str::contains("src/main.stfl").not());

    fs::write(
        temp.path().join("programs/app.stfl"),
        "def main() -> int64:\n  return 7\n",
    )
    .unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("check")
        .arg(temp.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("programs/app.stfl"))
        .stdout(predicate::str::contains("src/main.stfl").not());
}

#[test]
fn build_accepts_uppercase_configured_source_extension() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    fs::write(
        temp.path().join("src/upper.STFL"),
        "def main() -> int64:\n  return 7\n",
    )
    .unwrap();
    let config = fs::read_to_string(temp.path().join("Stoffel.toml")).unwrap();
    fs::write(
        temp.path().join("Stoffel.toml"),
        config.replace("source = \"src/main.stfl\"", "source = \"src/upper.STFL\""),
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("check")
        .arg(temp.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("src/upper.STFL"));
}

#[test]
fn build_rejects_configured_source_with_wrong_extension() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    let config = fs::read_to_string(temp.path().join("Stoffel.toml")).unwrap();
    fs::write(
        temp.path().join("Stoffel.toml"),
        config.replace("source = \"src/main.stfl\"", "source = \"src/main.txt\""),
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(temp.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "invalid build.source src/main.txt",
        ))
        .stderr(predicate::str::contains(
            "expected a .stfl source file or source directory",
        ));
}

#[test]
fn build_rejects_unsafe_configured_source_paths() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    let config = fs::read_to_string(temp.path().join("Stoffel.toml")).unwrap();

    for (source, expected) in [
        (".", "choose a source file like src/main.stfl"),
        ("..", "source paths must stay inside the project"),
        ("../other", "source paths must stay inside the project"),
    ] {
        fs::write(
            temp.path().join("Stoffel.toml"),
            config.replace(
                "source = \"src/main.stfl\"",
                &format!("source = \"{source}\""),
            ),
        )
        .unwrap();
        Command::cargo_bin("stoffel")
            .unwrap()
            .arg("build")
            .arg(temp.path())
            .assert()
            .failure()
            .stderr(predicate::str::contains("invalid build.source"))
            .stderr(predicate::str::contains(expected));
    }

    let absolute_source = temp.path().join("src/main.stfl");
    fs::write(
        temp.path().join("Stoffel.toml"),
        config.replace(
            "source = \"src/main.stfl\"",
            &format!("source = \"{}\"", absolute_source.display()),
        ),
    )
    .unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(temp.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid build.source"))
        .stderr(predicate::str::contains(
            "expected a relative path inside the project",
        ));
}

#[test]
fn build_rejects_unsafe_configured_target_dir() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    let config = fs::read_to_string(temp.path().join("Stoffel.toml")).unwrap();

    for (target_dir, expected) in [
        ("src", "must not be written under src/"),
        (".", "choose a dedicated build directory"),
        ("..", "build artifacts must stay inside the project"),
        ("target/..", "build artifacts must stay inside the project"),
    ] {
        fs::write(
            temp.path().join("Stoffel.toml"),
            config.replace(
                "target_dir = \"target\"",
                &format!("target_dir = \"{target_dir}\""),
            ),
        )
        .unwrap();
        Command::cargo_bin("stoffel")
            .unwrap()
            .arg("build")
            .arg(temp.path())
            .assert()
            .failure()
            .stderr(predicate::str::contains("invalid build.target_dir"))
            .stderr(predicate::str::contains(expected));
    }

    let absolute_src_target = temp.path().join("src/build");
    fs::write(
        temp.path().join("Stoffel.toml"),
        config.replace(
            "target_dir = \"target\"",
            &format!("target_dir = \"{}\"", absolute_src_target.display()),
        ),
    )
    .unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(temp.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid build.target_dir"))
        .stderr(predicate::str::contains(
            "expected a relative directory inside the project",
        ));

    fs::write(temp.path().join("build-file"), "").unwrap();
    fs::write(
        temp.path().join("Stoffel.toml"),
        config.replace("target_dir = \"target\"", "target_dir = \"build-file\""),
    )
    .unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(temp.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "invalid build.target_dir build-file",
        ))
        .stderr(predicate::str::contains("is an existing file"));

    fs::write(temp.path().join("parent-file"), "").unwrap();
    fs::write(
        temp.path().join("Stoffel.toml"),
        config.replace(
            "target_dir = \"target\"",
            "target_dir = \"parent-file/target\"",
        ),
    )
    .unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(temp.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "invalid build.target_dir parent-file/target",
        ))
        .stderr(predicate::str::contains("parent-file"))
        .stderr(predicate::str::contains("is an existing file"))
        .stderr(predicate::str::contains("os error").not());
}

#[cfg(unix)]
#[test]
fn build_rejects_configured_target_through_intermediate_symlink() {
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("project");
    let outside = temp.path().join("outside");
    fs::create_dir_all(&outside).unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .success();

    std::os::unix::fs::symlink(&outside, project.join("escape")).unwrap();
    let config = fs::read_to_string(project.join("Stoffel.toml")).unwrap();
    fs::write(
        project.join("Stoffel.toml"),
        config.replace("target_dir = \"target\"", "target_dir = \"escape/target\""),
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(&project)
        .assert()
        .failure()
        .stderr(predicate::str::contains("symlink"));
    assert!(!outside.join("target").exists());
}

#[test]
fn build_rejects_configured_optimization_levels_outside_cli_range() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    let config = fs::read_to_string(temp.path().join("Stoffel.toml")).unwrap();
    fs::write(
        temp.path().join("Stoffel.toml"),
        config.replace(
            "target_dir = \"target\"",
            "target_dir = \"target\"\noptimization_level = 9",
        ),
    )
    .unwrap();

    for command in ["check", "build", "run", "status"] {
        let mut cmd = Command::cargo_bin("stoffel").unwrap();
        cmd.arg(command).arg(temp.path());
        if command == "run" {
            cmd.args(["--input", "a=1", "--input", "b=2"]);
        }
        cmd.assert()
            .failure()
            .stderr(predicate::str::contains(
                "invalid build.optimization_level 9",
            ))
            .stderr(predicate::str::contains(
                "expected an optimization level from 0 to 3",
            ));
    }
}

#[test]
fn build_invalid_mpc_flags_report_configuration_context() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(temp.path())
        .args(["--parties", "3", "--threshold", "1"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to compile or configure"))
        .stderr(predicate::str::contains("parties must be at least 5"))
        .stderr(predicate::str::contains("4 * threshold + 1"));
}

#[test]
fn project_config_rejects_invalid_mpc_values_before_running() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    let config = fs::read_to_string(temp.path().join("Stoffel.toml")).unwrap();

    fs::write(
        temp.path().join("Stoffel.toml"),
        config.replace("threshold = 1", "threshold = 0"),
    )
    .unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("check")
        .arg(temp.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid [mpc] config"))
        .stderr(predicate::str::contains(
            "threshold must be greater than zero",
        ));
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(temp.path())
        .args(["--input", "a=40", "--input", "b=2"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid [mpc] config"))
        .stderr(predicate::str::contains(
            "threshold must be greater than zero",
        ));

    fs::write(
        temp.path().join("Stoffel.toml"),
        config.replace("parties = 5", "parties = 3"),
    )
    .unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("status")
        .arg(temp.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid [mpc] config"))
        .stderr(predicate::str::contains("parties must be at least 5"));
}

#[test]
fn project_config_numeric_type_errors_include_actionable_hints() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    let original = fs::read_to_string(temp.path().join("Stoffel.toml")).unwrap();

    for (config, hint) in [
        (
            original.replace("parties = 5", "parties = \"5\""),
            "write [mpc].parties as an unquoted positive whole number",
        ),
        (
            original.replace("threshold = 1", "threshold = -1"),
            "write [mpc].threshold as an unquoted positive whole number",
        ),
    ] {
        fs::write(temp.path().join("Stoffel.toml"), config).unwrap();
        Command::cargo_bin("stoffel")
            .unwrap()
            .arg("check")
            .arg(temp.path())
            .assert()
            .failure()
            .stderr(predicate::str::contains("failed to parse"))
            .stderr(predicate::str::contains("Hint:"))
            .stderr(predicate::str::contains(hint));
    }
}

#[test]
fn cli_mpc_overrides_reject_zero_values_before_execution() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();

    for command in ["check", "build"] {
        Command::cargo_bin("stoffel")
            .unwrap()
            .arg(command)
            .arg(temp.path())
            .args(["--threshold", "0"])
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "0 is not valid here; use a positive whole number",
            ))
            .stderr(predicate::str::contains("failed to compile").not());
    }

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(temp.path())
        .args(["--threshold", "0", "--input", "a=1", "--input", "b=2"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "0 is not valid here; use a positive whole number",
        ))
        .stderr(predicate::str::contains("local network timeout must be greater than zero").not());

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("dev")
        .arg(temp.path())
        .args([
            "--once",
            "--parties",
            "0",
            "--input",
            "a=1",
            "--input",
            "b=2",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "0 is not valid here; use a positive whole number",
        ))
        .stderr(predicate::str::contains("failed to compile").not());

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(temp.path())
        .assert()
        .success();
    let bytecode = fs::read_dir(temp.path().join("target/debug"))
        .unwrap()
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .find(|path| path.extension().and_then(|extension| extension.to_str()) == Some("stflb"))
        .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(bytecode)
        .args(["--threshold", "0", "--input", "a=1", "--input", "b=2"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "0 is not valid here; use a positive whole number",
        ))
        .stderr(predicate::str::contains("could not load bytecode").not());

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(temp.path())
        .args(["--parties", "-1"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "'-1' is not valid here; use a positive whole number",
        ))
        .stderr(predicate::str::contains("unexpected argument '-1'").not());

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("dev")
        .arg(temp.path())
        .args(["--poll-ms", "-1"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "'-1' is not valid here; use a positive whole number",
        ))
        .stderr(predicate::str::contains("unexpected argument '-1'").not());
}

#[test]
fn run_broken_source_reports_command_and_path_context() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    fs::write(temp.path().join("src/main.stfl"), "def main(\n").unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(temp.path())
        .args(["--timeout-secs", LOCAL_MPC_TEST_TIMEOUT_SECS])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "stoffel run could not compile or load",
        ))
        .stderr(predicate::str::contains(temp.path().display().to_string()))
        .stderr(predicate::str::contains("Syntax"));
}

#[test]
fn explicit_wrong_file_types_report_actionable_errors() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(temp.path())
        .args(["--output", "target/debug/app.stflb"])
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(temp.path().join("README.md"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("expected a .stfl source file"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("check")
        .arg(temp.path().join("target/debug/app.stflb"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("expected a .stfl source file"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(temp.path().join("README.md"))
        .args(["--timeout-secs", LOCAL_MPC_TEST_TIMEOUT_SECS])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "expected a .stfl source file, .stflb bytecode file, or project directory",
        ));

    for command in ["build", "check"] {
        Command::cargo_bin("stoffel")
            .unwrap()
            .arg(command)
            .arg(temp.path().join("Stoffel.toml"))
            .assert()
            .failure()
            .stderr(predicate::str::contains("got project config"))
            .stderr(predicate::str::contains(
                "pass the project directory instead",
            ));
    }

    let network_config = temp.path().join("network.toml");
    fs::write(&network_config, "protocol = \"honeybadger\"\n").unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(&network_config)
        .args([
            "--input",
            "a=1",
            "--input",
            "b=2",
            "--timeout-secs",
            LOCAL_MPC_TEST_TIMEOUT_SECS,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("got TOML config"))
        .stderr(predicate::str::contains(
            "use `stoffel run <PROJECT> --config",
        ))
        .stderr(predicate::str::contains("could not find Stoffel.toml").not());

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(&network_config)
        .assert()
        .failure()
        .stderr(predicate::str::contains("got TOML config"))
        .stderr(predicate::str::contains(
            "build/check expect a project directory",
        ))
        .stderr(predicate::str::contains("could not find Stoffel.toml").not());
}

#[test]
fn build_rejects_output_directory() {
    let temp = TempDir::new().unwrap();
    let output_dir = temp.path().join("outdir");
    fs::create_dir_all(&output_dir).unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(temp.path())
        .arg("--output")
        .arg(&output_dir)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--output must be a .stflb bytecode file path",
        ));

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(temp.path())
        .args(["--output", "out.txt"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--output must end in .stflb"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(temp.path())
        .args(["--output", "target/debug"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--output must end in .stflb"));

    let outside_output = format!(
        "../{}-outside.stflb",
        temp.path().file_name().unwrap().to_string_lossy()
    );
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(temp.path())
        .args(["--output", outside_output.as_str()])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--output must not contain parent-directory segments",
        ));
    assert!(!temp.path().join(outside_output).exists());

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(temp.path())
        .args(["--output", "src/generated.stflb"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--output must not write bytecode under src/",
        ));
    assert!(!temp.path().join("src/generated.stflb").exists());

    let parent_file = temp.path().join("parent-file");
    fs::write(&parent_file, "not a directory").unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(temp.path())
        .args(["--output", "parent-file/app.stflb"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--output parent path"))
        .stderr(predicate::str::contains("is a file, not a directory"))
        .stderr(predicate::str::contains("os error").not());
}

#[test]
fn explicit_missing_path_reports_missing_path() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(temp.path().join("missing"))
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("missing").and(predicate::str::contains("does not exist")),
        );

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path().join("app"))
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(temp.path().join("app/src/mian.stfl"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("mian.stfl does not exist"))
        .stderr(predicate::str::contains("did you mean"))
        .stderr(predicate::str::contains("main.stfl"));
}

#[test]
fn run_missing_bytecode_artifact_suggests_building_first() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(temp.path().join("target/debug/app.stflb"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not exist"))
        .stderr(predicate::str::contains("run `stoffel build` first"))
        .stderr(predicate::str::contains("pass a project/source path"))
        .stderr(predicate::str::contains("failed to load bytecode").not());
}

#[test]
fn run_invalid_bytecode_suggests_rebuilding_or_using_source() {
    let temp = TempDir::new().unwrap();
    let bytecode = temp.path().join("bad.stflb");
    fs::write(&bytecode, "not bytecode").unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(&bytecode)
        .args(["--timeout-secs", LOCAL_MPC_TEST_TIMEOUT_SECS])
        .assert()
        .failure()
        .stderr(predicate::str::contains("could not load bytecode"))
        .stderr(predicate::str::contains("run `stoffel build`"))
        .stderr(predicate::str::contains("pass a .stfl source/project path"))
        .stderr(predicate::str::contains("InvalidMagicBytes"));
}

#[test]
fn run_auto_discovered_invalid_bytecode_suggests_rebuilding() {
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("app");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .success();
    let bytecode = project.join("target/debug/app.stflb");
    fs::create_dir_all(bytecode.parent().unwrap()).unwrap();
    thread::sleep(Duration::from_secs(1));
    fs::write(&bytecode, "not bytecode").unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(&project)
        .args([
            "--timeout-secs",
            LOCAL_MPC_TEST_TIMEOUT_SECS,
            "--input",
            "a=1",
            "--input",
            "b=2",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("could not load bytecode"))
        .stderr(predicate::str::contains("run `stoffel build`"))
        .stderr(predicate::str::contains("InvalidMagicBytes"));
}

#[test]
fn project_discovery_errors_name_the_search_directory() {
    let temp = TempDir::new().unwrap();
    for command in ["run", "build", "status", "clean", "update"] {
        let mut cmd = Command::cargo_bin("stoffel").unwrap();
        cmd.current_dir(temp.path()).arg(command);
        if command == "update" {
            cmd.arg("--check");
        }
        cmd.assert()
            .failure()
            .stderr(predicate::str::contains("could not find Stoffel.toml"))
            .stderr(predicate::str::contains(temp.path().display().to_string()))
            .stderr(predicate::str::contains("run `stoffel init` first"))
            .stderr(predicate::str::contains("pass a project path"));
    }
}

#[test]
fn init_supports_declared_templates_and_library_mode() {
    let temp = TempDir::new().unwrap();
    for (name, marker, readme_markers) in [
        (
            "python",
            "requirements.txt",
            &["stoffel run", "python3 -m pip install -r requirements.txt"][..],
        ),
        (
            "rust",
            "Cargo.toml",
            &[
                "stoffel check stoffel",
                "stoffel run stoffel --input a=40 --input b=2",
                "cargo run",
            ][..],
        ),
        (
            "solidity-foundry",
            "foundry.toml",
            &["stoffel run", "forge build"][..],
        ),
        (
            "solidity-hardhat",
            "hardhat.config.js",
            &["stoffel run", "npm install", "npx hardhat compile"][..],
        ),
    ] {
        let path = temp.path().join(name);
        Command::cargo_bin("stoffel")
            .unwrap()
            .args(["init", path.to_str().unwrap(), "--template", name])
            .assert()
            .success();
        assert!(path.join(marker).exists());
        let readme = fs::read_to_string(path.join("README.md")).unwrap();
        for marker in readme_markers {
            assert!(
                readme.contains(marker),
                "{name} README should contain `{marker}`"
            );
        }
        if name == "rust" {
            let cargo_toml = fs::read_to_string(path.join("Cargo.toml")).unwrap();
            assert!(cargo_toml.contains("tokio"));
            let main_rs = fs::read_to_string(path.join("src/main.rs")).unwrap();
            assert!(main_rs.contains("execute_local()"));
            assert!(main_rs.contains("await?"));
            assert!(!main_rs.contains("execute_clear"));
            let program = fs::read_to_string(path.join("stoffel/src/program.stfl")).unwrap();
            assert!(program.contains("secret int64"));
        }
        if name != "rust" {
            let program = fs::read_to_string(path.join("src/main.stfl")).unwrap();
            assert!(program.contains("secret bool"));
        }
    }

    for (name, marker) in [
        ("py", "requirements.txt"),
        ("foundry", "foundry.toml"),
        ("hardhat", "hardhat.config.js"),
        ("solidity_foundry", "foundry.toml"),
        ("solidity_hardhat", "hardhat.config.js"),
        ("Solidity-Foundry", "foundry.toml"),
        ("SOLIDITY-HARDHAT", "hardhat.config.js"),
    ] {
        let path = temp.path().join(format!("mixed-{name}"));
        Command::cargo_bin("stoffel")
            .unwrap()
            .args(["init", path.to_str().unwrap(), "--template", name])
            .assert()
            .success();
        assert!(path.join(marker).exists());
    }

    let library = temp.path().join("library");
    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["init", library.to_str().unwrap(), "--lib"])
        .assert()
        .success();
    assert!(library.join("src/lib.stfl").exists());
    let readme = fs::read_to_string(library.join("README.md")).unwrap();
    assert!(readme.contains("stoffel check"));
    assert!(readme.contains("stoffel build"));
    assert!(!readme.contains("stoffel run"));
}

#[test]
fn init_rejects_javascript_and_typescript_templates_as_unknown() {
    let temp = TempDir::new().unwrap();
    for template in ["typescript", "ts", "javascript", "js"] {
        Command::cargo_bin("stoffel")
            .unwrap()
            .arg("init")
            .arg(temp.path().join(format!("app-{template}")))
            .args(["--template", template])
            .assert()
            .failure()
            .stderr(predicate::str::contains(format!(
                "unknown template `{template}`"
            )))
            .stderr(predicate::str::contains("solidity-foundry"))
            .stderr(predicate::str::contains("solidity-hardhat"))
            .stderr(predicate::str::contains("Did you mean").not());
    }

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path().join("app-foundary"))
        .args(["--template", "foundary"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown template `foundary`"))
        .stderr(predicate::str::contains("Did you mean `foundry`?"));
}

#[test]
fn init_sanitizes_generated_project_names_for_manifests() {
    let temp = TempDir::new().unwrap();

    let plain = temp.path().join("!!!");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&plain)
        .assert()
        .success();
    assert!(fs::read_to_string(plain.join("Stoffel.toml"))
        .unwrap()
        .contains("name = \"stoffel-app\""));

    let hardhat = temp.path().join("My App");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&hardhat)
        .args(["--template", "solidity-hardhat"])
        .assert()
        .success();
    assert!(fs::read_to_string(hardhat.join("package.json"))
        .unwrap()
        .contains("\"name\": \"my-app\""));
    assert!(fs::read_to_string(hardhat.join("Stoffel.toml"))
        .unwrap()
        .contains("name = \"my-app\""));

    let rust = temp.path().join("--Rust_App--");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&rust)
        .args(["--template", "rust"])
        .assert()
        .success();
    assert!(fs::read_to_string(rust.join("Cargo.toml"))
        .unwrap()
        .contains("name = \"rust-app\""));
    assert!(fs::read_to_string(rust.join("stoffel/Stoffel.toml"))
        .unwrap()
        .contains("name = \"rust-app\""));
}

#[test]
fn nested_template_project_errors_suggest_nested_stoffel_path() {
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("rust-app");
    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["init", project.to_str().unwrap(), "--template", "rust"])
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("run")
        .arg(&project)
        .args(["--timeout-secs", LOCAL_MPC_TEST_TIMEOUT_SECS])
        .assert()
        .failure()
        .stderr(predicate::str::contains("found nested Stoffel project"))
        .stderr(predicate::str::contains(
            project.join("stoffel").display().to_string(),
        ))
        .stderr(predicate::str::contains("Pass one of those project paths"));
}

#[test]
fn init_rejects_library_with_template() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .args([
            "init",
            temp.path().join("lib-rust").to_str().unwrap(),
            "--lib",
            "--template",
            "rust",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn init_errors_explain_existing_project_vs_nonempty_directory() {
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("app");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .failure()
        .stderr(predicate::str::contains("already contains Stoffel.toml"))
        .stderr(predicate::str::contains("stoffel status"))
        .stderr(predicate::str::contains("stoffel run"))
        .stderr(predicate::str::contains("refresh template files"));

    let non_project = temp.path().join("non-project");
    fs::create_dir_all(&non_project).unwrap();
    fs::write(non_project.join("notes.txt"), "keep me").unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&non_project)
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists and is not empty"))
        .stderr(predicate::str::contains("Stoffel template files"))
        .stderr(predicate::str::contains("preserving unrelated files"));

    let file_target = temp.path().join("not-a-directory");
    fs::write(&file_target, "notes").unwrap();
    for args in [
        vec!["init", file_target.to_str().unwrap()],
        vec!["init", file_target.to_str().unwrap(), "--force"],
        vec!["init", file_target.to_str().unwrap(), "--lib"],
    ] {
        Command::cargo_bin("stoffel")
            .unwrap()
            .args(args)
            .assert()
            .failure()
            .stderr(predicate::str::contains("is a file"))
            .stderr(predicate::str::contains(
                "pass a directory path for the new Stoffel project",
            ));
    }

    for file_like in [
        temp.path().join("main.stfl"),
        temp.path().join("program.stflb"),
        temp.path().join("Stoffel.toml"),
        temp.path().join("README.md"),
    ] {
        Command::cargo_bin("stoffel")
            .unwrap()
            .arg("init")
            .arg(&file_like)
            .assert()
            .failure()
            .stderr(predicate::str::contains("looks like a file path"))
            .stderr(predicate::str::contains(
                "`stoffel init` creates a project directory",
            ));
        assert!(!file_like.exists());
    }

    let parent_file = temp.path().join("parent-file");
    fs::write(&parent_file, "not a directory").unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(parent_file.join("child"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("parent path"))
        .stderr(predicate::str::contains("is a file, not a directory"))
        .stderr(predicate::str::contains("os error 20").not());

    let template_parent_file = temp.path().join("template-parent-file");
    fs::create_dir_all(&template_parent_file).unwrap();
    fs::write(template_parent_file.join("src"), "not a directory").unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&template_parent_file)
        .arg("--force")
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot write"))
        .stderr(predicate::str::contains("parent path"))
        .stderr(predicate::str::contains("is a file, not a directory"))
        .stderr(predicate::str::contains("os error").not());
}

#[test]
fn init_force_refreshes_existing_template_files() {
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("app");
    fs::create_dir_all(&project).unwrap();
    fs::write(project.join("Stoffel.toml"), "not toml = ").unwrap();
    fs::write(project.join("notes.txt"), "keep me").unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .arg("--force")
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("status")
        .arg(&project)
        .assert()
        .success()
        .stdout(predicate::str::contains("Config: ok"));
    assert_eq!(
        fs::read_to_string(project.join("notes.txt")).unwrap(),
        "keep me"
    );
}

#[test]
fn project_config_rejects_unknown_fields_instead_of_hiding_typos() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();

    let original = fs::read_to_string(temp.path().join("Stoffel.toml")).unwrap();
    for (replacement, expected, hint) in [
        (
            "sorce = \"src/main.stfl\"",
            "unknown field `sorce`",
            "did you mean [build].source?",
        ),
        (
            "threshhold = 1",
            "unknown field `threshhold`",
            "did you mean [mpc].threshold?",
        ),
        (
            "naem = ",
            "unknown field `naem`",
            "did you mean [package].name?",
        ),
    ] {
        let config = if replacement.starts_with("sorce") {
            original.replace("source = \"src/main.stfl\"", replacement)
        } else if replacement.starts_with("threshhold") {
            original.replace("threshold = 1", replacement)
        } else {
            original.replace("name = ", replacement)
        };
        fs::write(temp.path().join("Stoffel.toml"), config).unwrap();

        Command::cargo_bin("stoffel")
            .unwrap()
            .arg("check")
            .arg(temp.path())
            .assert()
            .failure()
            .stderr(predicate::str::contains("failed to parse"))
            .stderr(predicate::str::contains(expected))
            .stderr(predicate::str::contains(hint));
    }
}

#[test]
fn project_config_unknown_field_errors_suggest_common_config_names() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();

    let original = fs::read_to_string(temp.path().join("Stoffel.toml")).unwrap();
    for (config, expected, hint) in [
        (
            original.replace("parties = 5", "party_count = 5"),
            "unknown field `party_count`",
            "did you mean [mpc].parties?",
        ),
        (
            original.replace(
                "target_dir = \"target\"",
                "target_dir = \"target\"\ninstance_id = 0",
            ),
            "unknown field `instance_id`",
            "did you mean [mpc].instance_id?",
        ),
        (
            original.replace("source = \"src/main.stfl\"", "main = \"src/main.stfl\""),
            "unknown field `main`",
            "did you mean [build].source?",
        ),
        (
            original.replace("target_dir = \"target\"", "target = \"target\""),
            "unknown field `target`",
            "did you mean [build].target_dir or [build].output_dir?",
        ),
        (
            original.replace("[mpc]", "[network]"),
            "unknown field `network`",
            "Network execution config is passed to `stoffel run --config`",
        ),
    ] {
        fs::write(temp.path().join("Stoffel.toml"), config).unwrap();
        Command::cargo_bin("stoffel")
            .unwrap()
            .arg("check")
            .arg(temp.path())
            .assert()
            .failure()
            .stderr(predicate::str::contains("failed to parse"))
            .stderr(predicate::str::contains(expected))
            .stderr(predicate::str::contains(hint));
    }
}

#[test]
fn project_config_rejects_missing_or_unsafe_package_metadata() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();

    let original = fs::read_to_string(temp.path().join("Stoffel.toml")).unwrap();
    let name_line = original
        .lines()
        .find(|line| line.starts_with("name = "))
        .unwrap();
    let version_line = original
        .lines()
        .find(|line| line.starts_with("version = "))
        .unwrap();
    for (config, expected) in [
        (
            original.replace("[package]\nname = \"", "[project]\nname = \""),
            "unknown field `project`",
        ),
        (
            original.replace(&format!("[package]\n{name_line}\n{version_line}\n\n"), ""),
            "missing [package] table",
        ),
        (
            original.replace(name_line, "name = \"\""),
            "project name cannot be empty",
        ),
        (
            original.replace(name_line, "name = \"nested/app\""),
            "use only letters, numbers",
        ),
        (
            original.replace(name_line, "name = \".\""),
            "use only letters, numbers",
        ),
        (
            original.replace(name_line, "name = \"app name\""),
            "use only letters, numbers",
        ),
        (
            original.replace(version_line, "version = \"\""),
            "version cannot be empty",
        ),
    ] {
        fs::write(temp.path().join("Stoffel.toml"), config).unwrap();
        Command::cargo_bin("stoffel")
            .unwrap()
            .arg("build")
            .arg(temp.path())
            .assert()
            .failure()
            .stderr(predicate::str::contains(expected));
        assert!(!temp.path().join("target/debug/nested/app.stflb").exists());
        assert!(!temp.path().join("target/debug/..stflb").exists());
    }
}

#[test]
fn project_config_accepts_documented_alias_fields() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    let config = fs::read_to_string(temp.path().join("Stoffel.toml"))
        .unwrap()
        .replace("backend = \"honeybadger\"", "protocol = \"honeybadger\"")
        .replace("target_dir = \"target\"", "output_dir = \"out\"");
    fs::write(temp.path().join("Stoffel.toml"), config).unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("build")
        .arg(temp.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("/out/debug/"));
}

#[test]
fn test_discovers_stfl_tests() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    fs::create_dir_all(temp.path().join("tests")).unwrap();
    fs::write(
        temp.path().join("tests/add.stfl"),
        "def main() -> int64:\n  return 7\n",
    )
    .unwrap();
    fs::create_dir_all(temp.path().join("tests/math/nested")).unwrap();
    fs::write(
        temp.path().join("tests/math/nested/mul.stfl"),
        "def main() -> int64:\n  return 9\n",
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .arg("test")
        .assert()
        .success()
        .stdout(predicate::str::contains("add.stfl"))
        .stdout(predicate::str::contains("mul.stfl"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args(["test", "--test", "mul"])
        .assert()
        .success()
        .stdout(predicate::str::contains("mul.stfl"))
        .stdout(predicate::str::contains("add.stfl").not());

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args(["test", "--test", ""])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--test value cannot be empty"))
        .stderr(predicate::str::contains("No Stoffel tests matched").not());

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args(["test", "mul"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "To select a test by function name or file stem",
        ))
        .stderr(predicate::str::contains("stoffel test --test mul"));
}

#[test]
fn test_rejects_parameterized_programs_with_run_guidance() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    write_addition_program(temp.path());

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("test")
        .arg(temp.path().join("src/main.stfl"))
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "stoffel test only runs no-argument test functions",
        ))
        .stderr(predicate::str::contains("requires inputs: a, b"))
        .stderr(predicate::str::contains("stoffel run"))
        .stderr(predicate::str::contains("--input a=<value>"))
        .stderr(predicate::str::contains("--input b=<value>"));
}

#[test]
fn test_rejects_run_only_flags_with_actionable_guidance() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    fs::create_dir_all(temp.path().join("tests")).unwrap();
    fs::write(
        temp.path().join("tests/basic.stfl"),
        "def main() -> int64:\n  return 7\n",
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("test")
        .arg(temp.path())
        .args(["--input", "a=1"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "stoffel test does not accept --input values",
        ))
        .stderr(predicate::str::contains(
            "stoffel run <PATH> --input NAME=VALUE",
        ));

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("test")
        .arg(temp.path())
        .args(["--entry", "main"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "stoffel test does not use --entry",
        ))
        .stderr(predicate::str::contains("stoffel test --test <name>"))
        .stderr(predicate::str::contains(
            "stoffel run <PATH> --entry <name>",
        ));

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("test")
        .arg(temp.path())
        .args(["--runner", "stoffel-run"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--runner only applies to local MPC tests",
        ))
        .stderr(predicate::str::contains("Add --local"));
}

#[test]
fn test_rejects_files_without_declared_default_entry() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    fs::create_dir_all(temp.path().join("tests")).unwrap();
    fs::write(temp.path().join("tests/empty.stfl"), "").unwrap();
    fs::write(
        temp.path().join("tests/helper.stfl"),
        "def helper() -> int64:\n  return 1\n",
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("test")
        .arg(temp.path().join("tests/empty.stfl"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("test entry 'main' not declared"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("test")
        .arg(temp.path().join("tests/helper.stfl"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("test entry 'main' not declared"))
        .stderr(predicate::str::contains("available functions:"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("test")
        .arg(temp.path())
        .arg("--test")
        .arg("helper")
        .assert()
        .success()
        .stdout(predicate::str::contains("helper.stfl => 1"));
}

#[test]
fn test_rejects_non_source_file_paths() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    fs::write(temp.path().join("notes.txt"), "not a Stoffel test").unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("test")
        .arg(temp.path().join("notes.txt"))
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "expected a .stfl test file or project directory",
        ));
}

#[test]
fn test_accepts_project_folder_path() {
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("app");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .success();
    fs::create_dir_all(project.join("tests")).unwrap();
    fs::write(
        project.join("tests/add.stfl"),
        "def main() -> int64:\n  return 7\n",
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("test")
        .arg(&project)
        .assert()
        .success()
        .stdout(predicate::str::contains("add.stfl"));
}

#[test]
fn test_empty_filters_explain_what_was_searched() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    fs::create_dir_all(temp.path().join("tests")).unwrap();
    fs::write(
        temp.path().join("tests/basic.stfl"),
        "def main() -> int64:\n  return 1\n",
    )
    .unwrap();
    fs::create_dir_all(temp.path().join("tests/nested")).unwrap();
    fs::write(
        temp.path().join("tests/nested/basic_integration.stfl"),
        "def main() -> int64:\n  return 2\n",
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("test")
        .arg(temp.path())
        .arg("--integration")
        .assert()
        .success()
        .stdout(predicate::str::contains("basic_integration.stfl"))
        .stdout(predicate::str::contains("basic.stfl").not());
}

#[test]
fn test_flag_selects_specific_test_file() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    fs::create_dir_all(temp.path().join("tests")).unwrap();
    fs::write(
        temp.path().join("tests/selected.stfl"),
        "def main() -> int64:\n  return 42\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("tests/ignored.stfl"),
        "def main() -> int64:\n  return 7\n",
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args(["test", "--test", "selected"])
        .assert()
        .success()
        .stdout(predicate::str::contains("selected.stfl"))
        .stdout(predicate::str::contains("ignored.stfl").not());
}

#[test]
fn test_flag_reports_when_name_matches_nothing() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    fs::create_dir_all(temp.path().join("tests")).unwrap();
    fs::write(
        temp.path().join("tests/one.stfl"),
        "def main() -> int64:\n  return 1\n",
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("test")
        .arg(temp.path())
        .args(["--test", "nope"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--test 'nope' did not match any test file or function",
        ));
}

#[test]
fn test_flag_selects_matching_function_files() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    fs::create_dir_all(temp.path().join("tests")).unwrap();
    fs::write(
        temp.path().join("tests/one.stfl"),
        "def main() -> int64:\n  return 1\n\ndef selected() -> int64:\n  return 42\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("tests/two.stfl"),
        "def main() -> int64:\n  return 2\n",
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("test")
        .arg(temp.path())
        .args(["--test", "selected"])
        .assert()
        .success()
        .stdout(predicate::str::contains("one.stfl"))
        .stdout(predicate::str::contains("two.stfl").not());
}

#[test]
fn dev_help_exposes_hot_reload_controls() {
    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["dev", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--once"))
        .stdout(predicate::str::contains("--no-watch"))
        .stdout(predicate::str::contains("--poll-ms"))
        .stdout(predicate::str::contains("--poll"))
        .stdout(predicate::str::contains("watch for file changes"))
        .stdout(predicate::str::contains("greater than zero"));
}

#[test]
fn status_reports_project_health() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    // The default template ships a Rust SDK wrapper (Cargo.toml). Drop it so this
    // test exercises a Stoffel-only project with no declared ecosystem dependencies.
    fs::remove_file(temp.path().join("Cargo.toml")).unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("Project:"))
        .stdout(predicate::str::contains("Config: ok"))
        .stdout(predicate::str::contains("Dependencies: ok (none declared)"))
        .stdout(predicate::str::contains("Compile: ok"))
        .stdout(predicate::str::contains("Network:"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args(["status", "--verbose"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Source:"))
        .stdout(predicate::str::contains("Target:"))
        .stdout(predicate::str::contains("Cache:"))
        .stdout(predicate::str::contains("Tests:"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("status")
        .arg(temp.path().join("README.md"))
        .arg("--verbose")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            temp.path().join("src/main.stfl").display().to_string(),
        ))
        .stdout(predicate::str::contains("README.md").not());
}

#[test]
fn status_verbose_names_missing_dependency_commands() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .args([
            "init",
            temp.path().to_str().unwrap(),
            "--template",
            "solidity-foundry",
            "--force",
        ])
        .assert()
        .success();
    // The Stoffel scaffold also writes a Rust SDK Cargo.toml; remove it so the
    // foundry toolchain is the only declared dependency this test reports on.
    fs::remove_file(temp.path().join("Cargo.toml")).unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("status")
        .arg(temp.path())
        .arg("--verbose")
        .env("PATH", "")
        .assert()
        .success()
        .stdout(predicate::str::contains("Dependencies: 0/1 ready"))
        .stdout(predicate::str::contains(
            "foundry.toml detected; required command 'forge' not found in PATH",
        ))
        .stdout(predicate::str::contains("missing expected files").not());
}

#[test]
fn status_compile_failures_suggest_check_after_fixing_source() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    fs::write(temp.path().join("src/main.stfl"), "def main(\n").unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("status")
        .arg(temp.path())
        .assert()
        .failure()
        .stdout(predicate::str::contains("Compile: failed"))
        .stdout(predicate::str::contains("Syntax"))
        .stdout(predicate::str::contains("Next: fix the source error above"))
        .stdout(predicate::str::contains("stoffel check"))
        .stderr(predicate::str::contains("source file(s) failed to compile"));
}

#[test]
fn status_uses_consistent_mpc_validation_errors() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    let config = fs::read_to_string(temp.path().join("Stoffel.toml")).unwrap();
    fs::write(
        temp.path().join("Stoffel.toml"),
        config.replace("threshold = 1", "threshold = 2"),
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("status")
        .arg(temp.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid [mpc] config"))
        .stderr(predicate::str::contains("4 * threshold"))
        .stderr(predicate::str::contains("3 * threshold").not());
}

#[test]
fn utility_commands_accept_project_folder_paths() {
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("app");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .success();
    fs::create_dir_all(project.join("target/debug")).unwrap();
    fs::create_dir_all(project.join(".stoffel/cache")).unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("status")
        .arg(&project)
        .assert()
        .success()
        .stdout(predicate::str::contains("Project: app"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["update", "--check"])
        .arg(&project)
        .assert()
        .success()
        .stdout(predicate::str::contains("Stoffel CLI:"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("clean")
        .arg(&project)
        .assert()
        .success();
    assert!(!project.join("target").exists());
    assert!(!project.join(".stoffel/cache").exists());
}

#[test]
fn clean_removes_target_and_cache_directories() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    fs::create_dir_all(temp.path().join("target/debug")).unwrap();
    fs::create_dir_all(temp.path().join(".stoffel/cache")).unwrap();
    fs::create_dir_all(temp.path().join("node_modules")).unwrap();
    fs::create_dir_all(temp.path().join("out")).unwrap();
    fs::create_dir_all(temp.path().join("cache")).unwrap();
    fs::create_dir_all(temp.path().join("artifacts")).unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args(["clean", "--all", "--dry-run"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Would clean Stoffel project artifacts and known ecosystem caches",
        ))
        .stdout(predicate::str::contains("Would remove"))
        .stdout(predicate::str::contains("target"))
        .stdout(predicate::str::contains(".stoffel"))
        .stdout(predicate::str::contains("node_modules"))
        .stdout(predicate::str::contains("Removed").not());

    assert!(temp.path().join("target").exists());
    assert!(temp.path().join(".stoffel").exists());
    assert!(temp.path().join("node_modules").exists());

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args(["clean", "--check"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Would clean Stoffel build artifacts",
        ))
        .stdout(predicate::str::contains("Would remove"))
        .stdout(predicate::str::contains("Removed").not());

    assert!(temp.path().join("target").exists());
    assert!(temp.path().join(".stoffel").exists());

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args(["clean", "--all"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Cleaned Stoffel project artifacts and known ecosystem caches",
        ))
        .stdout(predicate::str::contains("Removed"))
        .stdout(predicate::str::contains("target"))
        .stdout(predicate::str::contains(".stoffel"))
        .stdout(predicate::str::contains("node_modules"))
        .stdout(predicate::str::contains("Skipped missing"))
        .stdout(predicate::str::contains(".stoffel/cache").not());

    assert!(!temp.path().join("target").exists());
    assert!(!temp.path().join(".stoffel").exists());
    assert!(!temp.path().join("node_modules").exists());
    assert!(temp.path().join("out").exists());
    assert!(temp.path().join("cache").exists());
    assert!(temp.path().join("artifacts").exists());
}

#[test]
fn clean_removes_stale_artifact_files_and_symlinks() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();

    fs::write(temp.path().join("target"), "stale artifact file").unwrap();
    fs::create_dir_all(temp.path().join(".stoffel")).unwrap();
    fs::write(temp.path().join(".stoffel/cache"), "stale cache file").unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .arg("clean")
        .assert()
        .success()
        .stdout(predicate::str::contains("Removed"))
        .stdout(predicate::str::contains("target"))
        .stdout(predicate::str::contains(".stoffel/cache"))
        .stderr(predicate::str::contains("invalid build.target_dir").not());

    assert!(!temp.path().join("target").exists());
    assert!(!temp.path().join(".stoffel/cache").exists());

    let outside = temp.path().join("outside-target");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("keep.txt"), "keep").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, temp.path().join("target")).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(&outside, temp.path().join("target")).unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .arg("clean")
        .assert()
        .success()
        .stdout(predicate::str::contains("Removed"))
        .stdout(predicate::str::contains("target"));

    assert!(!temp.path().join("target").exists());
    assert!(outside.join("keep.txt").exists());
}

#[cfg(unix)]
#[test]
fn clean_rejects_configured_target_through_intermediate_symlink() {
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("project");
    let outside = temp.path().join("outside");
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(&project)
        .assert()
        .success();
    fs::create_dir_all(outside.join("target")).unwrap();
    fs::write(outside.join("target/keep.txt"), "keep").unwrap();
    std::os::unix::fs::symlink(&outside, project.join("escape")).unwrap();
    let config = fs::read_to_string(project.join("Stoffel.toml")).unwrap();
    fs::write(
        project.join("Stoffel.toml"),
        config.replace("target_dir = \"target\"", "target_dir = \"escape/target\""),
    )
    .unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("clean")
        .arg(&project)
        .assert()
        .failure()
        .stderr(predicate::str::contains("symlink"));
    assert!(outside.join("target/keep.txt").exists());
}

#[test]
fn clean_all_removes_framework_outputs_only_when_detected() {
    let temp = TempDir::new().unwrap();
    let foundry = temp.path().join("foundry-app");
    Command::cargo_bin("stoffel")
        .unwrap()
        .args([
            "init",
            foundry.to_str().unwrap(),
            "--template",
            "solidity-foundry",
        ])
        .assert()
        .success();
    fs::create_dir_all(foundry.join("out")).unwrap();
    fs::create_dir_all(foundry.join("cache")).unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["clean", "--all"])
        .arg(&foundry)
        .assert()
        .success()
        .stdout(predicate::str::contains("out"))
        .stdout(predicate::str::contains("cache"));
    assert!(!foundry.join("out").exists());
    assert!(!foundry.join("cache").exists());

    let hardhat = temp.path().join("hardhat-app");
    Command::cargo_bin("stoffel")
        .unwrap()
        .args([
            "init",
            hardhat.to_str().unwrap(),
            "--template",
            "solidity-hardhat",
        ])
        .assert()
        .success();
    fs::create_dir_all(hardhat.join("artifacts")).unwrap();
    fs::create_dir_all(hardhat.join("cache")).unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["clean", "--all"])
        .arg(&hardhat)
        .assert()
        .success()
        .stdout(predicate::str::contains("artifacts"))
        .stdout(predicate::str::contains("cache"));
    assert!(!hardhat.join("artifacts").exists());
    assert!(!hardhat.join("cache").exists());
}

#[test]
fn update_check_reports_detected_update_targets() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args(["update", "--check"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Stoffel CLI:"))
        .stdout(predicate::str::contains("Update check:"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .current_dir(temp.path())
        .args(["update", "--dry-run"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Stoffel CLI:"))
        .stdout(predicate::str::contains("Update check:"))
        .stdout(predicate::str::contains("Running:").not());

    let foundry = temp.path().join("foundry-app");
    Command::cargo_bin("stoffel")
        .unwrap()
        .args([
            "init",
            foundry.to_str().unwrap(),
            "--template",
            "solidity-foundry",
        ])
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["update", "--check", "--no-self"])
        .arg(&foundry)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Project update: foundry.toml detected",
        ))
        .stdout(predicate::str::contains("no dependency manifests detected").not());

    let python = temp.path().join("python-app");
    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["init", python.to_str().unwrap(), "--template", "python"])
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["update", "--check", "--no-self"])
        .arg(&python)
        .env("PATH", "")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Project update: requirements.txt detected",
        ))
        .stdout(predicate::str::contains(
            "required command 'python3' or 'python' not found in PATH",
        ));

    let rust = temp.path().join("rust-app");
    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["init", rust.to_str().unwrap(), "--template", "rust"])
        .assert()
        .success();

    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["update", "--check", "--no-self"])
        .arg(&rust)
        .env("PATH", "")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Project update: Cargo.toml detected",
        ))
        .stdout(predicate::str::contains("found nested Stoffel project").not());

    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["update", "--check", "--no-self"])
        .arg(rust.join("Cargo.toml"))
        .env("PATH", "")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Project update: Cargo.toml detected",
        ))
        .stdout(predicate::str::contains("found nested Stoffel project").not());
}

#[test]
fn update_python_dependencies_report_missing_python_commands() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .args([
            "init",
            temp.path().to_str().unwrap(),
            "--template",
            "python",
            "--force",
        ])
        .assert()
        .success();
    // `update` walks dependency manifests in order and the Stoffel scaffold also
    // writes a Rust SDK Cargo.toml, which would otherwise fail on `cargo` first.
    // Remove it so this test reaches the Python toolchain check it targets.
    fs::remove_file(temp.path().join("Cargo.toml")).unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["update", "--no-self"])
        .arg(temp.path())
        .env("PATH", "")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "required command 'python3' or 'python' was not found in PATH",
        ))
        .stderr(predicate::str::contains("required command 'python'").not());
}

#[test]
fn update_source_self_update_requires_explicit_opt_in() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("init")
        .arg(temp.path())
        .arg("--force")
        .assert()
        .success();
    // Drop the scaffolded Rust SDK Cargo.toml so the project-dependency pass has
    // nothing to run; this test only exercises the CLI self-update messaging.
    fs::remove_file(temp.path().join("Cargo.toml")).unwrap();

    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["update"])
        .arg(temp.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("source checkout detected"))
        .stdout(predicate::str::contains("--self-from-source"))
        .stdout(predicate::str::contains("cargo install").not())
        .stdout(predicate::str::contains("Running:").not());
}

#[test]
fn update_rejects_empty_target_selection() {
    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["update", "--check", "--no-self", "--no-project"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no update targets selected"))
        .stderr(predicate::str::contains("remove --no-self"))
        .stderr(predicate::str::contains("remove --no-project"))
        .stdout(predicate::str::contains("Stoffel CLI:").not())
        .stdout(predicate::str::contains("Update check:").not());
}

#[test]
fn update_rejects_conflicting_self_update_options_before_discovery() {
    let temp = TempDir::new().unwrap();
    let missing = temp.path().join("missing").display().to_string();
    for args in [
        vec!["update", "--self-from-source", "--no-self"],
        vec![
            "update",
            "--check",
            "--self-from-source",
            "--no-self",
            missing.as_str(),
        ],
    ] {
        Command::cargo_bin("stoffel")
            .unwrap()
            .args(args)
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "--self-from-source cannot be used with --no-self",
            ))
            .stderr(predicate::str::contains("does not exist").not())
            .stdout(predicate::str::contains("Project update:").not());
    }
}

#[test]
fn update_validates_project_path_before_self_update_output() {
    let temp = TempDir::new().unwrap();
    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["update", "--check"])
        .arg(temp.path().join("missing"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not exist"))
        .stdout(predicate::str::contains("CLI self-update").not());

    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["update", "--check", "--no-project"])
        .arg(temp.path().join("missing"))
        .assert()
        .success()
        .stdout(predicate::str::contains("Stoffel CLI:"));
}

#[test]
fn utility_help_lists_status_clean_update_options() {
    Command::cargo_bin("stoffel")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("status"))
        .stdout(predicate::str::contains("update"))
        .stdout(predicate::str::contains("new"))
        .stdout(predicate::str::contains("doctor"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["clean", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--all"))
        .stdout(predicate::str::contains("--dry-run"))
        .stdout(predicate::str::contains("aliases: --check"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["update", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("aliases: --dry-run"))
        .stdout(predicate::str::contains("dependency manifest path"))
        .stdout(predicate::str::contains("Cargo.toml/package.json"))
        .stdout(predicate::str::contains("--self-from-source"))
        .stdout(predicate::str::contains("Required for source builds"));

    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["test", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Project directory or .stfl test file",
        ))
        .stdout(predicate::str::contains("embedded no-network test runner"))
        .stdout(predicate::str::contains("Only used with --local"))
        .stdout(predicate::str::contains("fast clear test runner").not());

    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["build", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Project directory, source directory, or .stfl source file",
        ));

    Command::cargo_bin("stoffel")
        .unwrap()
        .args(["dev", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Project directory or .stfl source file to watch",
        ));
}
