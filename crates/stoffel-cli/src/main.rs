mod project;

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use stoffel::prelude::*;

use crate::project::{
    init_library_project, validate_project_controlled_path, BuildConfig, Project, Template,
};

macro_rules! print {
    ($($arg:tt)*) => {{
        crate::write_stdout(format_args!($($arg)*), false);
    }};
}

macro_rules! println {
    () => {{
        crate::write_stdout(format_args!(""), true);
    }};
    ($($arg:tt)*) => {{
        crate::write_stdout(format_args!($($arg)*), true);
    }};
}

fn write_stdout(args: fmt::Arguments<'_>, newline: bool) {
    let mut stdout = io::stdout().lock();
    let result = if newline {
        writeln!(stdout, "{args}")
    } else {
        write!(stdout, "{args}")
    };
    if let Err(error) = result {
        if error.kind() == io::ErrorKind::BrokenPipe {
            std::process::exit(0);
        }
        panic!("failed printing to stdout: {error}");
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "stoffel",
    version,
    about = "Develop, build, and run Stoffel projects"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a new Stoffel project.
    #[command(visible_alias = "new")]
    Init(InitArgs),
    /// Validate source and project MPC settings without writing bytecode.
    Check(CheckArgs),
    /// Write compiled bytecode for a project or source file.
    Compile(BuildArgs),
    /// Build project bytecode under target/.
    Build(ProjectBuildArgs),
    /// Run source or bytecode through MPC execution.
    #[command(visible_aliases = ["exec", "execute"])]
    Run(RunArgs),
    /// Watch a project and rerun it on local MPC when files change.
    Dev(DevArgs),
    /// Run no-argument Stoffel test functions.
    Test(TestArgs),
    /// Show project health and environment status.
    #[command(visible_alias = "doctor")]
    Status(StatusArgs),
    /// Remove generated build artifacts.
    Clean(CleanArgs),
    /// Check or update the CLI and project dependencies.
    #[command(visible_alias = "upgrade")]
    Update(UpdateArgs),
    /// Preserve planned and unknown commands for targeted diagnostics.
    #[command(external_subcommand)]
    External(Vec<String>),
}

#[derive(Debug, Args)]
struct InitArgs {
    /// Directory where the project files are created. Defaults to the current directory.
    path: Option<PathBuf>,
    /// Project template to create. Supported templates: stoffel, python (py), rust, solidity-foundry (foundry), solidity-hardhat (hardhat).
    #[arg(
        long,
        value_name = "TEMPLATE",
        default_value = "stoffel",
        conflicts_with = "lib"
    )]
    template: String,
    /// Write template files into an existing directory without deleting unrelated files.
    #[arg(long)]
    force: bool,
    /// Create a library-style Stoffel project. Cannot be combined with --template.
    #[arg(long)]
    lib: bool,
    /// Reserved for future interactive setup.
    #[arg(long, hide = true)]
    interactive: bool,
}

#[derive(Debug, Args, Clone)]
struct BuildArgs {
    /// Project directory, source directory, or .stfl source file to compile. Defaults to source files from Stoffel.toml.
    path: Option<PathBuf>,
    /// Catch extra positional paths so we can explain that compile accepts one path.
    #[arg(value_name = "EXTRA_PATH", hide = true)]
    extra_paths: Vec<PathBuf>,
    /// Write bytecode to this .stflb file. Only valid when one source file is selected.
    #[arg(short, long, visible_alias = "out")]
    output: Option<PathBuf>,
    /// Print instructions from an existing .stflb bytecode file instead of compiling source.
    #[arg(long)]
    disassemble: bool,
    /// Legacy flag from the old CLI. Modern compile writes bytecode by default.
    #[arg(short = 'b', long = "binary", hide = true)]
    binary: bool,
    /// Print compiler intermediate representation for debugging.
    #[arg(long)]
    print_ir: bool,
    /// Set optimization level. Use -O3, -O 3, or --opt-level 3.
    #[arg(
        short = 'O',
        long = "opt-level",
        value_parser = parse_opt_level,
        allow_hyphen_values = true,
        value_name = "N"
    )]
    opt_level: Option<u8>,
    /// Use O2 optimization unless --release selects O3.
    #[arg(long, conflicts_with = "opt_level")]
    optimize: bool,
    /// Write under target/release and use O3 unless --opt-level is set.
    #[arg(long, visible_aliases = ["prod", "production"])]
    release: bool,
    /// Override [mpc].backend from Stoffel.toml for this compile.
    #[arg(long, alias = "protocol")]
    backend: Option<MpcBackend>,
    /// Override [mpc].curve from Stoffel.toml for this compile.
    #[arg(long, alias = "curve")]
    field: Option<Curve>,
    /// Override [mpc].parties from Stoffel.toml for this compile.
    #[arg(long, value_parser = parse_positive_usize_arg, allow_hyphen_values = true)]
    parties: Option<usize>,
    /// Override [mpc].threshold from Stoffel.toml for this compile.
    #[arg(long, value_parser = parse_positive_usize_arg, allow_hyphen_values = true)]
    threshold: Option<usize>,
    /// Override [mpc].instance_id from Stoffel.toml for this compile.
    #[arg(long, value_parser = parse_u64_arg, allow_hyphen_values = true)]
    instance_id: Option<u64>,
}

#[derive(Debug, Args, Clone)]
struct CheckArgs {
    /// Project directory, source directory, or .stfl source file to validate. Defaults to source files from Stoffel.toml.
    path: Option<PathBuf>,
    /// Catch extra positional paths so we can explain that check accepts one path.
    #[arg(value_name = "EXTRA_PATH", hide = true)]
    extra_paths: Vec<PathBuf>,
    /// Print compiler intermediate representation for debugging.
    #[arg(long)]
    print_ir: bool,
    /// Override [mpc].backend from Stoffel.toml for this validation.
    #[arg(long, alias = "protocol")]
    backend: Option<MpcBackend>,
    /// Override [mpc].curve from Stoffel.toml for this validation.
    #[arg(long, alias = "curve")]
    field: Option<Curve>,
    /// Override [mpc].parties from Stoffel.toml for this validation.
    #[arg(long, value_parser = parse_positive_usize_arg, allow_hyphen_values = true)]
    parties: Option<usize>,
    /// Override [mpc].threshold from Stoffel.toml for this validation.
    #[arg(long, value_parser = parse_positive_usize_arg, allow_hyphen_values = true)]
    threshold: Option<usize>,
}

impl CheckArgs {
    fn to_build_args(&self) -> BuildArgs {
        BuildArgs {
            path: self.path.clone(),
            extra_paths: self.extra_paths.clone(),
            output: None,
            disassemble: false,
            binary: false,
            print_ir: self.print_ir,
            opt_level: None,
            optimize: false,
            release: false,
            backend: self.backend,
            field: self.field,
            parties: self.parties,
            threshold: self.threshold,
            instance_id: None,
        }
    }
}

#[derive(Debug, Args, Clone)]
struct ProjectBuildArgs {
    /// Project directory, source directory, or .stfl source file to build. Defaults to source files from Stoffel.toml.
    path: Option<PathBuf>,
    /// Catch extra positional paths so we can explain that build accepts one path.
    #[arg(value_name = "EXTRA_PATH", hide = true)]
    extra_paths: Vec<PathBuf>,
    /// Write bytecode to this .stflb file. Only valid when one source file is selected.
    #[arg(short, long, visible_alias = "out")]
    output: Option<PathBuf>,
    /// Print compiler intermediate representation for debugging.
    #[arg(long)]
    print_ir: bool,
    /// Set optimization level. Use -O3, -O 3, or --opt-level 3.
    #[arg(
        short = 'O',
        long = "opt-level",
        value_parser = parse_opt_level,
        allow_hyphen_values = true,
        value_name = "N"
    )]
    opt_level: Option<u8>,
    /// Use O2 optimization unless --release selects O3.
    #[arg(long, conflicts_with = "opt_level")]
    optimize: bool,
    /// Write under target/release and use O3 unless --opt-level is set.
    #[arg(long, visible_aliases = ["prod", "production"])]
    release: bool,
    /// Override [mpc].backend from Stoffel.toml for this build.
    #[arg(long, alias = "protocol")]
    backend: Option<MpcBackend>,
    /// Override [mpc].curve from Stoffel.toml for this build.
    #[arg(long, alias = "curve")]
    field: Option<Curve>,
    /// Override [mpc].parties from Stoffel.toml for this build.
    #[arg(long, value_parser = parse_positive_usize_arg, allow_hyphen_values = true)]
    parties: Option<usize>,
    /// Override [mpc].threshold from Stoffel.toml for this build.
    #[arg(long, value_parser = parse_positive_usize_arg, allow_hyphen_values = true)]
    threshold: Option<usize>,
    /// Override [mpc].instance_id from Stoffel.toml for this build.
    #[arg(long, value_parser = parse_u64_arg, allow_hyphen_values = true)]
    instance_id: Option<u64>,
}

impl ProjectBuildArgs {
    fn to_build_args(&self) -> BuildArgs {
        BuildArgs {
            path: self.path.clone(),
            extra_paths: self.extra_paths.clone(),
            output: self.output.clone(),
            disassemble: false,
            binary: false,
            print_ir: self.print_ir,
            opt_level: self.opt_level,
            optimize: self.optimize,
            release: self.release,
            backend: self.backend,
            field: self.field,
            parties: self.parties,
            threshold: self.threshold,
            instance_id: self.instance_id,
        }
    }
}

#[derive(Debug, Args)]
struct RunArgs {
    #[command(flatten)]
    build: RunBuildArgs,
    /// Function to execute from the compiled program.
    #[arg(
        long,
        visible_aliases = ["entrypoint", "function"],
        default_value = "main",
        value_parser = parse_entry_arg
    )]
    entry: String,
    /// Function argument value, written as NAME=VALUE. Repeat once per argument.
    #[arg(long = "input", visible_alias = "inputs", value_name = "NAME=VALUE")]
    inputs: Vec<InputArg>,
    /// Load named function inputs from a .json, .csv, or .txt file.
    #[arg(long = "input-file", value_name = "FILE")]
    input_files: Vec<PathBuf>,
    /// Semantic input for a numeric client slot, written as SLOT=VALUE.
    /// Fixed-point values are scaled automatically from ordinary integers or decimals.
    #[arg(
        long = "client-input",
        visible_alias = "client-inputs",
        value_name = "SLOT=VALUE",
        allow_hyphen_values = true
    )]
    client_inputs: Vec<ClientInputArg>,
    /// Load local ClientStore inputs from a .json, .csv, or .txt file.
    #[arg(long = "client-input-file", value_name = "FILE")]
    client_input_files: Vec<PathBuf>,
    /// Declare local output-capable client slots 0..N-1 for ClientStore programs.
    #[arg(
        long = "expected-output-clients",
        value_parser = parse_positive_usize_arg,
        allow_hyphen_values = true
    )]
    expected_output_clients: Option<usize>,
    /// Number of output values a client receives via `send_to_client`
    /// (`SLOT=COUNT`), for the local simulator. Fallback used only when the
    /// program does not statically declare the client's outputs. Repeatable.
    #[arg(long = "client-output-count", value_name = "SLOT=COUNT", value_parser = parse_client_output_count_arg)]
    client_output_counts: Vec<(u64, u64)>,
    /// Run on the local MPC simulator. This is the default unless --network or --config is set.
    #[arg(long)]
    local: bool,
    /// Connect to an MPC network described by --config.
    #[arg(long)]
    network: bool,
    /// MPC network/off-chain client TOML file. Do not pass project Stoffel.toml here.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Print function/instruction metadata before executing.
    #[arg(long = "program-info", visible_aliases = ["inspect", "info"])]
    program_info: bool,
    /// Network client slot to use with --network.
    #[arg(long, value_parser = parse_u64_arg, allow_hyphen_values = true)]
    client_id: Option<u64>,
    /// Timeout for connecting to network nodes, in milliseconds.
    #[arg(
        long,
        default_value_t = 10_000,
        value_parser = parse_positive_u64_arg,
        allow_hyphen_values = true
    )]
    connect_timeout_ms: u64,
    /// Path to the stoffel-run helper binary. Only used with --local.
    #[arg(long)]
    runner: Option<PathBuf>,
    /// Timeout for local MPC execution, in seconds.
    #[arg(
        long,
        default_value_t = 180,
        value_parser = parse_positive_u64_arg,
        allow_hyphen_values = true
    )]
    timeout_secs: u64,
    /// Catch positional input mistakes so we can explain --input NAME=VALUE.
    #[arg(value_name = "INPUT", trailing_var_arg = true, hide = true)]
    positional_inputs: Vec<String>,
}

#[derive(Debug, Args, Clone)]
struct RunBuildArgs {
    /// Project directory, .stfl source file, or .stflb bytecode file to run. Defaults to the current project.
    path: Option<PathBuf>,
    /// Print compiler intermediate representation when source must be compiled before running.
    #[arg(long)]
    print_ir: bool,
    /// Set optimization level. Use -O3, -O 3, or --opt-level 3.
    #[arg(
        short = 'O',
        long = "opt-level",
        value_parser = parse_opt_level,
        allow_hyphen_values = true,
        value_name = "N"
    )]
    opt_level: Option<u8>,
    /// Use O2 optimization unless --release selects O3.
    #[arg(long, conflicts_with = "opt_level")]
    optimize: bool,
    /// Prefer target/release bytecode and use O3 when compiling source unless --opt-level is set.
    #[arg(long, visible_aliases = ["prod", "production"])]
    release: bool,
    /// Override [mpc].backend from Stoffel.toml when compiling source before running.
    #[arg(long, alias = "protocol")]
    backend: Option<MpcBackend>,
    /// Override [mpc].curve from Stoffel.toml when compiling source before running.
    #[arg(long, alias = "curve")]
    field: Option<Curve>,
    /// Override [mpc].parties from Stoffel.toml for this run.
    #[arg(long, value_parser = parse_positive_usize_arg, allow_hyphen_values = true)]
    parties: Option<usize>,
    /// Override [mpc].threshold from Stoffel.toml for this run.
    #[arg(long, value_parser = parse_positive_usize_arg, allow_hyphen_values = true)]
    threshold: Option<usize>,
    /// Override [mpc].instance_id from Stoffel.toml for this run.
    #[arg(long, value_parser = parse_u64_arg, allow_hyphen_values = true)]
    instance_id: Option<u64>,
}

impl RunBuildArgs {
    fn to_build_args(&self) -> BuildArgs {
        BuildArgs {
            path: self.path.clone(),
            extra_paths: Vec::new(),
            output: None,
            disassemble: false,
            binary: false,
            print_ir: self.print_ir,
            opt_level: self.opt_level,
            optimize: self.optimize,
            release: self.release,
            backend: self.backend,
            field: self.field,
            parties: self.parties,
            threshold: self.threshold,
            instance_id: self.instance_id,
        }
    }
}

#[derive(Debug, Args, Clone)]
struct DevArgs {
    /// Project directory or .stfl source file to watch. Defaults to source files from Stoffel.toml.
    path: Option<PathBuf>,
    /// Function to execute after each reload.
    #[arg(
        long,
        visible_aliases = ["entrypoint", "function"],
        default_value = "main",
        value_parser = parse_entry_arg
    )]
    entry: String,
    /// Function argument value, written as NAME=VALUE. Repeat once per argument.
    #[arg(long = "input", visible_alias = "inputs", value_name = "NAME=VALUE")]
    inputs: Vec<InputArg>,
    /// Load named function inputs from a .json, .csv, or .txt file.
    #[arg(long = "input-file", value_name = "FILE")]
    input_files: Vec<PathBuf>,
    /// Semantic input for a numeric client slot, written as SLOT=VALUE.
    /// Fixed-point values are scaled automatically from ordinary integers or decimals.
    #[arg(
        long = "client-input",
        visible_alias = "client-inputs",
        value_name = "SLOT=VALUE",
        allow_hyphen_values = true
    )]
    client_inputs: Vec<ClientInputArg>,
    /// Load local ClientStore inputs from a .json, .csv, or .txt file.
    #[arg(long = "client-input-file", value_name = "FILE")]
    client_input_files: Vec<PathBuf>,
    /// Path to the stoffel-run helper binary. Only used with --local.
    #[arg(long)]
    runner: Option<PathBuf>,
    /// Override [mpc].parties from Stoffel.toml for each dev run.
    #[arg(long, value_parser = parse_positive_usize_arg, allow_hyphen_values = true)]
    parties: Option<usize>,
    /// Override [mpc].threshold from Stoffel.toml for each dev run.
    #[arg(long, value_parser = parse_positive_usize_arg, allow_hyphen_values = true)]
    threshold: Option<usize>,
    /// Override [mpc].backend from Stoffel.toml for each dev compile.
    #[arg(long, alias = "protocol")]
    backend: Option<MpcBackend>,
    /// Override [mpc].curve from Stoffel.toml for each dev compile.
    #[arg(long, alias = "curve")]
    field: Option<Curve>,
    /// Timeout for local MPC execution, in seconds.
    #[arg(
        long,
        default_value_t = 180,
        value_parser = parse_positive_u64_arg,
        allow_hyphen_values = true
    )]
    timeout_secs: u64,
    /// Run once and exit; do not watch for file changes.
    #[arg(long, visible_alias = "no-watch")]
    once: bool,
    /// Catch redundant watch requests so we can explain that watching is the default.
    #[arg(long, hide = true)]
    watch: bool,
    /// File-watch polling interval for hot reload, in milliseconds. Must be greater than zero.
    #[arg(
        long,
        visible_alias = "poll",
        default_value_t = 500,
        value_parser = parse_positive_u64_arg,
        allow_hyphen_values = true
    )]
    poll_ms: u64,
    /// Catch positional input mistakes so we can explain --input NAME=VALUE.
    #[arg(value_name = "INPUT", trailing_var_arg = true, hide = true)]
    positional_inputs: Vec<String>,
}

#[derive(Debug, Args)]
struct TestArgs {
    /// Project directory or .stfl test file. Defaults to every test file recursively under tests/.
    path: Option<PathBuf>,
    /// Run tests through local MPC simulation instead of the embedded no-network test runner.
    #[arg(long)]
    local: bool,
    /// Run tests whose function name or file stem matches this value.
    #[arg(long = "test", visible_alias = "name", value_parser = parse_test_filter_arg)]
    test: Option<String>,
    /// Run only test files marked as integration tests.
    #[arg(long)]
    integration: bool,
    /// Print each selected test and its result.
    #[arg(long, short)]
    verbose: bool,
    /// Path to the stoffel-run helper binary. Only used with --local.
    #[arg(long)]
    runner: Option<PathBuf>,
    /// Catch run-command input mistakes so we can explain the test/run split.
    #[arg(long = "input", hide = true, value_name = "NAME=VALUE")]
    inputs: Vec<InputArg>,
    /// Catch run-command entry mistakes so we can explain the test/run split.
    #[arg(long, hide = true, value_parser = parse_entry_arg)]
    entry: Option<String>,
}

#[derive(Debug, Args)]
struct StatusArgs {
    /// Project directory or any file inside a project. Defaults to the current directory.
    path: Option<PathBuf>,
    /// Show dependency details and MPC configuration diagnostics.
    #[arg(long, short)]
    verbose: bool,
}

#[derive(Debug, Args)]
struct CleanArgs {
    /// Project directory or any file inside a project. Defaults to the current directory.
    path: Option<PathBuf>,
    /// Show what would be removed without deleting anything.
    #[arg(long, visible_aliases = ["check", "dryrun"])]
    dry_run: bool,
    /// Also remove .stoffel and detected ecosystem caches such as node_modules or Foundry/Hardhat output.
    #[arg(long)]
    all: bool,
}

#[derive(Debug, Args)]
struct UpdateArgs {
    /// Stoffel project path or dependency manifest path such as Cargo.toml/package.json. Defaults to the current directory.
    path: Option<PathBuf>,
    /// Print available update actions without changing files.
    #[arg(long, visible_aliases = ["dry-run", "dryrun"])]
    check: bool,
    /// Do not check or update the Stoffel CLI executable.
    #[arg(long)]
    no_self: bool,
    /// Do not check or update project dependency files.
    #[arg(long)]
    no_project: bool,
    /// Reinstall the Stoffel CLI from this source checkout. Required for source builds.
    #[arg(long)]
    self_from_source: bool,
}

#[derive(Debug, Args)]
struct PlannedCommandArgs {
    /// Preserve user input so legacy planned commands can explain the supported workflow.
    #[arg(
        value_name = "ARG",
        trailing_var_arg = true,
        allow_hyphen_values = true,
        hide = true
    )]
    args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
struct InputArg {
    name: String,
    value: Value,
}

#[derive(Debug, Clone, PartialEq)]
struct ClientInputArg {
    client_slot: u64,
    value: Value,
}

impl std::str::FromStr for InputArg {
    type Err = anyhow::Error;

    fn from_str(raw: &str) -> Result<Self> {
        let (name, value) = raw
            .split_once('=')
            .with_context(|| format!("input '{raw}' must be written as name=value"))?;
        let name = name.trim();
        if name.is_empty() {
            anyhow::bail!("input name cannot be empty");
        }
        let value = value.trim();
        if value.is_empty() {
            anyhow::bail!("input '{name}' must include a value, written as {name}=value");
        }
        if let Some(next_name) = comma_separated_assignment_name(value) {
            anyhow::bail!(
                "input '{raw}' looks like multiple inputs in one flag. Repeat --input for each value, for example: --input {name}=<value> --input {next_name}=<value>"
            );
        }
        if value.contains('=') {
            anyhow::bail!(
                "input '{raw}' has more than one '='. Write one argument per flag as --input {name}=<value>; values must be integers, booleans, or 0x-prefixed hex bytes."
            );
        }
        Ok(Self {
            name: name.to_owned(),
            value: parse_value(value)
                .map_err(|error| anyhow::anyhow!("invalid value for input '{name}': {error}"))?,
        })
    }
}

impl std::str::FromStr for ClientInputArg {
    type Err = anyhow::Error;

    fn from_str(raw: &str) -> Result<Self> {
        let (client_slot, value) = raw.split_once('=').with_context(|| {
            format!("client input '{raw}' must be written as client_slot=value")
        })?;
        let client_slot = client_slot.trim();
        let value = value.trim();
        if client_slot.is_empty() {
            anyhow::bail!("client input slot cannot be empty");
        }
        if value.is_empty() {
            anyhow::bail!(
                "client input slot {client_slot} must include a value, written as {client_slot}=value"
            );
        }
        if let Some(next_slot) = comma_separated_assignment_name(value) {
            anyhow::bail!(
                "client input '{raw}' looks like multiple inputs in one flag. Repeat --client-input for each client slot, for example: --client-input {client_slot}=<value> --client-input {next_slot}=<value>"
            );
        }
        if value.contains('=') {
            anyhow::bail!(
                "client input '{raw}' has more than one '='. Write one client input per flag as --client-input {client_slot}=<value>; values may be integers, fixed-point decimals, booleans, or 0x-prefixed hex bytes."
            );
        }
        Ok(Self {
            client_slot: client_slot.parse().with_context(|| {
                format!(
                    "invalid client slot '{client_slot}'; use a numeric slot like 0, written as 0=value"
                )
            })?,
            value: parse_value(value).map_err(|error| {
                anyhow::anyhow!("invalid value for client input slot {client_slot}: {error}")
            })?,
        })
    }
}

fn comma_separated_assignment_name(value: &str) -> Option<&str> {
    value
        .split(',')
        .skip(1)
        .find_map(|part| part.split_once('=').map(|(left, _)| left.trim()))
        .filter(|left| !left.is_empty())
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Init(args) => init(args),
        Command::Check(args) => check(args),
        Command::Compile(args) => build("stoffel compile", args),
        Command::Build(args) => build("stoffel build", args.to_build_args()),
        Command::Run(args) => run(args).await,
        Command::Dev(args) => dev(args).await,
        Command::Test(args) => test(args).await,
        Command::Status(args) => status(args),
        Command::Clean(args) => clean(args),
        Command::Update(args) => update(args),
        Command::External(args) => external_command(args),
    }
}

fn external_command(args: Vec<String>) -> Result<()> {
    let Some((command, rest)) = args.split_first() else {
        anyhow::bail!("missing command. Run `stoffel --help` to see available commands.");
    };
    match command.as_str() {
        "deploy" | "add" | "publish" => planned_command(
            command,
            PlannedCommandArgs {
                args: rest.to_vec(),
            },
        ),
        _ => unknown_command(command),
    }
}

fn unknown_command(command: &str) -> Result<()> {
    if let Some(suggestion) = closest_cli_command(command) {
        anyhow::bail!(
            "unknown command `{command}`. Did you mean `stoffel {suggestion}`? Run `stoffel --help` to see available commands."
        );
    }
    anyhow::bail!("unknown command `{command}`. Run `stoffel --help` to see available commands.");
}

fn closest_cli_command(command: &str) -> Option<&'static str> {
    const COMMANDS: &[&str] = &[
        "init", "new", "check", "compile", "build", "run", "exec", "execute", "dev", "test",
        "status", "doctor", "clean", "update", "upgrade",
    ];
    COMMANDS
        .iter()
        .map(|candidate| (edit_distance(command, candidate), *candidate))
        .filter(|(distance, _)| *distance <= 2)
        .min_by_key(|(distance, candidate)| (*distance, candidate.len()))
        .map(|(_, candidate)| candidate)
}

fn planned_command(command: &str, args: PlannedCommandArgs) -> Result<()> {
    let suffix = if args.args.is_empty() {
        String::new()
    } else {
        format!(" {}", args.args.join(" "))
    };
    match command {
        "deploy" => anyhow::bail!(
            "`stoffel deploy{suffix}` is not available yet. Build bytecode with `stoffel build`; use `stoffel run --network --config <CONFIG>` for network execution."
        ),
        "add" => anyhow::bail!(
            "`stoffel add{suffix}` is not available yet. Edit project dependency files directly for now, then run `stoffel update --check` to inspect detected dependency managers."
        ),
        "publish" => anyhow::bail!(
            "`stoffel publish{suffix}` is not available yet. Build artifacts with `stoffel build --release` before publishing through your project-specific workflow."
        ),
        _ => unreachable!("planned command handler called for unsupported command"),
    }
}

fn init(args: InitArgs) -> Result<()> {
    let template = parse_template(&args.template)?;
    let path = args.path.unwrap_or_else(|| PathBuf::from("."));
    let _interactive = args.interactive;
    if args.lib {
        ensure_writable_project_dir(&path, args.force)?;
        init_library_project(&path)?;
    } else {
        Project::init(&path, template, args.force)?;
    }
    println!("Created Stoffel project at {}", path.display());
    Ok(())
}

fn parse_template(raw: &str) -> Result<Template> {
    let normalized = raw.trim().to_ascii_lowercase().replace('_', "-");
    match normalized.as_str() {
        "stoffel" => Ok(Template::Stoffel),
        "python" | "py" => Ok(Template::Python),
        "rust" => Ok(Template::Rust),
        "solidity-foundry" | "foundry" => Ok(Template::SolidityFoundry),
        "solidity-hardhat" | "hardhat" => Ok(Template::SolidityHardhat),
        "" => anyhow::bail!(
            "`--template` needs a template name. Supported templates are: stoffel, python (py), rust, solidity-foundry (foundry), solidity-hardhat (hardhat)."
        ),
        _ => {
            let supported = [
                "stoffel",
                "python",
                "py",
                "rust",
                "solidity-foundry",
                "foundry",
                "solidity-hardhat",
                "hardhat",
            ];
            if let Some(suggestion) = closest_supported_template(&normalized, &supported) {
                anyhow::bail!(
                    "unknown template `{raw}`. Did you mean `{suggestion}`? Supported templates are: stoffel, python (py), rust, solidity-foundry (foundry), solidity-hardhat (hardhat)."
                );
            }
            anyhow::bail!(
                "unknown template `{raw}`. Supported templates are: stoffel, python (py), rust, solidity-foundry (foundry), solidity-hardhat (hardhat)."
            );
        }
    }
}

fn closest_supported_template<'a>(candidate: &str, supported: &'a [&str]) -> Option<&'a str> {
    let max_distance = if candidate.len() <= 2 { 1 } else { 3 };
    supported
        .iter()
        .map(|template| (edit_distance(candidate, template), *template))
        .filter(|(distance, _)| *distance <= max_distance)
        .min_by_key(|(distance, template)| (*distance, template.len()))
        .map(|(_, template)| template)
}

fn check(args: CheckArgs) -> Result<()> {
    let args = args.to_build_args();
    validate_single_build_path_arg("stoffel check", args.path.as_deref(), &args.extra_paths)?;
    validate_explicit_build_path(args.path.as_deref())?;
    let project = Project::discover(args.path.as_deref())?;
    for source in selected_sources(&project, &args)? {
        let runtime = configured_builder_for_source(&project, &args, &source)?
            .build()
            .with_context(|| format!("failed to compile or configure {}", source.display()))?;
        println!(
            "Checked {} ({})",
            source.display(),
            function_list(runtime.program())
        );
    }
    Ok(())
}

fn build(command: &str, args: BuildArgs) -> Result<()> {
    validate_single_build_path_arg(command, args.path.as_deref(), &args.extra_paths)?;
    if args.binary {
        anyhow::bail!(
            "{command} writes bytecode by default; remove -b/--binary. Use --output <FILE.stflb> to choose the bytecode file path."
        );
    }
    if args.disassemble {
        return disassemble(args);
    }
    validate_explicit_build_path(args.path.as_deref())?;
    let project = Project::discover(args.path.as_deref())?;
    let sources = selected_sources(&project, &args)?;
    if args.output.is_some() && sources.len() > 1 {
        anyhow::bail!("--output can only be used when compiling one source file");
    }
    for source in sources {
        let output = args
            .output
            .clone()
            .map(|path| project_relative_output(&project, path))
            .unwrap_or_else(|| project.default_bytecode_path_for_source(&source, args.release));
        validate_bytecode_output_path(&project, &output)?;
        let runtime = configured_builder_for_source(&project, &args, &source)?
            .build()
            .with_context(|| format!("failed to compile or configure {}", source.display()))?;
        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        runtime.save_bytecode(&output)?;
        print_build_stats(&output, runtime.program(), &project, &args)?;
    }
    Ok(())
}

async fn run(args: RunArgs) -> Result<()> {
    validate_run_args(&args)?;
    let inputs = merged_named_inputs(&args.input_files, &args.inputs)?;
    let client_inputs = merged_client_inputs(&args.client_input_files, &args.client_inputs)?;
    if args.network || args.config.is_some() {
        return run_network(args, inputs).await;
    }

    let build = args.build.to_build_args();
    let mut run_source = run_builder(&build)?;
    if !inputs.is_empty() {
        if let (Some(_bytecode_path), Some(source_path)) = (
            run_source.bytecode_path.as_ref(),
            run_source.source_path.clone(),
        ) {
            if run_source.builder.clone().build().is_ok() {
                let project = Project::discover(build.path.as_deref())?;
                run_source.builder = configured_builder_for_source(&project, &build, &source_path)?;
                run_source.bytecode_path = None;
            }
        }
    }
    let runtime = run_source.builder.clone().build().with_context(|| {
        execution_build_context(
            "stoffel run",
            build.path.as_deref(),
            run_source.bytecode_path.as_deref(),
        )
    })?;
    validate_entry_declared_in_source(
        run_source.source_path.as_deref(),
        runtime.program(),
        &args.entry,
        "stoffel run",
    )?;
    let inputs = normalize_entry_inputs(runtime.program(), &args.entry, &inputs);
    validate_entry_and_named_inputs(runtime.program(), &args.entry, &inputs, "stoffel run")?;
    if args.program_info {
        print_program_summary(runtime.program());
    }
    let mut builder = apply_run_inputs(run_source.builder, &inputs, &client_inputs)?;
    if let Some(expected_output_clients) = args.expected_output_clients {
        builder = builder.expected_output_clients(expected_output_clients);
    }
    // Stoffel.toml `[mpc.client_output_counts]` fallback (the --client-output-count
    // flag below overrides it, and statically declared program outputs win at run).
    if let Ok(project) = Project::discover(build.path.as_deref()) {
        if let Some(counts) = &project.config().mpc.client_output_counts {
            for (slot, count) in counts {
                if let Ok(slot) = slot.parse::<u64>() {
                    builder = builder.client_output_count(slot, *count);
                }
            }
        }
    }
    for (slot, count) in &args.client_output_counts {
        builder = builder.client_output_count(*slot, *count);
    }
    if let Some(path) = args.runner {
        builder = builder.local_runner_path(path);
    }
    let result = builder
        .execute_local_function_with_timeout(&args.entry, Duration::from_secs(args.timeout_secs))
        .await?;
    print_values(&result);
    Ok(())
}

async fn run_network(args: RunArgs, inputs: Vec<InputArg>) -> Result<()> {
    let config_path = args
        .config
        .as_ref()
        .context("network execution requires --config")?;
    let config_path = resolve_network_config_path(config_path, &args.build.to_build_args());
    validate_network_config_path(&config_path)?;
    if !args.client_inputs.is_empty() || !args.client_input_files.is_empty() {
        anyhow::bail!(
            "network execution accepts --input or --input-file values for the configured client slot; --client-input and --client-input-file are only used for local ClientStore runs"
        );
    }
    if args.expected_output_clients.is_some() {
        anyhow::bail!(
            "network execution uses network/off-chain client configuration; --expected-output-clients is only used for local ClientStore runs"
        );
    }
    let build = args.build.to_build_args();
    let run_source = run_builder(&build)?;
    let builder = run_source.builder;
    let runtime = builder.build().with_context(|| {
        execution_build_context(
            "stoffel run --network",
            build.path.as_deref(),
            run_source.bytecode_path.as_deref(),
        )
    })?;
    validate_entry_declared_in_source(
        run_source.source_path.as_deref(),
        runtime.program(),
        &args.entry,
        "stoffel run --network",
    )?;
    let normalized_inputs = normalize_entry_inputs(runtime.program(), &args.entry, &inputs);
    validate_entry_and_named_inputs(
        runtime.program(),
        &args.entry,
        &normalized_inputs,
        "stoffel run --network",
    )?;
    if args.program_info {
        print_program_summary(runtime.program());
    }
    let inputs = normalized_inputs
        .iter()
        .map(|input| input.value.clone())
        .collect::<Vec<_>>();

    match read_run_network_config(&config_path)? {
        RunNetworkConfig::OffChain(config) => {
            let client_id = client_id_from_u64(args.client_id.unwrap_or(config.client_slot))?;
            let client = runtime
                .client()
                .client_id(client_id)
                .offchain_io(config)
                .build()
                .map_err(|error| {
                    anyhow::anyhow!(clean_repeated_invalid_config_prefix(&error.to_string()))
                })?;
            println!("Connected to off-chain MPC coordinator configuration");
            let result = client.run_function(&args.entry, &inputs).await?;
            print_values(&result);
        }
        RunNetworkConfig::Network(config) => {
            let summary = config.summary().map_err(|error| {
                anyhow::anyhow!(clean_repeated_invalid_config_prefix(&error.to_string()))
            })?;
            let client_id = client_id_from_u64(args.client_id.unwrap_or(0))?;
            let client = runtime
                .client()
                .client_id(client_id)
                .network_config(&config)
                .connection_timeout(Duration::from_millis(args.connect_timeout_ms))
                .connect()
                .await
                .map_err(|error| {
                    anyhow::anyhow!(clean_repeated_invalid_config_prefix(&error.to_string()))
                })?;
            let client_summary = client.summary();
            println!(
                "Connected to MPC network ({} servers, backend {}, threshold {})",
                client_summary.server_count, summary.backend, summary.threshold
            );
            anyhow::bail!(
                "network config establishes transport connectivity, but computation submission requires an off-chain client config with coordinator/node RPC and client identity"
            );
        }
    }
    Ok(())
}

fn client_id_from_u64(value: u64) -> Result<ClientId> {
    value
        .try_into()
        .map_err(|_| anyhow::anyhow!("client id {value} does not fit on this platform"))
}

fn validate_run_args(args: &RunArgs) -> Result<()> {
    validate_positional_inputs(
        "stoffel run",
        args.build.path.as_deref(),
        &args.positional_inputs,
    )?;
    if args.local && args.network {
        anyhow::bail!("--local and --network select different execution modes; remove one of them");
    }
    if args.local && args.config.is_some() {
        anyhow::bail!(
            "--local cannot be used with --config; remove --config for local simulation or remove --local to run against a network config"
        );
    }
    if args.network && args.config.is_none() {
        if let Some(path) = args.build.path.as_deref().filter(|path| is_toml_path(path)) {
            anyhow::bail!(
                "network config path {} was passed as PATH. Use: stoffel run <PROJECT> --network --config {}",
                path.display(),
                path.display()
            );
        }
    }
    let network_mode = args.network || args.config.is_some();
    if !network_mode && args.client_id.is_some() {
        anyhow::bail!(
            "--client-id only applies to network execution; pass --network --config <CONFIG> or remove --client-id"
        );
    }
    if network_mode && args.runner.is_some() {
        anyhow::bail!(
            "--runner only applies to local simulation; remove --runner when using --network or --config"
        );
    }
    if let Some(path) = args.runner.as_deref() {
        validate_runner_path(path)?;
    }
    Ok(())
}

fn validate_dev_args(args: &DevArgs) -> Result<()> {
    validate_positional_inputs("stoffel dev", args.path.as_deref(), &args.positional_inputs)?;
    if args.watch {
        anyhow::bail!(
            "stoffel dev watches by default. Remove --watch, or use --once/--no-watch to run one time and exit."
        );
    }
    if let Some(path) = args.path.as_deref() {
        if path.exists() && path.is_dir() {
            let project = Project::discover(Some(path))?;
            if !is_project_root_dir(&project, path)? {
                anyhow::bail!(
                    "stoffel dev expected a project directory containing Stoffel.toml or a .stfl source file; got directory {}. To watch this project, pass {}",
                    path.display(),
                    project.root().display()
                );
            }
        } else if path.exists() && !is_source_path(path) {
            if is_bytecode_path(path) {
                anyhow::bail!(
                    "stoffel dev watches project directories or .stfl source files; use `stoffel run {}` to execute bytecode",
                    path.display()
                );
            }
            anyhow::bail!(
                "stoffel dev expected a project directory or .stfl source file; got {}",
                path.display()
            );
        }
    }
    if let Some(path) = args.runner.as_deref() {
        validate_runner_path(path)?;
    }
    Ok(())
}

fn validate_runner_path(path: &Path) -> Result<()> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            anyhow::bail!(
                "--runner path {} does not exist. Pass the built stoffel-run executable path, or remove --runner to use the default local simulator runner.",
                path.display()
            );
        }
        Err(error) => {
            anyhow::bail!(
                "could not read --runner path {}: {error}. Pass the built stoffel-run executable path, or remove --runner to use the default local simulator runner.",
                path.display()
            );
        }
    };
    if metadata.is_dir() {
        anyhow::bail!(
            "--runner path {} is a directory. Pass the stoffel-run executable file, not its parent directory.",
            path.display()
        );
    }
    if !metadata.is_file() {
        anyhow::bail!(
            "--runner path {} is not a regular executable file. Pass the built stoffel-run executable path.",
            path.display()
        );
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o111 == 0 {
        anyhow::bail!(
            "--runner path {} is not executable. Run `chmod +x {}` or pass the built stoffel-run executable path.",
            path.display(),
            path.display()
        );
    }
    Ok(())
}

fn execution_build_context(
    command: &str,
    path: Option<&Path>,
    bytecode_path: Option<&Path>,
) -> String {
    if let Some(bytecode_path) = bytecode_path {
        return format!(
            "{command} could not load bytecode {}; run `stoffel build` to regenerate it or pass a .stfl source/project path",
            bytecode_path.display()
        );
    }
    match path {
        Some(path) => format!("{command} could not compile or load {}", path.display()),
        None => format!("{command} could not compile or load the current project"),
    }
}

fn validate_positional_inputs(
    command: &str,
    path: Option<&Path>,
    positional: &[String],
) -> Result<()> {
    if !path_looks_like_positional_input(path) && positional.is_empty() {
        return Ok(());
    }
    let mut values = Vec::new();
    if let Some(path) = path {
        if path_looks_like_positional_input(Some(path)) {
            values.push(path.display().to_string());
        }
    }
    values.extend(positional.iter().cloned());
    if command == "stoffel run" {
        if let Some(config) = values.iter().find(|value| is_toml_path(Path::new(value))) {
            anyhow::bail!(
                "unexpected TOML config path '{config}' after PATH. Use: stoffel run <PROJECT> --config {config}"
            );
        }
    }
    let hint = values
        .iter()
        .filter(|value| value.contains('='))
        .map(|value| format!("--input {value}"))
        .collect::<Vec<_>>()
        .join(" ");
    if hint.is_empty() {
        anyhow::bail!(
            "unexpected positional argument(s): {}. Named function inputs must use --input NAME=VALUE",
            values.join(" ")
        );
    }
    anyhow::bail!(
        "named inputs must use --input NAME=VALUE, not positional arguments. Try: {command} {hint}",
    );
}

fn validate_single_build_path_arg(
    command: &str,
    path: Option<&Path>,
    extra_paths: &[PathBuf],
) -> Result<()> {
    if extra_paths.is_empty() {
        return Ok(());
    }
    let mut paths = Vec::new();
    if let Some(path) = path {
        paths.push(path.display().to_string());
    }
    paths.extend(extra_paths.iter().map(|path| path.display().to_string()));
    anyhow::bail!(
        "{command} accepts one PATH, but got {}: {}. Use `{command} <PROJECT_DIR>` or `{command} <SOURCE.stfl>`",
        paths.len(),
        paths.join(" ")
    );
}

fn path_looks_like_positional_input(path: Option<&Path>) -> bool {
    path.and_then(Path::to_str)
        .is_some_and(|path| path.contains('=') && !Path::new(path).exists())
}

async fn dev(args: DevArgs) -> Result<()> {
    validate_dev_args(&args)?;
    if args.once {
        return run_dev_once(&args).await;
    }

    prepare_dev_run(&args)?;
    println!("Starting Stoffel dev server. Press Ctrl-C to stop.");
    let mut snapshot = WatchSnapshot::capture(args.path.as_deref())?;
    loop {
        if let Err(error) = run_dev_once(&args).await {
            eprintln!("dev run failed: {error:#}");
        }
        println!("Watching for changes...");
        snapshot
            .wait_for_change(args.path.as_deref(), Duration::from_millis(args.poll_ms))
            .await?;
        println!("Change detected. Reloading...");
    }
}

async fn run_dev_once(args: &DevArgs) -> Result<()> {
    let builder = prepare_dev_run(args)?;
    let result = builder
        .execute_local_function_with_timeout(&args.entry, Duration::from_secs(args.timeout_secs))
        .await?;
    print_values(&result);
    Ok(())
}

fn prepare_dev_run(args: &DevArgs) -> Result<Stoffel> {
    let build = BuildArgs {
        path: args.path.clone(),
        extra_paths: Vec::new(),
        output: None,
        disassemble: false,
        binary: false,
        print_ir: false,
        opt_level: None,
        optimize: false,
        release: false,
        backend: args.backend,
        field: args.field,
        parties: args.parties,
        threshold: args.threshold,
        instance_id: None,
    };
    let project = Project::discover(build.path.as_deref())?;
    let source = dev_source_path(&project, build.path.as_deref());
    let inputs = merged_named_inputs(&args.input_files, &args.inputs)?;
    let client_inputs = merged_client_inputs(&args.client_input_files, &args.client_inputs)?;
    let mut builder = apply_run_inputs(
        configured_builder_for_source(&project, &build, &source)?,
        &inputs,
        &client_inputs,
    )?;
    if let Some(path) = &args.runner {
        builder = builder.local_runner_path(path);
    }
    let runtime = builder
        .clone()
        .build()
        .with_context(|| execution_build_context("stoffel dev", build.path.as_deref(), None))?;
    validate_entry_declared_in_source(
        Some(&source),
        runtime.program(),
        &args.entry,
        "stoffel dev",
    )?;
    let inputs = normalize_entry_inputs(runtime.program(), &args.entry, &inputs);
    validate_entry_and_named_inputs(runtime.program(), &args.entry, &inputs, "stoffel dev")?;
    builder = apply_run_inputs(
        configured_builder_for_source(&project, &build, &source)?,
        &inputs,
        &client_inputs,
    )?;
    if let Some(path) = &args.runner {
        builder = builder.local_runner_path(path);
    }
    Ok(builder)
}

fn dev_source_path(project: &Project, path: Option<&Path>) -> PathBuf {
    if let Some(path) = path {
        if path.is_file() && is_source_path(path) {
            return path.to_path_buf();
        }
    }
    project.source_path().to_path_buf()
}

async fn test(args: TestArgs) -> Result<()> {
    validate_test_args(&args)?;
    validate_test_path_hint(args.path.as_deref())?;
    let project = Project::discover(args.path.as_deref())?;
    let mut files = match args.path.as_deref() {
        Some(path) if path.is_file() => {
            ensure_test_file_path(path)?;
            vec![path.to_path_buf()]
        }
        Some(path) if path.is_dir() => {
            select_test_files(&project, args.test.as_deref(), args.integration)?
        }
        Some(path) => anyhow::bail!("{} does not exist", path.display()),
        None => select_test_files(&project, args.test.as_deref(), args.integration)?,
    };
    if files.is_empty() {
        println!(
            "{}",
            no_tests_found_message(args.test.as_deref(), args.integration)
        );
        return Ok(());
    }
    if let Some(name) = args.test.as_deref() {
        if !files.iter().any(|file| test_name_matches_file(file, name)) {
            let mut matching = Vec::new();
            for file in &files {
                if source_declares_function(file, name)? {
                    matching.push(file.clone());
                }
            }
            if matching.is_empty() {
                anyhow::bail!("--test '{name}' did not match any test file or function");
            }
            files = matching;
        }
    }

    let mut failures = 0;
    for file in &files {
        let entry = selected_test_entry(file, args.test.as_deref())?;
        let mut builder = Stoffel::compile_file(file)?;
        if entry != "main" {
            builder = builder.entry_points([entry]);
        }
        let mut runtime = builder.build()?;
        validate_test_entry_has_no_parameters(runtime.program(), entry, file)?;
        let result = if args.local {
            if let Some(path) = &args.runner {
                runtime = runtime.local_runner_path(path);
            }
            runtime.execute_local_function(entry).await
        } else {
            runtime.execute_clear_function(entry)
        };
        match result {
            Ok(values) => {
                print!("ok {}", file.display());
                if args.verbose || !values.is_empty() {
                    print!(" => ");
                    print_inline_values(&values);
                }
                println!();
            }
            Err(error) => {
                failures += 1;
                eprintln!("FAILED {}: {error}", file.display());
            }
        }
    }
    if failures > 0 {
        anyhow::bail!("{failures} Stoffel test(s) failed");
    }
    Ok(())
}

fn validate_test_args(args: &TestArgs) -> Result<()> {
    if !args.inputs.is_empty() {
        anyhow::bail!(
            "stoffel test does not accept --input values; tests must be no-argument functions. Use `stoffel run <PATH> --input NAME=VALUE` for programs that require inputs."
        );
    }
    if args.entry.is_some() {
        anyhow::bail!(
            "stoffel test does not use --entry; use `stoffel test --test <name>` to select a no-argument test function, or use `stoffel run <PATH> --entry <name>` for normal program execution."
        );
    }
    if args.runner.is_some() && !args.local {
        anyhow::bail!(
            "--runner only applies to local MPC tests. Add --local to use the runner, or remove --runner for the embedded no-network test runner."
        );
    }
    if args.local {
        if let Some(path) = args.runner.as_deref() {
            validate_runner_path(path)?;
        }
    }
    Ok(())
}

fn validate_test_path_hint(path: Option<&Path>) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    if path.exists() {
        return Ok(());
    }
    let raw = path.to_string_lossy();
    let looks_like_name = path.components().count() == 1
        && path.extension().is_none()
        && !raw.contains(std::path::MAIN_SEPARATOR);
    if looks_like_name {
        anyhow::bail!(
            "{} does not exist. To select a test by function name or file stem, use `stoffel test --test {}`",
            path.display(),
            path.display()
        );
    }
    Ok(())
}

fn selected_test_entry<'a>(file: &Path, test: Option<&'a str>) -> Result<&'a str> {
    if let Some(name) = test {
        if source_declares_function(file, name)? {
            return Ok(name);
        }
    }
    Ok("main")
}

fn ensure_test_file_path(path: &Path) -> Result<()> {
    if !is_source_path(path) {
        anyhow::bail!(
            "stoffel test expected a .stfl test file or project directory; got {}",
            path.display()
        );
    }
    Ok(())
}

fn no_tests_found_message(test: Option<&str>, integration: bool) -> String {
    match (test, integration) {
        (Some(name), true) => {
            format!("No Stoffel integration tests matched --test '{name}' under tests/")
        }
        (Some(name), false) => format!("No Stoffel tests matched --test '{name}' under tests/"),
        (None, true) => "No Stoffel integration tests found under tests/".to_owned(),
        (None, false) => "No Stoffel tests found under tests/".to_owned(),
    }
}

fn validate_test_entry_has_no_parameters(
    program: &Program,
    entry: &str,
    file: &Path,
) -> Result<()> {
    if !source_declares_function(file, entry)? {
        let available = function_list(program);
        if available.is_empty() {
            anyhow::bail!("test entry '{entry}' not declared in {}", file.display());
        }
        anyhow::bail!(
            "test entry '{entry}' not declared in {}; available functions: {available}. Define `def {entry}(...):` or select a declared no-argument function with `stoffel test --test <name>`",
            file.display()
        );
    }
    let Some(function) = program.function(entry) else {
        let available = function_list(program);
        if available.is_empty() {
            anyhow::bail!("test entry '{entry}' not found in {}", file.display());
        }
        anyhow::bail!(
            "test entry '{entry}' not found in {}; available functions: {available}",
            file.display()
        );
    };
    let parameters = function
        .parameter_names()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if parameters.is_empty() {
        return Ok(());
    }
    let run_inputs = parameters
        .iter()
        .map(|parameter| format!("--input {parameter}=<value>"))
        .collect::<Vec<_>>()
        .join(" ");
    anyhow::bail!(
        "stoffel test only runs no-argument test functions; entry '{entry}' in {} requires inputs: {}. Use `stoffel run {} --entry {entry} {run_inputs}` to execute this program, or put no-argument tests under tests/",
        file.display(),
        parameters.join(", "),
        file.display()
    );
}

fn source_declares_function(file: &Path, entry: &str) -> Result<bool> {
    Ok(declared_function_list(file)?
        .iter()
        .any(|function| function == entry))
}

fn declared_function_list(file: &Path) -> Result<Vec<String>> {
    let raw = std::fs::read_to_string(file)
        .with_context(|| format!("failed to read {}", file.display()))?;
    let mut functions = raw
        .lines()
        .filter_map(declared_function_name)
        .collect::<Vec<_>>();
    functions.sort();
    functions.dedup();
    Ok(functions)
}

fn declared_function_name(line: &str) -> Option<String> {
    let rest = line.trim_start().strip_prefix("def")?;
    if !rest
        .chars()
        .next()
        .is_some_and(|character| character.is_whitespace())
    {
        return None;
    }
    let name = rest
        .trim_start()
        .chars()
        .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
        .collect::<String>();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn closest_name<'a>(needle: &str, candidates: &'a [String]) -> Option<&'a str> {
    candidates
        .iter()
        .map(|candidate| (edit_distance(needle, candidate), candidate.as_str()))
        .filter(|(distance, _)| *distance <= 2)
        .min_by_key(|(distance, _)| *distance)
        .map(|(_, candidate)| candidate)
}

fn edit_distance(left: &str, right: &str) -> usize {
    let left = left.chars().collect::<Vec<_>>();
    let right = right.chars().collect::<Vec<_>>();
    let mut previous = (0..=right.len()).collect::<Vec<_>>();
    let mut current = vec![0; right.len() + 1];
    for (i, left_char) in left.iter().enumerate() {
        current[0] = i + 1;
        for (j, right_char) in right.iter().enumerate() {
            let substitution = previous[j] + usize::from(left_char != right_char);
            let insertion = current[j] + 1;
            let deletion = previous[j + 1] + 1;
            current[j + 1] = substitution.min(insertion).min(deletion);
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[right.len()]
}

fn clean(args: CleanArgs) -> Result<()> {
    let project = Project::discover_for_clean(args.path.as_deref())?;
    let mut removed = Vec::new();
    let mut skipped = Vec::new();
    remove_dir_if_exists(
        project.root(),
        &project.target_dir(),
        args.dry_run,
        &mut removed,
        &mut skipped,
    )?;
    if args.all {
        for path in deep_clean_paths(&project) {
            remove_dir_if_exists(
                project.root(),
                &path,
                args.dry_run,
                &mut removed,
                &mut skipped,
            )?;
        }
    } else {
        remove_dir_if_exists(
            project.root(),
            &project.cache_dir(),
            args.dry_run,
            &mut removed,
            &mut skipped,
        )?;
    }
    if args.dry_run && args.all {
        println!("Would clean Stoffel project artifacts and known ecosystem caches");
    } else if args.dry_run {
        println!("Would clean Stoffel build artifacts");
    } else if args.all {
        println!("Cleaned Stoffel project artifacts and known ecosystem caches");
    } else {
        println!("Cleaned Stoffel build artifacts");
    }
    for path in &removed {
        if args.dry_run {
            println!("Would remove {}", path.display());
        } else {
            println!("Removed {}", path.display());
        }
    }
    if removed.is_empty() {
        println!("Nothing to remove");
    }
    if args.all {
        for path in skipped {
            println!("Skipped missing {}", path.display());
        }
    }
    Ok(())
}

fn status(args: StatusArgs) -> Result<()> {
    let project = Project::discover(args.path.as_deref())?;
    println!("Project: {}", project.config().package.name);
    println!("Root: {}", project.root().display());

    println!("Config: ok ({})", project.config_path().display());
    if args.verbose {
        println!("Source: {}", project.source_path().display());
        println!("Target: {}", project.target_dir().display());
        println!("Cache: {}", project.cache_dir().display());
        println!("Tests: {}", project.root().join("tests").display());
    }
    let mpc = MpcConfig::builder()
        .parties(project.config().mpc.parties.unwrap_or(5))
        .threshold(project.config().mpc.threshold.unwrap_or(1))
        .backend(project.config().mpc.backend.unwrap_or_default())
        .build();
    match mpc {
        Ok(config) => {
            let summary = config.summary()?;
            println!(
                "MPC: ok (backend {}, parties {}, threshold {})",
                summary.backend, summary.parties, summary.threshold
            );
        }
        Err(error) => println!("MPC: invalid ({error})"),
    }

    let dependencies = dependency_statuses(&project);
    if dependencies.is_empty() {
        println!("Dependencies: ok (none declared)");
    } else {
        let ready = dependencies.iter().filter(|dep| dep.ready).count();
        println!("Dependencies: {ready}/{} ready", dependencies.len());
        if args.verbose {
            for dep in &dependencies {
                println!("  {}: {}", dep.name, dep.detail);
            }
        }
    }

    let sources = project.source_files()?;
    let mut compile_failures = 0;
    for source in &sources {
        let build = default_build_for_status(source.clone());
        match configured_builder_for_source(&project, &build, source).and_then(|builder| {
            builder
                .build()
                .map_err(|error| anyhow::anyhow!(error.to_string()))
        }) {
            Ok(runtime) => {
                println!(
                    "Compile: ok {} ({})",
                    source.display(),
                    function_list(runtime.program())
                );
            }
            Err(error) => {
                compile_failures += 1;
                println!("Compile: failed {} ({error})", source.display());
            }
        }
    }
    if sources.is_empty() {
        println!("Compile: no source files found");
    }

    match network_status(&project) {
        Some(status) => println!("Network: {status}"),
        None => println!("Network: not configured"),
    }

    if compile_failures > 0 {
        println!(
            "Next: fix the source error above, then run `stoffel check {}`",
            project.root().display()
        );
        anyhow::bail!("{compile_failures} source file(s) failed to compile");
    }
    Ok(())
}

fn update(args: UpdateArgs) -> Result<()> {
    if args.self_from_source && args.no_self {
        anyhow::bail!(
            "--self-from-source cannot be used with --no-self; remove --no-self to reinstall the CLI from this source checkout"
        );
    }
    if args.no_self && args.no_project {
        anyhow::bail!(
            "no update targets selected; remove --no-self to include the Stoffel CLI or remove --no-project to include project dependencies"
        );
    }
    let project_root = if args.no_project {
        None
    } else {
        Some(update_dependency_root(args.path.as_deref())?)
    };

    if !args.no_self {
        println!("Stoffel CLI: {}", env!("CARGO_PKG_VERSION"));
        if args.check {
            println!(
                "Update check: online version discovery is not configured for this source build"
            );
        }
        update_self(args.check, args.self_from_source)?;
    }

    if let Some(root) = project_root {
        update_project_dependencies(&root, args.check)?;
    }
    Ok(())
}

fn configured_builder(project: &Project, args: &BuildArgs) -> Result<Stoffel> {
    configured_builder_for_source(project, args, project.source_path())
}

fn configured_builder_for_source(
    project: &Project,
    args: &BuildArgs,
    source: &Path,
) -> Result<Stoffel> {
    validate_mpc_overrides(args)?;
    let builder = Stoffel::compile_file(source)?;
    Ok(apply_build_config(builder, project, args))
}

struct RunSource {
    builder: Stoffel,
    bytecode_path: Option<PathBuf>,
    source_path: Option<PathBuf>,
}

fn run_builder(args: &BuildArgs) -> Result<RunSource> {
    validate_mpc_overrides(args)?;
    if let Some(path) = &args.path {
        if is_bytecode_path(path) {
            if !path.exists() {
                anyhow::bail!(
                    "{} does not exist; run `stoffel build` first or pass a project/source path",
                    path.display()
                );
            }
            let builder = load_bytecode_for_run(path)?;
            return Ok(RunSource {
                builder: apply_inline_build_config(builder, args),
                bytecode_path: Some(path.clone()),
                source_path: None,
            });
        }
        validate_explicit_run_path(path)?;
        let project = Project::discover(Some(path))?;
        if path.is_dir() {
            if !is_project_root_dir(&project, path)? {
                anyhow::bail!(
                    "stoffel run expected a project directory containing Stoffel.toml, a .stfl source file, or a .stflb bytecode file; got directory {}. To run the current project, pass {}",
                    path.display(),
                    project.root().display()
                );
            }
            if let Some(bytecode) = project.find_bytecode(args.release)? {
                let builder = load_bytecode_for_run(&bytecode)?;
                return Ok(RunSource {
                    builder: apply_inline_build_config(builder, args),
                    bytecode_path: Some(bytecode),
                    source_path: Some(project.source_path().to_path_buf()),
                });
            }
            return Ok(RunSource {
                builder: configured_builder(&project, args)?,
                bytecode_path: None,
                source_path: Some(project.source_path().to_path_buf()),
            });
        }
        ensure_run_path(path)?;
        return Ok(RunSource {
            builder: configured_builder_for_source(&project, args, path)?,
            bytecode_path: None,
            source_path: Some(path.to_path_buf()),
        });
    }

    let project = Project::discover(None)?;
    if let Some(bytecode) = project.find_bytecode(args.release)? {
        let builder = load_bytecode_for_run(&bytecode)?;
        return Ok(RunSource {
            builder: apply_inline_build_config(builder, args),
            bytecode_path: Some(bytecode),
            source_path: Some(project.source_path().to_path_buf()),
        });
    }
    Ok(RunSource {
        builder: configured_builder(&project, args)?,
        bytecode_path: None,
        source_path: Some(project.source_path().to_path_buf()),
    })
}

fn validate_explicit_build_path(path: Option<&Path>) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    if path.exists() && !path.is_dir() && !is_source_path(path) {
        ensure_source_path(path)?;
    }
    Ok(())
}

fn validate_explicit_run_path(path: &Path) -> Result<()> {
    if path.exists() && !path.is_dir() && !is_source_path(path) && !is_bytecode_path(path) {
        ensure_run_path(path)?;
    }
    Ok(())
}

fn load_bytecode_for_run(path: &Path) -> Result<Stoffel> {
    Stoffel::load_file(path).with_context(|| {
        format!(
            "failed to load bytecode {}; run `stoffel build` to regenerate it or pass a .stfl source/project path",
            path.display()
        )
    })
}

/// Bridge the project's optimizer budgets into the environment knobs the
/// compiler reads (`optimizations.rs` consults these at -O3). The compile runs
/// in-process after the builder is configured, so setting them here takes effect
/// for this run. An explicitly set environment variable wins, so a one-off
/// `STOFFEL_UNROLL_BUDGET=… stoffel run` still overrides the project file.
fn apply_optimizer_budget_env(build: &BuildConfig) {
    let set_if_unset = |name: &str, value: Option<u64>| {
        if let Some(value) = value {
            if std::env::var_os(name).is_none() {
                std::env::set_var(name, value.to_string());
            }
        }
    };
    set_if_unset("STOFFEL_INLINE_BUDGET", build.inline_budget);
    set_if_unset("STOFFEL_UNROLL_BUDGET", build.unroll_budget);
    set_if_unset("STOFFEL_UNROLL_MAX_EXPANSION", build.unroll_max_expansion);
}

fn apply_build_config(builder: Stoffel, project: &Project, args: &BuildArgs) -> Stoffel {
    let mut builder = builder;
    let config = project.config();
    let mut backend = args.backend.or(config.mpc.backend);
    if let Some(field) = args.field.or(config.mpc.curve) {
        if !matches!(backend, Some(MpcBackend::HoneyBadger)) || field != Curve::Bls12_381 {
            backend = Some(MpcBackend::Avss { curve: field });
        }
    }
    if let Some(backend) = backend {
        builder = builder.backend(backend);
    }
    let opt_level = effective_opt_level(args, config.build.optimization_level);
    builder = builder
        .optimization_level(opt_level)
        .optimize(args.optimize || opt_level > 0)
        .print_ir(args.print_ir);
    apply_optimizer_budget_env(&config.build);
    if let Some(parties) = args.parties.or(config.mpc.parties) {
        builder = builder.parties(parties);
    }
    if let Some(threshold) = args.threshold.or(config.mpc.threshold) {
        builder = builder.threshold(threshold);
    }
    if let Some(instance_id) = args.instance_id.or(config.mpc.instance_id) {
        builder = builder.instance_id(instance_id);
    }
    builder
}

fn apply_inline_build_config(mut builder: Stoffel, args: &BuildArgs) -> Stoffel {
    if let Some(backend) = args.backend {
        builder = builder.backend(backend);
    }
    if let Some(field) = args.field {
        builder = builder.curve(field);
    }
    let opt_level = effective_opt_level(args, None);
    builder = builder
        .optimization_level(opt_level)
        .optimize(args.optimize || opt_level > 0)
        .print_ir(args.print_ir);
    if let Some(parties) = args.parties {
        builder = builder.parties(parties);
    }
    if let Some(threshold) = args.threshold {
        builder = builder.threshold(threshold);
    }
    if let Some(instance_id) = args.instance_id {
        builder = builder.instance_id(instance_id);
    }
    builder
}

fn validate_mpc_overrides(args: &BuildArgs) -> Result<()> {
    if matches!(args.threshold, Some(0)) {
        anyhow::bail!("invalid --threshold 0; threshold must be greater than zero");
    }
    if matches!(args.parties, Some(0)) {
        anyhow::bail!("invalid --parties 0; parties must be greater than zero");
    }
    Ok(())
}

fn effective_opt_level(args: &BuildArgs, configured: Option<u8>) -> u8 {
    args.opt_level
        .or(configured)
        .unwrap_or(if args.release { 3 } else { 2 })
}

fn selected_sources(project: &Project, args: &BuildArgs) -> Result<Vec<PathBuf>> {
    if let Some(path) = &args.path {
        if path.is_dir() {
            if is_project_root_dir(project, path)? {
                project.source_files()
            } else {
                let sources = project.source_files_under(path)?;
                if sources.is_empty() {
                    anyhow::bail!(
                        "no .stfl source files found under {}; pass project directory {} to use build.source from Stoffel.toml",
                        path.display(),
                        project.root().display()
                    );
                }
                Ok(sources)
            }
        } else {
            ensure_source_path(path)?;
            Ok(vec![path.clone()])
        }
    } else {
        project.source_files()
    }
}

fn is_project_root_dir(project: &Project, path: &Path) -> Result<bool> {
    let explicit = path
        .canonicalize()
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    let root = project
        .root()
        .canonicalize()
        .with_context(|| format!("failed to inspect {}", project.root().display()))?;
    Ok(explicit == root)
}

fn ensure_source_path(path: &Path) -> Result<()> {
    if is_toml_path(path) {
        if is_project_config_path(path) {
            anyhow::bail!(
                "got project config {}; pass the project directory instead",
                path.display()
            );
        }
        anyhow::bail!(
            "got TOML config {}; build/check expect a project directory, source directory, or .stfl source file",
            path.display()
        );
    }
    if !is_source_path(path) {
        anyhow::bail!(
            "expected a .stfl source file or project directory; got {}",
            path.display()
        );
    }
    Ok(())
}

fn ensure_run_path(path: &Path) -> Result<()> {
    if is_toml_path(path) {
        if is_project_config_path(path) {
            anyhow::bail!(
                "got project config {}; pass the project directory instead",
                path.display()
            );
        }
        anyhow::bail!(
            "got TOML config {}; use `stoffel run <PROJECT> --config {}` for network execution, or pass a project/source/bytecode path",
            path.display(),
            path.display()
        );
    }
    if !is_source_path(path) {
        anyhow::bail!(
            "expected a .stfl source file, .stflb bytecode file, or project directory; got {}",
            path.display()
        );
    }
    Ok(())
}

fn is_toml_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("toml"))
}

fn is_project_config_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("Stoffel.toml"))
}

fn project_relative_output(project: &Project, output: PathBuf) -> PathBuf {
    if output.is_absolute() {
        output
    } else {
        project.root().join(output)
    }
}

fn validate_bytecode_output_path(project: &Project, output: &Path) -> Result<()> {
    if output.is_dir() {
        anyhow::bail!(
            "--output must be a .stflb bytecode file path, but {} is a directory",
            output.display()
        );
    }
    if !is_bytecode_path(output) {
        anyhow::bail!(
            "--output must end in .stflb for bytecode output; got {}",
            output.display()
        );
    }
    if let Some(parent) = output.parent() {
        if parent.exists() && !parent.is_dir() {
            anyhow::bail!(
                "--output parent path {} is a file, not a directory",
                parent.display()
            );
        }
    }
    if let Ok(relative) = output.strip_prefix(project.root()) {
        if relative
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            anyhow::bail!(
                "--output must not contain parent-directory segments (`..`); got {}",
                output.display()
            );
        }
        if relative.starts_with("src") {
            anyhow::bail!(
                "--output must not write bytecode under src/; use a path under target/ instead"
            );
        }
        validate_project_controlled_path(project.root(), output, false)?;
    }
    Ok(())
}

fn disassemble(args: BuildArgs) -> Result<()> {
    validate_disassemble_args(&args)?;
    let path = args
        .path
        .as_ref()
        .context("--disassemble requires a bytecode path")?;
    if !is_bytecode_path(path) {
        anyhow::bail!(
            "--disassemble requires .stflb bytecode; run `stoffel build` first or omit --disassemble to compile source"
        );
    }
    if !path.exists() {
        anyhow::bail!("{} does not exist", path.display());
    }
    let runtime = Stoffel::load_file(path)?.build()?;
    print!("{}", runtime.program().disassemble());
    Ok(())
}

fn validate_disassemble_args(args: &BuildArgs) -> Result<()> {
    let mut ignored = Vec::new();
    if args.output.is_some() {
        ignored.push("--output");
    }
    if args.print_ir {
        ignored.push("--print-ir");
    }
    if args.opt_level.is_some() {
        ignored.push("--opt-level");
    }
    if args.optimize {
        ignored.push("--optimize");
    }
    if args.release {
        ignored.push("--release");
    }
    if args.backend.is_some() {
        ignored.push("--backend");
    }
    if args.field.is_some() {
        ignored.push("--field");
    }
    if args.parties.is_some() {
        ignored.push("--parties");
    }
    if args.threshold.is_some() {
        ignored.push("--threshold");
    }
    if args.instance_id.is_some() {
        ignored.push("--instance-id");
    }
    if !ignored.is_empty() {
        anyhow::bail!(
            "--disassemble reads existing bytecode and cannot be combined with compile options: {}",
            ignored.join(", ")
        );
    }
    Ok(())
}

enum RunNetworkConfig {
    OffChain(OffChainClientConfig),
    Network(NetworkConfig),
}

fn read_run_network_config(path: &Path) -> Result<RunNetworkConfig> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    if looks_like_project_config(&raw) {
        anyhow::bail!(
            "--config expects an MPC network/off-chain client config, but {} looks like a Stoffel project config; pass the project path as PATH instead",
            path.display()
        );
    }
    if let Ok(config) = toml::from_str::<OffChainClientConfig>(&raw) {
        config.validate().map_err(|error| {
            anyhow::anyhow!(clean_repeated_invalid_config_prefix(&error.to_string()))
        })?;
        return Ok(RunNetworkConfig::OffChain(config));
    }
    NetworkConfig::from_toml_str(&raw)
        .map(RunNetworkConfig::Network)
        .map_err(|error| {
            anyhow::anyhow!(
                "failed to parse {} as off-chain or network config: {}",
                path.display(),
                clean_repeated_invalid_config_prefix(&error.to_string())
            )
        })
}

fn clean_repeated_invalid_config_prefix(error: &str) -> String {
    let repeated = "Invalid configuration: Invalid configuration: ";
    if let Some(rest) = error.strip_prefix(repeated) {
        format!("Invalid configuration: {rest}")
    } else {
        error.to_owned()
    }
}

fn looks_like_project_config(raw: &str) -> bool {
    let Ok(value) = toml::from_str::<toml::Value>(raw) else {
        return false;
    };
    let Some(table) = value.as_table() else {
        return false;
    };
    table.contains_key("package") || table.contains_key("build")
}

fn resolve_network_config_path(path: &Path, build: &BuildArgs) -> PathBuf {
    if path.exists() || path.is_absolute() {
        return path.to_path_buf();
    }
    let Some(project_path) = build.path.as_deref() else {
        return path.to_path_buf();
    };
    let Ok(project) = Project::discover(Some(project_path)) else {
        return path.to_path_buf();
    };
    let candidate = project.root().join(path);
    if candidate.exists() {
        candidate
    } else {
        path.to_path_buf()
    }
}

fn validate_network_config_path(path: &Path) -> Result<()> {
    if !path.exists() {
        anyhow::bail!("network config {} does not exist", path.display());
    }
    if path.is_dir() {
        anyhow::bail!(
            "network config {} is a directory; expected a TOML file",
            path.display()
        );
    }
    if path.extension().and_then(|extension| extension.to_str()) != Some("toml") {
        anyhow::bail!(
            "network config must be a .toml file; got {}",
            path.display()
        );
    }
    if path.file_name().and_then(|name| name.to_str()) == Some("Stoffel.toml") {
        anyhow::bail!(
            "--config expects an MPC network/off-chain client config, not project Stoffel.toml; pass the project path as PATH instead"
        );
    }
    Ok(())
}

fn select_test_files(
    project: &Project,
    test: Option<&str>,
    integration: bool,
) -> Result<Vec<PathBuf>> {
    let mut files = project.test_files()?;
    if integration {
        files.retain(|path| is_integration_test_file(path));
    }
    if let Some(name) = test {
        let matching_files = files
            .iter()
            .filter(|path| test_name_matches_file(path, name))
            .cloned()
            .collect::<Vec<_>>();
        if !matching_files.is_empty() {
            return Ok(matching_files);
        }
    }
    Ok(files)
}

fn test_name_matches_file(path: &Path, name: &str) -> bool {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .is_some_and(|stem| stem == name)
}

fn is_integration_test_file(path: &Path) -> bool {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .is_some_and(|stem| stem.contains("integration"))
}

fn ensure_writable_project_dir(path: &Path, force: bool) -> Result<()> {
    if path.exists() && !path.is_dir() {
        anyhow::bail!(
            "{} is a file; pass a directory path for the new Stoffel project",
            path.display()
        );
    }
    if path.exists() && !force && std::fs::read_dir(path)?.next().is_some() {
        if path.join("Stoffel.toml").exists() {
            anyhow::bail!(
                "{} already contains Stoffel.toml; use `stoffel status {}` or `stoffel run {}` for this project, or pass --force to refresh template files",
                path.display(),
                path.display(),
                path.display()
            );
        }
        anyhow::bail!(
            "{} already exists and is not empty; pass --force to write Stoffel template files while preserving unrelated files",
            path.display()
        );
    }
    std::fs::create_dir_all(path)?;
    Ok(())
}

fn is_bytecode_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("stflb"))
}

fn is_source_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("stfl"))
}

fn apply_inputs(mut builder: Stoffel, inputs: &[InputArg]) -> Stoffel {
    for input in inputs {
        builder = builder.with_input(input.name.clone(), input.value.clone());
    }
    builder
}

fn merged_named_inputs(input_files: &[PathBuf], explicit: &[InputArg]) -> Result<Vec<InputArg>> {
    let mut inputs = Vec::new();
    for path in input_files {
        let loaded = stoffel::load_named_inputs_file(path)
            .with_context(|| format!("failed to load input file {}", path.display()))?;
        inputs.extend(
            loaded
                .into_iter()
                .map(|(name, value)| InputArg { name, value }),
        );
    }
    for input in explicit {
        inputs.retain(|existing| existing.name != input.name);
    }
    inputs.extend(explicit.iter().cloned());
    Ok(inputs)
}

fn merged_client_inputs(
    input_files: &[PathBuf],
    explicit: &[ClientInputArg],
) -> Result<Vec<ClientInputArg>> {
    let mut inputs = Vec::new();
    for path in input_files {
        let loaded = stoffel::load_client_inputs_file(path)
            .with_context(|| format!("failed to load client input file {}", path.display()))?;
        for (client_slot, values) in loaded {
            inputs.extend(
                values
                    .into_iter()
                    .map(|value| ClientInputArg { client_slot, value }),
            );
        }
    }
    for input in explicit {
        inputs.retain(|existing| existing.client_slot != input.client_slot);
    }
    inputs.extend(explicit.iter().cloned());
    Ok(inputs)
}

fn apply_run_inputs(
    builder: Stoffel,
    inputs: &[InputArg],
    client_inputs: &[ClientInputArg],
) -> Result<Stoffel> {
    let mut builder = apply_inputs(builder, inputs);
    let mut grouped = BTreeMap::<u64, Vec<Value>>::new();
    for input in client_inputs {
        grouped
            .entry(input.client_slot)
            .or_default()
            .push(input.value.clone());
    }
    for (client_slot, values) in grouped {
        builder = builder.with_client_input(client_slot, &values);
    }
    Ok(builder)
}

fn normalize_entry_inputs(program: &Program, entry: &str, inputs: &[InputArg]) -> Vec<InputArg> {
    let Some(function) = program.function(entry) else {
        return inputs.to_vec();
    };
    let parameter_types = function
        .parameter_names()
        .zip(function.parameter_types())
        .collect::<BTreeMap<_, _>>();
    inputs
        .iter()
        .map(|input| {
            let value = parameter_types
                .get(input.name.as_str())
                .map(|ty| normalize_input_value_for_type(&input.value, ty))
                .unwrap_or_else(|| input.value.clone());
            InputArg {
                name: input.name.clone(),
                value,
            }
        })
        .collect()
}

fn normalize_input_value_for_type(value: &Value, ty: &FunctionType) -> Value {
    match ty.underlying_type() {
        FunctionType::Int { signed, bits } => normalize_integer_input_value(value, *signed, *bits),
        FunctionType::Bool => match value {
            Value::I64(0) | Value::U64(0) => Value::Bool(false),
            Value::I64(1) | Value::U64(1) => Value::Bool(true),
            _ => value.clone(),
        },
        FunctionType::List(element_type) => match value {
            Value::List(values) => Value::List(
                values
                    .iter()
                    .map(|value| normalize_input_value_for_type(value, element_type))
                    .collect(),
            ),
            _ => value.clone(),
        },
        _ => value.clone(),
    }
}

fn normalize_integer_input_value(value: &Value, signed: bool, bits: u8) -> Value {
    let max_unsigned = if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };

    if signed {
        let min = if bits >= 64 {
            i64::MIN
        } else {
            -(1i64 << (bits - 1))
        };
        let max = if bits >= 64 {
            i64::MAX
        } else {
            (1i64 << (bits - 1)) - 1
        };
        return match value {
            Value::U64(value) if *value <= max as u64 => Value::I64(*value as i64),
            Value::I64(value) if *value >= min && *value <= max => Value::I64(*value),
            _ => value.clone(),
        };
    }

    match value {
        Value::I64(value) if *value >= 0 && (*value as u64) <= max_unsigned => {
            Value::U64(*value as u64)
        }
        Value::U64(value) if *value <= max_unsigned => Value::U64(*value),
        _ => value.clone(),
    }
}

fn validate_entry_and_named_inputs(
    program: &Program,
    entry: &str,
    inputs: &[InputArg],
    command: &str,
) -> Result<()> {
    let function = program.function(entry).ok_or_else(|| {
        let available = function_list(program);
        if available.is_empty() {
            anyhow::anyhow!("function '{entry}' not found")
        } else {
            anyhow::anyhow!("function '{entry}' not found; available functions: {available}")
        }
    })?;
    let parameters = function
        .parameter_names()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let input_help = named_input_help(command, entry, &parameters);
    let sdk_inputs = inputs
        .iter()
        .map(|input| (input.name.clone(), input.value.clone()))
        .collect::<Vec<_>>();
    program
        .validate_function_inputs(entry, &sdk_inputs)
        .map_err(|error| anyhow::anyhow!("{error}. {input_help}"))
}

fn validate_entry_declared_in_source(
    source: Option<&Path>,
    _program: &Program,
    entry: &str,
    command: &str,
) -> Result<()> {
    let Some(source) = source else {
        return Ok(());
    };
    if source_declares_function(source, entry)? {
        return Ok(());
    }
    let available = declared_function_list(source)?;
    if available.is_empty() {
        anyhow::bail!(
            "entry function '{entry}' is not declared in {}; define `def {entry}(...):` before running `{command}`",
            source.display()
        );
    }
    let hint = closest_name(entry, &available)
        .map(|name| format!(" Did you mean --entry {name}?"))
        .unwrap_or_else(|| format!(" Available source functions: {}.", available.join(", ")));
    anyhow::bail!(
        "entry function '{entry}' is not declared in {}.{}",
        source.display(),
        hint
    );
}

fn named_input_help(command: &str, entry: &str, parameters: &[String]) -> String {
    if parameters.is_empty() {
        return "This function does not accept --input values.".to_owned();
    }
    let expected = parameters
        .iter()
        .map(|parameter| format!("--input {parameter}=<value>"))
        .collect::<Vec<_>>()
        .join(" ");
    format!("Pass inputs as: {command} --entry {entry} {expected}")
}

fn default_build_for_status(path: PathBuf) -> BuildArgs {
    BuildArgs {
        path: Some(path),
        extra_paths: Vec::new(),
        output: None,
        disassemble: false,
        binary: false,
        print_ir: false,
        opt_level: None,
        optimize: false,
        release: false,
        backend: None,
        field: None,
        parties: None,
        threshold: None,
        instance_id: None,
    }
}

#[derive(Debug)]
struct DependencyStatus {
    name: &'static str,
    ready: bool,
    detail: String,
}

fn dependency_statuses(project: &Project) -> Vec<DependencyStatus> {
    let root = project.root();
    let mut statuses = Vec::new();
    if root.join("Cargo.toml").exists() {
        let ready = command_exists("cargo");
        statuses.push(DependencyStatus {
            name: "cargo",
            ready,
            detail: command_dependency_detail("Cargo.toml detected", "cargo", ready),
        });
    }
    if root.join("package.json").exists() {
        let ready = command_exists("npm");
        statuses.push(DependencyStatus {
            name: "npm",
            ready,
            detail: command_dependency_detail("package.json detected", "npm", ready),
        });
    }
    if root.join("requirements.txt").exists() || root.join("pyproject.toml").exists() {
        let ready = command_exists("python3") || command_exists("python");
        statuses.push(DependencyStatus {
            name: "python",
            ready,
            detail: if ready {
                "Python dependency manifest detected; python available".to_owned()
            } else {
                "Python dependency manifest detected; required command 'python3' or 'python' not found in PATH".to_owned()
            },
        });
    }
    if root.join("foundry.toml").exists() {
        let ready = command_exists("forge");
        statuses.push(DependencyStatus {
            name: "foundry",
            ready,
            detail: command_dependency_detail("foundry.toml detected", "forge", ready),
        });
    }
    if root.join("hardhat.config.js").exists() || root.join("hardhat.config.ts").exists() {
        let ready = command_exists("npm");
        statuses.push(DependencyStatus {
            name: "hardhat",
            ready,
            detail: command_dependency_detail("Hardhat config detected", "npm", ready),
        });
    }
    statuses
}

fn command_dependency_detail(manifest: &str, command: &str, ready: bool) -> String {
    if ready {
        format!("{manifest}; {command} available")
    } else {
        format!("{manifest}; required command '{command}' not found in PATH")
    }
}

fn network_status(project: &Project) -> Option<String> {
    let config = project.config();
    let backend = config.mpc.backend.unwrap_or_default();
    let parties = config.mpc.parties.unwrap_or(5);
    let threshold = config.mpc.threshold.unwrap_or(1);
    if let Err(error) = MpcConfig::builder()
        .parties(parties)
        .threshold(threshold)
        .backend(backend)
        .build()
    {
        return Some(format!("invalid ({error})"));
    }
    Some(format!(
        "configured for local {backend} development ({parties} parties, threshold {threshold}); no live network probe configured"
    ))
}

fn update_self(check: bool, self_from_source: bool) -> Result<()> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    if check {
        println!(
            "CLI self-update: source checkout detected at {}",
            manifest_dir.display()
        );
        return Ok(());
    }
    if !self_from_source {
        println!(
            "CLI self-update: source checkout detected at {}; skipped. Re-run with --self-from-source to reinstall from this checkout, or --no-self to skip this message.",
            manifest_dir.display()
        );
        return Ok(());
    }
    println!("Updating Stoffel CLI from local source...");
    run_command(
        manifest_dir,
        "cargo",
        &["install", "--path", ".", "--force"],
    )
}

fn update_dependency_root(path: Option<&Path>) -> Result<PathBuf> {
    if let Some(root) = dependency_manifest_start_root(path)? {
        return Ok(root);
    }
    match Project::discover(path) {
        Ok(project) => Ok(project.root().to_path_buf()),
        Err(project_error) => {
            if let Some(root) = find_dependency_manifest_root(path)? {
                return Ok(root);
            }
            Err(project_error)
        }
    }
}

fn dependency_manifest_start_root(path: Option<&Path>) -> Result<Option<PathBuf>> {
    let root = match path {
        Some(path) if !path.exists() => return Ok(None),
        Some(path) if path.is_dir() => path.to_path_buf(),
        Some(path) => path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(".")),
        None => std::env::current_dir()?,
    };
    Ok(has_dependency_manifest(&root).then_some(root))
}

fn find_dependency_manifest_root(path: Option<&Path>) -> Result<Option<PathBuf>> {
    let start = match path {
        Some(path) if !path.exists() => return Ok(None),
        Some(path) if path.is_dir() => path.to_path_buf(),
        Some(path) => path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(".")),
        None => std::env::current_dir()?,
    };
    let mut cursor = start.as_path();
    loop {
        if has_dependency_manifest(cursor) {
            return Ok(Some(cursor.to_path_buf()));
        }
        let Some(parent) = cursor.parent() else {
            return Ok(None);
        };
        if parent == cursor {
            return Ok(None);
        }
        cursor = parent;
    }
}

fn has_dependency_manifest(root: &Path) -> bool {
    root.join("Cargo.toml").exists()
        || root.join("package.json").exists()
        || root.join("requirements.txt").exists()
        || root.join("foundry.toml").exists()
}

fn update_project_dependencies(root: &Path, check: bool) -> Result<()> {
    let mut detected = false;

    if root.join("Cargo.toml").exists() {
        detected = true;
        if check {
            println!(
                "Project update: Cargo.toml detected; {}",
                update_command_status("cargo")
            );
        } else {
            run_command(root, "cargo", &["update"])?;
        }
    }
    if root.join("package.json").exists() {
        detected = true;
        if check {
            println!(
                "Project update: package.json detected; {}",
                update_command_status("npm")
            );
        } else {
            run_command(root, "npm", &["update"])?;
        }
    }
    if root.join("requirements.txt").exists() {
        detected = true;
        if check {
            match python_command() {
                Some(program) => {
                    println!("Project update: requirements.txt detected; {program} available")
                }
                None => println!(
                    "Project update: requirements.txt detected; required command 'python3' or 'python' not found in PATH"
                ),
            }
        } else {
            let Some(program) = python_command() else {
                anyhow::bail!("required command 'python3' or 'python' was not found in PATH");
            };
            run_command(
                root,
                program,
                &[
                    "-m",
                    "pip",
                    "install",
                    "--upgrade",
                    "-r",
                    "requirements.txt",
                ],
            )?;
        }
    }
    if root.join("foundry.toml").exists() {
        detected = true;
        if check {
            println!(
                "Project update: foundry.toml detected; {}",
                update_command_status("forge")
            );
        } else {
            run_command(root, "forge", &["update"])?;
        }
    }

    if !detected {
        println!("Project update: no dependency manifests detected");
    }
    Ok(())
}

fn update_command_status(program: &str) -> String {
    if command_exists(program) {
        format!("{program} available")
    } else {
        format!("required command '{program}' not found in PATH")
    }
}

fn python_command() -> Option<&'static str> {
    if command_exists("python3") {
        Some("python3")
    } else if command_exists("python") {
        Some("python")
    } else {
        None
    }
}

fn run_command(cwd: &Path, program: &str, args: &[&str]) -> Result<()> {
    if !command_exists(program) {
        anyhow::bail!("required command '{program}' was not found in PATH");
    }
    println!("Running: {} {}", program, args.join(" "));
    let status = ProcessCommand::new(program)
        .args(args)
        .current_dir(cwd)
        .status()
        .with_context(|| format!("failed to start {program}"))?;
    if !status.success() {
        anyhow::bail!(
            "command '{program} {}' failed with {status}",
            args.join(" ")
        );
    }
    Ok(())
}

fn command_exists(program: &str) -> bool {
    ProcessCommand::new(program)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn deep_clean_paths(project: &Project) -> Vec<PathBuf> {
    let root = project.root();
    let mut paths = vec![
        root.join(".stoffel"),
        root.join("node_modules"),
        root.join(".pytest_cache"),
        root.join("__pycache__"),
    ];
    if root.join("foundry.toml").exists() {
        paths.push(root.join("out"));
        paths.push(root.join("cache"));
    }
    if root.join("hardhat.config.js").exists() || root.join("hardhat.config.ts").exists() {
        paths.push(root.join("artifacts"));
        paths.push(root.join("cache"));
    }
    paths.sort();
    paths.dedup();
    paths
}

fn parse_opt_level(raw: &str) -> std::result::Result<u8, String> {
    if raw.starts_with("-O") {
        return Err("use -O3 or --opt-level 3; do not write --opt-level -O3".to_owned());
    }
    let level = raw
        .parse::<u8>()
        .map_err(|_| format!("invalid optimization level '{raw}'; use 0, 1, 2, or 3"))?;
    if level > 3 {
        return Err(format!(
            "invalid optimization level '{raw}'; use 0, 1, 2, or 3"
        ));
    }
    Ok(level)
}

fn parse_u64_arg(raw: &str) -> std::result::Result<u64, String> {
    if raw.starts_with('-') {
        return Err(format!(
            "'{raw}' is not valid here; use 0 or a positive whole number"
        ));
    }
    raw.parse::<u64>()
        .map_err(|_| format!("invalid value '{raw}'; use 0 or a positive whole number"))
}

fn parse_client_output_count_arg(raw: &str) -> std::result::Result<(u64, u64), String> {
    let (slot, count) = raw
        .split_once('=')
        .ok_or_else(|| format!("expected SLOT=COUNT, got '{raw}'"))?;
    let slot = slot
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("invalid client slot '{slot}'; use a whole number"))?;
    let count = count
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("invalid output count '{count}'; use a whole number"))?;
    Ok((slot, count))
}

fn parse_positive_usize_arg(raw: &str) -> std::result::Result<usize, String> {
    if raw.starts_with('-') {
        return Err(format!(
            "'{raw}' is not valid here; use a positive whole number"
        ));
    }
    let value = raw
        .parse::<usize>()
        .map_err(|_| format!("invalid value '{raw}'; use a positive whole number"))?;
    if value == 0 {
        return Err("0 is not valid here; use a positive whole number".to_owned());
    }
    Ok(value)
}

fn parse_positive_u64_arg(raw: &str) -> std::result::Result<u64, String> {
    if raw.starts_with('-') {
        return Err(format!(
            "'{raw}' is not valid here; use a positive whole number"
        ));
    }
    let value = raw
        .parse::<u64>()
        .map_err(|_| format!("invalid value '{raw}'; use a positive whole number"))?;
    if value == 0 {
        return Err("0 is not valid here; use a positive whole number".to_owned());
    }
    Ok(value)
}

fn parse_entry_arg(raw: &str) -> std::result::Result<String, String> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(
            "entry function name cannot be empty; use a function name like main".to_owned(),
        );
    }
    if value.contains('(') || value.contains(')') {
        return Err(format!(
            "entry must be a function name, not a call expression; use --entry {}",
            value
                .split_once('(')
                .map(|(name, _)| name.trim())
                .filter(|name| !name.is_empty())
                .unwrap_or("main")
        ));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(
            "entry function name cannot contain spaces; use a single function name like main"
                .to_owned(),
        );
    }
    if !is_identifier_like(value) {
        return Err(
            "entry function name must use letters, numbers, or '_' and must not start with a number"
                .to_owned(),
        );
    }
    Ok(value.to_owned())
}

fn is_identifier_like(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

fn parse_test_filter_arg(raw: &str) -> std::result::Result<String, String> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(
            "--test value cannot be empty; pass a test function name or test file stem".to_owned(),
        );
    }
    Ok(value.to_owned())
}

fn parse_value(value: &str) -> Result<Value> {
    let value = value.trim();
    if value.starts_with('[') {
        return parse_list_value(value);
    }
    if value.starts_with('{') {
        return parse_object_value(value);
    }
    if let Some(quoted) = parse_quoted_string(value)? {
        return Ok(Value::String(quoted));
    }
    let comma_parts = split_top_level_commas(value)?;
    if comma_parts.len() > 1 {
        return parse_bare_list_value(comma_parts);
    }
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        return Ok(Value::Bytes(parse_hex_bytes(hex)?));
    }
    if let Some(value) = parse_suffixed_integer_value(value)? {
        return Ok(value);
    }
    if let Ok(value) = value.parse::<i64>() {
        return Ok(Value::I64(value));
    }
    if let Ok(value) = value.parse::<u64>() {
        return Ok(Value::U64(value));
    }
    if let Ok(value) = value.parse::<bool>() {
        return Ok(Value::Bool(value));
    }
    if let Ok(value) = value.parse::<f64>() {
        return Ok(Value::Float(value));
    }
    Ok(Value::String(value.to_owned()))
}

fn parse_suffixed_integer_value(value: &str) -> Result<Option<Value>> {
    let lower = value.to_ascii_lowercase();
    let suffixes = [
        ("uint64", false),
        ("uint32", false),
        ("uint16", false),
        ("uint8", false),
        ("u64", false),
        ("u32", false),
        ("u16", false),
        ("u8", false),
        ("int64", true),
        ("int32", true),
        ("int16", true),
        ("int8", true),
        ("i64", true),
        ("i32", true),
        ("i16", true),
        ("i8", true),
    ];

    for (suffix, signed) in suffixes {
        let Some(number) = lower.strip_suffix(suffix) else {
            continue;
        };
        if number.is_empty() || number == "-" || number == "+" {
            anyhow::bail!("integer suffix '{suffix}' must follow a numeric value");
        }
        if signed {
            return number
                .parse::<i64>()
                .map(Value::I64)
                .map(Some)
                .map_err(|error| anyhow::anyhow!("invalid signed integer '{value}': {error}"));
        }
        if number.starts_with('-') {
            anyhow::bail!("unsigned integer '{value}' cannot be negative");
        }
        return number
            .parse::<u64>()
            .map(Value::U64)
            .map(Some)
            .map_err(|error| anyhow::anyhow!("invalid unsigned integer '{value}': {error}"));
    }

    Ok(None)
}

fn parse_object_value(value: &str) -> Result<Value> {
    if !value.ends_with('}') {
        anyhow::bail!("object input must end with '}}'");
    }
    let inner = &value[1..value.len() - 1];
    let mut fields = BTreeMap::new();
    for field in split_top_level_commas(inner)? {
        let field = field.trim();
        if field.is_empty() {
            anyhow::bail!("object input contains an empty field");
        }
        let Some((key, value)) = split_top_level_once(field, ':')? else {
            anyhow::bail!("object field '{field}' must be written as key: value");
        };
        let key = parse_object_key(key.trim())?;
        if key.is_empty() {
            anyhow::bail!("object field name cannot be empty");
        }
        let value = value.trim();
        if value.is_empty() {
            anyhow::bail!("object field '{key}' must include a value");
        }
        if fields.insert(key.clone(), parse_value(value)?).is_some() {
            anyhow::bail!("object input contains duplicate field '{key}'");
        }
    }
    Ok(Value::Object(fields))
}

fn parse_list_value(value: &str) -> Result<Value> {
    if !value.ends_with(']') {
        anyhow::bail!("list input must end with ']'");
    }
    let inner = &value[1..value.len() - 1];
    let mut values = Vec::new();
    for item in split_top_level_commas(inner)? {
        let item = item.trim();
        if item.is_empty() {
            anyhow::bail!("list input contains an empty element");
        }
        values.push(parse_value(item)?);
    }
    Ok(Value::List(values))
}

fn parse_bare_list_value(parts: Vec<&str>) -> Result<Value> {
    let mut values = Vec::with_capacity(parts.len());
    for item in parts {
        let item = item.trim();
        if item.is_empty() {
            anyhow::bail!("comma-separated list input contains an empty element");
        }
        values.push(parse_value(item)?);
    }
    Ok(Value::List(values))
}

fn split_top_level_commas(value: &str) -> Result<Vec<&str>> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;

    for (index, character) in value.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            continue;
        }

        match character {
            '"' => in_string = true,
            '[' | '{' => depth += 1,
            ']' | '}' => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| anyhow::anyhow!("input has an unexpected closing delimiter"))?;
            }
            ',' if depth == 0 => {
                parts.push(&value[start..index]);
                start = index + character.len_utf8();
            }
            _ => {}
        }
    }

    if in_string {
        anyhow::bail!("list input contains an unterminated string");
    }
    if depth != 0 {
        anyhow::bail!("input contains an unterminated nested list or object");
    }
    if !value.is_empty() {
        parts.push(&value[start..]);
    }
    Ok(parts)
}

fn split_top_level_once(value: &str, delimiter: char) -> Result<Option<(&str, &str)>> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;

    for (index, character) in value.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            continue;
        }

        match character {
            '"' => in_string = true,
            '[' | '{' => depth += 1,
            ']' | '}' => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| anyhow::anyhow!("input has an unexpected closing delimiter"))?;
            }
            character if character == delimiter && depth == 0 => {
                let next = index + character.len_utf8();
                return Ok(Some((&value[..index], &value[next..])));
            }
            _ => {}
        }
    }

    if in_string {
        anyhow::bail!("input contains an unterminated string");
    }
    if depth != 0 {
        anyhow::bail!("input contains an unterminated nested list or object");
    }
    Ok(None)
}

fn parse_object_key(value: &str) -> Result<String> {
    if let Some(quoted) = parse_quoted_string(value)? {
        return Ok(quoted);
    }
    if is_identifier_like(value) {
        return Ok(value.to_owned());
    }
    anyhow::bail!("object field name '{value}' must be an identifier or quoted string")
}

fn parse_quoted_string(value: &str) -> Result<Option<String>> {
    if !value.starts_with('"') {
        return Ok(None);
    }
    if !value.ends_with('"') || value.len() == 1 {
        anyhow::bail!("string input must end with '\"'");
    }

    let mut out = String::new();
    let mut escaped = false;
    for character in value[1..value.len() - 1].chars() {
        if escaped {
            match character {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                other => {
                    anyhow::bail!("unsupported string escape '\\{other}'");
                }
            }
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else {
            out.push(character);
        }
    }
    if escaped {
        anyhow::bail!("string input ends with an incomplete escape");
    }
    Ok(Some(out))
}

fn parse_hex_bytes(raw: &str) -> Result<Vec<u8>> {
    if raw.is_empty() {
        anyhow::bail!("hex byte input must include at least one byte after 0x");
    }
    if !raw.len().is_multiple_of(2) {
        anyhow::bail!(
            "hex byte input must contain an even number of digits; write 0x0{raw} for one byte"
        );
    }
    let mut bytes = Vec::with_capacity(raw.len() / 2);
    for index in (0..raw.len()).step_by(2) {
        let pair = &raw[index..index + 2];
        let byte = u8::from_str_radix(pair, 16).map_err(|error| {
            anyhow::anyhow!(
                "hex byte input contains invalid digits '{pair}' at offset {index}: {error}"
            )
        })?;
        bytes.push(byte);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_value_accepts_bracketed_lists() {
        assert_eq!(
            parse_value("[1, true, 0x0a]").unwrap(),
            Value::List(vec![
                Value::I64(1),
                Value::Bool(true),
                Value::Bytes(vec![10])
            ])
        );
    }

    #[test]
    fn parse_value_accepts_bare_comma_lists() {
        assert_eq!(
            parse_value("1,10").unwrap(),
            Value::List(vec![Value::I64(1), Value::I64(10)])
        );
    }

    #[test]
    fn parse_value_accepts_integer_type_suffixes() {
        assert_eq!(parse_value("3u64").unwrap(), Value::U64(3));
        assert_eq!(parse_value("3uint64").unwrap(), Value::U64(3));
        assert_eq!(parse_value("3U32").unwrap(), Value::U64(3));
        assert_eq!(parse_value("3i64").unwrap(), Value::I64(3));
        assert_eq!(parse_value("-3int64").unwrap(), Value::I64(-3));

        let err = parse_value("-3u64").unwrap_err().to_string();
        assert!(err.contains("cannot be negative"));
    }

    #[test]
    fn normalize_input_value_coerces_integer_values_to_expected_signedness() {
        assert_eq!(
            normalize_input_value_for_type(&Value::I64(3), &FunctionType::uint64()),
            Value::U64(3)
        );
        assert_eq!(
            normalize_input_value_for_type(&Value::U64(3), &FunctionType::int64()),
            Value::I64(3)
        );
        assert_eq!(
            normalize_input_value_for_type(
                &Value::U64(i64::MAX as u64 + 1),
                &FunctionType::int64()
            ),
            Value::U64(i64::MAX as u64 + 1)
        );
    }

    #[test]
    fn normalize_input_value_accepts_numeric_bool_bits_for_secret_bool_lists() {
        let ty = FunctionType::List(Box::new(FunctionType::Secret(Box::new(FunctionType::Bool))));

        assert_eq!(
            normalize_input_value_for_type(
                &Value::List(vec![
                    Value::I64(0),
                    Value::I64(1),
                    Value::Bool(true),
                    Value::I64(2),
                ]),
                &ty,
            ),
            Value::List(vec![
                Value::Bool(false),
                Value::Bool(true),
                Value::Bool(true),
                Value::I64(2),
            ])
        );
    }

    #[test]
    fn parse_value_accepts_nested_lists_and_quoted_strings() {
        assert_eq!(
            parse_value(r#"[[1, 2], "hello, world"]"#).unwrap(),
            Value::List(vec![
                Value::List(vec![Value::I64(1), Value::I64(2)]),
                Value::String("hello, world".to_owned())
            ])
        );
    }

    #[test]
    fn parse_value_accepts_object_literals() {
        let mut expected = BTreeMap::new();
        expected.insert("n".to_owned(), Value::I64(1));
        expected.insert(
            "coeffs".to_owned(),
            Value::List(vec![Value::I64(1), Value::I64(10)]),
        );

        assert_eq!(
            parse_value(r#"{n: 1, "coeffs": [1, 10]}"#).unwrap(),
            Value::Object(expected)
        );
    }

    #[test]
    fn parse_value_rejects_malformed_lists() {
        let err = parse_value("[1, ]").unwrap_err().to_string();
        assert!(err.contains("empty element"));
    }

    #[test]
    fn input_files_merge_before_explicit_cli_values() {
        let named_file = tempfile::NamedTempFile::with_suffix(".json").unwrap();
        std::fs::write(named_file.path(), r#"{"a": 1, "b": 2}"#).unwrap();
        let inputs = merged_named_inputs(
            &[named_file.path().to_path_buf()],
            &[InputArg {
                name: "b".to_owned(),
                value: Value::I64(42),
            }],
        )
        .unwrap();

        assert_eq!(
            inputs,
            vec![
                InputArg {
                    name: "a".to_owned(),
                    value: Value::I64(1),
                },
                InputArg {
                    name: "b".to_owned(),
                    value: Value::I64(42),
                },
            ]
        );

        let client_file = tempfile::NamedTempFile::with_suffix(".txt").unwrap();
        std::fs::write(client_file.path(), "0=1\n0=2\n1=3\n").unwrap();
        let client_inputs = merged_client_inputs(
            &[client_file.path().to_path_buf()],
            &[ClientInputArg {
                client_slot: 0,
                value: Value::I64(99),
            }],
        )
        .unwrap();

        assert_eq!(
            client_inputs,
            vec![
                ClientInputArg {
                    client_slot: 1,
                    value: Value::I64(3),
                },
                ClientInputArg {
                    client_slot: 0,
                    value: Value::I64(99),
                },
            ]
        );
    }
}

fn print_values(values: &[Value]) {
    print_inline_values(values);
    println!();
}

fn print_inline_values(values: &[Value]) {
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            print!(" ");
        }
        print!("{value}");
    }
}

fn function_list(program: &Program) -> String {
    program.function_names().collect::<Vec<_>>().join(", ")
}

fn print_program_summary(program: &Program) {
    let summary = program.summary();
    println!("Functions: {}", summary.function_count);
    println!("Instructions: {}", summary.total_instruction_count);
    println!("Backend: {}", summary.bytecode_backend);
    println!("Curve: {}", summary.bytecode_curve);
    if !summary.client_slots.is_empty() {
        println!("Client slots: {:?}", summary.client_slots);
    }
}

fn print_build_stats(
    output: &Path,
    program: &Program,
    project: &Project,
    args: &BuildArgs,
) -> Result<()> {
    let bytecode = program.bytecode_summary()?;
    let summary = &bytecode.program;
    let opt_level = effective_opt_level(args, project.config().build.optimization_level);
    println!("Built {}", output.display());
    println!("Bytecode size: {} bytes", bytecode.byte_len);
    println!(
        "Optimization: O{} ({})",
        opt_level,
        if opt_level > 0 { "enabled" } else { "disabled" }
    );
    println!(
        "Profile: {}",
        if args.release { "release" } else { "debug" }
    );
    println!("Functions: {}", summary.function_count);
    println!("Instructions: {}", summary.total_instruction_count);
    Ok(())
}

fn remove_dir_if_exists(
    root: &Path,
    path: &Path,
    dry_run: bool,
    removed: &mut Vec<PathBuf>,
    skipped: &mut Vec<PathBuf>,
) -> Result<()> {
    validate_project_controlled_path(root, path, true)?;
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        skipped.push(path.to_path_buf());
        return Ok(());
    };
    if !dry_run {
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            std::fs::remove_dir_all(path)
                .with_context(|| format!("failed to remove {}", path.display()))?;
        } else {
            std::fs::remove_file(path)
                .with_context(|| format!("failed to remove {}", path.display()))?;
        }
    }
    removed.push(path.to_path_buf());
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WatchSnapshot {
    files: BTreeMap<PathBuf, Option<FileFingerprint>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileFingerprint {
    modified: Option<SystemTime>,
    len: u64,
}

impl WatchSnapshot {
    fn capture(path: Option<&Path>) -> Result<Self> {
        let project = Project::discover(path)?;
        let mut files = BTreeMap::new();
        for file in dev_watch_files(&project, path)? {
            files.insert(file.clone(), file_fingerprint(&file));
        }
        Ok(Self { files })
    }

    async fn wait_for_change(&mut self, path: Option<&Path>, interval: Duration) -> Result<()> {
        let interval = if interval.is_zero() {
            Duration::from_millis(500)
        } else {
            interval
        };
        loop {
            tokio::time::sleep(interval).await;
            let next = Self::capture(path)?;
            if next != *self {
                *self = next;
                return Ok(());
            }
        }
    }
}

fn dev_watch_files(project: &Project, path: Option<&Path>) -> Result<Vec<PathBuf>> {
    if let Some(path) = path {
        if path.is_file() && is_source_path(path) {
            let mut files = vec![project.config_path(), path.to_path_buf()];
            files.sort();
            files.dedup();
            return Ok(files);
        }
    }
    project.watch_files()
}

fn file_fingerprint(path: &Path) -> Option<FileFingerprint> {
    let metadata = std::fs::metadata(path).ok()?;
    Some(FileFingerprint {
        modified: metadata.modified().ok(),
        len: metadata.len(),
    })
}
