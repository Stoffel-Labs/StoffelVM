use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use stoffel::prelude::{MpcBackend, MpcConfig as SdkMpcConfig};

const CONFIG_FILE: &str = "Stoffel.toml";

#[derive(Debug, Clone, Copy)]
pub enum Template {
    Stoffel,
    Python,
    Rust,
    SolidityFoundry,
    SolidityHardhat,
}

#[derive(Debug, Clone)]
pub struct Project {
    root: PathBuf,
    source: PathBuf,
    config: ProjectConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProjectConfig {
    pub package: PackageConfig,
    pub mpc: MpcConfig,
    pub build: BuildConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PackageConfig {
    pub name: String,
    pub version: String,
    pub authors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MpcConfig {
    #[serde(alias = "protocol")]
    pub backend: Option<MpcBackend>,
    #[serde(alias = "field")]
    pub curve: Option<stoffel::prelude::Curve>,
    pub parties: Option<usize>,
    pub threshold: Option<usize>,
    pub instance_id: Option<u64>,
    /// Per-client output value counts for the local simulator, keyed by client
    /// slot (e.g. `[mpc.client_output_counts]` with `0 = 128`). A fallback used
    /// only when the program does not statically declare the client's outputs.
    pub client_output_counts: Option<std::collections::HashMap<String, u64>>,
}

impl Default for MpcConfig {
    fn default() -> Self {
        Self {
            backend: Some(MpcBackend::HoneyBadger),
            curve: None,
            parties: Some(5),
            threshold: Some(1),
            instance_id: None,
            client_output_counts: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BuildConfig {
    pub source: PathBuf,
    #[serde(alias = "output_dir")]
    pub target_dir: PathBuf,
    pub optimization_level: Option<u8>,
    /// Optimizer inlining budget (fixpoint blowup cap). Only consulted at -O3.
    /// Populates the `STOFFEL_INLINE_BUDGET` knob the compiler reads; an
    /// explicitly set environment variable overrides this project value.
    pub inline_budget: Option<u64>,
    /// Optimizer loop-unrolling global blowup budget. Only consulted at -O3.
    /// Populates `STOFFEL_UNROLL_BUDGET` (an env var overrides this).
    pub unroll_budget: Option<u64>,
    /// Per-loop unrolling expansion cap. Only consulted at -O3. Populates
    /// `STOFFEL_UNROLL_MAX_EXPANSION` (an env var overrides this).
    pub unroll_max_expansion: Option<u64>,
}

impl Default for PackageConfig {
    fn default() -> Self {
        Self {
            name: "stoffel-app".to_owned(),
            version: "0.1.0".to_owned(),
            authors: Vec::new(),
        }
    }
}

impl Default for BuildConfig {
    fn default() -> Self {
        Self {
            source: PathBuf::from("src/main.stfl"),
            target_dir: PathBuf::from("target"),
            optimization_level: None,
            inline_budget: None,
            unroll_budget: None,
            unroll_max_expansion: None,
        }
    }
}

impl Project {
    pub fn init(path: &Path, template: Template, force: bool) -> Result<()> {
        if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            anyhow::bail!(
                "cannot initialize project through symlink {}",
                path.display()
            );
        }
        if path.exists() && !path.is_dir() {
            anyhow::bail!(
                "{} is a file; pass a directory path for the new Stoffel project",
                path.display()
            );
        }
        if path.exists() && !force && fs::read_dir(path)?.next().is_some() {
            anyhow::bail!("{}", init_target_not_empty_message(path));
        }
        validate_init_project_dir_path(path)?;
        validate_init_parent_dir(path)?;
        fs::create_dir_all(path)?;
        match template {
            Template::Stoffel => init_stoffel_project(path),
            Template::Python => init_python_project(path),
            Template::Rust => init_rust_project(path),
            Template::SolidityFoundry => init_solidity_foundry_project(path),
            Template::SolidityHardhat => init_solidity_hardhat_project(path),
        }
    }

    pub fn discover(path: Option<&Path>) -> Result<Self> {
        Self::discover_with_options(path, false)
    }

    pub fn discover_for_clean(path: Option<&Path>) -> Result<Self> {
        Self::discover_with_options(path, true)
    }

    fn discover_with_options(
        path: Option<&Path>,
        allow_existing_target_file: bool,
    ) -> Result<Self> {
        if let Some(path) = path {
            if !path.exists() {
                anyhow::bail!("{}", missing_path_message(path));
            }
        }
        let start = match path {
            Some(path) if path.is_dir() => path.to_path_buf(),
            Some(path) => path
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from(".")),
            None => std::env::current_dir()?,
        };
        let root = find_root(&start)?;
        let config = read_config(&root.join(CONFIG_FILE), allow_existing_target_file)?;
        let source = root.join(&config.build.source);
        Ok(Self {
            root,
            source,
            config,
        })
    }

    pub fn source_path(&self) -> &Path {
        &self.source
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn config_path(&self) -> PathBuf {
        self.root.join(CONFIG_FILE)
    }

    pub fn cache_dir(&self) -> PathBuf {
        self.root.join(".stoffel").join("cache")
    }

    pub fn target_dir(&self) -> PathBuf {
        self.root.join(&self.config.build.target_dir)
    }

    pub fn default_bytecode_path(&self, release: bool) -> PathBuf {
        let profile = if release { "release" } else { "debug" };
        self.target_dir()
            .join(profile)
            .join(format!("{}.stflb", self.config.package.name))
    }

    pub fn config(&self) -> &ProjectConfig {
        &self.config
    }

    pub fn test_files(&self) -> Result<Vec<PathBuf>> {
        let tests_dir = self.root.join("tests");
        if !tests_dir.exists() {
            return Ok(Vec::new());
        }
        let mut files = Vec::new();
        collect_stfl_files(&tests_dir, &mut files)?;
        files.sort();
        Ok(files)
    }

    pub fn source_files(&self) -> Result<Vec<PathBuf>> {
        let source_dir = self.source_dir();
        if !source_dir.exists() {
            if self.configured_source_is_dir() {
                anyhow::bail!(
                    "configured build.source {} does not exist",
                    self.config.build.source.display()
                );
            }
            if !self.source.exists() {
                anyhow::bail!(
                    "configured build.source {} does not exist",
                    self.config.build.source.display()
                );
            }
            return Ok(vec![self.source.clone()]);
        }
        let mut files = Vec::new();
        collect_stfl_files(&source_dir, &mut files)?;
        files.sort();
        if files.is_empty() {
            if self.configured_source_is_dir() {
                anyhow::bail!(
                    "no .stfl source files found under configured build.source {}",
                    self.config.build.source.display()
                );
            }
            if !self.source.exists() {
                anyhow::bail!(
                    "configured build.source {} does not exist",
                    self.config.build.source.display()
                );
            }
            files.push(self.source.clone());
        }
        Ok(files)
    }

    pub fn source_files_under(&self, dir: &Path) -> Result<Vec<PathBuf>> {
        let dir = absolutize(dir)?;
        let mut files = Vec::new();
        collect_stfl_files(&dir, &mut files)?;
        files.sort();
        Ok(files)
    }

    pub fn watch_files(&self) -> Result<Vec<PathBuf>> {
        let mut files = vec![self.config_path()];
        files.extend(self.source_files()?);
        files.sort();
        files.dedup();
        Ok(files)
    }

    fn source_dir(&self) -> PathBuf {
        if self.configured_source_is_dir() {
            self.root.join(&self.config.build.source)
        } else {
            self.root.join(
                self.config
                    .build
                    .source
                    .parent()
                    .unwrap_or(Path::new("src")),
            )
        }
    }

    fn configured_source_is_dir(&self) -> bool {
        self.config
            .build
            .source
            .extension()
            .and_then(|extension| extension.to_str())
            .is_none_or(|extension| !extension.eq_ignore_ascii_case("stfl"))
    }

    pub fn default_bytecode_path_for_source(&self, source: &Path, release: bool) -> PathBuf {
        let profile = if release { "release" } else { "debug" };
        let source_path = if source.is_absolute() {
            source.to_path_buf()
        } else {
            self.root.join(source)
        };
        let stem = source_path
            .file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or("main");
        if source_path == self.source_path() && stem == "main" {
            return self
                .target_dir()
                .join(profile)
                .join(format!("{}.stflb", self.config.package.name));
        }
        if let Ok(relative) = source_path.strip_prefix(self.source_dir()) {
            if relative
                .parent()
                .is_some_and(|parent| !parent.as_os_str().is_empty())
            {
                return self
                    .target_dir()
                    .join(profile)
                    .join(relative)
                    .with_extension("stflb");
            }
        }
        let name = if stem == "main" {
            self.config.package.name.as_str()
        } else {
            stem
        };
        self.target_dir()
            .join(profile)
            .join(format!("{name}.stflb"))
    }

    pub fn find_bytecode(&self, release: bool) -> Result<Option<PathBuf>> {
        let preferred = self.default_bytecode_path(release);
        if self.is_fresh_bytecode(&preferred)? {
            return Ok(Some(preferred));
        }
        Ok(None)
    }

    fn is_fresh_bytecode(&self, bytecode: &Path) -> Result<bool> {
        if !bytecode.exists() {
            return Ok(false);
        }
        let bytecode_modified = fs::metadata(bytecode)
            .and_then(|metadata| metadata.modified())
            .with_context(|| format!("failed to inspect {}", bytecode.display()))?;
        for input in self.watch_files()? {
            let Ok(metadata) = fs::metadata(&input) else {
                continue;
            };
            let Ok(modified) = metadata.modified() else {
                continue;
            };
            if modified > bytecode_modified {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

fn validate_init_parent_dir(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() || parent.exists() && parent.is_dir() {
        return Ok(());
    }
    if parent.exists() {
        anyhow::bail!(
            "cannot create project at {}; parent path {} is a file, not a directory",
            path.display(),
            parent.display()
        );
    }
    Ok(())
}

fn validate_init_project_dir_path(path: &Path) -> Result<()> {
    let Some(extension) = path.extension().and_then(|extension| extension.to_str()) else {
        return Ok(());
    };
    if matches!(extension, "stfl" | "stflb" | "toml" | "md" | "txt" | "json") {
        anyhow::bail!(
            "{} looks like a file path; `stoffel init` creates a project directory. Pass a directory path such as {}",
            path.display(),
            path.with_extension("").display()
        );
    }
    Ok(())
}

fn missing_path_message(path: &Path) -> String {
    let mut message = format!("{} does not exist", path.display());
    if is_stoffel_source_path(path) {
        if let Some(suggestion) = nearest_stoffel_source(path) {
            message.push_str(&format!("; did you mean {}?", suggestion.display()));
        }
    }
    message
}

fn nearest_stoffel_source(path: &Path) -> Option<PathBuf> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let wanted = path.file_name()?.to_string_lossy();
    let mut best = None::<(usize, PathBuf)>;
    for entry in fs::read_dir(parent).ok()?.flatten() {
        let candidate = entry.path();
        if !candidate.is_file() || !is_stoffel_source_path(&candidate) {
            continue;
        }
        let Some(name) = candidate.file_name() else {
            continue;
        };
        let distance = levenshtein(&wanted, &name.to_string_lossy());
        if distance <= 3
            && best
                .as_ref()
                .is_none_or(|(best_distance, _)| distance < *best_distance)
        {
            best = Some((distance, candidate));
        }
    }
    best.map(|(_, path)| path)
}

fn is_stoffel_source_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("stfl"))
}

fn levenshtein(left: &str, right: &str) -> usize {
    let mut costs = (0..=right.chars().count()).collect::<Vec<_>>();
    for (left_index, left_char) in left.chars().enumerate() {
        let mut previous = costs[0];
        costs[0] = left_index + 1;
        for (right_index, right_char) in right.chars().enumerate() {
            let insert = costs[right_index + 1] + 1;
            let delete = costs[right_index] + 1;
            let replace = previous + usize::from(left_char != right_char);
            previous = costs[right_index + 1];
            costs[right_index + 1] = insert.min(delete).min(replace);
        }
    }
    costs[right.chars().count()]
}

fn init_stoffel_project(path: &Path) -> Result<()> {
    let name = project_name(path);
    write_new(path, CONFIG_FILE, &default_config_text(name.clone()))?;
    write_new(path, "src/main.stfl", default_stoffel_program_text())?;
    write_new(path, "Cargo.toml", &default_cargo_toml_text(&name))?;
    write_new(path, "build.rs", &default_build_rs_text("src/main.stfl"))?;
    write_new(path, "src/main.rs", default_main_rs_text())?;
    write_new(
        path,
        "README.md",
        &format!(
            "{}\nBuild the Rust SDK wrapper with included bindings:\n\n```sh\ncargo build\n```\n\nRun the Rust SDK wrapper:\n\n```sh\ncargo run\n```\n",
            default_readme_text("Stoffel Project")
        ),
    )?;
    Ok(())
}

pub fn init_library_project(path: &Path) -> Result<()> {
    write_new(
        path,
        CONFIG_FILE,
        &default_library_config_text(project_name(path)),
    )?;
    write_new(
        path,
        "src/lib.stfl",
        "def add(a: int64, b: int64) -> int64:\n  return a + b\n",
    )?;
    write_new(
        path,
        "README.md",
        "# Stoffel Library\n\nValidate the library source:\n\n```sh\nstoffel check\n```\n\nBuild bytecode when you need an artifact:\n\n```sh\nstoffel build\n```\n",
    )?;
    Ok(())
}

fn init_python_project(path: &Path) -> Result<()> {
    init_stoffel_project(path)?;
    write_new(path, "requirements.txt", "stoffel-python-sdk\n")?;
    write_new(path, "app.py", "print(\"Stoffel Python SDK project\")\n")?;
    write_new(
        path,
        "README.md",
        &format!(
            "{}\nPython wrapper files are included for SDK integration. Install Python dependencies with:\n\n```sh\npython3 -m pip install -r requirements.txt\n```\n",
            default_readme_text("Stoffel Python Project")
        ),
    )?;
    Ok(())
}

fn init_rust_project(path: &Path) -> Result<()> {
    write_new(
        path,
        "stoffel/Stoffel.toml",
        &config_text(project_name(path), "src/program.stfl"),
    )?;
    write_new(
        path,
        "stoffel/src/program.stfl",
        "def main(a: secret int64, b: secret int64) -> secret int64:\n  return a + b\n",
    )?;
    write_new(
        path,
        "Cargo.toml",
        &format!(
            "[package]\nname = \"{}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nstoffel = {{ package = \"stoffel-rust-sdk\", version = \"=0.2.0\" }}\ntokio = {{ version = \"1\", features = [\"macros\", \"rt-multi-thread\"] }}\n\n[build-dependencies]\nstoffel-bindgen = \"=0.2.0\"\n",
            project_name(path)
        ),
    )?;
    write_new(
        path,
        "build.rs",
        &default_build_rs_text("stoffel/src/program.stfl"),
    )?;
    write_new(
        path,
        "src/main.rs",
        "use stoffel::prelude::*;\n\n#[allow(dead_code, unused_mut, unused_variables)]\nmod stoffel_bindings {\n    include!(concat!(env!(\"OUT_DIR\"), \"/stoffel_bindings.rs\"));\n}\n\n#[tokio::main]\nasync fn main() -> stoffel::Result<()> {\n    let result = Stoffel::compile_file(\"stoffel/src/program.stfl\")?\n        .manifest::<stoffel_bindings::ProgramManifest>()\n        .parties(5)\n        .threshold(1)\n        .with_inputs(&[(\"a\", 40_i64), (\"b\", 2_i64)])\n        .execute_local()\n        .await?;\n    println!(\"{}\", result[0]);\n    Ok(())\n}\n",
    )?;
    write_new(
        path,
        "README.md",
        "# Stoffel Rust Project\n\nThe Stoffel program lives in `stoffel/src/program.stfl` and has its own `stoffel/Stoffel.toml`.\n\nValidate the Stoffel program:\n\n```sh\nstoffel check stoffel\n```\n\nRun the Stoffel program through the CLI:\n\n```sh\nstoffel run stoffel --input a=40 --input b=2\n```\n\nRun the Rust local-MPC wrapper:\n\n```sh\ncargo run\n```\n",
    )?;
    Ok(())
}

fn init_solidity_foundry_project(path: &Path) -> Result<()> {
    init_stoffel_project(path)?;
    write_new(
        path,
        "foundry.toml",
        "[profile.default]\nsrc = \"contracts\"\nout = \"out\"\nlibs = [\"lib\"]\n",
    )?;
    write_new(
        path,
        "contracts/StoffelApp.sol",
        "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n\ncontract StoffelApp {}\n",
    )?;
    write_new(
        path,
        "README.md",
        &format!(
            "{}\nFoundry contract files are included under `contracts/`. Build the Solidity project with:\n\n```sh\nforge build\n```\n",
            default_readme_text("Stoffel Foundry Project")
        ),
    )?;
    Ok(())
}

fn init_solidity_hardhat_project(path: &Path) -> Result<()> {
    init_stoffel_project(path)?;
    write_new(
        path,
        "package.json",
        &format!(
            "{{\n  \"name\": \"{}\",\n  \"version\": \"0.1.0\",\n  \"devDependencies\": {{\n    \"hardhat\": \"^2.22.0\"\n  }}\n}}\n",
            project_name(path)
        ),
    )?;
    write_new(
        path,
        "hardhat.config.js",
        "module.exports = { solidity: \"0.8.20\" };\n",
    )?;
    write_new(
        path,
        "contracts/StoffelApp.sol",
        "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n\ncontract StoffelApp {}\n",
    )?;
    write_new(
        path,
        "README.md",
        &format!(
            "{}\nHardhat contract files are included under `contracts/`. Install JavaScript dependencies, then compile contracts:\n\n```sh\nnpm install\nnpx hardhat compile\n```\n",
            default_readme_text("Stoffel Hardhat Project")
        ),
    )?;
    Ok(())
}

fn init_target_not_empty_message(path: &Path) -> String {
    if path.join(CONFIG_FILE).exists() {
        return format!(
            "{} already contains Stoffel.toml; use `stoffel status {}` or `stoffel run {}` for this project, or pass --force to refresh template files",
            path.display(),
            path.display(),
            path.display()
        );
    }
    format!(
        "{} already exists and is not empty; pass --force to write Stoffel template files while preserving unrelated files",
        path.display()
    )
}

fn find_root(start: &Path) -> Result<PathBuf> {
    let mut dir = absolutize(start)?;
    let original = dir.clone();
    loop {
        if dir.join(CONFIG_FILE).exists() {
            return Ok(dir);
        }
        if !dir.pop() {
            let nested = nested_config_paths(&original)?;
            if !nested.is_empty() {
                let paths = nested
                    .iter()
                    .map(|path| path.parent().unwrap_or(path).display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                anyhow::bail!(
                    "could not find {CONFIG_FILE} in {} or any parent directory; found nested Stoffel project(s) at {paths}. Pass one of those project paths instead",
                    original.display()
                );
            }
            anyhow::bail!(
                "could not find {CONFIG_FILE} in {} or any parent directory; run `stoffel init` first or pass a project path",
                original.display()
            );
        }
    }
}

fn nested_config_paths(root: &Path) -> Result<Vec<PathBuf>> {
    let mut configs = Vec::new();
    collect_nested_config_paths(root, 0, &mut configs)?;
    configs.sort();
    Ok(configs)
}

fn collect_nested_config_paths(
    root: &Path,
    depth: usize,
    configs: &mut Vec<PathBuf>,
) -> Result<()> {
    if depth >= 3 || !root.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() {
            let config = path.join(CONFIG_FILE);
            if config.exists() {
                configs.push(config);
            } else {
                collect_nested_config_paths(&path, depth + 1, configs)?;
            }
        }
    }
    Ok(())
}

fn read_config(path: &Path, allow_existing_target_file: bool) -> Result<ProjectConfig> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let document: toml::Value =
        toml::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))?;
    let mut config = parse_project_config(&raw, path)?;
    validate_package_config(&document, &config.package)?;
    if config.build.source.as_os_str().is_empty() {
        config.build.source = BuildConfig::default().source;
    }
    validate_source_config(&config.build.source)?;
    if config.build.target_dir.as_os_str().is_empty() {
        config.build.target_dir = BuildConfig::default().target_dir;
    }
    validate_target_dir(
        path.parent().unwrap_or(Path::new(".")),
        &config.build.target_dir,
        allow_existing_target_file,
    )?;
    validate_optimization_level(config.build.optimization_level)?;
    validate_optimizer_budget("build.inline_budget", config.build.inline_budget)?;
    validate_optimizer_budget("build.unroll_budget", config.build.unroll_budget)?;
    validate_optimizer_budget(
        "build.unroll_max_expansion",
        config.build.unroll_max_expansion,
    )?;
    validate_mpc_config(&config.mpc)?;
    Ok(config)
}

fn parse_project_config(raw: &str, path: &Path) -> Result<ProjectConfig> {
    toml::from_str(raw).map_err(|error| {
        let mut message = format!("failed to parse {}: {error}", path.display());
        if let Some(hint) = config_parse_hint(&error.to_string()) {
            message.push_str(&format!("\nHint: {hint}"));
        }
        anyhow::anyhow!(message)
    })
}

fn config_parse_hint(error: &str) -> Option<&'static str> {
    if error.contains("expected usize") {
        if error.contains("parties =") {
            return Some(
                "write [mpc].parties as an unquoted positive whole number, for example `parties = 5`.",
            );
        }
        if error.contains("threshold =") {
            return Some(
                "write [mpc].threshold as an unquoted positive whole number, for example `threshold = 1`.",
            );
        }
        return Some("write numeric config values as unquoted positive whole numbers.");
    }
    if error.contains("expected u64") && error.contains("instance_id =") {
        return Some(
            "write [mpc].instance_id as an unquoted whole number, for example `instance_id = 0`.",
        );
    }
    let unknown = unknown_config_field(error)?;
    match unknown {
        "naem" => Some("did you mean [package].name?"),
        "sorce" => Some("did you mean [build].source?"),
        "main" => Some("did you mean [build].source?"),
        "target" => Some("did you mean [build].target_dir or [build].output_dir?"),
        "threshhold" => Some("did you mean [mpc].threshold?"),
        "party_count" => Some("did you mean [mpc].parties?"),
        "instance_id" => Some(
            "did you mean [mpc].instance_id? Put instance_id under the [mpc] table, not [build].",
        ),
        "network" => Some(
            "did you mean [mpc]? Network execution config is passed to `stoffel run --config`, not stored as [network] in Stoffel.toml.",
        ),
        _ => None,
    }
}

fn unknown_config_field(error: &str) -> Option<&str> {
    let marker = "unknown field `";
    let start = error.find(marker)? + marker.len();
    let rest = &error[start..];
    let end = rest.find('`')?;
    Some(&rest[..end])
}

fn validate_package_config(document: &toml::Value, package: &PackageConfig) -> Result<()> {
    if document
        .get("package")
        .and_then(toml::Value::as_table)
        .is_none()
    {
        anyhow::bail!(
            "missing [package] table in Stoffel.toml; add [package] with name and version fields"
        );
    }
    if package.name.trim().is_empty() {
        anyhow::bail!("invalid [package].name; project name cannot be empty");
    }
    if !package
        .name
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        anyhow::bail!(
            "invalid [package].name {}; use only letters, numbers, '-' or '_' so build artifacts have safe file names",
            package.name
        );
    }
    if package.version.trim().is_empty() {
        anyhow::bail!("invalid [package].version; version cannot be empty");
    }
    Ok(())
}

fn validate_source_config(source: &Path) -> Result<()> {
    if source == Path::new(".") {
        anyhow::bail!(
            "invalid build.source .; choose a source file like src/main.stfl or a source directory like src"
        );
    }
    if source.is_absolute() {
        anyhow::bail!(
            "invalid build.source {}; expected a relative path inside the project",
            source.display()
        );
    }
    if source
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        anyhow::bail!(
            "invalid build.source {}; source paths must stay inside the project",
            source.display()
        );
    }
    if source
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| !extension.eq_ignore_ascii_case("stfl"))
    {
        anyhow::bail!(
            "invalid build.source {}; expected a .stfl source file or source directory",
            source.display()
        );
    }
    Ok(())
}

fn validate_mpc_config(config: &MpcConfig) -> Result<()> {
    if matches!(config.threshold, Some(0)) {
        anyhow::bail!("invalid [mpc] config: threshold must be greater than zero");
    }
    let mut builder = SdkMpcConfig::builder()
        .parties(config.parties.unwrap_or(5))
        .threshold(config.threshold.unwrap_or(1))
        .backend(config.backend.unwrap_or_default());
    if let Some(instance_id) = config.instance_id {
        builder = builder.instance_id(instance_id);
    }
    builder
        .build()
        .map(|_| ())
        .map_err(|error| anyhow::anyhow!("invalid [mpc] config: {error}"))
}

fn validate_optimization_level(level: Option<u8>) -> Result<()> {
    if let Some(level) = level {
        if level > 3 {
            anyhow::bail!(
                "invalid build.optimization_level {level}; expected an optimization level from 0 to 3"
            );
        }
    }
    Ok(())
}

fn validate_optimizer_budget(field: &str, budget: Option<u64>) -> Result<()> {
    if let Some(0) = budget {
        anyhow::bail!("invalid {field} 0; expected a positive budget or omit the field");
    }
    Ok(())
}

fn validate_target_dir(
    root: &Path,
    target_dir: &Path,
    allow_existing_final_file: bool,
) -> Result<()> {
    if target_dir.is_absolute() {
        anyhow::bail!(
            "invalid build.target_dir {}; expected a relative directory inside the project",
            target_dir.display()
        );
    }
    if target_dir
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        anyhow::bail!(
            "invalid build.target_dir {}; build artifacts must stay inside the project",
            target_dir.display()
        );
    }
    if target_dir == Path::new(".") {
        anyhow::bail!("invalid build.target_dir .; choose a dedicated build directory like target");
    }
    if target_dir.starts_with("src") {
        anyhow::bail!(
            "invalid build.target_dir {}; build artifacts must not be written under src/",
            target_dir.display()
        );
    }
    if target_dir.extension().is_some() {
        anyhow::bail!(
            "invalid build.target_dir {}; expected a directory path, not a file path",
            target_dir.display()
        );
    }
    validate_project_controlled_path(root, &root.join(target_dir), allow_existing_final_file)
        .with_context(|| format!("invalid build.target_dir {}", target_dir.display()))?;
    let mut absolute = root.to_path_buf();
    let mut components = target_dir.components().peekable();
    while let Some(component) = components.next() {
        absolute.push(component.as_os_str());
        let is_final = components.peek().is_none();
        let metadata = fs::symlink_metadata(&absolute).ok();
        if metadata.is_some_and(|metadata| {
            !metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && !(allow_existing_final_file && is_final)
        }) {
            anyhow::bail!(
                "invalid build.target_dir {}; {} is an existing file",
                target_dir.display(),
                absolute.display()
            );
        }
    }
    Ok(())
}

fn collect_stfl_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_stfl_files(&path, files)?;
        } else if path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("stfl"))
        {
            files.push(path);
        }
    }
    Ok(())
}

pub(crate) fn validate_project_controlled_path(
    root: &Path,
    path: &Path,
    allow_final_symlink: bool,
) -> Result<()> {
    let relative = path.strip_prefix(root).map_err(|_| {
        anyhow::anyhow!(
            "project-controlled path {} is outside project root {}",
            path.display(),
            root.display()
        )
    })?;
    if relative.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        anyhow::bail!(
            "project-controlled path {} escapes project root {}",
            path.display(),
            root.display()
        );
    }

    let mut current = root.to_path_buf();
    let mut components = relative.components().peekable();
    while let Some(component) = components.next() {
        current.push(component.as_os_str());
        let is_final = components.peek().is_none();
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                if allow_final_symlink && is_final {
                    return Ok(());
                }
                anyhow::bail!(
                    "project-controlled path {} traverses symlink {}",
                    path.display(),
                    current.display()
                );
            }
            Ok(metadata) if !is_final && !metadata.is_dir() => {
                anyhow::bail!(
                    "project-controlled path {} has non-directory component {}; it is an existing file, not a directory",
                    path.display(),
                    current.display()
                );
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect {}", current.display()));
            }
        }
    }
    Ok(())
}

fn write_new(root: &Path, relative: impl AsRef<Path>, contents: &str) -> Result<()> {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        if parent.exists() && !parent.is_dir() {
            anyhow::bail!(
                "cannot write {}; parent path {} is a file, not a directory",
                path.display(),
                parent.display()
            );
        }
        validate_project_controlled_path(root, &path, false)?;
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(&path, contents).with_context(|| format!("failed to write {}", path.display()))
}

fn default_config_text(name: String) -> String {
    config_text(name, "src/main.stfl")
}

fn default_readme_text(title: &str) -> String {
    format!(
        "# {title}\n\nValidate the Stoffel source:\n\n```sh\nstoffel check\n```\n\nRun the default local MPC example:\n\n```sh\nstoffel run\n```\n\nRun the default example once with the development command:\n\n```sh\nstoffel dev --once\n```\n\nBuild bytecode:\n\n```sh\nstoffel build\n```\n"
    )
}

fn default_stoffel_program_text() -> &'static str {
    concat!(
        "def gate_and(a: secret bool, b: secret bool) -> secret bool:\n",
        "  return Share.mul(a, b)\n",
        "\n",
        "def gate_not(a: secret bool) -> secret bool:\n",
        "  var one = Share.from_clear_int(1, 1)\n",
        "  return Share.sub(one, a)\n",
        "\n",
        "def gate_or(a: secret bool, b: secret bool) -> secret bool:\n",
        "  var ab: secret bool = gate_and(a, b)\n",
        "  var sum = Share.add(a, b)\n",
        "  return Share.sub(sum, ab)\n",
        "\n",
        "def gate_xor(a: secret bool, b: secret bool) -> secret bool:\n",
        "  var ab: secret bool = gate_and(a, b)\n",
        "  var sum = Share.add(a, b)\n",
        "  var two_ab = Share.mul_scalar(ab, 2)\n",
        "  return Share.sub(sum, two_ab)\n",
        "\n",
        "def circuit(x: secret bool, y: secret bool, z: secret bool) -> secret bool:\n",
        "  var left: secret bool = gate_or(gate_and(x, y), gate_not(z))\n",
        "  var right: secret bool = gate_and(x, gate_not(y))\n",
        "  return gate_xor(left, right)\n",
        "\n",
        "def main() -> bool:\n",
        "  var x: secret bool = Share.random()\n",
        "  var y: secret bool = Share.random()\n",
        "  var z: secret bool = Share.random()\n",
        "  var result: secret bool = circuit(x, y, z)\n",
        "  return result.reveal()\n",
    )
}

fn default_cargo_toml_text(name: &str) -> String {
    format!(
        "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nstoffel = {{ package = \"stoffel-rust-sdk\", version = \"=0.2.0\" }}\ntokio = {{ version = \"1\", features = [\"macros\", \"rt-multi-thread\"] }}\n\n[build-dependencies]\nstoffel-bindgen = \"=0.2.0\"\n"
    )
}

fn default_build_rs_text(program_path: &str) -> String {
    format!(
        "use std::path::PathBuf;\n\nfn main() -> std::result::Result<(), Box<dyn std::error::Error>> {{\n    println!(\"cargo:rerun-if-changed={program_path}\");\n\n    let out_file = PathBuf::from(std::env::var(\"OUT_DIR\")?).join(\"stoffel_bindings.rs\");\n    stoffel_bindgen::generate_bindings_from_source(\n        \"{program_path}\",\n        out_file,\n        stoffel_bindgen::BindingsConfig::default(),\n    )?;\n\n    Ok(())\n}}\n"
    )
}

fn default_main_rs_text() -> &'static str {
    "use stoffel::prelude::*;\n\n#[allow(dead_code, unused_mut, unused_variables)]\nmod stoffel_bindings {\n    include!(concat!(env!(\"OUT_DIR\"), \"/stoffel_bindings.rs\"));\n}\n\n#[tokio::main]\nasync fn main() -> stoffel::Result<()> {\n    let result = Stoffel::compile_file(\"src/main.stfl\")?\n        .manifest::<stoffel_bindings::ProgramManifest>()\n        .parties(5)\n        .threshold(1)\n        // Load named function inputs from JSON, CSV, or TXT when your program takes parameters.\n        // Examples:\n        //   inputs.json: {\"a\": 40, \"b\": 2}\n        //   inputs.csv:  a,b\\n40,2\n        //   inputs.txt:  a=40\\nb=2\n        // .with_input_file(\"inputs.json\")?\n        // Load ClientStore values for no-argument MPC programs with:\n        // .with_client_input_file(\"client-inputs.json\")?\n        .execute_local()\n        .await?;\n\n    println!(\"{}\", result[0]);\n    Ok(())\n}\n"
}

fn config_text(name: String, source: &str) -> String {
    format!(
        "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\n\n[mpc]\nbackend = \"honeybadger\"\nparties = 5\nthreshold = 1\n\n[build]\nsource = \"{source}\"\ntarget_dir = \"target\"\n"
    )
}

fn default_library_config_text(name: String) -> String {
    format!(
        "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\n\n[mpc]\nbackend = \"honeybadger\"\nparties = 5\nthreshold = 1\n\n[build]\nsource = \"src/lib.stfl\"\ntarget_dir = \"target\"\n"
    )
}

fn project_name(path: &Path) -> String {
    let mut name = String::new();
    let mut last_was_dash = false;
    for ch in path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty() && *name != ".")
        .unwrap_or("stoffel-app")
        .chars()
    {
        let ch = ch.to_ascii_lowercase();
        if ch.is_ascii_alphanumeric() {
            name.push(ch);
            last_was_dash = false;
        } else if !last_was_dash {
            name.push('-');
            last_was_dash = true;
        }
    }
    let name = name.trim_matches('-').to_owned();
    if name.is_empty() {
        "stoffel-app".to_owned()
    } else {
        name
    }
}

fn absolutize(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}
