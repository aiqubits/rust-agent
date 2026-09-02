use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, Read},
    path::{Component as PathComponent, Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde::Deserialize;
use serde_json::{Map, Value};
use thiserror::Error;

use crate::{
    cargo_context::{CargoConfigIsolationError, verify_cargo_config_isolation},
    catalog::validate_build_requirements,
    metadata::{
        BuildRequirements, CapabilitySpec, CatalogDocument, ComponentSpec, HostBoundarySpec,
        MAX_CATALOG_DOCUMENT_BYTES, MAX_CATALOG_OWNERS, RuntimeAdapterSpec,
    },
    target::MAX_TARGET_PREDICATE_PARTITIONS,
};

pub const MAX_CARGO_METADATA_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_CARGO_METADATA_DIAGNOSTIC_BYTES: usize = 256 * 1024;
pub const MAX_CARGO_METADATA_PACKAGES: usize = 1_024;

const CARGO_METADATA_TIMEOUT: Duration = Duration::from_secs(30);
const CARGO_METADATA_POLL_INTERVAL: Duration = Duration::from_millis(10);
const CARGO_METADATA_TERMINATION_GRACE: Duration = Duration::from_secs(1);

#[derive(Clone, Copy)]
struct CargoMetadataInvocation<'a> {
    workspace_root: &'a Path,
    cargo_path: &'a Path,
    rustc_path: &'a Path,
    working_directory: &'a Path,
    cargo_target_input: &'a Path,
    generated_config: &'a Path,
    cargo_home: &'a Path,
    timeout: Duration,
}

#[derive(Clone, Debug)]
pub(crate) struct DiscoveredCatalog {
    pub(crate) document: CatalogDocument,
    pub(crate) root_build_requirements: BTreeMap<String, BuildRequirements>,
}

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("Cargo metadata I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("Cargo metadata isolation failed: {0}")]
    CargoConfigIsolation(#[from] CargoConfigIsolationError),
    #[error("Cargo metadata exceeded its {stream} limit of {maximum} bytes")]
    OutputTooLarge {
        stream: &'static str,
        maximum: usize,
    },
    #[error("Cargo metadata timed out after {milliseconds} milliseconds")]
    TimedOut { milliseconds: u128 },
    #[error("Cargo metadata {stream} is not UTF-8")]
    InvalidOutputEncoding { stream: &'static str },
    #[error("Cargo metadata failed: {0}")]
    CargoFailed(String),
    #[error("Cargo metadata output is invalid: {0}")]
    InvalidMetadata(String),
}

#[derive(Deserialize)]
struct CargoMetadataDocument {
    packages: Vec<CargoMetadataPackage>,
    workspace_members: Vec<String>,
    workspace_root: String,
    version: u32,
}

#[derive(Deserialize)]
struct CargoMetadataPackage {
    name: String,
    id: String,
    manifest_path: String,
    source: Option<String>,
    features: BTreeMap<String, Vec<String>>,
    metadata: Value,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageNamespaces {
    #[serde(default)]
    capability: Vec<Value>,
    #[serde(default, rename = "runtime-adapter")]
    runtime_adapter: Option<Value>,
    #[serde(default, rename = "host-entry")]
    host_entry: Option<Value>,
    #[serde(default, rename = "host-export")]
    host_export: Option<Value>,
    #[serde(default, rename = "build-requirements")]
    build_requirements: Option<VersionedBuildRequirements>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VersionedBuildRequirements {
    schema: u32,
    executables: BTreeSet<String>,
    #[serde(rename = "read-inputs")]
    read_inputs: BTreeSet<String>,
    environment: BTreeSet<String>,
}

impl VersionedBuildRequirements {
    fn normalize(self, package: &str) -> Result<BuildRequirements, DiscoveryError> {
        if self.schema != 1 {
            return invalid(format!(
                "package `{package}` has unsupported build-requirements schema {}; expected 1",
                self.schema
            ));
        }
        let requirements = BuildRequirements {
            executables: self.executables,
            read_inputs: self.read_inputs,
            environment: self.environment,
        };
        validate_build_requirements(package, &requirements)
            .map_err(|error| DiscoveryError::InvalidMetadata(error.to_string()))?;
        Ok(requirements)
    }
}

pub(crate) fn discover_workspace_catalog(
    workspace_root: &Path,
    cargo_path: &Path,
    rustc_path: &Path,
    working_directory: &Path,
    cargo_target_input: &Path,
) -> Result<DiscoveredCatalog, DiscoveryError> {
    let generated_config = working_directory.join(".cargo/config.toml");
    verify_cargo_config_isolation(working_directory, &generated_config)?;
    let cargo_home = working_directory.join(".cargo-metadata-home");
    fs::create_dir(&cargo_home)?;
    let output = run_cargo_metadata(CargoMetadataInvocation {
        workspace_root,
        cargo_path,
        rustc_path,
        working_directory,
        cargo_target_input,
        generated_config: &generated_config,
        cargo_home: &cargo_home,
        timeout: CARGO_METADATA_TIMEOUT,
    });
    let cleanup = fs::remove_dir_all(&cargo_home);
    let output = output?;
    cleanup?;
    parse_cargo_metadata(workspace_root, &output)
}

fn run_cargo_metadata(invocation: CargoMetadataInvocation<'_>) -> Result<Vec<u8>, DiscoveryError> {
    let CargoMetadataInvocation {
        workspace_root,
        cargo_path,
        rustc_path,
        working_directory,
        cargo_target_input,
        generated_config,
        cargo_home,
        timeout,
    } = invocation;
    let mut command = Command::new(cargo_path);
    command
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--locked",
            "--offline",
            "--filter-platform",
        ])
        .arg(cargo_target_input)
        .arg("--manifest-path")
        .arg(workspace_root.join("Cargo.toml"))
        .arg("--config")
        .arg(generated_config)
        .current_dir(working_directory)
        .env_clear()
        .env("CARGO_HOME", cargo_home)
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_TERM_COLOR", "never")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env(
            "PATH",
            cargo_path.parent().unwrap_or_else(|| Path::new("/")),
        )
        .env("RUSTC", rustc_path)
        .env("SOURCE_DATE_EPOCH", "0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;

        command.process_group(0);
    }
    let mut child = command.spawn()?;
    #[cfg(unix)]
    let process_group = rustix::process::Pid::from_child(&child);
    let stdout = child.stdout.take().ok_or_else(|| {
        io::Error::other("Cargo metadata stdout pipe was unavailable after successful spawn")
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        io::Error::other("Cargo metadata stderr pipe was unavailable after successful spawn")
    })?;
    let mut stdout_reader = Some(thread::spawn(move || {
        read_bounded_stream(stdout, "stdout", MAX_CARGO_METADATA_OUTPUT_BYTES)
    }));
    let mut stderr_reader = Some(thread::spawn(move || {
        read_bounded_stream(stderr, "stderr", MAX_CARGO_METADATA_DIAGNOSTIC_BYTES)
    }));
    let started = Instant::now();
    let deadline = started.checked_add(timeout).unwrap_or(started);
    let mut status = None;
    let mut stdout = None;
    let mut stderr = None;
    loop {
        if status.is_none() {
            status = child.try_wait()?;
        }
        collect_finished_output_reader(&mut stdout_reader, &mut stdout);
        collect_finished_output_reader(&mut stderr_reader, &mut stderr);
        if status.is_some() && stdout.is_some() && stderr.is_some() {
            break;
        }
        let now = Instant::now();
        if now >= deadline {
            #[cfg(unix)]
            let _ =
                rustix::process::kill_process_group(process_group, rustix::process::Signal::KILL);
            terminate_and_collect(
                &mut child,
                &mut status,
                &mut stdout_reader,
                &mut stdout,
                &mut stderr_reader,
                &mut stderr,
                now.checked_add(CARGO_METADATA_TERMINATION_GRACE)
                    .unwrap_or(now),
            );
            return Err(DiscoveryError::TimedOut {
                milliseconds: timeout.as_millis(),
            });
        }
        thread::sleep(
            deadline
                .saturating_duration_since(now)
                .min(CARGO_METADATA_POLL_INTERVAL),
        );
    }
    let status = status.expect("Cargo metadata status is present after the query loop");
    let stdout = stdout.expect("Cargo metadata stdout is present after the query loop")?;
    let stderr = stderr.expect("Cargo metadata stderr is present after the query loop")?;
    let stderr = String::from_utf8(stderr)
        .map_err(|_| DiscoveryError::InvalidOutputEncoding { stream: "stderr" })?;
    if !status.success() {
        return Err(DiscoveryError::CargoFailed(stderr));
    }
    Ok(stdout)
}

type OutputReader = thread::JoinHandle<Result<Vec<u8>, DiscoveryError>>;

fn collect_finished_output_reader(
    reader: &mut Option<OutputReader>,
    output: &mut Option<Result<Vec<u8>, DiscoveryError>>,
) {
    if reader.as_ref().is_some_and(OutputReader::is_finished) {
        let finished = reader
            .take()
            .expect("a finished output reader must still be present");
        *output = Some(
            finished
                .join()
                .map_err(|_| io::Error::other("Cargo metadata output reader panicked").into())
                .and_then(|value| value),
        );
    }
}

fn terminate_and_collect(
    child: &mut Child,
    status: &mut Option<ExitStatus>,
    stdout_reader: &mut Option<OutputReader>,
    stdout: &mut Option<Result<Vec<u8>, DiscoveryError>>,
    stderr_reader: &mut Option<OutputReader>,
    stderr: &mut Option<Result<Vec<u8>, DiscoveryError>>,
    cleanup_deadline: Instant,
) {
    let _ = child.kill();
    loop {
        if status.is_none()
            && let Ok(observed) = child.try_wait()
        {
            *status = observed;
        }
        collect_finished_output_reader(stdout_reader, stdout);
        collect_finished_output_reader(stderr_reader, stderr);
        if status.is_some() && stdout_reader.is_none() && stderr_reader.is_none() {
            return;
        }
        let now = Instant::now();
        if now >= cleanup_deadline {
            return;
        }
        thread::sleep(
            cleanup_deadline
                .saturating_duration_since(now)
                .min(CARGO_METADATA_POLL_INTERVAL),
        );
    }
}

fn read_bounded_stream(
    mut stream: impl Read,
    name: &'static str,
    maximum: usize,
) -> Result<Vec<u8>, DiscoveryError> {
    let mut output = Vec::with_capacity(maximum.min(8 * 1_024));
    let mut chunk = [0_u8; 8 * 1_024];
    let mut too_large = false;
    loop {
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        if !too_large {
            let remaining = maximum.saturating_sub(output.len());
            if count <= remaining {
                output.extend_from_slice(&chunk[..count]);
            } else {
                too_large = true;
            }
        }
    }
    if too_large {
        Err(DiscoveryError::OutputTooLarge {
            stream: name,
            maximum,
        })
    } else {
        Ok(output)
    }
}

pub(crate) fn parse_cargo_metadata(
    workspace_root: &Path,
    bytes: &[u8],
) -> Result<DiscoveredCatalog, DiscoveryError> {
    if bytes.len() > MAX_CARGO_METADATA_OUTPUT_BYTES {
        return Err(DiscoveryError::OutputTooLarge {
            stream: "stdout",
            maximum: MAX_CARGO_METADATA_OUTPUT_BYTES,
        });
    }
    let mut metadata: CargoMetadataDocument = serde_json::from_slice(bytes)
        .map_err(|error| DiscoveryError::InvalidMetadata(error.to_string()))?;
    if metadata.version != 1 {
        return invalid(format!(
            "unsupported cargo metadata format {}; expected 1",
            metadata.version
        ));
    }
    if metadata.packages.len() > MAX_CARGO_METADATA_PACKAGES
        || metadata.workspace_members.len() > MAX_CARGO_METADATA_PACKAGES
    {
        return invalid(format!(
            "workspace has too many packages; maximum is {MAX_CARGO_METADATA_PACKAGES}"
        ));
    }
    let canonical_workspace = workspace_root.canonicalize()?;
    let reported_workspace = PathBuf::from(&metadata.workspace_root);
    if !reported_workspace.is_absolute()
        || reported_workspace.canonicalize()? != canonical_workspace
    {
        return invalid(format!(
            "reported workspace root `{}` does not match `{}`",
            reported_workspace.display(),
            canonical_workspace.display()
        ));
    }
    let member_ids = exact_set(metadata.workspace_members, "workspace member id")?;
    let package_ids = exact_set(
        metadata
            .packages
            .iter()
            .map(|package| package.id.clone())
            .collect(),
        "package id",
    )?;
    if member_ids != package_ids {
        return invalid("--no-deps Cargo metadata packages do not exactly match workspace members");
    }
    let package_names = exact_set(
        metadata
            .packages
            .iter()
            .map(|package| package.name.clone())
            .collect(),
        "workspace package name",
    )?;
    if package_names.len() != metadata.packages.len() {
        return invalid("workspace package names are not unique");
    }

    metadata
        .packages
        .sort_by(|left, right| (&left.name, &left.id).cmp(&(&right.name, &right.id)));
    let mut capabilities = Vec::new();
    let mut components = Vec::new();
    let mut runtime_adapters = Vec::new();
    let mut host_boundaries = Vec::new();
    let mut root_build_requirements = BTreeMap::new();
    let mut aggregate_metadata_bytes = 0_usize;

    for package in metadata.packages {
        let Some(rust_agent) = rust_agent_metadata(&package)? else {
            continue;
        };
        let encoded = serde_json::to_vec(rust_agent)
            .map_err(|error| DiscoveryError::InvalidMetadata(error.to_string()))?;
        if encoded.len() > MAX_CATALOG_DOCUMENT_BYTES {
            return invalid(format!(
                "package `{}` rust-agent metadata has {} bytes; maximum is {MAX_CATALOG_DOCUMENT_BYTES}",
                package.name,
                encoded.len()
            ));
        }
        aggregate_metadata_bytes = aggregate_metadata_bytes
            .checked_add(encoded.len())
            .ok_or_else(|| {
                DiscoveryError::InvalidMetadata("metadata byte count overflowed".into())
            })?;
        if aggregate_metadata_bytes > MAX_CATALOG_DOCUMENT_BYTES {
            return invalid(format!(
                "aggregate rust-agent metadata exceeds {MAX_CATALOG_DOCUMENT_BYTES} bytes"
            ));
        }
        require_empty_default_features(&package)?;
        if package.source.is_some() {
            return invalid(format!(
                "managed workspace package `{}` unexpectedly has an external source",
                package.name
            ));
        }
        let package_path = derive_package_path(&canonical_workspace, &package)?;
        let root = rust_agent.as_object().ok_or_else(|| {
            DiscoveryError::InvalidMetadata(format!(
                "package `{}` rust-agent metadata must be an object",
                package.name
            ))
        })?;

        if root.contains_key("schema") {
            let component = parse_component(root.clone(), &package.name, &package_path)?;
            components.push(component);
            continue;
        }

        let namespaces: PackageNamespaces =
            serde_json::from_value(rust_agent.clone()).map_err(|error| {
                DiscoveryError::InvalidMetadata(format!(
                    "package `{}` rust-agent metadata is invalid: {error}",
                    package.name
                ))
            })?;
        let boundary_roles = usize::from(namespaces.runtime_adapter.is_some())
            + usize::from(namespaces.host_entry.is_some())
            + usize::from(namespaces.host_export.is_some());
        if boundary_roles > 1 {
            return invalid(format!(
                "package `{}` declares more than one runtime/Host boundary role",
                package.name
            ));
        }
        if boundary_roles != 0 && !namespaces.capability.is_empty() {
            return invalid(format!(
                "package `{}` mixes Capability API and runtime/Host boundary metadata",
                package.name
            ));
        }
        if boundary_roles != 0 && namespaces.build_requirements.is_some() {
            return invalid(format!(
                "package `{}` duplicates inline build requirements with a root declaration",
                package.name
            ));
        }
        if !namespaces.capability.is_empty() && namespaces.build_requirements.is_none() {
            return invalid(format!(
                "Capability API package `{}` is missing root build requirements",
                package.name
            ));
        }
        for capability in namespaces.capability {
            capabilities.push(parse_capability(capability, &package.name)?);
        }
        if let Some(requirements) = namespaces.build_requirements {
            let requirements = requirements.normalize(&package.name)?;
            if root_build_requirements
                .insert(package.name.clone(), requirements)
                .is_some()
            {
                return invalid(format!(
                    "package `{}` has duplicate root build requirements",
                    package.name
                ));
            }
        }
        if let Some(adapter) = namespaces.runtime_adapter {
            runtime_adapters.push(parse_runtime_adapter(
                adapter,
                &package.name,
                &package_path,
            )?);
        }
        if let Some(boundary) = namespaces.host_entry {
            host_boundaries.push(parse_host_boundary(
                boundary,
                &package.name,
                &package_path,
                "entry",
            )?);
        }
        if let Some(boundary) = namespaces.host_export {
            host_boundaries.push(parse_host_boundary(
                boundary,
                &package.name,
                &package_path,
                "wasm-export",
            )?);
        }
        if root.is_empty() {
            return invalid(format!(
                "package `{}` has an empty rust-agent metadata object",
                package.name
            ));
        }
    }

    let document = CatalogDocument {
        schema: 1,
        capabilities,
        components,
        runtime_adapters,
        host_boundaries,
    };
    let owner_count = document
        .capabilities
        .len()
        .checked_add(document.components.len())
        .and_then(|count| count.checked_add(document.runtime_adapters.len()))
        .and_then(|count| count.checked_add(document.host_boundaries.len()))
        .ok_or_else(|| DiscoveryError::InvalidMetadata("catalog owner count overflowed".into()))?;
    if owner_count > MAX_CATALOG_OWNERS {
        return invalid(format!(
            "discovered catalog has {owner_count} owners; maximum is {MAX_CATALOG_OWNERS}"
        ));
    }
    Ok(DiscoveredCatalog {
        document,
        root_build_requirements,
    })
}

fn exact_set(values: Vec<String>, kind: &str) -> Result<BTreeSet<String>, DiscoveryError> {
    let count = values.len();
    let set: BTreeSet<_> = values.into_iter().collect();
    if set.len() == count {
        Ok(set)
    } else {
        invalid(format!("duplicate {kind}"))
    }
}

fn rust_agent_metadata(package: &CargoMetadataPackage) -> Result<Option<&Value>, DiscoveryError> {
    match &package.metadata {
        Value::Null => Ok(None),
        Value::Object(metadata) => Ok(metadata.get("rust-agent")),
        _ => invalid(format!(
            "package `{}` metadata must be an object or null",
            package.name
        )),
    }
}

fn require_empty_default_features(package: &CargoMetadataPackage) -> Result<(), DiscoveryError> {
    match package.features.get("default") {
        Some(default) if default.is_empty() => Ok(()),
        Some(_) => invalid(format!(
            "managed package `{}` has non-empty default features",
            package.name
        )),
        None => invalid(format!(
            "managed package `{}` does not declare an explicit empty default feature",
            package.name
        )),
    }
}

fn derive_package_path(
    workspace_root: &Path,
    package: &CargoMetadataPackage,
) -> Result<String, DiscoveryError> {
    let manifest = PathBuf::from(&package.manifest_path);
    if !manifest.is_absolute() {
        return invalid(format!(
            "package `{}` manifest path is not absolute",
            package.name
        ));
    }
    let relative = manifest.strip_prefix(workspace_root).map_err(|_| {
        DiscoveryError::InvalidMetadata(format!(
            "package `{}` manifest escapes the workspace",
            package.name
        ))
    })?;
    if relative.as_os_str().is_empty()
        || !relative
            .components()
            .all(|component| matches!(component, PathComponent::Normal(_)))
    {
        return invalid(format!(
            "package `{}` manifest path is not canonical",
            package.name
        ));
    }
    let mut current = workspace_root.to_owned();
    for component in relative.components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current)?;
        if metadata.file_type().is_symlink() {
            return invalid(format!(
                "package `{}` manifest path contains a symlink at `{}`",
                package.name,
                current.display()
            ));
        }
    }
    if current.canonicalize()? != manifest || !current.is_file() {
        return invalid(format!(
            "package `{}` manifest is not a canonical regular file",
            package.name
        ));
    }
    let package_directory = relative.parent().ok_or_else(|| {
        DiscoveryError::InvalidMetadata(format!(
            "package `{}` manifest has no package directory",
            package.name
        ))
    })?;
    if package_directory.as_os_str().is_empty() {
        return invalid(format!(
            "managed package `{}` cannot be the workspace root package",
            package.name
        ));
    }
    package_directory
        .components()
        .map(|component| {
            component.as_os_str().to_str().ok_or_else(|| {
                DiscoveryError::InvalidMetadata(format!(
                    "package `{}` path is not UTF-8",
                    package.name
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|components| components.join("/"))
}

fn parse_component(
    mut metadata: Map<String, Value>,
    package: &str,
    package_path: &str,
) -> Result<ComponentSpec, DiscoveryError> {
    take_schema(&mut metadata, package, "component")?;
    insert_derived(&mut metadata, "package", package, package)?;
    insert_derived(&mut metadata, "package-path", package_path, package)?;
    normalize_targets(&mut metadata, package)?;
    deserialize_owner(Value::Object(metadata), package, "component")
}

fn parse_capability(mut metadata: Value, package: &str) -> Result<CapabilitySpec, DiscoveryError> {
    let object = metadata.as_object_mut().ok_or_else(|| {
        DiscoveryError::InvalidMetadata(format!(
            "package `{package}` capability metadata must be an object"
        ))
    })?;
    if object.contains_key("api-package") || object.contains_key("rust-api") {
        return invalid(format!(
            "package `{package}` capability metadata may not self-declare derived API package fields"
        ));
    }
    let api = object.remove("api").ok_or_else(|| {
        DiscoveryError::InvalidMetadata(format!(
            "package `{package}` capability metadata is missing `api`"
        ))
    })?;
    object.insert("rust-api".into(), api);
    object.insert("api-package".into(), Value::String(package.into()));
    deserialize_owner(metadata, package, "capability")
}

fn parse_runtime_adapter(
    mut metadata: Value,
    package: &str,
    package_path: &str,
) -> Result<RuntimeAdapterSpec, DiscoveryError> {
    let object = owner_object(&mut metadata, package, "runtime-adapter")?;
    take_schema(object, package, "runtime-adapter")?;
    insert_derived(object, "package", package, package)?;
    insert_derived(object, "package-path", package_path, package)?;
    normalize_targets(object, package)?;
    deserialize_owner(metadata, package, "runtime-adapter")
}

fn parse_host_boundary(
    mut metadata: Value,
    package: &str,
    package_path: &str,
    kind: &str,
) -> Result<HostBoundarySpec, DiscoveryError> {
    let object = owner_object(&mut metadata, package, "host boundary")?;
    take_schema(object, package, "host boundary")?;
    insert_derived(object, "package", package, package)?;
    insert_derived(object, "package-path", package_path, package)?;
    insert_derived(object, "kind", kind, package)?;
    normalize_targets(object, package)?;
    deserialize_owner(metadata, package, "host boundary")
}

fn owner_object<'a>(
    metadata: &'a mut Value,
    package: &str,
    kind: &str,
) -> Result<&'a mut Map<String, Value>, DiscoveryError> {
    metadata.as_object_mut().ok_or_else(|| {
        DiscoveryError::InvalidMetadata(format!(
            "package `{package}` {kind} metadata must be an object"
        ))
    })
}

fn take_schema(
    metadata: &mut Map<String, Value>,
    package: &str,
    kind: &str,
) -> Result<(), DiscoveryError> {
    let schema = metadata.remove("schema").and_then(|value| value.as_u64());
    if schema == Some(1) {
        Ok(())
    } else {
        invalid(format!(
            "package `{package}` {kind} metadata has unsupported or missing schema"
        ))
    }
}

fn insert_derived(
    metadata: &mut Map<String, Value>,
    key: &str,
    value: &str,
    package: &str,
) -> Result<(), DiscoveryError> {
    if metadata
        .insert(key.into(), Value::String(value.into()))
        .is_some()
    {
        invalid(format!(
            "package `{package}` metadata may not self-declare derived field `{key}`"
        ))
    } else {
        Ok(())
    }
}

fn normalize_targets(
    metadata: &mut Map<String, Value>,
    package: &str,
) -> Result<(), DiscoveryError> {
    let targets = metadata.remove("targets").ok_or_else(|| {
        DiscoveryError::InvalidMetadata(format!(
            "package `{package}` metadata is missing `targets`"
        ))
    })?;
    let entries = targets.as_array().ok_or_else(|| {
        DiscoveryError::InvalidMetadata(format!("package `{package}` targets must be an array"))
    })?;
    if entries.is_empty() || entries.len() > MAX_TARGET_PREDICATE_PARTITIONS {
        return invalid(format!(
            "package `{package}` targets must contain 1..={MAX_TARGET_PREDICATE_PARTITIONS} predicates"
        ));
    }
    let mut predicates = Vec::with_capacity(entries.len());
    for entry in entries {
        let predicate = entry.as_str().ok_or_else(|| {
            DiscoveryError::InvalidMetadata(format!(
                "package `{package}` target predicate must be a string"
            ))
        })?;
        let inner = predicate
            .strip_prefix("cfg(")
            .and_then(|value| value.strip_suffix(')'))
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                DiscoveryError::InvalidMetadata(format!(
                    "package `{package}` target predicate must use cfg(...) syntax"
                ))
            })?;
        predicates.push(inner);
    }
    let predicate = if predicates.len() == 1 {
        format!("cfg({})", predicates[0])
    } else {
        format!("cfg(any({}))", predicates.join(", "))
    };
    metadata.insert("targets".into(), Value::String(predicate));
    Ok(())
}

fn deserialize_owner<T: for<'de> Deserialize<'de>>(
    metadata: Value,
    package: &str,
    kind: &str,
) -> Result<T, DiscoveryError> {
    serde_json::from_value(metadata).map_err(|error| {
        DiscoveryError::InvalidMetadata(format!(
            "package `{package}` {kind} metadata is invalid: {error}"
        ))
    })
}

fn invalid<T>(message: impl Into<String>) -> Result<T, DiscoveryError> {
    Err(DiscoveryError::InvalidMetadata(message.into()))
}

#[cfg(test)]
mod tests {
    use std::{env, ffi::OsString, fs::File};

    use serde_json::json;
    use tempfile::TempDir;

    use super::*;
    use crate::{catalog::NormalizedCatalog, metadata::CatalogDocument};

    fn tool(name: &str) -> PathBuf {
        let selected = Command::new("rustup")
            .args(["which", name])
            .output()
            .expect("rustup must resolve the selected test toolchain");
        if selected.status.success() {
            return PathBuf::from(String::from_utf8(selected.stdout).unwrap().trim())
                .canonicalize()
                .unwrap();
        }
        let path = env::var_os("PATH").unwrap_or_else(|| OsString::from(""));
        env::split_paths(&path)
            .map(|directory| directory.join(name))
            .find(|candidate| candidate.is_file())
            .unwrap()
            .canonicalize()
            .unwrap()
    }

    fn host_triple(rustc: &Path) -> String {
        let output = Command::new(rustc).arg("-vV").output().unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix("host: "))
            .unwrap()
            .to_owned()
    }

    fn sort_document(document: &mut CatalogDocument) {
        document
            .capabilities
            .sort_by(|left, right| left.id.cmp(&right.id));
        document
            .components
            .sort_by(|left, right| left.id.cmp(&right.id));
        document
            .runtime_adapters
            .sort_by(|left, right| left.id.cmp(&right.id));
        document
            .host_boundaries
            .sort_by(|left, right| left.id.cmp(&right.id));
    }

    #[test]
    fn cargo_metadata_package_discovery_round_trips_the_catalog_fixture() {
        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .canonicalize()
            .unwrap();
        let cargo = tool("cargo");
        let rustc = tool("rustc");
        let target = host_triple(&rustc);
        let working = TempDir::new().unwrap();
        fs::create_dir(working.path().join(".cargo")).unwrap();
        fs::write(
            working.path().join(".cargo/config.toml"),
            format!("[build]\ntarget = {target:?}\n\n[net]\noffline = true\n"),
        )
        .unwrap();

        let discovered = discover_workspace_catalog(
            &workspace,
            &cargo,
            &rustc,
            working.path(),
            Path::new(&target),
        )
        .unwrap();
        let mut actual = discovered.document.clone();
        let mut expected = CatalogDocument::from_toml(
            &fs::read_to_string(workspace.join("tests/fixtures/catalog.toml")).unwrap(),
        )
        .unwrap();
        sort_document(&mut actual);
        sort_document(&mut expected);
        assert_eq!(
            serde_json::to_value(&actual).unwrap(),
            serde_json::to_value(&expected).unwrap()
        );
        NormalizedCatalog::normalize(discovered.document).unwrap();
        assert_eq!(discovered.root_build_requirements.len(), 3);
        for package in [
            "rust-agent-core",
            "rust-agent-runtime-api",
            "rust-agent-fixture-api",
        ] {
            assert!(discovered.root_build_requirements[package].is_empty());
        }
    }

    fn synthetic_metadata(rust_agent: &Value) -> (TempDir, Value) {
        let workspace = TempDir::new().unwrap();
        fs::write(workspace.path().join("Cargo.toml"), "[workspace]\n").unwrap();
        fs::create_dir(workspace.path().join("member")).unwrap();
        let manifest = workspace.path().join("member/Cargo.toml");
        fs::write(&manifest, "[package]\nname = \"fixture\"\n").unwrap();
        let id = "path+file:///fixture#0.1.0";
        let document = json!({
            "packages": [{
                "name": "fixture",
                "id": id,
                "manifest_path": manifest,
                "source": null,
                "features": {"default": []},
                "metadata": {"rust-agent": rust_agent}
            }],
            "workspace_members": [id],
            "workspace_root": workspace.path(),
            "version": 1
        });
        (workspace, document)
    }

    fn parse_synthetic(
        workspace: &TempDir,
        document: &Value,
    ) -> Result<DiscoveredCatalog, DiscoveryError> {
        parse_cargo_metadata(workspace.path(), &serde_json::to_vec(document).unwrap())
    }

    fn empty_root_requirements() -> Value {
        json!({
            "schema": 1,
            "executables": [],
            "read-inputs": [],
            "environment": []
        })
    }

    #[test]
    fn unknown_spoofed_and_mixed_package_metadata_fail_closed() {
        let (workspace, unknown) = synthetic_metadata(&json!({"unknown-role": {}}));
        assert!(matches!(
            parse_synthetic(&workspace, &unknown),
            Err(DiscoveryError::InvalidMetadata(message)) if message.contains("unknown field")
        ));

        let (workspace, spoofed) = synthetic_metadata(&json!({
            "schema": 1,
            "package": "forged-package"
        }));
        assert!(matches!(
            parse_synthetic(&workspace, &spoofed),
            Err(DiscoveryError::InvalidMetadata(message))
                if message.contains("self-declare derived field `package`")
        ));

        let (workspace, mixed) = synthetic_metadata(&json!({
            "capability": [{
                "id": "cap:fixture",
                "api": "fixture::Fixture",
                "binding-type": "fixture::FixtureBinding",
                "binding-adapter": "fixture::bind",
                "binding": "singleton",
                "scope": "app"
            }],
            "runtime-adapter": {},
            "build-requirements": empty_root_requirements()
        }));
        assert!(matches!(
            parse_synthetic(&workspace, &mixed),
            Err(DiscoveryError::InvalidMetadata(message))
                if message.contains("mixes Capability API")
        ));
    }

    #[test]
    fn workspace_identity_feature_and_schema_drift_fail_closed() {
        let (workspace, mut mismatched_members) = synthetic_metadata(&json!({
            "build-requirements": empty_root_requirements()
        }));
        mismatched_members["workspace_members"] = json!([]);
        assert!(matches!(
            parse_synthetic(&workspace, &mismatched_members),
            Err(DiscoveryError::InvalidMetadata(message))
                if message.contains("exactly match workspace members")
        ));

        let (workspace, mut features) = synthetic_metadata(&json!({
            "build-requirements": empty_root_requirements()
        }));
        features["packages"][0]["features"]["default"] = json!(["ambient"]);
        assert!(matches!(
            parse_synthetic(&workspace, &features),
            Err(DiscoveryError::InvalidMetadata(message))
                if message.contains("non-empty default features")
        ));

        let (workspace, mut external_source) = synthetic_metadata(&json!({
            "build-requirements": empty_root_requirements()
        }));
        external_source["packages"][0]["source"] =
            json!("registry+https://github.com/rust-lang/crates.io-index");
        assert!(matches!(
            parse_synthetic(&workspace, &external_source),
            Err(DiscoveryError::InvalidMetadata(message))
                if message.contains("external source")
        ));

        let (workspace, mut noncanonical_manifest) = synthetic_metadata(&json!({
            "build-requirements": empty_root_requirements()
        }));
        noncanonical_manifest["packages"][0]["manifest_path"] =
            json!(workspace.path().join("member/../member/Cargo.toml"));
        assert!(matches!(
            parse_synthetic(&workspace, &noncanonical_manifest),
            Err(DiscoveryError::InvalidMetadata(message))
                if message.contains("manifest path is not canonical")
        ));

        let (workspace, bad_schema) = synthetic_metadata(&json!({
            "build-requirements": {
                "schema": 2,
                "executables": [],
                "read-inputs": [],
                "environment": []
            }
        }));
        assert!(matches!(
            parse_synthetic(&workspace, &bad_schema),
            Err(DiscoveryError::InvalidMetadata(message))
                if message.contains("unsupported build-requirements schema 2")
        ));
    }

    #[test]
    fn metadata_owner_and_output_byte_boundaries_are_closed() {
        let capability = |index| {
            json!({
                "id": format!("cap:c{index}"),
                "api": "fixture::Fixture",
                "binding-type": "fixture::FixtureBinding",
                "binding-adapter": "fixture::bind",
                "binding": "singleton",
                "scope": "app"
            })
        };
        for (count, succeeds) in [(MAX_CATALOG_OWNERS, true), (MAX_CATALOG_OWNERS + 1, false)] {
            let capabilities: Vec<_> = (0..count).map(capability).collect();
            let (workspace, document) = synthetic_metadata(&json!({
                "capability": capabilities,
                "build-requirements": empty_root_requirements()
            }));
            assert_eq!(parse_synthetic(&workspace, &document).is_ok(), succeeds);
        }

        let workspace = TempDir::new().unwrap();
        let oversized = vec![b' '; MAX_CARGO_METADATA_OUTPUT_BYTES + 1];
        assert!(matches!(
            parse_cargo_metadata(workspace.path(), &oversized),
            Err(DiscoveryError::OutputTooLarge {
                stream: "stdout",
                maximum: MAX_CARGO_METADATA_OUTPUT_BYTES
            })
        ));
    }

    #[cfg(unix)]
    fn write_executable(path: &Path, source: &str) {
        use std::os::unix::fs::PermissionsExt as _;

        fs::write(path, source).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    fn runner_fixture() -> (TempDir, PathBuf, PathBuf, PathBuf, PathBuf) {
        let root = TempDir::new().unwrap();
        let workspace = root.path().join("workspace");
        let working = root.path().join("working");
        let cargo_home = working.join("cargo-home");
        fs::create_dir(&workspace).unwrap();
        fs::create_dir(&working).unwrap();
        fs::create_dir(&cargo_home).unwrap();
        fs::write(workspace.join("Cargo.toml"), "[workspace]\n").unwrap();
        let config = working.join("config.toml");
        fs::write(&config, "[net]\noffline = true\n").unwrap();
        (root, workspace, working, cargo_home, config)
    }

    #[cfg(unix)]
    #[test]
    fn cargo_metadata_process_output_and_deadline_are_bounded() {
        let (root, workspace, working, cargo_home, config) = runner_fixture();
        let rustc = tool("rustc");
        let cargo = root.path().join("fake-cargo-valid");
        let invocation_log = root.path().join("invocation.log");
        write_executable(
            &cargo,
            &format!(
                concat!(
                    "#!/bin/sh\n",
                    "printf 'args:%s\\ncargo-home:%s\\nrustc:%s\\npwd:%s\\noffline:%s\\nepoch:%s\\n' ",
                    "\"$*\" \"$CARGO_HOME\" \"$RUSTC\" \"$PWD\" \"$CARGO_NET_OFFLINE\" ",
                    "\"$SOURCE_DATE_EPOCH\" > {:?}\n",
                    "printf '{{}}'\n"
                ),
                invocation_log,
            ),
        );
        assert_eq!(
            run_cargo_metadata(CargoMetadataInvocation {
                workspace_root: &workspace,
                cargo_path: &cargo,
                rustc_path: &rustc,
                working_directory: &working,
                cargo_target_input: Path::new("x86_64-unknown-linux-gnu"),
                generated_config: &config,
                cargo_home: &cargo_home,
                timeout: Duration::from_secs(5),
            })
            .unwrap(),
            b"{}"
        );
        let invocation = fs::read_to_string(&invocation_log).unwrap();
        assert!(invocation.contains(&format!(
            "args:metadata --format-version 1 --no-deps --locked --offline --filter-platform x86_64-unknown-linux-gnu --manifest-path {} --config {}",
            workspace.join("Cargo.toml").display(),
            config.display()
        )));
        assert!(invocation.contains(&format!("cargo-home:{}", cargo_home.display())));
        assert!(invocation.contains(&format!("rustc:{}", rustc.display())));
        assert!(invocation.contains(&format!("pwd:{}", working.display())));
        assert!(invocation.contains("offline:true\nepoch:0\n"));

        let payload = root.path().join("oversized-output");
        File::create(&payload)
            .unwrap()
            .set_len(MAX_CARGO_METADATA_OUTPUT_BYTES as u64 + 1)
            .unwrap();
        let oversized_cargo = root.path().join("fake-cargo-oversized");
        write_executable(
            &oversized_cargo,
            &format!("#!/bin/sh\nexec /bin/cat {payload:?}\n"),
        );
        assert!(matches!(
            run_cargo_metadata(CargoMetadataInvocation {
                workspace_root: &workspace,
                cargo_path: &oversized_cargo,
                rustc_path: &rustc,
                working_directory: &working,
                cargo_target_input: Path::new("x86_64-unknown-linux-gnu"),
                generated_config: &config,
                cargo_home: &cargo_home,
                timeout: Duration::from_secs(5),
            }),
            Err(DiscoveryError::OutputTooLarge {
                stream: "stdout",
                maximum: MAX_CARGO_METADATA_OUTPUT_BYTES
            })
        ));

        let timeout_cargo = root.path().join("fake-cargo-timeout");
        write_executable(&timeout_cargo, "#!/bin/sh\nexec /bin/sleep 5\n");
        let started = Instant::now();
        assert!(matches!(
            run_cargo_metadata(CargoMetadataInvocation {
                workspace_root: &workspace,
                cargo_path: &timeout_cargo,
                rustc_path: &rustc,
                working_directory: &working,
                cargo_target_input: Path::new("x86_64-unknown-linux-gnu"),
                generated_config: &config,
                cargo_home: &cargo_home,
                timeout: Duration::from_millis(50),
            }),
            Err(DiscoveryError::TimedOut { .. })
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
