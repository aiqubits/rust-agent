use std::{collections::BTreeMap, path::PathBuf};

use rust_agent_composition::canonical;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    BuildArtifactSelector, BuildArtifactTarget, BuildPanicStrategy, CargoUnitGraphPlannerIdentity,
    HostBuildClosureItemRole, NormalizedHostBuildInputClosure, NormalizedProductionBuildPolicy,
    ProductionBuildPolicyError,
};

mod normalization;

pub use normalization::{
    CargoPlannerEdgeSemantic, CargoPlannerEdgeSemantics, CargoUnitGraphNormalizationError,
    normalize_cargo_unit_graph,
};

const LOGICAL_RUSTC: &str = "/rust-agent/toolchain/bin/rustc";
const LOGICAL_CARGO_HOME: &str = "/rust-agent/cargo-home";
const LOGICAL_TARGET_DIR: &str = "/rust-agent/target";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CargoPlannerGraphRoot {
    EmittedStandalone,
    FinalHost,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CargoPlannerRequest {
    pub schema: u32,
    pub root: CargoPlannerGraphRoot,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CargoPlannerInvocation {
    pub executable: PathBuf,
    pub arguments: Vec<String>,
    pub environment: BTreeMap<String, String>,
    #[serde(rename = "working-directory")]
    pub working_directory: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedCargoPlannerRequest {
    root: CargoPlannerGraphRoot,
    planner: CargoUnitGraphPlannerIdentity,
    build_execution_policy_digest: String,
    host_build_input_closure_digest: String,
    manifest_logical_path: String,
    cargo_config_logical_path: String,
    build_triple: String,
    target: String,
    profile: String,
    artifact_selector: BuildArtifactSelector,
    panic_strategy: BuildPanicStrategy,
    invocation: CargoPlannerInvocation,
    digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedCargoUnitGraphEnvelope {
    request_digest: String,
    version: u32,
    unit_count: usize,
    edge_count: usize,
    root_count: usize,
    digest: String,
    graph: RawCargoUnitGraph,
}

#[derive(Debug, Error)]
pub enum CargoPlannerError {
    #[error("unsupported Cargo planner request schema {0}; expected 1")]
    UnsupportedRequestSchema(u32),
    #[error("Cargo planner policy does not match HostBuildInputClosure")]
    PolicyMismatch,
    #[error("HostBuildInputClosure is missing planner input role {0:?}")]
    MissingClosureItem(HostBuildClosureItemRole),
    #[error("Cargo planner logical path is invalid: {0}")]
    InvalidLogicalPath(String),
    #[error("Cargo unit-graph output is invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported Cargo unit-graph output schema {0}; expected 1")]
    UnsupportedUnitGraphSchema(u32),
    #[error("Cargo unit-graph output violates the closed v1 contract: {0}")]
    InvalidUnitGraph(&'static str),
    #[error("pinned Cargo does not expose the trusted unit-graph planning interface")]
    TrustedUnitGraphUnavailable,
    #[error("Cargo unit-graph planning failed with exit code {0}")]
    PlannerFailed(i32),
    #[error("Cargo unit-graph planning emitted unexpected stderr")]
    UnexpectedStderr,
    #[error("Cargo unit-graph output does not match the requested target/profile")]
    PlannerContextMismatch,
    #[error("production build policy verification failed: {0}")]
    ProductionPolicy(#[from] ProductionBuildPolicyError),
    #[error("canonical Cargo planner encoding failed: {0}")]
    Canonical(#[from] canonical::CanonicalError),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RawCargoUnitGraph {
    version: u32,
    units: Vec<RawCargoUnit>,
    roots: Vec<usize>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RawCargoUnit {
    pkg_id: String,
    target: RawCargoTarget,
    profile: RawCargoProfile,
    platform: Option<String>,
    mode: RawCargoCompileMode,
    features: Vec<String>,
    #[serde(default)]
    is_std: bool,
    dependencies: Vec<RawCargoUnitDependency>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RawCargoTarget {
    kind: Vec<String>,
    crate_types: Vec<String>,
    name: String,
    src_path: Option<String>,
    edition: String,
    #[serde(
        default,
        rename = "required-features",
        skip_serializing_if = "Option::is_none"
    )]
    required_features: Option<Vec<String>>,
    doc: bool,
    doctest: bool,
    test: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)] // Mirrors Cargo unit-graph v1's fixed profile schema.
struct RawCargoProfile {
    name: String,
    opt_level: String,
    lto: String,
    codegen_units: serde_json::Value,
    debuginfo: serde_json::Value,
    debug_assertions: bool,
    overflow_checks: bool,
    rpath: bool,
    incremental: bool,
    panic: String,
    split_debuginfo: serde_json::Value,
    strip: serde_json::Value,
    codegen_backend: serde_json::Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    rustflags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    trim_paths: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hint_mostly_unused: Option<bool>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum RawCargoCompileMode {
    Test,
    Build,
    Check,
    Doc,
    Doctest,
    RunCustomBuild,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RawCargoUnitDependency {
    index: usize,
    extern_crate_name: String,
    #[serde(default)]
    public: Option<bool>,
    #[serde(default)]
    noprelude: Option<bool>,
    #[serde(default)]
    nounused: Option<bool>,
}

#[derive(Serialize)]
struct PlannerRequestProjection<'a> {
    schema: u32,
    root: CargoPlannerGraphRoot,
    planner: &'a CargoUnitGraphPlannerIdentity,
    build_execution_policy_digest: &'a str,
    host_build_input_closure_digest: &'a str,
    manifest_logical_path: &'a str,
    cargo_config_logical_path: &'a str,
    target: &'a str,
    profile: &'a str,
    artifact_selector: &'a BuildArtifactSelector,
    panic_strategy: BuildPanicStrategy,
    arguments: &'a [String],
    environment: &'a BTreeMap<String, String>,
    working_directory: &'a str,
}

impl CargoPlannerRequest {
    pub fn normalize(
        &self,
        policy: &NormalizedProductionBuildPolicy,
        closure: &NormalizedHostBuildInputClosure,
    ) -> Result<NormalizedCargoPlannerRequest, CargoPlannerError> {
        if self.schema != 1 {
            return Err(CargoPlannerError::UnsupportedRequestSchema(self.schema));
        }
        if closure.build_execution_policy_digest() != policy.full_digest() {
            return Err(CargoPlannerError::PolicyMismatch);
        }
        let context = closure.build_context();
        context.validate()?;
        let cargo_config_logical_path =
            closure_item_path(closure, HostBuildClosureItemRole::CargoConfig)?;
        let (manifest_logical_path, artifact_selector) = match self.root {
            CargoPlannerGraphRoot::EmittedStandalone => {
                let root =
                    closure_item_path(closure, HostBuildClosureItemRole::EmittedCompositionTree)?;
                (
                    format!("{root}/Cargo.toml"),
                    BuildArtifactSelector {
                        package: closure.generated_package_name().into(),
                        target: BuildArtifactTarget::Library,
                    },
                )
            }
            CargoPlannerGraphRoot::FinalHost => (
                closure_item_path(closure, HostBuildClosureItemRole::HostRootManifest)?,
                context.artifact_selector.clone(),
            ),
        };
        if !is_logical_file(&manifest_logical_path, "Cargo.toml")
            || !is_logical_file(&cargo_config_logical_path, "config.toml")
        {
            return Err(CargoPlannerError::InvalidLogicalPath(manifest_logical_path));
        }

        let toolchain = &policy.policy().toolchain;
        let planner = CargoUnitGraphPlannerIdentity {
            interface: "cargo-unit-graph-v1".into(),
            cargo_version: declared_tool_version(&toolchain.cargo.version).into(),
            cargo_digest: toolchain.cargo.sha256.clone(),
            rustc_version: declared_tool_version(&toolchain.rustc.version).into(),
            rustc_digest: toolchain.rustc.sha256.clone(),
        };
        let mut arguments = vec![
            "build".into(),
            "--manifest-path".into(),
            manifest_logical_path.clone(),
            "--config".into(),
            cargo_config_logical_path.clone(),
            "--locked".into(),
            "--offline".into(),
            "--target".into(),
            context.target.clone(),
            "--profile".into(),
            context.profile.clone(),
        ];
        arguments.extend(artifact_selector.cargo_arguments());
        arguments.extend([
            "--unit-graph".into(),
            "-Z".into(),
            "unstable-options".into(),
        ]);
        let environment = BTreeMap::from([
            ("CARGO_HOME".into(), LOGICAL_CARGO_HOME.into()),
            ("CARGO_INCREMENTAL".into(), "0".into()),
            ("CARGO_NET_OFFLINE".into(), "true".into()),
            ("CARGO_TARGET_DIR".into(), LOGICAL_TARGET_DIR.into()),
            ("LANG".into(), "C.UTF-8".into()),
            ("LC_ALL".into(), "C.UTF-8".into()),
            ("PATH".into(), "/rust-agent/toolchain/bin".into()),
            ("RUSTC".into(), LOGICAL_RUSTC.into()),
            ("SOURCE_DATE_EPOCH".into(), "0".into()),
        ]);
        let working_directory = manifest_parent(&manifest_logical_path)?.into();
        let invocation = CargoPlannerInvocation {
            executable: toolchain.cargo.path.clone(),
            arguments,
            environment,
            working_directory,
        };
        let projection = PlannerRequestProjection {
            schema: 1,
            root: self.root,
            planner: &planner,
            build_execution_policy_digest: policy.full_digest(),
            host_build_input_closure_digest: closure.digest(),
            manifest_logical_path: &manifest_logical_path,
            cargo_config_logical_path: &cargo_config_logical_path,
            target: &context.target,
            profile: &context.profile,
            artifact_selector: &artifact_selector,
            panic_strategy: context.panic_strategy,
            arguments: &invocation.arguments,
            environment: &invocation.environment,
            working_directory: &invocation.working_directory,
        };
        let digest = hex::encode(canonical::domain_hash(
            b"rust-agent-cargo-unit-graph-planner-request-v1\0",
            &projection,
        )?);
        Ok(NormalizedCargoPlannerRequest {
            root: self.root,
            planner,
            build_execution_policy_digest: policy.full_digest().into(),
            host_build_input_closure_digest: closure.digest().into(),
            manifest_logical_path,
            cargo_config_logical_path,
            build_triple: context.build_triple.clone(),
            target: context.target.clone(),
            profile: context.profile.clone(),
            artifact_selector,
            panic_strategy: context.panic_strategy,
            invocation,
            digest,
        })
    }
}

impl NormalizedCargoPlannerRequest {
    pub fn root(&self) -> CargoPlannerGraphRoot {
        self.root
    }

    pub fn planner(&self) -> &CargoUnitGraphPlannerIdentity {
        &self.planner
    }

    pub fn build_execution_policy_digest(&self) -> &str {
        &self.build_execution_policy_digest
    }

    pub fn host_build_input_closure_digest(&self) -> &str {
        &self.host_build_input_closure_digest
    }

    pub fn manifest_logical_path(&self) -> &str {
        &self.manifest_logical_path
    }

    pub fn cargo_config_logical_path(&self) -> &str {
        &self.cargo_config_logical_path
    }

    pub fn build_triple(&self) -> &str {
        &self.build_triple
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }

    pub fn artifact_selector(&self) -> &BuildArtifactSelector {
        &self.artifact_selector
    }

    pub fn invocation(&self) -> &CargoPlannerInvocation {
        &self.invocation
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn verify_output(
        &self,
        exit_code: i32,
        stdout: &[u8],
        stderr: &[u8],
    ) -> Result<VerifiedCargoUnitGraphEnvelope, CargoPlannerError> {
        if exit_code != 0 {
            let stderr = String::from_utf8_lossy(stderr);
            if stderr.contains("the `--unit-graph` flag is unstable")
                && stderr.contains("this is the `stable` channel")
            {
                return Err(CargoPlannerError::TrustedUnitGraphUnavailable);
            }
            return Err(CargoPlannerError::PlannerFailed(exit_code));
        }
        if !stderr.is_empty() {
            return Err(CargoPlannerError::UnexpectedStderr);
        }
        if stdout.is_empty() || stdout.len() > 64 * 1024 * 1024 {
            return Err(CargoPlannerError::InvalidUnitGraph("encoded size"));
        }
        let graph: RawCargoUnitGraph = serde_json::from_slice(stdout)?;
        validate_raw_graph(&graph, &self.target, &self.profile, self.panic_strategy)?;
        let edge_count = graph.units.iter().map(|unit| unit.dependencies.len()).sum();
        let digest = hex::encode(canonical::domain_hash(
            b"rust-agent-cargo-unit-graph-v1-envelope-v1\0",
            &(&self.digest, &graph),
        )?);
        Ok(VerifiedCargoUnitGraphEnvelope {
            request_digest: self.digest.clone(),
            version: graph.version,
            unit_count: graph.units.len(),
            edge_count,
            root_count: graph.roots.len(),
            digest,
            graph,
        })
    }
}

impl VerifiedCargoUnitGraphEnvelope {
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn unit_count(&self) -> usize {
        self.unit_count
    }

    pub fn edge_count(&self) -> usize {
        self.edge_count
    }

    pub fn root_count(&self) -> usize {
        self.root_count
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }
}

fn validate_raw_graph(
    graph: &RawCargoUnitGraph,
    target: &str,
    profile: &str,
    panic_strategy: BuildPanicStrategy,
) -> Result<(), CargoPlannerError> {
    if graph.version != 1 {
        return Err(CargoPlannerError::UnsupportedUnitGraphSchema(graph.version));
    }
    if graph.units.is_empty() || graph.units.len() > 100_000 {
        return Err(CargoPlannerError::InvalidUnitGraph("unit cardinality"));
    }
    if graph.roots.is_empty()
        || graph.roots.windows(2).any(|pair| pair[0] >= pair[1])
        || graph.roots.iter().any(|index| *index >= graph.units.len())
    {
        return Err(CargoPlannerError::InvalidUnitGraph("roots"));
    }
    for unit in &graph.units {
        if !valid_text(&unit.pkg_id, 4096)
            || !valid_cargo_name(&unit.target.name)
            || unit
                .target
                .src_path
                .as_deref()
                .map_or(unit.target.kind.as_slice() != ["custom-build"], |path| {
                    !valid_text(path, 4096)
                })
            || !valid_text(&unit.target.edition, 32)
            || unit.target.kind.is_empty()
            || unit.target.crate_types.is_empty()
            || !strictly_sorted_text(&unit.target.kind)
            || !strictly_sorted_text(&unit.target.crate_types)
            || unit
                .target
                .required_features
                .as_deref()
                .is_some_and(|features| features.iter().any(|feature| !valid_feature(feature)))
            || unit.profile.name != profile
            || !valid_profile(&unit.profile)
            || unit.features.windows(2).any(|pair| pair[0] >= pair[1])
            || unit.features.iter().any(|feature| !valid_feature(feature))
            || unit.is_std
            || unit
                .platform
                .as_deref()
                .is_some_and(|value| value != target)
        {
            return Err(CargoPlannerError::PlannerContextMismatch);
        }
        let mut previous = None;
        for dependency in &unit.dependencies {
            if dependency.index >= graph.units.len()
                || !valid_cargo_name(&dependency.extern_crate_name)
            {
                return Err(CargoPlannerError::InvalidUnitGraph("dependency"));
            }
            let key = (dependency.index, dependency.extern_crate_name.as_str());
            if previous.is_some_and(|value| value >= key) {
                return Err(CargoPlannerError::InvalidUnitGraph("dependency ordering"));
            }
            previous = Some(key);
        }
    }
    if graph.roots.iter().any(|index| {
        let root = &graph.units[*index];
        root.platform.as_deref() != Some(target)
            || root.profile.panic != expected_panic_strategy(panic_strategy)
    }) {
        return Err(CargoPlannerError::PlannerContextMismatch);
    }
    validate_acyclic(graph)
}

fn validate_acyclic(graph: &RawCargoUnitGraph) -> Result<(), CargoPlannerError> {
    let mut incoming = vec![0_usize; graph.units.len()];
    let mut outgoing = vec![Vec::new(); graph.units.len()];
    for (dependent, unit) in graph.units.iter().enumerate() {
        for dependency in &unit.dependencies {
            incoming[dependency.index] += 1;
            outgoing[dependent].push(dependency.index);
        }
    }
    let mut ready: Vec<_> = incoming
        .iter()
        .enumerate()
        .filter_map(|(index, count)| (*count == 0).then_some(index))
        .collect();
    let mut visited = 0;
    while let Some(index) = ready.pop() {
        visited += 1;
        for dependency in &outgoing[index] {
            incoming[*dependency] -= 1;
            if incoming[*dependency] == 0 {
                ready.push(*dependency);
            }
        }
    }
    if visited == graph.units.len() {
        Ok(())
    } else {
        Err(CargoPlannerError::InvalidUnitGraph("dependency cycle"))
    }
}

fn valid_profile(profile: &RawCargoProfile) -> bool {
    valid_text(&profile.name, 64)
        && valid_text(&profile.opt_level, 32)
        && valid_text(&profile.lto, 32)
        && matches!(
            profile.panic.as_str(),
            "abort" | "unwind" | "immediate-abort"
        )
        && scalar_or_null(&profile.codegen_units)
        && scalar_or_null(&profile.debuginfo)
        && scalar_or_null(&profile.split_debuginfo)
        && scalar_or_null(&profile.strip)
        && scalar_or_null(&profile.codegen_backend)
        && profile
            .rustflags
            .iter()
            .all(|rustflag| valid_text(rustflag, 4096))
        && profile.trim_paths.as_ref().is_none_or(valid_trim_paths)
}

fn valid_trim_paths(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(value) => value == "all",
        serde_json::Value::Array(values) => {
            values.len() <= 3
                && values.iter().all(|value| {
                    value
                        .as_str()
                        .is_some_and(|value| matches!(value, "diagnostics" | "macro" | "object"))
                })
        }
        _ => false,
    }
}

fn expected_panic_strategy(strategy: BuildPanicStrategy) -> &'static str {
    match strategy {
        BuildPanicStrategy::Abort => "abort",
        BuildPanicStrategy::Unwind => "unwind",
    }
}

fn scalar_or_null(value: &serde_json::Value) -> bool {
    matches!(
        value,
        serde_json::Value::Null
            | serde_json::Value::Bool(_)
            | serde_json::Value::Number(_)
            | serde_json::Value::String(_)
    )
}

fn closure_item_path(
    closure: &NormalizedHostBuildInputClosure,
    role: HostBuildClosureItemRole,
) -> Result<String, CargoPlannerError> {
    closure
        .items()
        .iter()
        .find(|item| item.role == role)
        .map(|item| item.logical_path.clone())
        .ok_or(CargoPlannerError::MissingClosureItem(role))
}

fn manifest_parent(path: &str) -> Result<&str, CargoPlannerError> {
    path.rsplit_once('/')
        .map(|(parent, _)| parent)
        .filter(|parent| parent.starts_with("/rust-agent/closure/"))
        .ok_or_else(|| CargoPlannerError::InvalidLogicalPath(path.into()))
}

fn is_logical_file(path: &str, file_name: &str) -> bool {
    path.starts_with("/rust-agent/closure/")
        && path.ends_with(&format!("/{file_name}"))
        && path
            .split('/')
            .skip(1)
            .all(|part| !part.is_empty() && !matches!(part, "." | ".."))
}

fn declared_tool_version(value: &str) -> &str {
    value.split_ascii_whitespace().nth(1).unwrap_or(value)
}

fn valid_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value.contains(['\0', '\n', '\r'])
        && value.trim() == value
}

fn valid_cargo_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphabetic()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_feature(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn strictly_sorted_text(values: &[String]) -> bool {
    values.iter().all(|value| valid_text(value, 128))
        && !values.windows(2).any(|pair| pair[0] >= pair[1])
}

#[cfg(test)]
mod tests {
    use std::{fs, process::Command};

    use rust_agent_composition::metadata::BuildRequirements;
    use serde_json::json;
    use tempfile::tempdir;

    use super::*;
    use crate::{
        BuildEnforcementContext, BuildPanicStrategy, CanonicalSnapshotMetadataContract,
        CargoCompilationKind, CargoCompileMode, CargoCrateKind, CargoDependencyKind,
        CargoPackageIdentity, CargoPackageSource, CargoTargetEvaluationDomain, CargoUnit,
        CargoUnitGraphError, CargoUnitSelector, DerivedExecutablePolicy, HostBuildClosureContent,
        HostBuildClosureItem, HostBuildInputClosure, HostCargoUnitGraph, HostFeaturePolicyClosure,
        LockedSourceClosure, LockedSourceError, NormalizedLockedSourceClosure,
        ProductionAttestationPolicy, ProductionBuildExecutionPolicy, ProductionFetchPolicy,
        ProductionSandboxBackend, ProductionToolIdentity, ProductionToolchain,
        ProductionTreeIdentity, SigningHelper, TrustedSigner,
    };

    fn digest(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    fn policy() -> NormalizedProductionBuildPolicy {
        ProductionBuildExecutionPolicy {
            schema: 1,
            id: "ci-linux-hermetic-v1".into(),
            host: "cfg(target_os = \"linux\")".into(),
            backend: ProductionSandboxBackend::LinuxLandlockSeccomp,
            fetch: ProductionFetchPolicy {
                network_endpoints: vec![],
                credential_helper: None,
                max_redirects: 0,
            },
            attestation: ProductionAttestationPolicy {
                allowed_executors: vec!["rust-agent-build-host-v1".into()],
                trusted_signers: vec![TrustedSigner {
                    id: "ci-runner-2026".into(),
                    algorithm: "ed25519".into(),
                    public_key: "/runner/keys/ci-runner.pub".into(),
                    sha256: digest('1'),
                }],
                trusted_reviewer_policies: vec![],
                signing_helper: SigningHelper {
                    signer_id: "ci-runner-2026".into(),
                    path: "/runner/bin/sign".into(),
                    sha256: digest('2'),
                },
            },
            toolchain: ProductionToolchain {
                cargo: ProductionToolIdentity {
                    path: "/runner/toolchain/bin/cargo".into(),
                    sha256: digest('3'),
                    version: "cargo 1.97.1 (fixture 2026-08-01)".into(),
                },
                rustc: ProductionToolIdentity {
                    path: "/runner/toolchain/bin/rustc".into(),
                    sha256: digest('4'),
                    version: "rustc 1.97.1 (fixture 2026-08-01)".into(),
                },
                sysroot: ProductionTreeIdentity {
                    path: "/runner/toolchain/sysroot".into(),
                    tree_digest: digest('5'),
                },
            },
            read_inputs: vec![],
            executables: vec![],
            environment: vec![],
            derived_executable: DerivedExecutablePolicy {
                roots: vec!["target".into()],
                inherit_sandbox: true,
            },
        }
        .normalize()
        .unwrap()
    }

    fn context() -> BuildEnforcementContext {
        BuildEnforcementContext {
            schema: 1,
            build_triple: "x86_64-unknown-linux-gnu".into(),
            target: "aarch64-unknown-linux-gnu".into(),
            target_facts_digest: digest('6'),
            custom_target_spec_digest: None,
            cargo_resolution_digest: digest('7'),
            cargo_config_digest: digest('8'),
            profile: "release".into(),
            artifact_selector: BuildArtifactSelector {
                package: "host-fixture".into(),
                target: BuildArtifactTarget::Binary {
                    name: "host-app".into(),
                },
            },
            panic_strategy: BuildPanicStrategy::Unwind,
            rustc_settings_digest: digest('9'),
            prefix_remap_schema: 1,
        }
    }

    fn graph() -> HostCargoUnitGraph {
        HostCargoUnitGraph {
            schema: 1,
            planner: CargoUnitGraphPlannerIdentity {
                interface: "cargo-unit-graph-v1".into(),
                cargo_version: "1.97.1".into(),
                cargo_digest: digest('3'),
                rustc_version: "1.97.1".into(),
                rustc_digest: digest('4'),
            },
            build_triple: "x86_64-unknown-linux-gnu".into(),
            composition_target: "aarch64-unknown-linux-gnu".into(),
            profile: "release".into(),
            nodes: vec![CargoUnit {
                selector: CargoUnitSelector {
                    package: CargoPackageIdentity {
                        name: "host-fixture".into(),
                        version: "0.1.0".into(),
                        source: CargoPackageSource::Path {
                            tree_digest: digest('a'),
                        },
                    },
                    target_name: "host_app".into(),
                    compilation_kind: CargoCompilationKind::Target,
                    compilation_target: "aarch64-unknown-linux-gnu".into(),
                    compile_mode: CargoCompileMode::Build,
                    profile: "release".into(),
                    crate_kind: CargoCrateKind::Binary,
                },
                features: vec![],
                build_script: false,
                proc_macro: false,
            }],
            edges: vec![],
        }
    }

    fn item(
        role: HostBuildClosureItemRole,
        id: &str,
        logical_path: &str,
        content: HostBuildClosureContent,
    ) -> HostBuildClosureItem {
        HostBuildClosureItem {
            role,
            id: id.into(),
            logical_path: logical_path.into(),
            metadata_contract: CanonicalSnapshotMetadataContract::ReadOnlyEpochV1,
            content,
        }
    }

    fn closure(policy: &NormalizedProductionBuildPolicy) -> NormalizedHostBuildInputClosure {
        closure_with_artifact(policy, context().artifact_selector.target)
    }

    fn closure_with_artifact(
        policy: &NormalizedProductionBuildPolicy,
        target: BuildArtifactTarget,
    ) -> NormalizedHostBuildInputClosure {
        let mut context = context();
        context.artifact_selector.target = target;
        let requirements = BuildRequirements::default();
        let record = |role, id, path, value| {
            item(
                role,
                id,
                path,
                HostBuildClosureContent::CanonicalRecord { digest: value },
            )
        };
        HostBuildInputClosure {
            schema: 1,
            composition_hash: digest('b'),
            host_dependency_alias: "generated-agent".into(),
            generated_package_name: "rust-agent-composition-fixture".into(),
            items: vec![
                item(
                    HostBuildClosureItemRole::HostRootManifest,
                    "host-root-manifest",
                    "/rust-agent/closure/host/Cargo.toml",
                    HostBuildClosureContent::File {
                        sha256: digest('c'),
                    },
                ),
                item(
                    HostBuildClosureItemRole::HostCargoLock,
                    "host-cargo-lock",
                    "/rust-agent/closure/host/Cargo.lock",
                    HostBuildClosureContent::File {
                        sha256: digest('d'),
                    },
                ),
                item(
                    HostBuildClosureItemRole::CargoConfig,
                    "cargo-config",
                    "/rust-agent/closure/host/.cargo/config.toml",
                    HostBuildClosureContent::File {
                        sha256: digest('8'),
                    },
                ),
                item(
                    HostBuildClosureItemRole::HostPackageTree,
                    "host-package-tree",
                    "/rust-agent/closure/trees/host-fixture",
                    HostBuildClosureContent::SnapshotTree {
                        tree_digest: digest('e'),
                    },
                ),
                item(
                    HostBuildClosureItemRole::EmittedCompositionTree,
                    "emitted-composition-tree",
                    "/rust-agent/closure/trees/generated-agent",
                    HostBuildClosureContent::SnapshotTree {
                        tree_digest: digest('f'),
                    },
                ),
                record(
                    HostBuildClosureItemRole::CargoResolutionRecord,
                    "cargo-resolution",
                    "/rust-agent/closure/records/cargo-resolution.json",
                    digest('7'),
                ),
                record(
                    HostBuildClosureItemRole::TargetFactsRecord,
                    "target-facts",
                    "/rust-agent/closure/records/target-facts.json",
                    digest('6'),
                ),
                record(
                    HostBuildClosureItemRole::RustcSettingsRecord,
                    "rustc-settings",
                    "/rust-agent/closure/records/rustc-settings.json",
                    digest('9'),
                ),
                record(
                    HostBuildClosureItemRole::ArtifactSelectorRecord,
                    "artifact-selector",
                    "/rust-agent/closure/records/artifact-selector.json",
                    context.artifact_selector.digest().unwrap(),
                ),
            ],
            standalone_unit_graph: graph(),
            final_unit_graph: graph(),
            build_context: context.clone(),
            build_requirements: requirements.clone(),
            build_execution_policy_digest: policy.full_digest().into(),
            build_enforcement_identity_digest: policy
                .enforcement_identity_digest(&requirements, &context)
                .unwrap(),
            host_feature_policy: HostFeaturePolicyClosure::None,
            unit_feature_delta_digest: digest('0'),
        }
        .normalize(policy)
        .unwrap()
    }

    fn raw_graph() -> serde_json::Value {
        json!({
            "version": 1,
            "units": [{
                "pkg_id": "path+file:///rust-agent/closure/host#host-fixture@0.1.0",
                "target": {
                    "kind": ["bin"],
                    "crate_types": ["bin"],
                    "name": "host_app",
                    "src_path": "/rust-agent/closure/host/src/main.rs",
                    "edition": "2024",
                    "doc": true,
                    "doctest": false,
                    "test": true
                },
                "profile": {
                    "name": "release",
                    "opt_level": "3",
                    "lto": "false",
                    "codegen_units": 16,
                    "debuginfo": 0,
                    "debug_assertions": false,
                    "overflow_checks": false,
                    "rpath": false,
                    "incremental": false,
                    "panic": "unwind",
                    "split_debuginfo": "off",
                    "strip": "none",
                    "codegen_backend": null
                },
                "platform": "aarch64-unknown-linux-gnu",
                "mode": "build",
                "features": [],
                "dependencies": []
            }],
            "roots": [0]
        })
    }

    fn raw_profile() -> serde_json::Value {
        json!({
            "name": "release",
            "opt_level": "3",
            "lto": "false",
            "codegen_units": 16,
            "debuginfo": 0,
            "debug_assertions": false,
            "overflow_checks": false,
            "rpath": false,
            "incremental": false,
            "panic": "unwind",
            "split_debuginfo": "off",
            "strip": "none",
            "codegen_backend": null
        })
    }

    fn raw_cross_compile_graph() -> serde_json::Value {
        json!({
            "version": 1,
            "units": [
                {
                    "pkg_id": "path+file:///rust-agent/closure/trees/host-fixture#0.1.0",
                    "target": {
                        "kind": ["bin"],
                        "crate_types": ["bin"],
                        "name": "host-app",
                        "src_path": "/rust-agent/closure/trees/host-fixture/src/main.rs",
                        "edition": "2024",
                        "doc": true,
                        "doctest": false,
                        "test": true
                    },
                    "profile": raw_profile(),
                    "platform": "aarch64-unknown-linux-gnu",
                    "mode": "build",
                    "features": ["host-ui"],
                    "dependencies": [
                        {
                            "index": 1,
                            "extern_crate_name": "build_script_build",
                            "public": false,
                            "noprelude": false,
                            "nounused": false
                        },
                        {
                            "index": 3,
                            "extern_crate_name": "macro_helper",
                            "public": false,
                            "noprelude": false,
                            "nounused": false
                        },
                        {
                            "index": 4,
                            "extern_crate_name": "git_helper",
                            "public": false,
                            "noprelude": false,
                            "nounused": false
                        }
                    ]
                },
                {
                    "pkg_id": "path+file:///rust-agent/closure/trees/host-fixture#0.1.0",
                    "target": {
                        "kind": ["custom-build"],
                        "crate_types": ["bin"],
                        "name": "build-script-build",
                        "src_path": "/rust-agent/closure/trees/host-fixture/build.rs",
                        "edition": "2024",
                        "doc": false,
                        "doctest": false,
                        "test": false
                    },
                    "profile": raw_profile(),
                    "platform": "aarch64-unknown-linux-gnu",
                    "mode": "run-custom-build",
                    "features": ["build-mode"],
                    "dependencies": [{
                        "index": 2,
                        "extern_crate_name": "build_helper",
                        "public": false,
                        "noprelude": false,
                        "nounused": false
                    }]
                },
                {
                    "pkg_id": "registry+https://github.com/rust-lang/crates.io-index#build-helper@1.0.0",
                    "target": {
                        "kind": ["lib"],
                        "crate_types": ["lib"],
                        "name": "build_helper",
                        "src_path": "/rust-agent/cargo-home/registry/src/build-helper/src/lib.rs",
                        "edition": "2024",
                        "doc": true,
                        "doctest": true,
                        "test": true
                    },
                    "profile": raw_profile(),
                    "platform": null,
                    "mode": "build",
                    "features": ["host-only"],
                    "dependencies": []
                },
                {
                    "pkg_id": "registry+https://github.com/rust-lang/crates.io-index#macro-helper@2.0.0",
                    "target": {
                        "kind": ["proc-macro"],
                        "crate_types": ["proc-macro"],
                        "name": "macro_helper",
                        "src_path": "/rust-agent/cargo-home/registry/src/macro-helper/src/lib.rs",
                        "edition": "2024",
                        "doc": true,
                        "doctest": false,
                        "test": true
                    },
                    "profile": raw_profile(),
                    "platform": null,
                    "mode": "build",
                    "features": ["derive"],
                    "dependencies": []
                },
                {
                    "pkg_id": "git+https://github.com/example/git-helper?rev=stable#git-helper@3.0.0",
                    "target": {
                        "kind": ["lib"],
                        "crate_types": ["lib"],
                        "name": "git_helper",
                        "src_path": "/rust-agent/cargo-home/git/checkouts/git-helper/src/lib.rs",
                        "edition": "2024",
                        "doc": true,
                        "doctest": true,
                        "test": true
                    },
                    "profile": raw_profile(),
                    "platform": "aarch64-unknown-linux-gnu",
                    "mode": "build",
                    "features": ["target-only"],
                    "dependencies": []
                }
            ],
            "roots": [0]
        })
    }

    fn locked_sources() -> NormalizedLockedSourceClosure {
        LockedSourceClosure {
            schema: 1,
            cargo_lock_digest: digest('d'),
            packages: vec![
                CargoPackageIdentity {
                    name: "host-fixture".into(),
                    version: "0.1.0".into(),
                    source: CargoPackageSource::Path {
                        tree_digest: digest('a'),
                    },
                },
                CargoPackageIdentity {
                    name: "build-helper".into(),
                    version: "1.0.0".into(),
                    source: CargoPackageSource::Registry {
                        registry: "https://github.com/rust-lang/crates.io-index".into(),
                        checksum: digest('b'),
                    },
                },
                CargoPackageIdentity {
                    name: "macro-helper".into(),
                    version: "2.0.0".into(),
                    source: CargoPackageSource::Registry {
                        registry: "https://github.com/rust-lang/crates.io-index".into(),
                        checksum: digest('c'),
                    },
                },
                CargoPackageIdentity {
                    name: "git-helper".into(),
                    version: "3.0.0".into(),
                    source: CargoPackageSource::Git {
                        repository: "https://github.com/example/git-helper?rev=stable".into(),
                        precise: "1".repeat(40),
                    },
                },
            ],
        }
        .normalize()
        .unwrap()
    }

    fn edge_semantics(
        request: &NormalizedCargoPlannerRequest,
        envelope: &VerifiedCargoUnitGraphEnvelope,
    ) -> CargoPlannerEdgeSemantics {
        CargoPlannerEdgeSemantics {
            schema: 1,
            planner_request_digest: request.digest().into(),
            unit_graph_envelope_digest: envelope.digest().into(),
            edges: vec![
                CargoPlannerEdgeSemantic {
                    dependent_index: 0,
                    dependency_index: 1,
                    extern_crate_name: "build_script_build".into(),
                    dependency_kind: CargoDependencyKind::Build,
                    target_evaluation_domain: CargoTargetEvaluationDomain::BuildHost,
                },
                CargoPlannerEdgeSemantic {
                    dependent_index: 0,
                    dependency_index: 3,
                    extern_crate_name: "macro_helper".into(),
                    dependency_kind: CargoDependencyKind::Normal,
                    target_evaluation_domain: CargoTargetEvaluationDomain::BuildHost,
                },
                CargoPlannerEdgeSemantic {
                    dependent_index: 1,
                    dependency_index: 2,
                    extern_crate_name: "build_helper".into(),
                    dependency_kind: CargoDependencyKind::Build,
                    target_evaluation_domain: CargoTargetEvaluationDomain::BuildHost,
                },
                CargoPlannerEdgeSemantic {
                    dependent_index: 0,
                    dependency_index: 4,
                    extern_crate_name: "git_helper".into(),
                    dependency_kind: CargoDependencyKind::Normal,
                    target_evaluation_domain: CargoTargetEvaluationDomain::Target,
                },
            ],
        }
    }

    #[test]
    fn requests_bind_exact_roots_selector_policy_toolchain_and_invocation() {
        let policy = policy();
        let closure = closure(&policy);
        let final_request = CargoPlannerRequest {
            schema: 1,
            root: CargoPlannerGraphRoot::FinalHost,
        }
        .normalize(&policy, &closure)
        .unwrap();
        assert_eq!(
            final_request.manifest_logical_path(),
            "/rust-agent/closure/host/Cargo.toml"
        );
        assert_eq!(
            final_request.artifact_selector(),
            &context().artifact_selector
        );
        assert_eq!(
            final_request.host_build_input_closure_digest(),
            closure.digest()
        );
        assert_eq!(
            final_request.planner(),
            &CargoUnitGraphPlannerIdentity {
                interface: "cargo-unit-graph-v1".into(),
                cargo_version: "1.97.1".into(),
                cargo_digest: digest('3'),
                rustc_version: "1.97.1".into(),
                rustc_digest: digest('4'),
            }
        );
        assert_eq!(
            final_request.invocation().arguments,
            vec![
                "build",
                "--manifest-path",
                "/rust-agent/closure/host/Cargo.toml",
                "--config",
                "/rust-agent/closure/host/.cargo/config.toml",
                "--locked",
                "--offline",
                "--target",
                "aarch64-unknown-linux-gnu",
                "--profile",
                "release",
                "--package",
                "host-fixture",
                "--bin",
                "host-app",
                "--unit-graph",
                "-Z",
                "unstable-options",
            ]
        );
        assert_eq!(
            final_request.digest(),
            "906547b86302af2a8319aa95029d7343be0154e211cdd15e5d3a14d7db16219a"
        );

        let standalone = CargoPlannerRequest {
            schema: 1,
            root: CargoPlannerGraphRoot::EmittedStandalone,
        }
        .normalize(&policy, &closure)
        .unwrap();
        assert_eq!(
            standalone.manifest_logical_path(),
            "/rust-agent/closure/trees/generated-agent/Cargo.toml"
        );
        assert_eq!(
            standalone.artifact_selector(),
            &BuildArtifactSelector {
                package: "rust-agent-composition-fixture".into(),
                target: BuildArtifactTarget::Library,
            }
        );
        assert_ne!(standalone.digest(), final_request.digest());
    }

    #[test]
    fn unit_graph_v1_envelope_is_closed_context_checked_and_mutation_detecting() {
        let policy = policy();
        let request = CargoPlannerRequest {
            schema: 1,
            root: CargoPlannerGraphRoot::FinalHost,
        }
        .normalize(&policy, &closure(&policy))
        .unwrap();
        let raw = raw_graph();
        let encoded = serde_json::to_vec(&raw).unwrap();
        let verified = request.verify_output(0, &encoded, b"").unwrap();
        assert_eq!(verified.version(), 1);
        assert_eq!(verified.unit_count(), 1);
        assert_eq!(verified.edge_count(), 0);
        assert_eq!(verified.root_count(), 1);
        assert_eq!(
            verified.digest(),
            "7dd5674051aa7f731a53a406dee159af35122769398253e64e870faab13317cc"
        );

        assert!(matches!(
            CargoPlannerRequest {
                schema: 2,
                root: CargoPlannerGraphRoot::FinalHost,
            }
            .normalize(&policy, &closure(&policy)),
            Err(CargoPlannerError::UnsupportedRequestSchema(2))
        ));
        let mut rotated = policy.policy().clone();
        rotated.attestation.allowed_executors = vec!["rotated-executor-v1".into()];
        let rotated = rotated.normalize().unwrap();
        assert!(matches!(
            CargoPlannerRequest {
                schema: 1,
                root: CargoPlannerGraphRoot::FinalHost,
            }
            .normalize(&rotated, &closure(&policy)),
            Err(CargoPlannerError::PolicyMismatch)
        ));

        let mut unknown = raw.clone();
        unknown["units"][0]["ambient"] = json!(true);
        assert!(matches!(
            request.verify_output(0, &serde_json::to_vec(&unknown).unwrap(), b""),
            Err(CargoPlannerError::Json(_))
        ));

        let mut wrong_schema = raw.clone();
        wrong_schema["version"] = json!(2);
        assert!(matches!(
            request.verify_output(0, &serde_json::to_vec(&wrong_schema).unwrap(), b""),
            Err(CargoPlannerError::UnsupportedUnitGraphSchema(2))
        ));

        let mut wrong_target = raw.clone();
        wrong_target["units"][0]["platform"] = serde_json::Value::Null;
        assert!(matches!(
            request.verify_output(0, &serde_json::to_vec(&wrong_target).unwrap(), b""),
            Err(CargoPlannerError::PlannerContextMismatch)
        ));

        let mut unsorted_features = raw.clone();
        unsorted_features["units"][0]["features"] = json!(["std", "alloc"]);
        assert!(matches!(
            request.verify_output(0, &serde_json::to_vec(&unsorted_features).unwrap(), b""),
            Err(CargoPlannerError::PlannerContextMismatch)
        ));

        let mut cycle = raw;
        cycle["units"][0]["dependencies"] = json!([{
            "index": 0,
            "extern_crate_name": "host_fixture",
            "public": false,
            "noprelude": false,
            "nounused": false
        }]);
        assert!(matches!(
            request.verify_output(0, &serde_json::to_vec(&cycle).unwrap(), b""),
            Err(CargoPlannerError::InvalidUnitGraph("dependency cycle"))
        ));
        assert!(matches!(
            request.verify_output(0, b"", b""),
            Err(CargoPlannerError::InvalidUnitGraph("encoded size"))
        ));
        assert!(matches!(
            request.verify_output(0, &encoded, b"warning"),
            Err(CargoPlannerError::UnexpectedStderr)
        ));
        assert!(matches!(
            request.verify_output(7, b"", b"other failure"),
            Err(CargoPlannerError::PlannerFailed(7))
        ));

        let mut exact_optional_fields = raw_graph();
        exact_optional_fields["units"][0]["target"]["required-features"] = json!(["host_feature"]);
        exact_optional_fields["units"][0]["profile"]["rustflags"] =
            json!(["-Ctarget-feature=+crt-static"]);
        exact_optional_fields["units"][0]["profile"]["trim_paths"] = json!(["object"]);
        exact_optional_fields["units"][0]["profile"]["hint_mostly_unused"] = json!(true);
        let dependency = exact_optional_fields["units"][0].clone();
        exact_optional_fields["units"]
            .as_array_mut()
            .unwrap()
            .push(dependency);
        exact_optional_fields["units"][0]["dependencies"] = json!([{
            "index": 1,
            "extern_crate_name": "host_fixture",
            "public": true,
            "noprelude": true,
            "nounused": true
        }]);
        request
            .verify_output(0, &serde_json::to_vec(&exact_optional_fields).unwrap(), b"")
            .unwrap();

        exact_optional_fields["units"][0]["profile"]["trim_paths"] = json!(["ambient"]);
        assert!(matches!(
            request.verify_output(0, &serde_json::to_vec(&exact_optional_fields).unwrap(), b""),
            Err(CargoPlannerError::PlannerContextMismatch)
        ));

        let mut wrong_panic = raw_graph();
        wrong_panic["units"][0]["profile"]["panic"] = json!("abort");
        assert!(matches!(
            request.verify_output(0, &serde_json::to_vec(&wrong_panic).unwrap(), b""),
            Err(CargoPlannerError::PlannerContextMismatch)
        ));
    }

    #[test]
    fn raw_cross_compile_graph_normalizes_exact_host_target_units_and_edges() {
        let policy = policy();
        let host_closure = closure(&policy);
        let request = CargoPlannerRequest {
            schema: 1,
            root: CargoPlannerGraphRoot::FinalHost,
        }
        .normalize(&policy, &host_closure)
        .unwrap();
        let raw = raw_cross_compile_graph();
        let envelope = request
            .verify_output(0, &serde_json::to_vec(&raw).unwrap(), b"")
            .unwrap();
        let semantics = edge_semantics(&request, &envelope);
        let normalized = normalize_cargo_unit_graph(
            &request,
            &envelope,
            &host_closure,
            &locked_sources(),
            &semantics,
        )
        .unwrap();

        assert_eq!(normalized.nodes().len(), 5);
        assert_eq!(normalized.edges().len(), 4);
        assert_eq!(
            normalized
                .nodes()
                .values()
                .filter(|unit| {
                    unit.selector.compilation_kind == CargoCompilationKind::BuildHost
                })
                .count(),
            3
        );
        assert_eq!(
            normalized
                .nodes()
                .values()
                .filter(|unit| unit.selector.compilation_kind == CargoCompilationKind::Target)
                .count(),
            2
        );
        assert!(normalized.nodes().values().any(|unit| unit.build_script));
        assert!(normalized.nodes().values().any(|unit| unit.proc_macro));
        assert!(normalized.nodes().values().any(|unit| {
            matches!(
                &unit.selector.package.source,
                CargoPackageSource::Git { precise, .. } if precise == &"1".repeat(40)
            )
        }));
        assert_eq!(
            normalized.digest(),
            "34cc19f1c54a3c593c7a6609d09c048b2236a088f74e55880f8caee9fc5379f2"
        );

        let mut reordered = semantics;
        reordered.edges.reverse();
        assert_eq!(
            normalize_cargo_unit_graph(
                &request,
                &envelope,
                &host_closure,
                &locked_sources(),
                &reordered,
            )
            .unwrap(),
            normalized
        );

        for (target, kind, name) in [
            (
                BuildArtifactTarget::Test {
                    name: "integration-case".into(),
                },
                "test",
                "integration-case",
            ),
            (
                BuildArtifactTarget::Bench {
                    name: "throughput".into(),
                },
                "bench",
                "throughput",
            ),
        ] {
            let selected_closure = closure_with_artifact(&policy, target);
            let selected_request = CargoPlannerRequest {
                schema: 1,
                root: CargoPlannerGraphRoot::FinalHost,
            }
            .normalize(&policy, &selected_closure)
            .unwrap();
            let flag = format!("--{kind}");
            assert!(
                selected_request
                    .invocation()
                    .arguments
                    .windows(2)
                    .any(|arguments| arguments == [flag.as_str(), name])
            );
            let mut selected_raw = raw_cross_compile_graph();
            selected_raw["units"][0]["target"]["kind"] = json!([kind]);
            selected_raw["units"][0]["target"]["name"] = json!(name);
            selected_raw["units"][0]["mode"] = json!("test");
            let selected_envelope = selected_request
                .verify_output(0, &serde_json::to_vec(&selected_raw).unwrap(), b"")
                .unwrap();
            let selected_semantics = edge_semantics(&selected_request, &selected_envelope);
            normalize_cargo_unit_graph(
                &selected_request,
                &selected_envelope,
                &selected_closure,
                &locked_sources(),
                &selected_semantics,
            )
            .unwrap();
        }
    }

    #[test]
    fn raw_graph_normalization_rejects_identity_edge_and_root_drift() {
        let policy = policy();
        let host_closure = closure(&policy);
        let request = CargoPlannerRequest {
            schema: 1,
            root: CargoPlannerGraphRoot::FinalHost,
        }
        .normalize(&policy, &host_closure)
        .unwrap();
        let raw = raw_cross_compile_graph();
        let envelope = request
            .verify_output(0, &serde_json::to_vec(&raw).unwrap(), b"")
            .unwrap();
        let semantics = edge_semantics(&request, &envelope);
        let sources = locked_sources();

        let standalone = CargoPlannerRequest {
            schema: 1,
            root: CargoPlannerGraphRoot::EmittedStandalone,
        }
        .normalize(&policy, &closure(&policy))
        .unwrap();
        assert!(matches!(
            normalize_cargo_unit_graph(&standalone, &envelope, &host_closure, &sources, &semantics,),
            Err(CargoUnitGraphNormalizationError::PlannerRequestMismatch)
        ));

        let other_host_closure = closure_with_artifact(
            &policy,
            BuildArtifactTarget::Test {
                name: "other-test".into(),
            },
        );
        assert!(matches!(
            normalize_cargo_unit_graph(
                &request,
                &envelope,
                &other_host_closure,
                &sources,
                &semantics,
            ),
            Err(CargoUnitGraphNormalizationError::HostClosureMismatch)
        ));

        let wrong_lock_sources = LockedSourceClosure {
            schema: 1,
            cargo_lock_digest: digest('f'),
            packages: sources.packages().iter().cloned().collect(),
        }
        .normalize()
        .unwrap();
        assert!(matches!(
            normalize_cargo_unit_graph(
                &request,
                &envelope,
                &host_closure,
                &wrong_lock_sources,
                &semantics,
            ),
            Err(CargoUnitGraphNormalizationError::LockedSources(
                LockedSourceError::HostCargoLockMismatch
            ))
        ));

        let mut unsupported = semantics.clone();
        unsupported.schema = 2;
        assert!(matches!(
            normalize_cargo_unit_graph(&request, &envelope, &host_closure, &sources, &unsupported,),
            Err(CargoUnitGraphNormalizationError::UnsupportedEdgeSemanticsSchema(2))
        ));
        let mut wrong_identity = semantics.clone();
        wrong_identity.unit_graph_envelope_digest = digest('f');
        assert!(matches!(
            normalize_cargo_unit_graph(
                &request,
                &envelope,
                &host_closure,
                &sources,
                &wrong_identity,
            ),
            Err(CargoUnitGraphNormalizationError::EdgeSemanticsIdentityMismatch)
        ));
        let mut missing = semantics.clone();
        missing.edges.pop();
        assert!(matches!(
            normalize_cargo_unit_graph(&request, &envelope, &host_closure, &sources, &missing,),
            Err(CargoUnitGraphNormalizationError::EdgeSemanticsMismatch)
        ));
        let mut unknown = semantics.clone();
        unknown.edges[0].extern_crate_name = "unknown_edge".into();
        assert!(matches!(
            normalize_cargo_unit_graph(&request, &envelope, &host_closure, &sources, &unknown,),
            Err(CargoUnitGraphNormalizationError::EdgeSemanticsMismatch)
        ));
        let mut wrong_domain = semantics.clone();
        wrong_domain.edges[0].target_evaluation_domain = CargoTargetEvaluationDomain::Target;
        assert!(matches!(
            normalize_cargo_unit_graph(&request, &envelope, &host_closure, &sources, &wrong_domain,),
            Err(CargoUnitGraphNormalizationError::HostGraph(
                CargoUnitGraphError::EdgeDomainMismatch(_)
            ))
        ));

        let mut source_drift = raw.clone();
        source_drift["units"][2]["pkg_id"] =
            json!("registry+https://registry.invalid/index#build-helper@1.0.0");
        let source_drift = request
            .verify_output(0, &serde_json::to_vec(&source_drift).unwrap(), b"")
            .unwrap();
        let source_semantics = edge_semantics(&request, &source_drift);
        assert!(matches!(
            normalize_cargo_unit_graph(
                &request,
                &source_drift,
                &host_closure,
                &sources,
                &source_semantics,
            ),
            Err(CargoUnitGraphNormalizationError::PackageIdentityMismatch(_))
        ));

        let mut escaped_path = raw.clone();
        escaped_path["units"][0]["pkg_id"] =
            json!("path+file:///rust-agent/closure/trees/%2e%2e/host-fixture#host-fixture@0.1.0");
        let escaped_path = request
            .verify_output(0, &serde_json::to_vec(&escaped_path).unwrap(), b"")
            .unwrap();
        let escaped_semantics = edge_semantics(&request, &escaped_path);
        assert!(matches!(
            normalize_cargo_unit_graph(
                &request,
                &escaped_path,
                &host_closure,
                &sources,
                &escaped_semantics,
            ),
            Err(CargoUnitGraphNormalizationError::PackageIdentityMismatch(_))
        ));

        let mut proc_macro_target_drift = raw.clone();
        proc_macro_target_drift["units"][3]["platform"] = json!("aarch64-unknown-linux-gnu");
        let proc_macro_target_drift = request
            .verify_output(
                0,
                &serde_json::to_vec(&proc_macro_target_drift).unwrap(),
                b"",
            )
            .unwrap();
        let proc_macro_semantics = edge_semantics(&request, &proc_macro_target_drift);
        assert!(matches!(
            normalize_cargo_unit_graph(
                &request,
                &proc_macro_target_drift,
                &host_closure,
                &sources,
                &proc_macro_semantics,
            ),
            Err(CargoUnitGraphNormalizationError::RawUnitDomainMismatch(_))
        ));

        let mut root_drift = raw.clone();
        root_drift["units"][0]["target"]["name"] = json!("other-app");
        let root_drift = request
            .verify_output(0, &serde_json::to_vec(&root_drift).unwrap(), b"")
            .unwrap();
        let root_semantics = edge_semantics(&request, &root_drift);
        assert!(matches!(
            normalize_cargo_unit_graph(
                &request,
                &root_drift,
                &host_closure,
                &sources,
                &root_semantics,
            ),
            Err(CargoUnitGraphNormalizationError::RootArtifactMismatch)
        ));

        let mut unknown_kind = raw;
        unknown_kind["units"][2]["target"]["kind"] = json!(["plugin"]);
        unknown_kind["units"][2]["target"]["crate_types"] = json!(["plugin"]);
        let unknown_kind = request
            .verify_output(0, &serde_json::to_vec(&unknown_kind).unwrap(), b"")
            .unwrap();
        let kind_semantics = edge_semantics(&request, &unknown_kind);
        assert!(matches!(
            normalize_cargo_unit_graph(
                &request,
                &unknown_kind,
                &host_closure,
                &sources,
                &kind_semantics,
            ),
            Err(CargoUnitGraphNormalizationError::UnsupportedTargetKind(_))
        ));

        let unknown_json =
            serde_json::to_string(&semantics)
                .unwrap()
                .replacen('{', "{\"ambient\":true,", 1);
        assert!(CargoPlannerEdgeSemantics::from_json(&unknown_json).is_err());
    }

    #[test]
    fn stable_cargo_is_explicitly_unsupported_and_never_executes_build_script() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname='planner-probe'\nversion='0.1.0'\nedition='2024'\nbuild='build.rs'\n",
        )
        .unwrap();
        fs::write(temp.path().join("src/lib.rs"), "pub fn probe() {}\n").unwrap();
        fs::write(
            temp.path().join("build.rs"),
            "fn main() { std::fs::write(\"build-script-ran\", b\"bad\").unwrap(); }\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Cargo.lock"),
            "# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n[[package]]\nname = \"planner-probe\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let output = Command::new(cargo)
            .current_dir(temp.path())
            .args(["build", "--unit-graph", "--locked", "--offline"])
            .output()
            .unwrap();
        assert!(!output.status.success());

        let policy = policy();
        let request = CargoPlannerRequest {
            schema: 1,
            root: CargoPlannerGraphRoot::FinalHost,
        }
        .normalize(&policy, &closure(&policy))
        .unwrap();
        assert!(matches!(
            request.verify_output(
                output.status.code().unwrap(),
                &output.stdout,
                &output.stderr
            ),
            Err(CargoPlannerError::TrustedUnitGraphUnavailable)
        ));
        assert!(!temp.path().join("build-script-ran").exists());
    }
}
