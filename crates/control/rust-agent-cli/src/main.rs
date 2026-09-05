use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, BufRead as _, Read as _, Write as _},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use rust_agent_build_executor::{
    BuildExecutionPolicy, DevelopmentBuildOptions, development_build, emit_integration,
    inspect_development_build, verify_integration,
};
#[cfg(target_os = "linux")]
use rust_agent_build_executor::{
    CargoFetchCacheLayout, CargoFetchMode, CargoFetchRequest, CargoPlannerGraphRoot,
    CargoPlannerRequest, CargoUnitSelector, HostBuildClosureItemRole, HostBuildInputClosure,
    HostClosureSnapshotSource, HostFeatureUnionPolicy, HostFeatureUnitObservation,
    LinuxSandboxBackendIdentity, LockedSourceClosure, NormalizedHostBuildInputClosure,
    ProductBuildContribution, ProductionBuildExecutionPolicy, ProductionBuildPipelineOptions,
    ProductionCompletionHandle, ProductionHostBuildPipelineOptions, ProductionIntegrationPostInput,
    ProductionIntegrationPrePipelineOptions, VerifiedHostClosureSnapshot,
    VerifiedLinuxSandboxBackend, create_production_integration_post_payload,
    execute_trusted_production_build, execute_trusted_production_host_build,
    execute_trusted_production_integration_pre, materialize_host_closure_snapshot,
    open_verified_host_closure_snapshot, preflight_production_build_inputs,
    preflight_production_fetch_inputs, read_production_integration_pre_receipt,
    reverify_trusted_production_integration_pre, verify_production_build_attestation,
    write_production_integration_post_attestation,
};
use rust_agent_composition::{ComposeOptions, compose, verify_composition};
use serde::Serialize;

#[derive(Debug, Parser)]
#[command(
    name = "rust-agent",
    version,
    about = "Compile-time rust-agent composition control plane"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Resolve metadata and emit a deterministic standalone Cargo composition.
    Compose {
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        profile: PathBuf,
        /// Schema-owned allowlist for App coexistence evidence reviewers and rule sets.
        #[arg(long)]
        catalog_trust_policy: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        rustc: PathBuf,
        #[arg(long)]
        cargo: PathBuf,
        #[arg(long)]
        registry_cache: Option<PathBuf>,
        /// Optional custom rustc target JSON, snapshotted before target discovery.
        #[arg(long)]
        custom_target_spec: Option<PathBuf>,
    },
    /// Build a verified composition through the Phase 1A development runner.
    Build(BuildArgs),
    /// Build an independently verified library Host through the Phase 1B production runner.
    BuildHost(HostBuildArgs),
    /// Inspect and re-verify a composition or built artifact.
    Inspect(InspectArgs),
    /// Emit a verified immutable library integration tree.
    EmitIntegration {
        #[arg(long)]
        composition: PathBuf,
        #[arg(long)]
        destination: PathBuf,
    },
    /// Verify an emitted integration tree and its development/production tier.
    VerifyIntegration(VerifyIntegrationArgs),
}

#[derive(Debug, Args)]
struct BuildArgs {
    #[arg(long)]
    composition: PathBuf,
    #[arg(long)]
    artifact_dir: Option<PathBuf>,
    #[arg(long)]
    rustc: Option<PathBuf>,
    #[arg(long)]
    cargo: Option<PathBuf>,
    #[arg(long)]
    linker: Option<PathBuf>,
    #[arg(long)]
    registry_cache: Option<PathBuf>,
    #[arg(long)]
    policy: Option<PathBuf>,
    #[arg(long, conflicts_with = "execution_policy")]
    development_build: bool,
    #[arg(long, default_value_t = true)]
    run_generated_tests: bool,
    #[arg(long)]
    locked: bool,
    #[arg(long, conflicts_with = "development_build")]
    execution_policy: Option<PathBuf>,
    #[arg(long)]
    sandbox_backend: Option<PathBuf>,
    #[arg(long)]
    host_closure: Option<PathBuf>,
    #[arg(long)]
    closure_snapshot: Option<PathBuf>,
    #[arg(long)]
    closure_sources: Option<PathBuf>,
    #[arg(long)]
    host_trust_root: Option<PathBuf>,
    #[arg(long)]
    locked_sources: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = CliFetchMode::Preprovisioned)]
    fetch_mode: CliFetchMode,
    #[arg(long)]
    fetch_staging: Option<PathBuf>,
    #[arg(long)]
    fetch_cache_output: Option<PathBuf>,
    #[arg(long)]
    fetch_cache_layout: Option<PathBuf>,
    #[arg(long)]
    target_root: Option<PathBuf>,
    #[arg(long)]
    temp_root: Option<PathBuf>,
    #[arg(long)]
    wasm_bundle_root: Option<PathBuf>,
    #[arg(long)]
    artifact_parent: Option<PathBuf>,
    #[arg(long)]
    attestation_root: Option<PathBuf>,
    #[arg(long)]
    completion_nonce_directory: Option<PathBuf>,
    #[arg(long)]
    executor_id: Option<String>,
    #[arg(long)]
    workload_identity: Option<String>,
    #[arg(long)]
    verifier_identity_digest: Option<String>,
    #[arg(long)]
    timestamp: Option<String>,
    #[arg(long)]
    transparency_proof: Option<String>,
}

#[derive(Debug, Args)]
struct InspectArgs {
    #[arg(long)]
    composition: Option<PathBuf>,
    #[arg(long)]
    artifact_dir: Option<PathBuf>,
    #[arg(long)]
    allow_development: bool,
    /// Production policy used to revalidate the append-only signed attestation.
    #[arg(long, requires_all = ["attestation", "workload_identity"])]
    execution_policy: Option<PathBuf>,
    /// Exact append-only production attestation to verify.
    #[arg(long, requires_all = ["execution_policy", "workload_identity"])]
    attestation: Option<PathBuf>,
    /// Expected workload identity carried by the production attestation.
    #[arg(long, requires_all = ["execution_policy", "attestation"])]
    workload_identity: Option<String>,
}

#[derive(Debug, Args)]
struct HostBuildArgs {
    #[arg(long)]
    host_manifest: PathBuf,
    #[arg(long)]
    dependency: String,
    #[arg(long)]
    composition: String,
    #[arg(long)]
    composition_artifact_dir: PathBuf,
    #[arg(long)]
    composition_attestation: PathBuf,
    #[arg(long)]
    composition_workload_identity: String,
    #[arg(long)]
    pre_receipt: PathBuf,
    #[arg(long, required = true)]
    locked: bool,
    #[arg(long)]
    execution_policy: PathBuf,
    #[arg(long)]
    sandbox_backend: PathBuf,
    #[arg(long)]
    host_closure: PathBuf,
    #[arg(long)]
    closure_snapshot: PathBuf,
    #[arg(long)]
    closure_sources: PathBuf,
    #[arg(long)]
    host_trust_root: PathBuf,
    #[arg(long)]
    locked_sources: PathBuf,
    #[arg(long, value_enum, default_value_t = CliFetchMode::Preprovisioned)]
    fetch_mode: CliFetchMode,
    #[arg(long)]
    fetch_staging: PathBuf,
    #[arg(long)]
    fetch_cache_output: PathBuf,
    #[arg(long)]
    fetch_cache_layout: PathBuf,
    #[arg(long)]
    host_feature_policy: Option<PathBuf>,
    #[arg(long)]
    host_feature_inputs: PathBuf,
    #[arg(long)]
    target_root: PathBuf,
    #[arg(long)]
    temp_root: PathBuf,
    #[arg(long)]
    artifact_parent: PathBuf,
    #[arg(long)]
    attestation_root: PathBuf,
    #[arg(long)]
    completion_nonce_directory: PathBuf,
    #[arg(long)]
    executor_id: String,
    #[arg(long)]
    workload_identity: String,
    #[arg(long)]
    verifier_identity_digest: String,
    #[arg(long)]
    timestamp: String,
    #[arg(long)]
    transparency_proof: Option<String>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostFeatureExecutionInputs {
    #[serde(rename = "first-party-units")]
    first_party_units: BTreeSet<CargoUnitSelector>,
    observations: Vec<HostFeatureObservationInput>,
    #[serde(rename = "host-root-runtime-effects")]
    host_root_runtime_effects: BTreeSet<String>,
    #[serde(rename = "product-build-contributions")]
    product_build_contributions: Vec<ProductBuildContribution>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostFeatureObservationInput {
    unit: CargoUnitSelector,
    observation: HostFeatureUnitObservation,
}

#[cfg(target_os = "linux")]
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostClosureSourceMap {
    schema: u32,
    sources: Vec<HostClosureSourceInput>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostClosureSourceInput {
    #[serde(rename = "item-id")]
    item_id: String,
    path: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum CliFetchMode {
    Preprovisioned,
    Networked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum IntegrationPhase {
    Pre,
    Post,
}

#[derive(Debug, Args)]
struct VerifyIntegrationArgs {
    #[arg(long)]
    integration: Option<PathBuf>,
    #[arg(long)]
    allow_development: bool,
    #[arg(long, value_enum)]
    phase: Option<IntegrationPhase>,
    #[arg(long)]
    host_manifest: Option<PathBuf>,
    #[arg(long)]
    dependency: Option<String>,
    #[arg(long)]
    composition: Option<String>,
    #[arg(long)]
    composition_artifact_dir: Option<PathBuf>,
    #[arg(long)]
    composition_attestation: Option<PathBuf>,
    #[arg(long)]
    composition_workload_identity: Option<String>,
    #[arg(long)]
    execution_policy: Option<PathBuf>,
    #[arg(long)]
    sandbox_backend: Option<PathBuf>,
    #[arg(long)]
    host_closure: Option<PathBuf>,
    #[arg(long)]
    closure_snapshot: Option<PathBuf>,
    #[arg(long)]
    closure_sources: Option<PathBuf>,
    #[arg(long)]
    host_trust_root: Option<PathBuf>,
    #[arg(long)]
    locked_sources: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = CliFetchMode::Preprovisioned)]
    fetch_mode: CliFetchMode,
    #[arg(long)]
    fetch_staging: Option<PathBuf>,
    #[arg(long)]
    fetch_cache_output: Option<PathBuf>,
    #[arg(long)]
    fetch_cache_layout: Option<PathBuf>,
    #[arg(long)]
    host_feature_policy: Option<PathBuf>,
    #[arg(long)]
    host_feature_inputs: Option<PathBuf>,
    #[arg(long)]
    write_receipt: Option<PathBuf>,
    #[arg(long)]
    pre_receipt: Option<PathBuf>,
    #[arg(long)]
    executor_artifact_dir: Option<PathBuf>,
    #[arg(long)]
    executor_attestation: Option<PathBuf>,
    #[arg(long)]
    executor_workload_identity: Option<String>,
    #[arg(long)]
    write_attestation: Option<PathBuf>,
    #[arg(long)]
    completion_nonce_directory: Option<PathBuf>,
    #[arg(long)]
    executor_id: Option<String>,
    #[arg(long)]
    workload_identity: Option<String>,
    #[arg(long)]
    verifier_identity_digest: Option<String>,
    #[arg(long)]
    timestamp: Option<String>,
    #[arg(long)]
    transparency_proof: Option<String>,
}

#[derive(Serialize)]
struct CommandOutput<'a, T> {
    status: &'static str,
    value: &'a T,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Compose {
            workspace,
            profile,
            catalog_trust_policy,
            output,
            rustc,
            cargo,
            registry_cache,
            custom_target_spec,
        } => {
            let workspace = canonical_existing(&workspace)?;
            let generated = compose(&ComposeOptions {
                // Preserve each input path component so the compiler can reject
                // symlink provenance instead of receiving an already-resolved
                // path. The canonical workspace above remains the trust root.
                profile_path: absolute_output(&profile)?,
                catalog_trust_policy_path: absolute_output(&catalog_trust_policy)?,
                output_root: absolute_output(&output)?,
                rustc_path: canonical_existing(&rustc)?,
                cargo_path: canonical_existing(&cargo)?,
                registry_cache_path: registry_cache
                    .as_deref()
                    .map(canonical_existing)
                    .transpose()?,
                custom_target_spec_path: custom_target_spec
                    .as_deref()
                    // Preserve every input path component so the composition
                    // compiler can reject symlinked specs instead of receiving
                    // an already-resolved path with that provenance erased.
                    .map(absolute_output)
                    .transpose()?,
                workspace_root: workspace,
            })?;
            print_json(&CommandOutput {
                status: "composed",
                value: &generated.composition_hash,
            })?;
        }
        Command::Build(args) => run_build(args)?,
        Command::BuildHost(args) => run_host_build(args)?,
        Command::Inspect(args) => run_inspect(args)?,
        Command::EmitIntegration {
            composition,
            destination,
        } => {
            let manifest = emit_integration(
                &absolute_output(&composition)?,
                &absolute_output(&destination)?,
            )?;
            print_json(&CommandOutput {
                status: "emitted-integration",
                value: &manifest.composition_hash,
            })?;
        }
        Command::VerifyIntegration(args) => run_verify_integration(args)?,
    }
    Ok(())
}

fn run_inspect(args: InspectArgs) -> Result<()> {
    match (args.composition, args.artifact_dir) {
        (Some(path), None) => {
            if args.execution_policy.is_some()
                || args.attestation.is_some()
                || args.workload_identity.is_some()
            {
                bail!("production attestation options require --artifact-dir");
            }
            let manifest = verify_composition(&absolute_output(&path)?)?;
            if !args.allow_development && !manifest.deployable {
                bail!(
                    "development composition rejected by production inspection; pass --allow-development"
                );
            }
            print_json(&CommandOutput {
                status: "verified-composition",
                value: &manifest,
            })
        }
        (None, Some(path)) if args.execution_policy.is_some() => {
            if args.allow_development {
                bail!("production artifact inspection cannot use --allow-development");
            }
            let execution_policy = required(args.execution_policy, "--execution-policy")?;
            let attestation = required(args.attestation, "--attestation")?;
            let workload_identity = required(args.workload_identity, "--workload-identity")?;
            run_production_inspect(&path, &execution_policy, &attestation, &workload_identity)
        }
        (None, Some(path)) => {
            let manifest =
                inspect_development_build(&canonical_existing(&path)?, args.allow_development)?;
            print_json(&CommandOutput {
                status: "verified-build",
                value: &manifest,
            })
        }
        _ => bail!("exactly one of --composition or --artifact-dir is required"),
    }
}

#[cfg(not(target_os = "linux"))]
fn run_production_inspect(
    _artifact_dir: &Path,
    _execution_policy: &Path,
    _attestation: &Path,
    _workload_identity: &str,
) -> Result<()> {
    bail!("production artifact inspection is supported only on Linux")
}

#[cfg(target_os = "linux")]
fn run_production_inspect(
    artifact_dir: &Path,
    execution_policy: &Path,
    attestation: &Path,
    workload_identity: &str,
) -> Result<()> {
    let policy = load_production_policy(execution_policy)?;
    let artifact_dir = canonical_existing(artifact_dir)?;
    let attestation = canonical_existing(attestation)?;
    let verified = verify_production_build_attestation(
        &artifact_dir,
        &attestation,
        &policy,
        workload_identity,
    )?;
    print_json(&CommandOutput {
        status: "verified-production-build",
        value: verified.manifest(),
    })
}

fn run_build(args: BuildArgs) -> Result<()> {
    if args.development_build {
        return run_development_build(args);
    }
    if !args.locked {
        bail!("production build requires --locked");
    }
    run_production_build(args)
}

fn run_development_build(args: BuildArgs) -> Result<()> {
    if args.locked || args.execution_policy.is_some() {
        bail!("--development-build cannot use production --locked/--execution-policy options");
    }
    let policy = if let Some(path) = args.policy {
        let input = fs::read_to_string(canonical_existing(&path)?)?;
        BuildExecutionPolicy::from_toml(&input).context("invalid build policy TOML")?
    } else {
        BuildExecutionPolicy::empty_development()
    };
    let artifact_dir = required(args.artifact_dir, "--artifact-dir")?;
    let cargo = required(args.cargo, "--cargo")?;
    let rustc = required(args.rustc, "--rustc")?;
    let linker = required(args.linker, "--linker")?;
    let manifest = development_build(&DevelopmentBuildOptions {
        composition_path: absolute_output(&args.composition)?,
        artifact_dir: absolute_output(&artifact_dir)?,
        cargo_path: canonical_existing(&cargo)?,
        rustc_path: canonical_existing(&rustc)?,
        linker_path: canonical_existing(&linker)?,
        registry_cache_path: args
            .registry_cache
            .as_deref()
            .map(canonical_existing)
            .transpose()?,
        policy,
        run_generated_tests: args.run_generated_tests,
    })?;
    print_json(&CommandOutput {
        status: "built-development",
        value: &manifest,
    })
}

#[cfg(not(target_os = "linux"))]
fn run_production_build(_args: BuildArgs) -> Result<()> {
    bail!("the Phase 1B production build runner is supported only on Linux")
}

#[cfg(target_os = "linux")]
fn run_production_build(args: BuildArgs) -> Result<()> {
    if args.policy.is_some()
        || args.artifact_dir.is_some()
        || args.rustc.is_some()
        || args.cargo.is_some()
        || args.linker.is_some()
        || args.registry_cache.is_some()
    {
        bail!("development-only build options cannot be used for a production build");
    }
    require_options(&[
        (args.execution_policy.is_some(), "--execution-policy"),
        (args.sandbox_backend.is_some(), "--sandbox-backend"),
        (args.host_closure.is_some(), "--host-closure"),
        (args.closure_snapshot.is_some(), "--closure-snapshot"),
        (args.closure_sources.is_some(), "--closure-sources"),
        (args.host_trust_root.is_some(), "--host-trust-root"),
        (args.locked_sources.is_some(), "--locked-sources"),
        (args.fetch_staging.is_some(), "--fetch-staging"),
        (args.fetch_cache_output.is_some(), "--fetch-cache-output"),
        (args.fetch_cache_layout.is_some(), "--fetch-cache-layout"),
        (args.target_root.is_some(), "--target-root"),
        (args.temp_root.is_some(), "--temp-root"),
        (args.artifact_parent.is_some(), "--artifact-parent"),
        (args.attestation_root.is_some(), "--attestation-root"),
        (
            args.completion_nonce_directory.is_some(),
            "--completion-nonce-directory",
        ),
        (args.executor_id.is_some(), "--executor-id"),
        (args.workload_identity.is_some(), "--workload-identity"),
        (
            args.verifier_identity_digest.is_some(),
            "--verifier-identity-digest",
        ),
        (args.timestamp.is_some(), "--timestamp"),
    ])?;
    let composition_path = canonical_existing(&args.composition)?;
    let composition = verify_composition(&composition_path)?;
    let policy_path = required(args.execution_policy, "--execution-policy")?;
    let policy = ProductionBuildExecutionPolicy::from_toml(&fs::read_to_string(
        canonical_existing(&policy_path)?,
    )?)?
    .normalize()?;
    let backend_path = required(args.sandbox_backend, "--sandbox-backend")?;
    let backend_identity: LinuxSandboxBackendIdentity =
        serde_json::from_slice(&fs::read(canonical_existing(&backend_path)?)?)?;
    let backend = VerifiedLinuxSandboxBackend::open(backend_identity)?;
    let closure_path = required(args.host_closure, "--host-closure")?;
    let closure =
        HostBuildInputClosure::from_json(&fs::read_to_string(canonical_existing(&closure_path)?)?)?
            .normalize(&policy)?;
    let snapshot_path = absolute_output(&required(args.closure_snapshot, "--closure-snapshot")?)?;
    let snapshot = materialize_verified_host_snapshot(
        &closure,
        &required(args.closure_sources, "--closure-sources")?,
        &snapshot_path,
        &required(args.host_trust_root, "--host-trust-root")?,
        None,
        &composition_path,
    )?;
    let locked_sources_path = required(args.locked_sources, "--locked-sources")?;
    let locked_sources = LockedSourceClosure::from_json(&fs::read_to_string(canonical_existing(
        &locked_sources_path,
    )?)?)?
    .normalize()?;
    let fetch_mode = match args.fetch_mode {
        CliFetchMode::Preprovisioned => CargoFetchMode::Preprovisioned,
        CliFetchMode::Networked => CargoFetchMode::Networked,
    };
    let fetch_request = CargoFetchRequest {
        schema: 3,
        mode: fetch_mode,
    }
    .normalize(&policy, &closure, &locked_sources)?;
    let fetch_inputs = preflight_production_fetch_inputs(&policy, fetch_mode)?;
    let fetch_layout_path = required(args.fetch_cache_layout, "--fetch-cache-layout")?;
    let fetch_layout: CargoFetchCacheLayout =
        serde_json::from_slice(&fs::read(canonical_existing(&fetch_layout_path)?)?)?;
    let production_inputs = preflight_production_build_inputs(&policy, &closure)?;
    let planner_request = CargoPlannerRequest {
        schema: 2,
        root: CargoPlannerGraphRoot::EmittedStandalone,
    }
    .normalize(&policy, &closure)?;

    let fetch_staging = canonical_existing(&required(args.fetch_staging, "--fetch-staging")?)?;
    let fetch_cache_output =
        absolute_output(&required(args.fetch_cache_output, "--fetch-cache-output")?)?;
    let target_root = canonical_existing(&required(args.target_root, "--target-root")?)?;
    let temp_root = canonical_existing(&required(args.temp_root, "--temp-root")?)?;
    let artifact_parent =
        canonical_existing(&required(args.artifact_parent, "--artifact-parent")?)?;
    let attestation_root =
        canonical_existing(&required(args.attestation_root, "--attestation-root")?)?;
    let completion_nonce_directory = canonical_existing(&required(
        args.completion_nonce_directory,
        "--completion-nonce-directory",
    )?)?;
    let wasm_bundle_root = args
        .wasm_bundle_root
        .as_deref()
        .map(canonical_existing)
        .transpose()?;
    let executor_id = required(args.executor_id, "--executor-id")?;
    let workload_identity = required(args.workload_identity, "--workload-identity")?;
    let verifier_identity_digest =
        required(args.verifier_identity_digest, "--verifier-identity-digest")?;
    let timestamp = required(args.timestamp, "--timestamp")?;
    let mut completion_authority =
        |payload: &rust_agent_build_executor::ProductionBuildAttestationPayload| {
            request_completion_handle(payload)
        };
    let result = execute_trusted_production_build(
        ProductionBuildPipelineOptions {
            composition: &composition,
            cargo_lock: &composition_path.join("Cargo.lock"),
            policy: &policy,
            backend: &backend,
            closure: &closure,
            closure_snapshot: &snapshot,
            locked_sources: &locked_sources,
            fetch_request: &fetch_request,
            fetch_inputs: &fetch_inputs,
            fetch_staging: &fetch_staging,
            fetch_cache_output: &fetch_cache_output,
            fetch_cache_layout: &fetch_layout,
            production_inputs: &production_inputs,
            planner_request: &planner_request,
            target_root: &target_root,
            temp_root: &temp_root,
            wasm_bundle_root: wasm_bundle_root.as_deref(),
            artifact_parent: &artifact_parent,
            attestation_root: &attestation_root,
            completion_nonce_directory: &completion_nonce_directory,
            executor_id,
            workload_identity,
            verifier_identity_digest,
            timestamp,
            transparency_proof: args.transparency_proof,
        },
        &mut completion_authority,
    )?;
    let output = ProductionCommandOutput {
        artifact_directory: &result.publication().path,
        attestation: result.attestation().path(),
        build_output_digest: &result.attestation().manifest().build_output_digest,
    };
    print_json(&CommandOutput {
        status: "built-production",
        value: &output,
    })
}

#[cfg(not(target_os = "linux"))]
fn run_host_build(_args: HostBuildArgs) -> Result<()> {
    bail!("the Phase 1B production Host runner is supported only on Linux")
}

#[cfg(target_os = "linux")]
fn run_host_build(args: HostBuildArgs) -> Result<()> {
    if !args.locked {
        bail!("production build-host requires --locked");
    }
    let host_manifest = canonical_existing(&args.host_manifest)?;
    let host_root = host_manifest
        .parent()
        .context("Host manifest has no parent directory")?;
    let cargo_lock = canonical_existing(&host_root.join("Cargo.lock"))?;
    let policy = ProductionBuildExecutionPolicy::from_toml(&fs::read_to_string(
        canonical_existing(&args.execution_policy)?,
    )?)?
    .normalize()?;
    let composition_artifact_dir = canonical_existing(&args.composition_artifact_dir)?;
    let composition_attestation = canonical_existing(&args.composition_attestation)?;
    let composition_build = verify_production_build_attestation(
        &composition_artifact_dir,
        &composition_attestation,
        &policy,
        &args.composition_workload_identity,
    )?;
    let backend_identity: LinuxSandboxBackendIdentity =
        serde_json::from_slice(&fs::read(canonical_existing(&args.sandbox_backend)?)?)?;
    let backend = VerifiedLinuxSandboxBackend::open(backend_identity)?;
    let closure = HostBuildInputClosure::from_json(&fs::read_to_string(canonical_existing(
        &args.host_closure,
    )?)?)?
    .normalize(&policy)?;
    if closure.composition_hash() != args.composition
        || closure.host_dependency_alias() != args.dependency
    {
        bail!("--composition/--dependency differ from the verified Host closure");
    }
    let snapshot_path = absolute_output(&args.closure_snapshot)?;
    let integration_path = closure_source_path(
        &closure,
        &args.closure_sources,
        HostBuildClosureItemRole::EmittedCompositionTree,
    )?;
    let snapshot = materialize_verified_host_snapshot(
        &closure,
        &args.closure_sources,
        &snapshot_path,
        &args.host_trust_root,
        Some(&host_manifest),
        &integration_path,
    )?;
    verify_host_dependency_alias(
        &host_manifest,
        &args.dependency,
        closure.generated_package_name(),
        &integration_path,
    )?;
    let locked_sources = LockedSourceClosure::from_json(&fs::read_to_string(canonical_existing(
        &args.locked_sources,
    )?)?)?
    .normalize()?;
    let pre_receipt = read_production_integration_pre_receipt(
        &canonical_existing(&args.pre_receipt)?,
        &closure,
        &policy,
        &composition_build,
    )?;
    let fetch_mode = match args.fetch_mode {
        CliFetchMode::Preprovisioned => CargoFetchMode::Preprovisioned,
        CliFetchMode::Networked => CargoFetchMode::Networked,
    };
    let fetch_request = CargoFetchRequest {
        schema: 3,
        mode: fetch_mode,
    }
    .normalize(&policy, &closure, &locked_sources)?;
    let fetch_inputs = preflight_production_fetch_inputs(&policy, fetch_mode)?;
    let fetch_layout: CargoFetchCacheLayout =
        serde_json::from_slice(&fs::read(canonical_existing(&args.fetch_cache_layout)?)?)?;
    let production_inputs = preflight_production_build_inputs(&policy, &closure)?;
    let standalone_planner_request = CargoPlannerRequest {
        schema: 2,
        root: CargoPlannerGraphRoot::EmittedStandalone,
    }
    .normalize(&policy, &closure)?;
    let final_planner_request = CargoPlannerRequest {
        schema: 2,
        root: CargoPlannerGraphRoot::FinalHost,
    }
    .normalize(&policy, &closure)?;
    let feature_inputs = parse_host_feature_inputs(&args.host_feature_inputs)?;
    let host_feature_policy = args
        .host_feature_policy
        .as_deref()
        .map(|path| -> Result<_> {
            let input = fs::read_to_string(canonical_existing(path)?)?;
            Ok(toml::from_str::<HostFeatureUnionPolicy>(&input)?.normalize()?)
        })
        .transpose()?;
    let fetch_staging = canonical_existing(&args.fetch_staging)?;
    let fetch_cache_output = absolute_output(&args.fetch_cache_output)?;
    let target_root = canonical_existing(&args.target_root)?;
    let temp_root = canonical_existing(&args.temp_root)?;
    let artifact_parent = canonical_existing(&args.artifact_parent)?;
    let attestation_root = canonical_existing(&args.attestation_root)?;
    let nonce_directory = canonical_existing(&args.completion_nonce_directory)?;
    let mut completion_authority =
        |payload: &rust_agent_build_executor::ProductionBuildAttestationPayload| {
            request_completion_handle(payload)
        };
    let result = execute_trusted_production_host_build(
        ProductionHostBuildPipelineOptions {
            composition_build: &composition_build,
            pre_receipt: &pre_receipt,
            cargo_lock: &cargo_lock,
            policy: &policy,
            backend: &backend,
            closure: &closure,
            closure_snapshot: &snapshot,
            locked_sources: &locked_sources,
            fetch_request: &fetch_request,
            fetch_inputs: &fetch_inputs,
            fetch_staging: &fetch_staging,
            fetch_cache_output: &fetch_cache_output,
            fetch_cache_layout: &fetch_layout,
            production_inputs: &production_inputs,
            standalone_planner_request: &standalone_planner_request,
            final_planner_request: &final_planner_request,
            first_party_units: &feature_inputs.first_party_units,
            host_feature_policy: host_feature_policy.as_ref(),
            host_feature_observations: &feature_inputs.observations,
            host_root_runtime_effects: &feature_inputs.host_root_runtime_effects,
            product_build_contributions: &feature_inputs.product_build_contributions,
            target_root: &target_root,
            temp_root: &temp_root,
            artifact_parent: &artifact_parent,
            attestation_root: &attestation_root,
            completion_nonce_directory: &nonce_directory,
            executor_id: args.executor_id,
            workload_identity: args.workload_identity,
            verifier_identity_digest: args.verifier_identity_digest,
            timestamp: args.timestamp,
            transparency_proof: args.transparency_proof,
        },
        &mut completion_authority,
    )?;
    let output = ProductionCommandOutput {
        artifact_directory: &result.publication().path,
        attestation: result.attestation().path(),
        build_output_digest: &result.attestation().manifest().build_output_digest,
    };
    print_json(&CommandOutput {
        status: "built-host-production",
        value: &output,
    })
}

#[cfg(target_os = "linux")]
struct NormalizedHostFeatureExecutionInputs {
    first_party_units: BTreeSet<CargoUnitSelector>,
    observations: BTreeMap<CargoUnitSelector, HostFeatureUnitObservation>,
    host_root_runtime_effects: BTreeSet<String>,
    product_build_contributions: Vec<ProductBuildContribution>,
}

#[cfg(target_os = "linux")]
fn parse_host_feature_inputs(path: &Path) -> Result<NormalizedHostFeatureExecutionInputs> {
    let raw: HostFeatureExecutionInputs =
        serde_json::from_slice(&fs::read(canonical_existing(path)?)?)?;
    let mut observations = BTreeMap::new();
    for item in raw.observations {
        if observations.insert(item.unit, item.observation).is_some() {
            bail!("duplicate Host feature observation unit");
        }
    }
    Ok(NormalizedHostFeatureExecutionInputs {
        first_party_units: raw.first_party_units,
        observations,
        host_root_runtime_effects: raw.host_root_runtime_effects,
        product_build_contributions: raw.product_build_contributions,
    })
}

fn run_verify_integration(args: VerifyIntegrationArgs) -> Result<()> {
    match args.phase {
        None => {
            let integration = required(args.integration, "--integration")?;
            let manifest =
                verify_integration(&absolute_output(&integration)?, args.allow_development)?;
            print_json(&CommandOutput {
                status: "verified-integration",
                value: &manifest.composition_hash,
            })
        }
        Some(_) if args.allow_development => {
            bail!("production integration phases cannot use --allow-development")
        }
        Some(IntegrationPhase::Pre) => run_verify_integration_pre(args),
        Some(IntegrationPhase::Post) => run_verify_integration_post(args),
    }
}

#[cfg(not(target_os = "linux"))]
fn run_verify_integration_pre(_args: VerifyIntegrationArgs) -> Result<()> {
    bail!("production integration verification is supported only on Linux")
}

#[cfg(target_os = "linux")]
fn run_verify_integration_pre(args: VerifyIntegrationArgs) -> Result<()> {
    require_options(&[
        (args.integration.is_some(), "--integration"),
        (args.host_manifest.is_some(), "--host-manifest"),
        (args.dependency.is_some(), "--dependency"),
        (args.composition.is_some(), "--composition"),
        (
            args.composition_artifact_dir.is_some(),
            "--composition-artifact-dir",
        ),
        (
            args.composition_attestation.is_some(),
            "--composition-attestation",
        ),
        (
            args.composition_workload_identity.is_some(),
            "--composition-workload-identity",
        ),
        (args.execution_policy.is_some(), "--execution-policy"),
        (args.sandbox_backend.is_some(), "--sandbox-backend"),
        (args.host_closure.is_some(), "--host-closure"),
        (args.closure_snapshot.is_some(), "--closure-snapshot"),
        (args.closure_sources.is_some(), "--closure-sources"),
        (args.host_trust_root.is_some(), "--host-trust-root"),
        (args.locked_sources.is_some(), "--locked-sources"),
        (args.fetch_staging.is_some(), "--fetch-staging"),
        (args.fetch_cache_output.is_some(), "--fetch-cache-output"),
        (args.fetch_cache_layout.is_some(), "--fetch-cache-layout"),
        (args.host_feature_inputs.is_some(), "--host-feature-inputs"),
        (args.write_receipt.is_some(), "--write-receipt"),
    ])?;
    let integration_path = canonical_existing(&required(args.integration, "--integration")?)?;
    let emitted = verify_integration(&integration_path, true)?;
    let host_manifest = canonical_existing(&required(args.host_manifest, "--host-manifest")?)?;
    let _host_lock = canonical_existing(
        &host_manifest
            .parent()
            .context("Host manifest has no parent directory")?
            .join("Cargo.lock"),
    )?;
    let policy = load_production_policy(&required(args.execution_policy, "--execution-policy")?)?;
    let composition_artifact_dir = canonical_existing(&required(
        args.composition_artifact_dir,
        "--composition-artifact-dir",
    )?)?;
    let composition_attestation = canonical_existing(&required(
        args.composition_attestation,
        "--composition-attestation",
    )?)?;
    let composition_build = verify_production_build_attestation(
        &composition_artifact_dir,
        &composition_attestation,
        &policy,
        &required(
            args.composition_workload_identity,
            "--composition-workload-identity",
        )?,
    )?;
    if emitted != composition_build.manifest().composition {
        bail!("emitted integration differs from the attested composition");
    }
    let closure = load_host_closure(&required(args.host_closure, "--host-closure")?, &policy)?;
    if closure.composition_hash() != required(args.composition, "--composition")?
        || closure.host_dependency_alias() != required(args.dependency, "--dependency")?
        || closure.composition_hash() != emitted.composition_hash
    {
        bail!("integration identity/alias differs from the verified closure");
    }
    let snapshot_path = absolute_output(&required(args.closure_snapshot, "--closure-snapshot")?)?;
    let closure_sources = required(args.closure_sources, "--closure-sources")?;
    let host_trust_root = required(args.host_trust_root, "--host-trust-root")?;
    let snapshot = materialize_verified_host_snapshot(
        &closure,
        &closure_sources,
        &snapshot_path,
        &host_trust_root,
        Some(&host_manifest),
        &integration_path,
    )?;
    verify_host_dependency_alias(
        &host_manifest,
        closure.host_dependency_alias(),
        closure.generated_package_name(),
        &integration_path,
    )?;
    let locked_sources = load_locked_sources(&required(args.locked_sources, "--locked-sources")?)?;
    let fetch_mode = cli_fetch_mode(args.fetch_mode);
    let fetch_request = CargoFetchRequest {
        schema: 3,
        mode: fetch_mode,
    }
    .normalize(&policy, &closure, &locked_sources)?;
    let fetch_inputs = preflight_production_fetch_inputs(&policy, fetch_mode)?;
    let fetch_layout: CargoFetchCacheLayout = serde_json::from_slice(&fs::read(
        canonical_existing(&required(args.fetch_cache_layout, "--fetch-cache-layout")?)?,
    )?)?;
    let production_inputs = preflight_production_build_inputs(&policy, &closure)?;
    let standalone_planner_request = CargoPlannerRequest {
        schema: 2,
        root: CargoPlannerGraphRoot::EmittedStandalone,
    }
    .normalize(&policy, &closure)?;
    let final_planner_request = CargoPlannerRequest {
        schema: 2,
        root: CargoPlannerGraphRoot::FinalHost,
    }
    .normalize(&policy, &closure)?;
    let feature_inputs = parse_host_feature_inputs(&required(
        args.host_feature_inputs,
        "--host-feature-inputs",
    )?)?;
    let host_feature_policy = load_host_feature_policy(args.host_feature_policy.as_deref())?;
    let receipt_output = absolute_output(&required(args.write_receipt, "--write-receipt")?)?;
    let fetch_staging = canonical_existing(&required(args.fetch_staging, "--fetch-staging")?)?;
    let fetch_cache_output =
        absolute_output(&required(args.fetch_cache_output, "--fetch-cache-output")?)?;
    let backend = load_backend(&required(args.sandbox_backend, "--sandbox-backend")?)?;
    let result =
        execute_trusted_production_integration_pre(&ProductionIntegrationPrePipelineOptions {
            composition_build: &composition_build,
            receipt_output: &receipt_output,
            policy: &policy,
            backend: &backend,
            closure: &closure,
            closure_snapshot: &snapshot,
            locked_sources: &locked_sources,
            fetch_request: &fetch_request,
            fetch_inputs: &fetch_inputs,
            fetch_staging: &fetch_staging,
            fetch_cache_output: &fetch_cache_output,
            fetch_cache_layout: &fetch_layout,
            production_inputs: &production_inputs,
            standalone_planner_request: &standalone_planner_request,
            final_planner_request: &final_planner_request,
            first_party_units: &feature_inputs.first_party_units,
            host_feature_policy: host_feature_policy.as_ref(),
            host_feature_observations: &feature_inputs.observations,
            host_root_runtime_effects: &feature_inputs.host_root_runtime_effects,
            product_build_contributions: &feature_inputs.product_build_contributions,
        })?;
    print_json(&CommandOutput {
        status: "verified-integration-pre",
        value: result.receipt(),
    })
}

#[cfg(not(target_os = "linux"))]
fn run_verify_integration_post(_args: VerifyIntegrationArgs) -> Result<()> {
    bail!("production integration verification is supported only on Linux")
}

#[cfg(target_os = "linux")]
fn run_verify_integration_post(args: VerifyIntegrationArgs) -> Result<()> {
    require_options(&[
        (args.integration.is_some(), "--integration"),
        (args.host_manifest.is_some(), "--host-manifest"),
        (args.dependency.is_some(), "--dependency"),
        (args.composition.is_some(), "--composition"),
        (
            args.composition_artifact_dir.is_some(),
            "--composition-artifact-dir",
        ),
        (
            args.composition_attestation.is_some(),
            "--composition-attestation",
        ),
        (
            args.composition_workload_identity.is_some(),
            "--composition-workload-identity",
        ),
        (args.execution_policy.is_some(), "--execution-policy"),
        (args.sandbox_backend.is_some(), "--sandbox-backend"),
        (args.host_closure.is_some(), "--host-closure"),
        (args.closure_snapshot.is_some(), "--closure-snapshot"),
        (args.closure_sources.is_some(), "--closure-sources"),
        (args.host_trust_root.is_some(), "--host-trust-root"),
        (args.locked_sources.is_some(), "--locked-sources"),
        (args.fetch_staging.is_some(), "--fetch-staging"),
        (args.fetch_cache_output.is_some(), "--fetch-cache-output"),
        (args.fetch_cache_layout.is_some(), "--fetch-cache-layout"),
        (args.host_feature_inputs.is_some(), "--host-feature-inputs"),
        (args.pre_receipt.is_some(), "--pre-receipt"),
        (
            args.executor_artifact_dir.is_some(),
            "--executor-artifact-dir",
        ),
        (
            args.executor_attestation.is_some(),
            "--executor-attestation",
        ),
        (
            args.executor_workload_identity.is_some(),
            "--executor-workload-identity",
        ),
        (args.write_attestation.is_some(), "--write-attestation"),
        (
            args.completion_nonce_directory.is_some(),
            "--completion-nonce-directory",
        ),
        (args.executor_id.is_some(), "--executor-id"),
        (args.workload_identity.is_some(), "--workload-identity"),
        (
            args.verifier_identity_digest.is_some(),
            "--verifier-identity-digest",
        ),
        (args.timestamp.is_some(), "--timestamp"),
    ])?;
    let integration_path = canonical_existing(&required(args.integration, "--integration")?)?;
    let emitted = verify_integration(&integration_path, true)?;
    let host_manifest = canonical_existing(&required(args.host_manifest, "--host-manifest")?)?;
    let policy = load_production_policy(&required(args.execution_policy, "--execution-policy")?)?;
    let composition_artifact_dir = canonical_existing(&required(
        args.composition_artifact_dir,
        "--composition-artifact-dir",
    )?)?;
    let composition_attestation = canonical_existing(&required(
        args.composition_attestation,
        "--composition-attestation",
    )?)?;
    let composition_build = verify_production_build_attestation(
        &composition_artifact_dir,
        &composition_attestation,
        &policy,
        &required(
            args.composition_workload_identity,
            "--composition-workload-identity",
        )?,
    )?;
    if emitted != composition_build.manifest().composition {
        bail!("emitted integration differs from the attested composition");
    }
    let closure = load_host_closure(&required(args.host_closure, "--host-closure")?, &policy)?;
    if closure.composition_hash() != required(args.composition, "--composition")?
        || closure.host_dependency_alias() != required(args.dependency, "--dependency")?
    {
        bail!("integration identity/alias differs from the verified closure");
    }
    let receipt_path = canonical_existing(&required(args.pre_receipt, "--pre-receipt")?)?;
    let receipt = read_production_integration_pre_receipt(
        &receipt_path,
        &closure,
        &policy,
        &composition_build,
    )?;
    let snapshot_path = absolute_output(&required(args.closure_snapshot, "--closure-snapshot")?)?;
    let snapshot = materialize_verified_host_snapshot(
        &closure,
        &required(args.closure_sources, "--closure-sources")?,
        &snapshot_path,
        &required(args.host_trust_root, "--host-trust-root")?,
        Some(&host_manifest),
        &integration_path,
    )?;
    verify_host_dependency_alias(
        &host_manifest,
        closure.host_dependency_alias(),
        closure.generated_package_name(),
        &integration_path,
    )?;
    let locked_sources = load_locked_sources(&required(args.locked_sources, "--locked-sources")?)?;
    let fetch_mode = cli_fetch_mode(args.fetch_mode);
    let fetch_request = CargoFetchRequest {
        schema: 3,
        mode: fetch_mode,
    }
    .normalize(&policy, &closure, &locked_sources)?;
    let fetch_inputs = preflight_production_fetch_inputs(&policy, fetch_mode)?;
    let fetch_layout: CargoFetchCacheLayout = serde_json::from_slice(&fs::read(
        canonical_existing(&required(args.fetch_cache_layout, "--fetch-cache-layout")?)?,
    )?)?;
    let production_inputs = preflight_production_build_inputs(&policy, &closure)?;
    let standalone_planner_request = CargoPlannerRequest {
        schema: 2,
        root: CargoPlannerGraphRoot::EmittedStandalone,
    }
    .normalize(&policy, &closure)?;
    let final_planner_request = CargoPlannerRequest {
        schema: 2,
        root: CargoPlannerGraphRoot::FinalHost,
    }
    .normalize(&policy, &closure)?;
    let feature_inputs = parse_host_feature_inputs(&required(
        args.host_feature_inputs,
        "--host-feature-inputs",
    )?)?;
    let host_feature_policy = load_host_feature_policy(args.host_feature_policy.as_deref())?;
    let fetch_staging = canonical_existing(&required(args.fetch_staging, "--fetch-staging")?)?;
    let fetch_cache_output =
        absolute_output(&required(args.fetch_cache_output, "--fetch-cache-output")?)?;
    let backend = load_backend(&required(args.sandbox_backend, "--sandbox-backend")?)?;
    let reverified =
        reverify_trusted_production_integration_pre(&ProductionIntegrationPrePipelineOptions {
            composition_build: &composition_build,
            receipt_output: &receipt_path,
            policy: &policy,
            backend: &backend,
            closure: &closure,
            closure_snapshot: &snapshot,
            locked_sources: &locked_sources,
            fetch_request: &fetch_request,
            fetch_inputs: &fetch_inputs,
            fetch_staging: &fetch_staging,
            fetch_cache_output: &fetch_cache_output,
            fetch_cache_layout: &fetch_layout,
            production_inputs: &production_inputs,
            standalone_planner_request: &standalone_planner_request,
            final_planner_request: &final_planner_request,
            first_party_units: &feature_inputs.first_party_units,
            host_feature_policy: host_feature_policy.as_ref(),
            host_feature_observations: &feature_inputs.observations,
            host_root_runtime_effects: &feature_inputs.host_root_runtime_effects,
            product_build_contributions: &feature_inputs.product_build_contributions,
        })?;
    if reverified.receipt() != &receipt {
        bail!("post verification rederived a different production pre receipt");
    }
    let executor_artifact_dir = canonical_existing(&required(
        args.executor_artifact_dir,
        "--executor-artifact-dir",
    )?)?;
    let executor_attestation = canonical_existing(&required(
        args.executor_attestation,
        "--executor-attestation",
    )?)?;
    let executor = verify_production_build_attestation(
        &executor_artifact_dir,
        &executor_attestation,
        &policy,
        &required(
            args.executor_workload_identity,
            "--executor-workload-identity",
        )?,
    )?;
    let post_payload = create_production_integration_post_payload(
        &receipt,
        &closure,
        &policy,
        &composition_build,
        &executor,
        ProductionIntegrationPostInput {
            executor_id: required(args.executor_id, "--executor-id")?,
            workload_identity: required(args.workload_identity, "--workload-identity")?,
            verifier_identity_digest: required(
                args.verifier_identity_digest,
                "--verifier-identity-digest",
            )?,
        },
    )?;
    let completion = request_completion_handle(&post_payload).map_err(anyhow::Error::msg)?;
    let post_output = absolute_output(&required(args.write_attestation, "--write-attestation")?)?;
    let nonce_directory = canonical_existing(&required(
        args.completion_nonce_directory,
        "--completion-nonce-directory",
    )?)?;
    let verified = write_production_integration_post_attestation(
        &post_output,
        &executor_artifact_dir,
        &receipt_path,
        &receipt,
        &closure,
        &policy,
        &composition_build,
        &executor,
        post_payload,
        completion,
        &nonce_directory,
        required(args.timestamp, "--timestamp")?,
        args.transparency_proof,
    )?;
    print_json(&CommandOutput {
        status: "verified-integration-post",
        value: verified.attestation(),
    })
}

#[cfg(target_os = "linux")]
fn load_production_policy(
    path: &Path,
) -> Result<rust_agent_build_executor::NormalizedProductionBuildPolicy> {
    Ok(
        ProductionBuildExecutionPolicy::from_toml(&fs::read_to_string(canonical_existing(path)?)?)?
            .normalize()?,
    )
}

#[cfg(target_os = "linux")]
fn load_backend(path: &Path) -> Result<VerifiedLinuxSandboxBackend> {
    let identity: LinuxSandboxBackendIdentity =
        serde_json::from_slice(&fs::read(canonical_existing(path)?)?)?;
    Ok(VerifiedLinuxSandboxBackend::open(identity)?)
}

#[cfg(target_os = "linux")]
fn load_host_closure(
    path: &Path,
    policy: &rust_agent_build_executor::NormalizedProductionBuildPolicy,
) -> Result<rust_agent_build_executor::NormalizedHostBuildInputClosure> {
    Ok(
        HostBuildInputClosure::from_json(&fs::read_to_string(canonical_existing(path)?)?)?
            .normalize(policy)?,
    )
}

#[cfg(target_os = "linux")]
fn load_locked_sources(
    path: &Path,
) -> Result<rust_agent_build_executor::NormalizedLockedSourceClosure> {
    Ok(
        LockedSourceClosure::from_json(&fs::read_to_string(canonical_existing(path)?)?)?
            .normalize()?,
    )
}

#[cfg(target_os = "linux")]
fn load_closure_sources(path: &Path) -> Result<Vec<HostClosureSnapshotSource>> {
    let source_map: HostClosureSourceMap =
        serde_json::from_slice(&fs::read(canonical_existing(path)?)?)?;
    if source_map.schema != 1 {
        bail!("unsupported Host closure source-map schema");
    }
    source_map
        .sources
        .into_iter()
        .map(|source| {
            Ok(HostClosureSnapshotSource {
                item_id: source.item_id,
                path: absolute_output(&source.path)?,
            })
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn closure_source_path(
    closure: &NormalizedHostBuildInputClosure,
    source_map: &Path,
    role: HostBuildClosureItemRole,
) -> Result<PathBuf> {
    let item = closure
        .items()
        .iter()
        .find(|item| item.role == role)
        .context("Host closure is missing a required source role")?;
    let sources = load_closure_sources(source_map)?;
    let source = sources
        .iter()
        .find(|source| source.item_id == item.id)
        .context("Host closure source map is missing a required item")?;
    canonical_existing(&source.path)
}

#[cfg(target_os = "linux")]
fn materialize_verified_host_snapshot(
    closure: &NormalizedHostBuildInputClosure,
    source_map: &Path,
    snapshot_path: &Path,
    host_trust_root: &Path,
    host_manifest: Option<&Path>,
    integration: &Path,
) -> Result<VerifiedHostClosureSnapshot> {
    let trust_root = canonical_existing(host_trust_root)?;
    if !trust_root.is_dir() {
        bail!("--host-trust-root must be a canonical directory");
    }
    let integration = canonical_existing(integration)?;
    if !integration.starts_with(&trust_root) {
        bail!("emitted integration is outside --host-trust-root");
    }
    let sources = load_closure_sources(source_map)?;
    let source_by_id = sources
        .iter()
        .map(|source| (source.item_id.as_str(), &source.path))
        .collect::<BTreeMap<_, _>>();
    if source_by_id.len() != sources.len() {
        bail!("Host closure source map contains duplicate item ids");
    }
    for source in &sources {
        let canonical = canonical_existing(&source.path)?;
        if !canonical.starts_with(&trust_root) {
            bail!(
                "Host closure source `{}` is outside --host-trust-root",
                source.item_id
            );
        }
    }
    let source_for_role = |role| -> Result<PathBuf> {
        let item = closure
            .items()
            .iter()
            .find(|item| item.role == role)
            .context("Host closure is missing a required source role")?;
        let path = source_by_id
            .get(item.id.as_str())
            .context("Host closure source map is missing a required item")?;
        canonical_existing(path)
    };
    if source_for_role(HostBuildClosureItemRole::EmittedCompositionTree)? != integration {
        bail!("Host closure emitted tree does not point to the verified integration");
    }
    if let Some(host_manifest) = host_manifest {
        let host_manifest = canonical_existing(host_manifest)?;
        if !host_manifest.starts_with(&trust_root)
            || source_for_role(HostBuildClosureItemRole::HostRootManifest)? != host_manifest
            || source_for_role(HostBuildClosureItemRole::HostCargoLock)?
                != canonical_existing(
                    &host_manifest
                        .parent()
                        .context("Host manifest has no parent directory")?
                        .join("Cargo.lock"),
                )?
        {
            bail!("Host manifest or lock differs from the proposed closure");
        }
        verify_applicable_cargo_config(
            &host_manifest,
            &trust_root,
            &source_for_role(HostBuildClosureItemRole::CargoConfig)?,
        )?;
    } else {
        for (role, relative) in [
            (HostBuildClosureItemRole::HostRootManifest, "Cargo.toml"),
            (HostBuildClosureItemRole::HostCargoLock, "Cargo.lock"),
            (HostBuildClosureItemRole::CargoConfig, ".cargo/config.toml"),
        ] {
            if source_for_role(role)? != canonical_existing(&integration.join(relative))? {
                bail!("standalone closure root inputs differ from the composition");
            }
        }
    }
    materialize_host_closure_snapshot(closure, &sources, snapshot_path)?;
    Ok(open_verified_host_closure_snapshot(closure, snapshot_path)?)
}

#[cfg(target_os = "linux")]
fn verify_applicable_cargo_config(
    host_manifest: &Path,
    trust_root: &Path,
    expected: &Path,
) -> Result<()> {
    let mut current = host_manifest
        .parent()
        .context("Host manifest has no parent directory")?;
    let mut configs = Vec::new();
    loop {
        let modern = current.join(".cargo/config.toml");
        let legacy = current.join(".cargo/config");
        if modern.exists() && legacy.exists() {
            bail!("legacy and modern Cargo config coexist in the Host trust chain");
        }
        if modern.exists() {
            configs.push(canonical_existing(&modern)?);
        }
        if legacy.exists() {
            configs.push(canonical_existing(&legacy)?);
        }
        if current == trust_root {
            break;
        }
        current = current
            .parent()
            .filter(|parent| parent.starts_with(trust_root))
            .context("Host manifest is outside --host-trust-root")?;
    }
    if configs.as_slice() != [expected] {
        bail!("Host trust chain must contain the exact single closure Cargo config");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_host_dependency_alias(
    host_manifest: &Path,
    alias: &str,
    generated_package: &str,
    integration: &Path,
) -> Result<()> {
    let host: toml::Value = toml::from_str(&fs::read_to_string(host_manifest)?)?;
    let integration_manifest: toml::Value =
        toml::from_str(&fs::read_to_string(integration.join("Cargo.toml"))?)?;
    let actual_package = integration_manifest
        .get("package")
        .and_then(toml::Value::as_table)
        .and_then(|package| package.get("name"))
        .and_then(toml::Value::as_str)
        .context("emitted integration has no package name")?;
    if actual_package != generated_package {
        bail!("emitted integration package name differs from the Host closure");
    }
    let mut matches = Vec::new();
    collect_dependency_aliases(&host, alias, generated_package, &mut matches)?;
    let [(normal, path, package)] = matches.as_slice() else {
        bail!("Host must contain exactly one dependency on the emitted package");
    };
    if !normal
        || package.as_deref().unwrap_or(alias) != generated_package
        || canonical_existing(
            &host_manifest
                .parent()
                .context("Host manifest has no parent directory")?
                .join(path),
        )? != canonical_existing(integration)?
    {
        bail!("Host dependency alias does not point exactly to the verified integration");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn collect_dependency_aliases(
    value: &toml::Value,
    required_alias: &str,
    generated_package: &str,
    matches: &mut Vec<(bool, String, Option<String>)>,
) -> Result<()> {
    let Some(table) = value.as_table() else {
        return Ok(());
    };
    for (key, child) in table {
        if matches!(
            key.as_str(),
            "dependencies" | "dev-dependencies" | "build-dependencies"
        ) {
            let dependencies = child
                .as_table()
                .context("Cargo dependency section must be a table")?;
            for (alias, specification) in dependencies {
                let Some(specification) = specification.as_table() else {
                    continue;
                };
                let package = specification
                    .get("package")
                    .and_then(toml::Value::as_str)
                    .map(str::to_owned);
                if alias == required_alias
                    || package.as_deref() == Some(generated_package)
                    || alias == generated_package
                {
                    let path = specification
                        .get("path")
                        .and_then(toml::Value::as_str)
                        .context("rust-agent Host dependency must be path-based")?;
                    if specification.contains_key("git") || specification.contains_key("registry") {
                        bail!("rust-agent Host dependency cannot use git or a registry");
                    }
                    matches.push((key == "dependencies", path.into(), package));
                }
            }
        } else {
            collect_dependency_aliases(child, required_alias, generated_package, matches)?;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn load_host_feature_policy(
    path: Option<&Path>,
) -> Result<Option<rust_agent_build_executor::NormalizedHostFeaturePolicy>> {
    path.map(|path| -> Result<_> {
        let input = fs::read_to_string(canonical_existing(path)?)?;
        Ok(toml::from_str::<HostFeatureUnionPolicy>(&input)?.normalize()?)
    })
    .transpose()
}

#[cfg(target_os = "linux")]
fn cli_fetch_mode(mode: CliFetchMode) -> CargoFetchMode {
    match mode {
        CliFetchMode::Preprovisioned => CargoFetchMode::Preprovisioned,
        CliFetchMode::Networked => CargoFetchMode::Networked,
    }
}

#[cfg(target_os = "linux")]
#[derive(Serialize)]
struct ProductionCompletionChallenge<'a> {
    status: &'static str,
    payload: &'a rust_agent_build_executor::ProductionBuildAttestationPayload,
}

#[cfg(target_os = "linux")]
#[derive(Serialize)]
struct ProductionCommandOutput<'a> {
    #[serde(rename = "artifact-directory")]
    artifact_directory: &'a Path,
    attestation: &'a Path,
    #[serde(rename = "build-output-digest")]
    build_output_digest: &'a str,
}

#[cfg(target_os = "linux")]
fn request_completion_handle(
    payload: &rust_agent_build_executor::ProductionBuildAttestationPayload,
) -> std::result::Result<ProductionCompletionHandle, String> {
    const MAX_COMPLETION_HANDLE_BYTES: u64 = 1024 * 1024;

    let challenge = ProductionCompletionChallenge {
        status: "completion-required",
        payload,
    };
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, &challenge).map_err(|error| error.to_string())?;
    stdout.write_all(b"\n").map_err(|error| error.to_string())?;
    stdout.flush().map_err(|error| error.to_string())?;

    let stdin = io::stdin();
    let mut bounded = stdin.lock().take(MAX_COMPLETION_HANDLE_BYTES + 1);
    let mut line = String::new();
    bounded
        .read_line(&mut line)
        .map_err(|error| error.to_string())?;
    if line.is_empty() || line.len() as u64 > MAX_COMPLETION_HANDLE_BYTES {
        return Err("completion handle is missing or exceeds the protocol bound".into());
    }
    serde_json::from_str(&line).map_err(|error| error.to_string())
}

fn required<T>(value: Option<T>, name: &'static str) -> Result<T> {
    value.with_context(|| format!("production build requires {name}"))
}

fn require_options(options: &[(bool, &'static str)]) -> Result<()> {
    let missing = options
        .iter()
        .filter_map(|(present, name)| (!present).then_some(*name))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        bail!("production command requires {}", missing.join(", "));
    }
    Ok(())
}

fn canonical_existing(path: &Path) -> Result<PathBuf> {
    path.canonicalize()
        .with_context(|| format!("cannot resolve {}", path.display()))
}

fn absolute_output(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_owned());
    }
    Ok(std::env::current_dir()?.join(path))
}

fn print_json<T: Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn host_dependency_alias_and_cargo_config_are_unique_and_exact() {
        let temp = tempfile::TempDir::new().unwrap();
        let trust_root = temp.path().canonicalize().unwrap();
        let host = trust_root.join("host");
        let integration = trust_root.join("integration");
        fs::create_dir_all(host.join(".cargo")).unwrap();
        fs::create_dir(&integration).unwrap();
        fs::write(
            integration.join("Cargo.toml"),
            "[package]\nname = \"generated-agent\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fs::write(host.join("Cargo.lock"), "version = 4\n").unwrap();
        let config = host.join(".cargo/config.toml");
        fs::write(&config, "[net]\noffline = true\n").unwrap();
        let manifest = host.join("Cargo.toml");
        fs::write(
            &manifest,
            "[package]\nname = \"host\"\nversion = \"0.1.0\"\n\n[target.'cfg(target_os = \"linux\")'.dependencies]\ngenerated-alias = { package = \"generated-agent\", path = \"../integration\" }\n",
        )
        .unwrap();
        let manifest = manifest.canonicalize().unwrap();
        let integration = integration.canonicalize().unwrap();
        let config = config.canonicalize().unwrap();

        verify_host_dependency_alias(
            &manifest,
            "generated-alias",
            "generated-agent",
            &integration,
        )
        .unwrap();
        verify_applicable_cargo_config(&manifest, &trust_root, &config).unwrap();

        fs::write(host.join(".cargo/config"), "[net]\noffline = true\n").unwrap();
        assert!(verify_applicable_cargo_config(&manifest, &trust_root, &config).is_err());
        fs::remove_file(host.join(".cargo/config")).unwrap();

        fs::write(
            &manifest,
            "[package]\nname = \"host\"\nversion = \"0.1.0\"\n\n[dependencies]\ngenerated-alias = { package = \"generated-agent\", path = \"../integration\" }\n\n[dev-dependencies]\nshadow = { package = \"generated-agent\", path = \"../integration\" }\n",
        )
        .unwrap();
        assert!(
            verify_host_dependency_alias(
                &manifest,
                "generated-alias",
                "generated-agent",
                &integration,
            )
            .is_err()
        );
    }
}
