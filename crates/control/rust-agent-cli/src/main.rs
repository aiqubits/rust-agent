use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use rust_agent_build_executor::{
    BuildExecutionPolicy, DevelopmentBuildOptions, development_build, emit_integration,
    inspect_development_build, verify_integration,
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
    Build {
        #[arg(long)]
        composition: PathBuf,
        #[arg(long)]
        artifact_dir: PathBuf,
        #[arg(long)]
        rustc: PathBuf,
        #[arg(long)]
        cargo: PathBuf,
        #[arg(long)]
        linker: PathBuf,
        #[arg(long)]
        registry_cache: Option<PathBuf>,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long, required = true)]
        development_build: bool,
        #[arg(long, default_value_t = true)]
        run_generated_tests: bool,
    },
    /// Inspect and re-verify a composition or built artifact.
    Inspect {
        #[arg(long)]
        composition: Option<PathBuf>,
        #[arg(long)]
        artifact_dir: Option<PathBuf>,
        #[arg(long)]
        allow_development: bool,
    },
    /// Emit a verified immutable library integration tree.
    EmitIntegration {
        #[arg(long)]
        composition: PathBuf,
        #[arg(long)]
        destination: PathBuf,
    },
    /// Verify an emitted integration tree and its development/production tier.
    VerifyIntegration {
        #[arg(long)]
        integration: PathBuf,
        #[arg(long)]
        allow_development: bool,
    },
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
        Command::Build {
            composition,
            artifact_dir,
            rustc,
            cargo,
            linker,
            registry_cache,
            policy,
            development_build: _,
            run_generated_tests,
        } => {
            let policy = if let Some(path) = policy {
                let input = fs::read_to_string(canonical_existing(&path)?)?;
                BuildExecutionPolicy::from_toml(&input).context("invalid build policy TOML")?
            } else {
                BuildExecutionPolicy::empty_development()
            };
            let manifest = development_build(&DevelopmentBuildOptions {
                composition_path: absolute_output(&composition)?,
                artifact_dir: absolute_output(&artifact_dir)?,
                cargo_path: canonical_existing(&cargo)?,
                rustc_path: canonical_existing(&rustc)?,
                linker_path: canonical_existing(&linker)?,
                registry_cache_path: registry_cache
                    .as_deref()
                    .map(canonical_existing)
                    .transpose()?,
                policy,
                run_generated_tests,
            })?;
            print_json(&CommandOutput {
                status: "built-development",
                value: &manifest,
            })?;
        }
        Command::Inspect {
            composition,
            artifact_dir,
            allow_development,
        } => match (composition, artifact_dir) {
            (Some(path), None) => {
                let manifest = verify_composition(&absolute_output(&path)?)?;
                if !allow_development && !manifest.deployable {
                    bail!(
                        "development composition rejected by production inspection; pass --allow-development"
                    );
                }
                print_json(&CommandOutput {
                    status: "verified-composition",
                    value: &manifest,
                })?;
            }
            (None, Some(path)) => {
                let manifest =
                    inspect_development_build(&canonical_existing(&path)?, allow_development)?;
                print_json(&CommandOutput {
                    status: "verified-build",
                    value: &manifest,
                })?;
            }
            _ => bail!("exactly one of --composition or --artifact-dir is required"),
        },
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
        Command::VerifyIntegration {
            integration,
            allow_development,
        } => {
            let manifest = verify_integration(&absolute_output(&integration)?, allow_development)?;
            print_json(&CommandOutput {
                status: "verified-integration",
                value: &manifest.composition_hash,
            })?;
        }
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
