use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use rust_agent_build_executor::{
    CargoCompilationKind, CargoCompileMode, CargoCrateKind, CargoPackageIdentity,
    CargoPackageSource, CargoUnit, CargoUnitGraphPlannerIdentity, CargoUnitSelector,
    DevelopmentHostFeatureVerification, FeatureAccountingMode, HostCargoUnitGraph,
    HostFeaturePolicyEntry, HostFeaturePolicyError, HostFeaturePolicyStageDigests,
    HostFeatureUnionPolicy, HostFeatureUnitObservation, ProductBuildContribution, emit_integration,
    verify_development_host_feature_union, verify_production_host_feature_union,
};
use rust_agent_composition::{ComposeError, ComposeOptions, compose, metadata::BuildRequirements};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

const TARGET: &str = "x86_64-unknown-linux-gnu";

#[derive(Debug)]
struct HexMetadata {
    selector: CargoUnitSelector,
    features: Vec<String>,
}

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
}

fn tool(name: &str) -> PathBuf {
    let selected = Command::new("rustup")
        .args(["which", name])
        .output()
        .expect("rustup must resolve the pinned toolchain");
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

fn registry_cache() -> PathBuf {
    let cargo_home = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
        .expect("Cargo home must be discoverable");
    cargo_home.join("registry").canonicalize().unwrap()
}

fn prepare_cargo_home(path: &Path, registry: &Path) {
    fs::create_dir_all(path).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(registry, path.join("registry")).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(registry, path.join("registry")).unwrap();
}

fn run_cargo(
    cargo: &Path,
    rustc: &Path,
    linker: &Path,
    directory: &Path,
    cargo_home: &Path,
    target_dir: &Path,
    args: &[&str],
) -> Output {
    let path = env::join_paths(
        [cargo, rustc, linker]
            .into_iter()
            .map(|tool| tool.parent().unwrap()),
    )
    .unwrap();
    Command::new(cargo)
        .args(args)
        .current_dir(directory)
        .env_clear()
        .env("PATH", path)
        .env("RUSTC", rustc)
        .env("CARGO_HOME", cargo_home)
        .env("CARGO_TARGET_DIR", target_dir)
        .output()
        .unwrap()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn tool_version(tool: &Path) -> String {
    let output = Command::new(tool).arg("--version").output().unwrap();
    assert_success(&output);
    String::from_utf8(output.stdout)
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_owned()
}

fn tool_digest(tool: &Path) -> String {
    hex::encode(Sha256::digest(fs::read(tool).unwrap()))
}

fn build_triple(rustc: &Path) -> String {
    let output = Command::new(rustc).arg("-vV").output().unwrap();
    assert_success(&output);
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("host: ").map(str::to_owned))
        .unwrap()
}

fn planner(cargo: &Path, rustc: &Path) -> CargoUnitGraphPlannerIdentity {
    CargoUnitGraphPlannerIdentity {
        interface: "cargo-unit-graph-v1".into(),
        cargo_version: tool_version(cargo),
        cargo_digest: tool_digest(cargo),
        rustc_version: tool_version(rustc),
        rustc_digest: tool_digest(rustc),
    }
}

fn hex_metadata(output: &Output, lockfile: &Path) -> HexMetadata {
    assert_success(output);
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    let package = document["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|package| package["name"] == "hex")
        .expect("hex must be resolved in the Cargo graph");
    let package_id = package["id"].as_str().unwrap();
    let resolve = document["resolve"]["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node| node["id"] == package_id)
        .expect("hex resolve node must exist");
    let mut features: Vec<_> = resolve["features"]
        .as_array()
        .unwrap()
        .iter()
        .map(|feature| feature.as_str().unwrap().to_owned())
        .collect();
    features.sort();
    let target_name = package["targets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|target| {
            target["kind"]
                .as_array()
                .unwrap()
                .iter()
                .any(|kind| kind == "lib")
        })
        .unwrap()["name"]
        .as_str()
        .unwrap()
        .to_owned();
    let registry = package["source"]
        .as_str()
        .unwrap()
        .strip_prefix("registry+")
        .unwrap()
        .to_owned();
    let lock: toml::Value = toml::from_str(&fs::read_to_string(lockfile).unwrap()).unwrap();
    let checksum = lock["package"]
        .as_array()
        .unwrap()
        .iter()
        .find(|locked| locked["name"].as_str() == Some("hex"))
        .and_then(|locked| locked["checksum"].as_str())
        .expect("the exact registry checksum must be locked")
        .to_owned();
    HexMetadata {
        selector: CargoUnitSelector {
            package: CargoPackageIdentity {
                name: package["name"].as_str().unwrap().to_owned(),
                version: package["version"].as_str().unwrap().to_owned(),
                source: CargoPackageSource::Registry { registry, checksum },
            },
            target_name,
            compilation_kind: CargoCompilationKind::Target,
            compilation_target: TARGET.into(),
            cargo_target_context:
                rust_agent_build_executor::CargoUnitTargetContext::CompositionTarget,
            compile_mode: CargoCompileMode::Build,
            profile: "dev".into(),
            crate_kind: CargoCrateKind::Library,
        },
        features,
    }
}

fn rustc_features(output: &Output, crate_name: &str) -> Vec<String> {
    assert_success(output);
    let stderr = String::from_utf8(output.stderr.clone()).unwrap();
    let line = stderr
        .lines()
        .find(|line| {
            line.contains(" Running `")
                && line.contains("--crate-name")
                && line.split_whitespace().any(|token| token == crate_name)
        })
        .unwrap_or_else(|| panic!("no observed rustc invocation for {crate_name}:\n{stderr}"));
    let tokens: Vec<_> = line.split_whitespace().collect();
    let mut features = BTreeSet::new();
    for pair in tokens.windows(2) {
        if pair[0] != "--cfg" {
            continue;
        }
        let value = pair[1].trim_matches(|character| matches!(character, '\'' | '"' | '`' | '\\'));
        if let Some(feature) = value.strip_prefix("feature=") {
            let feature =
                feature.trim_matches(|character| matches!(character, '\'' | '"' | '`' | '\\'));
            features.insert(feature.to_owned());
        }
    }
    features.into_iter().collect()
}

fn unit_graph(
    planner: &CargoUnitGraphPlannerIdentity,
    build_triple: &str,
    metadata: &HexMetadata,
    features: Vec<String>,
) -> rust_agent_build_executor::NormalizedHostCargoUnitGraph {
    HostCargoUnitGraph {
        schema: 2,
        planner: planner.clone(),
        build_triple: build_triple.to_owned(),
        composition_target: TARGET.into(),
        profile: "dev".into(),
        nodes: vec![CargoUnit {
            selector: metadata.selector.clone(),
            features,
            build_script: false,
            proc_macro: false,
        }],
        edges: vec![],
    }
    .normalize()
    .unwrap()
}

fn host_source_digest(host: &Path) -> String {
    let mut hasher = Sha256::new();
    for relative in ["Cargo.toml", "build.rs", "src/main.rs"] {
        hasher.update(relative.as_bytes());
        hasher.update([0]);
        hasher.update(fs::read(host.join(relative)).unwrap());
        hasher.update([0]);
    }
    hex::encode(hasher.finalize())
}

fn product_selector(host: &Path, build_triple: &str, build_script: bool) -> CargoUnitSelector {
    CargoUnitSelector {
        package: CargoPackageIdentity {
            name: "shared-feature-host".into(),
            version: "0.1.0".into(),
            source: CargoPackageSource::Path {
                tree_digest: host_source_digest(host),
            },
        },
        target_name: if build_script {
            "build-script-build".into()
        } else {
            "shared_feature_host".into()
        },
        compilation_kind: if build_script {
            CargoCompilationKind::BuildHost
        } else {
            CargoCompilationKind::Target
        },
        compilation_target: if build_script { build_triple } else { TARGET }.into(),
        cargo_target_context: rust_agent_build_executor::CargoUnitTargetContext::CompositionTarget,
        compile_mode: if build_script {
            CargoCompileMode::RunCustomBuild
        } else {
            CargoCompileMode::Build
        },
        profile: "dev".into(),
        crate_kind: if build_script {
            CargoCrateKind::CustomBuild
        } else {
            CargoCrateKind::Binary
        },
    }
}

#[test]
fn external_shared_target_feature_union_is_observed_and_accounted_end_to_end() {
    let root = repository_root();
    let temp = TempDir::new().unwrap();
    let cargo = tool("cargo");
    let rustc = tool("rustc");
    let linker = tool("cc");
    let registry = registry_cache();
    let planner = planner(&cargo, &rustc);
    let build_triple = build_triple(&rustc);

    let without_registry = compose(&ComposeOptions {
        workspace_root: root.clone(),
        profile_path: root.join("tests/fixtures/profiles/controlled-build.toml"),
        catalog_trust_policy_path: root.join("tests/fixtures/catalog-trust.toml"),
        output_root: temp.path().join("missing-registry-compositions"),
        rustc_path: rustc.clone(),
        cargo_path: cargo.clone(),
        registry_cache_path: None,
        custom_target_spec_path: None,
    });
    assert!(matches!(
        without_registry,
        Err(ComposeError::InvalidRegistryCache(_))
    ));

    let generated = compose(&ComposeOptions {
        workspace_root: root.clone(),
        profile_path: root.join("tests/fixtures/profiles/controlled-build.toml"),
        catalog_trust_policy_path: root.join("tests/fixtures/catalog-trust.toml"),
        output_root: temp.path().join("compositions"),
        rustc_path: rustc.clone(),
        cargo_path: cargo.clone(),
        registry_cache_path: Some(registry.clone()),
        custom_target_spec_path: None,
    })
    .unwrap();
    assert_eq!(
        generated
            .manifest
            .cargo_resolution
            .registries
            .get("crates-io")
            .map(String::as_str),
        Some("registry+https://github.com/rust-lang/crates.io-index")
    );
    let integration = temp.path().join("integration");
    emit_integration(&generated.path, &integration).unwrap();

    let standalone_home = temp.path().join("standalone-cargo-home");
    prepare_cargo_home(&standalone_home, &registry);
    let standalone_target = temp.path().join("standalone-target");
    let standalone_metadata = hex_metadata(
        &run_cargo(
            &cargo,
            &rustc,
            &linker,
            &integration,
            &standalone_home,
            &standalone_target,
            &[
                "metadata",
                "--format-version",
                "1",
                "--locked",
                "--offline",
                "--filter-platform",
                TARGET,
            ],
        ),
        &integration.join("Cargo.lock"),
    );
    assert_eq!(standalone_metadata.features, ["alloc"]);
    let standalone_build = run_cargo(
        &cargo,
        &rustc,
        &linker,
        &integration,
        &standalone_home,
        &standalone_target,
        &["build", "--target", TARGET, "--locked", "--offline", "-vv"],
    );
    let standalone_observed = rustc_features(&standalone_build, "hex");
    assert_eq!(standalone_observed, standalone_metadata.features);

    let host = temp.path().join("shared-feature-host");
    fs::create_dir_all(host.join("src")).unwrap();
    fs::copy(
        root.join("tests/fixtures/topologies/shared-feature-host/build.rs"),
        host.join("build.rs"),
    )
    .unwrap();
    fs::copy(
        root.join("tests/fixtures/topologies/shared-feature-host/src/main.rs"),
        host.join("src/main.rs"),
    )
    .unwrap();
    fs::write(
        host.join("Cargo.toml"),
        format!(
            "[package]\nname = \"shared-feature-host\"\nversion = \"0.1.0\"\nedition = \"2024\"\nrust-version = \"1.97.1\"\npublish = false\n\n[dependencies]\nagent = {{ package = \"rust-agent-generated-composition\", path = {integration:?}, default-features = false }}\nhex = {{ version = \"=0.4.3\", default-features = false, features = [\"std\"] }}\n\n[workspace]\n"
        ),
    )
    .unwrap();

    let host_home = temp.path().join("host-cargo-home");
    prepare_cargo_home(&host_home, &registry);
    let host_target = temp.path().join("host-target");
    assert_success(&run_cargo(
        &cargo,
        &rustc,
        &linker,
        &host,
        &host_home,
        &host_target,
        &["generate-lockfile", "--offline"],
    ));
    let final_metadata = hex_metadata(
        &run_cargo(
            &cargo,
            &rustc,
            &linker,
            &host,
            &host_home,
            &host_target,
            &[
                "metadata",
                "--format-version",
                "1",
                "--locked",
                "--offline",
                "--filter-platform",
                TARGET,
            ],
        ),
        &host.join("Cargo.lock"),
    );
    assert_eq!(final_metadata.selector, standalone_metadata.selector);
    assert_eq!(final_metadata.features, ["alloc", "std"]);
    let host_build = run_cargo(
        &cargo,
        &rustc,
        &linker,
        &host,
        &host_home,
        &host_target,
        &["build", "--target", TARGET, "--locked", "--offline", "-vv"],
    );
    let final_observed = rustc_features(&host_build, "hex");
    assert_eq!(final_observed, final_metadata.features);
    let binary = host_target.join(TARGET).join("debug/shared-feature-host");
    let execution = Command::new(binary).env_clear().output().unwrap();
    assert_success(&execution);
    let stdout = String::from_utf8(execution.stdout).unwrap();
    assert!(stdout.contains("fixture-response:shared-feature:product-generated-marker"));

    let standalone_graph = unit_graph(
        &planner,
        &build_triple,
        &standalone_metadata,
        standalone_observed,
    );
    let final_graph = unit_graph(
        &planner,
        &build_triple,
        &final_metadata,
        final_metadata.features.clone(),
    );
    let observed_graph = unit_graph(&planner, &build_triple, &final_metadata, final_observed);
    let requester = product_selector(&host, &build_triple, false);
    let policy = HostFeatureUnionPolicy {
        schema: 1,
        entries: vec![HostFeaturePolicyEntry {
            unit: final_metadata.selector.clone(),
            baseline_features: ["alloc".into()].into_iter().collect(),
            additive_features: ["std".into()].into_iter().collect(),
            allowed_added_units: vec![],
            allowed_added_edges: vec![],
            accounting: FeatureAccountingMode::CompositionConservative,
            composition_effects: BTreeSet::new(),
            product_host_effects: BTreeSet::new(),
            build_requirements: BuildRequirements::default(),
            audit_ref: "tests/fixtures/topologies/shared-feature-host".into(),
            evidence: vec![],
        }],
    }
    .normalize()
    .unwrap();
    let stages = HostFeaturePolicyStageDigests::for_policy(Some(&policy));
    let observations: BTreeMap<_, _> = [(
        final_metadata.selector.clone(),
        HostFeatureUnitObservation {
            feature_requesters: [requester].into_iter().collect(),
            added_units: vec![],
            added_edges: vec![],
            runtime_effects: BTreeSet::new(),
            build_requirements: BuildRequirements::default(),
            has_generated_output: false,
            has_native_link_output: false,
        },
    )]
    .into_iter()
    .collect();
    let host_root_effects = ["host-bridge".into()].into_iter().collect();
    let build_contribution = ProductBuildContribution {
        unit: product_selector(&host, &build_triple, true),
        build_requirements: BuildRequirements::default(),
        downstream_runtime_effects: ["host-bridge".into()].into_iter().collect(),
    };
    let receipt = verify_development_host_feature_union(&DevelopmentHostFeatureVerification {
        standalone_graph: &standalone_graph,
        final_graph: &final_graph,
        observed_graph: &observed_graph,
        first_party_units: &BTreeSet::new(),
        policy: Some(&policy),
        stage_policy_digests: &stages,
        observations: &observations,
        composition_compiled_runtime_effects: &generated.manifest.compiled_runtime_effects,
        host_root_runtime_effects: &host_root_effects,
        product_build_contributions: std::slice::from_ref(&build_contribution),
    })
    .unwrap();

    assert!(!receipt.deployable);
    assert_ne!(
        receipt.standalone_unit_graph_digest,
        receipt.final_unit_graph_digest
    );
    assert_eq!(
        receipt.final_unit_graph_digest,
        receipt.observed_unit_graph_digest
    );
    assert_eq!(receipt.policy_digest.as_deref(), Some(policy.digest()));
    assert_eq!(stages.pre, stages.build_host);
    assert_eq!(stages.build_host, stages.post);
    assert_eq!(receipt.deltas.len(), 1);
    assert_eq!(
        receipt.deltas[0].added_features,
        ["std".into()].into_iter().collect()
    );
    assert_eq!(
        receipt.product_build_contributions[0].downstream_runtime_effects,
        host_root_effects
    );
    assert_eq!(receipt.product_compiled_runtime_effects, host_root_effects);
    let production = verify_production_host_feature_union(&DevelopmentHostFeatureVerification {
        standalone_graph: &standalone_graph,
        final_graph: &final_graph,
        observed_graph: &observed_graph,
        first_party_units: &BTreeSet::new(),
        policy: Some(&policy),
        stage_policy_digests: &stages,
        observations: &observations,
        composition_compiled_runtime_effects: &generated.manifest.compiled_runtime_effects,
        host_root_runtime_effects: &host_root_effects,
        product_build_contributions: &[build_contribution],
    })
    .unwrap();
    assert!(production.receipt().deployable);
    assert_ne!(production.receipt().digest, receipt.digest);

    let first_party = [final_metadata.selector.clone()].into_iter().collect();
    let rejected = verify_development_host_feature_union(&DevelopmentHostFeatureVerification {
        standalone_graph: &standalone_graph,
        final_graph: &final_graph,
        observed_graph: &observed_graph,
        first_party_units: &first_party,
        policy: Some(&policy),
        stage_policy_digests: &stages,
        observations: &observations,
        composition_compiled_runtime_effects: &generated.manifest.compiled_runtime_effects,
        host_root_runtime_effects: &host_root_effects,
        product_build_contributions: &[],
    });
    assert!(matches!(
        rejected,
        Err(HostFeaturePolicyError::FirstPartyFeatureDelta(_))
    ));
}
