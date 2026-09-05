use std::{collections::BTreeMap, env, ffi::OsString, fs, path::PathBuf, process::Command};

use rust_agent_build_executor::{
    BuildArtifactSelector, BuildArtifactTarget, BuildEnforcementContext,
    BuildEnforcementEnvironment, BuildEnforcementExecutable, BuildEnforcementIdentity,
    BuildEnforcementReadInput, BuildEnforcementToolchain, BuildPanicStrategy,
    DerivedExecutablePolicy, ProductionArtifactKind, ProductionBuildManifestInput,
    ProductionBuildOptionsIdentity, ProductionCargoInvocationIdentity,
    ProductionEnforcementResultIdentity, ProductionSandboxBackend,
    create_production_artifact_staging, production_artifact_record,
    write_production_build_manifest,
};
use rust_agent_composition::{ComposeOptions, compose};
use tempfile::TempDir;

fn tool(name: &str) -> PathBuf {
    let selected = Command::new("rustup")
        .args(["which", name])
        .output()
        .unwrap();
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

fn digest(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

#[test]
fn production_manifest_recomputes_identity_and_accounts_for_the_closed_artifact_tree() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let temp = TempDir::new().unwrap();
    let generated = compose(&ComposeOptions {
        workspace_root: workspace.clone(),
        profile_path: workspace.join("tests/fixtures/profiles/minimal.toml"),
        catalog_trust_policy_path: workspace.join("tests/fixtures/catalog-trust.toml"),
        output_root: temp.path().join("compositions"),
        rustc_path: tool("rustc"),
        cargo_path: tool("cargo"),
        registry_cache_path: None,
        custom_target_spec_path: None,
    })
    .unwrap();
    let artifact_parent = temp.path().join("artifacts");
    fs::create_dir(&artifact_parent).unwrap();
    let artifact_dir = create_production_artifact_staging(&artifact_parent).unwrap();
    fs::write(
        artifact_dir.join("libagent.rlib"),
        b"verified production artifact",
    )
    .unwrap();
    let artifact = production_artifact_record(
        &artifact_dir,
        "libagent.rlib",
        ProductionArtifactKind::RustLibrary,
        &generated.manifest.target,
    )
    .unwrap();
    let selector = BuildArtifactSelector {
        package: "rust-agent-generated-composition".into(),
        target: BuildArtifactTarget::Library,
    };
    let context = BuildEnforcementContext {
        schema: 1,
        build_triple: generated.manifest.target.clone(),
        target: generated.manifest.target.clone(),
        target_facts_digest: generated.manifest.target_fact_digest.clone(),
        custom_target_spec_digest: None,
        cargo_resolution_digest: generated.manifest.cargo_resolution_digest.clone(),
        cargo_config_digest: digest(1),
        profile: "release".into(),
        artifact_selector: selector.clone(),
        panic_strategy: BuildPanicStrategy::Unwind,
        rustc_settings_digest: digest(2),
        prefix_remap_schema: 1,
    };
    let executable = |id: &str, byte| BuildEnforcementExecutable {
        id: id.into(),
        sha256: digest(byte),
        version: "1.97.1".into(),
        logical_mount: format!("/rust-agent/toolchain/bin/{id}"),
    };
    let enforcement = BuildEnforcementIdentity {
        schema: 2,
        backend: ProductionSandboxBackend::LinuxLandlockSeccomp,
        backend_semantic_version: 3,
        context,
        toolchain: BuildEnforcementToolchain {
            cargo: executable("cargo", 3),
            rustc: executable("rustc", 4),
            sysroot: BuildEnforcementReadInput {
                id: "rust-sysroot".into(),
                tree_digest: digest(5),
                logical_mount: "/rust-agent/toolchain".into(),
            },
        },
        executables: vec![],
        host_linker: None,
        read_inputs: vec![],
        environment: Vec::<BuildEnforcementEnvironment>::new(),
        derived_executable: DerivedExecutablePolicy {
            roots: vec!["/rust-agent/target".into()],
            inherit_sandbox: true,
        },
        deterministic_environment: BTreeMap::from([
            ("LANG".into(), "C.UTF-8".into()),
            ("LC_ALL".into(), "C.UTF-8".into()),
            ("SOURCE_DATE_EPOCH".into(), "0".into()),
        ]),
    };
    let graph_digest = digest(10);
    let input = ProductionBuildManifestInput {
        composition: generated.manifest.clone(),
        build_requirements: generated.manifest.build_requirements.clone(),
        effective_compiled_runtime_effects: generated.manifest.compiled_runtime_effects.clone(),
        build_enforcement_identity: enforcement,
        enforcement_result: ProductionEnforcementResultIdentity {
            schema: 1,
            build_input_content_digest: digest(7),
            planned_unit_graph_digest: graph_digest.clone(),
            observed_unit_graph_digest: graph_digest,
            cargo_messages_digest: digest(15),
            filesystem_enforcement: "closed-world-read-write-exec".into(),
            network_enforcement: "isolated".into(),
            descendant_enforcement: "inherited".into(),
        },
        build_options: ProductionBuildOptionsIdentity {
            schema: 1,
            host_integration: false,
            build_kind: generated.manifest.build_kind,
            composition_profile: generated.manifest.profile.clone(),
            cargo_profile: "release".into(),
            target: generated.manifest.target.clone(),
            artifact_selector: selector,
            panic_strategy: BuildPanicStrategy::Unwind,
            locked: true,
            offline: true,
            jobs: 1,
        },
        cargo_invocation: ProductionCargoInvocationIdentity {
            schema: 1,
            arguments: vec!["build".into(), "--locked".into(), "--offline".into()],
            environment: BTreeMap::new(),
            working_directory: "/rust-agent/workspace".into(),
        },
        entry_artifact: artifact.path.clone(),
        artifacts: vec![artifact],
        postprocessor: None,
        gates: vec![
            "production-sandbox-verified".into(),
            "artifact-tree-accounted".into(),
            "cyclonedx-sbom-emitted".into(),
        ],
    };
    let manifest =
        write_production_build_manifest(&artifact_dir, &generated.path.join("Cargo.lock"), input)
            .unwrap();
    manifest
        .verify(
            &artifact_dir,
            false,
            Some(&generated.manifest),
            Some(&manifest.build_enforcement_identity),
        )
        .unwrap();

    let serialized = serde_json::to_string(&manifest).unwrap();
    assert!(!serialized.contains("attestation-file"));
    assert!(!serialized.contains("build-execution-policy-digest"));
    assert!(!serialized.contains("trusted-signers"));
    assert!(!serialized.contains("host-build-input-closure-digest"));
    assert!(!serialized.contains("sandbox-observation-digest"));

    fs::write(artifact_dir.join("libagent.rlib"), b"tampered").unwrap();
    assert!(manifest.verify(&artifact_dir, false, None, None).is_err());
    fs::write(
        artifact_dir.join("libagent.rlib"),
        b"verified production artifact",
    )
    .unwrap();
    fs::write(artifact_dir.join("unaccounted"), b"extra").unwrap();
    assert!(manifest.verify(&artifact_dir, false, None, None).is_err());
    fs::remove_file(artifact_dir.join("unaccounted")).unwrap();

    let mut security_drift = manifest.clone();
    security_drift.composition.deployable = !security_drift.composition.deployable;
    security_drift.composition_manifest_digest = hex::encode(
        rust_agent_composition::canonical::domain_hash(
            b"rust-agent-composition-manifest-identity-v1\0",
            &security_drift.composition,
        )
        .unwrap(),
    );
    security_drift.build_manifest_digest.clear();
    security_drift.build_output_digest.clear();
    security_drift.finalize_digests().unwrap();
    assert_ne!(
        manifest.build_manifest_digest,
        security_drift.build_manifest_digest
    );
    assert_ne!(
        manifest.build_output_digest,
        security_drift.build_output_digest
    );

    let mut forged = manifest.clone();
    forged.artifacts[0].digest = digest(99);
    assert!(forged.verify(&artifact_dir, false, None, None).is_err());
}
