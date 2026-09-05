#![cfg(target_os = "linux")]

use std::os::unix::fs::PermissionsExt as _;
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::OsString,
    fs,
    path::PathBuf,
    process::Command,
};

use ed25519_dalek::{Signer, SigningKey};
use rust_agent_build_executor::{
    BuildArtifactSelector, BuildArtifactTarget, BuildEnforcementContext, BuildPanicStrategy,
    CanonicalSnapshotMetadataContract, CargoCompilationKind, CargoCompileMode, CargoCrateKind,
    CargoPackageIdentity, CargoPackageSource, CargoUnit, CargoUnitGraphPlannerIdentity,
    CargoUnitSelector, DerivedExecutablePolicy, DevelopmentHostFeatureVerification,
    HostBuildClosureContent, HostBuildClosureItem, HostBuildClosureItemRole, HostBuildInputClosure,
    HostCargoUnitGraph, HostFeaturePolicyClosure, HostFeaturePolicyStageDigests,
    LinuxSandboxBackendIdentity, LinuxSandboxRuntimeIdentity, LinuxSandboxRuntimeSymlink,
    ProductionArtifactKind, ProductionAttestationError, ProductionAttestationPolicy,
    ProductionBuildAttestationInput, ProductionBuildExecutionPolicy, ProductionBuildManifestInput,
    ProductionBuildOptionsIdentity, ProductionCargoInvocationIdentity, ProductionCompletionHandle,
    ProductionCompletionHandlePayload, ProductionEnforcementResultIdentity,
    ProductionExecutionEvidence, ProductionFetchPolicy, ProductionFetchRedirectPolicy,
    ProductionIntegrationPostInput, ProductionOperationKind, ProductionSandboxBackend,
    ProductionToolIdentity, ProductionToolchain, ProductionTreeIdentity, SigningHelper,
    TrustedSigner, create_production_artifact_staging, create_production_build_attestation_payload,
    create_production_integration_post_payload, create_production_integration_pre_receipt,
    prepare_production_build_attestation_publication, production_artifact_record,
    publish_production_artifact, publish_production_build_attestation,
    read_production_integration_pre_receipt, sign_production_build_attestation,
    verify_production_build_attestation, verify_production_host_feature_union,
    write_production_build_attestation, write_production_build_manifest,
    write_production_integration_post_attestation, write_production_integration_pre_receipt,
};
use rust_agent_composition::{ComposeOptions, compose, metadata::BuildRequirements};
use sha2::{Digest as _, Sha256};
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

fn sha256_file(path: &std::path::Path) -> String {
    hex::encode(Sha256::digest(fs::read(path).unwrap()))
}

fn digest(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

fn sign_digest(key: &SigningKey, digest: &str) -> String {
    hex::encode(key.sign(&hex::decode(digest).unwrap()).to_bytes())
}

fn completion_handle(
    key: &SigningKey,
    payload: &rust_agent_build_executor::ProductionBuildAttestationPayload,
    nonce: String,
) -> ProductionCompletionHandle {
    let payload_digest = payload.digest().unwrap();
    let completion_payload = ProductionCompletionHandlePayload {
        schema: 1,
        operation: payload.operation,
        executor_id: payload.executor_id.clone(),
        workload_identity: payload.workload_identity.clone(),
        verifier_identity_digest: payload.verifier_identity_digest.clone(),
        backend_identity_digest: payload.sandbox_backend_identity_digest.clone(),
        upstream_evidence_digest: payload.evidence_digest.clone(),
        attestation_payload_digest: payload_digest,
        nonce,
    };
    ProductionCompletionHandle {
        signature: sign_digest(key, &completion_payload.digest().unwrap()),
        payload: completion_payload,
        signer_id: "test-ci-signer".into(),
        algorithm: "ed25519".into(),
    }
}

fn write_helper_response(
    helper: &std::path::Path,
    key: &SigningKey,
    payload: &rust_agent_build_executor::ProductionBuildAttestationPayload,
) {
    let response = serde_json::json!({
        "schema": 1,
        "signer-id": "test-ci-signer",
        "algorithm": "ed25519",
        "signature": sign_digest(key, &payload.digest().unwrap()),
    });
    fs::write(
        helper.with_extension("response"),
        serde_json::to_vec(&response).unwrap(),
    )
    .unwrap();
}

fn closure_item(
    role: HostBuildClosureItemRole,
    id: &str,
    path: &str,
    content: HostBuildClosureContent,
) -> HostBuildClosureItem {
    HostBuildClosureItem {
        role,
        id: id.into(),
        logical_path: path.into(),
        metadata_contract: CanonicalSnapshotMetadataContract::ReadOnlyEpochV1,
        content,
    }
}

fn host_closure(
    policy: &rust_agent_build_executor::NormalizedProductionBuildPolicy,
    context: &BuildEnforcementContext,
    composition_hash: &str,
) -> (
    rust_agent_build_executor::NormalizedHostBuildInputClosure,
    rust_agent_build_executor::VerifiedProductionHostFeatureReceipt,
) {
    let package = CargoPackageIdentity {
        name: "rust-agent-generated-composition".into(),
        version: "0.1.0".into(),
        source: CargoPackageSource::Path {
            tree_digest: digest(60),
        },
    };
    let selector = CargoUnitSelector {
        package,
        target_name: "rust_agent_generated_composition".into(),
        compilation_kind: CargoCompilationKind::Target,
        compilation_target: context.target.clone(),
        cargo_target_context: rust_agent_build_executor::CargoUnitTargetContext::CompositionTarget,
        compile_mode: CargoCompileMode::Build,
        profile: context.profile.clone(),
        crate_kind: CargoCrateKind::Library,
    };
    let graph = HostCargoUnitGraph {
        schema: 2,
        planner: CargoUnitGraphPlannerIdentity {
            interface: "cargo-unit-graph-v1".into(),
            cargo_version: "1.97.1".into(),
            cargo_digest: policy.policy().toolchain.cargo.sha256.clone(),
            rustc_version: "1.97.1".into(),
            rustc_digest: policy.policy().toolchain.rustc.sha256.clone(),
        },
        build_triple: context.build_triple.clone(),
        composition_target: context.target.clone(),
        profile: context.profile.clone(),
        nodes: vec![CargoUnit {
            selector: selector.clone(),
            features: vec![],
            build_script: false,
            proc_macro: false,
        }],
        edges: vec![],
    };
    let normalized_graph = graph.normalize().unwrap();
    let first_party_units = BTreeSet::from([selector.clone()]);
    let observations = BTreeMap::new();
    let empty_effects = BTreeSet::new();
    let product_build_contributions = Vec::new();
    let stage_policy_digests = HostFeaturePolicyStageDigests::for_policy(None);
    let feature_verification =
        verify_production_host_feature_union(&DevelopmentHostFeatureVerification {
            standalone_graph: &normalized_graph,
            final_graph: &normalized_graph,
            observed_graph: &normalized_graph,
            first_party_units: &first_party_units,
            policy: None,
            stage_policy_digests: &stage_policy_digests,
            observations: &observations,
            composition_compiled_runtime_effects: &empty_effects,
            host_root_runtime_effects: &empty_effects,
            product_build_contributions: &product_build_contributions,
        })
        .unwrap();
    let record = |role, id, path, value: String| {
        closure_item(
            role,
            id,
            path,
            HostBuildClosureContent::CanonicalRecord {
                bytes_sha256: value.clone(),
                digest: value,
            },
        )
    };
    let requirements = BuildRequirements::default();
    HostBuildInputClosure {
        schema: 1,
        composition_hash: composition_hash.into(),
        host_dependency_alias: "generated-agent".into(),
        generated_package_name: "rust-agent-generated-composition".into(),
        items: vec![
            closure_item(
                HostBuildClosureItemRole::HostRootManifest,
                "host-root-manifest",
                "/rust-agent/closure/host/Cargo.toml",
                HostBuildClosureContent::File { sha256: digest(61) },
            ),
            closure_item(
                HostBuildClosureItemRole::HostCargoLock,
                "host-cargo-lock",
                "/rust-agent/closure/host/Cargo.lock",
                HostBuildClosureContent::File { sha256: digest(62) },
            ),
            closure_item(
                HostBuildClosureItemRole::CargoConfig,
                "cargo-config",
                "/rust-agent/closure/host/.cargo/config.toml",
                HostBuildClosureContent::File {
                    sha256: context.cargo_config_digest.clone(),
                },
            ),
            closure_item(
                HostBuildClosureItemRole::HostPackageTree,
                "host-package-tree",
                "/rust-agent/closure/trees/host",
                HostBuildClosureContent::SnapshotTree {
                    tree_digest: digest(63),
                },
            ),
            closure_item(
                HostBuildClosureItemRole::EmittedCompositionTree,
                "emitted-composition-tree",
                "/rust-agent/closure/trees/generated-agent",
                HostBuildClosureContent::SnapshotTree {
                    tree_digest: digest(60),
                },
            ),
            record(
                HostBuildClosureItemRole::CargoResolutionRecord,
                "cargo-resolution",
                "/rust-agent/closure/records/cargo-resolution.json",
                context.cargo_resolution_digest.clone(),
            ),
            record(
                HostBuildClosureItemRole::TargetFactsRecord,
                "target-facts",
                "/rust-agent/closure/records/target-facts.json",
                context.target_facts_digest.clone(),
            ),
            record(
                HostBuildClosureItemRole::RustcSettingsRecord,
                "rustc-settings",
                "/rust-agent/closure/records/rustc-settings.json",
                context.rustc_settings_digest.clone(),
            ),
            record(
                HostBuildClosureItemRole::ArtifactSelectorRecord,
                "artifact-selector",
                "/rust-agent/closure/records/artifact-selector.json",
                context.artifact_selector.digest().unwrap(),
            ),
        ],
        standalone_unit_graph: graph.clone(),
        final_unit_graph: graph,
        build_context: context.clone(),
        build_requirements: requirements.clone(),
        build_execution_policy_digest: policy.full_digest().into(),
        build_enforcement_identity_digest: policy
            .enforcement_identity_digest(&requirements, context)
            .unwrap(),
        host_feature_policy: HostFeaturePolicyClosure::None,
        unit_feature_delta_digest: feature_verification.receipt().digest.clone(),
    }
    .normalize(policy)
    .map(|closure| (closure, feature_verification))
    .unwrap()
}

#[test]
fn signed_attestation_precedes_artifact_publication_and_rejects_replay() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let temp = TempDir::new().unwrap();
    let rustc = tool("rustc");
    let cargo = tool("cargo");
    let generated = compose(&ComposeOptions {
        workspace_root: workspace.clone(),
        profile_path: workspace.join("tests/fixtures/profiles/minimal.toml"),
        catalog_trust_policy_path: workspace.join("tests/fixtures/catalog-trust.toml"),
        output_root: temp.path().join("compositions"),
        rustc_path: rustc.clone(),
        cargo_path: cargo.clone(),
        registry_cache_path: None,
        custom_target_spec_path: None,
    })
    .unwrap();
    assert!(generated.manifest.build_requirements.executables.is_empty());
    assert!(generated.manifest.build_requirements.read_inputs.is_empty());
    assert!(generated.manifest.build_requirements.environment.is_empty());

    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let public_key = temp.path().join("signer.pub");
    fs::write(&public_key, signing_key.verifying_key().to_bytes()).unwrap();
    let public_key = public_key.canonicalize().unwrap();

    let helper_source = temp.path().join("signing-helper.rs");
    let helper = temp.path().join("signing-helper");
    fs::write(
        &helper_source,
        r#"use std::{env, fs, io::{self, Read}};
fn main() {
    assert_eq!(env::args().skip(1).collect::<Vec<_>>(), ["rust-agent-signing-helper-v1"]);
    let mut request = Vec::new();
    io::stdin().read_to_end(&mut request).unwrap();
    assert!(!request.is_empty());
    fs::write(env::current_exe().unwrap().with_extension("request"), &request).unwrap();
    let response = env::current_exe().unwrap().with_extension("response");
    print!("{}", fs::read_to_string(response).unwrap());
}
"#,
    )
    .unwrap();
    assert!(
        Command::new(&rustc)
            .args(["--edition=2024", "-C", "opt-level=0"])
            .arg(&helper_source)
            .arg("-o")
            .arg(&helper)
            .status()
            .unwrap()
            .success()
    );
    let helper = helper.canonicalize().unwrap();

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
    let policy = ProductionBuildExecutionPolicy {
        schema: 2,
        id: "phase-one-b-test-policy".into(),
        host: "cfg(target_os = \"linux\")".into(),
        backend: ProductionSandboxBackend::LinuxLandlockSeccomp,
        fetch: ProductionFetchPolicy {
            network_endpoints: vec![],
            credential_helper: None,
            tls_ca_bundle: None,
            redirect_policy: ProductionFetchRedirectPolicy::DenyUnlistedOrigin,
        },
        attestation: ProductionAttestationPolicy {
            allowed_executors: vec![
                "rust-agent-build-v1".into(),
                "rust-agent-build-host-v1".into(),
                "rust-agent-integration-post-v1".into(),
            ],
            trusted_signers: vec![TrustedSigner {
                id: "test-ci-signer".into(),
                algorithm: "ed25519".into(),
                public_key: public_key.clone(),
                sha256: sha256_file(&public_key),
            }],
            trusted_reviewer_policies: vec![],
            signing_helper: SigningHelper {
                signer_id: "test-ci-signer".into(),
                path: helper.clone(),
                sha256: sha256_file(&helper),
            },
        },
        toolchain: ProductionToolchain {
            cargo: ProductionToolIdentity {
                path: cargo,
                sha256: digest(3),
                version: "cargo 1.97.1 (test)".into(),
            },
            rustc: ProductionToolIdentity {
                path: rustc,
                sha256: digest(4),
                version: "rustc 1.97.1 (test)".into(),
            },
            sysroot: ProductionTreeIdentity {
                path: "/test/toolchain/sysroot".into(),
                tree_digest: digest(5),
            },
        },
        read_inputs: vec![],
        executables: vec![],
        environment: vec![],
        derived_executable: DerivedExecutablePolicy {
            roots: vec!["target".into()],
            inherit_sandbox: true,
        },
    };
    let policy = policy.normalize().unwrap();
    let enforcement = policy
        .enforcement_identity(&generated.manifest.build_requirements, &context)
        .unwrap();

    let artifact_parent = temp.path().join("artifacts");
    fs::create_dir(&artifact_parent).unwrap();
    let staging = create_production_artifact_staging(&artifact_parent).unwrap();
    fs::write(staging.join("libagent.rlib"), b"attested artifact").unwrap();
    let artifact = production_artifact_record(
        &staging,
        "libagent.rlib",
        ProductionArtifactKind::RustLibrary,
        &generated.manifest.target,
    )
    .unwrap();
    let graph_digest = digest(20);
    let input_content_digest = digest(21);
    let cargo_messages_digest = digest(22);
    let composition_lock = generated.path.join("Cargo.lock");
    let manifest = write_production_build_manifest(
        &staging,
        &composition_lock,
        ProductionBuildManifestInput {
            composition: generated.manifest,
            build_requirements: BuildRequirements::default(),
            effective_compiled_runtime_effects: BTreeSet::new(),
            build_enforcement_identity: enforcement,
            enforcement_result: ProductionEnforcementResultIdentity {
                schema: 1,
                build_input_content_digest: input_content_digest.clone(),
                planned_unit_graph_digest: graph_digest.clone(),
                observed_unit_graph_digest: graph_digest.clone(),
                cargo_messages_digest: cargo_messages_digest.clone(),
                filesystem_enforcement: "closed-world-read-write-exec".into(),
                network_enforcement: "isolated".into(),
                descendant_enforcement: "inherited".into(),
            },
            build_options: ProductionBuildOptionsIdentity {
                schema: 1,
                host_integration: false,
                build_kind: rust_agent_composition::profile::BuildKind::Library,
                composition_profile: "fixture-minimal".into(),
                cargo_profile: "release".into(),
                target: "x86_64-unknown-linux-gnu".into(),
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
                "artifact-tree-accounted".into(),
                "production-sandbox-verified".into(),
            ],
        },
    )
    .unwrap();
    let backend = LinuxSandboxBackendIdentity {
        schema: 1,
        executable: ProductionToolIdentity {
            path: "/test/backend/bwrap".into(),
            sha256: digest(30),
            version: "bubblewrap test".into(),
        },
        launcher_executable: ProductionToolIdentity {
            path: "/test/backend/launcher".into(),
            sha256: digest(31),
            version: "rust-agent-linux-sandbox-launcher 3".into(),
        },
        runtime: LinuxSandboxRuntimeIdentity {
            tree: ProductionTreeIdentity {
                path: "/test/backend/runtime".into(),
                tree_digest: digest(32),
            },
            logical_path: "/rust-agent/runtime".into(),
            interpreter_paths: vec!["/lib64/ld-linux-x86-64.so.2".into()],
            library_paths: vec![],
            null_input_path: "/rust-agent/runtime/empty-stdin".into(),
            symlinks: vec![
                LinuxSandboxRuntimeSymlink {
                    target: "/rust-agent/runtime/empty-stdin".into(),
                    link: "/dev/null".into(),
                },
                LinuxSandboxRuntimeSymlink {
                    target: "/rust-agent/runtime/loader".into(),
                    link: "/lib64/ld-linux-x86-64.so.2".into(),
                },
            ],
        },
    };
    let evidence = ProductionExecutionEvidence {
        schema: 1,
        pre_receipt_digest: None,
        executor_attestation_payload_digest: None,
        host_build_input_closure_digest: digest(40),
        build_input_content_digest: input_content_digest,
        production_input_request_digest: digest(41),
        production_input_observation_digest: digest(42),
        target_facts_request_digest: digest(43),
        target_facts_observation_digest: digest(44),
        standalone_planner_request_digest: digest(45),
        final_planner_request_digest: digest(46),
        standalone_planned_unit_graph_digest: digest(47),
        final_planned_unit_graph_digest: graph_digest.clone(),
        observed_unit_graph_digest: graph_digest,
        unit_feature_delta_digest: digest(48),
        sandbox_observation_digest: digest(49),
        cargo_messages_digest,
        wasm_postprocessor_observation_digest: None,
    };
    let payload = create_production_build_attestation_payload(
        &manifest,
        &policy,
        ProductionBuildAttestationInput {
            operation: ProductionOperationKind::Build,
            executor_id: "rust-agent-build-v1".into(),
            workload_identity: "github-actions:test-workload".into(),
            verifier_identity_digest: digest(50),
            sandbox_backend_identity: (&backend).try_into().unwrap(),
            evidence,
            product_integration: None,
            host_feature_policy: None,
        },
    )
    .unwrap();
    let serialized_payload = serde_json::to_string(&payload).unwrap();
    assert!(!serialized_payload.contains(temp.path().to_str().unwrap()));
    for forbidden_path in [
        "/test/backend/bwrap",
        "/test/backend/launcher",
        "/test/backend/runtime",
        "/test/toolchain/sysroot",
        policy.policy().toolchain.cargo.path.to_str().unwrap(),
        policy.policy().toolchain.rustc.path.to_str().unwrap(),
    ] {
        assert!(!serialized_payload.contains(forbidden_path));
    }
    let payload_digest = payload.digest().unwrap();
    let completion_payload = ProductionCompletionHandlePayload {
        schema: 1,
        operation: payload.operation,
        executor_id: payload.executor_id.clone(),
        workload_identity: payload.workload_identity.clone(),
        verifier_identity_digest: payload.verifier_identity_digest.clone(),
        backend_identity_digest: payload.sandbox_backend_identity_digest.clone(),
        upstream_evidence_digest: payload.evidence_digest.clone(),
        attestation_payload_digest: payload_digest.clone(),
        nonce: digest(51),
    };
    let completion = ProductionCompletionHandle {
        signature: sign_digest(&signing_key, &completion_payload.digest().unwrap()),
        payload: completion_payload,
        signer_id: "test-ci-signer".into(),
        algorithm: "ed25519".into(),
    };
    let response = serde_json::json!({
        "schema": 1,
        "signer-id": "test-ci-signer",
        "algorithm": "ed25519",
        "signature": sign_digest(&signing_key, &payload_digest),
    });
    fs::write(
        helper.with_extension("response"),
        serde_json::to_vec(&response).unwrap(),
    )
    .unwrap();
    let nonce_ledger = temp.path().join("nonce-ledger");
    fs::create_dir(&nonce_ledger).unwrap();
    let attestation_root = temp.path().join("attestations");
    fs::create_dir(&attestation_root).unwrap();
    let signed = sign_production_build_attestation(
        &manifest,
        &policy,
        payload.clone(),
        completion.clone(),
        &nonce_ledger,
        "2026-09-05T00:00:00Z".into(),
        Some("test-transparency-proof".into()),
    )
    .unwrap();
    let prepared = prepare_production_build_attestation_publication(
        &staging,
        &attestation_root,
        &policy,
        &signed,
    )
    .unwrap();
    assert!(!artifact_parent.join(&manifest.build_output_digest).exists());
    assert!(prepared.path().is_file());
    fs::set_permissions(prepared.path(), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        publish_production_artifact(
            &staging,
            &artifact_parent,
            &manifest,
            prepared.artifact_publication_permit(),
        )
        .is_err()
    );
    assert!(!artifact_parent.join(&manifest.build_output_digest).exists());
    fs::set_permissions(prepared.path(), fs::Permissions::from_mode(0o444)).unwrap();
    let publication = publish_production_artifact(
        &staging,
        &artifact_parent,
        &manifest,
        prepared.artifact_publication_permit(),
    )
    .unwrap();
    let artifact_dir = publication.path.clone();
    let attestation = prepared.finalize(&artifact_dir, &policy).unwrap();
    assert_eq!(attestation.attestation().payload_digest, payload_digest);

    let duplicate = create_production_artifact_staging(&artifact_parent).unwrap();
    for relative in [
        "libagent.rlib",
        "rust-agent-sbom.cdx.json",
        "rust-agent-build.json",
    ] {
        fs::copy(artifact_dir.join(relative), duplicate.join(relative)).unwrap();
    }
    let duplicate_prepared = prepare_production_build_attestation_publication(
        &duplicate,
        &attestation_root,
        &policy,
        attestation.attestation(),
    )
    .unwrap();
    let reused = publish_production_artifact(
        &duplicate,
        &artifact_parent,
        &manifest,
        duplicate_prepared.artifact_publication_permit(),
    )
    .unwrap();
    assert!(reused.reused);
    assert!(!duplicate.exists());
    let reused_attestation = duplicate_prepared.finalize(&reused.path, &policy).unwrap();
    assert_eq!(reused_attestation.path(), attestation.path());

    let reused = publish_production_build_attestation(
        &artifact_dir,
        &attestation_root,
        &policy,
        attestation.attestation(),
    )
    .unwrap();
    assert_eq!(reused.path(), attestation.path());
    let verified = verify_production_build_attestation(
        &artifact_dir,
        attestation.path(),
        &policy,
        "github-actions:test-workload",
    )
    .unwrap();
    let (closure, feature_verification) = host_closure(
        &policy,
        &verified.manifest().build_enforcement_identity.context,
        &verified.manifest().composition.composition_hash,
    );
    let receipt = create_production_integration_pre_receipt(
        &closure,
        &policy,
        &verified,
        &feature_verification,
    )
    .unwrap();
    let receipt_path = temp.path().join("integration.pre.json");
    write_production_integration_pre_receipt(&receipt_path, &receipt, &closure, &policy, &verified)
        .unwrap();
    assert_eq!(
        read_production_integration_pre_receipt(&receipt_path, &closure, &policy, &verified)
            .unwrap(),
        receipt
    );
    let mut changed_receipt = receipt.clone();
    changed_receipt.final_unit_graph_digest = digest(65);
    assert!(
        changed_receipt
            .verify(&closure, &policy, &verified)
            .is_err()
    );
    assert!(
        write_production_integration_pre_receipt(
            &receipt_path,
            &receipt,
            &closure,
            &policy,
            &verified,
        )
        .is_err()
    );

    let executor_parent = temp.path().join("executor");
    fs::create_dir(&executor_parent).unwrap();
    let executor_staging = executor_parent.join("staging");
    fs::create_dir(&executor_staging).unwrap();
    fs::copy(
        artifact_dir.join("libagent.rlib"),
        executor_staging.join("libagent.rlib"),
    )
    .unwrap();
    let executor_artifact = production_artifact_record(
        &executor_staging,
        "libagent.rlib",
        ProductionArtifactKind::RustLibrary,
        &manifest.composition.target,
    )
    .unwrap();
    let host_enforcement = policy
        .enforcement_identity(closure.build_requirements(), closure.build_context())
        .unwrap();
    let executor_manifest = write_production_build_manifest(
        &executor_staging,
        &composition_lock,
        ProductionBuildManifestInput {
            composition: manifest.composition.clone(),
            build_requirements: closure.build_requirements().clone(),
            effective_compiled_runtime_effects: manifest.effective_compiled_runtime_effects.clone(),
            build_enforcement_identity: host_enforcement,
            enforcement_result: ProductionEnforcementResultIdentity {
                schema: 1,
                build_input_content_digest: closure.content_identity_digest().into(),
                planned_unit_graph_digest: closure.final_unit_graph_digest().into(),
                observed_unit_graph_digest: closure.final_unit_graph_digest().into(),
                cargo_messages_digest: manifest.enforcement_result.cargo_messages_digest.clone(),
                filesystem_enforcement: "closed-world-read-write-exec".into(),
                network_enforcement: "isolated".into(),
                descendant_enforcement: "inherited".into(),
            },
            build_options: ProductionBuildOptionsIdentity {
                host_integration: true,
                ..manifest.build_options.clone()
            },
            cargo_invocation: manifest.cargo_invocation.clone(),
            entry_artifact: executor_artifact.path.clone(),
            artifacts: vec![executor_artifact],
            postprocessor: None,
            gates: manifest.gates.clone(),
        },
    )
    .unwrap();
    let executor_artifact_dir = executor_parent.join(&executor_manifest.build_output_digest);
    fs::rename(&executor_staging, &executor_artifact_dir).unwrap();
    let mut executor_evidence = payload.evidence.clone();
    executor_evidence.pre_receipt_digest = Some(receipt.digest.clone());
    executor_evidence.host_build_input_closure_digest = closure.digest().into();
    executor_evidence.build_input_content_digest = closure.content_identity_digest().into();
    executor_evidence.standalone_planned_unit_graph_digest =
        closure.standalone_unit_graph_digest().into();
    executor_evidence.final_planned_unit_graph_digest = closure.final_unit_graph_digest().into();
    executor_evidence.observed_unit_graph_digest = closure.final_unit_graph_digest().into();
    executor_evidence.unit_feature_delta_digest = closure.unit_feature_delta_digest().into();
    let executor_payload = create_production_build_attestation_payload(
        &executor_manifest,
        &policy,
        ProductionBuildAttestationInput {
            operation: ProductionOperationKind::BuildHost,
            executor_id: "rust-agent-build-host-v1".into(),
            workload_identity: "github-actions:test-workload".into(),
            verifier_identity_digest: digest(66),
            sandbox_backend_identity: payload.sandbox_backend_identity.clone(),
            evidence: executor_evidence,
            product_integration: Some(feature_verification),
            host_feature_policy: None,
        },
    )
    .unwrap();
    let executor_completion = completion_handle(&signing_key, &executor_payload, digest(67));
    write_helper_response(&helper, &signing_key, &executor_payload);
    let executor = write_production_build_attestation(
        &executor_artifact_dir,
        &attestation_root,
        &policy,
        executor_payload,
        executor_completion,
        &nonce_ledger,
        "2026-09-05T00:00:01Z".into(),
        None,
    )
    .unwrap();
    let post_payload = create_production_integration_post_payload(
        &receipt,
        &closure,
        &policy,
        &verified,
        &executor,
        ProductionIntegrationPostInput {
            executor_id: "rust-agent-integration-post-v1".into(),
            workload_identity: "github-actions:test-workload".into(),
            verifier_identity_digest: digest(68),
        },
    )
    .unwrap();
    let post_completion = completion_handle(&signing_key, &post_payload, digest(69));
    write_helper_response(&helper, &signing_key, &post_payload);
    let post_path = temp.path().join("integration.post.json");
    let post = write_production_integration_post_attestation(
        &post_path,
        &executor_artifact_dir,
        &receipt_path,
        &receipt,
        &closure,
        &policy,
        &verified,
        &executor,
        post_payload,
        post_completion,
        &nonce_ledger,
        "2026-09-05T00:00:02Z".into(),
        None,
    )
    .unwrap();
    assert_eq!(
        post.attestation().payload.operation,
        ProductionOperationKind::IntegrationPost
    );
    let helper_request: serde_json::Value =
        serde_json::from_slice(&fs::read(helper.with_extension("request")).unwrap()).unwrap();
    assert_eq!(
        helper_request
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "completion-handle",
            "operation",
            "payload-digest",
            "protocol",
            "schema",
            "workload-identity",
        ])
    );
    let helper_request_text = serde_json::to_string(&helper_request).unwrap();
    assert!(!helper_request_text.contains("build-execution-policy"));
    assert!(!helper_request_text.contains("sandbox-backend-identity"));
    assert!(!helper_request_text.contains("/test/"));
    let mut forged_post = serde_json::to_value(post.attestation()).unwrap();
    forged_post["payload"]["evidence"]["final-planned-unit-graph-digest"] =
        serde_json::Value::String(digest(70));
    fs::set_permissions(&post_path, fs::Permissions::from_mode(0o644)).unwrap();
    fs::write(&post_path, serde_json::to_vec(&forged_post).unwrap()).unwrap();
    assert!(
        rust_agent_build_executor::verify_production_integration_post_attestation(
            &post_path,
            &executor_artifact_dir,
            &receipt,
            &closure,
            &policy,
            &verified,
            &executor,
            "github-actions:test-workload",
        )
        .is_err()
    );

    let attestation_path = attestation.path().to_owned();
    assert_eq!(
        fs::metadata(&attestation_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o444
    );
    let original_attestation = fs::read(&attestation_path).unwrap();
    let mut tampered = attestation.attestation().clone();
    tampered.signature.replace_range(0..2, "00");
    fs::set_permissions(&attestation_path, fs::Permissions::from_mode(0o644)).unwrap();
    fs::write(&attestation_path, serde_json::to_vec(&tampered).unwrap()).unwrap();
    assert!(
        verify_production_build_attestation(
            &artifact_dir,
            &attestation_path,
            &policy,
            "github-actions:test-workload",
        )
        .is_err()
    );
    fs::write(&attestation_path, original_attestation).unwrap();
    fs::set_permissions(&attestation_path, fs::Permissions::from_mode(0o444)).unwrap();

    let replay_parent = temp.path().join("replay");
    fs::create_dir(&replay_parent).unwrap();
    let replay = replay_parent.join(&manifest.build_output_digest);
    fs::create_dir(&replay).unwrap();
    for relative in [
        "libagent.rlib",
        "rust-agent-sbom.cdx.json",
        "rust-agent-build.json",
    ] {
        fs::copy(artifact_dir.join(relative), replay.join(relative)).unwrap();
    }
    assert!(matches!(
        write_production_build_attestation(
            &replay,
            &attestation_root,
            &policy,
            payload,
            completion,
            &nonce_ledger,
            "2026-09-05T00:00:01Z".into(),
            None,
        ),
        Err(ProductionAttestationError::CompletionReplay)
    ));
    assert!(!replay.join("rust-agent-build-attestation.json").exists());
}
