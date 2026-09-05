#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
use std::{fs, path::Path};

use rust_agent_build_executor::{
    BuildArtifactSelector, BuildArtifactTarget, BuildEnforcementContext, BuildPanicStrategy,
    CanonicalSnapshotMetadataContract, CargoCompilationKind, CargoCompileMode, CargoCrateKind,
    CargoDependencyKind, CargoFetchCacheError, CargoFetchCacheLayout,
    CargoFetchCachePackageLocation, CargoFetchDescendantExecution, CargoFetchError, CargoFetchMode,
    CargoFetchObservation, CargoFetchRequest, CargoPackageIdentity, CargoPackageSource,
    CargoTargetEvaluationDomain, CargoUnit, CargoUnitEdge, CargoUnitGraphPlannerIdentity,
    CargoUnitSelector, DerivedExecutablePolicy, FetchedSourceEvidence, FetchedSourceObservation,
    FetchedSourcePackage, HostBuildClosureContent, HostBuildClosureItem, HostBuildClosureItemRole,
    HostBuildClosureStage, HostBuildInputClosure, HostBuildInputClosureError, HostCargoUnitGraph,
    HostFeaturePolicyClosure, LockedSourceClosure, LockedSourceError, NormalizedCargoFetchRequest,
    NormalizedLockedSourceClosure, NormalizedProductionBuildPolicy, ProductionAttestationPolicy,
    ProductionBuildExecutionPolicy, ProductionFetchPolicy, ProductionFetchRedirectPolicy,
    ProductionFileIdentity, ProductionSandboxBackend, ProductionToolIdentity, ProductionToolchain,
    ProductionTreeIdentity, SigningHelper, SnapshotMaterializationError, TrustedReviewerPolicy,
    TrustedSigner, ValidatedCargoFetchObservation, materialize_cargo_fetch_cache,
    open_verified_cargo_fetch_cache, verify_development_host_closure_stage_chain,
    verify_materialized_cargo_fetch_cache,
};
use rust_agent_composition::{
    CustomTargetSpecRecord,
    metadata::BuildRequirements,
    snapshot::{CanonicalSnapshotEntry, CanonicalSnapshotEntryKind, CanonicalSnapshotTree},
};
use sha2::{Digest, Sha256};

fn digest(byte: char) -> String {
    byte.to_string().repeat(64)
}

fn policy() -> NormalizedProductionBuildPolicy {
    ProductionBuildExecutionPolicy {
        schema: 3,
        id: "ci-linux-hermetic-v1".into(),
        host: "cfg(target_os = \"linux\")".into(),
        backend: ProductionSandboxBackend::LinuxLandlockSeccomp,
        fetch: ProductionFetchPolicy {
            network_endpoints: vec![],
            credential_helper: None,
            tls_ca_bundle: None,
            redirect_policy: ProductionFetchRedirectPolicy::DenyUnlistedOrigin,
        },
        attestation: ProductionAttestationPolicy {
            allowed_executors: vec!["rust-agent-build-host-v1".into()],
            trusted_signers: vec![TrustedSigner {
                id: "ci-runner-2026".into(),
                algorithm: "ed25519".into(),
                public_key: "/runner/keys/ci-runner.pub".into(),
                sha256: digest('1'),
            }],
            trusted_reviewer_policies: vec![TrustedReviewerPolicy {
                id: "cargo-feature-semantics-v1".into(),
                signer_ids: vec!["ci-runner-2026".into()],
                min_signatures: 1,
            }],
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
        host_linker: None,
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
            target: BuildArtifactTarget::Library,
        },
        panic_strategy: BuildPanicStrategy::Unwind,
        rustc_settings_digest: digest('9'),
        prefix_remap_schema: 1,
    }
}

fn package() -> CargoPackageIdentity {
    CargoPackageIdentity {
        name: "host-fixture".into(),
        version: "0.1.0".into(),
        source: CargoPackageSource::Path {
            tree_digest: digest('a'),
        },
    }
}

fn host_selector() -> CargoUnitSelector {
    CargoUnitSelector {
        package: package(),
        target_name: "build-script-build".into(),
        compilation_kind: CargoCompilationKind::BuildHost,
        compilation_target: "x86_64-unknown-linux-gnu".into(),
        cargo_target_context: rust_agent_build_executor::CargoUnitTargetContext::CompositionTarget,
        compile_mode: CargoCompileMode::RunCustomBuild,
        profile: "release".into(),
        crate_kind: CargoCrateKind::CustomBuild,
    }
}

fn target_selector() -> CargoUnitSelector {
    CargoUnitSelector {
        package: package(),
        target_name: "host_fixture".into(),
        compilation_kind: CargoCompilationKind::Target,
        compilation_target: "aarch64-unknown-linux-gnu".into(),
        cargo_target_context: rust_agent_build_executor::CargoUnitTargetContext::CompositionTarget,
        compile_mode: CargoCompileMode::Build,
        profile: "release".into(),
        crate_kind: CargoCrateKind::Library,
    }
}

fn unit_graph() -> HostCargoUnitGraph {
    HostCargoUnitGraph {
        schema: 2,
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
        nodes: vec![
            CargoUnit {
                selector: host_selector(),
                features: vec!["build".into()],
                build_script: true,
                proc_macro: false,
            },
            CargoUnit {
                selector: target_selector(),
                features: vec!["runtime".into()],
                build_script: false,
                proc_macro: false,
            },
        ],
        edges: vec![CargoUnitEdge {
            dependent: target_selector(),
            dependency: host_selector(),
            dependency_kind: CargoDependencyKind::Build,
            target_evaluation_domain: CargoTargetEvaluationDomain::BuildHost,
        }],
    }
}

fn file(role: HostBuildClosureItemRole, id: &str, path: &str, byte: char) -> HostBuildClosureItem {
    HostBuildClosureItem {
        role,
        id: id.into(),
        logical_path: path.into(),
        metadata_contract: CanonicalSnapshotMetadataContract::ReadOnlyEpochV1,
        content: HostBuildClosureContent::File {
            sha256: digest(byte),
        },
    }
}

fn tree(role: HostBuildClosureItemRole, id: &str, path: &str, byte: char) -> HostBuildClosureItem {
    HostBuildClosureItem {
        role,
        id: id.into(),
        logical_path: path.into(),
        metadata_contract: CanonicalSnapshotMetadataContract::ReadOnlyEpochV1,
        content: HostBuildClosureContent::SnapshotTree {
            tree_digest: digest(byte),
        },
    }
}

fn record(
    role: HostBuildClosureItemRole,
    id: &str,
    path: &str,
    byte: char,
) -> HostBuildClosureItem {
    HostBuildClosureItem {
        role,
        id: id.into(),
        logical_path: path.into(),
        metadata_contract: CanonicalSnapshotMetadataContract::ReadOnlyEpochV1,
        content: HostBuildClosureContent::CanonicalRecord {
            digest: digest(byte),
            bytes_sha256: digest(byte),
        },
    }
}

fn record_digest(
    role: HostBuildClosureItemRole,
    id: &str,
    path: &str,
    digest: String,
) -> HostBuildClosureItem {
    HostBuildClosureItem {
        role,
        id: id.into(),
        logical_path: path.into(),
        metadata_contract: CanonicalSnapshotMetadataContract::ReadOnlyEpochV1,
        content: HostBuildClosureContent::CanonicalRecord {
            bytes_sha256: digest.clone(),
            digest,
        },
    }
}

fn closure(policy: &NormalizedProductionBuildPolicy) -> HostBuildInputClosure {
    let context = context();
    let requirements = BuildRequirements::default();
    HostBuildInputClosure {
        schema: 1,
        composition_hash: digest('b'),
        host_dependency_alias: "generated-agent".into(),
        generated_package_name: "rust-agent-composition-fixture".into(),
        items: vec![
            file(
                HostBuildClosureItemRole::HostRootManifest,
                "host-root-manifest",
                "/rust-agent/closure/host/Cargo.toml",
                'c',
            ),
            file(
                HostBuildClosureItemRole::HostCargoLock,
                "host-cargo-lock",
                "/rust-agent/closure/host/Cargo.lock",
                'd',
            ),
            file(
                HostBuildClosureItemRole::CargoConfig,
                "cargo-config",
                "/rust-agent/closure/host/.cargo/config.toml",
                '8',
            ),
            tree(
                HostBuildClosureItemRole::HostPackageTree,
                "host-package-tree",
                "/rust-agent/closure/trees/host-fixture",
                'e',
            ),
            tree(
                HostBuildClosureItemRole::EmittedCompositionTree,
                "emitted-composition-tree",
                "/rust-agent/closure/trees/generated-agent",
                'f',
            ),
            record(
                HostBuildClosureItemRole::CargoResolutionRecord,
                "cargo-resolution",
                "/rust-agent/closure/records/cargo-resolution.json",
                '7',
            ),
            record(
                HostBuildClosureItemRole::TargetFactsRecord,
                "target-facts",
                "/rust-agent/closure/records/target-facts.json",
                '6',
            ),
            record(
                HostBuildClosureItemRole::RustcSettingsRecord,
                "rustc-settings",
                "/rust-agent/closure/records/rustc-settings.json",
                '9',
            ),
            record_digest(
                HostBuildClosureItemRole::ArtifactSelectorRecord,
                "artifact-selector",
                "/rust-agent/closure/records/artifact-selector.json",
                context.artifact_selector.digest().unwrap(),
            ),
        ],
        standalone_unit_graph: unit_graph(),
        final_unit_graph: unit_graph(),
        build_context: context.clone(),
        build_requirements: requirements.clone(),
        build_execution_policy_digest: policy.full_digest().into(),
        build_enforcement_identity_digest: policy
            .enforcement_identity_digest(&requirements, &context)
            .unwrap(),
        host_feature_policy: HostFeaturePolicyClosure::None,
        unit_feature_delta_digest: digest('0'),
    }
}

#[test]
fn closure_digest_is_order_independent_and_stage_chain_is_exact() {
    let policy = policy();
    let closure = closure(&policy);
    let normalized = closure.normalize(&policy).unwrap();
    let mut reordered = closure.clone();
    reordered.items.reverse();
    reordered.standalone_unit_graph.nodes.reverse();
    reordered.final_unit_graph.nodes.reverse();
    let reordered = reordered.normalize(&policy).unwrap();
    assert_eq!(normalized.digest(), reordered.digest());
    assert_eq!(normalized.items(), reordered.items());
    assert_eq!(
        normalized.digest(),
        "2689a1d3a63674d743a54f8876a5acea09fe06452d5d4ab756a02b82fabc7072"
    );

    let pre = normalized
        .development_stage_receipt(HostBuildClosureStage::Pre)
        .unwrap();
    let build_host = normalized
        .development_stage_receipt(HostBuildClosureStage::BuildHost)
        .unwrap();
    let post = normalized
        .development_stage_receipt(HostBuildClosureStage::Post)
        .unwrap();
    verify_development_host_closure_stage_chain(&pre, &build_host, &post).unwrap();
    assert!(!pre.deployable && !build_host.deployable && !post.deployable);
    assert_eq!(
        pre.host_build_input_closure_digest,
        build_host.host_build_input_closure_digest
    );
}

#[test]
fn item_and_context_drift_fail_before_stage_receipts() {
    let policy = policy();
    let baseline = closure(&policy).normalize(&policy).unwrap();

    let mut lock_drift = closure(&policy);
    let lock = lock_drift
        .items
        .iter_mut()
        .find(|item| item.role == HostBuildClosureItemRole::HostCargoLock)
        .unwrap();
    lock.content = HostBuildClosureContent::File {
        sha256: digest('1'),
    };
    assert_ne!(
        lock_drift.normalize(&policy).unwrap().digest(),
        baseline.digest()
    );

    let mut record_bytes_drift = closure(&policy);
    let record = record_bytes_drift
        .items
        .iter_mut()
        .find(|item| item.role == HostBuildClosureItemRole::CargoResolutionRecord)
        .unwrap();
    let HostBuildClosureContent::CanonicalRecord { bytes_sha256, .. } = &mut record.content else {
        panic!("Cargo resolution item must be a canonical record");
    };
    *bytes_sha256 = digest('1');
    assert_ne!(
        record_bytes_drift.normalize(&policy).unwrap().digest(),
        baseline.digest()
    );

    let mut config_drift = closure(&policy);
    config_drift
        .items
        .iter_mut()
        .find(|item| item.role == HostBuildClosureItemRole::CargoConfig)
        .unwrap()
        .content = HostBuildClosureContent::File {
        sha256: digest('1'),
    };
    assert!(matches!(
        config_drift.normalize(&policy),
        Err(HostBuildInputClosureError::ContextItemMismatch { .. })
    ));

    let mut target_drift = closure(&policy);
    target_drift.build_context.target = "wasm32-unknown-unknown".into();
    assert!(matches!(
        target_drift.normalize(&policy),
        Err(HostBuildInputClosureError::BuildEnforcementIdentityMismatch)
    ));

    let mut graph_drift = closure(&policy);
    graph_drift.final_unit_graph.profile = "dev".into();
    assert!(matches!(
        graph_drift.normalize(&policy),
        Err(HostBuildInputClosureError::UnitGraphContextMismatch
            | HostBuildInputClosureError::UnitGraph(_))
    ));
}

#[test]
fn required_roles_paths_content_and_custom_specs_are_closed() {
    let policy = policy();
    let mut missing_lock = closure(&policy);
    missing_lock
        .items
        .retain(|item| item.role != HostBuildClosureItemRole::HostCargoLock);
    assert!(matches!(
        missing_lock.normalize(&policy),
        Err(HostBuildInputClosureError::InvalidRoleCardinality {
            role: HostBuildClosureItemRole::HostCargoLock,
            ..
        })
    ));

    let mut missing_artifact_selector = closure(&policy);
    missing_artifact_selector
        .items
        .retain(|item| item.role != HostBuildClosureItemRole::ArtifactSelectorRecord);
    assert!(matches!(
        missing_artifact_selector.normalize(&policy),
        Err(HostBuildInputClosureError::InvalidRoleCardinality {
            role: HostBuildClosureItemRole::ArtifactSelectorRecord,
            ..
        })
    ));

    let mut artifact_selector_drift = closure(&policy);
    artifact_selector_drift
        .items
        .iter_mut()
        .find(|item| item.role == HostBuildClosureItemRole::ArtifactSelectorRecord)
        .unwrap()
        .content = HostBuildClosureContent::CanonicalRecord {
        digest: digest('1'),
        bytes_sha256: digest('1'),
    };
    assert!(matches!(
        artifact_selector_drift.normalize(&policy),
        Err(HostBuildInputClosureError::ContextItemMismatch { .. })
    ));

    let mut escape = closure(&policy);
    escape.items[0].logical_path = "/rust-agent/closure/../secret".into();
    assert!(matches!(
        escape.normalize(&policy),
        Err(HostBuildInputClosureError::InvalidLogicalPath(_))
    ));
    for invalid_path in [
        "/rust-agent/closure/host\\Cargo.toml",
        "/rust-agent/closure/host/Cargo\n.toml",
        "/rust-agent/closure/host/Cargó.toml",
    ] {
        let mut invalid = closure(&policy);
        invalid.items[0].logical_path = invalid_path.into();
        assert!(matches!(
            invalid.normalize(&policy),
            Err(HostBuildInputClosureError::InvalidLogicalPath(_))
        ));
    }

    let mut duplicate = closure(&policy);
    duplicate.items[1].logical_path = duplicate.items[0].logical_path.clone();
    assert!(matches!(
        duplicate.normalize(&policy),
        Err(HostBuildInputClosureError::DuplicateItem(_))
    ));

    let mut case_collision = closure(&policy);
    case_collision.items[1].logical_path = case_collision.items[0]
        .logical_path
        .replace("Cargo.toml", "cargo.toml");
    assert!(matches!(
        case_collision.normalize(&policy),
        Err(HostBuildInputClosureError::LogicalPathCaseCollision { .. })
    ));

    let mut wrong_content = closure(&policy);
    wrong_content.items[0].content = HostBuildClosureContent::SnapshotTree {
        tree_digest: digest('1'),
    };
    assert!(matches!(
        wrong_content.normalize(&policy),
        Err(HostBuildInputClosureError::ItemContentMismatch { .. })
    ));

    let mut missing_custom_spec = closure(&policy);
    missing_custom_spec.build_context.custom_target_spec_digest = Some(digest('1'));
    missing_custom_spec.build_enforcement_identity_digest = policy
        .enforcement_identity_digest(
            &missing_custom_spec.build_requirements,
            &missing_custom_spec.build_context,
        )
        .unwrap();
    assert!(matches!(
        missing_custom_spec.normalize(&policy),
        Err(HostBuildInputClosureError::InvalidRoleCardinality {
            role: HostBuildClosureItemRole::CustomTargetSpec,
            ..
        })
    ));

    let spec_bytes = br#"{"arch":"aarch64","llvm-target":"aarch64-unknown-linux-gnu"}"#;
    let spec = CustomTargetSpecRecord::from_raw_bytes(
        &missing_custom_spec.build_context.target,
        spec_bytes,
    )
    .unwrap();
    let mut custom_target = closure(&policy);
    custom_target.build_context.custom_target_spec_digest =
        Some(spec.custom_target_spec_digest.clone());
    custom_target.items.push(HostBuildClosureItem {
        role: HostBuildClosureItemRole::CustomTargetSpec,
        id: "custom-target-spec".into(),
        logical_path: format!("/rust-agent/closure/host/{}", spec.snapshot_path),
        metadata_contract: CanonicalSnapshotMetadataContract::ReadOnlyEpochV1,
        content: HostBuildClosureContent::CustomTargetSpec {
            digest: spec.custom_target_spec_digest.clone(),
            bytes_sha256: spec.raw_bytes_sha256.clone(),
        },
    });
    custom_target.build_enforcement_identity_digest = policy
        .enforcement_identity_digest(
            &custom_target.build_requirements,
            &custom_target.build_context,
        )
        .unwrap();
    custom_target.normalize(&policy).unwrap();

    let mut wrong_custom_content = custom_target;
    wrong_custom_content
        .items
        .iter_mut()
        .find(|item| item.role == HostBuildClosureItemRole::CustomTargetSpec)
        .unwrap()
        .content = HostBuildClosureContent::File {
        sha256: spec.raw_bytes_sha256,
    };
    assert!(matches!(
        wrong_custom_content.normalize(&policy),
        Err(HostBuildInputClosureError::ItemContentMismatch {
            role: HostBuildClosureItemRole::CustomTargetSpec,
            ..
        })
    ));
}

#[test]
fn policy_planner_and_feature_evidence_are_cross_checked() {
    let policy = policy();
    let mut wrong_policy = closure(&policy);
    wrong_policy.build_execution_policy_digest = digest('1');
    assert!(matches!(
        wrong_policy.normalize(&policy),
        Err(HostBuildInputClosureError::BuildPolicyDigestMismatch)
    ));

    let mut wrong_enforcement = closure(&policy);
    wrong_enforcement.build_enforcement_identity_digest = digest('1');
    assert!(matches!(
        wrong_enforcement.normalize(&policy),
        Err(HostBuildInputClosureError::BuildEnforcementIdentityMismatch)
    ));

    let mut wrong_planner = closure(&policy);
    wrong_planner.final_unit_graph.planner.cargo_digest = digest('1');
    wrong_planner.standalone_unit_graph.planner.cargo_digest = digest('1');
    assert!(matches!(
        wrong_planner.normalize(&policy),
        Err(HostBuildInputClosureError::PlannerToolchainMismatch)
    ));

    let reviewer_digest = policy
        .reviewer_policy_digest("cargo-feature-semantics-v1")
        .unwrap()
        .unwrap();
    let mut with_evidence = closure(&policy);
    with_evidence.items.push(HostBuildClosureItem {
        role: HostBuildClosureItemRole::FeatureSemanticsEvidence,
        id: "feature-evidence".into(),
        logical_path: "/rust-agent/closure/evidence/feature-evidence.json".into(),
        metadata_contract: CanonicalSnapshotMetadataContract::ReadOnlyEpochV1,
        content: HostBuildClosureContent::SignedEvidence {
            bytes_digest: digest('1'),
            reviewer_policy: "cargo-feature-semantics-v1".into(),
            reviewer_policy_digest: reviewer_digest,
            signature_set_digest: digest('2'),
        },
    });
    with_evidence.host_feature_policy = HostFeaturePolicyClosure::Policy {
        digest: digest('3'),
        evidence_ids: vec!["feature-evidence".into()],
    };
    with_evidence.normalize(&policy).unwrap();

    let mut unreferenced = with_evidence.clone();
    unreferenced.host_feature_policy = HostFeaturePolicyClosure::None;
    assert!(matches!(
        unreferenced.normalize(&policy),
        Err(HostBuildInputClosureError::HostFeaturePolicyEvidenceMismatch)
    ));

    let mut untrusted = with_evidence;
    if let HostBuildClosureContent::SignedEvidence {
        reviewer_policy_digest,
        ..
    } = &mut untrusted.items.last_mut().unwrap().content
    {
        *reviewer_policy_digest = digest('4');
    }
    assert!(matches!(
        untrusted.normalize(&policy),
        Err(HostBuildInputClosureError::FeatureEvidenceTrustMismatch(_))
    ));
}

#[test]
fn closed_json_and_stage_receipt_mutations_fail_closed() {
    let policy = policy();
    let base_closure = closure(&policy);
    let json = serde_json::to_string(&base_closure).unwrap();
    HostBuildInputClosure::from_json(&json)
        .unwrap()
        .normalize(&policy)
        .unwrap();
    let unknown = json.replacen('{', "{\"ambient-home\":true,", 1);
    assert!(matches!(
        HostBuildInputClosure::from_json(&unknown),
        Err(HostBuildInputClosureError::Json(_))
    ));
    let mut missing_record_bytes: serde_json::Value = serde_json::from_str(&json).unwrap();
    let record = missing_record_bytes["items"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|item| item["content"]["kind"] == "canonical-record")
        .unwrap();
    record["content"]
        .as_object_mut()
        .unwrap()
        .remove("bytes-sha256");
    assert!(matches!(
        HostBuildInputClosure::from_json(&serde_json::to_string(&missing_record_bytes).unwrap()),
        Err(HostBuildInputClosureError::Json(_))
    ));

    let normalized = base_closure.normalize(&policy).unwrap();
    let pre = normalized
        .development_stage_receipt(HostBuildClosureStage::Pre)
        .unwrap();
    let build_host = normalized
        .development_stage_receipt(HostBuildClosureStage::BuildHost)
        .unwrap();
    let post = normalized
        .development_stage_receipt(HostBuildClosureStage::Post)
        .unwrap();

    let mut deployable = pre.clone();
    deployable.deployable = true;
    assert!(matches!(
        deployable.verify(),
        Err(HostBuildInputClosureError::DevelopmentReceiptDeployable)
    ));

    assert!(matches!(
        verify_development_host_closure_stage_chain(&build_host, &pre, &post),
        Err(HostBuildInputClosureError::ReceiptStageMismatch)
    ));

    let mut other_closure = closure(&policy);
    other_closure.unit_feature_delta_digest = digest('1');
    let other_build = other_closure
        .normalize(&policy)
        .unwrap()
        .development_stage_receipt(HostBuildClosureStage::BuildHost)
        .unwrap();
    assert!(matches!(
        verify_development_host_closure_stage_chain(&pre, &other_build, &post),
        Err(HostBuildInputClosureError::ReceiptInputMismatch)
    ));
}

fn cargo_lock() -> Vec<u8> {
    format!(
        "# generated fixture\nversion = 4\n\n[[package]]\nname = \"host-fixture\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"registry-lib\"\nversion = \"1.2.3\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{}\"\n\n[[package]]\nname = \"git-helper\"\nversion = \"0.4.0\"\nsource = \"git+https://example.invalid/helper?rev=v1#{}\"\n",
        digest('c'),
        "1".repeat(40)
    )
    .into_bytes()
}

fn fetched_evidence(closure_digest: &str) -> FetchedSourceEvidence {
    FetchedSourceEvidence {
        schema: 1,
        locked_source_closure_digest: closure_digest.into(),
        packages: vec![
            FetchedSourcePackage {
                package: CargoPackageIdentity {
                    name: "registry-lib".into(),
                    version: "1.2.3".into(),
                    source: CargoPackageSource::Registry {
                        registry: "https://github.com/rust-lang/crates.io-index".into(),
                        checksum: digest('c'),
                    },
                },
                observation: FetchedSourceObservation::RegistryArchive {
                    archive_sha256: digest('c'),
                    snapshot_tree_digest: digest('d'),
                },
            },
            FetchedSourcePackage {
                package: CargoPackageIdentity {
                    name: "git-helper".into(),
                    version: "0.4.0".into(),
                    source: CargoPackageSource::Git {
                        repository: "https://example.invalid/helper?rev=v1".into(),
                        precise: "1".repeat(40),
                    },
                },
                observation: FetchedSourceObservation::GitCheckout {
                    precise: "1".repeat(40),
                    snapshot_tree_digest: digest('e'),
                },
            },
            FetchedSourcePackage {
                package: package(),
                observation: FetchedSourceObservation::PathSnapshot {
                    snapshot_tree_digest: digest('a'),
                },
            },
        ],
    }
}

#[test]
fn locked_sources_bind_lock_unit_packages_and_exact_fetch_observations() {
    let cargo_lock = cargo_lock();
    let sources = LockedSourceClosure::from_cargo_lock(&cargo_lock, &[package()]).unwrap();
    let normalized = sources.normalize().unwrap();
    assert_eq!(
        normalized.digest(),
        "f6c82d009052887741e32265a537fc27f1d81abb0f7e0eca8eceaf2813863003"
    );
    assert_eq!(normalized.packages().len(), 3);
    let mut reordered_sources = sources;
    reordered_sources.packages.reverse();
    assert_eq!(reordered_sources.normalize().unwrap(), normalized);

    let policy = policy();
    let mut host = closure(&policy);
    let lock_item = host
        .items
        .iter_mut()
        .find(|item| item.role == HostBuildClosureItemRole::HostCargoLock)
        .unwrap();
    lock_item.content = HostBuildClosureContent::File {
        sha256: normalized.cargo_lock_digest().into(),
    };
    let host = host.normalize(&policy).unwrap();
    normalized.verify_host_closure(&host).unwrap();

    let evidence = fetched_evidence(normalized.digest());
    let verified = evidence.normalize(&normalized).unwrap();
    assert_eq!(
        verified.digest(),
        "1de6cc4b87618d191449074240b95117f95239d5e72f9cac28f1a6bab298889d"
    );
    let mut reordered = evidence;
    reordered.packages.reverse();
    assert_eq!(reordered.normalize(&normalized).unwrap(), verified);
}

#[test]
fn locked_source_and_fetch_mutations_fail_closed() {
    let cargo_lock = cargo_lock();
    let normalized = LockedSourceClosure::from_cargo_lock(&cargo_lock, &[package()])
        .unwrap()
        .normalize()
        .unwrap();

    let unsupported =
        String::from_utf8(cargo_lock.clone())
            .unwrap()
            .replacen("version = 4", "version = 3", 1);
    assert!(matches!(
        LockedSourceClosure::from_cargo_lock(unsupported.as_bytes(), &[package()]),
        Err(LockedSourceError::UnsupportedCargoLock(3))
    ));

    let missing_checksum = String::from_utf8(cargo_lock.clone())
        .unwrap()
        .replace(&format!("checksum = \"{}\"\n", digest('c')), "");
    assert!(matches!(
        LockedSourceClosure::from_cargo_lock(missing_checksum.as_bytes(), &[package()]),
        Err(LockedSourceError::InvalidLockedPackage {
            field: "checksum",
            ..
        })
    ));
    let insecure_registry = String::from_utf8(cargo_lock.clone()).unwrap().replacen(
        "registry+https://",
        "registry+http://",
        1,
    );
    assert!(matches!(
        LockedSourceClosure::from_cargo_lock(insecure_registry.as_bytes(), &[package()]),
        Err(LockedSourceError::InvalidLockedPackage {
            field: "registry",
            ..
        })
    ));
    let imprecise_git = String::from_utf8(cargo_lock.clone()).unwrap().replacen(
        &format!("#{}", "1".repeat(40)),
        "#floating",
        1,
    );
    assert!(matches!(
        LockedSourceClosure::from_cargo_lock(imprecise_git.as_bytes(), &[package()]),
        Err(LockedSourceError::InvalidLockedPackage {
            field: "git-source",
            ..
        })
    ));
    assert!(matches!(
        LockedSourceClosure::from_cargo_lock(&cargo_lock, &[]),
        Err(LockedSourceError::PathPackageMapping(_))
    ));
    let mut extra_path = package();
    extra_path.name = "unused-path".into();
    assert!(matches!(
        LockedSourceClosure::from_cargo_lock(&cargo_lock, &[package(), extra_path]),
        Err(LockedSourceError::PathPackageMapping(_))
    ));
    let duplicated_path = format!(
        "{}\n[[package]]\nname = \"host-fixture\"\nversion = \"0.1.0\"\n",
        String::from_utf8(cargo_lock.clone()).unwrap()
    );
    assert!(matches!(
        LockedSourceClosure::from_cargo_lock(duplicated_path.as_bytes(), &[package()]),
        Err(LockedSourceError::DuplicateLockedPackage(_))
    ));

    let policy = policy();
    let wrong_lock_host = closure(&policy).normalize(&policy).unwrap();
    assert!(matches!(
        normalized.verify_host_closure(&wrong_lock_host),
        Err(LockedSourceError::HostCargoLockMismatch)
    ));
    assert!(!wrong_lock_host.items().is_empty());

    let mut wrong_unit_source = LockedSourceClosure::from_cargo_lock(
        &cargo_lock,
        &[CargoPackageIdentity {
            name: "host-fixture".into(),
            version: "0.1.0".into(),
            source: CargoPackageSource::Path {
                tree_digest: digest('b'),
            },
        }],
    )
    .unwrap();
    wrong_unit_source.cargo_lock_digest = normalized.cargo_lock_digest().into();
    let wrong_unit_source = wrong_unit_source.normalize().unwrap();
    let mut host = closure(&policy);
    host.items
        .iter_mut()
        .find(|item| item.role == HostBuildClosureItemRole::HostCargoLock)
        .unwrap()
        .content = HostBuildClosureContent::File {
        sha256: normalized.cargo_lock_digest().into(),
    };
    assert!(matches!(
        wrong_unit_source.verify_host_closure(&host.normalize(&policy).unwrap()),
        Err(LockedSourceError::UnitPackageMismatch(_))
    ));

    let evidence = fetched_evidence(normalized.digest());
    let mut wrong_closure = evidence.clone();
    wrong_closure.locked_source_closure_digest = digest('f');
    assert!(matches!(
        wrong_closure.normalize(&normalized),
        Err(LockedSourceError::InvalidClosureDigest)
    ));
    let mut missing = evidence.clone();
    missing.packages.pop();
    assert!(matches!(
        missing.normalize(&normalized),
        Err(LockedSourceError::EvidencePackageSetMismatch)
    ));

    let mut checksum_drift = evidence.clone();
    if let FetchedSourceObservation::RegistryArchive { archive_sha256, .. } =
        &mut checksum_drift.packages[0].observation
    {
        *archive_sha256 = digest('f');
    }
    assert!(matches!(
        checksum_drift.normalize(&normalized),
        Err(LockedSourceError::EvidenceObservationMismatch(_))
    ));

    let mut precise_drift = evidence;
    if let FetchedSourceObservation::GitCheckout { precise, .. } =
        &mut precise_drift.packages[1].observation
    {
        *precise = "2".repeat(40);
    }
    assert!(matches!(
        precise_drift.normalize(&normalized),
        Err(LockedSourceError::EvidenceObservationMismatch(_))
    ));

    let mut wrong_kind = fetched_evidence(normalized.digest());
    wrong_kind.packages[2].observation = FetchedSourceObservation::GitCheckout {
        precise: "1".repeat(40),
        snapshot_tree_digest: digest('a'),
    };
    assert!(matches!(
        wrong_kind.normalize(&normalized),
        Err(LockedSourceError::EvidenceObservationMismatch(_))
    ));

    let unknown = serde_json::to_string(
        &LockedSourceClosure::from_cargo_lock(&cargo_lock, &[package()]).unwrap(),
    )
    .unwrap()
    .replacen('{', "{\"ambient\":true,", 1);
    assert!(matches!(
        LockedSourceClosure::from_json(&unknown),
        Err(LockedSourceError::Json(_))
    ));
    let unknown_evidence = serde_json::to_string(&fetched_evidence(normalized.digest()))
        .unwrap()
        .replacen('{', "{\"ambient\":true,", 1);
    assert!(matches!(
        FetchedSourceEvidence::from_json(&unknown_evidence),
        Err(LockedSourceError::Json(_))
    ));
}

fn rustc_fetch_query(arguments: Vec<String>) -> CargoFetchDescendantExecution {
    CargoFetchDescendantExecution::RustcIdentityQuery {
        executable: "/rust-agent/toolchain/bin/rustc".into(),
        arguments,
        exit_code: 0,
    }
}

fn target_information_query(target: Option<&str>) -> Vec<String> {
    let mut arguments = vec![
        "-".into(),
        "--crate-name".into(),
        "___".into(),
        "--print=file-names".into(),
    ];
    if let Some(target) = target {
        arguments.extend(["--target".into(), target.into()]);
    }
    arguments.extend(
        [
            "--crate-type",
            "bin",
            "--crate-type",
            "rlib",
            "--crate-type",
            "dylib",
            "--crate-type",
            "cdylib",
            "--crate-type",
            "staticlib",
            "--crate-type",
            "proc-macro",
            "--print=sysroot",
            "--print=split-debuginfo",
            "--print=crate-name",
            "--print=cfg",
            "-Wwarnings",
        ]
        .map(str::to_owned),
    );
    arguments
}

fn valid_fetch_rustc_queries(
    request: &NormalizedCargoFetchRequest,
) -> Vec<CargoFetchDescendantExecution> {
    let mut queries = vec![
        rustc_fetch_query(vec!["-vV".into()]),
        rustc_fetch_query(target_information_query(None)),
    ];
    queries.push(rustc_fetch_query(target_information_query(Some(
        request.cargo_target_input(),
    ))));
    queries
}

#[test]
fn cargo_fetch_schema_three_binds_network_and_credential_contract() {
    let cargo_lock = cargo_lock();
    let locked_sources = LockedSourceClosure::from_cargo_lock(&cargo_lock, &[package()])
        .unwrap()
        .normalize()
        .unwrap();
    let policy = policy();
    let mut host = closure(&policy);
    host.items
        .iter_mut()
        .find(|item| item.role == HostBuildClosureItemRole::HostCargoLock)
        .unwrap()
        .content = HostBuildClosureContent::File {
        sha256: locked_sources.cargo_lock_digest().into(),
    };
    let host = host.normalize(&policy).unwrap();
    let request = CargoFetchRequest {
        schema: 3,
        mode: CargoFetchMode::Preprovisioned,
    }
    .normalize(&policy, &host, &locked_sources)
    .unwrap();
    assert_eq!(
        CargoFetchRequest {
            schema: 3,
            mode: CargoFetchMode::Preprovisioned,
        }
        .normalize(&policy, &host, &locked_sources)
        .unwrap(),
        request
    );

    assert_eq!(request.mode(), CargoFetchMode::Preprovisioned);
    assert_eq!(
        request.build_execution_policy_digest(),
        policy.full_digest()
    );
    assert_eq!(request.host_build_input_closure_digest(), host.digest());
    assert_eq!(
        request.locked_source_closure_digest(),
        locked_sources.digest()
    );
    assert_eq!(
        request.manifest_logical_path(),
        "/rust-agent/closure/host/Cargo.toml"
    );
    assert_eq!(
        request.cargo_lock_logical_path(),
        "/rust-agent/closure/host/Cargo.lock"
    );
    assert_eq!(
        request.cargo_config_logical_path(),
        "/rust-agent/closure/host/.cargo/config.toml"
    );
    assert_eq!(
        request.invocation().arguments,
        vec![
            "fetch",
            "--manifest-path",
            "/rust-agent/closure/host/Cargo.toml",
            "--config",
            "/rust-agent/closure/host/.cargo/config.toml",
            "--locked",
            "--offline",
        ]
    );
    assert_eq!(
        request.invocation().environment.get("CARGO_NET_OFFLINE"),
        Some(&"true".into())
    );
    assert!(request.sandbox().environment_cleared);
    assert!(request.sandbox().descendants_inherit_sandbox);
    assert!(request.sandbox().network_endpoints.is_empty());
    assert_eq!(
        request.sandbox().writable_mounts,
        ["/rust-agent/fetch-cache-staging"]
    );

    let observation = CargoFetchObservation {
        schema: 3,
        request_digest: request.digest().into(),
        sandbox: request.sandbox().clone(),
        cargo_exit_code: 0,
        descendant_executions: valid_fetch_rustc_queries(&request),
        fetched_sources: fetched_evidence(locked_sources.digest()),
        cache_tree_digest: digest('f'),
    };
    let validated = request
        .validate_observation(&observation, &locked_sources)
        .unwrap();
    assert_eq!(validated.request_digest(), request.digest());
    assert_eq!(validated.cache_tree_digest(), digest('f'));
    assert_eq!(
        validated.fetched_sources().packages().len(),
        locked_sources.packages().len()
    );

    let mut reordered = observation.clone();
    reordered.fetched_sources.packages.reverse();
    assert_eq!(
        request
            .validate_observation(&reordered, &locked_sources)
            .unwrap(),
        validated
    );

    let encoded = serde_json::to_string(&observation).unwrap();
    assert_eq!(
        CargoFetchObservation::from_json(&encoded).unwrap(),
        observation
    );
    let unknown = encoded.replacen('{', "{\"ambient\":true,", 1);
    assert!(matches!(
        CargoFetchObservation::from_json(&unknown),
        Err(CargoFetchError::Json(_))
    ));
}

#[test]
fn cargo_fetch_rejects_query_argument_target_and_schema_drift() {
    let cargo_lock = cargo_lock();
    let locked_sources = LockedSourceClosure::from_cargo_lock(&cargo_lock, &[package()])
        .unwrap()
        .normalize()
        .unwrap();
    let policy = policy();
    let mut host = closure(&policy);
    host.items
        .iter_mut()
        .find(|item| item.role == HostBuildClosureItemRole::HostCargoLock)
        .unwrap()
        .content = HostBuildClosureContent::File {
        sha256: locked_sources.cargo_lock_digest().into(),
    };
    let host = host.normalize(&policy).unwrap();

    assert!(matches!(
        CargoFetchRequest {
            schema: 1,
            mode: CargoFetchMode::Preprovisioned,
        }
        .normalize(&policy, &host, &locked_sources),
        Err(CargoFetchError::UnsupportedRequestSchema(1))
    ));
    assert!(matches!(
        CargoFetchRequest {
            schema: 3,
            mode: CargoFetchMode::Networked,
        }
        .normalize(&policy, &host, &locked_sources),
        Err(CargoFetchError::MissingSourceEndpoint(_))
    ));
    let mut rotated_policy = policy.policy().clone();
    rotated_policy.attestation.allowed_executors = vec!["rotated-executor-v1".into()];
    let rotated_policy = rotated_policy.normalize().unwrap();
    assert!(matches!(
        CargoFetchRequest {
            schema: 3,
            mode: CargoFetchMode::Preprovisioned,
        }
        .normalize(&rotated_policy, &host, &locked_sources),
        Err(CargoFetchError::PolicyMismatch)
    ));
    let unmatched_host = closure(&policy).normalize(&policy).unwrap();
    assert!(matches!(
        CargoFetchRequest {
            schema: 3,
            mode: CargoFetchMode::Preprovisioned,
        }
        .normalize(&policy, &unmatched_host, &locked_sources),
        Err(CargoFetchError::LockedSources(
            LockedSourceError::HostCargoLockMismatch
        ))
    ));

    let mut network_policy = policy.policy().clone();
    network_policy.fetch.network_endpoints = vec![
        "https://example.invalid:443".into(),
        "https://github.com:443".into(),
        "https://static.crates.io:443".into(),
    ];
    network_policy.fetch.credential_helper = Some(ProductionFileIdentity {
        path: "/runner/bin/cargo-credential-helper".into(),
        sha256: digest('5'),
    });
    network_policy.fetch.tls_ca_bundle = Some(ProductionFileIdentity {
        path: "/runner/tls/ca-bundle.pem".into(),
        sha256: digest('6'),
    });
    let network_policy = network_policy.normalize().unwrap();
    let mut network_host = closure(&network_policy);
    network_host
        .items
        .iter_mut()
        .find(|item| item.role == HostBuildClosureItemRole::HostCargoLock)
        .unwrap()
        .content = HostBuildClosureContent::File {
        sha256: locked_sources.cargo_lock_digest().into(),
    };
    let network_host = network_host.normalize(&network_policy).unwrap();
    let network_request = CargoFetchRequest {
        schema: 3,
        mode: CargoFetchMode::Networked,
    }
    .normalize(&network_policy, &network_host, &locked_sources)
    .unwrap();
    assert!(
        !network_request
            .invocation()
            .arguments
            .contains(&"--offline".into())
    );
    assert_eq!(
        network_request.sandbox().network_endpoints,
        [
            "https://example.invalid:443",
            "https://github.com:443",
            "https://static.crates.io:443",
        ]
    );
    assert_eq!(
        network_request
            .sandbox()
            .credential_helper
            .as_ref()
            .unwrap()
            .executable,
        "/rust-agent/fetch-tools/credential-helper"
    );
    let mut network_executions = valid_fetch_rustc_queries(&network_request);
    network_executions.push(CargoFetchDescendantExecution::CredentialHelper {
        executable: "/rust-agent/fetch-tools/credential-helper".into(),
        arguments: vec!["--cargo-plugin".into()],
        endpoint: "https://example.invalid:443".into(),
        exit_code: 0,
    });
    let network_observation = CargoFetchObservation {
        schema: 3,
        request_digest: network_request.digest().into(),
        sandbox: network_request.sandbox().clone(),
        cargo_exit_code: 0,
        descendant_executions: network_executions,
        fetched_sources: fetched_evidence(locked_sources.digest()),
        cache_tree_digest: digest('f'),
    };
    network_request
        .validate_observation(&network_observation, &locked_sources)
        .unwrap();

    let request = CargoFetchRequest {
        schema: 3,
        mode: CargoFetchMode::Preprovisioned,
    }
    .normalize(&policy, &host, &locked_sources)
    .unwrap();
    let baseline = CargoFetchObservation {
        schema: 3,
        request_digest: request.digest().into(),
        sandbox: request.sandbox().clone(),
        cargo_exit_code: 0,
        descendant_executions: valid_fetch_rustc_queries(&request),
        fetched_sources: fetched_evidence(locked_sources.digest()),
        cache_tree_digest: digest('f'),
    };

    let mut drift = baseline.clone();
    drift.request_digest = digest('0');
    assert!(matches!(
        request.validate_observation(&drift, &locked_sources),
        Err(CargoFetchError::ObservationRequestMismatch)
    ));
    let mut drift = baseline.clone();
    drift.sandbox.environment_cleared = false;
    assert!(matches!(
        request.validate_observation(&drift, &locked_sources),
        Err(CargoFetchError::SandboxMismatch)
    ));
    let mut drift = baseline.clone();
    drift.cargo_exit_code = 9;
    assert!(matches!(
        request.validate_observation(&drift, &locked_sources),
        Err(CargoFetchError::FetchFailed(9))
    ));
    let mut drift = baseline.clone();
    drift.descendant_executions.clear();
    assert!(matches!(
        request.validate_observation(&drift, &locked_sources),
        Err(CargoFetchError::InvalidDescendantExecution)
    ));
    let mut drift = baseline.clone();
    drift.descendant_executions = vec![CargoFetchDescendantExecution::RustcIdentityQuery {
        executable: "/rust-agent/toolchain/bin/rustc".into(),
        arguments: vec!["--crate-name".into(), "attacker".into()],
        exit_code: 0,
    }];
    assert!(matches!(
        request.validate_observation(&drift, &locked_sources),
        Err(CargoFetchError::InvalidDescendantExecution)
    ));
    let mut drift = baseline.clone();
    let target_query = drift
        .descendant_executions
        .iter_mut()
        .find_map(|execution| match execution {
            CargoFetchDescendantExecution::RustcIdentityQuery { arguments, .. }
                if arguments.iter().any(|argument| argument == "--target") =>
            {
                Some(arguments)
            }
            _ => None,
        })
        .unwrap();
    *target_query
        .iter_mut()
        .find(|argument| argument.as_str() == request.cargo_target_input())
        .unwrap() = "attacker-target".into();
    assert!(matches!(
        request.validate_observation(&drift, &locked_sources),
        Err(CargoFetchError::InvalidDescendantExecution)
    ));
    let mut drift = baseline.clone();
    drift.schema = 1;
    assert!(matches!(
        request.validate_observation(&drift, &locked_sources),
        Err(CargoFetchError::UnsupportedObservationSchema(1))
    ));
    let mut drift = baseline.clone();
    drift.descendant_executions = vec![CargoFetchDescendantExecution::CredentialHelper {
        executable: "/rust-agent/fetch-tools/credential-helper".into(),
        arguments: vec!["--cargo-plugin".into()],
        endpoint: "https://example.invalid:443".into(),
        exit_code: 0,
    }];
    assert!(matches!(
        request.validate_observation(&drift, &locked_sources),
        Err(CargoFetchError::InvalidDescendantExecution)
    ));
    let mut drift = baseline.clone();
    drift.cache_tree_digest = "not-a-digest".into();
    assert!(matches!(
        request.validate_observation(&drift, &locked_sources),
        Err(CargoFetchError::InvalidCacheTreeDigest)
    ));
    let mut drift = baseline.clone();
    drift.fetched_sources.packages.pop();
    assert!(matches!(
        request.validate_observation(&drift, &locked_sources),
        Err(CargoFetchError::LockedSources(
            LockedSourceError::EvidencePackageSetMismatch
        ))
    ));

    let mut boundary = baseline;
    boundary.descendant_executions = (0..254)
        .map(|_| CargoFetchDescendantExecution::RustcIdentityQuery {
            executable: "/rust-agent/toolchain/bin/rustc".into(),
            arguments: vec!["-vV".into()],
            exit_code: 0,
        })
        .collect();
    boundary
        .descendant_executions
        .extend(valid_fetch_rustc_queries(&request).into_iter().skip(1));
    assert_eq!(boundary.descendant_executions.len(), 256);
    request
        .validate_observation(&boundary, &locked_sources)
        .unwrap();
    boundary
        .descendant_executions
        .push(CargoFetchDescendantExecution::RustcIdentityQuery {
            executable: "/rust-agent/toolchain/bin/rustc".into(),
            arguments: vec!["-vV".into()],
            exit_code: 0,
        });
    assert!(matches!(
        request.validate_observation(&boundary, &locked_sources),
        Err(CargoFetchError::InvalidDescendantExecution)
    ));
}

fn fetch_cache_fixture() -> (
    NormalizedCargoFetchRequest,
    NormalizedLockedSourceClosure,
    CanonicalSnapshotTree,
    CargoFetchCacheLayout,
    FetchedSourceEvidence,
) {
    let cargo_lock = cargo_lock();
    let locked_sources = LockedSourceClosure::from_cargo_lock(&cargo_lock, &[package()])
        .unwrap()
        .normalize()
        .unwrap();
    let policy = policy();
    let mut host = closure(&policy);
    host.items
        .iter_mut()
        .find(|item| item.role == HostBuildClosureItemRole::HostCargoLock)
        .unwrap()
        .content = HostBuildClosureContent::File {
        sha256: locked_sources.cargo_lock_digest().into(),
    };
    let host = host.normalize(&policy).unwrap();
    let request = CargoFetchRequest {
        schema: 3,
        mode: CargoFetchMode::Preprovisioned,
    }
    .normalize(&policy, &host, &locked_sources)
    .unwrap();

    let registry_source = CanonicalSnapshotTree::from_entries(vec![
        CanonicalSnapshotEntry::regular_file("Cargo.toml", digest('2'), 12),
        CanonicalSnapshotEntry::directory("src"),
        CanonicalSnapshotEntry::regular_file("src/lib.rs", digest('3'), 18),
    ])
    .unwrap();
    let git_source = CanonicalSnapshotTree::from_entries(vec![
        CanonicalSnapshotEntry::regular_file("Cargo.toml", digest('4'), 14),
        CanonicalSnapshotEntry::directory("src"),
        CanonicalSnapshotEntry::regular_file("src/lib.rs", digest('5'), 20),
    ])
    .unwrap();
    let registry_root = "registry/src/github-index/registry-lib-1.2.3";
    let git_root = "git/checkouts/git-helper/revision";
    let mut entries = vec![
        CanonicalSnapshotEntry::directory("registry"),
        CanonicalSnapshotEntry::directory("registry/cache"),
        CanonicalSnapshotEntry::directory("registry/cache/github-index"),
        CanonicalSnapshotEntry::regular_file(
            "registry/cache/github-index/registry-lib-1.2.3.crate",
            digest('c'),
            128,
        ),
        CanonicalSnapshotEntry::directory("registry/src"),
        CanonicalSnapshotEntry::directory("registry/src/github-index"),
        CanonicalSnapshotEntry::directory(registry_root),
        CanonicalSnapshotEntry::directory("git"),
        CanonicalSnapshotEntry::directory("git/checkouts"),
        CanonicalSnapshotEntry::directory("git/checkouts/git-helper"),
        CanonicalSnapshotEntry::directory(git_root),
    ];
    for entry in registry_source.entries() {
        let mut entry = entry.clone();
        entry.path = format!("{registry_root}/{}", entry.path);
        entries.push(entry);
    }
    for entry in git_source.entries() {
        let mut entry = entry.clone();
        entry.path = format!("{git_root}/{}", entry.path);
        entries.push(entry);
    }
    let cache_tree = CanonicalSnapshotTree::from_entries(entries).unwrap();
    let evidence = FetchedSourceEvidence {
        schema: 1,
        locked_source_closure_digest: locked_sources.digest().into(),
        packages: vec![
            FetchedSourcePackage {
                package: package(),
                observation: FetchedSourceObservation::PathSnapshot {
                    snapshot_tree_digest: digest('a'),
                },
            },
            FetchedSourcePackage {
                package: CargoPackageIdentity {
                    name: "git-helper".into(),
                    version: "0.4.0".into(),
                    source: CargoPackageSource::Git {
                        repository: "https://example.invalid/helper?rev=v1".into(),
                        precise: "1".repeat(40),
                    },
                },
                observation: FetchedSourceObservation::GitCheckout {
                    precise: "1".repeat(40),
                    snapshot_tree_digest: git_source.digest().into(),
                },
            },
            FetchedSourcePackage {
                package: CargoPackageIdentity {
                    name: "registry-lib".into(),
                    version: "1.2.3".into(),
                    source: CargoPackageSource::Registry {
                        registry: "https://github.com/rust-lang/crates.io-index".into(),
                        checksum: digest('c'),
                    },
                },
                observation: FetchedSourceObservation::RegistryArchive {
                    archive_sha256: digest('c'),
                    snapshot_tree_digest: registry_source.digest().into(),
                },
            },
        ],
    };
    let layout = CargoFetchCacheLayout {
        schema: 1,
        packages: vec![
            CargoFetchCachePackageLocation {
                package: package(),
                archive_path: None,
                source_path: None,
            },
            CargoFetchCachePackageLocation {
                package: CargoPackageIdentity {
                    name: "git-helper".into(),
                    version: "0.4.0".into(),
                    source: CargoPackageSource::Git {
                        repository: "https://example.invalid/helper?rev=v1".into(),
                        precise: "1".repeat(40),
                    },
                },
                archive_path: None,
                source_path: Some(git_root.into()),
            },
            CargoFetchCachePackageLocation {
                package: CargoPackageIdentity {
                    name: "registry-lib".into(),
                    version: "1.2.3".into(),
                    source: CargoPackageSource::Registry {
                        registry: "https://github.com/rust-lang/crates.io-index".into(),
                        checksum: digest('c'),
                    },
                },
                archive_path: Some("registry/cache/github-index/registry-lib-1.2.3.crate".into()),
                source_path: Some(registry_root.into()),
            },
        ],
    };
    (request, locked_sources, cache_tree, layout, evidence)
}

fn validated_fetch_for_cache(
    request: &NormalizedCargoFetchRequest,
    locked_sources: &NormalizedLockedSourceClosure,
    cache_tree: &CanonicalSnapshotTree,
    evidence: FetchedSourceEvidence,
) -> ValidatedCargoFetchObservation {
    request
        .validate_observation(
            &CargoFetchObservation {
                schema: 3,
                request_digest: request.digest().into(),
                sandbox: request.sandbox().clone(),
                cargo_exit_code: 0,
                descendant_executions: valid_fetch_rustc_queries(request),
                fetched_sources: evidence,
                cache_tree_digest: cache_tree.digest().into(),
            },
            locked_sources,
        )
        .unwrap()
}

#[test]
fn fetch_cache_manifest_rederives_archives_and_source_subtrees() {
    let (request, locked_sources, cache_tree, layout, evidence) = fetch_cache_fixture();
    let observation =
        validated_fetch_for_cache(&request, &locked_sources, &cache_tree, evidence.clone());
    let manifest = layout.verify(&request, &observation, &cache_tree).unwrap();
    manifest
        .verify(&request, &observation, &cache_tree)
        .unwrap();
    assert_eq!(manifest.request_digest, request.digest());
    assert_eq!(manifest.fetch_observation_digest, observation.digest());
    assert_eq!(manifest.cache_tree_digest, cache_tree.digest());

    let mut reordered = layout;
    reordered.packages.reverse();
    assert_eq!(
        reordered
            .verify(&request, &observation, &cache_tree)
            .unwrap(),
        manifest
    );

    let encoded = serde_json::to_string(&manifest).unwrap();
    let decoded = rust_agent_build_executor::CargoFetchCacheManifest::from_json(&encoded).unwrap();
    decoded.verify(&request, &observation, &cache_tree).unwrap();
    let unknown = encoded.replacen('{', "{\"ambient\":true,", 1);
    assert!(matches!(
        rust_agent_build_executor::CargoFetchCacheManifest::from_json(&unknown),
        Err(CargoFetchCacheError::Json(_))
    ));
}

#[test]
fn fetch_cache_manifest_rejects_checksum_tree_path_and_projection_drift() {
    let (request, locked_sources, cache_tree, layout, evidence) = fetch_cache_fixture();
    let observation =
        validated_fetch_for_cache(&request, &locked_sources, &cache_tree, evidence.clone());

    let mut missing = layout.clone();
    missing.packages.pop();
    assert!(matches!(
        missing.verify(&request, &observation, &cache_tree),
        Err(CargoFetchCacheError::PackageSetMismatch)
    ));

    let mut traversal = layout.clone();
    traversal.packages[2].archive_path = Some("registry/cache/../escape.crate".into());
    assert!(matches!(
        traversal.verify(&request, &observation, &cache_tree),
        Err(CargoFetchCacheError::InvalidPackageLocation(_))
    ));

    let mut overlap = layout.clone();
    overlap.packages[1].source_path = layout.packages[2].source_path.clone();
    assert!(matches!(
        overlap.verify(&request, &observation, &cache_tree),
        Err(CargoFetchCacheError::OverlappingPackageLocation)
    ));

    let mut archive_entries = cache_tree.entries().to_vec();
    let archive = archive_entries
        .iter_mut()
        .find(|entry| entry.path.ends_with("registry-lib-1.2.3.crate"))
        .unwrap();
    archive.kind = CanonicalSnapshotEntryKind::RegularFile {
        sha256: digest('f'),
        bytes: 128,
    };
    let archive_drift = CanonicalSnapshotTree::from_entries(archive_entries).unwrap();
    let archive_observation =
        validated_fetch_for_cache(&request, &locked_sources, &archive_drift, evidence.clone());
    assert!(matches!(
        layout.verify(&request, &archive_observation, &archive_drift),
        Err(CargoFetchCacheError::RegistryArchiveMismatch(_))
    ));

    let mut source_entries = cache_tree.entries().to_vec();
    let source = source_entries
        .iter_mut()
        .find(|entry| entry.path.ends_with("registry-lib-1.2.3/src/lib.rs"))
        .unwrap();
    source.kind = CanonicalSnapshotEntryKind::RegularFile {
        sha256: digest('f'),
        bytes: 18,
    };
    let source_drift = CanonicalSnapshotTree::from_entries(source_entries).unwrap();
    let source_observation =
        validated_fetch_for_cache(&request, &locked_sources, &source_drift, evidence);
    assert!(matches!(
        layout.verify(&request, &source_observation, &source_drift),
        Err(CargoFetchCacheError::SourceTreeMismatch(_))
    ));

    let mut manifest = layout.verify(&request, &observation, &cache_tree).unwrap();
    manifest.digest = digest('0');
    assert!(matches!(
        manifest.verify(&request, &observation, &cache_tree),
        Err(CargoFetchCacheError::ManifestMismatch)
    ));
}

#[cfg(target_os = "linux")]
fn real_fetch_cache_fixture(
    root: &Path,
) -> (
    NormalizedCargoFetchRequest,
    NormalizedLockedSourceClosure,
    CanonicalSnapshotTree,
    CargoFetchCacheLayout,
    FetchedSourceEvidence,
) {
    let registry_root = "registry/src/github-index/registry-lib-1.2.3";
    let archive_path = "registry/cache/github-index/registry-lib-1.2.3.crate";
    let git_root = "git/checkouts/git-helper/revision";
    fs::create_dir_all(root.join(format!("{registry_root}/src"))).unwrap();
    fs::create_dir_all(root.join(format!("{git_root}/src"))).unwrap();
    fs::create_dir_all(root.join("registry/cache/github-index")).unwrap();
    let archive = b"registry archive bytes";
    let registry_manifest = b"[package]\nname='registry-lib'\nversion='1.2.3'\n";
    let registry_source = b"pub fn registry() {}\n";
    let git_manifest = b"[package]\nname='git-helper'\nversion='0.4.0'\n";
    let git_source = b"pub fn git() {}\n";
    fs::write(root.join(archive_path), archive).unwrap();
    fs::write(
        root.join(format!("{registry_root}/Cargo.toml")),
        registry_manifest,
    )
    .unwrap();
    fs::write(
        root.join(format!("{registry_root}/src/lib.rs")),
        registry_source,
    )
    .unwrap();
    fs::write(root.join(format!("{git_root}/Cargo.toml")), git_manifest).unwrap();
    fs::write(root.join(format!("{git_root}/src/lib.rs")), git_source).unwrap();

    let hash = |bytes: &[u8]| hex::encode(Sha256::digest(bytes));
    let archive_digest = hash(archive);
    let registry_tree = CanonicalSnapshotTree::from_entries(vec![
        CanonicalSnapshotEntry::regular_file(
            "Cargo.toml",
            hash(registry_manifest),
            registry_manifest.len() as u64,
        ),
        CanonicalSnapshotEntry::directory("src"),
        CanonicalSnapshotEntry::regular_file(
            "src/lib.rs",
            hash(registry_source),
            registry_source.len() as u64,
        ),
    ])
    .unwrap();
    let git_tree = CanonicalSnapshotTree::from_entries(vec![
        CanonicalSnapshotEntry::regular_file(
            "Cargo.toml",
            hash(git_manifest),
            git_manifest.len() as u64,
        ),
        CanonicalSnapshotEntry::directory("src"),
        CanonicalSnapshotEntry::regular_file(
            "src/lib.rs",
            hash(git_source),
            git_source.len() as u64,
        ),
    ])
    .unwrap();
    let mut entries = vec![
        CanonicalSnapshotEntry::directory("registry"),
        CanonicalSnapshotEntry::directory("registry/cache"),
        CanonicalSnapshotEntry::directory("registry/cache/github-index"),
        CanonicalSnapshotEntry::regular_file(archive_path, &archive_digest, archive.len() as u64),
        CanonicalSnapshotEntry::directory("registry/src"),
        CanonicalSnapshotEntry::directory("registry/src/github-index"),
        CanonicalSnapshotEntry::directory(registry_root),
        CanonicalSnapshotEntry::directory("git"),
        CanonicalSnapshotEntry::directory("git/checkouts"),
        CanonicalSnapshotEntry::directory("git/checkouts/git-helper"),
        CanonicalSnapshotEntry::directory(git_root),
    ];
    for entry in registry_tree.entries() {
        let mut entry = entry.clone();
        entry.path = format!("{registry_root}/{}", entry.path);
        entries.push(entry);
    }
    for entry in git_tree.entries() {
        let mut entry = entry.clone();
        entry.path = format!("{git_root}/{}", entry.path);
        entries.push(entry);
    }
    let cache_tree = CanonicalSnapshotTree::from_entries(entries).unwrap();
    let lock = format!(
        "version = 4\n\n[[package]]\nname = \"host-fixture\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"registry-lib\"\nversion = \"1.2.3\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{archive_digest}\"\n\n[[package]]\nname = \"git-helper\"\nversion = \"0.4.0\"\nsource = \"git+https://example.invalid/helper?rev=v1#{}\"\n",
        "1".repeat(40)
    );
    let locked_sources = LockedSourceClosure::from_cargo_lock(lock.as_bytes(), &[package()])
        .unwrap()
        .normalize()
        .unwrap();
    let policy = policy();
    let mut host = closure(&policy);
    host.items
        .iter_mut()
        .find(|item| item.role == HostBuildClosureItemRole::HostCargoLock)
        .unwrap()
        .content = HostBuildClosureContent::File {
        sha256: locked_sources.cargo_lock_digest().into(),
    };
    let host = host.normalize(&policy).unwrap();
    let request = CargoFetchRequest {
        schema: 3,
        mode: CargoFetchMode::Preprovisioned,
    }
    .normalize(&policy, &host, &locked_sources)
    .unwrap();
    let registry_package = CargoPackageIdentity {
        name: "registry-lib".into(),
        version: "1.2.3".into(),
        source: CargoPackageSource::Registry {
            registry: "https://github.com/rust-lang/crates.io-index".into(),
            checksum: archive_digest.clone(),
        },
    };
    let git_package = CargoPackageIdentity {
        name: "git-helper".into(),
        version: "0.4.0".into(),
        source: CargoPackageSource::Git {
            repository: "https://example.invalid/helper?rev=v1".into(),
            precise: "1".repeat(40),
        },
    };
    let evidence = FetchedSourceEvidence {
        schema: 1,
        locked_source_closure_digest: locked_sources.digest().into(),
        packages: vec![
            FetchedSourcePackage {
                package: package(),
                observation: FetchedSourceObservation::PathSnapshot {
                    snapshot_tree_digest: digest('a'),
                },
            },
            FetchedSourcePackage {
                package: registry_package.clone(),
                observation: FetchedSourceObservation::RegistryArchive {
                    archive_sha256: archive_digest,
                    snapshot_tree_digest: registry_tree.digest().into(),
                },
            },
            FetchedSourcePackage {
                package: git_package.clone(),
                observation: FetchedSourceObservation::GitCheckout {
                    precise: "1".repeat(40),
                    snapshot_tree_digest: git_tree.digest().into(),
                },
            },
        ],
    };
    let layout = CargoFetchCacheLayout {
        schema: 1,
        packages: vec![
            CargoFetchCachePackageLocation {
                package: package(),
                archive_path: None,
                source_path: None,
            },
            CargoFetchCachePackageLocation {
                package: registry_package,
                archive_path: Some(archive_path.into()),
                source_path: Some(registry_root.into()),
            },
            CargoFetchCachePackageLocation {
                package: git_package,
                archive_path: None,
                source_path: Some(git_root.into()),
            },
        ],
    };
    (request, locked_sources, cache_tree, layout, evidence)
}

#[cfg(target_os = "linux")]
fn make_cache_tree_writable(root: &Path) {
    for entry in walkdir::WalkDir::new(root).contents_first(true) {
        let entry = entry.unwrap();
        let mode = if entry.file_type().is_dir() {
            0o755
        } else {
            0o644
        };
        fs::set_permissions(entry.path(), fs::Permissions::from_mode(mode)).unwrap();
    }
}

#[cfg(target_os = "linux")]
#[test]
fn fetch_cache_materialization_is_sealed_reusable_and_mutation_detecting() {
    let temp = tempfile::TempDir::new().unwrap();
    let source = temp.path().join("cargo-home-source");
    let output = temp.path().join("verified-cache");
    fs::create_dir(&source).unwrap();
    let (request, locked_sources, cache_tree, layout, evidence) = real_fetch_cache_fixture(&source);
    let observation = validated_fetch_for_cache(&request, &locked_sources, &cache_tree, evidence);

    let first =
        materialize_cargo_fetch_cache(&source, &output, &request, &observation, &layout).unwrap();
    assert!(!first.reused());
    assert_eq!(first.path(), output);
    let verified = verify_materialized_cargo_fetch_cache(&output, &request, &observation).unwrap();
    assert_eq!(verified, *first.manifest());
    let verified_handle = open_verified_cargo_fetch_cache(&output, &request, &observation).unwrap();
    assert_eq!(verified_handle.path(), output);
    assert_eq!(verified_handle.manifest(), first.manifest());
    verified_handle.verify_unchanged().unwrap();

    let reused =
        materialize_cargo_fetch_cache(&source, &output, &request, &observation, &layout).unwrap();
    assert!(reused.reused());
    assert_eq!(reused.manifest(), first.manifest());

    let cached_source = output.join("registry/src/github-index/registry-lib-1.2.3/src/lib.rs");
    fs::set_permissions(&cached_source, fs::Permissions::from_mode(0o644)).unwrap();
    fs::write(&cached_source, b"attacker").unwrap();
    assert!(verified_handle.verify_unchanged().is_err());
    assert!(verify_materialized_cargo_fetch_cache(&output, &request, &observation).is_err());
    assert!(
        materialize_cargo_fetch_cache(&source, &output, &request, &observation, &layout).is_err()
    );
    assert_eq!(fs::read(&cached_source).unwrap(), b"attacker");

    make_cache_tree_writable(&output);
}

#[cfg(target_os = "linux")]
#[test]
fn verified_fetch_cache_handle_rejects_exact_path_replacement() {
    let temp = tempfile::TempDir::new().unwrap();
    let source = temp.path().join("cargo-home-source");
    let output = temp.path().join("verified-cache");
    let displaced = temp.path().join("displaced-cache");
    fs::create_dir(&source).unwrap();
    let (request, locked_sources, cache_tree, layout, evidence) = real_fetch_cache_fixture(&source);
    let observation = validated_fetch_for_cache(&request, &locked_sources, &cache_tree, evidence);

    materialize_cargo_fetch_cache(&source, &output, &request, &observation, &layout).unwrap();
    let verified = open_verified_cargo_fetch_cache(&output, &request, &observation).unwrap();

    fs::rename(&output, &displaced).unwrap();
    let replacement =
        materialize_cargo_fetch_cache(&source, &output, &request, &observation, &layout).unwrap();
    assert!(!replacement.reused());
    verify_materialized_cargo_fetch_cache(&output, &request, &observation).unwrap();
    assert!(matches!(
        verified.verify_unchanged(),
        Err(CargoFetchCacheError::Materialization(
            SnapshotMaterializationError::SourceChanged(_)
        ))
    ));

    make_cache_tree_writable(&output);
    make_cache_tree_writable(&displaced);
}

#[cfg(target_os = "linux")]
#[test]
fn concurrent_fetch_cache_publication_has_one_winner_and_verified_reuse() {
    let temp = tempfile::TempDir::new().unwrap();
    let source = temp.path().join("cargo-home-source");
    let output = temp.path().join("verified-cache");
    fs::create_dir(&source).unwrap();
    let (request, locked_sources, cache_tree, layout, evidence) = real_fetch_cache_fixture(&source);
    let observation = validated_fetch_for_cache(&request, &locked_sources, &cache_tree, evidence);

    let mut reused = std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            materialize_cargo_fetch_cache(&source, &output, &request, &observation, &layout)
                .unwrap()
                .reused()
        });
        let second = scope.spawn(|| {
            materialize_cargo_fetch_cache(&source, &output, &request, &observation, &layout)
                .unwrap()
                .reused()
        });
        vec![first.join().unwrap(), second.join().unwrap()]
    });
    reused.sort_unstable();
    assert_eq!(reused, [false, true]);
    verify_materialized_cargo_fetch_cache(&output, &request, &observation).unwrap();
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 2);

    make_cache_tree_writable(&output);
}

#[cfg(target_os = "linux")]
#[test]
fn fetch_cache_rejection_leaves_no_publication_or_staging_residue() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::TempDir::new().unwrap();
    let source = temp.path().join("cargo-home-source");
    let output = temp.path().join("verified-cache");
    fs::create_dir(&source).unwrap();
    let (request, locked_sources, cache_tree, mut layout, evidence) =
        real_fetch_cache_fixture(&source);
    let observation = validated_fetch_for_cache(&request, &locked_sources, &cache_tree, evidence);
    layout.packages[1].archive_path = Some("registry/cache/../escape.crate".into());
    assert!(
        materialize_cargo_fetch_cache(&source, &output, &request, &observation, &layout).is_err()
    );
    assert!(!output.exists());
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);

    symlink(
        "Cargo.toml",
        source.join("registry/src/github-index/registry-lib-1.2.3/redirect"),
    )
    .unwrap();
    assert!(
        materialize_cargo_fetch_cache(&source, &output, &request, &observation, &layout).is_err()
    );
    assert!(!output.exists());
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
}
