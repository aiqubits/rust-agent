use rust_agent_build_executor::{
    BuildEnforcementContext, BuildPanicStrategy, CanonicalSnapshotMetadataContract,
    CargoCompilationKind, CargoCompileMode, CargoCrateKind, CargoDependencyKind,
    CargoPackageIdentity, CargoPackageSource, CargoTargetEvaluationDomain, CargoUnit,
    CargoUnitEdge, CargoUnitGraphPlannerIdentity, CargoUnitSelector, DerivedExecutablePolicy,
    HostBuildClosureContent, HostBuildClosureItem, HostBuildClosureItemRole, HostBuildClosureStage,
    HostBuildInputClosure, HostBuildInputClosureError, HostCargoUnitGraph,
    HostFeaturePolicyClosure, NormalizedProductionBuildPolicy, ProductionAttestationPolicy,
    ProductionBuildExecutionPolicy, ProductionFetchPolicy, ProductionSandboxBackend,
    ProductionToolIdentity, ProductionToolchain, ProductionTreeIdentity, SigningHelper,
    TrustedReviewerPolicy, TrustedSigner, verify_development_host_closure_stage_chain,
};
use rust_agent_composition::metadata::BuildRequirements;

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
        artifact_selector: "host-integration".into(),
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
        compile_mode: CargoCompileMode::Build,
        profile: "release".into(),
        crate_kind: CargoCrateKind::Library,
    }
}

fn unit_graph() -> HostCargoUnitGraph {
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
        "2e7cfae555561ef0dbdd93b8965afdd11af8f97a99b8582acc1cf634e531c51e"
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

    let mut escape = closure(&policy);
    escape.items[0].logical_path = "/rust-agent/closure/../secret".into();
    assert!(matches!(
        escape.normalize(&policy),
        Err(HostBuildInputClosureError::InvalidLogicalPath(_))
    ));

    let mut duplicate = closure(&policy);
    duplicate.items[1].logical_path = duplicate.items[0].logical_path.clone();
    assert!(matches!(
        duplicate.normalize(&policy),
        Err(HostBuildInputClosureError::DuplicateItem(_))
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
