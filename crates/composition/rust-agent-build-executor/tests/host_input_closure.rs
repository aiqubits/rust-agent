use rust_agent_build_executor::{
    BuildArtifactSelector, BuildArtifactTarget, BuildEnforcementContext, BuildPanicStrategy,
    CanonicalSnapshotMetadataContract, CargoCompilationKind, CargoCompileMode, CargoCrateKind,
    CargoDependencyKind, CargoPackageIdentity, CargoPackageSource, CargoTargetEvaluationDomain,
    CargoUnit, CargoUnitEdge, CargoUnitGraphPlannerIdentity, CargoUnitSelector,
    DerivedExecutablePolicy, FetchedSourceEvidence, FetchedSourceObservation, FetchedSourcePackage,
    HostBuildClosureContent, HostBuildClosureItem, HostBuildClosureItemRole, HostBuildClosureStage,
    HostBuildInputClosure, HostBuildInputClosureError, HostCargoUnitGraph,
    HostFeaturePolicyClosure, LockedSourceClosure, LockedSourceError,
    NormalizedProductionBuildPolicy, ProductionAttestationPolicy, ProductionBuildExecutionPolicy,
    ProductionFetchPolicy, ProductionSandboxBackend, ProductionToolIdentity, ProductionToolchain,
    ProductionTreeIdentity, SigningHelper, TrustedReviewerPolicy, TrustedSigner,
    verify_development_host_closure_stage_chain,
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
        content: HostBuildClosureContent::CanonicalRecord { digest },
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
        "617bcaba945ed6f6186270552eed224bef3326632a2f9900b132037fce42e50a"
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
