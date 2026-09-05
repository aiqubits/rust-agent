use std::collections::BTreeSet;

use rust_agent_build_executor::{
    BuildArtifactSelector, BuildArtifactTarget, BuildEnforcementContext, BuildPanicStrategy,
    DerivedExecutablePolicy, ProductionAttestationPolicy, ProductionBuildExecutionPolicy,
    ProductionBuildPolicyError, ProductionEnvironment, ProductionExecutable, ProductionFetchPolicy,
    ProductionFetchRedirectPolicy, ProductionFileIdentity, ProductionHostLinker,
    ProductionReadInput, ProductionSandboxBackend, ProductionToolIdentity, ProductionToolchain,
    ProductionTreeIdentity, SigningHelper, TrustedReviewerPolicy, TrustedSigner,
};
use rust_agent_composition::metadata::BuildRequirements;

fn digest(byte: &str) -> String {
    byte.repeat(64)
}

fn policy() -> ProductionBuildExecutionPolicy {
    ProductionBuildExecutionPolicy {
        schema: 3,
        id: "ci-linux-hermetic-v1".into(),
        host: "cfg(target_os = \"linux\")".into(),
        backend: ProductionSandboxBackend::LinuxLandlockSeccomp,
        fetch: ProductionFetchPolicy {
            network_endpoints: vec![
                "https://index.crates.io:443".into(),
                "https://static.crates.io:443".into(),
            ],
            credential_helper: Some(ProductionFileIdentity {
                path: "/runner-a/bin/cargo-credential-helper".into(),
                sha256: digest("1"),
            }),
            tls_ca_bundle: Some(ProductionFileIdentity {
                path: "/runner-a/tls/ca-bundle.pem".into(),
                sha256: digest("0"),
            }),
            redirect_policy: ProductionFetchRedirectPolicy::DenyUnlistedOrigin,
        },
        attestation: ProductionAttestationPolicy {
            allowed_executors: vec![
                "rust-agent-build-host-v1".into(),
                "rust-agent-build-v1".into(),
            ],
            trusted_signers: vec![
                TrustedSigner {
                    id: "ci-runner-2026".into(),
                    algorithm: "ed25519".into(),
                    public_key: "/runner-a/keys/ci-runner.pub".into(),
                    sha256: digest("2"),
                },
                TrustedSigner {
                    id: "security-review-2026".into(),
                    algorithm: "ed25519".into(),
                    public_key: "/runner-a/keys/security-review.pub".into(),
                    sha256: digest("3"),
                },
            ],
            trusted_reviewer_policies: vec![TrustedReviewerPolicy {
                id: "cargo-feature-semantics-v1".into(),
                signer_ids: vec!["security-review-2026".into()],
                min_signatures: 1,
            }],
            signing_helper: SigningHelper {
                signer_id: "ci-runner-2026".into(),
                path: "/runner-a/bin/rust-agent-ci-sign".into(),
                sha256: digest("4"),
            },
        },
        toolchain: ProductionToolchain {
            cargo: ProductionToolIdentity {
                path: "/runner-a/toolchain/bin/cargo".into(),
                sha256: digest("5"),
                version: "cargo 1.97.1 (fixture 2026-08-01)".into(),
            },
            rustc: ProductionToolIdentity {
                path: "/runner-a/toolchain/bin/rustc".into(),
                sha256: digest("6"),
                version: "rustc 1.97.1 (fixture 2026-08-01)".into(),
            },
            sysroot: ProductionTreeIdentity {
                path: "/runner-a/toolchain/sysroot".into(),
                tree_digest: digest("7"),
            },
        },
        read_inputs: vec![
            ProductionReadInput {
                id: "target-sdk".into(),
                path: "/runner-a/sdk/target".into(),
                tree_digest: digest("8"),
            },
            ProductionReadInput {
                id: "unused-sdk".into(),
                path: "/runner-a/sdk/unused".into(),
                tree_digest: digest("9"),
            },
        ],
        executables: vec![
            ProductionExecutable {
                id: "target-linker".into(),
                path: "/runner-a/sdk/bin/target-cc".into(),
                sha256: digest("a"),
                version: "target-cc fixture-v1".into(),
            },
            ProductionExecutable {
                id: "unused-codegen".into(),
                path: "/runner-a/sdk/bin/unused-codegen".into(),
                sha256: digest("b"),
                version: "unused-codegen fixture-v1".into(),
            },
            ProductionExecutable {
                id: "host-linker-helper".into(),
                path: "/runner-a/sdk/bin/host-linker-helper".into(),
                sha256: digest("c"),
                version: "host-linker-helper fixture-v1".into(),
            },
        ],
        host_linker: Some(ProductionHostLinker {
            executable: "target-linker".into(),
            helpers: vec!["host-linker-helper".into()],
        }),
        environment: vec![
            ProductionEnvironment {
                id: "unused-channel".into(),
                variable: "UNUSED_CHANNEL".into(),
                value: "unused".into(),
            },
            ProductionEnvironment {
                id: "vendor-sdk-channel".into(),
                variable: "VENDOR_SDK_CHANNEL".into(),
                value: "stable".into(),
            },
        ],
        derived_executable: DerivedExecutablePolicy {
            roots: vec!["target".into()],
            inherit_sandbox: true,
        },
    }
}

fn requirements() -> BuildRequirements {
    BuildRequirements {
        executables: BTreeSet::from(["host-linker-helper".into(), "target-linker".into()]),
        read_inputs: BTreeSet::from(["target-sdk".into()]),
        environment: BTreeSet::from(["vendor-sdk-channel".into()]),
    }
}

fn context() -> BuildEnforcementContext {
    BuildEnforcementContext {
        schema: 1,
        build_triple: "x86_64-unknown-linux-gnu".into(),
        target: "aarch64-unknown-linux-gnu".into(),
        target_facts_digest: digest("c"),
        custom_target_spec_digest: None,
        cargo_resolution_digest: digest("d"),
        cargo_config_digest: digest("e"),
        profile: "release".into(),
        artifact_selector: BuildArtifactSelector {
            package: "host-fixture".into(),
            target: BuildArtifactTarget::Library,
        },
        panic_strategy: BuildPanicStrategy::Unwind,
        rustc_settings_digest: digest("f"),
        prefix_remap_schema: 1,
    }
}

#[test]
fn policy_and_enforcement_identity_have_separate_stable_domains() {
    let normalized = policy().normalize().unwrap();
    let full_digest = normalized.full_digest().to_owned();
    let enforcement_digest = normalized
        .enforcement_identity_digest(&requirements(), &context())
        .unwrap();
    let identity = normalized
        .enforcement_identity(&requirements(), &context())
        .unwrap();
    assert_eq!(identity.digest().unwrap(), enforcement_digest);

    let encoded = serde_json::to_string(&identity).unwrap();
    assert!(!encoded.contains("/runner-a/"));
    assert!(!encoded.contains("ci-runner-2026"));
    assert!(!encoded.contains("cargo-feature-semantics-v1"));
    assert!(encoded.contains("/rust-agent/tools/target-linker"));
    assert_eq!(identity.executables.len(), 2);
    assert_eq!(identity.host_linker.as_ref().unwrap().helpers.len(), 1);
    assert_eq!(
        identity.deterministic_environment.get("COMPILER_PATH"),
        Some(&"/rust-agent/tools".into())
    );
    assert_eq!(identity.read_inputs.len(), 1);
    assert_eq!(identity.environment.len(), 1);

    let mut rotated = policy();
    rotated.id = "ci-linux-hermetic-v2".into();
    rotated.fetch.network_endpoints = vec!["https://mirror.example:443".into()];
    rotated.fetch.credential_helper.as_mut().unwrap().path =
        "/runner-b/bin/cargo-credential-helper".into();
    rotated.fetch.tls_ca_bundle.as_mut().unwrap().path = "/runner-b/tls/ca-bundle.pem".into();
    rotated.attestation.trusted_signers[0].public_key = "/runner-b/keys/ci.pub".into();
    rotated.attestation.trusted_signers[0].sha256 = digest("c");
    rotated.attestation.signing_helper.path = "/runner-b/bin/sign".into();
    rotated.attestation.signing_helper.sha256 = digest("d");
    rotated.toolchain.cargo.path = "/runner-b/toolchain/bin/cargo".into();
    rotated.toolchain.rustc.path = "/runner-b/toolchain/bin/rustc".into();
    rotated.toolchain.sysroot.path = "/runner-b/toolchain/sysroot".into();
    rotated.executables[0].path = "/runner-b/sdk/bin/target-cc".into();
    rotated.read_inputs[0].path = "/runner-b/sdk/target".into();
    let rotated = rotated.normalize().unwrap();
    assert_ne!(rotated.full_digest(), full_digest);
    assert_eq!(
        rotated
            .enforcement_identity_digest(&requirements(), &context())
            .unwrap(),
        enforcement_digest
    );

    let mut changed_input = policy();
    changed_input.executables[0].sha256 = digest("e");
    assert_ne!(
        changed_input
            .normalize()
            .unwrap()
            .enforcement_identity_digest(&requirements(), &context())
            .unwrap(),
        enforcement_digest
    );

    let mut changed_unused_input = policy();
    changed_unused_input.executables[1].sha256 = digest("f");
    let changed_unused_input = changed_unused_input.normalize().unwrap();
    assert_ne!(changed_unused_input.full_digest(), full_digest);
    assert_eq!(
        changed_unused_input
            .enforcement_identity_digest(&requirements(), &context())
            .unwrap(),
        enforcement_digest
    );

    let mut changed_context = context();
    changed_context.target_facts_digest = digest("0");
    assert_ne!(
        normalized
            .enforcement_identity_digest(&requirements(), &changed_context)
            .unwrap(),
        enforcement_digest
    );
}

#[test]
fn normalization_is_order_independent_and_schema_digest_is_frozen() {
    let normalized = policy().normalize().unwrap();
    let mut reordered = policy();
    reordered.fetch.network_endpoints.reverse();
    reordered.attestation.allowed_executors.reverse();
    reordered.attestation.trusted_signers.reverse();
    reordered.attestation.trusted_reviewer_policies[0]
        .signer_ids
        .reverse();
    reordered.executables.reverse();
    reordered.read_inputs.reverse();
    reordered.environment.reverse();
    let reordered = reordered.normalize().unwrap();
    assert_eq!(reordered.full_digest(), normalized.full_digest());
    assert_eq!(
        reordered
            .enforcement_identity_digest(&requirements(), &context())
            .unwrap(),
        normalized
            .enforcement_identity_digest(&requirements(), &context())
            .unwrap()
    );

    assert_eq!(
        normalized.full_digest(),
        "ceb50e62bca590cf00851599eed1e85d8270f56af73e006deac6e72cbc5f89ab"
    );
    assert_eq!(
        normalized
            .enforcement_identity_digest(&requirements(), &context())
            .unwrap(),
        "b5e39569c2c3a4f11e4ffd1f88979ca4873ca1b680fca788f2fc0d938e693661"
    );
}

#[test]
fn requirement_resolution_is_typed_and_minimal() {
    let normalized = policy().normalize().unwrap();
    let mut wrong_kind = requirements();
    wrong_kind.executables = BTreeSet::from(["target-sdk".into()]);
    assert!(matches!(
        normalized.enforcement_identity(&wrong_kind, &context()),
        Err(ProductionBuildPolicyError::Requirement(
            rust_agent_build_executor::BuildPolicyError::KindMismatch { .. }
        ))
    ));

    let mut missing = requirements();
    missing.read_inputs = BTreeSet::from(["missing-sdk".into()]);
    assert!(matches!(
        normalized.enforcement_identity(&missing, &context()),
        Err(ProductionBuildPolicyError::Requirement(
            rust_agent_build_executor::BuildPolicyError::MissingMapping { .. }
        ))
    ));
}

#[test]
fn host_linker_bundle_is_closed_selected_and_path_free() {
    let mut old_schema = policy();
    old_schema.schema = 2;
    assert!(matches!(
        old_schema.normalize(),
        Err(ProductionBuildPolicyError::UnsupportedSchema(2))
    ));

    let mut unordered = policy();
    unordered.host_linker.as_mut().unwrap().helpers =
        vec!["unused-codegen".into(), "host-linker-helper".into()];
    let requirements = BuildRequirements {
        executables: BTreeSet::from([
            "host-linker-helper".into(),
            "target-linker".into(),
            "unused-codegen".into(),
        ]),
        ..BuildRequirements::default()
    };
    let normalized = unordered.normalize().unwrap();
    assert_eq!(
        normalized.policy().host_linker.as_ref().unwrap().helpers,
        ["host-linker-helper", "unused-codegen"]
    );
    let identity = normalized
        .enforcement_identity(&requirements, &context())
        .unwrap();
    let host_linker = identity.host_linker.unwrap();
    assert_eq!(identity.backend_semantic_version, 4);
    assert_eq!(
        host_linker.cargo_config,
        "host.x86_64-unknown-linux-gnu.linker=\"/rust-agent/tools/target-linker\""
    );
    assert_eq!(host_linker.compiler_path, "/rust-agent/tools");
    assert!(
        !serde_json::to_string(&host_linker)
            .unwrap()
            .contains("/runner-a/")
    );

    let partial = BuildRequirements {
        executables: BTreeSet::from(["target-linker".into()]),
        ..BuildRequirements::default()
    };
    assert!(matches!(
        normalized.enforcement_identity(&partial, &context()),
        Err(ProductionBuildPolicyError::PartialHostLinkerSelection)
    ));

    let unselected = normalized
        .enforcement_identity(&BuildRequirements::default(), &context())
        .unwrap();
    assert!(unselected.host_linker.is_none());
    assert!(
        !unselected
            .deterministic_environment
            .contains_key("COMPILER_PATH")
    );

    let mut duplicate = policy();
    duplicate
        .host_linker
        .as_mut()
        .unwrap()
        .helpers
        .push("host-linker-helper".into());
    assert!(matches!(
        duplicate.normalize(),
        Err(ProductionBuildPolicyError::InvalidHostLinker(_))
    ));

    let mut missing = policy();
    missing.host_linker.as_mut().unwrap().helpers = vec!["missing-helper".into()];
    assert!(matches!(
        missing.normalize(),
        Err(ProductionBuildPolicyError::InvalidHostLinker(_))
    ));
}

#[test]
fn production_policy_rejects_untrusted_or_ambient_surfaces() {
    let normalized = policy().normalize().unwrap();
    let mut invalid_context = context();
    invalid_context.prefix_remap_schema = 2;
    assert!(matches!(
        normalized.enforcement_identity(&requirements(), &invalid_context),
        Err(ProductionBuildPolicyError::UnsupportedPrefixRemapSchema(2))
    ));

    let mut invalid_context = context();
    invalid_context.artifact_selector.package = "Host Fixture".into();
    assert!(matches!(
        normalized.enforcement_identity(&requirements(), &invalid_context),
        Err(ProductionBuildPolicyError::InvalidEnforcementContext(
            "artifact-selector.package"
        ))
    ));

    let mut invalid_context = context();
    invalid_context.artifact_selector.target = BuildArtifactTarget::Binary {
        name: "../host".into(),
    };
    assert!(matches!(
        normalized.enforcement_identity(&requirements(), &invalid_context),
        Err(ProductionBuildPolicyError::InvalidEnforcementContext(
            "artifact-selector.target.name"
        ))
    ));

    let mut invalid = policy();
    invalid.host = "cfg(unix)".into();
    assert!(matches!(
        invalid.normalize(),
        Err(ProductionBuildPolicyError::UnsupportedHost)
    ));

    let mut invalid = policy();
    invalid.fetch.network_endpoints[0] = "http://index.crates.io:80".into();
    assert!(matches!(
        invalid.normalize(),
        Err(ProductionBuildPolicyError::InvalidFetchEndpoint(_))
    ));

    let mut invalid = policy();
    invalid.fetch.network_endpoints[0] = "https://Index.Crates.io:443".into();
    assert!(matches!(
        invalid.normalize(),
        Err(ProductionBuildPolicyError::InvalidFetchEndpoint(_))
    ));

    let mut invalid = policy();
    invalid.fetch.tls_ca_bundle = None;
    assert!(matches!(
        invalid.normalize(),
        Err(ProductionBuildPolicyError::MissingFetchTlsCaBundle)
    ));

    let mut invalid = policy();
    invalid.fetch.network_endpoints.clear();
    invalid.fetch.tls_ca_bundle = None;
    assert!(matches!(
        invalid.normalize(),
        Err(ProductionBuildPolicyError::CredentialHelperWithoutEndpoint)
    ));

    let mut invalid = policy();
    invalid.environment[0].variable = "RUSTFLAGS".into();
    assert!(matches!(
        invalid.normalize(),
        Err(ProductionBuildPolicyError::ForbiddenEnvironment { .. })
    ));

    let mut invalid = policy();
    invalid.environment[0].value = "/host/ambient/path".into();
    assert!(matches!(
        invalid.normalize(),
        Err(ProductionBuildPolicyError::InvalidEnvironmentValue { .. })
    ));

    let mut invalid = policy();
    invalid.toolchain.rustc.version = "rustc 1.98.0".into();
    assert!(matches!(
        invalid.normalize(),
        Err(ProductionBuildPolicyError::UnpinnedRustToolchain)
    ));

    let mut invalid = policy();
    invalid.toolchain.rustc.path = "/runner-a/toolchain/../bin/rustc".into();
    assert!(matches!(
        invalid.normalize(),
        Err(ProductionBuildPolicyError::InvalidPath(_))
    ));

    let mut invalid = policy();
    invalid.derived_executable.inherit_sandbox = false;
    assert!(matches!(
        invalid.normalize(),
        Err(ProductionBuildPolicyError::InvalidDerivedExecutablePolicy)
    ));
}

#[test]
fn attestation_trust_graph_and_closed_toml_fail_closed() {
    let mut external_executor = policy();
    external_executor.attestation.allowed_executors = vec!["framework-product-executor-v1".into()];
    external_executor.normalize().unwrap();

    let mut invalid = policy();
    invalid
        .attestation
        .allowed_executors
        .push("Shell Script".into());
    assert!(matches!(
        invalid.normalize(),
        Err(ProductionBuildPolicyError::InvalidId {
            kind: "allowed executor",
            ..
        })
    ));

    let mut invalid = policy();
    invalid.attestation.trusted_signers[0].algorithm = "rsa".into();
    assert!(matches!(
        invalid.normalize(),
        Err(ProductionBuildPolicyError::UnsupportedSignerAlgorithm { .. })
    ));

    let mut invalid = policy();
    invalid.attestation.signing_helper.signer_id = "untrusted".into();
    assert!(matches!(
        invalid.normalize(),
        Err(ProductionBuildPolicyError::UnknownSigningHelperSigner(_))
    ));

    let mut invalid = policy();
    invalid.attestation.trusted_reviewer_policies[0].min_signatures = 2;
    assert!(matches!(
        invalid.normalize(),
        Err(ProductionBuildPolicyError::InvalidReviewerThreshold { .. })
    ));

    let encoded = toml::to_string(&policy()).unwrap();
    ProductionBuildExecutionPolicy::from_toml(&encoded)
        .unwrap()
        .normalize()
        .unwrap();
    let unknown = encoded.replacen("schema = 3", "schema = 3\nambient-home = true", 1);
    assert!(matches!(
        ProductionBuildExecutionPolicy::from_toml(&unknown),
        Err(ProductionBuildPolicyError::Toml(_))
    ));
}

#[test]
fn network_fetch_schema_two_binds_ca_and_redirect_policy() {
    let normalized = policy().normalize().unwrap();
    let encoded = toml::to_string(normalized.policy()).unwrap();
    assert!(encoded.contains("redirect-policy = \"deny-unlisted-origin\""));
    assert!(encoded.contains("[fetch.tls-ca-bundle]"));

    let mut changed = policy();
    changed.fetch.tls_ca_bundle.as_mut().unwrap().sha256 = digest("d");
    assert_ne!(
        changed.normalize().unwrap().full_digest(),
        normalized.full_digest()
    );

    let unknown = encoded.replace(
        "redirect-policy = \"deny-unlisted-origin\"",
        "redirect-policy = \"follow-anywhere\"",
    );
    assert!(matches!(
        ProductionBuildExecutionPolicy::from_toml(&unknown),
        Err(ProductionBuildPolicyError::Toml(_))
    ));
}
