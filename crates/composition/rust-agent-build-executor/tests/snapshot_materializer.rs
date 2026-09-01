#![cfg(target_os = "linux")]

use std::{
    fs::{self, FileTimes, OpenOptions},
    io::Write,
    os::unix::{
        fs::{MetadataExt, PermissionsExt, symlink},
        net::UnixListener,
    },
    path::{Path, PathBuf},
    sync::{Arc, Barrier},
    thread,
    time::{Duration, SystemTime},
};

use rust_agent_build_executor::{
    BuildArtifactSelector, BuildArtifactTarget, BuildEnforcementContext, BuildPanicStrategy,
    CanonicalSnapshotMetadataContract, CargoCompilationKind, CargoCompileMode, CargoCrateKind,
    CargoDependencyKind, CargoPackageIdentity, CargoPackageSource, CargoTargetEvaluationDomain,
    CargoUnit, CargoUnitEdge, CargoUnitGraphPlannerIdentity, CargoUnitSelector,
    DerivedExecutablePolicy, HostBuildClosureContent, HostBuildClosureItem,
    HostBuildClosureItemRole, HostBuildInputClosure, HostCargoUnitGraph,
    HostClosureMountObservation, HostClosureSnapshotManifest, HostClosureSnapshotSource,
    HostFeaturePolicyClosure, NormalizedHostBuildInputClosure, NormalizedProductionBuildPolicy,
    ProductionAttestationPolicy, ProductionBuildExecutionPolicy, ProductionFetchPolicy,
    ProductionSandboxBackend, ProductionToolIdentity, ProductionToolchain, ProductionTreeIdentity,
    SigningHelper, SnapshotMaterializationError, TrustedSigner, materialize_host_closure_snapshot,
    verify_host_closure_snapshot,
};
use rust_agent_composition::{
    canonical,
    metadata::BuildRequirements,
    snapshot::{
        CanonicalSnapshotEntry, CanonicalSnapshotEntryKind, CanonicalSnapshotTree,
        MAX_CANONICAL_SNAPSHOT_FILE_BYTES, MAX_CANONICAL_SNAPSHOT_JSON_BYTES,
        MAX_CANONICAL_SNAPSHOT_TOTAL_FILE_BYTES,
    },
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const HOST_MANIFEST_IN_TREE: &[u8] = b"[package]\nname = \"host-fixture\"\nversion = \"0.1.0\"\n";
const HOST_MANIFEST_CONFLICT: &[u8] =
    b"[package]\nname = \"different-host\"\nversion = \"0.1.0\"\n";
const HOST_LOCK: &[u8] = b"version = 4\n";
const CARGO_CONFIG: &[u8] = b"[net]\noffline = true\n";
const HOST_LIB: &[u8] = b"pub fn host() {}\n";
const EMITTED_MANIFEST: &[u8] = b"[package]\nname = \"generated-agent\"\nversion = \"0.1.0\"\n";
const EMITTED_LIB: &[u8] = b"pub fn generated() {}\n";
const CARGO_RESOLUTION_BYTES: &[u8] = b"{\"schema\":1,\"registries\":{}}";
const TARGET_FACTS_BYTES: &[u8] = b"{\"schema\":1,\"target\":\"aarch64-unknown-linux-gnu\"}";
const RUSTC_SETTINGS_BYTES: &[u8] = b"{\"schema\":1,\"remap\":true}";
const ARTIFACT_SELECTOR_BYTES: &[u8] =
    b"{\"package\":\"host-fixture\",\"target\":{\"kind\":\"library\"}}";

struct Fixture {
    raw: HostBuildInputClosure,
    closure: NormalizedHostBuildInputClosure,
    sources: Vec<HostClosureSnapshotSource>,
    source_root: PathBuf,
    host_tree: PathBuf,
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn labeled_digest(label: &str) -> String {
    sha256(label.as_bytes())
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
                sha256: labeled_digest("signer-key"),
            }],
            trusted_reviewer_policies: vec![],
            signing_helper: SigningHelper {
                signer_id: "ci-runner-2026".into(),
                path: "/runner/bin/sign".into(),
                sha256: labeled_digest("signing-helper"),
            },
        },
        toolchain: ProductionToolchain {
            cargo: ProductionToolIdentity {
                path: "/runner/toolchain/bin/cargo".into(),
                sha256: labeled_digest("cargo"),
                version: "cargo 1.97.1 (fixture 2026-08-01)".into(),
            },
            rustc: ProductionToolIdentity {
                path: "/runner/toolchain/bin/rustc".into(),
                sha256: labeled_digest("rustc"),
                version: "rustc 1.97.1 (fixture 2026-08-01)".into(),
            },
            sysroot: ProductionTreeIdentity {
                path: "/runner/toolchain/sysroot".into(),
                tree_digest: labeled_digest("sysroot"),
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
        target_facts_digest: labeled_digest("target-facts-record"),
        custom_target_spec_digest: None,
        cargo_resolution_digest: labeled_digest("cargo-resolution-record"),
        cargo_config_digest: sha256(CARGO_CONFIG),
        profile: "release".into(),
        artifact_selector: BuildArtifactSelector {
            package: "host-fixture".into(),
            target: BuildArtifactTarget::Library,
        },
        panic_strategy: BuildPanicStrategy::Unwind,
        rustc_settings_digest: labeled_digest("rustc-settings-record"),
        prefix_remap_schema: 1,
    }
}

fn package() -> CargoPackageIdentity {
    CargoPackageIdentity {
        name: "host-fixture".into(),
        version: "0.1.0".into(),
        source: CargoPackageSource::Path {
            tree_digest: labeled_digest("host-unit-package-tree"),
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
            cargo_digest: labeled_digest("cargo"),
            rustc_version: "1.97.1".into(),
            rustc_digest: labeled_digest("rustc"),
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

fn canonical_tree(entries: Vec<CanonicalSnapshotEntry>) -> CanonicalSnapshotTree {
    CanonicalSnapshotTree::from_entries(entries).unwrap()
}

fn host_tree_digest() -> String {
    canonical_tree(vec![
        CanonicalSnapshotEntry::directory(".cargo"),
        CanonicalSnapshotEntry::regular_file(
            ".cargo/config.toml",
            sha256(CARGO_CONFIG),
            CARGO_CONFIG.len() as u64,
        ),
        CanonicalSnapshotEntry::regular_file(
            "Cargo.lock",
            sha256(HOST_LOCK),
            HOST_LOCK.len() as u64,
        ),
        CanonicalSnapshotEntry::regular_file(
            "Cargo.toml",
            sha256(HOST_MANIFEST_IN_TREE),
            HOST_MANIFEST_IN_TREE.len() as u64,
        ),
        CanonicalSnapshotEntry::directory("src"),
        CanonicalSnapshotEntry::regular_file("src/lib.rs", sha256(HOST_LIB), HOST_LIB.len() as u64),
    ])
    .digest()
    .into()
}

fn emitted_tree_digest() -> String {
    canonical_tree(vec![
        CanonicalSnapshotEntry::regular_file(
            "Cargo.toml",
            sha256(EMITTED_MANIFEST),
            EMITTED_MANIFEST.len() as u64,
        ),
        CanonicalSnapshotEntry::directory("src"),
        CanonicalSnapshotEntry::regular_file(
            "src/lib.rs",
            sha256(EMITTED_LIB),
            EMITTED_LIB.len() as u64,
        ),
    ])
    .digest()
    .into()
}

fn file_item(
    role: HostBuildClosureItemRole,
    id: &str,
    logical_path: &str,
    bytes: &[u8],
) -> HostBuildClosureItem {
    HostBuildClosureItem {
        role,
        id: id.into(),
        logical_path: logical_path.into(),
        metadata_contract: CanonicalSnapshotMetadataContract::ReadOnlyEpochV1,
        content: HostBuildClosureContent::File {
            sha256: sha256(bytes),
        },
    }
}

fn tree_item(
    role: HostBuildClosureItemRole,
    id: &str,
    logical_path: &str,
    tree_digest: String,
) -> HostBuildClosureItem {
    HostBuildClosureItem {
        role,
        id: id.into(),
        logical_path: logical_path.into(),
        metadata_contract: CanonicalSnapshotMetadataContract::ReadOnlyEpochV1,
        content: HostBuildClosureContent::SnapshotTree { tree_digest },
    }
}

fn record_item(
    role: HostBuildClosureItemRole,
    id: &str,
    logical_path: &str,
    semantic_digest: String,
    bytes: &[u8],
) -> HostBuildClosureItem {
    HostBuildClosureItem {
        role,
        id: id.into(),
        logical_path: logical_path.into(),
        metadata_contract: CanonicalSnapshotMetadataContract::ReadOnlyEpochV1,
        content: HostBuildClosureContent::CanonicalRecord {
            digest: semantic_digest,
            bytes_sha256: sha256(bytes),
        },
    }
}

fn write_file(root: &Path, relative: &str, bytes: &[u8]) -> PathBuf {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, bytes).unwrap();
    fs::canonicalize(path).unwrap()
}

impl Fixture {
    fn new(parent: &Path, name: &str, conflicting_overlay: bool) -> Self {
        let policy = policy();
        let context = context();
        let requirements = BuildRequirements::default();
        let source_root = parent.join(name);
        fs::create_dir(&source_root).unwrap();

        let host_tree = source_root.join("host-tree");
        fs::create_dir(&host_tree).unwrap();
        write_file(&host_tree, "Cargo.toml", HOST_MANIFEST_IN_TREE);
        write_file(&host_tree, "Cargo.lock", HOST_LOCK);
        write_file(&host_tree, ".cargo/config.toml", CARGO_CONFIG);
        write_file(&host_tree, "src/lib.rs", HOST_LIB);
        let host_tree = fs::canonicalize(host_tree).unwrap();

        let emitted_tree = source_root.join("emitted-tree");
        fs::create_dir(&emitted_tree).unwrap();
        write_file(&emitted_tree, "Cargo.toml", EMITTED_MANIFEST);
        write_file(&emitted_tree, "src/lib.rs", EMITTED_LIB);
        let emitted_tree = fs::canonicalize(emitted_tree).unwrap();

        let direct_manifest_bytes = if conflicting_overlay {
            HOST_MANIFEST_CONFLICT
        } else {
            HOST_MANIFEST_IN_TREE
        };
        let root_manifest = write_file(
            &source_root,
            "direct/host-root-Cargo.toml",
            direct_manifest_bytes,
        );
        let cargo_lock = write_file(&source_root, "direct/host-Cargo.lock", HOST_LOCK);
        let cargo_config = write_file(&source_root, "direct/cargo-config.toml", CARGO_CONFIG);
        let cargo_resolution = write_file(
            &source_root,
            "records/cargo-resolution.json",
            CARGO_RESOLUTION_BYTES,
        );
        let target_facts = write_file(
            &source_root,
            "records/target-facts.json",
            TARGET_FACTS_BYTES,
        );
        let rustc_settings = write_file(
            &source_root,
            "records/rustc-settings.json",
            RUSTC_SETTINGS_BYTES,
        );
        let artifact_selector = write_file(
            &source_root,
            "records/artifact-selector.json",
            ARTIFACT_SELECTOR_BYTES,
        );

        let raw = HostBuildInputClosure {
            schema: 1,
            composition_hash: labeled_digest("composition"),
            host_dependency_alias: "generated-agent".into(),
            generated_package_name: "rust-agent-composition-fixture".into(),
            items: vec![
                tree_item(
                    HostBuildClosureItemRole::HostPackageTree,
                    "host-package-tree",
                    "/rust-agent/closure/host",
                    host_tree_digest(),
                ),
                file_item(
                    HostBuildClosureItemRole::HostRootManifest,
                    "host-root-manifest",
                    "/rust-agent/closure/host/Cargo.toml",
                    direct_manifest_bytes,
                ),
                file_item(
                    HostBuildClosureItemRole::HostCargoLock,
                    "host-cargo-lock",
                    "/rust-agent/closure/host/Cargo.lock",
                    HOST_LOCK,
                ),
                file_item(
                    HostBuildClosureItemRole::CargoConfig,
                    "cargo-config",
                    "/rust-agent/closure/host/.cargo/config.toml",
                    CARGO_CONFIG,
                ),
                tree_item(
                    HostBuildClosureItemRole::EmittedCompositionTree,
                    "emitted-composition-tree",
                    "/rust-agent/closure/emitted",
                    emitted_tree_digest(),
                ),
                record_item(
                    HostBuildClosureItemRole::CargoResolutionRecord,
                    "cargo-resolution",
                    "/rust-agent/closure/records/cargo-resolution.json",
                    context.cargo_resolution_digest.clone(),
                    CARGO_RESOLUTION_BYTES,
                ),
                record_item(
                    HostBuildClosureItemRole::TargetFactsRecord,
                    "target-facts",
                    "/rust-agent/closure/records/target-facts.json",
                    context.target_facts_digest.clone(),
                    TARGET_FACTS_BYTES,
                ),
                record_item(
                    HostBuildClosureItemRole::RustcSettingsRecord,
                    "rustc-settings",
                    "/rust-agent/closure/records/rustc-settings.json",
                    context.rustc_settings_digest.clone(),
                    RUSTC_SETTINGS_BYTES,
                ),
                record_item(
                    HostBuildClosureItemRole::ArtifactSelectorRecord,
                    "artifact-selector",
                    "/rust-agent/closure/records/artifact-selector.json",
                    context.artifact_selector.digest().unwrap(),
                    ARTIFACT_SELECTOR_BYTES,
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
            unit_feature_delta_digest: labeled_digest("unit-feature-delta"),
        };
        let closure = raw.normalize(&policy).unwrap();
        let sources = vec![
            HostClosureSnapshotSource {
                item_id: "host-package-tree".into(),
                path: host_tree.clone(),
            },
            HostClosureSnapshotSource {
                item_id: "host-root-manifest".into(),
                path: root_manifest,
            },
            HostClosureSnapshotSource {
                item_id: "host-cargo-lock".into(),
                path: cargo_lock,
            },
            HostClosureSnapshotSource {
                item_id: "cargo-config".into(),
                path: cargo_config,
            },
            HostClosureSnapshotSource {
                item_id: "emitted-composition-tree".into(),
                path: emitted_tree,
            },
            HostClosureSnapshotSource {
                item_id: "cargo-resolution".into(),
                path: cargo_resolution,
            },
            HostClosureSnapshotSource {
                item_id: "target-facts".into(),
                path: target_facts,
            },
            HostClosureSnapshotSource {
                item_id: "rustc-settings".into(),
                path: rustc_settings,
            },
            HostClosureSnapshotSource {
                item_id: "artifact-selector".into(),
                path: artifact_selector,
            },
        ];
        Self {
            raw,
            closure,
            sources,
            source_root: fs::canonicalize(source_root).unwrap(),
            host_tree,
        }
    }
}

fn assert_local_mode_mtime_projection(root: &Path) {
    fn visit(path: &Path) {
        let metadata = fs::symlink_metadata(path).unwrap();
        assert!(!metadata.file_type().is_symlink());
        assert_eq!(metadata.mtime(), 0, "mtime drift at {}", path.display());
        assert_eq!(
            metadata.mtime_nsec(),
            0,
            "mtime drift at {}",
            path.display()
        );
        if metadata.is_dir() {
            assert_eq!(
                metadata.mode() & 0o777,
                0o555,
                "mode drift at {}",
                path.display()
            );
            for entry in fs::read_dir(path).unwrap() {
                visit(&entry.unwrap().path());
            }
        } else {
            assert!(metadata.is_file());
            assert_eq!(
                metadata.mode() & 0o777,
                0o444,
                "mode drift at {}",
                path.display()
            );
        }
    }
    visit(root);
}

fn make_tree_writable(root: &Path) {
    let Ok(metadata) = fs::symlink_metadata(root) else {
        return;
    };
    if metadata.file_type().is_symlink() {
        return;
    }
    if metadata.is_dir() {
        fs::set_permissions(root, fs::Permissions::from_mode(0o755)).unwrap();
        for entry in fs::read_dir(root).unwrap() {
            make_tree_writable(&entry.unwrap().path());
        }
    } else if metadata.is_file() {
        fs::set_permissions(root, fs::Permissions::from_mode(0o644)).unwrap();
    }
}

fn assert_no_staging_directory(parent: &Path) {
    assert!(fs::read_dir(parent).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("rust-agent-snapshot-stage-")
    }));
}

fn set_local_mode_mtime(path: &Path, mode: u32) {
    let file = OpenOptions::new().read(true).open(path).unwrap();
    file.set_times(
        FileTimes::new()
            .set_accessed(SystemTime::UNIX_EPOCH)
            .set_modified(SystemTime::UNIX_EPOCH),
    )
    .unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn reseal_manifest(manifest: &mut HostClosureSnapshotManifest) {
    manifest.digest = hex::encode(
        canonical::domain_hash(
            b"rust-agent-host-closure-snapshot-manifest-v1\0",
            &(
                manifest.schema,
                manifest.deployable,
                &manifest.host_build_input_closure_digest,
                manifest.metadata_contract,
                &manifest.items,
                &manifest.data_tree_digest,
                &manifest.data_tree_entries,
            ),
        )
        .unwrap(),
    );
}

fn reseal_observation(observation: &mut HostClosureMountObservation) {
    observation.digest = hex::encode(
        canonical::domain_hash(
            b"rust-agent-host-closure-mount-observation-v1\0",
            &(
                observation.schema,
                &observation.snapshot_manifest_digest,
                &observation.logical_root,
                observation.read_only,
                &observation.entries,
            ),
        )
        .unwrap(),
    );
}

#[test]
fn materialization_is_deterministic_locally_sealed_and_live_source_independent() {
    let temp = TempDir::new().unwrap();
    let fixture = Fixture::new(temp.path(), "sources", false);
    let first_path = temp.path().join("snapshot-a");
    let second_path = temp.path().join("snapshot-b");

    let first =
        materialize_host_closure_snapshot(&fixture.closure, &fixture.sources, &first_path).unwrap();
    let mut reversed_sources = fixture.sources.clone();
    reversed_sources.reverse();
    let second =
        materialize_host_closure_snapshot(&fixture.closure, &reversed_sources, &second_path)
            .unwrap();

    assert!(!first.reused() && !second.reused());
    assert_eq!(first.manifest(), second.manifest());
    assert!(!first.manifest().deployable);
    assert_eq!(
        fs::read(first_path.join("data/host/Cargo.toml")).unwrap(),
        HOST_MANIFEST_IN_TREE
    );
    assert_local_mode_mtime_projection(&first_path);
    assert_local_mode_mtime_projection(&second_path);

    fs::remove_dir_all(&fixture.source_root).unwrap();
    assert_eq!(
        verify_host_closure_snapshot(&fixture.closure, &first_path).unwrap(),
        *first.manifest()
    );
    assert_eq!(
        verify_host_closure_snapshot(&fixture.closure, &second_path).unwrap(),
        *second.manifest()
    );

    make_tree_writable(&first_path);
    make_tree_writable(&second_path);
}

#[test]
fn exact_overlay_is_allowed_but_conflicting_overlay_never_publishes() {
    let temp = TempDir::new().unwrap();
    let exact = Fixture::new(temp.path(), "exact-sources", false);
    let exact_output = temp.path().join("exact-snapshot");
    let snapshot =
        materialize_host_closure_snapshot(&exact.closure, &exact.sources, &exact_output).unwrap();
    assert_eq!(
        fs::read(exact_output.join("data/host/Cargo.toml")).unwrap(),
        HOST_MANIFEST_IN_TREE
    );
    assert!(!snapshot.manifest().deployable);

    let conflicting = Fixture::new(temp.path(), "conflicting-sources", true);
    let conflicting_output = temp.path().join("conflicting-snapshot");
    assert!(matches!(
        materialize_host_closure_snapshot(
            &conflicting.closure,
            &conflicting.sources,
            &conflicting_output,
        ),
        Err(SnapshotMaterializationError::ConflictingOverlay(_))
    ));
    assert!(!conflicting_output.exists());
    assert_no_staging_directory(temp.path());

    make_tree_writable(&exact_output);
}

#[test]
fn descendant_file_and_record_overlays_work_on_both_sides_of_the_ancestor_tree() {
    let temp = TempDir::new().unwrap();
    let fixture = Fixture::new(temp.path(), "sources", false);
    let mut raw = fixture.raw.clone();
    raw.items
        .iter_mut()
        .find(|item| item.id == "host-root-manifest")
        .unwrap()
        .logical_path = "/rust-agent/closure/host/before-tree/Cargo.toml".into();
    raw.items
        .iter_mut()
        .find(|item| item.id == "cargo-resolution")
        .unwrap()
        .logical_path = "/rust-agent/closure/host/after-tree/cargo-resolution.json".into();
    let closure = raw.normalize(&policy()).unwrap();
    let item_position = |id: &str| {
        closure
            .items()
            .iter()
            .position(|item| item.id == id)
            .unwrap()
    };
    assert!(item_position("host-root-manifest") < item_position("host-package-tree"));
    assert!(item_position("host-package-tree") < item_position("cargo-resolution"));

    let output = temp.path().join("descendant-file-record-snapshot");
    let snapshot = materialize_host_closure_snapshot(&closure, &fixture.sources, &output).unwrap();
    assert!(!snapshot.reused());
    assert_eq!(
        fs::read(output.join("data/host/before-tree/Cargo.toml")).unwrap(),
        HOST_MANIFEST_IN_TREE
    );
    assert_eq!(
        fs::read(output.join("data/host/after-tree/cargo-resolution.json")).unwrap(),
        CARGO_RESOLUTION_BYTES
    );
    verify_host_closure_snapshot(&closure, &output).unwrap();

    make_tree_writable(&output);
}

#[test]
fn nested_tree_overlays_work_in_forward_and_reverse_role_order() {
    let temp = TempDir::new().unwrap();
    let fixture = Fixture::new(temp.path(), "sources", false);
    let host_descendant_bytes = b"host descendant package\n";
    let emitted_descendant_bytes = b"emitted descendant package\n";

    let host_descendant_source = fixture.source_root.join("host-descendant-source");
    fs::create_dir(&host_descendant_source).unwrap();
    write_file(
        &host_descendant_source,
        "host-descendant.txt",
        host_descendant_bytes,
    );
    let host_descendant_source = fs::canonicalize(host_descendant_source).unwrap();
    let host_descendant_tree = canonical_tree(vec![CanonicalSnapshotEntry::regular_file(
        "host-descendant.txt",
        sha256(host_descendant_bytes),
        host_descendant_bytes.len() as u64,
    )]);

    let emitted_descendant_source = fixture.source_root.join("emitted-descendant-source");
    fs::create_dir(&emitted_descendant_source).unwrap();
    write_file(
        &emitted_descendant_source,
        "emitted-descendant.txt",
        emitted_descendant_bytes,
    );
    let emitted_descendant_source = fs::canonicalize(emitted_descendant_source).unwrap();
    let emitted_descendant_tree = canonical_tree(vec![CanonicalSnapshotEntry::regular_file(
        "emitted-descendant.txt",
        sha256(emitted_descendant_bytes),
        emitted_descendant_bytes.len() as u64,
    )]);

    let mut raw = fixture.raw.clone();
    raw.items.push(tree_item(
        HostBuildClosureItemRole::PathPackageTree,
        "host-descendant-tree",
        "/rust-agent/closure/host/nested-package",
        host_descendant_tree.digest().into(),
    ));
    raw.items.push(tree_item(
        HostBuildClosureItemRole::PathPackageTree,
        "emitted-descendant-tree",
        "/rust-agent/closure/emitted/nested-package",
        emitted_descendant_tree.digest().into(),
    ));
    let closure = raw.normalize(&policy()).unwrap();
    let mut sources = fixture.sources.clone();
    sources.push(HostClosureSnapshotSource {
        item_id: "host-descendant-tree".into(),
        path: host_descendant_source,
    });
    sources.push(HostClosureSnapshotSource {
        item_id: "emitted-descendant-tree".into(),
        path: emitted_descendant_source,
    });
    let item_position = |id: &str| {
        closure
            .items()
            .iter()
            .position(|item| item.id == id)
            .unwrap()
    };
    assert!(item_position("host-package-tree") < item_position("host-descendant-tree"));
    assert!(item_position("emitted-descendant-tree") < item_position("emitted-composition-tree"));

    let output = temp.path().join("nested-tree-snapshot");
    let snapshot = materialize_host_closure_snapshot(&closure, &sources, &output).unwrap();
    assert!(!snapshot.reused());
    assert_eq!(
        fs::read(output.join("data/host/nested-package/host-descendant.txt")).unwrap(),
        host_descendant_bytes
    );
    assert_eq!(
        fs::read(output.join("data/emitted/nested-package/emitted-descendant.txt")).unwrap(),
        emitted_descendant_bytes
    );
    verify_host_closure_snapshot(&closure, &output).unwrap();

    make_tree_writable(&output);
}

#[test]
fn source_set_symlink_and_special_entries_fail_before_publication() {
    let temp = TempDir::new().unwrap();
    let fixture = Fixture::new(temp.path(), "sources", false);

    let mut missing = fixture.sources.clone();
    missing.pop();
    let missing_output = temp.path().join("missing");
    assert!(matches!(
        materialize_host_closure_snapshot(&fixture.closure, &missing, &missing_output),
        Err(SnapshotMaterializationError::SourceSetMismatch)
    ));
    assert!(!missing_output.exists());

    let mut extra = fixture.sources.clone();
    extra.push(HostClosureSnapshotSource {
        item_id: "ambient-extra".into(),
        path: fixture.sources[0].path.clone(),
    });
    let extra_output = temp.path().join("extra");
    assert!(matches!(
        materialize_host_closure_snapshot(&fixture.closure, &extra, &extra_output),
        Err(SnapshotMaterializationError::SourceSetMismatch)
    ));
    assert!(!extra_output.exists());

    let mut duplicate = fixture.sources.clone();
    let duplicate_id = duplicate[0].item_id.clone();
    duplicate[1].item_id = duplicate_id.clone();
    let duplicate_output = temp.path().join("duplicate");
    assert!(matches!(
        materialize_host_closure_snapshot(&fixture.closure, &duplicate, &duplicate_output),
        Err(SnapshotMaterializationError::DuplicateSource(id)) if id == duplicate_id
    ));
    assert!(!duplicate_output.exists());

    let direct_file = fixture
        .sources
        .iter()
        .find(|source| source.item_id == "host-root-manifest")
        .unwrap()
        .path
        .clone();
    let mut directory_for_file = fixture.sources.clone();
    directory_for_file
        .iter_mut()
        .find(|source| source.item_id == "host-root-manifest")
        .unwrap()
        .path = fixture.host_tree.clone();
    let directory_for_file_output = temp.path().join("directory-for-file");
    assert!(matches!(
        materialize_host_closure_snapshot(
            &fixture.closure,
            &directory_for_file,
            &directory_for_file_output,
        ),
        Err(SnapshotMaterializationError::SourceKindMismatch(id))
            if id == "host-root-manifest"
    ));
    assert!(!directory_for_file_output.exists());

    let mut file_for_directory = fixture.sources.clone();
    file_for_directory
        .iter_mut()
        .find(|source| source.item_id == "host-package-tree")
        .unwrap()
        .path = direct_file;
    let file_for_directory_output = temp.path().join("file-for-directory");
    assert!(matches!(
        materialize_host_closure_snapshot(
            &fixture.closure,
            &file_for_directory,
            &file_for_directory_output,
        ),
        Err(SnapshotMaterializationError::SourceKindMismatch(id))
            if id == "host-package-tree"
    ));
    assert!(!file_for_directory_output.exists());

    let direct_symlink = fixture.source_root.join("direct-manifest-link");
    let direct_manifest = fixture
        .sources
        .iter()
        .find(|source| source.item_id == "host-root-manifest")
        .unwrap()
        .path
        .clone();
    symlink(&direct_manifest, &direct_symlink).unwrap();
    let mut direct_symlink_sources = fixture.sources.clone();
    direct_symlink_sources
        .iter_mut()
        .find(|source| source.item_id == "host-root-manifest")
        .unwrap()
        .path = direct_symlink.clone();
    let direct_symlink_output = temp.path().join("direct-symlink");
    assert!(matches!(
        materialize_host_closure_snapshot(
            &fixture.closure,
            &direct_symlink_sources,
            &direct_symlink_output,
        ),
        Err(SnapshotMaterializationError::InvalidConcretePath(_))
    ));
    assert!(!direct_symlink_output.exists());
    fs::remove_file(direct_symlink).unwrap();

    let real_output_parent = temp.path().join("real-output-parent");
    fs::create_dir(&real_output_parent).unwrap();
    let output_parent_link = temp.path().join("output-parent-link");
    symlink(&real_output_parent, &output_parent_link).unwrap();
    let escaped_output = output_parent_link.join("snapshot");
    assert!(matches!(
        materialize_host_closure_snapshot(&fixture.closure, &fixture.sources, &escaped_output),
        Err(SnapshotMaterializationError::InvalidDestinationParent(_))
    ));
    assert!(!real_output_parent.join("snapshot").exists());

    let symlink_path = fixture.host_tree.join("linked-manifest");
    symlink(fixture.host_tree.join("Cargo.toml"), &symlink_path).unwrap();
    let symlink_output = temp.path().join("symlink");
    assert!(matches!(
        materialize_host_closure_snapshot(&fixture.closure, &fixture.sources, &symlink_output,),
        Err(SnapshotMaterializationError::UnsupportedSourceEntry(_)
            | SnapshotMaterializationError::SnapshotTree(_))
    ));
    assert!(!symlink_output.exists());
    fs::remove_file(symlink_path).unwrap();

    let nested_socket_path = fixture.host_tree.join("nested-special.socket");
    let nested_listener = UnixListener::bind(&nested_socket_path).unwrap();
    let nested_special_output = temp.path().join("nested-special");
    assert!(matches!(
        materialize_host_closure_snapshot(
            &fixture.closure,
            &fixture.sources,
            &nested_special_output,
        ),
        Err(SnapshotMaterializationError::UnsupportedSourceEntry(_))
    ));
    assert!(!nested_special_output.exists());
    drop(nested_listener);
    fs::remove_file(nested_socket_path).unwrap();

    let socket_path = fixture.source_root.join("special.socket");
    let _listener = UnixListener::bind(&socket_path).unwrap();
    let mut special = fixture.sources.clone();
    special
        .iter_mut()
        .find(|source| source.item_id == "host-root-manifest")
        .unwrap()
        .path = fs::canonicalize(&socket_path).unwrap();
    let special_output = temp.path().join("special");
    assert!(matches!(
        materialize_host_closure_snapshot(&fixture.closure, &special, &special_output),
        Err(SnapshotMaterializationError::SourceKindMismatch(_)
            | SnapshotMaterializationError::UnsupportedSourceEntry(_))
    ));
    assert!(!special_output.exists());

    let drifted_source = &fixture
        .sources
        .iter()
        .find(|source| source.item_id == "target-facts")
        .unwrap()
        .path;
    fs::write(drifted_source, b"drifted target facts").unwrap();
    let drifted_output = temp.path().join("drifted");
    assert!(matches!(
        materialize_host_closure_snapshot(&fixture.closure, &fixture.sources, &drifted_output),
        Err(SnapshotMaterializationError::SourceDigestMismatch(_))
    ));
    assert!(!drifted_output.exists());
    assert_no_staging_directory(temp.path());
}

#[test]
fn source_bounds_fail_before_staging_or_publication() {
    let temp = TempDir::new().unwrap();
    let fixture = Fixture::new(temp.path(), "sources", false);
    let oversized_path = fixture.source_root.join("oversized-direct-file");
    let oversized = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&oversized_path)
        .unwrap();
    oversized
        .set_len(MAX_CANONICAL_SNAPSHOT_FILE_BYTES + 1)
        .unwrap();
    drop(oversized);

    let mut sources = fixture.sources.clone();
    sources
        .iter_mut()
        .find(|source| source.item_id == "host-root-manifest")
        .unwrap()
        .path = fs::canonicalize(oversized_path).unwrap();
    let output = temp.path().join("oversized-output");
    assert!(matches!(
        materialize_host_closure_snapshot(&fixture.closure, &sources, &output),
        Err(SnapshotMaterializationError::SourceBounds(id))
            if id.ends_with("oversized-direct-file")
    ));
    assert!(!output.exists());
    assert_no_staging_directory(temp.path());
}

#[test]
fn tree_aggregate_bounds_fail_before_hashing_or_staging() {
    let temp = TempDir::new().unwrap();
    let fixture = Fixture::new(temp.path(), "sources", false);
    for index in 0..4 {
        let path = fixture.host_tree.join(format!("aggregate-{index}"));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        file.set_len(MAX_CANONICAL_SNAPSHOT_FILE_BYTES).unwrap();
    }
    let output = temp.path().join("tree-aggregate-output");
    assert!(matches!(
        materialize_host_closure_snapshot(&fixture.closure, &fixture.sources, &output),
        Err(SnapshotMaterializationError::SourceBounds(_))
    ));
    assert!(!output.exists());
    assert_no_staging_directory(temp.path());
}

#[test]
fn closure_aggregate_bounds_fail_before_hashing_any_item_or_staging() {
    let temp = TempDir::new().unwrap();
    let fixture = Fixture::new(temp.path(), "sources", false);
    let record_ids = [
        "cargo-resolution",
        "target-facts",
        "rustc-settings",
        "artifact-selector",
    ];
    let mut sources = fixture.sources.clone();
    for (index, item_id) in record_ids.into_iter().enumerate() {
        let path = fixture
            .source_root
            .join(format!("aggregate-record-{index}"));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.set_len(MAX_CANONICAL_SNAPSHOT_FILE_BYTES).unwrap();
        sources
            .iter_mut()
            .find(|source| source.item_id == item_id)
            .unwrap()
            .path = fs::canonicalize(path).unwrap();
    }
    assert_eq!(
        record_ids.len() as u64 * MAX_CANONICAL_SNAPSHOT_FILE_BYTES,
        MAX_CANONICAL_SNAPSHOT_TOTAL_FILE_BYTES
    );
    let output = temp.path().join("closure-aggregate-output");
    assert!(matches!(
        materialize_host_closure_snapshot(&fixture.closure, &sources, &output),
        Err(SnapshotMaterializationError::SourceBounds(_))
    ));
    assert!(!output.exists());
    assert_no_staging_directory(temp.path());
}

#[test]
fn overlapping_source_bytes_are_bounded_before_hashing_or_staging() {
    let temp = TempDir::new().unwrap();
    let fixture = Fixture::new(temp.path(), "sources", false);
    for path in [
        fixture.host_tree.join("Cargo.toml"),
        fixture.host_tree.join("Cargo.lock"),
        fixture.host_tree.join(".cargo/config.toml"),
    ] {
        OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .set_len(MAX_CANONICAL_SNAPSHOT_FILE_BYTES)
            .unwrap();
    }
    for item_id in ["host-root-manifest", "host-cargo-lock", "cargo-config"] {
        let path = &fixture
            .sources
            .iter()
            .find(|source| source.item_id == item_id)
            .unwrap()
            .path;
        OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .set_len(MAX_CANONICAL_SNAPSHOT_FILE_BYTES)
            .unwrap();
    }

    let output = temp.path().join("overlapping-aggregate-output");
    assert!(matches!(
        materialize_host_closure_snapshot(&fixture.closure, &fixture.sources, &output),
        Err(SnapshotMaterializationError::SourceBounds(_))
    ));
    assert!(!output.exists());
    assert_no_staging_directory(temp.path());
}

#[test]
fn existing_snapshot_is_reused_exactly_and_mutation_is_never_repaired_in_place() {
    let temp = TempDir::new().unwrap();
    let fixture = Fixture::new(temp.path(), "sources", false);
    let output = temp.path().join("snapshot");
    let first =
        materialize_host_closure_snapshot(&fixture.closure, &fixture.sources, &output).unwrap();
    assert!(!first.reused());

    let second =
        materialize_host_closure_snapshot(&fixture.closure, &fixture.sources, &output).unwrap();
    assert!(second.reused());
    assert_eq!(first.manifest(), second.manifest());
    assert!(matches!(
        materialize_host_closure_snapshot(&fixture.closure, &[], &output),
        Err(SnapshotMaterializationError::SourceSetMismatch)
    ));
    assert_eq!(first.manifest(), second.manifest());

    let other_closure = Fixture::new(temp.path(), "other-closure", true);
    assert!(matches!(
        verify_host_closure_snapshot(&other_closure.closure, &output),
        Err(SnapshotMaterializationError::ClosureMismatch)
    ));

    let artifact = output.join("data/host/Cargo.toml");
    fs::set_permissions(&artifact, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        verify_host_closure_snapshot(&fixture.closure, &output),
        Err(SnapshotMaterializationError::StorageMetadataMismatch)
    ));
    fs::set_permissions(&artifact, fs::Permissions::from_mode(0o444)).unwrap();
    verify_host_closure_snapshot(&fixture.closure, &output).unwrap();

    fs::set_permissions(&artifact, fs::Permissions::from_mode(0o644)).unwrap();
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&artifact)
        .unwrap();
    file.write_all(&vec![b'x'; HOST_MANIFEST_IN_TREE.len()])
        .unwrap();
    file.set_permissions(fs::Permissions::from_mode(0o444))
        .unwrap();
    file.set_times(
        FileTimes::new()
            .set_accessed(SystemTime::UNIX_EPOCH)
            .set_modified(SystemTime::UNIX_EPOCH),
    )
    .unwrap();
    drop(file);

    assert!(matches!(
        materialize_host_closure_snapshot(&fixture.closure, &fixture.sources, &output),
        Err(SnapshotMaterializationError::SnapshotContentMismatch
            | SnapshotMaterializationError::StorageMetadataMismatch
            | SnapshotMaterializationError::DestinationConflict(_))
    ));
    assert_eq!(
        fs::read(&artifact).unwrap(),
        vec![b'x'; HOST_MANIFEST_IN_TREE.len()]
    );

    make_tree_writable(&output);
}

#[test]
fn verifier_rejects_projection_tree_type_symlink_and_noncanonical_manifest_drift() {
    let temp = TempDir::new().unwrap();
    let fixture = Fixture::new(temp.path(), "sources", false);
    let materialize = |name: &str| {
        let output = temp.path().join(name);
        materialize_host_closure_snapshot(&fixture.closure, &fixture.sources, &output).unwrap();
        output
    };

    let mtime_output = materialize("mtime-drift");
    let mtime_artifact = mtime_output.join("data/host/Cargo.toml");
    OpenOptions::new()
        .read(true)
        .open(&mtime_artifact)
        .unwrap()
        .set_times(
            FileTimes::new()
                .set_accessed(SystemTime::UNIX_EPOCH)
                .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1)),
        )
        .unwrap();
    assert!(matches!(
        verify_host_closure_snapshot(&fixture.closure, &mtime_output),
        Err(SnapshotMaterializationError::StorageMetadataMismatch)
    ));

    let directory_mode_output = materialize("directory-mode-drift");
    fs::set_permissions(
        directory_mode_output.join("data/host"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert!(matches!(
        verify_host_closure_snapshot(&fixture.closure, &directory_mode_output),
        Err(SnapshotMaterializationError::StorageMetadataMismatch)
    ));

    let missing_output = materialize("missing-entry");
    let missing_parent = missing_output.join("data/host");
    fs::set_permissions(&missing_parent, fs::Permissions::from_mode(0o755)).unwrap();
    fs::remove_file(missing_parent.join("Cargo.toml")).unwrap();
    set_local_mode_mtime(&missing_parent, 0o555);
    assert!(matches!(
        verify_host_closure_snapshot(&fixture.closure, &missing_output),
        Err(SnapshotMaterializationError::SnapshotContentMismatch)
    ));

    let extra_output = materialize("extra-entry");
    let extra_parent = extra_output.join("data");
    fs::set_permissions(&extra_parent, fs::Permissions::from_mode(0o755)).unwrap();
    let extra_path = extra_parent.join("ambient-extra");
    fs::write(&extra_path, b"ambient").unwrap();
    set_local_mode_mtime(&extra_path, 0o444);
    set_local_mode_mtime(&extra_parent, 0o555);
    assert!(matches!(
        verify_host_closure_snapshot(&fixture.closure, &extra_output),
        Err(SnapshotMaterializationError::SnapshotContentMismatch)
    ));

    let type_output = materialize("type-drift");
    let type_parent = type_output.join("data/host");
    let type_path = type_parent.join("Cargo.toml");
    fs::set_permissions(&type_parent, fs::Permissions::from_mode(0o755)).unwrap();
    fs::remove_file(&type_path).unwrap();
    fs::create_dir(&type_path).unwrap();
    set_local_mode_mtime(&type_path, 0o555);
    set_local_mode_mtime(&type_parent, 0o555);
    assert!(matches!(
        verify_host_closure_snapshot(&fixture.closure, &type_output),
        Err(SnapshotMaterializationError::SnapshotContentMismatch)
    ));

    let symlink_output = materialize("data-symlink");
    let symlink_parent = symlink_output.join("data/host");
    let symlink_path = symlink_parent.join("Cargo.toml");
    let external = write_file(temp.path(), "external-data-target", b"external");
    fs::set_permissions(&symlink_parent, fs::Permissions::from_mode(0o755)).unwrap();
    fs::remove_file(&symlink_path).unwrap();
    symlink(external, &symlink_path).unwrap();
    set_local_mode_mtime(&symlink_parent, 0o555);
    assert!(matches!(
        verify_host_closure_snapshot(&fixture.closure, &symlink_output),
        Err(SnapshotMaterializationError::SnapshotContentMismatch)
    ));

    let noncanonical_output = materialize("noncanonical-manifest");
    let manifest_path = noncanonical_output.join("rust-agent-host-closure-snapshot.json");
    let canonical_bytes = fs::read(&manifest_path).unwrap();
    let manifest_value: serde_json::Value = serde_json::from_slice(&canonical_bytes).unwrap();
    let noncanonical_bytes = serde_json::to_vec_pretty(&manifest_value).unwrap();
    assert_ne!(canonical_bytes, noncanonical_bytes);
    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o644)).unwrap();
    fs::write(&manifest_path, noncanonical_bytes).unwrap();
    set_local_mode_mtime(&manifest_path, 0o444);
    assert!(matches!(
        verify_host_closure_snapshot(&fixture.closure, &noncanonical_output),
        Err(SnapshotMaterializationError::SnapshotContentMismatch)
    ));

    for output in [
        mtime_output,
        directory_mode_output,
        missing_output,
        extra_output,
        type_output,
        symlink_output,
        noncanonical_output,
    ] {
        make_tree_writable(&output);
    }
}

#[test]
fn concurrent_publication_has_one_exact_winner_and_one_verified_reuse() {
    let temp = TempDir::new().unwrap();
    let fixture = Fixture::new(temp.path(), "sources", false);
    let output = temp.path().join("snapshot");
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let barrier = Arc::clone(&barrier);
        let closure = fixture.closure.clone();
        let sources = fixture.sources.clone();
        let output = output.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            materialize_host_closure_snapshot(&closure, &sources, &output)
        }));
    }
    let mut results = handles
        .into_iter()
        .map(|handle| handle.join().unwrap().unwrap())
        .collect::<Vec<_>>();
    results.sort_by_key(rust_agent_build_executor::MaterializedHostClosureSnapshot::reused);
    assert!(!results[0].reused());
    assert!(results[1].reused());
    assert_eq!(results[0].manifest(), results[1].manifest());
    verify_host_closure_snapshot(&fixture.closure, &output).unwrap();
    assert_no_staging_directory(temp.path());

    make_tree_writable(&output);
}

#[test]
fn mount_observation_verifier_rejects_every_context_and_entry_drift() {
    let temp = TempDir::new().unwrap();
    let fixture = Fixture::new(temp.path(), "sources", false);
    let output = temp.path().join("snapshot");
    let snapshot =
        materialize_host_closure_snapshot(&fixture.closure, &fixture.sources, &output).unwrap();
    let manifest = snapshot.manifest();
    let expected = manifest.expected_mount_observation().unwrap();
    assert!(expected.read_only);
    manifest.verify_mount_observation(&expected).unwrap();

    let mut schema = expected.clone();
    schema.schema = 2;
    reseal_observation(&mut schema);
    assert!(matches!(
        manifest.verify_mount_observation(&schema),
        Err(SnapshotMaterializationError::MountObservationMismatch)
    ));

    let mut manifest_digest = expected.clone();
    manifest_digest.snapshot_manifest_digest = labeled_digest("other-manifest");
    reseal_observation(&mut manifest_digest);
    manifest_digest.verify().unwrap();
    assert!(matches!(
        manifest.verify_mount_observation(&manifest_digest),
        Err(SnapshotMaterializationError::MountObservationMismatch)
    ));

    let mut logical_root = expected.clone();
    logical_root.logical_root = "/rust-agent/other".into();
    reseal_observation(&mut logical_root);
    assert!(matches!(
        manifest.verify_mount_observation(&logical_root),
        Err(SnapshotMaterializationError::MountObservationMismatch)
    ));

    let mut writable = expected.clone();
    writable.read_only = false;
    reseal_observation(&mut writable);
    assert!(matches!(
        manifest.verify_mount_observation(&writable),
        Err(SnapshotMaterializationError::MountObservationMismatch)
    ));

    let mut entry = expected.clone();
    let file_entry = entry
        .entries
        .iter_mut()
        .find(|entry| matches!(entry.kind, CanonicalSnapshotEntryKind::RegularFile { .. }))
        .unwrap();
    let CanonicalSnapshotEntryKind::RegularFile { sha256, .. } = &mut file_entry.kind else {
        unreachable!();
    };
    *sha256 = labeled_digest("mutated-mounted-file");
    reseal_observation(&mut entry);
    entry.verify().unwrap();
    assert!(matches!(
        manifest.verify_mount_observation(&entry),
        Err(SnapshotMaterializationError::MountObservationMismatch)
    ));

    let mut digest = expected;
    digest.digest = labeled_digest("forged-observation");
    assert!(matches!(
        manifest.verify_mount_observation(&digest),
        Err(SnapshotMaterializationError::MountObservationMismatch)
    ));

    make_tree_writable(&output);
}

#[test]
fn resealed_manifest_item_data_tree_drift_is_rejected_before_observation() {
    let temp = TempDir::new().unwrap();
    let fixture = Fixture::new(temp.path(), "sources", false);
    let output = temp.path().join("snapshot");
    let snapshot =
        materialize_host_closure_snapshot(&fixture.closure, &fixture.sources, &output).unwrap();
    let mut drifted = snapshot.manifest().clone();
    let item = drifted
        .items
        .iter_mut()
        .find(|item| item.id == "target-facts")
        .unwrap();
    let HostBuildClosureContent::CanonicalRecord { bytes_sha256, .. } = &mut item.content else {
        panic!("target facts must remain a canonical record");
    };
    *bytes_sha256 = labeled_digest("forged-target-facts-bytes");
    item.closure_item_digest = hex::encode(
        canonical::domain_hash(
            b"rust-agent-host-build-closure-item-v1\0",
            &(
                item.role,
                &item.id,
                &item.logical_path,
                item.metadata_contract,
                &item.content,
            ),
        )
        .unwrap(),
    );
    reseal_manifest(&mut drifted);

    assert!(matches!(
        drifted.expected_mount_observation(),
        Err(SnapshotMaterializationError::SnapshotContentMismatch)
    ));
    assert!(matches!(
        HostClosureSnapshotManifest::from_json(&serde_json::to_string(&drifted).unwrap()),
        Err(SnapshotMaterializationError::SnapshotContentMismatch)
    ));

    make_tree_writable(&output);
}

#[test]
fn manifest_and_observation_json_are_closed_canonical_and_self_verifying() {
    let temp = TempDir::new().unwrap();
    let fixture = Fixture::new(temp.path(), "sources", false);
    let output = temp.path().join("snapshot");
    let snapshot =
        materialize_host_closure_snapshot(&fixture.closure, &fixture.sources, &output).unwrap();
    let manifest = snapshot.manifest();
    let manifest_json = serde_json::to_string(manifest).unwrap();
    assert_eq!(
        HostClosureSnapshotManifest::from_json(&manifest_json).unwrap(),
        *manifest
    );

    let mut unknown: serde_json::Value = serde_json::from_str(&manifest_json).unwrap();
    unknown["ambient-source"] = serde_json::Value::String("/tmp/source".into());
    assert!(matches!(
        HostClosureSnapshotManifest::from_json(&serde_json::to_string(&unknown).unwrap()),
        Err(SnapshotMaterializationError::Json(_))
    ));

    let mut nested_unknown: serde_json::Value = serde_json::from_str(&manifest_json).unwrap();
    nested_unknown["items"][0]["ambient-source"] = serde_json::Value::String("/tmp/source".into());
    assert!(matches!(
        HostClosureSnapshotManifest::from_json(&serde_json::to_string(&nested_unknown).unwrap()),
        Err(SnapshotMaterializationError::Json(_))
    ));

    let mut unsupported_schema: serde_json::Value = serde_json::from_str(&manifest_json).unwrap();
    unsupported_schema["schema"] = serde_json::Value::Number(2.into());
    assert!(matches!(
        HostClosureSnapshotManifest::from_json(
            &serde_json::to_string(&unsupported_schema).unwrap()
        ),
        Err(SnapshotMaterializationError::UnsupportedManifestSchema(2))
    ));

    let mut drifted: serde_json::Value = serde_json::from_str(&manifest_json).unwrap();
    drifted["digest"] = serde_json::Value::String(labeled_digest("forged-manifest"));
    assert!(matches!(
        HostClosureSnapshotManifest::from_json(&serde_json::to_string(&drifted).unwrap()),
        Err(SnapshotMaterializationError::ManifestDigestMismatch)
    ));

    let mut deployable: serde_json::Value = serde_json::from_str(&manifest_json).unwrap();
    deployable["deployable"] = serde_json::Value::Bool(true);
    assert!(matches!(
        HostClosureSnapshotManifest::from_json(&serde_json::to_string(&deployable).unwrap()),
        Err(SnapshotMaterializationError::DeployableManifest)
    ));

    let mut reordered_items = manifest.clone();
    reordered_items.items.reverse();
    reseal_manifest(&mut reordered_items);
    assert!(matches!(
        HostClosureSnapshotManifest::from_json(&serde_json::to_string(&reordered_items).unwrap()),
        Err(SnapshotMaterializationError::ManifestDigestMismatch)
    ));

    let mut reordered_tree = manifest.clone();
    reordered_tree.data_tree_entries.reverse();
    reseal_manifest(&mut reordered_tree);
    assert!(matches!(
        HostClosureSnapshotManifest::from_json(&serde_json::to_string(&reordered_tree).unwrap()),
        Err(SnapshotMaterializationError::ManifestDigestMismatch)
    ));

    let observation = manifest.expected_mount_observation().unwrap();
    let observation_json = serde_json::to_string(&observation).unwrap();
    assert_eq!(
        HostClosureMountObservation::from_json(&observation_json).unwrap(),
        observation
    );

    let mut unknown_observation: serde_json::Value =
        serde_json::from_str(&observation_json).unwrap();
    unknown_observation["ambient-source"] = serde_json::Value::String("/tmp/source".into());
    assert!(matches!(
        HostClosureMountObservation::from_json(
            &serde_json::to_string(&unknown_observation).unwrap()
        ),
        Err(SnapshotMaterializationError::Json(_))
    ));

    let mut nested_unknown_observation: serde_json::Value =
        serde_json::from_str(&observation_json).unwrap();
    nested_unknown_observation["entries"][0]["metadata"]["ambient-owner"] =
        serde_json::Value::String("host".into());
    assert!(matches!(
        HostClosureMountObservation::from_json(
            &serde_json::to_string(&nested_unknown_observation).unwrap()
        ),
        Err(SnapshotMaterializationError::Json(_))
    ));

    let mut unsupported_observation_schema: serde_json::Value =
        serde_json::from_str(&observation_json).unwrap();
    unsupported_observation_schema["schema"] = serde_json::Value::Number(2.into());
    assert!(matches!(
        HostClosureMountObservation::from_json(
            &serde_json::to_string(&unsupported_observation_schema).unwrap()
        ),
        Err(SnapshotMaterializationError::MountObservationMismatch)
    ));

    let mut reordered = observation;
    reordered.entries.reverse();
    reseal_observation(&mut reordered);
    assert!(matches!(
        HostClosureMountObservation::from_json(&serde_json::to_string(&reordered).unwrap()),
        Err(SnapshotMaterializationError::MountObservationMismatch)
    ));

    make_tree_writable(&output);
}

#[test]
fn manifest_symlinks_and_oversize_files_are_rejected_before_parsing() {
    let temp = TempDir::new().unwrap();
    let fixture = Fixture::new(temp.path(), "sources", false);
    let output = temp.path().join("snapshot");
    materialize_host_closure_snapshot(&fixture.closure, &fixture.sources, &output).unwrap();
    let manifest_path = output.join("rust-agent-host-closure-snapshot.json");
    let external = write_file(temp.path(), "external-manifest.json", b"{}");

    fs::set_permissions(&output, fs::Permissions::from_mode(0o755)).unwrap();
    fs::remove_file(&manifest_path).unwrap();
    symlink(&external, &manifest_path).unwrap();
    assert!(matches!(
        verify_host_closure_snapshot(&fixture.closure, &output),
        Err(SnapshotMaterializationError::SnapshotContentMismatch)
    ));

    fs::remove_file(&manifest_path).unwrap();
    let oversized = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&manifest_path)
        .unwrap();
    oversized
        .set_len(MAX_CANONICAL_SNAPSHOT_JSON_BYTES as u64 + 1)
        .unwrap();
    drop(oversized);
    assert!(matches!(
        verify_host_closure_snapshot(&fixture.closure, &output),
        Err(SnapshotMaterializationError::JsonTooLarge)
    ));

    make_tree_writable(&output);
}
