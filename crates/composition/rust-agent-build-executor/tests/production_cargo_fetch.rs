#![cfg(target_os = "linux")]

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    os::unix::process::CommandExt as _,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use ed25519_dalek::{Signer as _, SigningKey};
use rust_agent_build_executor::{
    BuildArtifactSelector, BuildArtifactTarget, BuildEnforcementContext, BuildPanicStrategy,
    CanonicalSnapshotMetadataContract, CargoCompilationKind, CargoCompileMode, CargoCrateKind,
    CargoDependencyKind, CargoFetchCacheLayout, CargoFetchCachePackageLocation, CargoFetchMode,
    CargoFetchRequest, CargoPackageIdentity, CargoPackageSource, CargoPlannerGraphRoot,
    CargoPlannerRequest, CargoTargetEvaluationDomain, CargoUnit, CargoUnitEdge,
    CargoUnitGraphPlannerIdentity, CargoUnitSelector, DerivedExecutablePolicy,
    DevelopmentHostFeatureVerification, HostBuildClosureContent, HostBuildClosureItem,
    HostBuildClosureItemRole, HostBuildInputClosure, HostCargoUnitGraph, HostClosureSnapshotSource,
    HostFeaturePolicyClosure, HostFeaturePolicyStageDigests, LinuxSandboxBackendIdentity,
    LinuxSandboxResolvedEndpoint, LinuxSandboxRuntimeIdentity, LinuxSandboxRuntimeSymlink,
    LockedSourceClosure, ProductionArtifactKind, ProductionAttestationPolicy,
    ProductionBuildAttestationInput, ProductionBuildExecutionPolicy, ProductionBuildManifestInput,
    ProductionBuildOptionsIdentity, ProductionBuildPipelineOptions,
    ProductionCargoInvocationIdentity, ProductionCompletionHandle,
    ProductionCompletionHandlePayload, ProductionEnforcementResultIdentity, ProductionEnvironment,
    ProductionExecutable, ProductionExecutionEvidence, ProductionFetchPolicy,
    ProductionFetchRedirectPolicy, ProductionHostBuildPipelineOptions, ProductionHostLinker,
    ProductionIntegrationPostInput, ProductionIntegrationPrePipelineOptions,
    ProductionOperationKind, ProductionReadInput, ProductionSandboxBackend, ProductionTargetLinker,
    ProductionToolIdentity, ProductionToolchain, ProductionTreeIdentity, RustcSettingsRecord,
    SigningHelper, TrustedCargoFetchEndpointResolution, TrustedCargoFetchError, TrustedSigner,
    VerifiedLinuxSandboxBackend, cargo_resolution_record_digest,
    create_production_artifact_staging, create_production_build_attestation_payload,
    create_production_integration_post_payload, derive_cargo_planner_edge_semantics_from_metadata,
    execute_trusted_cargo_build, execute_trusted_cargo_fetch,
    execute_trusted_cargo_fetch_with_endpoint_resolution, execute_trusted_cargo_planner,
    execute_trusted_production_build, execute_trusted_production_host_build,
    execute_trusted_production_integration_pre, execute_trusted_production_preflight,
    materialize_host_closure_snapshot, normalize_cargo_unit_graph,
    open_verified_host_closure_snapshot, preflight_production_build_inputs,
    preflight_production_fetch_inputs, prepare_production_build_attestation_publication,
    production_artifact_record, publish_production_artifact,
    reverify_trusted_production_integration_pre, sign_production_build_attestation,
    verify_production_host_feature_union, write_production_build_manifest,
    write_production_integration_post_attestation,
};
use rust_agent_composition::{
    CompositionManifest, Environment, Target, WASM_BINDGEN_CLI_LOGICAL_ID, canonical,
    manifest::CargoResolutionRecord,
    metadata::BuildRequirements,
    profile::BuildKind,
    snapshot::{CanonicalSnapshotEntry, CanonicalSnapshotTree},
    target::TargetFactsRecord,
};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;
use walkdir::WalkDir;

const TEST_CREDENTIAL: &str = "phase-1b-fixture-token";
const LOGICAL_HOST_LINKER: &str = "/rust-agent/tools/host-linker";
const LOGICAL_TARGET_LINKER: &str = "/rust-agent/target-tools/wasm-rust-lld";
const LOGICAL_COMPILER_PATH: &str = "/rust-agent/tools";
const MAX_LINKER_SCRIPT_BYTES: u64 = 64 * 1024;
const MAX_LINKER_SCRIPT_FILES: usize = 64;

struct FixtureSigning {
    key: SigningKey,
    public_key: PathBuf,
    helper: PathBuf,
}

impl FixtureSigning {
    fn new(root: &Path, rustc: &Path) -> Self {
        let key = SigningKey::from_bytes(&[73; 32]);
        let public_key = root.join("fixture-signer.pub");
        fs::write(&public_key, key.verifying_key().to_bytes()).unwrap();
        let source = root.join("fixture-signing-helper.rs");
        let helper = root.join("fixture-signing-helper");
        fs::write(
            &source,
            r#"use std::{env, fs, io::{self, Read as _}};
fn main() {
    assert_eq!(env::args().skip(1).collect::<Vec<_>>(), ["rust-agent-signing-helper-v1"]);
    let mut request = Vec::new();
    io::stdin().read_to_end(&mut request).unwrap();
    assert!(!request.is_empty());
    print!("{}", fs::read_to_string(env::current_exe().unwrap().with_extension("response")).unwrap());
}
"#,
        )
        .unwrap();
        assert!(
            Command::new(rustc)
                .args(["--edition=2024", "-C", "opt-level=0"])
                .arg(&source)
                .arg("-o")
                .arg(&helper)
                .status()
                .unwrap()
                .success()
        );
        Self {
            key,
            public_key: public_key.canonicalize().unwrap(),
            helper: helper.canonicalize().unwrap(),
        }
    }

    fn prepare_response(
        &self,
        payload: &rust_agent_build_executor::ProductionBuildAttestationPayload,
    ) {
        let response = serde_json::json!({
            "schema": 1,
            "signer-id": "fixture-signer",
            "algorithm": "ed25519",
            "signature": sign_digest(&self.key, &payload.digest().unwrap()),
        });
        fs::write(
            self.helper.with_extension("response"),
            serde_json::to_vec(&response).unwrap(),
        )
        .unwrap();
    }

    fn completion_handle(
        &self,
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
            signature: sign_digest(&self.key, &completion_payload.digest().unwrap()),
            payload: completion_payload,
            signer_id: "fixture-signer".into(),
            algorithm: "ed25519".into(),
        }
    }
}

fn sign_digest(key: &SigningKey, digest: &str) -> String {
    hex::encode(key.sign(&hex::decode(digest).unwrap()).to_bytes())
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum FetchFixtureMode {
    Preprovisioned,
    Networked,
    Credential,
    Planner,
    CrossPlanner,
    BuildObserver,
    StandalonePipeline,
    WasmPipeline,
    HostPipeline,
}

impl FetchFixtureMode {
    fn networked(self) -> bool {
        matches!(self, Self::Networked | Self::Credential)
    }

    fn authenticated(self) -> bool {
        self == Self::Credential
    }

    fn cross_compile(self) -> bool {
        matches!(
            self,
            Self::CrossPlanner
                | Self::BuildObserver
                | Self::StandalonePipeline
                | Self::WasmPipeline
                | Self::HostPipeline
        )
    }
}

#[test]
fn host_linker_support_files_follow_logical_install_and_compiler_paths() {
    let linker = find_executable("cc");
    let host_install = compiler_install_directory(&linker, None);
    let logical_install = compiler_install_directory(&linker, Some(LOGICAL_HOST_LINKER));
    assert_ne!(logical_install, host_install);
    assert!(logical_install.starts_with("/rust-agent/lib/gcc"));

    let output = TempDir::new().unwrap();
    copy_compiler_support_files(&linker, output.path());
    let relocated_plugin = output.path().join(
        logical_install
            .strip_prefix(Path::new("/"))
            .unwrap()
            .join("liblto_plugin.so"),
    );
    assert!(relocated_plugin.is_file());
    assert_eq!(
        sha256_file(&relocated_plugin),
        sha256_file(&compiler_program_file(&linker, "liblto_plugin.so"))
    );
    let staged_compiler_path = output.path().join("compiler-path");
    let linker_dry_run =
        compiler_linker_dry_run_with_identity(&linker, LOGICAL_HOST_LINKER, &staged_compiler_path);
    assert!(
        linker_dry_run.contains(
            staged_compiler_path
                .join("liblto_plugin.so")
                .to_str()
                .unwrap()
        )
    );
    assert_eq!(
        compiler_install_runtime_symlink(output.path()),
        Some(LinuxSandboxRuntimeSymlink {
            target: "/rust-agent/runtime/rust-agent/lib".into(),
            link: "/rust-agent/lib".into(),
        })
    );
    assert_eq!(
        compiler_path_runtime_symlink(output.path()),
        Some(LinuxSandboxRuntimeSymlink {
            target: "/rust-agent/runtime/compiler-path/liblto_plugin.so".into(),
            link: "/rust-agent/tools/liblto_plugin.so".into(),
        })
    );
    let libm_script = compiler_program_file(&linker, "libm.so");
    let libm_dependencies = linker_script_dependencies(&libm_script);
    assert!(!libm_dependencies.is_empty());
    for dependency in libm_dependencies {
        assert!(
            output
                .path()
                .join(dependency.strip_prefix(Path::new("/")).unwrap())
                .is_file(),
            "linker-script dependency was not projected at {}",
            dependency.display()
        );
    }
}

#[test]
#[ignore = "requires the real pinned Cargo and Linux user/mount/network namespace runner"]
fn preprovisioned_fetch_runs_cargo_offline_and_publishes_a_verified_read_only_cache() {
    run_fetch_fixture(FetchFixtureMode::Preprovisioned);
}

#[test]
#[ignore = "requires the real pinned Cargo, Python/OpenSSL TLS fixture, and Linux namespace runner"]
fn networked_fetch_uses_only_attested_https_endpoints() {
    if enter_isolated_network_namespace("networked_fetch_uses_only_attested_https_endpoints") {
        run_fetch_fixture(FetchFixtureMode::Networked);
    }
}

#[test]
#[ignore = "requires the real pinned Cargo, Python/OpenSSL TLS fixture, and Linux namespace runner"]
fn credential_helper_is_exact_pipe_only_and_secret_free() {
    if enter_isolated_network_namespace("credential_helper_is_exact_pipe_only_and_secret_free") {
        run_fetch_fixture(FetchFixtureMode::Credential);
    }
}

#[test]
#[ignore = "requires the real pinned Cargo and Linux user/mount namespace runner"]
fn trusted_planner_runs_in_the_immutable_backend() {
    run_fetch_fixture(FetchFixtureMode::Planner);
}

#[test]
#[ignore = "requires the real pinned Cargo, wasm32 target, and Linux user/mount namespace runner"]
fn cross_compile_planner_keeps_host_and_target_units_distinct() {
    run_fetch_fixture(FetchFixtureMode::CrossPlanner);
}

#[test]
#[ignore = "requires the real pinned Cargo, wasm32 target, and Linux Landlock ABI 2 runner"]
fn trusted_build_observer_covers_cross_compiled_build_and_proc_macro_units() {
    run_fetch_fixture(FetchFixtureMode::BuildObserver);
}

#[test]
#[ignore = "requires the real pinned Cargo, wasm32 target, and Linux Landlock ABI 2 runner"]
fn production_standalone_pipeline_is_signed_and_reverified() {
    run_fetch_fixture(FetchFixtureMode::StandalonePipeline);
}

#[test]
#[ignore = "requires the pinned wasm-bindgen CLI, wasm32 target, and Linux Landlock ABI 2 runner"]
fn production_wasm_pipeline_sandboxes_and_attests_the_complete_bundle() {
    run_fetch_fixture(FetchFixtureMode::WasmPipeline);
}

#[test]
#[ignore = "requires the real pinned Cargo, wasm32 target, and Linux Landlock ABI 2 runner"]
fn production_host_pre_build_post_pipeline_is_signed_and_reverified() {
    run_fetch_fixture(FetchFixtureMode::HostPipeline);
}

fn enter_isolated_network_namespace(test_name: &str) -> bool {
    const NETNS_MARKER: &str = "RUST_AGENT_FETCH_NETNS_CHILD";
    if std::env::var_os(NETNS_MARKER).is_none() {
        let executable = std::env::current_exe().unwrap();
        let output = Command::new("/usr/bin/unshare")
            .args(["--user", "--map-root-user", "--net"])
            .arg(&executable)
            .args(["--ignored", "--exact", test_name, "--test-threads=1"])
            .env(NETNS_MARKER, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "network namespace child failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return false;
    }
    let loopback = Command::new("/usr/sbin/ip")
        .args(["link", "set", "lo", "up"])
        .status()
        .unwrap();
    assert!(loopback.success(), "failed to enable isolated loopback");
    true
}

fn run_fetch_fixture(mode: FetchFixtureMode) {
    let networked = mode.networked();
    let authenticated = mode.authenticated();
    let cross_compile = mode.cross_compile();
    let temp = TempDir::new().unwrap();
    let registry_archive = registry_archive();
    let registry_checksum = sha256(&registry_archive);
    let mut registry = networked.then(|| {
        LocalTlsRegistry::start(
            temp.path(),
            &registry_archive,
            &registry_checksum,
            authenticated,
        )
    });
    let source = temp.path().join("source");
    let host_root = source.join("host");
    let host_package = source.join("trees/host-fixture");
    let generated_package = source.join("trees/generated-agent");
    let macro_package = source.join("trees/macro-helper");
    let shared_package = source.join("trees/shared-helper");
    fs::create_dir_all(host_root.join(".cargo")).unwrap();
    fs::create_dir_all(host_package.join("src")).unwrap();
    fs::create_dir_all(generated_package.join("src")).unwrap();
    if cross_compile {
        fs::create_dir_all(macro_package.join("src")).unwrap();
        fs::create_dir_all(shared_package.join("src")).unwrap();
    }
    let network_dependency = if networked { "foo = \"=1.0.0\"\n" } else { "" };
    fs::write(
        host_root.join("Cargo.toml"),
        format!("[package]\nname = \"host-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[lib]\npath = \"../trees/host-fixture/src/lib.rs\"\n\n[dependencies]\ngenerated-agent = {{ path = \"../trees/generated-agent\" }}\n{network_dependency}"),
    )
    .unwrap();
    fs::write(
        host_package.join("Cargo.toml"),
        format!("[package]\nname = \"host-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[dependencies]\ngenerated-agent = {{ path = \"../generated-agent\" }}\n{network_dependency}"),
    )
    .unwrap();
    fs::write(host_package.join("src/lib.rs"), "pub fn host() {}\n").unwrap();
    if cross_compile {
        let crate_type = if mode == FetchFixtureMode::WasmPipeline {
            "\n[lib]\ncrate-type = [\"cdylib\"]\n"
        } else {
            ""
        };
        let wasm_dependency = if mode == FetchFixtureMode::WasmPipeline {
            "wasm-bindgen = { version = \"=0.2.127\", default-features = false, features = [\"std\"] }\n"
        } else {
            ""
        };
        fs::write(
            generated_package.join("Cargo.toml"),
            format!(
                "[package]\nname = \"generated-agent\"\nversion = \"0.1.0\"\nedition = \"2024\"\nbuild = \"build.rs\"\n{crate_type}\n[dependencies]\nmacro-helper = {{ path = \"../macro-helper\" }}\nshared-helper = {{ path = \"../shared-helper\", features = [\"target-feature\"] }}\n{wasm_dependency}\n[build-dependencies]\nshared-helper = {{ path = \"../shared-helper\", features = [\"host-feature\"] }}\n"
            ),
        )
        .unwrap();
        let build_script = if mode == FetchFixtureMode::HostPipeline {
            r#"use std::{fs, net::TcpStream, os::unix::net::UnixStream, process::Command};
fn main() {
    assert!(shared_helper::HOST_FEATURE);
    assert!(!shared_helper::TARGET_FEATURE);
    assert_eq!(fs::read("/rust-agent/inputs/fixture-sdk/input.txt").unwrap(), b"declared-sdk\n");
    assert_eq!(std::env::var("PHASE_1B_FIXTURE_CHANNEL").unwrap(), "attested");
    assert_eq!(std::env::var("CARGO_HOME").unwrap(), "/rust-agent/cargo-home");
    for variable in ["HOME", "HTTP_PROXY", "HTTPS_PROXY", "AWS_SECRET_ACCESS_KEY"] {
        assert!(std::env::var_os(variable).is_none(), "ambient {variable} leaked");
    }
    assert!(fs::read("/etc/passwd").is_err());
    assert!(fs::read("/root/.ssh/id_ed25519").is_err());
    assert!(fs::write("/rust-agent/closure/escape", b"escape").is_err());
    assert_eq!(TcpStream::connect(("127.0.0.1", 9)).unwrap_err().raw_os_error(), Some(1));
    assert_eq!(UnixStream::connect("/rust-agent/tmp/escape.sock").unwrap_err().raw_os_error(), Some(1));
    assert!(Command::new("/bin/sh").status().is_err());
    assert_eq!(std::env::var("COMPILER_PATH").unwrap(), "/rust-agent/tools");
    let output = Command::new("/rust-agent/tools/fixture-probe")
        .arg("--escape-test")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"descendant-escape-denied\n");
    assert!(output.stderr.is_empty());
    println!("cargo:rustc-check-cfg=cfg(rust_agent_build_script)");
    println!("cargo:rustc-cfg=rust_agent_build_script");
}
"#
        } else {
            "fn main() { assert!(shared_helper::HOST_FEATURE); assert!(!shared_helper::TARGET_FEATURE); assert_eq!(std::env::var(\"CARGO_HOME\").unwrap(), \"/rust-agent/cargo-home\"); assert!(std::env::var_os(\"HOME\").is_none()); assert_eq!(std::env::var(\"COMPILER_PATH\").unwrap(), \"/rust-agent/tools\"); println!(\"cargo:rustc-check-cfg=cfg(rust_agent_build_script)\"); println!(\"cargo:rustc-cfg=rust_agent_build_script\"); }\n"
        };
        fs::write(generated_package.join("build.rs"), build_script).unwrap();
        let generated_source = if mode == FetchFixtureMode::WasmPipeline {
            "use wasm_bindgen::prelude::*;\nmacro_helper::marker!();\n#[wasm_bindgen]\n#[cfg(rust_agent_build_script)]\npub fn generated() -> bool { shared_helper::TARGET_FEATURE && !shared_helper::HOST_FEATURE }\n"
        } else {
            "macro_helper::marker!();\n#[cfg(rust_agent_build_script)]\npub fn generated() -> bool { shared_helper::TARGET_FEATURE && !shared_helper::HOST_FEATURE }\n"
        };
        fs::write(generated_package.join("src/lib.rs"), generated_source).unwrap();
        fs::write(
            macro_package.join("Cargo.toml"),
            "[package]\nname = \"macro-helper\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[lib]\nproc-macro = true\n\n[dependencies]\nshared-helper = { path = \"../shared-helper\", features = [\"macro-feature\"] }\n",
        )
        .unwrap();
        fs::write(
            macro_package.join("src/lib.rs"),
            "extern crate proc_macro;\nuse proc_macro::TokenStream;\n#[proc_macro]\npub fn marker(_: TokenStream) -> TokenStream { assert!(shared_helper::MACRO_FEATURE); TokenStream::new() }\n",
        )
        .unwrap();
        fs::write(
            shared_package.join("Cargo.toml"),
            "[package]\nname = \"shared-helper\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[features]\ndefault = []\nhost-feature = []\nmacro-feature = []\ntarget-feature = []\n",
        )
        .unwrap();
        fs::write(
            shared_package.join("src/lib.rs"),
            "pub const HOST_FEATURE: bool = cfg!(feature = \"host-feature\");\npub const MACRO_FEATURE: bool = cfg!(feature = \"macro-feature\");\npub const TARGET_FEATURE: bool = cfg!(feature = \"target-feature\");\n",
        )
        .unwrap();
    } else {
        fs::write(
            generated_package.join("Cargo.toml"),
            "[package]\nname = \"generated-agent\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::write(
            generated_package.join("src/lib.rs"),
            "pub fn generated() {}\n",
        )
        .unwrap();
    }

    let cargo = rustup_which("cargo");
    let compiler_rustc = rustup_which("rustc");
    let rustc = compiler_rustc.clone();
    let credential_helper =
        authenticated.then(|| build_credential_helper(temp.path(), &compiler_rustc));
    let signing = matches!(
        mode,
        FetchFixtureMode::StandalonePipeline
            | FetchFixtureMode::WasmPipeline
            | FetchFixtureMode::HostPipeline
    )
    .then(|| FixtureSigning::new(temp.path(), &compiler_rustc));
    let sdk = (mode == FetchFixtureMode::HostPipeline).then(|| {
        let root = temp.path().join("fixture-sdk");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("input.txt"), b"declared-sdk\n").unwrap();
        root
    });
    let fixture_probe = (mode == FetchFixtureMode::HostPipeline)
        .then(|| build_escape_fixture_tool(temp.path(), &compiler_rustc));
    let host_linker = cross_compile.then(|| find_executable("cc"));
    let host_linker_collect2 = host_linker
        .as_deref()
        .map(|linker| compiler_program(linker, "collect2"));
    let host_linker_ld = cross_compile.then(|| find_executable("ld"));
    let wasm_bindgen =
        (mode == FetchFixtureMode::WasmPipeline).then(|| find_executable("wasm-bindgen"));
    let sysroot = PathBuf::from(
        String::from_utf8(
            Command::new(&compiler_rustc)
                .args(["--print", "sysroot"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim(),
    );
    let build_triple = host_triple(&compiler_rustc);
    let target_linker = cross_compile.then(|| {
        sysroot
            .join("lib/rustlib")
            .join(&build_triple)
            .join("bin/rust-lld")
    });
    let target_triple = if cross_compile {
        "wasm32-unknown-unknown".into()
    } else {
        build_triple.clone()
    };
    let target = Target::query(&compiler_rustc, target_triple, Environment::Server).unwrap();
    let target_record = TargetFactsRecord::from_target(&target).unwrap();
    let target_bytes = canonical::jcs_bytes(&target_record).unwrap();
    let lock = cargo_lock_bytes(
        networked,
        cross_compile,
        mode == FetchFixtureMode::WasmPipeline,
        &registry_checksum,
    );
    fs::write(host_root.join("Cargo.lock"), &lock).unwrap();
    fs::write(generated_package.join("Cargo.lock"), &lock).unwrap();
    let host_tree = canonical_tree(&host_package);
    let generated_tree = canonical_tree(&generated_package);
    let macro_tree = cross_compile.then(|| canonical_tree(&macro_package));
    let shared_tree = cross_compile.then(|| canonical_tree(&shared_package));
    let host_identity = path_package("host-fixture", host_tree.digest());
    let generated_identity = path_package("generated-agent", generated_tree.digest());
    let macro_identity = macro_tree
        .as_ref()
        .map(|tree| path_package("macro-helper", tree.digest()));
    let shared_identity = shared_tree
        .as_ref()
        .map(|tree| path_package("shared-helper", tree.digest()));
    let mut path_packages = vec![host_identity.clone(), generated_identity.clone()];
    path_packages.extend(macro_identity.clone());
    path_packages.extend(shared_identity.clone());
    let locked = LockedSourceClosure::from_cargo_lock(&lock, &path_packages)
        .unwrap()
        .normalize()
        .unwrap();

    let policy = ProductionBuildExecutionPolicy {
        schema: 4,
        id: "real-fetch-fixture".into(),
        host: "cfg(target_os = \"linux\")".into(),
        backend: ProductionSandboxBackend::LinuxLandlockSeccomp,
        fetch: ProductionFetchPolicy {
            network_endpoints: if networked {
                vec![
                    "https://github.com:443".into(),
                    "https://index.crates.io:443".into(),
                    "https://static.crates.io:443".into(),
                ]
            } else {
                vec![]
            },
            credential_helper: credential_helper.as_ref().map(|path| {
                rust_agent_build_executor::ProductionFileIdentity {
                    path: path.clone(),
                    sha256: sha256_file(path),
                }
            }),
            tls_ca_bundle: registry.as_ref().map(|registry| {
                rust_agent_build_executor::ProductionFileIdentity {
                    path: registry.ca_bundle.clone(),
                    sha256: sha256_file(&registry.ca_bundle),
                }
            }),
            redirect_policy: ProductionFetchRedirectPolicy::DenyUnlistedOrigin,
        },
        attestation: ProductionAttestationPolicy {
            allowed_executors: vec!["rust-agent-build-v1".into()],
            trusted_signers: vec![TrustedSigner {
                id: "fixture-signer".into(),
                algorithm: "ed25519".into(),
                public_key: signing.as_ref().map_or_else(
                    || temp.path().join("unused.pub"),
                    |value| value.public_key.clone(),
                ),
                sha256: signing
                    .as_ref()
                    .map_or_else(|| "1".repeat(64), |value| sha256_file(&value.public_key)),
            }],
            trusted_reviewer_policies: vec![],
            signing_helper: SigningHelper {
                signer_id: "fixture-signer".into(),
                path: signing.as_ref().map_or_else(
                    || temp.path().join("unused-sign"),
                    |value| value.helper.clone(),
                ),
                sha256: signing
                    .as_ref()
                    .map_or_else(|| "2".repeat(64), |value| sha256_file(&value.helper)),
            },
        },
        toolchain: ProductionToolchain {
            cargo: ProductionToolIdentity {
                path: cargo.clone(),
                sha256: sha256_file(&cargo),
                version: first_line(&cargo, &["-V"]),
            },
            rustc: ProductionToolIdentity {
                path: rustc.clone(),
                sha256: sha256_file(&rustc),
                version: first_line(&rustc, &["-vV"]),
            },
            sysroot: ProductionTreeIdentity {
                path: sysroot.clone(),
                tree_digest: canonical_tree(&sysroot).digest().into(),
            },
        },
        read_inputs: sdk
            .as_ref()
            .map(|path| ProductionReadInput {
                id: "fixture-sdk".into(),
                path: path.clone(),
                tree_digest: canonical_tree(path).digest().into(),
            })
            .into_iter()
            .collect(),
        executables: fixture_probe
            .as_ref()
            .map(|path| ProductionExecutable {
                id: "fixture-probe".into(),
                path: path.clone(),
                sha256: sha256_file(path),
                version: "fixture-probe 1".into(),
            })
            .into_iter()
            .chain(host_linker.as_ref().map(|path| ProductionExecutable {
                id: "host-linker".into(),
                path: path.clone(),
                sha256: sha256_file(path),
                version: first_line_with_arg0(path, LOGICAL_HOST_LINKER, &["--version"]),
            }))
            .chain(
                host_linker_collect2
                    .as_ref()
                    .map(|path| ProductionExecutable {
                        id: "collect2".into(),
                        path: path.clone(),
                        sha256: sha256_file(path),
                        version: first_line(path, &["--version"]),
                    }),
            )
            .chain(host_linker_ld.as_ref().map(|path| ProductionExecutable {
                id: "ld".into(),
                path: path.clone(),
                sha256: sha256_file(path),
                version: first_line(path, &["--version"]),
            }))
            .chain(wasm_bindgen.as_ref().map(|path| ProductionExecutable {
                id: WASM_BINDGEN_CLI_LOGICAL_ID.into(),
                path: path.clone(),
                sha256: sha256_file(path),
                version: first_line(path, &["--version"]),
            }))
            .collect(),
        host_linker: cross_compile.then(|| ProductionHostLinker {
            executable: "host-linker".into(),
            helpers: vec!["collect2".into(), "ld".into()],
        }),
        target_linkers: target_linker
            .as_ref()
            .map(|path| ProductionTargetLinker {
                target: "wasm32-unknown-unknown".into(),
                id: "wasm-rust-lld".into(),
                path: path.clone(),
                sha256: sha256_file(path),
                version: first_line(path, &["-flavor", "wasm", "--version"]),
            })
            .into_iter()
            .collect(),
        environment: (mode == FetchFixtureMode::HostPipeline)
            .then_some(ProductionEnvironment {
                id: "fixture-channel".into(),
                variable: "PHASE_1B_FIXTURE_CHANNEL".into(),
                value: "attested".into(),
            })
            .into_iter()
            .collect(),
        derived_executable: DerivedExecutablePolicy {
            roots: vec!["target".into()],
            inherit_sandbox: true,
        },
    }
    .normalize()
    .unwrap();

    let resolution = CargoResolutionRecord {
        schema: 1,
        target: target.triple.clone(),
        cargo_target_input: target.triple.clone(),
        target_fact_digest: target.target_fact_digest.clone(),
        custom_target_spec_digest: None,
        resolver: "2".into(),
        offline: true,
        isolated_cargo_home: true,
        ancestor_config: "forbidden".into(),
        registries: BTreeMap::default(),
        git_sources: BTreeSet::default(),
    };
    let config = resolution.canonical_cargo_config();
    fs::write(host_root.join(".cargo/config.toml"), &config).unwrap();
    let resolution_bytes = canonical::jcs_bytes(&resolution).unwrap();
    let selector = BuildArtifactSelector {
        package: if matches!(
            mode,
            FetchFixtureMode::StandalonePipeline | FetchFixtureMode::WasmPipeline
        ) {
            "generated-agent".into()
        } else {
            "host-fixture".into()
        },
        target: BuildArtifactTarget::Library,
    };
    let selector_bytes = canonical::jcs_bytes(&selector).unwrap();
    let mut context = BuildEnforcementContext {
        schema: 1,
        build_triple: build_triple.clone(),
        target: target.triple.clone(),
        target_facts_digest: target.target_fact_digest.clone(),
        custom_target_spec_digest: None,
        cargo_resolution_digest: cargo_resolution_record_digest(&resolution).unwrap(),
        cargo_config_digest: sha256(config.as_bytes()),
        profile: "release".into(),
        artifact_selector: selector.clone(),
        panic_strategy: BuildPanicStrategy::Unwind,
        rustc_settings_digest: String::new(),
        prefix_remap_schema: 1,
    };
    let rustc_settings = RustcSettingsRecord::from_context(&context);
    context.rustc_settings_digest = rustc_settings.digest().unwrap();
    let rustc_settings_bytes = canonical::jcs_bytes(&rustc_settings).unwrap();
    let planner = CargoUnitGraphPlannerIdentity {
        interface: "cargo-unit-graph-v1".into(),
        cargo_version: "1.97.1".into(),
        cargo_digest: policy.policy().toolchain.cargo.sha256.clone(),
        rustc_version: "1.97.1".into(),
        rustc_digest: policy.policy().toolchain.rustc.sha256.clone(),
    };
    let registry_identity = networked.then(|| CargoPackageIdentity {
        name: "foo".into(),
        version: "1.0.0".into(),
        source: CargoPackageSource::Registry {
            registry: "https://github.com/rust-lang/crates.io-index".into(),
            checksum: registry_checksum.clone(),
        },
    });
    let mut graph_nodes = vec![
        unit(&host_identity, "host_fixture", &target.triple),
        unit(&generated_identity, "generated_agent", &target.triple),
    ];
    if cross_compile {
        let macro_identity = macro_identity.as_ref().unwrap();
        let shared_identity = shared_identity.as_ref().unwrap();
        graph_nodes.extend([
            specialized_unit(
                &generated_identity,
                "build-script-build",
                CargoCompilationKind::BuildHost,
                &build_triple,
                CargoCompileMode::Build,
                CargoCrateKind::CustomBuild,
                &[],
            ),
            specialized_unit(
                &generated_identity,
                "build-script-build",
                CargoCompilationKind::BuildHost,
                &build_triple,
                CargoCompileMode::RunCustomBuild,
                CargoCrateKind::CustomBuild,
                &[],
            ),
            specialized_unit(
                macro_identity,
                "macro_helper",
                CargoCompilationKind::BuildHost,
                &build_triple,
                CargoCompileMode::Build,
                CargoCrateKind::ProcMacro,
                &[],
            ),
            specialized_unit(
                shared_identity,
                "shared_helper",
                CargoCompilationKind::Target,
                &target.triple,
                CargoCompileMode::Build,
                CargoCrateKind::Library,
                &["default", "target-feature"],
            ),
            specialized_unit(
                shared_identity,
                "shared_helper",
                CargoCompilationKind::BuildHost,
                &build_triple,
                CargoCompileMode::Build,
                CargoCrateKind::Library,
                &["default", "host-feature", "macro-feature"],
            ),
        ]);
    } else if let Some(package) = &registry_identity {
        graph_nodes.push(unit(package, "foo", &target.triple));
    }
    let mut graph_edges = vec![CargoUnitEdge {
        dependent: graph_nodes[0].selector.clone(),
        dependency: graph_nodes[1].selector.clone(),
        extern_crate_name: "generated_agent".into(),
        dependency_kind: CargoDependencyKind::Normal,
        target_evaluation_domain: CargoTargetEvaluationDomain::Target,
    }];
    if cross_compile {
        graph_edges.extend([
            CargoUnitEdge {
                dependent: graph_nodes[1].selector.clone(),
                dependency: graph_nodes[3].selector.clone(),
                extern_crate_name: "build_script_build".into(),
                dependency_kind: CargoDependencyKind::Build,
                target_evaluation_domain: CargoTargetEvaluationDomain::BuildHost,
            },
            CargoUnitEdge {
                dependent: graph_nodes[1].selector.clone(),
                dependency: graph_nodes[4].selector.clone(),
                extern_crate_name: "macro_helper".into(),
                dependency_kind: CargoDependencyKind::Normal,
                target_evaluation_domain: CargoTargetEvaluationDomain::BuildHost,
            },
            CargoUnitEdge {
                dependent: graph_nodes[1].selector.clone(),
                dependency: graph_nodes[5].selector.clone(),
                extern_crate_name: "shared_helper".into(),
                dependency_kind: CargoDependencyKind::Normal,
                target_evaluation_domain: CargoTargetEvaluationDomain::Target,
            },
            CargoUnitEdge {
                dependent: graph_nodes[2].selector.clone(),
                dependency: graph_nodes[6].selector.clone(),
                extern_crate_name: "shared_helper".into(),
                dependency_kind: CargoDependencyKind::Build,
                target_evaluation_domain: CargoTargetEvaluationDomain::BuildHost,
            },
            CargoUnitEdge {
                dependent: graph_nodes[3].selector.clone(),
                dependency: graph_nodes[2].selector.clone(),
                extern_crate_name: "build_script_build".into(),
                dependency_kind: CargoDependencyKind::Build,
                target_evaluation_domain: CargoTargetEvaluationDomain::BuildHost,
            },
            CargoUnitEdge {
                dependent: graph_nodes[4].selector.clone(),
                dependency: graph_nodes[6].selector.clone(),
                extern_crate_name: "shared_helper".into(),
                dependency_kind: CargoDependencyKind::Normal,
                target_evaluation_domain: CargoTargetEvaluationDomain::BuildHost,
            },
        ]);
    } else if registry_identity.is_some() {
        graph_edges.push(CargoUnitEdge {
            dependent: graph_nodes[0].selector.clone(),
            dependency: graph_nodes[2].selector.clone(),
            extern_crate_name: "foo".into(),
            dependency_kind: CargoDependencyKind::Normal,
            target_evaluation_domain: CargoTargetEvaluationDomain::Target,
        });
    }
    let host_graph = HostCargoUnitGraph {
        schema: 2,
        planner,
        build_triple: build_triple.clone(),
        composition_target: target.triple.clone(),
        profile: "release".into(),
        nodes: graph_nodes,
        edges: graph_edges,
    };
    let mut standalone_graph = dependency_projection(&host_graph, &host_graph.nodes[1].selector);
    let mut final_graph = if matches!(
        mode,
        FetchFixtureMode::StandalonePipeline | FetchFixtureMode::WasmPipeline
    ) {
        standalone_graph.clone()
    } else {
        host_graph
    };
    let normalized_standalone_graph = standalone_graph.clone().normalize().unwrap();
    let normalized_final_graph = final_graph.clone().normalize().unwrap();
    let no_feature_policy = HostFeaturePolicyStageDigests::for_policy(None);
    let feature_verification =
        verify_production_host_feature_union(&DevelopmentHostFeatureVerification {
            standalone_graph: &normalized_standalone_graph,
            final_graph: &normalized_final_graph,
            observed_graph: &normalized_final_graph,
            first_party_units: &BTreeSet::new(),
            policy: None,
            stage_policy_digests: &no_feature_policy,
            observations: &BTreeMap::new(),
            composition_compiled_runtime_effects: &BTreeSet::new(),
            host_root_runtime_effects: &BTreeSet::new(),
            product_build_contributions: &[],
        })
        .unwrap();
    let mut requirements = BuildRequirements::default();
    if cross_compile {
        requirements
            .executables
            .extend(["collect2".into(), "host-linker".into(), "ld".into()]);
    }
    if mode == FetchFixtureMode::HostPipeline {
        requirements.executables.insert("fixture-probe".into());
        requirements.read_inputs.insert("fixture-sdk".into());
        requirements.environment.insert("fixture-channel".into());
    }
    if mode == FetchFixtureMode::WasmPipeline {
        requirements
            .executables
            .insert(WASM_BINDGEN_CLI_LOGICAL_ID.into());
    }
    let mut closure_items = vec![
        file_item(
            HostBuildClosureItemRole::HostRootManifest,
            "host-root-manifest",
            "/rust-agent/closure/host/Cargo.toml",
            &fs::read(host_root.join("Cargo.toml")).unwrap(),
        ),
        file_item(
            HostBuildClosureItemRole::HostCargoLock,
            "host-cargo-lock",
            "/rust-agent/closure/host/Cargo.lock",
            &lock,
        ),
        file_item(
            HostBuildClosureItemRole::CargoConfig,
            "cargo-config",
            "/rust-agent/closure/host/.cargo/config.toml",
            config.as_bytes(),
        ),
        tree_item(
            HostBuildClosureItemRole::HostPackageTree,
            "host-package-tree",
            "/rust-agent/closure/trees/host-fixture",
            host_tree.digest(),
        ),
        tree_item(
            HostBuildClosureItemRole::EmittedCompositionTree,
            "emitted-composition-tree",
            "/rust-agent/closure/trees/generated-agent",
            generated_tree.digest(),
        ),
        record_item(
            HostBuildClosureItemRole::CargoResolutionRecord,
            "cargo-resolution",
            "/rust-agent/closure/records/cargo-resolution.json",
            context.cargo_resolution_digest.clone(),
            &resolution_bytes,
        ),
        record_item(
            HostBuildClosureItemRole::TargetFactsRecord,
            "target-facts",
            "/rust-agent/closure/records/target-facts.json",
            context.target_facts_digest.clone(),
            &target_bytes,
        ),
        record_item(
            HostBuildClosureItemRole::RustcSettingsRecord,
            "rustc-settings",
            "/rust-agent/closure/records/rustc-settings.json",
            context.rustc_settings_digest.clone(),
            &rustc_settings_bytes,
        ),
        record_item(
            HostBuildClosureItemRole::ArtifactSelectorRecord,
            "artifact-selector",
            "/rust-agent/closure/records/artifact-selector.json",
            selector.digest().unwrap(),
            &selector_bytes,
        ),
    ];
    if cross_compile {
        closure_items.extend([
            tree_item(
                HostBuildClosureItemRole::PathPackageTree,
                "macro-package-tree",
                "/rust-agent/closure/trees/macro-helper",
                macro_tree.as_ref().unwrap().digest(),
            ),
            tree_item(
                HostBuildClosureItemRole::PathPackageTree,
                "shared-package-tree",
                "/rust-agent/closure/trees/shared-helper",
                shared_tree.as_ref().unwrap().digest(),
            ),
        ]);
    }
    let mut closure = HostBuildInputClosure {
        schema: 1,
        composition_hash: "b".repeat(64),
        host_dependency_alias: "generated-agent".into(),
        generated_package_name: "generated-agent".into(),
        items: closure_items,
        standalone_unit_graph: standalone_graph,
        final_unit_graph: final_graph,
        build_context: context.clone(),
        build_requirements: requirements.clone(),
        build_execution_policy_digest: policy.full_digest().into(),
        build_enforcement_identity_digest: policy
            .enforcement_identity_digest(&requirements, &context)
            .unwrap(),
        host_feature_policy: HostFeaturePolicyClosure::None,
        unit_feature_delta_digest: feature_verification.receipt().digest.clone(),
    };
    let mut normalized_closure = closure.normalize(&policy).unwrap();
    if mode == FetchFixtureMode::WasmPipeline {
        let actual_graph = derive_fixture_cargo_graph(
            &cargo,
            &rustc,
            &host_root,
            &generated_package,
            temp.path(),
            &policy,
            &normalized_closure,
            &locked,
        );
        standalone_graph = actual_graph;
        final_graph = standalone_graph.clone();
        let normalized_graph = standalone_graph.clone().normalize().unwrap();
        let verification =
            verify_production_host_feature_union(&DevelopmentHostFeatureVerification {
                standalone_graph: &normalized_graph,
                final_graph: &normalized_graph,
                observed_graph: &normalized_graph,
                first_party_units: &BTreeSet::new(),
                policy: None,
                stage_policy_digests: &no_feature_policy,
                observations: &BTreeMap::new(),
                composition_compiled_runtime_effects: &BTreeSet::new(),
                host_root_runtime_effects: &BTreeSet::new(),
                product_build_contributions: &[],
            })
            .unwrap();
        closure.standalone_unit_graph = standalone_graph;
        closure.final_unit_graph = final_graph;
        closure
            .unit_feature_delta_digest
            .clone_from(&verification.receipt().digest);
        normalized_closure = closure.normalize(&policy).unwrap();
    }

    let record_dir = temp.path().join("records");
    fs::create_dir(&record_dir).unwrap();
    for (name, bytes) in [
        ("resolution", &resolution_bytes),
        ("target", &target_bytes),
        ("rustc-settings", &rustc_settings_bytes),
        ("selector", &selector_bytes),
    ] {
        fs::write(record_dir.join(name), bytes).unwrap();
    }
    let mut sources = vec![
        source_item("host-root-manifest", host_root.join("Cargo.toml")),
        source_item("host-cargo-lock", host_root.join("Cargo.lock")),
        source_item("cargo-config", host_root.join(".cargo/config.toml")),
        source_item("host-package-tree", host_package.clone()),
        source_item("emitted-composition-tree", generated_package.clone()),
        source_item("cargo-resolution", record_dir.join("resolution")),
        source_item("target-facts", record_dir.join("target")),
        source_item("rustc-settings", record_dir.join("rustc-settings")),
        source_item("artifact-selector", record_dir.join("selector")),
    ];
    if cross_compile {
        sources.extend([
            source_item("macro-package-tree", macro_package.clone()),
            source_item("shared-package-tree", shared_package.clone()),
        ]);
    }
    let snapshot_path = temp.path().join("closure-snapshot");
    materialize_host_closure_snapshot(&normalized_closure, &sources, &snapshot_path).unwrap();
    let snapshot =
        open_verified_host_closure_snapshot(&normalized_closure, &snapshot_path).unwrap();
    let request = CargoFetchRequest {
        schema: 3,
        mode: if networked {
            CargoFetchMode::Networked
        } else {
            CargoFetchMode::Preprovisioned
        },
    }
    .normalize(&policy, &normalized_closure, &locked)
    .unwrap();
    let inputs = preflight_production_fetch_inputs(&policy, request.mode()).unwrap();

    let runtime = temp.path().join("runtime");
    fs::create_dir(&runtime).unwrap();
    let mut runtime_executables = vec![
        cargo.as_path(),
        rustc.as_path(),
        Path::new(env!("CARGO_BIN_EXE_rust-agent-linux-sandbox-launcher")),
    ];
    runtime_executables.extend(credential_helper.as_deref());
    runtime_executables.extend(wasm_bindgen.as_deref());
    runtime_executables.extend(host_linker.as_deref());
    runtime_executables.extend(host_linker_collect2.as_deref());
    runtime_executables.extend(host_linker_ld.as_deref());
    runtime_executables.extend(target_linker.as_deref());
    let (runtime_symlinks, interpreters) = copy_dynamic_runtime(
        &runtime_executables,
        &[cargo.as_path(), rustc.as_path()],
        &runtime,
        &sysroot,
        &build_triple,
        host_linker.as_deref(),
    );
    let backend_path = Path::new("/usr/bin/bwrap");
    let launcher = Path::new(env!("CARGO_BIN_EXE_rust-agent-linux-sandbox-launcher"));
    let runtime_tree = canonical_tree(&runtime);
    let backend = VerifiedLinuxSandboxBackend::open(LinuxSandboxBackendIdentity {
        schema: 1,
        executable: ProductionToolIdentity {
            path: backend_path.into(),
            sha256: sha256_file(backend_path),
            version: first_line(backend_path, &["--version"]),
        },
        launcher_executable: ProductionToolIdentity {
            path: launcher.into(),
            sha256: sha256_file(launcher),
            version: "rust-agent-linux-sandbox-launcher 3".into(),
        },
        runtime: LinuxSandboxRuntimeIdentity {
            tree: ProductionTreeIdentity {
                path: runtime,
                tree_digest: runtime_tree.digest().into(),
            },
            logical_path: "/rust-agent/runtime".into(),
            interpreter_paths: interpreters,
            // Descriptor-supervised descendant execution cannot rely on the
            // executable pathname for `$ORIGIN`. Use only the separately
            // copied, digest-bound dynamic closure observed for the exact
            // Cargo and rustc files.
            library_paths: vec!["/rust-agent/runtime/lib".into()],
            null_input_path: "/rust-agent/runtime/empty-stdin".into(),
            symlinks: runtime_symlinks,
        },
    })
    .unwrap();
    let staging = temp.path().join("fetch-staging");
    fs::create_dir(&staging).unwrap();
    let output = temp.path().join("published-cache");
    let mut layout_packages = vec![
        CargoFetchCachePackageLocation {
            package: generated_identity,
            archive_path: None,
            source_path: None,
        },
        CargoFetchCachePackageLocation {
            package: host_identity,
            archive_path: None,
            source_path: None,
        },
    ];
    if let Some(package) = macro_identity {
        layout_packages.push(CargoFetchCachePackageLocation {
            package,
            archive_path: None,
            source_path: None,
        });
    }
    if let Some(package) = shared_identity {
        layout_packages.push(CargoFetchCachePackageLocation {
            package,
            archive_path: None,
            source_path: None,
        });
    }
    if let Some(package) = registry_identity {
        layout_packages.push(CargoFetchCachePackageLocation {
            package,
            archive_path: Some(
                "registry/cache/index.crates.io-1949cf8c6b5b557f/foo-1.0.0.crate".into(),
            ),
            source_path: Some("registry/src/index.crates.io-1949cf8c6b5b557f/foo-1.0.0".into()),
        });
    }
    if mode == FetchFixtureMode::WasmPipeline {
        layout_packages.extend(seed_locked_registry_cache(&staging, &locked));
    }
    let layout = CargoFetchCacheLayout {
        schema: 1,
        packages: layout_packages,
    };
    let result = if networked {
        let endpoints = request
            .sandbox()
            .network_endpoints
            .iter()
            .map(|origin| LinuxSandboxResolvedEndpoint {
                origin: origin.clone(),
                host: origin
                    .strip_prefix("https://")
                    .unwrap()
                    .strip_suffix(":443")
                    .unwrap()
                    .into(),
                port: 443,
                addresses: vec!["127.0.0.1".parse().unwrap()],
            })
            .collect::<Vec<_>>();
        let mut missing = endpoints.clone();
        missing.pop();
        assert!(matches!(
            TrustedCargoFetchEndpointResolution::from_outer_resolution(&request, missing),
            Err(TrustedCargoFetchError::EndpointResolution(_))
        ));
        let mut mismatched = endpoints.clone();
        mismatched[0].host = "unlisted.invalid".into();
        assert!(matches!(
            TrustedCargoFetchEndpointResolution::from_outer_resolution(&request, mismatched),
            Err(TrustedCargoFetchError::EndpointResolution(_))
        ));
        assert_eq!(fs::read_dir(&staging).unwrap().count(), 0);
        assert!(!output.exists());

        let mut reordered = endpoints;
        reordered.reverse();
        reordered[0].addresses.push("127.0.0.1".parse().unwrap());
        let resolution =
            TrustedCargoFetchEndpointResolution::from_outer_resolution(&request, reordered)
                .unwrap();
        assert_eq!(resolution.endpoints().len(), 3);
        assert!(
            resolution
                .endpoints()
                .iter()
                .all(|endpoint| endpoint.addresses.len() == 1)
        );
        execute_trusted_cargo_fetch_with_endpoint_resolution(
            &backend,
            &request,
            &locked,
            &snapshot,
            &inputs,
            &resolution,
            &staging,
            &output,
            &layout,
        )
    } else {
        execute_trusted_cargo_fetch(
            &backend, &request, &locked, &snapshot, &inputs, &staging, &output, &layout,
        )
    };
    if let Err(error) = &result
        && let Some(registry) = registry.as_mut()
    {
        assert!(
            registry.child.try_wait().unwrap().is_none(),
            "local TLS registry exited during fetch: {error}"
        );
    }
    let result = result.unwrap();
    assert_eq!(result.sandbox_observation().exit_code, 0);
    assert!(!result.sandbox_observation().executed_commands.is_empty());
    result.cache().verify_unchanged().unwrap();
    if matches!(
        mode,
        FetchFixtureMode::StandalonePipeline | FetchFixtureMode::WasmPipeline
    ) {
        let signing = signing.as_ref().unwrap();
        let build_kind = if mode == FetchFixtureMode::WasmPipeline {
            BuildKind::Wasm
        } else {
            BuildKind::Library
        };
        let composition = fixture_composition_manifest(&policy, &normalized_closure, build_kind);
        let build_inputs = preflight_production_build_inputs(&policy, &normalized_closure).unwrap();
        let planner_request = CargoPlannerRequest {
            schema: 5,
            root: CargoPlannerGraphRoot::EmittedStandalone,
        }
        .normalize(&policy, &normalized_closure)
        .unwrap();
        let target_root = temp.path().join("standalone-target");
        let temp_root = temp.path().join("standalone-temp");
        let artifact_parent = temp.path().join("standalone-artifacts");
        let attestation_root = temp.path().join("standalone-attestations");
        let nonce_directory = temp.path().join("standalone-nonces");
        let bundle_root = temp.path().join("standalone-bundle");
        for directory in [
            &target_root,
            &temp_root,
            &artifact_parent,
            &attestation_root,
            &nonce_directory,
            &bundle_root,
        ] {
            fs::create_dir(directory).unwrap();
        }
        let mut completion_authority =
            |payload: &rust_agent_build_executor::ProductionBuildAttestationPayload| {
                signing.prepare_response(payload);
                Ok(signing.completion_handle(payload, "94".repeat(32)))
            };
        let built = execute_trusted_production_build(
            ProductionBuildPipelineOptions {
                composition: &composition,
                cargo_lock: &host_root.join("Cargo.lock"),
                policy: &policy,
                backend: &backend,
                closure: &normalized_closure,
                closure_snapshot: &snapshot,
                locked_sources: &locked,
                fetch_request: &request,
                fetch_inputs: &inputs,
                fetch_staging: &staging,
                fetch_cache_output: &output,
                fetch_cache_layout: &layout,
                production_inputs: &build_inputs,
                planner_request: &planner_request,
                target_root: &target_root,
                temp_root: &temp_root,
                wasm_bundle_root: (build_kind == BuildKind::Wasm).then_some(bundle_root.as_path()),
                artifact_parent: &artifact_parent,
                attestation_root: &attestation_root,
                completion_nonce_directory: &nonce_directory,
                executor_id: "rust-agent-build-v1".into(),
                workload_identity: "phase-1b-standalone-fixture".into(),
                verifier_identity_digest: "95".repeat(32),
                timestamp: "2026-09-05T00:00:00Z".into(),
                transparency_proof: None,
            },
            &mut completion_authority,
        )
        .unwrap();
        assert!(built.attestation().manifest().deployable);
        assert!(built.attestation().product_integration().is_none());
        assert_eq!(
            built.attestation().manifest().artifacts[0].target,
            "wasm32-unknown-unknown"
        );
        if build_kind == BuildKind::Wasm {
            assert!(built.wasm().is_some());
            assert_eq!(
                built
                    .build()
                    .sandbox_observation()
                    .executed_commands
                    .iter()
                    .filter(|execution| execution.executable == LOGICAL_TARGET_LINKER)
                    .count(),
                1
            );
            assert_eq!(
                built.attestation().manifest().entry_artifact,
                "bundle/rust_agent.js"
            );
            assert_eq!(built.attestation().manifest().artifacts.len(), 5);
            assert!(
                built
                    .attestation()
                    .manifest()
                    .postprocessor
                    .as_ref()
                    .is_some_and(|postprocessor| postprocessor.outputs.len() == 4)
            );
        } else {
            assert!(built.wasm().is_none());
            let policy_path = temp.path().join("production-policy.toml");
            fs::write(
                &policy_path,
                toml::to_string_pretty(policy.policy()).unwrap(),
            )
            .unwrap();
            let cli = PathBuf::from(
                env::var_os("RUST_AGENT_CLI_BIN")
                    .expect("the Phase 1B runner must provide RUST_AGENT_CLI_BIN"),
            );
            let inspected = Command::new(&cli)
                .args([
                    "inspect",
                    "--artifact-dir",
                    built.publication().path.to_str().unwrap(),
                    "--execution-policy",
                    policy_path.to_str().unwrap(),
                    "--attestation",
                    built.attestation().path().to_str().unwrap(),
                    "--workload-identity",
                    "phase-1b-standalone-fixture",
                ])
                .output()
                .unwrap();
            assert!(
                inspected.status.success(),
                "production CLI inspect failed: stdout={} stderr={}",
                String::from_utf8_lossy(&inspected.stdout),
                String::from_utf8_lossy(&inspected.stderr)
            );
            let inspected: serde_json::Value = serde_json::from_slice(&inspected.stdout).unwrap();
            assert_eq!(inspected["status"], "verified-production-build");
            assert_eq!(
                inspected["value"]["build-output-digest"],
                built.attestation().manifest().build_output_digest
            );
        }
        return;
    }
    if mode == FetchFixtureMode::HostPipeline {
        let signing = signing.as_ref().unwrap();
        let composition_build = create_fixture_composition_build(
            temp.path(),
            &policy,
            &backend,
            &normalized_closure,
            &host_root.join("Cargo.lock"),
            signing,
        );
        let build_inputs = preflight_production_build_inputs(&policy, &normalized_closure).unwrap();
        let standalone_request = CargoPlannerRequest {
            schema: 5,
            root: CargoPlannerGraphRoot::EmittedStandalone,
        }
        .normalize(&policy, &normalized_closure)
        .unwrap();
        let final_request = CargoPlannerRequest {
            schema: 5,
            root: CargoPlannerGraphRoot::FinalHost,
        }
        .normalize(&policy, &normalized_closure)
        .unwrap();
        let receipt_path = temp.path().join("integration.pre.json");
        let pre =
            execute_trusted_production_integration_pre(&ProductionIntegrationPrePipelineOptions {
                composition_build: &composition_build,
                receipt_output: &receipt_path,
                policy: &policy,
                backend: &backend,
                closure: &normalized_closure,
                closure_snapshot: &snapshot,
                locked_sources: &locked,
                fetch_request: &request,
                fetch_inputs: &inputs,
                fetch_staging: &staging,
                fetch_cache_output: &output,
                fetch_cache_layout: &layout,
                production_inputs: &build_inputs,
                standalone_planner_request: &standalone_request,
                final_planner_request: &final_request,
                first_party_units: &BTreeSet::new(),
                host_feature_policy: None,
                host_feature_observations: &BTreeMap::new(),
                host_root_runtime_effects: &BTreeSet::new(),
                product_build_contributions: &[],
            })
            .unwrap();
        assert_eq!(
            pre.standalone_planner().graph(),
            normalized_closure.standalone_unit_graph()
        );
        assert_eq!(
            pre.final_planner().graph(),
            normalized_closure.final_unit_graph()
        );
        assert_ne!(
            pre.standalone_planner().graph().digest(),
            pre.final_planner().graph().digest()
        );

        let target_root = temp.path().join("pipeline-target");
        let temp_root = temp.path().join("pipeline-temp");
        let artifact_parent = temp.path().join("host-artifacts");
        let attestation_root = temp.path().join("host-attestations");
        let nonce_directory = temp.path().join("host-nonces");
        for directory in [
            &target_root,
            &temp_root,
            &artifact_parent,
            &attestation_root,
            &nonce_directory,
        ] {
            fs::create_dir(directory).unwrap();
        }
        let mut completion_counter = 0_u8;
        let mut completion_authority =
            |payload: &rust_agent_build_executor::ProductionBuildAttestationPayload| {
                completion_counter += 1;
                signing.prepare_response(payload);
                Ok(signing.completion_handle(
                    payload,
                    format!("{:02x}", 0x80_u8 + completion_counter).repeat(32),
                ))
            };
        let host_build = execute_trusted_production_host_build(
            ProductionHostBuildPipelineOptions {
                composition_build: &composition_build,
                pre_receipt: pre.receipt(),
                cargo_lock: &host_root.join("Cargo.lock"),
                policy: &policy,
                backend: &backend,
                closure: &normalized_closure,
                closure_snapshot: &snapshot,
                locked_sources: &locked,
                fetch_request: &request,
                fetch_inputs: &inputs,
                fetch_staging: &staging,
                fetch_cache_output: &output,
                fetch_cache_layout: &layout,
                production_inputs: &build_inputs,
                standalone_planner_request: &standalone_request,
                final_planner_request: &final_request,
                first_party_units: &BTreeSet::new(),
                host_feature_policy: None,
                host_feature_observations: &BTreeMap::new(),
                host_root_runtime_effects: &BTreeSet::new(),
                product_build_contributions: &[],
                target_root: &target_root,
                temp_root: &temp_root,
                artifact_parent: &artifact_parent,
                attestation_root: &attestation_root,
                completion_nonce_directory: &nonce_directory,
                executor_id: "rust-agent-build-v1".into(),
                workload_identity: "phase-1b-host-fixture".into(),
                verifier_identity_digest: "91".repeat(32),
                timestamp: "2026-09-05T00:00:00Z".into(),
                transparency_proof: None,
            },
            &mut completion_authority,
        )
        .unwrap();
        assert!(host_build.attestation().manifest().deployable);
        assert!(host_build.attestation().product_integration().is_some());

        let post_reverification =
            reverify_trusted_production_integration_pre(&ProductionIntegrationPrePipelineOptions {
                composition_build: &composition_build,
                receipt_output: &receipt_path,
                policy: &policy,
                backend: &backend,
                closure: &normalized_closure,
                closure_snapshot: &snapshot,
                locked_sources: &locked,
                fetch_request: &request,
                fetch_inputs: &inputs,
                fetch_staging: &staging,
                fetch_cache_output: &output,
                fetch_cache_layout: &layout,
                production_inputs: &build_inputs,
                standalone_planner_request: &standalone_request,
                final_planner_request: &final_request,
                first_party_units: &BTreeSet::new(),
                host_feature_policy: None,
                host_feature_observations: &BTreeMap::new(),
                host_root_runtime_effects: &BTreeSet::new(),
                product_build_contributions: &[],
            })
            .unwrap();
        assert_eq!(post_reverification.receipt(), pre.receipt());

        let post_payload = create_production_integration_post_payload(
            pre.receipt(),
            &normalized_closure,
            &policy,
            &composition_build,
            host_build.attestation(),
            ProductionIntegrationPostInput {
                executor_id: "rust-agent-build-v1".into(),
                workload_identity: "phase-1b-post-fixture".into(),
                verifier_identity_digest: "92".repeat(32),
            },
        )
        .unwrap();
        signing.prepare_response(&post_payload);
        let post_completion = signing.completion_handle(&post_payload, "93".repeat(32));
        let post_path = temp.path().join("integration.post.json");
        let post = write_production_integration_post_attestation(
            &post_path,
            &host_build.publication().path,
            &receipt_path,
            pre.receipt(),
            &normalized_closure,
            &policy,
            &composition_build,
            host_build.attestation(),
            post_payload,
            post_completion,
            &nonce_directory,
            "2026-09-05T00:00:01Z".into(),
            None,
        )
        .unwrap();
        assert_eq!(
            post.attestation().payload.operation,
            ProductionOperationKind::IntegrationPost
        );
        assert!(post_path.is_file());
        return;
    }
    if matches!(
        mode,
        FetchFixtureMode::Planner
            | FetchFixtureMode::CrossPlanner
            | FetchFixtureMode::BuildObserver
    ) {
        let build_inputs = preflight_production_build_inputs(&policy, &normalized_closure).unwrap();
        let preflight = execute_trusted_production_preflight(
            &backend,
            &build_inputs,
            &normalized_closure,
            &snapshot,
        )
        .unwrap();
        assert_eq!(
            preflight.version_sandbox_observations().len(),
            build_inputs.request().expected_probes().count()
        );
        assert_eq!(
            preflight.validated_version_observation().request_digest(),
            build_inputs.request().digest()
        );
        assert_eq!(
            preflight
                .validated_target_facts_observation()
                .target_facts_digest(),
            normalized_closure.build_context().target_facts_digest
        );
        if cross_compile {
            let standalone_request = CargoPlannerRequest {
                schema: 5,
                root: CargoPlannerGraphRoot::EmittedStandalone,
            }
            .normalize(&policy, &normalized_closure)
            .unwrap();
            let standalone = execute_trusted_cargo_planner(
                &backend,
                &standalone_request,
                &normalized_closure,
                &snapshot,
                &locked,
                result.cache(),
                &build_inputs,
            )
            .unwrap();
            assert_eq!(
                standalone.graph(),
                normalized_closure.standalone_unit_graph()
            );
            assert_ne!(
                standalone.graph().digest(),
                normalized_closure.final_unit_graph().digest()
            );
            assert_eq!(standalone.graph().nodes().len(), 6);
            assert!(
                standalone
                    .graph()
                    .nodes()
                    .keys()
                    .all(|selector| selector.package.name != "host-fixture")
            );
        }
        let planner_request = CargoPlannerRequest {
            schema: 5,
            root: CargoPlannerGraphRoot::FinalHost,
        }
        .normalize(&policy, &normalized_closure)
        .unwrap();
        let plan = execute_trusted_cargo_planner(
            &backend,
            &planner_request,
            &normalized_closure,
            &snapshot,
            &locked,
            result.cache(),
            &build_inputs,
        )
        .unwrap();
        assert_eq!(plan.unit_graph_sandbox_observation().exit_code, 0);
        assert_eq!(plan.metadata_sandbox_observation().exit_code, 0);
        assert_eq!(
            plan.graph().nodes().len(),
            if cross_compile { 7 } else { 2 }
        );
        assert_eq!(
            plan.graph().edges().len(),
            if cross_compile { 7 } else { 1 }
        );
        if cross_compile {
            let shared_units = plan
                .graph()
                .nodes()
                .iter()
                .filter(|(selector, _)| selector.package.name == "shared-helper")
                .collect::<Vec<_>>();
            assert_eq!(shared_units.len(), 2);
            assert!(shared_units.iter().any(|(selector, unit)| {
                selector.compilation_kind == CargoCompilationKind::BuildHost
                    && unit.features
                        == BTreeSet::from([
                            "default".into(),
                            "host-feature".into(),
                            "macro-feature".into(),
                        ])
            }));
            assert!(shared_units.iter().any(|(selector, unit)| {
                selector.compilation_kind == CargoCompilationKind::Target
                    && unit.features == BTreeSet::from(["default".into(), "target-feature".into()])
            }));
            assert!(plan.graph().nodes().keys().any(|selector| {
                selector.compilation_kind == CargoCompilationKind::BuildHost
                    && selector.crate_kind == CargoCrateKind::ProcMacro
            }));
            assert!(plan.graph().nodes().keys().any(|selector| {
                selector.compilation_kind == CargoCompilationKind::BuildHost
                    && selector.compile_mode == CargoCompileMode::RunCustomBuild
            }));
        }
        if mode == FetchFixtureMode::BuildObserver {
            let target_root = temp.path().join("production-target");
            let temp_root = temp.path().join("production-temp");
            fs::create_dir(&target_root).unwrap();
            fs::create_dir(&temp_root).unwrap();
            let build = execute_trusted_cargo_build(
                &backend,
                &policy,
                &planner_request,
                &normalized_closure,
                &snapshot,
                result.cache(),
                &build_inputs,
                plan.graph(),
                &target_root,
                &temp_root,
            )
            .unwrap();
            plan.graph()
                .verify_observation(build.observed_graph())
                .unwrap();
            assert_eq!(build.sandbox_observation().exit_code, 0);
            assert_eq!(build.cargo_messages_sha256().len(), 64);
        }
    }
    if networked {
        assert!(result.sandbox_observation().enforcements.contains(
            &rust_agent_build_executor::LinuxSandboxEnforcement::NetworkEndpointAllowlistEnforced
        ));
        let configuration_mounts = result
            .sandbox_observation()
            .read_only_mounts
            .iter()
            .filter(|mount| {
                mount.kind == rust_agent_build_executor::LinuxSandboxMountKind::NetworkConfiguration
            })
            .map(|mount| (mount.id.as_str(), mount.logical_path.as_str()))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            configuration_mounts,
            BTreeSet::from([
                ("network-host-conf", "/etc/host.conf"),
                ("network-hosts", "/etc/hosts"),
                ("network-nsswitch", "/etc/nsswitch.conf"),
                ("network-resolv", "/etc/resolv.conf"),
            ])
        );
    }
    if authenticated {
        let helper_executions = result
            .fetch_observation()
            .descendant_executions
            .iter()
            .filter(|execution| {
                matches!(
                    execution,
                    rust_agent_build_executor::CargoFetchDescendantExecution::CredentialHelper {
                        executable,
                        arguments,
                        exit_code: 0,
                        ..
                    } if executable == "/rust-agent/fetch-tools/credential-helper"
                        && arguments == &["--cargo-plugin"]
                )
            })
            .count();
        assert_eq!(helper_executions, 1);
        let mut evidence = canonical::jcs_bytes(result.sandbox_observation()).unwrap();
        evidence.extend(canonical::jcs_bytes(result.fetch_observation()).unwrap());
        assert!(
            !evidence
                .windows(TEST_CREDENTIAL.len())
                .any(|window| { window == TEST_CREDENTIAL.as_bytes() })
        );
        for entry in WalkDir::new(&output).into_iter().filter_map(Result::ok) {
            if entry.file_type().is_file() {
                let bytes = fs::read(entry.path()).unwrap();
                assert!(
                    !bytes
                        .windows(TEST_CREDENTIAL.len())
                        .any(|window| { window == TEST_CREDENTIAL.as_bytes() })
                );
            }
        }
    }
}

fn build_credential_helper(root: &Path, rustc: &Path) -> PathBuf {
    let source = root.join("credential-helper.rs");
    let executable = root.join("credential-helper");
    fs::write(
        &source,
        format!(
            r#"use std::io::{{BufRead as _, Write as _}};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::process::Command;

const TOKEN: &str = {TEST_CREDENTIAL:?};

fn main() {{
    assert_eq!(std::env::args().collect::<Vec<_>>().len(), 2);
    assert_eq!(std::env::args().nth(1).as_deref(), Some("--cargo-plugin"));
    assert_eq!(
        TcpStream::connect(("127.0.0.1", 443)).unwrap_err().raw_os_error(),
        Some(1)
    );
    assert_eq!(UnixStream::pair().unwrap_err().raw_os_error(), Some(1));
    assert_eq!(
        Command::new("/rust-agent/toolchain/bin/rustc")
            .arg("-vV")
            .status()
            .unwrap_err()
            .raw_os_error(),
        Some(13)
    );

    let mut output = std::io::stdout().lock();
    writeln!(output, "{{{{\"v\":[1]}}}}").unwrap();
    output.flush().unwrap();
    let mut request = String::new();
    std::io::stdin().lock().read_line(&mut request).unwrap();
    assert!(request.len() <= 4096);
    assert!(request.contains("\"v\":1"));
    assert!(request.contains("\"kind\":\"get\""));
    assert!(request.contains("\"operation\":\"read\""));
    assert!(request.contains("\"index-url\":"));
    assert!(!request.contains(TOKEN));
    writeln!(
        output,
        "{{{{\"Ok\":{{{{\"kind\":\"get\",\"token\":{{TOKEN:?}},\"cache\":\"session\",\"operation_independent\":true}}}}}}}}"
    )
    .unwrap();
    output.flush().unwrap();
}}
"#,
        ),
    )
    .unwrap();
    let status = Command::new(rustc)
        .args(["--edition=2024", "-C", "strip=symbols"])
        .arg(&source)
        .arg("-o")
        .arg(&executable)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "failed to build credential helper fixture"
    );
    executable
}

fn build_escape_fixture_tool(root: &Path, rustc: &Path) -> PathBuf {
    let source = root.join("fixture-linker.rs");
    let executable = root.join("fixture-linker");
    fs::write(
        &source,
        r#"use std::{fs, net::TcpStream, os::unix::net::UnixStream, process::Command};
fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("--version") => println!("fixture-probe 1"),
        Some("--escape-test") => {
            assert!(fs::read("/etc/passwd").is_err());
            assert!(fs::write("/tmp/descendant-escape", b"escape").is_err());
            assert_eq!(TcpStream::connect(("127.0.0.1", 9)).unwrap_err().raw_os_error(), Some(1));
            assert_eq!(UnixStream::connect("/rust-agent/tmp/descendant.sock").unwrap_err().raw_os_error(), Some(1));
            assert!(Command::new("/bin/sh").status().is_err());
            println!("descendant-escape-denied");
        }
        _ => panic!("unsupported fixture-probe invocation"),
    }
}
"#,
    )
    .unwrap();
    let status = Command::new(rustc)
        .args(["--edition=2024", "-C", "strip=symbols"])
        .arg(&source)
        .arg("-o")
        .arg(&executable)
        .status()
        .unwrap();
    assert!(status.success(), "failed to build escape fixture tool");
    executable.canonicalize().unwrap()
}

struct LocalTlsRegistry {
    child: Child,
    ca_bundle: PathBuf,
}

impl LocalTlsRegistry {
    fn start(root: &Path, archive: &[u8], checksum: &str, authenticated: bool) -> Self {
        let registry = root.join("tls-registry");
        fs::create_dir_all(registry.join("3/f")).unwrap();
        fs::create_dir_all(registry.join("crates/foo")).unwrap();
        fs::write(registry.join("crates/foo/foo-1.0.0.crate"), archive).unwrap();
        let authentication = if authenticated {
            ",\"auth-required\":true"
        } else {
            ""
        };
        fs::write(
            registry.join("config.json"),
            format!(
                "{{\"dl\":\"https://static.crates.io/crates/{{crate}}/{{crate}}-{{version}}.crate\"{authentication}}}\n"
            ),
        )
        .unwrap();
        fs::write(
            registry.join("3/f/foo"),
            format!(
                "{{\"name\":\"foo\",\"vers\":\"1.0.0\",\"deps\":[],\"cksum\":\"{checksum}\",\"features\":{{}},\"yanked\":false,\"links\":null}}\n"
            ),
        )
        .unwrap();
        let certificate = registry.join("ca.pem");
        let key = registry.join("key.pem");
        let openssl = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                key.to_str().unwrap(),
                "-out",
                certificate.to_str().unwrap(),
                "-subj",
                "/CN=index.crates.io",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "subjectAltName=DNS:index.crates.io,DNS:static.crates.io,DNS:github.com",
                "-days",
                "36500",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(openssl.success());
        let server = registry.join("server.py");
        let authentication = if authenticated { "True" } else { "False" };
        fs::write(
            &server,
            format!(
                "import http.server\nimport pathlib\nimport ssl\nAUTH_REQUIRED = {authentication}\nTOKEN = '{TEST_CREDENTIAL}'\nclass H(http.server.SimpleHTTPRequestHandler):\n    def log_message(self, *args): pass\n    def do_GET(self):\n        if AUTH_REQUIRED and self.path != '/config.json' and self.headers.get('Authorization') != TOKEN:\n            self.send_response(403)\n            self.end_headers()\n            return\n        super().do_GET()\nserver = http.server.ThreadingHTTPServer(('127.0.0.1', 443), H)\nctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\nctx.load_cert_chain('ca.pem', 'key.pem')\nserver.socket = ctx.wrap_socket(server.socket, server_side=True)\npathlib.Path('ready').write_text('ready\\n')\nserver.serve_forever()\n"
            ),
        )
        .unwrap();
        let mut child = Command::new("python3")
            .arg("server.py")
            .current_dir(&registry)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            assert!(
                child.try_wait().unwrap().is_none(),
                "local TLS registry exited before becoming ready"
            );
            if registry.join("ready").is_file() {
                thread::sleep(Duration::from_millis(25));
                assert!(
                    child.try_wait().unwrap().is_none(),
                    "local TLS registry exited after publishing readiness"
                );
                break;
            }
            assert!(
                Instant::now() < deadline,
                "local TLS registry did not start"
            );
            thread::sleep(Duration::from_millis(25));
        }
        Self {
            child,
            ca_bundle: certificate,
        }
    }
}

impl Drop for LocalTlsRegistry {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn cargo_lock_bytes(
    networked: bool,
    cross_compile: bool,
    wasm_bindgen: bool,
    checksum: &str,
) -> Vec<u8> {
    let dependency = if networked { " \"foo\"," } else { "" };
    let registry = if networked {
        format!(
            "\n[[package]]\nname = \"foo\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{checksum}\"\n"
        )
    } else {
        String::new()
    };
    let generated_dependencies = if cross_compile {
        let wasm_dependency = if wasm_bindgen {
            " \"wasm-bindgen\",\n"
        } else {
            ""
        };
        format!("dependencies = [\n \"macro-helper\",\n \"shared-helper\",\n{wasm_dependency}]\n")
    } else {
        String::new()
    };
    let cross_packages = if cross_compile {
        "\n[[package]]\nname = \"macro-helper\"\nversion = \"0.1.0\"\ndependencies = [\n \"shared-helper\",\n]\n\n[[package]]\nname = \"shared-helper\"\nversion = \"0.1.0\"\n"
    } else {
        ""
    };
    let wasm_packages = if wasm_bindgen {
        r#"
[[package]]
name = "bumpalo"
version = "3.20.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "72f5acc6cb2ba439de613abc23857ec3d78374d8ed5ac84e9d11336e87da8649"

[[package]]
name = "cfg-if"
version = "1.0.4"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "9330f8b2ff13f34540b44e946ef35111825727b38d33286ef986142615121801"

[[package]]
name = "once_cell"
version = "1.21.4"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "9f7c3e4beb33f85d45ae3e3a1792185706c8e16d043238c593331cc7cd313b50"

[[package]]
name = "proc-macro2"
version = "1.0.107"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "985e7ec9bb745e6ce6535b544d84d6cd6f7ad8bd711c398938ae983b91a766d9"
dependencies = [
 "unicode-ident",
]

[[package]]
name = "quote"
version = "1.0.47"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "1fbf4db142a473a8d80c26bbf18454ed458bf8d26c8219c331daecfdbd079001"
dependencies = [
 "proc-macro2",
]

[[package]]
name = "rustversion"
version = "1.0.23"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "cf54715a573b99ac80df0bc206da022bcd442c974952c7b9720069370852e21f"

[[package]]
name = "syn"
version = "2.0.119"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "872831b642d1a07999a962a351ed35b955ea2cfc8f3862091e2a240a84f17297"
dependencies = [
 "proc-macro2",
 "quote",
 "unicode-ident",
]

[[package]]
name = "unicode-ident"
version = "1.0.24"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "e6e4313cd5fcd3dad5cafa179702e2b244f760991f45397d14d4ebf38247da75"

[[package]]
name = "wasm-bindgen"
version = "0.2.127"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "1b70935747edd64d89de3efa29d73789b806c15798f8e7dca4d8ac356b50ce70"
dependencies = [
 "cfg-if",
 "once_cell",
 "rustversion",
 "wasm-bindgen-macro",
 "wasm-bindgen-shared",
]

[[package]]
name = "wasm-bindgen-macro"
version = "0.2.127"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "77775f8f3f7217702089053b94958f8f54061a3f663417df76e19cbdcca29bc1"
dependencies = [
 "quote",
 "wasm-bindgen-macro-support",
]

[[package]]
name = "wasm-bindgen-macro-support"
version = "0.2.127"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "e11d33f857dc2fb11b8bc75aee111aa9cbeb12cd9f25efd3d4c2a3dd4e235284"
dependencies = [
 "bumpalo",
 "proc-macro2",
 "quote",
 "syn",
 "wasm-bindgen-shared",
]

[[package]]
name = "wasm-bindgen-shared"
version = "0.2.127"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "7ef64dbcc55df09c7e5a46182d181c2cfa3e925f3da937ea764728b4bbb9dcbf"
dependencies = [
 "unicode-ident",
]
"#
    } else {
        ""
    };
    format!(
        "# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n[[package]]\nname = \"generated-agent\"\nversion = \"0.1.0\"\n{generated_dependencies}{cross_packages}\n[[package]]\nname = \"host-fixture\"\nversion = \"0.1.0\"\ndependencies = [{dependency} \"generated-agent\",]\n{registry}{wasm_packages}"
    )
    .into_bytes()
}

fn registry_archive() -> Vec<u8> {
    fn append(
        builder: &mut tar::Builder<flate2::write::GzEncoder<Vec<u8>>>,
        path: &str,
        bytes: &[u8],
    ) {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_size(u64::try_from(bytes.len()).unwrap());
        header.set_cksum();
        builder.append_data(&mut header, path, bytes).unwrap();
    }
    let encoder = flate2::GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    append(
        &mut builder,
        "foo-1.0.0/Cargo.toml",
        b"[package]\nname = \"foo\"\nversion = \"1.0.0\"\nedition = \"2024\"\n",
    );
    append(
        &mut builder,
        "foo-1.0.0/src/lib.rs",
        b"pub fn fetched_over_attested_tls() {}\n",
    );
    builder.into_inner().unwrap().finish().unwrap()
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
    digest: &str,
) -> HostBuildClosureItem {
    HostBuildClosureItem {
        role,
        id: id.into(),
        logical_path: logical_path.into(),
        metadata_contract: CanonicalSnapshotMetadataContract::ReadOnlyEpochV1,
        content: HostBuildClosureContent::SnapshotTree {
            tree_digest: digest.into(),
        },
    }
}

fn record_item(
    role: HostBuildClosureItemRole,
    id: &str,
    logical_path: &str,
    digest: String,
    bytes: &[u8],
) -> HostBuildClosureItem {
    HostBuildClosureItem {
        role,
        id: id.into(),
        logical_path: logical_path.into(),
        metadata_contract: CanonicalSnapshotMetadataContract::ReadOnlyEpochV1,
        content: HostBuildClosureContent::CanonicalRecord {
            digest,
            bytes_sha256: sha256(bytes),
        },
    }
}

fn source_item(id: &str, path: PathBuf) -> HostClosureSnapshotSource {
    HostClosureSnapshotSource {
        item_id: id.into(),
        path,
    }
}

fn path_package(name: &str, tree_digest: &str) -> CargoPackageIdentity {
    CargoPackageIdentity {
        name: name.into(),
        version: "0.1.0".into(),
        source: CargoPackageSource::Path {
            tree_digest: tree_digest.into(),
        },
    }
}

fn unit(package: &CargoPackageIdentity, target_name: &str, triple: &str) -> CargoUnit {
    specialized_unit(
        package,
        target_name,
        CargoCompilationKind::Target,
        triple,
        CargoCompileMode::Build,
        CargoCrateKind::Library,
        &[],
    )
}

fn specialized_unit(
    package: &CargoPackageIdentity,
    target_name: &str,
    compilation_kind: CargoCompilationKind,
    compilation_target: &str,
    compile_mode: CargoCompileMode,
    crate_kind: CargoCrateKind,
    features: &[&str],
) -> CargoUnit {
    CargoUnit {
        selector: CargoUnitSelector {
            package: package.clone(),
            target_name: target_name.into(),
            compilation_kind,
            compilation_target: compilation_target.into(),
            cargo_target_context: if compilation_kind == CargoCompilationKind::Target
                || compile_mode == CargoCompileMode::RunCustomBuild
            {
                rust_agent_build_executor::CargoUnitTargetContext::CompositionTarget
            } else {
                rust_agent_build_executor::CargoUnitTargetContext::BuildHost
            },
            compile_mode,
            profile: "release".into(),
            crate_kind,
        },
        features: features.iter().map(|value| (*value).into()).collect(),
        build_script: crate_kind == CargoCrateKind::CustomBuild,
        proc_macro: crate_kind == CargoCrateKind::ProcMacro,
    }
}

fn rustup_which(tool: &str) -> PathBuf {
    PathBuf::from(
        String::from_utf8(
            Command::new("rustup")
                .args(["which", tool])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim(),
    )
    .canonicalize()
    .unwrap()
}

fn host_triple(rustc: &Path) -> String {
    Command::new(rustc)
        .arg("-vV")
        .output()
        .unwrap()
        .stdout
        .split(|byte| *byte == b'\n')
        .find_map(|line| {
            std::str::from_utf8(line)
                .ok()?
                .strip_prefix("host: ")
                .map(str::to_owned)
        })
        .unwrap()
}

fn canonical_tree(root: &Path) -> CanonicalSnapshotTree {
    let mut entries = Vec::new();
    for entry in WalkDir::new(root).sort_by_file_name().into_iter().skip(1) {
        let entry = entry.unwrap();
        let relative = entry
            .path()
            .strip_prefix(root)
            .unwrap()
            .to_str()
            .unwrap()
            .replace('\\', "/");
        if entry.file_type().is_dir() {
            entries.push(CanonicalSnapshotEntry::directory(relative));
        } else {
            let bytes = fs::read(entry.path()).unwrap();
            entries.push(CanonicalSnapshotEntry::regular_file(
                relative,
                sha256(&bytes),
                bytes.len() as u64,
            ));
        }
    }
    CanonicalSnapshotTree::from_entries(entries).unwrap()
}

fn dependency_projection(
    graph: &HostCargoUnitGraph,
    root: &CargoUnitSelector,
) -> HostCargoUnitGraph {
    let mut selected = BTreeSet::from([root.clone()]);
    loop {
        let mut changed = false;
        for edge in &graph.edges {
            if selected.contains(&edge.dependent) && selected.insert(edge.dependency.clone()) {
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    HostCargoUnitGraph {
        schema: graph.schema,
        planner: graph.planner.clone(),
        build_triple: graph.build_triple.clone(),
        composition_target: graph.composition_target.clone(),
        profile: graph.profile.clone(),
        nodes: graph
            .nodes
            .iter()
            .filter(|unit| selected.contains(&unit.selector))
            .cloned()
            .collect(),
        edges: graph
            .edges
            .iter()
            .filter(|edge| {
                selected.contains(&edge.dependent) && selected.contains(&edge.dependency)
            })
            .cloned()
            .collect(),
    }
}

#[allow(clippy::too_many_arguments)]
fn derive_fixture_cargo_graph(
    cargo: &Path,
    rustc: &Path,
    host_root: &Path,
    generated_package: &Path,
    fixture_root: &Path,
    policy: &rust_agent_build_executor::NormalizedProductionBuildPolicy,
    bootstrap_closure: &rust_agent_build_executor::NormalizedHostBuildInputClosure,
    locked: &rust_agent_build_executor::NormalizedLockedSourceClosure,
) -> HostCargoUnitGraph {
    let request = CargoPlannerRequest {
        schema: 5,
        root: CargoPlannerGraphRoot::EmittedStandalone,
    }
    .normalize(policy, bootstrap_closure)
    .unwrap();
    let cargo_home = ambient_cargo_home();
    let target_root = fixture_root.join("bootstrap-planner-target");
    fs::create_dir(&target_root).unwrap();

    let physical_arguments = request
        .invocation()
        .arguments
        .iter()
        .map(|argument| match argument.as_str() {
            "/rust-agent/closure/trees/generated-agent/Cargo.toml" => generated_package
                .join("Cargo.toml")
                .to_str()
                .unwrap()
                .into(),
            "/rust-agent/closure/host/.cargo/config.toml" => host_root
                .join(".cargo/config.toml")
                .to_str()
                .unwrap()
                .into(),
            _ => argument.clone(),
        })
        .collect::<Vec<_>>();
    let mut unit_graph = Command::new(cargo);
    unit_graph
        .args(&physical_arguments)
        .current_dir(generated_package);
    configure_fixture_cargo_command(
        &mut unit_graph,
        request.invocation().environment.iter(),
        &cargo_home,
        &target_root,
        rustc,
        true,
    );
    let unit_graph = unit_graph.output().unwrap();
    let logical_unit_graph = logicalize_fixture_cargo_output(
        &unit_graph.stdout,
        host_root,
        generated_package.parent().unwrap(),
        &cargo_home,
        &target_root,
    );
    let envelope = request
        .verify_output(
            unit_graph.status.code().unwrap_or(255),
            &logical_unit_graph,
            &unit_graph.stderr,
        )
        .unwrap_or_else(|error| {
            panic!(
                "fixture Cargo unit-graph failed: {error}; stdout={} stderr={}",
                String::from_utf8_lossy(&unit_graph.stdout),
                String::from_utf8_lossy(&unit_graph.stderr)
            )
        });

    let metadata_arguments: Vec<String> = vec![
        "metadata".into(),
        "--format-version".into(),
        "1".into(),
        "--manifest-path".into(),
        generated_package
            .join("Cargo.toml")
            .to_str()
            .unwrap()
            .into(),
        "--config".into(),
        host_root
            .join(".cargo/config.toml")
            .to_str()
            .unwrap()
            .into(),
        "--locked".into(),
        "--offline".into(),
        "--filter-platform".into(),
        request.target().into(),
    ];
    let mut metadata = Command::new(cargo);
    metadata
        .args(metadata_arguments)
        .current_dir(generated_package);
    configure_fixture_cargo_command(
        &mut metadata,
        request.invocation().environment.iter(),
        &cargo_home,
        &target_root,
        rustc,
        false,
    );
    let metadata = metadata.output().unwrap();
    assert!(
        metadata.status.success(),
        "fixture Cargo metadata failed: stdout={} stderr={}",
        String::from_utf8_lossy(&metadata.stdout),
        String::from_utf8_lossy(&metadata.stderr)
    );
    assert!(
        metadata.stderr.is_empty(),
        "fixture Cargo metadata emitted stderr: {}",
        String::from_utf8_lossy(&metadata.stderr)
    );
    let logical_metadata = logicalize_fixture_cargo_output(
        &metadata.stdout,
        host_root,
        generated_package.parent().unwrap(),
        &cargo_home,
        &target_root,
    );
    let semantics =
        derive_cargo_planner_edge_semantics_from_metadata(&request, &envelope, &logical_metadata)
            .unwrap_or_else(|error| {
                panic!(
                    "fixture Cargo edge semantics failed: {error}; unit-graph={} metadata={}",
                    String::from_utf8_lossy(&logical_unit_graph),
                    String::from_utf8_lossy(&logical_metadata)
                )
            });
    let normalized =
        normalize_cargo_unit_graph(&request, &envelope, bootstrap_closure, locked, &semantics)
            .unwrap();
    HostCargoUnitGraph {
        schema: 2,
        planner: normalized.planner().clone(),
        build_triple: normalized.build_triple().into(),
        composition_target: normalized.composition_target().into(),
        profile: normalized.profile().into(),
        nodes: normalized
            .nodes()
            .values()
            .map(|unit| CargoUnit {
                selector: unit.selector.clone(),
                features: unit.features.iter().cloned().collect(),
                build_script: unit.build_script,
                proc_macro: unit.proc_macro,
            })
            .collect(),
        edges: normalized.edges().iter().cloned().collect(),
    }
}

fn logicalize_fixture_cargo_output(
    bytes: &[u8],
    host_root: &Path,
    trees_root: &Path,
    cargo_home: &Path,
    target_root: &Path,
) -> Vec<u8> {
    let mut output = String::from_utf8(bytes.to_vec()).unwrap();
    for (physical, logical) in [
        (target_root, "/rust-agent/target"),
        (cargo_home, "/rust-agent/cargo-home"),
        (trees_root, "/rust-agent/closure/trees"),
        (host_root, "/rust-agent/closure/host"),
    ] {
        output = output.replace(physical.to_str().unwrap(), logical);
    }
    output.into_bytes()
}

fn configure_fixture_cargo_command<'a>(
    command: &mut Command,
    environment: impl Iterator<Item = (&'a String, &'a String)>,
    cargo_home: &Path,
    target_root: &Path,
    rustc: &Path,
    include_channel_override: bool,
) {
    const CHANNEL_OVERRIDE: &str = "__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS";
    command.env_clear();
    for (name, value) in environment {
        if name == CHANNEL_OVERRIDE && !include_channel_override {
            continue;
        }
        match name.as_str() {
            "CARGO_HOME" => {
                command.env(name, cargo_home);
            }
            "CARGO_TARGET_DIR" => {
                command.env(name, target_root);
            }
            "RUSTC" => {
                command.env(name, rustc);
            }
            "PATH" => {
                command.env(name, rustc.parent().unwrap());
            }
            _ => {
                command.env(name, value);
            }
        }
    }
}

fn ambient_cargo_home() -> PathBuf {
    if let Some(path) = env::var_os("CARGO_HOME") {
        return PathBuf::from(path).canonicalize().unwrap();
    }
    PathBuf::from(env::var_os("HOME").expect("fixture runner must define HOME"))
        .join(".cargo")
        .canonicalize()
        .unwrap()
}

fn seed_locked_registry_cache(
    staging: &Path,
    locked: &rust_agent_build_executor::NormalizedLockedSourceClosure,
) -> Vec<CargoFetchCachePackageLocation> {
    let ambient = ambient_cargo_home();
    let ambient_cache = ambient.join("registry/cache");
    let ambient_index = ambient.join("registry/index");
    let staged_home = staging.join("cargo-home");
    let mut initialized_indexes = BTreeSet::new();
    let mut locations = Vec::new();
    for package in locked.packages() {
        let CargoPackageSource::Registry { checksum, .. } = &package.source else {
            continue;
        };
        let archive_name = format!("{}-{}.crate", package.name, package.version);
        let matches = fs::read_dir(&ambient_cache)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path().join(&archive_name))
            .filter(|path| path.is_file())
            .collect::<Vec<_>>();
        assert_eq!(
            matches.len(),
            1,
            "expected one ambient archive for {} {}",
            package.name,
            package.version
        );
        let archive = &matches[0];
        assert_eq!(sha256_file(archive), *checksum);
        let index_id = archive
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap();
        let staged_archive = staged_home
            .join("registry/cache")
            .join(index_id)
            .join(&archive_name);
        fs::create_dir_all(staged_archive.parent().unwrap()).unwrap();
        fs::copy(archive, &staged_archive).unwrap();

        let ambient_index_root = ambient_index.join(index_id);
        let staged_index_root = staged_home.join("registry/index").join(index_id);
        if initialized_indexes.insert(index_id.to_owned()) {
            fs::create_dir_all(&staged_index_root).unwrap();
            fs::copy(
                ambient_index_root.join("config.json"),
                staged_index_root.join("config.json"),
            )
            .unwrap();
        }
        let relative_index_entry = crates_io_index_entry(&package.name);
        let source_index_entry = ambient_index_root
            .join(".cache")
            .join(&relative_index_entry);
        let staged_index_entry = staged_index_root.join(".cache").join(&relative_index_entry);
        fs::create_dir_all(staged_index_entry.parent().unwrap()).unwrap();
        fs::copy(source_index_entry, staged_index_entry).unwrap();

        locations.push(CargoFetchCachePackageLocation {
            package: package.clone(),
            archive_path: Some(format!("registry/cache/{index_id}/{archive_name}")),
            source_path: Some(format!(
                "registry/src/{index_id}/{}-{}",
                package.name, package.version
            )),
        });
    }
    locations
}

fn crates_io_index_entry(name: &str) -> PathBuf {
    let name = name.to_ascii_lowercase();
    match name.len() {
        1 => PathBuf::from("1").join(name),
        2 => PathBuf::from("2").join(name),
        3 => PathBuf::from("3").join(&name[..1]).join(name),
        _ => PathBuf::from(&name[..2]).join(&name[2..4]).join(name),
    }
}

fn create_fixture_composition_build(
    root: &Path,
    policy: &rust_agent_build_executor::NormalizedProductionBuildPolicy,
    backend: &VerifiedLinuxSandboxBackend,
    closure: &rust_agent_build_executor::NormalizedHostBuildInputClosure,
    cargo_lock: &Path,
    signing: &FixtureSigning,
) -> rust_agent_build_executor::VerifiedProductionBuildAttestation {
    let composition = fixture_composition_manifest(policy, closure, BuildKind::Library);

    let artifact_parent = root.join("composition-artifacts");
    let attestation_root = root.join("composition-attestations");
    let nonce_directory = root.join("composition-nonces");
    for directory in [&artifact_parent, &attestation_root, &nonce_directory] {
        fs::create_dir(directory).unwrap();
    }
    let staging = create_production_artifact_staging(&artifact_parent).unwrap();
    fs::create_dir(staging.join("artifact")).unwrap();
    fs::write(
        staging.join("artifact/generated-composition.rlib"),
        b"fixture generated composition artifact\n",
    )
    .unwrap();
    let artifact = production_artifact_record(
        &staging,
        "artifact/generated-composition.rlib",
        ProductionArtifactKind::RustLibrary,
        &composition.target,
    )
    .unwrap();
    let selector = BuildArtifactSelector {
        package: closure.generated_package_name().into(),
        target: BuildArtifactTarget::Library,
    };
    let mut context = closure.build_context().clone();
    context.artifact_selector = selector.clone();
    let enforcement = policy
        .enforcement_identity(&BuildRequirements::default(), &context)
        .unwrap();
    let cargo_environment = enforcement.cargo_driver_environment.clone();
    let graph_digest = closure.standalone_unit_graph().digest().to_owned();
    let cargo_messages_digest = "d1".repeat(32);
    let manifest = write_production_build_manifest(
        &staging,
        cargo_lock,
        ProductionBuildManifestInput {
            composition,
            build_requirements: BuildRequirements::default(),
            effective_compiled_runtime_effects: BTreeSet::new(),
            build_enforcement_identity: enforcement,
            enforcement_result: ProductionEnforcementResultIdentity {
                schema: 1,
                build_input_content_digest: closure.content_identity_digest().into(),
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
                build_kind: BuildKind::Library,
                composition_profile: "phase-1b-fixture".into(),
                cargo_profile: context.profile.clone(),
                target: context.target.clone(),
                artifact_selector: selector,
                panic_strategy: context.panic_strategy,
                locked: true,
                offline: true,
                jobs: 1,
            },
            cargo_invocation: ProductionCargoInvocationIdentity {
                schema: 1,
                arguments: vec!["build".into(), "--locked".into(), "--offline".into()],
                environment: cargo_environment,
                working_directory: "/rust-agent/closure/trees/generated-agent".into(),
            },
            entry_artifact: artifact.path.clone(),
            artifacts: vec![artifact],
            postprocessor: None,
            gates: vec!["fixture-production-isolation".into()],
        },
    )
    .unwrap();
    let evidence = ProductionExecutionEvidence {
        schema: 1,
        pre_receipt_digest: None,
        executor_attestation_payload_digest: None,
        host_build_input_closure_digest: closure.digest().into(),
        build_input_content_digest: closure.content_identity_digest().into(),
        production_input_request_digest: "d2".repeat(32),
        production_input_observation_digest: "d3".repeat(32),
        target_facts_request_digest: "d4".repeat(32),
        target_facts_observation_digest: "d5".repeat(32),
        standalone_planner_request_digest: "d6".repeat(32),
        final_planner_request_digest: "d6".repeat(32),
        standalone_planned_unit_graph_digest: graph_digest.clone(),
        final_planned_unit_graph_digest: graph_digest.clone(),
        observed_unit_graph_digest: graph_digest,
        unit_feature_delta_digest: closure.unit_feature_delta_digest().into(),
        sandbox_observation_digest: "d7".repeat(32),
        cargo_messages_digest,
        wasm_postprocessor_observation_digest: None,
    };
    let payload = create_production_build_attestation_payload(
        &manifest,
        policy,
        ProductionBuildAttestationInput {
            operation: ProductionOperationKind::Build,
            executor_id: "rust-agent-build-v1".into(),
            workload_identity: "phase-1b-composition-fixture".into(),
            verifier_identity_digest: "d8".repeat(32),
            sandbox_backend_identity: backend.identity().try_into().unwrap(),
            evidence,
            product_integration: None,
            host_feature_policy: None,
        },
    )
    .unwrap();
    signing.prepare_response(&payload);
    let completion = signing.completion_handle(&payload, "d9".repeat(32));
    let signed = sign_production_build_attestation(
        &manifest,
        policy,
        payload,
        completion,
        &nonce_directory,
        "2026-09-05T00:00:00Z".into(),
        None,
    )
    .unwrap();
    let prepared = prepare_production_build_attestation_publication(
        &staging,
        &attestation_root,
        policy,
        &signed,
    )
    .unwrap();
    let publication = publish_production_artifact(
        &staging,
        &artifact_parent,
        &manifest,
        prepared.artifact_publication_permit(),
    )
    .unwrap();
    prepared.finalize(&publication.path, policy).unwrap()
}

fn fixture_composition_manifest(
    policy: &rust_agent_build_executor::NormalizedProductionBuildPolicy,
    closure: &rust_agent_build_executor::NormalizedHostBuildInputClosure,
    build_kind: BuildKind,
) -> CompositionManifest {
    let mut composition: CompositionManifest = serde_json::from_slice(include_bytes!(
        "../../../../tests/golden/minimal/rust-agent-composition.json"
    ))
    .unwrap();
    let target = Target::query(
        &policy.policy().toolchain.rustc.path,
        closure.build_context().target.clone(),
        Environment::Server,
    )
    .unwrap();
    composition.composition_hash = closure.composition_hash().into();
    composition.build_kind = build_kind;
    composition.profile = "phase-1b-fixture".into();
    composition.target.clone_from(&target.triple);
    composition.normalized_target = target.clone();
    composition
        .target_fact_digest
        .clone_from(&target.target_fact_digest);
    composition.target_facts = TargetFactsRecord::from_target(&target).unwrap();
    composition
        .cargo_resolution
        .target
        .clone_from(&target.triple);
    composition
        .cargo_resolution
        .cargo_target_input
        .clone_from(&target.triple);
    composition
        .cargo_resolution
        .target_fact_digest
        .clone_from(&target.target_fact_digest);
    composition.cargo_resolution.custom_target_spec_digest = None;
    composition
        .cargo_resolution_digest
        .clone_from(&closure.build_context().cargo_resolution_digest);
    composition.custom_target_spec = None;
    composition.component_runtime_effects.clear();
    composition.host_runtime_effects.clear();
    composition.compiled_runtime_effects.clear();
    composition.build_requirements = BuildRequirements::default();
    composition.direct_root_build_requirements.clear();
    composition.deployable = false;
    composition
}

fn copy_dynamic_runtime(
    executables: &[&Path],
    toolchain_executables: &[&Path],
    output: &Path,
    toolchain_sysroot: &Path,
    build_triple: &str,
    host_linker: Option<&Path>,
) -> (Vec<LinuxSandboxRuntimeSymlink>, Vec<String>) {
    fs::write(output.join("empty-stdin"), []).unwrap();
    let mut sources = Vec::new();
    let mut toolchain_sources = BTreeMap::<String, String>::new();
    let mut loaders = Vec::new();
    for executable in executables {
        let toolchain_executable = toolchain_executables.contains(executable);
        let result = Command::new("ldd").arg(executable).output().unwrap();
        assert!(result.status.success());
        for line in String::from_utf8(result.stdout).unwrap().lines() {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            let source = fields
                .windows(2)
                .find(|pair| pair[0] == "=>" && pair[1].starts_with('/'))
                .map(|pair| pair[1])
                .or_else(|| fields.first().copied().filter(|path| path.starts_with('/')));
            if let Some(source) = source {
                if toolchain_executable && line.contains("=>") {
                    let basename = Path::new(source)
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .into_owned();
                    if let Some(previous) = toolchain_sources.insert(basename, source.into()) {
                        assert_eq!(
                            sha256_file(Path::new(&previous)),
                            sha256_file(Path::new(source)),
                            "the exact Cargo/rustc dynamic closures contain a basename collision"
                        );
                    }
                    continue;
                }
                if !line.contains("=>") {
                    loaders.push(source.to_owned());
                }
                sources.push(source.to_owned());
            }
        }
    }
    let libc = sources
        .iter()
        .find(|source| {
            Path::new(source)
                .file_name()
                .is_some_and(|name| name == "libc.so.6")
        })
        .expect("the pinned Linux Cargo runtime includes libc");
    let nss_files = Path::new(libc).with_file_name("libnss_files.so.2");
    assert!(
        nss_files.is_file(),
        "the Phase 1B Linux runner requires a digest-bound files-only NSS module"
    );
    sources.push(nss_files.to_str().unwrap().into());
    sources.sort();
    sources.dedup();
    loaders.sort();
    loaders.dedup();
    for source in sources {
        let destination = output.join(source.strip_prefix('/').unwrap());
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::copy(&source, destination).unwrap();
    }
    let toolchain_library_root = output.join("lib");
    fs::create_dir_all(&toolchain_library_root).unwrap();
    for (basename, source) in toolchain_sources {
        fs::copy(source, toolchain_library_root.join(basename)).unwrap();
    }
    copy_regular_tree(
        &toolchain_sysroot.join("lib/rustlib").join(build_triple),
        &toolchain_library_root.join("rustlib").join(build_triple),
    );
    if let Some(host_linker) = host_linker {
        copy_compiler_support_files(host_linker, output);
    }
    let mut symlinks = ["lib", "lib64", "root", "usr"]
        .into_iter()
        .filter(|name| output.join(name).exists())
        .map(|name| LinuxSandboxRuntimeSymlink {
            target: format!("/rust-agent/runtime/{name}"),
            link: format!("/{name}"),
        })
        .collect::<Vec<_>>();
    symlinks.push(LinuxSandboxRuntimeSymlink {
        target: "/rust-agent/runtime/empty-stdin".into(),
        link: "/dev/null".into(),
    });
    symlinks.extend(compiler_install_runtime_symlink(output));
    symlinks.extend(compiler_path_runtime_symlink(output));
    symlinks.sort();
    (symlinks, loaders)
}

fn compiler_install_runtime_symlink(output: &Path) -> Option<LinuxSandboxRuntimeSymlink> {
    output
        .join("rust-agent/lib")
        .is_dir()
        .then(|| LinuxSandboxRuntimeSymlink {
            target: "/rust-agent/runtime/rust-agent/lib".into(),
            link: "/rust-agent/lib".into(),
        })
}

fn compiler_path_runtime_symlink(output: &Path) -> Option<LinuxSandboxRuntimeSymlink> {
    output
        .join("compiler-path/liblto_plugin.so")
        .is_file()
        .then(|| LinuxSandboxRuntimeSymlink {
            target: "/rust-agent/runtime/compiler-path/liblto_plugin.so".into(),
            link: "/rust-agent/tools/liblto_plugin.so".into(),
        })
}

fn copy_regular_tree(source: &Path, destination: &Path) {
    assert!(source.is_dir(), "required runtime tree is unavailable");
    for entry in WalkDir::new(source).sort_by_file_name() {
        let entry = entry.unwrap();
        let relative = entry.path().strip_prefix(source).unwrap();
        let output = destination.join(relative);
        let file_type = entry.file_type();
        assert!(
            !file_type.is_symlink(),
            "runtime tree contains an unsupported symlink: {}",
            entry.path().display()
        );
        if file_type.is_dir() {
            fs::create_dir_all(&output).unwrap();
        } else {
            assert!(
                file_type.is_file(),
                "runtime tree contains a special entry: {}",
                entry.path().display()
            );
            fs::create_dir_all(output.parent().unwrap()).unwrap();
            fs::copy(entry.path(), output).unwrap();
        }
    }
}

fn copy_compiler_support_files(host_linker: &Path, output: &Path) {
    const REQUIRED: &[&str] = &[
        "Scrt1.o",
        "crti.o",
        "crtn.o",
        "crtbeginS.o",
        "crtendS.o",
        "libgcc.a",
        "libgcc_s.so",
        "libc.so",
        "libc_nonshared.a",
        "liblto_plugin.so",
    ];
    const OPTIONAL: &[&str] = &[
        "crt1.o",
        "crtbegin.o",
        "crtend.o",
        "libdl.a",
        "libgcc_eh.a",
        "libgcc_s.so.1",
        "libm.so",
        "libm.so.6",
        "libmvec.so.1",
        "libpthread.a",
        "librt.a",
        "libutil.a",
        "lto-wrapper",
    ];
    let host_install = compiler_install_directory(host_linker, None);
    let logical_install = compiler_install_directory(host_linker, Some(LOGICAL_HOST_LINKER));
    for (name, required) in REQUIRED
        .iter()
        .map(|name| (*name, true))
        .chain(OPTIONAL.iter().map(|name| (*name, false)))
    {
        let query = Command::new(host_linker)
            .arg(format!("-print-file-name={name}"))
            .output()
            .unwrap();
        assert!(
            query.status.success(),
            "compiler file query failed for {name}"
        );
        let printed = String::from_utf8(query.stdout).unwrap();
        let printed = Path::new(printed.trim());
        if !printed.is_absolute() || !printed.is_file() {
            assert!(
                !required,
                "required compiler support file `{name}` is unavailable"
            );
            continue;
        }
        let logical = normalize_absolute_path(printed);
        let source = printed.canonicalize().unwrap();
        let mut destinations = BTreeSet::from([logical.clone()]);
        if let Ok(relative) = logical.strip_prefix(&host_install) {
            destinations.insert(logical_install.join(relative));
        }
        if name == "liblto_plugin.so" {
            destinations.insert(PathBuf::from("/compiler-path/liblto_plugin.so"));
        }
        for destination in destinations {
            let destination = output.join(destination.strip_prefix(Path::new("/")).unwrap());
            fs::create_dir_all(destination.parent().unwrap()).unwrap();
            fs::copy(&source, destination).unwrap();
        }
        copy_linker_script_dependencies(printed, output);
    }
}

fn copy_linker_script_dependencies(root: &Path, output: &Path) {
    let mut pending = BTreeSet::from([normalize_absolute_path(root)]);
    let mut visited = BTreeSet::new();
    while let Some(path) = pending.pop_first() {
        assert!(
            visited.len() < MAX_LINKER_SCRIPT_FILES,
            "compiler linker-script dependency closure is too large"
        );
        if !visited.insert(path.clone()) {
            continue;
        }
        for dependency in linker_script_dependencies(&path) {
            let source = dependency.canonicalize().unwrap();
            let destination = output.join(dependency.strip_prefix(Path::new("/")).unwrap());
            fs::create_dir_all(destination.parent().unwrap()).unwrap();
            fs::copy(source, destination).unwrap();
            pending.insert(dependency);
        }
    }
}

fn linker_script_dependencies(path: &Path) -> BTreeSet<PathBuf> {
    let metadata = fs::metadata(path).unwrap();
    if metadata.len() > MAX_LINKER_SCRIPT_BYTES {
        return BTreeSet::new();
    }
    let bytes = fs::read(path).unwrap();
    let Ok(script) = std::str::from_utf8(&bytes) else {
        return BTreeSet::new();
    };
    if !script.contains("GROUP") && !script.contains("INPUT") {
        return BTreeSet::new();
    }
    script
        .split(|character: char| {
            character.is_ascii_whitespace() || matches!(character, '(' | ')' | ',' | ';')
        })
        .filter(|token| {
            token.starts_with('/')
                && token
                    .as_bytes()
                    .get(1)
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
        .map(PathBuf::from)
        .map(|dependency| {
            assert!(
                dependency.is_file(),
                "linker script references missing absolute dependency {}",
                dependency.display()
            );
            normalize_absolute_path(&dependency)
        })
        .collect()
}

fn compiler_install_directory(compiler: &Path, arg0: Option<&str>) -> PathBuf {
    let mut command = Command::new(compiler);
    if let Some(arg0) = arg0 {
        command
            .arg0(arg0)
            .env("COMPILER_PATH", LOGICAL_COMPILER_PATH);
    }
    let output = command.arg("-print-search-dirs").output().unwrap();
    assert!(output.status.success(), "compiler search-dir query failed");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let install = stdout
        .lines()
        .find_map(|line| line.strip_prefix("install: "))
        .expect("compiler search dirs omitted its install root");
    let install = Path::new(install);
    assert!(
        install.is_absolute(),
        "compiler install root is not absolute"
    );
    normalize_absolute_path(install)
}

fn normalize_absolute_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::from("/");
    for component in path.components() {
        match component {
            std::path::Component::Normal(component) => normalized.push(component),
            std::path::Component::ParentDir => {
                assert!(normalized.pop(), "absolute compiler path escaped root");
            }
            std::path::Component::RootDir | std::path::Component::CurDir => {}
            std::path::Component::Prefix(_) => panic!("Windows path in Linux fixture"),
        }
    }
    normalized
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn sha256_file(path: &Path) -> String {
    sha256(&fs::read(path).unwrap())
}
fn find_executable(name: &str) -> PathBuf {
    env::split_paths(&env::var_os("PATH").unwrap_or_default())
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| panic!("required fixture executable `{name}` is unavailable"))
        .canonicalize()
        .unwrap()
}
fn compiler_program(compiler: &Path, name: &str) -> PathBuf {
    let output = Command::new(compiler)
        .arg(format!("-print-prog-name={name}"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let path = PathBuf::from(String::from_utf8(output.stdout).unwrap().trim());
    assert!(
        path.is_absolute() && path.is_file(),
        "compiler did not resolve required program `{name}` to an absolute file"
    );
    path.canonicalize().unwrap()
}
fn compiler_program_file(compiler: &Path, name: &str) -> PathBuf {
    let output = Command::new(compiler)
        .arg(format!("-print-file-name={name}"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let path = PathBuf::from(String::from_utf8(output.stdout).unwrap().trim());
    assert!(
        path.is_absolute() && path.is_file(),
        "compiler did not resolve required file `{name}` to an absolute file"
    );
    path.canonicalize().unwrap()
}
fn compiler_linker_dry_run_with_identity(
    compiler: &Path,
    arg0: &str,
    compiler_path: &Path,
) -> String {
    let output = Command::new(compiler)
        .arg0(arg0)
        .env("COMPILER_PATH", compiler_path)
        .args(["-fuse-linker-plugin", "-###", "-x", "c", "/dev/null"])
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stderr).unwrap()
}
fn first_line(path: &Path, arguments: &[&str]) -> String {
    let output = Command::new(path).args(arguments).output().unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .into()
}
fn first_line_with_arg0(path: &Path, arg0: &str, arguments: &[&str]) -> String {
    let output = Command::new(path)
        .arg0(arg0)
        .args(arguments)
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .into()
}
