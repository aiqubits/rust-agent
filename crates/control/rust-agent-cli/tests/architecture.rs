use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
    process::Command,
};

use toml::Value;
use walkdir::WalkDir;

const PINNED_RUST_VERSION: &str = "1.97.1";
const PINNED_WASM_BINDGEN_VERSION: &str = "0.2.127";
const PINNED_WASM_BINDGEN_FUTURES_VERSION: &str = "0.4.77";
const PINNED_WASM_BINDGEN_TEST_VERSION: &str = "0.3.77";
const PINNED_TARGETS: [&str; 5] = [
    "wasm32-unknown-unknown",
    "aarch64-linux-android",
    "aarch64-apple-ios",
    "x86_64-apple-darwin",
    "x86_64-pc-windows-msvc",
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
}

#[test]
fn workspace_has_no_product_dependency() {
    let root = workspace_root();
    for entry in WalkDir::new(&root).into_iter().filter_entry(|entry| {
        let name = entry.file_name().to_string_lossy();
        !matches!(
            name.as_ref(),
            ".git" | "target" | "AINS" | "deepseek-harness" | ".rust-agent"
        )
    }) {
        let entry = entry.unwrap();
        if entry.file_name() == "Cargo.toml" {
            let input = fs::read_to_string(entry.path()).unwrap();
            for forbidden in ["client-api", "dioxus", "tauri", "ains-"] {
                assert!(
                    !input.to_ascii_lowercase().contains(forbidden),
                    "{} contains forbidden dependency marker {forbidden}",
                    entry.path().display()
                );
            }
        }
    }
}

#[test]
fn api_dependency_direction_is_acyclic() {
    let root = workspace_root();
    let core = fs::read_to_string(root.join("crates/api/rust-agent-core/Cargo.toml")).unwrap();
    let runtime =
        fs::read_to_string(root.join("crates/api/rust-agent-runtime-api/Cargo.toml")).unwrap();
    assert!(!core.contains("rust-agent-runtime-api"));
    assert!(runtime.contains("rust-agent-core"));
    assert!(!runtime.contains("rust-agent-agent"));
    assert!(!runtime.contains("rust-agent-session"));
}

#[test]
fn phase_three_tool_api_dependency_and_privacy_boundary_is_isolated() {
    let root = workspace_root();
    let manifest: Value = toml::from_str(
        &fs::read_to_string(root.join("crates/api/rust-agent-tools/Cargo.toml")).unwrap(),
    )
    .unwrap();
    let dependencies = manifest["dependencies"]
        .as_table()
        .unwrap()
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        dependencies,
        ["rust-agent-core", "rust-agent-runtime-api", "serde_json"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );

    let output = Command::new("cargo")
        .args([
            "tree",
            "-p",
            "rust-agent-tools",
            "--edges",
            "normal",
            "--no-default-features",
        ])
        .current_dir(&root)
        .output()
        .unwrap();
    assert!(output.status.success());
    let tree = String::from_utf8(output.stdout).unwrap();
    for forbidden in [
        "AINS",
        "rust-agent-agent",
        "rust-agent-commands",
        "rust-agent-driver-",
        "rust-agent-model",
        "rust-agent-session",
        "tokio",
    ] {
        assert!(
            !tree.contains(forbidden),
            "tool API dependency tree contains forbidden owner {forbidden}:\n{tree}"
        );
    }

    let source = fs::read_to_string(root.join("crates/api/rust-agent-tools/src/lib.rs")).unwrap();
    assert!(source.contains("pub struct ExecutionPermit"));
    assert!(source.contains("handler: Arc<dyn Tool>"));
    assert!(!source.contains("pub handler:"));
    assert!(!source.contains("unsafe"));
}

#[test]
fn phase_two_session_public_closure_is_agent_free_in_every_feature_mode() {
    let root = workspace_root();
    let session_manifest =
        fs::read_to_string(root.join("crates/api/rust-agent-session/Cargo.toml")).unwrap();
    let agent_manifest =
        fs::read_to_string(root.join("crates/api/rust-agent-agent/Cargo.toml")).unwrap();
    assert!(session_manifest.contains("rust-agent-runtime-api"));
    assert!(session_manifest.contains("rust-agent-core"));
    assert!(!session_manifest.contains("rust-agent-agent"));
    assert!(agent_manifest.contains("rust-agent-session"));
    assert!(!agent_manifest.contains("rust-agent-extension-api"));

    for arguments in [
        vec![
            "tree",
            "-p",
            "rust-agent-session",
            "--edges",
            "normal",
            "--no-default-features",
        ],
        vec![
            "tree",
            "-p",
            "rust-agent-session",
            "--edges",
            "normal",
            "--no-default-features",
            "--features",
            "development",
        ],
        vec![
            "tree",
            "-p",
            "rust-agent-session",
            "--edges",
            "normal",
            "--all-features",
        ],
    ] {
        let output = Command::new("cargo")
            .args(arguments)
            .current_dir(&root)
            .output()
            .unwrap();
        assert!(output.status.success());
        let tree = String::from_utf8(output.stdout).unwrap();
        assert!(tree.contains("rust-agent-session"));
        assert!(tree.contains("rust-agent-runtime-api"));
        assert!(tree.contains("rust-agent-core"));
        assert!(!tree.contains("rust-agent-agent"));
    }

    let session_source =
        fs::read_to_string(root.join("crates/api/rust-agent-session/src/lib.rs")).unwrap();
    assert!(session_source.contains("pub trait SessionPersistenceAdmin"));
    assert!(session_source.contains("rust_agent_runtime_api"));
    assert!(!session_source.contains("rust_agent_agent"));
}

#[test]
fn mandatory_api_crates_have_an_exact_effect_free_dependency_closure() {
    let root = workspace_root();
    let core: Value = toml::from_str(
        &fs::read_to_string(root.join("crates/api/rust-agent-core/Cargo.toml")).unwrap(),
    )
    .unwrap();
    assert!(core.get("dependencies").is_none());

    let runtime: Value = toml::from_str(
        &fs::read_to_string(root.join("crates/api/rust-agent-runtime-api/Cargo.toml")).unwrap(),
    )
    .unwrap();
    let dependencies = runtime["dependencies"].as_table().unwrap();
    assert_eq!(dependencies.len(), 1);
    let core_dependency = dependencies["rust-agent-core"].as_table().unwrap();
    assert_eq!(core_dependency["path"].as_str(), Some("../rust-agent-core"));
    assert_eq!(core_dependency["default-features"].as_bool(), Some(false));

    for manifest in [core, runtime] {
        let requirements = &manifest["package"]["metadata"]["rust-agent"]["build-requirements"];
        assert_eq!(requirements["schema"].as_integer(), Some(1));
        for field in ["executables", "read-inputs", "environment"] {
            assert!(requirements[field].as_array().unwrap().is_empty());
        }
    }
}

#[test]
fn rust_toolchain_version_is_pinned_and_synchronized() {
    let root = workspace_root();
    assert_eq!(env!("CARGO_PKG_RUST_VERSION"), PINNED_RUST_VERSION);
    for tool in ["rustc", "cargo"] {
        let output = Command::new(tool).arg("--version").output().unwrap();
        assert!(output.status.success(), "{tool} --version failed");
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!(
            stdout.split_whitespace().nth(1),
            Some(PINNED_RUST_VERSION),
            "{tool} is not the repository-pinned version"
        );
    }

    let workspace: Value =
        toml::from_str(&fs::read_to_string(root.join("Cargo.toml")).unwrap()).unwrap();
    assert_eq!(
        workspace["workspace"]["package"]["rust-version"].as_str(),
        Some(PINNED_RUST_VERSION)
    );
    for member in workspace["workspace"]["members"].as_array().unwrap() {
        let member = member.as_str().unwrap();
        let manifest: Value =
            toml::from_str(&fs::read_to_string(root.join(member).join("Cargo.toml")).unwrap())
                .unwrap();
        assert_eq!(
            manifest["package"]["rust-version"]["workspace"].as_bool(),
            Some(true),
            "{member} must inherit the pinned workspace rust-version"
        );
    }

    let toolchain: Value =
        toml::from_str(&fs::read_to_string(root.join("rust-toolchain.toml")).unwrap()).unwrap();
    assert_eq!(
        toolchain["toolchain"]["channel"].as_str(),
        Some(PINNED_RUST_VERSION)
    );
    let components: Vec<_> = toolchain["toolchain"]["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|component| component.as_str().unwrap())
        .collect();
    assert_eq!(components, ["clippy", "rustfmt", "rust-src"]);
    let targets: Vec<_> = toolchain["toolchain"]["targets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|target| target.as_str().unwrap())
        .collect();
    assert_eq!(targets, PINNED_TARGETS);

    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml")).unwrap();
    assert!(ci.contains("toolchain: 1.97.1"));
    assert!(ci.contains("components: rustfmt,clippy,rust-src"));
    assert!(ci.contains(&format!("targets: {}", PINNED_TARGETS.join(","))));
    assert!(ci.contains("Verify pinned Rust and Cargo versions"));
    assert!(ci.contains("rustc --version | grep -E '^rustc 1\\.97\\.1 '"));
    assert!(ci.contains("cargo --version | grep -E '^cargo 1\\.97\\.1 '"));
    assert!(ci.contains("Prepare pinned custom-target sysroot cache"));
    assert!(ci.contains(
        "cargo fetch --locked --manifest-path \"$(rustc --print sysroot)/lib/rustlib/src/rust/library/Cargo.toml\""
    ));
    assert!(ci.contains("Verify browser-local runtime cancellation"));
    assert!(ci.contains(
        "cargo test -p rust-agent-runtime-wasm --target wasm32-unknown-unknown --all-features"
    ));
    assert!(ci.contains("Verify exact Phase 0/1A/1B/2 acceptance mappings"));
    assert!(ci.contains(
        "phase_zero_through_two_acceptance_mappings_are_exact_complete_and_runnable -- --exact"
    ));
    assert!(ci.contains("Build pinned-toolchain custom-target composition"));
    assert!(ci.contains("pinned_toolchain_custom_target_compose_lock_build_end_to_end -- --exact"));
    assert!(ci.contains("Verify Phase 2 API dependency closures"));
    for command in [
        "cargo check -p rust-agent-core --no-default-features",
        "cargo check -p rust-agent-runtime-api --no-default-features",
        "cargo check -p rust-agent-session --no-default-features",
        "cargo check -p rust-agent-agent --no-default-features",
        "cargo check -p rust-agent-session --no-default-features --features development",
        "cargo check -p rust-agent-agent --no-default-features --features development",
        "cargo check -p rust-agent-session --all-features",
        "cargo check -p rust-agent-agent --all-features",
    ] {
        assert!(
            ci.contains(command),
            "missing Phase 2 CI command: {command}"
        );
    }
    assert!(ci.contains("Verify Phase 2 claimed target matrix"));
    assert!(ci.contains(
        "cargo check --target wasm32-unknown-unknown --all-features \"${phase2_packages[@]}\""
    ));
    assert!(ci.contains(
        "for target in aarch64-linux-android aarch64-apple-ios x86_64-apple-darwin x86_64-pc-windows-msvc"
    ));
    for package in [
        "rust-agent-core",
        "rust-agent-runtime-api",
        "rust-agent-session",
        "rust-agent-model",
        "rust-agent-commands",
        "rust-agent-agent",
        "rust-agent-model-replay",
        "rust-agent-model-host",
        "rust-agent-driver-direct",
        "rust-agent-lifecycle-observer-noop",
        "rust-agent-runtime-wasm",
        "rust-agent-runtime-tokio",
    ] {
        assert!(
            ci.contains(&format!("-p {package}")),
            "missing Phase 2 target-matrix package: {package}"
        );
    }

    let golden: Value =
        toml::from_str(&fs::read_to_string(root.join("tests/golden/minimal/Cargo.toml")).unwrap())
            .unwrap();
    assert_eq!(
        golden["package"]["rust-version"].as_str(),
        Some(PINNED_RUST_VERSION)
    );
}

#[test]
fn phase_one_a_generated_graph_uses_only_minimal_api_and_fixtures() {
    let root = workspace_root();
    let dependency_names = |relative: &str| {
        let manifest: Value =
            toml::from_str(&fs::read_to_string(root.join(relative)).unwrap()).unwrap();
        manifest["dependencies"]
            .as_table()
            .unwrap()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
    };
    assert_eq!(
        dependency_names("tests/golden/minimal/Cargo.toml"),
        [
            "rust-agent-core",
            "rust-agent-fixture-api",
            "rust-agent-fixture-driver",
            "rust-agent-fixture-model",
            "rust-agent-fixture-runtime",
            "rust-agent-runtime-api",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
    assert_eq!(
        dependency_names("tests/golden/wasm-js/Cargo.toml"),
        [
            "rust-agent-core",
            "rust-agent-fixture-api",
            "rust-agent-fixture-driver",
            "rust-agent-fixture-host-export",
            "rust-agent-fixture-model",
            "rust-agent-fixture-runtime",
            "rust-agent-runtime-api",
            "wasm-bindgen",
            "wasm-bindgen-futures",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
}

#[test]
fn phase_zero_through_two_acceptance_mappings_are_exact_complete_and_runnable() {
    let root = workspace_root();
    let architecture = fs::read_to_string(root.join("ARCHITECTURE.md")).unwrap();
    let invariant_map = fs::read_to_string(root.join("docs/invariant-tests.md")).unwrap();
    let architecture_phases = markdown_section(
        &architecture,
        "### Phase 0 — 独立仓库与 Architecture Contract",
        "### Phase 3 — Tool Execution Plane",
    );
    let mapped_phases =
        markdown_section(&invariant_map, "## Phase 0", "## Accepted ADR amendments");
    for prefix in ["P0-AC-", "P1A-AC-", "P1B-AC-", "P2-AC-"] {
        let declared = acceptance_ids(architecture_phases, prefix);
        let mapped = acceptance_ids(mapped_phases, prefix);
        assert!(!declared.is_empty(), "no {prefix} criteria are declared");
        assert_eq!(
            mapped, declared,
            "{prefix} criteria and invariant mappings differ"
        );
        for criterion in declared {
            assert_eq!(
                architecture_phases.matches(&criterion).count(),
                1,
                "{criterion} must be declared exactly once"
            );
            assert_eq!(
                mapped_phases.matches(&criterion).count(),
                1,
                "{criterion} must be mapped exactly once"
            );
        }
    }

    let rust_sources = WalkDir::new(&root)
        .into_iter()
        .filter_entry(|entry| {
            !matches!(
                entry.file_name().to_string_lossy().as_ref(),
                ".git" | "target" | ".rust-agent"
            )
        })
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|value| value == "rs"))
        .map(|entry| {
            (
                entry.path().to_path_buf(),
                fs::read_to_string(entry.path()).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    let mut crate_roots = BTreeMap::new();
    for entry in WalkDir::new(&root)
        .into_iter()
        .filter_entry(|entry| {
            !matches!(
                entry.file_name().to_string_lossy().as_ref(),
                ".git" | "target" | ".rust-agent"
            )
        })
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name() == "Cargo.toml")
    {
        let manifest: Value = toml::from_str(&fs::read_to_string(entry.path()).unwrap()).unwrap();
        let Some(package) = manifest.get("package") else {
            continue;
        };
        let Some(name) = package.get("name").and_then(Value::as_str) else {
            continue;
        };
        crate_roots.insert(
            name.replace('-', "_"),
            entry.path().parent().unwrap().to_path_buf(),
        );
    }
    let mut integration_sources: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (index, (path, _)) in rust_sources.iter().enumerate() {
        if path
            .parent()
            .and_then(|parent| parent.file_name())
            .is_some_and(|name| name == "tests")
            && let Some(stem) = path.file_stem().and_then(|stem| stem.to_str())
        {
            integration_sources
                .entry(stem.to_owned())
                .or_default()
                .push(index);
        }
    }
    let listed = Command::new("cargo")
        .args([
            "test",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "--list",
            "--format",
            "terse",
        ])
        .current_dir(&root)
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "could not enumerate runnable workspace tests:\n{}{}",
        String::from_utf8_lossy(&listed.stdout),
        String::from_utf8_lossy(&listed.stderr)
    );
    let mut runnable_tests = String::from_utf8(listed.stdout)
        .unwrap()
        .lines()
        .filter_map(|line| line.strip_suffix(": test"))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let wasm_listed = Command::new("cargo")
        .args([
            "test",
            "-p",
            "rust-agent-runtime-wasm",
            "--target",
            "wasm32-unknown-unknown",
            "--all-features",
            "--",
            "--list",
            "--format",
            "terse",
        ])
        .env(
            "CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER",
            "wasm-bindgen-test-runner",
        )
        .current_dir(&root)
        .output()
        .unwrap();
    assert!(
        wasm_listed.status.success(),
        "could not enumerate runnable WASM tests:\n{}{}",
        String::from_utf8_lossy(&wasm_listed.stdout),
        String::from_utf8_lossy(&wasm_listed.stderr)
    );
    runnable_tests.extend(
        String::from_utf8(wasm_listed.stdout)
            .unwrap()
            .lines()
            .filter_map(|line| line.strip_suffix(": test"))
            .map(str::to_owned),
    );
    let mut mapped_rows = 0_usize;
    for line in mapped_phases.lines().filter(|line| line.starts_with('|')) {
        let cells = line
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect::<Vec<_>>();
        let Some(evidence) = cells.last() else {
            continue;
        };
        if matches!(*evidence, "Automated evidence" | "---") {
            continue;
        }
        let references = evidence
            .split('`')
            .enumerate()
            .filter_map(|(index, value)| (index % 2 == 1).then_some(value))
            .collect::<Vec<_>>();
        assert!(
            !references.is_empty(),
            "mapping row has no evidence: {line}"
        );
        mapped_rows += 1;
        for reference in references {
            assert!(
                !reference.contains('*'),
                "wildcard evidence is forbidden: {reference}"
            );
            let (owner, test_name) = reference
                .rsplit_once("::")
                .unwrap_or_else(|| panic!("evidence is not an exact named gate: {reference}"));
            if owner.starts_with(".github/") {
                let workflow = owner.split("::").next().unwrap();
                let contents = fs::read_to_string(root.join(workflow)).unwrap();
                assert!(
                    contents.contains(test_name),
                    "workflow gate does not exist: {reference}"
                );
                continue;
            }
            let owner_segments = owner.split("::").collect::<Vec<_>>();
            let first_owner = owner_segments[0];
            let mut candidate_sources = Vec::new();
            let runnable_name = if let Some(crate_root) = crate_roots.get(first_owner) {
                candidate_sources.extend(
                    rust_sources
                        .iter()
                        .enumerate()
                        .filter(|(_, (path, _))| path.starts_with(crate_root.join("src")))
                        .map(|(index, _)| index),
                );
                let module = owner_segments[1..].join("::");
                if module.is_empty() {
                    test_name.to_owned()
                } else {
                    format!("{module}::{test_name}")
                }
            } else if owner_segments.len() == 1
                && let Some(sources) = integration_sources.get(first_owner)
            {
                candidate_sources.extend(sources.iter().copied());
                test_name.to_owned()
            } else {
                candidate_sources.extend(
                    rust_sources
                        .iter()
                        .enumerate()
                        .filter(|(_, (path, _))| {
                            let module_file = path
                                .file_stem()
                                .and_then(|stem| stem.to_str())
                                .is_some_and(|stem| stem == first_owner)
                                && path
                                    .parent()
                                    .and_then(|parent| parent.file_name())
                                    .is_some_and(|parent| parent == "src");
                            let module_directory = path.ancestors().any(|ancestor| {
                                ancestor.file_name().is_some_and(|name| name == first_owner)
                                    && ancestor
                                        .parent()
                                        .and_then(|parent| parent.file_name())
                                        .is_some_and(|name| name == "src")
                            });
                            module_file || module_directory
                        })
                        .map(|(index, _)| index),
                );
                if matches!(first_owner, "lib" | "main") {
                    let module = owner_segments[1..].join("::");
                    if module.is_empty() {
                        test_name.to_owned()
                    } else {
                        format!("{module}::{test_name}")
                    }
                } else {
                    format!("{owner}::{test_name}")
                }
            };
            let pattern = format!("fn {test_name}(");
            assert!(
                candidate_sources
                    .iter()
                    .any(
                        |source_index| rust_sources[*source_index].1.match_indices(&pattern).any(
                            |(index, _)| {
                                let prefix = &rust_sources[*source_index].1
                                    [index.saturating_sub(256)..index];
                                prefix.contains("#[test]")
                                    || prefix.contains("#[tokio::test]")
                                    || prefix.contains("#[wasm_bindgen_test]")
                            }
                        )
                    ),
                "mapped Rust test does not exist under its declared owner: {reference}"
            );
            assert!(
                runnable_tests.contains(&runnable_name),
                "mapped Rust test is not runnable at `{runnable_name}`: {reference}"
            );
        }
    }
    assert!(
        !runnable_tests
            .contains("observer::tests::bounded_dispatcher_contains_timeout_panic_and_shutdown")
    );
    assert!(runnable_tests.contains(
        "observer::native::tests::bounded_dispatcher_contains_timeout_panic_and_shutdown"
    ));
    assert!(
        mapped_rows > 50,
        "Phase 0 through Phase 2 mapping tables are unexpectedly empty"
    );
}

#[test]
fn phase_one_b_linux_reference_runner_executes_every_real_backend_gate() {
    let ci = fs::read_to_string(workspace_root().join(".github/workflows/ci.yml")).unwrap();
    let (_, phase_job) = ci
        .split_once("  phase-1b-linux-production:\n")
        .expect("missing Phase 1B CI job");
    for required in [
        "name: Phase 1B Linux production gate",
        "runs-on: ubuntu-24.04",
        "timeout-minutes: 120",
        "sudo apt-get install --yes bubblewrap iproute2 openssl python3",
        "cargo install wasm-bindgen-cli --version 0.2.127 --locked",
        "Prefetch locked Phase 1B fixture sources",
        "cargo fetch --locked",
        "cargo build -p rust-agent-cli",
        "cargo test -p rust-agent-build-executor --test linux_sandbox_launcher writable_root_allows_internal_atomic_rename_but_not_escape -- --ignored --exact --test-threads=1",
        "cargo test -p rust-agent-build-executor --test linux_namespace_backend -- --ignored --test-threads=1",
        "cargo test -p rust-agent-build-executor --test production_cargo_fetch -- --ignored --test-threads=1",
        "RUST_AGENT_CLI_BIN: ${{ github.workspace }}/target/debug/rust-agent",
    ] {
        assert!(
            phase_job.contains(required),
            "missing Phase 1B CI gate: {required}"
        );
    }
    assert!(
        phase_job.find("cargo fetch --locked") < phase_job.find("cargo build -p rust-agent-cli")
    );
    assert!(
        phase_job.find("cargo build -p rust-agent-cli")
            < phase_job.find("--test production_cargo_fetch")
    );
    assert!(!phase_job.contains("continue-on-error:"));
}

fn markdown_section<'a>(input: &'a str, start: &str, end: &str) -> &'a str {
    let start = input
        .find(start)
        .unwrap_or_else(|| panic!("missing {start}"));
    let tail = &input[start..];
    let end = tail.find(end).unwrap_or_else(|| panic!("missing {end}"));
    &tail[..end]
}

fn acceptance_ids(input: &str, prefix: &str) -> BTreeSet<String> {
    input
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '-'))
        .filter(|token| {
            token.strip_prefix(prefix).is_some_and(|suffix| {
                suffix.len() == 2 && suffix.bytes().all(|byte| byte.is_ascii_digit())
            })
        })
        .map(str::to_owned)
        .collect()
}

#[test]
fn wasm_bindgen_protocol_is_pinned_and_synchronized() {
    let root = workspace_root();
    let output = Command::new("wasm-bindgen")
        .arg("--version")
        .output()
        .unwrap();
    assert!(output.status.success(), "wasm-bindgen --version failed");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        format!("wasm-bindgen {PINNED_WASM_BINDGEN_VERSION}")
    );

    let workspace: Value =
        toml::from_str(&fs::read_to_string(root.join("Cargo.toml")).unwrap()).unwrap();
    assert_eq!(
        workspace["workspace"]["dependencies"]["wasm-bindgen"]["version"].as_str(),
        Some("=0.2.127")
    );
    assert_eq!(
        workspace["workspace"]["dependencies"]["wasm-bindgen-futures"]["version"].as_str(),
        Some("=0.4.77")
    );

    let runtime_wasm: Value = toml::from_str(
        &fs::read_to_string(root.join("crates/runtime/rust-agent-runtime-wasm/Cargo.toml"))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        runtime_wasm["target"]["cfg(all(target_arch = \"wasm32\", target_os = \"unknown\"))"]
            ["dev-dependencies"]["wasm-bindgen-test"]["version"]
            .as_str(),
        Some("=0.3.77")
    );

    let golden: Value =
        toml::from_str(&fs::read_to_string(root.join("tests/golden/wasm-js/Cargo.toml")).unwrap())
            .unwrap();
    assert_eq!(
        golden["dependencies"]["wasm-bindgen"]["version"].as_str(),
        Some("=0.2.127")
    );
    assert_eq!(
        golden["dependencies"]["wasm-bindgen-futures"]["version"].as_str(),
        Some("=0.4.77")
    );

    let lock: Value =
        toml::from_str(&fs::read_to_string(root.join("Cargo.lock")).unwrap()).unwrap();
    let packages = lock["package"].as_array().unwrap();
    for (name, version) in [
        ("wasm-bindgen", PINNED_WASM_BINDGEN_VERSION),
        ("wasm-bindgen-futures", PINNED_WASM_BINDGEN_FUTURES_VERSION),
        ("wasm-bindgen-test", PINNED_WASM_BINDGEN_TEST_VERSION),
    ] {
        let versions: Vec<_> = packages
            .iter()
            .filter(|package| package["name"].as_str() == Some(name))
            .map(|package| package["version"].as_str().unwrap())
            .collect();
        assert_eq!(versions, [version]);
    }

    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml")).unwrap();
    assert!(ci.contains("cargo install wasm-bindgen-cli --version 0.2.127 --locked"));
    assert!(ci.contains("wasm-bindgen --version | grep -E '^wasm-bindgen 0\\.2\\.127$'"));
}
