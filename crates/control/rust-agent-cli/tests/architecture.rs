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
        [
            "rust-agent-commands",
            "rust-agent-core",
            "rust-agent-policy",
            "rust-agent-runtime-api",
            "serde_json",
            "sha2",
        ]
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
    let commands =
        fs::read_to_string(root.join("crates/api/rust-agent-commands/src/lib.rs")).unwrap();
    let registry =
        fs::read_to_string(root.join("crates/api/rust-agent-tools/src/registry.rs")).unwrap();
    let execution =
        fs::read_to_string(root.join("crates/api/rust-agent-tools/src/execution.rs")).unwrap();
    let middleware =
        fs::read_to_string(root.join("crates/api/rust-agent-tools/src/middleware.rs")).unwrap();
    let runtime_api =
        fs::read_to_string(root.join("crates/api/rust-agent-runtime-api/src/lib.rs")).unwrap();
    let agent = fs::read_to_string(root.join("crates/api/rust-agent-agent/src/lib.rs")).unwrap();
    let model = fs::read_to_string(root.join("crates/api/rust-agent-model/src/lib.rs")).unwrap();
    let model_manifest: Value = toml::from_str(
        &fs::read_to_string(root.join("crates/api/rust-agent-model/Cargo.toml")).unwrap(),
    )
    .unwrap();
    let guarded_component =
        fs::read_to_string(root.join("crates/api/rust-agent-tools/src/guarded_component.rs"))
            .unwrap();
    assert!(source.contains("pub struct ExecutionPermit"));
    assert!(source.contains("pub const MAX_TOOL_CALL_COST_UNITS: usize = 1024;"));
    assert!(source.contains("pub fn prepare_nested<'a>("));
    assert!(commands.contains("pub struct CommandPermit"));
    assert!(commands.contains("pub const MAX_COMMAND_TOOL_COST_UNITS: usize = 4 * 1024;"));
    assert!(commands.contains("pub struct CommandToolGrant<'a>"));
    assert!(commands.contains("PhantomData<&'a mut &'a ()>"));
    assert!(execution.contains("fn prepare_command<'a>("));
    assert!(execution.contains("pub const MAX_PARALLEL_TOOL_CALLS: usize = 16;"));
    assert!(execution.contains("pub const MAX_NESTED_TOOL_COST_UNITS: usize = 4 * 1024;"));
    assert!(execution.contains("pub fn execute_prepared_batch("));
    assert!(execution.contains("fn next_dispatchable_call("));
    assert!(runtime_api.contains("struct ToolCallJournalAuthority;"));
    assert!(!runtime_api.contains("pub struct ToolCallJournalAuthority;"));
    assert!(runtime_api.contains("pub struct GeneratedToolConsumerBinding"));
    assert!(runtime_api.contains("pub fn bind_tool_consumer("));
    assert!(agent.contains("pub fn prepare_tool_call("));
    assert!(agent.contains("fn build_driver_with_tools("));
    assert!(model.contains("pub struct ModelToolCall"));
    assert!(model.contains("ToolCall(ModelToolCall)"));
    assert!(
        !model_manifest["dependencies"]
            .as_table()
            .unwrap()
            .contains_key("rust-agent-tools")
    );
    assert!(guarded_component.contains("binding: GeneratedToolConsumerBinding"));
    assert!(guarded_component.contains(".into_verifier_for_edge(consumer,"));
    assert!(registry.contains("handler: Arc<dyn crate::Tool>"));
    assert!(!registry.contains("pub handler:"));
    assert!(execution.contains("PhantomData<&'a mut &'a ()>"));
    assert_eq!(execution.matches(".handler().execute(").count(), 1);
    for checked in [&source, &commands, &registry, &execution, &middleware] {
        assert!(!checked.contains("unsafe"));
    }

    let commands_manifest: Value = toml::from_str(
        &fs::read_to_string(root.join("crates/api/rust-agent-commands/Cargo.toml")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        commands_manifest["dependencies"]
            .as_table()
            .unwrap()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        ["rust-agent-core", "rust-agent-runtime-api"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );
    let output = Command::new("cargo")
        .args([
            "tree",
            "-p",
            "rust-agent-commands",
            "--edges",
            "normal",
            "--no-default-features",
        ])
        .current_dir(&root)
        .output()
        .unwrap();
    assert!(output.status.success());
    let tree = String::from_utf8(output.stdout).unwrap();
    for forbidden in ["rust-agent-agent", "rust-agent-session", "rust-agent-tools"] {
        assert!(
            !tree.contains(forbidden),
            "commands API dependency tree contains forbidden owner {forbidden}:\n{tree}"
        );
    }
}

#[test]
fn guarded_tool_executor_wrapper_is_metadata_only_and_dependency_one_way() {
    let root = workspace_root();
    let manifest: Value = toml::from_str(
        &fs::read_to_string(root.join("crates/components/tool-executor-guarded/Cargo.toml"))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        manifest["dependencies"]
            .as_table()
            .unwrap()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        ["rust-agent-tools"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );
    let wrapper =
        fs::read_to_string(root.join("crates/components/tool-executor-guarded/src/lib.rs"))
            .unwrap();
    assert!(
        wrapper.contains(
            "pub use rust_agent_tools::guarded_component::{Config, Dependencies, build};"
        )
    );
    assert!(!wrapper.contains("fn build("));
    assert!(!wrapper.contains("ExecutionPermit"));
    assert!(!wrapper.contains("ToolRegistry"));

    let tools_manifest: Value = toml::from_str(
        &fs::read_to_string(root.join("crates/api/rust-agent-tools/Cargo.toml")).unwrap(),
    )
    .unwrap();
    assert!(
        !tools_manifest["dependencies"]
            .as_table()
            .unwrap()
            .contains_key("rust-agent-tool-executor-guarded")
    );
}

#[test]
fn driver_tools_is_api_only_ordered_and_matrixed() {
    let root = workspace_root();
    let manifest: Value = toml::from_str(
        &fs::read_to_string(root.join("crates/components/driver-tools/Cargo.toml")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        manifest["dependencies"]
            .as_table()
            .unwrap()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        [
            "rust-agent-agent",
            "rust-agent-core",
            "rust-agent-model",
            "rust-agent-runtime-api",
            "rust-agent-tools",
            "serde_json",
            "sha2",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
    assert!(
        !manifest["dependencies"]
            .as_table()
            .unwrap()
            .contains_key("rust-agent-tool-executor-guarded")
    );
    let requirements = manifest["package"]["metadata"]["rust-agent"]["requires"]
        .as_array()
        .unwrap();
    assert_eq!(requirements.len(), 2);
    assert_eq!(requirements[0]["capability"].as_str(), Some("cap:model"));
    assert_eq!(
        requirements[1]["capability"].as_str(),
        Some("cap:tool-executor")
    );
    assert!(
        requirements
            .iter()
            .all(|requirement| requirement["mode"].as_str() == Some("required"))
    );

    let source =
        fs::read_to_string(root.join("crates/components/driver-tools/src/lib.rs")).unwrap();
    for required in [
        ".prepare_model_step(",
        ".plan_call(request)",
        "context.prepare_tool_call(",
        "plan.seal(proof)",
        ".execute_prepared_batch(",
    ] {
        assert!(
            source.contains(required),
            "missing Tool loop step: {required}"
        );
    }
    assert!(!source.contains("unsafe"));

    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml")).unwrap();
    for command in [
        "cargo check -p rust-agent-driver-tools --no-default-features",
        "cargo check -p rust-agent-driver-tools --all-features",
        "-p rust-agent-driver-tools",
    ] {
        assert!(
            ci.contains(command),
            "missing driver-tools CI gate: {command}"
        );
    }
}

#[test]
fn phase_three_policy_api_and_default_provider_are_dependency_isolated() {
    let root = workspace_root();
    let dependencies = |relative: &str| {
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
        dependencies("crates/api/rust-agent-policy/Cargo.toml"),
        ["rust-agent-core", "rust-agent-runtime-api", "sha2"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );
    assert_eq!(
        dependencies("crates/components/permission-default/Cargo.toml"),
        [
            "rust-agent-core",
            "rust-agent-policy",
            "rust-agent-runtime-api",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );

    let output = Command::new("cargo")
        .args([
            "tree",
            "-p",
            "rust-agent-permission-default",
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
        "rust-agent-model",
        "rust-agent-session",
        "rust-agent-tools",
        "tokio",
    ] {
        assert!(
            !tree.contains(forbidden),
            "permission-default dependency tree contains forbidden owner {forbidden}:\n{tree}"
        );
    }

    let source = fs::read_to_string(root.join("crates/api/rust-agent-policy/src/lib.rs")).unwrap();
    assert!(source.contains("pub trait PermissionPolicy"));
    assert!(source.contains("pub trait Approval"));
    assert!(!source.contains("unsafe"));
}

#[test]
fn phase_three_supporting_capability_contracts_are_bounded_and_dependency_isolated() {
    let root = workspace_root();
    let dependencies = |package: &str| {
        let manifest: Value = toml::from_str(
            &fs::read_to_string(root.join("crates/api").join(package).join("Cargo.toml")).unwrap(),
        )
        .unwrap();
        manifest["dependencies"]
            .as_table()
            .unwrap()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
    };
    assert_eq!(
        dependencies("rust-agent-prompt"),
        ["rust-agent-core", "rust-agent-runtime-api"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );
    for package in ["rust-agent-attachments", "rust-agent-spill"] {
        assert_eq!(
            dependencies(package),
            ["rust-agent-core", "rust-agent-runtime-api", "sha2"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        );
    }
    assert_eq!(
        dependencies("rust-agent-telemetry"),
        ["rust-agent-core"].into_iter().map(str::to_owned).collect()
    );

    for package in [
        "rust-agent-prompt",
        "rust-agent-attachments",
        "rust-agent-spill",
        "rust-agent-telemetry",
    ] {
        let output = Command::new("cargo")
            .args([
                "tree",
                "-p",
                package,
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
            "rust-agent-policy",
            "rust-agent-session",
            "rust-agent-tools",
            "tokio",
        ] {
            assert!(
                !tree.contains(forbidden),
                "{package} dependency tree contains forbidden owner {forbidden}:\n{tree}"
            );
        }
        let source =
            fs::read_to_string(root.join("crates/api").join(package).join("src/lib.rs")).unwrap();
        assert!(!source.contains("unsafe"));
    }

    let prompt = fs::read_to_string(root.join("crates/api/rust-agent-prompt/Cargo.toml")).unwrap();
    for capability in [
        "cap:prompt-contributor",
        "cap:prompt-assembly",
        "cap:conversation-compaction",
        "cap:tool-result-pruner",
        "cap:token-meter",
    ] {
        assert!(prompt.contains(capability));
    }
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
fn phase_four_filesystem_api_is_bounded_and_dependency_isolated() {
    let root = workspace_root();
    let manifest: Value = toml::from_str(
        &fs::read_to_string(root.join("crates/api/rust-agent-fs/Cargo.toml")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        manifest["dependencies"]
            .as_table()
            .unwrap()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        ["rust-agent-core", "rust-agent-runtime-api"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );
    let capabilities = manifest["package"]["metadata"]["rust-agent"]["capability"]
        .as_array()
        .unwrap();
    assert_eq!(capabilities.len(), 2);
    assert_eq!(capabilities[0]["id"].as_str(), Some("cap:fs-read"));
    assert_eq!(capabilities[1]["id"].as_str(), Some("cap:fs-write"));
    for capability in capabilities {
        assert_eq!(capability["binding"].as_str(), Some("singleton"));
        assert_eq!(capability["scope"].as_str(), Some("agent"));
    }

    let source = fs::read_to_string(root.join("crates/api/rust-agent-fs/src/lib.rs")).unwrap();
    for required in [
        "pub struct AgentPath",
        "pub struct FsCallContext",
        "pub struct ByteRange",
        "pub struct DirPageRequest",
        "pub struct DirPageCursor",
        "pub trait FileRead",
        "pub trait FileWrite",
        "pub struct FileReadBinding",
        "pub struct FileWriteBinding",
        "MAX_AGENT_PATH_DEPTH",
        "MAX_FS_CALL_BYTES",
        "MAX_DIR_PAGE_ENTRIES",
    ] {
        assert!(
            source.contains(required),
            "missing filesystem contract `{required}`"
        );
    }
    for forbidden in ["std::fs", "std::process", "tokio", "unsafe"] {
        assert!(
            !source.contains(forbidden),
            "filesystem API contains effectful implementation marker `{forbidden}`"
        );
    }

    let output = Command::new("cargo")
        .args([
            "tree",
            "-p",
            "rust-agent-fs",
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
        "rust-agent-agent",
        "rust-agent-tools",
        "rust-agent-fs-local",
        "rust-agent-subprocess",
        "tokio",
    ] {
        assert!(
            !tree.contains(forbidden),
            "filesystem API dependency tree contains forbidden owner {forbidden}:\n{tree}"
        );
    }

    let invariant_map = fs::read_to_string(root.join("docs/invariant-tests.md")).unwrap();
    let mapped = markdown_section(&invariant_map, "## Phase 4", "## Accepted ADR amendments");
    for required in [
        "rust_agent_fs::tests::logical_paths_are_canonical_bounded_and_deterministic",
        "rust_agent_fs::tests::contexts_ranges_cursors_and_pages_enforce_every_boundary",
        "rust_agent_fs::tests::read_and_write_rejections_precede_provider_callbacks",
        "rust_agent_fs::tests::provider_outputs_and_cursor_identity_are_revalidated",
        "privacy::filesystem_paths_contexts_pages_and_raw_providers_remain_private",
        "architecture::phase_four_filesystem_api_is_bounded_and_dependency_isolated",
    ] {
        assert!(
            mapped.contains(required),
            "unmapped Phase 4.1 evidence: {required}"
        );
    }

    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml")).unwrap();
    for required in [
        "Verify Phase 4 filesystem API dependency closure",
        "cargo check -p rust-agent-fs --no-default-features",
        "cargo check -p rust-agent-fs --all-features",
        "Verify Phase 4 filesystem API target matrix",
        "cargo check --target \"$target\" --all-features -p rust-agent-fs",
    ] {
        assert!(
            ci.contains(required),
            "missing Phase 4 API CI gate: {required}"
        );
    }
}

#[test]
fn phase_four_resource_namespace_bootstrap_is_projected_anchored_and_linux_exact() {
    let root = workspace_root();
    let api_manifest: Value = toml::from_str(
        &fs::read_to_string(root.join("crates/api/rust-agent-resource-namespace/Cargo.toml"))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        api_manifest["dependencies"]
            .as_table()
            .unwrap()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        ["rust-agent-core", "rust-agent-runtime-api", "sha2"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );
    let capability = &api_manifest["package"]["metadata"]["rust-agent"]["capability"]
        .as_array()
        .unwrap()[0];
    assert_eq!(
        capability["id"].as_str(),
        Some("cap:resource-namespace-bootstrap")
    );
    assert_eq!(capability["binding"].as_str(), Some("registry"));
    assert_eq!(capability["scope"].as_str(), Some("app"));

    let component_manifest: Value = toml::from_str(
        &fs::read_to_string(
            root.join("crates/components/resource-namespace-bootstrap-local/Cargo.toml"),
        )
        .unwrap(),
    )
    .unwrap();
    let metadata = &component_manifest["package"]["metadata"]["rust-agent"];
    assert_eq!(
        metadata["id"].as_str(),
        Some("resource-namespace-bootstrap-local")
    );
    assert_eq!(metadata["scope"].as_str(), Some("app"));
    assert_eq!(metadata["config-source"].as_str(), Some("none"));
    assert_eq!(metadata["targets"].as_array().unwrap().len(), 1);
    assert_eq!(
        metadata["targets"][0].as_str(),
        Some("cfg(target_os = \"linux\")")
    );
    assert_eq!(metadata["support"].as_str(), Some("production"));
    assert!(metadata["lifecycle-effects"].as_array().unwrap().is_empty());
    assert!(metadata["requires"].as_array().unwrap().is_empty());
    assert!(
        metadata["runtime-primitives"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        metadata["security"].as_array().unwrap(),
        &[Value::String("read-local".into())]
    );
    let provide = &metadata["provides"].as_array().unwrap()[0];
    assert_eq!(
        provide["capability"].as_str(),
        Some("cap:resource-namespace-bootstrap")
    );
    assert_eq!(
        provide["key"].as_str(),
        Some("resource-namespace-bootstrap-local")
    );
    assert_eq!(
        provide["effects"].as_array().unwrap(),
        &[Value::String("read-local".into())]
    );
    assert!(
        component_manifest["dependencies"]
            .as_table()
            .unwrap()
            .keys()
            .all(|dependency| matches!(
                dependency.as_str(),
                "rust-agent-core" | "rust-agent-resource-namespace" | "rust-agent-runtime-api"
            ))
    );
    assert!(
        component_manifest["target"]["cfg(target_os = \"linux\")"]["dependencies"]["rustix"]
            .is_table()
    );

    let api_source =
        fs::read_to_string(root.join("crates/api/rust-agent-resource-namespace/src/lib.rs"))
            .unwrap();
    let production_api = api_source.split("#[cfg(test)]").next().unwrap();
    for required in [
        "pub struct BootstrapAuthorityProjection",
        "pub struct ResourceNamespacePreparationContext",
        "pub struct PreparedComponentConfig",
        "pub struct ResourceNamespaceDescriptor",
        "RESOURCE_NAMESPACE_DIGEST_DOMAIN",
        "canonical CBOR array(2)",
    ] {
        assert!(
            production_api.contains(required),
            "missing resource namespace protocol marker `{required}`"
        );
    }
    for forbidden in [
        "std::fs",
        "std::process",
        "openat",
        "canonicalize",
        "unsafe",
    ] {
        assert!(
            !production_api.contains(forbidden),
            "resource namespace API contains implementation effect `{forbidden}`"
        );
    }

    let component_source = fs::read_to_string(
        root.join("crates/components/resource-namespace-bootstrap-local/src/lib.rs"),
    )
    .unwrap();
    for required in [
        "openat2(",
        "ResolveFlags::BENEATH",
        "ResolveFlags::NO_SYMLINKS",
        "ResolveFlags::NO_MAGICLINKS",
        "LocalDirectoryAnchor::from_owned_descriptor",
        "fstat(&descriptor)",
    ] {
        assert!(
            component_source.contains(required),
            "local bootstrap is missing `{required}`"
        );
    }
    for forbidden in ["canonicalize(", "std::process", "unsafe"] {
        assert!(
            !component_source.contains(forbidden),
            "local bootstrap contains forbidden bypass `{forbidden}`"
        );
    }

    let output = Command::new("cargo")
        .args([
            "tree",
            "-p",
            "rust-agent-resource-namespace",
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
        "rust-agent-resource-namespace-bootstrap-local",
        "rust-agent-fs",
        "rustix",
        "tokio",
    ] {
        assert!(
            !tree.contains(forbidden),
            "namespace API graph contains concrete/effectful dependency `{forbidden}`:\n{tree}"
        );
    }

    let invariant_map = fs::read_to_string(root.join("docs/invariant-tests.md")).unwrap();
    let mapped = markdown_section(&invariant_map, "## Phase 4", "## Accepted ADR amendments");
    for required in [
        "rust_agent_resource_namespace::tests::projection_precedes_provider_calls_and_rejects_binding_drift",
        "rust_agent_resource_namespace::tests::context_computes_commitment_and_revalidates_provider_output",
        "rust_agent_resource_namespace_bootstrap_local::tests::descriptor_anchor_survives_root_replacement_without_reopen",
        "rust_agent_resource_namespace_bootstrap_local::tests::symlink_escape_and_cancelled_calls_fail_closed",
        "rust_agent_resource_namespace_bootstrap_local::tests::independent_instances_open_independent_descriptor_anchors",
        "architecture::phase_four_resource_namespace_bootstrap_is_projected_anchored_and_linux_exact",
    ] {
        assert!(
            mapped.contains(required),
            "unmapped Phase 4.2 evidence: {required}"
        );
    }

    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml")).unwrap();
    for required in [
        "Verify Phase 4 resource namespace dependency closures",
        "Verify Phase 4 resource namespace API target matrix",
        "Verify Phase 4 real Linux local namespace bootstrap",
    ] {
        assert!(
            ci.contains(required),
            "missing Phase 4.2 CI gate `{required}`"
        );
    }
}

#[test]
fn phase_four_local_filesystems_and_tool_adapter_are_capability_exact() {
    let root = workspace_root();
    let read_manifest: Value = toml::from_str(
        &fs::read_to_string(root.join("crates/components/fs-read-local/Cargo.toml")).unwrap(),
    )
    .unwrap();
    let write_manifest: Value = toml::from_str(
        &fs::read_to_string(root.join("crates/components/fs-local/Cargo.toml")).unwrap(),
    )
    .unwrap();
    let tool_manifest: Value = toml::from_str(
        &fs::read_to_string(root.join("crates/components/tool-fs/Cargo.toml")).unwrap(),
    )
    .unwrap();
    let read_metadata = &read_manifest["package"]["metadata"]["rust-agent"];
    let write_metadata = &write_manifest["package"]["metadata"]["rust-agent"];
    let tool_metadata = &tool_manifest["package"]["metadata"]["rust-agent"];

    for (metadata, id) in [
        (read_metadata, "fs-read-local"),
        (write_metadata, "fs-local"),
    ] {
        assert_eq!(metadata["id"].as_str(), Some(id));
        assert_eq!(metadata["scope"].as_str(), Some("agent"));
        assert_eq!(metadata["config-source"].as_str(), Some("file"));
        assert_eq!(metadata["config-key"].as_str(), Some(id));
        assert_eq!(
            metadata["targets"][0].as_str(),
            Some("cfg(target_os = \"linux\")")
        );
        assert_eq!(metadata["support"].as_str(), Some("production"));
        assert!(metadata["lifecycle-effects"].as_array().unwrap().is_empty());
        assert_eq!(
            metadata["runtime-primitives"].as_array().unwrap(),
            &[Value::String("clock".into())]
        );
        assert!(metadata["resource-namespace-preparer"].as_str().is_some());
        assert!(metadata["prepared-config-type"].as_str().is_some());
        let namespace = &metadata["provides"][0]["resource-namespace"];
        assert_eq!(namespace["mode"].as_str(), Some("required"));
        assert_eq!(
            namespace["bootstrap"].as_str(),
            Some("resource-namespace-bootstrap-local")
        );
    }
    assert_eq!(read_metadata["provides"].as_array().unwrap().len(), 1);
    assert_eq!(
        read_metadata["provides"][0]["capability"].as_str(),
        Some("cap:fs-read")
    );
    assert_eq!(write_metadata["provides"].as_array().unwrap().len(), 2);
    assert_eq!(
        write_metadata["provides"][1]["capability"].as_str(),
        Some("cap:fs-write")
    );
    assert_eq!(
        write_metadata["provides"][1]["effects"].as_array().unwrap(),
        &[
            Value::String("read-local".into()),
            Value::String("write-local".into()),
        ]
    );

    assert_eq!(tool_metadata["id"].as_str(), Some("tool-fs"));
    assert_eq!(tool_metadata["scope"].as_str(), Some("agent"));
    assert!(tool_metadata["security"].as_array().unwrap().is_empty());
    assert!(
        tool_metadata["provides"][0]["effects"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let requirements = tool_metadata["requires"].as_array().unwrap();
    assert_eq!(requirements.len(), 2);
    assert_eq!(requirements[0]["capability"].as_str(), Some("cap:fs-read"));
    assert_eq!(requirements[0]["mode"].as_str(), Some("required"));
    assert_eq!(requirements[1]["capability"].as_str(), Some("cap:fs-write"));
    assert_eq!(requirements[1]["mode"].as_str(), Some("uses-if-present"));

    let read_dependencies = read_manifest["dependencies"]
        .as_table()
        .unwrap()
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let write_dependencies = write_manifest["dependencies"]
        .as_table()
        .unwrap()
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert!(!read_dependencies.contains("rust-agent-fs-local"));
    assert!(!write_dependencies.contains("rust-agent-fs-read-local"));
    let tool_dependencies = tool_manifest["dependencies"]
        .as_table()
        .unwrap()
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    for forbidden in [
        "rust-agent-fs-local",
        "rust-agent-fs-read-local",
        "rust-agent-resource-namespace",
        "rustix",
        "tokio",
    ] {
        assert!(
            !tool_dependencies.contains(forbidden),
            "tool-fs directly depends on concrete/effectful package `{forbidden}`"
        );
    }

    for relative in [
        "crates/components/fs-read-local/src/lib.rs",
        "crates/components/fs-local/src/lib.rs",
    ] {
        let source = fs::read_to_string(root.join(relative)).unwrap();
        let production = source.split("#[cfg(all(test").next().unwrap();
        for required in [
            "prepare_resource_namespaces(",
            "LocalDirectoryAnchor",
            "openat2(",
            "ResolveFlags::BENEATH",
            "ResolveFlags::NO_SYMLINKS",
            "ResolveFlags::NO_MAGICLINKS",
            "OFlags::NOFOLLOW",
            "st_nlink",
        ] {
            assert!(
                production.contains(required),
                "{relative} is missing `{required}`"
            );
        }
        for forbidden in ["canonicalize(", "std::fs", "unsafe"] {
            assert!(
                !production.contains(forbidden),
                "{relative} contains pathname/unsafe bypass `{forbidden}`"
            );
        }
    }
    let write_source =
        fs::read_to_string(root.join("crates/components/fs-local/src/lib.rs")).unwrap();
    for required in ["mkdirat(", "ftruncate(", "fsync(", "WriteMode::CreateNew"] {
        assert!(
            write_source.contains(required),
            "fs-local is missing `{required}`"
        );
    }
    let tool_source =
        fs::read_to_string(root.join("crates/components/tool-fs/src/lib.rs")).unwrap();
    let tool_production = tool_source.split("#[cfg(test)]").next().unwrap();
    for required in [
        "self.read.effects()",
        "self.write.effects()",
        "if let Some(write)",
        "SEARCH_MAX_VISITED_ENTRIES",
        "SEARCH_MAX_TOTAL_READ_BYTES",
        "GitignoreBuilder::new",
        "FileReadBinding",
        "FileWriteBinding",
    ] {
        assert!(
            tool_production.contains(required),
            "tool-fs is missing `{required}`"
        );
    }
    for forbidden in ["std::fs", "std::process", "rustix", "fs_local"] {
        assert!(
            !tool_production.contains(forbidden),
            "tool-fs contains provider bypass `{forbidden}`"
        );
    }

    let tree = Command::new("cargo")
        .args([
            "tree",
            "-p",
            "rust-agent-tool-fs",
            "--edges",
            "normal",
            "--no-default-features",
        ])
        .current_dir(&root)
        .output()
        .unwrap();
    assert!(tree.status.success());
    let tree = String::from_utf8(tree.stdout).unwrap();
    for forbidden in [
        "rust-agent-fs-local",
        "rust-agent-fs-read-local",
        "rust-agent-resource-namespace-bootstrap-local",
        "rustix",
    ] {
        assert!(
            !tree.contains(forbidden),
            "tool-fs resolved concrete filesystem dependency `{forbidden}`:\n{tree}"
        );
    }

    let invariant_map = fs::read_to_string(root.join("docs/invariant-tests.md")).unwrap();
    let mapped = markdown_section(&invariant_map, "## Phase 4", "## Accepted ADR amendments");
    for required in [
        "rust_agent_fs_read_local::tests::symlink_hardlink_and_namespace_mutation_fail_closed",
        "rust_agent_fs_local::tests::symlink_and_hardlink_write_redirects_are_rejected_before_mutation",
        "rust_agent_tool_fs::tests::glob_and_grep_are_provider_only_sorted_bounded_and_gitignore_aware",
        "resolver::tests::optional_tool_provider_is_order_independent_and_inherits_exact_fs_effects",
        "architecture::phase_four_local_filesystems_and_tool_adapter_are_capability_exact",
    ] {
        assert!(
            mapped.contains(required),
            "unmapped Phase 4.3 evidence: {required}"
        );
    }
    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml")).unwrap();
    for required in [
        "Verify Phase 4 filesystem provider dependency closures",
        "Verify Phase 4 tool-fs target matrix",
        "Verify Phase 4 real Linux filesystem providers",
        "Verify Phase 4 filesystem resolver projection",
    ] {
        assert!(
            ci.contains(required),
            "missing Phase 4.3 CI gate `{required}`"
        );
    }
}

#[test]
fn phase_four_process_confinement_api_is_closed_bounded_and_dependency_isolated() {
    let root = workspace_root();
    let manifest: Value = toml::from_str(
        &fs::read_to_string(root.join("crates/api/rust-agent-process/Cargo.toml")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        manifest["dependencies"]
            .as_table()
            .unwrap()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        [
            "rust-agent-core",
            "rust-agent-fs",
            "rust-agent-policy",
            "rust-agent-runtime-api",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
    let capabilities = manifest["package"]["metadata"]["rust-agent"]["capability"]
        .as_array()
        .unwrap();
    assert_eq!(capabilities.len(), 6);
    assert_eq!(
        capabilities
            .iter()
            .map(|capability| capability["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "cap:subprocess",
            "cap:sandbox",
            "cap:confinement-issuer",
            "cap:confinement-verifier",
            "cap:shell",
            "cap:terminal",
        ]
    );
    assert!(capabilities.iter().all(|capability| {
        capability["binding"].as_str() == Some("singleton")
            && capability["scope"].as_str() == Some("agent")
    }));

    let process_root = root.join("crates/api/rust-agent-process/src");
    let lib = fs::read_to_string(process_root.join("lib.rs")).unwrap();
    let confinement = fs::read_to_string(process_root.join("confinement.rs")).unwrap();
    let process = fs::read_to_string(process_root.join("process.rs")).unwrap();
    let spec = fs::read_to_string(process_root.join("spec.rs")).unwrap();
    let shell = fs::read_to_string(process_root.join("shell.rs")).unwrap();
    let terminal = fs::read_to_string(process_root.join("terminal.rs")).unwrap();
    let policy =
        fs::read_to_string(root.join("crates/api/rust-agent-policy/src/process.rs")).unwrap();
    for required in [
        "pub struct ProcessSpec",
        "pub struct ProcessEnvironment",
        "MAX_PROCESS_ARGUMENTS",
        "CredentialEnvironmentDenied",
    ] {
        assert!(
            spec.contains(required),
            "process spec is missing `{required}`"
        );
    }
    for required in [
        "pub struct ConfinementAuthority",
        "pub struct ConfinementIssuer",
        "pub struct ConfinementVerifier",
        "pub struct ConfinedProcessSpec",
        "pub struct VerifiedProcessSpec",
        "Arc::ptr_eq",
        ".is_within(self.state.ceiling.policy())",
        ".validate_for(&projection.effective_policy)",
    ] {
        assert!(
            confinement.contains(required),
            "confinement boundary is missing `{required}`"
        );
    }
    assert!(!confinement.contains("impl Clone for ConfinedProcessSpec"));
    assert!(
        !confinement
            .contains("derive(Clone, Debug, Eq, PartialEq)]\npub struct ConfinedProcessSpec")
    );
    let subprocess_trait = process
        .split("pub trait Subprocess")
        .nth(1)
        .unwrap()
        .split("#[derive(Clone)]")
        .next()
        .unwrap();
    assert!(subprocess_trait.contains("spec: ConfinedProcessSpec"));
    assert!(!subprocess_trait.contains("spec: ProcessSpec"));
    assert!(process.contains("pub struct EnforcementReport"));
    assert!(process.contains("applied_primitives().contains(required_primitives)"));
    assert!(shell.contains("pub trait Shell"));
    assert!(shell.contains("fn resolve(&self, request: ShellRequest) -> Result<ShellSpec"));
    assert!(shell.contains("spec: ShellSpec"));
    assert!(shell.contains("binding_authority: Option<Arc<()>>"));
    assert!(shell.contains("Arc::ptr_eq(authority, &self.binding_authority)"));
    assert!(!shell.contains("ShellSpec::for_provider"));
    assert!(!shell.contains("ProviderShellSpec"));
    assert!(terminal.contains("pub trait TerminalManager"));
    assert!(terminal.contains("Result<TerminalId, TerminalError>"));
    assert!(terminal.contains("id: TerminalId"));
    assert!(terminal.contains("binding_authority: Option<Arc<()>>"));
    assert!(terminal.contains("Arc::ptr_eq(authority, &self.binding_authority)"));
    assert!(!terminal.contains("TerminalId::for_provider"));
    assert!(!terminal.contains("ProviderTerminalId"));
    assert!(policy.contains("pub struct SandboxPolicyCeiling"));
    assert!(policy.contains("pub struct BackendPlan"));
    assert!(policy.contains("BACKEND_PLAN_SCHEMA_VERSION"));
    assert!(policy.contains("required_linux_primitives"));
    for source in [
        &lib,
        &confinement,
        &process,
        &spec,
        &shell,
        &terminal,
        &policy,
    ] {
        assert!(!source.contains("unsafe"));
        assert!(!source.contains("std::process"));
        assert!(!source.contains("std::fs"));
    }

    let tree = Command::new("cargo")
        .args([
            "tree",
            "-p",
            "rust-agent-process",
            "--edges",
            "normal",
            "--no-default-features",
        ])
        .current_dir(&root)
        .output()
        .unwrap();
    assert!(tree.status.success());
    let tree = String::from_utf8(tree.stdout).unwrap();
    for forbidden in [
        "AINS",
        "rust-agent-agent",
        "rust-agent-fs-local",
        "rust-agent-subprocess-local",
        "rust-agent-sandbox-linux",
        "rust-agent-shell-local",
        "rust-agent-terminal-local",
        "libc",
        "nix",
        "rustix",
        "tokio",
    ] {
        assert!(
            !tree.contains(forbidden),
            "process API resolved concrete/effectful dependency `{forbidden}`:\n{tree}"
        );
    }

    let invariant_map = fs::read_to_string(root.join("docs/invariant-tests.md")).unwrap();
    let mapped = markdown_section(&invariant_map, "## Phase 4", "## Accepted ADR amendments");
    for required in [
        "rust_agent_policy::process::tests::policy_projection_is_monotonic_bounded_and_deterministic",
        "rust_agent_process::tests::confinement_authority_is_pair_exact_and_policy_digest_bound",
        "rust_agent_process::tests::sandbox_and_subprocess_pipeline_has_no_raw_or_cancelled_spawn_bypass",
        "rust_agent_process::tests::subprocess_rejects_effect_and_enforcement_report_drift",
        "privacy::confinement_process_shell_terminal_authority_remains_private",
        "architecture::phase_four_process_confinement_api_is_closed_bounded_and_dependency_isolated",
    ] {
        assert!(
            mapped.contains(required),
            "unmapped Phase 4.4 evidence: {required}"
        );
    }
    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml")).unwrap();
    for required in [
        "Verify Phase 4 process API dependency closures",
        "Verify Phase 4 process API target matrix",
        "Verify Phase 4 process API contracts",
    ] {
        assert!(
            ci.contains(required),
            "missing Phase 4.4 CI gate `{required}`"
        );
    }
}

#[test]
fn phase_four_linux_sandbox_planner_is_issuer_only_and_effect_free() {
    let root = workspace_root();
    let path = root.join("crates/components/sandbox-linux");
    let manifest_text = fs::read_to_string(path.join("Cargo.toml")).unwrap();
    let manifest: Value = toml::from_str(&manifest_text).unwrap();
    let metadata = &manifest["package"]["metadata"]["rust-agent"];
    assert_eq!(metadata["id"].as_str(), Some("sandbox-linux"));
    assert_eq!(metadata["scope"].as_str(), Some("agent"));
    assert_eq!(metadata["targets"].as_array().unwrap().len(), 1);
    assert_eq!(metadata["support"].as_str(), Some("production"));
    assert!(metadata["lifecycle-effects"].as_array().unwrap().is_empty());
    assert!(metadata["security"].as_array().unwrap().is_empty());
    assert!(
        metadata["runtime-primitives"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let provides = metadata["provides"].as_array().unwrap();
    assert_eq!(provides.len(), 1);
    assert_eq!(provides[0]["capability"].as_str(), Some("cap:sandbox"));
    assert!(provides[0]["effects"].as_array().unwrap().is_empty());
    let requires = metadata["requires"].as_array().unwrap();
    assert_eq!(requires.len(), 1);
    assert_eq!(
        requires[0]["capability"].as_str(),
        Some("cap:confinement-issuer")
    );
    assert_eq!(requires[0]["mode"].as_str(), Some("required"));
    assert_eq!(requires[0]["field"].as_str(), Some("confinement_issuer"));

    let source = fs::read_to_string(path.join("src/lib.rs")).unwrap();
    for required in [
        "pub confinement_issuer: ConfinementIssuerBinding",
        ".project(&requested_policy)",
        "BackendPlan::linux",
        ".seal(process, projection, plan)",
        "SecurityEffects::empty()",
        "sandbox-linux declares no runtime primitives",
    ] {
        assert!(
            source.contains(required),
            "sandbox-linux is missing `{required}`"
        );
    }
    for forbidden in [
        "ConfinementVerifier",
        "EnforcementReport",
        "ProcessHandle",
        "std::process",
        "std::fs",
        "unsafe",
    ] {
        assert!(
            !source
                .split("#[cfg(all(test")
                .next()
                .unwrap()
                .contains(forbidden),
            "sandbox-linux production source contains forbidden boundary `{forbidden}`"
        );
    }

    let tree = Command::new("cargo")
        .args([
            "tree",
            "-p",
            "rust-agent-sandbox-linux",
            "--edges",
            "normal",
            "--no-default-features",
        ])
        .current_dir(&root)
        .output()
        .unwrap();
    assert!(tree.status.success());
    let tree = String::from_utf8(tree.stdout).unwrap();
    for forbidden in [
        "AINS",
        "rust-agent-agent",
        "rust-agent-subprocess-local",
        "rust-agent-fs-local",
        "rust-agent-runtime-tokio",
        "tokio",
        "libc",
        "nix",
        "rustix",
    ] {
        assert!(
            !tree.contains(forbidden),
            "sandbox-linux resolved forbidden dependency `{forbidden}`:\n{tree}"
        );
    }

    let invariant_map = fs::read_to_string(root.join("docs/invariant-tests.md")).unwrap();
    let mapped = markdown_section(&invariant_map, "## Phase 4", "## Accepted ADR amendments");
    for required in [
        "rust_agent_sandbox_linux::tests::requested_policy_is_monotonically_projected_and_pair_sealed",
        "rust_agent_sandbox_linux::tests::authority_and_runtime_projection_fail_closed_without_a_spec_escape",
        "rust_agent_sandbox_linux::tests::provider_is_effect_free_and_backend_plan_is_deterministic",
        "architecture::phase_four_linux_sandbox_planner_is_issuer_only_and_effect_free",
    ] {
        assert!(
            mapped.contains(required),
            "unmapped Phase 4.5 evidence: {required}"
        );
    }
    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml")).unwrap();
    for required in [
        "Verify Phase 4 Linux sandbox planner closure",
        "Verify Phase 4 Linux sandbox planner contracts",
    ] {
        assert!(
            ci.contains(required),
            "missing Phase 4.5 CI gate `{required}`"
        );
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
    assert!(ci.contains("Verify exact Phase 0/1A/1B/2 identities and Phase 3 evidence"));
    assert!(ci.contains(
        "phase_zero_through_three_acceptance_mappings_are_exact_complete_and_runnable -- --exact"
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
fn phase_zero_through_three_acceptance_mappings_are_exact_complete_and_runnable() {
    let root = workspace_root();
    let architecture = fs::read_to_string(root.join("ARCHITECTURE.md")).unwrap();
    let invariant_map = fs::read_to_string(root.join("docs/invariant-tests.md")).unwrap();
    let architecture_phases = markdown_section(
        &architecture,
        "### Phase 0 — 独立仓库与 Architecture Contract",
        "### Phase 3 — Tool Execution Plane",
    );
    let mapped_phases = markdown_section(&invariant_map, "## Phase 0", "## Phase 4");
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
        "Phase 0 through Phase 3 mapping tables are unexpectedly empty"
    );
}

#[test]
fn phase_three_acceptance_mapping_is_complete_and_generated() {
    let root = workspace_root();
    let architecture = fs::read_to_string(root.join("ARCHITECTURE.md")).unwrap();
    let contract = markdown_section(
        &architecture,
        "### Phase 3 — Tool Execution Plane",
        "### Phase 4 — Local Execution Providers",
    );
    for required in [
        "薄 wrapper compile-pass",
        "wrapper 尝试访问 handler/private registry 的 compile-fail",
        "普通 consumer 构造/保存 permit 的 compile-fail",
        "Sessionless positive fixture",
        "missing/wrong/cross-Agent verifier",
        "Targeted cancel 的 idle/stale/queued/racing-send/first-cause/shutdown matrix",
    ] {
        assert!(
            contract.contains(required),
            "Phase 3 acceptance contract lost `{required}`"
        );
    }

    let invariant_map = fs::read_to_string(root.join("docs/invariant-tests.md")).unwrap();
    let mapped = markdown_section(&invariant_map, "## Phase 3", "## Phase 4");
    assert!(!mapped.contains("not yet complete"));
    assert!(!mapped.contains("incremental evidence"));
    for required in [
        "generator::tests::phase_three_tool_composition_is_generated_built_and_graph_exact",
        "privacy::wrapper_cannot_access_guarded_registry_or_builder_internals",
        "privacy::tool_policy_registration_and_permit_boundaries_cannot_be_bypassed",
        "architecture::guarded_tool_executor_wrapper_is_metadata_only_and_dependency_one_way",
        "architecture::phase_three_tool_api_dependency_and_privacy_boundary_is_isolated",
        "rust_agent_tools::policy::tests::valid_policy_preserves_canonical_rule_and_predicate_order",
        "rust_agent_tools::policy::tests::predicate_count_is_rejected_before_the_candidate_is_retained",
        "rust_agent_tools::policy::tests::rule_count_is_rejected_before_the_candidate_is_retained",
        "rust_agent_tools::execution::tests::sessionless_committed_proof_reaches_only_guarded_dispatch",
        "rust_agent_tools::execution::tests::wrong_proof_and_cross_agent_scope_fail_before_callbacks",
        "rust_agent_agent::tests::agent_context_without_generated_tool_edge_rejects_proof",
        "rust_agent_agent::tests::targeted_cancel_is_exact_idempotent_and_preserves_first_cause",
        "rust_agent_agent::tests::admission_retry_completion_deadline_and_shutdown_are_bounded",
        ".github/workflows/ci.yml::quality::Verify Phase 3 API dependency closures",
        ".github/workflows/ci.yml::quality::Verify Phase 3 target matrix",
    ] {
        assert!(
            mapped.contains(required),
            "unmapped Phase 3 gate: {required}"
        );
    }

    let status = fs::read_to_string(root.join("docs/phase-status.md")).unwrap();
    assert!(status.contains("| 3 — tool execution plane | Complete |"));
    assert!(!status.contains("Phase 3 still requires generated tool composition"));

    let profile =
        fs::read_to_string(root.join("tests/fixtures/profiles/phase3-tools.toml")).unwrap();
    for required in [
        "driver-tools = \"enabled\"",
        "permission-default = \"enabled\"",
        "tool-executor-guarded = \"enabled\"",
        "agent-driver = \"driver-tools\"",
    ] {
        assert!(profile.contains(required));
    }

    for fixture in [
        "crates/components/tool-executor-guarded/tests/ui/access_guarded_internals.rs",
        "crates/api/rust-agent-tools/tests/ui/forge_execution_permit.rs",
        "crates/api/rust-agent-tools/tests/ui/save_execution_permit.rs",
        "crates/api/rust-agent-tools/tests/ui/forge_tool_policy.rs",
        "crates/api/rust-agent-tools/tests/ui/forge_tool_risk_rule.rs",
        "crates/api/rust-agent-tools/tests/ui/default_and_deserialize_policy.rs",
        "crates/api/rust-agent-tools/tests/ui/forge_prepared_tool_call.rs",
        "crates/api/rust-agent-tools/tests/ui/model_session_has_no_raw_execute.rs",
        "crates/api/rust-agent-runtime-api/tests/ui/issue_tool_journal_authority.rs",
    ] {
        assert!(
            root.join(fixture).is_file(),
            "missing Phase 3 fixture: {fixture}"
        );
    }

    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml")).unwrap();
    for required in [
        "Verify Phase 3 acceptance completion",
        "phase_three_acceptance_mapping_is_complete_and_generated -- --exact",
        "Verify Phase 3 generated Tool composition",
        "phase_three_tool_composition_is_generated_built_and_graph_exact -- --exact",
    ] {
        assert!(ci.contains(required), "missing Phase 3 CI gate: {required}");
    }
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
