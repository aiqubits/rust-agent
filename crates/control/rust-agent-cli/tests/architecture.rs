use std::{fs, path::PathBuf, process::Command};

use toml::Value;
use walkdir::WalkDir;

const PINNED_RUST_VERSION: &str = "1.97.1";
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
fn phase_zero_exposes_no_session_api_with_an_agent_dependency() {
    let session_api = workspace_root().join("crates/api/rust-agent-session");
    assert!(
        !session_api.exists(),
        "Phase 2 must replace this Phase 0 absence check with a transitive public-API closure check before introducing rust-agent-session"
    );
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
    assert_eq!(components, ["clippy", "rustfmt"]);
    let targets: Vec<_> = toolchain["toolchain"]["targets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|target| target.as_str().unwrap())
        .collect();
    assert_eq!(targets, PINNED_TARGETS);

    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml")).unwrap();
    assert!(ci.contains("toolchain: 1.97.1"));
    assert!(ci.contains("components: rustfmt,clippy"));
    assert!(ci.contains(&format!("targets: {}", PINNED_TARGETS.join(","))));
    assert!(ci.contains("Verify pinned Rust and Cargo versions"));
    assert!(ci.contains("rustc --version | grep -E '^rustc 1\\.97\\.1 '"));
    assert!(ci.contains("cargo --version | grep -E '^cargo 1\\.97\\.1 '"));

    let golden: Value =
        toml::from_str(&fs::read_to_string(root.join("tests/golden/minimal/Cargo.toml")).unwrap())
            .unwrap();
    assert_eq!(
        golden["package"]["rust-version"].as_str(),
        Some(PINNED_RUST_VERSION)
    );
}
