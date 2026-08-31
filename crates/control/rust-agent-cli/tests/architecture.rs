use std::{fs, path::PathBuf};

use toml::Value;
use walkdir::WalkDir;

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
