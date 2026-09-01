use std::{env, ffi::OsString, path::PathBuf, process::Command};

use rust_agent_build_executor::{BuildExecutionPolicy, DevelopmentBuildOptions, development_build};
use rust_agent_composition::{ComposeOptions, compose};
use tempfile::TempDir;

fn tool(name: &str) -> PathBuf {
    let selected = Command::new("rustup")
        .args(["which", name])
        .output()
        .unwrap();
    if selected.status.success() {
        return PathBuf::from(String::from_utf8(selected.stdout).unwrap().trim())
            .canonicalize()
            .unwrap();
    }
    let path = env::var_os("PATH").unwrap_or_else(|| OsString::from(""));
    env::split_paths(&path)
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
        .unwrap()
        .canonicalize()
        .unwrap()
}

#[test]
fn product_neutral_library_compile_matrix() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let temp = TempDir::new().unwrap();
    let rustc = tool("rustc");
    let cargo = tool("cargo");
    let linker = tool("cc");
    for profile in [
        "wasm-library.toml",
        "android-library.toml",
        "ios-library.toml",
        "macos-library.toml",
        "windows-library.toml",
    ] {
        let generated = compose(&ComposeOptions {
            workspace_root: root.clone(),
            catalog_path: root.join("tests/fixtures/catalog.toml"),
            profile_path: root.join("tests/fixtures/profiles").join(profile),
            output_root: temp.path().join("compositions"),
            rustc_path: rustc.clone(),
            cargo_path: cargo.clone(),
            registry_cache_path: None,
            custom_target_spec_path: None,
        })
        .unwrap();
        let built = development_build(&DevelopmentBuildOptions {
            composition_path: generated.path,
            artifact_dir: temp.path().join("artifacts").join(profile),
            cargo_path: cargo.clone(),
            rustc_path: rustc.clone(),
            linker_path: linker.clone(),
            registry_cache_path: None,
            policy: BuildExecutionPolicy::empty_development(),
            run_generated_tests: false,
        })
        .unwrap_or_else(|error| panic!("{profile} failed: {error}"));
        assert_eq!(built.target, generated.manifest.target);
        assert!(!built.deployable);
    }
}
