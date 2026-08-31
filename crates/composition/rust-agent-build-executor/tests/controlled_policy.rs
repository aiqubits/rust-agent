use std::{env, ffi::OsString, fs, path::PathBuf, process::Command};

use rust_agent_build_executor::{
    BuildExecutable, BuildExecutionPolicy, BuildPolicyError, BuildReadInput, DevelopmentBuildError,
    DevelopmentBuildOptions, development_build,
};
use rust_agent_composition::{ComposeOptions, compose};
use sha2::{Digest as _, Sha256};
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
fn build_requirements_need_exact_policy_kind_but_never_expand_runtime_effects() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let temp = TempDir::new().unwrap();
    let rustc = tool("rustc");
    let cargo = tool("cargo");
    let linker = tool("cc");
    let generated = compose(&ComposeOptions {
        workspace_root: root.clone(),
        catalog_path: root.join("tests/fixtures/catalog.toml"),
        profile_path: root.join("tests/fixtures/profiles/controlled-build.toml"),
        output_root: temp.path().join("compositions"),
        rustc_path: rustc.clone(),
        cargo_path: cargo.clone(),
        registry_cache_path: None,
    })
    .unwrap();
    assert!(generated.manifest.compiled_runtime_effects.is_empty());
    assert!(
        generated
            .manifest
            .build_requirements
            .executables
            .contains("fixture-codegen")
    );

    let denied = development_build(&DevelopmentBuildOptions {
        composition_path: generated.path.clone(),
        artifact_dir: temp.path().join("denied-artifacts"),
        cargo_path: cargo.clone(),
        rustc_path: rustc.clone(),
        linker_path: linker.clone(),
        registry_cache_path: None,
        policy: BuildExecutionPolicy::empty_development(),
        run_generated_tests: false,
    });
    assert!(matches!(
        denied,
        Err(DevelopmentBuildError::Policy(
            BuildPolicyError::MissingMapping { .. }
        ))
    ));

    let sdk = temp.path().join("fixture-sdk");
    fs::create_dir(&sdk).unwrap();
    let policy = BuildExecutionPolicy {
        schema: 1,
        executables: vec![BuildExecutable {
            id: "fixture-codegen".into(),
            path: linker.clone(),
            digest: hex::encode(Sha256::digest(fs::read(&linker).unwrap())),
            version: "fixture-v1".into(),
        }],
        read_inputs: vec![BuildReadInput {
            id: "fixture-sdk".into(),
            path: sdk,
            digest: "00".repeat(32),
        }],
        environment: vec![],
    };
    let built = development_build(&DevelopmentBuildOptions {
        composition_path: generated.path,
        artifact_dir: temp.path().join("allowed-artifacts"),
        cargo_path: cargo,
        rustc_path: rustc,
        linker_path: linker,
        registry_cache_path: None,
        policy,
        run_generated_tests: true,
    })
    .unwrap();
    assert!(!built.deployable);
    assert!(built.generated_tests_ran);
}
