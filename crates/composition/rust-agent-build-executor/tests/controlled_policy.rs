use std::{env, ffi::OsString, fs, path::PathBuf, process::Command};

use rust_agent_build_executor::{
    BuildExecutable, BuildExecutionPolicy, BuildPolicyError, BuildReadInput, DevelopmentBuildError,
    DevelopmentBuildOptions, development_build,
};
#[cfg(unix)]
use rust_agent_composition::ComposeError;
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

fn registry_cache() -> PathBuf {
    let cargo_home = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
        .expect("Cargo home must be discoverable");
    cargo_home.join("registry").canonicalize().unwrap()
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
    let registry = registry_cache();
    let generated = compose(&ComposeOptions {
        workspace_root: root.clone(),
        profile_path: root.join("tests/fixtures/profiles/controlled-build.toml"),
        output_root: temp.path().join("compositions"),
        rustc_path: rustc.clone(),
        cargo_path: cargo.clone(),
        registry_cache_path: Some(registry.clone()),
        custom_target_spec_path: None,
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
        registry_cache_path: Some(registry.clone()),
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
        registry_cache_path: Some(registry),
        policy,
        run_generated_tests: true,
    })
    .unwrap();
    assert!(!built.deployable);
    assert!(built.generated_tests_ran);
}

#[cfg(unix)]
#[test]
fn development_build_rejects_ancestor_cargo_config_before_cargo_side_effects() {
    use std::os::unix::fs::PermissionsExt;

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
        profile_path: root.join("tests/fixtures/profiles/minimal.toml"),
        output_root: temp.path().join("compositions"),
        rustc_path: rustc.clone(),
        cargo_path: cargo,
        registry_cache_path: None,
        custom_target_spec_path: None,
    })
    .unwrap();

    let cargo_marker = temp.path().join("cargo-ran");
    let fake_cargo = temp.path().join("fake-cargo");
    fs::write(
        &fake_cargo,
        format!("#!/bin/sh\nprintf cargo-ran > {cargo_marker:?}\nexit 97\n"),
    )
    .unwrap();
    fs::set_permissions(&fake_cargo, fs::Permissions::from_mode(0o755)).unwrap();
    fs::create_dir(temp.path().join(".cargo")).unwrap();
    fs::write(
        temp.path().join(".cargo/config.toml"),
        b"[build]\nrustc-wrapper = \"malicious-wrapper\"\n",
    )
    .unwrap();
    let artifact_dir = temp.path().join("artifacts");

    assert!(matches!(
        development_build(&DevelopmentBuildOptions {
            composition_path: generated.path,
            artifact_dir: artifact_dir.clone(),
            cargo_path: fake_cargo,
            rustc_path: rustc,
            linker_path: linker,
            registry_cache_path: None,
            policy: BuildExecutionPolicy::empty_development(),
            run_generated_tests: false,
        }),
        Err(DevelopmentBuildError::CargoConfigIsolation(_))
    ));
    assert!(!cargo_marker.exists());
    assert!(!artifact_dir.exists());
}

#[cfg(unix)]
#[test]
fn development_build_rejects_noncanonical_and_duplicate_composition_manifests_before_cargo() {
    use std::os::unix::fs::PermissionsExt;

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
        profile_path: root.join("tests/fixtures/profiles/minimal.toml"),
        output_root: temp.path().join("compositions"),
        rustc_path: rustc.clone(),
        cargo_path: cargo,
        registry_cache_path: None,
        custom_target_spec_path: None,
    })
    .unwrap();
    let manifest_path = generated.path.join("rust-agent-composition.json");
    let canonical = fs::read(&manifest_path).unwrap();

    let cargo_marker = temp.path().join("cargo-ran");
    let fake_cargo = temp.path().join("fake-cargo");
    fs::write(
        &fake_cargo,
        format!("#!/bin/sh\nprintf cargo-ran > {cargo_marker:?}\nexit 97\n"),
    )
    .unwrap();
    fs::set_permissions(&fake_cargo, fs::Permissions::from_mode(0o755)).unwrap();

    let assert_rejected_before_cargo = |bytes: &[u8], artifact_dir: PathBuf| {
        fs::write(&manifest_path, bytes).unwrap();
        assert!(matches!(
            development_build(&DevelopmentBuildOptions {
                composition_path: generated.path.clone(),
                artifact_dir: artifact_dir.clone(),
                cargo_path: fake_cargo.clone(),
                rustc_path: rustc.clone(),
                linker_path: linker.clone(),
                registry_cache_path: None,
                policy: BuildExecutionPolicy::empty_development(),
                run_generated_tests: false,
            }),
            Err(DevelopmentBuildError::Composition(
                ComposeError::ManifestNormalization { .. }
            ))
        ));
        assert!(!cargo_marker.exists());
        assert!(!artifact_dir.exists());
    };

    let compact = serde_json::to_vec(&generated.manifest).unwrap();
    assert_rejected_before_cargo(&compact, temp.path().join("compact-artifacts"));

    let (owner, support) = generated
        .manifest
        .resolution
        .target_support
        .first_key_value()
        .unwrap();
    let owner = serde_json::to_string(owner).unwrap();
    let mut forged = support.clone();
    forged.targets = "cfg(false)".into();
    let forged = serde_json::to_string(&forged).unwrap();
    let mut duplicate = String::from_utf8(canonical.clone()).unwrap();
    let marker = "\"target-support\": {";
    let insert_at = duplicate.find(marker).unwrap() + marker.len();
    duplicate.insert_str(insert_at, &format!("\n      {owner}: {forged},"));
    assert_rejected_before_cargo(
        duplicate.as_bytes(),
        temp.path().join("duplicate-artifacts"),
    );

    fs::write(manifest_path, canonical).unwrap();
}
