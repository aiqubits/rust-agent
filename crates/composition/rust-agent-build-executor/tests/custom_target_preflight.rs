#![cfg(unix)]

use std::{
    env,
    ffi::OsString,
    fs,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::Command,
};

use rust_agent_build_executor::{
    BuildExecutionPolicy, DevelopmentBuildError, DevelopmentBuildOptions, development_build,
};
use rust_agent_composition::{ComposeOptions, compose};
use tempfile::TempDir;

const LOGICAL_TARGET: &str = "x86_64-unknown-linux-gnu";

fn tool(name: &str) -> PathBuf {
    let selected = Command::new("rustup")
        .args(["which", name])
        .output()
        .expect("rustup must resolve the selected test toolchain");
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

fn write_executable(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn write_fake_rustc(path: &Path, arch: &str) {
    let real_rustc = tool("rustc");
    write_executable(
        path,
        &format!(
            concat!(
                "#!/bin/sh\n",
                "if [ \"$1\" = -vV ]; then exec {:?} \"$@\"; fi\n",
                "IFS= read -r observed < \"$4\"\n",
                "[ \"$observed\" = '{{\"arch\":\"x86_64\"}}' ] || exit 41\n",
                "printf '%s\\n' 'panic=\"unwind\"' 'target_abi=\"\"' ",
                "'target_arch=\"{arch}\"' 'target_endian=\"little\"' ",
                "'target_env=\"gnu\"' 'target_family=\"unix\"' ",
                "'target_os=\"linux\"' 'target_pointer_width=\"64\"' ",
                "'target_vendor=\"unknown\"' 'unix'\n"
            ),
            real_rustc,
            arch = arch,
        ),
    );
}

fn write_fake_cargo(path: &Path, marker: &Path) {
    let real_cargo = tool("cargo");
    write_executable(
        path,
        &format!(
            concat!(
                "#!/bin/sh\n",
                "if [ \"$1\" = metadata ]; then exec {:?} \"$@\"; fi\n",
                "manifest=\nconfig=\nnext=\n",
                "for arg in \"$@\"; do\n",
                "  if [ \"$next\" = manifest ]; then manifest=\"$arg\"; next=; continue; fi\n",
                "  if [ \"$next\" = config ]; then config=\"$arg\"; next=; continue; fi\n",
                "  if [ \"$arg\" = \"--manifest-path\" ]; then next=manifest; fi\n",
                "  if [ \"$arg\" = \"--config\" ]; then next=config; fi\n",
                "done\n",
                "[ -n \"$manifest\" ] && [ -n \"$config\" ] || exit 30\n",
                "found=0\n",
                "while IFS= read -r line; do\n",
                "  [ \"$line\" = 'target = \"targets/{LOGICAL_TARGET}.json\"' ] && found=1\n",
                "done < \"$config\"\n",
                "[ \"$found\" = 1 ] || exit 31\n",
                "snapshot=\"${{manifest%/*}}/targets/{LOGICAL_TARGET}.json\"\n",
                "IFS= read -r observed < \"$snapshot\"\n",
                "[ \"$observed\" = '{{\"arch\":\"x86_64\"}}' ] || exit 33\n",
                "printf 'args:%s\\nsnapshot-path:%s\\nsnapshot:%s\\n' ",
                "\"$*\" \"$snapshot\" \"$observed\" >> {:?}\n",
                "case \"$1\" in\n",
                "  generate-lockfile)\n",
                "    printf 'version = 4\\n\\n[[package]]\\nname = ",
                "\"rust-agent-generated-composition\"\\nversion = \"0.1.0\"\\n' ",
                "> \"${{manifest%/*}}/Cargo.lock\"\n",
                "    ;;\n",
                "  build)\n",
                "    output=\"$CARGO_TARGET_DIR/{LOGICAL_TARGET}/debug\"\n",
                "    /bin/mkdir -p \"$output\"\n",
                "    printf 'fixture rlib' > ",
                "\"$output/librust_agent_generated_composition.rlib\"\n",
                "    ;;\n",
                "  *) exit 32 ;;\n",
                "esac\n"
            ),
            real_cargo,
            marker,
            LOGICAL_TARGET = LOGICAL_TARGET,
        ),
    );
}

fn write_mutating_fake_cargo(path: &Path, marker: &Path) {
    write_executable(
        path,
        &format!(
            concat!(
                "#!/bin/sh\n",
                ": > {:?}\n",
                "printf '{{\"arch\":\"aarch64\"}}' > ",
                "\"$PWD/targets/{LOGICAL_TARGET}.json\"\n",
                "exit 37\n"
            ),
            marker,
            LOGICAL_TARGET = LOGICAL_TARGET,
        ),
    );
}

#[test]
fn custom_target_development_preflight_uses_the_snapshot_and_stops_mismatch_before_cargo() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    fs::create_dir_all(workspace.join("target/custom-target-build-tests")).unwrap();
    let temp = TempDir::new_in(workspace.join("target/custom-target-build-tests")).unwrap();
    let spec = temp.path().join("target.json");
    let rustc = temp.path().join("rustc");
    let cargo = temp.path().join("cargo");
    let cargo_marker = temp.path().join("cargo-invocations");
    fs::write(&spec, br#"{"arch":"x86_64"}"#).unwrap();
    write_fake_rustc(&rustc, "x86_64");
    write_fake_cargo(&cargo, &cargo_marker);

    let generated = compose(&ComposeOptions {
        workspace_root: workspace.clone(),
        profile_path: workspace.join("tests/fixtures/profiles/minimal.toml"),
        output_root: temp.path().join("compositions"),
        rustc_path: rustc.clone(),
        cargo_path: cargo.clone(),
        registry_cache_path: None,
        custom_target_spec_path: Some(spec.clone()),
    })
    .unwrap();

    fs::remove_file(&spec).unwrap();
    fs::remove_file(&cargo_marker).unwrap();
    let built = development_build(&DevelopmentBuildOptions {
        composition_path: generated.path.clone(),
        artifact_dir: temp.path().join("artifacts-success"),
        cargo_path: cargo.clone(),
        rustc_path: rustc.clone(),
        linker_path: rustc.clone(),
        registry_cache_path: None,
        policy: BuildExecutionPolicy::empty_development(),
        run_generated_tests: false,
    })
    .unwrap();
    assert_eq!(built.target, LOGICAL_TARGET);
    let cargo_observation = fs::read_to_string(&cargo_marker).unwrap();
    assert!(cargo_observation.contains("snapshot:{\"arch\":\"x86_64\"}"));
    assert!(cargo_observation.contains(&format!("targets/{LOGICAL_TARGET}.json")));

    write_fake_rustc(&rustc, "aarch64");
    fs::remove_file(&cargo_marker).unwrap();
    let rejected_artifacts = temp.path().join("artifacts-rejected");
    let rejected = development_build(&DevelopmentBuildOptions {
        composition_path: generated.path,
        artifact_dir: rejected_artifacts.clone(),
        cargo_path: cargo,
        rustc_path: rustc.clone(),
        linker_path: rustc,
        registry_cache_path: None,
        policy: BuildExecutionPolicy::empty_development(),
        run_generated_tests: false,
    });
    assert!(matches!(
        rejected,
        Err(DevelopmentBuildError::CustomTargetPreflight(message))
            if message.contains("differ from the composition snapshot")
    ));
    assert!(!cargo_marker.exists());
    assert!(!rejected_artifacts.exists());
}

#[test]
fn custom_target_development_cargo_prioritizes_snapshot_drift_over_child_failure() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    fs::create_dir_all(workspace.join("target/custom-target-build-tests")).unwrap();
    let temp = TempDir::new_in(workspace.join("target/custom-target-build-tests")).unwrap();
    let spec = temp.path().join("target.json");
    let rustc = temp.path().join("rustc");
    let cargo = temp.path().join("cargo");
    let cargo_marker = temp.path().join("cargo-invocations");
    fs::write(&spec, br#"{"arch":"x86_64"}"#).unwrap();
    write_fake_rustc(&rustc, "x86_64");
    write_fake_cargo(&cargo, &cargo_marker);

    let generated = compose(&ComposeOptions {
        workspace_root: workspace.clone(),
        profile_path: workspace.join("tests/fixtures/profiles/minimal.toml"),
        output_root: temp.path().join("compositions"),
        rustc_path: rustc.clone(),
        cargo_path: cargo.clone(),
        registry_cache_path: None,
        custom_target_spec_path: Some(spec),
    })
    .unwrap();

    fs::remove_file(&cargo_marker).unwrap();
    write_mutating_fake_cargo(&cargo, &cargo_marker);
    let artifact_dir = temp.path().join("artifacts-rejected");
    let rejected = development_build(&DevelopmentBuildOptions {
        composition_path: generated.path,
        artifact_dir: artifact_dir.clone(),
        cargo_path: cargo,
        rustc_path: rustc.clone(),
        linker_path: rustc,
        registry_cache_path: None,
        policy: BuildExecutionPolicy::empty_development(),
        run_generated_tests: false,
    });

    assert!(cargo_marker.exists());
    assert!(matches!(
        rejected,
        Err(DevelopmentBuildError::CustomTargetPreflight(message))
            if message.contains("changed") || message.contains("match")
    ));
    assert!(artifact_dir.exists());
    assert!(fs::read_dir(&artifact_dir).unwrap().next().is_none());
}
