use std::{
    env,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use rust_agent_build_executor::{
    BuildExecutable, BuildExecutionPolicy, BuildPolicyError, BuildReadInput,
    DevelopmentArtifactKind, DevelopmentBuildError, DevelopmentBuildOptions, development_build,
    inspect_development_build,
};
use rust_agent_composition::{
    ComposeOptions, WASM_BINDGEN_CLI_LOGICAL_ID, WASM_BINDGEN_PROTOCOL_VERSION, compose,
    profile::BuildKind,
};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

const MAX_SIZE_GROWTH_PERCENT: u64 = 10;
const RAW_WASM_ABSOLUTE_CEILING: u64 = 8 * 1024 * 1024;
const BUNDLE_ABSOLUTE_CEILING: u64 = 512 * 1024;
const WASM_SIZE_BASELINES: [(&str, u64); 5] = [
    ("bundle/rust_agent.d.ts", 2_940),
    ("bundle/rust_agent.js", 19_330),
    ("bundle/rust_agent_bg.wasm", 344_995),
    ("bundle/rust_agent_bg.wasm.d.ts", 1_703),
    ("intermediate/rust_agent_raw.wasm", 6_354_252),
];

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
}

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
    env::split_paths(&env::var_os("PATH").unwrap_or_else(|| OsString::from("")))
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| panic!("required test tool `{name}` is not installed"))
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

fn executable_policy(path: &Path, digest: String, version: String) -> BuildExecutionPolicy {
    BuildExecutionPolicy {
        schema: 1,
        executables: vec![BuildExecutable {
            id: WASM_BINDGEN_CLI_LOGICAL_ID.into(),
            path: path.to_owned(),
            digest,
            version,
        }],
        read_inputs: vec![],
        environment: vec![],
    }
}

fn build_options(
    composition: &Path,
    artifact_dir: PathBuf,
    cargo: &Path,
    rustc: &Path,
    linker: &Path,
    registry: &Path,
    policy: BuildExecutionPolicy,
) -> DevelopmentBuildOptions {
    DevelopmentBuildOptions {
        composition_path: composition.to_owned(),
        artifact_dir,
        cargo_path: cargo.to_owned(),
        rustc_path: rustc.to_owned(),
        linker_path: linker.to_owned(),
        registry_cache_path: Some(registry.to_owned()),
        policy,
        run_generated_tests: true,
    }
}

#[test]
fn javascript_wasm_bundle_is_closed_verified_and_executable_end_to_end() {
    let root = repository_root();
    let temp = TempDir::new().unwrap();
    let cargo = tool("cargo");
    let rustc = tool("rustc");
    let linker = tool("cc");
    let wasm_bindgen = tool("wasm-bindgen");
    let node = tool("node");
    let registry = registry_cache();
    let generated = compose(&ComposeOptions {
        workspace_root: root.clone(),
        profile_path: root.join("tests/fixtures/profiles/wasm-js.toml"),
        catalog_trust_policy_path: root.join("tests/fixtures/catalog-trust.toml"),
        output_root: temp.path().join("compositions"),
        rustc_path: rustc.clone(),
        cargo_path: cargo.clone(),
        registry_cache_path: Some(registry.clone()),
        custom_target_spec_path: None,
    })
    .unwrap();
    assert_eq!(generated.manifest.build_kind, BuildKind::Wasm);
    assert!(
        generated.manifest.direct_root_build_requirements["host-boundary:fixture-host-export"]
            .executables
            .contains(WASM_BINDGEN_CLI_LOGICAL_ID)
    );

    let executable_digest = hex::encode(Sha256::digest(fs::read(&wasm_bindgen).unwrap()));
    let version = format!("wasm-bindgen {WASM_BINDGEN_PROTOCOL_VERSION}");

    let mut no_cache = build_options(
        &generated.path,
        temp.path().join("missing-registry-cache"),
        &cargo,
        &rustc,
        &linker,
        &registry,
        executable_policy(&wasm_bindgen, executable_digest.clone(), version.clone()),
    );
    no_cache.registry_cache_path = None;
    assert!(matches!(
        development_build(&no_cache),
        Err(DevelopmentBuildError::RegistryCacheRequired(_))
    ));

    let missing = development_build(&build_options(
        &generated.path,
        temp.path().join("missing-policy"),
        &cargo,
        &rustc,
        &linker,
        &registry,
        BuildExecutionPolicy::empty_development(),
    ));
    assert!(matches!(
        missing,
        Err(DevelopmentBuildError::Policy(
            BuildPolicyError::MissingMapping { .. }
        ))
    ));

    let wrong_kind = development_build(&build_options(
        &generated.path,
        temp.path().join("wrong-kind"),
        &cargo,
        &rustc,
        &linker,
        &registry,
        BuildExecutionPolicy {
            schema: 1,
            executables: vec![],
            read_inputs: vec![BuildReadInput {
                id: WASM_BINDGEN_CLI_LOGICAL_ID.into(),
                path: wasm_bindgen.clone(),
                digest: executable_digest.clone(),
            }],
            environment: vec![],
        },
    ));
    assert!(matches!(
        wrong_kind,
        Err(DevelopmentBuildError::Policy(
            BuildPolicyError::KindMismatch { .. }
        ))
    ));

    let wrong_digest = development_build(&build_options(
        &generated.path,
        temp.path().join("wrong-digest"),
        &cargo,
        &rustc,
        &linker,
        &registry,
        executable_policy(&wasm_bindgen, "00".repeat(32), version.clone()),
    ));
    assert!(matches!(
        wrong_digest,
        Err(DevelopmentBuildError::Policy(
            BuildPolicyError::ExecutableDigestMismatch { .. }
        ))
    ));

    let wrong_version = development_build(&build_options(
        &generated.path,
        temp.path().join("wrong-version"),
        &cargo,
        &rustc,
        &linker,
        &registry,
        executable_policy(
            &wasm_bindgen,
            executable_digest.clone(),
            "wasm-bindgen 0.2.126".into(),
        ),
    ));
    assert!(matches!(
        wrong_version,
        Err(DevelopmentBuildError::Policy(
            BuildPolicyError::ExecutableVersionMismatch { .. }
        ))
    ));

    let artifact_dir = temp.path().join("artifacts");
    let built = development_build(&build_options(
        &generated.path,
        artifact_dir.clone(),
        &cargo,
        &rustc,
        &linker,
        &registry,
        executable_policy(&wasm_bindgen, executable_digest, version),
    ))
    .unwrap();
    assert_eq!(built.schema, 2);
    assert_eq!(built.build_kind, BuildKind::Wasm);
    assert!(!built.deployable);
    assert!(!built.generated_tests_ran);
    assert_eq!(built.entry_artifact, "bundle/rust_agent.js");
    verify_wasm_size_budget(&built.artifacts);
    assert!(
        built
            .artifacts
            .iter()
            .any(|artifact| artifact.kind == DevelopmentArtifactKind::RawWasmIntermediate)
    );
    assert!(
        built
            .artifacts
            .iter()
            .any(|artifact| artifact.kind == DevelopmentArtifactKind::TransformedWasm)
    );
    inspect_development_build(&artifact_dir, true).unwrap();
    assert!(inspect_development_build(&artifact_dir, false).is_err());

    execute_bundle_with_node(&node, &artifact_dir);

    let loader = artifact_dir.join("bundle/rust_agent.js");
    let loader_bytes = fs::read(&loader).unwrap();
    fs::write(&loader, b"mutated").unwrap();
    assert!(inspect_development_build(&artifact_dir, true).is_err());
    fs::write(&loader, &loader_bytes).unwrap();
    inspect_development_build(&artifact_dir, true).unwrap();

    let sbom = artifact_dir.join("rust-agent-sbom.cdx.json");
    let sbom_bytes = fs::read(&sbom).unwrap();
    fs::write(&sbom, b"{}").unwrap();
    assert!(inspect_development_build(&artifact_dir, true).is_err());
    fs::write(&sbom, &sbom_bytes).unwrap();

    let build_manifest = artifact_dir.join("rust-agent-build.json");
    let manifest_bytes = fs::read(&build_manifest).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&manifest_bytes).unwrap();
    value["deployable"] = true.into();
    fs::write(&build_manifest, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    assert!(inspect_development_build(&artifact_dir, false).is_err());
    value["deployable"] = false.into();
    value["gates"]
        .as_array_mut()
        .unwrap()
        .push("zz-forged".into());
    fs::write(&build_manifest, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    assert!(inspect_development_build(&artifact_dir, true).is_err());
    fs::write(&build_manifest, manifest_bytes).unwrap();
    inspect_development_build(&artifact_dir, true).unwrap();

    let unknown = artifact_dir.join("bundle/ambient.js");
    fs::write(&unknown, b"export {};").unwrap();
    assert!(inspect_development_build(&artifact_dir, true).is_err());
    fs::remove_file(unknown).unwrap();

    #[cfg(unix)]
    {
        let symlink = artifact_dir.join("bundle/linked.js");
        std::os::unix::fs::symlink(&loader, &symlink).unwrap();
        assert!(inspect_development_build(&artifact_dir, true).is_err());
        fs::remove_file(symlink).unwrap();
    }

    fs::remove_file(&loader).unwrap();
    assert!(inspect_development_build(&artifact_dir, true).is_err());
}

fn verify_wasm_size_budget(artifacts: &[rust_agent_build_executor::DevelopmentArtifactRecord]) {
    for (path, baseline) in WASM_SIZE_BASELINES {
        let actual = artifacts
            .iter()
            .find(|artifact| artifact.path == path)
            .unwrap_or_else(|| panic!("size baseline artifact `{path}` is missing"))
            .bytes;
        let growth_ceiling = baseline * (100 + MAX_SIZE_GROWTH_PERCENT) / 100;
        assert!(
            actual <= growth_ceiling,
            "artifact `{path}` grew from baseline {baseline} to {actual} bytes"
        );
    }
    let raw = artifacts
        .iter()
        .find(|artifact| artifact.kind == DevelopmentArtifactKind::RawWasmIntermediate)
        .unwrap()
        .bytes;
    let bundle: u64 = artifacts
        .iter()
        .filter(|artifact| artifact.kind != DevelopmentArtifactKind::RawWasmIntermediate)
        .map(|artifact| artifact.bytes)
        .sum();
    assert!(raw <= RAW_WASM_ABSOLUTE_CEILING);
    assert!(bundle <= BUNDLE_ABSOLUTE_CEILING);
}

fn execute_bundle_with_node(node: &Path, artifact_dir: &Path) {
    let loader = format!(
        "file://{}",
        artifact_dir.join("bundle/rust_agent.js").display()
    );
    let wasm = format!(
        "file://{}",
        artifact_dir.join("bundle/rust_agent_bg.wasm").display()
    );
    let script = format!(
        r#"
import init, {{ start }} from {};
import {{ readFile }} from "node:fs/promises";
await init({{ module_or_path: await readFile(new URL({})) }});
const app = await start({{}}, {{}});
if (app.status() !== "ready") throw new Error("unexpected status");
if (app.run("hello") !== "fixture-response:hello") throw new Error("unexpected response");
"#,
        serde_json::to_string(&loader).unwrap(),
        serde_json::to_string(&wasm).unwrap(),
    );
    let output = Command::new(node)
        .args(["--input-type=module", "--eval", &script])
        .env_clear()
        .env("PATH", node.parent().unwrap())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
