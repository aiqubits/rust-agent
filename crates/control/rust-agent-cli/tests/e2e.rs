use std::{
    env,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use sha2::{Digest as _, Sha256};
use tempfile::TempDir;
use walkdir::WalkDir;

use rust_agent_build_executor::{BuildExecutable, BuildExecutionPolicy};

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

fn run(binary: &Path, args: &[OsString]) -> Output {
    Command::new(binary).args(args).output().unwrap()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn registry_cache() -> PathBuf {
    let cargo_home = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
        .expect("Cargo home must be discoverable");
    cargo_home.join("registry").canonicalize().unwrap()
}

#[test]
fn compose_build_inspect_emit_verify_end_to_end() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_rust-agent"));
    let rustc = tool("rustc");
    let cargo = tool("cargo");
    let linker = tool("cc");
    let temp = TempDir::new().unwrap();
    let compositions = temp.path().join("compositions");

    let compose_output = run(
        &binary,
        &[
            "compose".into(),
            "--workspace".into(),
            root.as_os_str().into(),
            "--catalog".into(),
            root.join("tests/fixtures/catalog.toml").into_os_string(),
            "--profile".into(),
            root.join("tests/fixtures/profiles/minimal.toml")
                .into_os_string(),
            "--output".into(),
            compositions.as_os_str().into(),
            "--rustc".into(),
            rustc.as_os_str().into(),
            "--cargo".into(),
            cargo.as_os_str().into(),
        ],
    );
    assert_success(&compose_output);
    let composition = fs::read_dir(&compositions)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert!(composition.join("rust-agent-composition.json").is_file());

    let artifacts = temp.path().join("artifacts");
    let build_output = run(
        &binary,
        &[
            "build".into(),
            "--composition".into(),
            composition.as_os_str().into(),
            "--artifact-dir".into(),
            artifacts.as_os_str().into(),
            "--rustc".into(),
            rustc.as_os_str().into(),
            "--cargo".into(),
            cargo.as_os_str().into(),
            "--development-build".into(),
            "--linker".into(),
            linker.as_os_str().into(),
        ],
    );
    assert_success(&build_output);
    assert!(artifacts.join("rust-agent-build.json").is_file());

    let production_inspect = run(
        &binary,
        &[
            "inspect".into(),
            "--artifact-dir".into(),
            artifacts.as_os_str().into(),
        ],
    );
    assert!(!production_inspect.status.success());
    let development_inspect = run(
        &binary,
        &[
            "inspect".into(),
            "--artifact-dir".into(),
            artifacts.as_os_str().into(),
            "--allow-development".into(),
        ],
    );
    assert_success(&development_inspect);

    let integration = temp.path().join("emitted-integration");
    let emit = run(
        &binary,
        &[
            "emit-integration".into(),
            "--composition".into(),
            composition.as_os_str().into(),
            "--destination".into(),
            integration.as_os_str().into(),
        ],
    );
    assert_success(&emit);
    let production_verify = run(
        &binary,
        &[
            "verify-integration".into(),
            "--integration".into(),
            integration.as_os_str().into(),
        ],
    );
    assert!(!production_verify.status.success());
    let development_verify = run(
        &binary,
        &[
            "verify-integration".into(),
            "--integration".into(),
            integration.as_os_str().into(),
            "--allow-development".into(),
        ],
    );
    assert_success(&development_verify);

    compile_independent_host(&cargo, &rustc, &linker, temp.path(), &integration);

    fs::write(integration.join("src/lib.rs"), "// mutated\n").unwrap();
    let mutated = run(
        &binary,
        &[
            "verify-integration".into(),
            "--integration".into(),
            integration.as_os_str().into(),
            "--allow-development".into(),
        ],
    );
    assert!(!mutated.status.success());
}

#[test]
fn javascript_wasm_compose_build_and_inspect_end_to_end() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_rust-agent"));
    let rustc = tool("rustc");
    let cargo = tool("cargo");
    let linker = tool("cc");
    let wasm_bindgen = tool("wasm-bindgen");
    let registry = registry_cache();
    let temp = TempDir::new().unwrap();
    let compositions = temp.path().join("compositions");

    let compose_output = run(
        &binary,
        &[
            "compose".into(),
            "--workspace".into(),
            root.as_os_str().into(),
            "--catalog".into(),
            root.join("tests/fixtures/catalog.toml").into_os_string(),
            "--profile".into(),
            root.join("tests/fixtures/profiles/wasm-js.toml")
                .into_os_string(),
            "--output".into(),
            compositions.as_os_str().into(),
            "--rustc".into(),
            rustc.as_os_str().into(),
            "--cargo".into(),
            cargo.as_os_str().into(),
            "--registry-cache".into(),
            registry.as_os_str().into(),
        ],
    );
    assert_success(&compose_output);
    let composition = fs::read_dir(&compositions)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();

    let policy = BuildExecutionPolicy {
        schema: 1,
        executables: vec![BuildExecutable {
            id: "wasm-bindgen-cli".into(),
            path: wasm_bindgen.clone(),
            digest: hex::encode(Sha256::digest(fs::read(&wasm_bindgen).unwrap())),
            version: "wasm-bindgen 0.2.127".into(),
        }],
        read_inputs: vec![],
        environment: vec![],
    };
    let policy_path = temp.path().join("build-policy.toml");
    fs::write(&policy_path, toml::to_string(&policy).unwrap()).unwrap();
    let artifacts = temp.path().join("wasm-artifacts");
    let build_args: [OsString; 16] = [
        "build".into(),
        "--composition".into(),
        composition.as_os_str().into(),
        "--artifact-dir".into(),
        artifacts.as_os_str().into(),
        "--rustc".into(),
        rustc.as_os_str().into(),
        "--cargo".into(),
        cargo.as_os_str().into(),
        "--linker".into(),
        linker.as_os_str().into(),
        "--registry-cache".into(),
        registry.as_os_str().into(),
        "--policy".into(),
        policy_path.as_os_str().into(),
        "--development-build".into(),
    ];
    let empty_path = temp.path().join("empty-ambient-path");
    fs::create_dir(&empty_path).unwrap();
    let build_output = Command::new(&binary)
        .args(&build_args)
        .env("PATH", &empty_path)
        .output()
        .unwrap();
    assert_success(&build_output);
    for relative in [
        "rust-agent-build.json",
        "rust-agent-sbom.cdx.json",
        "intermediate/rust_agent_raw.wasm",
        "bundle/rust_agent.js",
        "bundle/rust_agent_bg.wasm",
        "bundle/rust_agent.d.ts",
    ] {
        assert!(artifacts.join(relative).is_file(), "missing {relative}");
    }
    let inspect = run(
        &binary,
        &[
            "inspect".into(),
            "--artifact-dir".into(),
            artifacts.as_os_str().into(),
            "--allow-development".into(),
        ],
    );
    assert_success(&inspect);
}

fn compile_independent_host(
    cargo: &Path,
    rustc: &Path,
    linker: &Path,
    temp: &Path,
    integration: &Path,
) {
    let host = temp.join("independent-host");
    fs::create_dir_all(host.join("src")).unwrap();
    let integration_path = integration.display();
    fs::write(
        host.join("Cargo.toml"),
        format!(
            "[package]\nname = \"independent-host\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[dependencies]\nagent = {{ package = \"rust-agent-generated-composition\", version = \"0.1.0\", path = \"{integration_path}\", default-features = false }}\n"
        ),
    )
    .unwrap();
    fs::write(
        host.join("src/main.rs"),
        "fn main() {\n    let runtime = agent::create_runtime_primitives().unwrap();\n    let app = agent::build(runtime).unwrap();\n    assert_eq!(app.run(\"host\"), \"fixture-response:host\");\n}\n",
    )
    .unwrap();
    assert_success(&run_host_cargo(
        cargo,
        rustc,
        linker,
        &host,
        &["generate-lockfile", "--offline"],
    ));
    assert_success(&run_host_cargo(
        cargo,
        rustc,
        linker,
        &host,
        &["run", "--locked", "--offline"],
    ));

    let duplicate = temp.join("duplicate-api");
    copy_tree(
        &integration.join("sources/crates/api/rust-agent-core"),
        &duplicate.join("crates/api/rust-agent-core"),
    );
    copy_tree(
        &integration.join("sources/crates/api/rust-agent-runtime-api"),
        &duplicate.join("crates/api/rust-agent-runtime-api"),
    );
    for manifest in [
        duplicate.join("crates/api/rust-agent-core/Cargo.toml"),
        duplicate.join("crates/api/rust-agent-runtime-api/Cargo.toml"),
    ] {
        let input = fs::read_to_string(&manifest).unwrap();
        fs::write(
            &manifest,
            input.replace("version = \"0.1.0\"", "version = \"0.1.1\""),
        )
        .unwrap();
    }
    let duplicate_runtime = duplicate.join("crates/api/rust-agent-runtime-api");
    let duplicate_runtime_path = duplicate_runtime.display();
    fs::write(
        host.join("Cargo.toml"),
        format!(
            "[package]\nname = \"independent-host\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[dependencies]\nagent = {{ package = \"rust-agent-generated-composition\", version = \"0.1.0\", path = \"{integration_path}\", default-features = false }}\nsecond-runtime-api = {{ package = \"rust-agent-runtime-api\", version = \"0.1.1\", path = \"{duplicate_runtime_path}\", default-features = false }}\n"
        ),
    )
    .unwrap();
    fs::write(
        host.join("src/main.rs"),
        "fn main() {\n    let identity = second_runtime_api::RuntimeAdapterIdentity::checked(\"fixture-runtime\").unwrap();\n    let runtime = second_runtime_api::RuntimePrimitives::new(identity);\n    let _ = agent::build(runtime);\n}\n",
    )
    .unwrap();
    assert_success(&run_host_cargo(
        cargo,
        rustc,
        linker,
        &host,
        &["generate-lockfile", "--offline"],
    ));
    let negative = run_host_cargo(
        cargo,
        rustc,
        linker,
        &host,
        &["check", "--locked", "--offline"],
    );
    assert!(
        !negative.status.success(),
        "duplicate API type identity unexpectedly compiled"
    );
    assert!(String::from_utf8_lossy(&negative.stderr).contains("mismatched types"));
}

fn run_host_cargo(
    cargo: &Path,
    rustc: &Path,
    linker: &Path,
    directory: &Path,
    args: &[&str],
) -> Output {
    let path = env::join_paths(
        [cargo, rustc, linker]
            .into_iter()
            .map(|tool| tool.parent().unwrap()),
    )
    .unwrap();
    let cargo_home = directory.parent().unwrap().join("host-cargo-home");
    fs::create_dir_all(&cargo_home).unwrap();
    Command::new(cargo)
        .args(args)
        .current_dir(directory)
        .env_clear()
        .env("PATH", path)
        .env("RUSTC", rustc)
        .env("CARGO_HOME", cargo_home)
        .env(
            "CARGO_TARGET_DIR",
            directory.parent().unwrap().join("host-target"),
        )
        .output()
        .unwrap()
}

fn copy_tree(source: &Path, destination: &Path) {
    for entry in WalkDir::new(source) {
        let entry = entry.unwrap();
        let relative = entry.path().strip_prefix(source).unwrap();
        let target = destination.join(relative);
        if entry.file_type().is_dir() {
            fs::create_dir_all(target).unwrap();
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}
