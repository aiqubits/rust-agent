use std::{
    env,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use rust_agent_build_executor::{
    HostIntegrationTopology, emit_integration, verify_host_topology, verify_integration_topology,
};
use rust_agent_composition::{ComposeOptions, GeneratedComposition, compose};
use tempfile::TempDir;

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
        .expect("rustup must resolve the pinned toolchain");
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

fn compose_fixture(
    root: &Path,
    temp: &Path,
    rustc: &Path,
    cargo: &Path,
    profile: &str,
) -> GeneratedComposition {
    compose(&ComposeOptions {
        workspace_root: root.to_owned(),
        profile_path: root.join("tests/fixtures/profiles").join(profile),
        catalog_trust_policy_path: root.join("tests/fixtures/catalog-trust.toml"),
        output_root: temp.join("compositions"),
        rustc_path: rustc.to_owned(),
        cargo_path: cargo.to_owned(),
        registry_cache_path: (profile == "wasm-js.toml").then(registry_cache),
        custom_target_spec_path: None,
    })
    .unwrap()
}

#[test]
fn framework_neutral_host_topology_matrix() {
    let root = repository_root();
    let temp = TempDir::new().unwrap();
    let rustc = tool("rustc");
    let cargo = tool("cargo");
    let linker = tool("cc");

    let native = compose_fixture(&root, temp.path(), &rustc, &cargo, "minimal.toml");
    verify_host_topology(
        &native.manifest,
        HostIntegrationTopology::SameProcessNativeRust,
    )
    .unwrap();
    verify_host_topology(&native.manifest, HostIntegrationTopology::NativeBackendIpc).unwrap();
    for rejected in [
        HostIntegrationTopology::SameModuleRustWasm,
        HostIntegrationTopology::JavaScriptWasm,
    ] {
        assert!(verify_host_topology(&native.manifest, rejected).is_err());
    }

    let wasm = compose_fixture(&root, temp.path(), &rustc, &cargo, "wasm-library.toml");
    verify_host_topology(&wasm.manifest, HostIntegrationTopology::SameModuleRustWasm).unwrap();
    for rejected in [
        HostIntegrationTopology::SameProcessNativeRust,
        HostIntegrationTopology::NativeBackendIpc,
        HostIntegrationTopology::JavaScriptWasm,
    ] {
        assert!(verify_host_topology(&wasm.manifest, rejected).is_err());
    }

    let javascript = compose_fixture(&root, temp.path(), &rustc, &cargo, "wasm-js.toml");
    verify_host_topology(
        &javascript.manifest,
        HostIntegrationTopology::JavaScriptWasm,
    )
    .unwrap();
    for rejected in [
        HostIntegrationTopology::SameProcessNativeRust,
        HostIntegrationTopology::NativeBackendIpc,
        HostIntegrationTopology::SameModuleRustWasm,
    ] {
        assert!(verify_host_topology(&javascript.manifest, rejected).is_err());
    }

    let native_integration = temp.path().join("native-integration");
    emit_integration(&native.path, &native_integration).unwrap();
    verify_integration_topology(
        &native_integration,
        true,
        HostIntegrationTopology::NativeBackendIpc,
    )
    .unwrap();
    compile_native_ipc_fixture(
        &root,
        temp.path(),
        &native_integration,
        &cargo,
        &rustc,
        &linker,
    );

    let wasm_integration = temp.path().join("wasm-integration");
    emit_integration(&wasm.path, &wasm_integration).unwrap();
    verify_integration_topology(
        &wasm_integration,
        true,
        HostIntegrationTopology::SameModuleRustWasm,
    )
    .unwrap();
    compile_same_module_wasm_fixture(
        &root,
        temp.path(),
        &wasm_integration,
        &cargo,
        &rustc,
        &linker,
    );
}

fn compile_same_module_wasm_fixture(
    root: &Path,
    temp: &Path,
    integration: &Path,
    cargo: &Path,
    rustc: &Path,
    linker: &Path,
) {
    let fixture = temp.join("same-module-wasm-host");
    fs::create_dir_all(fixture.join("src")).unwrap();
    fs::copy(
        root.join("tests/fixtures/topologies/same-module-wasm/src/lib.rs"),
        fixture.join("src/lib.rs"),
    )
    .unwrap();
    let integration_path = integration.display();
    fs::write(
        fixture.join("Cargo.toml"),
        format!(
            "[package]\nname = \"same-module-wasm-host\"\nversion = \"0.1.0\"\nedition = \"2024\"\nrust-version = \"1.97.1\"\npublish = false\n\n[lib]\ncrate-type = [\"cdylib\"]\n\n[dependencies]\nagent = {{ package = \"rust-agent-generated-composition\", path = \"{integration_path}\", default-features = false }}\n\n[workspace]\n"
        ),
    )
    .unwrap();
    assert_success(&run_cargo(
        cargo,
        rustc,
        linker,
        &fixture,
        temp,
        &["generate-lockfile", "--offline"],
    ));
    assert_success(&run_cargo(
        cargo,
        rustc,
        linker,
        &fixture,
        temp,
        &[
            "build",
            "--target",
            "wasm32-unknown-unknown",
            "--locked",
            "--offline",
        ],
    ));
    let module =
        temp.join("topology-target/wasm32-unknown-unknown/debug/same_module_wasm_host.wasm");
    assert!(module.is_file());
    assert!(fs::metadata(module).unwrap().len() > 0);
    let tree = run_cargo(
        cargo,
        rustc,
        linker,
        &fixture,
        temp,
        &[
            "tree",
            "--target",
            "wasm32-unknown-unknown",
            "--locked",
            "--offline",
        ],
    );
    assert_success(&tree);
    let tree = String::from_utf8(tree.stdout).unwrap();
    assert!(tree.contains("rust-agent-generated-composition"));
    assert!(!tree.contains("rust-agent-fixture-host-export"));
    assert!(!tree.contains("wasm-bindgen"));
}

fn compile_native_ipc_fixture(
    root: &Path,
    temp: &Path,
    integration: &Path,
    cargo: &Path,
    rustc: &Path,
    linker: &Path,
) {
    let fixture = temp.join("webview-ipc-host");
    for package in ["contract", "backend", "frontend"] {
        fs::create_dir_all(fixture.join(package).join("src")).unwrap();
    }
    for (source, destination) in [
        (
            "tests/fixtures/topologies/webview-ipc/contract/src/lib.rs",
            "contract/src/lib.rs",
        ),
        (
            "tests/fixtures/topologies/webview-ipc/backend/src/lib.rs",
            "backend/src/lib.rs",
        ),
        (
            "tests/fixtures/topologies/webview-ipc/frontend/src/lib.rs",
            "frontend/src/lib.rs",
        ),
    ] {
        fs::copy(root.join(source), fixture.join(destination)).unwrap();
    }
    fs::write(
        fixture.join("Cargo.toml"),
        "[workspace]\nmembers = [\"contract\", \"backend\", \"frontend\"]\nresolver = \"2\"\n",
    )
    .unwrap();
    fs::write(
        fixture.join("contract/Cargo.toml"),
        package_manifest("ipc-contract", ""),
    )
    .unwrap();
    let fixture_api = integration.join("sources/tests/fixtures/api/fixture-api");
    let integration_path = integration.display();
    let fixture_api_path = fixture_api.display();
    fs::write(
        fixture.join("backend/Cargo.toml"),
        package_manifest(
            "ipc-backend",
            &format!(
                "ipc-contract = {{ path = \"../contract\" }}\nagent = {{ package = \"rust-agent-generated-composition\", path = \"{integration_path}\", default-features = false }}\nrust-agent-fixture-api = {{ path = \"{fixture_api_path}\", default-features = false }}\n"
            ),
        ),
    )
    .unwrap();
    fs::write(
        fixture.join("frontend/Cargo.toml"),
        package_manifest(
            "ipc-frontend",
            "ipc-contract = { path = \"../contract\" }\n",
        ),
    )
    .unwrap();

    assert_success(&run_cargo(
        cargo,
        rustc,
        linker,
        &fixture,
        temp,
        &["generate-lockfile", "--offline"],
    ));
    assert_success(&run_cargo(
        cargo,
        rustc,
        linker,
        &fixture,
        temp,
        &["test", "--workspace", "--locked", "--offline"],
    ));
    let tree = run_cargo(
        cargo,
        rustc,
        linker,
        &fixture,
        temp,
        &["tree", "-p", "ipc-frontend", "--locked", "--offline"],
    );
    assert_success(&tree);
    let tree = String::from_utf8(tree.stdout).unwrap();
    for forbidden in [
        "rust-agent-generated-composition",
        "rust-agent-fixture-api",
        "rust-agent-runtime-api",
    ] {
        assert!(
            !tree.contains(forbidden),
            "frontend dependency graph exposes {forbidden}:\n{tree}"
        );
    }

    fs::create_dir_all(fixture.join("frontend/src/bin")).unwrap();
    fs::write(
        fixture.join("frontend/src/bin/internal_escape.rs"),
        "use rust_agent_fixture_api::FixtureApp;\nfn main() { let _ = core::mem::size_of::<FixtureApp>(); }\n",
    )
    .unwrap();
    let escape = run_cargo(
        cargo,
        rustc,
        linker,
        &fixture,
        temp,
        &[
            "check",
            "-p",
            "ipc-frontend",
            "--bin",
            "internal_escape",
            "--locked",
            "--offline",
        ],
    );
    assert!(!escape.status.success());
    let diagnostics = String::from_utf8_lossy(&escape.stderr);
    assert!(
        diagnostics.contains("unresolved import")
            || diagnostics.contains("unresolved module or unlinked crate")
    );
}

fn package_manifest(name: &str, dependencies: &str) -> String {
    format!(
        "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\nrust-version = \"1.97.1\"\npublish = false\n\n[dependencies]\n{dependencies}"
    )
}

fn run_cargo(
    cargo: &Path,
    rustc: &Path,
    linker: &Path,
    directory: &Path,
    temp: &Path,
    args: &[&str],
) -> Output {
    let path = env::join_paths(
        [cargo, rustc, linker]
            .into_iter()
            .map(|tool| tool.parent().unwrap()),
    )
    .unwrap();
    let cargo_home = temp.join("topology-cargo-home");
    fs::create_dir_all(&cargo_home).unwrap();
    Command::new(cargo)
        .args(args)
        .current_dir(directory)
        .env_clear()
        .env("PATH", path)
        .env("RUSTC", rustc)
        .env("CARGO_HOME", cargo_home)
        .env("CARGO_TARGET_DIR", temp.join("topology-target"))
        .output()
        .unwrap()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
