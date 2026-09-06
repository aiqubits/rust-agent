use std::{
    collections::BTreeSet,
    fs, io,
    path::{Component, Path},
    process::Command,
};

use rust_agent_composition::{
    WASM_BINDGEN_CLI_LOGICAL_ID, WASM_BINDGEN_FUTURES_VERSION, WASM_BINDGEN_PROTOCOL_VERSION,
};
use tempfile::TempDir;
use walkdir::WalkDir;

use crate::{
    VerifiedBuildExecutable,
    artifact::{
        ArtifactError, DevelopmentArtifactKind, DevelopmentArtifactRecord,
        WasmPostprocessorManifest, artifact_record,
    },
};

pub(crate) fn normalized_invocation() -> Vec<String> {
    [
        "wasm-bindgen",
        "--target",
        "web",
        "--out-name",
        "rust_agent",
        "--out-dir",
        "<bundle>",
        "<raw-wasm>",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

pub(crate) fn verify_protocol_lock(cargo_lock: &Path) -> Result<(), String> {
    let value: toml::Value =
        toml::from_str(&fs::read_to_string(cargo_lock).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let packages = value
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| "Cargo.lock has no package array".to_owned())?;
    for (name, version) in [
        ("wasm-bindgen", WASM_BINDGEN_PROTOCOL_VERSION),
        ("wasm-bindgen-macro", WASM_BINDGEN_PROTOCOL_VERSION),
        ("wasm-bindgen-macro-support", WASM_BINDGEN_PROTOCOL_VERSION),
        ("wasm-bindgen-shared", WASM_BINDGEN_PROTOCOL_VERSION),
        ("wasm-bindgen-futures", WASM_BINDGEN_FUTURES_VERSION),
    ] {
        let versions: Vec<_> = packages
            .iter()
            .filter(|package| package.get("name").and_then(toml::Value::as_str) == Some(name))
            .filter_map(|package| package.get("version").and_then(toml::Value::as_str))
            .collect();
        if versions != [version] {
            return Err(format!(
                "Cargo.lock protocol package `{name}` must be exactly `{version}`, got {versions:?}"
            ));
        }
    }
    Ok(())
}

pub(crate) fn postprocess(
    raw_source: &Path,
    artifact_dir: &Path,
    executable: &VerifiedBuildExecutable,
) -> Result<(Vec<DevelopmentArtifactRecord>, WasmPostprocessorManifest), ArtifactError> {
    fs::create_dir_all(artifact_dir.join("intermediate"))?;
    fs::create_dir_all(artifact_dir.join("bundle"))?;
    let raw_relative = "intermediate/rust_agent_raw.wasm";
    fs::copy(raw_source, artifact_dir.join(raw_relative))?;
    let raw = artifact_record(
        artifact_dir,
        raw_relative,
        DevelopmentArtifactKind::RawWasmIntermediate,
    )?;

    let staging = TempDir::new()?;
    let output = Command::new(executable.path())
        .args(["--target", "web", "--out-name", "rust_agent", "--out-dir"])
        .arg(staging.path())
        .arg(raw_source)
        .current_dir(staging.path())
        .env_clear()
        .env(
            "PATH",
            executable.path().parent().unwrap_or_else(|| Path::new("/")),
        )
        .output()?;
    if !output.status.success() {
        return Err(ArtifactError::InvalidManifest(format!(
            "wasm-bindgen post-link failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    let mut records = Vec::new();
    let mut folded = BTreeSet::new();
    for entry in WalkDir::new(staging.path()).sort_by_file_name() {
        let entry = entry.map_err(|error| io::Error::other(error.to_string()))?;
        let relative = entry
            .path()
            .strip_prefix(staging.path())
            .expect("walked bundle output is below staging");
        if relative.as_os_str().is_empty() || entry.file_type().is_dir() {
            continue;
        }
        if !entry.file_type().is_file()
            || !relative
                .components()
                .all(|component| matches!(component, Component::Normal(_)))
        {
            return Err(ArtifactError::InvalidManifest(
                "wasm-bindgen emitted a symlink or invalid output path".into(),
            ));
        }
        let relative = relative
            .to_str()
            .ok_or_else(|| {
                ArtifactError::InvalidManifest("wasm-bindgen emitted a non-UTF-8 path".into())
            })?
            .replace('\\', "/");
        if !folded.insert(relative.to_ascii_lowercase()) {
            return Err(ArtifactError::InvalidManifest(
                "wasm-bindgen output has a case-fold path collision".into(),
            ));
        }
        let kind = classify_output(&relative)?;
        let destination_relative = format!("bundle/{relative}");
        let destination = artifact_dir.join(&destination_relative);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(entry.path(), destination)?;
        records.push(artifact_record(artifact_dir, &destination_relative, kind)?);
    }
    records.sort_by(|left, right| left.path.cmp(&right.path));
    let paths: BTreeSet<_> = records.iter().map(|record| record.path.as_str()).collect();
    if !paths.contains("bundle/rust_agent.js")
        || !paths.contains("bundle/rust_agent_bg.wasm")
        || !paths.contains("bundle/rust_agent.d.ts")
    {
        return Err(ArtifactError::InvalidManifest(
            "wasm-bindgen bundle is missing its JS, transformed WASM, or TypeScript entry".into(),
        ));
    }
    let postprocessor = WasmPostprocessorManifest {
        schema: 1,
        logical_id: WASM_BINDGEN_CLI_LOGICAL_ID.into(),
        protocol_version: WASM_BINDGEN_PROTOCOL_VERSION.into(),
        executable_digest: executable.digest().into(),
        executable_version: executable.version().into(),
        invocation: normalized_invocation(),
        raw_input_digest: raw.digest.clone(),
        outputs: records.iter().map(|record| record.path.clone()).collect(),
    };
    let mut artifacts = vec![raw];
    artifacts.extend(records);
    artifacts.sort_by(|left, right| left.path.cmp(&right.path));
    Ok((artifacts, postprocessor))
}

pub(crate) fn classify_output(relative: &str) -> Result<DevelopmentArtifactKind, ArtifactError> {
    match relative {
        "rust_agent.js" => Ok(DevelopmentArtifactKind::JavaScriptLoader),
        "rust_agent_bg.wasm" => Ok(DevelopmentArtifactKind::TransformedWasm),
        value if value.ends_with(".d.ts") => Ok(DevelopmentArtifactKind::TypeScriptDeclaration),
        value
            if value.starts_with("snippets/")
                && Path::new(value).extension() == Some(std::ffi::OsStr::new("js"))
                && Path::new(value).components().count() >= 3 =>
        {
            Ok(DevelopmentArtifactKind::JavaScriptSnippet)
        }
        _ => Err(ArtifactError::InvalidManifest(format!(
            "wasm-bindgen emitted unsupported output `{relative}`"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_classifier_is_closed() {
        assert_eq!(
            classify_output("rust_agent.js").unwrap(),
            DevelopmentArtifactKind::JavaScriptLoader
        );
        assert_eq!(
            classify_output("rust_agent_bg.wasm.d.ts").unwrap(),
            DevelopmentArtifactKind::TypeScriptDeclaration
        );
        assert!(classify_output("package.json").is_err());
        assert!(classify_output("../escape.js").is_err());
    }

    #[test]
    fn protocol_lock_requires_each_exact_unique_crate_version() {
        let temp = TempDir::new().unwrap();
        let lock = temp.path().join("Cargo.lock");
        let entries = [
            ("wasm-bindgen", WASM_BINDGEN_PROTOCOL_VERSION),
            ("wasm-bindgen-macro", WASM_BINDGEN_PROTOCOL_VERSION),
            ("wasm-bindgen-macro-support", WASM_BINDGEN_PROTOCOL_VERSION),
            ("wasm-bindgen-shared", WASM_BINDGEN_PROTOCOL_VERSION),
            ("wasm-bindgen-futures", WASM_BINDGEN_FUTURES_VERSION),
        ];
        let encode = |entries: &[(&str, &str)]| {
            let mut input = String::new();
            for (name, version) in entries {
                input.push_str(&format!(
                    "[[package]]\nname = \"{name}\"\nversion = \"{version}\"\n\n"
                ));
            }
            input
        };

        let exact = encode(&entries);
        fs::write(&lock, &exact).unwrap();
        verify_protocol_lock(&lock).unwrap();

        fs::write(
            &lock,
            exact.replacen(WASM_BINDGEN_PROTOCOL_VERSION, "0.2.126", 1),
        )
        .unwrap();
        assert!(verify_protocol_lock(&lock).is_err());

        fs::write(&lock, encode(&entries[..entries.len() - 1])).unwrap();
        assert!(verify_protocol_lock(&lock).is_err());

        let mut duplicate = exact;
        duplicate.push_str(&encode(&entries[..1]));
        fs::write(&lock, duplicate).unwrap();
        assert!(verify_protocol_lock(&lock).is_err());
    }
}
