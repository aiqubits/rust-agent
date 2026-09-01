use std::{
    fs, io,
    path::{Path, PathBuf},
};

use thiserror::Error;

const CARGO_CONFIG_NAMES: [&str; 2] = ["config", "config.toml"];

#[derive(Debug, Error)]
pub enum CargoConfigIsolationError {
    #[error("Cargo discovery path must be absolute: {0}")]
    NonAbsolutePath(String),
    #[error("Cargo discovery path is not an existing directory: {0}")]
    NotDirectory(String),
    #[error("Cargo config isolation inspection failed for `{path}`: {source}")]
    Inspection {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error(
        "generated Cargo config must be the exact local `.cargo/config.toml` for `{working_directory}`: {actual}"
    )]
    UnexpectedGeneratedConfig {
        working_directory: String,
        actual: String,
    },
    #[error("generated Cargo config is not a real regular file: {0}")]
    InvalidGeneratedConfig(String),
    #[error("Cargo discovery directory is a symlink or unsupported entry: {0}")]
    UnsupportedCargoDirectory(String),
    #[error("ambient Cargo config would be merged into the controlled invocation: {0}")]
    AmbientConfig(String),
}

/// Reject Cargo configuration discoverable from a path that is about to become
/// part of a controlled Cargo working-directory ancestry.
///
/// The path itself may not exist yet. In that case, the nearest existing
/// directory and all of its physical ancestors are inspected.
pub(crate) fn reject_ambient_cargo_config_for_planned_path(
    path: &Path,
) -> Result<(), CargoConfigIsolationError> {
    require_absolute(path)?;
    let existing = nearest_existing_directory(path)?;
    inspect_discovery_chain(&existing, None)
}

/// Verify that Cargo can discover only the generated config owned by the
/// composition in `working_directory`.
///
/// Cargo merges `.cargo/config` and `.cargo/config.toml` found while walking
/// the current directory and its parents even when an explicit `--config` is
/// passed. This check allows the exact generated local `config.toml`, rejects
/// the legacy local spelling, and rejects both spellings in every ancestor.
pub fn verify_cargo_config_isolation(
    working_directory: &Path,
    generated_config: &Path,
) -> Result<(), CargoConfigIsolationError> {
    require_absolute(working_directory)?;
    require_absolute(generated_config)?;
    let working_directory = canonical_directory(working_directory)?;
    let expected = working_directory.join(".cargo/config.toml");
    let cargo_directory = working_directory.join(".cargo");
    let cargo_directory_metadata = symlink_metadata(&cargo_directory)?;
    if !cargo_directory_metadata.file_type().is_dir() {
        return Err(CargoConfigIsolationError::UnsupportedCargoDirectory(
            cargo_directory.display().to_string(),
        ));
    }
    let generated_metadata = symlink_metadata(&expected)?;
    if !generated_metadata.file_type().is_file() {
        return Err(CargoConfigIsolationError::InvalidGeneratedConfig(
            expected.display().to_string(),
        ));
    }
    if generated_config != expected {
        return Err(CargoConfigIsolationError::UnexpectedGeneratedConfig {
            working_directory: working_directory.display().to_string(),
            actual: generated_config.display().to_string(),
        });
    }
    let actual = canonical_path(generated_config)?;
    let expected_canonical = canonical_path(&expected)?;
    if actual != expected_canonical {
        return Err(CargoConfigIsolationError::UnexpectedGeneratedConfig {
            working_directory: working_directory.display().to_string(),
            actual: generated_config.display().to_string(),
        });
    }
    inspect_discovery_chain(&working_directory, Some(expected.as_path()))
}

fn inspect_discovery_chain(
    working_directory: &Path,
    allowed_local_config: Option<&Path>,
) -> Result<(), CargoConfigIsolationError> {
    for (index, directory) in working_directory.ancestors().enumerate() {
        let cargo_directory = directory.join(".cargo");
        match fs::symlink_metadata(&cargo_directory) {
            Ok(metadata) if !metadata.file_type().is_dir() => {
                return Err(CargoConfigIsolationError::UnsupportedCargoDirectory(
                    cargo_directory.display().to_string(),
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(source) => {
                return Err(CargoConfigIsolationError::Inspection {
                    path: cargo_directory.display().to_string(),
                    source,
                });
            }
        }
        for name in CARGO_CONFIG_NAMES {
            let candidate = cargo_directory.join(name);
            match fs::symlink_metadata(&candidate) {
                Ok(metadata) => {
                    let is_allowed = index == 0
                        && allowed_local_config.is_some_and(|allowed| allowed == candidate)
                        && name == "config.toml"
                        && metadata.file_type().is_file();
                    if !is_allowed {
                        return Err(CargoConfigIsolationError::AmbientConfig(
                            candidate.display().to_string(),
                        ));
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(CargoConfigIsolationError::Inspection {
                        path: candidate.display().to_string(),
                        source,
                    });
                }
            }
        }
    }
    Ok(())
}

fn nearest_existing_directory(path: &Path) -> Result<PathBuf, CargoConfigIsolationError> {
    for candidate in path.ancestors() {
        match fs::canonicalize(candidate) {
            Ok(canonical) => return canonical_directory(&canonical),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(CargoConfigIsolationError::Inspection {
                    path: candidate.display().to_string(),
                    source,
                });
            }
        }
    }
    Err(CargoConfigIsolationError::NotDirectory(
        path.display().to_string(),
    ))
}

fn require_absolute(path: &Path) -> Result<(), CargoConfigIsolationError> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(CargoConfigIsolationError::NonAbsolutePath(
            path.display().to_string(),
        ))
    }
}

fn canonical_directory(path: &Path) -> Result<PathBuf, CargoConfigIsolationError> {
    let canonical = canonical_path(path)?;
    if canonical.is_dir() {
        Ok(canonical)
    } else {
        Err(CargoConfigIsolationError::NotDirectory(
            path.display().to_string(),
        ))
    }
}

fn canonical_path(path: &Path) -> Result<PathBuf, CargoConfigIsolationError> {
    fs::canonicalize(path).map_err(|source| CargoConfigIsolationError::Inspection {
        path: path.display().to_string(),
        source,
    })
}

fn symlink_metadata(path: &Path) -> Result<fs::Metadata, CargoConfigIsolationError> {
    fs::symlink_metadata(path).map_err(|source| CargoConfigIsolationError::Inspection {
        path: path.display().to_string(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn exact_generated_config_is_the_only_allowed_discovered_config() {
        let temp = TempDir::new().unwrap();
        let working_directory = temp.path().join("composition");
        fs::create_dir_all(working_directory.join(".cargo")).unwrap();
        let generated = working_directory.join(".cargo/config.toml");
        fs::write(&generated, b"[net]\noffline = true\n").unwrap();

        verify_cargo_config_isolation(&working_directory, &generated).unwrap();

        fs::write(working_directory.join(".cargo/config"), b"[alias]\n").unwrap();
        assert!(matches!(
            verify_cargo_config_isolation(&working_directory, &generated),
            Err(CargoConfigIsolationError::AmbientConfig(path))
                if path.ends_with(".cargo/config")
        ));
    }

    #[test]
    fn both_ancestor_config_spellings_are_rejected_for_planned_paths() {
        for name in CARGO_CONFIG_NAMES {
            let temp = TempDir::new().unwrap();
            fs::create_dir(temp.path().join(".cargo")).unwrap();
            fs::write(temp.path().join(".cargo").join(name), b"[build]\n").unwrap();
            let planned = temp.path().join("not-yet-created/compositions");

            assert!(matches!(
                reject_ambient_cargo_config_for_planned_path(&planned),
                Err(CargoConfigIsolationError::AmbientConfig(path)) if path.ends_with(name)
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_generated_config_is_not_treated_as_owned() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let working_directory = temp.path().join("composition");
        fs::create_dir_all(working_directory.join(".cargo")).unwrap();
        let outside = temp.path().join("outside.toml");
        fs::write(&outside, b"[net]\noffline = true\n").unwrap();
        let generated = working_directory.join(".cargo/config.toml");
        symlink(outside, &generated).unwrap();

        assert!(matches!(
            verify_cargo_config_isolation(&working_directory, &generated),
            Err(CargoConfigIsolationError::InvalidGeneratedConfig(_))
        ));

        fs::remove_file(&generated).unwrap();
        fs::write(&generated, b"[net]\noffline = true\n").unwrap();
        let alias = temp.path().join("config-alias.toml");
        symlink(&generated, &alias).unwrap();
        assert!(matches!(
            verify_cargo_config_isolation(&working_directory, &alias),
            Err(CargoConfigIsolationError::UnexpectedGeneratedConfig { .. })
        ));
    }
}
