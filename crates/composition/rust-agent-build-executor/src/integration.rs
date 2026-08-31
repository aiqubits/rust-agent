use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use rust_agent_composition::{CompositionManifest, verify_composition};
use thiserror::Error;
use walkdir::WalkDir;

use crate::topology::{HostIntegrationTopology, HostTopologyError, verify_host_topology};

static EMIT_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Error)]
pub enum IntegrationError {
    #[error("integration paths must be absolute: {0}")]
    NonAbsolutePath(String),
    #[error("composition verification failed: {0}")]
    Composition(#[from] rust_agent_composition::ComposeError),
    #[error("integration destination already contains a different tree: {0}")]
    DestinationConflict(String),
    #[error("development composition requires --allow-development")]
    DevelopmentNotAllowed,
    #[error("Host topology verification failed: {0}")]
    HostTopology(#[from] HostTopologyError),
    #[error("integration tree contains a symlink or unsupported file: {0}")]
    UnsupportedEntry(String),
    #[error("I/O failed during integration emission: {0}")]
    Io(#[from] io::Error),
}

pub fn emit_integration(
    source: &Path,
    destination: &Path,
) -> Result<CompositionManifest, IntegrationError> {
    validate_absolute(source)?;
    validate_absolute(destination)?;
    let manifest = verify_composition(source)?;
    if destination.exists() {
        let existing = verify_composition(destination).map_err(|_| {
            IntegrationError::DestinationConflict(destination.display().to_string())
        })?;
        if existing == manifest {
            return Ok(manifest);
        }
        return Err(IntegrationError::DestinationConflict(
            destination.display().to_string(),
        ));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| IntegrationError::NonAbsolutePath(destination.display().to_string()))?;
    fs::create_dir_all(parent)?;
    let name = destination
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("integration");
    let staging = parent.join(format!(
        ".{name}.staging-{}-{}",
        std::process::id(),
        EMIT_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&staging)?;
    if let Err(error) = copy_tree(source, &staging) {
        let _ = fs::remove_dir_all(&staging);
        return Err(error);
    }
    verify_composition(&staging).map_err(|error| {
        let _ = fs::remove_dir_all(&staging);
        IntegrationError::Composition(error)
    })?;
    fs::rename(&staging, destination)?;
    verify_composition(destination)?;
    Ok(manifest)
}

pub fn verify_integration(
    destination: &Path,
    allow_development: bool,
) -> Result<CompositionManifest, IntegrationError> {
    validate_absolute(destination)?;
    let manifest = verify_composition(destination)?;
    if !allow_development && !manifest.deployable {
        return Err(IntegrationError::DevelopmentNotAllowed);
    }
    Ok(manifest)
}

pub fn verify_integration_topology(
    destination: &Path,
    allow_development: bool,
    topology: HostIntegrationTopology,
) -> Result<CompositionManifest, IntegrationError> {
    let manifest = verify_integration(destination, allow_development)?;
    verify_host_topology(&manifest, topology)?;
    Ok(manifest)
}

fn copy_tree(source: &Path, destination: &Path) -> Result<(), IntegrationError> {
    for entry in WalkDir::new(source).sort_by_file_name() {
        let entry = entry.map_err(|error| io::Error::other(error.to_string()))?;
        let relative = entry
            .path()
            .strip_prefix(source)
            .expect("walked path is below source");
        if relative.as_os_str().is_empty() {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() {
            return Err(IntegrationError::UnsupportedEntry(
                entry.path().display().to_string(),
            ));
        }
        let target = destination.join(relative);
        if metadata.is_dir() {
            fs::create_dir_all(target)?;
        } else if metadata.is_file() {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(entry.path(), target)?;
        } else {
            return Err(IntegrationError::UnsupportedEntry(
                entry.path().display().to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_absolute(path: &Path) -> Result<(), IntegrationError> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(IntegrationError::NonAbsolutePath(
            path.display().to_string(),
        ))
    }
}

#[allow(dead_code)]
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    path.parent().unwrap_or_else(|| Path::new("/")).join(suffix)
}
