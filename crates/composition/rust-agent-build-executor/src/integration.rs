use std::{
    fs::{self, File, FileTimes},
    io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use rust_agent_composition::{CompositionManifest, verify_composition};
#[cfg(any(
    target_os = "android",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos"
))]
use rustix::fs::{CWD, RenameFlags, renameat_with};
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
    match fs::symlink_metadata(destination) {
        Ok(_) => return reuse_existing_integration(destination, &manifest),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
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
        let _ = remove_staging_tree(&staging);
        return Err(error);
    }
    verify_composition(&staging).map_err(|error| {
        let _ = remove_staging_tree(&staging);
        IntegrationError::Composition(error)
    })?;
    match publish_integration_noreplace(&staging, destination) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            remove_staging_tree(&staging)?;
            return reuse_existing_integration(destination, &manifest);
        }
        Err(error) => {
            remove_staging_tree(&staging)?;
            return Err(error.into());
        }
    }
    let published = verify_composition(destination)?;
    if published != manifest {
        return Err(IntegrationError::DestinationConflict(
            destination.display().to_string(),
        ));
    }
    Ok(manifest)
}

fn reuse_existing_integration(
    destination: &Path,
    expected: &CompositionManifest,
) -> Result<CompositionManifest, IntegrationError> {
    let existing = verify_composition(destination)
        .map_err(|_| IntegrationError::DestinationConflict(destination.display().to_string()))?;
    if &existing == expected {
        Ok(existing)
    } else {
        Err(IntegrationError::DestinationConflict(
            destination.display().to_string(),
        ))
    }
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
    let mut directories = Vec::new();
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
            fs::create_dir_all(&target)?;
            directories.push((target, metadata));
        } else if metadata.is_file() {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(entry.path(), &target)?;
            preserve_local_storage_projection(&target, &metadata)?;
        } else {
            return Err(IntegrationError::UnsupportedEntry(
                entry.path().display().to_string(),
            ));
        }
    }
    directories.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
    for (path, metadata) in directories {
        preserve_local_storage_projection(&path, &metadata)?;
    }
    Ok(())
}

fn preserve_local_storage_projection(path: &Path, source: &fs::Metadata) -> io::Result<()> {
    open_metadata_handle(path)?.set_times(FileTimes::new().set_modified(source.modified()?))?;
    fs::set_permissions(path, source.permissions())
}

#[cfg(windows)]
fn open_metadata_handle(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

    File::options()
        .access_mode(FILE_WRITE_ATTRIBUTES)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
}

#[cfg(not(windows))]
fn open_metadata_handle(path: &Path) -> io::Result<File> {
    File::open(path)
}

#[cfg(any(
    target_os = "android",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos"
))]
fn publish_integration_noreplace(source: &Path, destination: &Path) -> io::Result<()> {
    renameat_with(CWD, source, CWD, destination, RenameFlags::NOREPLACE)
        .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))
}

#[cfg(windows)]
fn publish_integration_noreplace(source: &Path, destination: &Path) -> io::Result<()> {
    renamore::rename_exclusive(source, destination)
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos",
    windows
)))]
fn publish_integration_noreplace(_source: &Path, _destination: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic no-clobber integration publication is unsupported on this Host",
    ))
}

fn remove_staging_tree(path: &Path) -> io::Result<()> {
    make_staging_tree_owner_writable(path)?;
    fs::remove_dir_all(path)
}

fn make_staging_tree_owner_writable(root: &Path) -> io::Result<()> {
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry.map_err(|error| io::Error::other(error.to_string()))?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        let mut permissions = metadata.permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let owner_access = if metadata.is_dir() { 0o700 } else { 0o600 };
            permissions.set_mode(permissions.mode() | owner_access);
        }
        #[cfg(not(unix))]
        permissions.set_readonly(false);
        fs::set_permissions(entry.path(), permissions)?;
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

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use tempfile::TempDir;

    use super::*;

    #[cfg(any(
        target_os = "android",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        windows
    ))]
    #[test]
    fn integration_publication_never_replaces_an_existing_empty_directory() {
        let temp = TempDir::new().unwrap();
        let staging = temp.path().join("staging");
        let destination = temp.path().join("destination");
        fs::create_dir(&staging).unwrap();
        fs::write(staging.join("source-marker"), b"source").unwrap();
        fs::create_dir(&destination).unwrap();

        let error = publish_integration_noreplace(&staging, &destination).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert!(fs::read_dir(&destination).unwrap().next().is_none());
        assert_eq!(fs::read(staging.join("source-marker")).unwrap(), b"source");
    }

    #[test]
    fn metadata_projection_opens_files_and_directories() {
        let temp = TempDir::new().unwrap();
        let source_directory = temp.path().join("source-directory");
        let target_directory = temp.path().join("target-directory");
        fs::create_dir(&source_directory).unwrap();
        fs::create_dir(&target_directory).unwrap();
        let source_file = temp.path().join("source-file");
        let target_file = temp.path().join("target-file");
        fs::write(&source_file, b"source").unwrap();
        fs::write(&target_file, b"target").unwrap();

        for (source, target) in [
            (&source_file, &target_file),
            (&source_directory, &target_directory),
        ] {
            preserve_local_storage_projection(target, &fs::metadata(source).unwrap()).unwrap();
            assert_eq!(
                fs::metadata(target).unwrap().modified().unwrap(),
                fs::metadata(source).unwrap().modified().unwrap()
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn readonly_integration_staging_cleanup_restores_owner_write() {
        let temp = TempDir::new().unwrap();
        let staging = temp.path().join("integration-staging");
        let nested = staging.join("sources/package/src");
        fs::create_dir_all(&nested).unwrap();
        let file = nested.join("lib.rs");
        fs::write(&file, b"pub fn fixture() {}\n").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o444)).unwrap();
        let package = staging.join("sources/package");
        let sources = staging.join("sources");
        for directory in [&nested, &package, &sources, &staging] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o555)).unwrap();
        }

        make_staging_tree_owner_writable(&staging).unwrap();
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o600,
            0o600
        );
        assert_eq!(
            fs::metadata(&nested).unwrap().permissions().mode() & 0o700,
            0o700
        );
        remove_staging_tree(&staging).unwrap();
        assert!(!staging.exists());
    }
}
