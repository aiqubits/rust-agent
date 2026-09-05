#![cfg(target_os = "linux")]

use std::{
    fs,
    io::{self, Write as _},
};

use flate2::{Compression, write::GzEncoder};
use git2::{IndexAddOption, Repository, Signature};
use rust_agent_build_executor::{
    CargoFetchCacheError, CargoFetchCacheLayout, CargoFetchCachePackageLocation,
    CargoPackageIdentity, CargoPackageSource, LockedSourceClosure, observe_cargo_fetch_cache,
};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

#[test]
fn registry_cache_observation_rederives_archive_and_extracted_tree() {
    let temp = TempDir::new().unwrap();
    let cache = temp.path().join("cargo-home");
    let archive_path = "registry/cache/index-fixture/demo-1.2.3.crate";
    let source_path = "registry/src/index-fixture/demo-1.2.3";
    fs::create_dir_all(cache.join("registry/cache/index-fixture")).unwrap();
    fs::create_dir_all(cache.join(source_path).join("src")).unwrap();
    fs::write(
        cache.join(source_path).join("Cargo.toml"),
        b"[package]\nname='demo'\nversion='1.2.3'\n",
    )
    .unwrap();
    fs::write(
        cache.join(source_path).join("src/lib.rs"),
        b"pub fn demo() {}\n",
    )
    .unwrap();
    fs::write(cache.join(source_path).join(".cargo-ok"), b"").unwrap();
    let archive = crate_archive();
    fs::write(cache.join(archive_path), &archive).unwrap();
    let checksum = hex::encode(Sha256::digest(&archive));
    let package = CargoPackageIdentity {
        name: "demo".into(),
        version: "1.2.3".into(),
        source: CargoPackageSource::Registry {
            registry: "https://index.crates.io/".into(),
            checksum,
        },
    };
    let locked = locked(package.clone());
    let layout = CargoFetchCacheLayout {
        schema: 1,
        packages: vec![CargoFetchCachePackageLocation {
            package,
            archive_path: Some(archive_path.into()),
            source_path: Some(source_path.into()),
        }],
    };

    let observed = observe_cargo_fetch_cache(&cache, &locked, &layout).unwrap();
    assert_eq!(observed.evidence().packages.len(), 1);
    assert_eq!(observed.tree().digest().len(), 64);

    fs::write(
        cache.join(source_path).join("src/lib.rs"),
        b"pub fn tampered() {}\n",
    )
    .unwrap();
    assert!(matches!(
        observe_cargo_fetch_cache(&cache, &locked, &layout),
        Err(CargoFetchCacheError::SourceTreeMismatch(_))
    ));
}

#[test]
fn git_cache_observation_rederives_commit_tree_and_rejects_drift() {
    let temp = TempDir::new().unwrap();
    let cache = temp.path().join("cargo-home");
    let source_path = "git/checkouts/demo-fixture/0123456";
    let checkout = cache.join(source_path);
    fs::create_dir_all(&checkout).unwrap();
    fs::write(checkout.join("Cargo.toml"), b"[package]\n").unwrap();
    let repository = Repository::init(&checkout).unwrap();
    repository
        .remote("origin", "https://example.invalid/demo")
        .unwrap();
    let mut index = repository.index().unwrap();
    index
        .add_all(["Cargo.toml"], IndexAddOption::DEFAULT, None)
        .unwrap();
    index.write().unwrap();
    let tree_id = index.write_tree().unwrap();
    let tree = repository.find_tree(tree_id).unwrap();
    let signature = Signature::now("rust-agent", "fixture@example.invalid").unwrap();
    let commit = repository
        .commit(Some("HEAD"), &signature, &signature, "fixture", &tree, &[])
        .unwrap();
    let precise = commit.to_string();
    drop(tree);
    drop(repository);
    let package = CargoPackageIdentity {
        name: "demo-git".into(),
        version: "0.1.0".into(),
        source: CargoPackageSource::Git {
            repository: "https://example.invalid/demo".into(),
            precise: precise.clone(),
        },
    };
    let locked = locked(package.clone());
    let layout = CargoFetchCacheLayout {
        schema: 1,
        packages: vec![CargoFetchCachePackageLocation {
            package,
            archive_path: None,
            source_path: Some(source_path.into()),
        }],
    };
    observe_cargo_fetch_cache(&cache, &locked, &layout).unwrap();

    fs::write(checkout.join("Cargo.toml"), b"[package]\nname='drift'\n").unwrap();
    assert!(matches!(
        observe_cargo_fetch_cache(&cache, &locked, &layout),
        Err(CargoFetchCacheError::SourceTreeMismatch(_))
    ));

    fs::write(checkout.join("Cargo.toml"), b"[package]\n").unwrap();
    let repository = Repository::open(&checkout).unwrap();
    repository
        .remote_set_url("origin", "https://attacker.invalid/demo")
        .unwrap();
    drop(repository);
    assert!(matches!(
        observe_cargo_fetch_cache(&cache, &locked, &layout),
        Err(CargoFetchCacheError::InvalidGitCheckout { .. })
    ));
}

fn locked(
    package: CargoPackageIdentity,
) -> rust_agent_build_executor::NormalizedLockedSourceClosure {
    LockedSourceClosure {
        schema: 1,
        cargo_lock_digest: "a".repeat(64),
        packages: vec![package],
    }
    .normalize()
    .unwrap()
}

fn crate_archive() -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = tar::Builder::new(encoder);
    append(
        &mut archive,
        "demo-1.2.3/Cargo.toml",
        b"[package]\nname='demo'\nversion='1.2.3'\n",
    );
    append(&mut archive, "demo-1.2.3/src/lib.rs", b"pub fn demo() {}\n");
    append_directory(&mut archive, "demo-1.2.3/src/");
    let encoder = archive.into_inner().unwrap();
    encoder.finish().unwrap()
}

fn append_directory(archive: &mut tar::Builder<GzEncoder<Vec<u8>>>, path: &str) {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Directory);
    header.set_mode(0o755);
    header.set_size(0);
    header.set_cksum();
    archive.append_data(&mut header, path, io::empty()).unwrap();
}

fn append(archive: &mut tar::Builder<GzEncoder<Vec<u8>>>, path: &str, bytes: &[u8]) {
    let mut header = tar::Header::new_gnu();
    header.set_mode(0o644);
    header.set_size(bytes.len() as u64);
    header.set_cksum();
    archive.append_data(&mut header, path, bytes).unwrap();
    archive.get_mut().flush().unwrap();
}
