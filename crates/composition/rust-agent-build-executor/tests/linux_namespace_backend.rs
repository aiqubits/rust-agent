#![cfg(target_os = "linux")]

use std::{
    collections::BTreeMap,
    fs,
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream, ToSocketAddrs as _, UdpSocket},
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    os::unix::net::{UnixDatagram, UnixStream},
    path::Path,
    process::Command,
};

use rust_agent_build_executor::{
    LinuxSandboxAnonymousSocketpair, LinuxSandboxBackendIdentity, LinuxSandboxCommand,
    LinuxSandboxEnforcement, LinuxSandboxMountKind, LinuxSandboxNetworkPolicy,
    LinuxSandboxReadOnlyMount, LinuxSandboxResolvedEndpoint, LinuxSandboxRuntimeIdentity,
    LinuxSandboxRuntimeSymlink, LinuxSandboxWritableMount, ProductionToolIdentity,
    ProductionTreeIdentity, VerifiedLinuxSandboxBackend,
};
use rust_agent_composition::snapshot::{CanonicalSnapshotEntry, CanonicalSnapshotTree};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;
use walkdir::WalkDir;

#[test]
#[ignore = "requires a real Linux user/mount/network namespace runner"]
fn runtime_null_input_is_identity_bound_and_host_devices_remain_hidden() {
    const MARKER: &str = "RUST_AGENT_REAL_NAMESPACE_CHILD";
    if std::env::var_os(MARKER).is_some() {
        let file = fs::metadata("/rust-agent/input/value.txt").unwrap();
        assert_eq!(file.mode() & 0o7777, 0o444);
        assert_eq!(file.uid(), 0);
        assert_eq!(file.gid(), 0);
        assert_eq!(file.atime(), 0);
        assert_eq!(file.mtime(), 0);
        assert_eq!(file.ctime(), 0);
        assert_eq!(file.nlink(), 1);
        assert_eq!(file.dev(), 0);
        assert_eq!(file.ino(), 0);
        let directory = fs::metadata("/rust-agent/input").unwrap();
        assert_eq!(directory.mode() & 0o7777, 0o555);
        let null = fs::metadata("/dev/null").unwrap();
        assert!(null.is_file());
        assert_eq!(null.len(), 0);
        assert!(fs::read("/dev/null").unwrap().is_empty());
        assert!(fs::metadata("/dev/zero").is_err());
        return;
    }

    let temp = TempDir::new().unwrap();
    let launcher = Path::new(env!("CARGO_BIN_EXE_rust-agent-linux-sandbox-launcher"));
    let test_executable = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
    let backend_path = Path::new("/usr/bin/bwrap");
    let runtime = temp.path().join("runtime");
    let input = temp.path().join("input");
    fs::create_dir(&runtime).unwrap();
    fs::create_dir(&input).unwrap();
    fs::write(input.join("value.txt"), b"mounted-view\n").unwrap();
    fs::set_permissions(input.join("value.txt"), fs::Permissions::from_mode(0o600)).unwrap();
    let (runtime_symlinks, loader_paths) = copy_dynamic_runtime(&test_executable, &runtime);
    let runtime_tree = canonical_tree(&runtime);
    let input_tree = canonical_tree(&input);

    let backend = VerifiedLinuxSandboxBackend::open(LinuxSandboxBackendIdentity {
        schema: 1,
        executable: ProductionToolIdentity {
            path: backend_path.into(),
            sha256: sha256_file(backend_path),
            version: first_stdout_line(backend_path, &["--version"]),
        },
        launcher_executable: ProductionToolIdentity {
            path: launcher.into(),
            sha256: sha256_file(launcher),
            version: "rust-agent-linux-sandbox-launcher 3".into(),
        },
        runtime: LinuxSandboxRuntimeIdentity {
            tree: ProductionTreeIdentity {
                path: runtime.clone(),
                tree_digest: runtime_tree.digest().into(),
            },
            logical_path: "/rust-agent/runtime".into(),
            interpreter_paths: loader_paths,
            library_paths: vec![],
            null_input_path: "/rust-agent/runtime/empty-stdin".into(),
            symlinks: runtime_symlinks,
        },
    })
    .unwrap();
    let input_mount = LinuxSandboxReadOnlyMount::verified_tree(
        "build-input",
        LinuxSandboxMountKind::BuildReadInput,
        &input,
        "/rust-agent/input",
        input_tree.digest(),
    )
    .unwrap();
    let executable_mount = LinuxSandboxReadOnlyMount::verified_file(
        "namespace-test",
        LinuxSandboxMountKind::BuildExecutable,
        &test_executable,
        "/rust-agent/tools/namespace-test",
        &sha256_file(&test_executable),
        true,
    )
    .unwrap();
    let mut allowed_executables = vec!["/rust-agent/tools/namespace-test".into()];
    allowed_executables.sort();
    allowed_executables.dedup();
    let observation = backend
        .run(
            &LinuxSandboxCommand {
                schema: 3,
                executable: "/rust-agent/tools/namespace-test".into(),
                arguments: vec![
                    "--ignored".into(),
                    "--exact".into(),
                    "runtime_null_input_is_identity_bound_and_host_devices_remain_hidden".into(),
                    "--test-threads=1".into(),
                ],
                environment: BTreeMap::from([
                    ("LANG".into(), "C.UTF-8".into()),
                    ("LC_ALL".into(), "C.UTF-8".into()),
                    (MARKER.into(), "1".into()),
                    ("SOURCE_DATE_EPOCH".into(), "0".into()),
                ]),
                working_directory: "/rust-agent/input".into(),
                allowed_executables,
                anonymous_socketpairs: vec![LinuxSandboxAnonymousSocketpair::StreamWakeup],
                read_only_empty_directories: vec![],
                network: LinuxSandboxNetworkPolicy::Isolated,
                timeout_milliseconds: 10_000,
            },
            vec![input_mount, executable_mount],
            vec![],
        )
        .unwrap();

    assert_eq!(observation.exit_code, 0);
    assert_eq!(observation.executed_commands.len(), 1);
    assert_eq!(
        observation.executed_commands[0].executable,
        "/rust-agent/tools/namespace-test"
    );
    assert_eq!(
        observation.executed_commands[0].executable_sha256,
        sha256_file(&test_executable)
    );
    assert_eq!(
        observation.canonical_metadata_roots,
        vec!["/rust-agent/input"]
    );
    assert_eq!(
        observation.enforcements,
        vec![
            LinuxSandboxEnforcement::AllNamespacesUnshared,
            LinuxSandboxEnforcement::CanonicalMetadataProjected,
            LinuxSandboxEnforcement::CapabilitiesDropped,
            LinuxSandboxEnforcement::DescendantsInheritSandbox,
            LinuxSandboxEnforcement::EnvironmentCleared,
            LinuxSandboxEnforcement::ExecveSupervised,
            LinuxSandboxEnforcement::FilesystemPolicyFullyEnforced,
            LinuxSandboxEnforcement::NetworkUnshared,
            LinuxSandboxEnforcement::StandardInputDisconnected,
            LinuxSandboxEnforcement::SyscallFilterEnforced,
        ]
    );
}

#[test]
#[ignore = "requires the real Linux user/mount/network namespace runner"]
fn descendant_escape_matrix_denies_ambient_host_surfaces_and_preserves_declared_inputs() {
    const MARKER: &str = "RUST_AGENT_DESCENDANT_ESCAPE_CHILD";
    const LOADER: &str = "RUST_AGENT_DESCENDANT_ESCAPE_LOADER";
    if let Some(marker) = std::env::var_os(MARKER) {
        assert_eq!(
            fs::read("/rust-agent/sdk/input.txt").unwrap(),
            b"declared-sdk\n"
        );
        for variable in [
            "HOME",
            "CARGO_HOME",
            "RUSTFLAGS",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "AWS_SECRET_ACCESS_KEY",
        ] {
            assert!(
                std::env::var_os(variable).is_none(),
                "ambient {variable} leaked"
            );
        }
        assert!(fs::read("/root/.ssh/id_ed25519").is_err());
        assert!(fs::read("/proc/self/status").is_err());
        assert!(fs::read("/sys/kernel/security/landlock").is_err());
        assert!(fs::read("/dev/zero").is_err());
        assert!(fs::write("/rust-agent/sdk/denied.txt", b"denied").is_err());
        assert!(fs::write("/tmp/denied.txt", b"denied").is_err());
        assert!(fs::write("/root/denied.txt", b"denied").is_err());
        assert_eq!(
            TcpStream::connect(("127.0.0.1", 9))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EPERM)
        );
        assert_eq!(
            UdpSocket::bind(("127.0.0.1", 0))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EPERM)
        );
        UnixStream::pair().unwrap();
        assert_eq!(
            UnixStream::connect("/rust-agent/output/forbidden.sock")
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EPERM)
        );
        assert_eq!(
            nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWUSER).unwrap_err(),
            nix::errno::Errno::EPERM
        );
        assert_eq!(
            rustix::mount::mount(
                "none",
                "/rust-agent/output",
                "tmpfs",
                rustix::mount::MountFlags::empty(),
                None::<&std::ffi::CStr>,
            )
            .unwrap_err(),
            rustix::io::Errno::PERM
        );
        assert_eq!(
            rustix::process::pivot_root("/rust-agent/output", "/rust-agent/output").unwrap_err(),
            rustix::io::Errno::PERM
        );
        assert_eq!(
            nix::sys::ptrace::traceme().unwrap_err(),
            nix::errno::Errno::EPERM
        );
        assert!(Command::new("/usr/bin/id").status().is_err());
        let loader = std::env::var(LOADER).unwrap();
        assert!(
            Command::new(loader)
                .arg("/rust-agent/tools/escape-test")
                .status()
                .is_err()
        );
        if marker == "root" {
            fs::write("/rust-agent/output/root.txt", b"root\n").unwrap();
            let status = Command::new("/rust-agent/tools/escape-test")
                .args([
                    "--ignored",
                    "--exact",
                    "descendant_escape_matrix_denies_ambient_host_surfaces_and_preserves_declared_inputs",
                    "--test-threads=1",
                ])
                .env(MARKER, "descendant")
                .status()
                .unwrap();
            assert!(status.success());
        } else {
            assert_eq!(marker, "descendant");
            fs::write("/rust-agent/output/descendant.txt", b"descendant\n").unwrap();
        }
        return;
    }

    let temp = TempDir::new().unwrap();
    let launcher = Path::new(env!("CARGO_BIN_EXE_rust-agent-linux-sandbox-launcher"));
    let test_executable = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
    let backend_path = Path::new("/usr/bin/bwrap");
    let runtime = temp.path().join("runtime");
    let input = temp.path().join("input");
    let output = temp.path().join("output");
    fs::create_dir(&runtime).unwrap();
    fs::create_dir(&input).unwrap();
    fs::create_dir(&output).unwrap();
    fs::write(input.join("input.txt"), b"declared-sdk\n").unwrap();
    let (runtime_symlinks, loader_paths) = copy_dynamic_runtime(&test_executable, &runtime);
    let loader = loader_paths.first().unwrap().clone();
    let runtime_tree = canonical_tree(&runtime);
    let input_tree = canonical_tree(&input);
    let backend = VerifiedLinuxSandboxBackend::open(LinuxSandboxBackendIdentity {
        schema: 1,
        executable: ProductionToolIdentity {
            path: backend_path.into(),
            sha256: sha256_file(backend_path),
            version: first_stdout_line(backend_path, &["--version"]),
        },
        launcher_executable: ProductionToolIdentity {
            path: launcher.into(),
            sha256: sha256_file(launcher),
            version: "rust-agent-linux-sandbox-launcher 3".into(),
        },
        runtime: LinuxSandboxRuntimeIdentity {
            tree: ProductionTreeIdentity {
                path: runtime,
                tree_digest: runtime_tree.digest().into(),
            },
            logical_path: "/rust-agent/runtime".into(),
            interpreter_paths: loader_paths,
            library_paths: vec![],
            null_input_path: "/rust-agent/runtime/empty-stdin".into(),
            symlinks: runtime_symlinks,
        },
    })
    .unwrap();
    let input_mount = LinuxSandboxReadOnlyMount::verified_tree(
        "declared-sdk",
        LinuxSandboxMountKind::BuildReadInput,
        &input,
        "/rust-agent/sdk",
        input_tree.digest(),
    )
    .unwrap();
    let executable_mount = LinuxSandboxReadOnlyMount::verified_file(
        "escape-test",
        LinuxSandboxMountKind::BuildExecutable,
        &test_executable,
        "/rust-agent/tools/escape-test",
        &sha256_file(&test_executable),
        true,
    )
    .unwrap();
    let output_mount =
        LinuxSandboxWritableMount::open("escape-output", &output, "/rust-agent/output", false)
            .unwrap();
    let execution = backend
        .run_with_output(
            &LinuxSandboxCommand {
                schema: 3,
                executable: "/rust-agent/tools/escape-test".into(),
                arguments: vec![
                    "--ignored".into(),
                    "--exact".into(),
                    "descendant_escape_matrix_denies_ambient_host_surfaces_and_preserves_declared_inputs".into(),
                    "--test-threads=1".into(),
                ],
                environment: BTreeMap::from([
                    ("LANG".into(), "C.UTF-8".into()),
                    ("LC_ALL".into(), "C.UTF-8".into()),
                    (LOADER.into(), loader),
                    (MARKER.into(), "root".into()),
                    ("SOURCE_DATE_EPOCH".into(), "0".into()),
                ]),
                working_directory: "/rust-agent/sdk".into(),
                allowed_executables: vec!["/rust-agent/tools/escape-test".into()],
                anonymous_socketpairs: vec![
                    LinuxSandboxAnonymousSocketpair::StreamWakeup,
                    LinuxSandboxAnonymousSocketpair::RustSpawnError,
                ],
                read_only_empty_directories: vec![],
                network: LinuxSandboxNetworkPolicy::Isolated,
                timeout_milliseconds: 20_000,
            },
            vec![input_mount, executable_mount],
            vec![output_mount],
        )
        .unwrap();
    assert_eq!(
        execution.observation().exit_code,
        0,
        "stdout={} stderr={}",
        String::from_utf8_lossy(execution.stdout()),
        String::from_utf8_lossy(execution.stderr()),
    );
    assert_eq!(execution.observation().executed_commands.len(), 2);
    assert_eq!(fs::read(output.join("root.txt")).unwrap(), b"root\n");
    assert_eq!(
        fs::read(output.join("descendant.txt")).unwrap(),
        b"descendant\n"
    );
    assert!(!input.join("denied.txt").exists());
}

#[test]
#[ignore = "requires a real Linux user/mount namespace runner with shared network access"]
fn network_escape_matrix_denies_dns_udp_unix_listen_and_unlisted_tcp() {
    const MARKER: &str = "RUST_AGENT_REAL_NETWORK_CHILD";
    const ALLOWED_PORT: &str = "RUST_AGENT_REAL_NETWORK_ALLOWED_PORT";
    const ALLOWED_V6_PORT: &str = "RUST_AGENT_REAL_NETWORK_ALLOWED_V6_PORT";
    const DENIED_PORT: &str = "RUST_AGENT_REAL_NETWORK_DENIED_PORT";
    if std::env::var_os(MARKER).is_some() {
        let allowed_port = std::env::var(ALLOWED_PORT).unwrap().parse::<u16>().unwrap();
        let allowed_v6_port = std::env::var(ALLOWED_V6_PORT)
            .unwrap()
            .parse::<u16>()
            .unwrap();
        let denied_port = std::env::var(DENIED_PORT).unwrap().parse::<u16>().unwrap();
        assert_eq!(
            fs::read_to_string("/etc/hosts").unwrap(),
            "127.0.0.1\tindex.crates.io\n"
        );
        assert_eq!(
            fs::read_to_string("/etc/nsswitch.conf").unwrap(),
            "hosts: files\n"
        );
        assert_eq!(fs::read_to_string("/etc/host.conf").unwrap(), "multi on\n");
        assert_eq!(fs::read_to_string("/etc/resolv.conf").unwrap(), "");
        let resolved = ("index.crates.io", allowed_port)
            .to_socket_addrs()
            .unwrap()
            .collect::<Vec<_>>();
        assert!(!resolved.is_empty());
        assert!(resolved.iter().all(|address| {
            address.ip() == "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
                && address.port() == allowed_port
        }));
        TcpStream::connect(("127.0.0.1", allowed_port)).unwrap();
        TcpStream::connect(("::1", allowed_v6_port)).unwrap();
        assert_eq!(
            TcpStream::connect(("127.0.0.1", denied_port))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EPERM)
        );
        assert_eq!(
            UdpSocket::bind(("127.0.0.1", 0))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EPERM)
        );
        let (mut wake_reader, mut wake_writer) = UnixStream::pair().unwrap();
        wake_writer.write_all(b"w").unwrap();
        let mut wake = [0_u8; 1];
        wake_reader.read_exact(&mut wake).unwrap();
        assert_eq!(wake, *b"w");
        assert_eq!(
            UnixStream::connect("/rust-agent/runtime/forbidden.sock")
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EPERM)
        );
        assert_eq!(
            UnixDatagram::unbound().unwrap_err().raw_os_error(),
            Some(libc::EPERM)
        );
        assert_eq!(
            rustix::net::socketpair(
                rustix::net::AddressFamily::UNIX,
                rustix::net::SocketType::DGRAM,
                rustix::net::SocketFlags::empty(),
                None,
            )
            .unwrap_err(),
            rustix::io::Errno::PERM
        );
        assert_eq!(
            TcpListener::bind(("127.0.0.1", 0))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EPERM)
        );
        assert_eq!(
            rustix::net::socket(
                rustix::net::AddressFamily::INET,
                rustix::net::SocketType::RAW,
                Some(rustix::net::ipproto::RAW),
            )
            .unwrap_err(),
            rustix::io::Errno::PERM
        );
        assert_eq!(
            rustix::net::socket(
                rustix::net::AddressFamily::NETLINK,
                rustix::net::SocketType::RAW,
                None,
            )
            .unwrap_err(),
            rustix::io::Errno::PERM
        );
        assert!(("unlisted.invalid", 443).to_socket_addrs().is_err());
        let mut bytes = Vec::new();
        std::io::stdin().read_to_end(&mut bytes).unwrap();
        assert!(bytes.is_empty());
        return;
    }

    let allowed = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let allowed_v6 = TcpListener::bind(("::1", 0)).unwrap();
    let denied = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let allowed_port = allowed.local_addr().unwrap().port();
    let allowed_v6_port = allowed_v6.local_addr().unwrap().port();
    let denied_port = denied.local_addr().unwrap().port();
    let temp = TempDir::new().unwrap();
    let launcher = Path::new(env!("CARGO_BIN_EXE_rust-agent-linux-sandbox-launcher"));
    let test_executable = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
    let backend_path = Path::new("/usr/bin/bwrap");
    let runtime = temp.path().join("runtime");
    fs::create_dir(&runtime).unwrap();
    let (runtime_symlinks, loader_paths) = copy_dynamic_runtime(&test_executable, &runtime);
    let runtime_tree = canonical_tree(&runtime);
    let network_configuration = temp.path().join("network-configuration");
    fs::create_dir(&network_configuration).unwrap();
    let hosts = b"127.0.0.1\tindex.crates.io\n";
    let host_conf = b"multi on\n";
    let nsswitch = b"hosts: files\n";
    let resolv = b"";
    fs::write(network_configuration.join("hosts"), hosts).unwrap();
    fs::write(network_configuration.join("host.conf"), host_conf).unwrap();
    fs::write(network_configuration.join("nsswitch.conf"), nsswitch).unwrap();
    fs::write(network_configuration.join("resolv.conf"), resolv).unwrap();
    let backend = VerifiedLinuxSandboxBackend::open(LinuxSandboxBackendIdentity {
        schema: 1,
        executable: ProductionToolIdentity {
            path: backend_path.into(),
            sha256: sha256_file(backend_path),
            version: first_stdout_line(backend_path, &["--version"]),
        },
        launcher_executable: ProductionToolIdentity {
            path: launcher.into(),
            sha256: sha256_file(launcher),
            version: "rust-agent-linux-sandbox-launcher 3".into(),
        },
        runtime: LinuxSandboxRuntimeIdentity {
            tree: ProductionTreeIdentity {
                path: runtime,
                tree_digest: runtime_tree.digest().into(),
            },
            logical_path: "/rust-agent/runtime".into(),
            interpreter_paths: loader_paths,
            library_paths: vec![],
            null_input_path: "/rust-agent/runtime/empty-stdin".into(),
            symlinks: runtime_symlinks,
        },
    })
    .unwrap();
    let executable_mount = LinuxSandboxReadOnlyMount::verified_file(
        "network-test",
        LinuxSandboxMountKind::BuildExecutable,
        &test_executable,
        "/rust-agent/tools/network-test",
        &sha256_file(&test_executable),
        true,
    )
    .unwrap();
    let host_conf_mount = LinuxSandboxReadOnlyMount::verified_file(
        "network-host-conf",
        LinuxSandboxMountKind::NetworkConfiguration,
        &network_configuration.join("host.conf"),
        "/etc/host.conf",
        &sha256(host_conf),
        false,
    )
    .unwrap();
    let hosts_mount = LinuxSandboxReadOnlyMount::verified_file(
        "network-hosts",
        LinuxSandboxMountKind::NetworkConfiguration,
        &network_configuration.join("hosts"),
        "/etc/hosts",
        &sha256(hosts),
        false,
    )
    .unwrap();
    let resolv_mount = LinuxSandboxReadOnlyMount::verified_file(
        "network-resolv",
        LinuxSandboxMountKind::NetworkConfiguration,
        &network_configuration.join("resolv.conf"),
        "/etc/resolv.conf",
        &sha256(resolv),
        false,
    )
    .unwrap();
    let nsswitch_mount = LinuxSandboxReadOnlyMount::verified_file(
        "network-nsswitch",
        LinuxSandboxMountKind::NetworkConfiguration,
        &network_configuration.join("nsswitch.conf"),
        "/etc/nsswitch.conf",
        &sha256(nsswitch),
        false,
    )
    .unwrap();
    let execution = backend
        .run_with_output(
            &LinuxSandboxCommand {
                schema: 3,
                executable: "/rust-agent/tools/network-test".into(),
                arguments: vec![
                    "--ignored".into(),
                    "--exact".into(),
                    "network_escape_matrix_denies_dns_udp_unix_listen_and_unlisted_tcp".into(),
                    "--test-threads=1".into(),
                ],
                environment: BTreeMap::from([
                    ("LANG".into(), "C.UTF-8".into()),
                    ("LC_ALL".into(), "C.UTF-8".into()),
                    (MARKER.into(), "1".into()),
                    (ALLOWED_PORT.into(), allowed_port.to_string()),
                    (ALLOWED_V6_PORT.into(), allowed_v6_port.to_string()),
                    (DENIED_PORT.into(), denied_port.to_string()),
                    ("SOURCE_DATE_EPOCH".into(), "0".into()),
                ]),
                working_directory: "/rust-agent/runtime".into(),
                allowed_executables: vec!["/rust-agent/tools/network-test".into()],
                anonymous_socketpairs: vec![LinuxSandboxAnonymousSocketpair::StreamWakeup],
                read_only_empty_directories: vec![],
                network: LinuxSandboxNetworkPolicy::EndpointAllowlist {
                    endpoints: vec![
                        LinuxSandboxResolvedEndpoint {
                            origin: format!("https://127.0.0.1:{allowed_port}"),
                            host: "127.0.0.1".into(),
                            port: allowed_port,
                            addresses: vec!["127.0.0.1".parse().unwrap()],
                        },
                        LinuxSandboxResolvedEndpoint {
                            origin: format!("https://[::1]:{allowed_v6_port}"),
                            host: "::1".into(),
                            port: allowed_v6_port,
                            addresses: vec!["::1".parse().unwrap()],
                        },
                    ],
                },
                timeout_milliseconds: 10_000,
            },
            vec![
                executable_mount,
                host_conf_mount,
                hosts_mount,
                nsswitch_mount,
                resolv_mount,
            ],
            vec![],
        )
        .unwrap();
    let observation = execution.observation();
    assert_eq!(
        observation.exit_code,
        0,
        "stdout={} stderr={}",
        String::from_utf8_lossy(execution.stdout()),
        String::from_utf8_lossy(execution.stderr())
    );
    assert!(
        observation
            .enforcements
            .contains(&LinuxSandboxEnforcement::NetworkEndpointAllowlistEnforced)
    );
    assert!(
        !observation
            .enforcements
            .contains(&LinuxSandboxEnforcement::NetworkUnshared)
    );
}

fn copy_dynamic_runtime(
    executable: &Path,
    output: &Path,
) -> (Vec<LinuxSandboxRuntimeSymlink>, Vec<String>) {
    fs::write(output.join("empty-stdin"), []).unwrap();
    let result = Command::new("ldd").arg(executable).output().unwrap();
    assert!(result.status.success());
    let stdout = String::from_utf8(result.stdout).unwrap();
    let mut sources = Vec::new();
    let mut loaders = Vec::new();
    for line in stdout.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let source = fields
            .windows(2)
            .find(|pair| pair[0] == "=>" && pair[1].starts_with('/'))
            .map(|pair| pair[1])
            .or_else(|| fields.first().copied().filter(|path| path.starts_with('/')));
        let Some(source) = source else {
            continue;
        };
        if !line.contains("=>") {
            loaders.push(source.to_owned());
        }
        sources.push(source.to_owned());
    }
    let libc = sources
        .iter()
        .find(|source| {
            Path::new(source)
                .file_name()
                .is_some_and(|name| name == "libc.so.6")
        })
        .expect("the Linux test runtime includes libc");
    let nss_files = Path::new(libc).with_file_name("libnss_files.so.2");
    assert!(
        nss_files.is_file(),
        "the Phase 1B Linux runner requires a digest-bound files-only NSS module"
    );
    sources.push(nss_files.to_str().unwrap().into());
    sources.sort();
    sources.dedup();
    for source in &sources {
        let relative = source.strip_prefix('/').unwrap();
        let destination = output.join(relative);
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::copy(source, destination).unwrap();
    }
    let mut symlinks = ["lib", "lib64", "usr"]
        .into_iter()
        .filter(|name| output.join(name).exists())
        .map(|name| LinuxSandboxRuntimeSymlink {
            target: format!("/rust-agent/runtime/{name}"),
            link: format!("/{name}"),
        })
        .collect::<Vec<_>>();
    symlinks.push(LinuxSandboxRuntimeSymlink {
        target: "/rust-agent/runtime/empty-stdin".into(),
        link: "/dev/null".into(),
    });
    symlinks.sort();
    (symlinks, loaders)
}

fn canonical_tree(root: &Path) -> CanonicalSnapshotTree {
    let mut entries = Vec::new();
    for entry in WalkDir::new(root).sort_by_file_name().into_iter().skip(1) {
        let entry = entry.unwrap();
        let relative = entry
            .path()
            .strip_prefix(root)
            .unwrap()
            .to_str()
            .unwrap()
            .replace('\\', "/");
        if entry.file_type().is_dir() {
            entries.push(CanonicalSnapshotEntry::directory(relative));
        } else {
            let bytes = fs::read(entry.path()).unwrap();
            entries.push(CanonicalSnapshotEntry::regular_file(
                relative,
                hex::encode(Sha256::digest(&bytes)),
                bytes.len() as u64,
            ));
        }
    }
    CanonicalSnapshotTree::from_entries(entries).unwrap()
}

fn sha256_file(path: &Path) -> String {
    sha256(&fs::read(path).unwrap())
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn first_stdout_line(path: &Path, arguments: &[&str]) -> String {
    let output = Command::new(path).args(arguments).output().unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .into()
}
