#![cfg(target_os = "linux")]

use std::{
    fs::{self, File, FileTimes},
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream, ToSocketAddrs as _, UdpSocket},
    os::unix::fs::{DirEntryExt as _, MetadataExt as _, PermissionsExt as _},
    os::unix::net::{UnixDatagram, UnixStream},
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, SystemTime},
};

use rust_agent_build_executor::{
    LandlockExecutionPolicy, LinuxSandboxAnonymousSocketpair, LinuxSandboxResolvedEndpoint,
};
use tempfile::TempDir;

#[test]
fn launcher_projects_the_complete_canonical_stat_view() {
    const MARKER: &str = "RUST_AGENT_CANONICAL_STAT_CHILD";
    const INPUT: &str = "RUST_AGENT_CANONICAL_STAT_INPUT";
    const SECRET: &str = "RUST_AGENT_CANONICAL_STAT_SECRET";
    if std::env::var_os(MARKER).is_some() {
        let input = std::env::var_os(INPUT).unwrap();
        let input = std::path::PathBuf::from(input);
        let secret = std::path::PathBuf::from(std::env::var_os(SECRET).unwrap());
        let file = fs::metadata(input.join("observed.txt")).unwrap();
        assert_eq!(file.mode() & 0o7777, 0o444);
        assert_eq!(file.uid(), 0);
        assert_eq!(file.gid(), 0);
        assert_eq!(file.atime(), 0);
        assert_eq!(file.atime_nsec(), 0);
        assert_eq!(file.mtime(), 0);
        assert_eq!(file.mtime_nsec(), 0);
        assert_eq!(file.ctime(), 0);
        assert_eq!(file.ctime_nsec(), 0);
        assert_eq!(file.nlink(), 1);
        assert_eq!(file.dev(), 0);
        assert_eq!(file.ino(), 0);

        let directory = fs::metadata(&input).unwrap();
        assert_eq!(directory.mode() & 0o7777, 0o555);
        assert_eq!(directory.uid(), 0);
        assert_eq!(directory.gid(), 0);
        assert_eq!(directory.nlink(), 1);
        assert_eq!(directory.dev(), 0);
        assert_eq!(directory.ino(), 0);
        let root = fs::metadata("/").unwrap();
        assert_eq!(root.mode() & 0o7777, 0o555);
        assert_eq!(root.dev(), 0);
        assert_eq!(root.ino(), 0);
        assert_eq!(
            fs::metadata(&secret).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            fs::metadata(secret.with_extension("missing"))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );

        let statx = rustix::fs::statx(
            rustix::fs::CWD,
            input.join("observed.txt"),
            rustix::fs::AtFlags::empty(),
            rustix::fs::StatxFlags::ALL,
        )
        .unwrap();
        assert_eq!(statx.stx_mode & 0o7777, 0o444);
        assert_eq!(statx.stx_uid, 0);
        assert_eq!(statx.stx_gid, 0);
        assert_eq!(statx.stx_nlink, 1);
        assert_eq!(statx.stx_ino, 0);
        assert_eq!(statx.stx_atime.tv_sec, 0);
        assert_eq!(statx.stx_mtime.tv_sec, 0);
        assert_eq!(statx.stx_ctime.tv_sec, 0);
        assert_eq!(statx.stx_btime.tv_sec, 0);
        assert_eq!(statx.stx_dev_major, 0);
        assert_eq!(statx.stx_dev_minor, 0);
        assert_eq!(statx.stx_mnt_id, 0);
        assert!(
            rustix::fs::ioctl_getflags(File::open(input.join("observed.txt")).unwrap())
                .unwrap()
                .is_empty()
        );
        let mut first_inodes = None;
        for _ in 0..2 {
            let entries = fs::read_dir(&input)
                .unwrap()
                .map(|entry| {
                    let entry = entry.unwrap();
                    (entry.file_name(), entry.ino())
                })
                .collect::<Vec<_>>();
            assert_eq!(
                entries
                    .iter()
                    .map(|(name, _)| name.to_str().unwrap())
                    .collect::<Vec<_>>(),
                vec!["alpha.txt", "middle.txt", "observed.txt", "zulu.txt"]
            );
            let inodes = entries.iter().map(|(_, inode)| *inode).collect::<Vec<_>>();
            assert!(inodes.iter().all(|inode| *inode != 0));
            if let Some(first) = &first_inodes {
                assert_eq!(&inodes, first);
            } else {
                first_inodes = Some(inodes);
            }
        }
        return;
    }

    let temp = TempDir::new().unwrap();
    let input = temp.path().join("input");
    fs::create_dir(&input).unwrap();
    let observed = input.join("observed.txt");
    let secret = temp.path().join("secret.txt");
    fs::write(&secret, b"must-not-leak\n").unwrap();
    fs::write(input.join("zulu.txt"), b"z").unwrap();
    fs::write(input.join("middle.txt"), b"m").unwrap();
    fs::write(input.join("alpha.txt"), b"a").unwrap();
    fs::write(&observed, b"canonical\n").unwrap();
    fs::set_permissions(&observed, fs::Permissions::from_mode(0o600)).unwrap();
    let noncanonical_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_234_567);
    File::options()
        .write(true)
        .open(&observed)
        .unwrap()
        .set_times(
            FileTimes::new()
                .set_accessed(noncanonical_time)
                .set_modified(noncanonical_time),
        )
        .unwrap();

    let test_executable = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
    let loader = fs::canonicalize("/lib64/ld-linux-x86-64.so.2").unwrap();
    let policy = LandlockExecutionPolicy::new(
        vec![
            "/lib".into(),
            "/lib64".into(),
            "/usr".into(),
            input.to_str().unwrap().into(),
            test_executable.to_str().unwrap().into(),
        ],
        vec![],
        vec![test_executable.to_str().unwrap().into()],
        vec![loader.to_str().unwrap().into()],
        vec![input.to_str().unwrap().into()],
        vec![],
        vec![],
        vec![LinuxSandboxAnonymousSocketpair::StreamWakeup],
    )
    .unwrap();
    let policy_path = temp.path().join("policy.json");
    let audit_path = temp.path().join("audit.json");
    fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_rust-agent-linux-sandbox-launcher"))
        .args([
            "--audit",
            audit_path.to_str().unwrap(),
            "--policy",
            policy_path.to_str().unwrap(),
            "--",
            test_executable.to_str().unwrap(),
            "--exact",
            "launcher_projects_the_complete_canonical_stat_view",
            "--test-threads=1",
        ])
        .env(MARKER, "1")
        .env(INPUT, &input)
        .env(SECRET, &secret)
        .output()
        .unwrap();

    assert!(
        result.status.success(),
        "metadata launcher failed with {}: stdout={} stderr={}",
        result.status,
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    let backing = fs::metadata(&observed).unwrap();
    assert_eq!(backing.mode() & 0o7777, 0o600);
    assert_ne!(backing.ino(), 0);
    assert_eq!(backing.mtime(), 1_234_567);
}

#[test]
fn launcher_runs_a_declared_dynamic_executable() {
    let temp = TempDir::new().unwrap();
    let executable = fs::canonicalize("/usr/bin/true").unwrap();
    let loader = fs::canonicalize("/lib64/ld-linux-x86-64.so.2").unwrap();
    let policy = LandlockExecutionPolicy::new(
        vec!["/lib".into(), "/lib64".into(), "/usr".into()],
        vec![],
        vec![executable.to_str().unwrap().into()],
        vec![loader.to_str().unwrap().into()],
        vec![],
        vec![],
        vec![],
        vec![LinuxSandboxAnonymousSocketpair::StreamWakeup],
    )
    .unwrap();
    let policy_path = temp.path().join("policy.json");
    let audit_path = temp.path().join("audit.json");
    fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_rust-agent-linux-sandbox-launcher"))
        .args([
            "--audit",
            audit_path.to_str().unwrap(),
            "--policy",
            policy_path.to_str().unwrap(),
            "--",
            executable.to_str().unwrap(),
        ])
        .env_clear()
        .output()
        .unwrap();

    assert_eq!(result.status.code(), Some(0), "{result:?}");
}

#[test]
#[ignore = "requires a real Linux runner with Landlock ABI 2 rename enforcement"]
fn writable_root_allows_internal_atomic_rename_but_not_escape() {
    const MARKER: &str = "RUST_AGENT_WRITABLE_RENAME_CHILD";
    const OUTPUT: &str = "RUST_AGENT_WRITABLE_RENAME_OUTPUT";
    const SECRET: &str = "RUST_AGENT_WRITABLE_RENAME_SECRET";
    if std::env::var_os(MARKER).is_some() {
        let output = std::path::PathBuf::from(std::env::var_os(OUTPUT).unwrap());
        let secret = std::path::PathBuf::from(std::env::var_os(SECRET).unwrap());
        fs::create_dir(output.join("from")).unwrap();
        fs::create_dir(output.join("to")).unwrap();
        fs::write(output.join("from/value"), b"value").unwrap();
        fs::rename(output.join("from/value"), output.join("to/value")).unwrap();
        assert_eq!(fs::read(output.join("to/value")).unwrap(), b"value");
        assert!(fs::rename(output.join("to/value"), secret).is_err());
        return;
    }

    let temp = TempDir::new().unwrap();
    let output = temp.path().join("output");
    let secret = temp.path().join("secret");
    fs::create_dir(&output).unwrap();
    fs::create_dir(&secret).unwrap();
    let test_executable = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
    let loader = fs::canonicalize("/lib64/ld-linux-x86-64.so.2").unwrap();
    let policy = LandlockExecutionPolicy::new(
        vec![
            "/lib".into(),
            "/lib64".into(),
            "/usr".into(),
            test_executable.to_str().unwrap().into(),
        ],
        vec![output.to_str().unwrap().into()],
        vec![test_executable.to_str().unwrap().into()],
        vec![loader.to_str().unwrap().into()],
        vec![],
        vec![output.to_str().unwrap().into()],
        vec![],
        vec![
            LinuxSandboxAnonymousSocketpair::StreamWakeup,
            LinuxSandboxAnonymousSocketpair::RustSpawnError,
        ],
    )
    .unwrap();
    let policy_path = temp.path().join("policy.json");
    let audit_path = temp.path().join("audit.json");
    fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_rust-agent-linux-sandbox-launcher"))
        .args([
            "--audit",
            audit_path.to_str().unwrap(),
            "--policy",
            policy_path.to_str().unwrap(),
            "--",
            test_executable.to_str().unwrap(),
            "--exact",
            "writable_root_allows_internal_atomic_rename_but_not_escape",
            "--test-threads=1",
        ])
        .env(MARKER, "1")
        .env(OUTPUT, &output)
        .env(SECRET, secret.join("escaped"))
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "launcher failed with {}: stdout={} stderr={}",
        result.status,
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn network_policy_allows_only_resolved_tcp_endpoints() {
    const MARKER: &str = "RUST_AGENT_SECCOMP_NETWORK_CHILD";
    const ALLOWED_PORT: &str = "RUST_AGENT_SECCOMP_ALLOWED_PORT";
    const DENIED_PORT: &str = "RUST_AGENT_SECCOMP_DENIED_PORT";
    if std::env::var_os(MARKER).is_some() {
        let allowed_port = std::env::var(ALLOWED_PORT).unwrap().parse::<u16>().unwrap();
        let denied_port = std::env::var(DENIED_PORT).unwrap().parse::<u16>().unwrap();
        TcpStream::connect(("127.0.0.1", allowed_port)).unwrap();
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
        assert!(("unlisted.invalid", 443).to_socket_addrs().is_err());
        return;
    }

    let allowed = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let denied = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let allowed_port = allowed.local_addr().unwrap().port();
    let denied_port = denied.local_addr().unwrap().port();
    let temp = TempDir::new().unwrap();
    let test_executable = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
    let loader = fs::canonicalize("/lib64/ld-linux-x86-64.so.2").unwrap();
    let policy = LandlockExecutionPolicy::new(
        vec![
            "/lib".into(),
            "/lib64".into(),
            "/usr".into(),
            test_executable.to_str().unwrap().into(),
        ],
        vec![],
        vec![test_executable.to_str().unwrap().into()],
        vec![loader.to_str().unwrap().into()],
        vec![],
        vec![],
        vec![LinuxSandboxResolvedEndpoint {
            origin: format!("https://127.0.0.1:{allowed_port}"),
            host: "127.0.0.1".into(),
            port: allowed_port,
            addresses: vec!["127.0.0.1".parse().unwrap()],
        }],
        vec![LinuxSandboxAnonymousSocketpair::StreamWakeup],
    )
    .unwrap();
    let policy_path = temp.path().join("policy.json");
    let audit_path = temp.path().join("audit.json");
    fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_rust-agent-linux-sandbox-launcher"))
        .args([
            "--audit",
            audit_path.to_str().unwrap(),
            "--policy",
            policy_path.to_str().unwrap(),
            "--",
            test_executable.to_str().unwrap(),
            "--exact",
            "network_policy_allows_only_resolved_tcp_endpoints",
            "--test-threads=1",
        ])
        .env(MARKER, "1")
        .env(ALLOWED_PORT, allowed_port.to_string())
        .env(DENIED_PORT, denied_port.to_string())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "network policy launcher failed with {}: stdout={} stderr={}",
        result.status,
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn socketpair_classes_are_command_bound_and_closed() {
    const MARKER: &str = "RUST_AGENT_SOCKETPAIR_CLASS_CHILD";
    if std::env::var_os(MARKER).is_some() {
        use rustix::net::{AddressFamily, SocketFlags, SocketType, socket_with, socketpair};

        UnixStream::pair().unwrap();
        socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        for flags in [
            SocketFlags::empty(),
            SocketFlags::NONBLOCK,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        ] {
            assert_eq!(
                socketpair(AddressFamily::UNIX, SocketType::SEQPACKET, flags, None).unwrap_err(),
                rustix::io::Errno::PERM
            );
        }
        assert_eq!(
            socketpair(
                AddressFamily::UNIX,
                SocketType::DGRAM,
                SocketFlags::CLOEXEC,
                None,
            )
            .unwrap_err(),
            rustix::io::Errno::PERM
        );
        assert_eq!(
            socketpair(
                AddressFamily::INET,
                SocketType::SEQPACKET,
                SocketFlags::CLOEXEC,
                None,
            )
            .unwrap_err(),
            rustix::io::Errno::PERM
        );
        assert_eq!(
            socketpair(
                AddressFamily::UNIX,
                SocketType::SEQPACKET,
                SocketFlags::CLOEXEC,
                Some(rustix::net::ipproto::TCP),
            )
            .unwrap_err(),
            rustix::io::Errno::PERM
        );
        assert_eq!(
            socket_with(
                AddressFamily::UNIX,
                SocketType::SEQPACKET,
                SocketFlags::CLOEXEC,
                None,
            )
            .unwrap_err(),
            rustix::io::Errno::PERM
        );
        return;
    }

    let temp = TempDir::new().unwrap();
    let test_executable = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
    let loader = fs::canonicalize("/lib64/ld-linux-x86-64.so.2").unwrap();
    let policy = LandlockExecutionPolicy::new(
        vec![
            "/lib".into(),
            "/lib64".into(),
            "/usr".into(),
            test_executable.to_str().unwrap().into(),
        ],
        vec![],
        vec![test_executable.to_str().unwrap().into()],
        vec![loader.to_str().unwrap().into()],
        vec![],
        vec![],
        vec![],
        vec![
            LinuxSandboxAnonymousSocketpair::StreamWakeup,
            LinuxSandboxAnonymousSocketpair::RustSpawnError,
        ],
    )
    .unwrap();
    let policy_path = temp.path().join("policy.json");
    let audit_path = temp.path().join("audit.json");
    fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_rust-agent-linux-sandbox-launcher"))
        .args([
            "--audit",
            audit_path.to_str().unwrap(),
            "--policy",
            policy_path.to_str().unwrap(),
            "--",
            test_executable.to_str().unwrap(),
            "--exact",
            "socketpair_classes_are_command_bound_and_closed",
            "--test-threads=1",
        ])
        .env(MARKER, "1")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "launcher failed with {}: stdout={} stderr={}",
        result.status,
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn launcher_confirms_exec_with_a_multithreaded_parent() {
    const MARKER: &str = "RUST_AGENT_SECCOMP_THREADED_CHILD";
    if std::env::var_os(MARKER).is_some() {
        let running = Arc::new(AtomicBool::new(true));
        let worker_flag = Arc::clone(&running);
        let worker = thread::spawn(move || {
            while worker_flag.load(Ordering::Acquire) {
                thread::yield_now();
            }
        });
        let result = Command::new("/usr/bin/true").status().unwrap();
        running.store(false, Ordering::Release);
        worker.join().unwrap();
        assert!(result.success());
        return;
    }

    let temp = TempDir::new().unwrap();
    let test_executable = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
    let allowed_child = fs::canonicalize("/usr/bin/true").unwrap();
    let loader = fs::canonicalize("/lib64/ld-linux-x86-64.so.2").unwrap();
    let policy = LandlockExecutionPolicy::new(
        vec![
            "/lib".into(),
            "/lib64".into(),
            "/usr".into(),
            test_executable.to_str().unwrap().into(),
        ],
        vec![],
        vec![
            allowed_child.to_str().unwrap().into(),
            test_executable.to_str().unwrap().into(),
        ],
        vec![loader.to_str().unwrap().into()],
        vec![],
        vec![],
        vec![],
        vec![LinuxSandboxAnonymousSocketpair::StreamWakeup],
    )
    .unwrap();
    let policy_path = temp.path().join("policy.json");
    let audit_path = temp.path().join("audit.json");
    fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_rust-agent-linux-sandbox-launcher"))
        .args([
            "--audit",
            audit_path.to_str().unwrap(),
            "--policy",
            policy_path.to_str().unwrap(),
            "--",
            test_executable.to_str().unwrap(),
            "--exact",
            "launcher_confirms_exec_with_a_multithreaded_parent",
            "--test-threads=1",
        ])
        .env(MARKER, "1")
        .output()
        .unwrap();

    assert!(
        result.status.success(),
        "threaded launcher failed with {}: stdout={} stderr={}",
        result.status,
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn landlock_launcher_enforces_descendant_read_write_and_execute_sets() {
    let temp = TempDir::new().unwrap();
    let input = temp.path().join("input");
    let output = temp.path().join("output");
    let secret = temp.path().join("secret.txt");
    fs::create_dir(&input).unwrap();
    fs::create_dir(&output).unwrap();
    fs::write(input.join("allowed.txt"), b"allowed\n").unwrap();
    fs::write(&secret, b"secret\n").unwrap();
    fs::set_permissions(&input, fs::Permissions::from_mode(0o555)).unwrap();
    fs::set_permissions(input.join("allowed.txt"), fs::Permissions::from_mode(0o444)).unwrap();

    let shell = fs::canonicalize("/bin/sh").unwrap();
    let cat = fs::canonicalize("/usr/bin/cat").unwrap();
    let loader = fs::canonicalize("/lib64/ld-linux-x86-64.so.2").unwrap();
    let policy = LandlockExecutionPolicy::new(
        vec![
            "/lib".into(),
            "/lib64".into(),
            "/usr".into(),
            input.to_str().unwrap().into(),
        ],
        vec![output.to_str().unwrap().into()],
        vec![cat.to_str().unwrap().into(), shell.to_str().unwrap().into()],
        vec![loader.to_str().unwrap().into()],
        vec![input.to_str().unwrap().into()],
        vec![],
        vec![],
        vec![LinuxSandboxAnonymousSocketpair::StreamWakeup],
    )
    .unwrap();
    let policy_path = temp.path().join("policy.json");
    let audit_path = temp.path().join("audit.json");
    fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();

    let script = format!(
        "set -eu\n\
         test \"$({cat} {input}/allowed.txt)\" = allowed\n\
         if {cat} {secret} >/dev/null 2>&1; then exit 41; fi\n\
         printf 'written\\n' > {output}/written.txt\n\
         if printf denied > {input}/denied.txt 2>/dev/null; then exit 42; fi\n\
         if /usr/bin/id >/dev/null 2>&1; then exit 43; fi\n\
         if {loader} /usr/bin/id >/dev/null 2>&1; then exit 44; fi\n\
         if {cat} /proc/self/status >/dev/null 2>&1; then exit 45; fi\n",
        cat = cat.display(),
        input = input.display(),
        loader = loader.display(),
        secret = secret.display(),
        output = output.display(),
    );
    let result = Command::new(env!("CARGO_BIN_EXE_rust-agent-linux-sandbox-launcher"))
        .args([
            "--audit",
            audit_path.to_str().unwrap(),
            "--policy",
            policy_path.to_str().unwrap(),
            "--",
            shell.to_str().unwrap(),
            "-c",
            &script,
        ])
        .env_clear()
        .output()
        .unwrap();

    assert!(
        result.status.success(),
        "launcher failed with {}: stdout={} stderr={}",
        result.status,
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::read(output.join("written.txt")).unwrap(), b"written\n");
    assert!(!input.join("denied.txt").exists());
    assert_eq!(fs::read(input.join("allowed.txt")).unwrap(), b"allowed\n");
}

#[test]
fn launcher_rejects_an_initial_undeclared_command_before_exec() {
    let temp = TempDir::new().unwrap();
    let policy = LandlockExecutionPolicy::new(
        vec!["/usr".into()],
        vec![],
        vec!["/usr/bin/true".into()],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![LinuxSandboxAnonymousSocketpair::StreamWakeup],
    )
    .unwrap();
    let policy_path = temp.path().join("policy.json");
    let audit_path = temp.path().join("audit.json");
    fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_rust-agent-linux-sandbox-launcher"))
        .args([
            "--audit",
            audit_path.to_str().unwrap(),
            "--policy",
            policy_path.to_str().unwrap(),
            "--",
            "/usr/bin/id",
        ])
        .env_clear()
        .output()
        .unwrap();

    assert_eq!(result.status.code(), Some(125));
    assert!(String::from_utf8_lossy(&result.stderr).contains("not an allowed executable"));
}
