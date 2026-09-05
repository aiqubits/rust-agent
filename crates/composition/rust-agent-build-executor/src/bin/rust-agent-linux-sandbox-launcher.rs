#[cfg(target_os = "linux")]
mod linux {
    use std::{
        env,
        ffi::{OsStr, OsString},
        fs::{self, OpenOptions},
        io::Write as _,
        os::unix::process::ExitStatusExt as _,
        path::{Path, PathBuf},
    };

    use rust_agent_build_executor::{
        LandlockExecutionPolicy, run_seccomp_child, supervise_landlock_command,
    };

    const VERSION: &str = "rust-agent-linux-sandbox-launcher 3";

    pub fn main() {
        match run() {
            Ok(code) => std::process::exit(code),
            Err(error) => {
                eprintln!("rust-agent Linux sandbox launcher failed: {error}");
                std::process::exit(125);
            }
        }
    }

    fn run() -> Result<i32, Box<dyn std::error::Error>> {
        let mut arguments = env::args_os().skip(1);
        let first = arguments.next().ok_or("missing launcher arguments")?;
        if first == "--version" {
            if arguments.next().is_some() {
                return Err("--version does not accept additional arguments".into());
            }
            println!("{VERSION}");
            return Ok(0);
        }
        if first == "--seccomp-child" {
            return run_child(arguments);
        }
        if first != "--audit" {
            return Err(
                "expected --audit <path> --policy <path> -- <command> [arguments...]".into(),
            );
        }
        let audit_path = PathBuf::from(arguments.next().ok_or("missing audit path")?);
        if arguments.next().as_deref() != Some(OsStr::new("--policy")) {
            return Err("expected --policy after --audit <path>".into());
        }
        let (policy_path, command, arguments) = parse_command(arguments)?;
        let policy = read_policy(&policy_path)?;
        let launcher = env::current_exe()?;
        let (status, report) =
            supervise_landlock_command(&launcher, &policy_path, &policy, &command, arguments)?;
        write_report(&audit_path, &report.canonical_bytes()?)?;
        Ok(status
            .code()
            .or_else(|| status.signal().map(|signal| 128 + signal))
            .unwrap_or(125))
    }

    fn run_child(
        mut arguments: impl Iterator<Item = OsString>,
    ) -> Result<i32, Box<dyn std::error::Error>> {
        if arguments.next().as_deref() != Some(OsStr::new("--policy")) {
            return Err("expected --policy after --seccomp-child".into());
        }
        let (policy_path, command, arguments) = parse_command(arguments)?;
        let policy = read_policy(&policy_path)?;
        match run_seccomp_child(&policy, &command, arguments) {
            Ok(never) => match never {},
            Err(error) => Err(error.into()),
        }
    }

    fn parse_command(
        mut arguments: impl Iterator<Item = OsString>,
    ) -> Result<(PathBuf, OsString, Vec<OsString>), Box<dyn std::error::Error>> {
        let policy_path = PathBuf::from(arguments.next().ok_or("missing policy path")?);
        if arguments.next().as_deref() != Some(OsStr::new("--")) {
            return Err("missing command separator".into());
        }
        let command = arguments.next().ok_or("missing command")?;
        Ok((policy_path, command, arguments.collect()))
    }

    fn read_policy(path: &Path) -> Result<LandlockExecutionPolicy, Box<dyn std::error::Error>> {
        Ok(LandlockExecutionPolicy::from_json(&fs::read_to_string(
            path,
        )?)?)
    }

    fn write_report(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let mut output = OpenOptions::new().write(true).create_new(true).open(path)?;
        output.write_all(bytes)?;
        output.sync_all()?;
        fs::File::open(path.parent().ok_or("audit path has no parent")?)?.sync_all()?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn main() {
    linux::main();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("rust-agent Linux sandbox launcher is only available on Linux");
    std::process::exit(125);
}
