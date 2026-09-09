use std::{collections::BTreeMap, fmt, sync::Arc};

use rust_agent_fs::AgentPath;

pub const MAX_PROCESS_EXECUTABLE_BYTES: usize = 4 * 1024;
pub const MAX_PROCESS_ARGUMENTS: usize = 256;
pub const MAX_PROCESS_ARGUMENT_BYTES: usize = 64 * 1024;
pub const MAX_PROCESS_ENVIRONMENT_ENTRIES: usize = 128;
pub const MAX_PROCESS_ENVIRONMENT_BYTES: usize = 64 * 1024;
pub const MAX_PROCESS_INPUT_BYTES: usize = 1024 * 1024;
const MAX_ENVIRONMENT_NAME_BYTES: usize = 128;

#[derive(Clone, Eq, PartialEq)]
pub struct ProcessExecutable(Arc<str>);

impl ProcessExecutable {
    pub fn absolute(value: impl Into<String>) -> Result<Self, ProcessSpecError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_PROCESS_EXECUTABLE_BYTES
            || value
                .bytes()
                .any(|byte| byte == 0 || byte.is_ascii_control())
            || !is_lexically_absolute(&value)
            || has_noncanonical_path_segment(&value)
        {
            return Err(ProcessSpecError::InvalidExecutable);
        }
        Ok(Self(Arc::from(value)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ProcessExecutable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessExecutable")
            .field("len", &self.0.len())
            .finish()
    }
}

fn is_lexically_absolute(value: &str) -> bool {
    value.starts_with('/')
        || (value.len() >= 3
            && value.as_bytes()[0].is_ascii_alphabetic()
            && value.as_bytes()[1] == b':'
            && matches!(value.as_bytes()[2], b'/' | b'\\'))
}

fn has_noncanonical_path_segment(value: &str) -> bool {
    value
        .replace('\\', "/")
        .split('/')
        .skip(1)
        .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProcessEnvironment(Arc<[(Arc<str>, Arc<str>)]>);

impl ProcessEnvironment {
    pub fn empty() -> Self {
        Self(Arc::from([]))
    }

    pub fn checked<I>(entries: I) -> Result<Self, ProcessSpecError>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let mut normalized = BTreeMap::new();
        let mut encoded_bytes = 0_usize;
        for (name, value) in entries {
            if normalized.len() >= MAX_PROCESS_ENVIRONMENT_ENTRIES {
                return Err(ProcessSpecError::EnvironmentTooLarge);
            }
            validate_environment_name(&name)?;
            if value.len() > MAX_PROCESS_ENVIRONMENT_BYTES || value.bytes().any(|byte| byte == 0) {
                return Err(ProcessSpecError::InvalidEnvironmentValue);
            }
            encoded_bytes = encoded_bytes
                .checked_add(name.len())
                .and_then(|bytes| bytes.checked_add(value.len()))
                .and_then(|bytes| bytes.checked_add(2))
                .ok_or(ProcessSpecError::EnvironmentTooLarge)?;
            if encoded_bytes > MAX_PROCESS_ENVIRONMENT_BYTES {
                return Err(ProcessSpecError::EnvironmentTooLarge);
            }
            if normalized.insert(name, value).is_some() {
                return Err(ProcessSpecError::DuplicateEnvironmentName);
            }
        }
        Ok(Self(Arc::from(
            normalized
                .into_iter()
                .map(|(name, value)| (Arc::from(name), Arc::from(value)))
                .collect::<Vec<_>>(),
        )))
    }

    pub fn entries(&self) -> &[(Arc<str>, Arc<str>)] {
        &self.0
    }
}

impl fmt::Debug for ProcessEnvironment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessEnvironment")
            .field(
                "names",
                &self.0.iter().map(|(name, _)| name).collect::<Vec<_>>(),
            )
            .finish()
    }
}

fn validate_environment_name(name: &str) -> Result<(), ProcessSpecError> {
    if name.is_empty()
        || name.len() > MAX_ENVIRONMENT_NAME_BYTES
        || !name.as_bytes()[0].is_ascii_uppercase()
        || name
            .bytes()
            .any(|byte| !(byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'))
    {
        return Err(ProcessSpecError::InvalidEnvironmentName);
    }
    let credential_like = [
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "CREDENTIAL",
        "PRIVATE_KEY",
        "API_KEY",
        "ACCESS_KEY",
        "AUTH",
        "COOKIE",
    ];
    if credential_like.iter().any(|marker| name.contains(marker)) {
        return Err(ProcessSpecError::CredentialEnvironmentDenied);
    }
    Ok(())
}

/// Normalized raw process intent. It is intentionally distinct from [`crate::ConfinedProcessSpec`].
#[derive(Clone, Eq, PartialEq)]
pub struct ProcessSpec {
    executable: ProcessExecutable,
    arguments: Arc<[Arc<str>]>,
    cwd: AgentPath,
    environment: ProcessEnvironment,
    stdin: Arc<[u8]>,
}

impl fmt::Debug for ProcessSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessSpec")
            .field("executable_len", &self.executable.as_str().len())
            .field("argument_count", &self.arguments.len())
            .field("cwd", &self.cwd)
            .field("environment", &self.environment)
            .field("stdin_len", &self.stdin.len())
            .finish()
    }
}

impl ProcessSpec {
    pub fn checked<I>(
        executable: ProcessExecutable,
        arguments: I,
        cwd: AgentPath,
        environment: ProcessEnvironment,
        stdin: Vec<u8>,
    ) -> Result<Self, ProcessSpecError>
    where
        I: IntoIterator<Item = String>,
    {
        if stdin.len() > MAX_PROCESS_INPUT_BYTES {
            return Err(ProcessSpecError::InputTooLarge);
        }
        let mut normalized = Vec::new();
        let mut argument_bytes = 0_usize;
        for argument in arguments {
            if normalized.len() >= MAX_PROCESS_ARGUMENTS {
                return Err(ProcessSpecError::TooManyArguments);
            }
            if argument.bytes().any(|byte| byte == 0) {
                return Err(ProcessSpecError::InvalidArgument);
            }
            argument_bytes = argument_bytes
                .checked_add(argument.len())
                .and_then(|bytes| bytes.checked_add(1))
                .ok_or(ProcessSpecError::ArgumentsTooLarge)?;
            if argument_bytes > MAX_PROCESS_ARGUMENT_BYTES {
                return Err(ProcessSpecError::ArgumentsTooLarge);
            }
            normalized.push(Arc::from(argument));
        }
        Ok(Self {
            executable,
            arguments: Arc::from(normalized),
            cwd,
            environment,
            stdin: Arc::from(stdin),
        })
    }

    pub const fn executable(&self) -> &ProcessExecutable {
        &self.executable
    }

    pub fn arguments(&self) -> &[Arc<str>] {
        &self.arguments
    }

    pub const fn cwd(&self) -> &AgentPath {
        &self.cwd
    }

    pub const fn environment(&self) -> &ProcessEnvironment {
        &self.environment
    }

    pub fn stdin(&self) -> &[u8] {
        &self.stdin
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessSpecError {
    InvalidExecutable,
    TooManyArguments,
    ArgumentsTooLarge,
    InvalidArgument,
    InvalidEnvironmentName,
    InvalidEnvironmentValue,
    DuplicateEnvironmentName,
    CredentialEnvironmentDenied,
    EnvironmentTooLarge,
    InputTooLarge,
}

impl fmt::Display for ProcessSpecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidExecutable => "process executable is not a canonical absolute path",
            Self::TooManyArguments => "process argument count exceeds the hard maximum",
            Self::ArgumentsTooLarge => "process argument bytes exceed the hard maximum",
            Self::InvalidArgument => "process argument contains a null byte",
            Self::InvalidEnvironmentName => "process environment name is not canonical",
            Self::InvalidEnvironmentValue => "process environment value is invalid",
            Self::DuplicateEnvironmentName => "process environment name is duplicated",
            Self::CredentialEnvironmentDenied => "credential-like process environment is denied",
            Self::EnvironmentTooLarge => "process environment exceeds the hard maximum",
            Self::InputTooLarge => "process standard input exceeds the hard maximum",
        })
    }
}

impl std::error::Error for ProcessSpecError {}
