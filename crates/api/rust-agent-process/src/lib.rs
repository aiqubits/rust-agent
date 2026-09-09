//! Bounded process, confinement, shell, and terminal capability contracts.
//!
//! The API enforces the `ProcessSpec -> ConfinedProcessSpec -> Subprocess` boundary. A sandbox
//! receives the issuer half of one Agent-scoped authority pair, while the selected subprocess
//! provider receives only the verifier half. Shell and terminal consumers see opaque bindings and
//! cannot access either raw provider or authority half.

mod confinement;
mod process;
mod shell;
mod spec;
mod terminal;

use std::{future::Future, pin::Pin};

pub use confinement::{
    ConfinedProcessSpec, ConfinementAuthority, ConfinementIssuer, ConfinementIssuerBinding,
    ConfinementProjection, ConfinementVerifier, ConfinementVerifierBinding, VerifiedProcessSpec,
};
pub use process::{
    EnforcementReport, ProcessControl, ProcessError, ProcessExit, ProcessHandle, ProcessOutput,
    Sandbox, SandboxBinding, SandboxError, Subprocess, SubprocessBinding,
};
pub use shell::{
    MAX_SHELL_COMMAND_BYTES, Shell, ShellBinding, ShellError, ShellProcess, ShellProcessControl,
    ShellRequest, ShellResult, ShellSpec,
};
pub use spec::{
    MAX_PROCESS_ARGUMENT_BYTES, MAX_PROCESS_ARGUMENTS, MAX_PROCESS_ENVIRONMENT_BYTES,
    MAX_PROCESS_ENVIRONMENT_ENTRIES, MAX_PROCESS_EXECUTABLE_BYTES, MAX_PROCESS_INPUT_BYTES,
    ProcessEnvironment, ProcessExecutable, ProcessSpec, ProcessSpecError,
};
pub use terminal::{
    MAX_TERMINAL_IO_BYTES, TerminalBinding, TerminalBytes, TerminalError, TerminalId,
    TerminalManager, TerminalReadRequest, TerminalSize, TerminalSpec,
};

#[cfg(not(target_arch = "wasm32"))]
pub type ProcessFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub type ProcessFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

#[cfg(test)]
mod tests;
