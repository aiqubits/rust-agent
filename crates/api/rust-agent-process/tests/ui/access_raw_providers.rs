use rust_agent_process::{SandboxBinding, ShellBinding, SubprocessBinding, TerminalBinding};

fn subprocess(binding: &SubprocessBinding) {
    let _ = &binding.provider;
}

fn sandbox(binding: &SandboxBinding) {
    let _ = &binding.provider;
}

fn shell(binding: &ShellBinding) {
    let _ = &binding.provider;
}

fn terminal(binding: &TerminalBinding) {
    let _ = &binding.provider;
}

fn main() {}
