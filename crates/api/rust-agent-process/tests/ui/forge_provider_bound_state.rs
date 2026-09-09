use rust_agent_core::CanonicalId;
use rust_agent_process::{ShellRequest, ShellSpec, TerminalId};

fn forge_shell(provider_key: CanonicalId, request: ShellRequest) -> ShellSpec {
    ShellSpec {
        provider_key,
        binding_authority: Some(std::sync::Arc::new(())),
        request,
    }
}

fn forge_terminal(provider_key: CanonicalId) -> TerminalId {
    TerminalId {
        provider_key,
        binding_authority: Some(std::sync::Arc::new(())),
        identity: std::num::NonZeroU64::MIN,
    }
}

fn main() {}
