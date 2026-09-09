use rust_agent_process::{ProcessSpec, SubprocessBinding};
use rust_agent_runtime_api::CancellationToken;

fn bypass(binding: &SubprocessBinding, raw: ProcessSpec) {
    let _ = binding.spawn(raw, CancellationToken::new());
}

fn main() {}
