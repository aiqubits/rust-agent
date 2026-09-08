use rust_agent_tools::ExecutionPermit;

fn main() {
    let _forged = ExecutionPermit {
        authority: unreachable!(),
    };
}
