use rust_agent_tools::ExecutionPermit;

struct SavedPermit {
    permit: &'static ExecutionPermit,
}

fn save(permit: &ExecutionPermit) -> SavedPermit {
    SavedPermit { permit }
}

fn main() {}
