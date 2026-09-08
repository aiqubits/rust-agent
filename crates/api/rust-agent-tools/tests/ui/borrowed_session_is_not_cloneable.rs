use rust_agent_tools::BorrowedToolExecutionSession;

fn require_clone<T: Clone>() {}

fn main() {
    require_clone::<BorrowedToolExecutionSession<'static>>();
}
