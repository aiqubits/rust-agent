use rust_agent_tools::{BorrowedToolExecutionSession, ToolExecutionSession};

fn convert(session: BorrowedToolExecutionSession<'_>) -> ToolExecutionSession {
    session.into()
}

fn main() {}
