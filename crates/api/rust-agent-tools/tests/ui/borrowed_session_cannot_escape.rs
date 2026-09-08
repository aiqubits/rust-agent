use rust_agent_tools::BorrowedToolExecutionSession;

fn escape<'a>(
    session: BorrowedToolExecutionSession<'a>,
) -> BorrowedToolExecutionSession<'static> {
    session
}

fn main() {}
