use rust_agent_commands::CommandToolGrant;
use rust_agent_tools::{BorrowedToolExecutionSession, ToolExecutorBinding};

fn escape<'a>(
    executor: &'a ToolExecutorBinding,
    grant: &'a CommandToolGrant<'a>,
) -> BorrowedToolExecutionSession<'static> {
    executor.prepare_command(grant).unwrap()
}

fn main() {}
