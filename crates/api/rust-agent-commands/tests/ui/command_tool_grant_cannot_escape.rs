use rust_agent_commands::{CommandContext, CommandPermit, CommandToolGrant};

fn escape<'a>(
    permit: &'a CommandPermit,
    context: &'a CommandContext,
) -> CommandToolGrant<'static> {
    permit.delegate_tools(context).unwrap()
}

fn main() {}
