use rust_agent_commands::{CommandContext, CommandPermit};

fn main() {
    let _permit = CommandPermit {
        authority: unreachable!(),
    };
    let _context = CommandContext {
        authority: unreachable!(),
    };
}
