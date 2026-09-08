use std::marker::PhantomData;

use rust_agent_commands::CommandToolGrant;

fn main() {
    let _grant: CommandToolGrant<'static> = CommandToolGrant {
        permit: unreachable!(),
        _authority: PhantomData,
    };
}
