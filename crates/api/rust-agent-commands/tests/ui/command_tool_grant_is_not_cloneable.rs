use rust_agent_commands::CommandToolGrant;

fn require_clone<T: Clone>() {}

fn main() {
    require_clone::<CommandToolGrant<'static>>();
}
