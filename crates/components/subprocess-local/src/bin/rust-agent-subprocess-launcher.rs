#[path = "../launcher.rs"]
mod launcher;
#[path = "../protocol.rs"]
mod protocol;

const SANDBOX_WORKSPACE: &str = "/workspace";
const SANDBOX_TARGET: &str = "/rust-agent/target";

fn main() {
    if let Err(error) = launcher::run() {
        eprintln!("rust-agent subprocess launcher failed: {error}");
        std::process::exit(125);
    }
}
