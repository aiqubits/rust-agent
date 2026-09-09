use std::sync::Arc;

use rust_agent_fs::AgentPath;

fn main() {
    let _path = AgentPath(Arc::from("root"));
}
