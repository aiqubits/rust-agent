use std::sync::Arc;

use rust_agent_tools::{ToolError, ToolErrorKind};

fn main() {
    let _forged = ToolError {
        kind: ToolErrorKind::Provider,
        category: Some("provider"),
        message: Arc::from("unbounded"),
    };
}
