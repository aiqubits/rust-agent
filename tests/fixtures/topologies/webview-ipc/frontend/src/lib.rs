#![forbid(unsafe_code)]

use ipc_contract::RunCompleted;

/// Frontend projection consumes only the versionable IPC DTO contract.
pub fn render(result: &RunCompleted) -> String {
    format!("{}:{}", result.request_id().as_str(), result.output())
}

#[cfg(test)]
mod tests {
    use ipc_contract::{RequestId, RunCompleted};

    use super::*;

    #[test]
    fn frontend_observes_only_the_ipc_projection() {
        let result =
            RunCompleted::from_backend(RequestId::checked("request-42").unwrap(), "done".into());
        assert_eq!(render(&result), "request-42:done");
    }
}
