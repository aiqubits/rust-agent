#![forbid(unsafe_code)]

use ipc_contract::{ChannelError, EventSender, RunCommand, RunCompleted};
use rust_agent_fixture_api::FixtureApp;

/// Product-backend adapter. Its runtime handle remains private and never enters
/// the frontend contract crate.
#[derive(Debug)]
pub struct BackendIpcAdapter {
    app: FixtureApp,
}

impl BackendIpcAdapter {
    pub fn new(app: FixtureApp) -> Self {
        Self { app }
    }

    pub fn dispatch(&self, command: RunCommand) -> RunCompleted {
        let output = self.app.run(command.input());
        RunCompleted::from_backend(command.request_id().clone(), output)
    }

    pub fn dispatch_to(
        &self,
        command: RunCommand,
        events: &EventSender,
    ) -> Result<(), ChannelError> {
        events.try_publish(self.dispatch(command))
    }
}

#[cfg(test)]
mod tests {
    use ipc_contract::RequestId;

    use super::*;

    #[test]
    fn command_mapping_preserves_the_exact_request_identity() {
        let runtime = agent::create_runtime_primitives().unwrap();
        let adapter = BackendIpcAdapter::new(agent::build(runtime).unwrap());
        let id = RequestId::checked("request-42").unwrap();
        let result = adapter.dispatch(RunCommand::checked(id.clone(), "hello").unwrap());
        assert_eq!(result.request_id(), &id);
        assert_eq!(result.output(), "fixture-response:hello");
    }

    #[test]
    fn channel_mapping_is_bounded_and_never_exposes_the_runtime_handle() {
        let runtime = agent::create_runtime_primitives().unwrap();
        let adapter = BackendIpcAdapter::new(agent::build(runtime).unwrap());
        let (events, frontend) = ipc_contract::bounded_event_channel(1).unwrap();
        let id = RequestId::checked("request-42").unwrap();
        adapter
            .dispatch_to(RunCommand::checked(id.clone(), "hello").unwrap(), &events)
            .unwrap();
        let result = frontend.try_receive().unwrap();
        assert_eq!(result.request_id(), &id);
        assert_eq!(result.output(), "fixture-response:hello");
    }
}
