use std::{
    future::Future,
    sync::Arc,
    task::{Context, Poll, Wake, Waker},
    thread,
};

use rust_agent_generated_composition::*;

struct ThreadWake(thread::Thread);

impl Wake for ThreadWake {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

fn run<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let waker = Waker::from(Arc::new(ThreadWake(thread::current())));
    let mut context = Context::from_waker(&waker);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => thread::park(),
        }
    }
}

#[test]
fn generated_phase4_scope_prepares_initializes_runs_and_shuts_down() {
    let workspace_root = std::env::var("RUST_AGENT_PHASE4_WORKSPACE_ROOT").unwrap();
    let bubblewrap = std::env::var("RUST_AGENT_PHASE4_BWRAP").unwrap();
    let bubblewrap_digest = std::env::var("RUST_AGENT_PHASE4_BWRAP_SHA256").unwrap();
    let launcher = std::env::var("RUST_AGENT_PHASE4_LAUNCHER").unwrap();
    let launcher_digest = std::env::var("RUST_AGENT_PHASE4_LAUNCHER_SHA256").unwrap();
    let shell = std::env::var("RUST_AGENT_PHASE4_SHELL").unwrap();
    let shell_parent = std::path::Path::new(&shell)
        .parent()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();

    let runtime = create_runtime_primitives().unwrap();
    let config = RuntimeConfig {
        runtime: Default::default(),
        model_routing: None,
        fs_local: rust_agent_fs_local::Config::checked("").unwrap(),
        subprocess_local: rust_agent_subprocess_local::Config::checked(
            workspace_root,
            bubblewrap,
            bubblewrap_digest,
            launcher,
            launcher_digest,
            vec![shell_parent],
            vec![shell.clone()],
            Vec::new(),
        )
        .unwrap(),
        shell_local: rust_agent_shell_local::Config::checked(shell.clone()).unwrap(),
        terminal_local: rust_agent_terminal_local::Config::checked(shell).unwrap(),
    };
    let app = build(config, HostBindings, runtime).unwrap();
    assert!(app.publication_snapshot().entries().is_empty());
    let sealed = run(app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
    let allocated = run(app.allocate_agent_operation(sealed)).unwrap();
    let agent = run(app.create_agent(allocated.into_create_request())).unwrap();
    assert_eq!(app.publication_snapshot().entries().len(), 1);
    let request = AgentSendRequest::new(
        agent.allocate_turn_request().unwrap(),
        AgentInput::text("phase4").unwrap(),
        rust_agent_core::Digest::from_bytes([4; 32]),
        None,
    );
    assert_eq!(run(agent.send(request)).unwrap().text, "replay:phase4");
    run(agent.shutdown()).unwrap();
    assert!(app.publication_snapshot().entries().is_empty());
    run(app.shutdown()).unwrap();
}
