#![forbid(unsafe_code)]

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use agent::host_api::fixture_model_shared::{
    Config, SharedHostHandle, SharedModelResource,
};

#[derive(Debug)]
struct HostResource;

impl SharedModelResource for HostResource {
    fn respond(&self, request: &str) -> String {
        format!("shared-host:{request}")
    }
}

fn open_resource(open_count: &AtomicUsize) -> Arc<dyn SharedModelResource> {
    open_count.fetch_add(1, Ordering::SeqCst);
    Arc::new(HostResource)
}

fn build_app(shared: SharedHostHandle<dyn SharedModelResource>) -> agent::FixtureApp {
    let runtime = agent::create_runtime_primitives().unwrap();
    let mut bindings = agent::HostBindingsBuilder::new();
    bindings
        .set_fixture_model_shared(Config { shared })
        .unwrap();
    agent::build(
        agent::RuntimeConfig::default(),
        bindings.build().unwrap(),
        runtime,
    )
    .unwrap()
}

#[cfg(test)]
mod tests {
    use agent::{AppHandoffError, AppHandoffMode};

    use super::*;

    #[test]
    fn host_bindings_builder_rejects_missing_and_duplicate_values() {
        assert!(matches!(
            agent::HostBindingsBuilder::new().build(),
            Err(agent::HostBindingsError::MissingField(
                "fixture-model-shared"
            ))
        ));

        let open_count = AtomicUsize::new(0);
        let shared = SharedHostHandle::new(open_resource(&open_count));
        let mut bindings = agent::HostBindingsBuilder::new();
        bindings
            .set_fixture_model_shared(Config {
                shared: shared.clone(),
            })
            .unwrap();
        assert!(matches!(
            bindings.set_fixture_model_shared(Config { shared }),
            Err(agent::HostBindingsError::DuplicateField(
                "fixture-model-shared"
            ))
        ));
        assert_eq!(open_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn two_apps_share_one_host_open_and_one_private_wrapper_identity() {
        let open_count = AtomicUsize::new(0);
        let shared = SharedHostHandle::new(open_resource(&open_count));

        let old = build_app(shared.clone());
        let new = build_app(shared);

        assert_eq!(open_count.load(Ordering::SeqCst), 1);
        assert_eq!(old.app_handoff_mode(), AppHandoffMode::Concurrent);
        assert_eq!(new.run("request"), "shared-host:request");
        new.verify_concurrent_handoff_from(&old).unwrap();
    }

    #[test]
    fn a_second_wrapper_for_the_same_resource_cannot_impersonate_the_first() {
        let open_count = AtomicUsize::new(0);
        let resource = open_resource(&open_count);
        let old = build_app(SharedHostHandle::new(Arc::clone(&resource)));
        let new = build_app(SharedHostHandle::new(resource));

        assert_eq!(open_count.load(Ordering::SeqCst), 1);
        assert_eq!(
            new.verify_concurrent_handoff_from(&old),
            Err(AppHandoffError::SharedIdentityMismatch(
                "fixture-model-shared.shared"
            ))
        );
    }
}
