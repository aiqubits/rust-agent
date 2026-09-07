//! Model provider that delegates to an explicitly supplied typed Host handle.

use std::sync::Arc;

use rust_agent_model::{
    LanguageModel, ModelCallContext, ModelError, ModelFuture, ModelId, ModelRequest, ModelStream,
    ProviderKey,
};
use rust_agent_runtime_api::{ComponentBuildError, ComponentOutput, RuntimePrimitiveBindings};

pub mod host_api {
    use rust_agent_model::LanguageModel;
    use rust_agent_runtime_api::SharedHostHandle;

    #[derive(Clone, Debug)]
    pub struct Config {
        pub model: SharedHostHandle<dyn LanguageModel>,
    }
}

#[derive(Clone, Debug, Default)]
pub struct Dependencies;

pub struct HostModel {
    inner: Arc<dyn LanguageModel>,
}

impl std::fmt::Debug for HostModel {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("HostModel(<opaque>)")
    }
}

impl LanguageModel for HostModel {
    fn provider_key(&self) -> ProviderKey {
        ProviderKey::new("host").expect("built-in provider key is canonical")
    }

    fn model_id(&self) -> ModelId {
        self.inner.model_id()
    }

    fn stream(
        &self,
        context: ModelCallContext,
        request: ModelRequest,
    ) -> ModelFuture<'_, Result<ModelStream, ModelError>> {
        self.inner.stream(context, request)
    }
}

pub fn build(
    config: &host_api::Config,
    _dependencies: Dependencies,
    _runtime: RuntimePrimitiveBindings,
) -> Result<ComponentOutput<HostModel>, ComponentBuildError> {
    Ok(ComponentOutput::stateless(HostModel {
        inner: config.model.service(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_agent_runtime_api::SharedHostHandle;

    #[derive(Debug)]
    struct TestModel;

    impl LanguageModel for TestModel {
        fn provider_key(&self) -> ProviderKey {
            ProviderKey::new("test-host").unwrap()
        }

        fn model_id(&self) -> ModelId {
            ModelId::new("test-host-v1").unwrap()
        }

        fn stream(
            &self,
            _context: ModelCallContext,
            _request: ModelRequest,
        ) -> ModelFuture<'_, Result<ModelStream, ModelError>> {
            Box::pin(async {
                Err(ModelError::Provider {
                    category: "test",
                    message: "not invoked".into(),
                })
            })
        }
    }

    #[test]
    fn host_service_identity_is_reused_without_reopen() {
        let service: Arc<dyn LanguageModel> = Arc::new(TestModel);
        let shared = SharedHostHandle::new(Arc::clone(&service));
        let first = build(
            &host_api::Config {
                model: shared.clone(),
            },
            Dependencies,
            RuntimePrimitiveBindings::none(),
        )
        .unwrap();
        let second = build(
            &host_api::Config { model: shared },
            Dependencies,
            RuntimePrimitiveBindings::none(),
        )
        .unwrap();

        assert!(Arc::ptr_eq(&first.service().inner, &service));
        assert!(Arc::ptr_eq(&first.service().inner, &second.service().inner));
    }
}
