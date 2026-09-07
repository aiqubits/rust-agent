//! Deterministic, effect-free model replay provider.

use futures_util::stream;
use rust_agent_core::Usage;
use rust_agent_model::{
    LanguageModel, ModelCallContext, ModelError, ModelEvent, ModelFuture, ModelId, ModelRequest,
    ModelStream, ProviderKey,
};
use rust_agent_runtime_api::{ComponentBuildError, ComponentOutput, RuntimePrimitiveBindings};

#[derive(Clone, Debug, Default)]
pub struct Config;

#[derive(Clone, Debug, Default)]
pub struct Dependencies;

#[derive(Debug)]
pub struct ReplayModel;

impl LanguageModel for ReplayModel {
    fn provider_key(&self) -> ProviderKey {
        ProviderKey::new("replay").expect("built-in provider key is canonical")
    }

    fn model_id(&self) -> ModelId {
        ModelId::new("replay-v1").expect("built-in model id is canonical")
    }

    fn stream(
        &self,
        context: ModelCallContext,
        request: ModelRequest,
    ) -> ModelFuture<'_, Result<ModelStream, ModelError>> {
        Box::pin(async move {
            if context.cancellation().is_cancelled() {
                return Err(ModelError::Cancelled);
            }
            let input = request
                .messages
                .last()
                .and_then(|message| message.content.last())
                .and_then(|content| match content {
                    rust_agent_core::ContentBlock::Text(value) => Some(value.as_str()),
                    _ => None,
                })
                .ok_or(ModelError::InvalidRequest(
                    "replay requires a final text message",
                ))?;
            let response = format!("replay:{input}");
            let usage = Usage {
                input_tokens: input.split_whitespace().count() as u64,
                output_tokens: response.split_whitespace().count() as u64,
            };
            Ok(Box::pin(stream::iter([
                Ok(ModelEvent::Delta(response)),
                Ok(ModelEvent::Completed(usage)),
            ])) as ModelStream)
        })
    }
}

pub fn build(
    _config: &Config,
    _dependencies: Dependencies,
    _runtime: RuntimePrimitiveBindings,
) -> Result<ComponentOutput<ReplayModel>, ComponentBuildError> {
    Ok(ComponentOutput::stateless(ReplayModel))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instances_are_independent_for_identical_and_boundary_construction() {
        let config = Config;
        let first = build(&config, Dependencies, RuntimePrimitiveBindings::none()).unwrap();
        let second = build(&Config, Dependencies, RuntimePrimitiveBindings::none()).unwrap();

        assert!(!std::sync::Arc::ptr_eq(first.service(), second.service()));
        assert_eq!(
            first.service().provider_key(),
            second.service().provider_key()
        );
    }
}
