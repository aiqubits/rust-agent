//! Direct Agent driver: one prepared model call per turn.

use rust_agent_agent::{
    AgentContext, AgentDriver, AgentError, AgentFuture, AgentOutput, AgentRequest,
};
use rust_agent_core::{ContentBlock, Message, MessageRole};
use rust_agent_model::{
    ModelCallDraft, ModelParams, ModelRegistryBinding, ModelRequest, ModelRequestPurpose,
};
use rust_agent_runtime_api::{ComponentBuildError, ComponentOutput, RuntimePrimitiveBindings};

#[derive(Clone, Debug, Default)]
pub struct Config;

#[derive(Clone, Debug)]
pub struct Dependencies {
    pub model: ModelRegistryBinding,
}

#[derive(Debug)]
pub struct DirectDriver {
    model: ModelRegistryBinding,
}

impl AgentDriver for DirectDriver {
    fn run<'a>(
        &'a self,
        context: &'a AgentContext,
        request: AgentRequest,
    ) -> AgentFuture<'a, Result<AgentOutput, AgentError>> {
        Box::pin(async move {
            let plan = self.model.plan_call(ModelCallDraft {
                request_id: context.allocate_model_request()?,
                purpose: ModelRequestPurpose::AgentTurn,
                route: request.model_route().clone(),
                request: ModelRequest {
                    messages: vec![Message {
                        role: MessageRole::User,
                        content: vec![ContentBlock::Text(request.input().as_str().to_owned())],
                    }],
                    system: None,
                    tools: Vec::new(),
                    params: ModelParams::default(),
                },
                linked_from: None,
            })?;
            let prepared = context.prepare_model_call(plan).await?;
            let response = context.complete_model_call(&self.model, prepared).await?;
            AgentOutput::from_model_response(response)
        })
    }
}

pub fn build(
    _config: &Config,
    dependencies: Dependencies,
    runtime: RuntimePrimitiveBindings,
) -> Result<ComponentOutput<DirectDriver>, ComponentBuildError> {
    validate_runtime_projection(&runtime)?;
    drop(runtime);
    Ok(ComponentOutput::stateless(DirectDriver {
        model: dependencies.model,
    }))
}

fn validate_runtime_projection(
    runtime: &RuntimePrimitiveBindings,
) -> Result<(), ComponentBuildError> {
    validate_runtime_primitive_list(runtime.allowed())
}

fn validate_runtime_primitive_list(
    primitives: &[rust_agent_runtime_api::RuntimePrimitiveKind],
) -> Result<(), ComponentBuildError> {
    if primitives.is_empty() {
        Ok(())
    } else {
        Err(ComponentBuildError::InvalidConfig(
            "driver-direct declares no runtime primitives".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use rust_agent_runtime_api::RuntimePrimitiveKind;

    use super::*;

    #[test]
    fn driver_uses_only_its_projected_runtime_primitives() {
        assert!(validate_runtime_projection(&RuntimePrimitiveBindings::none()).is_ok());
        assert!(matches!(
            validate_runtime_primitive_list(&[RuntimePrimitiveKind::Clock]),
            Err(ComponentBuildError::InvalidConfig(_))
        ));
    }
}
