//! Conservative default permission provider.

use rust_agent_policy::{Action, ActionRisk, PermissionDecision, PermissionPolicy};
use rust_agent_runtime_api::{ComponentBuildError, ComponentOutput, RuntimePrimitiveBindings};

#[derive(Clone, Debug, Default)]
pub struct Config;

#[derive(Clone, Debug, Default)]
pub struct Dependencies;

#[derive(Debug)]
pub struct DefaultPermissionPolicy;

impl PermissionPolicy for DefaultPermissionPolicy {
    fn evaluate(&self, action: &Action) -> PermissionDecision {
        match action.risk() {
            ActionRisk::ReadOnly
                if action
                    .effects()
                    .is_subset_of(rust_agent_core::SecurityEffects::READ_LOCAL) =>
            {
                PermissionDecision::Allow
            }
            ActionRisk::ReadOnly => PermissionDecision::Deny,
            ActionRisk::Mutating | ActionRisk::Sensitive | ActionRisk::Unknown => {
                PermissionDecision::Ask
            }
        }
    }
}

pub fn build(
    _config: &Config,
    _dependencies: Dependencies,
    runtime: RuntimePrimitiveBindings,
) -> Result<ComponentOutput<DefaultPermissionPolicy>, ComponentBuildError> {
    validate_runtime_primitive_list(runtime.allowed())?;
    drop(runtime);
    Ok(ComponentOutput::stateless(DefaultPermissionPolicy))
}

fn validate_runtime_primitive_list(
    primitives: &[rust_agent_runtime_api::RuntimePrimitiveKind],
) -> Result<(), ComponentBuildError> {
    if primitives.is_empty() {
        Ok(())
    } else {
        Err(ComponentBuildError::InvalidConfig(
            "permission-default declares no runtime primitives".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use rust_agent_core::{Digest, SecurityEffects};
    use rust_agent_policy::{ActionKind, PermissionPolicyBinding};
    use rust_agent_runtime_api::RuntimePrimitiveKind;

    use super::*;

    fn action(risk: ActionRisk, effects: SecurityEffects) -> Action {
        Action::new(
            ActionKind::Tool,
            "fixture-tool",
            risk,
            effects,
            Digest::from_bytes([0; 32]),
        )
        .unwrap()
    }

    #[test]
    fn default_policy_allows_read_only_and_asks_for_every_higher_risk() {
        let binding = PermissionPolicyBinding::from_provider(
            build(&Config, Dependencies, RuntimePrimitiveBindings::none())
                .unwrap()
                .into_service(),
        );
        assert_eq!(
            binding.evaluate(&action(ActionRisk::ReadOnly, SecurityEffects::READ_LOCAL)),
            PermissionDecision::Allow
        );
        for risk in [
            ActionRisk::Mutating,
            ActionRisk::Sensitive,
            ActionRisk::Unknown,
        ] {
            assert_eq!(
                binding.evaluate(&action(risk, SecurityEffects::empty())),
                PermissionDecision::Ask
            );
        }
        assert_eq!(
            binding.evaluate(&action(ActionRisk::ReadOnly, SecurityEffects::WRITE_LOCAL)),
            PermissionDecision::Deny
        );
    }

    #[test]
    fn build_rejects_every_undeclared_runtime_primitive() {
        for primitive in [
            RuntimePrimitiveKind::Clock,
            RuntimePrimitiveKind::Sleep,
            RuntimePrimitiveKind::Spawn,
        ] {
            assert!(validate_runtime_primitive_list(&[primitive]).is_err());
        }
    }
}
