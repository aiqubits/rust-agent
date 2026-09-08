//! Canonical Component factory kept in the same privacy boundary as raw Tool handlers.

use rust_agent_policy::{ApprovalBinding, PermissionPolicyBinding};
use rust_agent_runtime_api::{
    ComponentBuildError, ComponentOutput, RuntimePrimitiveBindings, RuntimePrimitiveKind,
    ToolCallJournalVerifier,
};

use crate::{GuardedToolExecutor, ToolExecutionMiddlewareBinding, ToolProviderBinding};

#[derive(Clone, Debug, Default)]
pub struct Config;

/// Generated-only dependency envelope. Private fields prevent alternate dispatch assembly.
#[derive(Clone)]
pub struct Dependencies {
    providers: Vec<ToolProviderBinding>,
    permission: PermissionPolicyBinding,
    approval: Option<ApprovalBinding>,
    middleware: Vec<ToolExecutionMiddlewareBinding>,
    verifier: ToolCallJournalVerifier,
}

impl std::fmt::Debug for Dependencies {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Dependencies")
            .field("provider_count", &self.providers.len())
            .field("approval_present", &self.approval.is_some())
            .field("middleware_count", &self.middleware.len())
            .finish_non_exhaustive()
    }
}

impl Dependencies {
    #[doc(hidden)]
    pub fn from_generated_agent(
        providers: Vec<ToolProviderBinding>,
        permission: PermissionPolicyBinding,
        approval: Option<ApprovalBinding>,
        middleware: Vec<ToolExecutionMiddlewareBinding>,
        verifier: ToolCallJournalVerifier,
    ) -> Self {
        Self {
            providers,
            permission,
            approval,
            middleware,
            verifier,
        }
    }
}

pub fn build(
    _config: &Config,
    dependencies: Dependencies,
    runtime: RuntimePrimitiveBindings,
) -> Result<ComponentOutput<GuardedToolExecutor>, ComponentBuildError> {
    if runtime.allowed() != [RuntimePrimitiveKind::Clock, RuntimePrimitiveKind::Sleep] {
        return Err(ComponentBuildError::InvalidConfig(
            "tool-executor-guarded requires the exact clock/sleep primitive projection".into(),
        ));
    }
    let executor = GuardedToolExecutor::build(
        &dependencies.providers,
        dependencies.permission,
        dependencies.approval,
        &dependencies.middleware,
        dependencies.verifier,
        runtime,
    )
    .map_err(|error| ComponentBuildError::InvalidConfig(error.to_string()))?;
    Ok(ComponentOutput::stateless(executor))
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use rust_agent_core::{AgentId, CompositionHash, Digest};
    use rust_agent_policy::{Action, PermissionDecision, PermissionPolicy};
    use rust_agent_runtime_api::{
        AgentLifecycleNonce, RuntimeAdapterIdentity, RuntimeClock, RuntimeFuture,
        RuntimePrimitiveError, RuntimePrimitives, RuntimeSleeper, RuntimeSpawner, RuntimeTaskOwner,
        ToolCallJournalAuthority, ToolCallScopeIdentity,
    };

    use super::*;

    #[derive(Debug)]
    struct Allow;

    impl PermissionPolicy for Allow {
        fn evaluate(&self, _action: &Action) -> PermissionDecision {
            PermissionDecision::Allow
        }
    }

    #[derive(Debug)]
    struct ImmediateRuntime;

    impl RuntimeClock for ImmediateRuntime {
        fn now(&self) -> rust_agent_runtime_api::RuntimeInstant {
            rust_agent_runtime_api::RuntimeInstant::from_monotonic_duration(Duration::ZERO)
        }
    }

    impl RuntimeSleeper for ImmediateRuntime {
        fn sleep_until(
            &self,
            _deadline: rust_agent_runtime_api::RuntimeInstant,
        ) -> RuntimeFuture<'static, ()> {
            Box::pin(async {})
        }
    }

    impl RuntimeSpawner for ImmediateRuntime {
        fn spawn(
            &self,
            _owner: RuntimeTaskOwner,
            _task: RuntimeFuture<'static, ()>,
        ) -> Result<(), RuntimePrimitiveError> {
            Ok(())
        }

        fn drain(&self, _owner: RuntimeTaskOwner) -> RuntimeFuture<'static, ()> {
            Box::pin(async {})
        }
    }

    fn runtime() -> RuntimePrimitives {
        let driver = Arc::new(ImmediateRuntime);
        RuntimePrimitives::from_adapter(
            RuntimeAdapterIdentity::checked("test-runtime").unwrap(),
            Arc::clone(&driver),
            driver.clone(),
            driver.clone(),
            driver,
        )
    }

    fn dependencies() -> Dependencies {
        let (_, verifier) = ToolCallJournalAuthority::issue_for_generated_scope(
            ToolCallScopeIdentity::for_generated_agent(
                AgentId::from_nonzero_u128(1).unwrap(),
                AgentLifecycleNonce::from_nonzero(std::num::NonZeroU64::new(1).unwrap()),
                None,
                CompositionHash::from_digest(Digest::from_bytes([2; 32])),
                Digest::from_bytes([3; 32]),
            ),
        )
        .unwrap();
        Dependencies::from_generated_agent(
            Vec::new(),
            PermissionPolicyBinding::from_provider(Arc::new(Allow)),
            None,
            Vec::new(),
            verifier,
        )
    }

    #[test]
    fn build_accepts_only_the_declared_clock_and_sleep_projection() {
        assert!(matches!(
            build(&Config, dependencies(), RuntimePrimitiveBindings::none()),
            Err(ComponentBuildError::InvalidConfig(_))
        ));
        assert!(matches!(
            build(
                &Config,
                dependencies(),
                RuntimePrimitiveBindings::projected(
                    runtime(),
                    &[
                        RuntimePrimitiveKind::Clock,
                        RuntimePrimitiveKind::Sleep,
                        RuntimePrimitiveKind::Spawn,
                    ],
                )
                .unwrap(),
            ),
            Err(ComponentBuildError::InvalidConfig(_))
        ));
        let output = build(
            &Config,
            dependencies(),
            RuntimePrimitiveBindings::projected(
                runtime(),
                &[RuntimePrimitiveKind::Clock, RuntimePrimitiveKind::Sleep],
            )
            .unwrap(),
        )
        .unwrap();
        assert!(Arc::strong_count(output.service()) >= 1);
    }
}
