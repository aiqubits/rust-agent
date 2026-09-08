//! Stateless lifecycle observer used when a composition wants an explicit observer seam.

use rust_agent_runtime_api::{
    ComponentBuildError, ComponentOutput, DisposalEvent, LifecycleNotificationContext,
    LifecycleObserver, LifecycleObserverFuture, PublicationCandidate, PublicationEvent,
    PublicationSnapshot, PublicationTransactionView, PublicationVeto, RuntimePrimitiveBindings,
};

#[derive(Clone, Debug, Default)]
pub struct Config;

#[derive(Clone, Debug, Default)]
pub struct Dependencies;

#[derive(Debug)]
pub struct NoopLifecycleObserver;

impl LifecycleObserver for NoopLifecycleObserver {
    fn before_publish(
        &self,
        _event: &PublicationCandidate,
        _view: &PublicationTransactionView<'_>,
    ) -> Result<(), PublicationVeto> {
        Ok(())
    }

    fn published<'a>(
        &'a self,
        _context: LifecycleNotificationContext,
        _event: &'a PublicationEvent,
        _snapshot: &'a PublicationSnapshot,
    ) -> LifecycleObserverFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    fn disposed<'a>(
        &'a self,
        _context: LifecycleNotificationContext,
        _event: &'a DisposalEvent,
        _snapshot: &'a PublicationSnapshot,
    ) -> LifecycleObserverFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

pub fn build(
    _config: &Config,
    _dependencies: Dependencies,
    runtime: RuntimePrimitiveBindings,
) -> Result<ComponentOutput<NoopLifecycleObserver>, ComponentBuildError> {
    validate_runtime_primitive_list(runtime.allowed())?;
    drop(runtime);
    Ok(ComponentOutput::stateless(NoopLifecycleObserver))
}

fn validate_runtime_primitive_list(
    primitives: &[rust_agent_runtime_api::RuntimePrimitiveKind],
) -> Result<(), ComponentBuildError> {
    if primitives.is_empty() {
        Ok(())
    } else {
        Err(ComponentBuildError::InvalidConfig(
            "lifecycle-observer-noop declares no runtime primitives".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observer_is_stateless_and_requires_no_runtime_primitive() {
        assert!(build(&Config, Dependencies, RuntimePrimitiveBindings::none()).is_ok());
        assert!(
            validate_runtime_primitive_list(
                &[rust_agent_runtime_api::RuntimePrimitiveKind::Clock,]
            )
            .is_err()
        );
    }
}
