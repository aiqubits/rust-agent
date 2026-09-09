//! Linux sandbox planner that seals one ceiling-projected backend plan.

use rust_agent_core::{CanonicalId, SecurityEffects};
use rust_agent_policy::process::SandboxPolicy;
#[cfg(target_os = "linux")]
use rust_agent_policy::process::{BackendPlan, EnforcementPrimitives};
use rust_agent_process::{
    ConfinedProcessSpec, ConfinementIssuerBinding, ProcessFuture, ProcessSpec, Sandbox,
    SandboxError,
};
use rust_agent_runtime_api::{ComponentBuildError, ComponentOutput, RuntimePrimitiveBindings};

#[derive(Clone, Debug, Default)]
pub struct Config;

#[derive(Debug)]
pub struct Dependencies {
    pub confinement_issuer: ConfinementIssuerBinding,
}

#[derive(Debug)]
pub struct LinuxSandbox {
    confinement_issuer: ConfinementIssuerBinding,
}

impl Sandbox for LinuxSandbox {
    fn provider_key(&self) -> CanonicalId {
        CanonicalId::new("sandbox-linux").expect("static provider key is canonical")
    }

    fn effects(&self) -> SecurityEffects {
        SecurityEffects::empty()
    }

    fn confine(
        &self,
        process: ProcessSpec,
        requested_policy: SandboxPolicy,
    ) -> ProcessFuture<'_, Result<ConfinedProcessSpec, SandboxError>> {
        Box::pin(async move {
            #[cfg(target_os = "linux")]
            {
                let projection = self.confinement_issuer.project(&requested_policy);
                let plan =
                    BackendPlan::linux(projection.effective_policy(), supported_linux_primitives())
                        .map_err(|_| SandboxError::UnsupportedPolicy)?;
                self.confinement_issuer.seal(process, projection, plan)
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (process, requested_policy);
                Err(SandboxError::UnsupportedPolicy)
            }
        })
    }
}

#[cfg(target_os = "linux")]
fn supported_linux_primitives() -> EnforcementPrimitives {
    EnforcementPrimitives::NO_NEW_PRIVILEGES
        | EnforcementPrimitives::MOUNT_NAMESPACE
        | EnforcementPrimitives::PID_NAMESPACE
        | EnforcementPrimitives::NETWORK_NAMESPACE
        | EnforcementPrimitives::SECCOMP
        | EnforcementPrimitives::LANDLOCK
        | EnforcementPrimitives::PROCESS_GROUP
        | EnforcementPrimitives::RESOURCE_LIMITS
}

pub fn build(
    _config: &Config,
    dependencies: Dependencies,
    runtime: RuntimePrimitiveBindings,
) -> Result<ComponentOutput<LinuxSandbox>, ComponentBuildError> {
    validate_runtime_primitives(runtime.allowed())?;
    drop(runtime);
    #[cfg(not(target_os = "linux"))]
    {
        let _ = dependencies;
        return Err(ComponentBuildError::InvalidConfig(
            "sandbox-linux is available only on Linux".into(),
        ));
    }
    #[cfg(target_os = "linux")]
    Ok(ComponentOutput::stateless(LinuxSandbox {
        confinement_issuer: dependencies.confinement_issuer,
    }))
}

fn validate_runtime_primitives(
    primitives: &[rust_agent_runtime_api::RuntimePrimitiveKind],
) -> Result<(), ComponentBuildError> {
    if primitives.is_empty() {
        Ok(())
    } else {
        Err(ComponentBuildError::InvalidConfig(
            "sandbox-linux declares no runtime primitives".into(),
        ))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::{
        future::Future,
        num::{NonZeroU32, NonZeroU64, NonZeroUsize},
        task::{Context, Poll, Waker},
    };

    use rust_agent_fs::AgentPath;
    use rust_agent_policy::process::{
        FilesystemAccess, NetworkAccess, ProcessResourceLimits, SandboxPolicyCeiling,
    };
    use rust_agent_process::{
        ConfinementAuthority, ConfinementVerifierBinding, ProcessEnvironment, ProcessExecutable,
        SandboxBinding,
    };

    use super::*;

    fn ready<T>(mut future: ProcessFuture<'_, T>) -> T {
        let mut context = Context::from_waker(Waker::noop());
        match Future::poll(future.as_mut(), &mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("sandbox future unexpectedly pending"),
        }
    }

    fn policy(
        filesystem: FilesystemAccess,
        network: NetworkAccess,
        processes: u32,
        output: usize,
    ) -> SandboxPolicy {
        SandboxPolicy::new(
            filesystem,
            network,
            ProcessResourceLimits::checked(
                NonZeroU32::new(processes).unwrap(),
                NonZeroU64::new(512 * 1024 * 1024).unwrap(),
                NonZeroUsize::new(output).unwrap(),
                NonZeroU64::new(30_000).unwrap(),
            )
            .unwrap(),
        )
    }

    fn process() -> ProcessSpec {
        ProcessSpec::checked(
            ProcessExecutable::absolute("/usr/bin/printf").unwrap(),
            ["ok".to_owned()],
            AgentPath::new("workspace").unwrap(),
            ProcessEnvironment::empty(),
            Vec::new(),
        )
        .unwrap()
    }

    fn make_sandbox(ceiling: SandboxPolicy) -> (SandboxBinding, ConfinementVerifierBinding) {
        let (issuer, verifier) =
            ConfinementAuthority::new(SandboxPolicyCeiling::new(ceiling)).unwrap();
        let service = build(
            &Config,
            Dependencies {
                confinement_issuer: ConfinementIssuerBinding::from_generated_authority(issuer),
            },
            RuntimePrimitiveBindings::none(),
        )
        .unwrap()
        .into_service();
        (
            SandboxBinding::from_generated_component(
                "sandbox-linux",
                SecurityEffects::empty(),
                service,
            )
            .unwrap(),
            ConfinementVerifierBinding::from_generated_authority(verifier),
        )
    }

    #[test]
    fn requested_policy_is_monotonically_projected_and_pair_sealed() {
        let ceiling = policy(FilesystemAccess::ReadOnly, NetworkAccess::Deny, 2, 1024);
        let requested = policy(
            FilesystemAccess::ReadWrite,
            NetworkAccess::Outbound,
            8,
            4096,
        );
        let (sandbox, verifier) = make_sandbox(ceiling.clone());
        let confined = ready(sandbox.confine(process(), requested)).unwrap();
        assert_eq!(confined.output_budget(), 1024);
        let checked = verifier.verify(confined).unwrap();
        assert_eq!(checked.effective_policy(), &ceiling);
        assert_eq!(checked.policy_digest(), ceiling.digest());
        let required = checked.backend_plan().required_primitives();
        assert!(required.contains(EnforcementPrimitives::NO_NEW_PRIVILEGES));
        assert!(required.contains(EnforcementPrimitives::MOUNT_NAMESPACE));
        assert!(required.contains(EnforcementPrimitives::PID_NAMESPACE));
        assert!(required.contains(EnforcementPrimitives::NETWORK_NAMESPACE));
        assert!(required.contains(EnforcementPrimitives::SECCOMP));
        assert!(required.contains(EnforcementPrimitives::LANDLOCK));
        assert!(required.contains(EnforcementPrimitives::PROCESS_GROUP));
        assert!(required.contains(EnforcementPrimitives::RESOURCE_LIMITS));
    }

    #[test]
    fn authority_and_runtime_projection_fail_closed_without_a_spec_escape() {
        let ceiling = policy(FilesystemAccess::ReadOnly, NetworkAccess::Deny, 2, 1024);
        let (sandbox, _verifier) = make_sandbox(ceiling.clone());
        let (_foreign_sandbox, foreign_verifier) = make_sandbox(ceiling.clone());
        let confined = ready(sandbox.confine(process(), ceiling)).unwrap();
        assert!(matches!(
            foreign_verifier.verify(confined),
            Err(rust_agent_process::ProcessError::AuthorityMismatch)
        ));

        assert!(matches!(
            validate_runtime_primitives(&[rust_agent_runtime_api::RuntimePrimitiveKind::Clock]),
            Err(ComponentBuildError::InvalidConfig(_))
        ));
    }

    #[test]
    fn provider_is_effect_free_and_backend_plan_is_deterministic() {
        let ceiling = policy(FilesystemAccess::None, NetworkAccess::Outbound, 1, 256);
        let requested = policy(
            FilesystemAccess::ReadWrite,
            NetworkAccess::Outbound,
            8,
            4096,
        );
        let (sandbox, verifier) = make_sandbox(ceiling);
        assert_eq!(sandbox.effects(), SecurityEffects::empty());
        let first = verifier
            .verify(ready(sandbox.confine(process(), requested.clone())).unwrap())
            .unwrap();
        let first_digest = first.policy_digest();
        let first_primitives = first.backend_plan().required_primitives();

        let ceiling = policy(FilesystemAccess::None, NetworkAccess::Outbound, 1, 256);
        let (sandbox, verifier) = make_sandbox(ceiling);
        let second = verifier
            .verify(ready(sandbox.confine(process(), requested)).unwrap())
            .unwrap();
        assert_eq!(second.policy_digest(), first_digest);
        assert_eq!(
            second.backend_plan().required_primitives(),
            first_primitives
        );
        assert!(!first_primitives.contains(EnforcementPrimitives::LANDLOCK));
        assert!(!first_primitives.contains(EnforcementPrimitives::NETWORK_NAMESPACE));
    }
}
