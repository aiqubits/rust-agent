use std::{fmt, num::NonZeroU64, sync::Arc, sync::atomic::AtomicU64, sync::atomic::Ordering};

use rust_agent_core::Digest;
use rust_agent_policy::process::{BackendPlan, SandboxPolicy, SandboxPolicyCeiling};

use crate::{ProcessError, ProcessSpec, SandboxError};

static NEXT_CONFINEMENT_AUTHORITY: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
struct ConfinementAuthorityState {
    identity: NonZeroU64,
    ceiling: SandboxPolicyCeiling,
}

/// Factory for an unforgeable issuer/verifier pair belonging to one Agent scope.
#[derive(Debug)]
pub struct ConfinementAuthority;

impl ConfinementAuthority {
    #[doc(hidden)]
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        ceiling: SandboxPolicyCeiling,
    ) -> Result<(ConfinementIssuer, ConfinementVerifier), SandboxError> {
        let identity = NEXT_CONFINEMENT_AUTHORITY
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .ok()
            .and_then(NonZeroU64::new)
            .ok_or(SandboxError::AuthorityExhausted)?;
        let state = Arc::new(ConfinementAuthorityState { identity, ceiling });
        Ok((
            ConfinementIssuer {
                state: Arc::clone(&state),
            },
            ConfinementVerifier { state },
        ))
    }
}

/// Issuer half injected only into the selected sandbox provider.
pub struct ConfinementIssuer {
    state: Arc<ConfinementAuthorityState>,
}

impl ConfinementIssuer {
    pub fn project(&self, requested: &SandboxPolicy) -> ConfinementProjection {
        let effective_policy = self.state.ceiling.project(requested);
        let policy_digest = effective_policy.digest();
        ConfinementProjection {
            authority: Arc::clone(&self.state),
            effective_policy,
            policy_digest,
        }
    }

    pub fn seal(
        &self,
        process: ProcessSpec,
        projection: ConfinementProjection,
        backend_plan: BackendPlan,
    ) -> Result<ConfinedProcessSpec, SandboxError> {
        if !Arc::ptr_eq(&self.state, &projection.authority) {
            return Err(SandboxError::AuthorityMismatch);
        }
        if !projection
            .effective_policy
            .is_within(self.state.ceiling.policy())
        {
            return Err(SandboxError::PolicyExceedsCeiling);
        }
        if projection.policy_digest != projection.effective_policy.digest()
            || backend_plan.policy_digest() != projection.policy_digest
        {
            return Err(SandboxError::PolicyDigestMismatch);
        }
        backend_plan
            .validate_for(&projection.effective_policy)
            .map_err(SandboxError::from_policy)?;
        Ok(ConfinedProcessSpec {
            authority: projection.authority,
            process,
            effective_policy: projection.effective_policy,
            policy_digest: projection.policy_digest,
            backend_plan,
        })
    }
}

impl fmt::Debug for ConfinementIssuer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfinementIssuer")
            .field("authority", &self.state.identity)
            .finish_non_exhaustive()
    }
}

/// Verifier half injected only into the selected subprocess provider.
pub struct ConfinementVerifier {
    state: Arc<ConfinementAuthorityState>,
}

impl ConfinementVerifier {
    pub fn verify(
        &self,
        confined: ConfinedProcessSpec,
    ) -> Result<VerifiedProcessSpec, ProcessError> {
        if !Arc::ptr_eq(&self.state, &confined.authority) {
            return Err(ProcessError::AuthorityMismatch);
        }
        if !confined
            .effective_policy
            .is_within(self.state.ceiling.policy())
        {
            return Err(ProcessError::PolicyExceedsCeiling);
        }
        if confined.policy_digest != confined.effective_policy.digest()
            || confined.backend_plan.policy_digest() != confined.policy_digest
        {
            return Err(ProcessError::PolicyDigestMismatch);
        }
        confined
            .backend_plan
            .validate_for(&confined.effective_policy)
            .map_err(ProcessError::from_policy)?;
        Ok(VerifiedProcessSpec {
            process: confined.process,
            effective_policy: confined.effective_policy,
            policy_digest: confined.policy_digest,
            backend_plan: confined.backend_plan,
        })
    }
}

impl fmt::Debug for ConfinementVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfinementVerifier")
            .field("authority", &self.state.identity)
            .finish_non_exhaustive()
    }
}

/// Exact effective policy projection. It is scope-bound, non-cloneable and non-serializable.
pub struct ConfinementProjection {
    authority: Arc<ConfinementAuthorityState>,
    effective_policy: SandboxPolicy,
    policy_digest: Digest,
}

impl ConfinementProjection {
    pub const fn effective_policy(&self) -> &SandboxPolicy {
        &self.effective_policy
    }

    pub const fn policy_digest(&self) -> Digest {
        self.policy_digest
    }
}

impl fmt::Debug for ConfinementProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfinementProjection")
            .field("policy_digest", &self.policy_digest)
            .finish_non_exhaustive()
    }
}

/// The only process input accepted by [`crate::Subprocess`].
///
/// Its fields are private and it deliberately implements neither `Clone`, `Default` nor any
/// deserialization trait.
pub struct ConfinedProcessSpec {
    authority: Arc<ConfinementAuthorityState>,
    process: ProcessSpec,
    effective_policy: SandboxPolicy,
    policy_digest: Digest,
    backend_plan: BackendPlan,
}

impl ConfinedProcessSpec {
    pub const fn policy_digest(&self) -> Digest {
        self.policy_digest
    }

    pub const fn output_budget(&self) -> usize {
        self.effective_policy.limits().max_output_bytes().get()
    }

    pub(crate) const fn backend_kind(&self) -> rust_agent_policy::process::BackendKind {
        self.backend_plan.kind()
    }

    pub(crate) const fn required_primitives(
        &self,
    ) -> rust_agent_policy::process::EnforcementPrimitives {
        self.backend_plan.required_primitives()
    }
}

impl fmt::Debug for ConfinedProcessSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfinedProcessSpec")
            .field("authority", &self.authority.identity)
            .field("policy_digest", &self.policy_digest)
            .field("backend", &self.backend_plan.kind())
            .finish_non_exhaustive()
    }
}

/// Verifier output consumed by a subprocess provider while performing pre-exec setup.
pub struct VerifiedProcessSpec {
    process: ProcessSpec,
    effective_policy: SandboxPolicy,
    policy_digest: Digest,
    backend_plan: BackendPlan,
}

impl VerifiedProcessSpec {
    pub const fn process(&self) -> &ProcessSpec {
        &self.process
    }

    pub const fn effective_policy(&self) -> &SandboxPolicy {
        &self.effective_policy
    }

    pub const fn policy_digest(&self) -> Digest {
        self.policy_digest
    }

    pub const fn backend_plan(&self) -> &BackendPlan {
        &self.backend_plan
    }
}

impl fmt::Debug for VerifiedProcessSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedProcessSpec")
            .field("process", &self.process)
            .field("policy_digest", &self.policy_digest)
            .field("backend", &self.backend_plan.kind())
            .finish_non_exhaustive()
    }
}

/// Generated-only binding for the authority issuer half.
pub struct ConfinementIssuerBinding {
    issuer: ConfinementIssuer,
}

impl ConfinementIssuerBinding {
    #[doc(hidden)]
    pub const fn from_generated_authority(issuer: ConfinementIssuer) -> Self {
        Self { issuer }
    }

    pub fn project(&self, requested: &SandboxPolicy) -> ConfinementProjection {
        self.issuer.project(requested)
    }

    pub fn seal(
        &self,
        process: ProcessSpec,
        projection: ConfinementProjection,
        backend_plan: BackendPlan,
    ) -> Result<ConfinedProcessSpec, SandboxError> {
        self.issuer.seal(process, projection, backend_plan)
    }
}

impl fmt::Debug for ConfinementIssuerBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfinementIssuerBinding")
            .finish_non_exhaustive()
    }
}

/// Generated-only binding for the paired verifier half.
pub struct ConfinementVerifierBinding {
    verifier: ConfinementVerifier,
}

impl ConfinementVerifierBinding {
    #[doc(hidden)]
    pub const fn from_generated_authority(verifier: ConfinementVerifier) -> Self {
        Self { verifier }
    }

    pub fn verify(
        &self,
        confined: ConfinedProcessSpec,
    ) -> Result<VerifiedProcessSpec, ProcessError> {
        self.verifier.verify(confined)
    }
}

impl fmt::Debug for ConfinementVerifierBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfinementVerifierBinding")
            .finish_non_exhaustive()
    }
}
