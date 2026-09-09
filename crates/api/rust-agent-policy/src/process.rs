//! Closed, provider-neutral process confinement policy and backend-plan schema.

use std::{fmt, num::NonZeroU32, num::NonZeroU64, num::NonZeroUsize};

use rust_agent_core::Digest;
use sha2::{Digest as _, Sha256};

pub const BACKEND_PLAN_SCHEMA_VERSION: u16 = 1;
pub const MAX_PROCESS_COUNT: u32 = 256;
pub const MAX_PROCESS_MEMORY_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub const MAX_PROCESS_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_PROCESS_WALL_TIME_MILLIS: u64 = 24 * 60 * 60 * 1_000;

const POLICY_DIGEST_DOMAIN: &[u8] = b"rust-agent-sandbox-policy-v1\0";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FilesystemAccess {
    None,
    ReadOnly,
    ReadWrite,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NetworkAccess {
    Deny,
    Outbound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::struct_field_names)]
pub struct ProcessResourceLimits {
    max_processes: NonZeroU32,
    max_memory_bytes: NonZeroU64,
    max_output_bytes: NonZeroUsize,
    max_wall_time_millis: NonZeroU64,
}

impl ProcessResourceLimits {
    pub fn checked(
        max_processes: NonZeroU32,
        max_memory_bytes: NonZeroU64,
        max_output_bytes: NonZeroUsize,
        max_wall_time_millis: NonZeroU64,
    ) -> Result<Self, SandboxPolicyError> {
        if max_processes.get() > MAX_PROCESS_COUNT
            || max_memory_bytes.get() > MAX_PROCESS_MEMORY_BYTES
            || max_output_bytes.get() > MAX_PROCESS_OUTPUT_BYTES
            || max_wall_time_millis.get() > MAX_PROCESS_WALL_TIME_MILLIS
        {
            return Err(SandboxPolicyError::LimitExceedsHardMaximum);
        }
        Ok(Self {
            max_processes,
            max_memory_bytes,
            max_output_bytes,
            max_wall_time_millis,
        })
    }

    pub const fn max_processes(self) -> NonZeroU32 {
        self.max_processes
    }

    pub const fn max_memory_bytes(self) -> NonZeroU64 {
        self.max_memory_bytes
    }

    pub const fn max_output_bytes(self) -> NonZeroUsize {
        self.max_output_bytes
    }

    pub const fn max_wall_time_millis(self) -> NonZeroU64 {
        self.max_wall_time_millis
    }

    const fn intersect(self, requested: Self) -> Self {
        Self {
            max_processes: min_nonzero_u32(self.max_processes, requested.max_processes),
            max_memory_bytes: min_nonzero_u64(self.max_memory_bytes, requested.max_memory_bytes),
            max_output_bytes: min_nonzero_usize(self.max_output_bytes, requested.max_output_bytes),
            max_wall_time_millis: min_nonzero_u64(
                self.max_wall_time_millis,
                requested.max_wall_time_millis,
            ),
        }
    }

    const fn is_within(self, ceiling: Self) -> bool {
        self.max_processes.get() <= ceiling.max_processes.get()
            && self.max_memory_bytes.get() <= ceiling.max_memory_bytes.get()
            && self.max_output_bytes.get() <= ceiling.max_output_bytes.get()
            && self.max_wall_time_millis.get() <= ceiling.max_wall_time_millis.get()
    }
}

const fn min_nonzero_u32(left: NonZeroU32, right: NonZeroU32) -> NonZeroU32 {
    if left.get() <= right.get() {
        left
    } else {
        right
    }
}

const fn min_nonzero_u64(left: NonZeroU64, right: NonZeroU64) -> NonZeroU64 {
    if left.get() <= right.get() {
        left
    } else {
        right
    }
}

const fn min_nonzero_usize(left: NonZeroUsize, right: NonZeroUsize) -> NonZeroUsize {
    if left.get() <= right.get() {
        left
    } else {
        right
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxPolicy {
    filesystem: FilesystemAccess,
    network: NetworkAccess,
    limits: ProcessResourceLimits,
}

impl SandboxPolicy {
    pub const fn new(
        filesystem: FilesystemAccess,
        network: NetworkAccess,
        limits: ProcessResourceLimits,
    ) -> Self {
        Self {
            filesystem,
            network,
            limits,
        }
    }

    pub const fn filesystem(&self) -> FilesystemAccess {
        self.filesystem
    }

    pub const fn network(&self) -> NetworkAccess {
        self.network
    }

    pub const fn limits(&self) -> ProcessResourceLimits {
        self.limits
    }

    #[must_use]
    pub fn intersect(&self, requested: &Self) -> Self {
        Self {
            filesystem: self.filesystem.min(requested.filesystem),
            network: self.network.min(requested.network),
            limits: self.limits.intersect(requested.limits),
        }
    }

    pub fn is_within(&self, ceiling: &Self) -> bool {
        self.filesystem <= ceiling.filesystem
            && self.network <= ceiling.network
            && self.limits.is_within(ceiling.limits)
    }

    pub fn digest(&self) -> Digest {
        let mut hasher = Sha256::new();
        hasher.update(POLICY_DIGEST_DOMAIN);
        hasher.update([filesystem_tag(self.filesystem), network_tag(self.network)]);
        hasher.update(self.limits.max_processes.get().to_be_bytes());
        hasher.update(self.limits.max_memory_bytes.get().to_be_bytes());
        hasher.update((self.limits.max_output_bytes.get() as u64).to_be_bytes());
        hasher.update(self.limits.max_wall_time_millis.get().to_be_bytes());
        Digest::from_bytes(hasher.finalize().into())
    }
}

const fn filesystem_tag(access: FilesystemAccess) -> u8 {
    match access {
        FilesystemAccess::None => 0,
        FilesystemAccess::ReadOnly => 1,
        FilesystemAccess::ReadWrite => 2,
    }
}

const fn network_tag(access: NetworkAccess) -> u8 {
    match access {
        NetworkAccess::Deny => 0,
        NetworkAccess::Outbound => 1,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxPolicyCeiling(SandboxPolicy);

impl SandboxPolicyCeiling {
    pub const fn new(policy: SandboxPolicy) -> Self {
        Self(policy)
    }

    pub const fn policy(&self) -> &SandboxPolicy {
        &self.0
    }

    pub fn project(&self, requested: &SandboxPolicy) -> SandboxPolicy {
        self.0.intersect(requested)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxPolicyError {
    LimitExceedsHardMaximum,
    UnsupportedPolicy,
    PolicyDigestMismatch,
}

impl fmt::Display for SandboxPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::LimitExceedsHardMaximum => "process resource limit exceeds the hard maximum",
            Self::UnsupportedPolicy => "the selected backend cannot enforce the policy",
            Self::PolicyDigestMismatch => "backend plan does not match the effective policy",
        })
    }
}

impl std::error::Error for SandboxPolicyError {}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct EnforcementPrimitives(u16);

impl EnforcementPrimitives {
    pub const NO_NEW_PRIVILEGES: Self = Self(1 << 0);
    pub const MOUNT_NAMESPACE: Self = Self(1 << 1);
    pub const PID_NAMESPACE: Self = Self(1 << 2);
    pub const NETWORK_NAMESPACE: Self = Self(1 << 3);
    pub const SECCOMP: Self = Self(1 << 4);
    pub const LANDLOCK: Self = Self(1 << 5);
    pub const PROCESS_GROUP: Self = Self(1 << 6);
    pub const RESOURCE_LIMITS: Self = Self(1 << 7);
    const ALL_BITS: u16 = (1 << 8) - 1;

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn all() -> Self {
        Self(Self::ALL_BITS)
    }

    pub const fn bits(self) -> u16 {
        self.0
    }

    pub const fn from_bits(bits: u16) -> Option<Self> {
        if bits & !Self::ALL_BITS == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }
}

impl std::ops::BitOr for EnforcementPrimitives {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl fmt::Debug for EnforcementPrimitives {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("EnforcementPrimitives")
            .field(&format_args!("{:#06x}", self.0))
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendKind {
    Linux,
}

#[derive(Debug, Eq, PartialEq)]
pub struct BackendPlan {
    schema_version: u16,
    kind: BackendKind,
    policy_digest: Digest,
    required_primitives: EnforcementPrimitives,
}

impl BackendPlan {
    #[cfg(target_os = "linux")]
    pub fn linux(
        policy: &SandboxPolicy,
        primitives: EnforcementPrimitives,
    ) -> Result<Self, SandboxPolicyError> {
        let required = required_linux_primitives(policy);
        if !primitives.contains(required) {
            return Err(SandboxPolicyError::UnsupportedPolicy);
        }
        Ok(Self {
            schema_version: BACKEND_PLAN_SCHEMA_VERSION,
            kind: BackendKind::Linux,
            policy_digest: policy.digest(),
            required_primitives: required,
        })
    }

    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub const fn kind(&self) -> BackendKind {
        self.kind
    }

    pub const fn policy_digest(&self) -> Digest {
        self.policy_digest
    }

    pub const fn required_primitives(&self) -> EnforcementPrimitives {
        self.required_primitives
    }

    pub fn validate_for(&self, policy: &SandboxPolicy) -> Result<(), SandboxPolicyError> {
        if self.schema_version != BACKEND_PLAN_SCHEMA_VERSION
            || self.policy_digest != policy.digest()
        {
            return Err(SandboxPolicyError::PolicyDigestMismatch);
        }
        #[cfg(target_os = "linux")]
        if self.kind == BackendKind::Linux
            && self.required_primitives != required_linux_primitives(policy)
        {
            return Err(SandboxPolicyError::UnsupportedPolicy);
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
const fn required_linux_primitives(policy: &SandboxPolicy) -> EnforcementPrimitives {
    let mut bits = EnforcementPrimitives::NO_NEW_PRIVILEGES.bits()
        | EnforcementPrimitives::MOUNT_NAMESPACE.bits()
        | EnforcementPrimitives::PID_NAMESPACE.bits()
        | EnforcementPrimitives::SECCOMP.bits()
        | EnforcementPrimitives::PROCESS_GROUP.bits()
        | EnforcementPrimitives::RESOURCE_LIMITS.bits();
    if !matches!(policy.filesystem, FilesystemAccess::None) {
        bits |= EnforcementPrimitives::LANDLOCK.bits();
    }
    if matches!(policy.network, NetworkAccess::Deny) {
        bits |= EnforcementPrimitives::NETWORK_NAMESPACE.bits();
    }
    EnforcementPrimitives(bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(processes: u32, output: usize) -> ProcessResourceLimits {
        ProcessResourceLimits::checked(
            NonZeroU32::new(processes).unwrap(),
            NonZeroU64::new(512 * 1024 * 1024).unwrap(),
            NonZeroUsize::new(output).unwrap(),
            NonZeroU64::new(30_000).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn policy_projection_is_monotonic_bounded_and_deterministic() {
        let ceiling = SandboxPolicyCeiling::new(SandboxPolicy::new(
            FilesystemAccess::ReadOnly,
            NetworkAccess::Deny,
            limits(2, 1024),
        ));
        let requested = SandboxPolicy::new(
            FilesystemAccess::ReadWrite,
            NetworkAccess::Outbound,
            limits(8, 4096),
        );
        let effective = ceiling.project(&requested);
        assert_eq!(effective.filesystem(), FilesystemAccess::ReadOnly);
        assert_eq!(effective.network(), NetworkAccess::Deny);
        assert_eq!(effective.limits().max_processes().get(), 2);
        assert_eq!(effective.limits().max_output_bytes().get(), 1024);
        assert!(effective.is_within(ceiling.policy()));
        assert_eq!(effective.digest(), ceiling.project(&requested).digest());
        assert_ne!(effective.digest(), requested.digest());
    }

    #[test]
    fn hard_limits_reject_before_a_policy_is_retained() {
        assert_eq!(
            ProcessResourceLimits::checked(
                NonZeroU32::new(MAX_PROCESS_COUNT + 1).unwrap(),
                NonZeroU64::MIN,
                NonZeroUsize::MIN,
                NonZeroU64::MIN,
            ),
            Err(SandboxPolicyError::LimitExceedsHardMaximum)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_plan_is_closed_policy_bound_and_fail_closed() {
        let policy = SandboxPolicy::new(
            FilesystemAccess::ReadOnly,
            NetworkAccess::Deny,
            limits(2, 1024),
        );
        assert_eq!(
            BackendPlan::linux(&policy, EnforcementPrimitives::empty()),
            Err(SandboxPolicyError::UnsupportedPolicy)
        );
        let plan = BackendPlan::linux(&policy, EnforcementPrimitives::all()).unwrap();
        assert_eq!(plan.schema_version(), BACKEND_PLAN_SCHEMA_VERSION);
        assert_eq!(plan.kind(), BackendKind::Linux);
        assert_eq!(plan.policy_digest(), policy.digest());
        assert!(
            plan.required_primitives()
                .contains(EnforcementPrimitives::NETWORK_NAMESPACE)
        );
        assert_eq!(plan.validate_for(&policy), Ok(()));

        let wider = SandboxPolicy::new(
            FilesystemAccess::ReadWrite,
            NetworkAccess::Outbound,
            limits(4, 2048),
        );
        assert_eq!(
            plan.validate_for(&wider),
            Err(SandboxPolicyError::PolicyDigestMismatch)
        );
    }
}
