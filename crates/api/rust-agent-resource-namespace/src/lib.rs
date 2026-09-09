//! Stamped, bounded resource-namespace preparation contracts.
//!
//! This crate performs only validation and hashing. Locator I/O belongs to a selected bootstrap
//! Component, while generated scope code owns projection and context creation.

#[cfg(unix)]
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::{fmt, future::Future, pin::Pin, sync::Arc};

use rust_agent_core::{CanonicalId, CapabilityId, Digest, MaybeSendSync, SecurityEffects};
use rust_agent_runtime_api::{CancellationToken, RuntimeInstant};
use sha2::{Digest as _, Sha256};

pub const MAX_RESOURCE_LOCATOR_BYTES: usize = 4 * 1024;
pub const MAX_RESOURCE_LOCATOR_DEPTH: usize = 128;
pub const MAX_HOST_STABLE_NAMESPACE_ID_BYTES: usize = 256;
pub const MAX_PREPARED_NAMESPACES: usize = 16;

const RESOURCE_NAMESPACE_DIGEST_DOMAIN: &[u8] = b"rust-agent-resource-namespace-v1\0";

#[cfg(not(target_arch = "wasm32"))]
pub type ResourceNamespaceFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub type ResourceNamespaceFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// A lexically normalized root relative to the bootstrap provider's local base directory.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LocalResourceLocator(Arc<str>);

impl LocalResourceLocator {
    pub fn root() -> Self {
        Self(Arc::from(""))
    }

    pub fn new(value: impl Into<String>) -> Result<Self, ResourceNamespacePrepareError> {
        let value = value.into();
        validate_locator(&value)?;
        Ok(Self(Arc::from(value)))
    }

    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn depth(&self) -> usize {
        if self.is_root() {
            0
        } else {
            self.0.split('/').count()
        }
    }

    pub fn provider_relative_path(&self) -> &str {
        if self.is_root() { "." } else { &self.0 }
    }
}

impl fmt::Debug for LocalResourceLocator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("LocalResourceLocator")
            .field(&self.0)
            .finish()
    }
}

fn validate_locator(value: &str) -> Result<(), ResourceNamespacePrepareError> {
    if value.is_empty()
        || value.len() > MAX_RESOURCE_LOCATOR_BYTES
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains('\\')
    {
        return Err(ResourceNamespacePrepareError::InvalidLocator);
    }
    let mut depth = 0_usize;
    for segment in value.split('/') {
        if segment.is_empty()
            || matches!(segment, "." | "..")
            || segment
                .chars()
                .any(|character| character == '\0' || character.is_control())
        {
            return Err(ResourceNamespacePrepareError::InvalidLocator);
        }
        depth = depth
            .checked_add(1)
            .ok_or(ResourceNamespacePrepareError::InvalidLocator)?;
        if depth > MAX_RESOURCE_LOCATOR_DEPTH {
            return Err(ResourceNamespacePrepareError::LocatorTooDeep);
        }
    }
    Ok(())
}

/// Exact generated identity for one Component provide that requires a namespace.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ResourceNamespaceRoute {
    component: CanonicalId,
    provide_capability: CapabilityId,
    provide_key: Option<CanonicalId>,
    bootstrap_component: CanonicalId,
    bootstrap_key: CanonicalId,
    bootstrap_effects: SecurityEffects,
}

impl ResourceNamespaceRoute {
    pub fn checked(
        component: impl Into<String>,
        provide_capability: &str,
        provide_key: Option<String>,
        bootstrap_component: impl Into<String>,
        bootstrap_key: impl Into<String>,
        bootstrap_effects: SecurityEffects,
    ) -> Result<Self, ResourceNamespacePrepareError> {
        if bootstrap_effects == SecurityEffects::empty() {
            return Err(ResourceNamespacePrepareError::InvalidRoute);
        }
        Ok(Self {
            component: CanonicalId::new(component.into())
                .map_err(|_| ResourceNamespacePrepareError::InvalidRoute)?,
            provide_capability: CapabilityId::new(provide_capability)
                .map_err(|_| ResourceNamespacePrepareError::InvalidRoute)?,
            provide_key: provide_key
                .map(CanonicalId::new)
                .transpose()
                .map_err(|_| ResourceNamespacePrepareError::InvalidRoute)?,
            bootstrap_component: CanonicalId::new(bootstrap_component.into())
                .map_err(|_| ResourceNamespacePrepareError::InvalidRoute)?,
            bootstrap_key: CanonicalId::new(bootstrap_key.into())
                .map_err(|_| ResourceNamespacePrepareError::InvalidRoute)?,
            bootstrap_effects,
        })
    }

    pub fn component(&self) -> &str {
        self.component.as_str()
    }

    pub const fn provide_capability(&self) -> &CapabilityId {
        &self.provide_capability
    }

    pub fn provide_key(&self) -> Option<&str> {
        self.provide_key.as_ref().map(CanonicalId::as_str)
    }

    pub fn bootstrap_component(&self) -> &str {
        self.bootstrap_component.as_str()
    }

    pub fn bootstrap_key(&self) -> &str {
        self.bootstrap_key.as_str()
    }

    pub const fn bootstrap_effects(&self) -> SecurityEffects {
        self.bootstrap_effects
    }
}

/// Monotonic projection result for a single compiled namespace route.
#[derive(Clone, Debug)]
pub struct BootstrapAuthorityProjection {
    route: ResourceNamespaceRoute,
    retained: bool,
}

impl BootstrapAuthorityProjection {
    pub fn checked(
        route: ResourceNamespaceRoute,
        allowed_effects: SecurityEffects,
        retained: bool,
    ) -> Result<Self, ResourceNamespacePrepareError> {
        if retained && !route.bootstrap_effects().is_subset_of(allowed_effects) {
            return Err(ResourceNamespacePrepareError::AuthorityEscalationDenied);
        }
        Ok(Self { route, retained })
    }

    pub fn context<'a>(
        &'a self,
        binding: &'a ResourceNamespaceBootstrapBinding,
        cancellation: CancellationToken,
        deadline: Option<RuntimeInstant>,
    ) -> Result<ResourceNamespacePreparationContext<'a>, ResourceNamespacePrepareError> {
        if !self.retained {
            return Err(ResourceNamespacePrepareError::RouteRemoved);
        }
        if binding.component_identity() != self.route.bootstrap_component()
            || binding.provider_key() != self.route.bootstrap_key()
            || binding.effects() != self.route.bootstrap_effects()
        {
            return Err(ResourceNamespacePrepareError::BootstrapBindingMismatch);
        }
        Ok(ResourceNamespacePreparationContext {
            route: &self.route,
            binding,
            cancellation,
            deadline,
        })
    }

    pub fn retained(&self) -> bool {
        self.retained
    }
}

/// Provider input constructed only after an exact retained projection has been validated.
#[derive(Clone, Debug)]
pub struct ResourceNamespaceBootstrapRequest {
    route: ResourceNamespaceRoute,
    locator: LocalResourceLocator,
    cancellation: CancellationToken,
    deadline: Option<RuntimeInstant>,
}

impl ResourceNamespaceBootstrapRequest {
    pub const fn route(&self) -> &ResourceNamespaceRoute {
        &self.route
    }

    pub const fn locator(&self) -> &LocalResourceLocator {
        &self.locator
    }

    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub const fn deadline(&self) -> Option<RuntimeInstant> {
        self.deadline
    }
}

/// Owner-scoped local directory descriptor retained across preparation and provider construction.
#[derive(Clone)]
pub struct LocalDirectoryAnchor {
    #[cfg(unix)]
    descriptor: Arc<OwnedFd>,
    #[cfg(not(unix))]
    _unsupported: (),
}

impl LocalDirectoryAnchor {
    #[cfg(unix)]
    #[doc(hidden)]
    pub fn from_owned_descriptor(descriptor: OwnedFd) -> Self {
        Self {
            descriptor: Arc::new(descriptor),
        }
    }

    #[cfg(unix)]
    #[doc(hidden)]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.descriptor.as_fd()
    }
}

impl fmt::Debug for LocalDirectoryAnchor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalDirectoryAnchor")
            .finish_non_exhaustive()
    }
}

/// Bootstrap-provider output. The provider supplies observations; the context computes identity.
#[derive(Debug)]
pub struct ResourceNamespaceBootstrapResult {
    locator: LocalResourceLocator,
    stable_id: Arc<[u8]>,
    anchor: LocalDirectoryAnchor,
}

impl ResourceNamespaceBootstrapResult {
    pub fn local_directory(
        locator: LocalResourceLocator,
        stable_id: Vec<u8>,
        anchor: LocalDirectoryAnchor,
    ) -> Result<Self, ResourceNamespacePrepareError> {
        if stable_id.is_empty() || stable_id.len() > MAX_HOST_STABLE_NAMESPACE_ID_BYTES {
            return Err(ResourceNamespacePrepareError::InvalidStableNamespaceId);
        }
        Ok(Self {
            locator,
            stable_id: Arc::from(stable_id),
            anchor,
        })
    }
}

pub trait ResourceNamespaceBootstrap: MaybeSendSync {
    fn component_identity(&self) -> CanonicalId;

    fn provider_key(&self) -> CanonicalId;

    fn effects(&self) -> SecurityEffects;

    fn open_local_directory(
        &self,
        request: ResourceNamespaceBootstrapRequest,
    ) -> ResourceNamespaceFuture<
        '_,
        Result<ResourceNamespaceBootstrapResult, ResourceNamespacePrepareError>,
    >;
}

/// Consumer binding that keeps the raw bootstrap provider private.
#[derive(Clone)]
pub struct ResourceNamespaceBootstrapBinding {
    component_identity: CanonicalId,
    provider_key: CanonicalId,
    effects: SecurityEffects,
    provider: Arc<dyn ResourceNamespaceBootstrap>,
}

impl ResourceNamespaceBootstrapBinding {
    pub fn from_provider<T>(provider: Arc<T>) -> Self
    where
        T: ResourceNamespaceBootstrap + 'static,
    {
        Self {
            component_identity: provider.component_identity(),
            provider_key: provider.provider_key(),
            effects: provider.effects(),
            provider,
        }
    }

    pub fn provider_key(&self) -> &str {
        self.provider_key.as_str()
    }

    pub fn component_identity(&self) -> &str {
        self.component_identity.as_str()
    }

    pub const fn effects(&self) -> SecurityEffects {
        self.effects
    }
}

impl fmt::Debug for ResourceNamespaceBootstrapBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResourceNamespaceBootstrapBinding")
            .field("component_identity", &self.component_identity)
            .field("provider_key", &self.provider_key)
            .field("effects", &self.effects)
            .finish_non_exhaustive()
    }
}

/// One-shot preparation context with a private bootstrap binding and exact route stamp.
#[allow(missing_debug_implementations)]
pub struct ResourceNamespacePreparationContext<'a> {
    route: &'a ResourceNamespaceRoute,
    binding: &'a ResourceNamespaceBootstrapBinding,
    cancellation: CancellationToken,
    deadline: Option<RuntimeInstant>,
}

impl<'a> ResourceNamespacePreparationContext<'a> {
    pub fn prepare_local_directory(
        self,
        locator: LocalResourceLocator,
    ) -> ResourceNamespaceFuture<'a, Result<PreparedResourceNamespace, ResourceNamespacePrepareError>>
    {
        if self.cancellation.is_cancelled() {
            return Box::pin(async { Err(ResourceNamespacePrepareError::Cancelled) });
        }
        let route = self.route.clone();
        let expected_locator = locator.clone();
        let cancellation = self.cancellation.clone();
        let request = ResourceNamespaceBootstrapRequest {
            route: route.clone(),
            locator,
            cancellation: self.cancellation,
            deadline: self.deadline,
        };
        let future = self.binding.provider.open_local_directory(request);
        Box::pin(async move {
            let result = future.await?;
            if cancellation.is_cancelled() {
                return Err(ResourceNamespacePrepareError::Cancelled);
            }
            if result.locator != expected_locator {
                return Err(ResourceNamespacePrepareError::ProviderContractViolation);
            }
            let commitment = resource_namespace_commitment(&result.locator, &result.stable_id)?;
            Ok(PreparedResourceNamespace {
                descriptor: ResourceNamespaceDescriptor {
                    route,
                    kind: ResourceNamespaceKind::LocalDirectory,
                    commitment,
                },
                anchor: result.anchor,
            })
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ResourceNamespaceKind {
    LocalDirectory,
}

/// Path-free authority descriptor retained in effective Agent authority and durable records.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ResourceNamespaceDescriptor {
    route: ResourceNamespaceRoute,
    kind: ResourceNamespaceKind,
    commitment: Digest,
}

impl ResourceNamespaceDescriptor {
    pub const fn route(&self) -> &ResourceNamespaceRoute {
        &self.route
    }

    pub const fn kind(&self) -> ResourceNamespaceKind {
        self.kind
    }

    pub const fn commitment(&self) -> Digest {
        self.commitment
    }

    fn matches_route(&self, route: &ResourceNamespaceRoute) -> bool {
        &self.route == route
    }
}

/// Prepared namespace plus its still-open descriptor-relative anchor.
#[allow(missing_debug_implementations)]
pub struct PreparedResourceNamespace {
    descriptor: ResourceNamespaceDescriptor,
    anchor: LocalDirectoryAnchor,
}

impl PreparedResourceNamespace {
    pub const fn descriptor(&self) -> &ResourceNamespaceDescriptor {
        &self.descriptor
    }

    #[doc(hidden)]
    pub fn into_local_parts(self) -> (ResourceNamespaceDescriptor, LocalDirectoryAnchor) {
        (self.descriptor, self.anchor)
    }
}

/// Exact descriptor set paired with a provider-owned prepared configuration value.
#[allow(missing_debug_implementations)]
pub struct PreparedComponentConfig<T> {
    value: T,
    descriptors: Arc<[ResourceNamespaceDescriptor]>,
}

impl<T> PreparedComponentConfig<T> {
    pub fn checked(
        value: T,
        descriptors: Vec<ResourceNamespaceDescriptor>,
        expected_routes: &[ResourceNamespaceRoute],
    ) -> Result<Self, ResourceNamespacePrepareError> {
        if descriptors.len() > MAX_PREPARED_NAMESPACES
            || descriptors.len() != expected_routes.len()
            || !expected_routes.windows(2).all(|pair| pair[0] < pair[1])
            || descriptors
                .iter()
                .zip(expected_routes)
                .any(|(descriptor, route)| !descriptor.matches_route(route))
        {
            return Err(ResourceNamespacePrepareError::DescriptorSetMismatch);
        }
        Ok(Self {
            value,
            descriptors: Arc::from(descriptors),
        })
    }

    pub fn value(&self) -> &T {
        &self.value
    }

    pub fn descriptors(&self) -> &[ResourceNamespaceDescriptor] {
        &self.descriptors
    }

    pub fn into_value(self) -> T {
        self.value
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceNamespacePrepareError {
    InvalidLocator,
    LocatorTooDeep,
    InvalidRoute,
    AuthorityEscalationDenied,
    RouteRemoved,
    BootstrapBindingMismatch,
    Cancelled,
    DeadlineExceeded,
    UnsupportedTarget,
    InvalidStableNamespaceId,
    DescriptorSetMismatch,
    ProviderContractViolation,
    Provider,
}

impl fmt::Display for ResourceNamespacePrepareError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLocator => "invalid resource namespace locator",
            Self::LocatorTooDeep => "resource namespace locator exceeds its depth limit",
            Self::InvalidRoute => "invalid resource namespace route",
            Self::AuthorityEscalationDenied => "resource namespace projection exceeds authority",
            Self::RouteRemoved => "resource namespace route was removed by authority projection",
            Self::BootstrapBindingMismatch => "resource namespace bootstrap binding mismatch",
            Self::Cancelled => "resource namespace preparation was cancelled",
            Self::DeadlineExceeded => "resource namespace preparation deadline exceeded",
            Self::UnsupportedTarget => "resource namespace bootstrap is unsupported on this target",
            Self::InvalidStableNamespaceId => "invalid Host-stable namespace identity",
            Self::DescriptorSetMismatch => "prepared resource namespace descriptors do not match",
            Self::ProviderContractViolation => "resource namespace provider violated its contract",
            Self::Provider => "resource namespace bootstrap provider failed",
        })
    }
}

impl std::error::Error for ResourceNamespacePrepareError {}

fn resource_namespace_commitment(
    locator: &LocalResourceLocator,
    stable_id: &[u8],
) -> Result<Digest, ResourceNamespacePrepareError> {
    let mut canonical = Vec::with_capacity(locator.as_str().len() + stable_id.len() + 12);
    canonical.push(0x82); // canonical CBOR array(2)
    encode_cbor_length(3, locator.as_str().len(), &mut canonical)?;
    canonical.extend_from_slice(locator.as_str().as_bytes());
    encode_cbor_length(2, stable_id.len(), &mut canonical)?;
    canonical.extend_from_slice(stable_id);
    let mut hasher = Sha256::new();
    hasher.update(RESOURCE_NAMESPACE_DIGEST_DOMAIN);
    hasher.update(canonical);
    Ok(Digest::from_bytes(hasher.finalize().into()))
}

fn encode_cbor_length(
    major: u8,
    length: usize,
    output: &mut Vec<u8>,
) -> Result<(), ResourceNamespacePrepareError> {
    let major = major << 5;
    match length {
        0..=23 => output.push(
            major
                | u8::try_from(length)
                    .map_err(|_| ResourceNamespacePrepareError::InvalidLocator)?,
        ),
        24..=0xff => {
            output.push(major | 0x18);
            output.push(
                u8::try_from(length).map_err(|_| ResourceNamespacePrepareError::InvalidLocator)?,
            );
        }
        0x100..=0xffff => {
            output.push(major | 0x19);
            output.extend_from_slice(
                &u16::try_from(length)
                    .map_err(|_| ResourceNamespacePrepareError::InvalidLocator)?
                    .to_be_bytes(),
            );
        }
        _ => return Err(ResourceNamespacePrepareError::InvalidLocator),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs::File,
        sync::atomic::{AtomicUsize, Ordering},
        task::{Context, Poll, Waker},
    };

    use super::*;

    struct FakeBootstrap {
        calls: AtomicUsize,
        component: &'static str,
        key: &'static str,
        effects: SecurityEffects,
        wrong_locator: bool,
    }

    impl FakeBootstrap {
        fn valid() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                component: "resource-namespace-bootstrap-local",
                key: "resource-namespace-bootstrap-local",
                effects: SecurityEffects::READ_LOCAL,
                wrong_locator: false,
            }
        }
    }

    impl ResourceNamespaceBootstrap for FakeBootstrap {
        fn component_identity(&self) -> CanonicalId {
            CanonicalId::new(self.component).unwrap()
        }

        fn provider_key(&self) -> CanonicalId {
            CanonicalId::new(self.key).unwrap()
        }

        fn effects(&self) -> SecurityEffects {
            self.effects
        }

        fn open_local_directory(
            &self,
            request: ResourceNamespaceBootstrapRequest,
        ) -> ResourceNamespaceFuture<
            '_,
            Result<ResourceNamespaceBootstrapResult, ResourceNamespacePrepareError>,
        > {
            assert_eq!(request.route(), &route());
            self.calls.fetch_add(1, Ordering::SeqCst);
            let locator = if self.wrong_locator {
                LocalResourceLocator::new("other").unwrap()
            } else {
                request.locator().clone()
            };
            #[cfg(unix)]
            let anchor =
                LocalDirectoryAnchor::from_owned_descriptor(File::open(".").unwrap().into());
            #[cfg(not(unix))]
            let anchor = LocalDirectoryAnchor { _unsupported: () };
            Box::pin(async move {
                ResourceNamespaceBootstrapResult::local_directory(locator, vec![1, 2], anchor)
            })
        }
    }

    fn route() -> ResourceNamespaceRoute {
        ResourceNamespaceRoute::checked(
            "fs-read-local",
            "cap:fs-read",
            None,
            "resource-namespace-bootstrap-local",
            "resource-namespace-bootstrap-local",
            SecurityEffects::READ_LOCAL,
        )
        .unwrap()
    }

    fn ready<T>(mut future: ResourceNamespaceFuture<'_, T>) -> T {
        let mut context = Context::from_waker(Waker::noop());
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("test future unexpectedly pending"),
        }
    }

    #[test]
    fn locators_routes_and_descriptor_sets_are_canonical_and_bounded() {
        let locator = LocalResourceLocator::new("workspace/src").unwrap();
        assert_eq!(locator.as_str(), "workspace/src");
        assert_eq!(locator.depth(), 2);
        assert_eq!(LocalResourceLocator::root().provider_relative_path(), ".");
        for invalid in ["", "/tmp", "a/", "a//b", ".", "..", "a/../b", "a\\b"] {
            assert_eq!(
                LocalResourceLocator::new(invalid),
                Err(ResourceNamespacePrepareError::InvalidLocator)
            );
        }
        let too_deep = std::iter::repeat_n("x", MAX_RESOURCE_LOCATOR_DEPTH + 1)
            .collect::<Vec<_>>()
            .join("/");
        assert_eq!(
            LocalResourceLocator::new(too_deep),
            Err(ResourceNamespacePrepareError::LocatorTooDeep)
        );
        assert!(
            ResourceNamespaceRoute::checked(
                "fs-read-local",
                "cap:fs-read",
                None,
                "resource-namespace-bootstrap-local",
                "resource-namespace-bootstrap-local",
                SecurityEffects::empty(),
            )
            .is_err()
        );
    }

    #[test]
    fn projection_precedes_provider_calls_and_rejects_binding_drift() {
        let provider = Arc::new(FakeBootstrap::valid());
        let binding = ResourceNamespaceBootstrapBinding::from_provider(Arc::clone(&provider));
        let removed =
            BootstrapAuthorityProjection::checked(route(), SecurityEffects::empty(), false)
                .unwrap();
        assert!(matches!(
            removed.context(&binding, CancellationToken::new(), None),
            Err(ResourceNamespacePrepareError::RouteRemoved)
        ));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
        assert!(matches!(
            BootstrapAuthorityProjection::checked(route(), SecurityEffects::empty(), true),
            Err(ResourceNamespacePrepareError::AuthorityEscalationDenied)
        ));

        let wrong = Arc::new(FakeBootstrap {
            key: "other-bootstrap",
            ..FakeBootstrap::valid()
        });
        let wrong_binding = ResourceNamespaceBootstrapBinding::from_provider(wrong);
        let retained =
            BootstrapAuthorityProjection::checked(route(), SecurityEffects::READ_LOCAL, true)
                .unwrap();
        assert!(matches!(
            retained.context(&wrong_binding, CancellationToken::new(), None),
            Err(ResourceNamespacePrepareError::BootstrapBindingMismatch)
        ));

        let wrong = Arc::new(FakeBootstrap {
            component: "other-component",
            ..FakeBootstrap::valid()
        });
        let wrong_binding = ResourceNamespaceBootstrapBinding::from_provider(wrong);
        assert!(matches!(
            retained.context(&wrong_binding, CancellationToken::new(), None),
            Err(ResourceNamespacePrepareError::BootstrapBindingMismatch)
        ));

        let wrong = Arc::new(FakeBootstrap {
            effects: SecurityEffects::READ_LOCAL | SecurityEffects::WRITE_LOCAL,
            ..FakeBootstrap::valid()
        });
        let wrong_binding = ResourceNamespaceBootstrapBinding::from_provider(wrong);
        assert!(matches!(
            retained.context(&wrong_binding, CancellationToken::new(), None),
            Err(ResourceNamespacePrepareError::BootstrapBindingMismatch)
        ));

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let context = retained.context(&binding, cancellation, None).unwrap();
        assert!(matches!(
            ready(context.prepare_local_directory(LocalResourceLocator::root())),
            Err(ResourceNamespacePrepareError::Cancelled)
        ));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn context_computes_commitment_and_revalidates_provider_output() {
        let provider = Arc::new(FakeBootstrap::valid());
        let binding = ResourceNamespaceBootstrapBinding::from_provider(Arc::clone(&provider));
        let retained =
            BootstrapAuthorityProjection::checked(route(), SecurityEffects::READ_LOCAL, true)
                .unwrap();
        let prepared = ready(
            retained
                .context(&binding, CancellationToken::new(), None)
                .unwrap()
                .prepare_local_directory(LocalResourceLocator::new("workspace").unwrap()),
        )
        .unwrap();
        let descriptor = prepared.descriptor().clone();
        assert_eq!(descriptor.route(), &route());
        assert_eq!(
            descriptor.commitment().to_lower_hex(),
            "97d5194b211eac030a3559798578f54bb49691c1e5023bc35555c7f80f399a85"
        );
        assert!(matches!(
            PreparedComponentConfig::checked((), Vec::new(), &[route()]),
            Err(ResourceNamespacePrepareError::DescriptorSetMismatch)
        ));
        let prepared_config =
            PreparedComponentConfig::checked((), vec![descriptor.clone()], &[route()]).unwrap();
        assert_eq!(prepared_config.descriptors().len(), 1);
        assert!(matches!(
            PreparedComponentConfig::checked(
                (),
                vec![descriptor.clone(), descriptor],
                &[route(), route()]
            ),
            Err(ResourceNamespacePrepareError::DescriptorSetMismatch)
        ));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);

        let wrong = Arc::new(FakeBootstrap {
            wrong_locator: true,
            ..FakeBootstrap::valid()
        });
        let wrong_binding = ResourceNamespaceBootstrapBinding::from_provider(wrong);
        assert!(matches!(
            ready(
                retained
                    .context(&wrong_binding, CancellationToken::new(), None)
                    .unwrap()
                    .prepare_local_directory(LocalResourceLocator::new("workspace").unwrap())
            ),
            Err(ResourceNamespacePrepareError::ProviderContractViolation)
        ));
    }
}
