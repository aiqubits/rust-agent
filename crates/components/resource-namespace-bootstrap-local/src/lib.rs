//! Linux local resource-namespace bootstrap using a retained directory descriptor.

use rust_agent_core::{CanonicalId, SecurityEffects};
use rust_agent_resource_namespace::{
    LocalDirectoryAnchor, ResourceNamespaceBootstrap, ResourceNamespaceBootstrapRequest,
    ResourceNamespaceBootstrapResult, ResourceNamespaceFuture, ResourceNamespacePrepareError,
};
use rust_agent_runtime_api::{ComponentBuildError, ComponentOutput, RuntimePrimitiveBindings};

#[cfg(target_os = "linux")]
use rustix::fs::{CWD, Mode, OFlags, ResolveFlags, fstat, openat2};

#[derive(Clone, Debug, Default)]
pub struct Config;

#[derive(Clone, Debug, Default)]
pub struct Dependencies;

#[derive(Debug)]
pub struct LocalResourceNamespaceBootstrap;

impl ResourceNamespaceBootstrap for LocalResourceNamespaceBootstrap {
    fn component_identity(&self) -> CanonicalId {
        CanonicalId::new("resource-namespace-bootstrap-local")
            .expect("static bootstrap component identity is canonical")
    }

    fn provider_key(&self) -> CanonicalId {
        CanonicalId::new("resource-namespace-bootstrap-local")
            .expect("static bootstrap provider key is canonical")
    }

    fn effects(&self) -> SecurityEffects {
        SecurityEffects::READ_LOCAL
    }

    fn open_local_directory(
        &self,
        request: ResourceNamespaceBootstrapRequest,
    ) -> ResourceNamespaceFuture<
        '_,
        Result<ResourceNamespaceBootstrapResult, ResourceNamespacePrepareError>,
    > {
        #[cfg(target_os = "linux")]
        {
            Box::pin(async move {
                if request.cancellation().is_cancelled() {
                    return Err(ResourceNamespacePrepareError::Cancelled);
                }
                let locator = request.locator().clone();
                let descriptor = openat2(
                    CWD,
                    locator.provider_relative_path(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                    ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
                )
                .map_err(|_| ResourceNamespacePrepareError::Provider)?;
                if request.cancellation().is_cancelled() {
                    return Err(ResourceNamespacePrepareError::Cancelled);
                }
                let stat =
                    fstat(&descriptor).map_err(|_| ResourceNamespacePrepareError::Provider)?;
                let mut stable_id = Vec::with_capacity(16);
                stable_id.extend_from_slice(&(stat.st_dev as u64).to_be_bytes());
                stable_id.extend_from_slice(&(stat.st_ino as u64).to_be_bytes());
                ResourceNamespaceBootstrapResult::local_directory(
                    locator,
                    stable_id,
                    LocalDirectoryAnchor::from_owned_descriptor(descriptor),
                )
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = request;
            Box::pin(async { Err(ResourceNamespacePrepareError::UnsupportedTarget) })
        }
    }
}

pub fn build(
    _config: &Config,
    _dependencies: Dependencies,
    runtime: RuntimePrimitiveBindings,
) -> Result<ComponentOutput<LocalResourceNamespaceBootstrap>, ComponentBuildError> {
    validate_runtime_primitives(runtime.allowed())?;
    drop(runtime);
    Ok(ComponentOutput::stateless(LocalResourceNamespaceBootstrap))
}

fn validate_runtime_primitives(
    primitives: &[rust_agent_runtime_api::RuntimePrimitiveKind],
) -> Result<(), ComponentBuildError> {
    if primitives.is_empty() {
        Ok(())
    } else {
        Err(ComponentBuildError::InvalidConfig(
            "resource-namespace-bootstrap-local declares no runtime primitives".into(),
        ))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::{
        fs,
        future::Future,
        os::unix::fs::MetadataExt,
        path::Path,
        sync::Arc,
        task::{Context, Poll, Waker},
    };

    use rust_agent_resource_namespace::{
        BootstrapAuthorityProjection, LocalResourceLocator, ResourceNamespaceBootstrapBinding,
        ResourceNamespaceRoute,
    };
    use rust_agent_runtime_api::{CancellationToken, RuntimePrimitiveKind};
    use tempfile::Builder;

    use super::*;

    fn run<F: Future>(mut future: std::pin::Pin<Box<F>>) -> F::Output {
        let mut context = Context::from_waker(Waker::noop());
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("bootstrap future unexpectedly pending"),
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

    fn prepare(
        binding: &ResourceNamespaceBootstrapBinding,
        locator: LocalResourceLocator,
    ) -> rust_agent_resource_namespace::PreparedResourceNamespace {
        let projection =
            BootstrapAuthorityProjection::checked(route(), SecurityEffects::READ_LOCAL, true)
                .unwrap();
        run(Box::pin(
            projection
                .context(binding, CancellationToken::new(), None)
                .unwrap()
                .prepare_local_directory(locator),
        ))
        .unwrap()
    }

    #[test]
    fn descriptor_anchor_survives_root_replacement_without_reopen() {
        let outer = Builder::new()
            .prefix("rust-agent-bootstrap-")
            .tempdir_in(".")
            .unwrap();
        let root = outer.path().join("root");
        let moved = outer.path().join("moved");
        fs::create_dir(&root).unwrap();
        let relative = format!(
            "{}/root",
            outer.path().file_name().unwrap().to_str().unwrap()
        );
        let service = build(&Config, Dependencies, RuntimePrimitiveBindings::none())
            .unwrap()
            .into_service();
        let binding = ResourceNamespaceBootstrapBinding::from_provider(service);
        let prepared = prepare(&binding, LocalResourceLocator::new(relative).unwrap());
        let original_commitment = prepared.descriptor().commitment();
        let original = fs::metadata(&root).unwrap();
        fs::rename(&root, &moved).unwrap();
        fs::create_dir(&root).unwrap();
        let replacement = fs::metadata(&root).unwrap();
        let (_, anchor) = prepared.into_local_parts();
        let anchored = fstat(anchor.as_fd()).unwrap();
        assert_eq!(anchored.st_dev as u64, original.dev());
        assert_eq!(anchored.st_ino as u64, original.ino());
        assert_ne!(
            (replacement.dev(), replacement.ino()),
            (original.dev(), original.ino())
        );
        let relative = format!(
            "{}/root",
            outer.path().file_name().unwrap().to_str().unwrap()
        );
        let replacement_prepared = prepare(&binding, LocalResourceLocator::new(relative).unwrap());
        assert_ne!(
            replacement_prepared.descriptor().commitment(),
            original_commitment
        );
    }

    #[test]
    fn symlink_escape_and_cancelled_calls_fail_closed() {
        let outer = Builder::new()
            .prefix("rust-agent-bootstrap-")
            .tempdir_in(".")
            .unwrap();
        let root = outer.path().join("root");
        fs::create_dir(&root).unwrap();
        std::os::unix::fs::symlink(Path::new(".."), root.join("escape")).unwrap();
        let relative = format!(
            "{}/root/escape",
            outer.path().file_name().unwrap().to_str().unwrap()
        );
        let binding = ResourceNamespaceBootstrapBinding::from_provider(Arc::new(
            LocalResourceNamespaceBootstrap,
        ));
        let projection =
            BootstrapAuthorityProjection::checked(route(), SecurityEffects::READ_LOCAL, true)
                .unwrap();
        assert!(matches!(
            run(Box::pin(
                projection
                    .context(&binding, CancellationToken::new(), None)
                    .unwrap()
                    .prepare_local_directory(LocalResourceLocator::new(relative).unwrap()),
            )),
            Err(ResourceNamespacePrepareError::Provider)
        ));

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert!(matches!(
            run(Box::pin(
                projection
                    .context(&binding, cancellation, None)
                    .unwrap()
                    .prepare_local_directory(LocalResourceLocator::new("missing").unwrap()),
            )),
            Err(ResourceNamespacePrepareError::Cancelled)
        ));
    }

    #[test]
    fn locator_open_is_deferred_until_the_preparation_future_is_polled() {
        let outer = Builder::new()
            .prefix("rust-agent-bootstrap-")
            .tempdir_in(".")
            .unwrap();
        let relative = format!(
            "{}/created-after-future",
            outer.path().file_name().unwrap().to_str().unwrap()
        );
        let binding = ResourceNamespaceBootstrapBinding::from_provider(Arc::new(
            LocalResourceNamespaceBootstrap,
        ));
        let projection =
            BootstrapAuthorityProjection::checked(route(), SecurityEffects::READ_LOCAL, true)
                .unwrap();
        let future = projection
            .context(&binding, CancellationToken::new(), None)
            .unwrap()
            .prepare_local_directory(LocalResourceLocator::new(relative).unwrap());
        fs::create_dir(outer.path().join("created-after-future")).unwrap();
        assert!(run(Box::pin(future)).is_ok());
    }

    #[test]
    fn independent_instances_open_independent_descriptor_anchors() {
        let outer = Builder::new()
            .prefix("rust-agent-bootstrap-")
            .tempdir_in(".")
            .unwrap();
        fs::create_dir(outer.path().join("first")).unwrap();
        fs::create_dir(outer.path().join("second")).unwrap();
        let first = build(&Config, Dependencies, RuntimePrimitiveBindings::none())
            .unwrap()
            .into_service();
        let second = build(&Config, Dependencies, RuntimePrimitiveBindings::none())
            .unwrap()
            .into_service();
        assert!(!Arc::ptr_eq(&first, &second));
        let first_binding = ResourceNamespaceBootstrapBinding::from_provider(first);
        let second_binding = ResourceNamespaceBootstrapBinding::from_provider(second);
        let outer_name = outer.path().file_name().unwrap().to_str().unwrap();
        let first = prepare(
            &first_binding,
            LocalResourceLocator::new(format!("{outer_name}/first")).unwrap(),
        );
        let second = prepare(
            &second_binding,
            LocalResourceLocator::new(format!("{outer_name}/second")).unwrap(),
        );
        assert_ne!(
            first.descriptor().commitment(),
            second.descriptor().commitment()
        );
        let (_, first_anchor) = first.into_local_parts();
        let (_, second_anchor) = second.into_local_parts();
        let first_stat = fstat(first_anchor.as_fd()).unwrap();
        let second_stat = fstat(second_anchor.as_fd()).unwrap();
        assert_ne!(
            (first_stat.st_dev, first_stat.st_ino),
            (second_stat.st_dev, second_stat.st_ino)
        );
        for primitive in [
            RuntimePrimitiveKind::Clock,
            RuntimePrimitiveKind::Sleep,
            RuntimePrimitiveKind::Spawn,
        ] {
            assert!(validate_runtime_primitives(&[primitive]).is_err());
        }
    }
}
