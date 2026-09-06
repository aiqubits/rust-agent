use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    CargoPlannerGraphRoot, NormalizedCargoPlannerRequest, RawCargoCompileMode, RawCargoTarget,
    VerifiedCargoUnitGraphEnvelope,
};
use crate::{
    BuildArtifactTarget, CargoCompilationKind, CargoCompileMode, CargoCrateKind,
    CargoDependencyKind, CargoPackageIdentity, CargoPackageSource, CargoTargetEvaluationDomain,
    CargoUnit, CargoUnitEdge, CargoUnitGraphError, CargoUnitSelector, CargoUnitTargetContext,
    HostCargoUnitGraph, LockedSourceError, NormalizedHostBuildInputClosure,
    NormalizedHostCargoUnitGraph, NormalizedLockedSourceClosure,
};

const MAX_EDGE_COUNT: usize = 1_000_000;

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CargoPlannerEdgeSemantic {
    #[serde(rename = "dependent-index")]
    pub dependent_index: usize,
    #[serde(rename = "dependency-index")]
    pub dependency_index: usize,
    #[serde(rename = "extern-crate-name")]
    pub extern_crate_name: String,
    #[serde(rename = "dependency-kind")]
    pub dependency_kind: CargoDependencyKind,
    #[serde(rename = "target-evaluation-domain")]
    pub target_evaluation_domain: CargoTargetEvaluationDomain,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CargoPlannerEdgeSemantics {
    pub schema: u32,
    #[serde(rename = "planner-request-digest")]
    pub planner_request_digest: String,
    #[serde(rename = "unit-graph-envelope-digest")]
    pub unit_graph_envelope_digest: String,
    pub edges: Vec<CargoPlannerEdgeSemantic>,
}

#[derive(Debug, Error)]
pub enum CargoUnitGraphNormalizationError {
    #[error("unsupported Cargo edge-semantics schema {0}; expected 1")]
    UnsupportedEdgeSemanticsSchema(u32),
    #[error("Cargo unit-graph envelope was produced for a different planner request")]
    PlannerRequestMismatch,
    #[error("Cargo planner request and Host build input closure identities differ")]
    HostClosureMismatch,
    #[error("Cargo edge semantics do not bind the exact planner request and unit graph")]
    EdgeSemanticsIdentityMismatch,
    #[error("Cargo edge semantics are incomplete, duplicated or contain an unknown edge")]
    EdgeSemanticsMismatch,
    #[error("Cargo metadata output is invalid JSON: {0}")]
    MetadataJson(serde_json::Error),
    #[error("Cargo metadata output violates the closed v1 edge-semantics contract: {0}")]
    InvalidMetadata(&'static str),
    #[error("Cargo metadata cannot identify one exact dependency kind for a unit edge")]
    AmbiguousEdgeSemantic,
    #[error("Cargo raw package id is not an exact locked source identity: {0}")]
    PackageIdentityMismatch(String),
    #[error("Cargo raw unit platform/mode conflicts with its target kind: {0}")]
    RawUnitDomainMismatch(String),
    #[error("Cargo target kind/crate-type combination is unsupported: {0}")]
    UnsupportedTargetKind(String),
    #[error("Cargo unit-graph root does not match the exact artifact selector")]
    RootArtifactMismatch,
    #[error("normalized Host Cargo unit graph is invalid: {0}")]
    HostGraph(#[from] CargoUnitGraphError),
    #[error("locked source closure does not match the Host build input closure: {0}")]
    LockedSources(#[from] LockedSourceError),
}

impl CargoPlannerEdgeSemantics {
    pub fn from_json(input: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(input)
    }
}

/// Derives the dependency-kind and target-domain labels which Cargo's unit-graph
/// v1 output omits. The metadata bytes must be produced by the same pinned Cargo
/// invocation boundary as the unit graph; the returned record is bound to both
/// the exact planner request and verified graph envelope.
pub fn derive_cargo_planner_edge_semantics_from_metadata(
    request: &NormalizedCargoPlannerRequest,
    envelope: &VerifiedCargoUnitGraphEnvelope,
    metadata: &[u8],
) -> Result<CargoPlannerEdgeSemantics, CargoUnitGraphNormalizationError> {
    if envelope.request_digest() != request.digest() {
        return Err(CargoUnitGraphNormalizationError::PlannerRequestMismatch);
    }
    if metadata.is_empty() || metadata.len() > 64 * 1024 * 1024 {
        return Err(CargoUnitGraphNormalizationError::InvalidMetadata(
            "encoded size",
        ));
    }
    let metadata: CargoMetadata =
        serde_json::from_slice(metadata).map_err(CargoUnitGraphNormalizationError::MetadataJson)?;
    metadata.validate()?;
    let resolve = metadata
        .resolve
        .ok_or(CargoUnitGraphNormalizationError::InvalidMetadata(
            "missing resolve graph",
        ))?;
    let nodes = resolve
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect::<BTreeMap<_, _>>();
    if nodes.len() != resolve.nodes.len() {
        return Err(CargoUnitGraphNormalizationError::InvalidMetadata(
            "duplicate resolve node",
        ));
    }

    let graph = &envelope.graph;
    let mut edges = Vec::new();
    for (dependent_index, unit) in graph.units.iter().enumerate() {
        let node = nodes.get(unit.pkg_id.as_str()).ok_or(
            CargoUnitGraphNormalizationError::InvalidMetadata("unit package is absent"),
        )?;
        for dependency in &unit.dependencies {
            let dependency_unit = graph
                .units
                .get(dependency.index)
                .ok_or(CargoUnitGraphNormalizationError::EdgeSemanticsMismatch)?;
            let (dependency_kind, target_evaluation_domain) = if unit.pkg_id
                == dependency_unit.pkg_id
                && (unit.target.kind.as_slice() == ["custom-build"]
                    || dependency_unit.target.kind.as_slice() == ["custom-build"])
            {
                (
                    CargoDependencyKind::Build,
                    CargoTargetEvaluationDomain::BuildHost,
                )
            } else {
                let matches = node
                    .deps
                    .iter()
                    .filter(|candidate| {
                        metadata_dependency_matches(candidate, dependency, dependency_unit)
                    })
                    .collect::<Vec<_>>();
                if matches.is_empty() {
                    return Err(CargoUnitGraphNormalizationError::AmbiguousEdgeSemantic);
                }
                let expected_kind = expected_dependency_kind(unit, &matches)?;
                let dependency_crate_kind = crate_kind(&dependency_unit.target)?;
                let dependency_compilation_kind =
                    compilation_kind(dependency_unit, dependency_crate_kind)?;
                let domain = if expected_kind == CargoDependencyKind::Build
                    || dependency_compilation_kind == CargoCompilationKind::BuildHost
                {
                    CargoTargetEvaluationDomain::BuildHost
                } else {
                    CargoTargetEvaluationDomain::Target
                };
                (expected_kind, domain)
            };
            edges.push(CargoPlannerEdgeSemantic {
                dependent_index,
                dependency_index: dependency.index,
                extern_crate_name: dependency.extern_crate_name.clone(),
                dependency_kind,
                target_evaluation_domain,
            });
        }
    }
    edges.sort();
    Ok(CargoPlannerEdgeSemantics {
        schema: 1,
        planner_request_digest: request.digest().into(),
        unit_graph_envelope_digest: envelope.digest().into(),
        edges,
    })
}

fn metadata_dependency_matches(
    candidate: &CargoMetadataNodeDependency,
    dependency: &super::RawCargoUnitDependency,
    dependency_unit: &super::RawCargoUnit,
) -> bool {
    candidate.pkg == dependency_unit.pkg_id
        && (candidate.name == dependency.extern_crate_name
            || dependency.extern_crate_name == "build_script_build"
                && dependency_unit.target.kind.as_slice() == ["custom-build"])
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CargoMetadata {
    packages: Vec<serde_json::Value>,
    workspace_members: Vec<String>,
    workspace_default_members: Vec<String>,
    resolve: Option<CargoMetadataResolve>,
    target_directory: String,
    version: u32,
    workspace_root: String,
    metadata: serde_json::Value,
    build_directory: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CargoMetadataResolve {
    nodes: Vec<CargoMetadataNode>,
    root: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CargoMetadataNode {
    id: String,
    dependencies: Vec<String>,
    deps: Vec<CargoMetadataNodeDependency>,
    features: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CargoMetadataNodeDependency {
    name: String,
    pkg: String,
    dep_kinds: Vec<CargoMetadataDependencyKind>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CargoMetadataDependencyKind {
    kind: Option<String>,
    target: Option<String>,
}

impl CargoMetadata {
    fn validate(&self) -> Result<(), CargoUnitGraphNormalizationError> {
        if self.version != 1
            || self.packages.len() > 100_000
            || self.workspace_members.len() > 100_000
            || self.workspace_default_members.len() > 100_000
            || !valid_metadata_text(&self.target_directory, 4096)
            || !valid_metadata_text(&self.workspace_root, 4096)
            || !valid_metadata_text(&self.build_directory, 4096)
            || !(self.metadata.is_null() || self.metadata.is_object())
        {
            return Err(CargoUnitGraphNormalizationError::InvalidMetadata(
                "root context",
            ));
        }
        let Some(resolve) = &self.resolve else {
            return Ok(());
        };
        if resolve.nodes.is_empty() || resolve.nodes.len() > 100_000 {
            return Err(CargoUnitGraphNormalizationError::InvalidMetadata(
                "resolve cardinality",
            ));
        }
        if resolve
            .root
            .as_deref()
            .is_some_and(|root| !valid_metadata_text(root, 4096))
        {
            return Err(CargoUnitGraphNormalizationError::InvalidMetadata(
                "resolve root",
            ));
        }
        for node in &resolve.nodes {
            if !valid_metadata_text(&node.id, 4096)
                || node.dependencies.len() > 100_000
                || node.deps.len() > 100_000
                || node.features.len() > 16_384
                || node
                    .dependencies
                    .iter()
                    .any(|value| !valid_metadata_text(value, 4096))
                || node
                    .features
                    .iter()
                    .any(|value| !super::valid_feature(value))
            {
                return Err(CargoUnitGraphNormalizationError::InvalidMetadata(
                    "resolve node",
                ));
            }
            let dependency_packages = node
                .deps
                .iter()
                .map(|dep| dep.pkg.as_str())
                .collect::<BTreeSet<_>>();
            let legacy_dependencies = node
                .dependencies
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            if dependency_packages != legacy_dependencies {
                return Err(CargoUnitGraphNormalizationError::InvalidMetadata(
                    "dependency projection",
                ));
            }
            for dependency in &node.deps {
                if !super::valid_cargo_name(&dependency.name)
                    || !valid_metadata_text(&dependency.pkg, 4096)
                    || dependency.dep_kinds.is_empty()
                    || dependency.dep_kinds.len() > 128
                    || dependency.dep_kinds.iter().any(|kind| {
                        !matches!(kind.kind.as_deref(), None | Some("dev" | "build"))
                            || kind
                                .target
                                .as_deref()
                                .is_some_and(|target| !valid_metadata_text(target, 4096))
                    })
                {
                    return Err(CargoUnitGraphNormalizationError::InvalidMetadata(
                        "dependency",
                    ));
                }
            }
        }
        Ok(())
    }
}

fn expected_dependency_kind(
    dependent: &super::RawCargoUnit,
    dependencies: &[&CargoMetadataNodeDependency],
) -> Result<CargoDependencyKind, CargoUnitGraphNormalizationError> {
    let candidates = dependencies
        .iter()
        .flat_map(|dependency| &dependency.dep_kinds)
        .map(|kind| match kind.kind.as_deref() {
            None => CargoDependencyKind::Normal,
            Some("dev") => CargoDependencyKind::Development,
            Some("build") => CargoDependencyKind::Build,
            Some(_) => unreachable!("validated Cargo dependency kind"),
        })
        .collect::<BTreeSet<_>>();
    let preferred = if dependent.target.kind.as_slice() == ["custom-build"] {
        CargoDependencyKind::Build
    } else if matches!(
        dependent.target.kind.as_slice(),
        [kind] if matches!(kind.as_str(), "test" | "bench" | "example")
    ) && candidates.contains(&CargoDependencyKind::Development)
    {
        CargoDependencyKind::Development
    } else {
        CargoDependencyKind::Normal
    };
    if candidates.contains(&preferred) {
        Ok(preferred)
    } else if dependent.target.kind.as_slice() == ["custom-build"]
        && candidates == BTreeSet::from([CargoDependencyKind::Normal])
    {
        // A package with `links` makes Cargo connect its run-custom-build unit
        // to the linked normal dependency's run-custom-build unit. Metadata
        // correctly retains the original normal dependency kind for that edge.
        Ok(CargoDependencyKind::Normal)
    } else {
        Err(CargoUnitGraphNormalizationError::AmbiguousEdgeSemantic)
    }
}

fn valid_metadata_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value.contains(['\0', '\n', '\r'])
        && value.trim() == value
}

pub fn normalize_cargo_unit_graph(
    request: &NormalizedCargoPlannerRequest,
    envelope: &VerifiedCargoUnitGraphEnvelope,
    host_closure: &NormalizedHostBuildInputClosure,
    locked_sources: &NormalizedLockedSourceClosure,
    edge_semantics: &CargoPlannerEdgeSemantics,
) -> Result<NormalizedHostCargoUnitGraph, CargoUnitGraphNormalizationError> {
    if envelope.request_digest() != request.digest() {
        return Err(CargoUnitGraphNormalizationError::PlannerRequestMismatch);
    }
    if request.host_build_input_closure_digest() != host_closure.digest() {
        return Err(CargoUnitGraphNormalizationError::HostClosureMismatch);
    }
    locked_sources.verify_host_closure(host_closure)?;
    if edge_semantics.schema != 1 {
        return Err(
            CargoUnitGraphNormalizationError::UnsupportedEdgeSemanticsSchema(edge_semantics.schema),
        );
    }
    if edge_semantics.planner_request_digest != request.digest()
        || edge_semantics.unit_graph_envelope_digest != envelope.digest()
    {
        return Err(CargoUnitGraphNormalizationError::EdgeSemanticsIdentityMismatch);
    }

    let graph = &envelope.graph;
    let raw_edge_count: usize = graph.units.iter().map(|unit| unit.dependencies.len()).sum();
    if raw_edge_count > MAX_EDGE_COUNT || edge_semantics.edges.len() != raw_edge_count {
        return Err(CargoUnitGraphNormalizationError::EdgeSemanticsMismatch);
    }

    let package_index = index_locked_packages(locked_sources);
    let mut package_cache: BTreeMap<String, CargoPackageIdentity> = BTreeMap::new();
    let mut units = Vec::with_capacity(graph.units.len());
    for raw in &graph.units {
        let package = if let Some(package) = package_cache.get(&raw.pkg_id) {
            package.clone()
        } else {
            let package = resolve_package(&raw.pkg_id, &package_index)?;
            package_cache.insert(raw.pkg_id.clone(), package.clone());
            package
        };
        let crate_kind = crate_kind(&raw.target)?;
        let compilation_kind = compilation_kind(raw, crate_kind)?;
        let compilation_target = match compilation_kind {
            CargoCompilationKind::BuildHost => request.build_triple(),
            CargoCompilationKind::Target => request.target(),
        };
        let cargo_target_context = if raw.platform.is_some() {
            CargoUnitTargetContext::CompositionTarget
        } else {
            CargoUnitTargetContext::BuildHost
        };
        let selector = CargoUnitSelector {
            package,
            target_name: raw.target.name.clone(),
            compilation_kind,
            compilation_target: compilation_target.into(),
            cargo_target_context,
            compile_mode: compile_mode(raw.mode),
            profile: raw.profile.name.clone(),
            crate_kind,
        };
        units.push(CargoUnit {
            selector,
            features: raw.features.clone(),
            build_script: crate_kind == CargoCrateKind::CustomBuild,
            proc_macro: crate_kind == CargoCrateKind::ProcMacro,
        });
    }

    verify_root(request, graph.roots.as_slice(), &units)?;

    let expected_edges: BTreeSet<_> = graph
        .units
        .iter()
        .enumerate()
        .flat_map(|(dependent_index, unit)| {
            unit.dependencies
                .iter()
                .map(move |dependency| CargoPlannerEdgeKey {
                    dependent_index,
                    dependency_index: dependency.index,
                    extern_crate_name: dependency.extern_crate_name.clone(),
                })
        })
        .collect();
    if expected_edges.len() != raw_edge_count {
        return Err(CargoUnitGraphNormalizationError::EdgeSemanticsMismatch);
    }

    let mut provided_edges = BTreeSet::new();
    let mut edges = Vec::with_capacity(edge_semantics.edges.len());
    for semantic in &edge_semantics.edges {
        let key = CargoPlannerEdgeKey {
            dependent_index: semantic.dependent_index,
            dependency_index: semantic.dependency_index,
            extern_crate_name: semantic.extern_crate_name.clone(),
        };
        if !provided_edges.insert(key.clone()) || !expected_edges.contains(&key) {
            return Err(CargoUnitGraphNormalizationError::EdgeSemanticsMismatch);
        }
        let Some(dependent) = units.get(semantic.dependent_index) else {
            return Err(CargoUnitGraphNormalizationError::EdgeSemanticsMismatch);
        };
        let Some(dependency) = units.get(semantic.dependency_index) else {
            return Err(CargoUnitGraphNormalizationError::EdgeSemanticsMismatch);
        };
        edges.push(CargoUnitEdge {
            dependent: dependent.selector.clone(),
            dependency: dependency.selector.clone(),
            extern_crate_name: semantic.extern_crate_name.clone(),
            dependency_kind: semantic.dependency_kind,
            target_evaluation_domain: semantic.target_evaluation_domain,
        });
    }
    if provided_edges != expected_edges {
        return Err(CargoUnitGraphNormalizationError::EdgeSemanticsMismatch);
    }

    Ok(HostCargoUnitGraph {
        schema: 2,
        planner: request.planner().clone(),
        build_triple: request.build_triple().into(),
        composition_target: request.target().into(),
        profile: request.profile().into(),
        nodes: units,
        edges,
    }
    .normalize()?)
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CargoPlannerEdgeKey {
    dependent_index: usize,
    dependency_index: usize,
    extern_crate_name: String,
}

fn resolve_package(
    raw_package_id: &str,
    package_index: &LockedPackageIndex<'_>,
) -> Result<CargoPackageIdentity, CargoUnitGraphNormalizationError> {
    let Some(raw) = RawPackageId::parse(raw_package_id) else {
        return Err(CargoUnitGraphNormalizationError::PackageIdentityMismatch(
            raw_package_id.into(),
        ));
    };
    let matches: Vec<_> = package_index
        .get(raw.name)
        .and_then(|versions| versions.get(raw.version))
        .into_iter()
        .flatten()
        .copied()
        .filter(|package| raw.matches(package))
        .collect();
    if let [package] = matches.as_slice() {
        Ok((**package).clone())
    } else {
        Err(CargoUnitGraphNormalizationError::PackageIdentityMismatch(
            raw_package_id.into(),
        ))
    }
}

type LockedPackageIndex<'a> = BTreeMap<String, BTreeMap<String, Vec<&'a CargoPackageIdentity>>>;

fn index_locked_packages(locked_sources: &NormalizedLockedSourceClosure) -> LockedPackageIndex<'_> {
    let mut index: LockedPackageIndex<'_> = BTreeMap::new();
    for package in locked_sources.packages() {
        index
            .entry(package.name.clone())
            .or_default()
            .entry(package.version.clone())
            .or_default()
            .push(package);
    }
    index
}

struct RawPackageId<'a> {
    source: &'a str,
    name: &'a str,
    version: &'a str,
}

impl<'a> RawPackageId<'a> {
    fn parse(value: &'a str) -> Option<Self> {
        let (source, fragment) = value.rsplit_once('#')?;
        if !source.contains("://") || source.contains(['\0', '\n', '\r']) {
            return None;
        }
        let (name, version) = if let Some((name, version)) = fragment.rsplit_once('@') {
            (name, version)
        } else {
            let source_without_query = source.split_once('?').map_or(source, |(url, _)| url);
            let name = source_without_query
                .trim_end_matches('/')
                .rsplit('/')
                .next()?;
            (name, fragment)
        };
        if name.is_empty() || version.is_empty() {
            return None;
        }
        Some(Self {
            source,
            name,
            version,
        })
    }

    fn matches(&self, package: &CargoPackageIdentity) -> bool {
        if self.name != package.name || self.version != package.version {
            return false;
        }
        match &package.source {
            CargoPackageSource::Registry { registry, .. } => {
                self.source == format!("registry+{registry}")
                    || (registry.starts_with("sparse+") && self.source == registry)
            }
            CargoPackageSource::Git { repository, .. } => {
                self.source == format!("git+{repository}")
            }
            CargoPackageSource::Path { .. } => {
                let Some(path) = self.source.strip_prefix("path+file:///rust-agent/closure/")
                else {
                    return false;
                };
                !path.is_empty()
                    && !path.contains(['%', '\\', '?', '#'])
                    && path
                        .split('/')
                        .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
            }
        }
    }
}

fn compilation_kind(
    raw: &super::RawCargoUnit,
    crate_kind: CargoCrateKind,
) -> Result<CargoCompilationKind, CargoUnitGraphNormalizationError> {
    match crate_kind {
        CargoCrateKind::ProcMacro if raw.platform.is_none() => Ok(CargoCompilationKind::BuildHost),
        CargoCrateKind::ProcMacro => Err(CargoUnitGraphNormalizationError::RawUnitDomainMismatch(
            raw.target.name.clone(),
        )),
        CargoCrateKind::CustomBuild => match (raw.mode, raw.platform.is_none()) {
            (RawCargoCompileMode::Build, true) | (RawCargoCompileMode::RunCustomBuild, _) => {
                Ok(CargoCompilationKind::BuildHost)
            }
            _ => Err(CargoUnitGraphNormalizationError::RawUnitDomainMismatch(
                raw.target.name.clone(),
            )),
        },
        _ if raw.platform.is_none() => Ok(CargoCompilationKind::BuildHost),
        _ => Ok(CargoCompilationKind::Target),
    }
}

fn crate_kind(target: &RawCargoTarget) -> Result<CargoCrateKind, CargoUnitGraphNormalizationError> {
    let kind = match target.kind.as_slice() {
        [kind] if kind == "bin" => CargoCrateKind::Binary,
        [kind] if kind == "example" => CargoCrateKind::Example,
        [kind] if kind == "test" => CargoCrateKind::Test,
        [kind] if kind == "bench" => CargoCrateKind::Bench,
        [kind] if kind == "custom-build" => CargoCrateKind::CustomBuild,
        kinds
            if kinds.iter().all(|kind| {
                matches!(
                    kind.as_str(),
                    "lib" | "rlib" | "dylib" | "cdylib" | "staticlib"
                )
            }) =>
        {
            CargoCrateKind::Library
        }
        [kind] if kind == "proc-macro" => CargoCrateKind::ProcMacro,
        _ => {
            return Err(CargoUnitGraphNormalizationError::UnsupportedTargetKind(
                target.kind.join(","),
            ));
        }
    };
    let crate_types_match = match kind {
        CargoCrateKind::Library => target.crate_types.iter().all(|crate_type| {
            matches!(
                crate_type.as_str(),
                "lib" | "rlib" | "dylib" | "cdylib" | "staticlib"
            )
        }),
        CargoCrateKind::ProcMacro => target.crate_types.as_slice() == ["proc-macro"],
        CargoCrateKind::CustomBuild
        | CargoCrateKind::Binary
        | CargoCrateKind::Test
        | CargoCrateKind::Bench => target.crate_types.as_slice() == ["bin"],
        CargoCrateKind::Example => target.crate_types.iter().all(|crate_type| {
            matches!(
                crate_type.as_str(),
                "bin" | "lib" | "rlib" | "dylib" | "cdylib" | "staticlib"
            )
        }),
    };
    if crate_types_match {
        Ok(kind)
    } else {
        Err(CargoUnitGraphNormalizationError::UnsupportedTargetKind(
            format!("{}:{:?}", target.kind.join(","), target.crate_types),
        ))
    }
}

fn compile_mode(mode: RawCargoCompileMode) -> CargoCompileMode {
    match mode {
        RawCargoCompileMode::Test => CargoCompileMode::Test,
        RawCargoCompileMode::Build => CargoCompileMode::Build,
        RawCargoCompileMode::Check => CargoCompileMode::Check,
        RawCargoCompileMode::Doc => CargoCompileMode::Doc,
        RawCargoCompileMode::Doctest => CargoCompileMode::Doctest,
        RawCargoCompileMode::RunCustomBuild => CargoCompileMode::RunCustomBuild,
    }
}

fn verify_root(
    request: &NormalizedCargoPlannerRequest,
    roots: &[usize],
    units: &[CargoUnit],
) -> Result<(), CargoUnitGraphNormalizationError> {
    let [root_index] = roots else {
        return Err(CargoUnitGraphNormalizationError::RootArtifactMismatch);
    };
    let Some(root) = units.get(*root_index) else {
        return Err(CargoUnitGraphNormalizationError::RootArtifactMismatch);
    };
    let (expected_kind, expected_mode) = match &request.artifact_selector().target {
        BuildArtifactTarget::Library => (CargoCrateKind::Library, CargoCompileMode::Build),
        BuildArtifactTarget::Binary { name } => {
            if root.selector.target_name != *name {
                return Err(CargoUnitGraphNormalizationError::RootArtifactMismatch);
            }
            (CargoCrateKind::Binary, CargoCompileMode::Build)
        }
        BuildArtifactTarget::Example { name } => {
            if root.selector.target_name != *name {
                return Err(CargoUnitGraphNormalizationError::RootArtifactMismatch);
            }
            (CargoCrateKind::Example, CargoCompileMode::Build)
        }
        BuildArtifactTarget::Test { name } => {
            if root.selector.target_name != *name {
                return Err(CargoUnitGraphNormalizationError::RootArtifactMismatch);
            }
            (CargoCrateKind::Test, CargoCompileMode::Test)
        }
        BuildArtifactTarget::Bench { name } => {
            if root.selector.target_name != *name {
                return Err(CargoUnitGraphNormalizationError::RootArtifactMismatch);
            }
            (CargoCrateKind::Bench, CargoCompileMode::Test)
        }
    };
    if root.selector.package.name != request.artifact_selector().package
        || root.selector.crate_kind != expected_kind
        || root.selector.compilation_kind != CargoCompilationKind::Target
        || root.selector.compile_mode != expected_mode
        || request.root() == CargoPlannerGraphRoot::EmittedStandalone
            && root.selector.crate_kind != CargoCrateKind::Library
    {
        return Err(CargoUnitGraphNormalizationError::RootArtifactMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn custom_build_unit() -> super::super::RawCargoUnit {
        serde_json::from_value(serde_json::json!({
            "pkg_id": "registry+https://github.com/rust-lang/crates.io-index#consumer@1.0.0",
            "target": {
                "kind": ["custom-build"],
                "crate_types": ["bin"],
                "name": "build-script-build",
                "src_path": "/rust-agent/cargo-home/registry/src/consumer/build.rs",
                "edition": "2024",
                "doc": false,
                "doctest": false,
                "test": false
            },
            "profile": {
                "name": "release",
                "opt_level": "0",
                "lto": "false",
                "codegen_units": null,
                "debuginfo": 0,
                "debug_assertions": false,
                "overflow_checks": false,
                "rpath": false,
                "incremental": false,
                "panic": "unwind",
                "split_debuginfo": null,
                "strip": "none",
                "codegen_backend": null
            },
            "platform": "wasm32-unknown-unknown",
            "mode": "run-custom-build",
            "features": [],
            "dependencies": []
        }))
        .unwrap()
    }

    fn dependency(kind: Option<&str>) -> CargoMetadataNodeDependency {
        CargoMetadataNodeDependency {
            name: "linked_dependency".into(),
            pkg: "registry+https://github.com/rust-lang/crates.io-index#linked-dependency@1.0.0"
                .into(),
            dep_kinds: vec![CargoMetadataDependencyKind {
                kind: kind.map(str::to_owned),
                target: None,
            }],
        }
    }

    #[test]
    fn custom_build_links_edge_retains_exact_normal_metadata_kind() {
        let unit = custom_build_unit();
        let normal = dependency(None);
        assert_eq!(
            expected_dependency_kind(&unit, &[&normal]).unwrap(),
            CargoDependencyKind::Normal
        );

        let build = dependency(Some("build"));
        assert_eq!(
            expected_dependency_kind(&unit, &[&build]).unwrap(),
            CargoDependencyKind::Build
        );

        let development = dependency(Some("dev"));
        assert!(matches!(
            expected_dependency_kind(&unit, &[&development]),
            Err(CargoUnitGraphNormalizationError::AmbiguousEdgeSemantic)
        ));
        assert!(matches!(
            expected_dependency_kind(&unit, &[&normal, &development]),
            Err(CargoUnitGraphNormalizationError::AmbiguousEdgeSemantic)
        ));

        let unit_edge = super::super::RawCargoUnitDependency {
            index: 1,
            extern_crate_name: "build_script_build".into(),
            public: Some(false),
            noprelude: Some(false),
            nounused: Some(false),
        };
        let mut linked_unit = custom_build_unit();
        linked_unit.pkg_id.clone_from(&normal.pkg);
        assert!(metadata_dependency_matches(
            &normal,
            &unit_edge,
            &linked_unit
        ));

        let mut wrong_package = dependency(None);
        wrong_package.pkg.push_str("-other");
        assert!(!metadata_dependency_matches(
            &wrong_package,
            &unit_edge,
            &linked_unit
        ));
    }
}
