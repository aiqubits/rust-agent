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
    CargoUnit, CargoUnitEdge, CargoUnitGraphError, CargoUnitSelector, HostCargoUnitGraph,
    LockedSourceError, NormalizedHostBuildInputClosure, NormalizedHostCargoUnitGraph,
    NormalizedLockedSourceClosure,
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
        let selector = CargoUnitSelector {
            package,
            target_name: raw.target.name.clone(),
            compilation_kind,
            compilation_target: compilation_target.into(),
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
            dependency_kind: semantic.dependency_kind,
            target_evaluation_domain: semantic.target_evaluation_domain,
        });
    }
    if provided_edges != expected_edges {
        return Err(CargoUnitGraphNormalizationError::EdgeSemanticsMismatch);
    }

    Ok(HostCargoUnitGraph {
        schema: 1,
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
