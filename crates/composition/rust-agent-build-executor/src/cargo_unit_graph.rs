use std::collections::{BTreeMap, BTreeSet};

use rust_agent_composition::canonical;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CargoPackageIdentity {
    pub name: String,
    pub version: String,
    pub source: CargoPackageSource,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CargoPackageSource {
    Registry {
        registry: String,
        checksum: String,
    },
    Git {
        repository: String,
        precise: String,
    },
    Path {
        #[serde(rename = "tree-digest")]
        tree_digest: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CargoUnitSelector {
    pub package: CargoPackageIdentity,
    #[serde(rename = "target-name")]
    pub target_name: String,
    #[serde(rename = "compilation-kind")]
    pub compilation_kind: CargoCompilationKind,
    #[serde(rename = "compilation-target")]
    pub compilation_target: String,
    #[serde(rename = "cargo-target-context")]
    pub cargo_target_context: CargoUnitTargetContext,
    #[serde(rename = "compile-mode")]
    pub compile_mode: CargoCompileMode,
    pub profile: String,
    #[serde(rename = "crate-kind")]
    pub crate_kind: CargoCrateKind,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CargoCompilationKind {
    #[serde(rename = "host")]
    BuildHost,
    Target,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CargoUnitTargetContext {
    BuildHost,
    CompositionTarget,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CargoCrateKind {
    #[serde(rename = "lib")]
    Library,
    #[serde(rename = "bin")]
    Binary,
    Example,
    Test,
    Bench,
    CustomBuild,
    ProcMacro,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CargoCompileMode {
    Build,
    Check,
    Test,
    Doc,
    Doctest,
    RunCustomBuild,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CargoUnit {
    pub selector: CargoUnitSelector,
    pub features: Vec<String>,
    #[serde(rename = "build-script")]
    pub build_script: bool,
    #[serde(rename = "proc-macro")]
    pub proc_macro: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedCargoUnit {
    pub selector: CargoUnitSelector,
    pub features: BTreeSet<String>,
    pub build_script: bool,
    pub proc_macro: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CargoDependencyKind {
    Normal,
    Build,
    Development,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CargoTargetEvaluationDomain {
    #[serde(rename = "host")]
    BuildHost,
    Target,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CargoUnitEdge {
    pub dependent: CargoUnitSelector,
    pub dependency: CargoUnitSelector,
    #[serde(rename = "extern-crate-name")]
    pub extern_crate_name: String,
    #[serde(rename = "dependency-kind")]
    pub dependency_kind: CargoDependencyKind,
    #[serde(rename = "target-evaluation-domain")]
    pub target_evaluation_domain: CargoTargetEvaluationDomain,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CargoUnitGraphPlannerIdentity {
    pub interface: String,
    #[serde(rename = "cargo-version")]
    pub cargo_version: String,
    #[serde(rename = "cargo-digest")]
    pub cargo_digest: String,
    #[serde(rename = "rustc-version")]
    pub rustc_version: String,
    #[serde(rename = "rustc-digest")]
    pub rustc_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostCargoUnitGraph {
    pub schema: u32,
    pub planner: CargoUnitGraphPlannerIdentity,
    #[serde(rename = "build-triple")]
    pub build_triple: String,
    #[serde(rename = "composition-target")]
    pub composition_target: String,
    pub profile: String,
    pub nodes: Vec<CargoUnit>,
    pub edges: Vec<CargoUnitEdge>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedHostCargoUnitGraph {
    planner: CargoUnitGraphPlannerIdentity,
    build_triple: String,
    composition_target: String,
    profile: String,
    nodes: BTreeMap<CargoUnitSelector, NormalizedCargoUnit>,
    edges: BTreeSet<CargoUnitEdge>,
    digest: String,
}

#[derive(Debug, Error)]
pub enum CargoUnitGraphError {
    #[error("unsupported HostCargoUnitGraph schema {0}; expected 2")]
    UnsupportedSchema(u32),
    #[error("invalid planner identity field `{0}`")]
    InvalidPlannerIdentity(&'static str),
    #[error("invalid Cargo unit selector: {0}")]
    InvalidSelector(String),
    #[error("Cargo unit features must be strictly sorted, unique identifiers: {0:?}")]
    InvalidFeatures(Box<CargoUnitSelector>),
    #[error("duplicate Cargo unit selector: {0:?}")]
    DuplicateUnit(Box<CargoUnitSelector>),
    #[error("Cargo unit flags do not match its crate kind: {0:?}")]
    UnitFlagMismatch(Box<CargoUnitSelector>),
    #[error("build script/proc-macro unit is not in the build-host domain: {0:?}")]
    HostUnitInTargetDomain(Box<CargoUnitSelector>),
    #[error("Cargo unit edge references a missing node: {0:?}")]
    MissingEdgeNode(Box<CargoUnitEdge>),
    #[error("duplicate Cargo unit edge: {0:?}")]
    DuplicateEdge(Box<CargoUnitEdge>),
    #[error("Cargo compile unit has an ambiguous extern-crate name: {0:?}")]
    AmbiguousExternCrateName(Box<CargoUnitEdge>),
    #[error("HostCargoUnitGraph contains a dependency cycle")]
    DependencyCycle,
    #[error("Cargo edge dependency kind/domain does not match its dependency unit: {0:?}")]
    EdgeDomainMismatch(Box<CargoUnitEdge>),
    #[error("planned and observed HostCargoUnitGraph differ")]
    ObservationDrift,
    #[error("canonical HostCargoUnitGraph encoding failed: {0}")]
    Canonical(#[from] canonical::CanonicalError),
}

impl HostCargoUnitGraph {
    pub fn normalize(&self) -> Result<NormalizedHostCargoUnitGraph, CargoUnitGraphError> {
        if self.schema != 2 {
            return Err(CargoUnitGraphError::UnsupportedSchema(self.schema));
        }
        validate_planner(&self.planner)?;
        validate_text("build-triple", &self.build_triple)?;
        validate_text("composition-target", &self.composition_target)?;
        validate_text("profile", &self.profile)?;

        let mut nodes = BTreeMap::new();
        for unit in &self.nodes {
            validate_selector(&unit.selector, &self.build_triple, &self.composition_target)?;
            validate_unit(unit)?;
            let normalized = NormalizedCargoUnit {
                selector: unit.selector.clone(),
                features: unit.features.iter().cloned().collect(),
                build_script: unit.build_script,
                proc_macro: unit.proc_macro,
            };
            if nodes.insert(unit.selector.clone(), normalized).is_some() {
                return Err(CargoUnitGraphError::DuplicateUnit(Box::new(
                    unit.selector.clone(),
                )));
            }
        }
        if nodes.is_empty() {
            return Err(CargoUnitGraphError::InvalidSelector(
                "unit graph must contain at least one node".into(),
            ));
        }

        let mut edges = BTreeSet::new();
        let mut extern_names = BTreeSet::new();
        for edge in &self.edges {
            if !nodes.contains_key(&edge.dependent) || !nodes.contains_key(&edge.dependency) {
                return Err(CargoUnitGraphError::MissingEdgeNode(Box::new(edge.clone())));
            }
            validate_edge(edge)?;
            if !edges.insert(edge.clone()) {
                return Err(CargoUnitGraphError::DuplicateEdge(Box::new(edge.clone())));
            }
            if edge.dependency.compile_mode != CargoCompileMode::RunCustomBuild
                && !extern_names.insert((edge.dependent.clone(), edge.extern_crate_name.clone()))
            {
                return Err(CargoUnitGraphError::AmbiguousExternCrateName(Box::new(
                    edge.clone(),
                )));
            }
        }
        validate_acyclic(&nodes, &edges)?;

        let canonical_nodes: Vec<_> = nodes.values().cloned().collect();
        let canonical_edges: Vec<_> = edges.iter().cloned().collect();
        let digest = hex::encode(canonical::domain_hash(
            b"rust-agent-host-cargo-unit-graph-v2\0",
            &(
                2_u32,
                &self.planner,
                &self.build_triple,
                &self.composition_target,
                &self.profile,
                &canonical_nodes
                    .iter()
                    .map(|unit| {
                        (
                            &unit.selector,
                            &unit.features,
                            unit.build_script,
                            unit.proc_macro,
                        )
                    })
                    .collect::<Vec<_>>(),
                &canonical_edges,
            ),
        )?);
        Ok(NormalizedHostCargoUnitGraph {
            planner: self.planner.clone(),
            build_triple: self.build_triple.clone(),
            composition_target: self.composition_target.clone(),
            profile: self.profile.clone(),
            nodes,
            edges,
            digest,
        })
    }
}

impl NormalizedHostCargoUnitGraph {
    pub fn planner(&self) -> &CargoUnitGraphPlannerIdentity {
        &self.planner
    }

    pub fn build_triple(&self) -> &str {
        &self.build_triple
    }

    pub fn composition_target(&self) -> &str {
        &self.composition_target
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn nodes(&self) -> &BTreeMap<CargoUnitSelector, NormalizedCargoUnit> {
        &self.nodes
    }

    pub fn edges(&self) -> &BTreeSet<CargoUnitEdge> {
        &self.edges
    }

    pub fn verify_observation(&self, observed: &Self) -> Result<(), CargoUnitGraphError> {
        if self == observed {
            Ok(())
        } else {
            Err(CargoUnitGraphError::ObservationDrift)
        }
    }
}

fn validate_planner(planner: &CargoUnitGraphPlannerIdentity) -> Result<(), CargoUnitGraphError> {
    if planner.interface != "cargo-unit-graph-v1" {
        return Err(CargoUnitGraphError::InvalidPlannerIdentity("interface"));
    }
    for (field, value) in [
        ("cargo-version", planner.cargo_version.as_str()),
        ("rustc-version", planner.rustc_version.as_str()),
    ] {
        if validate_text(field, value).is_err() {
            return Err(CargoUnitGraphError::InvalidPlannerIdentity(field));
        }
    }
    for (field, digest) in [
        ("cargo-digest", planner.cargo_digest.as_str()),
        ("rustc-digest", planner.rustc_digest.as_str()),
    ] {
        if !is_digest(digest) {
            return Err(CargoUnitGraphError::InvalidPlannerIdentity(field));
        }
    }
    Ok(())
}

pub(crate) fn validate_selector(
    selector: &CargoUnitSelector,
    build_triple: &str,
    composition_target: &str,
) -> Result<(), CargoUnitGraphError> {
    validate_selector_identity(selector)?;
    let expected = match selector.compilation_kind {
        CargoCompilationKind::BuildHost => build_triple,
        CargoCompilationKind::Target => composition_target,
    };
    if selector.compilation_target != expected {
        return Err(CargoUnitGraphError::InvalidSelector(format!(
            "compilation target `{}` does not match `{expected}`",
            selector.compilation_target
        )));
    }
    let valid_context = matches!(
        (
            selector.compilation_kind,
            selector.cargo_target_context,
            selector.crate_kind,
            selector.compile_mode,
        ),
        (
            CargoCompilationKind::Target,
            CargoUnitTargetContext::CompositionTarget,
            _,
            _
        ) | (
            CargoCompilationKind::BuildHost,
            CargoUnitTargetContext::BuildHost,
            _,
            _
        ) | (
            CargoCompilationKind::BuildHost,
            CargoUnitTargetContext::CompositionTarget,
            CargoCrateKind::CustomBuild,
            CargoCompileMode::RunCustomBuild,
        )
    );
    if !valid_context {
        return Err(CargoUnitGraphError::InvalidSelector(format!(
            "Cargo target context {:?} is invalid for {:?}/{:?}/{:?}",
            selector.cargo_target_context,
            selector.compilation_kind,
            selector.crate_kind,
            selector.compile_mode,
        )));
    }
    Ok(())
}

pub(crate) fn validate_selector_identity(
    selector: &CargoUnitSelector,
) -> Result<(), CargoUnitGraphError> {
    validate_package(&selector.package)?;
    validate_text("target-name", &selector.target_name)?;
    validate_text("compilation-target", &selector.compilation_target)?;
    validate_text("profile", &selector.profile)?;
    Ok(())
}

fn validate_package(package: &CargoPackageIdentity) -> Result<(), CargoUnitGraphError> {
    validate_text("package-name", &package.name)?;
    validate_text("package-version", &package.version)?;
    match &package.source {
        CargoPackageSource::Registry { registry, checksum } => {
            validate_source("registry", registry)?;
            if !is_digest(checksum) {
                return Err(CargoUnitGraphError::InvalidSelector(
                    "registry checksum is not canonical SHA-256".into(),
                ));
            }
        }
        CargoPackageSource::Git {
            repository,
            precise,
        } => {
            validate_source("repository", repository)?;
            if !matches!(precise.len(), 40 | 64)
                || precise
                    .bytes()
                    .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
            {
                return Err(CargoUnitGraphError::InvalidSelector(
                    "git source lacks a precise lowercase revision".into(),
                ));
            }
        }
        CargoPackageSource::Path { tree_digest } if !is_digest(tree_digest) => {
            return Err(CargoUnitGraphError::InvalidSelector(
                "path source lacks a canonical tree digest".into(),
            ));
        }
        CargoPackageSource::Path { .. } => {}
    }
    Ok(())
}

fn validate_unit(unit: &CargoUnit) -> Result<(), CargoUnitGraphError> {
    if unit.features.windows(2).any(|pair| pair[0] >= pair[1])
        || unit.features.iter().any(|feature| !is_feature(feature))
    {
        return Err(CargoUnitGraphError::InvalidFeatures(Box::new(
            unit.selector.clone(),
        )));
    }
    let flags_match = unit.build_script
        == (unit.selector.crate_kind == CargoCrateKind::CustomBuild)
        && unit.proc_macro == (unit.selector.crate_kind == CargoCrateKind::ProcMacro);
    if !flags_match || (unit.build_script && unit.proc_macro) {
        return Err(CargoUnitGraphError::UnitFlagMismatch(Box::new(
            unit.selector.clone(),
        )));
    }
    if (unit.selector.compile_mode == CargoCompileMode::RunCustomBuild && !unit.build_script)
        || (unit.selector.compile_mode == CargoCompileMode::Doctest
            && unit.selector.crate_kind != CargoCrateKind::Library)
    {
        return Err(CargoUnitGraphError::UnitFlagMismatch(Box::new(
            unit.selector.clone(),
        )));
    }
    if matches!(
        unit.selector.crate_kind,
        CargoCrateKind::CustomBuild | CargoCrateKind::ProcMacro
    ) && unit.selector.compilation_kind != CargoCompilationKind::BuildHost
    {
        return Err(CargoUnitGraphError::HostUnitInTargetDomain(Box::new(
            unit.selector.clone(),
        )));
    }
    Ok(())
}

fn validate_acyclic(
    nodes: &BTreeMap<CargoUnitSelector, NormalizedCargoUnit>,
    edges: &BTreeSet<CargoUnitEdge>,
) -> Result<(), CargoUnitGraphError> {
    let mut incoming: BTreeMap<_, usize> = nodes.keys().cloned().map(|node| (node, 0)).collect();
    let mut outgoing: BTreeMap<CargoUnitSelector, Vec<CargoUnitSelector>> = BTreeMap::new();
    for edge in edges {
        *incoming
            .get_mut(&edge.dependency)
            .expect("edge nodes were validated") += 1;
        outgoing
            .entry(edge.dependent.clone())
            .or_default()
            .push(edge.dependency.clone());
    }
    let mut ready: BTreeSet<_> = incoming
        .iter()
        .filter_map(|(node, count)| (*count == 0).then_some(node.clone()))
        .collect();
    let mut visited = 0;
    while let Some(node) = ready.pop_first() {
        visited += 1;
        for dependency in outgoing.get(&node).into_iter().flatten() {
            let count = incoming
                .get_mut(dependency)
                .expect("edge nodes were validated");
            *count -= 1;
            if *count == 0 {
                ready.insert(dependency.clone());
            }
        }
    }
    if visited == nodes.len() {
        Ok(())
    } else {
        Err(CargoUnitGraphError::DependencyCycle)
    }
}

fn validate_edge(edge: &CargoUnitEdge) -> Result<(), CargoUnitGraphError> {
    if !valid_cargo_name(&edge.extern_crate_name) {
        return Err(CargoUnitGraphError::InvalidSelector(
            "invalid `extern-crate-name`".into(),
        ));
    }
    let expected_domain = match edge.dependency.compilation_kind {
        CargoCompilationKind::BuildHost => CargoTargetEvaluationDomain::BuildHost,
        CargoCompilationKind::Target => CargoTargetEvaluationDomain::Target,
    };
    if edge.target_evaluation_domain != expected_domain
        || (edge.dependency_kind == CargoDependencyKind::Build
            && edge.dependency.compilation_kind != CargoCompilationKind::BuildHost)
    {
        return Err(CargoUnitGraphError::EdgeDomainMismatch(Box::new(
            edge.clone(),
        )));
    }
    Ok(())
}

fn valid_cargo_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphabetic()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn validate_source(field: &'static str, value: &str) -> Result<(), CargoUnitGraphError> {
    if value.is_empty()
        || value.len() > 2048
        || value.contains('*')
        || value.chars().any(char::is_whitespace)
    {
        Err(CargoUnitGraphError::InvalidSelector(format!(
            "invalid exact {field} source"
        )))
    } else {
        Ok(())
    }
}

fn validate_text(field: &'static str, value: &str) -> Result<(), CargoUnitGraphError> {
    if value.is_empty()
        || value.len() > 256
        || value.chars().any(char::is_whitespace)
        || value.contains('*')
    {
        Err(CargoUnitGraphError::InvalidSelector(format!(
            "invalid `{field}`"
        )))
    } else {
        Ok(())
    }
}

fn is_feature(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package(name: &str) -> CargoPackageIdentity {
        CargoPackageIdentity {
            name: name.into(),
            version: "1.0.0".into(),
            source: CargoPackageSource::Registry {
                registry: "https://github.com/rust-lang/crates.io-index".into(),
                checksum: "11".repeat(32),
            },
        }
    }

    fn selector(
        name: &str,
        crate_kind: CargoCrateKind,
        compilation_kind: CargoCompilationKind,
    ) -> CargoUnitSelector {
        CargoUnitSelector {
            package: package(name),
            target_name: name.replace('-', "_"),
            compilation_kind,
            compilation_target: match compilation_kind {
                CargoCompilationKind::BuildHost => "x86_64-unknown-linux-gnu",
                CargoCompilationKind::Target => "wasm32-unknown-unknown",
            }
            .into(),
            cargo_target_context: match compilation_kind {
                CargoCompilationKind::BuildHost => CargoUnitTargetContext::BuildHost,
                CargoCompilationKind::Target => CargoUnitTargetContext::CompositionTarget,
            },
            compile_mode: CargoCompileMode::Build,
            profile: "release".into(),
            crate_kind,
        }
    }

    fn graph() -> HostCargoUnitGraph {
        let target = selector(
            "shared-helper",
            CargoCrateKind::Library,
            CargoCompilationKind::Target,
        );
        let build = selector(
            "shared-helper",
            CargoCrateKind::CustomBuild,
            CargoCompilationKind::BuildHost,
        );
        HostCargoUnitGraph {
            schema: 2,
            planner: CargoUnitGraphPlannerIdentity {
                interface: "cargo-unit-graph-v1".into(),
                cargo_version: "1.97.1".into(),
                cargo_digest: "22".repeat(32),
                rustc_version: "1.97.1".into(),
                rustc_digest: "33".repeat(32),
            },
            build_triple: "x86_64-unknown-linux-gnu".into(),
            composition_target: "wasm32-unknown-unknown".into(),
            profile: "release".into(),
            nodes: vec![
                CargoUnit {
                    selector: target.clone(),
                    features: vec!["std".into(), "wasm".into()],
                    build_script: false,
                    proc_macro: false,
                },
                CargoUnit {
                    selector: build.clone(),
                    features: vec!["host-tool".into()],
                    build_script: true,
                    proc_macro: false,
                },
            ],
            edges: vec![CargoUnitEdge {
                dependent: target,
                dependency: build,
                extern_crate_name: "build_script_build".into(),
                dependency_kind: CargoDependencyKind::Build,
                target_evaluation_domain: CargoTargetEvaluationDomain::BuildHost,
            }],
        }
    }

    #[test]
    fn host_and_target_units_remain_distinct_and_deterministic() {
        let first = graph().normalize().unwrap();
        assert_eq!(first.nodes().len(), 2);
        assert!(first.nodes().keys().any(|unit| {
            unit.compilation_kind == CargoCompilationKind::BuildHost
                && unit.compilation_target == "x86_64-unknown-linux-gnu"
        }));
        assert!(first.nodes().keys().any(|unit| {
            unit.compilation_kind == CargoCompilationKind::Target
                && unit.compilation_target == "wasm32-unknown-unknown"
        }));

        let mut reordered = graph();
        reordered.nodes.reverse();
        assert_eq!(first.digest(), reordered.normalize().unwrap().digest());
    }

    #[test]
    fn schema_two_distinguishes_build_script_target_contexts() {
        let mut build_host = selector(
            "linked-helper",
            CargoCrateKind::CustomBuild,
            CargoCompilationKind::BuildHost,
        );
        build_host.compile_mode = CargoCompileMode::RunCustomBuild;
        let mut composition_target = build_host.clone();
        composition_target.cargo_target_context = CargoUnitTargetContext::CompositionTarget;
        let mut value = graph();
        value.nodes = vec![
            CargoUnit {
                selector: build_host,
                features: vec![],
                build_script: true,
                proc_macro: false,
            },
            CargoUnit {
                selector: composition_target,
                features: vec![],
                build_script: true,
                proc_macro: false,
            },
        ];
        value.edges.clear();
        let normalized = value.normalize().unwrap();
        assert_eq!(normalized.nodes().len(), 2);
        assert_eq!(
            normalized
                .nodes()
                .keys()
                .map(|selector| selector.cargo_target_context)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                CargoUnitTargetContext::BuildHost,
                CargoUnitTargetContext::CompositionTarget,
            ])
        );

        let mut legacy = graph();
        legacy.schema = 1;
        assert!(matches!(
            legacy.normalize(),
            Err(CargoUnitGraphError::UnsupportedSchema(1))
        ));

        let mut invalid = graph();
        invalid.nodes[0].selector.cargo_target_context = CargoUnitTargetContext::BuildHost;
        assert!(matches!(
            invalid.normalize(),
            Err(CargoUnitGraphError::InvalidSelector(_))
        ));
    }

    #[test]
    fn unknown_fields_unsorted_features_and_domain_confusion_fail_closed() {
        let mut value = serde_json::to_value(graph()).unwrap();
        value["ambient"] = serde_json::json!(true);
        assert!(serde_json::from_value::<HostCargoUnitGraph>(value).is_err());

        let mut unsorted = graph();
        unsorted.nodes[0].features.reverse();
        assert!(matches!(
            unsorted.normalize(),
            Err(CargoUnitGraphError::InvalidFeatures(_))
        ));

        let mut wrong_domain = graph();
        wrong_domain.edges[0].target_evaluation_domain = CargoTargetEvaluationDomain::Target;
        assert!(matches!(
            wrong_domain.normalize(),
            Err(CargoUnitGraphError::EdgeDomainMismatch(_))
        ));

        for invalid_name in ["", "0dependency", "dependency name", "dependency!"] {
            let mut invalid = graph();
            invalid.edges[0].extern_crate_name = invalid_name.into();
            assert!(matches!(
                invalid.normalize(),
                Err(CargoUnitGraphError::InvalidSelector(_))
            ));
        }
    }

    #[test]
    fn missing_nodes_duplicates_and_observation_drift_are_rejected() {
        let mut missing = graph();
        missing.nodes.pop();
        assert!(matches!(
            missing.normalize(),
            Err(CargoUnitGraphError::MissingEdgeNode(_))
        ));

        let mut duplicate = graph();
        duplicate.nodes.push(duplicate.nodes[0].clone());
        assert!(matches!(
            duplicate.normalize(),
            Err(CargoUnitGraphError::DuplicateUnit(_))
        ));

        let mut duplicate_edge = graph();
        duplicate_edge.edges.push(duplicate_edge.edges[0].clone());
        assert!(matches!(
            duplicate_edge.normalize(),
            Err(CargoUnitGraphError::DuplicateEdge(_))
        ));

        let mut ambiguous_extern = graph();
        let second_dependency = selector(
            "second-helper",
            CargoCrateKind::Library,
            CargoCompilationKind::Target,
        );
        ambiguous_extern.nodes.push(CargoUnit {
            selector: second_dependency.clone(),
            features: vec![],
            build_script: false,
            proc_macro: false,
        });
        ambiguous_extern.edges.push(CargoUnitEdge {
            dependent: ambiguous_extern.edges[0].dependent.clone(),
            dependency: second_dependency,
            extern_crate_name: ambiguous_extern.edges[0].extern_crate_name.clone(),
            dependency_kind: CargoDependencyKind::Normal,
            target_evaluation_domain: CargoTargetEvaluationDomain::Target,
        });
        assert!(matches!(
            ambiguous_extern.normalize(),
            Err(CargoUnitGraphError::AmbiguousExternCrateName(_))
        ));

        let mut cyclic = graph();
        let reverse = CargoUnitEdge {
            dependent: cyclic.edges[0].dependency.clone(),
            dependency: cyclic.edges[0].dependent.clone(),
            extern_crate_name: "shared_helper".into(),
            dependency_kind: CargoDependencyKind::Normal,
            target_evaluation_domain: CargoTargetEvaluationDomain::Target,
        };
        cyclic.edges.push(reverse);
        assert!(matches!(
            cyclic.normalize(),
            Err(CargoUnitGraphError::DependencyCycle)
        ));

        let planned = graph().normalize().unwrap();
        let mut renamed = graph();
        renamed.edges[0].extern_crate_name = "renamed_build_script".into();
        let renamed = renamed.normalize().unwrap();
        assert_ne!(planned.digest(), renamed.digest());
        assert!(matches!(
            planned.verify_observation(&renamed),
            Err(CargoUnitGraphError::ObservationDrift)
        ));

        let mut observed = graph();
        observed.nodes[0].features.push("z-extra".into());
        let observed = observed.normalize().unwrap();
        assert!(matches!(
            planned.verify_observation(&observed),
            Err(CargoUnitGraphError::ObservationDrift)
        ));
    }
}
