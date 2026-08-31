use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogDocument {
    pub schema: u32,
    #[serde(default)]
    pub capabilities: Vec<CapabilitySpec>,
    #[serde(default)]
    pub components: Vec<ComponentSpec>,
    #[serde(default, rename = "runtime-adapters")]
    pub runtime_adapters: Vec<RuntimeAdapterSpec>,
    #[serde(default, rename = "host-boundaries")]
    pub host_boundaries: Vec<HostBoundarySpec>,
}

impl CatalogDocument {
    pub fn from_toml(input: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(input)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySpec {
    pub id: String,
    #[serde(rename = "api-package")]
    pub api_package: String,
    #[serde(rename = "rust-api")]
    pub rust_api: String,
    #[serde(rename = "binding-type")]
    pub binding_type: String,
    #[serde(rename = "binding-adapter")]
    pub binding_adapter: String,
    pub binding: BindingKind,
    pub scope: ScopeKind,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BindingKind {
    Singleton,
    Registry,
    OrderedMulti,
    DecoratorChain,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScopeKind {
    App,
    Session,
    Agent,
}

impl ScopeKind {
    pub const fn may_depend_on(self, provider: Self) -> bool {
        match self {
            Self::App => matches!(provider, Self::App),
            Self::Session => matches!(provider, Self::App | Self::Session),
            Self::Agent => true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentSpec {
    pub id: String,
    pub package: String,
    #[serde(rename = "package-path")]
    pub package_path: String,
    pub scope: ScopeKind,
    pub factory: String,
    #[serde(rename = "dependencies-type")]
    pub dependencies_type: String,
    #[serde(rename = "config-type")]
    pub config_type: String,
    #[serde(rename = "config-source")]
    pub config_source: ConfigSource,
    #[serde(default, rename = "config-key")]
    pub config_key: Option<String>,
    pub targets: String,
    pub support: SupportTier,
    #[serde(rename = "lifecycle-effects")]
    pub lifecycle_effects: BTreeSet<String>,
    pub provides: Vec<CapabilityProvide>,
    #[serde(default)]
    pub requires: Vec<CapabilityRequirement>,
    #[serde(default)]
    pub conflicts: BTreeSet<String>,
    pub security: BTreeSet<String>,
    #[serde(rename = "runtime-primitives")]
    pub runtime_primitives: BTreeSet<String>,
    #[serde(rename = "build-requirements")]
    pub build_requirements: BuildRequirements,
    #[serde(default, rename = "app-coexistence")]
    pub app_coexistence: Option<AppCoexistence>,
    #[serde(default, rename = "cargo-features")]
    pub cargo_features: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigSource {
    None,
    File,
    Host,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SupportTier {
    Experimental,
    Production,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityProvide {
    pub capability: String,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub order: i32,
    #[serde(default)]
    pub layer: ProvideLayer,
    pub effects: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProvideLayer {
    #[default]
    Provider,
    Decorator,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRequirement {
    pub capability: String,
    pub mode: RequirementMode,
    pub field: String,
    #[serde(default)]
    pub key: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RequirementMode {
    Required,
    UsesIfPresent,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
pub enum AppCoexistence {
    ConcurrentIndependent {
        evidence: EvidenceRef,
    },
    ConcurrentSharedHostHandle {
        evidence: EvidenceRef,
        #[serde(rename = "host-config-fields")]
        host_config_fields: Vec<String>,
    },
    RequiresStop,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRef {
    pub source: String,
    pub algorithm: String,
    pub digest: String,
    #[serde(rename = "reviewer-policy")]
    pub reviewer_policy: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuildRequirements {
    pub executables: BTreeSet<String>,
    #[serde(rename = "read-inputs")]
    pub read_inputs: BTreeSet<String>,
    pub environment: BTreeSet<String>,
}

impl BuildRequirements {
    pub fn is_empty(&self) -> bool {
        self.executables.is_empty() && self.read_inputs.is_empty() && self.environment.is_empty()
    }

    pub fn merge_from(&mut self, other: &Self) {
        self.executables.extend(other.executables.iter().cloned());
        self.read_inputs.extend(other.read_inputs.iter().cloned());
        self.environment.extend(other.environment.iter().cloned());
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAdapterSpec {
    pub id: String,
    pub package: String,
    #[serde(rename = "package-path")]
    pub package_path: String,
    pub constructor: String,
    pub targets: String,
    pub support: SupportTier,
    pub primitives: BTreeSet<String>,
    pub security: BTreeSet<String>,
    #[serde(rename = "app-coexistence")]
    pub app_coexistence: AppCoexistence,
    #[serde(rename = "build-requirements")]
    pub build_requirements: BuildRequirements,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostBoundarySpec {
    pub id: String,
    pub package: String,
    #[serde(rename = "package-path")]
    pub package_path: String,
    pub kind: HostBoundaryKind,
    #[serde(default)]
    pub entry: Option<String>,
    #[serde(default, rename = "export-module")]
    pub export_module: Option<String>,
    pub targets: String,
    pub support: SupportTier,
    pub security: BTreeSet<String>,
    #[serde(rename = "runtime-adapters")]
    pub runtime_adapters: BTreeSet<String>,
    #[serde(rename = "build-requirements")]
    pub build_requirements: BuildRequirements,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostBoundaryKind {
    Entry,
    WasmExport,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogTrustPolicy {
    pub schema: u32,
    #[serde(default, rename = "reviewer-policies")]
    pub reviewer_policies: BTreeMap<String, BTreeSet<String>>,
}
