use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, SeqAccess, Visitor},
};

use crate::target::MAX_TARGET_PREDICATE_PARTITIONS;

pub const MAX_CATALOG_DOCUMENT_BYTES: usize = 1024 * 1024;
pub const MAX_CATALOG_OWNERS: usize = 256;
pub const MAX_CATALOG_TRUST_POLICY_BYTES: usize = 64 * 1024;
pub const MAX_SHARED_HOST_CONFIG_FIELDS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CatalogResourceBoundsError {
    OwnerCountOverflow,
    TooManyOwners { actual: usize, maximum: usize },
}

impl fmt::Display for CatalogResourceBoundsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OwnerCountOverflow => formatter.write_str("catalog owner count overflowed"),
            Self::TooManyOwners { actual, maximum } => {
                write!(
                    formatter,
                    "catalog has {actual} owners; maximum is {maximum}"
                )
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedCatalogDocument {
    schema: u32,
    #[serde(default)]
    capabilities: Vec<CapabilitySpec>,
    #[serde(default)]
    components: Vec<ComponentSpec>,
    #[serde(default, rename = "runtime-adapters")]
    runtime_adapters: Vec<RuntimeAdapterSpec>,
    #[serde(default, rename = "host-boundaries")]
    host_boundaries: Vec<HostBoundarySpec>,
}

impl<'de> Deserialize<'de> for CatalogDocument {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unchecked = UncheckedCatalogDocument::deserialize(deserializer)?;
        let document = Self {
            schema: unchecked.schema,
            capabilities: unchecked.capabilities,
            components: unchecked.components,
            runtime_adapters: unchecked.runtime_adapters,
            host_boundaries: unchecked.host_boundaries,
        };
        document
            .validate_resource_bounds()
            .map_err(de::Error::custom)?;
        Ok(document)
    }
}

impl CatalogDocument {
    pub fn from_toml(input: &str) -> Result<Self, toml::de::Error> {
        if input.len() > MAX_CATALOG_DOCUMENT_BYTES {
            return Err(<toml::de::Error as de::Error>::custom(format!(
                "catalog document has {} bytes; maximum is {MAX_CATALOG_DOCUMENT_BYTES}",
                input.len()
            )));
        }
        toml::from_str(input)
    }

    pub(crate) fn validate_resource_bounds(&self) -> Result<(), CatalogResourceBoundsError> {
        let owner_count = self
            .capabilities
            .len()
            .checked_add(self.components.len())
            .and_then(|count| count.checked_add(self.runtime_adapters.len()))
            .and_then(|count| count.checked_add(self.host_boundaries.len()))
            .ok_or(CatalogResourceBoundsError::OwnerCountOverflow)?;
        if owner_count > MAX_CATALOG_OWNERS {
            return Err(CatalogResourceBoundsError::TooManyOwners {
                actual: owner_count,
                maximum: MAX_CATALOG_OWNERS,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
    #[serde(default, rename = "host-api", skip_serializing_if = "Option::is_none")]
    pub host_api: Option<String>,
    #[serde(default, rename = "resource-namespace-preparer")]
    pub resource_namespace_preparer: Option<String>,
    #[serde(default, rename = "prepared-config-type")]
    pub prepared_config_type: Option<String>,
    pub targets: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support: Option<SupportTier>,
    #[serde(
        default,
        rename = "target-support",
        deserialize_with = "deserialize_target_support_entries",
        skip_serializing_if = "Option::is_none"
    )]
    pub target_support: Option<Vec<TargetSupport>>,
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

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetSupport {
    pub predicate: String,
    pub tier: SupportTier,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
    #[serde(default, rename = "resource-namespace")]
    pub resource_namespace: ResourceNamespaceMode,
    pub effects: BTreeSet<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ResourceNamespaceMode {
    #[default]
    None,
    Required {
        bootstrap: String,
    },
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProvideLayer {
    #[default]
    Provider,
    Decorator,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAdapterSpec {
    pub id: String,
    pub package: String,
    #[serde(rename = "package-path")]
    pub package_path: String,
    pub constructor: String,
    pub targets: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support: Option<SupportTier>,
    #[serde(
        default,
        rename = "target-support",
        deserialize_with = "deserialize_target_support_entries",
        skip_serializing_if = "Option::is_none"
    )]
    pub target_support: Option<Vec<TargetSupport>>,
    pub primitives: BTreeSet<String>,
    pub security: BTreeSet<String>,
    #[serde(rename = "app-coexistence")]
    pub app_coexistence: AppCoexistence,
    #[serde(rename = "build-requirements")]
    pub build_requirements: BuildRequirements,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support: Option<SupportTier>,
    #[serde(
        default,
        rename = "target-support",
        deserialize_with = "deserialize_target_support_entries",
        skip_serializing_if = "Option::is_none"
    )]
    pub target_support: Option<Vec<TargetSupport>>,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogTrustPolicy {
    pub schema: u32,
    #[serde(default, rename = "reviewer-policies")]
    pub reviewer_policies: BTreeMap<String, CatalogReviewerPolicy>,
}

impl CatalogTrustPolicy {
    pub fn from_toml(input: &str) -> Result<Self, toml::de::Error> {
        if input.len() > MAX_CATALOG_TRUST_POLICY_BYTES {
            return Err(<toml::de::Error as de::Error>::custom(format!(
                "catalog trust policy has {} bytes; maximum is {MAX_CATALOG_TRUST_POLICY_BYTES}",
                input.len()
            )));
        }
        toml::from_str(input)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogReviewerPolicy {
    #[serde(rename = "evidence-schema")]
    pub evidence_schema: u32,
    #[serde(rename = "rule-sets")]
    pub rule_sets: BTreeSet<String>,
}

fn deserialize_target_support_entries<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<TargetSupport>>, D::Error>
where
    D: Deserializer<'de>,
{
    struct TargetSupportEntriesVisitor;

    impl<'de> Visitor<'de> for TargetSupportEntriesVisitor {
        type Value = Option<Vec<TargetSupport>>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "at most {MAX_TARGET_PREDICATE_PARTITIONS} target-support entries"
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut entries = Vec::new();
            while let Some(entry) = sequence.next_element::<TargetSupport>()? {
                if entries.len() == MAX_TARGET_PREDICATE_PARTITIONS {
                    return Err(de::Error::custom(format!(
                        "target-support entry count exceeds {MAX_TARGET_PREDICATE_PARTITIONS}"
                    )));
                }
                entries.push(entry);
            }
            Ok(Some(entries))
        }
    }

    deserializer.deserialize_seq(TargetSupportEntriesVisitor)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog_with_capabilities(count: usize) -> String {
        let mut input = String::from("schema = 1\n");
        for index in 0..count {
            input.push_str(&format!(
                r#"
[[capabilities]]
id = "cap:test-{index}"
api-package = "test-api-{index}"
rust-api = "test_api_{index}::Api"
binding-type = "test_api_{index}::Binding"
binding-adapter = "test_api_{index}::Adapter"
binding = "singleton"
scope = "app"
"#,
            ));
        }
        input
    }

    #[test]
    fn catalog_document_byte_and_owner_boundaries_are_closed() {
        let prefix = "schema = 1\n";
        let exact_bytes = format!(
            "{prefix}{}",
            " ".repeat(MAX_CATALOG_DOCUMENT_BYTES - prefix.len())
        );
        CatalogDocument::from_toml(&exact_bytes).unwrap();
        let oversized_bytes = format!("{exact_bytes} ");
        assert!(CatalogDocument::from_toml(&oversized_bytes).is_err());

        let maximum_catalog =
            CatalogDocument::from_toml(&catalog_with_capabilities(MAX_CATALOG_OWNERS)).unwrap();
        assert!(
            CatalogDocument::from_toml(&catalog_with_capabilities(MAX_CATALOG_OWNERS + 1)).is_err()
        );
        assert!(
            toml::from_str::<CatalogDocument>(&catalog_with_capabilities(MAX_CATALOG_OWNERS + 1))
                .is_err()
        );

        let mut direct_json = serde_json::to_value(maximum_catalog).unwrap();
        let capabilities = direct_json["capabilities"].as_array_mut().unwrap();
        capabilities.push(capabilities[0].clone());
        assert!(serde_json::from_value::<CatalogDocument>(direct_json).is_err());
    }

    #[test]
    fn catalog_trust_policy_input_bytes_are_bounded() {
        let prefix = "schema = 1\n";
        let exact = format!(
            "{prefix}{}",
            " ".repeat(MAX_CATALOG_TRUST_POLICY_BYTES - prefix.len())
        );
        CatalogTrustPolicy::from_toml(&exact).unwrap();
        assert!(CatalogTrustPolicy::from_toml(&format!("{exact} ")).is_err());
    }
}
