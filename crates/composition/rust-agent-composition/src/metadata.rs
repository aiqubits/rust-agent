use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Deserializer, Serialize, de};

use crate::{
    serde_bounds::{
        deserialize_bounded_vec, deserialize_unique_bounded_map, deserialize_unique_bounded_set,
    },
    target::MAX_TARGET_PREDICATE_PARTITIONS,
};

pub const MAX_CATALOG_DOCUMENT_BYTES: usize = 1024 * 1024;
pub const MAX_CATALOG_OWNERS: usize = 256;
pub const MAX_CATALOG_TRUST_POLICY_BYTES: usize = 64 * 1024;
pub const MAX_SHARED_HOST_CONFIG_FIELDS: usize = 64;
pub const MAX_CATALOG_REVIEWER_RULE_SETS: usize = 16;
pub const MAX_BUILD_REQUIREMENT_ENTRIES_PER_KIND: usize = 16 * 1_024;

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
    #[serde(default, deserialize_with = "deserialize_catalog_capabilities")]
    capabilities: Vec<CapabilitySpec>,
    #[serde(default, deserialize_with = "deserialize_catalog_components")]
    components: Vec<ComponentSpec>,
    #[serde(
        default,
        rename = "runtime-adapters",
        deserialize_with = "deserialize_catalog_runtime_adapters"
    )]
    runtime_adapters: Vec<RuntimeAdapterSpec>,
    #[serde(
        default,
        rename = "host-boundaries",
        deserialize_with = "deserialize_catalog_host_boundaries"
    )]
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
        #[serde(
            rename = "host-config-fields",
            deserialize_with = "deserialize_shared_host_config_fields"
        )]
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

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuildRequirements {
    pub executables: BTreeSet<String>,
    #[serde(rename = "read-inputs")]
    pub read_inputs: BTreeSet<String>,
    pub environment: BTreeSet<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedBuildRequirements {
    #[serde(deserialize_with = "deserialize_build_requirement_set")]
    executables: BTreeSet<String>,
    #[serde(
        rename = "read-inputs",
        deserialize_with = "deserialize_build_requirement_set"
    )]
    read_inputs: BTreeSet<String>,
    #[serde(deserialize_with = "deserialize_build_requirement_set")]
    environment: BTreeSet<String>,
}

impl<'de> Deserialize<'de> for BuildRequirements {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unchecked = UncheckedBuildRequirements::deserialize(deserializer)?;
        Ok(Self {
            executables: unchecked.executables,
            read_inputs: unchecked.read_inputs,
            environment: unchecked.environment,
        })
    }
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
    #[serde(
        default,
        rename = "reviewer-policies",
        deserialize_with = "deserialize_catalog_reviewer_policies"
    )]
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
    #[serde(
        rename = "rule-sets",
        deserialize_with = "deserialize_catalog_reviewer_rule_sets"
    )]
    pub rule_sets: BTreeSet<String>,
}

fn deserialize_target_support_entries<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<TargetSupport>>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(
        deserializer,
        MAX_TARGET_PREDICATE_PARTITIONS,
        "target-support entries",
    )
    .map(Some)
}

fn deserialize_catalog_capabilities<'de, D>(
    deserializer: D,
) -> Result<Vec<CapabilitySpec>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(deserializer, MAX_CATALOG_OWNERS, "catalog capabilities")
}

fn deserialize_catalog_components<'de, D>(deserializer: D) -> Result<Vec<ComponentSpec>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(deserializer, MAX_CATALOG_OWNERS, "catalog components")
}

fn deserialize_catalog_runtime_adapters<'de, D>(
    deserializer: D,
) -> Result<Vec<RuntimeAdapterSpec>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(deserializer, MAX_CATALOG_OWNERS, "catalog runtime adapters")
}

fn deserialize_catalog_host_boundaries<'de, D>(
    deserializer: D,
) -> Result<Vec<HostBoundarySpec>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(deserializer, MAX_CATALOG_OWNERS, "catalog host boundaries")
}

fn deserialize_build_requirement_set<'de, D>(deserializer: D) -> Result<BTreeSet<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_unique_bounded_set(
        deserializer,
        MAX_BUILD_REQUIREMENT_ENTRIES_PER_KIND,
        "build requirements",
    )
}

fn deserialize_shared_host_config_fields<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(
        deserializer,
        MAX_SHARED_HOST_CONFIG_FIELDS,
        "shared-host config fields",
    )
}

fn deserialize_catalog_reviewer_policies<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, CatalogReviewerPolicy>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_unique_bounded_map(
        deserializer,
        MAX_CATALOG_OWNERS,
        "catalog reviewer policies",
    )
}

fn deserialize_catalog_reviewer_rule_sets<'de, D>(
    deserializer: D,
) -> Result<BTreeSet<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_unique_bounded_set(
        deserializer,
        MAX_CATALOG_REVIEWER_RULE_SETS,
        "catalog reviewer rule sets",
    )
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

    #[test]
    fn schema_counted_metadata_collections_are_bounded_during_deserialization() {
        let reviewer_policies = (0..=MAX_CATALOG_OWNERS)
            .map(|index| {
                (
                    format!("reviewer-{index}"),
                    serde_json::json!({
                        "evidence-schema": 1,
                        "rule-sets": ["rule-v1"],
                    }),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        let excessive_policy = serde_json::json!({
            "schema": 1,
            "reviewer-policies": reviewer_policies,
        });
        let error = serde_json::from_value::<CatalogTrustPolicy>(excessive_policy).unwrap_err();
        assert!(error.to_string().contains("catalog reviewer policies"));

        let duplicate_rule_set = r#"{
            "schema": 1,
            "reviewer-policies": {
                "reviewer": {"evidence-schema": 1, "rule-sets": ["rule-v1", "rule-v1"]}
            }
        }"#;
        let error = serde_json::from_str::<CatalogTrustPolicy>(duplicate_rule_set).unwrap_err();
        assert!(error.to_string().contains("duplicate entry"));

        let excessive_host_fields = serde_json::json!({
            "mode": "concurrent-shared-host-handle",
            "evidence": {
                "source": "evidence.toml",
                "algorithm": "sha256",
                "digest": "00",
                "reviewer-policy": "reviewer",
            },
            "host-config-fields": (0..=MAX_SHARED_HOST_CONFIG_FIELDS)
                .map(|index| format!("field-{index}"))
                .collect::<Vec<_>>(),
        });
        let error = serde_json::from_value::<AppCoexistence>(excessive_host_fields).unwrap_err();
        assert!(error.to_string().contains("shared-host config fields"));
    }

    #[test]
    fn build_requirement_collections_close_the_direct_serde_boundary() {
        let requirements = (0..MAX_BUILD_REQUIREMENT_ENTRIES_PER_KIND)
            .map(|index| format!("requirement-{index:05}"))
            .collect::<Vec<_>>();
        let exact = serde_json::json!({
            "executables": requirements,
            "read-inputs": [],
            "environment": [],
        });
        serde_json::from_value::<BuildRequirements>(exact.clone()).unwrap();

        let mut excessive = exact;
        excessive["executables"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::Value::String("one-too-many".into()));
        let error = serde_json::from_value::<BuildRequirements>(excessive).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("build requirements has more than")
        );
    }
}
