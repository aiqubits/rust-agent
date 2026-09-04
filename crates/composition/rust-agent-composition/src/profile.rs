use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Deserializer, Serialize, de};

use crate::{
    metadata::SupportTier,
    serde_bounds::{deserialize_unique_bounded_map, deserialize_unique_bounded_set},
    target::Environment,
};

pub const MAX_PROFILE_DOCUMENT_BYTES: usize = 256 * 1024;
pub const MAX_PROFILE_SELECTION_ENTRIES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProfileResourceBoundsError {
    SelectionCountOverflow,
    TooManySelections { actual: usize, maximum: usize },
}

impl fmt::Display for ProfileResourceBoundsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelectionCountOverflow => {
                formatter.write_str("profile selection count overflowed")
            }
            Self::TooManySelections { actual, maximum } => write!(
                formatter,
                "profile has {actual} selections; maximum is {maximum}"
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CompositionProfile {
    pub schema: u32,
    pub name: String,
    #[serde(rename = "build-kind")]
    pub build_kind: BuildKind,
    pub target: String,
    pub environment: Environment,
    #[serde(rename = "support-tier")]
    pub support_tier: SupportTier,
    #[serde(rename = "runtime-adapter")]
    pub runtime_adapter: String,
    #[serde(default, rename = "host-boundary")]
    pub host_boundary: Option<String>,
    pub components: BTreeMap<String, ComponentChoice>,
    #[serde(default, rename = "bindings")]
    pub bindings: BTreeMap<String, String>,
    #[serde(default, rename = "preferred-providers")]
    pub preferred_providers: BTreeMap<String, String>,
    #[serde(default, rename = "denied-effects")]
    pub denied_effects: BTreeSet<String>,
    #[serde(
        default = "default_decision_budget",
        rename = "resolver-decision-budget"
    )]
    pub resolver_decision_budget: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedCompositionProfile {
    schema: u32,
    name: String,
    #[serde(rename = "build-kind")]
    build_kind: BuildKind,
    target: String,
    environment: Environment,
    #[serde(rename = "support-tier")]
    support_tier: SupportTier,
    #[serde(rename = "runtime-adapter")]
    runtime_adapter: String,
    #[serde(default, rename = "host-boundary")]
    host_boundary: Option<String>,
    #[serde(deserialize_with = "deserialize_profile_components")]
    components: BTreeMap<String, ComponentChoice>,
    #[serde(
        default,
        rename = "bindings",
        deserialize_with = "deserialize_profile_string_map"
    )]
    bindings: BTreeMap<String, String>,
    #[serde(
        default,
        rename = "preferred-providers",
        deserialize_with = "deserialize_profile_string_map"
    )]
    preferred_providers: BTreeMap<String, String>,
    #[serde(
        default,
        rename = "denied-effects",
        deserialize_with = "deserialize_profile_denied_effects"
    )]
    denied_effects: BTreeSet<String>,
    #[serde(
        default = "default_decision_budget",
        rename = "resolver-decision-budget"
    )]
    resolver_decision_budget: u32,
}

fn deserialize_profile_components<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, ComponentChoice>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_unique_bounded_map(
        deserializer,
        MAX_PROFILE_SELECTION_ENTRIES,
        "profile components",
    )
}

fn deserialize_profile_string_map<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_unique_bounded_map(
        deserializer,
        MAX_PROFILE_SELECTION_ENTRIES,
        "profile selections",
    )
}

fn deserialize_profile_denied_effects<'de, D>(deserializer: D) -> Result<BTreeSet<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_unique_bounded_set(
        deserializer,
        MAX_PROFILE_SELECTION_ENTRIES,
        "profile denied effects",
    )
}

impl<'de> Deserialize<'de> for CompositionProfile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unchecked = UncheckedCompositionProfile::deserialize(deserializer)?;
        let profile = Self {
            schema: unchecked.schema,
            name: unchecked.name,
            build_kind: unchecked.build_kind,
            target: unchecked.target,
            environment: unchecked.environment,
            support_tier: unchecked.support_tier,
            runtime_adapter: unchecked.runtime_adapter,
            host_boundary: unchecked.host_boundary,
            components: unchecked.components,
            bindings: unchecked.bindings,
            preferred_providers: unchecked.preferred_providers,
            denied_effects: unchecked.denied_effects,
            resolver_decision_budget: unchecked.resolver_decision_budget,
        };
        profile
            .validate_resource_bounds()
            .map_err(de::Error::custom)?;
        Ok(profile)
    }
}

impl CompositionProfile {
    pub fn from_toml(input: &str) -> Result<Self, toml::de::Error> {
        if input.len() > MAX_PROFILE_DOCUMENT_BYTES {
            return Err(<toml::de::Error as de::Error>::custom(format!(
                "profile document has {} bytes; maximum is {MAX_PROFILE_DOCUMENT_BYTES}",
                input.len()
            )));
        }
        toml::from_str(input)
    }

    pub(crate) fn validate_resource_bounds(&self) -> Result<(), ProfileResourceBoundsError> {
        let selection_count = self
            .components
            .len()
            .checked_add(self.bindings.len())
            .and_then(|count| count.checked_add(self.preferred_providers.len()))
            .and_then(|count| count.checked_add(self.denied_effects.len()))
            .ok_or(ProfileResourceBoundsError::SelectionCountOverflow)?;
        if selection_count > MAX_PROFILE_SELECTION_ENTRIES {
            return Err(ProfileResourceBoundsError::TooManySelections {
                actual: selection_count,
                maximum: MAX_PROFILE_SELECTION_ENTRIES,
            });
        }
        Ok(())
    }
}

const fn default_decision_budget() -> u32 {
    10_000
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BuildKind {
    Bin,
    Library,
    Wasm,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ComponentChoice {
    Enabled,
    Auto,
    Disabled,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile_with_components(count: usize) -> String {
        let mut input = String::from(
            r#"schema = 1
name = "bounded"
build-kind = "library"
target = "x86_64-unknown-linux-gnu"
environment = "server"
support-tier = "experimental"
runtime-adapter = "runtime-test"

[components]
"#,
        );
        for index in 0..count {
            input.push_str(&format!("component-{index} = \"disabled\"\n"));
        }
        input
    }

    #[test]
    fn profile_document_byte_and_selection_boundaries_are_closed() {
        let prefix = profile_with_components(0);
        let exact_bytes = format!(
            "{prefix}{}",
            " ".repeat(MAX_PROFILE_DOCUMENT_BYTES - prefix.len())
        );
        CompositionProfile::from_toml(&exact_bytes).unwrap();
        let oversized_bytes = format!("{exact_bytes} ");
        assert!(CompositionProfile::from_toml(&oversized_bytes).is_err());

        let maximum_profile =
            CompositionProfile::from_toml(&profile_with_components(MAX_PROFILE_SELECTION_ENTRIES))
                .unwrap();
        assert!(
            CompositionProfile::from_toml(&profile_with_components(
                MAX_PROFILE_SELECTION_ENTRIES + 1,
            ))
            .is_err()
        );
        assert!(
            toml::from_str::<CompositionProfile>(&profile_with_components(
                MAX_PROFILE_SELECTION_ENTRIES + 1,
            ))
            .is_err()
        );

        let mut direct_json = serde_json::to_value(maximum_profile).unwrap();
        direct_json["components"]
            .as_object_mut()
            .unwrap()
            .insert("overflow".into(), serde_json::json!("disabled"));
        assert!(serde_json::from_value::<CompositionProfile>(direct_json).is_err());
    }
}
