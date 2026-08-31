use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{metadata::SupportTier, target::Environment};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
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

impl CompositionProfile {
    pub fn from_toml(input: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(input)
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
