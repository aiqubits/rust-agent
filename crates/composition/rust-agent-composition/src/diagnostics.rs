use serde::{Deserialize, Deserializer, Serialize};

use crate::{metadata::MAX_CATALOG_OWNERS, serde_bounds::deserialize_bounded_vec};

pub const MAX_DIAGNOSTIC_REASONS: usize = MAX_CATALOG_OWNERS;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Diagnostic {
    pub component: String,
    pub conclusion: String,
    pub reasons: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedDiagnostic {
    component: String,
    conclusion: String,
    #[serde(deserialize_with = "deserialize_diagnostic_reasons")]
    reasons: Vec<String>,
}

impl<'de> Deserialize<'de> for Diagnostic {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unchecked = UncheckedDiagnostic::deserialize(deserializer)?;
        Ok(Self {
            component: unchecked.component,
            conclusion: unchecked.conclusion,
            reasons: unchecked.reasons,
        })
    }
}

fn deserialize_diagnostic_reasons<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(deserializer, MAX_DIAGNOSTIC_REASONS, "diagnostic reasons")
}

impl Diagnostic {
    pub fn selected(component: impl Into<String>, reasons: Vec<String>) -> Self {
        Self {
            component: component.into(),
            conclusion: "selected".into(),
            reasons,
        }
    }

    pub fn excluded(component: impl Into<String>, reasons: Vec<String>) -> Self {
        Self {
            component: component.into(),
            conclusion: "excluded".into(),
            reasons,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_reasons_are_bounded_during_deserialization() {
        let exact = serde_json::json!({
            "component": "fixture",
            "conclusion": "selected",
            "reasons": (0..MAX_DIAGNOSTIC_REASONS)
                .map(|index| format!("reason-{index:03}"))
                .collect::<Vec<_>>(),
        });
        serde_json::from_value::<Diagnostic>(exact.clone()).unwrap();

        let mut excessive = exact;
        excessive["reasons"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::Value::String("one-too-many".into()));
        let error = serde_json::from_value::<Diagnostic>(excessive).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("diagnostic reasons has more than")
        );
    }
}
