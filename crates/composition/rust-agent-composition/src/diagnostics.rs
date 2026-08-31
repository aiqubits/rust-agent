use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Diagnostic {
    pub component: String,
    pub conclusion: String,
    pub reasons: Vec<String>,
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
