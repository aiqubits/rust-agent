use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    process::Command,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::canonical;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Environment {
    Browser,
    Server,
    Desktop,
    Mobile,
}

impl Environment {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Browser => "browser",
            Self::Server => "server",
            Self::Desktop => "desktop",
            Self::Mobile => "mobile",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub triple: String,
    pub environment: Environment,
    pub facts: BTreeMap<String, BTreeSet<Option<String>>>,
    #[serde(rename = "target-fact-digest")]
    pub target_fact_digest: String,
    #[serde(default, rename = "custom-target-spec-digest")]
    pub custom_target_spec_digest: Option<String>,
}

#[derive(Debug, Error)]
pub enum TargetError {
    #[error("rustc path must be explicit and absolute: {0}")]
    RustcPathNotAbsolute(String),
    #[error("failed to execute rustc target-fact query: {0}")]
    RustcIo(#[from] std::io::Error),
    #[error("rustc target-fact query failed: {0}")]
    RustcFailed(String),
    #[error("invalid rustc cfg line: {0}")]
    InvalidFact(String),
    #[error("invalid target predicate: {0}")]
    InvalidPredicate(String),
    #[error("canonical target-fact encoding failed: {0}")]
    Canonical(#[from] canonical::CanonicalError),
}

impl Target {
    pub fn query(
        rustc: &Path,
        triple: impl Into<String>,
        environment: Environment,
    ) -> Result<Self, TargetError> {
        if !rustc.is_absolute() {
            return Err(TargetError::RustcPathNotAbsolute(
                rustc.display().to_string(),
            ));
        }
        let triple = triple.into();
        let output = Command::new(rustc)
            .args(["--print", "cfg", "--target", &triple])
            .env_clear()
            .env("PATH", rustc.parent().unwrap_or_else(|| Path::new("/")))
            .output()?;
        if !output.status.success() {
            return Err(TargetError::RustcFailed(
                String::from_utf8_lossy(&output.stderr).into_owned(),
            ));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let facts = parse_facts(&stdout)?;
        Self::from_facts(triple, environment, facts)
    }

    pub fn from_facts(
        triple: impl Into<String>,
        environment: Environment,
        facts: BTreeMap<String, BTreeSet<Option<String>>>,
    ) -> Result<Self, TargetError> {
        let triple = triple.into();
        let payload = (&triple, environment, &facts, Option::<String>::None);
        let digest = canonical::domain_hash(b"rust-agent-target-facts-v1\0", &payload)?;
        Ok(Self {
            triple,
            environment,
            facts,
            target_fact_digest: hex::encode(digest),
            custom_target_spec_digest: None,
        })
    }

    pub fn matches(&self, predicate: &str) -> Result<bool, TargetError> {
        PredicateParser::new(predicate).parse()?.evaluate(self)
    }

    pub fn fact_value(&self, key: &str) -> Option<&str> {
        self.facts
            .get(key)?
            .iter()
            .find_map(|value| value.as_deref())
    }
}

pub fn parse_facts(input: &str) -> Result<BTreeMap<String, BTreeSet<Option<String>>>, TargetError> {
    let mut facts: BTreeMap<String, BTreeSet<Option<String>>> = BTreeMap::new();
    for line in input.lines().filter(|line| !line.trim().is_empty()) {
        let line = line.trim();
        let (key, value) = if let Some((key, raw)) = line.split_once('=') {
            if !(raw.starts_with('"') && raw.ends_with('"') && raw.len() >= 2) {
                return Err(TargetError::InvalidFact(line.to_owned()));
            }
            (key, Some(raw[1..raw.len() - 1].to_owned()))
        } else {
            (line, None)
        };
        if !valid_fact_key(key) {
            return Err(TargetError::InvalidFact(line.to_owned()));
        }
        facts.entry(key.to_owned()).or_default().insert(value);
    }
    Ok(facts)
}

fn valid_fact_key(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Predicate {
    All(Vec<Self>),
    Any(Vec<Self>),
    Not(Box<Self>),
    Equals(String, String),
    Present(String),
}

impl Predicate {
    fn evaluate(&self, target: &Target) -> Result<bool, TargetError> {
        match self {
            Self::All(items) => {
                for item in items {
                    if !item.evaluate(target)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            Self::Any(items) => {
                for item in items {
                    if item.evaluate(target)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Self::Not(item) => Ok(!item.evaluate(target)?),
            Self::Equals(key, value) if key == "environment" => {
                Ok(value == target.environment.as_str())
            }
            Self::Equals(key, value) => Ok(target
                .facts
                .get(key)
                .is_some_and(|values| values.contains(&Some(value.clone())))),
            Self::Present(key) if key == "true" => Ok(true),
            Self::Present(key) if key == "false" => Ok(false),
            Self::Present(key) => Ok(target.facts.contains_key(key)),
        }
    }
}

struct PredicateParser<'a> {
    input: &'a [u8],
    cursor: usize,
}

impl<'a> PredicateParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input: input.as_bytes(),
            cursor: 0,
        }
    }

    fn parse(mut self) -> Result<Predicate, TargetError> {
        self.skip_space();
        let name = self.ident()?;
        if name != "cfg" {
            return Err(self.error("predicate must start with cfg"));
        }
        self.expect(b'(')?;
        let value = self.expression()?;
        self.expect(b')')?;
        self.skip_space();
        if self.cursor != self.input.len() {
            return Err(self.error("trailing predicate input"));
        }
        Ok(value)
    }

    fn expression(&mut self) -> Result<Predicate, TargetError> {
        self.skip_space();
        let name = self.ident()?;
        self.skip_space();
        if self.consume(b'=') {
            let value = self.quoted()?;
            return Ok(Predicate::Equals(name, value));
        }
        if !self.consume(b'(') {
            return Ok(Predicate::Present(name));
        }
        let mut values = Vec::new();
        loop {
            values.push(self.expression()?);
            self.skip_space();
            if self.consume(b')') {
                break;
            }
            self.expect(b',')?;
        }
        match name.as_str() {
            "all" if !values.is_empty() => Ok(Predicate::All(values)),
            "any" if !values.is_empty() => Ok(Predicate::Any(values)),
            "not" if values.len() == 1 => Ok(Predicate::Not(Box::new(values.pop().unwrap()))),
            _ => Err(self.error("unknown predicate function or invalid arity")),
        }
    }

    fn ident(&mut self) -> Result<String, TargetError> {
        self.skip_space();
        let start = self.cursor;
        while self
            .input
            .get(self.cursor)
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
        {
            self.cursor += 1;
        }
        if start == self.cursor {
            return Err(self.error("expected identifier"));
        }
        Ok(String::from_utf8_lossy(&self.input[start..self.cursor]).into_owned())
    }

    fn quoted(&mut self) -> Result<String, TargetError> {
        self.skip_space();
        self.expect(b'"')?;
        let start = self.cursor;
        while let Some(byte) = self.input.get(self.cursor) {
            if *byte == b'"' {
                let result = String::from_utf8_lossy(&self.input[start..self.cursor]).into_owned();
                self.cursor += 1;
                return Ok(result);
            }
            if *byte == b'\\' || !byte.is_ascii() || byte.is_ascii_control() {
                return Err(self.error("predicate strings must be unescaped printable ASCII"));
            }
            self.cursor += 1;
        }
        Err(self.error("unterminated predicate string"))
    }

    fn expect(&mut self, expected: u8) -> Result<(), TargetError> {
        self.skip_space();
        if self.consume(expected) {
            Ok(())
        } else {
            Err(self.error(&format!("expected `{}`", char::from(expected))))
        }
    }

    fn consume(&mut self, expected: u8) -> bool {
        self.skip_space();
        if self.input.get(self.cursor) == Some(&expected) {
            self.cursor += 1;
            true
        } else {
            false
        }
    }

    fn skip_space(&mut self) {
        while self
            .input
            .get(self.cursor)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.cursor += 1;
        }
    }

    fn error(&self, message: &str) -> TargetError {
        TargetError::InvalidPredicate(format!("{message} at byte {}", self.cursor))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linux() -> Target {
        Target::from_facts(
            "x86_64-unknown-linux-gnu",
            Environment::Desktop,
            parse_facts(
                "target_arch=\"x86_64\"\ntarget_os=\"linux\"\ntarget_family=\"unix\"\nunix\n",
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn facts_are_sorted_and_digest_is_stable() {
        let first = linux();
        let second = linux();
        assert_eq!(first.target_fact_digest, second.target_fact_digest);
        assert_eq!(first.fact_value("target_os"), Some("linux"));
    }

    #[test]
    fn closed_predicate_language_separates_environment() {
        let target = linux();
        assert!(
            target
                .matches("cfg(all(target_os = \"linux\", environment = \"desktop\"))")
                .unwrap()
        );
        assert!(
            !target
                .matches("cfg(any(target_os = \"windows\", environment = \"browser\"))")
                .unwrap()
        );
        assert!(
            target
                .matches("cfg(not(target_arch = \"wasm32\"))")
                .unwrap()
        );
        assert!(target.matches("cfg(unix)").unwrap());
        assert!(target.matches("target_os = \"linux\"").is_err());
        assert!(target.matches("cfg(unknown())").is_err());
    }

    #[test]
    fn malformed_facts_fail_closed() {
        assert!(parse_facts("Target=\"linux\"").is_err());
        assert!(parse_facts("target_os=linux").is_err());
    }
}
