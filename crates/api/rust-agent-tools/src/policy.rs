use std::{fmt, sync::Arc};

use rust_agent_core::SecurityEffects;
use serde_json::Value as JsonValue;

pub const MAX_TOOL_POLICY_RULES: usize = 64;
pub const MAX_TOOL_RULE_PREDICATES: usize = 16;
pub const MAX_TOOL_POLICY_BYTES: usize = 64 * 1024;
pub const MAX_TOOL_POLICY_EVALUATOR_STEPS: usize = 1_024;
pub const MAX_TOOL_JSON_POINTER_BYTES: usize = 256;
pub const MAX_TOOL_JSON_POINTER_DEPTH: usize = 16;
pub const MAX_TOOL_SCALAR_BYTES: usize = 1_024;
pub const MAX_TOOL_EXCLUSIVE_KEY_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ToolSafety {
    ReadOnly,
    Mutating,
    Sensitive,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JsonKind {
    Null,
    Boolean,
    Number,
    String,
    Array,
    Object,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BoundedJsonPointer {
    value: Arc<str>,
    depth: usize,
}

impl BoundedJsonPointer {
    pub fn new(value: impl Into<String>) -> Result<Self, ToolPolicyBuildError> {
        let value = value.into();
        if value.len() > MAX_TOOL_JSON_POINTER_BYTES {
            return Err(ToolPolicyBuildError::JsonPointerTooLong);
        }
        let depth = validate_json_pointer(&value)?;
        if depth > MAX_TOOL_JSON_POINTER_DEPTH {
            return Err(ToolPolicyBuildError::JsonPointerTooDeep);
        }
        Ok(Self {
            value: Arc::from(value),
            depth,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }

    pub const fn depth(&self) -> usize {
        self.depth
    }

    const fn evaluator_steps(&self) -> usize {
        self.depth + 1
    }

    fn canonical_bytes(&self) -> usize {
        self.value.len() + 1
    }
}

fn validate_json_pointer(value: &str) -> Result<usize, ToolPolicyBuildError> {
    if value.is_empty() {
        return Ok(0);
    }
    if !value.starts_with('/') {
        return Err(ToolPolicyBuildError::InvalidJsonPointer);
    }
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'~' {
            let Some(escaped) = bytes.get(index + 1) else {
                return Err(ToolPolicyBuildError::InvalidJsonPointer);
            };
            if !matches!(escaped, b'0' | b'1') {
                return Err(ToolPolicyBuildError::InvalidJsonPointer);
            }
            index += 2;
        } else {
            index += 1;
        }
    }
    Ok(value.bytes().filter(|byte| *byte == b'/').count())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedJsonScalar {
    value: JsonValue,
    canonical_bytes: usize,
}

impl BoundedJsonScalar {
    pub fn null() -> Self {
        Self {
            value: JsonValue::Null,
            canonical_bytes: 4,
        }
    }

    pub fn boolean(value: bool) -> Self {
        Self {
            value: JsonValue::Bool(value),
            canonical_bytes: if value { 4 } else { 5 },
        }
    }

    pub fn signed(value: i64) -> Self {
        let value = JsonValue::from(value);
        let canonical_bytes = value.to_string().len();
        Self {
            value,
            canonical_bytes,
        }
    }

    pub fn unsigned(value: u64) -> Self {
        let value = JsonValue::from(value);
        let canonical_bytes = value.to_string().len();
        Self {
            value,
            canonical_bytes,
        }
    }

    pub fn string(value: impl Into<String>) -> Result<Self, ToolPolicyBuildError> {
        Self::try_from_json(JsonValue::String(value.into()))
    }

    pub fn try_from_json(value: JsonValue) -> Result<Self, ToolPolicyBuildError> {
        if !matches!(
            value,
            JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) | JsonValue::String(_)
        ) {
            return Err(ToolPolicyBuildError::NonScalarValue);
        }
        let canonical_bytes = serde_json::to_vec(&value)
            .map_err(|_| ToolPolicyBuildError::NonScalarValue)?
            .len();
        if canonical_bytes > MAX_TOOL_SCALAR_BYTES {
            return Err(ToolPolicyBuildError::ScalarTooLarge);
        }
        Ok(Self {
            value,
            canonical_bytes,
        })
    }

    pub fn as_json(&self) -> &JsonValue {
        &self.value
    }

    const fn canonical_bytes(&self) -> usize {
        self.canonical_bytes
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BoundedKey(Arc<str>);

impl BoundedKey {
    pub fn new(value: impl Into<String>) -> Result<Self, ToolPolicyBuildError> {
        let value = value.into();
        if value.is_empty()
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(ToolPolicyBuildError::InvalidExclusiveKey);
        }
        if value.len() > MAX_TOOL_EXCLUSIVE_KEY_BYTES {
            return Err(ToolPolicyBuildError::ExclusiveKeyTooLong);
        }
        Ok(Self(Arc::from(value)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn canonical_bytes(&self) -> usize {
        self.0.len() + 1
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ToolArgumentPredicate {
    Present {
        pointer: BoundedJsonPointer,
    },
    TypeIs {
        pointer: BoundedJsonPointer,
        kind: JsonKind,
    },
    ScalarEquals {
        pointer: BoundedJsonPointer,
        value: BoundedJsonScalar,
    },
}

impl ToolArgumentPredicate {
    fn canonical_bytes(&self) -> usize {
        match self {
            Self::Present { pointer } => 1 + pointer.canonical_bytes(),
            Self::TypeIs { pointer, .. } => 2 + pointer.canonical_bytes(),
            Self::ScalarEquals { pointer, value } => {
                2 + pointer.canonical_bytes() + value.canonical_bytes()
            }
        }
    }

    const fn evaluator_steps(&self) -> usize {
        match self {
            Self::Present { pointer }
            | Self::TypeIs { pointer, .. }
            | Self::ScalarEquals { pointer, .. } => pointer.evaluator_steps() + 1,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ToolConcurrencyRule {
    Exclusive,
    ParallelSafe,
    ExclusiveByScalar {
        prefix: BoundedKey,
        pointer: BoundedJsonPointer,
    },
}

impl ToolConcurrencyRule {
    fn canonical_bytes(&self) -> usize {
        match self {
            Self::Exclusive | Self::ParallelSafe => 1,
            Self::ExclusiveByScalar { prefix, pointer } => {
                1 + prefix.canonical_bytes() + pointer.canonical_bytes()
            }
        }
    }

    const fn evaluator_steps(&self) -> usize {
        match self {
            Self::Exclusive | Self::ParallelSafe => 1,
            Self::ExclusiveByScalar { pointer, .. } => pointer.evaluator_steps() + 1,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolRiskRule {
    all: Arc<[ToolArgumentPredicate]>,
    raise_to: ToolSafety,
    add_effects: SecurityEffects,
    canonical_bytes: usize,
    evaluator_steps: usize,
}

impl ToolRiskRule {
    pub fn builder(raise_to: ToolSafety, add_effects: SecurityEffects) -> ToolRiskRuleBuilder {
        ToolRiskRuleBuilder {
            all: Vec::new(),
            raise_to,
            add_effects,
            canonical_bytes: 10,
            evaluator_steps: 1,
        }
    }

    pub fn predicates(&self) -> &[ToolArgumentPredicate] {
        &self.all
    }

    pub const fn raise_to(&self) -> ToolSafety {
        self.raise_to
    }

    pub const fn add_effects(&self) -> SecurityEffects {
        self.add_effects
    }

    fn validate_bounded(&self) -> Result<(), ToolPolicyBuildError> {
        if self.all.len() > MAX_TOOL_RULE_PREDICATES {
            return Err(ToolPolicyBuildError::TooManyPredicates);
        }
        let (bytes, steps) = self
            .all
            .iter()
            .try_fold((10_usize, 1_usize), |state, item| {
                let bytes = state
                    .0
                    .checked_add(item.canonical_bytes())
                    .ok_or(ToolPolicyBuildError::CanonicalBytesExceeded)?;
                let steps = state
                    .1
                    .checked_add(item.evaluator_steps())
                    .ok_or(ToolPolicyBuildError::EvaluatorStepsExceeded)?;
                Ok::<_, ToolPolicyBuildError>((bytes, steps))
            })?;
        if bytes != self.canonical_bytes || bytes > MAX_TOOL_POLICY_BYTES {
            return Err(ToolPolicyBuildError::CanonicalBytesExceeded);
        }
        if steps != self.evaluator_steps || steps > MAX_TOOL_POLICY_EVALUATOR_STEPS {
            return Err(ToolPolicyBuildError::EvaluatorStepsExceeded);
        }
        if effects_require_mutating(self.add_effects) && self.raise_to < ToolSafety::Mutating {
            return Err(ToolPolicyBuildError::SafetyNotMonotonic);
        }
        Ok(())
    }
}

pub(crate) fn effects_require_mutating(effects: SecurityEffects) -> bool {
    let mut effect_floor = SecurityEffects::WRITE_LOCAL;
    effect_floor |= SecurityEffects::NETWORK;
    effect_floor |= SecurityEffects::PROCESS_EXEC;
    effect_floor |= SecurityEffects::REMOTE_EXEC;
    effect_floor |= SecurityEffects::SECRET_ACCESS;
    effect_floor |= SecurityEffects::CODE_EXEC;
    effect_floor |= SecurityEffects::MCP_CONNECT;
    effects.bits() & effect_floor.bits() != 0
}

#[derive(Debug)]
pub struct ToolRiskRuleBuilder {
    all: Vec<ToolArgumentPredicate>,
    raise_to: ToolSafety,
    add_effects: SecurityEffects,
    canonical_bytes: usize,
    evaluator_steps: usize,
}

impl ToolRiskRuleBuilder {
    pub fn try_push_predicate(
        &mut self,
        predicate: ToolArgumentPredicate,
    ) -> Result<(), ToolPolicyBuildError> {
        if self.all.len() == MAX_TOOL_RULE_PREDICATES {
            return Err(ToolPolicyBuildError::TooManyPredicates);
        }
        let canonical_bytes = self
            .canonical_bytes
            .checked_add(predicate.canonical_bytes())
            .ok_or(ToolPolicyBuildError::CanonicalBytesExceeded)?;
        if canonical_bytes > MAX_TOOL_POLICY_BYTES {
            return Err(ToolPolicyBuildError::CanonicalBytesExceeded);
        }
        let evaluator_steps = self
            .evaluator_steps
            .checked_add(predicate.evaluator_steps())
            .ok_or(ToolPolicyBuildError::EvaluatorStepsExceeded)?;
        if evaluator_steps > MAX_TOOL_POLICY_EVALUATOR_STEPS {
            return Err(ToolPolicyBuildError::EvaluatorStepsExceeded);
        }
        self.all.push(predicate);
        self.canonical_bytes = canonical_bytes;
        self.evaluator_steps = evaluator_steps;
        Ok(())
    }

    pub fn build(self) -> Result<ToolRiskRule, ToolPolicyBuildError> {
        let rule = ToolRiskRule {
            all: self.all.into(),
            raise_to: self.raise_to,
            add_effects: self.add_effects,
            canonical_bytes: self.canonical_bytes,
            evaluator_steps: self.evaluator_steps,
        };
        rule.validate_bounded()?;
        Ok(rule)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolCallPolicy {
    rules: Arc<[ToolRiskRule]>,
    concurrency: ToolConcurrencyRule,
    canonical_bytes: usize,
    evaluator_steps: usize,
}

impl ToolCallPolicy {
    pub fn builder(concurrency: ToolConcurrencyRule) -> ToolCallPolicyBuilder {
        ToolCallPolicyBuilder {
            canonical_bytes: concurrency.canonical_bytes(),
            evaluator_steps: concurrency.evaluator_steps(),
            concurrency,
            rules: Vec::new(),
        }
    }

    pub fn rules(&self) -> &[ToolRiskRule] {
        &self.rules
    }

    pub const fn concurrency(&self) -> &ToolConcurrencyRule {
        &self.concurrency
    }

    pub(crate) fn validate_bounded(
        &self,
        static_safety: ToolSafety,
    ) -> Result<(), ToolPolicyBuildError> {
        if self.rules.len() > MAX_TOOL_POLICY_RULES {
            return Err(ToolPolicyBuildError::TooManyRules);
        }
        let mut bytes = self.concurrency.canonical_bytes();
        let mut steps = self.concurrency.evaluator_steps();
        for rule in self.rules.iter() {
            rule.validate_bounded()?;
            if rule.raise_to < static_safety {
                return Err(ToolPolicyBuildError::SafetyNotMonotonic);
            }
            bytes = bytes
                .checked_add(rule.canonical_bytes)
                .ok_or(ToolPolicyBuildError::CanonicalBytesExceeded)?;
            steps = steps
                .checked_add(rule.evaluator_steps)
                .ok_or(ToolPolicyBuildError::EvaluatorStepsExceeded)?;
        }
        if bytes != self.canonical_bytes || bytes > MAX_TOOL_POLICY_BYTES {
            return Err(ToolPolicyBuildError::CanonicalBytesExceeded);
        }
        if steps != self.evaluator_steps || steps > MAX_TOOL_POLICY_EVALUATOR_STEPS {
            return Err(ToolPolicyBuildError::EvaluatorStepsExceeded);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct ToolCallPolicyBuilder {
    rules: Vec<ToolRiskRule>,
    concurrency: ToolConcurrencyRule,
    canonical_bytes: usize,
    evaluator_steps: usize,
}

impl ToolCallPolicyBuilder {
    pub fn try_push_rule(&mut self, rule: ToolRiskRule) -> Result<(), ToolPolicyBuildError> {
        rule.validate_bounded()?;
        if self.rules.len() == MAX_TOOL_POLICY_RULES {
            return Err(ToolPolicyBuildError::TooManyRules);
        }
        let canonical_bytes = self
            .canonical_bytes
            .checked_add(rule.canonical_bytes)
            .ok_or(ToolPolicyBuildError::CanonicalBytesExceeded)?;
        if canonical_bytes > MAX_TOOL_POLICY_BYTES {
            return Err(ToolPolicyBuildError::CanonicalBytesExceeded);
        }
        let evaluator_steps = self
            .evaluator_steps
            .checked_add(rule.evaluator_steps)
            .ok_or(ToolPolicyBuildError::EvaluatorStepsExceeded)?;
        if evaluator_steps > MAX_TOOL_POLICY_EVALUATOR_STEPS {
            return Err(ToolPolicyBuildError::EvaluatorStepsExceeded);
        }
        self.rules.push(rule);
        self.canonical_bytes = canonical_bytes;
        self.evaluator_steps = evaluator_steps;
        Ok(())
    }

    pub fn build(self) -> Result<ToolCallPolicy, ToolPolicyBuildError> {
        let policy = ToolCallPolicy {
            rules: self.rules.into(),
            concurrency: self.concurrency,
            canonical_bytes: self.canonical_bytes,
            evaluator_steps: self.evaluator_steps,
        };
        policy.validate_bounded(ToolSafety::ReadOnly)?;
        Ok(policy)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolPolicyBuildError {
    InvalidJsonPointer,
    JsonPointerTooLong,
    JsonPointerTooDeep,
    NonScalarValue,
    ScalarTooLarge,
    InvalidExclusiveKey,
    ExclusiveKeyTooLong,
    TooManyPredicates,
    TooManyRules,
    CanonicalBytesExceeded,
    EvaluatorStepsExceeded,
    SafetyNotMonotonic,
}

impl fmt::Display for ToolPolicyBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidJsonPointer => "invalid JSON pointer",
            Self::JsonPointerTooLong => "JSON pointer exceeds its byte bound",
            Self::JsonPointerTooDeep => "JSON pointer exceeds its depth bound",
            Self::NonScalarValue => "tool policy value is not a JSON scalar",
            Self::ScalarTooLarge => "tool policy scalar exceeds its byte bound",
            Self::InvalidExclusiveKey => "invalid tool exclusive-key prefix",
            Self::ExclusiveKeyTooLong => "tool exclusive-key prefix exceeds its byte bound",
            Self::TooManyPredicates => "tool risk rule has too many predicates",
            Self::TooManyRules => "tool call policy has too many rules",
            Self::CanonicalBytesExceeded => "tool policy exceeds its canonical byte bound",
            Self::EvaluatorStepsExceeded => "tool policy exceeds its evaluator step bound",
            Self::SafetyNotMonotonic => "tool policy rule lowers the static safety floor",
        })
    }
}

impl std::error::Error for ToolPolicyBuildError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn present(pointer: &str) -> ToolArgumentPredicate {
        ToolArgumentPredicate::Present {
            pointer: BoundedJsonPointer::new(pointer).unwrap(),
        }
    }

    fn rule_with(predicate: ToolArgumentPredicate) -> ToolRiskRule {
        let mut builder = ToolRiskRule::builder(ToolSafety::Sensitive, SecurityEffects::NETWORK);
        builder.try_push_predicate(predicate).unwrap();
        builder.build().unwrap()
    }

    #[test]
    fn valid_policy_preserves_canonical_rule_and_predicate_order() {
        let mut first = ToolRiskRule::builder(ToolSafety::Mutating, SecurityEffects::WRITE_LOCAL);
        first.try_push_predicate(present("/path")).unwrap();
        first
            .try_push_predicate(ToolArgumentPredicate::TypeIs {
                pointer: BoundedJsonPointer::new("/path").unwrap(),
                kind: JsonKind::String,
            })
            .unwrap();
        let first = first.build().unwrap();
        let second = rule_with(ToolArgumentPredicate::ScalarEquals {
            pointer: BoundedJsonPointer::new("/mode").unwrap(),
            value: BoundedJsonScalar::string("force").unwrap(),
        });
        let mut builder = ToolCallPolicy::builder(ToolConcurrencyRule::Exclusive);
        builder.try_push_rule(first).unwrap();
        builder.try_push_rule(second).unwrap();
        let policy = builder.build().unwrap();

        assert_eq!(policy.rules().len(), 2);
        assert!(matches!(
            policy.rules()[0].predicates(),
            [
                ToolArgumentPredicate::Present { .. },
                ToolArgumentPredicate::TypeIs { .. }
            ]
        ));
        assert!(matches!(
            policy.rules()[1].predicates(),
            [ToolArgumentPredicate::ScalarEquals { .. }]
        ));
    }

    #[test]
    fn predicate_count_is_rejected_before_the_candidate_is_retained() {
        let mut builder = ToolRiskRule::builder(ToolSafety::Unknown, SecurityEffects::empty());
        for _ in 0..MAX_TOOL_RULE_PREDICATES {
            builder.try_push_predicate(present("/a")).unwrap();
        }
        assert_eq!(
            builder.try_push_predicate(present("/rejected")),
            Err(ToolPolicyBuildError::TooManyPredicates)
        );
        let rule = builder.build().unwrap();
        assert_eq!(rule.predicates().len(), MAX_TOOL_RULE_PREDICATES);
        assert!(rule.predicates().iter().all(|predicate| {
            matches!(predicate, ToolArgumentPredicate::Present { pointer } if pointer.as_str() == "/a")
        }));
    }

    #[test]
    fn rule_count_is_rejected_before_the_candidate_is_retained() {
        let mut builder = ToolCallPolicy::builder(ToolConcurrencyRule::Exclusive);
        for _ in 0..MAX_TOOL_POLICY_RULES {
            builder
                .try_push_rule(rule_with(present("/accepted")))
                .unwrap();
        }
        assert_eq!(
            builder.try_push_rule(rule_with(present("/rejected"))),
            Err(ToolPolicyBuildError::TooManyRules)
        );
        let policy = builder.build().unwrap();
        assert_eq!(policy.rules().len(), MAX_TOOL_POLICY_RULES);
    }

    #[test]
    fn pointer_scalar_key_and_evaluator_bounds_fail_closed() {
        assert_eq!(
            BoundedJsonPointer::new("not-a-pointer"),
            Err(ToolPolicyBuildError::InvalidJsonPointer)
        );
        assert_eq!(
            BoundedJsonPointer::new(format!("/{}", "a".repeat(MAX_TOOL_JSON_POINTER_BYTES))),
            Err(ToolPolicyBuildError::JsonPointerTooLong)
        );
        assert_eq!(
            BoundedJsonPointer::new(format!(
                "/{}",
                vec!["a"; MAX_TOOL_JSON_POINTER_DEPTH + 1].join("/")
            )),
            Err(ToolPolicyBuildError::JsonPointerTooDeep)
        );
        assert_eq!(
            BoundedJsonScalar::string("x".repeat(MAX_TOOL_SCALAR_BYTES)),
            Err(ToolPolicyBuildError::ScalarTooLarge)
        );
        assert_eq!(
            BoundedKey::new("x".repeat(MAX_TOOL_EXCLUSIVE_KEY_BYTES + 1)),
            Err(ToolPolicyBuildError::ExclusiveKeyTooLong)
        );

        let deep = format!("/{}", vec!["a"; MAX_TOOL_JSON_POINTER_DEPTH].join("/"));
        let mut policy = ToolCallPolicy::builder(ToolConcurrencyRule::Exclusive);
        let mut rejected = false;
        for _ in 0..MAX_TOOL_POLICY_RULES {
            let mut rule = ToolRiskRule::builder(ToolSafety::Unknown, SecurityEffects::empty());
            for _ in 0..MAX_TOOL_RULE_PREDICATES {
                rule.try_push_predicate(present(&deep)).unwrap();
            }
            match policy.try_push_rule(rule.build().unwrap()) {
                Ok(()) => {}
                Err(ToolPolicyBuildError::EvaluatorStepsExceeded) => {
                    rejected = true;
                    break;
                }
                Err(error) => panic!("unexpected error: {error}"),
            }
        }
        assert!(rejected);
        assert!(policy.build().is_ok());
    }

    #[test]
    fn canonical_byte_limit_rejects_before_retaining_the_candidate_rule() {
        let scalar = BoundedJsonScalar::string("x".repeat(MAX_TOOL_SCALAR_BYTES - 2)).unwrap();
        let large_rule = || {
            rule_with(ToolArgumentPredicate::ScalarEquals {
                pointer: BoundedJsonPointer::new("").unwrap(),
                value: scalar.clone(),
            })
        };
        let mut builder = ToolCallPolicy::builder(ToolConcurrencyRule::Exclusive);
        let mut accepted = 0;
        loop {
            match builder.try_push_rule(large_rule()) {
                Ok(()) => accepted += 1,
                Err(ToolPolicyBuildError::CanonicalBytesExceeded) => break,
                Err(error) => panic!("unexpected error: {error}"),
            }
        }
        let policy = builder.build().unwrap();
        assert_eq!(policy.rules().len(), accepted);
        assert!(accepted < MAX_TOOL_POLICY_RULES);
    }

    #[test]
    fn registration_revalidation_rejects_a_rule_below_the_static_floor() {
        let mut rule = ToolRiskRule::builder(ToolSafety::ReadOnly, SecurityEffects::empty());
        rule.try_push_predicate(present("/dry_run")).unwrap();
        let mut builder = ToolCallPolicy::builder(ToolConcurrencyRule::Exclusive);
        builder.try_push_rule(rule.build().unwrap()).unwrap();
        let policy = builder.build().unwrap();
        assert_eq!(
            policy.validate_bounded(ToolSafety::Mutating),
            Err(ToolPolicyBuildError::SafetyNotMonotonic)
        );

        let effectful = ToolRiskRule::builder(ToolSafety::ReadOnly, SecurityEffects::NETWORK);
        assert_eq!(
            effectful.build(),
            Err(ToolPolicyBuildError::SafetyNotMonotonic)
        );
    }
}
