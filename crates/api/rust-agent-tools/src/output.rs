use std::{fmt, num::NonZeroUsize, sync::Arc};

use rust_agent_core::Digest;
use serde_json::Value as JsonValue;

pub const MAX_TOOL_OUTPUT_ITEMS: usize = 128;
pub const MAX_TOOL_OUTPUT_BYTES: usize = 256 * 1024;
pub const MAX_TOOL_OUTPUT_JSON_DEPTH: usize = 16;
pub const MAX_TOOL_OUTPUT_REFERENCE_BYTES: usize = 1_024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ToolValueItem {
    Text(String),
    Structured(JsonValue),
    BinaryReference { reference: String, digest: Digest },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolValue {
    items: Arc<[ToolValueItem]>,
    encoded_bytes: usize,
}

impl ToolValue {
    pub fn items(&self) -> &[ToolValueItem] {
        &self.items
    }

    pub const fn encoded_bytes(&self) -> usize {
        self.encoded_bytes
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ToolOutputLimits {
    items: usize,
    bytes: usize,
    json_depth: usize,
}

impl ToolOutputLimits {
    #[allow(dead_code)] // Used by the guarded executor constructor introduced in the next slice.
    pub(crate) fn checked(
        max_items: usize,
        max_bytes: NonZeroUsize,
        max_json_depth: usize,
    ) -> Result<Self, ToolOutputError> {
        if max_items == 0 || max_items > MAX_TOOL_OUTPUT_ITEMS {
            return Err(ToolOutputError::InvalidLimit);
        }
        if max_bytes.get() > MAX_TOOL_OUTPUT_BYTES {
            return Err(ToolOutputError::InvalidLimit);
        }
        if max_json_depth == 0 || max_json_depth > MAX_TOOL_OUTPUT_JSON_DEPTH {
            return Err(ToolOutputError::InvalidLimit);
        }
        Ok(Self {
            items: max_items,
            bytes: max_bytes.get(),
            json_depth: max_json_depth,
        })
    }
}

#[derive(Debug)]
pub struct ToolOutputBuilder {
    items: Vec<ToolValueItem>,
    encoded_bytes: usize,
    limits: ToolOutputLimits,
}

impl ToolOutputBuilder {
    pub(crate) const fn with_limits(limits: ToolOutputLimits) -> Self {
        Self {
            items: Vec::new(),
            encoded_bytes: 0,
            limits,
        }
    }

    pub fn append_text(&mut self, value: impl Into<String>) -> Result<(), ToolOutputError> {
        let value = value.into();
        self.reserve_item(value.len())?;
        self.items.push(ToolValueItem::Text(value));
        Ok(())
    }

    pub fn append_structured(&mut self, value: JsonValue) -> Result<(), ToolOutputError> {
        if json_depth(&value) > self.limits.json_depth {
            return Err(ToolOutputError::JsonDepthExceeded);
        }
        let bytes = serde_json::to_vec(&value)
            .map_err(|_| ToolOutputError::InvalidStructuredValue)?
            .len();
        self.reserve_item(bytes)?;
        self.items.push(ToolValueItem::Structured(value));
        Ok(())
    }

    pub fn append_binary_reference(
        &mut self,
        reference: impl Into<String>,
        digest: Digest,
    ) -> Result<(), ToolOutputError> {
        let reference = reference.into();
        if reference.is_empty()
            || reference.len() > MAX_TOOL_OUTPUT_REFERENCE_BYTES
            || reference.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(ToolOutputError::InvalidBinaryReference);
        }
        self.reserve_item(reference.len() + Digest::LEN)?;
        self.items
            .push(ToolValueItem::BinaryReference { reference, digest });
        Ok(())
    }

    pub fn build(self) -> ToolValue {
        ToolValue {
            items: self.items.into(),
            encoded_bytes: self.encoded_bytes,
        }
    }

    fn reserve_item(&mut self, bytes: usize) -> Result<(), ToolOutputError> {
        if self.items.len() == self.limits.items {
            return Err(ToolOutputError::ItemLimitExceeded);
        }
        let encoded_bytes = self
            .encoded_bytes
            .checked_add(bytes)
            .ok_or(ToolOutputError::ByteLimitExceeded)?;
        if encoded_bytes > self.limits.bytes {
            return Err(ToolOutputError::ByteLimitExceeded);
        }
        self.encoded_bytes = encoded_bytes;
        Ok(())
    }
}

fn json_depth(value: &JsonValue) -> usize {
    match value {
        JsonValue::Array(values) => 1 + values.iter().map(json_depth).max().unwrap_or_default(),
        JsonValue::Object(values) => 1 + values.values().map(json_depth).max().unwrap_or_default(),
        _ => 1,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolOutputError {
    InvalidLimit,
    ItemLimitExceeded,
    ByteLimitExceeded,
    JsonDepthExceeded,
    InvalidStructuredValue,
    InvalidBinaryReference,
}

impl fmt::Display for ToolOutputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLimit => "invalid tool output limit",
            Self::ItemLimitExceeded => "tool output item limit exceeded",
            Self::ByteLimitExceeded => "tool output byte limit exceeded",
            Self::JsonDepthExceeded => "tool output JSON depth limit exceeded",
            Self::InvalidStructuredValue => "tool output contains invalid structured data",
            Self::InvalidBinaryReference => "tool output binary reference is invalid",
        })
    }
}

impl std::error::Error for ToolOutputError {}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use serde_json::json;

    use super::*;

    fn builder(items: usize, bytes: usize, depth: usize) -> ToolOutputBuilder {
        ToolOutputBuilder::with_limits(
            ToolOutputLimits::checked(items, NonZeroUsize::new(bytes).unwrap(), depth).unwrap(),
        )
    }

    #[test]
    fn output_budget_is_checked_before_an_item_is_retained() {
        let mut output = builder(2, 5, 2);
        output.append_text("abc").unwrap();
        assert_eq!(
            output.append_text("def"),
            Err(ToolOutputError::ByteLimitExceeded)
        );
        output.append_text("de").unwrap();
        assert_eq!(
            output.append_text(""),
            Err(ToolOutputError::ItemLimitExceeded)
        );
        let value = output.build();
        assert_eq!(value.encoded_bytes(), 5);
        assert_eq!(value.items().len(), 2);
    }

    #[test]
    fn output_budget_counts_utf8_bytes_and_rejects_deep_json() {
        let mut output = builder(2, 4, 2);
        output.append_text("界").unwrap();
        assert_eq!(
            output.append_text("界"),
            Err(ToolOutputError::ByteLimitExceeded)
        );
        assert_eq!(
            output.append_structured(json!({"a": {"b": true}})),
            Err(ToolOutputError::JsonDepthExceeded)
        );
        assert_eq!(output.build().items().len(), 1);
    }
}
