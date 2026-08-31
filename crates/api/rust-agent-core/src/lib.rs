//! Stable, effect-free primitives shared by rust-agent capability APIs.

use std::{fmt, str::FromStr};

/// Error returned when a canonical identifier is malformed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentifierError {
    Empty,
    TooLong,
    InvalidStart,
    InvalidCharacter { index: usize, byte: u8 },
    EmptySegment,
}

impl fmt::Display for IdentifierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("identifier is empty"),
            Self::TooLong => formatter.write_str("identifier exceeds 128 bytes"),
            Self::InvalidStart => {
                formatter.write_str("identifier must start with a lowercase letter")
            }
            Self::InvalidCharacter { index, byte } => {
                write!(
                    formatter,
                    "invalid identifier byte 0x{byte:02x} at offset {index}"
                )
            }
            Self::EmptySegment => {
                formatter.write_str("identifier contains an empty kebab-case segment")
            }
        }
    }
}

impl std::error::Error for IdentifierError {}

/// Canonical kebab-case identifier used by components and provider keys.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CanonicalId(String);

impl CanonicalId {
    pub const MAX_LEN: usize = 128;

    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        let value = value.into();
        validate_id(value.as_bytes())?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

fn validate_id(bytes: &[u8]) -> Result<(), IdentifierError> {
    if bytes.is_empty() {
        return Err(IdentifierError::Empty);
    }
    if bytes.len() > CanonicalId::MAX_LEN {
        return Err(IdentifierError::TooLong);
    }
    if !bytes[0].is_ascii_lowercase() {
        return Err(IdentifierError::InvalidStart);
    }
    let mut previous_dash = false;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if byte == b'-' {
            if previous_dash || index + 1 == bytes.len() {
                return Err(IdentifierError::EmptySegment);
            }
            previous_dash = true;
        } else if byte.is_ascii_lowercase() || byte.is_ascii_digit() {
            previous_dash = false;
        } else {
            return Err(IdentifierError::InvalidCharacter { index, byte });
        }
    }
    Ok(())
}

impl fmt::Debug for CanonicalId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("CanonicalId").field(&self.0).finish()
    }
}

impl fmt::Display for CanonicalId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for CanonicalId {
    type Err = IdentifierError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

/// A complete `cap:<kebab-case>` capability identifier.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CapabilityId(CanonicalId);

impl CapabilityId {
    pub fn new(value: &str) -> Result<Self, IdentifierError> {
        let suffix = value
            .strip_prefix("cap:")
            .ok_or(IdentifierError::InvalidStart)?;
        CanonicalId::new(suffix).map(Self)
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for CapabilityId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "CapabilityId(cap:{})", self.0)
    }
}

impl fmt::Display for CapabilityId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "cap:{}", self.0)
    }
}

/// A SHA-256 digest with checked lowercase hexadecimal encoding.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Digest([u8; 32]);

impl Digest {
    pub const LEN: usize = 32;

    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    pub fn from_lower_hex(value: &str) -> Result<Self, DigestEncodingError> {
        if value.len() != Self::LEN * 2 {
            return Err(DigestEncodingError::InvalidLength);
        }
        if value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        {
            return Err(DigestEncodingError::NonCanonicalHex);
        }
        let mut result = [0_u8; Self::LEN];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            result[index] = (decode_nibble(pair[0])? << 4) | decode_nibble(pair[1])?;
        }
        Ok(Self(result))
    }

    pub fn to_lower_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut result = String::with_capacity(Self::LEN * 2);
        for byte in self.0 {
            result.push(char::from(HEX[usize::from(byte >> 4)]));
            result.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        result
    }
}

fn decode_nibble(byte: u8) -> Result<u8, DigestEncodingError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(DigestEncodingError::NonCanonicalHex),
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Digest")
            .field(&self.to_lower_hex())
            .finish()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_lower_hex())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DigestEncodingError {
    InvalidLength,
    NonCanonicalHex,
}

impl fmt::Display for DigestEncodingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => {
                formatter.write_str("digest must contain exactly 64 hex characters")
            }
            Self::NonCanonicalHex => {
                formatter.write_str("digest must use lowercase canonical hexadecimal")
            }
        }
    }
}

impl std::error::Error for DigestEncodingError {}

/// Canonical composition identity used by lifecycle protocol records.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CompositionHash(Digest);

impl CompositionHash {
    pub const fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }

    pub const fn digest(self) -> Digest {
        self.0
    }
}

/// Error returned when a lifecycle or Session identity is not canonical.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleIdentityEncodingError {
    UnknownVersion(u8),
    UnknownKind(u8),
    ZeroIssuer,
    ZeroGeneration,
    ZeroCounter,
    VolatileOperation,
}

impl fmt::Display for LifecycleIdentityEncodingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownVersion(version) => {
                write!(formatter, "unknown lifecycle identity version {version}")
            }
            Self::UnknownKind(kind) => write!(formatter, "unknown lifecycle identity kind {kind}"),
            Self::ZeroIssuer => formatter.write_str("lifecycle issuer must not be all zero"),
            Self::ZeroGeneration => {
                formatter.write_str("lifecycle issuer generation must not be zero")
            }
            Self::ZeroCounter => formatter.write_str("lifecycle counter must not be zero"),
            Self::VolatileOperation => {
                formatter.write_str("volatile lifecycle identity is not durable")
            }
        }
    }
}

impl std::error::Error for LifecycleIdentityEncodingError {}

/// Whether an Agent lifecycle operation is process-local or store-persistent.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AgentLifecycleOperationIdKind {
    Volatile,
    Persistent,
}

/// A private-field, versioned lifecycle operation identity.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AgentLifecycleOperationId([u8; Self::ENCODED_LEN]);

impl AgentLifecycleOperationId {
    pub const VERSION: u8 = 1;
    pub const ENCODED_LEN: usize = 50;
    const VOLATILE_TAG: u8 = 1;
    const PERSISTENT_TAG: u8 = 2;

    pub fn from_canonical_v1_bytes(
        bytes: [u8; Self::ENCODED_LEN],
    ) -> Result<Self, LifecycleIdentityEncodingError> {
        validate_lifecycle_identity(&bytes)?;
        Ok(Self(bytes))
    }

    pub const fn to_canonical_v1_bytes(self) -> [u8; Self::ENCODED_LEN] {
        self.0
    }

    pub fn to_durable_canonical_v1_bytes(
        self,
    ) -> Result<[u8; Self::ENCODED_LEN], LifecycleIdentityEncodingError> {
        if self.is_persistent() {
            Ok(self.0)
        } else {
            Err(LifecycleIdentityEncodingError::VolatileOperation)
        }
    }

    pub const fn kind(self) -> AgentLifecycleOperationIdKind {
        if self.0[1] == Self::VOLATILE_TAG {
            AgentLifecycleOperationIdKind::Volatile
        } else {
            AgentLifecycleOperationIdKind::Persistent
        }
    }

    pub const fn is_persistent(self) -> bool {
        matches!(self.kind(), AgentLifecycleOperationIdKind::Persistent)
    }
}

impl fmt::Debug for AgentLifecycleOperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentLifecycleOperationId")
            .field("kind", &self.kind())
            .finish_non_exhaustive()
    }
}

fn validate_lifecycle_identity(
    bytes: &[u8; AgentLifecycleOperationId::ENCODED_LEN],
) -> Result<(), LifecycleIdentityEncodingError> {
    if bytes[0] != AgentLifecycleOperationId::VERSION {
        return Err(LifecycleIdentityEncodingError::UnknownVersion(bytes[0]));
    }
    if !matches!(
        bytes[1],
        AgentLifecycleOperationId::VOLATILE_TAG | AgentLifecycleOperationId::PERSISTENT_TAG
    ) {
        return Err(LifecycleIdentityEncodingError::UnknownKind(bytes[1]));
    }
    if bytes[2..34].iter().all(|byte| *byte == 0) {
        return Err(LifecycleIdentityEncodingError::ZeroIssuer);
    }
    if bytes[34..42].iter().all(|byte| *byte == 0) {
        return Err(LifecycleIdentityEncodingError::ZeroGeneration);
    }
    if bytes[42..50].iter().all(|byte| *byte == 0) {
        return Err(LifecycleIdentityEncodingError::ZeroCounter);
    }
    Ok(())
}

/// A canonical Session identity. New durable Sessions derive this losslessly
/// from their persistent lifecycle operation id.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SessionId([u8; Self::ENCODED_LEN]);

impl SessionId {
    pub const VERSION: u8 = 1;
    pub const ENCODED_LEN: usize = AgentLifecycleOperationId::ENCODED_LEN;

    pub fn from_canonical_v1_bytes(
        bytes: [u8; Self::ENCODED_LEN],
    ) -> Result<Self, LifecycleIdentityEncodingError> {
        validate_lifecycle_identity(&bytes)?;
        Ok(Self(bytes))
    }

    pub fn from_persistent_operation(
        operation: AgentLifecycleOperationId,
    ) -> Result<Self, LifecycleIdentityEncodingError> {
        if !operation.is_persistent() {
            return Err(LifecycleIdentityEncodingError::VolatileOperation);
        }
        Ok(Self(operation.to_canonical_v1_bytes()))
    }

    pub const fn to_canonical_v1_bytes(self) -> [u8; Self::ENCODED_LEN] {
        self.0
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionId(<canonical>)")
    }
}

/// A caller-persisted, versioned idempotency key for durable lifecycle requests.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct AgentOperationRecoveryKey([u8; Self::ENCODED_LEN]);

impl AgentOperationRecoveryKey {
    pub const VERSION: u8 = 1;
    pub const ENCODED_LEN: usize = 33;
    pub const V1_ENCODED_LEN: usize = Self::ENCODED_LEN;

    pub fn from_canonical_v1_bytes(
        bytes: [u8; Self::ENCODED_LEN],
    ) -> Result<Self, RecoveryKeyEncodingError> {
        if bytes[0] != Self::VERSION {
            return Err(RecoveryKeyEncodingError::UnknownVersion(bytes[0]));
        }
        if bytes[1..].iter().all(|byte| *byte == 0) {
            return Err(RecoveryKeyEncodingError::ZeroPayload);
        }
        Ok(Self(bytes))
    }

    pub const fn to_canonical_v1_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        self.0
    }
}

impl fmt::Debug for AgentOperationRecoveryKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AgentOperationRecoveryKey(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryKeyEncodingError {
    UnknownVersion(u8),
    ZeroPayload,
}

impl fmt::Display for RecoveryKeyEncodingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownVersion(version) => {
                write!(formatter, "unknown recovery-key version {version}")
            }
            Self::ZeroPayload => formatter.write_str("recovery-key payload must not be all zero"),
        }
    }
}

impl std::error::Error for RecoveryKeyEncodingError {}

pub type AgentOperationRecoveryKeyEncodingError = RecoveryKeyEncodingError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_ids_accept_only_normalized_kebab_case() {
        assert_eq!(
            CanonicalId::new("model-replay").unwrap().as_str(),
            "model-replay"
        );
        for invalid in [
            "",
            "Model",
            "model_1",
            "model--one",
            "model-",
            "1model",
            "é",
        ] {
            assert!(
                CanonicalId::new(invalid).is_err(),
                "{invalid:?} should be rejected"
            );
        }
    }

    #[test]
    fn capability_prefix_is_checked_once() {
        assert_eq!(
            CapabilityId::new("cap:model").unwrap().to_string(),
            "cap:model"
        );
        assert!(CapabilityId::new("model").is_err());
        assert!(CapabilityId::new("cap:cap:model").is_err());
    }

    #[test]
    fn digest_hex_round_trip_is_canonical() {
        let digest = Digest::from_bytes([0xab; 32]);
        let encoded = digest.to_lower_hex();
        assert_eq!(Digest::from_lower_hex(&encoded).unwrap(), digest);
        assert!(Digest::from_lower_hex(&encoded.to_uppercase()).is_err());
    }

    #[test]
    fn recovery_key_checks_version_and_zero_value() {
        let mut bytes = [0_u8; AgentOperationRecoveryKey::ENCODED_LEN];
        bytes[0] = AgentOperationRecoveryKey::VERSION;
        bytes[1] = 7;
        let key = AgentOperationRecoveryKey::from_canonical_v1_bytes(bytes).unwrap();
        assert_eq!(key.to_canonical_v1_bytes(), bytes);

        bytes[0] = 2;
        assert_eq!(
            AgentOperationRecoveryKey::from_canonical_v1_bytes(bytes),
            Err(RecoveryKeyEncodingError::UnknownVersion(2))
        );
    }

    fn operation_bytes(kind: u8) -> [u8; AgentLifecycleOperationId::ENCODED_LEN] {
        let mut bytes = [0_u8; AgentLifecycleOperationId::ENCODED_LEN];
        bytes[0] = AgentLifecycleOperationId::VERSION;
        bytes[1] = kind;
        bytes[2] = 1;
        bytes[41] = 1;
        bytes[49] = 1;
        bytes
    }

    #[test]
    fn lifecycle_identity_rejects_unknown_and_zero_fields() {
        let persistent = operation_bytes(AgentLifecycleOperationId::PERSISTENT_TAG);
        let operation = AgentLifecycleOperationId::from_canonical_v1_bytes(persistent).unwrap();
        assert!(operation.is_persistent());
        assert_eq!(operation.to_canonical_v1_bytes(), persistent);

        let mut invalid = persistent;
        invalid[2..34].fill(0);
        assert_eq!(
            AgentLifecycleOperationId::from_canonical_v1_bytes(invalid),
            Err(LifecycleIdentityEncodingError::ZeroIssuer)
        );
        let mut invalid = persistent;
        invalid[1] = 9;
        assert_eq!(
            AgentLifecycleOperationId::from_canonical_v1_bytes(invalid),
            Err(LifecycleIdentityEncodingError::UnknownKind(9))
        );
    }

    #[test]
    fn only_persistent_operations_derive_durable_session_ids() {
        let persistent = AgentLifecycleOperationId::from_canonical_v1_bytes(operation_bytes(
            AgentLifecycleOperationId::PERSISTENT_TAG,
        ))
        .unwrap();
        let session = SessionId::from_persistent_operation(persistent).unwrap();
        assert_eq!(
            session.to_canonical_v1_bytes(),
            persistent.to_canonical_v1_bytes()
        );

        let volatile = AgentLifecycleOperationId::from_canonical_v1_bytes(operation_bytes(
            AgentLifecycleOperationId::VOLATILE_TAG,
        ))
        .unwrap();
        assert!(SessionId::from_persistent_operation(volatile).is_err());
    }
}
