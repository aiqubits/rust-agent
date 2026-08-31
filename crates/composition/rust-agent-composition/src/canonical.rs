use serde::Serialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CanonicalError {
    #[error("canonical payload serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("floating-point and out-of-range numbers are forbidden in canonical payloads")]
    UnsupportedNumber,
}

pub fn deterministic_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    let value = serde_json::to_value(value)?;
    let mut output = Vec::new();
    encode_value(&value, &mut output)?;
    Ok(output)
}

pub fn domain_hash<T: Serialize>(domain: &[u8], value: &T) -> Result<[u8; 32], CanonicalError> {
    let payload = deterministic_cbor(value)?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(payload);
    Ok(hasher.finalize().into())
}

pub fn raw_domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}

pub fn jcs_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    serde_jcs::to_vec(value).map_err(CanonicalError::Serialize)
}

fn encode_value(value: &Value, output: &mut Vec<u8>) -> Result<(), CanonicalError> {
    match value {
        Value::Null => output.push(0xf6),
        Value::Bool(false) => output.push(0xf4),
        Value::Bool(true) => output.push(0xf5),
        Value::Number(number) => {
            if let Some(value) = number.as_u64() {
                encode_major(0, value, output);
            } else if let Some(value) = number.as_i64() {
                let encoded = u64::try_from(-1_i128 - i128::from(value))
                    .map_err(|_| CanonicalError::UnsupportedNumber)?;
                encode_major(1, encoded, output);
            } else {
                return Err(CanonicalError::UnsupportedNumber);
            }
        }
        Value::String(value) => {
            encode_major(3, value.len() as u64, output);
            output.extend_from_slice(value.as_bytes());
        }
        Value::Array(values) => {
            encode_major(4, values.len() as u64, output);
            for value in values {
                encode_value(value, output)?;
            }
        }
        Value::Object(values) => {
            let mut entries = Vec::with_capacity(values.len());
            for (key, value) in values {
                let mut encoded_key = Vec::new();
                encode_value(&Value::String(key.clone()), &mut encoded_key)?;
                let mut encoded_value = Vec::new();
                encode_value(value, &mut encoded_value)?;
                entries.push((encoded_key, encoded_value));
            }
            entries.sort_by(|left, right| {
                left.0
                    .len()
                    .cmp(&right.0.len())
                    .then_with(|| left.0.cmp(&right.0))
            });
            encode_major(5, entries.len() as u64, output);
            for (key, value) in entries {
                output.extend_from_slice(&key);
                output.extend_from_slice(&value);
            }
        }
    }
    Ok(())
}

fn encode_major(major: u8, value: u64, output: &mut Vec<u8>) {
    let prefix = major << 5;
    match value {
        0..=23 => output.push(prefix | u8::try_from(value).expect("matched u8 range")),
        24..=0xff => {
            output.push(prefix | 0x18);
            output.push(u8::try_from(value).expect("matched u8 range"));
        }
        0x100..=0xffff => {
            output.push(prefix | 0x19);
            output.extend_from_slice(
                &u16::try_from(value)
                    .expect("matched u16 range")
                    .to_be_bytes(),
            );
        }
        0x1_0000..=0xffff_ffff => {
            output.push(prefix | 0x1a);
            output.extend_from_slice(
                &u32::try_from(value)
                    .expect("matched u32 range")
                    .to_be_bytes(),
            );
        }
        _ => {
            output.push(prefix | 0x1b);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use serde::Serialize;

    use super::*;

    #[test]
    fn map_keys_use_rfc_8949_deterministic_order() {
        #[derive(Serialize)]
        struct Input<'a> {
            aaa: &'a str,
            b: &'a str,
        }
        let encoded = deterministic_cbor(&Input { aaa: "1", b: "2" }).unwrap();
        assert_eq!(
            encoded,
            vec![
                0xa2, 0x61, b'b', 0x61, b'2', 0x63, b'a', b'a', b'a', 0x61, b'1'
            ]
        );
    }

    #[test]
    fn domain_separation_changes_hash() {
        assert_ne!(
            domain_hash(b"a\0", &42_u64).unwrap(),
            domain_hash(b"b\0", &42_u64).unwrap()
        );
    }
}
