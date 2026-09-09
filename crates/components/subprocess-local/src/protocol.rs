use rust_agent_core::Digest;
use rust_agent_policy::process::EnforcementPrimitives;

pub(super) const SETUP_HEADER_BYTES: usize = 16 + Digest::LEN + 2;
const SETUP_MAGIC: [u8; 16] = *b"RA_SETUP_ACK_V1!";

#[derive(Clone, Copy, Debug)]
pub(super) struct SetupAcknowledgement {
    pub(super) policy_digest: Digest,
    pub(super) applied_primitives: EnforcementPrimitives,
}

// Each binary target consumes only one direction of this private wire protocol.
#[allow(dead_code)]
pub(super) fn encode_setup_header(
    acknowledgement: SetupAcknowledgement,
) -> [u8; SETUP_HEADER_BYTES] {
    let mut header = [0_u8; SETUP_HEADER_BYTES];
    header[..SETUP_MAGIC.len()].copy_from_slice(&SETUP_MAGIC);
    header[SETUP_MAGIC.len()..SETUP_MAGIC.len() + Digest::LEN]
        .copy_from_slice(acknowledgement.policy_digest.as_bytes());
    header[SETUP_MAGIC.len() + Digest::LEN..]
        .copy_from_slice(&acknowledgement.applied_primitives.bits().to_be_bytes());
    header
}

#[allow(dead_code)]
pub(super) fn decode_setup_header(
    header: &[u8; SETUP_HEADER_BYTES],
) -> Option<SetupAcknowledgement> {
    if header[..SETUP_MAGIC.len()] != SETUP_MAGIC {
        return None;
    }
    let mut digest = [0_u8; Digest::LEN];
    digest.copy_from_slice(&header[SETUP_MAGIC.len()..SETUP_MAGIC.len() + Digest::LEN]);
    let mut primitive_bits = [0_u8; 2];
    primitive_bits.copy_from_slice(&header[SETUP_MAGIC.len() + Digest::LEN..]);
    Some(SetupAcknowledgement {
        policy_digest: Digest::from_bytes(digest),
        applied_primitives: EnforcementPrimitives::from_bits(u16::from_be_bytes(primitive_bits))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_header_is_fixed_bounded_and_rejects_forgery() {
        let acknowledgement = SetupAcknowledgement {
            policy_digest: Digest::from_bytes([7; Digest::LEN]),
            applied_primitives: EnforcementPrimitives::NO_NEW_PRIVILEGES
                | EnforcementPrimitives::SECCOMP,
        };
        let mut header = encode_setup_header(acknowledgement);
        let decoded = decode_setup_header(&header).unwrap();
        assert_eq!(decoded.policy_digest, acknowledgement.policy_digest);
        assert_eq!(
            decoded.applied_primitives,
            acknowledgement.applied_primitives
        );
        header[0] ^= 1;
        assert!(decode_setup_header(&header).is_none());
    }
}
