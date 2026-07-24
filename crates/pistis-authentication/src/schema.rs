use crate::{ChallengeDocument, Decision, ServiceError, UnixTimeMillis};
use pistis_canonical::{Value, from_slice_with_fields, to_vec};
use pistis_crypto::sha256;
use pistis_domain::{ChallengeId, DeviceId, ExternalIdentityId, InstallationId, KeyId, UserId};
use std::collections::BTreeMap;

const VERSION: u64 = 1;
const CHALLENGE_PURPOSE: &str = "pistis.authentication-challenge.v1";
const RESPONSE_PURPOSE: &str = "pistis.authentication-response.v1";
const ACTION: &str = "authenticate-session";
const CHALLENGE_FIELDS: &[u64] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
const RESPONSE_FIELDS: &[u64] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthenticationResponse {
    pub issued_at: UnixTimeMillis,
    pub user_verified_at: UnixTimeMillis,
    pub installation_id: InstallationId,
    pub key_id: KeyId,
    pub challenge_id: ChallengeId,
    pub nonce: [u8; 32],
    pub challenge_digest: [u8; 32],
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub external_identity_id: ExternalIdentityId,
    pub decision: Decision,
}

/// Encodes the complete closed v1 challenge schema.
///
/// # Errors
///
/// Rejects invalid string bounds, endpoint hints, temporal ordering, or an
/// encoder failure.
pub fn encode_challenge(challenge: &ChallengeDocument) -> Result<Vec<u8>, ServiceError> {
    validate_challenge(challenge)?;
    let endpoints = challenge
        .endpoint_hints
        .iter()
        .cloned()
        .map(Value::Text)
        .collect();
    to_vec(&Value::Map(BTreeMap::from([
        (0, Value::Unsigned(VERSION)),
        (1, Value::Text(CHALLENGE_PURPOSE.into())),
        (2, Value::Unsigned(challenge.issued_at.0)),
        (3, Value::Unsigned(challenge.expires_at.0)),
        (
            4,
            Value::Bytes(challenge.installation_id.into_bytes().to_vec()),
        ),
        (
            5,
            Value::Bytes(challenge.installation_key_id.into_bytes().to_vec()),
        ),
        (
            6,
            Value::Bytes(challenge.challenge_id.into_bytes().to_vec()),
        ),
        (7, Value::Bytes(challenge.nonce.to_vec())),
        (8, Value::Bytes(challenge.user_id.into_bytes().to_vec())),
        (
            9,
            Value::Bytes(challenge.external_identity_id.into_bytes().to_vec()),
        ),
        (10, Value::Text(ACTION.into())),
        (11, Value::Text(challenge.audience.clone())),
        (12, Value::Text(challenge.installation_name.clone())),
        (13, Value::Text(challenge.local_username.clone())),
        (14, Value::Bytes(challenge.display_context_digest.to_vec())),
        (
            15,
            Value::Bytes(challenge.installation_fingerprint.to_vec()),
        ),
        (16, Value::Array(endpoints)),
    ])))
    .map_err(invalid)
}

/// Decodes the complete closed v1 challenge schema.
///
/// # Errors
///
/// Rejects unknown/missing fields, wrong constants, invalid bounds, incorrect
/// widths, and malformed or non-canonical input.
pub fn decode_challenge(bytes: &[u8]) -> Result<ChallengeDocument, ServiceError> {
    let mut f = from_slice_with_fields(bytes, CHALLENGE_FIELDS).map_err(invalid)?;
    require_len(&f, CHALLENGE_FIELDS.len())?;
    require_header(&mut f, CHALLENGE_PURPOSE)?;
    let challenge = ChallengeDocument {
        issued_at: UnixTimeMillis(take_u64(&mut f, 2)?),
        expires_at: UnixTimeMillis(take_u64(&mut f, 3)?),
        installation_id: InstallationId::from_bytes(take_array(&mut f, 4)?),
        installation_key_id: KeyId::from_bytes(take_array(&mut f, 5)?),
        challenge_id: ChallengeId::from_bytes(take_array(&mut f, 6)?),
        nonce: take_array(&mut f, 7)?,
        user_id: UserId::from_bytes(take_array(&mut f, 8)?),
        external_identity_id: ExternalIdentityId::from_bytes(take_array(&mut f, 9)?),
        audience: {
            require_text(&mut f, 10, ACTION)?;
            take_text(&mut f, 11)?
        },
        installation_name: take_text(&mut f, 12)?,
        local_username: take_text(&mut f, 13)?,
        display_context_digest: take_array(&mut f, 14)?,
        installation_fingerprint: take_array(&mut f, 15)?,
        endpoint_hints: take_text_array(&mut f, 16)?,
    };
    validate_challenge(&challenge)?;
    Ok(challenge)
}

/// Encodes the closed v1 signed-response body.
///
/// The response intentionally contains no claimant-controlled expiry.
///
/// # Errors
///
/// Returns an error when challenge encoding or response encoding fails.
pub fn encode_response(
    challenge: &ChallengeDocument,
    device_id: DeviceId,
    key_id: KeyId,
    decision: Decision,
    issued_at: UnixTimeMillis,
    user_verified_at: UnixTimeMillis,
) -> Result<Vec<u8>, ServiceError> {
    if issued_at > user_verified_at {
        return Err(ServiceError::InvalidResponse);
    }
    let challenge_digest = sha256(&encode_challenge(challenge)?).into_bytes();
    to_vec(&Value::Map(BTreeMap::from([
        (0, Value::Unsigned(VERSION)),
        (1, Value::Text(RESPONSE_PURPOSE.into())),
        (2, Value::Unsigned(issued_at.0)),
        (3, Value::Unsigned(user_verified_at.0)),
        (
            4,
            Value::Bytes(challenge.installation_id.into_bytes().to_vec()),
        ),
        (5, Value::Bytes(key_id.into_bytes().to_vec())),
        (
            6,
            Value::Bytes(challenge.challenge_id.into_bytes().to_vec()),
        ),
        (7, Value::Bytes(challenge.nonce.to_vec())),
        (8, Value::Bytes(challenge_digest.to_vec())),
        (9, Value::Bytes(challenge.user_id.into_bytes().to_vec())),
        (10, Value::Bytes(device_id.into_bytes().to_vec())),
        (
            11,
            Value::Bytes(challenge.external_identity_id.into_bytes().to_vec()),
        ),
        (
            12,
            Value::Text(
                match decision {
                    Decision::Approve => "approved",
                    Decision::Deny => "denied",
                }
                .into(),
            ),
        ),
    ])))
    .map_err(invalid)
}

pub(crate) fn decode_response(bytes: &[u8]) -> Result<AuthenticationResponse, ServiceError> {
    let mut f = from_slice_with_fields(bytes, RESPONSE_FIELDS).map_err(invalid)?;
    require_len(&f, RESPONSE_FIELDS.len())?;
    require_header(&mut f, RESPONSE_PURPOSE)?;
    let issued_at = UnixTimeMillis(take_u64(&mut f, 2)?);
    let user_verified_at = UnixTimeMillis(take_u64(&mut f, 3)?);
    if issued_at > user_verified_at {
        return Err(ServiceError::InvalidResponse);
    }
    let decision = match take_text(&mut f, 12)?.as_str() {
        "approved" => Decision::Approve,
        "denied" => Decision::Deny,
        _ => return Err(ServiceError::InvalidResponse),
    };
    Ok(AuthenticationResponse {
        issued_at,
        user_verified_at,
        installation_id: InstallationId::from_bytes(take_array(&mut f, 4)?),
        key_id: KeyId::from_bytes(take_array(&mut f, 5)?),
        challenge_id: ChallengeId::from_bytes(take_array(&mut f, 6)?),
        nonce: take_array(&mut f, 7)?,
        challenge_digest: take_array(&mut f, 8)?,
        user_id: UserId::from_bytes(take_array(&mut f, 9)?),
        device_id: DeviceId::from_bytes(take_array(&mut f, 10)?),
        external_identity_id: ExternalIdentityId::from_bytes(take_array(&mut f, 11)?),
        decision,
    })
}

fn validate_challenge(value: &ChallengeDocument) -> Result<(), ServiceError> {
    if value.issued_at >= value.expires_at
        || !bounded(&value.audience, 128)
        || !bounded(&value.installation_name, 128)
        || !bounded(&value.local_username, 128)
        || value.endpoint_hints.len() > 2
        || value.endpoint_hints.iter().any(|hint| {
            hint.len() > 256 || !hint.starts_with("https://") || hint.chars().any(char::is_control)
        })
    {
        return Err(ServiceError::InvalidResponse);
    }
    let mut unique = value.endpoint_hints.clone();
    unique.sort();
    unique.dedup();
    if unique.len() != value.endpoint_hints.len() {
        return Err(ServiceError::InvalidResponse);
    }
    Ok(())
}

fn bounded(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn require_len(fields: &BTreeMap<u64, Value>, expected: usize) -> Result<(), ServiceError> {
    if fields.len() == expected {
        Ok(())
    } else {
        Err(ServiceError::InvalidResponse)
    }
}

fn require_header(fields: &mut BTreeMap<u64, Value>, purpose: &str) -> Result<(), ServiceError> {
    if take_u64(fields, 0)? != VERSION {
        return Err(ServiceError::InvalidResponse);
    }
    require_text(fields, 1, purpose)
}

fn require_text(
    fields: &mut BTreeMap<u64, Value>,
    key: u64,
    expected: &str,
) -> Result<(), ServiceError> {
    if take_text(fields, key)? == expected {
        Ok(())
    } else {
        Err(ServiceError::InvalidResponse)
    }
}

fn take_u64(fields: &mut BTreeMap<u64, Value>, key: u64) -> Result<u64, ServiceError> {
    match fields.remove(&key) {
        Some(Value::Unsigned(value)) => Ok(value),
        _ => Err(ServiceError::InvalidResponse),
    }
}

fn take_text(fields: &mut BTreeMap<u64, Value>, key: u64) -> Result<String, ServiceError> {
    match fields.remove(&key) {
        Some(Value::Text(value)) => Ok(value),
        _ => Err(ServiceError::InvalidResponse),
    }
}

fn take_bytes(fields: &mut BTreeMap<u64, Value>, key: u64) -> Result<Vec<u8>, ServiceError> {
    match fields.remove(&key) {
        Some(Value::Bytes(value)) => Ok(value),
        _ => Err(ServiceError::InvalidResponse),
    }
}

fn take_array<const N: usize>(
    fields: &mut BTreeMap<u64, Value>,
    key: u64,
) -> Result<[u8; N], ServiceError> {
    take_bytes(fields, key)?
        .try_into()
        .map_err(|_| ServiceError::InvalidResponse)
}

fn take_text_array(
    fields: &mut BTreeMap<u64, Value>,
    key: u64,
) -> Result<Vec<String>, ServiceError> {
    match fields.remove(&key) {
        Some(Value::Array(values)) => values
            .into_iter()
            .map(|value| match value {
                Value::Text(text) => Ok(text),
                _ => Err(ServiceError::InvalidResponse),
            })
            .collect(),
        _ => Err(ServiceError::InvalidResponse),
    }
}

fn invalid(_: pistis_canonical::CanonicalError) -> ServiceError {
    ServiceError::InvalidResponse
}

#[cfg(test)]
mod tests {
    use super::*;

    fn challenge() -> ChallengeDocument {
        ChallengeDocument {
            issued_at: UnixTimeMillis(100),
            expires_at: UnixTimeMillis(500),
            installation_id: InstallationId::from_bytes([1; 16]),
            installation_key_id: KeyId::from_bytes([2; 32]),
            challenge_id: ChallengeId::from_bytes([3; 16]),
            nonce: [4; 32],
            user_id: UserId::from_bytes([5; 16]),
            external_identity_id: ExternalIdentityId::from_bytes([6; 16]),
            audience: "local-session".into(),
            installation_name: "Fixture installation".into(),
            local_username: "fixture-user".into(),
            display_context_digest: [7; 32],
            installation_fingerprint: [8; 32],
            endpoint_hints: vec!["https://127.0.0.1:8443/response".into()],
        }
    }

    #[test]
    fn complete_challenge_schema_round_trips() {
        let expected = challenge();
        let encoded = encode_challenge(&expected).expect("encode closed challenge");
        assert_eq!(decode_challenge(&encoded), Ok(expected));
    }

    #[test]
    fn unknown_challenge_field_fails_closed() {
        let encoded = encode_challenge(&challenge()).expect("encode closed challenge");
        let Value::Map(mut fields) =
            pistis_canonical::from_slice(&encoded).expect("decode fixture")
        else {
            panic!("challenge must be a map");
        };
        fields.insert(99, Value::Bool(true));
        let changed = to_vec(&Value::Map(fields)).expect("encode changed fixture");
        assert_eq!(
            decode_challenge(&changed),
            Err(ServiceError::InvalidResponse)
        );
    }

    #[test]
    fn response_contains_digest_and_no_claimant_expiry() {
        let challenge = challenge();
        let encoded = encode_response(
            &challenge,
            DeviceId::from_bytes([9; 16]),
            KeyId::from_bytes([10; 32]),
            Decision::Approve,
            UnixTimeMillis(150),
            UnixTimeMillis(175),
        )
        .expect("encode response");
        let response = decode_response(&encoded).expect("decode response");
        assert_eq!(
            response.challenge_digest,
            sha256(&encode_challenge(&challenge).expect("encode challenge")).into_bytes()
        );
        let Value::Map(fields) = pistis_canonical::from_slice(&encoded).expect("decode response")
        else {
            panic!("response must be a map");
        };
        assert_eq!(fields.len(), RESPONSE_FIELDS.len());
        assert_eq!(fields.keys().copied().collect::<Vec<_>>(), RESPONSE_FIELDS);
    }
}
