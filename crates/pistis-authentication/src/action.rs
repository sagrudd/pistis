use crate::{Decision, ServiceError, UnixTimeMillis};
use pistis_canonical::{Value, from_slice_with_fields, to_vec};
use pistis_crypto::sha256;
use pistis_domain::{ChallengeId, DeviceId, ExternalIdentityId, InstallationId, KeyId, UserId};
use std::collections::{BTreeMap, BTreeSet};

const VERSION: u64 = 2;
const DESCRIPTOR_PURPOSE: &str = "pistis.action-descriptor.v2";
const CHALLENGE_PURPOSE: &str = "pistis.action-approval-challenge.v2";
const RESPONSE_PURPOSE: &str = "pistis.action-approval-response.v2";
const DESCRIPTOR_FIELDS: &[u64] = &[0, 1, 2, 3, 4, 5, 6, 7];
const CHALLENGE_FIELDS: &[u64] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
const RESPONSE_FIELDS: &[u64] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
const ENVIRONMENT_FIELDS: &[u64] = &[0, 1];
const RESOURCE_FIELDS: &[u64] = &[0, 1, 2];

/// Maximum number of ordered command arguments.
pub const MAX_ACTION_ARGUMENTS: usize = 128;
/// Maximum number of explicitly disclosed environment bindings.
pub const MAX_ACTION_ENVIRONMENT: usize = 32;
/// Maximum number of resources bound to one action.
pub const MAX_ACTION_RESOURCES: usize = 64;

/// One explicitly disclosed, non-secret environment binding.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ActionEnvironment {
    /// Portable uppercase environment key.
    pub name: String,
    /// Exact non-secret value shown to and approved by the user.
    pub value: String,
}

/// How an approved command intends to use a resource.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ActionResourceKind {
    /// Existing resource read by the command.
    Input,
    /// Resource created or replaced by the command.
    Output,
    /// Existing resource used as configuration or reference data.
    Reference,
}

/// One stable resource binding displayed during approval.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ActionResource {
    /// Intended use of the resource.
    pub kind: ActionResourceKind,
    /// Absolute URI or another reviewed stable identifier.
    pub identifier: String,
    /// Optional SHA-256 digest of immutable content.
    pub sha256: Option<[u8; 32]>,
}

/// Closed canonical description of the exact command an agent may execute.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionDescriptor {
    /// Resolved absolute POSIX executable path.
    pub executable_path: String,
    /// SHA-256 digest of executable contents.
    pub executable_sha256: [u8; 32],
    /// Exact ordered argument vector, including argument zero.
    pub arguments: Vec<String>,
    /// Resolved absolute POSIX working directory.
    pub working_directory: String,
    /// Sorted, duplicate-free non-secret environment allow-list.
    pub environment: Vec<ActionEnvironment>,
    /// Sorted, duplicate-free resource bindings.
    pub resources: Vec<ActionResource>,
}

/// Signed version 2 exact-action challenge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionApprovalChallenge {
    /// Issuer-controlled creation time.
    pub issued_at: UnixTimeMillis,
    /// Exclusive expiry.
    pub expires_at: UnixTimeMillis,
    /// Installation receiving the response.
    pub installation_id: InstallationId,
    /// Installation signing-key identifier.
    pub installation_key_id: KeyId,
    /// Single-use challenge identifier.
    pub challenge_id: ChallengeId,
    /// Single-use random value.
    pub nonce: [u8; 32],
    /// Local user requesting execution.
    pub user_id: UserId,
    /// Required enrolled external identity.
    pub external_identity_id: ExternalIdentityId,
    /// Installation-scoped audience.
    pub audience: String,
    /// Human-readable installation name.
    pub installation_name: String,
    /// Human-readable local username.
    pub local_username: String,
    /// Installation identity fingerprint.
    pub installation_fingerprint: [u8; 32],
    /// Exact action descriptor.
    pub action: ActionDescriptor,
}

/// Decoded version 2 action-approval response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionApprovalResponse {
    /// Device-controlled response creation time.
    pub issued_at: UnixTimeMillis,
    /// Time of explicit user verification.
    pub user_verified_at: UnixTimeMillis,
    /// Target installation.
    pub installation_id: InstallationId,
    /// Device signing-key identifier.
    pub key_id: KeyId,
    /// Approved challenge identifier.
    pub challenge_id: ChallengeId,
    /// Exact challenge nonce.
    pub nonce: [u8; 32],
    /// SHA-256 digest of exact canonical challenge bytes.
    pub challenge_digest: [u8; 32],
    /// Bound local user.
    pub user_id: UserId,
    /// Approving device.
    pub device_id: DeviceId,
    /// Bound external identity.
    pub external_identity_id: ExternalIdentityId,
    /// Explicit approval or denial.
    pub decision: Decision,
}

/// Encodes a closed version 2 action descriptor.
///
/// # Errors
///
/// Rejects relative paths, unsafe text, unsorted or duplicate collections,
/// excessive collection sizes, and canonical encodings over 16 KiB.
pub fn encode_action_descriptor(value: &ActionDescriptor) -> Result<Vec<u8>, ServiceError> {
    validate_descriptor(value)?;
    let environment = value
        .environment
        .iter()
        .map(|binding| {
            Value::Map(BTreeMap::from([
                (0, Value::Text(binding.name.clone())),
                (1, Value::Text(binding.value.clone())),
            ]))
        })
        .collect();
    let resources = value
        .resources
        .iter()
        .map(|resource| {
            Value::Map(BTreeMap::from([
                (0, Value::Unsigned(resource_kind(resource.kind))),
                (1, Value::Text(resource.identifier.clone())),
                (
                    2,
                    resource
                        .sha256
                        .map_or(Value::Null, |digest| Value::Bytes(digest.to_vec())),
                ),
            ]))
        })
        .collect();
    let bytes = to_vec(&Value::Map(BTreeMap::from([
        (0, Value::Unsigned(VERSION)),
        (1, Value::Text(DESCRIPTOR_PURPOSE.into())),
        (2, Value::Text(value.executable_path.clone())),
        (3, Value::Bytes(value.executable_sha256.to_vec())),
        (
            4,
            Value::Array(value.arguments.iter().cloned().map(Value::Text).collect()),
        ),
        (5, Value::Text(value.working_directory.clone())),
        (6, Value::Array(environment)),
        (7, Value::Array(resources)),
    ])))
    .map_err(invalid)?;
    if bytes.len() > 16 * 1024 {
        return Err(ServiceError::InvalidResponse);
    }
    Ok(bytes)
}

/// Decodes a closed version 2 action descriptor.
///
/// # Errors
///
/// Rejects non-canonical, unknown, missing, ill-typed, unsafe, or excessive
/// fields.
pub fn decode_action_descriptor(bytes: &[u8]) -> Result<ActionDescriptor, ServiceError> {
    let mut fields = from_slice_with_fields(bytes, DESCRIPTOR_FIELDS).map_err(invalid)?;
    require_len(&fields, DESCRIPTOR_FIELDS.len())?;
    require_header(&mut fields, DESCRIPTOR_PURPOSE)?;
    let value = ActionDescriptor {
        executable_path: take_text(&mut fields, 2)?,
        executable_sha256: take_array(&mut fields, 3)?,
        arguments: take_text_array(&mut fields, 4, MAX_ACTION_ARGUMENTS)?,
        working_directory: take_text(&mut fields, 5)?,
        environment: take_environment(&mut fields, 6)?,
        resources: take_resources(&mut fields, 7)?,
    };
    validate_descriptor(&value)?;
    Ok(value)
}

/// Returns the domain-separated digest of a validated action descriptor.
///
/// # Errors
///
/// Returns the same validation failures as [`encode_action_descriptor`].
pub fn action_descriptor_digest(value: &ActionDescriptor) -> Result<[u8; 32], ServiceError> {
    Ok(sha256(&encode_action_descriptor(value)?).into_bytes())
}

/// Encodes a closed version 2 action-approval challenge.
///
/// # Errors
///
/// Rejects invalid descriptor, time, text, or canonical encoding.
pub fn encode_action_challenge(value: &ActionApprovalChallenge) -> Result<Vec<u8>, ServiceError> {
    validate_challenge(value)?;
    let descriptor = encode_action_descriptor(&value.action)?;
    to_vec(&Value::Map(BTreeMap::from([
        (0, Value::Unsigned(VERSION)),
        (1, Value::Text(CHALLENGE_PURPOSE.into())),
        (2, Value::Unsigned(value.issued_at.0)),
        (3, Value::Unsigned(value.expires_at.0)),
        (4, Value::Bytes(value.installation_id.into_bytes().to_vec())),
        (
            5,
            Value::Bytes(value.installation_key_id.into_bytes().to_vec()),
        ),
        (6, Value::Bytes(value.challenge_id.into_bytes().to_vec())),
        (7, Value::Bytes(value.nonce.to_vec())),
        (8, Value::Bytes(value.user_id.into_bytes().to_vec())),
        (
            9,
            Value::Bytes(value.external_identity_id.into_bytes().to_vec()),
        ),
        (10, Value::Text(value.audience.clone())),
        (11, Value::Text(value.installation_name.clone())),
        (12, Value::Text(value.local_username.clone())),
        (13, Value::Bytes(value.installation_fingerprint.to_vec())),
        (14, Value::Bytes(descriptor)),
    ])))
    .map_err(invalid)
}

/// Decodes a closed version 2 action-approval challenge.
///
/// # Errors
///
/// Rejects unknown, missing, non-canonical, substituted, or invalid fields.
pub fn decode_action_challenge(bytes: &[u8]) -> Result<ActionApprovalChallenge, ServiceError> {
    let mut fields = from_slice_with_fields(bytes, CHALLENGE_FIELDS).map_err(invalid)?;
    require_len(&fields, CHALLENGE_FIELDS.len())?;
    require_header(&mut fields, CHALLENGE_PURPOSE)?;
    let value = ActionApprovalChallenge {
        issued_at: UnixTimeMillis(take_u64(&mut fields, 2)?),
        expires_at: UnixTimeMillis(take_u64(&mut fields, 3)?),
        installation_id: InstallationId::from_bytes(take_array(&mut fields, 4)?),
        installation_key_id: KeyId::from_bytes(take_array(&mut fields, 5)?),
        challenge_id: ChallengeId::from_bytes(take_array(&mut fields, 6)?),
        nonce: take_array(&mut fields, 7)?,
        user_id: UserId::from_bytes(take_array(&mut fields, 8)?),
        external_identity_id: ExternalIdentityId::from_bytes(take_array(&mut fields, 9)?),
        audience: take_text(&mut fields, 10)?,
        installation_name: take_text(&mut fields, 11)?,
        local_username: take_text(&mut fields, 12)?,
        installation_fingerprint: take_array(&mut fields, 13)?,
        action: decode_action_descriptor(&take_bytes(&mut fields, 14)?)?,
    };
    validate_challenge(&value)?;
    Ok(value)
}

/// Encodes the response body for an exact action challenge.
///
/// # Errors
///
/// Rejects invalid challenge fields or response time ordering.
pub fn encode_action_response(
    challenge: &ActionApprovalChallenge,
    device_id: DeviceId,
    key_id: KeyId,
    decision: Decision,
    issued_at: UnixTimeMillis,
    user_verified_at: UnixTimeMillis,
) -> Result<Vec<u8>, ServiceError> {
    if issued_at > user_verified_at {
        return Err(ServiceError::InvalidResponse);
    }
    let digest = sha256(&encode_action_challenge(challenge)?).into_bytes();
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
        (8, Value::Bytes(digest.to_vec())),
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

/// Decodes a closed version 2 exact-action response.
///
/// # Errors
///
/// Rejects version, purpose, field, type, width, decision, and time failures.
pub fn decode_action_response(bytes: &[u8]) -> Result<ActionApprovalResponse, ServiceError> {
    let mut fields = from_slice_with_fields(bytes, RESPONSE_FIELDS).map_err(invalid)?;
    require_len(&fields, RESPONSE_FIELDS.len())?;
    require_header(&mut fields, RESPONSE_PURPOSE)?;
    let issued_at = UnixTimeMillis(take_u64(&mut fields, 2)?);
    let user_verified_at = UnixTimeMillis(take_u64(&mut fields, 3)?);
    if issued_at > user_verified_at {
        return Err(ServiceError::InvalidResponse);
    }
    let decision = match take_text(&mut fields, 12)?.as_str() {
        "approved" => Decision::Approve,
        "denied" => Decision::Deny,
        _ => return Err(ServiceError::InvalidResponse),
    };
    Ok(ActionApprovalResponse {
        issued_at,
        user_verified_at,
        installation_id: InstallationId::from_bytes(take_array(&mut fields, 4)?),
        key_id: KeyId::from_bytes(take_array(&mut fields, 5)?),
        challenge_id: ChallengeId::from_bytes(take_array(&mut fields, 6)?),
        nonce: take_array(&mut fields, 7)?,
        challenge_digest: take_array(&mut fields, 8)?,
        user_id: UserId::from_bytes(take_array(&mut fields, 9)?),
        device_id: DeviceId::from_bytes(take_array(&mut fields, 10)?),
        external_identity_id: ExternalIdentityId::from_bytes(take_array(&mut fields, 11)?),
        decision,
    })
}

fn validate_descriptor(value: &ActionDescriptor) -> Result<(), ServiceError> {
    if !absolute_path(&value.executable_path)
        || !absolute_path(&value.working_directory)
        || value.arguments.is_empty()
        || value.arguments.len() > MAX_ACTION_ARGUMENTS
        || value
            .arguments
            .iter()
            .any(|argument| !bounded(argument, 4096, true))
        || value.environment.len() > MAX_ACTION_ENVIRONMENT
        || value.resources.len() > MAX_ACTION_RESOURCES
        || !strictly_sorted(&value.environment)
        || !strictly_sorted(&value.resources)
        || value
            .environment
            .iter()
            .any(|binding| !environment_name(&binding.name) || !bounded(&binding.value, 1024, true))
        || value.resources.iter().any(|resource| {
            !bounded(&resource.identifier, 2048, false)
                || !(resource.identifier.contains(':') || absolute_path(&resource.identifier))
        })
    {
        return Err(ServiceError::InvalidResponse);
    }
    Ok(())
}

fn validate_challenge(value: &ActionApprovalChallenge) -> Result<(), ServiceError> {
    if value.issued_at >= value.expires_at
        || !bounded(&value.audience, 128, false)
        || !bounded(&value.installation_name, 128, false)
        || !bounded(&value.local_username, 128, false)
    {
        return Err(ServiceError::InvalidResponse);
    }
    validate_descriptor(&value.action)
}

fn absolute_path(value: &str) -> bool {
    value.starts_with('/') && bounded(value, 4096, false)
}

fn bounded(value: &str, maximum: usize, allow_empty: bool) -> bool {
    (allow_empty || !value.is_empty())
        && value.len() <= maximum
        && !value.chars().any(char::is_control)
}

fn environment_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'_'))
        && bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        && value.len() <= 128
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn resource_kind(value: ActionResourceKind) -> u64 {
    match value {
        ActionResourceKind::Input => 1,
        ActionResourceKind::Output => 2,
        ActionResourceKind::Reference => 3,
    }
}

fn take_environment(
    fields: &mut BTreeMap<u64, Value>,
    key: u64,
) -> Result<Vec<ActionEnvironment>, ServiceError> {
    take_maps(fields, key, MAX_ACTION_ENVIRONMENT)?
        .into_iter()
        .map(|mut item| {
            require_nested_fields(&item, ENVIRONMENT_FIELDS)?;
            Ok(ActionEnvironment {
                name: take_text(&mut item, 0)?,
                value: take_text(&mut item, 1)?,
            })
        })
        .collect()
}

fn take_resources(
    fields: &mut BTreeMap<u64, Value>,
    key: u64,
) -> Result<Vec<ActionResource>, ServiceError> {
    take_maps(fields, key, MAX_ACTION_RESOURCES)?
        .into_iter()
        .map(|mut item| {
            require_nested_fields(&item, RESOURCE_FIELDS)?;
            let kind = match take_u64(&mut item, 0)? {
                1 => ActionResourceKind::Input,
                2 => ActionResourceKind::Output,
                3 => ActionResourceKind::Reference,
                _ => return Err(ServiceError::InvalidResponse),
            };
            let identifier = take_text(&mut item, 1)?;
            let sha256 = match item.remove(&2) {
                Some(Value::Null) => None,
                Some(Value::Bytes(bytes)) => Some(
                    bytes
                        .try_into()
                        .map_err(|_| ServiceError::InvalidResponse)?,
                ),
                _ => return Err(ServiceError::InvalidResponse),
            };
            Ok(ActionResource {
                kind,
                identifier,
                sha256,
            })
        })
        .collect()
}

fn take_maps(
    fields: &mut BTreeMap<u64, Value>,
    key: u64,
    maximum: usize,
) -> Result<Vec<BTreeMap<u64, Value>>, ServiceError> {
    let Some(Value::Array(items)) = fields.remove(&key) else {
        return Err(ServiceError::InvalidResponse);
    };
    if items.len() > maximum {
        return Err(ServiceError::InvalidResponse);
    }
    items
        .into_iter()
        .map(|item| match item {
            Value::Map(map) => Ok(map),
            _ => Err(ServiceError::InvalidResponse),
        })
        .collect()
}

fn require_nested_fields(
    fields: &BTreeMap<u64, Value>,
    expected: &[u64],
) -> Result<(), ServiceError> {
    let actual: BTreeSet<u64> = fields.keys().copied().collect();
    let expected: BTreeSet<u64> = expected.iter().copied().collect();
    if actual == expected {
        Ok(())
    } else {
        Err(ServiceError::InvalidResponse)
    }
}

fn take_text_array(
    fields: &mut BTreeMap<u64, Value>,
    key: u64,
    maximum: usize,
) -> Result<Vec<String>, ServiceError> {
    let Some(Value::Array(items)) = fields.remove(&key) else {
        return Err(ServiceError::InvalidResponse);
    };
    if items.len() > maximum {
        return Err(ServiceError::InvalidResponse);
    }
    items
        .into_iter()
        .map(|item| match item {
            Value::Text(text) => Ok(text),
            _ => Err(ServiceError::InvalidResponse),
        })
        .collect()
}

fn require_len(fields: &BTreeMap<u64, Value>, expected: usize) -> Result<(), ServiceError> {
    if fields.len() == expected {
        Ok(())
    } else {
        Err(ServiceError::InvalidResponse)
    }
}

fn require_header(fields: &mut BTreeMap<u64, Value>, purpose: &str) -> Result<(), ServiceError> {
    if take_u64(fields, 0)? != VERSION || take_text(fields, 1)? != purpose {
        Err(ServiceError::InvalidResponse)
    } else {
        Ok(())
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

fn invalid(_: impl std::fmt::Debug) -> ServiceError {
    ServiceError::InvalidResponse
}
