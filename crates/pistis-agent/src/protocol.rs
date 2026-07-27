use pistis_canonical::{Value, from_slice_with_fields, to_vec};
use std::{collections::BTreeMap, error::Error, fmt};

const VERSION: u64 = 1;
const REQUEST_PURPOSE: &str = "pistis.local-agent-request.v1";
const RESPONSE_PURPOSE: &str = "pistis.local-agent-response.v1";
const TOP_FIELDS: &[u64] = &[0, 1, 2, 3];
const PENDING_FIELDS: &[u64] = &[0, 1, 2, 3, 4, 5];
const MAX_ARGUMENTS: usize = 128;
const MAX_TRANSFER: usize = 2_331;

/// Opaque per-ceremony local-agent reference.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AgentReference([u8; 32]);

impl AgentReference {
    /// Constructs a reference from cryptographically random bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns reference bytes for durable lookup and socket encoding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// One closed request accepted by the local agent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentRequest {
    /// Begin version 1 session authentication.
    BeginLogin,
    /// Begin version 2 exact-action approval from the exact argument vector.
    BeginAction {
        /// Ordered arguments, including argument zero.
        arguments: Vec<String>,
    },
    /// Query coarse direct-local status.
    Status {
        /// Opaque local reference.
        reference: AgentReference,
    },
    /// Submit one terminal-framed signed mobile response.
    Submit {
        /// Opaque local reference.
        reference: AgentReference,
        /// Exact control-free `PISTIS1` response transfer.
        transfer: String,
    },
    /// Cancel a pending ceremony.
    Cancel {
        /// Opaque local reference.
        reference: AgentReference,
    },
}

/// Public challenge presentation returned only after durable creation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingChallenge {
    /// Opaque local reference that must not be displayed.
    pub reference: AgentReference,
    /// Exact signed `PISTIS1` challenge transfer.
    pub challenge_transfer: String,
    /// Reviewed installation display name.
    pub installation_name: String,
    /// Printable installation fingerprint.
    pub installation_fingerprint: String,
    /// Human-readable signed purpose.
    pub purpose: String,
    /// Exclusive expiry in Unix milliseconds.
    pub expires_at_millis: u64,
}

/// Coarse ceremony state returned to the CLI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentStatus {
    /// No verified response is available yet.
    Pending,
    /// Authentication or approval completed.
    Completed,
    /// Mobile user explicitly denied.
    Denied,
    /// Authoritative expiry was reached.
    Expired,
}

/// Coarse public agent failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentFailure {
    /// Request schema or response transfer was rejected.
    Rejected,
    /// No configured installation or signing provider exists.
    Unavailable,
    /// Request conflicts with terminal or consumed state.
    Conflict,
}

/// One closed response emitted by the local agent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentResponse {
    /// Newly created signed challenge.
    Pending(PendingChallenge),
    /// Coarse lifecycle result.
    Status(AgentStatus),
    /// Cancellation completed without returning state.
    Acknowledged,
    /// Coarse fail-closed error.
    Failure(AgentFailure),
}

/// Local-agent semantic protocol failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolError;

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("local agent protocol rejected")
    }
}

impl Error for ProtocolError {}

/// Encodes one closed canonical local-agent request.
///
/// # Errors
///
/// Rejects excessive, empty, or control-bearing arguments and transfers.
pub fn encode_request(request: &AgentRequest) -> Result<Vec<u8>, ProtocolError> {
    let (operation, body) = match request {
        AgentRequest::BeginLogin => (1, Value::Null),
        AgentRequest::BeginAction { arguments } => {
            validate_arguments(arguments)?;
            (
                2,
                Value::Array(arguments.iter().cloned().map(Value::Text).collect()),
            )
        }
        AgentRequest::Status { reference } => (3, Value::Bytes(reference.as_bytes().to_vec())),
        AgentRequest::Submit {
            reference,
            transfer,
        } => {
            validate_transfer(transfer)?;
            (
                4,
                Value::Array(vec![
                    Value::Bytes(reference.as_bytes().to_vec()),
                    Value::Text(transfer.clone()),
                ]),
            )
        }
        AgentRequest::Cancel { reference } => (5, Value::Bytes(reference.as_bytes().to_vec())),
    };
    envelope(REQUEST_PURPOSE, operation, body)
}

/// Decodes one closed canonical local-agent request.
///
/// # Errors
///
/// Rejects unknown operations or fields, non-canonical input, invalid widths,
/// unsafe text, excessive collections, and wrong version or purpose.
pub fn decode_request(bytes: &[u8]) -> Result<AgentRequest, ProtocolError> {
    let (operation, body) = decode_envelope(bytes, REQUEST_PURPOSE)?;
    match (operation, body) {
        (1, Value::Null) => Ok(AgentRequest::BeginLogin),
        (2, Value::Array(items)) => {
            let arguments = text_array(items)?;
            validate_arguments(&arguments)?;
            Ok(AgentRequest::BeginAction { arguments })
        }
        (3, Value::Bytes(reference)) => Ok(AgentRequest::Status {
            reference: AgentReference(take_array(reference)?),
        }),
        (4, Value::Array(mut items)) if items.len() == 2 => {
            let Value::Text(transfer) = items.pop().ok_or(ProtocolError)? else {
                return Err(ProtocolError);
            };
            let Value::Bytes(reference) = items.pop().ok_or(ProtocolError)? else {
                return Err(ProtocolError);
            };
            validate_transfer(&transfer)?;
            Ok(AgentRequest::Submit {
                reference: AgentReference(take_array(reference)?),
                transfer,
            })
        }
        (5, Value::Bytes(reference)) => Ok(AgentRequest::Cancel {
            reference: AgentReference(take_array(reference)?),
        }),
        _ => Err(ProtocolError),
    }
}

/// Encodes one closed canonical local-agent response.
///
/// # Errors
///
/// Rejects unsafe or excessive pending-challenge display fields.
pub fn encode_response(response: &AgentResponse) -> Result<Vec<u8>, ProtocolError> {
    let (operation, body) = match response {
        AgentResponse::Pending(pending) => {
            validate_pending(pending)?;
            (
                1,
                Value::Map(BTreeMap::from([
                    (0, Value::Bytes(pending.reference.as_bytes().to_vec())),
                    (1, Value::Text(pending.challenge_transfer.clone())),
                    (2, Value::Text(pending.installation_name.clone())),
                    (3, Value::Text(pending.installation_fingerprint.clone())),
                    (4, Value::Text(pending.purpose.clone())),
                    (5, Value::Unsigned(pending.expires_at_millis)),
                ])),
            )
        }
        AgentResponse::Status(status) => (2, Value::Unsigned(status_code(*status))),
        AgentResponse::Acknowledged => (3, Value::Null),
        AgentResponse::Failure(failure) => (4, Value::Unsigned(failure_code(*failure))),
    };
    envelope(RESPONSE_PURPOSE, operation, body)
}

/// Decodes one closed canonical local-agent response.
///
/// # Errors
///
/// Rejects unknown operations, states, errors or fields, invalid widths,
/// unsafe text, non-canonical input, and wrong version or purpose.
pub fn decode_response(bytes: &[u8]) -> Result<AgentResponse, ProtocolError> {
    let (operation, body) = decode_envelope(bytes, RESPONSE_PURPOSE)?;
    match (operation, body) {
        (1, Value::Map(mut fields)) => {
            if fields.keys().copied().collect::<Vec<_>>() != PENDING_FIELDS {
                return Err(ProtocolError);
            }
            let pending = PendingChallenge {
                reference: AgentReference(take_array(take_bytes(&mut fields, 0)?)?),
                challenge_transfer: take_text(&mut fields, 1)?,
                installation_name: take_text(&mut fields, 2)?,
                installation_fingerprint: take_text(&mut fields, 3)?,
                purpose: take_text(&mut fields, 4)?,
                expires_at_millis: take_unsigned(&mut fields, 5)?,
            };
            validate_pending(&pending)?;
            Ok(AgentResponse::Pending(pending))
        }
        (2, Value::Unsigned(code)) => Ok(AgentResponse::Status(match code {
            1 => AgentStatus::Pending,
            2 => AgentStatus::Completed,
            3 => AgentStatus::Denied,
            4 => AgentStatus::Expired,
            _ => return Err(ProtocolError),
        })),
        (3, Value::Null) => Ok(AgentResponse::Acknowledged),
        (4, Value::Unsigned(code)) => Ok(AgentResponse::Failure(match code {
            1 => AgentFailure::Rejected,
            2 => AgentFailure::Unavailable,
            3 => AgentFailure::Conflict,
            _ => return Err(ProtocolError),
        })),
        _ => Err(ProtocolError),
    }
}

fn envelope(purpose: &str, operation: u64, body: Value) -> Result<Vec<u8>, ProtocolError> {
    to_vec(&Value::Map(BTreeMap::from([
        (0, Value::Unsigned(VERSION)),
        (1, Value::Text(purpose.into())),
        (2, Value::Unsigned(operation)),
        (3, body),
    ])))
    .map_err(|_| ProtocolError)
}

fn decode_envelope(bytes: &[u8], purpose: &str) -> Result<(u64, Value), ProtocolError> {
    let mut fields = from_slice_with_fields(bytes, TOP_FIELDS).map_err(|_| ProtocolError)?;
    if fields.len() != TOP_FIELDS.len()
        || take_unsigned(&mut fields, 0)? != VERSION
        || take_text(&mut fields, 1)? != purpose
    {
        return Err(ProtocolError);
    }
    let operation = take_unsigned(&mut fields, 2)?;
    let body = fields.remove(&3).ok_or(ProtocolError)?;
    Ok((operation, body))
}

fn validate_arguments(arguments: &[String]) -> Result<(), ProtocolError> {
    if arguments.is_empty()
        || arguments.len() > MAX_ARGUMENTS
        || arguments
            .iter()
            .any(|value| value.len() > 4_096 || value.chars().any(char::is_control))
    {
        Err(ProtocolError)
    } else {
        Ok(())
    }
}

fn validate_transfer(value: &str) -> Result<(), ProtocolError> {
    if value.is_empty()
        || value.len() > MAX_TRANSFER
        || !value.is_ascii()
        || value.chars().any(char::is_control)
        || !value.starts_with("PISTIS1:")
    {
        Err(ProtocolError)
    } else {
        Ok(())
    }
}

fn validate_pending(value: &PendingChallenge) -> Result<(), ProtocolError> {
    validate_transfer(&value.challenge_transfer)?;
    for text in [
        &value.installation_name,
        &value.installation_fingerprint,
        &value.purpose,
    ] {
        if text.is_empty() || text.len() > 256 || text.chars().any(char::is_control) {
            return Err(ProtocolError);
        }
    }
    Ok(())
}

fn text_array(items: Vec<Value>) -> Result<Vec<String>, ProtocolError> {
    items
        .into_iter()
        .map(|item| match item {
            Value::Text(value) => Ok(value),
            _ => Err(ProtocolError),
        })
        .collect()
}

fn take_array<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], ProtocolError> {
    bytes.try_into().map_err(|_| ProtocolError)
}

fn take_bytes(fields: &mut BTreeMap<u64, Value>, key: u64) -> Result<Vec<u8>, ProtocolError> {
    match fields.remove(&key) {
        Some(Value::Bytes(value)) => Ok(value),
        _ => Err(ProtocolError),
    }
}

fn take_text(fields: &mut BTreeMap<u64, Value>, key: u64) -> Result<String, ProtocolError> {
    match fields.remove(&key) {
        Some(Value::Text(value)) => Ok(value),
        _ => Err(ProtocolError),
    }
}

fn take_unsigned(fields: &mut BTreeMap<u64, Value>, key: u64) -> Result<u64, ProtocolError> {
    match fields.remove(&key) {
        Some(Value::Unsigned(value)) => Ok(value),
        _ => Err(ProtocolError),
    }
}

const fn status_code(status: AgentStatus) -> u64 {
    match status {
        AgentStatus::Pending => 1,
        AgentStatus::Completed => 2,
        AgentStatus::Denied => 3,
        AgentStatus::Expired => 4,
    }
}

const fn failure_code(failure: AgentFailure) -> u64 {
    match failure {
        AgentFailure::Rejected => 1,
        AgentFailure::Unavailable => 2,
        AgentFailure::Conflict => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pistis_canonical::{Value, from_slice, to_vec};

    fn reference() -> AgentReference {
        AgentReference::from_bytes([7; 32])
    }

    #[test]
    fn every_request_round_trips() {
        for request in [
            AgentRequest::BeginLogin,
            AgentRequest::BeginAction {
                arguments: vec!["samtools".into(), "view".into(), "sample.bam".into()],
            },
            AgentRequest::Status {
                reference: reference(),
            },
            AgentRequest::Submit {
                reference: reference(),
                transfer: "PISTIS1:response.checksum".into(),
            },
            AgentRequest::Cancel {
                reference: reference(),
            },
        ] {
            assert_eq!(
                decode_request(&encode_request(&request).unwrap()),
                Ok(request)
            );
        }
    }

    #[test]
    fn every_response_round_trips() {
        let pending = AgentResponse::Pending(PendingChallenge {
            reference: reference(),
            challenge_transfer: "PISTIS1:challenge.checksum".into(),
            installation_name: "Workstation".into(),
            installation_fingerprint: "12:34".into(),
            purpose: "authenticate terminal".into(),
            expires_at_millis: 42,
        });
        for response in [
            pending,
            AgentResponse::Status(AgentStatus::Pending),
            AgentResponse::Status(AgentStatus::Completed),
            AgentResponse::Status(AgentStatus::Denied),
            AgentResponse::Status(AgentStatus::Expired),
            AgentResponse::Acknowledged,
            AgentResponse::Failure(AgentFailure::Rejected),
            AgentResponse::Failure(AgentFailure::Unavailable),
            AgentResponse::Failure(AgentFailure::Conflict),
        ] {
            assert_eq!(
                decode_response(&encode_response(&response).unwrap()),
                Ok(response)
            );
        }
    }

    #[test]
    fn unknown_fields_operations_controls_and_oversize_fail_closed() {
        let encoded = encode_request(&AgentRequest::BeginLogin).unwrap();
        let Value::Map(mut fields) = from_slice(&encoded).unwrap() else {
            panic!("request must be a map");
        };
        fields.insert(99, Value::Null);
        assert!(decode_request(&to_vec(&Value::Map(fields)).unwrap()).is_err());

        let request = AgentRequest::BeginAction {
            arguments: vec!["bad\u{1b}[2J".into()],
        };
        assert!(encode_request(&request).is_err());
        let request = AgentRequest::Submit {
            reference: reference(),
            transfer: format!("PISTIS1:{}", "a".repeat(MAX_TRANSFER)),
        };
        assert!(encode_request(&request).is_err());
    }
}
