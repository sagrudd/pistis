//! Strict `COSE_Sign1` production profile for Pistis.
//!
//! The profile has one accepted representation: an untagged `COSE_Sign1` array
//! with protected `alg` and `kid`, no unprotected headers, an embedded
//! canonical payload, and a fixed-width ES256 signature. The external
//! additional authenticated data is always empty.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use pistis_canonical::{CanonicalError, Value, from_slice, to_vec};
use pistis_crypto::{PublicKey, SignatureError, SignatureSuite, derive_key_id, verify};
use pistis_domain::KeyId;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

const HEADER_ALGORITHM: u64 = 1;
const HEADER_KEY_ID: u64 = 4;
const ES256: i64 = -7;
const SIGNATURE_BYTES: usize = 64;
const SIGNATURE_CONTEXT: &str = "Signature1";

/// A decoded Pistis `COSE_Sign1` envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sign1 {
    protected: Vec<u8>,
    key_id: KeyId,
    payload: Vec<u8>,
    signature: [u8; SIGNATURE_BYTES],
}

impl Sign1 {
    /// Return the signing key identifier carried in the protected headers.
    #[must_use]
    pub const fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// Return the exact embedded canonical payload bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Return the fixed-width low-S signature bytes.
    #[must_use]
    pub fn signature(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.signature
    }

    fn signing_input(&self) -> Result<Vec<u8>, CoseError> {
        encode_signature_structure(&self.protected, &self.payload)
    }
}

/// A production-envelope validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoseError {
    /// The envelope is malformed, non-canonical, unsupported, or oversized.
    InvalidEnvelope,
    /// The protected key identifier does not identify the supplied key.
    KeyMismatch,
    /// The ES256 signature failed strict verification.
    Signature(SignatureError),
}

impl fmt::Display for CoseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEnvelope => formatter.write_str("invalid COSE_Sign1 envelope"),
            Self::KeyMismatch => formatter.write_str("COSE signing key mismatch"),
            Self::Signature(error) => error.fmt(formatter),
        }
    }
}

impl Error for CoseError {}

impl From<CanonicalError> for CoseError {
    fn from(_: CanonicalError) -> Self {
        Self::InvalidEnvelope
    }
}

/// Produce the exact bytes a Pistis ES256 signer must sign.
///
/// This encodes the RFC 9052 `Sig_structure` with context `Signature1`, the
/// profile's protected headers, empty external AAD, and the exact payload.
///
/// # Errors
///
/// Returns [`CoseError::InvalidEnvelope`] when the resulting structure exceeds
/// the canonical encoding bounds.
pub fn signing_input(payload: &[u8], key_id: KeyId) -> Result<Vec<u8>, CoseError> {
    validate_payload(payload)?;
    encode_signature_structure(&protected_headers(key_id)?, payload)
}

/// Assemble a Pistis `COSE_Sign1` envelope from an externally produced signature.
///
/// The caller must sign the bytes returned by [`signing_input`] for the same
/// payload and key identifier. Signature verification remains mandatory at
/// every trust boundary.
///
/// # Errors
///
/// Rejects a non-canonical payload, a signature of the wrong width, or an
/// envelope that exceeds canonical encoding bounds.
pub fn encode(payload: &[u8], key_id: KeyId, signature: &[u8]) -> Result<Vec<u8>, CoseError> {
    validate_payload(payload)?;
    let signature: [u8; SIGNATURE_BYTES] = signature
        .try_into()
        .map_err(|_| CoseError::InvalidEnvelope)?;
    to_vec(&Value::Array(vec![
        Value::Bytes(protected_headers(key_id)?),
        Value::Map(BTreeMap::new()),
        Value::Bytes(payload.to_vec()),
        Value::Bytes(signature.to_vec()),
    ]))
    .map_err(Into::into)
}

/// Decode one strict Pistis `COSE_Sign1` envelope without verifying its signature.
///
/// Decode is useful only for bounded inspection. Call [`verify_sign1`] before
/// relying on the payload or protected key identifier.
///
/// # Errors
///
/// Rejects tagged, detached, non-canonical, oversized, trailing, incomplete,
/// or structurally different envelopes and any unsupported header.
pub fn decode(bytes: &[u8]) -> Result<Sign1, CoseError> {
    let Value::Array(mut items) = from_slice(bytes)? else {
        return Err(CoseError::InvalidEnvelope);
    };
    if items.len() != 4 {
        return Err(CoseError::InvalidEnvelope);
    }
    let signature = take_bytes(items.pop())?;
    let payload = take_bytes(items.pop())?;
    let Some(Value::Map(unprotected)) = items.pop() else {
        return Err(CoseError::InvalidEnvelope);
    };
    if !unprotected.is_empty() {
        return Err(CoseError::InvalidEnvelope);
    }
    let protected = take_bytes(items.pop())?;
    let key_id = decode_protected(&protected)?;
    validate_payload(&payload)?;
    let signature = signature
        .try_into()
        .map_err(|_| CoseError::InvalidEnvelope)?;
    Ok(Sign1 {
        protected,
        key_id,
        payload,
        signature,
    })
}

/// Decode and cryptographically verify a strict Pistis `COSE_Sign1` envelope.
///
/// Verification derives the Pistis key identifier from `key`, compares it
/// with the protected `kid`, reconstructs the exact `Sig_structure`, and
/// requires a fixed-width low-S ES256 signature.
///
/// # Errors
///
/// Returns [`CoseError::KeyMismatch`] for key substitution and
/// [`CoseError::Signature`] for malformed, high-S, or invalid signatures.
pub fn verify_sign1(bytes: &[u8], key: &PublicKey) -> Result<Sign1, CoseError> {
    let envelope = decode(bytes)?;
    if envelope.key_id != derive_key_id(key) {
        return Err(CoseError::KeyMismatch);
    }
    verify(
        SignatureSuite::Es256,
        key,
        &envelope.signing_input()?,
        &envelope.signature,
    )
    .map_err(CoseError::Signature)?;
    Ok(envelope)
}

fn protected_headers(key_id: KeyId) -> Result<Vec<u8>, CoseError> {
    to_vec(&Value::Map(BTreeMap::from([
        (HEADER_ALGORITHM, Value::Negative(ES256)),
        (HEADER_KEY_ID, Value::Bytes(key_id.into_bytes().to_vec())),
    ])))
    .map_err(Into::into)
}

fn decode_protected(bytes: &[u8]) -> Result<KeyId, CoseError> {
    let Value::Map(mut headers) = from_slice(bytes)? else {
        return Err(CoseError::InvalidEnvelope);
    };
    if headers.len() != 2 || headers.remove(&HEADER_ALGORITHM) != Some(Value::Negative(ES256)) {
        return Err(CoseError::InvalidEnvelope);
    }
    let Some(Value::Bytes(key_id)) = headers.remove(&HEADER_KEY_ID) else {
        return Err(CoseError::InvalidEnvelope);
    };
    if !headers.is_empty() {
        return Err(CoseError::InvalidEnvelope);
    }
    let key_id = key_id.try_into().map_err(|_| CoseError::InvalidEnvelope)?;
    Ok(KeyId::from_bytes(key_id))
}

fn encode_signature_structure(protected: &[u8], payload: &[u8]) -> Result<Vec<u8>, CoseError> {
    to_vec(&Value::Array(vec![
        Value::Text(SIGNATURE_CONTEXT.into()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.to_vec()),
    ]))
    .map_err(Into::into)
}

fn validate_payload(payload: &[u8]) -> Result<(), CoseError> {
    from_slice(payload)
        .map(|_| ())
        .map_err(|_| CoseError::InvalidEnvelope)
}

fn take_bytes(value: Option<Value>) -> Result<Vec<u8>, CoseError> {
    match value {
        Some(Value::Bytes(bytes)) => Ok(bytes),
        _ => Err(CoseError::InvalidEnvelope),
    }
}
