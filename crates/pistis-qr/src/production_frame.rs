//! Accepted ADR 0021 production QR outer frame.

use crate::frame::{
    CHECKSUM_HEX_BYTES, MAX_TRANSFER_TEXT_BYTES, PREFIX, QrError, TransferKind, append_hex,
    checksum, decode_checksum,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use pistis_canonical::{Value, from_slice_with_fields, to_vec};
use std::collections::BTreeMap;

const PRODUCTION_VERSION: u64 = 2;
const PRODUCTION_FIELDS: &[u64] = &[0, 1, 2];

/// Maximum accepted complete untagged COSE Sign1 envelope length.
pub const MAX_COSE_ENVELOPE_BYTES: usize = 2_048;

/// Borrowed production COSE material carried by a version-2 transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductionTransferRef<'a> {
    /// Separates authentication challenges from signed device responses.
    pub kind: TransferKind,
    /// Exact complete untagged COSE Sign1 bytes.
    pub cose: &'a [u8],
}

/// Encode exact COSE Sign1 bytes as an accepted production QR transfer.
///
/// The scanning checksum detects corruption only. Callers must verify the
/// returned COSE bytes independently.
///
/// # Errors
///
/// Rejects an invalid strict Pistis COSE envelope or a transfer that exceeds
/// either the envelope or single-symbol text bound.
pub fn encode_production(transfer: ProductionTransferRef<'_>) -> Result<String, QrError> {
    validate_cose(transfer.cose)?;
    let frame = to_vec(&Value::Map(BTreeMap::from([
        (0, Value::Unsigned(PRODUCTION_VERSION)),
        (1, Value::Unsigned(transfer.kind as u64)),
        (2, Value::Bytes(transfer.cose.to_vec())),
    ])))
    .map_err(|_| QrError::InvalidFrame)?;
    let body = URL_SAFE_NO_PAD.encode(frame);
    let mut output = String::with_capacity(PREFIX.len() + body.len() + 1 + CHECKSUM_HEX_BYTES);
    output.push_str(PREFIX);
    output.push_str(&body);
    output.push('.');
    append_hex(&mut output, &checksum(&body));
    if output.len() > MAX_TRANSFER_TEXT_BYTES {
        return Err(QrError::TooLarge);
    }
    Ok(output)
}

/// Decode an accepted production transfer and return its exact COSE bytes.
///
/// Bounds, ASCII, alphabet, and checksum are checked before canonical CBOR
/// parsing. Version and expected kind precede strict COSE-profile validation.
///
/// # Errors
///
/// Returns a classified fail-closed error for malformed, corrupted,
/// unsupported, oversized, wrong-kind, or invalid-COSE input.
pub fn decode_production(input: &str, expected: TransferKind) -> Result<Vec<u8>, QrError> {
    if input.len() > MAX_TRANSFER_TEXT_BYTES {
        return Err(QrError::TooLarge);
    }
    if !input.is_ascii() {
        return Err(QrError::NonAscii);
    }
    let remainder = input.strip_prefix(PREFIX).ok_or(QrError::InvalidPrefix)?;
    let (body, checksum_text) = remainder
        .rsplit_once('.')
        .ok_or(QrError::InvalidStructure)?;
    if body.is_empty() || checksum_text.len() != CHECKSUM_HEX_BYTES {
        return Err(QrError::InvalidStructure);
    }
    if body.contains('=')
        || !body
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        || !checksum_text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(QrError::InvalidAlphabet);
    }
    if checksum(body) != decode_checksum(checksum_text)? {
        return Err(QrError::ChecksumMismatch);
    }
    let frame = URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|_| QrError::InvalidAlphabet)?;
    let mut fields =
        from_slice_with_fields(&frame, PRODUCTION_FIELDS).map_err(|_| QrError::InvalidFrame)?;
    if fields.len() != PRODUCTION_FIELDS.len() {
        return Err(QrError::InvalidFrame);
    }
    match fields.remove(&0) {
        Some(Value::Unsigned(PRODUCTION_VERSION)) => {}
        Some(Value::Unsigned(_)) => return Err(QrError::UnsupportedVersion),
        _ => return Err(QrError::InvalidFrame),
    }
    let kind = match fields.remove(&1) {
        Some(Value::Unsigned(value)) => TransferKind::parse(value)?,
        _ => return Err(QrError::InvalidFrame),
    };
    if kind != expected {
        return Err(QrError::UnsupportedKind);
    }
    let Some(Value::Bytes(cose)) = fields.remove(&2) else {
        return Err(QrError::InvalidFrame);
    };
    validate_cose(&cose)?;
    Ok(cose)
}

fn validate_cose(cose: &[u8]) -> Result<(), QrError> {
    if cose.len() > MAX_COSE_ENVELOPE_BYTES {
        return Err(QrError::TooLarge);
    }
    pistis_cose::decode(cose)
        .map(|_| ())
        .map_err(|_| QrError::InvalidEnvelope)
}
