//! Accepted ADR 0029 version-4/kind-3 first-device QR framing.

use crate::frame::{
    CHECKSUM_HEX_BYTES, MAX_TRANSFER_TEXT_BYTES, PREFIX, QrError, append_hex, checksum,
    decode_checksum,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use pistis_canonical::{Value, from_slice_with_fields, to_vec};
use std::{collections::BTreeMap, fmt};

const VERSION: u64 = 4;
const KIND: u64 = 3;
const FIELDS: &[u64] = &[0, 1, 2, 3];
const MAX_BUNDLE_BYTES: usize = 512;

/// Borrowed exact signed presentation and purpose-separated authority bundle.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct EnrolmentTransferRef<'a> {
    /// Exact untagged COSE Sign1 invitation-presentation envelope.
    pub presentation_cose: &'a [u8],
    /// Exact canonical authority bundle bytes.
    pub authority_bundle: &'a [u8],
}

impl fmt::Debug for EnrolmentTransferRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnrolmentTransferRef")
            .field("presentation_cose_length", &self.presentation_cose.len())
            .field("authority_bundle_length", &self.authority_bundle.len())
            .finish()
    }
}

/// Exact binary material decoded from a version-4/kind-3 transfer.
#[derive(Clone, Eq, PartialEq)]
pub struct EnrolmentTransfer {
    /// Exact untagged COSE Sign1 invitation-presentation envelope.
    pub presentation_cose: Vec<u8>,
    /// Exact canonical authority bundle bytes.
    pub authority_bundle: Vec<u8>,
}

impl fmt::Debug for EnrolmentTransfer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnrolmentTransfer")
            .field("presentation_cose_length", &self.presentation_cose.len())
            .field("authority_bundle_length", &self.authority_bundle.len())
            .finish()
    }
}

/// Encode one distinct first-device QR transfer.
///
/// This function validates only framing and the strict COSE shape. Authority,
/// signature, invitation, identity, origin, and time verification remain
/// mandatory at the protocol boundary.
///
/// # Errors
///
/// Rejects malformed COSE, oversized descriptor material, or a frame that
/// cannot fit the accepted single-symbol text bound.
pub fn encode_enrolment(transfer: EnrolmentTransferRef<'_>) -> Result<String, QrError> {
    pistis_cose::decode(transfer.presentation_cose).map_err(|_| QrError::InvalidEnvelope)?;
    if transfer.authority_bundle.is_empty() || transfer.authority_bundle.len() > MAX_BUNDLE_BYTES {
        return Err(QrError::TooLarge);
    }
    let frame = to_vec(&Value::Map(BTreeMap::from([
        (0, Value::Unsigned(VERSION)),
        (1, Value::Unsigned(KIND)),
        (2, Value::Bytes(transfer.presentation_cose.to_vec())),
        (3, Value::Bytes(transfer.authority_bundle.to_vec())),
    ])))
    .map_err(|_| QrError::InvalidFrame)?;
    encode_frame(&frame)
}

/// Validate and encode the exact binary outer frame received through the
/// protected producer pipe.
///
/// # Errors
///
/// Rejects a non-canonical map, wrong version or kind, invalid nested
/// materials, or an oversized transfer.
pub fn encode_enrolment_frame(frame: &[u8]) -> Result<String, QrError> {
    let mut fields = from_slice_with_fields(frame, FIELDS).map_err(|_| QrError::InvalidFrame)?;
    if fields.len() != FIELDS.len()
        || fields.remove(&0) != Some(Value::Unsigned(VERSION))
        || fields.remove(&1) != Some(Value::Unsigned(KIND))
    {
        return Err(QrError::InvalidFrame);
    }
    let Some(Value::Bytes(presentation_cose)) = fields.remove(&2) else {
        return Err(QrError::InvalidFrame);
    };
    let Some(Value::Bytes(authority_bundle)) = fields.remove(&3) else {
        return Err(QrError::InvalidFrame);
    };
    encode_enrolment(EnrolmentTransferRef {
        presentation_cose: &presentation_cose,
        authority_bundle: &authority_bundle,
    })
}

/// Decode only a version-4/kind-3 first-device QR transfer.
///
/// Authentication QR decoders do not call this function and continue to
/// reject version 4 and kind 3.
///
/// # Errors
///
/// Rejects all malformed, corrupted, oversized, downgraded, wrong-kind, or
/// invalid-COSE input.
pub fn decode_enrolment(input: &str) -> Result<EnrolmentTransfer, QrError> {
    let frame = decode_frame(input)?;
    let mut fields = from_slice_with_fields(&frame, FIELDS).map_err(|_| QrError::InvalidFrame)?;
    if fields.len() != FIELDS.len() {
        return Err(QrError::InvalidFrame);
    }
    match fields.remove(&0) {
        Some(Value::Unsigned(VERSION)) => {}
        Some(Value::Unsigned(_)) => return Err(QrError::UnsupportedVersion),
        _ => return Err(QrError::InvalidFrame),
    }
    match fields.remove(&1) {
        Some(Value::Unsigned(KIND)) => {}
        Some(Value::Unsigned(_)) => return Err(QrError::UnsupportedKind),
        _ => return Err(QrError::InvalidFrame),
    }
    let Some(Value::Bytes(presentation_cose)) = fields.remove(&2) else {
        return Err(QrError::InvalidFrame);
    };
    let Some(Value::Bytes(authority_bundle)) = fields.remove(&3) else {
        return Err(QrError::InvalidFrame);
    };
    if authority_bundle.is_empty() || authority_bundle.len() > MAX_BUNDLE_BYTES {
        return Err(QrError::TooLarge);
    }
    pistis_cose::decode(&presentation_cose).map_err(|_| QrError::InvalidEnvelope)?;
    Ok(EnrolmentTransfer {
        presentation_cose,
        authority_bundle,
    })
}

fn encode_frame(frame: &[u8]) -> Result<String, QrError> {
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

fn decode_frame(input: &str) -> Result<Vec<u8>, QrError> {
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
    URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|_| QrError::InvalidAlphabet)
}
