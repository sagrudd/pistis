use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use pistis_canonical::{CanonicalError, Value, from_slice, from_slice_with_fields, to_vec};
use pistis_crypto::sha256;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

pub(crate) const PREFIX: &str = "PISTIS1:";
const VERSION: u64 = 1;
const CHECKSUM_BYTES: usize = 8;
pub(crate) const CHECKSUM_HEX_BYTES: usize = CHECKSUM_BYTES * 2;
const FRAME_FIELDS: &[u64] = &[0, 1, 2, 3];

/// Maximum accepted text length for one version-40 QR symbol at EC level M.
pub const MAX_TRANSFER_TEXT_BYTES: usize = 2_331;
/// Maximum exact signed-payload length in a transport frame.
pub const MAX_PAYLOAD_BYTES: usize = 2_048;
/// Required fixed-width detached ES256 signature length.
pub const SIGNATURE_BYTES: usize = 64;

/// The domain-separated object carried by a transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum TransferKind {
    /// An installation-signed authentication challenge.
    Challenge = 1,
    /// A device-signed authentication response.
    Response = 2,
}

impl TransferKind {
    pub(crate) fn parse(value: u64) -> Result<Self, QrError> {
        match value {
            1 => Ok(Self::Challenge),
            2 => Ok(Self::Response),
            _ => Err(QrError::UnsupportedKind),
        }
    }
}

/// Borrowed signed material returned by callers or a decoded transfer.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct TransferRef<'a> {
    /// Separates challenge and response frames.
    pub kind: TransferKind,
    /// Exact canonical protocol payload bytes.
    pub payload: &'a [u8],
    /// Detached fixed-width ES256 signature bytes.
    pub signature: &'a [u8],
}

impl fmt::Debug for TransferRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransferRef")
            .field("kind", &self.kind)
            .field("payload_length", &self.payload.len())
            .field("signature_length", &self.signature.len())
            .finish()
    }
}

/// A bounded QR framing, parsing, or rendering failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QrError {
    /// The transfer or payload exceeds its protocol bound.
    TooLarge,
    /// The supplied text contains non-ASCII data.
    NonAscii,
    /// The protocol prefix is absent or incorrect.
    InvalidPrefix,
    /// The transfer separator or checksum width is invalid.
    InvalidStructure,
    /// The encoded body contains padding or a non-base64url character.
    InvalidAlphabet,
    /// The transfer checksum does not match its body.
    ChecksumMismatch,
    /// The deterministic CBOR frame is malformed or non-canonical.
    InvalidFrame,
    /// The selected transport version is unsupported.
    UnsupportedVersion,
    /// The selected frame kind is unsupported or unexpected.
    UnsupportedKind,
    /// The detached signature has the wrong width.
    InvalidSignature,
    /// The production COSE Sign1 envelope is malformed or unsupported.
    InvalidEnvelope,
    /// The QR encoder cannot represent the transfer at EC level M.
    Unrepresentable,
}

impl fmt::Display for QrError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TooLarge => "QR transfer exceeds its size bound",
            Self::NonAscii => "QR transfer is not ASCII",
            Self::InvalidPrefix => "invalid QR transfer prefix",
            Self::InvalidStructure => "invalid QR transfer structure",
            Self::InvalidAlphabet => "invalid QR transfer alphabet",
            Self::ChecksumMismatch => "QR transfer checksum mismatch",
            Self::InvalidFrame => "invalid canonical QR frame",
            Self::UnsupportedVersion => "unsupported QR transport version",
            Self::UnsupportedKind => "unsupported or unexpected QR transfer kind",
            Self::InvalidSignature => "invalid QR transfer signature width",
            Self::InvalidEnvelope => "invalid production COSE Sign1 envelope",
            Self::Unrepresentable => "QR transfer cannot be represented",
        })
    }
}

impl Error for QrError {}

/// Encodes exact signed material as a checksummed v1 transfer string.
///
/// The checksum detects scanning errors only and does not authenticate the
/// payload or signature.
///
/// # Errors
///
/// Returns an error for oversized payloads, wrong signature width, or a frame
/// that exceeds the v1 single-symbol bound.
pub fn encode(transfer: TransferRef<'_>) -> Result<String, QrError> {
    validate_parts(transfer.payload, transfer.signature)?;
    let frame = to_vec(&Value::Map(BTreeMap::from([
        (0, Value::Unsigned(VERSION)),
        (1, Value::Unsigned(transfer.kind as u64)),
        (2, Value::Bytes(transfer.payload.to_vec())),
        (3, Value::Bytes(transfer.signature.to_vec())),
    ])))
    .map_err(map_canonical)?;
    let body = URL_SAFE_NO_PAD.encode(frame);
    let checksum = checksum(&body);
    let mut output = String::with_capacity(PREFIX.len() + body.len() + 1 + CHECKSUM_HEX_BYTES);
    output.push_str(PREFIX);
    output.push_str(&body);
    output.push('.');
    append_hex(&mut output, &checksum);
    if output.len() > MAX_TRANSFER_TEXT_BYTES {
        return Err(QrError::TooLarge);
    }
    Ok(output)
}

/// Decodes and validates one v1 transfer of the expected kind.
///
/// Validation is deliberately ordered so input bounds, ASCII, syntax, and the
/// checksum are checked before canonical CBOR allocation.
///
/// # Errors
///
/// Returns a classified fail-closed error for malformed, corrupted,
/// unsupported, oversized, or kind-confused input.
pub fn decode(input: &str, expected: TransferKind) -> Result<(Vec<u8>, Vec<u8>), QrError> {
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
    if !body
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        || body.contains('=')
        || !checksum_text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(QrError::InvalidAlphabet);
    }
    let supplied_checksum = decode_checksum(checksum_text)?;
    if checksum(body) != supplied_checksum {
        return Err(QrError::ChecksumMismatch);
    }
    let frame = URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|_| QrError::InvalidAlphabet)?;
    let mut fields = from_slice_with_fields(&frame, FRAME_FIELDS).map_err(map_canonical)?;
    if fields.len() != FRAME_FIELDS.len() {
        return Err(QrError::InvalidFrame);
    }
    let version = take_unsigned(&mut fields, 0)?;
    if version != VERSION {
        return Err(QrError::UnsupportedVersion);
    }
    let kind = TransferKind::parse(take_unsigned(&mut fields, 1)?)?;
    if kind != expected {
        return Err(QrError::UnsupportedKind);
    }
    let payload = take_bytes(&mut fields, 2)?;
    let signature = take_bytes(&mut fields, 3)?;
    validate_parts(&payload, &signature)?;
    Ok((payload, signature))
}

fn validate_parts(payload: &[u8], signature: &[u8]) -> Result<(), QrError> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(QrError::TooLarge);
    }
    if signature.len() != SIGNATURE_BYTES {
        return Err(QrError::InvalidSignature);
    }
    from_slice(payload).map_err(map_canonical)?;
    Ok(())
}

fn take_unsigned(fields: &mut BTreeMap<u64, Value>, field: u64) -> Result<u64, QrError> {
    match fields.remove(&field) {
        Some(Value::Unsigned(value)) => Ok(value),
        _ => Err(QrError::InvalidFrame),
    }
}

fn take_bytes(fields: &mut BTreeMap<u64, Value>, field: u64) -> Result<Vec<u8>, QrError> {
    match fields.remove(&field) {
        Some(Value::Bytes(value)) => Ok(value),
        _ => Err(QrError::InvalidFrame),
    }
}

pub(crate) fn checksum(body: &str) -> [u8; CHECKSUM_BYTES] {
    let mut checked = Vec::with_capacity(PREFIX.len() + body.len());
    checked.extend_from_slice(PREFIX.as_bytes());
    checked.extend_from_slice(body.as_bytes());
    let digest = sha256(&checked);
    let mut output = [0; CHECKSUM_BYTES];
    output.copy_from_slice(&digest.as_bytes()[..CHECKSUM_BYTES]);
    output
}

pub(crate) fn append_hex(output: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
}

pub(crate) fn decode_checksum(input: &str) -> Result<[u8; CHECKSUM_BYTES], QrError> {
    let mut output = [0; CHECKSUM_BYTES];
    for (index, pair) in input.as_bytes().chunks_exact(2).enumerate() {
        output[index] = hex_value(pair[0])?
            .checked_mul(16)
            .and_then(|high| high.checked_add(hex_value(pair[1]).ok()?))
            .ok_or(QrError::InvalidAlphabet)?;
    }
    Ok(output)
}

fn hex_value(byte: u8) -> Result<u8, QrError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(QrError::InvalidAlphabet),
    }
}

fn map_canonical(_: CanonicalError) -> QrError {
    QrError::InvalidFrame
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> Vec<u8> {
        to_vec(&Value::Map(BTreeMap::from([
            (0, Value::Unsigned(1)),
            (1, Value::Text("pistis.authentication-challenge.v1".into())),
        ])))
        .unwrap()
    }

    fn transfer(kind: TransferKind) -> TransferRef<'static> {
        let payload = Box::leak(payload().into_boxed_slice());
        let signature = Box::leak(Box::new([0x5a; SIGNATURE_BYTES]));
        TransferRef {
            kind,
            payload,
            signature,
        }
    }

    fn checked_text(frame: &[u8]) -> String {
        let body = URL_SAFE_NO_PAD.encode(frame);
        let mut output = format!("{PREFIX}{body}.");
        append_hex(&mut output, &checksum(&body));
        output
    }

    #[test]
    fn golden_challenge_is_stable_and_round_trips() {
        let encoded = encode(transfer(TransferKind::Challenge)).unwrap();
        assert_eq!(
            encoded,
            include_str!("../../../fixtures/protocol-v1/qr/challenge-minimal.qr.txt").trim()
        );
        let (decoded_payload, decoded_signature) =
            decode(&encoded, TransferKind::Challenge).unwrap();
        assert_eq!(decoded_payload, payload());
        assert_eq!(decoded_signature, [0x5a; SIGNATURE_BYTES]);
    }

    #[test]
    fn response_round_trips_and_kind_confusion_fails() {
        let encoded = encode(transfer(TransferKind::Response)).unwrap();
        assert!(decode(&encoded, TransferKind::Response).is_ok());
        assert_eq!(
            decode(&encoded, TransferKind::Challenge),
            Err(QrError::UnsupportedKind)
        );
    }

    #[test]
    fn rejects_bad_prefix_structure_alphabet_and_checksum() {
        let valid = encode(transfer(TransferKind::Challenge)).unwrap();
        assert_eq!(
            decode(
                &valid.replacen(PREFIX, "PISTIS2:", 1),
                TransferKind::Challenge
            ),
            Err(QrError::InvalidPrefix)
        );
        assert_eq!(
            decode(PREFIX, TransferKind::Challenge),
            Err(QrError::InvalidStructure)
        );
        let mut padded = valid.clone();
        padded.insert(valid.find('.').unwrap(), '=');
        assert_eq!(
            decode(&padded, TransferKind::Challenge),
            Err(QrError::InvalidAlphabet)
        );
        let mut corrupt = valid;
        let checksum_index = corrupt.len() - CHECKSUM_HEX_BYTES;
        let replacement = if corrupt.as_bytes()[checksum_index] == b'0' {
            "1"
        } else {
            "0"
        };
        corrupt.replace_range(checksum_index..=checksum_index, replacement);
        assert_eq!(
            decode(&corrupt, TransferKind::Challenge),
            Err(QrError::ChecksumMismatch)
        );
    }

    #[test]
    fn rejects_non_ascii_and_oversized_text_before_decoding() {
        assert_eq!(
            decode("PISTIS1:é.0000000000000000", TransferKind::Challenge),
            Err(QrError::NonAscii)
        );
        let oversized = "A".repeat(MAX_TRANSFER_TEXT_BYTES + 1);
        assert_eq!(
            decode(&oversized, TransferKind::Challenge),
            Err(QrError::TooLarge)
        );
    }

    #[test]
    fn rejects_noncanonical_payload_and_wrong_signature_width() {
        assert_eq!(
            encode(TransferRef {
                kind: TransferKind::Challenge,
                payload: &[0x18, 0x01],
                signature: &[0; SIGNATURE_BYTES],
            }),
            Err(QrError::InvalidFrame)
        );
        assert_eq!(
            encode(TransferRef {
                kind: TransferKind::Challenge,
                payload: &payload(),
                signature: &[0; SIGNATURE_BYTES - 1],
            }),
            Err(QrError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_missing_unknown_wrong_type_version_kind_and_width() {
        let cases = [
            (
                Value::Map(BTreeMap::from([
                    (0, Value::Unsigned(1)),
                    (1, Value::Unsigned(1)),
                    (2, Value::Bytes(payload())),
                ])),
                QrError::InvalidFrame,
            ),
            (
                Value::Map(BTreeMap::from([
                    (0, Value::Unsigned(1)),
                    (1, Value::Unsigned(1)),
                    (2, Value::Bytes(payload())),
                    (3, Value::Bytes(vec![0; SIGNATURE_BYTES])),
                    (4, Value::Null),
                ])),
                QrError::InvalidFrame,
            ),
            (
                Value::Map(BTreeMap::from([
                    (0, Value::Text("1".into())),
                    (1, Value::Unsigned(1)),
                    (2, Value::Bytes(payload())),
                    (3, Value::Bytes(vec![0; SIGNATURE_BYTES])),
                ])),
                QrError::InvalidFrame,
            ),
            (
                Value::Map(BTreeMap::from([
                    (0, Value::Unsigned(2)),
                    (1, Value::Unsigned(1)),
                    (2, Value::Bytes(payload())),
                    (3, Value::Bytes(vec![0; SIGNATURE_BYTES])),
                ])),
                QrError::UnsupportedVersion,
            ),
            (
                Value::Map(BTreeMap::from([
                    (0, Value::Unsigned(1)),
                    (1, Value::Unsigned(3)),
                    (2, Value::Bytes(payload())),
                    (3, Value::Bytes(vec![0; SIGNATURE_BYTES])),
                ])),
                QrError::UnsupportedKind,
            ),
            (
                Value::Map(BTreeMap::from([
                    (0, Value::Unsigned(1)),
                    (1, Value::Unsigned(1)),
                    (2, Value::Bytes(payload())),
                    (3, Value::Bytes(vec![0; SIGNATURE_BYTES - 1])),
                ])),
                QrError::InvalidSignature,
            ),
        ];
        for (value, expected) in cases {
            let frame = to_vec(&value).unwrap();
            assert_eq!(
                decode(&checked_text(&frame), TransferKind::Challenge),
                Err(expected)
            );
        }
    }

    #[test]
    fn every_truncation_and_single_body_corruption_fails() {
        let valid = encode(transfer(TransferKind::Challenge)).unwrap();
        for length in 0..valid.len() {
            assert!(
                decode(&valid[..length], TransferKind::Challenge).is_err(),
                "truncation {length}"
            );
        }
        let body_start = PREFIX.len();
        let body_end = valid.find('.').unwrap();
        for index in body_start..body_end {
            let mut corrupt = valid.clone().into_bytes();
            corrupt[index] = if corrupt[index] == b'A' { b'B' } else { b'A' };
            let corrupt = String::from_utf8(corrupt).unwrap();
            assert_eq!(
                decode(&corrupt, TransferKind::Challenge),
                Err(QrError::ChecksumMismatch),
                "corruption {index}"
            );
        }
    }
}
