//! Strict verification of the redacted EPIC-18 physical-device observation.

use pistis_crypto::{PublicKey, SignatureError, SignatureSuite, derive_key_id, sha256, verify};
use pistis_domain::KeyId;
use serde::Deserialize;
use serde::de::{self, MapAccess, Visitor};
use std::error::Error;
use std::fmt;

const MAX_RECORD_BYTES: usize = 4096;
const PUBLIC_KEY_BYTES: usize = 33;
const KEY_ID_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const PINNED_SIGNING_INPUT: &str =
    include_str!("../../../fixtures/protocol-v1/cose/signing-input.hex");

/// A verified, non-secret physical-device interoperability observation.
///
/// This record is evidence for the narrowly scoped EPIC-18 ceremony. It is
/// not a device registration, authority assertion, or production envelope.
#[derive(Clone, Debug)]
pub struct DeviceInteroperabilityRecord {
    public_key: PublicKey,
    key_id: KeyId,
    signature: [u8; SIGNATURE_BYTES],
}

impl DeviceInteroperabilityRecord {
    /// Return the validated public key in canonical compressed SEC1 form.
    #[must_use]
    pub fn public_key_compressed_sec1(&self) -> [u8; PUBLIC_KEY_BYTES] {
        self.public_key.canonical_bytes()
    }

    /// Return the key identifier derived from the validated public key.
    #[must_use]
    pub const fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// Return the verified fixed-width, low-S ES256 signature.
    #[must_use]
    pub fn raw_es256_signature(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.signature
    }
}

/// A rejected physical-device interoperability observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceInteroperabilityError {
    /// The JSON record is oversized, malformed, incomplete, or has an unknown field.
    InvalidRecord,
    /// A hexadecimal field is not lowercase ASCII hex with its required width.
    InvalidEncoding,
    /// The record does not bind the exact pinned COSE `Sig_structure` fixture.
    SigningInputMismatch,
    /// The stated key identifier is not derived from the supplied public key.
    KeyMismatch,
    /// The signature is malformed, high-S, or invalid for the pinned input and key.
    Signature(SignatureError),
}

impl fmt::Display for DeviceInteroperabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRecord => formatter.write_str("invalid interoperability record"),
            Self::InvalidEncoding => {
                formatter.write_str("invalid interoperability record encoding")
            }
            Self::SigningInputMismatch => formatter
                .write_str("interoperability record does not bind the pinned signing input"),
            Self::KeyMismatch => formatter.write_str("interoperability record key mismatch"),
            Self::Signature(error) => error.fmt(formatter),
        }
    }
}

impl Error for DeviceInteroperabilityError {}

/// Verify one redacted iOS EPIC-18 physical-device observation.
///
/// The input must have exactly the five JSON string fields emitted by
/// `DeviceInteroperabilityRecord.renderedJSON()` in the iOS test harness. The
/// verifier rejects duplicate and unknown fields, validates lowercase fixed
/// width hexadecimal, derives `kid` from the compressed SEC1 public key, and
/// verifies the raw low-S ES256 signature over the exact pinned COSE
/// `Sig_structure` fixture. It deliberately accepts no caller-selected
/// message, key, or DER signature.
///
/// # Errors
///
/// Returns a fail-closed error for every schema, encoding, binding, or
/// signature failure. No parsed value may be used unless this function
/// succeeds.
pub fn verify_device_interoperability_record(
    json: &[u8],
) -> Result<DeviceInteroperabilityRecord, DeviceInteroperabilityError> {
    if json.is_empty() || json.len() > MAX_RECORD_BYTES {
        return Err(DeviceInteroperabilityError::InvalidRecord);
    }
    let raw: RawRecord =
        serde_json::from_slice(json).map_err(|_| DeviceInteroperabilityError::InvalidRecord)?;

    let public_key_bytes = decode_hex_exact::<PUBLIC_KEY_BYTES>(&raw.public_key)?;
    let key_id_bytes = decode_hex_exact::<KEY_ID_BYTES>(&raw.key_id)?;
    let signing_input_digest = decode_hex_exact::<KEY_ID_BYTES>(&raw.signing_input_digest)?;
    let signing_input = decode_hex(&raw.signing_input)?;
    let signature = decode_hex_exact::<SIGNATURE_BYTES>(&raw.signature)?;

    let pinned = pinned_signing_input()?;
    if signing_input != pinned || sha256(&signing_input).into_bytes() != signing_input_digest {
        return Err(DeviceInteroperabilityError::SigningInputMismatch);
    }

    let public_key = PublicKey::from_sec1_bytes(&public_key_bytes)
        .map_err(|_| DeviceInteroperabilityError::InvalidEncoding)?;
    let key_id = KeyId::from_bytes(key_id_bytes);
    if derive_key_id(&public_key) != key_id {
        return Err(DeviceInteroperabilityError::KeyMismatch);
    }
    verify(SignatureSuite::Es256, &public_key, &pinned, &signature)
        .map_err(DeviceInteroperabilityError::Signature)?;

    Ok(DeviceInteroperabilityRecord {
        public_key,
        key_id,
        signature,
    })
}

fn pinned_signing_input() -> Result<Vec<u8>, DeviceInteroperabilityError> {
    decode_hex(PINNED_SIGNING_INPUT.trim_end())
}

fn decode_hex_exact<const N: usize>(input: &str) -> Result<[u8; N], DeviceInteroperabilityError> {
    let bytes = decode_hex(input)?;
    bytes
        .try_into()
        .map_err(|_| DeviceInteroperabilityError::InvalidEncoding)
}

fn decode_hex(input: &str) -> Result<Vec<u8>, DeviceInteroperabilityError> {
    if input.is_empty() || !input.len().is_multiple_of(2) {
        return Err(DeviceInteroperabilityError::InvalidEncoding);
    }
    let mut bytes = Vec::with_capacity(input.len() / 2);
    for pair in input.as_bytes().chunks_exact(2) {
        let high = decode_nibble(pair[0]).ok_or(DeviceInteroperabilityError::InvalidEncoding)?;
        let low = decode_nibble(pair[1]).ok_or(DeviceInteroperabilityError::InvalidEncoding)?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

const fn decode_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

struct RawRecord {
    public_key: String,
    key_id: String,
    signing_input_digest: String,
    signing_input: String,
    signature: String,
}

impl<'de> Deserialize<'de> for RawRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "publicKeyCompressedSEC1Hex",
            "keyIDHex",
            "signatureStructureSHA256Hex",
            "signatureStructureHex",
            "rawES256SignatureHex",
        ];

        struct RawRecordVisitor;

        impl<'de> Visitor<'de> for RawRecordVisitor {
            type Value = RawRecord;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("the exact Pistis device interoperability record object")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut public_key_compressed_sec1_hex = None;
                let mut key_id_hex = None;
                let mut signature_structure_sha256_hex = None;
                let mut signature_structure_hex = None;
                let mut raw_es256_signature_hex = None;

                while let Some(field) = map.next_key::<String>()? {
                    let slot = match field.as_str() {
                        "publicKeyCompressedSEC1Hex" => &mut public_key_compressed_sec1_hex,
                        "keyIDHex" => &mut key_id_hex,
                        "signatureStructureSHA256Hex" => &mut signature_structure_sha256_hex,
                        "signatureStructureHex" => &mut signature_structure_hex,
                        "rawES256SignatureHex" => &mut raw_es256_signature_hex,
                        _ => return Err(de::Error::unknown_field(&field, FIELDS)),
                    };
                    if slot.is_some() {
                        return Err(de::Error::custom("duplicate record field"));
                    }
                    *slot = Some(map.next_value()?);
                }

                Ok(RawRecord {
                    public_key: public_key_compressed_sec1_hex
                        .ok_or_else(|| de::Error::missing_field(FIELDS[0]))?,
                    key_id: key_id_hex.ok_or_else(|| de::Error::missing_field(FIELDS[1]))?,
                    signing_input_digest: signature_structure_sha256_hex
                        .ok_or_else(|| de::Error::missing_field(FIELDS[2]))?,
                    signing_input: signature_structure_hex
                        .ok_or_else(|| de::Error::missing_field(FIELDS[3]))?,
                    signature: raw_es256_signature_hex
                        .ok_or_else(|| de::Error::missing_field(FIELDS[4]))?,
                })
            }
        }

        deserializer.deserialize_struct("DeviceInteroperabilityRecord", FIELDS, RawRecordVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{Signature, SigningKey};
    use std::fmt::Write as _;

    const POSITIVE: &str = include_str!(
        "../../../fixtures/protocol-v1/cose/device-interoperability-record-example.json"
    );
    const PHYSICAL_IOS_RECORD: &str = include_str!(
        "../../../fixtures/protocol-v1/cose/ios-physical-interoperability-record.json"
    );
    const IOS_OPERATOR_GUIDE: &str = include_str!("../../../docs/operations/ios.md");

    fn replace_field(record: &str, field: &str, replacement: &str) -> String {
        let needle = format!("\"{field}\": \"");
        let start = record.find(&needle).unwrap() + needle.len();
        let end = start + record[start..].find('"').unwrap();
        let mut changed = record.to_owned();
        changed.replace_range(start..end, replacement);
        changed
    }

    fn lowercase_hex(bytes: &[u8]) -> String {
        let mut text = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(text, "{byte:02x}").unwrap();
        }
        text
    }

    #[test]
    fn verifies_pinned_test_only_record() {
        let record = verify_device_interoperability_record(POSITIVE.as_bytes()).unwrap();
        assert_eq!(
            record.public_key_compressed_sec1().as_slice(),
            decode_hex(
                include_str!("../../../fixtures/protocol-v1/cose/public-key-compressed.hex")
                    .trim_end()
            )
            .unwrap()
        );
        assert_eq!(
            record.key_id().as_bytes().as_slice(),
            decode_hex(include_str!("../../../fixtures/protocol-v1/cose/key-id.hex").trim_end())
                .unwrap()
        );
    }

    #[test]
    fn verifies_retained_physical_ios_record() {
        let record = verify_device_interoperability_record(PHYSICAL_IOS_RECORD.as_bytes()).unwrap();
        assert_eq!(
            record.key_id().as_bytes().as_slice(),
            decode_hex("fb8cc53e5fc6da7ff9082c6560f1150ad5dd04018dc703cd1de5b42fa99cdec5").unwrap()
        );
    }

    #[test]
    fn operator_guide_pins_exact_retained_physical_ios_record_digest() {
        let digest = lowercase_hex(sha256(PHYSICAL_IOS_RECORD.as_bytes()).as_bytes());
        assert!(
            IOS_OPERATOR_GUIDE.contains(&format!("`{digest}`")),
            "operator guide must publish the exact retained record SHA-256"
        );
    }

    #[test]
    fn rejects_schema_unknown_duplicate_and_noncanonical_hex() {
        let unknown = POSITIVE.replacen('{', "{\n  \"extra\": \"x\",", 1);
        assert_eq!(
            verify_device_interoperability_record(unknown.as_bytes()).unwrap_err(),
            DeviceInteroperabilityError::InvalidRecord
        );
        let duplicate =
            POSITIVE.replacen("\"keyIDHex\":", "\"keyIDHex\": \"00\",\n  \"keyIDHex\":", 1);
        assert_eq!(
            verify_device_interoperability_record(duplicate.as_bytes()).unwrap_err(),
            DeviceInteroperabilityError::InvalidRecord
        );
        let uppercase = replace_field(
            POSITIVE,
            "keyIDHex",
            "7AD63DF38DE8C402C7259DB7BBC1B97B6890FFAA0A4ADF78BC2B873EFCABBF8D",
        );
        assert_eq!(
            verify_device_interoperability_record(uppercase.as_bytes()).unwrap_err(),
            DeviceInteroperabilityError::InvalidEncoding
        );
    }

    #[test]
    fn rejects_wrong_key_changed_input_high_s_and_der() {
        let alternate_signing = SigningKey::from_bytes((&[2_u8; 32]).into()).unwrap();
        let alternate_public = alternate_signing.verifying_key().to_encoded_point(true);
        let wrong_key = replace_field(
            POSITIVE,
            "publicKeyCompressedSEC1Hex",
            &lowercase_hex(alternate_public.as_bytes()),
        );
        assert_eq!(
            verify_device_interoperability_record(wrong_key.as_bytes()).unwrap_err(),
            DeviceInteroperabilityError::KeyMismatch
        );

        let changed_input = replace_field(POSITIVE, "signatureStructureHex", "a0");
        assert_eq!(
            verify_device_interoperability_record(changed_input.as_bytes()).unwrap_err(),
            DeviceInteroperabilityError::SigningInputMismatch
        );

        let raw: RawRecord = serde_json::from_str(POSITIVE).unwrap();
        let low_s =
            Signature::from_slice(&decode_hex_exact::<SIGNATURE_BYTES>(&raw.signature).unwrap())
                .unwrap();
        let high_s_signature =
            Signature::from_scalars(low_s.r().to_bytes(), (-low_s.s()).to_bytes()).unwrap();
        let high_s = replace_field(
            POSITIVE,
            "rawES256SignatureHex",
            &lowercase_hex(&high_s_signature.to_bytes()),
        );
        assert_eq!(
            verify_device_interoperability_record(high_s.as_bytes()).unwrap_err(),
            DeviceInteroperabilityError::Signature(SignatureError::NonCanonical)
        );

        let der = replace_field(
            POSITIVE,
            "rawES256SignatureHex",
            "30440220e9e77b093027bcc200a9e7b5512f9fb56bbb687b06484f2f43e90b5e0e2a3bb602207a26a33169eeda014d858ac445d3cfc7a0b31b34b45dbf15581847cdca93daa4",
        );
        assert_eq!(
            verify_device_interoperability_record(der.as_bytes()).unwrap_err(),
            DeviceInteroperabilityError::InvalidEncoding
        );
    }
}
