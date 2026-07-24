use p256::ecdsa::VerifyingKey;
use pistis_domain::KeyId;
use sha2::{Digest as _, Sha256};
use std::error::Error;
use std::fmt;

const KEY_ID_DOMAIN: &[u8] = b"pistis:key-id:v1\0";

/// A validated P-256 public key.
#[derive(Clone, Debug)]
pub struct PublicKey(VerifyingKey);

/// A malformed, unsupported, or non-canonical public key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicKeyError;

impl fmt::Display for PublicKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid P-256 public key")
    }
}

impl Error for PublicKeyError {}

impl PublicKey {
    /// Parse a compressed (33-byte) or uncompressed (65-byte) SEC1 P-256 point.
    ///
    /// The parser rejects infinity, off-curve points, hybrid encodings,
    /// coordinates of the wrong width, and trailing bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PublicKeyError`] without exposing parser details when the
    /// complete input is not a supported valid P-256 point.
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, PublicKeyError> {
        let supported_encoding = match bytes.first() {
            Some(0x02 | 0x03) => bytes.len() == 33,
            Some(0x04) => bytes.len() == 65,
            _ => false,
        };
        if !supported_encoding {
            return Err(PublicKeyError);
        }
        VerifyingKey::from_sec1_bytes(bytes)
            .map(Self)
            .map_err(|_| PublicKeyError)
    }

    /// Return the unique compressed SEC1 encoding used by Pistis identifiers.
    #[must_use]
    pub fn canonical_bytes(&self) -> [u8; 33] {
        let encoded = self.0.to_encoded_point(true);
        let mut bytes = [0_u8; 33];
        bytes.copy_from_slice(encoded.as_bytes());
        bytes
    }

    pub(crate) const fn verifying_key(&self) -> &VerifyingKey {
        &self.0
    }
}

/// Derive a stable [`KeyId`] from a validated public key.
///
/// The construction is the complete 256-bit result of
/// `SHA-256("pistis:key-id:v1\0" || compressed-sec1-key)`. The prefix separates
/// identifiers from every other Pistis SHA-256 use; canonicalization ensures
/// compressed and uncompressed input representations identify the same key.
#[must_use]
pub fn derive_key_id(key: &PublicKey) -> KeyId {
    let mut hasher = Sha256::new();
    hasher.update(KEY_ID_DOMAIN);
    hasher.update(key.canonical_bytes());
    KeyId::from_bytes(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMPRESSED: [u8; 33] = [
        0x03, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
        0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8,
        0x98, 0xc2, 0x96,
    ];
    const UNCOMPRESSED: [u8; 65] = [
        0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
        0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8,
        0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a,
        0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40,
        0x68, 0x37, 0xbf, 0x51, 0xf5,
    ];

    #[test]
    fn parses_generator_and_derives_stable_identifier() {
        let key = PublicKey::from_sec1_bytes(&COMPRESSED).unwrap();
        assert_eq!(
            derive_key_id(&key).to_string(),
            "key_7ad63df38de8c402c7259db7bbc1b97b6890ffaa0a4adf78bc2b873efcabbf8d"
        );
        let uncompressed = PublicKey::from_sec1_bytes(&UNCOMPRESSED).unwrap();
        assert_eq!(uncompressed.canonical_bytes(), COMPRESSED);
        assert_eq!(derive_key_id(&uncompressed), derive_key_id(&key));
    }

    #[test]
    fn rejects_invalid_sec1_forms() {
        assert_eq!(PublicKey::from_sec1_bytes(&[]).unwrap_err(), PublicKeyError);
        assert_eq!(
            PublicKey::from_sec1_bytes(&[0x00]).unwrap_err(),
            PublicKeyError
        );
        let mut hybrid = [0_u8; 65];
        hybrid[0] = 0x06;
        assert_eq!(
            PublicKey::from_sec1_bytes(&hybrid).unwrap_err(),
            PublicKeyError
        );
        let mut trailing = COMPRESSED.to_vec();
        trailing.push(0);
        assert_eq!(
            PublicKey::from_sec1_bytes(&trailing).unwrap_err(),
            PublicKeyError
        );
    }
}
