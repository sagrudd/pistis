use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq;

/// A complete 256-bit SHA-256 digest.
#[derive(Clone, Copy, Debug)]
pub struct Sha256Digest([u8; Self::LENGTH]);

impl Sha256Digest {
    /// Digest length in bytes.
    pub const LENGTH: usize = 32;

    /// Construct a digest from all 32 digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Borrow the complete digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }

    /// Return the complete digest.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; Self::LENGTH] {
        self.0
    }
}

impl PartialEq for Sha256Digest {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl Eq for Sha256Digest {}

/// Compute SHA-256 over an arbitrary byte string.
#[must_use]
pub fn sha256(message: &[u8]) -> Sha256Digest {
    Sha256Digest(Sha256::digest(message).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_nist_empty_message_vector() {
        assert_eq!(
            sha256(b"").into_bytes(),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ]
        );
    }

    #[test]
    fn distinguishes_different_messages() {
        assert_ne!(sha256(b"pistis"), sha256(b"Pistis"));
    }
}
