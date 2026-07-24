use crate::{PublicKey, SignatureSuite};
use p256::ecdsa::Signature;
use p256::ecdsa::signature::Verifier as _;
use std::error::Error;
use std::fmt;

/// A failed signature verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureError {
    /// The signature is not the fixed-width 64-byte COSE `r || s` form.
    InvalidEncoding,
    /// The signature uses a high-S scalar and is therefore malleable.
    NonCanonical,
    /// The signature does not authenticate the supplied message and key.
    InvalidSignature,
}

impl fmt::Display for SignatureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEncoding => formatter.write_str("invalid signature encoding"),
            Self::NonCanonical => formatter.write_str("non-canonical signature"),
            Self::InvalidSignature => formatter.write_str("signature verification failed"),
        }
    }
}

impl Error for SignatureError {}

/// Verify a protocol signature over the exact supplied message bytes.
///
/// Protocol v1 accepts only [`SignatureSuite::Es256`]. `signature` must be the
/// 64-byte COSE encoding `r || s`, never ASN.1 DER. High-S signatures are
/// rejected even when mathematically valid, preventing ECDSA malleability.
///
/// # Errors
///
/// Returns a non-disclosing structured error for malformed, non-canonical, or
/// invalid signatures.
pub fn verify(
    suite: SignatureSuite,
    key: &PublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), SignatureError> {
    match suite {
        SignatureSuite::Es256 => {
            let signature =
                Signature::from_slice(signature).map_err(|_| SignatureError::InvalidEncoding)?;
            if signature.normalize_s().is_some() {
                return Err(SignatureError::NonCanonical);
            }
            key.verifying_key()
                .verify(message, &signature)
                .map_err(|_| SignatureError::InvalidSignature)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer as _;

    const SECRET: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ];

    fn fixture() -> (PublicKey, SigningKey) {
        let signing = SigningKey::from_bytes((&SECRET).into()).unwrap();
        let encoded = signing.verifying_key().to_encoded_point(false);
        (
            PublicKey::from_sec1_bytes(encoded.as_bytes()).unwrap(),
            signing,
        )
    }

    #[test]
    fn verifies_rfc6979_p256_sha256_known_answer() {
        // RFC 6979 A.2.5, message "sample". RFC 6979's high-S value is
        // replaced by its mathematically equivalent low-S canonical twin.
        let public_key = [
            0x04, 0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb, 0x74, 0xc6,
            0x35, 0x6d, 0x68, 0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c, 0xe6, 0x69, 0x62,
            0x2e, 0x60, 0xf2, 0x9f, 0xb6, 0x79, 0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4,
            0x1a, 0xe9, 0xe9, 0x56, 0x28, 0xbc, 0x64, 0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f,
            0x51, 0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99,
        ];
        let signature = [
            0xef, 0xd4, 0x8b, 0x2a, 0xac, 0xb6, 0xa8, 0xfd, 0x11, 0x40, 0xdd, 0x9c, 0xd4, 0x5e,
            0x81, 0xd6, 0x9d, 0x2c, 0x87, 0x7b, 0x56, 0xaa, 0xf9, 0x91, 0xc3, 0x4d, 0x0e, 0xa8,
            0x4e, 0xaf, 0x37, 0x16, 0x08, 0x34, 0xe3, 0x6a, 0xd2, 0x9a, 0x83, 0xbf, 0x2b, 0xc9,
            0x38, 0x5e, 0x49, 0x1d, 0x60, 0x99, 0xc8, 0xfd, 0xf9, 0xd1, 0xed, 0x67, 0xaa, 0x7e,
            0xa5, 0xf5, 0x1f, 0x93, 0x78, 0x28, 0x57, 0xa9,
        ];
        let key = PublicKey::from_sec1_bytes(&public_key).unwrap();
        assert_eq!(
            verify(SignatureSuite::Es256, &key, b"sample", &signature),
            Ok(())
        );
    }

    #[test]
    fn verifies_fixed_width_low_s_signature() {
        let (key, signing) = fixture();
        let signature: Signature = signing.sign(b"canonical message");
        let signature = signature.normalize_s().unwrap_or(signature);
        let signature_bytes = signature.to_bytes();
        assert_eq!(
            verify(
                SignatureSuite::Es256,
                &key,
                b"canonical message",
                &signature_bytes
            ),
            Ok(())
        );
    }

    #[test]
    fn rejects_wrong_message_der_and_wrong_width() {
        let (key, signing) = fixture();
        let signature: Signature = signing.sign(b"canonical message");
        let signature = signature.normalize_s().unwrap_or(signature);
        let signature_bytes = signature.to_bytes();
        assert_eq!(
            verify(
                SignatureSuite::Es256,
                &key,
                b"changed message",
                &signature_bytes
            ),
            Err(SignatureError::InvalidSignature)
        );
        assert_eq!(
            verify(
                SignatureSuite::Es256,
                &key,
                b"canonical message",
                signature.to_der().as_bytes()
            ),
            Err(SignatureError::InvalidEncoding)
        );
        assert_eq!(
            verify(SignatureSuite::Es256, &key, b"canonical message", &[0; 63]),
            Err(SignatureError::InvalidEncoding)
        );
    }

    #[test]
    fn rejects_high_s_malleable_twin() {
        let (key, signing) = fixture();
        let signature: Signature = signing.sign(b"canonical message");
        let low = signature.normalize_s().unwrap_or(signature);
        let high = Signature::from_scalars(low.r().to_bytes(), (-low.s()).to_bytes()).unwrap();
        let high_bytes = high.to_bytes();
        assert_eq!(
            verify(
                SignatureSuite::Es256,
                &key,
                b"canonical message",
                &high_bytes
            ),
            Err(SignatureError::NonCanonical)
        );
    }
}
