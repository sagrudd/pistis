use crate::{Algorithm, PublicKey, SignatureError, SignatureVerifier};
use pistis_crypto::{
    PublicKey as CryptoPublicKey, SignatureError as CryptoSignatureError, SignatureSuite,
};

/// ES256 adapter backed by the reviewed `pistis-crypto` verification boundary.
///
/// Public keys are SEC1 points and signatures are fixed-width, low-S COSE
/// values. No signing or private-key API is reachable through this adapter.
#[derive(Clone, Copy, Debug, Default)]
pub struct Es256SignatureVerifier;

impl SignatureVerifier for Es256SignatureVerifier {
    fn verify(
        &self,
        algorithm: &Algorithm,
        public_key: &PublicKey,
        canonical_bytes: &[u8],
        signature: &[u8],
    ) -> Result<(), SignatureError> {
        if algorithm.as_str() != "ES256" {
            return Err(SignatureError::UnsupportedAlgorithm);
        }
        let key = CryptoPublicKey::from_sec1_bytes(public_key.as_bytes())
            .map_err(|_| SignatureError::InvalidSignature)?;
        pistis_crypto::verify(SignatureSuite::Es256, &key, canonical_bytes, signature).map_err(
            |error| match error {
                CryptoSignatureError::NonCanonical => SignatureError::NonCanonical,
                CryptoSignatureError::InvalidEncoding | CryptoSignatureError::InvalidSignature => {
                    SignatureError::InvalidSignature
                }
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_algorithm_confusion_before_key_parsing() {
        assert_eq!(
            Es256SignatureVerifier.verify(
                &Algorithm::new("ES384"),
                &PublicKey::new([]),
                b"message",
                &[]
            ),
            Err(SignatureError::UnsupportedAlgorithm)
        );
    }

    #[test]
    fn rejects_malformed_public_keys_without_disclosure() {
        assert_eq!(
            Es256SignatureVerifier.verify(
                &Algorithm::new("ES256"),
                &PublicKey::new([0; 33]),
                b"message",
                &[0; 64]
            ),
            Err(SignatureError::InvalidSignature)
        );
    }
}
