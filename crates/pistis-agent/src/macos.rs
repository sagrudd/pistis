use crate::{InstallationSignature, KeychainBackend, SignerError};
use p256::ecdsa::Signature;
use pistis_crypto::{PublicKey, SignatureSuite, derive_key_id, verify};
use security_framework::{
    item::{ItemSearchOptions, KeyClass, Reference, SearchResult},
    key::Algorithm,
};

/// Native macOS Security-framework installation-key backend.
///
/// The backend looks up exactly one private EC key by its Keychain label,
/// signs through `SecKeyCreateSignature`, derives the Pistis key identifier
/// from the corresponding public key, converts Apple's DER ECDSA result into
/// fixed-width low-S form, and verifies the result before returning it. It
/// never requests a private-key external representation.
#[derive(Clone, Copy, Debug, Default)]
pub struct MacOsKeychainBackend;

impl KeychainBackend for MacOsKeychainBackend {
    fn sign_with_key(
        &self,
        label: &str,
        canonical: &[u8],
    ) -> Result<InstallationSignature, SignerError> {
        let mut query = ItemSearchOptions::new();
        let results = query
            .key_class(KeyClass::private())
            .label(label)
            .load_refs(true)
            .limit(2_i64)
            .search()
            .map_err(|_| SignerError::Unavailable)?;
        let [SearchResult::Ref(Reference::Key(private_key))] = results.as_slice() else {
            return Err(SignerError::InvalidConfiguration);
        };
        let public_key = private_key.public_key().ok_or(SignerError::Unavailable)?;
        let public_bytes = public_key
            .external_representation()
            .ok_or(SignerError::Unavailable)?
            .to_vec();
        let public_key = PublicKey::from_sec1_bytes(&public_bytes)
            .map_err(|_| SignerError::InvalidConfiguration)?;
        let der = private_key
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, canonical)
            .map_err(|_| SignerError::Denied)?;
        let signature = Signature::from_der(&der).map_err(|_| SignerError::InvalidSignature)?;
        let signature = signature.normalize_s().unwrap_or(signature);
        let signature = signature.to_bytes().to_vec();
        verify(SignatureSuite::Es256, &public_key, canonical, &signature)
            .map_err(|_| SignerError::InvalidSignature)?;
        Ok(InstallationSignature {
            key_id: derive_key_id(&public_key),
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_or_duplicate_label_fails_without_fallback() {
        let label = format!(
            "org.mnemosyne.pistis.absent-test-key.{}",
            std::process::id()
        );
        assert!(matches!(
            MacOsKeychainBackend.sign_with_key(&label, b"canonical"),
            Err(SignerError::InvalidConfiguration | SignerError::Unavailable)
        ));
    }
}
