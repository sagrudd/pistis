use pistis_domain::KeyId;
use std::{error::Error, fmt};

/// Public result of installation signing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallationSignature {
    /// Identifier of the public installation key.
    pub key_id: KeyId,
    /// Provider-produced signature bytes.
    pub signature: Vec<u8>,
}

/// Non-exportable installation-signing provider.
pub trait InstallationSigner {
    /// Signs exact canonical challenge bytes.
    ///
    /// There is intentionally no method for exporting private-key material.
    ///
    /// # Errors
    ///
    /// Fails closed when the configured key, user-presence policy, or provider
    /// is unavailable.
    fn sign(&self, canonical: &[u8]) -> Result<InstallationSignature, SignerError>;
}

/// Narrow platform Keychain operation used by [`KeychainSigner`].
pub trait KeychainBackend {
    /// Signs bytes using the non-exportable key selected by `label`.
    ///
    /// # Errors
    ///
    /// Fails without returning key material or provider diagnostics containing
    /// secrets.
    fn sign_with_key(
        &self,
        label: &str,
        canonical: &[u8],
    ) -> Result<InstallationSignature, SignerError>;
}

/// macOS Keychain signing adapter configured by an opaque key label.
///
/// The platform backend is injected so portable code never calls a command
/// line tool or obtains private-key bytes. A production backend must use the
/// Security framework signing API and enforce its reviewed access control.
pub struct KeychainSigner<B> {
    label: String,
    backend: B,
}

impl<B> KeychainSigner<B> {
    /// Constructs a signer for a bounded, control-free Keychain label.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, whitespace-padded, or control-bearing labels.
    pub fn new(label: impl Into<String>, backend: B) -> Result<Self, SignerError> {
        let label = label.into();
        if label.is_empty()
            || label.len() > 128
            || label.trim() != label
            || label.chars().any(char::is_control)
        {
            return Err(SignerError::InvalidConfiguration);
        }
        Ok(Self { label, backend })
    }
}

impl<B: KeychainBackend> InstallationSigner for KeychainSigner<B> {
    fn sign(&self, canonical: &[u8]) -> Result<InstallationSignature, SignerError> {
        if canonical.is_empty() || canonical.len() > 64 * 1024 {
            return Err(SignerError::InvalidMessage);
        }
        self.backend.sign_with_key(&self.label, canonical)
    }
}

/// Coarse installation-signing failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignerError {
    /// Key label or provider configuration is invalid.
    InvalidConfiguration,
    /// Canonical message is empty or excessive.
    InvalidMessage,
    /// Key or platform provider is unavailable.
    Unavailable,
    /// Signing was denied by user-presence or access-control policy.
    Denied,
    /// Provider returned an invalid signature.
    InvalidSignature,
}

impl fmt::Display for SignerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "installation signer configuration rejected",
            Self::InvalidMessage => "installation signing message rejected",
            Self::Unavailable => "installation signer unavailable",
            Self::Denied => "installation signing denied",
            Self::InvalidSignature => "installation signer returned invalid output",
        })
    }
}

impl Error for SignerError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Backend(Mutex<Vec<u8>>);

    impl KeychainBackend for Backend {
        fn sign_with_key(
            &self,
            label: &str,
            canonical: &[u8],
        ) -> Result<InstallationSignature, SignerError> {
            assert_eq!(label, "org.mnemosyne.pistis.installation");
            *self.0.lock().unwrap() = canonical.to_vec();
            Ok(InstallationSignature {
                key_id: KeyId::from_bytes([1; 32]),
                signature: vec![2; 64],
            })
        }
    }

    #[test]
    fn adapter_exposes_signing_but_no_key_export() {
        let signer = KeychainSigner::new(
            "org.mnemosyne.pistis.installation",
            Backend(Mutex::new(Vec::new())),
        )
        .unwrap();
        let signature = signer.sign(b"canonical challenge").unwrap();
        assert_eq!(signature.key_id, KeyId::from_bytes([1; 32]));
        assert_eq!(signature.signature.len(), 64);
    }

    #[test]
    fn unsafe_labels_and_messages_fail_before_provider() {
        assert!(matches!(
            KeychainSigner::new(" bad ", Backend(Mutex::new(Vec::new()))),
            Err(SignerError::InvalidConfiguration)
        ));
        let signer = KeychainSigner::new("valid", Backend(Mutex::new(Vec::new()))).unwrap();
        assert_eq!(signer.sign(&[]), Err(SignerError::InvalidMessage));
    }
}
