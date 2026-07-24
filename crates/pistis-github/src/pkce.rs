//! PKCE S256 and OAuth state primitives.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

const SECRET_BYTES: usize = 32;

/// Supplies cryptographically secure random bytes.
///
/// Platform code should implement this using its operating-system CSPRNG.
pub trait EntropySource {
    /// Fills the complete destination or returns an error without using it.
    ///
    /// # Errors
    ///
    /// Returns [`EntropyError`] if secure random bytes are unavailable.
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), EntropyError>;
}

/// Operating-system entropy was unavailable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntropyError;

/// Failure to prepare an authorization request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PkceError {
    /// Secure random generation failed.
    EntropyUnavailable,
}

/// A single-use PKCE code verifier.
///
/// The verifier is intentionally neither `Clone` nor `Debug`.
pub struct PkceVerifier([u8; SECRET_BYTES]);

/// PKCE values for one authorization attempt.
pub struct Pkce {
    verifier: PkceVerifier,
    challenge: String,
}

/// A single-use OAuth CSRF correlation value.
///
/// The state is intentionally neither `Clone` nor `Debug`.
pub struct State([u8; SECRET_BYTES]);

impl Drop for PkceVerifier {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for State {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Pkce {
    /// Generates a verifier and its RFC 7636 S256 challenge.
    ///
    /// # Errors
    ///
    /// Returns [`PkceError::EntropyUnavailable`] if generation fails.
    pub fn generate(entropy: &mut impl EntropySource) -> Result<Self, PkceError> {
        let mut bytes = [0_u8; SECRET_BYTES];
        entropy
            .fill(&mut bytes)
            .map_err(|EntropyError| PkceError::EntropyUnavailable)?;
        let verifier = PkceVerifier(bytes);
        let digest = Sha256::digest(verifier.0);
        Ok(Self {
            verifier,
            challenge: base64_url(&digest),
        })
    }

    /// Returns the S256 challenge safe to include in the browser request.
    #[must_use]
    pub fn challenge(&self) -> &str {
        &self.challenge
    }

    /// Consumes the pair and returns the secret verifier for token exchange.
    #[must_use]
    pub fn into_verifier(self) -> PkceVerifier {
        self.verifier
    }
}

impl PkceVerifier {
    pub(crate) fn into_exposed(self) -> String {
        base64_url(&self.0)
    }
}

impl State {
    /// Generates a state value containing 256 bits of entropy.
    ///
    /// # Errors
    ///
    /// Returns [`PkceError::EntropyUnavailable`] if generation fails.
    pub fn generate(entropy: &mut impl EntropySource) -> Result<Self, PkceError> {
        let mut bytes = [0_u8; SECRET_BYTES];
        entropy
            .fill(&mut bytes)
            .map_err(|EntropyError| PkceError::EntropyUnavailable)?;
        Ok(Self(bytes))
    }

    /// Returns the browser-safe state representation.
    #[must_use]
    pub fn expose(&self) -> String {
        base64_url(&self.0)
    }

    pub(crate) fn matches(&self, candidate: &str) -> bool {
        let expected = self.expose();
        expected.len() == candidate.len()
            && bool::from(expected.as_bytes().ct_eq(candidate.as_bytes()))
    }
}

fn base64_url(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        output.push(char::from(ALPHABET[((value >> 18) & 63) as usize]));
        output.push(char::from(ALPHABET[((value >> 12) & 63) as usize]));
        if chunk.len() > 1 {
            output.push(char::from(ALPHABET[((value >> 6) & 63) as usize]));
        }
        if chunk.len() > 2 {
            output.push(char::from(ALPHABET[(value & 63) as usize]));
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedEntropy(u8);

    impl EntropySource for FixedEntropy {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
            destination.fill(self.0);
            Ok(())
        }
    }

    #[test]
    fn creates_deterministic_s256_values_without_padding() {
        let pkce = Pkce::generate(&mut FixedEntropy(0)).unwrap();
        assert_eq!(
            pkce.challenge(),
            "Zmh6rfhivXdsj8GLjp-OIAiXFIVu4jOzkCpZHQ1fKSU"
        );
        let verifier = pkce.into_verifier().into_exposed();
        assert_eq!(verifier.len(), 43);
        assert!(!verifier.contains('='));
    }

    #[test]
    fn state_matches_only_exact_value() {
        let state = State::generate(&mut FixedEntropy(7)).unwrap();
        assert!(state.matches(&state.expose()));
        assert!(!state.matches(""));
        assert!(!state.matches(&format!("{}x", state.expose())));
    }
}
