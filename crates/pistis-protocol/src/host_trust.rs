//! ADR 0029 host-trust comparison words.

use pistis_canonical::{Value, to_vec};
use pistis_crypto::sha256;
use std::collections::BTreeMap;

const WORDS: &str = include_str!("../data/host-trust-words-v1.txt");

/// Version of the host-trust comparison-word derivation.
pub const HOST_TRUST_WORDS_VERSION: u64 = 1;

/// Three human-comparable words derived from the authenticated host binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostTrustWords([&'static str; 3]);

impl HostTrustWords {
    /// Returns the words in display and entry order.
    #[must_use]
    pub const fn as_array(&self) -> [&'static str; 3] {
        self.0
    }
}

/// Derive the ADR 0029 comparison words from authenticated presentation facts.
///
/// The words are only a human comparison checksum. Callers must still enforce
/// the full 256-bit TLS SPKI pin and the authority signature.
///
/// # Errors
///
/// Returns a canonical-encoding error if the fixed derivation map cannot be
/// represented by the shared deterministic CBOR profile.
pub fn derive_host_trust_words(
    authority_id: [u8; 16],
    installation_id: [u8; 16],
    https_origin: &str,
    tls_spki_sha256: [u8; 32],
    app_configuration_digest: [u8; 32],
) -> Result<HostTrustWords, pistis_canonical::CanonicalError> {
    let input = Value::Map(BTreeMap::from([
        (0, Value::Unsigned(HOST_TRUST_WORDS_VERSION)),
        (1, Value::Text("pistis.host-trust-words.v1".into())),
        (2, Value::Bytes(authority_id.to_vec())),
        (3, Value::Bytes(installation_id.to_vec())),
        (4, Value::Text(https_origin.into())),
        (5, Value::Bytes(tls_spki_sha256.to_vec())),
        (6, Value::Bytes(app_configuration_digest.to_vec())),
    ]));
    let canonical = to_vec(&input)?;
    let digest = sha256(&canonical).into_bytes();
    let indices = [
        (usize::from(digest[0]) << 3) | (usize::from(digest[1]) >> 5),
        (usize::from(digest[1] & 0x1f) << 6) | (usize::from(digest[2]) >> 2),
        (usize::from(digest[2] & 0x03) << 9)
            | (usize::from(digest[3]) << 1)
            | (usize::from(digest[4]) >> 7),
    ];
    let words: Vec<_> = WORDS.lines().collect();
    debug_assert_eq!(words.len(), 2_048);
    Ok(HostTrustWords([
        words[indices[0]],
        words[indices[1]],
        words[indices[2]],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_word_list_is_exact_and_unique() {
        let words: Vec<_> = WORDS.lines().collect();
        assert_eq!(words.len(), 2_048);
        assert!(words.iter().all(|word| {
            !word.is_empty()
                && word.len() <= 8
                && word.bytes().all(|byte| byte.is_ascii_lowercase())
        }));
        let unique: std::collections::BTreeSet<_> = words.iter().collect();
        assert_eq!(unique.len(), words.len());
    }

    #[test]
    fn derivation_uses_all_authenticated_inputs() {
        let baseline =
            derive_host_trust_words([1; 16], [2; 16], "https://host.test", [3; 32], [4; 32])
                .unwrap();
        assert_ne!(
            baseline,
            derive_host_trust_words([5; 16], [2; 16], "https://host.test", [3; 32], [4; 32])
                .unwrap()
        );
        assert_ne!(
            baseline,
            derive_host_trust_words([1; 16], [2; 16], "https://host.test", [5; 32], [4; 32])
                .unwrap()
        );
    }
}
