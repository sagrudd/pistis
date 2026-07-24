use pistis_domain::{ChallengeId, InstallationId, KeyId, UserId};
use pistis_protocol::{Nonce, UnixTimeMillis};

/// A signature algorithm identifier carried by a signed message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Algorithm(String);

impl Algorithm {
    /// Constructs an algorithm identifier without treating it as supported.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the wire identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Public verification-key bytes in the resolver's agreed representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKey(Vec<u8>);

impl PublicKey {
    /// Wraps public key bytes. This type cannot represent private key material.
    #[must_use]
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Returns the public key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Resolver-maintained lifecycle state for a public key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyStatus {
    /// The key may verify messages.
    Active,
    /// The key was revoked and must fail closed.
    Revoked,
}

/// A resolved public key and its authoritative status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyRecord {
    /// Public verification key.
    pub public_key: PublicKey,
    /// Current key lifecycle state.
    pub status: KeyStatus,
}

/// Security bindings expected by the relying operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedBindings {
    /// Installation allowed to accept the message.
    pub installation_id: InstallationId,
    /// User allowed to satisfy the operation.
    pub user_id: UserId,
    /// Exact domain-separation purpose.
    pub purpose: String,
}

/// Semantically parsed fields covered by `canonical_bytes`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedMessage {
    /// Protocol version selected by the producer.
    pub version: u64,
    /// Exact signature algorithm identifier.
    pub algorithm: Algorithm,
    /// Key identifier bound into the message.
    pub key_id: KeyId,
    /// Installation namespace bound into the message.
    pub installation_id: InstallationId,
    /// User bound into the purpose-specific payload.
    pub user_id: UserId,
    /// Exact domain-separation purpose.
    pub purpose: String,
    /// Exclusive upper bound on validity.
    pub expires_at: UnixTimeMillis,
    /// Challenge identifier to consume after every other check succeeds.
    pub challenge_id: ChallengeId,
    /// Challenge nonce to compare atomically during consumption.
    pub nonce: Nonce,
}

/// Inputs controlled by the verifier, not by the signed producer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationInput<'a> {
    /// Exact signed bytes. These bytes are canonicality-checked and verified.
    pub canonical_bytes: &'a [u8],
    /// Detached signature authenticating exactly `canonical_bytes`.
    pub signature: &'a [u8],
    /// Security bindings required by the relying operation.
    pub expected: ExpectedBindings,
}

/// Complete structured result of one verification attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationOutcome {
    /// Every check succeeded and the challenge was atomically consumed.
    Valid,
    /// The signature did not verify over the exact canonical bytes.
    InvalidSignature,
    /// The message or its challenge reached its exclusive expiry.
    Expired,
    /// The challenge was already consumed.
    AlreadyConsumed,
    /// The installation binding differs from the verifier's expectation.
    WrongInstallation,
    /// The user binding differs from the verifier's expectation.
    WrongUser,
    /// The purpose binding differs from the verifier's expectation.
    WrongPurpose,
    /// No trusted public key has the signed key identifier.
    UnknownKey,
    /// The resolved key is revoked.
    RevokedKey,
    /// Local authorization policy rejected an otherwise valid message.
    PolicyRejected,
    /// The canonical value does not match the selected protocol schema.
    Malformed,
    /// The protocol version is not explicitly supported.
    UnsupportedVersion,
    /// The signature algorithm is not explicitly supported.
    UnsupportedAlgorithm,
    /// The bytes violate the deterministic CBOR profile.
    NonCanonical,
}
