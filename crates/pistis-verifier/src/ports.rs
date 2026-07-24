use crate::{Algorithm, KeyRecord, ParsedMessage, PublicKey};
use pistis_domain::{ChallengeId, KeyId};
use pistis_protocol::{Nonce, UnixTimeMillis};

/// Parses a canonical value according to one closed protocol schema.
pub trait SignedMessageParser {
    /// Parses fields while preserving the exact input as the signature payload.
    ///
    /// # Errors
    ///
    /// Returns a classified semantic failure. Implementations must reject
    /// unknown critical fields.
    fn parse(&self, canonical_bytes: &[u8]) -> Result<ParsedMessage, ParseError>;
}

/// Semantic parsing failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    /// Fields are absent, ill-typed, out of range, or otherwise malformed.
    Malformed,
    /// The selected protocol version is unsupported.
    UnsupportedVersion,
    /// The selected signature algorithm is unsupported at the schema boundary.
    UnsupportedAlgorithm,
}

/// Resolves public verification keys from authoritative local trust material.
pub trait KeyResolver {
    /// Returns a public key record, or `None` when it is unknown.
    fn resolve(&self, key_id: &KeyId) -> Option<KeyRecord>;
}

/// Adapter for a reviewed signature implementation such as `pistis-crypto`.
pub trait SignatureVerifier {
    /// Verifies `signature` over the exact canonical bytes.
    ///
    /// # Errors
    ///
    /// Distinguishes unsupported algorithms from invalid signatures.
    fn verify(
        &self,
        algorithm: &Algorithm,
        public_key: &PublicKey,
        canonical_bytes: &[u8],
        signature: &[u8],
    ) -> Result<(), SignatureError>;
}

/// Signature verification failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureError {
    /// The algorithm is not on the verifier's explicit allow-list.
    UnsupportedAlgorithm,
    /// The signature violates the suite's unique canonical representation.
    NonCanonical,
    /// The public key, signature encoding, or signature value is invalid.
    InvalidSignature,
}

/// Source of verifier-controlled wall-clock time.
pub trait Clock {
    /// Returns the authoritative verification time, or `None` on clock failure.
    fn now(&self) -> Option<UnixTimeMillis>;
}

/// Local authorization policy evaluated before state mutation.
pub trait Policy {
    /// Authorizes a cryptographically valid, correctly bound message.
    ///
    /// # Errors
    ///
    /// Returns rejection for both negative decisions and unavailable policy
    /// state, preserving fail-closed behavior.
    fn authorize(&self, message: &ParsedMessage) -> Result<(), PolicyError>;
}

/// Fail-closed policy result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyError;

/// Atomic single-use challenge boundary.
pub trait ChallengeConsumer {
    /// Compares identifier, nonce, and expiry and consumes in one transaction.
    ///
    /// This operation runs only after parsing, signature, binding, time, key,
    /// and policy checks succeed.
    ///
    /// # Errors
    ///
    /// Distinguishes replay and expiry from other fail-closed state rejection.
    fn consume(
        &self,
        challenge_id: ChallengeId,
        nonce: &Nonce,
        now: UnixTimeMillis,
    ) -> Result<(), ChallengeError>;
}

/// Atomic challenge-consumption failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengeError {
    /// A tombstone or missing active record identifies a replay.
    AlreadyConsumed,
    /// The authoritative challenge reached its exclusive expiry.
    Expired,
    /// State is unavailable or the nonce/identifier does not match.
    Rejected,
}
