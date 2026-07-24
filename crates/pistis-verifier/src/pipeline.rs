use crate::{
    ChallengeConsumer, ChallengeError, Clock, KeyResolver, KeyStatus, ParseError, Policy,
    SignatureError, SignatureVerifier, SignedMessageParser, VerificationInput, VerificationOutcome,
};
use pistis_canonical::{CanonicalError, from_slice};

/// Composes verification dependencies into one deterministic pipeline.
pub struct Verifier<P, K, S, C, A> {
    parser: P,
    keys: K,
    signatures: S,
    clock: C,
    policy: A,
}

impl<P, K, S, C, A> Verifier<P, K, S, C, A> {
    /// Constructs a verifier from narrow, independently testable dependencies.
    #[must_use]
    pub const fn new(parser: P, keys: K, signatures: S, clock: C, policy: A) -> Self {
        Self {
            parser,
            keys,
            signatures,
            clock,
            policy,
        }
    }
}

impl<P, K, S, C, A> Verifier<P, K, S, C, A>
where
    P: SignedMessageParser,
    K: KeyResolver,
    S: SignatureVerifier,
    C: Clock,
    A: Policy,
{
    /// Verifies a signed message and consumes its challenge on success.
    ///
    /// Canonical parsing precedes semantic parsing. Signature verification uses
    /// the exact caller-provided bytes. State mutation is the final operation.
    #[must_use]
    pub fn verify(
        &self,
        input: &VerificationInput<'_>,
        challenges: &impl ChallengeConsumer,
    ) -> VerificationOutcome {
        if let Err(error) = from_slice(input.canonical_bytes) {
            return canonical_outcome(&error);
        }
        let message = match self.parser.parse(input.canonical_bytes) {
            Ok(message) => message,
            Err(error) => return parse_outcome(error),
        };
        let Some(key) = self.keys.resolve(&message.key_id) else {
            return VerificationOutcome::UnknownKey;
        };
        if key.status == KeyStatus::Revoked {
            return VerificationOutcome::RevokedKey;
        }
        if let Err(error) = self.signatures.verify(
            &message.algorithm,
            &key.public_key,
            input.canonical_bytes,
            input.signature,
        ) {
            return match error {
                SignatureError::UnsupportedAlgorithm => VerificationOutcome::UnsupportedAlgorithm,
                SignatureError::NonCanonical => VerificationOutcome::NonCanonical,
                SignatureError::InvalidSignature => VerificationOutcome::InvalidSignature,
            };
        }
        if message.installation_id != input.expected.installation_id {
            return VerificationOutcome::WrongInstallation;
        }
        if message.user_id != input.expected.user_id {
            return VerificationOutcome::WrongUser;
        }
        if message.purpose != input.expected.purpose {
            return VerificationOutcome::WrongPurpose;
        }
        let Some(now) = self.clock.now() else {
            return VerificationOutcome::PolicyRejected;
        };
        if now >= message.expires_at {
            return VerificationOutcome::Expired;
        }
        if self.policy.authorize(&message).is_err() {
            return VerificationOutcome::PolicyRejected;
        }
        match challenges.consume(message.challenge_id, &message.nonce, now) {
            Ok(()) => VerificationOutcome::Valid,
            Err(ChallengeError::AlreadyConsumed) => VerificationOutcome::AlreadyConsumed,
            Err(ChallengeError::Expired) => VerificationOutcome::Expired,
            Err(ChallengeError::Rejected) => VerificationOutcome::PolicyRejected,
        }
    }
}

fn parse_outcome(error: ParseError) -> VerificationOutcome {
    match error {
        ParseError::Malformed => VerificationOutcome::Malformed,
        ParseError::UnsupportedVersion => VerificationOutcome::UnsupportedVersion,
        ParseError::UnsupportedAlgorithm => VerificationOutcome::UnsupportedAlgorithm,
    }
}

fn canonical_outcome(error: &CanonicalError) -> VerificationOutcome {
    match error {
        CanonicalError::NonMinimalInteger
        | CanonicalError::MapKeyOrder
        | CanonicalError::DuplicateMapKey => VerificationOutcome::NonCanonical,
        CanonicalError::MessageTooLarge
        | CanonicalError::NestingTooDeep
        | CanonicalError::Truncated
        | CanonicalError::TrailingData
        | CanonicalError::UnsupportedType
        | CanonicalError::InvalidMapKey
        | CanonicalError::InvalidUtf8
        | CanonicalError::NegativeOutOfRange
        | CanonicalError::UnknownCriticalField(_) => VerificationOutcome::Malformed,
    }
}
