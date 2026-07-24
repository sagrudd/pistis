use pistis_domain::{ChallengeId, InstallationId, KeyId, UserId};
use pistis_protocol::{Nonce, UnixTimeMillis};
use pistis_verifier::{
    Algorithm, ChallengeConsumer, ChallengeError, Clock, ExpectedBindings, KeyRecord, KeyResolver,
    KeyStatus, ParseError, ParsedMessage, Policy, PolicyError, PublicKey, SignatureError,
    SignatureVerifier, SignedMessageParser, VerificationInput, VerificationOutcome, Verifier,
};
use std::cell::Cell;

const CANONICAL: &[u8] = &[0xa0];

fn id<const BYTE: u8>() -> [u8; 16] {
    [BYTE; 16]
}

fn key_id<const BYTE: u8>() -> [u8; 32] {
    [BYTE; 32]
}

fn message() -> ParsedMessage {
    ParsedMessage {
        version: 1,
        algorithm: Algorithm::new("ES256"),
        key_id: KeyId::from_bytes(key_id::<3>()),
        installation_id: InstallationId::from_bytes(id::<1>()),
        user_id: UserId::from_bytes(id::<2>()),
        purpose: "pistis.authentication-response.v1".into(),
        expires_at: UnixTimeMillis::new(200),
        challenge_id: ChallengeId::from_bytes(id::<4>()),
        nonce: Nonce::from_bytes([5; 32]),
    }
}

fn expected() -> ExpectedBindings {
    ExpectedBindings {
        installation_id: InstallationId::from_bytes(id::<1>()),
        user_id: UserId::from_bytes(id::<2>()),
        purpose: "pistis.authentication-response.v1".into(),
    }
}

struct Parser(Result<ParsedMessage, ParseError>);
impl SignedMessageParser for Parser {
    fn parse(&self, _: &[u8]) -> Result<ParsedMessage, ParseError> {
        self.0.clone()
    }
}

struct Keys(Option<KeyRecord>);
impl KeyResolver for Keys {
    fn resolve(&self, _: &KeyId) -> Option<KeyRecord> {
        self.0.clone()
    }
}

struct Signatures {
    result: Result<(), SignatureError>,
}
impl SignatureVerifier for Signatures {
    fn verify(
        &self,
        _: &Algorithm,
        _: &PublicKey,
        bytes: &[u8],
        _: &[u8],
    ) -> Result<(), SignatureError> {
        assert_eq!(bytes, CANONICAL, "signature must cover the exact input");
        self.result
    }
}

struct TestClock(Option<UnixTimeMillis>);
impl Clock for TestClock {
    fn now(&self) -> Option<UnixTimeMillis> {
        self.0
    }
}

struct TestPolicy(Result<(), PolicyError>);
impl Policy for TestPolicy {
    fn authorize(&self, _: &ParsedMessage) -> Result<(), PolicyError> {
        self.0
    }
}

struct Challenges {
    result: Result<(), ChallengeError>,
    calls: Cell<usize>,
}
impl ChallengeConsumer for Challenges {
    fn consume(&self, _: ChallengeId, _: &Nonce, _: UnixTimeMillis) -> Result<(), ChallengeError> {
        self.calls.set(self.calls.get() + 1);
        self.result
    }
}

#[allow(clippy::too_many_arguments)]
fn run(
    parsed: Result<ParsedMessage, ParseError>,
    key: Option<KeyRecord>,
    signature: Result<(), SignatureError>,
    now: Option<UnixTimeMillis>,
    policy: Result<(), PolicyError>,
    consumption: Result<(), ChallengeError>,
    bytes: &[u8],
    bindings: ExpectedBindings,
) -> (VerificationOutcome, usize) {
    let signatures = Signatures { result: signature };
    let challenges = Challenges {
        result: consumption,
        calls: Cell::new(0),
    };
    let verifier = Verifier::new(
        Parser(parsed),
        Keys(key),
        signatures,
        TestClock(now),
        TestPolicy(policy),
    );
    let outcome = verifier.verify(
        &VerificationInput {
            canonical_bytes: bytes,
            signature: &[6; 64],
            expected: bindings,
        },
        &challenges,
    );
    (outcome, challenges.calls.get())
}

#[allow(clippy::unnecessary_wraps)]
fn active_key() -> Option<KeyRecord> {
    Some(KeyRecord {
        public_key: PublicKey::new([7; 65]),
        status: KeyStatus::Active,
    })
}

#[allow(clippy::too_many_arguments)]
fn outcome_with(
    parsed: Result<ParsedMessage, ParseError>,
    key: Option<KeyRecord>,
    signature: Result<(), SignatureError>,
    now: Option<UnixTimeMillis>,
    policy: Result<(), PolicyError>,
    consumption: Result<(), ChallengeError>,
    bytes: &[u8],
    bindings: ExpectedBindings,
) -> (VerificationOutcome, usize) {
    run(
        parsed,
        key,
        signature,
        now,
        policy,
        consumption,
        bytes,
        bindings,
    )
}

#[test]
fn accepts_and_consumes_only_after_all_checks() {
    assert_eq!(
        outcome_with(
            Ok(message()),
            active_key(),
            Ok(()),
            Some(UnixTimeMillis::new(199)),
            Ok(()),
            Ok(()),
            CANONICAL,
            expected(),
        ),
        (VerificationOutcome::Valid, 1)
    );
}

#[test]
fn classifies_canonical_and_schema_failures_without_consuming() {
    for (bytes, parsed, expected_outcome) in [
        (
            &[0x18, 0x00][..],
            Ok(message()),
            VerificationOutcome::NonCanonical,
        ),
        (&[0xff][..], Ok(message()), VerificationOutcome::Malformed),
        (
            CANONICAL,
            Err(ParseError::Malformed),
            VerificationOutcome::Malformed,
        ),
        (
            CANONICAL,
            Err(ParseError::UnsupportedVersion),
            VerificationOutcome::UnsupportedVersion,
        ),
        (
            CANONICAL,
            Err(ParseError::UnsupportedAlgorithm),
            VerificationOutcome::UnsupportedAlgorithm,
        ),
    ] {
        assert_eq!(
            outcome_with(
                parsed,
                active_key(),
                Ok(()),
                Some(UnixTimeMillis::new(100)),
                Ok(()),
                Ok(()),
                bytes,
                expected(),
            ),
            (expected_outcome, 0)
        );
    }
}

#[test]
fn classifies_key_and_signature_failures_without_consuming() {
    let revoked = Some(KeyRecord {
        public_key: PublicKey::new([]),
        status: KeyStatus::Revoked,
    });
    for (key, signature, expected_outcome) in [
        (None, Ok(()), VerificationOutcome::UnknownKey),
        (revoked, Ok(()), VerificationOutcome::RevokedKey),
        (
            active_key(),
            Err(SignatureError::InvalidSignature),
            VerificationOutcome::InvalidSignature,
        ),
        (
            active_key(),
            Err(SignatureError::UnsupportedAlgorithm),
            VerificationOutcome::UnsupportedAlgorithm,
        ),
        (
            active_key(),
            Err(SignatureError::NonCanonical),
            VerificationOutcome::NonCanonical,
        ),
    ] {
        assert_eq!(
            outcome_with(
                Ok(message()),
                key,
                signature,
                Some(UnixTimeMillis::new(100)),
                Ok(()),
                Ok(()),
                CANONICAL,
                expected(),
            ),
            (expected_outcome, 0)
        );
    }
}

#[test]
fn classifies_binding_time_and_policy_failures_without_consuming() {
    let mut wrong_installation = expected();
    wrong_installation.installation_id = InstallationId::from_bytes(id::<9>());
    let mut wrong_user = expected();
    wrong_user.user_id = UserId::from_bytes(id::<9>());
    let mut wrong_purpose = expected();
    wrong_purpose.purpose = "pistis.artefact-response.v1".into();
    for (bindings, now, policy, expected_outcome) in [
        (
            wrong_installation,
            Some(UnixTimeMillis::new(100)),
            Ok(()),
            VerificationOutcome::WrongInstallation,
        ),
        (
            wrong_user,
            Some(UnixTimeMillis::new(100)),
            Ok(()),
            VerificationOutcome::WrongUser,
        ),
        (
            wrong_purpose,
            Some(UnixTimeMillis::new(100)),
            Ok(()),
            VerificationOutcome::WrongPurpose,
        ),
        (
            expected(),
            Some(UnixTimeMillis::new(200)),
            Ok(()),
            VerificationOutcome::Expired,
        ),
        (
            expected(),
            None,
            Ok(()),
            VerificationOutcome::PolicyRejected,
        ),
        (
            expected(),
            Some(UnixTimeMillis::new(100)),
            Err(PolicyError),
            VerificationOutcome::PolicyRejected,
        ),
    ] {
        assert_eq!(
            outcome_with(
                Ok(message()),
                active_key(),
                Ok(()),
                now,
                policy,
                Ok(()),
                CANONICAL,
                bindings,
            ),
            (expected_outcome, 0)
        );
    }
}

#[test]
fn classifies_atomic_consumption_failures() {
    for (error, expected_outcome) in [
        (
            ChallengeError::AlreadyConsumed,
            VerificationOutcome::AlreadyConsumed,
        ),
        (ChallengeError::Expired, VerificationOutcome::Expired),
        (
            ChallengeError::Rejected,
            VerificationOutcome::PolicyRejected,
        ),
    ] {
        assert_eq!(
            outcome_with(
                Ok(message()),
                active_key(),
                Ok(()),
                Some(UnixTimeMillis::new(100)),
                Ok(()),
                Err(error),
                CANONICAL,
                expected(),
            ),
            (expected_outcome, 1)
        );
    }
}
