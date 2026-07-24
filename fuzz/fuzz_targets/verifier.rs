#![no_main]

use libfuzzer_sys::fuzz_target;
use pistis_canonical::MAX_MESSAGE_SIZE;
use pistis_domain::{ChallengeId, InstallationId, KeyId, UserId};
use pistis_protocol::{Nonce, UnixTimeMillis};
use pistis_verifier::{
    Algorithm, ChallengeConsumer, ChallengeError, Clock, ExpectedBindings, KeyRecord, KeyResolver,
    KeyStatus, ParseError, ParsedMessage, Policy, PolicyError, PublicKey, SignatureError,
    SignatureVerifier, SignedMessageParser, VerificationInput, Verifier,
};

struct AdversarialParser(u8);

impl SignedMessageParser for AdversarialParser {
    fn parse(&self, bytes: &[u8]) -> Result<ParsedMessage, ParseError> {
        match self.0 & 0x0f {
            0 => return Err(ParseError::Malformed),
            1 => return Err(ParseError::UnsupportedVersion),
            2 => return Err(ParseError::UnsupportedAlgorithm),
            _ => {}
        }
        Ok(ParsedMessage {
            version: u64::from(self.0 & 1) + 1,
            algorithm: Algorithm::new(if self.0 & 2 == 0 { "ES256" } else { "other" }),
            key_id: KeyId::from_bytes([self.0; 32]),
            installation_id: InstallationId::from_bytes([self.0; 16]),
            user_id: UserId::from_bytes([self.0.rotate_left(1); 16]),
            purpose: String::from_utf8_lossy(bytes.get(..bytes.len().min(32)).unwrap_or(bytes))
                .into_owned(),
            expires_at: UnixTimeMillis::new(u64::from(self.0).saturating_mul(10)),
            challenge_id: ChallengeId::from_bytes([self.0.rotate_left(2); 16]),
            nonce: Nonce::from_bytes([self.0.rotate_left(3); 32]),
        })
    }
}

struct AdversarialKeys(u8);

impl KeyResolver for AdversarialKeys {
    fn resolve(&self, _: &KeyId) -> Option<KeyRecord> {
        (self.0 & 0x10 == 0).then(|| KeyRecord {
            public_key: PublicKey::new([self.0; 33]),
            status: if self.0 & 0x20 == 0 {
                KeyStatus::Active
            } else {
                KeyStatus::Revoked
            },
        })
    }
}

struct AdversarialSignatures(u8);

impl SignatureVerifier for AdversarialSignatures {
    fn verify(
        &self,
        _: &Algorithm,
        _: &PublicKey,
        _: &[u8],
        _: &[u8],
    ) -> Result<(), SignatureError> {
        match self.0 & 0xc0 {
            0x40 => Err(SignatureError::UnsupportedAlgorithm),
            0x80 | 0xc0 => Err(SignatureError::InvalidSignature),
            _ => Ok(()),
        }
    }
}

struct AdversarialClock(u8);

impl Clock for AdversarialClock {
    fn now(&self) -> Option<UnixTimeMillis> {
        (self.0 != u8::MAX).then(|| UnixTimeMillis::new(u64::from(self.0)))
    }
}

struct AdversarialPolicy(u8);

impl Policy for AdversarialPolicy {
    fn authorize(&self, _: &ParsedMessage) -> Result<(), PolicyError> {
        if self.0 & 8 == 0 {
            Ok(())
        } else {
            Err(PolicyError)
        }
    }
}

struct AdversarialChallenges(u8);

impl ChallengeConsumer for AdversarialChallenges {
    fn consume(&self, _: ChallengeId, _: &Nonce, _: UnixTimeMillis) -> Result<(), ChallengeError> {
        match self.0 & 3 {
            0 => Ok(()),
            1 => Err(ChallengeError::AlreadyConsumed),
            2 => Err(ChallengeError::Expired),
            _ => Err(ChallengeError::Rejected),
        }
    }
}

fuzz_target!(|input: &[u8]| {
    if input.len() > MAX_MESSAGE_SIZE {
        return;
    }
    let selector = input.first().copied().unwrap_or_default();
    let verifier = Verifier::new(
        AdversarialParser(selector),
        AdversarialKeys(selector),
        AdversarialSignatures(selector),
        AdversarialClock(selector),
        AdversarialPolicy(selector),
    );
    let expected = ExpectedBindings {
        installation_id: InstallationId::from_bytes([selector; 16]),
        user_id: UserId::from_bytes([selector.rotate_left(1); 16]),
        purpose: String::from_utf8_lossy(input.get(..input.len().min(32)).unwrap_or(input))
            .into_owned(),
    };
    let verification_input = VerificationInput {
        canonical_bytes: input,
        signature: input.get(..input.len().min(80)).unwrap_or(input),
        expected,
    };
    let _ = verifier.verify(&verification_input, &AdversarialChallenges(selector));
});
