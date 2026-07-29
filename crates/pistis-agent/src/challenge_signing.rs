//! Host-side production signing of authentication challenges.

use crate::{InstallationSigner, SignerError};
use pistis_authentication::{ChallengeDocument, UnixTimeMillis, encode_challenge};
use pistis_cose::{CoseError, encode, signing_input, verify_sign1};
use pistis_crypto::{PublicKey, PublicKeyError, Sha256Digest, derive_key_id, sha256};
use pistis_domain::{ChallengeId, ExternalIdentityId, InstallationId, KeyId, UserId};
use std::{error::Error, fmt};

/// Closed ADR 0019 purpose for a signed authentication challenge.
pub const AUTHENTICATION_CHALLENGE_PURPOSE: &str = "pistis.authentication-challenge.v1";

macro_rules! digest_type {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct $name(Sha256Digest);

        impl $name {
            /// Borrow all 32 digest bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                self.0.as_bytes()
            }

            /// Return all 32 digest bytes.
            #[must_use]
            pub const fn into_bytes(self) -> [u8; 32] {
                self.0.into_bytes()
            }
        }
    };
}

digest_type!(
    ChallengePayloadDigest,
    "SHA-256 of the exact canonical ADR 0019 challenge payload."
);
digest_type!(
    ChallengeEnvelopeDigest,
    "SHA-256 of the exact production COSE Sign1 challenge envelope."
);
digest_type!(
    NonceDigest,
    "SHA-256 of the challenge nonce; safe to persist instead of the raw nonce."
);

/// Immutable authority facts derived from one signed challenge.
///
/// Prosopikon's durable `challenge_digest` is [`Self::payload_digest`], while
/// its separately named signed-envelope fingerprint is
/// [`Self::envelope_digest`]. The raw nonce is intentionally absent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationChallengeFacts {
    /// Closed payload purpose.
    pub purpose: &'static str,
    /// Authority-generated challenge identifier.
    pub challenge_id: ChallengeId,
    /// Installation receiving the response.
    pub installation_id: InstallationId,
    /// Installation key bound into the protected header and payload.
    pub installation_key_id: KeyId,
    /// Authority-selected local user.
    pub user_id: UserId,
    /// Required external identity binding.
    pub external_identity_id: ExternalIdentityId,
    /// Host-owned issue time.
    pub issued_at: UnixTimeMillis,
    /// Exclusive host-owned expiry.
    pub expires_at: UnixTimeMillis,
    /// Exact signed audience.
    pub audience: String,
    /// Bounded signed response endpoint hints.
    pub endpoint_hints: Vec<String>,
    /// Digest of the exact canonical payload.
    pub payload_digest: ChallengePayloadDigest,
    /// Digest of the exact COSE envelope; a separate signed-envelope fingerprint.
    pub envelope_digest: ChallengeEnvelopeDigest,
    /// Digest of the secret nonce.
    pub nonce_digest: NonceDigest,
}

/// Exact production bytes and persistence-safe facts for one host challenge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedAuthenticationChallenge {
    /// Exact canonical ADR 0019 payload embedded in `envelope`.
    pub payload: Vec<u8>,
    /// Exact untagged ADR 0018 COSE Sign1 transported to the phone.
    pub envelope: Vec<u8>,
    /// Typed facts for the authoritative begin transaction.
    pub facts: AuthenticationChallengeFacts,
}

/// Reviewed adapter from a non-exportable provider to ADR 0018 COSE Sign1.
pub struct HostChallengeSigner<S> {
    public_key: PublicKey,
    key_id: KeyId,
    provider: S,
}

impl<S> HostChallengeSigner<S> {
    /// Configure from an enrolled canonical public key and expected key ID.
    ///
    /// Private material is neither accepted nor retained. The provider may be
    /// backed by a file, HSM, platform keychain, or secret store, but exposes
    /// only the narrow [`InstallationSigner`] operation.
    ///
    /// # Errors
    ///
    /// Rejects malformed public keys and a key ID not derived from that key.
    pub fn new(
        public_key_sec1: &[u8],
        expected_key_id: KeyId,
        provider: S,
    ) -> Result<Self, ChallengeSigningError> {
        let public_key = PublicKey::from_sec1_bytes(public_key_sec1)
            .map_err(ChallengeSigningError::InvalidPublicKey)?;
        let key_id = derive_key_id(&public_key);
        if key_id != expected_key_id {
            return Err(ChallengeSigningError::KeyMismatch);
        }
        Ok(Self {
            public_key,
            key_id,
            provider,
        })
    }

    /// Return the enrolled installation key identifier.
    #[must_use]
    pub const fn key_id(&self) -> KeyId {
        self.key_id
    }
}

impl<S: InstallationSigner> HostChallengeSigner<S> {
    /// Canonically encode and sign one complete ADR 0019 challenge.
    ///
    /// The provider signs the exact ADR 0018 `Sig_structure`. Its returned key
    /// ID and signature are checked against the configured public key before
    /// any envelope or authority facts are returned.
    ///
    /// # Errors
    ///
    /// Fails closed for invalid fields, key substitution, provider failure,
    /// malformed/high-S/incorrect signatures, or oversized output.
    pub fn sign(
        &self,
        challenge: &ChallengeDocument,
    ) -> Result<SignedAuthenticationChallenge, ChallengeSigningError> {
        if challenge.installation_key_id != self.key_id {
            return Err(ChallengeSigningError::KeyMismatch);
        }
        let payload =
            encode_challenge(challenge).map_err(|_| ChallengeSigningError::InvalidChallenge)?;
        let sig_structure =
            signing_input(&payload, self.key_id).map_err(ChallengeSigningError::Cose)?;
        let signed = self
            .provider
            .sign(&sig_structure)
            .map_err(ChallengeSigningError::Provider)?;
        if signed.key_id != self.key_id {
            return Err(ChallengeSigningError::KeyMismatch);
        }
        let envelope = encode(&payload, self.key_id, &signed.signature)
            .map_err(ChallengeSigningError::Cose)?;
        let verified =
            verify_sign1(&envelope, &self.public_key).map_err(ChallengeSigningError::Cose)?;
        if verified.payload() != payload {
            return Err(ChallengeSigningError::InvalidSignature);
        }
        let facts = AuthenticationChallengeFacts {
            purpose: AUTHENTICATION_CHALLENGE_PURPOSE,
            challenge_id: challenge.challenge_id,
            installation_id: challenge.installation_id,
            installation_key_id: challenge.installation_key_id,
            user_id: challenge.user_id,
            external_identity_id: challenge.external_identity_id,
            issued_at: challenge.issued_at,
            expires_at: challenge.expires_at,
            audience: challenge.audience.clone(),
            endpoint_hints: challenge.endpoint_hints.clone(),
            payload_digest: ChallengePayloadDigest(sha256(&payload)),
            envelope_digest: ChallengeEnvelopeDigest(sha256(&envelope)),
            nonce_digest: NonceDigest(sha256(&challenge.nonce)),
        };
        Ok(SignedAuthenticationChallenge {
            payload,
            envelope,
            facts,
        })
    }
}

/// Fail-closed host challenge signing error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengeSigningError {
    /// Configured public key is malformed.
    InvalidPublicKey(PublicKeyError),
    /// Payload, provider, expected key ID, or public key did not match.
    KeyMismatch,
    /// Challenge violates the closed ADR 0019 schema.
    InvalidChallenge,
    /// Non-exportable provider failed.
    Provider(SignerError),
    /// COSE assembly or strict verification failed.
    Cose(CoseError),
    /// Provider output could not authenticate the exact challenge.
    InvalidSignature,
}

impl fmt::Display for ChallengeSigningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPublicKey(_) => "installation public key rejected",
            Self::KeyMismatch => "installation signing key mismatch",
            Self::InvalidChallenge => "authentication challenge rejected",
            Self::Provider(_) => "installation signing provider failed",
            Self::Cose(_) | Self::InvalidSignature => "challenge signature rejected",
        })
    }
}

impl Error for ChallengeSigningError {}
