//! Production verification boundary for ADR 0019 authentication responses.

use crate::{Decision, UnixTimeMillis, schema::decode_response};
use pistis_cose::{CoseError, verify_sign1};
use pistis_crypto::{PublicKey, derive_key_id, sha256};
use pistis_domain::{ChallengeId, DeviceId, ExternalIdentityId, InstallationId, KeyId, UserId};
use pistis_qr::MAX_COSE_ENVELOPE_BYTES;
use std::{error::Error, fmt};

/// Authority-owned, active verification material for the enrolled device.
#[derive(Clone, Debug)]
pub struct AuthenticationResponseCredential {
    /// Key identifier persisted by the authority at enrolment.
    pub key_id: KeyId,
    /// Reviewed ES256 public key persisted by the authority.
    pub public_key: PublicKey,
    /// Whether the authority currently permits this credential to authenticate.
    pub active: bool,
}

/// Immutable authority facts against which one signed response is verified.
///
/// `challenge_digest` is SHA-256 of the exact canonical challenge payload.
/// `nonce_digest` is SHA-256 of its secret nonce, so the raw nonce need not
/// cross the authority boundary. Captured and current generations are both
/// required; equality is checked here and again by the durable authority
/// transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationResponseExpectation {
    /// Host time at which verification is attempted.
    pub now: UnixTimeMillis,
    /// Host-owned challenge creation time.
    pub challenge_issued_at: UnixTimeMillis,
    /// Exclusive host-owned challenge expiry.
    pub challenge_expires_at: UnixTimeMillis,
    /// Installation that issued the challenge.
    pub installation_id: InstallationId,
    /// Single-use challenge identifier.
    pub challenge_id: ChallengeId,
    /// Digest of the exact canonical challenge payload.
    pub challenge_digest: [u8; 32],
    /// Digest of the challenge nonce.
    pub nonce_digest: [u8; 32],
    /// Existing local principal bound to the challenge.
    pub user_id: UserId,
    /// Stable provider identity bound to the principal.
    pub external_identity_id: ExternalIdentityId,
    /// Enrolled device selected by the authority.
    pub device_id: DeviceId,
    /// Binding generation captured when the challenge was created.
    pub binding_generation: u64,
    /// Current binding generation.
    pub current_binding_generation: u64,
    /// Policy generation captured when the challenge was created.
    pub policy_generation: u64,
    /// Current policy generation.
    pub current_policy_generation: u64,
    /// Revocation generation captured when the challenge was created.
    pub revocation_generation: u64,
    /// Current revocation generation.
    pub current_revocation_generation: u64,
    /// Whether the durable authority has already consumed the challenge.
    pub response_consumed: bool,
}

/// Credential-free facts established by signature and authoritative binding.
///
/// This value contains no public key, signature, nonce, browser secret, bearer
/// credential, provider token, email address, or caller-selected assertion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAuthenticationResponse {
    /// Explicit Face ID-gated decision signed by the device.
    pub decision: Decision,
    /// SHA-256 of the exact submitted COSE envelope.
    pub response_digest: [u8; 32],
}

/// Fail-closed reason that a production response was not accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationResponseVerificationError {
    /// Input was empty, oversized, malformed, non-canonical, or unsigned.
    InvalidResponse,
    /// The authority-owned credential is inactive or internally inconsistent.
    InactiveCredential,
    /// Host time is outside the challenge validity interval.
    Expired,
    /// The durable authority reports that the challenge was already consumed.
    Replayed,
    /// A binding, digest, identity, time, or generation was substituted.
    BindingMismatch,
}

impl fmt::Display for AuthenticationResponseVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidResponse => "invalid signed authentication response",
            Self::InactiveCredential => "authentication credential is not active",
            Self::Expired => "authentication challenge has expired",
            Self::Replayed => "authentication challenge has already been consumed",
            Self::BindingMismatch => "authentication response binding mismatch",
        })
    }
}

impl Error for AuthenticationResponseVerificationError {}

/// Verify one bounded ADR 0018 COSE Sign1 / ADR 0019 authentication response.
///
/// Both approval and denial are valid signed terminal decisions. A caller must
/// pass the returned facts to its durable single-use authority transaction;
/// this function creates no session and mutates no state.
///
/// # Errors
///
/// Rejects malformed, non-canonical, oversized, wrongly keyed, invalid,
/// high-S, expired, replayed, inactive, stale-generation, or substituted input.
pub fn verify_authentication_response(
    envelope: &[u8],
    expected: &AuthenticationResponseExpectation,
    credential: &AuthenticationResponseCredential,
) -> Result<VerifiedAuthenticationResponse, AuthenticationResponseVerificationError> {
    validate_envelope_size(envelope)?;
    if !credential.active || derive_key_id(&credential.public_key) != credential.key_id {
        return Err(AuthenticationResponseVerificationError::InactiveCredential);
    }
    if expected.response_consumed {
        return Err(AuthenticationResponseVerificationError::Replayed);
    }
    if expected.challenge_issued_at >= expected.challenge_expires_at
        || expected.now < expected.challenge_issued_at
        || expected.now >= expected.challenge_expires_at
    {
        return Err(AuthenticationResponseVerificationError::Expired);
    }
    if expected.binding_generation != expected.current_binding_generation
        || expected.policy_generation != expected.current_policy_generation
        || expected.revocation_generation != expected.current_revocation_generation
    {
        return Err(AuthenticationResponseVerificationError::BindingMismatch);
    }

    let verified = verify_sign1(envelope, &credential.public_key).map_err(map_cose)?;
    if verified.key_id() != credential.key_id {
        return Err(AuthenticationResponseVerificationError::BindingMismatch);
    }
    let response = decode_response(verified.payload())
        .map_err(|_| AuthenticationResponseVerificationError::InvalidResponse)?;
    if response.issued_at < expected.challenge_issued_at
        || response.user_verified_at >= expected.challenge_expires_at
        || response.issued_at > expected.now
        || response.user_verified_at > expected.now
        || response.installation_id != expected.installation_id
        || response.key_id != credential.key_id
        || response.challenge_id != expected.challenge_id
        || sha256(&response.nonce).into_bytes() != expected.nonce_digest
        || response.challenge_digest != expected.challenge_digest
        || response.user_id != expected.user_id
        || response.device_id != expected.device_id
        || response.external_identity_id != expected.external_identity_id
    {
        return Err(AuthenticationResponseVerificationError::BindingMismatch);
    }

    Ok(VerifiedAuthenticationResponse {
        decision: response.decision,
        response_digest: sha256(envelope).into_bytes(),
    })
}

fn validate_envelope_size(envelope: &[u8]) -> Result<(), AuthenticationResponseVerificationError> {
    if envelope.is_empty() || envelope.len() > MAX_COSE_ENVELOPE_BYTES {
        Err(AuthenticationResponseVerificationError::InvalidResponse)
    } else {
        Ok(())
    }
}

fn map_cose(_: CoseError) -> AuthenticationResponseVerificationError {
    AuthenticationResponseVerificationError::InvalidResponse
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_envelope_bound_matches_qr_and_is_inclusive() {
        assert_eq!(
            validate_envelope_size(&vec![0; MAX_COSE_ENVELOPE_BYTES]),
            Ok(())
        );
        assert_eq!(
            validate_envelope_size(&vec![0; MAX_COSE_ENVELOPE_BYTES + 1]),
            Err(AuthenticationResponseVerificationError::InvalidResponse)
        );
    }
}
