//! Typed handoff from a verified App Attest fact to Monas session completion.
//!
//! The handoff is deliberately a framework-neutral, non-secret record. It
//! carries no raw Apple assertion, credential, cookie, role, token, local
//! account, operating-system identity, or browser-session material. Monas and
//! Prosopikon retain authority: they re-resolve bindings, consume the fact,
//! issue the protected session, and append audit evidence atomically.

use core::fmt;

use sha2::{Digest as _, Sha256};

use crate::{
    AuditCorrelationId, BindingExpectation, BindingResolver, DeliveryProfile, HostSessionRequest,
    IntegrationBlocker, OperationPurpose, SiteTrustFactConsumptionRequestV1,
    SiteTrustHumanAuthorityFactV1, StandaloneReadiness,
};
use pistis_protocol::UnixTimeMillis;

/// Exact versioned profile for a fact-to-session handoff.
pub const MONAS_APP_ATTEST_SESSION_HANDOFF_PROFILE_V1: &str =
    "mnemosyne.pistis.monas-app-attest-session-handoff.v1";

const MONAS_LOCAL_AUDIENCE_V1: &str = "monas-local";
const MONAS_SESSION_SITE_TRUST_PURPOSE_V1: &str = "trust-admission";

const HANDOFF_DIGEST_DOMAIN_V1: &[u8] = b"mnemosyne.pistis.monas-app-attest-session-handoff.v1\0";
const MAXIMUM_CANONICAL_HANDOFF_BYTES: usize = 1024;
const HANDOFF_FIELD_COUNT: usize = 17;

/// Redacted failure while deriving a Monas session handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MonasAppAttestSessionHandoffErrorV1 {
    /// The fact was issued for another product audience.
    WrongAudience,
    /// The Site Trust fact cannot establish a Monas session.
    WrongSiteTrustPurpose,
    /// The fact does not bind the exact installation, device, or key request.
    FactBindingMismatch,
    /// The request attempts a non-session purpose.
    WrongPurpose,
    /// The audit correlation or authentication timestamp is unusable.
    InvalidCompletionMetadata,
    /// A bounded canonical handoff could not be constructed.
    Malformed,
    /// Monas readiness or current authority resolution blocked the handoff.
    Integration(IntegrationBlocker),
}

impl fmt::Display for MonasAppAttestSessionHandoffErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WrongAudience => "App Attest fact did not target Monas",
            Self::WrongSiteTrustPurpose => "App Attest fact cannot establish a Monas session",
            Self::FactBindingMismatch => "App Attest fact did not bind the Monas session request",
            Self::WrongPurpose => "App Attest fact cannot authorize this Monas operation",
            Self::InvalidCompletionMetadata => "Monas session handoff metadata is invalid",
            Self::Malformed => "Monas session handoff is malformed",
            Self::Integration(_) => "Monas session handoff was blocked",
        })
    }
}

impl std::error::Error for MonasAppAttestSessionHandoffErrorV1 {}

/// Canonical, typed proof handoff to the Monas completion transaction.
///
/// This value is created only from an opaque verified fact. Its bytes are
/// deterministic, bounded, and suitable for a private authenticated transport
/// between Pistis and Monas; it is not a browser payload or a session token.
#[derive(Clone, Eq, PartialEq)]
pub struct MonasAppAttestSessionHandoffV1 {
    fact: SiteTrustHumanAuthorityFactV1,
    expected: BindingExpectation,
    authenticated_at: UnixTimeMillis,
    correlation_id: AuditCorrelationId,
    canonical_bytes: Vec<u8>,
    digest: [u8; 32],
}

impl fmt::Debug for MonasAppAttestSessionHandoffV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MonasAppAttestSessionHandoffV1")
            .field("profile", &MONAS_APP_ATTEST_SESSION_HANDOFF_PROFILE_V1)
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

impl MonasAppAttestSessionHandoffV1 {
    /// Binds one verified iPhone fact to one exact Monas session request.
    ///
    /// # Errors
    ///
    /// Denies any fact substitution, non-session purpose, or all-zero
    /// correlation/timestamp before a host resolver, store, or session issuer
    /// is reachable.
    pub fn from_verified_app_attest_fact(
        fact: SiteTrustHumanAuthorityFactV1,
        expected: BindingExpectation,
        authenticated_at: UnixTimeMillis,
        correlation_id: AuditCorrelationId,
    ) -> Result<Self, MonasAppAttestSessionHandoffErrorV1> {
        if fact.canonical_payload().audience() != MONAS_LOCAL_AUDIENCE_V1 {
            return Err(MonasAppAttestSessionHandoffErrorV1::WrongAudience);
        }
        if fact.canonical_payload().purpose() != MONAS_SESSION_SITE_TRUST_PURPOSE_V1 {
            return Err(MonasAppAttestSessionHandoffErrorV1::WrongSiteTrustPurpose);
        }
        if expected.purpose != OperationPurpose::AuthenticateSession {
            return Err(MonasAppAttestSessionHandoffErrorV1::WrongPurpose);
        }
        if fact.installation_id() != expected.installation_id
            || fact.device_id() != expected.device_id
            || fact.key_id() != expected.key_id
        {
            return Err(MonasAppAttestSessionHandoffErrorV1::FactBindingMismatch);
        }
        if authenticated_at.get() == 0 || correlation_id.is_zero_sentinel() {
            return Err(MonasAppAttestSessionHandoffErrorV1::InvalidCompletionMetadata);
        }
        let canonical_bytes = canonical_bytes(&fact, expected, authenticated_at, correlation_id)?;
        let digest =
            Sha256::digest([HANDOFF_DIGEST_DOMAIN_V1, canonical_bytes.as_slice()].concat()).into();
        Ok(Self {
            fact,
            expected,
            authenticated_at,
            correlation_id,
            canonical_bytes,
            digest,
        })
    }

    /// Returns the exact canonical bounded handoff bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Returns a domain-separated digest suitable for a Monas audit record.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Returns the exact request for the Monas-owned one-use fact consumption.
    #[must_use]
    pub fn fact_consumption_request(&self) -> SiteTrustFactConsumptionRequestV1 {
        self.fact.consumption_request()
    }

    /// Re-resolves current Monas authority and creates a session request.
    ///
    /// This only prepares the request. The host must consume
    /// [`Self::fact_consumption_request`], invalidate pre-authentication state,
    /// issue its protected Prosopikon session, and append the audit record in
    /// one transaction. No session is issued by Pistis.
    ///
    /// # Errors
    ///
    /// Readiness and every authoritative binding are re-evaluated by Monas;
    /// any failure denies before session issuance.
    pub fn authorize_for_monas(
        &self,
        profile: DeliveryProfile,
        readiness: &StandaloneReadiness,
        resolver: &impl BindingResolver,
    ) -> Result<HostSessionRequest, MonasAppAttestSessionHandoffErrorV1> {
        HostSessionRequest::authorize(
            profile,
            readiness,
            resolver,
            self.expected,
            self.authenticated_at,
            self.correlation_id,
        )
        .map_err(MonasAppAttestSessionHandoffErrorV1::Integration)
    }
}

fn canonical_bytes(
    fact: &SiteTrustHumanAuthorityFactV1,
    expected: BindingExpectation,
    authenticated_at: UnixTimeMillis,
    correlation_id: AuditCorrelationId,
) -> Result<Vec<u8>, MonasAppAttestSessionHandoffErrorV1> {
    let mut output = Vec::new();
    for (tag, value) in [
        (1, MONAS_APP_ATTEST_SESSION_HANDOFF_PROFILE_V1.as_bytes()),
        (2, fact.profile().as_bytes()),
        (3, fact.id().as_bytes().as_slice()),
        (4, fact.ceremony_id().as_bytes().as_slice()),
        (5, fact.canonical_payload().digest().as_slice()),
        (6, fact.pistis_intent().as_str().as_bytes()),
        (7, expected.installation_id.as_bytes().as_slice()),
        (8, expected.principal_id.as_bytes().as_slice()),
        (9, expected.external_identity_id.as_bytes().as_slice()),
        (10, expected.device_id.as_bytes().as_slice()),
        (11, expected.key_id.as_bytes().as_slice()),
        (12, expected.binding_id.as_bytes().as_slice()),
        (
            13,
            expected.policy_generation.get().to_be_bytes().as_slice(),
        ),
        (
            14,
            expected
                .revocation_generation
                .get()
                .to_be_bytes()
                .as_slice(),
        ),
        (15, authenticated_at.get().to_be_bytes().as_slice()),
        (16, correlation_id.as_bytes().as_slice()),
        (17, &[operation_purpose_tag(expected.purpose)]),
    ] {
        output.push(tag);
        output.extend_from_slice(
            &u16::try_from(value.len())
                .map_err(|_| MonasAppAttestSessionHandoffErrorV1::Malformed)?
                .to_be_bytes(),
        );
        output.extend_from_slice(value);
    }
    if output.len() > MAXIMUM_CANONICAL_HANDOFF_BYTES || HANDOFF_FIELD_COUNT != 17 {
        return Err(MonasAppAttestSessionHandoffErrorV1::Malformed);
    }
    Ok(output)
}

const fn operation_purpose_tag(purpose: OperationPurpose) -> u8 {
    match purpose {
        OperationPurpose::AuthenticateSession => 1,
        OperationPurpose::ConsequentialApproval => 2,
        OperationPurpose::ArtefactSigning => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MONAS_APP_ATTEST_SESSION_HANDOFF_PROFILE_V1, MonasAppAttestSessionHandoffErrorV1,
        MonasAppAttestSessionHandoffV1,
    };
    use crate::{
        AuditCorrelationId, BindingExpectation, BindingFailure, BindingResolver, BindingState,
        DeliveryProfile, Generation, OperationPurpose, ProductionEvidence, ReadinessRequirement,
        ResolvedBinding, StandaloneReadiness,
    };
    use pistis_device_registry::DeviceStatus;
    use pistis_domain::{ExternalIdentityId, InstallationId, KeyId, UserId};
    use pistis_identity::BindingId;
    use pistis_protocol::UnixTimeMillis;

    fn expected() -> BindingExpectation {
        BindingExpectation {
            installation_id: InstallationId::from_bytes([2; 16]),
            principal_id: UserId::from_bytes([7; 16]),
            external_identity_id: ExternalIdentityId::from_bytes([8; 16]),
            device_id: pistis_domain::DeviceId::from_bytes([3; 16]),
            key_id: KeyId::from_bytes([4; 32]),
            binding_id: BindingId::from_bytes([9; 16]),
            policy_generation: Generation::new(10),
            revocation_generation: Generation::new(11),
            purpose: OperationPurpose::AuthenticateSession,
        }
    }

    fn ready() -> StandaloneReadiness {
        let mut readiness = StandaloneReadiness::unknown();
        for requirement in [
            ReadinessRequirement::CoseProfileAndFixtures,
            ReadinessRequirement::DurableSqliteRepositories,
            ReadinessRequirement::PersistedChallengeSignature,
            ReadinessRequirement::CompleteBindingResolution,
            ReadinessRequirement::AtomicHostCompletion,
            ReadinessRequirement::ProtectedServerCookie,
            ReadinessRequirement::SessionInvalidation,
            ReadinessRequirement::OperationalStateSafety,
            ReadinessRequirement::PinnedJenkinsEvidence,
        ] {
            readiness = readiness.with(requirement, ProductionEvidence::Verified);
        }
        readiness
    }

    struct Resolver;
    impl BindingResolver for Resolver {
        fn resolve(
            &self,
            requested: BindingExpectation,
        ) -> Result<ResolvedBinding, BindingFailure> {
            Ok(ResolvedBinding {
                installation_id: requested.installation_id,
                principal_id: requested.principal_id,
                external_identity_id: requested.external_identity_id,
                device_id: requested.device_id,
                key_id: requested.key_id,
                binding_id: requested.binding_id,
                installation_state: BindingState::Active,
                principal_state: BindingState::Active,
                binding_state: BindingState::Active,
                key_state: BindingState::Active,
                device_state: DeviceStatus::Active,
                policy_generation: requested.policy_generation,
                revocation_generation: requested.revocation_generation,
            })
        }
    }

    #[test]
    fn verified_fact_has_one_canonical_handoff_then_rechecks_monas_authority() {
        let handoff = MonasAppAttestSessionHandoffV1::from_verified_app_attest_fact(
            crate::site_trust::test_fixture::human_authority_fact_v1(),
            expected(),
            UnixTimeMillis::new(100),
            AuditCorrelationId::from_bytes([12; 16]),
        )
        .unwrap();
        assert_eq!(handoff.canonical_bytes()[0], 1);
        assert_ne!(handoff.digest(), &[0; 32]);
        assert_eq!(
            handoff
                .authorize_for_monas(DeliveryProfile::Standalone, &ready(), &Resolver)
                .unwrap()
                .principal_id,
            expected().principal_id
        );
        assert!(MONAS_APP_ATTEST_SESSION_HANDOFF_PROFILE_V1.starts_with("mnemosyne.pistis."));
    }

    #[test]
    fn substitutions_and_non_session_authority_deny_before_monas_resolution() {
        let fact = crate::site_trust::test_fixture::human_authority_fact_v1();
        assert_eq!(
            MonasAppAttestSessionHandoffV1::from_verified_app_attest_fact(
                fact.clone(),
                BindingExpectation {
                    key_id: KeyId::from_bytes([99; 32]),
                    ..expected()
                },
                UnixTimeMillis::new(100),
                AuditCorrelationId::from_bytes([12; 16]),
            ),
            Err(MonasAppAttestSessionHandoffErrorV1::FactBindingMismatch)
        );
        assert_eq!(
            MonasAppAttestSessionHandoffV1::from_verified_app_attest_fact(
                fact,
                BindingExpectation {
                    purpose: OperationPurpose::ConsequentialApproval,
                    ..expected()
                },
                UnixTimeMillis::new(100),
                AuditCorrelationId::from_bytes([0; 16]),
            ),
            Err(MonasAppAttestSessionHandoffErrorV1::WrongPurpose)
        );
    }

    #[test]
    fn other_product_audiences_and_site_trust_purposes_never_produce_monas_handoffs() {
        assert_eq!(
            MonasAppAttestSessionHandoffV1::from_verified_app_attest_fact(
                crate::site_trust::test_fixture::human_authority_fact_with_audience_and_purpose_v1(
                    "jenkins-local",
                    "trust-admission",
                ),
                expected(),
                UnixTimeMillis::new(100),
                AuditCorrelationId::from_bytes([12; 16]),
            ),
            Err(MonasAppAttestSessionHandoffErrorV1::WrongAudience)
        );
        assert_eq!(
            MonasAppAttestSessionHandoffV1::from_verified_app_attest_fact(
                crate::site_trust::test_fixture::human_authority_fact_with_audience_and_purpose_v1(
                    "monas-local",
                    "trust-deploy",
                ),
                expected(),
                UnixTimeMillis::new(100),
                AuditCorrelationId::from_bytes([12; 16]),
            ),
            Err(MonasAppAttestSessionHandoffErrorV1::WrongSiteTrustPurpose)
        );
    }
}
