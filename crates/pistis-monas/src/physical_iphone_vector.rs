//! Redacted physical-iPhone App Attest vector validation and retention.
//!
//! This is a package- and service-disabled evidence boundary. It cannot make a
//! Site Trust decision, issue a Monas session, create a local account, or
//! accept an iOS capability claim. A reviewed in-process verifier must first
//! establish the physical Apple App Attest result; this module then verifies
//! its exact bindings to the immutable Pistis human-authority fact and retains
//! only redacted non-secret evidence through a host-owned atomic store.

use core::fmt;

use sha2::{Digest as _, Sha256};

use crate::{
    SiteTrustFactCeremonyIdV1, SiteTrustFactIdV1, SiteTrustHumanAuthorityFactV1,
    SiteTrustPistisIntentV1,
};
use pistis_domain::{DeviceId, InstallationId, KeyId};
use pistis_protocol::UnixTimeMillis;

/// Exact reviewed Monas Apple verifier profile identity from Monas #145.
pub const MONAS_APP_ATTEST_VERIFIER_PROFILE_V1: &str = "monas.apple-app-attest-verifier-profile.v1";
/// Exact redacted physical-iPhone vector profile.
pub const PHYSICAL_IPHONE_APP_ATTEST_VECTOR_PROFILE_V1: &str =
    "mnemosyne.pistis.physical-iphone-app-attest-vector.v1";

const VECTOR_ID_DOMAIN_V1: &[u8] = b"mnemosyne.pistis.physical-iphone-vector-id.v1\0";
const MAXIMUM_TRUST_ANCHOR_SET_ID_BYTES: usize = 128;
const MAXIMUM_APP_IDENTIFIER_BYTES: usize = 192;

/// A stable, non-secret identifier for one retained physical iPhone vector.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PhysicalIPhoneAppAttestVectorIdV1([u8; 32]);

impl PhysicalIPhoneAppAttestVectorIdV1 {
    /// Returns the opaque vector identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Exact public bindings a reviewed physical-vector verifier must establish.
///
/// The request is derived only from a fact that Pistis issued after prior App
/// Attest verification. It carries no assertion, device secret, browser
/// material, cookie, token, or local operating-system identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhysicalIPhoneAppAttestVectorRequestV1 {
    fact_id: SiteTrustFactIdV1,
    installation_id: InstallationId,
    device_id: DeviceId,
    key_id: KeyId,
    ceremony_id: SiteTrustFactCeremonyIdV1,
    canonical_payload_digest: [u8; 32],
    pistis_intent: SiteTrustPistisIntentV1,
    attestation_digest: [u8; 32],
}

impl PhysicalIPhoneAppAttestVectorRequestV1 {
    /// Derives the exact vector request from one verified typed authority fact.
    ///
    /// # Errors
    ///
    /// A zero ceremony or digest is incomplete and cannot reach a physical
    /// verifier or retention store.
    pub fn from_fact(
        fact: &SiteTrustHumanAuthorityFactV1,
    ) -> Result<Self, PhysicalIPhoneAppAttestVectorErrorV1> {
        let attestation_digest = *fact.attestation_digest();
        let canonical_payload_digest = *fact.canonical_payload().digest();
        if fact.ceremony_id().is_zero_sentinel()
            || attestation_digest == [0; 32]
            || canonical_payload_digest == [0; 32]
        {
            return Err(PhysicalIPhoneAppAttestVectorErrorV1::Incomplete);
        }
        Ok(Self {
            fact_id: fact.id(),
            installation_id: fact.installation_id(),
            device_id: fact.device_id(),
            key_id: fact.key_id(),
            ceremony_id: fact.ceremony_id(),
            canonical_payload_digest,
            pistis_intent: fact.pistis_intent().clone(),
            attestation_digest,
        })
    }

    /// Returns the immutable fact identity.
    #[must_use]
    pub const fn fact_id(&self) -> SiteTrustFactIdV1 {
        self.fact_id
    }

    /// Returns the expected installation identity.
    #[must_use]
    pub const fn installation_id(&self) -> InstallationId {
        self.installation_id
    }

    /// Returns the expected physical iPhone identity.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Returns the expected App Attest key identity.
    #[must_use]
    pub const fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// Returns the expected one-use ceremony identity.
    #[must_use]
    pub const fn ceremony_id(&self) -> SiteTrustFactCeremonyIdV1 {
        self.ceremony_id
    }

    /// Returns the exact frozen Proxenos payload digest.
    #[must_use]
    pub const fn canonical_payload_digest(&self) -> &[u8; 32] {
        &self.canonical_payload_digest
    }

    /// Returns the exact opaque Pistis intent.
    #[must_use]
    pub fn pistis_intent(&self) -> &SiteTrustPistisIntentV1 {
        &self.pistis_intent
    }

    /// Returns the previously verified App Attest assertion digest.
    #[must_use]
    pub const fn attestation_digest(&self) -> &[u8; 32] {
        &self.attestation_digest
    }
}

/// Reviewed physical-iPhone evidence, opaque outside Pistis implementation.
///
/// There is deliberately no public constructor. A browser, cookie, CLI, local
/// account, PAM identity, kernel UID, capability report, simulator, or test
/// vector cannot mint verified physical-iPhone evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPhysicalIPhoneAppAttestVectorV1 {
    installation_id: InstallationId,
    device_id: DeviceId,
    key_id: KeyId,
    ceremony_id: SiteTrustFactCeremonyIdV1,
    canonical_payload_digest: [u8; 32],
    pistis_intent: SiteTrustPistisIntentV1,
    attestation_digest: [u8; 32],
    verifier_profile: String,
    trust_anchor_set_id: String,
    trust_anchor_set_digest: [u8; 32],
    app_identifier: String,
    verified_at: UnixTimeMillis,
}

/// A reviewed, in-process physical iPhone vector verifier.
///
/// An implementation must validate the production Apple App Attest trust
/// chain, production AAGUID, organisation App ID, registered credential/key,
/// counter, challenge binding, and the exact request fields. Trust anchors are
/// local reviewed input, never fetched or accepted from a device. Raw Apple
/// objects remain transient and cannot reach the retention store.
pub trait PhysicalIPhoneAppAttestVectorVerifierV1 {
    /// Validates one physical iPhone vector for the exact typed fact request.
    ///
    /// # Errors
    ///
    /// Unavailable Apple material, incomplete evidence, a simulator, an
    /// assertion failure, or any binding drift must deny without retention.
    fn verify_physical_iphone_vector(
        &self,
        request: &PhysicalIPhoneAppAttestVectorRequestV1,
    ) -> Result<VerifiedPhysicalIPhoneAppAttestVectorV1, PhysicalIPhoneAppAttestVectorErrorV1>;
}

/// The shipped default until a reviewed physical-iPhone verifier is integrated.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailablePhysicalIPhoneAppAttestVectorVerifierV1;

impl PhysicalIPhoneAppAttestVectorVerifierV1
    for UnavailablePhysicalIPhoneAppAttestVectorVerifierV1
{
    fn verify_physical_iphone_vector(
        &self,
        _request: &PhysicalIPhoneAppAttestVectorRequestV1,
    ) -> Result<VerifiedPhysicalIPhoneAppAttestVectorV1, PhysicalIPhoneAppAttestVectorErrorV1> {
        Err(PhysicalIPhoneAppAttestVectorErrorV1::Unavailable)
    }
}

/// Redacted non-secret retained evidence for one verified physical iPhone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhysicalIPhoneAppAttestVectorV1 {
    id: PhysicalIPhoneAppAttestVectorIdV1,
    fact_id: SiteTrustFactIdV1,
    installation_id: InstallationId,
    device_id: DeviceId,
    key_id: KeyId,
    ceremony_id: SiteTrustFactCeremonyIdV1,
    canonical_payload_digest: [u8; 32],
    attestation_digest: [u8; 32],
    verifier_profile: String,
    trust_anchor_set_id: String,
    trust_anchor_set_digest: [u8; 32],
    app_identifier: String,
    verified_at: UnixTimeMillis,
}

impl PhysicalIPhoneAppAttestVectorV1 {
    /// Returns the exact redacted vector profile.
    #[must_use]
    pub const fn profile(&self) -> &'static str {
        PHYSICAL_IPHONE_APP_ATTEST_VECTOR_PROFILE_V1
    }

    /// Returns the stable vector identifier.
    #[must_use]
    pub const fn id(&self) -> PhysicalIPhoneAppAttestVectorIdV1 {
        self.id
    }

    /// Returns the source fact identity.
    #[must_use]
    pub const fn fact_id(&self) -> SiteTrustFactIdV1 {
        self.fact_id
    }

    /// Returns the installation owning the retained vector.
    #[must_use]
    pub const fn installation_id(&self) -> InstallationId {
        self.installation_id
    }

    /// Returns the physical iPhone identity bound by the verifier.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Returns the verified App Attest key identity.
    #[must_use]
    pub const fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// Returns the one-use ceremony identity.
    #[must_use]
    pub const fn ceremony_id(&self) -> SiteTrustFactCeremonyIdV1 {
        self.ceremony_id
    }

    /// Returns the frozen Proxenos payload digest.
    #[must_use]
    pub const fn canonical_payload_digest(&self) -> &[u8; 32] {
        &self.canonical_payload_digest
    }

    /// Returns the App Attest assertion digest, never the raw assertion.
    #[must_use]
    pub const fn attestation_digest(&self) -> &[u8; 32] {
        &self.attestation_digest
    }

    /// Returns the reviewed trust-anchor manifest digest.
    #[must_use]
    pub const fn trust_anchor_set_digest(&self) -> &[u8; 32] {
        &self.trust_anchor_set_digest
    }

    /// Returns the reviewed non-secret trust-anchor set identity.
    #[must_use]
    pub fn trust_anchor_set_id(&self) -> &str {
        &self.trust_anchor_set_id
    }

    /// Returns the production Apple App Attest verifier profile.
    #[must_use]
    pub fn verifier_profile(&self) -> &str {
        &self.verifier_profile
    }

    /// Returns the verified organisation application identifier.
    #[must_use]
    pub fn app_identifier(&self) -> &str {
        &self.app_identifier
    }

    /// Returns the reviewed verifier observation time.
    #[must_use]
    pub const fn verified_at(&self) -> UnixTimeMillis {
        self.verified_at
    }
}

/// Monas-owned durable retention port for redacted physical vector evidence.
///
/// The store must reject a repeated vector or an ambiguous partial transaction.
/// It stores no raw App Attest object, challenge, browser material, credential,
/// private key, token, or device secret.
pub trait PhysicalIPhoneAppAttestVectorStoreV1 {
    /// Atomically retains one fully validated redacted physical-iPhone vector.
    ///
    /// # Errors
    ///
    /// A duplicate, unavailable, corrupt, or partial record must fail closed.
    fn retain_verified_vector(
        &mut self,
        vector: PhysicalIPhoneAppAttestVectorV1,
    ) -> Result<(), PhysicalIPhoneAppAttestVectorErrorV1>;
}

/// Validates and atomically retains one physical-iPhone vector.
///
/// # Errors
///
/// This refuses incomplete, unavailable, unverified, production-profile,
/// trust-anchor, application, or typed-fact binding drift before the store is
/// called. It is evidence-only and grants no Site Trust, session, host, or
/// service authority.
pub fn validate_and_retain_physical_iphone_app_attest_vector_v1(
    verifier: &impl PhysicalIPhoneAppAttestVectorVerifierV1,
    store: &mut impl PhysicalIPhoneAppAttestVectorStoreV1,
    fact: &SiteTrustHumanAuthorityFactV1,
) -> Result<PhysicalIPhoneAppAttestVectorV1, PhysicalIPhoneAppAttestVectorErrorV1> {
    let request = PhysicalIPhoneAppAttestVectorRequestV1::from_fact(fact)?;
    let verified_evidence = verifier.verify_physical_iphone_vector(&request)?;
    if !verified_evidence.matches(&request) {
        return Err(PhysicalIPhoneAppAttestVectorErrorV1::BindingMismatch);
    }
    let vector = PhysicalIPhoneAppAttestVectorV1::from_verified(&request, verified_evidence)?;
    store.retain_verified_vector(vector.clone())?;
    Ok(vector)
}

impl VerifiedPhysicalIPhoneAppAttestVectorV1 {
    fn matches(&self, request: &PhysicalIPhoneAppAttestVectorRequestV1) -> bool {
        self.installation_id == request.installation_id
            && self.device_id == request.device_id
            && self.key_id == request.key_id
            && self.ceremony_id == request.ceremony_id
            && self.canonical_payload_digest == request.canonical_payload_digest
            && self.pistis_intent == request.pistis_intent
            && self.attestation_digest == request.attestation_digest
            && self.verifier_profile == MONAS_APP_ATTEST_VERIFIER_PROFILE_V1
            && !self.trust_anchor_set_id.is_empty()
            && self.trust_anchor_set_id.len() <= MAXIMUM_TRUST_ANCHOR_SET_ID_BYTES
            && self.trust_anchor_set_digest != [0; 32]
            && valid_production_app_identifier(&self.app_identifier)
            && self.verified_at.get() != 0
    }

    #[cfg(test)]
    fn test_verified(request: &PhysicalIPhoneAppAttestVectorRequestV1) -> Self {
        Self {
            installation_id: request.installation_id,
            device_id: request.device_id,
            key_id: request.key_id,
            ceremony_id: request.ceremony_id,
            canonical_payload_digest: request.canonical_payload_digest,
            pistis_intent: request.pistis_intent.clone(),
            attestation_digest: request.attestation_digest,
            verifier_profile: MONAS_APP_ATTEST_VERIFIER_PROFILE_V1.to_owned(),
            trust_anchor_set_id: "apple-app-attest-production-root-set-1".to_owned(),
            trust_anchor_set_digest: [9; 32],
            app_identifier: "ABCDE12345.uk.co.mnemosyne.pistis".to_owned(),
            verified_at: UnixTimeMillis::new(1_700_000_000_000),
        }
    }
}

impl PhysicalIPhoneAppAttestVectorV1 {
    fn from_verified(
        request: &PhysicalIPhoneAppAttestVectorRequestV1,
        verified: VerifiedPhysicalIPhoneAppAttestVectorV1,
    ) -> Result<Self, PhysicalIPhoneAppAttestVectorErrorV1> {
        if !verified.matches(request) {
            return Err(PhysicalIPhoneAppAttestVectorErrorV1::BindingMismatch);
        }
        let id = PhysicalIPhoneAppAttestVectorIdV1(digest_components(
            VECTOR_ID_DOMAIN_V1,
            [
                request.fact_id.as_bytes().as_slice(),
                request.installation_id.as_bytes().as_slice(),
                request.device_id.as_bytes().as_slice(),
                request.key_id.as_bytes().as_slice(),
                request.ceremony_id.as_bytes().as_slice(),
                request.canonical_payload_digest.as_slice(),
                request.attestation_digest.as_slice(),
                verified.verifier_profile.as_bytes(),
                verified.trust_anchor_set_id.as_bytes(),
                verified.trust_anchor_set_digest.as_slice(),
                verified.app_identifier.as_bytes(),
                &verified.verified_at.get().to_be_bytes(),
            ],
        ));
        Ok(Self {
            id,
            fact_id: request.fact_id,
            installation_id: request.installation_id,
            device_id: request.device_id,
            key_id: request.key_id,
            ceremony_id: request.ceremony_id,
            canonical_payload_digest: request.canonical_payload_digest,
            attestation_digest: request.attestation_digest,
            verifier_profile: verified.verifier_profile,
            trust_anchor_set_id: verified.trust_anchor_set_id,
            trust_anchor_set_digest: verified.trust_anchor_set_digest,
            app_identifier: verified.app_identifier,
            verified_at: verified.verified_at,
        })
    }
}

/// Coarse redacted physical-vector failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhysicalIPhoneAppAttestVectorErrorV1 {
    /// Required typed-fact or App Attest fields are absent or zero.
    Incomplete,
    /// No reviewed physical-iPhone Apple verifier is available.
    Unavailable,
    /// A reviewed verifier rejected the evidence without retaining it.
    Rejected,
    /// One exact physical, verifier, trust, or typed-fact binding differs.
    BindingMismatch,
    /// The host retention transaction is unavailable, ambiguous, or repeated.
    RetentionUnavailable,
}

impl fmt::Display for PhysicalIPhoneAppAttestVectorErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Incomplete => "physical iPhone vector is incomplete",
            Self::Unavailable => "physical iPhone vector verifier is unavailable",
            Self::Rejected => "physical iPhone vector was rejected",
            Self::BindingMismatch => "physical iPhone vector binding did not match",
            Self::RetentionUnavailable => "physical iPhone vector retention is unavailable",
        })
    }
}

impl std::error::Error for PhysicalIPhoneAppAttestVectorErrorV1 {}

fn valid_production_app_identifier(value: &str) -> bool {
    value.len() <= MAXIMUM_APP_IDENTIFIER_BYTES
        && value.contains('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn digest_components<const N: usize>(domain: &[u8], components: [&[u8]; N]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for component in components {
        let length = u32::try_from(component.len()).expect("physical vector fields are bounded");
        hasher.update(length.to_be_bytes());
        hasher.update(component);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RecordingStore {
        retained: Vec<PhysicalIPhoneAppAttestVectorV1>,
    }

    impl PhysicalIPhoneAppAttestVectorStoreV1 for RecordingStore {
        fn retain_verified_vector(
            &mut self,
            vector: PhysicalIPhoneAppAttestVectorV1,
        ) -> Result<(), PhysicalIPhoneAppAttestVectorErrorV1> {
            if self
                .retained
                .iter()
                .any(|existing| existing.id == vector.id)
            {
                return Err(PhysicalIPhoneAppAttestVectorErrorV1::RetentionUnavailable);
            }
            self.retained.push(vector);
            Ok(())
        }
    }

    struct VerifiedVector;

    impl PhysicalIPhoneAppAttestVectorVerifierV1 for VerifiedVector {
        fn verify_physical_iphone_vector(
            &self,
            request: &PhysicalIPhoneAppAttestVectorRequestV1,
        ) -> Result<VerifiedPhysicalIPhoneAppAttestVectorV1, PhysicalIPhoneAppAttestVectorErrorV1>
        {
            Ok(VerifiedPhysicalIPhoneAppAttestVectorV1::test_verified(
                request,
            ))
        }
    }

    struct MismatchedVector;

    impl PhysicalIPhoneAppAttestVectorVerifierV1 for MismatchedVector {
        fn verify_physical_iphone_vector(
            &self,
            request: &PhysicalIPhoneAppAttestVectorRequestV1,
        ) -> Result<VerifiedPhysicalIPhoneAppAttestVectorV1, PhysicalIPhoneAppAttestVectorErrorV1>
        {
            let mut verified = VerifiedPhysicalIPhoneAppAttestVectorV1::test_verified(request);
            verified.app_identifier = "not-a-production-app-id".to_owned();
            Ok(verified)
        }
    }

    #[test]
    fn only_exact_redacted_verified_evidence_is_retained() {
        let fact = crate::site_trust::test_fixture::human_authority_fact_v1();
        let mut store = RecordingStore {
            retained: Vec::new(),
        };

        let vector = validate_and_retain_physical_iphone_app_attest_vector_v1(
            &VerifiedVector,
            &mut store,
            &fact,
        )
        .expect("test-only exact verification");

        assert_eq!(store.retained, vec![vector.clone()]);
        assert_eq!(vector.fact_id(), fact.id());
        assert_eq!(vector.device_id(), fact.device_id());
        assert_eq!(vector.key_id(), fact.key_id());
        assert_eq!(vector.ceremony_id(), fact.ceremony_id());
        assert_eq!(
            vector.canonical_payload_digest(),
            fact.canonical_payload().digest()
        );
        assert_eq!(vector.attestation_digest(), fact.attestation_digest());
        assert_eq!(
            vector.verifier_profile(),
            MONAS_APP_ATTEST_VERIFIER_PROFILE_V1
        );
        assert_eq!(
            vector.profile(),
            PHYSICAL_IPHONE_APP_ATTEST_VECTOR_PROFILE_V1
        );
    }

    #[test]
    fn unavailable_or_mismatched_evidence_never_reaches_retention() {
        let fact = crate::site_trust::test_fixture::human_authority_fact_v1();
        let mut store = RecordingStore {
            retained: Vec::new(),
        };

        assert_eq!(
            validate_and_retain_physical_iphone_app_attest_vector_v1(
                &UnavailablePhysicalIPhoneAppAttestVectorVerifierV1,
                &mut store,
                &fact,
            ),
            Err(PhysicalIPhoneAppAttestVectorErrorV1::Unavailable)
        );
        assert!(store.retained.is_empty());

        assert_eq!(
            validate_and_retain_physical_iphone_app_attest_vector_v1(
                &MismatchedVector,
                &mut store,
                &fact,
            ),
            Err(PhysicalIPhoneAppAttestVectorErrorV1::BindingMismatch)
        );
        assert!(store.retained.is_empty());
    }
}
