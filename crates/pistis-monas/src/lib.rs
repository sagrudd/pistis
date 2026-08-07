//! Framework-neutral contract between Pistis and a Monas host.
//!
//! This crate cannot issue a browser session or declare a standalone
//! installation production ready. It describes the evidence and exact
//! authoritative bindings that Monas and Prosopikon must re-evaluate inside
//! their rollback-capable completion transaction.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod binding;
mod physical_iphone_vector;
mod readiness;
mod session;
mod site_trust;
mod site_trust_assertion_ingress;
mod site_trust_registration_acceptance;

pub use binding::{
    BindingExpectation, BindingFailure, BindingResolver, BindingState, Generation,
    OperationPurpose, ResolvedBinding,
};
pub use physical_iphone_vector::{
    MONAS_APP_ATTEST_VERIFIER_PROFILE_V1, PHYSICAL_IPHONE_APP_ATTEST_VECTOR_PROFILE_V1,
    PhysicalIPhoneAppAttestVectorErrorV1, PhysicalIPhoneAppAttestVectorIdV1,
    PhysicalIPhoneAppAttestVectorRequestV1, PhysicalIPhoneAppAttestVectorStoreV1,
    PhysicalIPhoneAppAttestVectorV1, PhysicalIPhoneAppAttestVectorVerifierV1,
    UnavailablePhysicalIPhoneAppAttestVectorVerifierV1,
    validate_and_retain_physical_iphone_app_attest_vector_v1,
};
pub use readiness::{
    DeliveryProfile, IntegrationBlocker, ProductionEvidence, ReadinessRequirement,
    StandaloneReadiness,
};
pub use session::{
    AuditCorrelationId, HostSessionError, HostSessionIssuer, HostSessionOutcome,
    HostSessionRequest, SessionIdDigest,
};
pub use site_trust::{
    AppleAppAttestAssertionV1, AppleAppAttestVerifierV1, AttestationVerificationFailureV1,
    SiteTrustAttestationChallengeDigestV1, SiteTrustAttestationRequestV1,
    SiteTrustAttestationVerificationRequestV1, SiteTrustCanonicalPayloadErrorV1,
    SiteTrustCanonicalPayloadV1, SiteTrustFactCeremonyIdV1, SiteTrustFactConsumptionErrorV1,
    SiteTrustFactConsumptionRequestV1, SiteTrustFactConsumptionV1, SiteTrustFactIdV1,
    SiteTrustFactIssuanceErrorV1, SiteTrustFactStoreV1, SiteTrustHumanAuthorityFactV1,
    SiteTrustPistisIntentV1, UnavailableAppleAppAttestVerifierV1, VerifiedIPhoneAppAttestationV1,
    issue_site_trust_human_authority_fact_v1,
};
pub use site_trust_assertion_ingress::{
    MONAS_PRODUCTION_APP_ATTEST_APP_IDENTIFIER_V1, MonasSiteTrustAppAttestAtomicStoreV1,
    MonotonicAppAttestCounterV1, ProductionAppleAppAttestAssertionVerifierV1,
    SITE_TRUST_APP_ATTEST_ASSERTION_INGRESS_PROFILE_V1, ServerHeldMonasAppAttestAcceptanceV1,
    SiteTrustAppAttestAssertionIngressErrorV1, SiteTrustAppAttestAssertionIngressOutcomeV1,
    SiteTrustAppAttestAssertionRedactedVectorV1, SiteTrustAppAttestMobileSubmissionV1,
    decode_site_trust_app_attest_mobile_submission_v1,
    issue_site_trust_human_authority_fact_from_server_held_app_attest_assertion_v1,
};
pub use site_trust_registration_acceptance::{
    MONAS_APP_ATTEST_REVIEWED_MANIFEST_PROFILE_V1, PISTIS_APP_ATTEST_REGISTRATION_PROFILE_V1,
    ProductionAppleAppAttestAcceptanceFactoryV1, SiteTrustAppAttestRegistrationErrorV1,
    SiteTrustAppAttestRegistrationSubmissionV1,
    decode_site_trust_app_attest_registration_submission_v1,
};
