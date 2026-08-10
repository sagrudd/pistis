//! Framework-neutral contract between Pistis and a Monas host.
//!
//! This crate cannot issue a browser session or declare a standalone
//! installation production ready. It describes the evidence and exact
//! authoritative bindings that Monas and Prosopikon must re-evaluate inside
//! their rollback-capable completion transaction.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod app_attest_session_handoff;
mod binding;
mod mobile_enrolment_receipt;
mod physical_iphone_vector;
mod readiness;
mod session;
mod site_root_genesis_device_binding;
mod site_trust;
mod site_trust_assertion_ingress;
mod site_trust_registration_acceptance;

pub use app_attest_session_handoff::{
    MONAS_APP_ATTEST_SESSION_HANDOFF_PROFILE_V1, MonasAppAttestSessionHandoffErrorV1,
    MonasAppAttestSessionHandoffV1,
};
pub use binding::{
    BindingExpectation, BindingFailure, BindingResolver, BindingState, Generation,
    OperationPurpose, ResolvedBinding,
};
pub use mobile_enrolment_receipt::{
    ExpectedProviderEnrolmentConfirmationV2, MobileEnrolmentReceiptErrorV2,
    PISTIS_MOBILE_ENROLMENT_RECEIPT_PROFILE_V2, ProviderEnrolmentConfirmResponseV2,
    VerifiedMobileEnrolmentReceiptV2, verify_provider_enrolment_confirm_response_v2,
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
pub use site_root_genesis_device_binding::{
    ExpectedSiteRootGenesisDeviceBindingV1, SITE_ROOT_GENESIS_DEVICE_BINDING_PROFILE_V1,
    SiteRootGenesisBindingContextV1, SiteRootGenesisDeviceBindingErrorV1,
    VerifiedSiteRootGenesisDeviceBindingV1, decode_and_verify_site_root_genesis_device_binding_v1,
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
    CustodyRotationAppAttestFailureStageV1, CustodyRotationAppAttestOutcomeV1,
    CustodyRotationAppAttestRequestV1, MONAS_PRODUCTION_APP_ATTEST_APP_IDENTIFIER_V1,
    MonasSiteTrustAppAttestAtomicStoreV1, MonotonicAppAttestCounterV1,
    ProductionAppleAppAttestAssertionVerifierV1,
    SITE_TRUST_APP_ATTEST_ASSERTION_INGRESS_PROFILE_V1,
    ServerHeldCustodyRotationAppAttestAcceptanceV1, ServerHeldMonasAppAttestAcceptanceV1,
    SiteTrustAppAttestAssertionIngressErrorV1, SiteTrustAppAttestAssertionIngressOutcomeV1,
    SiteTrustAppAttestAssertionRedactedVectorV1, SiteTrustAppAttestMobileSubmissionV1,
    decode_site_trust_app_attest_mobile_submission_v1,
    issue_site_trust_human_authority_fact_from_server_held_app_attest_assertion_v1,
    verify_custody_rotation_app_attest_assertion_diagnostic_v1,
    verify_custody_rotation_app_attest_assertion_v1,
};
pub use site_trust_registration_acceptance::{
    MONAS_APP_ATTEST_REVIEWED_MANIFEST_PROFILE_V1, PISTIS_APP_ATTEST_REGISTRATION_PROFILE_V1,
    ProductionAppleAppAttestAcceptanceFactoryV1, SiteTrustAppAttestRegistrationErrorV1,
    SiteTrustAppAttestRegistrationSubmissionV1,
    decode_site_trust_app_attest_registration_submission_v1,
};
