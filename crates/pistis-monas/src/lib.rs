//! Framework-neutral contract between Pistis and a Monas host.
//!
//! This crate cannot issue a browser session or declare a standalone
//! installation production ready. It describes the evidence and exact
//! authoritative bindings that Monas and Prosopikon must re-evaluate inside
//! their rollback-capable completion transaction.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod binding;
mod readiness;
mod session;
mod site_trust;

pub use binding::{
    BindingExpectation, BindingFailure, BindingResolver, BindingState, Generation,
    OperationPurpose, ResolvedBinding,
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
