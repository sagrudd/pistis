//! Framework-neutral contract between Pistis and a Synoptikon host.
//!
//! This crate cannot issue a session or declare an integration production
//! ready. It describes the evidence and complete authoritative bindings a host
//! must re-evaluate inside its own rollback-capable completion transaction.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod binding;
mod readiness;
mod session;

pub use binding::{
    BindingExpectation, BindingFailure, BindingResolver, BindingState, CeremonyPurpose, Generation,
    ResolvedBinding,
};
pub use readiness::{
    IntegrationBlocker, ProductionEvidence, ProductionReadiness, ReadinessRequirement,
};
pub use session::{
    AuditCorrelationId, HostSessionError, HostSessionIssuer, HostSessionOutcome,
    HostSessionRequest, SessionIdDigest,
};
