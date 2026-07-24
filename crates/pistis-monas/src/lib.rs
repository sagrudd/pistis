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
