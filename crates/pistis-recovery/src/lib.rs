//! Framework-neutral recovery, revocation, and historic-lifecycle contract.
//!
//! This crate cannot mutate a registry, grant a role, or issue a session. It
//! authorizes an exact recovery plan from host-resolved state and separately
//! classifies historic signature facts without confusing current revocation
//! with cryptographic validity at signing time.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod historic;
mod recovery;

pub use historic::{
    CompromiseTreatment, CryptographicResult, HistoricClassification, HistoricPolicyResult,
    RevocationFact, SigningTimeEvidence, TemporalResult, classify_historic,
};
pub use recovery::{
    AuthorityClass, BindingGeneration, CredentialState, NewCredential, OperationId,
    PriorCredential, ProviderAuthorization, RecoveryAuthorization, RecoveryFailure, RecoveryImpact,
    RecoveryMode, RecoveryPlan, RecoveryPurpose, RecoverySnapshot,
};
