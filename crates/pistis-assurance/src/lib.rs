//! Machine-checkable, revision-bound security assurance readiness.
//!
//! This crate records evidence and deterministic release blockers. It performs
//! no scan and cannot turn internal review into an independent assessment.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod model;
mod readiness;
mod revision;

pub use model::{
    ControlCategory, Evidence, EvidenceFreshness, EvidenceProvenance, EvidenceScope,
    EvidenceStatus, Finding, FindingDisposition, FindingSeverity, Independence, ResidualRisk,
    UnixTimeSeconds,
};
pub use readiness::{AssuranceCase, ReadinessBlocker, ReadinessOutcome};
pub use revision::{InvalidSourceRevision, SourceRevision};
