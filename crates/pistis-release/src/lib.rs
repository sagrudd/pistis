//! Credential-free release manifest and readiness contract.
//!
//! This crate cannot sign, tag, publish, or declare a release complete. It
//! validates immutable candidate metadata and reports deterministic blockers
//! before a protected Jenkins release phase may be requested.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod manifest;
mod readiness;

pub use manifest::{
    Approval, ApprovalRole, Artifact, ArtifactId, ArtifactKind, CandidateId, Digest, EvidenceState,
    Manifest, ManifestError, PublicationState, ReleasePhase, ReleaseVersion, Revision,
    SigningIdentity,
};
pub use readiness::{ReadinessBlocker, ReleaseGate, ReleaseReadiness};
