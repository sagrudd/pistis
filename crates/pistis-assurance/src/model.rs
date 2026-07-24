use crate::SourceRevision;

/// Seconds since the Unix epoch, supplied by an authoritative caller.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct UnixTimeSeconds(pub u64);

/// Required M13 security-control categories.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ControlCategory {
    /// Implementation-reconciled threat model.
    ThreatModel,
    /// Independent penetration assessment.
    PenetrationTest,
    /// Locked dependency and supply-chain review.
    DependencyReview,
    /// Data inventory and privacy assessment.
    PrivacyReview,
    /// Independent production-profile cryptographic review.
    CryptographicReview,
    /// Exercised security incident readiness.
    IncidentReadiness,
}

impl ControlCategory {
    /// All mandatory categories in deterministic gate order.
    pub const REQUIRED: [Self; 6] = [
        Self::ThreatModel,
        Self::PenetrationTest,
        Self::DependencyReview,
        Self::PrivacyReview,
        Self::CryptographicReview,
        Self::IncidentReadiness,
    ];

    /// Whether evidence must come from an independent reviewer.
    #[must_use]
    pub const fn requires_independence(self) -> bool {
        matches!(self, Self::PenetrationTest | Self::CryptographicReview)
    }
}

/// Review conclusion represented by evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceStatus {
    /// The applicable control was verified.
    Verified,
    /// Required evidence is known to be absent.
    Missing,
    /// The conclusion has not been established.
    Unknown,
}

/// Whether evidence remains current for its candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceFreshness {
    /// The evidence remains current.
    Current,
    /// A change or expiry made the evidence stale.
    Stale,
}

/// Coverage of the applicable review scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceScope {
    /// Every applicable surface was reviewed.
    Complete,
    /// At least one applicable surface was excluded or unavailable.
    Partial,
}

/// Relationship between reviewer and implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Independence {
    /// Reviewer is independent under ADR 0013.
    Independent,
    /// Evidence was produced by the implementation organization.
    Internal,
}

/// Authentication and traceability of retained evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceProvenance {
    /// Evidence identity and candidate binding are authenticated.
    Authenticated,
    /// Evidence provenance is missing or cannot be verified.
    Unauthenticated,
}

/// Evidence for exactly one required category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Evidence {
    /// Control category covered.
    pub category: ControlCategory,
    /// Exact reviewed source revision.
    pub revision: SourceRevision,
    /// Review conclusion.
    pub status: EvidenceStatus,
    /// Whether the evidence is still current.
    pub freshness: EvidenceFreshness,
    /// Applicable surface coverage.
    pub scope: EvidenceScope,
    /// Reviewer relationship.
    pub independence: Independence,
    /// Authenticated evidence provenance.
    pub provenance: EvidenceProvenance,
}

/// Security finding severity.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FindingSeverity {
    /// Release-blocking critical impact.
    Critical,
    /// Release-blocking high impact.
    High,
    /// Medium impact requiring remediation or explicit risk acceptance.
    Medium,
    /// Tracked lower impact.
    Low,
}

/// Owned and time-bounded acceptance of a medium residual risk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResidualRisk {
    /// Accountable owner; empty values are invalid.
    pub owner: String,
    /// Concrete remediation plan; empty values are invalid.
    pub remediation_plan: String,
    /// Plan target date.
    pub remediation_due: UnixTimeSeconds,
    /// Expiry of the security owner's acceptance.
    pub acceptance_expires: UnixTimeSeconds,
}

impl ResidualRisk {
    pub(crate) fn valid_at(&self, now: UnixTimeSeconds) -> bool {
        !self.owner.trim().is_empty()
            && !self.remediation_plan.trim().is_empty()
            && self.remediation_due > now
            && self.acceptance_expires > now
    }
}

/// Current disposition of a security finding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FindingDisposition {
    /// Finding remains open.
    Open,
    /// Remediation was independently or appropriately verified.
    RemediatedVerified,
    /// Security owner accepted a medium residual risk.
    RiskAccepted(ResidualRisk),
}

/// One finding tied to the assessed candidate revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Finding {
    /// Private stable identifier.
    pub id: String,
    /// Exact affected source revision.
    pub revision: SourceRevision,
    /// Assessed severity.
    pub severity: FindingSeverity,
    /// Current disposition.
    pub disposition: FindingDisposition,
}
