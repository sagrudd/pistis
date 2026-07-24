use crate::{
    ControlCategory, Evidence, EvidenceFreshness, EvidenceProvenance, EvidenceScope,
    EvidenceStatus, Finding, FindingDisposition, FindingSeverity, Independence, SourceRevision,
    UnixTimeSeconds,
};
use std::collections::BTreeMap;

/// Revision-bound inputs to the security assurance gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssuranceCase {
    /// Exact candidate source revision.
    pub candidate: SourceRevision,
    /// Evidence records; each required category must occur exactly once.
    pub evidence: Vec<Evidence>,
    /// Known security findings.
    pub findings: Vec<Finding>,
}

impl AssuranceCase {
    /// Evaluates every gate and returns blockers in deterministic order.
    #[must_use]
    pub fn readiness(&self, now: UnixTimeSeconds) -> ReadinessOutcome {
        let mut blockers = Vec::new();
        let mut by_category: BTreeMap<ControlCategory, Vec<&Evidence>> = BTreeMap::new();
        for evidence in &self.evidence {
            by_category
                .entry(evidence.category)
                .or_default()
                .push(evidence);
        }

        for category in ControlCategory::REQUIRED {
            let records = by_category.get(&category).map_or(&[][..], Vec::as_slice);
            if records.is_empty() {
                blockers.push(ReadinessBlocker::MissingCategory(category));
                continue;
            }
            if records.len() != 1 {
                blockers.push(ReadinessBlocker::DuplicateCategory(category));
                continue;
            }
            let evidence = records[0];
            if evidence.revision != self.candidate {
                blockers.push(ReadinessBlocker::WrongEvidenceRevision(category));
            }
            if evidence.status != EvidenceStatus::Verified {
                blockers.push(ReadinessBlocker::EvidenceNotVerified(category));
            }
            if evidence.freshness != EvidenceFreshness::Current {
                blockers.push(ReadinessBlocker::StaleEvidence(category));
            }
            if evidence.scope != EvidenceScope::Complete {
                blockers.push(ReadinessBlocker::PartialScope(category));
            }
            if evidence.provenance != EvidenceProvenance::Authenticated {
                blockers.push(ReadinessBlocker::UnauthenticatedEvidence(category));
            }
            if category.requires_independence()
                && evidence.independence != Independence::Independent
            {
                blockers.push(ReadinessBlocker::NotIndependent(category));
            }
        }

        let mut findings: Vec<&Finding> = self.findings.iter().collect();
        findings.sort_by(|left, right| left.id.cmp(&right.id));
        for finding in findings {
            if finding.revision != self.candidate {
                blockers.push(ReadinessBlocker::WrongFindingRevision(finding.id.clone()));
                continue;
            }
            match (&finding.severity, &finding.disposition) {
                (_, FindingDisposition::RemediatedVerified)
                | (FindingSeverity::Low, FindingDisposition::Open) => {}
                (FindingSeverity::Medium, FindingDisposition::RiskAccepted(residual))
                    if residual.valid_at(now) => {}
                (FindingSeverity::Critical | FindingSeverity::High, _) => {
                    blockers.push(ReadinessBlocker::SevereFindingOpen(finding.id.clone()));
                }
                (FindingSeverity::Medium, FindingDisposition::Open) => {
                    blockers.push(ReadinessBlocker::MediumFindingOpen(finding.id.clone()));
                }
                (
                    FindingSeverity::Medium | FindingSeverity::Low,
                    FindingDisposition::RiskAccepted(_),
                ) => {
                    blockers.push(ReadinessBlocker::InvalidResidualRisk(finding.id.clone()));
                }
            }
        }

        if blockers.is_empty() {
            ReadinessOutcome::Ready
        } else {
            ReadinessOutcome::Blocked(blockers)
        }
    }
}

/// Security-assurance gate result. There is no inferred or partial pass state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadinessOutcome {
    /// Every mandatory gate is satisfied for the exact candidate.
    Ready,
    /// One or more deterministic blockers prevent approval.
    Blocked(Vec<ReadinessBlocker>),
}

/// Deterministic reason the exact candidate is not security-ready.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadinessBlocker {
    /// Required category has no evidence.
    MissingCategory(ControlCategory),
    /// Category has ambiguous duplicate evidence.
    DuplicateCategory(ControlCategory),
    /// Evidence covers another source revision.
    WrongEvidenceRevision(ControlCategory),
    /// Evidence is missing, unknown, or otherwise unverified.
    EvidenceNotVerified(ControlCategory),
    /// Evidence was invalidated or expired.
    StaleEvidence(ControlCategory),
    /// At least one applicable surface was not reviewed.
    PartialScope(ControlCategory),
    /// Evidence identity or candidate binding is unauthenticated.
    UnauthenticatedEvidence(ControlCategory),
    /// Independent evidence is required but only internal evidence exists.
    NotIndependent(ControlCategory),
    /// Finding record covers another source revision.
    WrongFindingRevision(String),
    /// Critical or high finding is not verified remediated.
    SevereFindingOpen(String),
    /// Medium finding has neither verified remediation nor accepted risk.
    MediumFindingOpen(String),
    /// Residual-risk acceptance is incomplete, stale, or inapplicable.
    InvalidResidualRisk(String),
}
