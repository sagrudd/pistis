use pistis_assurance::{
    AssuranceCase, ControlCategory, Evidence, EvidenceFreshness, EvidenceProvenance, EvidenceScope,
    EvidenceStatus, Finding, FindingDisposition, FindingSeverity, Independence, ReadinessBlocker,
    ReadinessOutcome, ResidualRisk, SourceRevision, UnixTimeSeconds,
};

const NOW: UnixTimeSeconds = UnixTimeSeconds(1_000);

fn revision(byte: u8) -> SourceRevision {
    SourceRevision::from_hex(&format!("{byte:02x}").repeat(20)).unwrap()
}

fn complete_evidence(candidate: SourceRevision) -> Vec<Evidence> {
    ControlCategory::REQUIRED
        .into_iter()
        .map(|category| Evidence {
            category,
            revision: candidate,
            status: EvidenceStatus::Verified,
            freshness: EvidenceFreshness::Current,
            scope: EvidenceScope::Complete,
            independence: if category.requires_independence() {
                Independence::Independent
            } else {
                Independence::Internal
            },
            provenance: EvidenceProvenance::Authenticated,
        })
        .collect()
}

fn ready_case() -> AssuranceCase {
    let candidate = revision(1);
    AssuranceCase {
        candidate,
        evidence: complete_evidence(candidate),
        findings: Vec::new(),
    }
}

#[test]
fn exact_complete_authenticated_evidence_is_ready() {
    assert_eq!(ready_case().readiness(NOW), ReadinessOutcome::Ready);
}

#[test]
fn source_revision_requires_exact_full_hex() {
    assert!(SourceRevision::from_hex("abcd").is_err());
    assert!(SourceRevision::from_hex(&"gg".repeat(20)).is_err());
    assert_eq!(
        SourceRevision::from_hex(&"AB".repeat(20)).unwrap(),
        revision(0xab)
    );
}

#[test]
fn missing_and_duplicate_categories_block_in_normative_order() {
    let mut case = ready_case();
    case.evidence.remove(0);
    let duplicate = case.evidence[0];
    case.evidence.push(duplicate);
    assert_eq!(
        case.readiness(NOW),
        ReadinessOutcome::Blocked(vec![
            ReadinessBlocker::MissingCategory(ControlCategory::ThreatModel),
            ReadinessBlocker::DuplicateCategory(ControlCategory::PenetrationTest),
        ])
    );
}

#[test]
fn wrong_revision_unknown_stale_partial_and_unauthenticated_all_block() {
    let mut case = ready_case();
    let evidence = &mut case.evidence[0];
    evidence.revision = revision(2);
    evidence.status = EvidenceStatus::Unknown;
    evidence.freshness = EvidenceFreshness::Stale;
    evidence.scope = EvidenceScope::Partial;
    evidence.provenance = EvidenceProvenance::Unauthenticated;
    assert_eq!(
        case.readiness(NOW),
        ReadinessOutcome::Blocked(vec![
            ReadinessBlocker::WrongEvidenceRevision(ControlCategory::ThreatModel),
            ReadinessBlocker::EvidenceNotVerified(ControlCategory::ThreatModel),
            ReadinessBlocker::StaleEvidence(ControlCategory::ThreatModel),
            ReadinessBlocker::PartialScope(ControlCategory::ThreatModel),
            ReadinessBlocker::UnauthenticatedEvidence(ControlCategory::ThreatModel),
        ])
    );
}

#[test]
fn internal_penetration_and_crypto_reviews_cannot_claim_independence() {
    let mut case = ready_case();
    case.evidence[1].independence = Independence::Internal;
    case.evidence[4].independence = Independence::Internal;
    assert_eq!(
        case.readiness(NOW),
        ReadinessOutcome::Blocked(vec![
            ReadinessBlocker::NotIndependent(ControlCategory::PenetrationTest),
            ReadinessBlocker::NotIndependent(ControlCategory::CryptographicReview),
        ])
    );
}

#[test]
fn critical_and_high_findings_block_even_when_risk_is_claimed_accepted() {
    let mut case = ready_case();
    for (id, severity) in [
        ("critical", FindingSeverity::Critical),
        ("high", FindingSeverity::High),
    ] {
        case.findings.push(Finding {
            id: id.into(),
            revision: case.candidate,
            severity,
            disposition: FindingDisposition::RiskAccepted(valid_risk()),
        });
    }
    assert_eq!(
        case.readiness(NOW),
        ReadinessOutcome::Blocked(vec![
            ReadinessBlocker::SevereFindingOpen("critical".into()),
            ReadinessBlocker::SevereFindingOpen("high".into()),
        ])
    );
}

#[test]
fn medium_risk_requires_owner_plan_and_future_dates() {
    let mut case = ready_case();
    case.findings.push(Finding {
        id: "medium".into(),
        revision: case.candidate,
        severity: FindingSeverity::Medium,
        disposition: FindingDisposition::RiskAccepted(ResidualRisk {
            owner: " ".into(),
            remediation_plan: "patch".into(),
            remediation_due: UnixTimeSeconds(2_000),
            acceptance_expires: UnixTimeSeconds(2_000),
        }),
    });
    assert_eq!(
        case.readiness(NOW),
        ReadinessOutcome::Blocked(vec![ReadinessBlocker::InvalidResidualRisk("medium".into())])
    );
}

#[test]
fn valid_medium_acceptance_and_tracked_low_finding_are_ready() {
    let mut case = ready_case();
    case.findings = vec![
        Finding {
            id: "medium".into(),
            revision: case.candidate,
            severity: FindingSeverity::Medium,
            disposition: FindingDisposition::RiskAccepted(valid_risk()),
        },
        Finding {
            id: "low".into(),
            revision: case.candidate,
            severity: FindingSeverity::Low,
            disposition: FindingDisposition::Open,
        },
    ];
    assert_eq!(case.readiness(NOW), ReadinessOutcome::Ready);
}

#[test]
fn evidence_never_defaults_to_ready() {
    let case = AssuranceCase {
        candidate: revision(1),
        evidence: Vec::new(),
        findings: Vec::new(),
    };
    let ReadinessOutcome::Blocked(blockers) = case.readiness(NOW) else {
        panic!("absence must be blocked");
    };
    assert_eq!(blockers.len(), ControlCategory::REQUIRED.len());
}

fn valid_risk() -> ResidualRisk {
    ResidualRisk {
        owner: "security-owner".into(),
        remediation_plan: "owned remediation".into(),
        remediation_due: UnixTimeSeconds(2_000),
        acceptance_expires: UnixTimeSeconds(1_500),
    }
}
