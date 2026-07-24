use crate::{Approval, ApprovalRole, Digest, EvidenceState, Manifest, ManifestError, ReleasePhase};

/// One independently reviewable release gate.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ReleaseGate {
    /// Source is the exact clean protected `main` revision.
    CleanProtectedMain,
    /// Inputs, locks, toolchains, SDKs, and environments are immutable.
    ImmutableInputs,
    /// Exact protected Jenkins release pipeline is verified.
    JenkinsReleasePipeline,
    /// Package contents and runtime dependencies were inspected.
    PackageContents,
    /// SBOMs reconcile against final packaged contents.
    SbomReconciled,
    /// Provenance binds source, builder, inputs, commands, and outputs.
    ProvenanceBound,
    /// Applicable tests pass against packaged artifacts.
    PackagedTests,
    /// M15 acceptance matrix passed without hidden skips.
    AcceptanceMatrix,
    /// Revision-bound security assurance is ready.
    SecurityAssurance,
    /// Reproducibility or qualified native correspondence was established.
    Reproducibility,
    /// Installation, upgrade, backup, restore, and rollback were exercised.
    OperationalRecovery,
    /// Required documentation and compatibility declarations are current.
    Documentation,
}

const GATES: [ReleaseGate; 12] = [
    ReleaseGate::CleanProtectedMain,
    ReleaseGate::ImmutableInputs,
    ReleaseGate::JenkinsReleasePipeline,
    ReleaseGate::PackageContents,
    ReleaseGate::SbomReconciled,
    ReleaseGate::ProvenanceBound,
    ReleaseGate::PackagedTests,
    ReleaseGate::AcceptanceMatrix,
    ReleaseGate::SecurityAssurance,
    ReleaseGate::Reproducibility,
    ReleaseGate::OperationalRecovery,
    ReleaseGate::Documentation,
];

const ROLES: [ApprovalRole; 7] = [
    ApprovalRole::Product,
    ApprovalRole::Backend,
    ApprovalRole::Ios,
    ApprovalRole::Android,
    ApprovalRole::Synoptikon,
    ApprovalRole::Security,
    ApprovalRole::ReleaseManager,
];

/// Candidate readiness evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseReadiness {
    evidence: [(ReleaseGate, EvidenceState); 12],
}

impl ReleaseReadiness {
    /// Creates a readiness set with no inferred evidence.
    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            evidence: [
                (GATES[0], EvidenceState::Unknown),
                (GATES[1], EvidenceState::Unknown),
                (GATES[2], EvidenceState::Unknown),
                (GATES[3], EvidenceState::Unknown),
                (GATES[4], EvidenceState::Unknown),
                (GATES[5], EvidenceState::Unknown),
                (GATES[6], EvidenceState::Unknown),
                (GATES[7], EvidenceState::Unknown),
                (GATES[8], EvidenceState::Unknown),
                (GATES[9], EvidenceState::Unknown),
                (GATES[10], EvidenceState::Unknown),
                (GATES[11], EvidenceState::Unknown),
            ],
        }
    }

    /// Records reviewed evidence for one exact gate.
    #[must_use]
    pub fn with(mut self, gate: ReleaseGate, state: EvidenceState) -> Self {
        if let Some(entry) = self.evidence.iter_mut().find(|entry| entry.0 == gate) {
            entry.1 = state;
        }
        self
    }

    /// Returns every blocker in deterministic normative order.
    #[must_use]
    pub fn blockers(
        &self,
        manifest: &Manifest,
        manifest_digest: Digest,
        approvals: &[Approval],
        now: u64,
    ) -> Vec<ReadinessBlocker> {
        if let Err(error) = manifest.validate() {
            return vec![ReadinessBlocker::Manifest(error)];
        }
        let mut blockers: Vec<_> = self
            .evidence
            .iter()
            .filter_map(|(gate, state)| {
                (*state != EvidenceState::Verified).then_some(ReadinessBlocker::Evidence {
                    gate: *gate,
                    state: *state,
                })
            })
            .collect();
        if manifest_digest.is_zero() {
            blockers.push(ReadinessBlocker::MissingManifestDigest);
        }
        for role in ROLES {
            let matching: Vec<_> = approvals
                .iter()
                .filter(|approval| approval.role == role)
                .collect();
            if matching.is_empty() {
                blockers.push(ReadinessBlocker::MissingApproval(role));
            } else if matching.len() != 1 {
                blockers.push(ReadinessBlocker::DuplicateApproval(role));
            } else {
                let approval = matching[0];
                if approval.manifest_digest != manifest_digest {
                    blockers.push(ReadinessBlocker::ApprovalDigestMismatch(role));
                } else if approval.approved_at > now || now >= approval.expires_at {
                    blockers.push(ReadinessBlocker::ExpiredApproval(role));
                }
            }
        }
        blockers
    }

    /// Authorizes progression to the protected approval/sign phase only.
    ///
    /// # Errors
    ///
    /// Returns the first deterministic blocker. Publication remains a separate
    /// protected phase and is never performed by this contract.
    pub fn require_approval_and_sign(
        &self,
        manifest: &Manifest,
        manifest_digest: Digest,
        approvals: &[Approval],
        now: u64,
    ) -> Result<ReleasePhase, ReadinessBlocker> {
        if manifest.phase != ReleasePhase::Verify {
            return Err(ReadinessBlocker::WrongPhase {
                expected: ReleasePhase::Verify,
                actual: manifest.phase,
            });
        }
        self.blockers(manifest, manifest_digest, approvals, now)
            .into_iter()
            .next()
            .map_or(Ok(ReleasePhase::ApproveAndSign), Err)
    }
}

impl Default for ReleaseReadiness {
    fn default() -> Self {
        Self::unknown()
    }
}

/// Typed reason a candidate cannot enter protected signing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadinessBlocker {
    /// Manifest structure is invalid.
    Manifest(ManifestError),
    /// Required evidence is absent or unknown.
    Evidence {
        /// Blocked release gate.
        gate: ReleaseGate,
        /// Observed evidence state.
        state: EvidenceState,
    },
    /// Manifest digest is a sentinel.
    MissingManifestDigest,
    /// Required approval role is absent.
    MissingApproval(ApprovalRole),
    /// More than one approval claims the same role.
    DuplicateApproval(ApprovalRole),
    /// Approval covers a different manifest.
    ApprovalDigestMismatch(ApprovalRole),
    /// Approval is expired or was issued in the future.
    ExpiredApproval(ApprovalRole),
    /// Candidate attempted to skip or repeat a release phase.
    WrongPhase {
        /// Required current phase.
        expected: ReleasePhase,
        /// Actual current phase.
        actual: ReleasePhase,
    },
}
