use pistis_release::{
    Approval, ApprovalRole, Artifact, ArtifactId, ArtifactKind, CandidateId, Digest, EvidenceState,
    Manifest, ManifestError, PublicationState, ReadinessBlocker, ReleaseGate, ReleasePhase,
    ReleaseReadiness, ReleaseVersion, Revision, SigningIdentity,
};

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

fn digest(byte: u8) -> Digest {
    Digest::from_bytes([byte; 32])
}

fn artifact() -> Artifact {
    Artifact {
        id: ArtifactId::from_bytes([1; 16]),
        kind: ArtifactKind::Rpm,
        filename: "pistis-1.0.0-1.x86_64.rpm".into(),
        size: 1024,
        digest: digest(2),
        sbom_digest: digest(3),
        provenance_digest: digest(4),
        signing_identity: SigningIdentity::from_bytes([5; 16]),
        publication: PublicationState::Unpublished,
    }
}

fn manifest() -> Manifest {
    Manifest {
        version: ReleaseVersion {
            major: 1,
            minor: 0,
            patch: 0,
        },
        candidate_id: CandidateId::from_bytes([6; 16]),
        source_revision: Revision::from_bytes([7; 20]),
        pipeline_digest: digest(8),
        input_digest: digest(9),
        artifacts: vec![artifact()],
        phase: ReleasePhase::Verify,
    }
}

fn ready() -> ReleaseReadiness {
    GATES
        .into_iter()
        .fold(ReleaseReadiness::unknown(), |readiness, gate| {
            readiness.with(gate, EvidenceState::Verified)
        })
}

fn approvals(manifest_digest: Digest) -> Vec<Approval> {
    ROLES
        .into_iter()
        .map(|role| Approval {
            role,
            manifest_digest,
            approved_at: 10,
            expires_at: 30,
        })
        .collect()
}

#[test]
fn every_release_gate_is_independently_fail_closed() {
    for missing in GATES {
        let readiness = GATES
            .into_iter()
            .fold(ReleaseReadiness::unknown(), |readiness, gate| {
                readiness.with(
                    gate,
                    if gate == missing {
                        EvidenceState::Missing
                    } else {
                        EvidenceState::Verified
                    },
                )
            });
        let blockers = readiness.blockers(&manifest(), digest(20), &approvals(digest(20)), 20);
        assert!(blockers.contains(&ReadinessBlocker::Evidence {
            gate: missing,
            state: EvidenceState::Missing,
        }));
    }
}

#[test]
fn unknown_evidence_has_deterministic_normative_order() {
    let blockers =
        ReleaseReadiness::unknown().blockers(&manifest(), digest(20), &approvals(digest(20)), 20);
    for (blocker, gate) in blockers.into_iter().take(GATES.len()).zip(GATES) {
        assert_eq!(
            blocker,
            ReadinessBlocker::Evidence {
                gate,
                state: EvidenceState::Unknown,
            }
        );
    }
}

#[test]
fn development_or_sentinel_candidate_never_reaches_signing() {
    for invalid in [
        Manifest {
            version: ReleaseVersion {
                major: 0,
                minor: 1,
                patch: 0,
            },
            ..manifest()
        },
        Manifest {
            candidate_id: CandidateId::from_bytes([0; 16]),
            ..manifest()
        },
        Manifest {
            source_revision: Revision::from_bytes([0; 20]),
            ..manifest()
        },
    ] {
        assert!(matches!(
            ready().require_approval_and_sign(&invalid, digest(20), &approvals(digest(20)), 20),
            Err(ReadinessBlocker::Manifest(
                ManifestError::DevelopmentVersion | ManifestError::SentinelIdentity
            ))
        ));
    }
}

#[test]
fn artifact_paths_and_inventory_identifiers_are_unique_and_safe() {
    for filename in ["", ".", "..", "../escape", r"dir\escape", "line\nbreak"] {
        assert_eq!(
            Manifest {
                artifacts: vec![Artifact {
                    filename: filename.into(),
                    ..artifact()
                }],
                ..manifest()
            }
            .validate(),
            Err(ManifestError::UnsafeFilename)
        );
    }

    let duplicate = artifact();
    assert_eq!(
        Manifest {
            artifacts: vec![duplicate.clone(), duplicate],
            ..manifest()
        }
        .validate(),
        Err(ManifestError::DuplicateArtifactId)
    );
}

#[test]
fn empty_or_unattested_artifacts_fail_closed() {
    for invalid in [
        Artifact {
            size: 0,
            ..artifact()
        },
        Artifact {
            digest: digest(0),
            ..artifact()
        },
        Artifact {
            sbom_digest: digest(0),
            ..artifact()
        },
        Artifact {
            provenance_digest: digest(0),
            ..artifact()
        },
    ] {
        assert!(manifest_with(invalid).validate().is_err());
    }
}

fn manifest_with(artifact: Artifact) -> Manifest {
    Manifest {
        artifacts: vec![artifact],
        ..manifest()
    }
}

#[test]
fn publication_record_must_bind_the_exact_artifact_digest() {
    assert_eq!(
        manifest_with(Artifact {
            publication: PublicationState::Published {
                reference: "registry.example/pistis@sha256:immutable".into(),
                digest: digest(99),
            },
            ..artifact()
        })
        .validate(),
        Err(ManifestError::InvalidPublication)
    );
    assert!(
        manifest_with(Artifact {
            publication: PublicationState::Staged {
                reference: "staging.example/pistis@sha256:immutable".into(),
                digest: digest(2),
            },
            ..artifact()
        })
        .validate()
        .is_ok()
    );

    assert_eq!(
        manifest_with(Artifact {
            publication: PublicationState::Published {
                reference: "registry.example/pistis@sha256:immutable".into(),
                digest: digest(2),
            },
            ..artifact()
        })
        .validate(),
        Err(ManifestError::PrematurePublication)
    );
}

#[test]
fn every_required_approval_must_exist_exactly_once() {
    for missing in ROLES {
        let partial: Vec<_> = approvals(digest(20))
            .into_iter()
            .filter(|approval| approval.role != missing)
            .collect();
        assert!(
            ready()
                .blockers(&manifest(), digest(20), &partial, 20)
                .contains(&ReadinessBlocker::MissingApproval(missing))
        );
    }

    let mut duplicated = approvals(digest(20));
    duplicated.push(duplicated[0]);
    assert!(
        ready()
            .blockers(&manifest(), digest(20), &duplicated, 20)
            .contains(&ReadinessBlocker::DuplicateApproval(ApprovalRole::Product))
    );
}

#[test]
fn approval_substitution_expiry_and_future_time_fail_closed() {
    let mut wrong_digest = approvals(digest(20));
    wrong_digest[0].manifest_digest = digest(21);
    assert!(
        ready()
            .blockers(&manifest(), digest(20), &wrong_digest, 20)
            .contains(&ReadinessBlocker::ApprovalDigestMismatch(
                ApprovalRole::Product
            ))
    );

    for approval in [
        Approval {
            approved_at: 21,
            ..approvals(digest(20))[0]
        },
        Approval {
            expires_at: 20,
            ..approvals(digest(20))[0]
        },
    ] {
        let mut invalid = approvals(digest(20));
        invalid[0] = approval;
        assert!(
            ready()
                .blockers(&manifest(), digest(20), &invalid, 20)
                .contains(&ReadinessBlocker::ExpiredApproval(ApprovalRole::Product))
        );
    }
}

#[test]
fn release_phases_cannot_be_skipped_or_replayed() {
    for phase in [
        ReleasePhase::Assemble,
        ReleasePhase::ApproveAndSign,
        ReleasePhase::Publish,
    ] {
        assert_eq!(
            ready().require_approval_and_sign(
                &Manifest {
                    phase,
                    ..manifest()
                },
                digest(20),
                &approvals(digest(20)),
                20
            ),
            Err(ReadinessBlocker::WrongPhase {
                expected: ReleasePhase::Verify,
                actual: phase,
            })
        );
    }
}

#[test]
fn complete_verified_candidate_only_authorizes_next_phase() {
    assert_eq!(
        ready().require_approval_and_sign(&manifest(), digest(20), &approvals(digest(20)), 20),
        Ok(ReleasePhase::ApproveAndSign)
    );
}
