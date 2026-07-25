use pistis_device_registry::DeviceStatus;
use pistis_domain::{DeviceId, ExternalIdentityId, InstallationId, KeyId, UserId};
use pistis_identity::BindingId;
use pistis_protocol::UnixTimeMillis;
use pistis_synoptikon::{
    AuditCorrelationId, BindingExpectation, BindingFailure, BindingResolver, BindingState,
    CeremonyPurpose, Generation, HostSessionError, HostSessionIssuer, HostSessionOutcome,
    HostSessionRequest, IntegrationBlocker, ProductionEvidence, ProductionReadiness,
    ReadinessRequirement, ResolvedBinding, SessionIdDigest,
};
use std::cell::Cell;

const REQUIREMENTS: [ReadinessRequirement; 7] = [
    ReadinessRequirement::DurableCeremonyTransaction,
    ReadinessRequirement::CoseProfileAndFixtures,
    ReadinessRequirement::PersistedChallengeSignature,
    ReadinessRequirement::CompleteBindingResolution,
    ReadinessRequirement::AtomicHostCompletion,
    ReadinessRequirement::ProtectedServerCookie,
    ReadinessRequirement::SessionInvalidation,
];

fn id16(value: u8) -> [u8; 16] {
    [value; 16]
}

fn expected() -> BindingExpectation {
    BindingExpectation {
        installation_id: InstallationId::from_bytes(id16(1)),
        user_id: UserId::from_bytes(id16(2)),
        external_identity_id: ExternalIdentityId::from_bytes(id16(3)),
        device_id: DeviceId::from_bytes(id16(4)),
        key_id: KeyId::from_bytes([5; 32]),
        binding_id: BindingId::from_bytes(id16(6)),
        policy_generation: Generation::new(7),
        revocation_generation: Generation::new(8),
        purpose: CeremonyPurpose::AuthenticateSession,
    }
}

fn resolved() -> ResolvedBinding {
    let expected = expected();
    ResolvedBinding {
        installation_id: expected.installation_id,
        user_id: expected.user_id,
        external_identity_id: expected.external_identity_id,
        device_id: expected.device_id,
        key_id: expected.key_id,
        binding_id: expected.binding_id,
        installation_state: BindingState::Active,
        user_state: BindingState::Active,
        binding_state: BindingState::Active,
        key_state: BindingState::Active,
        device_state: DeviceStatus::Active,
        policy_generation: expected.policy_generation,
        revocation_generation: expected.revocation_generation,
    }
}

fn ready() -> ProductionReadiness {
    REQUIREMENTS
        .into_iter()
        .fold(ProductionReadiness::unknown(), |readiness, requirement| {
            readiness.with(requirement, ProductionEvidence::Verified)
        })
}

struct Resolver(Result<ResolvedBinding, BindingFailure>);

impl BindingResolver for Resolver {
    fn resolve(&self, _expected: BindingExpectation) -> Result<ResolvedBinding, BindingFailure> {
        self.0.clone()
    }
}

fn authorize(
    readiness: &ProductionReadiness,
    resolver: &Resolver,
) -> Result<HostSessionRequest, IntegrationBlocker> {
    HostSessionRequest::authorize(
        readiness,
        resolver,
        expected(),
        UnixTimeMillis::new(9),
        AuditCorrelationId::from_bytes(id16(10)),
    )
}

#[test]
fn every_readiness_requirement_is_independently_fail_closed() {
    for missing in REQUIREMENTS {
        let readiness = REQUIREMENTS.into_iter().fold(
            ProductionReadiness::unknown(),
            |readiness, requirement| {
                readiness.with(
                    requirement,
                    if requirement == missing {
                        ProductionEvidence::Missing
                    } else {
                        ProductionEvidence::Verified
                    },
                )
            },
        );

        assert_eq!(
            authorize(&readiness, &Resolver(Ok(resolved()))),
            Err(IntegrationBlocker::Readiness {
                requirement: missing,
                evidence: ProductionEvidence::Missing,
            })
        );
    }
}

#[test]
fn unknown_readiness_reports_all_blockers_in_normative_order() {
    let blockers = ProductionReadiness::unknown().blockers();
    assert_eq!(blockers.len(), REQUIREMENTS.len());
    for (blocker, requirement) in blockers.into_iter().zip(REQUIREMENTS) {
        assert_eq!(
            blocker,
            IntegrationBlocker::Readiness {
                requirement,
                evidence: ProductionEvidence::Unknown,
            }
        );
    }
}

#[test]
fn readiness_is_checked_before_authoritative_resolution() {
    let unavailable = Resolver(Err(BindingFailure::Unavailable));
    assert_eq!(
        authorize(&ProductionReadiness::unknown(), &unavailable),
        Err(IntegrationBlocker::Readiness {
            requirement: ReadinessRequirement::DurableCeremonyTransaction,
            evidence: ProductionEvidence::Unknown,
        })
    );
}

#[test]
fn every_exact_binding_substitution_is_rejected() {
    let cases: Vec<(ResolvedBinding, BindingFailure)> = vec![
        (
            ResolvedBinding {
                installation_id: InstallationId::from_bytes(id16(20)),
                ..resolved()
            },
            BindingFailure::WrongInstallation,
        ),
        (
            ResolvedBinding {
                user_id: UserId::from_bytes(id16(20)),
                ..resolved()
            },
            BindingFailure::WrongUser,
        ),
        (
            ResolvedBinding {
                external_identity_id: ExternalIdentityId::from_bytes(id16(20)),
                ..resolved()
            },
            BindingFailure::WrongExternalIdentity,
        ),
        (
            ResolvedBinding {
                device_id: DeviceId::from_bytes(id16(20)),
                ..resolved()
            },
            BindingFailure::WrongDevice,
        ),
        (
            ResolvedBinding {
                key_id: KeyId::from_bytes([20; 32]),
                ..resolved()
            },
            BindingFailure::WrongKey,
        ),
        (
            ResolvedBinding {
                binding_id: BindingId::from_bytes(id16(20)),
                ..resolved()
            },
            BindingFailure::WrongBinding,
        ),
    ];

    for (substituted, failure) in cases {
        assert_eq!(
            authorize(&ready(), &Resolver(Ok(substituted))),
            Err(IntegrationBlocker::Binding(failure))
        );
    }
}

#[test]
fn revocation_generation_boundary_and_revoked_state_are_rejected() {
    let stale = ResolvedBinding {
        revocation_generation: Generation::new(expected().revocation_generation.get() + 1),
        ..resolved()
    };
    assert_eq!(
        authorize(&ready(), &Resolver(Ok(stale))),
        Err(IntegrationBlocker::Binding(BindingFailure::StaleRevocation))
    );

    let revoked = ResolvedBinding {
        key_state: BindingState::Revoked,
        ..resolved()
    };
    assert_eq!(
        authorize(&ready(), &Resolver(Ok(revoked))),
        Err(IntegrationBlocker::Binding(BindingFailure::InactiveKey))
    );
}

#[test]
fn bootstrap_and_consequential_purposes_cannot_issue_sessions() {
    for purpose in [
        CeremonyPurpose::BootstrapEnrollment,
        CeremonyPurpose::ConsequentialApproval,
    ] {
        let expectation = BindingExpectation {
            purpose,
            ..expected()
        };
        assert_eq!(
            HostSessionRequest::authorize(
                &ready(),
                &Resolver(Ok(resolved())),
                expectation,
                UnixTimeMillis::new(9),
                AuditCorrelationId::from_bytes(id16(10)),
            ),
            Err(IntegrationBlocker::Binding(BindingFailure::WrongPurpose))
        );
    }
}

#[test]
fn authorized_session_request_retains_exact_authentication_purpose() {
    let request = authorize(&ready(), &Resolver(Ok(resolved()))).unwrap();
    assert_eq!(request.purpose, CeremonyPurpose::AuthenticateSession);
}

#[test]
fn resolver_errors_are_never_interpreted_as_active_bindings() {
    for failure in [
        BindingFailure::NotFound,
        BindingFailure::Corrupt,
        BindingFailure::Unavailable,
    ] {
        assert_eq!(
            authorize(&ready(), &Resolver(Err(failure))),
            Err(IntegrationBlocker::Binding(failure))
        );
    }
}

struct CountingIssuer {
    calls: Cell<usize>,
}

impl HostSessionIssuer for CountingIssuer {
    fn issue(&self, _request: HostSessionRequest) -> Result<HostSessionOutcome, HostSessionError> {
        self.calls.set(self.calls.get() + 1);
        Ok(HostSessionOutcome {
            session_id_digest: SessionIdDigest::from_bytes([11; 32]),
            expires_at: UnixTimeMillis::new(12),
        })
    }
}

fn authorize_then_issue(
    readiness: &ProductionReadiness,
    resolver: &Resolver,
    issuer: &impl HostSessionIssuer,
) -> Result<HostSessionOutcome, HostSessionError> {
    let request = authorize(readiness, resolver).map_err(|_| HostSessionError::Conflict)?;
    issuer.issue(request)
}

#[test]
fn blocked_or_rejected_authorization_never_reaches_session_issuer() {
    let issuer = CountingIssuer {
        calls: Cell::new(0),
    };
    assert_eq!(
        authorize_then_issue(
            &ProductionReadiness::unknown(),
            &Resolver(Ok(resolved())),
            &issuer
        ),
        Err(HostSessionError::Conflict)
    );
    assert_eq!(
        authorize_then_issue(
            &ready(),
            &Resolver(Err(BindingFailure::InactiveDevice)),
            &issuer
        ),
        Err(HostSessionError::Conflict)
    );
    assert_eq!(issuer.calls.get(), 0);
}

#[test]
fn audit_correlation_is_independent_of_session_material() {
    let correlation = AuditCorrelationId::from_bytes(id16(10));
    let digest = SessionIdDigest::from_bytes([11; 32]);

    assert_eq!(correlation.as_bytes(), &id16(10));
    assert_eq!(digest.as_bytes(), &[11; 32]);
    assert_ne!(
        correlation.as_bytes().as_slice(),
        &digest.as_bytes()[..correlation.as_bytes().len()]
    );

    let request = authorize(&ready(), &Resolver(Ok(resolved()))).unwrap();
    assert_eq!(request.correlation_id, correlation);
}
