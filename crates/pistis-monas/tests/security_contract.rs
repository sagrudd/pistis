use pistis_device_registry::{DeviceStatus, LifecycleReason};
use pistis_domain::{DeviceId, ExternalIdentityId, InstallationId, KeyId, UserId};
use pistis_identity::BindingId;
use pistis_monas::{
    AuditCorrelationId, BindingExpectation, BindingFailure, BindingResolver, BindingState,
    DeliveryProfile, Generation, IntegrationBlocker, OperationPurpose, ProductionEvidence,
    ReadinessRequirement, ResolvedBinding, StandaloneReadiness,
};
use pistis_protocol::UnixTimeMillis;
use std::cell::Cell;

const REQUIREMENTS: [ReadinessRequirement; 9] = [
    ReadinessRequirement::CoseProfileAndFixtures,
    ReadinessRequirement::DurableSqliteRepositories,
    ReadinessRequirement::PersistedChallengeSignature,
    ReadinessRequirement::CompleteBindingResolution,
    ReadinessRequirement::AtomicHostCompletion,
    ReadinessRequirement::ProtectedServerCookie,
    ReadinessRequirement::SessionInvalidation,
    ReadinessRequirement::OperationalStateSafety,
    ReadinessRequirement::PinnedJenkinsEvidence,
];

fn id16(byte: u8) -> [u8; 16] {
    [byte; 16]
}

fn expectation() -> BindingExpectation {
    BindingExpectation {
        installation_id: InstallationId::from_bytes(id16(1)),
        principal_id: UserId::from_bytes(id16(2)),
        external_identity_id: ExternalIdentityId::from_bytes(id16(3)),
        device_id: DeviceId::from_bytes(id16(4)),
        key_id: KeyId::from_bytes([5; 32]),
        binding_id: BindingId::from_bytes(id16(6)),
        policy_generation: Generation::new(7),
        revocation_generation: Generation::new(8),
        purpose: OperationPurpose::AuthenticateSession,
    }
}

fn resolved() -> ResolvedBinding {
    let expected = expectation();
    ResolvedBinding {
        installation_id: expected.installation_id,
        principal_id: expected.principal_id,
        external_identity_id: expected.external_identity_id,
        device_id: expected.device_id,
        key_id: expected.key_id,
        binding_id: expected.binding_id,
        installation_state: BindingState::Active,
        principal_state: BindingState::Active,
        binding_state: BindingState::Active,
        key_state: BindingState::Active,
        device_state: DeviceStatus::Active,
        policy_generation: expected.policy_generation,
        revocation_generation: expected.revocation_generation,
    }
}

fn ready() -> StandaloneReadiness {
    REQUIREMENTS
        .into_iter()
        .fold(StandaloneReadiness::unknown(), |readiness, requirement| {
            readiness.with(requirement, ProductionEvidence::Verified)
        })
}

struct Resolver {
    calls: Cell<u8>,
    outcome: Result<ResolvedBinding, BindingFailure>,
}

impl Resolver {
    fn new(outcome: Result<ResolvedBinding, BindingFailure>) -> Self {
        Self {
            calls: Cell::new(0),
            outcome,
        }
    }
}

impl BindingResolver for Resolver {
    fn resolve(&self, _: BindingExpectation) -> Result<ResolvedBinding, BindingFailure> {
        self.calls.set(self.calls.get() + 1);
        self.outcome.clone()
    }
}

fn authorize(
    profile: DeliveryProfile,
    readiness: &StandaloneReadiness,
    resolver: &Resolver,
    expected: BindingExpectation,
) -> Result<pistis_monas::HostSessionRequest, IntegrationBlocker> {
    pistis_monas::HostSessionRequest::authorize(
        profile,
        readiness,
        resolver,
        expected,
        UnixTimeMillis::new(9),
        AuditCorrelationId::from_bytes(id16(10)),
    )
}

#[test]
fn every_readiness_requirement_is_independently_fail_closed() {
    for missing in REQUIREMENTS {
        let readiness = REQUIREMENTS.into_iter().fold(
            StandaloneReadiness::unknown(),
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
            authorize(
                DeliveryProfile::Standalone,
                &readiness,
                &Resolver::new(Ok(resolved())),
                expectation()
            ),
            Err(IntegrationBlocker::Readiness {
                requirement: missing,
                evidence: ProductionEvidence::Missing,
            })
        );
    }
}

#[test]
fn unknown_evidence_reports_all_blockers_in_normative_order() {
    let blockers = StandaloneReadiness::unknown().blockers();
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
fn non_standalone_profiles_never_resolve_or_request_sessions() {
    for profile in [
        DeliveryProfile::Contract,
        DeliveryProfile::Reference,
        DeliveryProfile::OfflineVerifier,
    ] {
        let resolver = Resolver::new(Ok(resolved()));
        assert_eq!(
            authorize(profile, &ready(), &resolver, expectation()),
            Err(IntegrationBlocker::WrongProfile(profile))
        );
        assert_eq!(resolver.calls.get(), 0);
    }
}

#[test]
fn readiness_is_checked_before_authoritative_resolution() {
    let resolver = Resolver::new(Err(BindingFailure::Unavailable));
    assert_eq!(
        authorize(
            DeliveryProfile::Standalone,
            &StandaloneReadiness::unknown(),
            &resolver,
            expectation()
        ),
        Err(IntegrationBlocker::Readiness {
            requirement: ReadinessRequirement::CoseProfileAndFixtures,
            evidence: ProductionEvidence::Unknown,
        })
    );
    assert_eq!(resolver.calls.get(), 0);
}

#[test]
fn zero_audit_correlation_is_rejected_before_authoritative_resolution() {
    let resolver = Resolver::new(Ok(resolved()));

    assert_eq!(
        pistis_monas::HostSessionRequest::authorize(
            DeliveryProfile::Standalone,
            &ready(),
            &resolver,
            expectation(),
            UnixTimeMillis::new(9),
            AuditCorrelationId::from_bytes([0; 16]),
        ),
        Err(IntegrationBlocker::InvalidAuditCorrelation)
    );
    assert_eq!(resolver.calls.get(), 0);
}

#[test]
fn non_zero_audit_correlation_remains_eligible_for_authorized_request() {
    let resolver = Resolver::new(Ok(resolved()));

    let request = authorize(
        DeliveryProfile::Standalone,
        &ready(),
        &resolver,
        expectation(),
    )
    .expect("non-zero correlation must preserve the authorized contract path");

    assert_eq!(
        request.correlation_id,
        AuditCorrelationId::from_bytes(id16(10))
    );
    assert_eq!(resolver.calls.get(), 1);
}

#[test]
fn every_exact_binding_substitution_is_rejected() {
    let cases = [
        (
            ResolvedBinding {
                installation_id: InstallationId::from_bytes(id16(20)),
                ..resolved()
            },
            BindingFailure::WrongInstallation,
        ),
        (
            ResolvedBinding {
                principal_id: UserId::from_bytes(id16(20)),
                ..resolved()
            },
            BindingFailure::WrongPrincipal,
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
    for (substitution, failure) in cases {
        assert_eq!(
            authorize(
                DeliveryProfile::Standalone,
                &ready(),
                &Resolver::new(Ok(substitution)),
                expectation()
            ),
            Err(IntegrationBlocker::Binding(failure))
        );
    }
}

#[test]
fn stale_generations_and_every_inactive_authority_fail_closed() {
    let cases = [
        (
            ResolvedBinding {
                policy_generation: Generation::new(99),
                ..resolved()
            },
            BindingFailure::StalePolicy,
        ),
        (
            ResolvedBinding {
                revocation_generation: Generation::new(99),
                ..resolved()
            },
            BindingFailure::StaleRevocation,
        ),
        (
            ResolvedBinding {
                installation_state: BindingState::Suspended,
                ..resolved()
            },
            BindingFailure::InactiveInstallation,
        ),
        (
            ResolvedBinding {
                principal_state: BindingState::Revoked,
                ..resolved()
            },
            BindingFailure::InactivePrincipal,
        ),
        (
            ResolvedBinding {
                binding_state: BindingState::Suspended,
                ..resolved()
            },
            BindingFailure::InactiveBinding,
        ),
        (
            ResolvedBinding {
                key_state: BindingState::Revoked,
                ..resolved()
            },
            BindingFailure::InactiveKey,
        ),
        (
            ResolvedBinding {
                device_state: DeviceStatus::Revoked {
                    at: UnixTimeMillis::new(9),
                    reason: LifecycleReason::new("security test").expect("valid reason"),
                },
                ..resolved()
            },
            BindingFailure::InactiveDevice,
        ),
    ];
    for (binding, failure) in cases {
        assert_eq!(
            authorize(
                DeliveryProfile::Standalone,
                &ready(),
                &Resolver::new(Ok(binding)),
                expectation()
            ),
            Err(IntegrationBlocker::Binding(failure))
        );
    }
}

#[test]
fn non_authentication_purposes_cannot_request_a_browser_session() {
    for purpose in [
        OperationPurpose::ConsequentialApproval,
        OperationPurpose::ArtefactSigning,
    ] {
        assert_eq!(
            authorize(
                DeliveryProfile::Standalone,
                &ready(),
                &Resolver::new(Ok(resolved())),
                BindingExpectation {
                    purpose,
                    ..expectation()
                }
            ),
            Err(IntegrationBlocker::Binding(BindingFailure::WrongPurpose))
        );
    }
}

#[test]
fn resolver_errors_are_never_interpreted_as_active_bindings() {
    for failure in [
        BindingFailure::NotFound,
        BindingFailure::Corrupt,
        BindingFailure::Unavailable,
    ] {
        assert_eq!(
            authorize(
                DeliveryProfile::Standalone,
                &ready(),
                &Resolver::new(Err(failure)),
                expectation()
            ),
            Err(IntegrationBlocker::Binding(failure))
        );
    }
}

#[test]
fn authorized_request_contains_context_but_no_role_or_session_credential() {
    let request = authorize(
        DeliveryProfile::Standalone,
        &ready(),
        &Resolver::new(Ok(resolved())),
        expectation(),
    )
    .expect("complete readiness and active bindings");
    assert_eq!(request.principal_id, expectation().principal_id);
    assert_eq!(request.purpose, OperationPurpose::AuthenticateSession);
    assert_eq!(
        core::mem::size_of_val(&request.correlation_id),
        core::mem::size_of::<[u8; 16]>()
    );
}
