use pistis_device_registry::DeviceStatus;
use pistis_domain::{DeviceId, ExternalIdentityId, InstallationId, KeyId, UserId};
use pistis_identity::BindingId;
use pistis_protocol::UnixTimeMillis;
use pistis_synoptikon::{
    AuditCorrelationId, BindingExpectation, BindingFailure, BindingResolver, BindingState,
    CeremonyPurpose, Generation, HostSessionRequest, IntegrationBlocker, ProductionEvidence,
    ProductionReadiness, ReadinessRequirement,
};

const REQUIREMENTS: [ReadinessRequirement; 7] = [
    ReadinessRequirement::DurableCeremonyTransaction,
    ReadinessRequirement::CoseProfileAndFixtures,
    ReadinessRequirement::PersistedChallengeSignature,
    ReadinessRequirement::CompleteBindingResolution,
    ReadinessRequirement::AtomicHostCompletion,
    ReadinessRequirement::ProtectedServerCookie,
    ReadinessRequirement::SessionInvalidation,
];

fn expected() -> BindingExpectation {
    BindingExpectation {
        installation_id: InstallationId::from_bytes([1; 16]),
        user_id: UserId::from_bytes([2; 16]),
        external_identity_id: ExternalIdentityId::from_bytes([3; 16]),
        device_id: DeviceId::from_bytes([4; 16]),
        key_id: KeyId::from_bytes([5; 32]),
        binding_id: BindingId::from_bytes([6; 16]),
        policy_generation: Generation::new(7),
        revocation_generation: Generation::new(8),
        purpose: CeremonyPurpose::AuthenticateSession,
    }
}

fn resolved() -> pistis_synoptikon::ResolvedBinding {
    let expected = expected();
    pistis_synoptikon::ResolvedBinding {
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

struct Resolver(Result<pistis_synoptikon::ResolvedBinding, BindingFailure>);

impl BindingResolver for Resolver {
    fn resolve(
        &self,
        _expected: BindingExpectation,
    ) -> Result<pistis_synoptikon::ResolvedBinding, BindingFailure> {
        self.0.clone()
    }
}

#[test]
fn unknown_readiness_reports_every_requirement_in_normative_order() {
    let blockers = ProductionReadiness::unknown().blockers();
    assert_eq!(blockers.len(), REQUIREMENTS.len());
    for (blocker, requirement) in blockers.iter().zip(REQUIREMENTS) {
        assert_eq!(
            *blocker,
            IntegrationBlocker::Readiness {
                requirement,
                evidence: ProductionEvidence::Unknown,
            }
        );
    }
}

#[test]
fn missing_cose_evidence_blocks_before_binding_resolution() {
    let readiness = ready().with(
        ReadinessRequirement::CoseProfileAndFixtures,
        ProductionEvidence::Missing,
    );
    let result = HostSessionRequest::authorize(
        &readiness,
        &Resolver(Ok(resolved())),
        expected(),
        UnixTimeMillis::new(10),
        AuditCorrelationId::from_bytes([9; 16]),
    );
    assert_eq!(
        result,
        Err(IntegrationBlocker::Readiness {
            requirement: ReadinessRequirement::CoseProfileAndFixtures,
            evidence: ProductionEvidence::Missing,
        })
    );
}

#[test]
fn complete_active_binding_produces_token_free_host_request() {
    let request = HostSessionRequest::authorize(
        &ready(),
        &Resolver(Ok(resolved())),
        expected(),
        UnixTimeMillis::new(10),
        AuditCorrelationId::from_bytes([9; 16]),
    )
    .expect("complete current binding should authorize a host request");

    assert_eq!(request.user_id, expected().user_id);
    assert_eq!(request.policy_generation, Generation::new(7));
    assert_eq!(request.revocation_generation, Generation::new(8));
    assert_eq!(request.correlation_id.as_bytes(), &[9; 16]);
    assert_eq!(request.purpose, CeremonyPurpose::AuthenticateSession);
}

#[test]
fn bootstrap_and_approval_purposes_cannot_issue_login_sessions() {
    for purpose in [
        CeremonyPurpose::BootstrapEnrollment,
        CeremonyPurpose::ConsequentialApproval,
    ] {
        let mut substituted = expected();
        substituted.purpose = purpose;
        let result = HostSessionRequest::authorize(
            &ready(),
            &Resolver(Ok(resolved())),
            substituted,
            UnixTimeMillis::new(10),
            AuditCorrelationId::from_bytes([9; 16]),
        );
        assert_eq!(
            result,
            Err(IntegrationBlocker::Binding(BindingFailure::WrongPurpose))
        );
    }
}

#[test]
fn changed_revocation_generation_fails_closed() {
    let mut stale = resolved();
    stale.revocation_generation = Generation::new(9);
    let result = HostSessionRequest::authorize(
        &ready(),
        &Resolver(Ok(stale)),
        expected(),
        UnixTimeMillis::new(10),
        AuditCorrelationId::from_bytes([9; 16]),
    );
    assert_eq!(
        result,
        Err(IntegrationBlocker::Binding(BindingFailure::StaleRevocation))
    );
}

#[test]
fn suspended_device_and_unavailable_resolver_fail_closed() {
    let mut suspended = resolved();
    suspended.device_state = DeviceStatus::Suspended {
        at: UnixTimeMillis::new(9),
        reason: pistis_device_registry::LifecycleReason::new("operator suspension")
            .expect("valid reason"),
    };
    assert_eq!(
        suspended.validate(expected()),
        Err(BindingFailure::InactiveDevice)
    );

    let result = HostSessionRequest::authorize(
        &ready(),
        &Resolver(Err(BindingFailure::Unavailable)),
        expected(),
        UnixTimeMillis::new(10),
        AuditCorrelationId::from_bytes([9; 16]),
    );
    assert_eq!(
        result,
        Err(IntegrationBlocker::Binding(BindingFailure::Unavailable))
    );
}
