use pistis_discovery::{
    AddressScope, Advertisement, AdvertisementError, AttemptFailure, BindingContext, Candidate,
    CandidateFailure, Capability, EndpointBinding, EndpointId, InstanceName, InterfaceId,
    ProtocolVersion, SelectionState, ServiceType, TlsPublicKeyDigest, TransferAttempt,
    TransferPlan, TransportRejection,
};
use pistis_domain::{ChallengeId, InstallationId};
use pistis_protocol::UnixTimeMillis;

fn time(value: u64) -> UnixTimeMillis {
    UnixTimeMillis::new(value)
}

fn endpoint(byte: u8) -> EndpointId {
    EndpointId::from_bytes([byte; 16])
}

fn interface(byte: u8) -> InterfaceId {
    InterfaceId::from_bytes([byte; 16])
}

fn installation(byte: u8) -> InstallationId {
    InstallationId::from_bytes([byte; 16])
}

fn context(byte: u8) -> BindingContext {
    BindingContext::Challenge(ChallengeId::from_bytes([byte; 16]))
}

fn binding() -> EndpointBinding {
    EndpointBinding {
        version: ProtocolVersion::V1,
        installation_id: installation(1),
        endpoint_id: endpoint(2),
        service_type: ServiceType::PistisTcpLocal,
        https_port: 8443,
        tls_public_key_digest: TlsPublicKeyDigest::from_bytes([3; 32]),
        issued_at: time(10),
        expires_at: time(30),
        context: context(4),
    }
}

fn candidate() -> Candidate {
    Candidate {
        version: ProtocolVersion::V1,
        service_type: ServiceType::PistisTcpLocal,
        endpoint_id: endpoint(2),
        port: 8443,
        answer_interface: interface(5),
        connection_interface: interface(5),
        address_scope: AddressScope::LocalUnicast,
        record_expires_at: time(25),
    }
}

fn authorize(
    candidate: Candidate,
    binding: EndpointBinding,
) -> Result<pistis_discovery::DirectRequest, CandidateFailure> {
    candidate.authorize(binding, installation(1), context(4), time(20))
}

#[test]
fn advertisement_is_minimal_and_cannot_outlive_the_ceremony() {
    let advertisement = Advertisement::new(
        InstanceName::from_bytes([1; 16]),
        endpoint(2),
        Capability::DirectHttps,
        time(10),
        time(20),
        time(20),
    )
    .expect("bounded advertisement");
    assert_eq!(advertisement.service_type, ServiceType::PistisTcpLocal);
    assert_eq!(advertisement.version, ProtocolVersion::V1);

    assert_eq!(
        Advertisement::new(
            InstanceName::from_bytes([1; 16]),
            endpoint(2),
            Capability::DirectHttps,
            time(10),
            time(21),
            time(20),
        ),
        Err(AdvertisementError::BeyondCeremony)
    );
    assert_eq!(
        Advertisement::new(
            InstanceName::from_bytes([1; 16]),
            endpoint(2),
            Capability::DirectHttps,
            time(10),
            time(10),
            time(20),
        ),
        Err(AdvertisementError::Expired)
    );
}

#[test]
fn every_discovery_control_substitution_fails_closed() {
    let cases = [
        (
            Candidate {
                version: ProtocolVersion::Unsupported(2),
                ..candidate()
            },
            CandidateFailure::WrongVersion,
        ),
        (
            Candidate {
                service_type: ServiceType::Other,
                ..candidate()
            },
            CandidateFailure::WrongService,
        ),
        (
            Candidate {
                endpoint_id: endpoint(9),
                ..candidate()
            },
            CandidateFailure::WrongEndpoint,
        ),
        (
            Candidate {
                port: 443,
                ..candidate()
            },
            CandidateFailure::WrongPort,
        ),
        (
            Candidate {
                connection_interface: interface(9),
                ..candidate()
            },
            CandidateFailure::WrongInterface,
        ),
    ];

    for (substitution, failure) in cases {
        assert_eq!(authorize(substitution, binding()), Err(failure));
    }
}

#[test]
fn installation_and_challenge_context_substitution_fail_closed() {
    assert_eq!(
        candidate().authorize(binding(), installation(9), context(4), time(20)),
        Err(CandidateFailure::WrongInstallation)
    );
    assert_eq!(
        candidate().authorize(binding(), installation(1), context(9), time(20)),
        Err(CandidateFailure::WrongContext)
    );
}

#[test]
fn stale_and_not_yet_valid_bindings_and_records_fail_closed() {
    assert_eq!(
        candidate().authorize(binding(), installation(1), context(4), time(9)),
        Err(CandidateFailure::StaleBinding)
    );
    assert_eq!(
        candidate().authorize(binding(), installation(1), context(4), time(30)),
        Err(CandidateFailure::StaleBinding)
    );
    assert_eq!(
        authorize(
            Candidate {
                record_expires_at: time(20),
                ..candidate()
            },
            binding()
        ),
        Err(CandidateFailure::StaleRecord)
    );
}

#[test]
fn non_unicast_address_scopes_are_never_direct_endpoints() {
    for address_scope in [
        AddressScope::Loopback,
        AddressScope::Unspecified,
        AddressScope::Multicast,
    ] {
        assert_eq!(
            authorize(
                Candidate {
                    address_scope,
                    ..candidate()
                },
                binding()
            ),
            Err(CandidateFailure::UnsupportedAddressScope)
        );
    }
}

#[test]
fn authorized_request_uses_only_authenticated_pin_port_interface_and_context() {
    let request = authorize(candidate(), binding()).expect("matching candidate");
    assert_eq!(request.installation_id, installation(1));
    assert_eq!(request.endpoint_id, endpoint(2));
    assert_eq!(request.port, 8443);
    assert_eq!(request.interface_id, interface(5));
    assert_eq!(
        request.tls_public_key_digest,
        TlsPublicKeyDigest::from_bytes([3; 32])
    );
    assert_eq!(request.context, context(4));
}

#[test]
fn bounded_transport_failures_follow_the_normative_order() {
    let mut plan = TransferPlan::new();
    assert_eq!(
        plan.state(),
        SelectionState::Attempting(TransferAttempt::PairedLocal)
    );
    plan.advance(AttemptFailure::Unavailable);
    assert_eq!(
        plan.state(),
        SelectionState::Attempting(TransferAttempt::DiscoveredLocal)
    );
    plan.advance(AttemptFailure::CandidateRejected);
    assert_eq!(
        plan.state(),
        SelectionState::Attempting(TransferAttempt::SignedHttpsHint)
    );
    plan.advance(AttemptFailure::Timeout);
    assert_eq!(plan.state(), SelectionState::QrReady);
}

#[test]
fn permission_denial_and_network_change_cleanly_reach_qr() {
    for failure in [
        AttemptFailure::PermissionDenied,
        AttemptFailure::NetworkChanged,
    ] {
        let mut plan = TransferPlan::new();
        plan.advance(failure);
        plan.advance(failure);
        plan.advance(failure);
        assert_eq!(plan.state(), SelectionState::QrReady);
        plan.advance(failure);
        assert_eq!(plan.state(), SelectionState::QrReady);
    }
}

#[test]
fn security_rejection_is_terminal_and_never_becomes_fallback() {
    for rejection in [
        TransportRejection::ChallengeRejected,
        TransportRejection::ResponseRejected,
    ] {
        let mut plan = TransferPlan::new();
        plan.reject(rejection);
        assert_eq!(plan.state(), SelectionState::Rejected(rejection));
        plan.advance(AttemptFailure::Timeout);
        assert_eq!(plan.state(), SelectionState::Rejected(rejection));
    }
}
