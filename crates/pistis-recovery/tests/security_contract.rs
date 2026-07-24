use pistis_domain::{DeviceId, ExternalIdentityId, InstallationId, KeyId, UserId};
use pistis_identity::BindingId;
use pistis_protocol::UnixTimeMillis;
use pistis_recovery::{
    AuthorityClass, BindingGeneration, CompromiseTreatment, CredentialState, CryptographicResult,
    HistoricPolicyResult, NewCredential, OperationId, PriorCredential, ProviderAuthorization,
    RecoveryAuthorization, RecoveryFailure, RecoveryMode, RecoveryPlan, RecoveryPurpose,
    RecoverySnapshot, RevocationFact, SigningTimeEvidence, TemporalResult, classify_historic,
};

fn id16(byte: u8) -> [u8; 16] {
    [byte; 16]
}

fn time(value: u64) -> UnixTimeMillis {
    UnixTimeMillis::new(value)
}

fn device(byte: u8) -> DeviceId {
    DeviceId::from_bytes(id16(byte))
}

fn key(byte: u8) -> KeyId {
    KeyId::from_bytes([byte; 32])
}

fn snapshot() -> RecoverySnapshot {
    RecoverySnapshot {
        installation_id: InstallationId::from_bytes(id16(1)),
        principal_id: UserId::from_bytes(id16(2)),
        external_identity_id: ExternalIdentityId::from_bytes(id16(3)),
        binding_id: BindingId::from_bytes(id16(4)),
        generation: BindingGeneration::new(5),
        prior_credentials: vec![
            PriorCredential {
                device_id: device(6),
                key_id: key(7),
                state: CredentialState::Active,
            },
            PriorCredential {
                device_id: device(8),
                key_id: key(9),
                state: CredentialState::Suspended,
            },
            PriorCredential {
                device_id: device(10),
                key_id: key(11),
                state: CredentialState::Revoked,
            },
        ],
    }
}

fn authorization(purpose: RecoveryPurpose) -> RecoveryAuthorization {
    let state = snapshot();
    RecoveryAuthorization {
        installation_id: state.installation_id,
        principal_id: state.principal_id,
        binding_id: state.binding_id,
        generation: state.generation,
        purpose,
        authority: AuthorityClass::ExistingDevice(device(6)),
        provider: ProviderAuthorization::ExactExistingSubject(state.external_identity_id),
        operation_id: OperationId::from_bytes(id16(12)),
        expires_at: time(100),
    }
}

fn fresh() -> NewCredential {
    NewCredential {
        device_id: device(20),
        key_id: key(21),
    }
}

fn authorize(
    state: &RecoverySnapshot,
    authority: RecoveryAuthorization,
    mode: RecoveryMode,
    credential: NewCredential,
) -> Result<RecoveryPlan, RecoveryFailure> {
    RecoveryPlan::authorize(state, authority, mode, credential, time(50))
}

#[test]
fn exact_context_substitution_and_stale_generation_fail_closed() {
    let state = snapshot();
    let cases = [
        (
            RecoveryAuthorization {
                installation_id: InstallationId::from_bytes(id16(99)),
                ..authorization(RecoveryPurpose::AddDevice)
            },
            RecoveryFailure::WrongInstallation,
        ),
        (
            RecoveryAuthorization {
                principal_id: UserId::from_bytes(id16(99)),
                ..authorization(RecoveryPurpose::AddDevice)
            },
            RecoveryFailure::WrongPrincipal,
        ),
        (
            RecoveryAuthorization {
                binding_id: BindingId::from_bytes(id16(99)),
                ..authorization(RecoveryPurpose::AddDevice)
            },
            RecoveryFailure::WrongBinding,
        ),
        (
            RecoveryAuthorization {
                generation: BindingGeneration::new(99),
                ..authorization(RecoveryPurpose::AddDevice)
            },
            RecoveryFailure::StaleGeneration,
        ),
        (
            RecoveryAuthorization {
                provider: ProviderAuthorization::ExactExistingSubject(
                    ExternalIdentityId::from_bytes(id16(99)),
                ),
                ..authorization(RecoveryPurpose::AddDevice)
            },
            RecoveryFailure::WrongExternalIdentity,
        ),
    ];
    for (substitution, failure) in cases {
        assert_eq!(
            authorize(&state, substitution, RecoveryMode::AddDevice, fresh()),
            Err(failure)
        );
    }
}

#[test]
fn purpose_substitution_and_expiry_fail_closed() {
    assert_eq!(
        authorize(
            &snapshot(),
            authorization(RecoveryPurpose::LostDevice),
            RecoveryMode::AddDevice,
            fresh()
        ),
        Err(RecoveryFailure::WrongPurpose)
    );
    assert_eq!(
        authorize(
            &snapshot(),
            RecoveryAuthorization {
                expires_at: time(50),
                ..authorization(RecoveryPurpose::AddDevice)
            },
            RecoveryMode::AddDevice,
            fresh()
        ),
        Err(RecoveryFailure::Expired)
    );
}

#[test]
fn device_and_private_key_migration_are_unrepresentable_and_reuse_is_rejected() {
    for credential in [
        NewCredential {
            device_id: device(6),
            key_id: key(21),
        },
        NewCredential {
            device_id: device(20),
            key_id: key(7),
        },
    ] {
        assert!(matches!(
            authorize(
                &snapshot(),
                authorization(RecoveryPurpose::AddDevice),
                RecoveryMode::AddDevice,
                credential
            ),
            Err(RecoveryFailure::ReusedDevice | RecoveryFailure::ReusedKey)
        ));
    }
}

#[test]
fn only_an_active_existing_device_can_act_as_device_authority() {
    for authority_device in [device(8), device(10), device(99)] {
        assert_eq!(
            authorize(
                &snapshot(),
                RecoveryAuthorization {
                    authority: AuthorityClass::ExistingDevice(authority_device),
                    ..authorization(RecoveryPurpose::AddDevice)
                },
                RecoveryMode::AddDevice,
                fresh()
            ),
            Err(RecoveryFailure::InactiveAuthority)
        );
    }
}

#[test]
fn governed_console_is_exclusive_to_sole_administrator_recovery() {
    assert_eq!(
        authorize(
            &snapshot(),
            RecoveryAuthorization {
                authority: AuthorityClass::GovernedConsole,
                ..authorization(RecoveryPurpose::AddDevice)
            },
            RecoveryMode::AddDevice,
            fresh()
        ),
        Err(RecoveryFailure::WrongAuthority)
    );
    assert_eq!(
        authorize(
            &snapshot(),
            authorization(RecoveryPurpose::SoleAdministrator),
            RecoveryMode::SoleAdministrator,
            fresh()
        ),
        Err(RecoveryFailure::WrongAuthority)
    );
}

#[test]
fn replacement_and_loss_derive_exact_predecessor_invalidation() {
    for (purpose, mode) in [
        (
            RecoveryPurpose::ReplaceDevice,
            RecoveryMode::ReplaceDevice(device(6)),
        ),
        (
            RecoveryPurpose::LostDevice,
            RecoveryMode::LostDevice(device(8)),
        ),
    ] {
        let (RecoveryMode::ReplaceDevice(expected_device)
        | RecoveryMode::LostDevice(expected_device)) = mode
        else {
            unreachable!()
        };
        let plan = authorize(&snapshot(), authorization(purpose), mode, fresh())
            .expect("exact predecessor");
        assert_eq!(plan.impact.revoked_devices, vec![expected_device]);
        assert_eq!(plan.next_generation, BindingGeneration::new(6));
    }
}

#[test]
fn missing_or_already_revoked_predecessor_cannot_be_replaced() {
    for predecessor in [device(10), device(99)] {
        assert_eq!(
            authorize(
                &snapshot(),
                authorization(RecoveryPurpose::ReplaceDevice),
                RecoveryMode::ReplaceDevice(predecessor),
                fresh()
            ),
            Err(RecoveryFailure::InvalidPredecessor)
        );
    }
}

#[test]
fn sole_administrator_plan_revokes_every_nonterminal_prior_device() {
    let plan = authorize(
        &snapshot(),
        RecoveryAuthorization {
            authority: AuthorityClass::GovernedConsole,
            provider: ProviderAuthorization::GovernedProviderLoss(snapshot().external_identity_id),
            ..authorization(RecoveryPurpose::SoleAdministrator)
        },
        RecoveryMode::SoleAdministrator,
        fresh(),
    )
    .expect("governed console plan");
    assert_eq!(plan.impact.revoked_devices, vec![device(6), device(8)]);
}

#[test]
fn trusted_time_before_retirement_preserves_historic_validity() {
    let result = classify_historic(
        CryptographicResult::Valid,
        SigningTimeEvidence::Trusted(time(10)),
        RevocationFact::Retirement(time(20)),
        CompromiseTreatment::RejectAll,
    );
    assert_eq!(result.temporal, TemporalResult::BeforeRevocation);
    assert_eq!(result.policy, HistoricPolicyResult::Accept);
}

#[test]
fn signing_at_or_after_revocation_is_rejected() {
    for signing_time in [time(20), time(21)] {
        let result = classify_historic(
            CryptographicResult::Valid,
            SigningTimeEvidence::AuthoritativelyBounded {
                earliest: signing_time,
                latest: signing_time,
            },
            RevocationFact::Replacement(time(20)),
            CompromiseTreatment::AcceptBeforeEffectiveTime,
        );
        assert_eq!(result.temporal, TemporalResult::AtOrAfterRevocation);
        assert_eq!(result.policy, HistoricPolicyResult::Reject);
    }
}

#[test]
fn authoritative_range_overlapping_revocation_cannot_prove_validity() {
    let result = classify_historic(
        CryptographicResult::Valid,
        SigningTimeEvidence::AuthoritativelyBounded {
            earliest: time(10),
            latest: time(30),
        },
        RevocationFact::Administrative(time(20)),
        CompromiseTreatment::AcceptBeforeEffectiveTime,
    );
    assert_eq!(
        result.temporal,
        TemporalResult::IndeterminateAuthoritativeRange
    );
    assert_eq!(result.policy, HistoricPolicyResult::Reject);
}

#[test]
fn claimed_time_cannot_prove_a_pre_revocation_signature() {
    let result = classify_historic(
        CryptographicResult::Valid,
        SigningTimeEvidence::SignerClaimed(time(10)),
        RevocationFact::Loss(time(20)),
        CompromiseTreatment::AcceptBeforeEffectiveTime,
    );
    assert_eq!(result.temporal, TemporalResult::IndeterminateClaimedTime);
    assert_eq!(result.policy, HistoricPolicyResult::Reject);
}

#[test]
fn compromise_policy_is_separate_from_cryptographic_validity() {
    for (treatment, expected) in [
        (
            CompromiseTreatment::AcceptBeforeEffectiveTime,
            HistoricPolicyResult::Accept,
        ),
        (
            CompromiseTreatment::QualifyBeforeEffectiveTime,
            HistoricPolicyResult::Qualified,
        ),
        (CompromiseTreatment::RejectAll, HistoricPolicyResult::Reject),
    ] {
        let result = classify_historic(
            CryptographicResult::Valid,
            SigningTimeEvidence::Trusted(time(10)),
            RevocationFact::Compromise(time(20)),
            treatment,
        );
        assert_eq!(result.cryptographic, CryptographicResult::Valid);
        assert_eq!(result.policy, expected);
    }
}

#[test]
fn invalid_signature_is_rejected_regardless_of_lifecycle() {
    let result = classify_historic(
        CryptographicResult::Invalid,
        SigningTimeEvidence::Trusted(time(10)),
        RevocationFact::NotRevoked,
        CompromiseTreatment::AcceptBeforeEffectiveTime,
    );
    assert_eq!(result.temporal, TemporalResult::NotRevoked);
    assert_eq!(result.policy, HistoricPolicyResult::Reject);
}
