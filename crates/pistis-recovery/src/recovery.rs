use pistis_domain::{DeviceId, ExternalIdentityId, InstallationId, KeyId, UserId};
use pistis_identity::BindingId;
use pistis_protocol::UnixTimeMillis;

/// Monotonic binding generation used for recovery concurrency control.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BindingGeneration(u64);

impl BindingGeneration {
    /// Constructs a persisted generation.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the persisted integer.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }
}

/// Single-use identifier for one recovery transaction.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct OperationId([u8; 16]);

impl OperationId {
    /// Constructs an identifier from independent random bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

/// Closed purpose separating recovery from every other ceremony.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryPurpose {
    /// Enrol another independent device.
    AddDevice,
    /// Replace one available predecessor.
    ReplaceDevice,
    /// Contain and replace a lost device.
    LostDevice,
    /// Recover a sole administrator through governed local console authority.
    SoleAdministrator,
}

/// Recovery operation selected by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryMode {
    /// Add a device without revoking another.
    AddDevice,
    /// Replace an exact predecessor.
    ReplaceDevice(DeviceId),
    /// Revoke and replace an exact lost device.
    LostDevice(DeviceId),
    /// Revoke every prior device for a recovered principal.
    SoleAdministrator,
}

impl RecoveryMode {
    const fn purpose(self) -> RecoveryPurpose {
        match self {
            Self::AddDevice => RecoveryPurpose::AddDevice,
            Self::ReplaceDevice(_) => RecoveryPurpose::ReplaceDevice,
            Self::LostDevice(_) => RecoveryPurpose::LostDevice,
            Self::SoleAdministrator => RecoveryPurpose::SoleAdministrator,
        }
    }
}

/// Host-resolved recovery authority class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityClass {
    /// Approval by an existing active device on the same binding.
    ExistingDevice(DeviceId),
    /// A currently authorized administrator using device-management purpose.
    Administrator(UserId),
    /// Governed privileged local-console recovery.
    GovernedConsole,
}

/// Provider authorization for the immutable existing external identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderAuthorization {
    /// Fresh provider authentication proved the exact existing stable subject.
    ExactExistingSubject(ExternalIdentityId),
    /// Explicit governed provider-loss policy authorized continuation.
    GovernedProviderLoss(ExternalIdentityId),
}

impl ProviderAuthorization {
    const fn identity(self) -> ExternalIdentityId {
        match self {
            Self::ExactExistingSubject(identity) | Self::GovernedProviderLoss(identity) => identity,
        }
    }
}

/// Authoritative current state of a prior device/key pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PriorCredential {
    /// Distinct device identifier.
    pub device_id: DeviceId,
    /// Distinct public-key identifier.
    pub key_id: KeyId,
    /// Current effective state.
    pub state: CredentialState,
}

/// Effective lifecycle state relevant to recovery authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialState {
    /// Credential can authorize a purpose-specific operation.
    Active,
    /// Credential is temporarily contained.
    Suspended,
    /// Credential is terminally revoked.
    Revoked,
}

/// Newly generated independent device credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NewCredential {
    /// New random device identifier.
    pub device_id: DeviceId,
    /// Key identifier derived from a newly generated public key.
    pub key_id: KeyId,
}

/// Complete authoritative snapshot loaded inside the recovery transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoverySnapshot {
    /// Installation owning the binding.
    pub installation_id: InstallationId,
    /// Immutable local principal.
    pub principal_id: UserId,
    /// Exact stable external identity.
    pub external_identity_id: ExternalIdentityId,
    /// Durable external-identity binding.
    pub binding_id: BindingId,
    /// Current binding generation.
    pub generation: BindingGeneration,
    /// Every historic device/key for this binding.
    pub prior_credentials: Vec<PriorCredential>,
}

/// Purpose-specific authorization resolved by the host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryAuthorization {
    /// Installation covered by the authority.
    pub installation_id: InstallationId,
    /// Exact target principal.
    pub principal_id: UserId,
    /// Exact target binding.
    pub binding_id: BindingId,
    /// Binding generation observed by authorization.
    pub generation: BindingGeneration,
    /// Domain-separated purpose.
    pub purpose: RecoveryPurpose,
    /// Host-resolved authority class.
    pub authority: AuthorityClass,
    /// Existing identity or governed provider-loss authorization.
    pub provider: ProviderAuthorization,
    /// Single-use operation identifier.
    pub operation_id: OperationId,
    /// Exclusive authorization expiry.
    pub expires_at: UnixTimeMillis,
}

/// Exact transaction plan emitted after fail-closed validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryPlan {
    /// Single-use operation identifier.
    pub operation_id: OperationId,
    /// New independent credential to enrol.
    pub new_credential: NewCredential,
    /// Prior devices to revoke atomically.
    pub impact: RecoveryImpact,
    /// Generation to persist on successful commit.
    pub next_generation: BindingGeneration,
}

/// Authoritative invalidation impact derived from the recovery mode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryImpact {
    /// Devices whose sessions and pending ceremonies must be invalidated.
    pub revoked_devices: Vec<DeviceId>,
}

impl RecoveryPlan {
    /// Authorizes an exact plan without performing mutation.
    ///
    /// # Errors
    ///
    /// Rejects stale, substituted, expired, reused, cross-purpose, cloned, or
    /// under-authorized recovery inputs.
    pub fn authorize(
        snapshot: &RecoverySnapshot,
        authorization: RecoveryAuthorization,
        mode: RecoveryMode,
        new_credential: NewCredential,
        now: UnixTimeMillis,
    ) -> Result<Self, RecoveryFailure> {
        validate_context(snapshot, authorization, mode, now)?;
        validate_new_credential(snapshot, new_credential)?;
        validate_authority(snapshot, authorization.authority, mode)?;
        let revoked_devices = impacted_devices(snapshot, mode)?;
        let next_generation = snapshot
            .generation
            .next()
            .ok_or(RecoveryFailure::GenerationExhausted)?;
        Ok(Self {
            operation_id: authorization.operation_id,
            new_credential,
            impact: RecoveryImpact { revoked_devices },
            next_generation,
        })
    }
}

fn validate_context(
    snapshot: &RecoverySnapshot,
    authorization: RecoveryAuthorization,
    mode: RecoveryMode,
    now: UnixTimeMillis,
) -> Result<(), RecoveryFailure> {
    if snapshot.installation_id != authorization.installation_id {
        return Err(RecoveryFailure::WrongInstallation);
    }
    if snapshot.principal_id != authorization.principal_id {
        return Err(RecoveryFailure::WrongPrincipal);
    }
    if snapshot.binding_id != authorization.binding_id {
        return Err(RecoveryFailure::WrongBinding);
    }
    if snapshot.generation != authorization.generation {
        return Err(RecoveryFailure::StaleGeneration);
    }
    if snapshot.external_identity_id != authorization.provider.identity() {
        return Err(RecoveryFailure::WrongExternalIdentity);
    }
    if mode.purpose() != authorization.purpose {
        return Err(RecoveryFailure::WrongPurpose);
    }
    if now >= authorization.expires_at {
        return Err(RecoveryFailure::Expired);
    }
    Ok(())
}

fn validate_new_credential(
    snapshot: &RecoverySnapshot,
    new_credential: NewCredential,
) -> Result<(), RecoveryFailure> {
    if snapshot
        .prior_credentials
        .iter()
        .any(|prior| prior.device_id == new_credential.device_id)
    {
        return Err(RecoveryFailure::ReusedDevice);
    }
    if snapshot
        .prior_credentials
        .iter()
        .any(|prior| prior.key_id == new_credential.key_id)
    {
        return Err(RecoveryFailure::ReusedKey);
    }
    Ok(())
}

fn validate_authority(
    snapshot: &RecoverySnapshot,
    authority: AuthorityClass,
    mode: RecoveryMode,
) -> Result<(), RecoveryFailure> {
    match (authority, mode) {
        (AuthorityClass::GovernedConsole, RecoveryMode::SoleAdministrator) => Ok(()),
        (AuthorityClass::GovernedConsole, _) | (_, RecoveryMode::SoleAdministrator) => {
            Err(RecoveryFailure::WrongAuthority)
        }
        (AuthorityClass::Administrator(_), _) => Ok(()),
        (AuthorityClass::ExistingDevice(device_id), _) => snapshot
            .prior_credentials
            .iter()
            .find(|prior| prior.device_id == device_id)
            .filter(|prior| prior.state == CredentialState::Active)
            .map(|_| ())
            .ok_or(RecoveryFailure::InactiveAuthority),
    }
}

fn impacted_devices(
    snapshot: &RecoverySnapshot,
    mode: RecoveryMode,
) -> Result<Vec<DeviceId>, RecoveryFailure> {
    match mode {
        RecoveryMode::AddDevice => Ok(Vec::new()),
        RecoveryMode::ReplaceDevice(device_id) | RecoveryMode::LostDevice(device_id) => snapshot
            .prior_credentials
            .iter()
            .find(|prior| prior.device_id == device_id)
            .filter(|prior| prior.state != CredentialState::Revoked)
            .map(|_| vec![device_id])
            .ok_or(RecoveryFailure::InvalidPredecessor),
        RecoveryMode::SoleAdministrator => Ok(snapshot
            .prior_credentials
            .iter()
            .filter(|prior| prior.state != CredentialState::Revoked)
            .map(|prior| prior.device_id)
            .collect()),
    }
}

/// Typed recovery-plan rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryFailure {
    /// Authority covers another installation.
    WrongInstallation,
    /// Authority covers another local principal.
    WrongPrincipal,
    /// Authority covers another binding.
    WrongBinding,
    /// Authority uses stale binding state.
    StaleGeneration,
    /// Provider subject differs from the immutable external identity.
    WrongExternalIdentity,
    /// Authorization purpose differs from the requested mode.
    WrongPurpose,
    /// Authorization expired.
    Expired,
    /// Existing authority is absent, suspended, or revoked.
    InactiveAuthority,
    /// Authority class cannot authorize the selected mode.
    WrongAuthority,
    /// Replacement or loss target is absent or already revoked.
    InvalidPredecessor,
    /// New device identifier copies a prior device.
    ReusedDevice,
    /// New key identifier copies a prior key.
    ReusedKey,
    /// Monotonic binding generation cannot advance.
    GenerationExhausted,
}
