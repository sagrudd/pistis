use pistis_device_registry::DeviceStatus;
use pistis_domain::{DeviceId, ExternalIdentityId, InstallationId, KeyId, UserId};
use pistis_identity::BindingId;

/// Monotonic generation used to invalidate stale policy and revocation views.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Generation(u64);

impl Generation {
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
}

/// Effective authoritative state of an installation, user, binding, or key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingState {
    /// The entity may participate in authentication.
    Active,
    /// The entity is temporarily ineligible.
    Suspended,
    /// The entity is terminally revoked.
    Revoked,
}

/// Closed domain-separation purpose for Synoptikon ceremonies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CeremonyPurpose {
    /// Authenticate an existing local user into a normal host session.
    AuthenticateSession,
    /// Enrol the first administrator without issuing a normal session directly.
    BootstrapEnrollment,
    /// Approve a consequential action without authenticating a browser session.
    ConsequentialApproval,
}

/// Exact bindings covered by the challenged authentication operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BindingExpectation {
    /// Installation accepting the authentication.
    pub installation_id: InstallationId,
    /// Existing local Pistis user.
    pub user_id: UserId,
    /// Required provider-backed identity.
    pub external_identity_id: ExternalIdentityId,
    /// Device presenting the response.
    pub device_id: DeviceId,
    /// Exact public-key identifier carried by the response.
    pub key_id: KeyId,
    /// Durable external-identity binding slot.
    pub binding_id: BindingId,
    /// Policy generation persisted with the challenge.
    pub policy_generation: Generation,
    /// Revocation generation persisted with the challenge.
    pub revocation_generation: Generation,
    /// Domain-separated operation covered by the challenge.
    pub purpose: CeremonyPurpose,
}

/// Complete authoritative binding snapshot loaded during completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedBinding {
    /// Installation owning every resolved entity.
    pub installation_id: InstallationId,
    /// Local user authenticated by the ceremony.
    pub user_id: UserId,
    /// Stable external identity bound to the user.
    pub external_identity_id: ExternalIdentityId,
    /// Enrolled device.
    pub device_id: DeviceId,
    /// Exact active verification key.
    pub key_id: KeyId,
    /// Durable binding slot.
    pub binding_id: BindingId,
    /// Effective installation state.
    pub installation_state: BindingState,
    /// Effective local-user state.
    pub user_state: BindingState,
    /// Effective external binding state.
    pub binding_state: BindingState,
    /// Effective key state.
    pub key_state: BindingState,
    /// Effective device lifecycle state.
    pub device_state: DeviceStatus,
    /// Current authorization and verification policy generation.
    pub policy_generation: Generation,
    /// Current effective revocation generation.
    pub revocation_generation: Generation,
}

impl ResolvedBinding {
    /// Validates identity equality, active lifecycle state, and fresh generations.
    ///
    /// # Errors
    ///
    /// Returns a typed mismatch without exposing key material or credentials.
    pub fn validate(&self, expected: BindingExpectation) -> Result<(), BindingFailure> {
        if self.installation_id != expected.installation_id {
            return Err(BindingFailure::WrongInstallation);
        }
        if self.user_id != expected.user_id {
            return Err(BindingFailure::WrongUser);
        }
        if self.external_identity_id != expected.external_identity_id {
            return Err(BindingFailure::WrongExternalIdentity);
        }
        if self.device_id != expected.device_id {
            return Err(BindingFailure::WrongDevice);
        }
        if self.key_id != expected.key_id {
            return Err(BindingFailure::WrongKey);
        }
        if self.binding_id != expected.binding_id {
            return Err(BindingFailure::WrongBinding);
        }
        if self.policy_generation != expected.policy_generation {
            return Err(BindingFailure::StalePolicy);
        }
        if self.revocation_generation != expected.revocation_generation {
            return Err(BindingFailure::StaleRevocation);
        }
        if expected.purpose != CeremonyPurpose::AuthenticateSession {
            return Err(BindingFailure::WrongPurpose);
        }
        if self.installation_state != BindingState::Active {
            return Err(BindingFailure::InactiveInstallation);
        }
        if self.user_state != BindingState::Active {
            return Err(BindingFailure::InactiveUser);
        }
        if self.binding_state != BindingState::Active {
            return Err(BindingFailure::InactiveBinding);
        }
        if self.key_state != BindingState::Active {
            return Err(BindingFailure::InactiveKey);
        }
        if !matches!(self.device_state, DeviceStatus::Active) {
            return Err(BindingFailure::InactiveDevice);
        }
        Ok(())
    }
}

/// Fail-closed authoritative binding lookup implemented by the host.
pub trait BindingResolver {
    /// Resolves the complete current snapshot in the host completion transaction.
    ///
    /// # Errors
    ///
    /// Missing, corrupt, ambiguous, or unavailable state must return a typed
    /// error and must never be interpreted as an active binding.
    fn resolve(&self, expected: BindingExpectation) -> Result<ResolvedBinding, BindingFailure>;
}

/// Typed binding resolution or validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingFailure {
    /// No complete authoritative binding exists.
    NotFound,
    /// Persisted binding state is ambiguous or corrupt.
    Corrupt,
    /// Authoritative storage is unavailable.
    Unavailable,
    /// Installation differs from the challenged installation.
    WrongInstallation,
    /// User differs from the challenged local user.
    WrongUser,
    /// External identity differs from the challenged identity.
    WrongExternalIdentity,
    /// Device differs from the response device.
    WrongDevice,
    /// Key differs from the response key.
    WrongKey,
    /// Binding slot differs from the challenged slot.
    WrongBinding,
    /// Policy changed after challenge persistence.
    StalePolicy,
    /// Effective revocation state changed after challenge persistence.
    StaleRevocation,
    /// The ceremony purpose cannot issue a normal host session.
    WrongPurpose,
    /// Installation cannot authenticate.
    InactiveInstallation,
    /// User cannot authenticate.
    InactiveUser,
    /// External identity binding cannot authenticate.
    InactiveBinding,
    /// Public key cannot authenticate.
    InactiveKey,
    /// Device cannot authenticate.
    InactiveDevice,
}
