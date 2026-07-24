use pistis_device_registry::DeviceStatus;
use pistis_domain::{DeviceId, ExternalIdentityId, InstallationId, KeyId, UserId};
use pistis_identity::BindingId;

/// Monotonic generation used to reject stale policy or revocation views.
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

/// Effective authoritative lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingState {
    /// The entity may participate in authentication.
    Active,
    /// The entity is temporarily ineligible.
    Suspended,
    /// The entity is terminally revoked.
    Revoked,
}

/// Closed domain-separation purpose for Monas ceremonies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationPurpose {
    /// Authenticate an existing Prosopikon principal.
    AuthenticateSession,
    /// Approve a consequential action without issuing a session.
    ConsequentialApproval,
    /// Sign an artefact without issuing a session.
    ArtefactSigning,
}

/// Exact bindings covered by the challenged authentication operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BindingExpectation {
    /// Installation accepting authentication.
    pub installation_id: InstallationId,
    /// Immutable Prosopikon principal represented by its Pistis user ID.
    pub principal_id: UserId,
    /// Stable provider-backed identity.
    pub external_identity_id: ExternalIdentityId,
    /// Device presenting the response.
    pub device_id: DeviceId,
    /// Exact verification key carried by the response.
    pub key_id: KeyId,
    /// Durable external-identity binding slot.
    pub binding_id: BindingId,
    /// Policy generation persisted with the challenge.
    pub policy_generation: Generation,
    /// Revocation generation persisted with the challenge.
    pub revocation_generation: Generation,
    /// Domain-separated operation.
    pub purpose: OperationPurpose,
}

/// Complete authoritative binding snapshot loaded during completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedBinding {
    /// Installation owning the resolved entities.
    pub installation_id: InstallationId,
    /// Existing immutable local principal.
    pub principal_id: UserId,
    /// Stable external identity bound to the principal.
    pub external_identity_id: ExternalIdentityId,
    /// Enrolled device.
    pub device_id: DeviceId,
    /// Exact active verification key.
    pub key_id: KeyId,
    /// Durable binding slot.
    pub binding_id: BindingId,
    /// Effective installation state.
    pub installation_state: BindingState,
    /// Effective principal state.
    pub principal_state: BindingState,
    /// Effective external binding state.
    pub binding_state: BindingState,
    /// Effective key state.
    pub key_state: BindingState,
    /// Effective device lifecycle state.
    pub device_state: DeviceStatus,
    /// Current verification policy generation.
    pub policy_generation: Generation,
    /// Current effective revocation generation.
    pub revocation_generation: Generation,
}

impl ResolvedBinding {
    /// Validates exact identities, active states, fresh generations, and purpose.
    ///
    /// # Errors
    ///
    /// Returns a typed mismatch without exposing credentials or key material.
    pub fn validate(&self, expected: BindingExpectation) -> Result<(), BindingFailure> {
        if self.installation_id != expected.installation_id {
            return Err(BindingFailure::WrongInstallation);
        }
        if self.principal_id != expected.principal_id {
            return Err(BindingFailure::WrongPrincipal);
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
        if expected.purpose != OperationPurpose::AuthenticateSession {
            return Err(BindingFailure::WrongPurpose);
        }
        if self.installation_state != BindingState::Active {
            return Err(BindingFailure::InactiveInstallation);
        }
        if self.principal_state != BindingState::Active {
            return Err(BindingFailure::InactivePrincipal);
        }
        if self.binding_state != BindingState::Active {
            return Err(BindingFailure::InactiveBinding);
        }
        if self.key_state != BindingState::Active {
            return Err(BindingFailure::InactiveKey);
        }
        if self.device_state != DeviceStatus::Active {
            return Err(BindingFailure::InactiveDevice);
        }
        Ok(())
    }
}

/// Fail-closed authoritative binding lookup implemented by Monas.
pub trait BindingResolver {
    /// Resolves current state inside the host completion transaction.
    ///
    /// # Errors
    ///
    /// Missing, corrupt, ambiguous, or unavailable state returns a typed error.
    fn resolve(&self, expected: BindingExpectation) -> Result<ResolvedBinding, BindingFailure>;
}

/// Typed authoritative resolution or validation failure.
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
    /// Principal differs from the challenged principal.
    WrongPrincipal,
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
    /// Revocation state changed after challenge persistence.
    StaleRevocation,
    /// The purpose cannot issue a browser session.
    WrongPurpose,
    /// Installation cannot authenticate.
    InactiveInstallation,
    /// Principal cannot authenticate.
    InactivePrincipal,
    /// External identity binding cannot authenticate.
    InactiveBinding,
    /// Public key cannot authenticate.
    InactiveKey,
    /// Device cannot authenticate.
    InactiveDevice,
}
