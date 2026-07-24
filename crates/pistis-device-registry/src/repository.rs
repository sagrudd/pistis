use crate::{DeviceRecord, DeviceRevision, DeviceTransition, LifecycleEvent, NewDevice};
use pistis_domain::{DeviceId, InstallationId, KeyId};
use pistis_protocol::UnixTimeMillis;
use std::{error::Error, fmt};

/// Fail-closed device repository failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceRepositoryError {
    /// A device with the same identifier already exists.
    AlreadyExists,
    /// The installation already associates the key with another device.
    KeyConflict,
    /// The requested device does not exist.
    NotFound,
    /// The expected revision is stale.
    Conflict,
    /// The requested lifecycle transition is forbidden.
    InvalidTransition,
    /// A supplied effective or last-used time violates monotonic ordering.
    InvalidTimestamp,
    /// Persisted state violates the domain model or schema.
    Corrupt,
    /// Storage could not be read or committed safely.
    Unavailable,
}

impl fmt::Display for DeviceRepositoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::AlreadyExists => "device already exists",
            Self::KeyConflict => "public key is already enrolled",
            Self::NotFound => "device was not found",
            Self::Conflict => "device revision conflict",
            Self::InvalidTransition => "invalid device lifecycle transition",
            Self::InvalidTimestamp => "invalid device lifecycle timestamp",
            Self::Corrupt => "device repository contains invalid state",
            Self::Unavailable => "device repository is unavailable",
        };
        formatter.write_str(message)
    }
}

impl Error for DeviceRepositoryError {}

/// Atomic persistence boundary for the local device registry.
///
/// Implementations must never interpret corrupt or unavailable storage as an
/// empty registry. Immutable enrolment fields cannot be replaced through this
/// interface, and revocation is terminal.
pub trait DeviceRepository {
    /// Inserts a new active device.
    ///
    /// # Errors
    ///
    /// Returns a conflict when either the device ID or installation-scoped key
    /// is already present. Storage failures fail closed.
    fn insert(&self, device: NewDevice) -> Result<DeviceRecord, DeviceRepositoryError>;

    /// Loads a device by identifier.
    ///
    /// # Errors
    ///
    /// Returns an explicit error for corrupt or unavailable storage.
    fn get(&self, id: DeviceId) -> Result<Option<DeviceRecord>, DeviceRepositoryError>;

    /// Finds the device owning a key within an installation.
    ///
    /// # Errors
    ///
    /// Returns an explicit error for corrupt or unavailable storage.
    fn find_by_key(
        &self,
        installation_id: InstallationId,
        key_id: KeyId,
    ) -> Result<Option<DeviceRecord>, DeviceRepositoryError>;

    /// Applies one lifecycle transition with optimistic concurrency.
    ///
    /// The new state, event, and revision must be committed atomically.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceRepositoryError::Conflict`] for a stale revision and
    /// [`DeviceRepositoryError::InvalidTransition`] for a forbidden state
    /// change.
    fn transition(
        &self,
        id: DeviceId,
        expected_revision: DeviceRevision,
        transition: DeviceTransition,
    ) -> Result<DeviceRecord, DeviceRepositoryError>;

    /// Records successful use of an active device with optimistic concurrency.
    ///
    /// # Errors
    ///
    /// Suspended and revoked devices fail closed. Times must be monotonic.
    fn record_use(
        &self,
        id: DeviceId,
        expected_revision: DeviceRevision,
        at: UnixTimeMillis,
    ) -> Result<DeviceRecord, DeviceRepositoryError>;

    /// Returns retained lifecycle events in revision order.
    ///
    /// # Errors
    ///
    /// Returns an explicit error for corrupt or unavailable storage.
    fn lifecycle(&self, id: DeviceId) -> Result<Vec<LifecycleEvent>, DeviceRepositoryError>;
}
