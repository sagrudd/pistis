//! `SQLite` implementation of the device-registry persistence boundary.

use crate::{
    ApplicationVersion, AssuranceMetadata, AssuranceState, AttestationState, DevicePlatform,
    DevicePublicKey, DeviceRecord, DeviceRepository, DeviceRepositoryError, DeviceRevision,
    DeviceStatus, DeviceTransition, LifecycleEvent, LifecycleEventKind, LifecycleReason, NewDevice,
    UserVerification,
    migration::{MigrationError, migrate},
};
use pistis_domain::{DeviceId, EvidenceId, ExternalIdentityId, InstallationId, KeyId, UserId};
use pistis_protocol::UnixTimeMillis;
use rusqlite::{Connection, OptionalExtension as _, Row, Transaction, TransactionBehavior, params};
use std::{
    path::Path,
    sync::{Arc, Mutex},
};

const SELECT_RECORD: &str = "
SELECT d.device_id, d.installation_id, d.user_id, d.external_identity_id,
       d.platform, d.app_version, d.status, d.enrolled_at_ms, d.last_used_at_ms,
       d.suspended_at_ms, d.suspension_reason, d.revoked_at_ms,
       d.revocation_reason, d.revision, d.enrolment_evidence_id,
       k.key_id, k.public_key,
       a.app_generated_key, a.hardware_backing, a.user_verification,
       a.attestation, a.integrity, a.evidence_version, a.verifier_version
FROM devices d
JOIN device_keys k ON k.device_id = d.device_id
JOIN device_assurance a ON a.device_id = d.device_id";

/// Durable SQLite-backed device repository.
///
/// Clones share a connection and serialize complete repository transactions.
#[derive(Clone)]
pub struct SqliteDeviceRepository {
    connection: Arc<Mutex<Connection>>,
}

impl std::fmt::Debug for SqliteDeviceRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqliteDeviceRepository")
            .finish_non_exhaustive()
    }
}

impl SqliteDeviceRepository {
    /// Opens, validates, and migrates a registry at `path`.
    ///
    /// # Errors
    ///
    /// Returns a migration error for foreign, corrupt, unavailable, or newer
    /// storage. The parent directory must already exist.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, MigrationError> {
        let mut connection = Connection::open(path)?;
        migrate(&mut connection)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    #[cfg(test)]
    fn in_memory() -> Self {
        let mut connection = Connection::open_in_memory().expect("open SQLite");
        migrate(&mut connection).expect("migrate SQLite");
        Self {
            connection: Arc::new(Mutex::new(connection)),
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>, DeviceRepositoryError> {
        self.connection
            .lock()
            .map_err(|_| DeviceRepositoryError::Unavailable)
    }
}

impl DeviceRepository for SqliteDeviceRepository {
    fn insert(&self, device: NewDevice) -> Result<DeviceRecord, DeviceRepositoryError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(unavailable)?;
        if exists(
            &transaction,
            "SELECT 1 FROM devices WHERE device_id=?1",
            device.id.as_bytes(),
        )? {
            return Err(DeviceRepositoryError::AlreadyExists);
        }
        if transaction
            .query_row(
                "SELECT 1 FROM device_keys WHERE installation_id=?1 AND key_id=?2",
                params![
                    device.installation_id.as_bytes(),
                    device.public_key.key_id().as_bytes()
                ],
                |_| Ok(()),
            )
            .optional()
            .map_err(unavailable)?
            .is_some()
        {
            return Err(DeviceRepositoryError::KeyConflict);
        }
        insert_device(&transaction, &device)?;
        let id = device.id;
        transaction.commit().map_err(unavailable)?;
        drop(connection);
        self.get(id)?.ok_or(DeviceRepositoryError::Corrupt)
    }

    fn get(&self, id: DeviceId) -> Result<Option<DeviceRecord>, DeviceRepositoryError> {
        let connection = self.lock()?;
        query_record(
            &connection,
            &format!("{SELECT_RECORD} WHERE d.device_id=?1"),
            [id.as_bytes().as_slice()],
        )
    }

    fn find_by_key(
        &self,
        installation_id: InstallationId,
        key_id: KeyId,
    ) -> Result<Option<DeviceRecord>, DeviceRepositoryError> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare(&format!(
                "{SELECT_RECORD} WHERE d.installation_id=?1 AND k.key_id=?2"
            ))
            .map_err(unavailable)?;
        statement
            .query_row(
                params![installation_id.as_bytes(), key_id.as_bytes()],
                hydrate,
            )
            .optional()
            .map_err(|error| map_read_error(&error))
    }

    fn transition(
        &self,
        id: DeviceId,
        expected_revision: DeviceRevision,
        transition: DeviceTransition,
    ) -> Result<DeviceRecord, DeviceRepositoryError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(unavailable)?;
        let current = query_record(
            &transaction,
            &format!("{SELECT_RECORD} WHERE d.device_id=?1"),
            [id.as_bytes().as_slice()],
        )?
        .ok_or(DeviceRepositoryError::NotFound)?;
        if current.revision != expected_revision {
            return Err(DeviceRepositoryError::Conflict);
        }
        let latest_at = latest_event_time(&transaction, id)?.unwrap_or(current.enrolled_at);
        if transition.at() < latest_at {
            return Err(DeviceRepositoryError::InvalidTimestamp);
        }
        let next_revision = current
            .revision
            .next()
            .ok_or(DeviceRepositoryError::Corrupt)?;
        apply_transition(&transaction, &current, next_revision, &transition)?;
        transaction.commit().map_err(unavailable)?;
        drop(connection);
        self.get(id)?.ok_or(DeviceRepositoryError::Corrupt)
    }

    fn record_use(
        &self,
        id: DeviceId,
        expected_revision: DeviceRevision,
        at: UnixTimeMillis,
    ) -> Result<DeviceRecord, DeviceRepositoryError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(unavailable)?;
        let current = query_record(
            &transaction,
            &format!("{SELECT_RECORD} WHERE d.device_id=?1"),
            [id.as_bytes().as_slice()],
        )?
        .ok_or(DeviceRepositoryError::NotFound)?;
        if current.revision != expected_revision {
            return Err(DeviceRepositoryError::Conflict);
        }
        if current.status != DeviceStatus::Active {
            return Err(DeviceRepositoryError::InvalidTransition);
        }
        if at < current.enrolled_at || current.last_used_at.is_some_and(|last| at <= last) {
            return Err(DeviceRepositoryError::InvalidTimestamp);
        }
        let revision = current
            .revision
            .next()
            .ok_or(DeviceRepositoryError::Corrupt)?;
        transaction
            .execute(
                "UPDATE devices SET last_used_at_ms=?1, revision=?2
                 WHERE device_id=?3 AND revision=?4",
                params![
                    to_i64(at.get())?,
                    to_i64(revision.get())?,
                    id.as_bytes(),
                    to_i64(expected_revision.get())?
                ],
            )
            .map_err(unavailable)?;
        transaction.commit().map_err(unavailable)?;
        drop(connection);
        self.get(id)?.ok_or(DeviceRepositoryError::Corrupt)
    }

    fn lifecycle(&self, id: DeviceId) -> Result<Vec<LifecycleEvent>, DeviceRepositoryError> {
        let connection = self.lock()?;
        if !exists(
            &connection,
            "SELECT 1 FROM devices WHERE device_id=?1",
            id.as_bytes(),
        )? {
            return Err(DeviceRepositoryError::NotFound);
        }
        let mut statement = connection
            .prepare(
                "SELECT sequence, to_status, effective_at_ms, reason
                 FROM device_lifecycle_events
                 WHERE device_id=?1 ORDER BY sequence",
            )
            .map_err(unavailable)?;
        let rows = statement
            .query_map([id.as_bytes().as_slice()], |row| hydrate_event(row, id))
            .map_err(unavailable)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| map_read_error(&error))
    }
}

fn insert_device(
    transaction: &Transaction<'_>,
    device: &NewDevice,
) -> Result<(), DeviceRepositoryError> {
    transaction
        .execute(
            "INSERT INTO devices (
                device_id, installation_id, user_id, external_identity_id,
                platform, app_version, status, enrolled_at_ms, revision,
                enrolment_evidence_id
             ) VALUES (?1,?2,?3,?4,?5,?6,'active',?7,0,?8)",
            params![
                device.id.as_bytes(),
                device.installation_id.as_bytes(),
                device.user_id.as_bytes(),
                device.external_identity_id.as_bytes(),
                platform_text(device.platform),
                device.application_version.as_str(),
                to_i64(device.enrolled_at.get())?,
                device.enrolment_evidence_id.as_bytes()
            ],
        )
        .map_err(unavailable)?;
    transaction
        .execute(
            "INSERT INTO device_keys (
                device_id, installation_id, key_id, algorithm, public_key, registered_at_ms
             ) VALUES (?1,?2,?3,'ES256',?4,?5)",
            params![
                device.id.as_bytes(),
                device.installation_id.as_bytes(),
                device.public_key.key_id().as_bytes(),
                device.public_key.canonical_sec1(),
                to_i64(device.enrolled_at.get())?
            ],
        )
        .map_err(unavailable)?;
    let assurance = &device.assurance;
    transaction
        .execute(
            "INSERT INTO device_assurance (
                device_id, schema_version, app_generated_key, hardware_backing,
                user_verification, attestation, integrity, evidence_version,
                verifier_version, observed_at_ms
             ) VALUES (?1,1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                device.id.as_bytes(),
                assurance.application_generated_key,
                assurance_text(assurance.hardware_backing),
                verification_text(assurance.user_verification),
                attestation_text(assurance.platform_attestation),
                attestation_text(assurance.device_integrity),
                assurance.evidence_version.as_str(),
                assurance.verifier_version.as_str(),
                to_i64(device.enrolled_at.get())?
            ],
        )
        .map_err(unavailable)?;
    Ok(())
}

fn apply_transition(
    transaction: &Transaction<'_>,
    current: &DeviceRecord,
    revision: DeviceRevision,
    transition: &DeviceTransition,
) -> Result<(), DeviceRepositoryError> {
    let (to_status, reason, suspended_at, revoked_at) = match (&current.status, &transition) {
        (DeviceStatus::Active, DeviceTransition::Suspend { at, reason }) => (
            "suspended",
            Some(reason.as_str()),
            Some(to_i64(at.get())?),
            None,
        ),
        (DeviceStatus::Suspended { .. }, DeviceTransition::Resume { .. }) => {
            ("active", None, None, None)
        }
        (
            DeviceStatus::Active | DeviceStatus::Suspended { .. },
            DeviceTransition::Revoke { at, reason },
        ) => (
            "revoked",
            Some(reason.as_str()),
            status_suspended_at(&current.status)?,
            Some(to_i64(at.get())?),
        ),
        _ => return Err(DeviceRepositoryError::InvalidTransition),
    };
    let from_status = status_text(&current.status);
    transaction
        .execute(
            "UPDATE devices SET status=?1, suspended_at_ms=?2,
             suspension_reason=CASE WHEN ?1='suspended' THEN ?3
                WHEN ?1='revoked' THEN suspension_reason ELSE NULL END,
             revoked_at_ms=?4,
             revocation_reason=CASE WHEN ?1='revoked' THEN ?3 ELSE NULL END,
             revision=?5 WHERE device_id=?6 AND revision=?7",
            params![
                to_status,
                suspended_at,
                reason,
                revoked_at,
                to_i64(revision.get())?,
                current.id.as_bytes(),
                to_i64(current.revision.get())?
            ],
        )
        .map_err(unavailable)?;
    transaction
        .execute(
            "INSERT INTO device_lifecycle_events (
                device_id, sequence, from_status, to_status, effective_at_ms, reason
             ) VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                current.id.as_bytes(),
                to_i64(revision.get())?,
                from_status,
                to_status,
                to_i64(transition.at().get())?,
                reason
            ],
        )
        .map_err(unavailable)?;
    Ok(())
}

fn query_record<P: rusqlite::Params>(
    connection: &Connection,
    sql: &str,
    parameters: P,
) -> Result<Option<DeviceRecord>, DeviceRepositoryError> {
    connection
        .query_row(sql, parameters, hydrate)
        .optional()
        .map_err(|error| map_read_error(&error))
}

fn hydrate(row: &Row<'_>) -> rusqlite::Result<DeviceRecord> {
    let key_id = KeyId::from_bytes(array(row.get_ref(15)?.as_blob()?)?);
    let public_key = DevicePublicKey::from_persisted(key_id, row.get_ref(16)?.as_blob()?)
        .map_err(corrupt_sql)?;
    let enrolled_at = time(row.get(7)?)?;
    let status = status(row)?;
    Ok(DeviceRecord {
        id: DeviceId::from_bytes(array(row.get_ref(0)?.as_blob()?)?),
        installation_id: InstallationId::from_bytes(array(row.get_ref(1)?.as_blob()?)?),
        user_id: UserId::from_bytes(array(row.get_ref(2)?.as_blob()?)?),
        external_identity_id: ExternalIdentityId::from_bytes(array(row.get_ref(3)?.as_blob()?)?),
        public_key,
        platform: parse_platform(row.get_ref(4)?.as_str()?)?,
        application_version: ApplicationVersion::new(row.get::<_, String>(5)?)
            .map_err(corrupt_sql)?,
        assurance: AssuranceMetadata {
            application_generated_key: row.get(17)?,
            hardware_backing: parse_assurance(row.get_ref(18)?.as_str()?)?,
            user_verification: parse_verification(row.get_ref(19)?.as_str()?)?,
            platform_attestation: parse_attestation(row.get_ref(20)?.as_str()?)?,
            device_integrity: parse_attestation(row.get_ref(21)?.as_str()?)?,
            evidence_version: ApplicationVersion::new(row.get::<_, String>(22)?)
                .map_err(corrupt_sql)?,
            verifier_version: ApplicationVersion::new(row.get::<_, String>(23)?)
                .map_err(corrupt_sql)?,
        },
        enrolment_evidence_id: EvidenceId::from_bytes(array(row.get_ref(14)?.as_blob()?)?),
        status,
        enrolled_at,
        last_used_at: row.get::<_, Option<i64>>(8)?.map(time).transpose()?,
        revision: DeviceRevision::new(from_i64(row.get(13)?)?),
    })
}

fn status(row: &Row<'_>) -> rusqlite::Result<DeviceStatus> {
    match row.get_ref(6)?.as_str()? {
        "active" => Ok(DeviceStatus::Active),
        "suspended" => Ok(DeviceStatus::Suspended {
            at: time(row.get::<_, Option<i64>>(9)?.ok_or_else(corrupt_value)?)?,
            reason: LifecycleReason::new(
                row.get::<_, Option<String>>(10)?
                    .ok_or_else(corrupt_value)?,
            )
            .map_err(corrupt_sql)?,
        }),
        "revoked" => Ok(DeviceStatus::Revoked {
            at: time(row.get::<_, Option<i64>>(11)?.ok_or_else(corrupt_value)?)?,
            reason: LifecycleReason::new(
                row.get::<_, Option<String>>(12)?
                    .ok_or_else(corrupt_value)?,
            )
            .map_err(corrupt_sql)?,
        }),
        _ => Err(corrupt_value()),
    }
}

fn hydrate_event(row: &Row<'_>, device_id: DeviceId) -> rusqlite::Result<LifecycleEvent> {
    let reason = row.get::<_, Option<String>>(3)?;
    let kind = match row.get_ref(1)?.as_str()? {
        "suspended" => LifecycleEventKind::Suspended(
            LifecycleReason::new(reason.ok_or_else(corrupt_value)?).map_err(corrupt_sql)?,
        ),
        "active" => LifecycleEventKind::Resumed,
        "revoked" => LifecycleEventKind::Revoked(
            LifecycleReason::new(reason.ok_or_else(corrupt_value)?).map_err(corrupt_sql)?,
        ),
        _ => return Err(corrupt_value()),
    };
    Ok(LifecycleEvent {
        device_id,
        revision: DeviceRevision::new(from_i64(row.get(0)?)?),
        at: time(row.get(2)?)?,
        kind,
    })
}

fn latest_event_time(
    connection: &Connection,
    id: DeviceId,
) -> Result<Option<UnixTimeMillis>, DeviceRepositoryError> {
    connection
        .query_row(
            "SELECT effective_at_ms FROM device_lifecycle_events
             WHERE device_id=?1 ORDER BY sequence DESC LIMIT 1",
            [id.as_bytes().as_slice()],
            |row| time(row.get(0)?),
        )
        .optional()
        .map_err(|error| map_read_error(&error))
}

fn exists(connection: &Connection, sql: &str, id: &[u8]) -> Result<bool, DeviceRepositoryError> {
    connection
        .query_row(sql, [id], |_| Ok(()))
        .optional()
        .map(|value| value.is_some())
        .map_err(unavailable)
}

const fn platform_text(value: DevicePlatform) -> &'static str {
    match value {
        DevicePlatform::Ios => "ios",
        DevicePlatform::Android => "android",
    }
}

const fn assurance_text(value: AssuranceState) -> &'static str {
    match value {
        AssuranceState::Verified => "verified",
        AssuranceState::Reported => "reported",
        AssuranceState::Unavailable => "unavailable",
        AssuranceState::Unknown => "unknown",
    }
}

const fn verification_text(value: UserVerification) -> &'static str {
    match value {
        UserVerification::Required => "required",
        UserVerification::NotRequired => "not_required",
        UserVerification::Unknown => "unknown",
    }
}

const fn attestation_text(value: AttestationState) -> &'static str {
    match value {
        AttestationState::Verified => "verified",
        AttestationState::Unavailable => "unavailable",
        AttestationState::NotRequested => "not_requested",
    }
}

fn parse_platform(value: &str) -> rusqlite::Result<DevicePlatform> {
    match value {
        "ios" => Ok(DevicePlatform::Ios),
        "android" => Ok(DevicePlatform::Android),
        _ => Err(corrupt_value()),
    }
}

fn parse_assurance(value: &str) -> rusqlite::Result<AssuranceState> {
    match value {
        "verified" => Ok(AssuranceState::Verified),
        "reported" => Ok(AssuranceState::Reported),
        "unavailable" => Ok(AssuranceState::Unavailable),
        "unknown" => Ok(AssuranceState::Unknown),
        _ => Err(corrupt_value()),
    }
}

fn parse_verification(value: &str) -> rusqlite::Result<UserVerification> {
    match value {
        "required" => Ok(UserVerification::Required),
        "not_required" => Ok(UserVerification::NotRequired),
        "unknown" => Ok(UserVerification::Unknown),
        _ => Err(corrupt_value()),
    }
}

fn parse_attestation(value: &str) -> rusqlite::Result<AttestationState> {
    match value {
        "verified" => Ok(AttestationState::Verified),
        "unavailable" => Ok(AttestationState::Unavailable),
        "not_requested" => Ok(AttestationState::NotRequested),
        _ => Err(corrupt_value()),
    }
}

fn status_text(status: &DeviceStatus) -> &'static str {
    match status {
        DeviceStatus::Active => "active",
        DeviceStatus::Suspended { .. } => "suspended",
        DeviceStatus::Revoked { .. } => "revoked",
    }
}

fn status_suspended_at(status: &DeviceStatus) -> Result<Option<i64>, DeviceRepositoryError> {
    match status {
        DeviceStatus::Suspended { at, .. } => Ok(Some(to_i64(at.get())?)),
        _ => Ok(None),
    }
}

fn to_i64(value: u64) -> Result<i64, DeviceRepositoryError> {
    i64::try_from(value).map_err(|_| DeviceRepositoryError::InvalidTimestamp)
}

fn from_i64(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(corrupt_sql)
}

fn time(value: i64) -> rusqlite::Result<UnixTimeMillis> {
    from_i64(value).map(UnixTimeMillis::new)
}

fn array<const N: usize>(bytes: &[u8]) -> rusqlite::Result<[u8; N]> {
    bytes.try_into().map_err(corrupt_sql)
}

fn unavailable(_error: rusqlite::Error) -> DeviceRepositoryError {
    DeviceRepositoryError::Unavailable
}

fn map_read_error(error: &rusqlite::Error) -> DeviceRepositoryError {
    match error {
        rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::InvalidColumnType(..)
        | rusqlite::Error::IntegralValueOutOfRange(..) => DeviceRepositoryError::Corrupt,
        _ => DeviceRepositoryError::Unavailable,
    }
}

fn corrupt_sql(error: impl std::error::Error + Send + Sync + 'static) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(error))
}

fn corrupt_value() -> rusqlite::Error {
    corrupt_sql(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "invalid persisted device registry value",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBLIC_KEY: [u8; 33] = [
        0x03, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
        0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8,
        0x98, 0xc2, 0x96,
    ];

    fn device() -> NewDevice {
        let version = ApplicationVersion::new("1.2.3").expect("version");
        NewDevice {
            id: DeviceId::from_bytes([1; 16]),
            installation_id: InstallationId::from_bytes([2; 16]),
            user_id: UserId::from_bytes([3; 16]),
            external_identity_id: ExternalIdentityId::from_bytes([4; 16]),
            public_key: DevicePublicKey::from_sec1_bytes(&PUBLIC_KEY).expect("key"),
            platform: DevicePlatform::Ios,
            application_version: version.clone(),
            assurance: AssuranceMetadata {
                application_generated_key: true,
                hardware_backing: AssuranceState::Verified,
                user_verification: UserVerification::Required,
                platform_attestation: AttestationState::Verified,
                device_integrity: AttestationState::Unavailable,
                evidence_version: version.clone(),
                verifier_version: version,
            },
            enrolment_evidence_id: EvidenceId::from_bytes([5; 16]),
            enrolled_at: UnixTimeMillis::new(1_000),
        }
    }

    #[test]
    fn complete_record_round_trips_and_key_lookup_is_scoped() {
        let repository = SqliteDeviceRepository::in_memory();
        let expected = DeviceRecord::from(device());
        assert_eq!(repository.insert(device()), Ok(expected.clone()));
        assert_eq!(repository.get(expected.id), Ok(Some(expected.clone())));
        assert_eq!(
            repository.find_by_key(expected.installation_id, expected.public_key.key_id()),
            Ok(Some(expected))
        );
    }

    #[test]
    fn lifecycle_and_use_updates_are_atomic_and_fail_closed() {
        let repository = SqliteDeviceRepository::in_memory();
        let active = repository.insert(device()).expect("insert");
        let suspended = repository
            .transition(
                active.id,
                active.revision,
                DeviceTransition::Suspend {
                    at: UnixTimeMillis::new(2_000),
                    reason: LifecycleReason::new("lost temporarily").expect("reason"),
                },
            )
            .expect("suspend");
        assert_eq!(
            repository.record_use(suspended.id, suspended.revision, UnixTimeMillis::new(3_000)),
            Err(DeviceRepositoryError::InvalidTransition)
        );
        assert_eq!(repository.lifecycle(active.id).expect("events").len(), 1);
    }

    #[test]
    fn same_key_is_allowed_only_across_installations() {
        let repository = SqliteDeviceRepository::in_memory();
        repository.insert(device()).expect("first");
        let mut duplicate = device();
        duplicate.id = DeviceId::from_bytes([9; 16]);
        assert_eq!(
            repository.insert(duplicate.clone()),
            Err(DeviceRepositoryError::KeyConflict)
        );
        duplicate.installation_id = InstallationId::from_bytes([8; 16]);
        assert!(repository.insert(duplicate).is_ok());
    }
}
