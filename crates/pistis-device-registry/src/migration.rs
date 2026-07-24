//! Embedded, forward-only `SQLite` schema migrations.

use rusqlite::{Connection, TransactionBehavior, params};
use sha2::{Digest as _, Sha256};
use std::{error::Error, fmt, time::SystemTime};

const APPLICATION_ID: i64 = 0x5053_5453;
const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "device_registry",
    sql: include_str!("../migrations/0001_device_registry.sql"),
}];

struct Migration {
    version: i64,
    name: &'static str,
    sql: &'static str,
}

/// The embedded schema version understood by this binary.
pub const CURRENT_SCHEMA_VERSION: i64 = 1;

/// Failure to establish or validate the device-registry schema.
#[derive(Debug)]
pub enum MigrationError {
    /// `SQLite` rejected an operation or reported corrupt storage.
    Database(rusqlite::Error),
    /// The database belongs to a different application.
    ForeignApplication {
        /// Application identifier found in the database.
        observed: i64,
    },
    /// An unmarked database already contains user tables.
    UnclaimedDatabase,
    /// The database was migrated by a newer binary.
    NewerSchema {
        /// Highest migration version found in the database.
        observed: i64,
        /// Highest migration version supported by this binary.
        supported: i64,
    },
    /// Applied migration versions are not a contiguous prefix.
    VersionGap {
        /// Contiguous migration version required at this position.
        expected: i64,
        /// Migration version actually present.
        observed: i64,
    },
    /// An applied migration no longer matches the embedded migration.
    ChecksumMismatch {
        /// Applied migration whose name or checksum differs.
        version: i64,
    },
    /// The system clock could not produce a migration timestamp.
    Clock,
    /// `SQLite`'s post-migration integrity validation failed.
    Integrity,
}

impl fmt::Display for MigrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(_) => formatter.write_str("device registry database is unavailable"),
            Self::ForeignApplication { observed } => {
                write!(formatter, "database has foreign application id {observed}")
            }
            Self::UnclaimedDatabase => {
                formatter.write_str("unclaimed database already contains tables")
            }
            Self::NewerSchema {
                observed,
                supported,
            } => write!(
                formatter,
                "database schema version {observed} is newer than supported version {supported}"
            ),
            Self::VersionGap { expected, observed } => write!(
                formatter,
                "database migration history expected version {expected}, found {observed}"
            ),
            Self::ChecksumMismatch { version } => {
                write!(formatter, "database migration {version} checksum differs")
            }
            Self::Clock => formatter.write_str("system clock is unavailable"),
            Self::Integrity => formatter.write_str("database integrity validation failed"),
        }
    }
}

impl Error for MigrationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for MigrationError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

/// Applies every pending embedded migration in one immediate transaction.
///
/// Existing history is accepted only when it is an exact, contiguous prefix
/// of the migrations embedded in this binary.
pub fn migrate(connection: &mut Connection) -> Result<(), MigrationError> {
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;

    let application_id: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let user_tables: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema \
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    match (application_id, user_tables) {
        (0, 0) | (APPLICATION_ID, _) => {}
        (0, _) => return Err(MigrationError::UnclaimedDatabase),
        (observed, _) => return Err(MigrationError::ForeignApplication { observed }),
    }

    let applied_at_ms = unix_time_millis()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if application_id == 0 {
        transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
    }

    let has_history: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema \
         WHERE type = 'table' AND name = 'schema_migrations')",
        [],
        |row| row.get(0),
    )?;
    let applied = if has_history {
        read_history(&transaction)?
    } else {
        Vec::new()
    };
    validate_history(&applied)?;

    for migration in MIGRATIONS.iter().skip(applied.len()) {
        transaction.execute_batch(migration.sql)?;
        transaction.execute(
            "INSERT INTO schema_migrations \
             (version, name, checksum, applied_at_ms) VALUES (?1, ?2, ?3, ?4)",
            params![
                migration.version,
                migration.name,
                checksum(migration.sql),
                applied_at_ms
            ],
        )?;
    }

    let foreign_key_failures: i64 =
        transaction.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })?;
    let integrity: String =
        transaction.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if foreign_key_failures != 0 || integrity != "ok" {
        return Err(MigrationError::Integrity);
    }
    transaction.commit()?;
    Ok(())
}

fn read_history(connection: &Connection) -> Result<Vec<(i64, String, Vec<u8>)>, MigrationError> {
    let mut statement = connection
        .prepare("SELECT version, name, checksum FROM schema_migrations ORDER BY version")?;
    let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(MigrationError::Database)
}

fn validate_history(applied: &[(i64, String, Vec<u8>)]) -> Result<(), MigrationError> {
    if applied.len() > MIGRATIONS.len() {
        return Err(MigrationError::NewerSchema {
            observed: applied.last().map_or(0, |entry| entry.0),
            supported: CURRENT_SCHEMA_VERSION,
        });
    }
    for (index, (version, name, observed_checksum)) in applied.iter().enumerate() {
        let expected_version = i64::try_from(index).expect("migration count fits i64") + 1;
        if *version != expected_version {
            return Err(MigrationError::VersionGap {
                expected: expected_version,
                observed: *version,
            });
        }
        let migration = &MIGRATIONS[index];
        if migration.version != *version
            || migration.name != name
            || checksum(migration.sql).as_slice() != observed_checksum
        {
            return Err(MigrationError::ChecksumMismatch { version: *version });
        }
    }
    Ok(())
}

fn checksum(sql: &str) -> [u8; 32] {
    Sha256::digest(sql.as_bytes()).into()
}

fn unix_time_millis() -> Result<i64, MigrationError> {
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| MigrationError::Clock)?;
    i64::try_from(duration.as_millis()).map_err(|_| MigrationError::Clock)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_database_migrates_and_reopen_is_a_no_op() {
        let mut connection = Connection::open_in_memory().expect("open");
        migrate(&mut connection).expect("first migration");
        migrate(&mut connection).expect("second migration");

        let count: i64 = connection
            .query_row("SELECT count(*) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .expect("history");
        assert_eq!(count, 1);
    }

    #[test]
    fn refuses_an_unclaimed_database_with_tables() {
        let mut connection = Connection::open_in_memory().expect("open");
        connection
            .execute("CREATE TABLE unrelated(value TEXT)", [])
            .expect("table");
        assert!(matches!(
            migrate(&mut connection),
            Err(MigrationError::UnclaimedDatabase)
        ));
    }

    #[test]
    fn refuses_checksum_drift() {
        let mut connection = Connection::open_in_memory().expect("open");
        migrate(&mut connection).expect("migration");
        connection
            .execute("UPDATE schema_migrations SET checksum = zeroblob(32)", [])
            .expect("tamper");
        assert!(matches!(
            migrate(&mut connection),
            Err(MigrationError::ChecksumMismatch { version: 1 })
        ));
    }

    #[test]
    fn schema_constraints_reject_private_or_malformed_key_material() {
        let mut connection = Connection::open_in_memory().expect("open");
        migrate(&mut connection).expect("migration");
        connection
            .execute(
                "INSERT INTO devices (
                    device_id, installation_id, user_id, external_identity_id,
                    platform, app_version, status, enrolled_at_ms,
                    enrolment_evidence_id
                 ) VALUES (
                    zeroblob(16), randomblob(16), randomblob(16), randomblob(16),
                    'ios', '1.0', 'active', 1, randomblob(16)
                 )",
                [],
            )
            .expect("device");
        let result = connection.execute(
            "INSERT INTO device_keys (
                key_id, device_id, installation_id, algorithm, public_key,
                registered_at_ms
             ) VALUES (
                zeroblob(32), zeroblob(16),
                (SELECT installation_id FROM devices WHERE device_id=zeroblob(16)),
                'ES256', zeroblob(65), 1
             )",
            [],
        );
        assert!(result.is_err());
    }

    #[test]
    fn lifecycle_constraint_rejects_revoked_without_reason() {
        let mut connection = Connection::open_in_memory().expect("open");
        migrate(&mut connection).expect("migration");
        let result = connection.execute(
            "INSERT INTO devices (
                device_id, installation_id, user_id, external_identity_id,
                platform, app_version, status, enrolled_at_ms, revoked_at_ms
             ) VALUES (
                zeroblob(16), randomblob(16), randomblob(16), randomblob(16),
                'android', '1.0', 'revoked', 1, 2
             )",
            [],
        );
        assert!(result.is_err());
    }
}
