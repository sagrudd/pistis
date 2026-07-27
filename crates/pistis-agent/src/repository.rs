use pistis_domain::ChallengeId;
use rusqlite::{Connection, OptionalExtension as _, TransactionBehavior, params};
use std::{
    error::Error,
    fmt, fs, io,
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::Path,
};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS agent_schema (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    version INTEGER NOT NULL CHECK (version = 1)
) STRICT;
INSERT OR IGNORE INTO agent_schema(singleton, version) VALUES (1, 1);
CREATE TABLE IF NOT EXISTS ceremonies (
    challenge_id BLOB PRIMARY KEY CHECK (length(challenge_id) = 16),
    kind INTEGER NOT NULL CHECK (kind IN (1, 2)),
    canonical_challenge BLOB NOT NULL CHECK (
        length(canonical_challenge) BETWEEN 1 AND 65536
    ),
    installation_signature BLOB NOT NULL CHECK (
        length(installation_signature) BETWEEN 1 AND 512
    ),
    expires_at INTEGER NOT NULL CHECK (expires_at >= 0),
    state TEXT NOT NULL CHECK (
        state IN (
            'pending', 'response_available', 'consumed', 'denied',
            'cancelled', 'expired', 'failed'
        )
    ),
    response BLOB CHECK (response IS NULL OR length(response) BETWEEN 1 AND 65536),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    CHECK (
        (state = 'response_available' AND response IS NOT NULL)
        OR (state != 'response_available')
    )
) STRICT;
";

const MIGRATE_V2: &str = "
CREATE TABLE sessions (
    session_id BLOB PRIMARY KEY CHECK (length(session_id) = 32),
    challenge_id BLOB NOT NULL UNIQUE
        REFERENCES ceremonies(challenge_id),
    user_id BLOB NOT NULL CHECK (length(user_id) = 16),
    device_id BLOB NOT NULL CHECK (length(device_id) = 16),
    created_at INTEGER NOT NULL CHECK (created_at >= 0)
) STRICT;
CREATE TABLE audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge_id BLOB NOT NULL UNIQUE
        REFERENCES ceremonies(challenge_id),
    user_id BLOB NOT NULL CHECK (length(user_id) = 16),
    device_id BLOB NOT NULL CHECK (length(device_id) = 16),
    ceremony_kind INTEGER NOT NULL CHECK (ceremony_kind IN (1, 2)),
    transfer INTEGER NOT NULL CHECK (transfer IN (1, 2)),
    completed_at INTEGER NOT NULL CHECK (completed_at >= 0)
) STRICT;
CREATE TABLE agent_schema_v2 (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    version INTEGER NOT NULL CHECK (version = 2)
) STRICT;
INSERT INTO agent_schema_v2(singleton, version) VALUES (1, 2);
DROP TABLE agent_schema;
ALTER TABLE agent_schema_v2 RENAME TO agent_schema;
";

/// Ceremony protocol stored by the local agent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CeremonyKind {
    /// Version 1 session authentication.
    Login,
    /// Version 2 exact-action approval.
    Action,
}

/// Durable ceremony lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CeremonyState {
    /// Awaiting a mobile response.
    Pending,
    /// One response has been durably staged.
    ResponseAvailable,
    /// Verified authority was atomically consumed.
    Consumed,
    /// Mobile user denied the request.
    Denied,
    /// Local requester cancelled the ceremony.
    Cancelled,
    /// Authoritative expiry was reached.
    Expired,
    /// Verification or durable completion failed terminally.
    Failed,
}

/// Complete public and encrypted-at-rest-agent ceremony record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CeremonyRecord {
    /// Single-use challenge identifier.
    pub challenge_id: ChallengeId,
    /// Login or action protocol.
    pub kind: CeremonyKind,
    /// Exact canonical signed challenge bytes.
    pub canonical_challenge: Vec<u8>,
    /// Installation signature over the challenge.
    pub installation_signature: Vec<u8>,
    /// Exclusive issuer-controlled expiry in Unix milliseconds.
    pub expires_at: u64,
    /// Durable lifecycle.
    pub state: CeremonyState,
    /// Staged signed mobile response, never returned over a presentation API.
    pub response: Option<Vec<u8>>,
    /// Monotonic optimistic-concurrency revision.
    pub revision: u64,
}

/// Owner-only durable ceremony repository.
pub struct CeremonyRepository {
    pub(crate) connection: Connection,
}

impl CeremonyRepository {
    /// Opens or creates an owner-only `SQLite` repository.
    ///
    /// The parent directory must already exist, be owned by the process user,
    /// and grant no group or world permission. The database is created mode
    /// `0600`; symlink paths and permissive existing files are rejected.
    ///
    /// # Errors
    ///
    /// Returns a coarse permission, corruption, conflict, or availability
    /// failure without treating an unreadable database as empty.
    pub fn open(path: &Path) -> Result<Self, RepositoryError> {
        validate_parent(path)?;
        if let Ok(metadata) = fs::symlink_metadata(path)
            && (metadata.file_type().is_symlink() || metadata.permissions().mode() & 0o077 != 0)
        {
            return Err(RepositoryError::Permissions);
        }
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)
            .map_err(map_io)?;
        let mut connection = Connection::open(path).map_err(map_sql)?;
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .and_then(|()| connection.pragma_update(None, "journal_mode", "WAL"))
            .and_then(|()| connection.pragma_update(None, "synchronous", "FULL"))
            .map_err(map_sql)?;
        connection.execute_batch(SCHEMA).map_err(map_sql)?;
        let mut version: i64 = connection
            .query_row(
                "SELECT version FROM agent_schema WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(map_sql)?;
        if version == 1 {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(map_sql)?;
            transaction.execute_batch(MIGRATE_V2).map_err(map_sql)?;
            transaction.commit().map_err(map_sql)?;
            version = 2;
        }
        if version != 2 {
            return Err(RepositoryError::Corrupt);
        }
        Ok(Self { connection })
    }

    /// Inserts one independently signed pending challenge.
    ///
    /// # Errors
    ///
    /// Rejects invalid bounds, unrepresentable expiry, and duplicate challenge
    /// identifiers without replacing existing state.
    pub fn insert(&mut self, record: &CeremonyRecord) -> Result<(), RepositoryError> {
        if record.canonical_challenge.is_empty()
            || record.canonical_challenge.len() > 64 * 1024
            || record.installation_signature.is_empty()
            || record.installation_signature.len() > 512
            || record.state != CeremonyState::Pending
            || record.response.is_some()
            || record.revision != 0
        {
            return Err(RepositoryError::Invalid);
        }
        let expires_at = i64::try_from(record.expires_at).map_err(|_| RepositoryError::Invalid)?;
        self.connection
            .execute(
                "INSERT INTO ceremonies(
                    challenge_id, kind, canonical_challenge, installation_signature,
                    expires_at, state, response, revision
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 'pending', NULL, 0)",
                params![
                    record.challenge_id.as_bytes().as_slice(),
                    kind_number(record.kind),
                    record.canonical_challenge,
                    record.installation_signature,
                    expires_at
                ],
            )
            .map_err(|error| {
                if is_constraint(&error) {
                    RepositoryError::Conflict
                } else {
                    map_sql(error)
                }
            })?;
        Ok(())
    }

    /// Loads one record without mutating it.
    ///
    /// # Errors
    ///
    /// Returns `NotFound`, `Corrupt`, or `Unavailable` distinctly.
    pub fn get(&self, challenge_id: ChallengeId) -> Result<CeremonyRecord, RepositoryError> {
        self.connection
            .query_row(
                "SELECT kind, canonical_challenge, installation_signature,
                        expires_at, state, response, revision
                 FROM ceremonies WHERE challenge_id = ?1",
                params![challenge_id.as_bytes().as_slice()],
                |row| hydrate(row, challenge_id),
            )
            .optional()
            .map_err(map_sql)?
            .ok_or(RepositoryError::NotFound)
    }

    /// Stages exactly one bounded signed mobile response.
    ///
    /// # Errors
    ///
    /// Fails on empty or oversized response, replay, stale state, missing
    /// challenge, corruption, or storage unavailability.
    pub fn stage_response(
        &mut self,
        challenge_id: ChallengeId,
        response: &[u8],
    ) -> Result<(), RepositoryError> {
        if response.is_empty() || response.len() > 64 * 1024 {
            return Err(RepositoryError::Invalid);
        }
        transition(
            &mut self.connection,
            challenge_id,
            "pending",
            "response_available",
            Some(response),
        )
    }

    /// Atomically consumes and returns a staged response before `now`.
    ///
    /// # Errors
    ///
    /// Expiry is terminal. Replay, missing response, wrong state, corruption,
    /// and unavailable storage fail closed.
    pub fn consume_response(
        &mut self,
        challenge_id: ChallengeId,
        now: u64,
    ) -> Result<Vec<u8>, RepositoryError> {
        let now = i64::try_from(now).map_err(|_| RepositoryError::Invalid)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql)?;
        let row: Option<(i64, String, Option<Vec<u8>>)> = transaction
            .query_row(
                "SELECT expires_at, state, response FROM ceremonies
                 WHERE challenge_id = ?1",
                params![challenge_id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(map_sql)?;
        let Some((expires_at, state, response)) = row else {
            return Err(RepositoryError::NotFound);
        };
        if expires_at <= now {
            transaction
                .execute(
                    "UPDATE ceremonies SET state = 'expired', response = NULL,
                            revision = revision + 1
                     WHERE challenge_id = ?1 AND state IN ('pending', 'response_available')",
                    params![challenge_id.as_bytes().as_slice()],
                )
                .map_err(map_sql)?;
            transaction.commit().map_err(map_sql)?;
            return Err(RepositoryError::Expired);
        }
        if state != "response_available" {
            return Err(RepositoryError::Conflict);
        }
        let response = response.ok_or(RepositoryError::Corrupt)?;
        let changed = transaction
            .execute(
                "UPDATE ceremonies SET state = 'consumed', response = NULL,
                        revision = revision + 1
                 WHERE challenge_id = ?1 AND state = 'response_available'",
                params![challenge_id.as_bytes().as_slice()],
            )
            .map_err(map_sql)?;
        if changed != 1 {
            return Err(RepositoryError::Conflict);
        }
        transaction.commit().map_err(map_sql)?;
        Ok(response)
    }

    /// Cancels a pending or staged ceremony and erases its staged response.
    ///
    /// # Errors
    ///
    /// Terminal, missing, corrupt, and unavailable records fail closed.
    pub fn cancel(&mut self, challenge_id: ChallengeId) -> Result<(), RepositoryError> {
        let changed = self
            .connection
            .execute(
                "UPDATE ceremonies SET state = 'cancelled', response = NULL,
                        revision = revision + 1
                 WHERE challenge_id = ?1
                   AND state IN ('pending', 'response_available')",
                params![challenge_id.as_bytes().as_slice()],
            )
            .map_err(map_sql)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(RepositoryError::Conflict)
        }
    }
}

/// Coarse durable-agent repository failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryError {
    /// Parent directory or database permissions are unsafe.
    Permissions,
    /// Input record or transition is invalid.
    Invalid,
    /// Challenge does not exist.
    NotFound,
    /// Duplicate, replayed, stale, or terminal transition.
    Conflict,
    /// Stored state violates the closed schema.
    Corrupt,
    /// Authoritative expiry has been made terminal.
    Expired,
    /// Filesystem or `SQLite` service is unavailable.
    Unavailable,
}

impl fmt::Display for RepositoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Permissions => "local agent storage permissions rejected",
            Self::Invalid => "local agent record rejected",
            Self::NotFound => "local agent ceremony not found",
            Self::Conflict => "local agent ceremony state conflict",
            Self::Corrupt => "local agent storage is corrupt",
            Self::Expired => "local agent ceremony expired",
            Self::Unavailable => "local agent storage unavailable",
        })
    }
}

impl Error for RepositoryError {}

fn transition(
    connection: &mut Connection,
    challenge_id: ChallengeId,
    expected: &str,
    next: &str,
    response: Option<&[u8]>,
) -> Result<(), RepositoryError> {
    let changed = connection
        .execute(
            "UPDATE ceremonies SET state = ?1, response = ?2, revision = revision + 1
             WHERE challenge_id = ?3 AND state = ?4",
            params![next, response, challenge_id.as_bytes().as_slice(), expected],
        )
        .map_err(map_sql)?;
    if changed == 1 {
        Ok(())
    } else {
        Err(RepositoryError::Conflict)
    }
}

fn validate_parent(path: &Path) -> Result<(), RepositoryError> {
    let parent = path.parent().ok_or(RepositoryError::Permissions)?;
    let metadata = fs::symlink_metadata(parent).map_err(map_io)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(RepositoryError::Permissions);
    }
    Ok(())
}

fn hydrate(row: &rusqlite::Row<'_>, challenge_id: ChallengeId) -> rusqlite::Result<CeremonyRecord> {
    let kind = match row.get::<_, i64>(0)? {
        1 => CeremonyKind::Login,
        2 => CeremonyKind::Action,
        _ => return Err(corrupt()),
    };
    let state = match row.get::<_, String>(4)?.as_str() {
        "pending" => CeremonyState::Pending,
        "response_available" => CeremonyState::ResponseAvailable,
        "consumed" => CeremonyState::Consumed,
        "denied" => CeremonyState::Denied,
        "cancelled" => CeremonyState::Cancelled,
        "expired" => CeremonyState::Expired,
        "failed" => CeremonyState::Failed,
        _ => return Err(corrupt()),
    };
    Ok(CeremonyRecord {
        challenge_id,
        kind,
        canonical_challenge: row.get(1)?,
        installation_signature: row.get(2)?,
        expires_at: u64::try_from(row.get::<_, i64>(3)?).map_err(|_| corrupt())?,
        state,
        response: row.get(5)?,
        revision: u64::try_from(row.get::<_, i64>(6)?).map_err(|_| corrupt())?,
    })
}

fn kind_number(kind: CeremonyKind) -> i64 {
    match kind {
        CeremonyKind::Login => 1,
        CeremonyKind::Action => 2,
    }
}

pub(crate) fn is_constraint(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == rusqlite::ErrorCode::ConstraintViolation
    )
}

fn map_io(_: io::Error) -> RepositoryError {
    RepositoryError::Unavailable
}

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn map_sql(error: rusqlite::Error) -> RepositoryError {
    match error {
        rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::InvalidColumnType(..)
        | rusqlite::Error::IntegralValueOutOfRange(..) => RepositoryError::Corrupt,
        _ => RepositoryError::Unavailable,
    }
}

pub(crate) fn corrupt() -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Blob,
        Box::new(io::Error::new(io::ErrorKind::InvalidData, "corrupt")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    fn directory() -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "pistis-agent-{}-{suffix}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn record(id: u8) -> CeremonyRecord {
        CeremonyRecord {
            challenge_id: ChallengeId::from_bytes([id; 16]),
            kind: CeremonyKind::Login,
            canonical_challenge: vec![0xa0],
            installation_signature: vec![2; 64],
            expires_at: 1_000,
            state: CeremonyState::Pending,
            response: None,
            revision: 0,
        }
    }

    #[test]
    fn restart_preserves_single_use_consumption() {
        let directory = directory();
        let database = directory.join("agent.sqlite3");
        let challenge = record(1);
        {
            let mut repository = CeremonyRepository::open(&database).unwrap();
            repository.insert(&challenge).unwrap();
            repository
                .stage_response(challenge.challenge_id, b"signed response")
                .unwrap();
        }
        {
            let mut repository = CeremonyRepository::open(&database).unwrap();
            assert_eq!(
                repository
                    .consume_response(challenge.challenge_id, 500)
                    .unwrap(),
                b"signed response"
            );
        }
        {
            let mut repository = CeremonyRepository::open(&database).unwrap();
            assert_eq!(
                repository.consume_response(challenge.challenge_id, 500),
                Err(RepositoryError::Conflict)
            );
            assert_eq!(
                repository.get(challenge.challenge_id).unwrap().state,
                CeremonyState::Consumed
            );
        }
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn duplicate_expiry_and_cancellation_fail_closed() {
        let directory = directory();
        let database = directory.join("agent.sqlite3");
        let mut repository = CeremonyRepository::open(&database).unwrap();
        let challenge = record(2);
        repository.insert(&challenge).unwrap();
        assert_eq!(
            repository.insert(&challenge),
            Err(RepositoryError::Conflict)
        );
        repository
            .stage_response(challenge.challenge_id, b"response")
            .unwrap();
        assert_eq!(
            repository.consume_response(challenge.challenge_id, 1_000),
            Err(RepositoryError::Expired)
        );
        assert_eq!(
            repository.get(challenge.challenge_id).unwrap().state,
            CeremonyState::Expired
        );

        let challenge = record(3);
        repository.insert(&challenge).unwrap();
        repository.cancel(challenge.challenge_id).unwrap();
        assert_eq!(
            repository.stage_response(challenge.challenge_id, b"response"),
            Err(RepositoryError::Conflict)
        );
        drop(repository);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn permissive_parent_and_database_are_rejected() {
        let directory = directory();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            CeremonyRepository::open(&directory.join("agent.sqlite3")),
            Err(RepositoryError::Permissions)
        ));
        fs::remove_dir_all(directory).unwrap();
    }
}
