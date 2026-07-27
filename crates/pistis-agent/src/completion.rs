use crate::{CeremonyKind, CeremonyRepository, RepositoryError};
use pistis_domain::{ChallengeId, DeviceId, UserId};
use rusqlite::{OptionalExtension as _, TransactionBehavior, params};

/// How an authenticated mobile response reached the local authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditTransfer {
    /// Submitted over an authenticated direct-local channel.
    DirectLocal,
    /// Submitted as a checksummed terminal response frame.
    ResponseQr,
}

/// Verified facts committed as one durable session and audit transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedCompletion {
    /// Ceremony whose exact staged response was independently verified.
    pub challenge_id: ChallengeId,
    /// Exact staged bytes covered by the completed verification.
    pub verified_response: Vec<u8>,
    /// Fresh unpredictable session capability, never returned in audit data.
    pub session_id: [u8; 32],
    /// Authenticated local user.
    pub user_id: UserId,
    /// Active enrolled device that signed the response.
    pub device_id: DeviceId,
    /// Transport retained as non-secret evidence.
    pub transfer: AuditTransfer,
    /// Authoritative completion time in Unix milliseconds.
    pub completed_at: u64,
}

/// Non-secret durable session metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedSession {
    /// Authenticated local user.
    pub user_id: UserId,
    /// Device that approved the session.
    pub device_id: DeviceId,
    /// Session creation time in Unix milliseconds.
    pub created_at: u64,
}

/// Redacted durable authentication evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableAuditEvent {
    /// Monotonic database-local sequence.
    pub sequence: u64,
    /// Single-use ceremony identifier.
    pub challenge_id: ChallengeId,
    /// Authenticated local user.
    pub user_id: UserId,
    /// Device that approved the operation.
    pub device_id: DeviceId,
    /// Login or exact-action ceremony.
    pub ceremony_kind: CeremonyKind,
    /// Transport used for the signed response.
    pub transfer: AuditTransfer,
    /// Authoritative completion time in Unix milliseconds.
    pub completed_at: u64,
}

impl CeremonyRepository {
    /// Atomically consumes an exactly rechecked response, creates its session,
    /// and appends redacted audit evidence.
    ///
    /// Signature, schema, device, binding, decision, and policy verification
    /// must finish before this call. The transaction rechecks that the staged
    /// response is byte-for-byte the verified response and that the ceremony
    /// remains unexpired. It then inserts the session and audit rows before
    /// making the ceremony terminal. Any failure commits none of those writes.
    ///
    /// # Errors
    ///
    /// Rejects invalid fields, response substitution, expiry, replay, session
    /// collision, corrupt state, and unavailable durable storage.
    pub fn complete_verified(
        &mut self,
        completion: &VerifiedCompletion,
    ) -> Result<(), RepositoryError> {
        validate_completion(completion)?;
        let completed_at =
            i64::try_from(completion.completed_at).map_err(|_| RepositoryError::Invalid)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(super::repository::map_sql)?;
        let row: Option<(i64, i64, String, Option<Vec<u8>>)> = transaction
            .query_row(
                "SELECT kind, expires_at, state, response FROM ceremonies
                 WHERE challenge_id = ?1",
                params![completion.challenge_id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(super::repository::map_sql)?;
        let Some((kind, expires_at, state, staged)) = row else {
            return Err(RepositoryError::NotFound);
        };
        if expires_at <= completed_at {
            transaction
                .execute(
                    "UPDATE ceremonies SET state = 'expired', response = NULL,
                            revision = revision + 1
                     WHERE challenge_id = ?1
                       AND state IN ('pending', 'response_available')",
                    params![completion.challenge_id.as_bytes().as_slice()],
                )
                .map_err(super::repository::map_sql)?;
            transaction.commit().map_err(super::repository::map_sql)?;
            return Err(RepositoryError::Expired);
        }
        if state != "response_available"
            || staged.as_deref() != Some(completion.verified_response.as_slice())
        {
            return Err(RepositoryError::Conflict);
        }
        if !matches!(kind, 1 | 2) {
            return Err(RepositoryError::Corrupt);
        }
        transaction
            .execute(
                "INSERT INTO sessions(
                    session_id, challenge_id, user_id, device_id, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    completion.session_id.as_slice(),
                    completion.challenge_id.as_bytes().as_slice(),
                    completion.user_id.as_bytes().as_slice(),
                    completion.device_id.as_bytes().as_slice(),
                    completed_at,
                ],
            )
            .map_err(map_write)?;
        transaction
            .execute(
                "INSERT INTO audit_events(
                    challenge_id, user_id, device_id, ceremony_kind,
                    transfer, completed_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    completion.challenge_id.as_bytes().as_slice(),
                    completion.user_id.as_bytes().as_slice(),
                    completion.device_id.as_bytes().as_slice(),
                    kind,
                    transfer_number(completion.transfer),
                    completed_at,
                ],
            )
            .map_err(map_write)?;
        let changed = transaction
            .execute(
                "UPDATE ceremonies SET state = 'consumed', response = NULL,
                        revision = revision + 1
                 WHERE challenge_id = ?1 AND state = 'response_available'",
                params![completion.challenge_id.as_bytes().as_slice()],
            )
            .map_err(super::repository::map_sql)?;
        if changed != 1 {
            return Err(RepositoryError::Conflict);
        }
        transaction.commit().map_err(super::repository::map_sql)
    }

    /// Resolves non-secret metadata for an exact session capability.
    ///
    /// # Errors
    ///
    /// Unknown sessions return `NotFound`; corrupt or unavailable storage
    /// remains distinguishable.
    pub fn session(&self, session_id: &[u8; 32]) -> Result<VerifiedSession, RepositoryError> {
        self.connection
            .query_row(
                "SELECT user_id, device_id, created_at
                 FROM sessions WHERE session_id = ?1",
                params![session_id.as_slice()],
                |row| {
                    Ok(VerifiedSession {
                        user_id: UserId::from_bytes(take_id(row.get(0)?)?),
                        device_id: DeviceId::from_bytes(take_id(row.get(1)?)?),
                        created_at: u64::try_from(row.get::<_, i64>(2)?)
                            .map_err(|_| super::repository::corrupt())?,
                    })
                },
            )
            .optional()
            .map_err(super::repository::map_sql)?
            .ok_or(RepositoryError::NotFound)
    }

    /// Returns redacted audit evidence in durable sequence order.
    ///
    /// # Errors
    ///
    /// Corrupt or unavailable storage fails without returning partial events.
    pub fn audit_events(&self) -> Result<Vec<DurableAuditEvent>, RepositoryError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT sequence, challenge_id, user_id, device_id,
                        ceremony_kind, transfer, completed_at
                 FROM audit_events ORDER BY sequence",
            )
            .map_err(super::repository::map_sql)?;
        let rows = statement
            .query_map([], |row| {
                Ok(DurableAuditEvent {
                    sequence: u64::try_from(row.get::<_, i64>(0)?)
                        .map_err(|_| super::repository::corrupt())?,
                    challenge_id: ChallengeId::from_bytes(take_id(row.get(1)?)?),
                    user_id: UserId::from_bytes(take_id(row.get(2)?)?),
                    device_id: DeviceId::from_bytes(take_id(row.get(3)?)?),
                    ceremony_kind: match row.get::<_, i64>(4)? {
                        1 => CeremonyKind::Login,
                        2 => CeremonyKind::Action,
                        _ => return Err(super::repository::corrupt()),
                    },
                    transfer: match row.get::<_, i64>(5)? {
                        1 => AuditTransfer::DirectLocal,
                        2 => AuditTransfer::ResponseQr,
                        _ => return Err(super::repository::corrupt()),
                    },
                    completed_at: u64::try_from(row.get::<_, i64>(6)?)
                        .map_err(|_| super::repository::corrupt())?,
                })
            })
            .map_err(super::repository::map_sql)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(super::repository::map_sql)
    }
}

fn validate_completion(completion: &VerifiedCompletion) -> Result<(), RepositoryError> {
    if completion.verified_response.is_empty()
        || completion.verified_response.len() > 64 * 1024
        || completion.session_id == [0; 32]
    {
        return Err(RepositoryError::Invalid);
    }
    Ok(())
}

const fn transfer_number(transfer: AuditTransfer) -> i64 {
    match transfer {
        AuditTransfer::DirectLocal => 1,
        AuditTransfer::ResponseQr => 2,
    }
}

fn take_id(bytes: Vec<u8>) -> rusqlite::Result<[u8; 16]> {
    bytes.try_into().map_err(|_| super::repository::corrupt())
}

fn map_write(error: rusqlite::Error) -> RepositoryError {
    if super::repository::is_constraint(&error) {
        RepositoryError::Conflict
    } else {
        super::repository::map_sql(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CeremonyRecord, CeremonyState};
    use std::{
        fs,
        os::unix::fs::PermissionsExt as _,
        path::PathBuf,
        sync::{
            Arc, Barrier,
            atomic::{AtomicU64, Ordering},
        },
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    fn database() -> (PathBuf, PathBuf) {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "pistis-completion-{}-{suffix}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let database = directory.join("agent.sqlite3");
        (directory, database)
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

    fn completion(id: u8, session: u8) -> VerifiedCompletion {
        VerifiedCompletion {
            challenge_id: ChallengeId::from_bytes([id; 16]),
            verified_response: b"signed response".to_vec(),
            session_id: [session; 32],
            user_id: UserId::from_bytes([7; 16]),
            device_id: DeviceId::from_bytes([8; 16]),
            transfer: AuditTransfer::ResponseQr,
            completed_at: 500,
        }
    }

    #[test]
    fn completion_commits_session_audit_and_consumption_across_restart() {
        let (directory, database) = database();
        let mut repository = CeremonyRepository::open(&database).unwrap();
        repository.insert(&record(1)).unwrap();
        repository
            .stage_response(ChallengeId::from_bytes([1; 16]), b"signed response")
            .unwrap();
        repository.complete_verified(&completion(1, 9)).unwrap();
        assert_eq!(
            repository.session(&[9; 32]).unwrap(),
            VerifiedSession {
                user_id: UserId::from_bytes([7; 16]),
                device_id: DeviceId::from_bytes([8; 16]),
                created_at: 500,
            }
        );
        drop(repository);

        let repository = CeremonyRepository::open(&database).unwrap();
        assert_eq!(
            repository
                .get(ChallengeId::from_bytes([1; 16]))
                .unwrap()
                .state,
            CeremonyState::Consumed
        );
        let audit = repository.audit_events().unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].challenge_id, ChallengeId::from_bytes([1; 16]));
        assert_eq!(audit[0].transfer, AuditTransfer::ResponseQr);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn substitution_replay_and_expiry_never_create_authority() {
        let (directory, database) = database();
        let mut repository = CeremonyRepository::open(&database).unwrap();
        repository.insert(&record(2)).unwrap();
        repository
            .stage_response(ChallengeId::from_bytes([2; 16]), b"signed response")
            .unwrap();
        let mut substituted = completion(2, 10);
        substituted.verified_response = b"other response".to_vec();
        assert_eq!(
            repository.complete_verified(&substituted),
            Err(RepositoryError::Conflict)
        );
        assert_eq!(
            repository.session(&[10; 32]),
            Err(RepositoryError::NotFound)
        );
        assert!(repository.audit_events().unwrap().is_empty());

        repository.complete_verified(&completion(2, 10)).unwrap();
        assert_eq!(
            repository.complete_verified(&completion(2, 11)),
            Err(RepositoryError::Conflict)
        );
        assert_eq!(
            repository.session(&[11; 32]),
            Err(RepositoryError::NotFound)
        );

        repository.insert(&record(3)).unwrap();
        repository
            .stage_response(ChallengeId::from_bytes([3; 16]), b"signed response")
            .unwrap();
        let mut expired = completion(3, 12);
        expired.completed_at = 1_000;
        assert_eq!(
            repository.complete_verified(&expired),
            Err(RepositoryError::Expired)
        );
        assert_eq!(
            repository.session(&[12; 32]),
            Err(RepositoryError::NotFound)
        );
        assert_eq!(repository.audit_events().unwrap().len(), 1);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn session_collision_rolls_back_ceremony_and_audit() {
        let (directory, database) = database();
        let mut repository = CeremonyRepository::open(&database).unwrap();
        for id in [4, 5] {
            repository.insert(&record(id)).unwrap();
            repository
                .stage_response(ChallengeId::from_bytes([id; 16]), b"signed response")
                .unwrap();
        }
        repository.complete_verified(&completion(4, 13)).unwrap();
        assert_eq!(
            repository.complete_verified(&completion(5, 13)),
            Err(RepositoryError::Conflict)
        );
        assert_eq!(
            repository
                .get(ChallengeId::from_bytes([5; 16]))
                .unwrap()
                .state,
            CeremonyState::ResponseAvailable
        );
        assert_eq!(repository.audit_events().unwrap().len(), 1);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn concurrent_completion_creates_exactly_one_session_and_audit() {
        let (directory, database) = database();
        let mut repository = CeremonyRepository::open(&database).unwrap();
        repository.insert(&record(6)).unwrap();
        repository
            .stage_response(ChallengeId::from_bytes([6; 16]), b"signed response")
            .unwrap();
        drop(repository);

        let barrier = Arc::new(Barrier::new(2));
        let attempts: Vec<_> = [14, 15]
            .into_iter()
            .map(|session| {
                let database = database.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let mut repository = CeremonyRepository::open(&database).unwrap();
                    barrier.wait();
                    repository.complete_verified(&completion(6, session))
                })
            })
            .collect();
        let results: Vec<_> = attempts
            .into_iter()
            .map(|attempt| attempt.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);

        let repository = CeremonyRepository::open(&database).unwrap();
        assert_eq!(repository.audit_events().unwrap().len(), 1);
        assert_eq!(
            [14, 15]
                .into_iter()
                .filter(|session| repository.session(&[*session; 32]).is_ok())
                .count(),
            1
        );
        fs::remove_dir_all(directory).unwrap();
    }
}
