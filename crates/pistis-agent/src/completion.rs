use crate::{CeremonyKind, CeremonyRecord, CeremonyRepository, RepositoryError};
use pistis_crypto::sha256;
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

/// Verified facts presented to the host-owned completion transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletionRequest {
    /// Ceremony whose exact staged response was independently verified.
    pub challenge_id: ChallengeId,
    /// Exact staged bytes covered by the completed verification.
    pub verified_response: Vec<u8>,
    /// Fresh unpredictable key making host retries idempotent.
    pub idempotency_key: [u8; 32],
    /// Authenticated local user.
    pub user_id: UserId,
    /// Active enrolled device that signed the response.
    pub device_id: DeviceId,
    /// Transport retained as non-secret evidence.
    pub transfer: AuditTransfer,
    /// Authoritative completion time in Unix milliseconds.
    pub completed_at: u64,
}

/// Non-secret result of the host-owned atomic transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletionOutcome {
    /// Stable, non-secret host correlation reference.
    pub authority_reference: Vec<u8>,
    /// Principal whose Prosopikon authority was established.
    pub user_id: UserId,
    /// Device whose approval was committed.
    pub device_id: DeviceId,
    /// Authoritative host completion time in Unix milliseconds.
    pub completed_at: u64,
}

/// Host-owned atomic authentication completion boundary.
///
/// Production implementations live with the Prosopikon authority and own
/// challenge consumption, binding and generation rechecks, session or
/// exact-action capability issuance, idempotency, and authority plus Pistis
/// audit append in one database transaction. No capability may be returned.
pub trait HostCompletionPort {
    /// Loads the authoritative staged ceremony for deterministic verification.
    ///
    /// # Errors
    ///
    /// Missing, terminal, corrupt, or unavailable state fails closed.
    fn ceremony(&self, challenge_id: ChallengeId) -> Result<CeremonyRecord, RepositoryError>;

    /// Commits one verified request or returns its prior identical outcome.
    ///
    /// # Errors
    ///
    /// Any stale binding, replay with different facts, unavailable authority,
    /// or partially applicable mutation fails closed.
    fn complete(
        &mut self,
        request: &CompletionRequest,
    ) -> Result<CompletionOutcome, RepositoryError>;
}

impl HostCompletionPort for CeremonyRepository {
    fn ceremony(&self, challenge_id: ChallengeId) -> Result<CeremonyRecord, RepositoryError> {
        self.get(challenge_id)
    }

    fn complete(
        &mut self,
        request: &CompletionRequest,
    ) -> Result<CompletionOutcome, RepositoryError> {
        // The local reference adapter deliberately returns only a non-secret
        // challenge correlation. It is not a session or authorization issuer.
        let authority_reference = request.challenge_id.as_bytes();
        match self.complete_verified(request, authority_reference) {
            Ok(outcome) => Ok(outcome),
            Err(RepositoryError::Conflict) => {
                let prior = self.completion_outcome(&request.idempotency_key)?;
                if self.completion_matches(request, authority_reference)? {
                    Ok(prior)
                } else {
                    Err(RepositoryError::Conflict)
                }
            }
            Err(error) => Err(error),
        }
    }
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
    /// Atomically consumes an exactly rechecked response, records the host
    /// outcome, and appends redacted audit evidence.
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
        completion: &CompletionRequest,
        authority_reference: &[u8],
    ) -> Result<CompletionOutcome, RepositoryError> {
        validate_completion(completion)?;
        if authority_reference.is_empty() || authority_reference.len() > 512 {
            return Err(RepositoryError::Invalid);
        }
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
                "INSERT INTO completion_receipts(
                    idempotency_key, challenge_id, user_id, device_id,
                    response_digest, transfer, authority_reference, completed_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    completion.idempotency_key.as_slice(),
                    completion.challenge_id.as_bytes().as_slice(),
                    completion.user_id.as_bytes().as_slice(),
                    completion.device_id.as_bytes().as_slice(),
                    sha256(&completion.verified_response).as_bytes().as_slice(),
                    transfer_number(completion.transfer),
                    authority_reference,
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
        transaction.commit().map_err(super::repository::map_sql)?;
        Ok(CompletionOutcome {
            authority_reference: authority_reference.to_vec(),
            user_id: completion.user_id,
            device_id: completion.device_id,
            completed_at: completion.completed_at,
        })
    }

    /// Resolves a non-secret completion receipt by idempotency key.
    ///
    /// # Errors
    ///
    /// Unknown keys return `NotFound`; corrupt or unavailable storage
    /// remains distinguishable.
    pub fn completion_outcome(
        &self,
        idempotency_key: &[u8; 32],
    ) -> Result<CompletionOutcome, RepositoryError> {
        self.connection
            .query_row(
                "SELECT authority_reference, user_id, device_id, completed_at
                 FROM completion_receipts WHERE idempotency_key = ?1",
                params![idempotency_key.as_slice()],
                |row| {
                    Ok(CompletionOutcome {
                        authority_reference: row.get(0)?,
                        user_id: UserId::from_bytes(take_id(row.get(1)?)?),
                        device_id: DeviceId::from_bytes(take_id(row.get(2)?)?),
                        completed_at: u64::try_from(row.get::<_, i64>(3)?)
                            .map_err(|_| super::repository::corrupt())?,
                    })
                },
            )
            .optional()
            .map_err(super::repository::map_sql)?
            .ok_or(RepositoryError::NotFound)
    }

    fn completion_matches(
        &self,
        request: &CompletionRequest,
        authority_reference: &[u8],
    ) -> Result<bool, RepositoryError> {
        let stored: Option<(Vec<u8>, Vec<u8>, Vec<u8>, i64, Vec<u8>, i64)> = self
            .connection
            .query_row(
                "SELECT challenge_id, user_id, device_id, transfer,
                        response_digest, completed_at
                 FROM completion_receipts
                 WHERE idempotency_key = ?1 AND authority_reference = ?2",
                params![request.idempotency_key.as_slice(), authority_reference],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(super::repository::map_sql)?;
        let Some((challenge, user, device, transfer, digest, completed_at)) = stored else {
            return Ok(false);
        };
        Ok(challenge == request.challenge_id.as_bytes()
            && user == request.user_id.as_bytes()
            && device == request.device_id.as_bytes()
            && transfer == transfer_number(request.transfer)
            && digest == sha256(&request.verified_response).as_bytes()
            && completed_at == i64::try_from(request.completed_at).unwrap_or(-1))
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

fn validate_completion(completion: &CompletionRequest) -> Result<(), RepositoryError> {
    if completion.verified_response.is_empty()
        || completion.verified_response.len() > 64 * 1024
        || completion.idempotency_key == [0; 32]
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

    fn completion(id: u8, key: u8) -> CompletionRequest {
        CompletionRequest {
            challenge_id: ChallengeId::from_bytes([id; 16]),
            verified_response: b"signed response".to_vec(),
            idempotency_key: [key; 32],
            user_id: UserId::from_bytes([7; 16]),
            device_id: DeviceId::from_bytes([8; 16]),
            transfer: AuditTransfer::ResponseQr,
            completed_at: 500,
        }
    }

    #[test]
    fn completion_commits_receipt_audit_and_consumption_across_restart() {
        let (directory, database) = database();
        let mut repository = CeremonyRepository::open(&database).unwrap();
        repository.insert(&record(1)).unwrap();
        repository
            .stage_response(ChallengeId::from_bytes([1; 16]), b"signed response")
            .unwrap();
        repository
            .complete_verified(&completion(1, 9), &[1; 16])
            .unwrap();
        assert_eq!(
            repository.completion_outcome(&[9; 32]).unwrap(),
            CompletionOutcome {
                authority_reference: vec![1; 16],
                user_id: UserId::from_bytes([7; 16]),
                device_id: DeviceId::from_bytes([8; 16]),
                completed_at: 500,
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
            repository.complete_verified(&substituted, &[2; 16]),
            Err(RepositoryError::Conflict)
        );
        assert_eq!(
            repository.completion_outcome(&[10; 32]),
            Err(RepositoryError::NotFound)
        );
        assert!(repository.audit_events().unwrap().is_empty());

        repository
            .complete_verified(&completion(2, 10), &[1; 16])
            .unwrap();
        assert_eq!(
            repository.complete_verified(&completion(2, 11), &[1; 16]),
            Err(RepositoryError::Conflict)
        );
        assert_eq!(
            repository.completion_outcome(&[11; 32]),
            Err(RepositoryError::NotFound)
        );

        repository.insert(&record(3)).unwrap();
        repository
            .stage_response(ChallengeId::from_bytes([3; 16]), b"signed response")
            .unwrap();
        let mut expired = completion(3, 12);
        expired.completed_at = 1_000;
        assert_eq!(
            repository.complete_verified(&expired, &[3; 16]),
            Err(RepositoryError::Expired)
        );
        assert_eq!(
            repository.completion_outcome(&[12; 32]),
            Err(RepositoryError::NotFound)
        );
        assert_eq!(repository.audit_events().unwrap().len(), 1);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn idempotency_collision_rolls_back_ceremony_and_audit() {
        let (directory, database) = database();
        let mut repository = CeremonyRepository::open(&database).unwrap();
        for id in [4, 5] {
            repository.insert(&record(id)).unwrap();
            repository
                .stage_response(ChallengeId::from_bytes([id; 16]), b"signed response")
                .unwrap();
        }
        repository
            .complete_verified(&completion(4, 13), &[1; 16])
            .unwrap();
        assert_eq!(
            repository.complete_verified(&completion(5, 13), &[1; 16]),
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
    fn host_port_repeats_only_an_identical_completion() {
        let (directory, database) = database();
        let mut repository = CeremonyRepository::open(&database).unwrap();
        repository.insert(&record(7)).unwrap();
        repository
            .stage_response(ChallengeId::from_bytes([7; 16]), b"signed response")
            .unwrap();
        let request = completion(7, 16);
        let first = HostCompletionPort::complete(&mut repository, &request).unwrap();
        assert_eq!(
            HostCompletionPort::complete(&mut repository, &request),
            Ok(first)
        );

        let mut altered = request;
        altered.transfer = AuditTransfer::DirectLocal;
        assert_eq!(
            HostCompletionPort::complete(&mut repository, &altered),
            Err(RepositoryError::Conflict)
        );
        assert_eq!(repository.audit_events().unwrap().len(), 1);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn concurrent_completion_creates_exactly_one_receipt_and_audit() {
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
                    repository.complete_verified(&completion(6, session), &[1; 16])
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
                .filter(|session| repository.completion_outcome(&[*session; 32]).is_ok())
                .count(),
            1
        );
        fs::remove_dir_all(directory).unwrap();
    }
}
