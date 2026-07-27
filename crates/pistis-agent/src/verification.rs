use crate::{
    AuditTransfer, CeremonyRecord, CeremonyRepository, CeremonyState, RepositoryError,
    VerifiedCompletion, VerifiedSession,
};
use pistis_domain::{ChallengeId, DeviceId, UserId};
use std::{error::Error, fmt};

/// Identity facts returned only after complete shared response verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedPrincipal {
    /// Authenticated local user bound into the signed response.
    pub user_id: UserId,
    /// Active enrolled device that produced the signature.
    pub device_id: DeviceId,
}

/// Shared verifier boundary for an exact durably staged response.
pub trait StagedResponseVerifier {
    /// Verifies canonicality, schema, signature, bindings, active device,
    /// decision, time, nonce, challenge digest, and policy.
    ///
    /// # Errors
    ///
    /// Returns a coarse rejection and makes no durable mutation.
    fn verify(
        &self,
        ceremony: &CeremonyRecord,
        staged_response: &[u8],
        now: u64,
    ) -> Result<VerifiedPrincipal, CompletionError>;
}

/// Fresh session-capability source.
pub trait SessionIdSource {
    /// Produces a cryptographically unpredictable non-zero capability.
    ///
    /// # Errors
    ///
    /// Fails closed when randomness is unavailable.
    fn generate(&self) -> Result<[u8; 32], CompletionError>;
}

/// Operating-system cryptographic session-capability source.
pub struct OsSessionIds;

impl SessionIdSource for OsSessionIds {
    fn generate(&self) -> Result<[u8; 32], CompletionError> {
        let mut session = [0; 32];
        getrandom::fill(&mut session).map_err(|_| CompletionError::Unavailable)?;
        if session == [0; 32] {
            return Err(CompletionError::Unavailable);
        }
        Ok(session)
    }
}

/// Concrete staged-verification and durable-completion coordinator.
pub struct CompletionCoordinator<V, S> {
    repository: CeremonyRepository,
    verifier: V,
    sessions: S,
}

impl<V, S> CompletionCoordinator<V, S> {
    /// Constructs the sole completion path over one durable repository.
    #[must_use]
    pub const fn new(repository: CeremonyRepository, verifier: V, sessions: S) -> Self {
        Self {
            repository,
            verifier,
            sessions,
        }
    }

    /// Returns the owned components.
    pub fn into_inner(self) -> (CeremonyRepository, V, S) {
        (self.repository, self.verifier, self.sessions)
    }
}

impl<V: StagedResponseVerifier, S: SessionIdSource> CompletionCoordinator<V, S> {
    /// Verifies the staged response and atomically establishes authority.
    ///
    /// The verifier performs no mutation. The repository then rechecks the
    /// same response bytes inside its immediate transaction before consuming
    /// the ceremony, creating the session, and appending audit evidence.
    ///
    /// # Errors
    ///
    /// Rejects unready, expired, invalid, replayed, colliding, corrupt, or
    /// unavailable completion attempts.
    pub fn complete(
        &mut self,
        challenge_id: ChallengeId,
        transfer: AuditTransfer,
        now: u64,
    ) -> Result<[u8; 32], CompletionError> {
        let ceremony = self.repository.get(challenge_id).map_err(map_repository)?;
        if ceremony.state != CeremonyState::ResponseAvailable || now >= ceremony.expires_at {
            return Err(CompletionError::Conflict);
        }
        let staged_response = ceremony
            .response
            .as_deref()
            .ok_or(CompletionError::Unavailable)?;
        let principal = self.verifier.verify(&ceremony, staged_response, now)?;
        let session_id = self.sessions.generate()?;
        self.repository
            .complete_verified(&VerifiedCompletion {
                challenge_id,
                verified_response: staged_response.to_vec(),
                session_id,
                user_id: principal.user_id,
                device_id: principal.device_id,
                transfer,
                completed_at: now,
            })
            .map_err(map_repository)?;
        Ok(session_id)
    }

    /// Resolves non-secret session metadata through the same repository.
    ///
    /// # Errors
    ///
    /// Unknown, corrupt, or unavailable sessions fail closed.
    pub fn session(&self, session_id: &[u8; 32]) -> Result<VerifiedSession, CompletionError> {
        self.repository.session(session_id).map_err(map_repository)
    }
}

/// Coarse authoritative completion failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionError {
    /// Signed response or policy verification rejected the operation.
    Rejected,
    /// Ceremony state, expiry, replay, or capability collision conflicts.
    Conflict,
    /// Randomness, verification dependencies, or durable storage are absent.
    Unavailable,
}

impl fmt::Display for CompletionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Rejected => "staged response verification rejected",
            Self::Conflict => "durable completion state conflict",
            Self::Unavailable => "durable completion unavailable",
        })
    }
}

impl Error for CompletionError {}

const fn map_repository(error: RepositoryError) -> CompletionError {
    match error {
        RepositoryError::Conflict | RepositoryError::Expired | RepositoryError::NotFound => {
            CompletionError::Conflict
        }
        RepositoryError::Invalid
        | RepositoryError::Permissions
        | RepositoryError::Corrupt
        | RepositoryError::Unavailable => CompletionError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CeremonyKind, CeremonyRecord};
    use std::{
        fs,
        os::unix::fs::PermissionsExt as _,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    struct Verifier(Result<VerifiedPrincipal, CompletionError>);

    impl StagedResponseVerifier for Verifier {
        fn verify(
            &self,
            _: &CeremonyRecord,
            response: &[u8],
            _: u64,
        ) -> Result<VerifiedPrincipal, CompletionError> {
            if response != b"signed response" {
                return Err(CompletionError::Rejected);
            }
            self.0
        }
    }

    struct Sessions(Result<[u8; 32], CompletionError>);

    impl SessionIdSource for Sessions {
        fn generate(&self) -> Result<[u8; 32], CompletionError> {
            self.0
        }
    }

    fn database() -> (PathBuf, PathBuf) {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "pistis-verification-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let database = directory.join("agent.sqlite3");
        (directory, database)
    }

    fn repository(path: &Path) -> CeremonyRepository {
        let mut repository = CeremonyRepository::open(path).unwrap();
        let challenge_id = ChallengeId::from_bytes([1; 16]);
        repository
            .insert(&CeremonyRecord {
                challenge_id,
                kind: CeremonyKind::Login,
                canonical_challenge: vec![0xa0],
                installation_signature: vec![2; 64],
                expires_at: 1_000,
                state: CeremonyState::Pending,
                response: None,
                revision: 0,
            })
            .unwrap();
        repository
            .stage_response(challenge_id, b"signed response")
            .unwrap();
        repository
    }

    const fn principal() -> VerifiedPrincipal {
        VerifiedPrincipal {
            user_id: UserId::from_bytes([3; 16]),
            device_id: DeviceId::from_bytes([4; 16]),
        }
    }

    #[test]
    fn verification_coordinator_creates_one_resolvable_authority() {
        let (directory, database) = database();
        let mut coordinator = CompletionCoordinator::new(
            repository(&database),
            Verifier(Ok(principal())),
            Sessions(Ok([5; 32])),
        );
        assert_eq!(
            coordinator.complete(
                ChallengeId::from_bytes([1; 16]),
                AuditTransfer::DirectLocal,
                500,
            ),
            Ok([5; 32])
        );
        assert_eq!(
            coordinator.session(&[5; 32]).unwrap().user_id,
            UserId::from_bytes([3; 16])
        );
        let (repository, _, _) = coordinator.into_inner();
        assert_eq!(repository.audit_events().unwrap().len(), 1);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejection_and_random_failure_leave_staged_response_unchanged() {
        for (verifier, sessions) in [
            (
                Verifier(Err(CompletionError::Rejected)),
                Sessions(Ok([6; 32])),
            ),
            (
                Verifier(Ok(principal())),
                Sessions(Err(CompletionError::Unavailable)),
            ),
        ] {
            let (directory, database) = database();
            let mut coordinator =
                CompletionCoordinator::new(repository(&database), verifier, sessions);
            assert!(
                coordinator
                    .complete(
                        ChallengeId::from_bytes([1; 16]),
                        AuditTransfer::ResponseQr,
                        500,
                    )
                    .is_err()
            );
            let (repository, _, _) = coordinator.into_inner();
            assert_eq!(
                repository
                    .get(ChallengeId::from_bytes([1; 16]))
                    .unwrap()
                    .state,
                CeremonyState::ResponseAvailable
            );
            assert!(repository.audit_events().unwrap().is_empty());
            fs::remove_dir_all(directory).unwrap();
        }
    }
}
