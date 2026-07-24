use crate::{BindingId, IdentityBinding, IdentityBindingRepository, RepositoryError, StoreOutcome};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

/// Thread-safe in-memory repository for deterministic integration tests.
///
/// Clones share the same repository state. Each store operation holds one lock
/// while validating and replacing the complete record.
#[derive(Clone, Debug, Default)]
pub struct InMemoryIdentityBindingRepository {
    bindings: Arc<Mutex<BTreeMap<BindingId, IdentityBinding>>>,
}

impl IdentityBindingRepository for InMemoryIdentityBindingRepository {
    fn get(&self, id: BindingId) -> Result<Option<IdentityBinding>, RepositoryError> {
        let bindings = self
            .bindings
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?;
        Ok(bindings.get(&id).cloned())
    }

    fn store(&self, binding: IdentityBinding) -> Result<StoreOutcome, RepositoryError> {
        let mut bindings = self
            .bindings
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?;

        let outcome = match bindings.get(&binding.id) {
            None => StoreOutcome::Inserted,
            Some(existing) if existing.identity.has_same_subject(&binding.identity) => {
                StoreOutcome::Updated
            }
            Some(_) => return Err(RepositoryError::SubjectConflict),
        };
        bindings.insert(binding.id, binding);
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExternalIdentity, GitHubIdentity, GitHubSubject, IdentityMetadata};

    fn binding(id_byte: u8, subject: u64, login: &str) -> IdentityBinding {
        IdentityBinding {
            id: BindingId::from_bytes([id_byte; 16]),
            identity: ExternalIdentity::GitHub(GitHubIdentity {
                subject: GitHubSubject::new(subject).expect("test subject is non-zero"),
                metadata: IdentityMetadata {
                    login: Some(login.into()),
                    ..IdentityMetadata::default()
                },
            }),
            authenticated_at_ms: 1_000,
            refreshed_at_ms: 2_000,
        }
    }

    #[test]
    fn inserts_complete_binding() {
        let repository = InMemoryIdentityBindingRepository::default();
        let expected = binding(1, 42, "octocat");

        assert_eq!(
            repository.store(expected.clone()),
            Ok(StoreOutcome::Inserted)
        );
        assert_eq!(repository.get(expected.id), Ok(Some(expected)));
    }

    #[test]
    fn same_subject_atomically_refreshes_mutable_metadata() {
        let repository = InMemoryIdentityBindingRepository::default();
        let original = binding(1, 42, "old-login");
        let mut refreshed = binding(1, 42, "new-login");
        refreshed.refreshed_at_ms = 3_000;

        repository.store(original).expect("initial insert");
        assert_eq!(
            repository.store(refreshed.clone()),
            Ok(StoreOutcome::Updated)
        );
        assert_eq!(repository.get(refreshed.id), Ok(Some(refreshed)));
    }

    #[test]
    fn subject_substitution_is_rejected_without_partial_persistence() {
        let repository = InMemoryIdentityBindingRepository::default();
        let original = binding(1, 42, "trusted");
        let substitute = binding(1, 99, "attacker");

        repository.store(original.clone()).expect("initial insert");
        assert_eq!(
            repository.store(substitute),
            Err(RepositoryError::SubjectConflict)
        );
        assert_eq!(repository.get(original.id), Ok(Some(original)));
    }

    #[test]
    fn separate_binding_slots_can_hold_separate_subjects() {
        let repository = InMemoryIdentityBindingRepository::default();
        let first = binding(1, 42, "first");
        let second = binding(2, 99, "second");

        repository.store(first.clone()).expect("first insert");
        repository.store(second.clone()).expect("second insert");

        assert_eq!(repository.get(first.id), Ok(Some(first)));
        assert_eq!(repository.get(second.id), Ok(Some(second)));
    }

    #[test]
    fn clones_observe_the_same_atomic_state() {
        let writer = InMemoryIdentityBindingRepository::default();
        let reader = writer.clone();
        let expected = binding(1, 42, "octocat");

        writer.store(expected.clone()).expect("insert");
        assert_eq!(reader.get(expected.id), Ok(Some(expected)));
    }
}
