use crate::{BindingId, IdentityBinding, IdentityBindingRepository, RepositoryError, StoreOutcome};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

static TEMPORARY_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Durable file-backed identity-binding repository.
///
/// The complete repository is encoded as JSON and committed with a
/// same-directory temporary file followed by an atomic rename. A malformed or
/// inaccessible file fails closed; it is never treated as an empty repository.
/// Clones share an in-process transaction lock.
#[derive(Clone, Debug)]
pub struct FileIdentityBindingRepository {
    path: Arc<PathBuf>,
    transaction: Arc<Mutex<()>>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredBindings {
    version: u32,
    bindings: Vec<IdentityBinding>,
}

impl FileIdentityBindingRepository {
    /// Opens a repository at `path`.
    ///
    /// The file is created by the first successful store operation. Parent
    /// directories are not created implicitly.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: Arc::new(path.into()),
            transaction: Arc::new(Mutex::new(())),
        }
    }

    fn read(&self) -> Result<StoredBindings, RepositoryError> {
        match fs::read(self.path.as_ref()) {
            Ok(bytes) => {
                let stored: StoredBindings =
                    serde_json::from_slice(&bytes).map_err(|_| RepositoryError::Unavailable)?;
                if stored.version != 1 || has_duplicate_ids(&stored.bindings) {
                    return Err(RepositoryError::Unavailable);
                }
                Ok(stored)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(StoredBindings {
                version: 1,
                bindings: Vec::new(),
            }),
            Err(_) => Err(RepositoryError::Unavailable),
        }
    }

    fn commit(&self, stored: &StoredBindings) -> Result<(), RepositoryError> {
        let bytes = serde_json::to_vec(stored).map_err(|_| RepositoryError::Unavailable)?;
        let temporary_path = temporary_path(self.path.as_ref());
        let result = write_and_rename(&temporary_path, self.path.as_ref(), &bytes);
        if result.is_err() {
            let _ignored = fs::remove_file(&temporary_path);
        }
        result.map_err(|_| RepositoryError::Unavailable)
    }
}

impl IdentityBindingRepository for FileIdentityBindingRepository {
    fn get(&self, id: BindingId) -> Result<Option<IdentityBinding>, RepositoryError> {
        let _transaction = self
            .transaction
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?;
        Ok(self
            .read()?
            .bindings
            .into_iter()
            .find(|binding| binding.id == id))
    }

    fn store(&self, binding: IdentityBinding) -> Result<StoreOutcome, RepositoryError> {
        let _transaction = self
            .transaction
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?;
        let mut stored = self.read()?;

        let outcome = match stored
            .bindings
            .iter_mut()
            .find(|existing| existing.id == binding.id)
        {
            None => {
                stored.bindings.push(binding);
                StoreOutcome::Inserted
            }
            Some(existing) if existing.identity.has_same_subject(&binding.identity) => {
                *existing = binding;
                StoreOutcome::Updated
            }
            Some(_) => return Err(RepositoryError::SubjectConflict),
        };

        stored.bindings.sort_by_key(|entry| entry.id);
        self.commit(&stored)?;
        Ok(outcome)
    }
}

fn has_duplicate_ids(bindings: &[IdentityBinding]) -> bool {
    let mut ids: Vec<_> = bindings.iter().map(|binding| binding.id).collect();
    ids.sort_unstable();
    ids.windows(2).any(|pair| pair[0] == pair[1])
}

fn temporary_path(target: &Path) -> PathBuf {
    let sequence = TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let file_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("pistis-identities");
    target.with_file_name(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        sequence
    ))
}

fn write_and_rename(temporary: &Path, target: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(temporary, target)?;
    sync_parent(target)
}

#[cfg(unix)]
fn sync_parent(target: &Path) -> io::Result<()> {
    let parent = target
        .parent()
        .map_or_else(|| Path::new("."), |parent| parent);
    File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent(_target: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExternalIdentity, GitHubIdentity, GitHubSubject, IdentityMetadata};
    use std::sync::atomic::{AtomicU64, Ordering};

    static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "pistis-identity-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create isolated test directory");
            Self(path)
        }

        fn repository_path(&self) -> PathBuf {
            self.0.join("bindings.json")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove isolated test directory");
        }
    }

    fn binding(subject: u64, login: &str) -> IdentityBinding {
        IdentityBinding {
            id: BindingId::from_bytes([7; 16]),
            identity: ExternalIdentity::GitHub(GitHubIdentity {
                subject: GitHubSubject::new(subject).expect("non-zero subject"),
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
    fn binding_survives_repository_restart() {
        let directory = TestDirectory::new();
        let expected = binding(42, "octocat");
        FileIdentityBindingRepository::new(directory.repository_path())
            .store(expected.clone())
            .expect("store binding");

        let reopened = FileIdentityBindingRepository::new(directory.repository_path());
        assert_eq!(reopened.get(expected.id), Ok(Some(expected)));
    }

    #[test]
    fn same_subject_refreshes_metadata() {
        let directory = TestDirectory::new();
        let repository = FileIdentityBindingRepository::new(directory.repository_path());
        repository
            .store(binding(42, "old-login"))
            .expect("initial binding");
        let refreshed = binding(42, "new-login");

        assert_eq!(
            repository.store(refreshed.clone()),
            Ok(StoreOutcome::Updated)
        );
        assert_eq!(repository.get(refreshed.id), Ok(Some(refreshed)));
    }

    #[test]
    fn conflict_leaves_durable_record_unchanged() {
        let directory = TestDirectory::new();
        let path = directory.repository_path();
        let repository = FileIdentityBindingRepository::new(&path);
        let original = binding(42, "trusted");
        repository.store(original.clone()).expect("initial binding");
        let original_bytes = fs::read(&path).expect("read stored representation");

        assert_eq!(
            repository.store(binding(99, "attacker")),
            Err(RepositoryError::SubjectConflict)
        );
        assert_eq!(
            fs::read(&path).expect("read unchanged representation"),
            original_bytes
        );
        assert_eq!(repository.get(original.id), Ok(Some(original)));
    }

    #[test]
    fn malformed_storage_fails_closed_and_is_not_overwritten() {
        let directory = TestDirectory::new();
        let path = directory.repository_path();
        fs::write(&path, b"not json").expect("write corrupt repository");
        let repository = FileIdentityBindingRepository::new(&path);

        assert_eq!(
            repository.get(BindingId::from_bytes([7; 16])),
            Err(RepositoryError::Unavailable)
        );
        assert_eq!(
            repository.store(binding(42, "octocat")),
            Err(RepositoryError::Unavailable)
        );
        assert_eq!(fs::read(path).expect("read corruption"), b"not json");
    }

    #[cfg(unix)]
    #[test]
    fn repository_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TestDirectory::new();
        let path = directory.repository_path();
        FileIdentityBindingRepository::new(&path)
            .store(binding(42, "octocat"))
            .expect("store binding");

        let mode = fs::metadata(path).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
