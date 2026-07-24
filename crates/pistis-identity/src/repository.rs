use crate::{BindingId, IdentityBinding};
use core::fmt;

/// Result of atomically storing an identity binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreOutcome {
    /// No record existed and the binding was inserted.
    Inserted,
    /// The same stable subject existed and its complete record was replaced.
    Updated,
}

/// Persistence errors for identity bindings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryError {
    /// The binding slot is already associated with another stable subject.
    SubjectConflict,
    /// The repository could not safely access its state.
    Unavailable,
}

impl fmt::Display for RepositoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SubjectConflict => {
                formatter.write_str("binding slot is already assigned to another provider subject")
            }
            Self::Unavailable => formatter.write_str("identity binding repository is unavailable"),
        }
    }
}

impl std::error::Error for RepositoryError {}

/// Atomic persistence boundary for durable external identity bindings.
///
/// Implementations must commit the complete record or leave their prior state
/// unchanged. Storing the same stable subject is idempotent and may refresh
/// mutable metadata; storing a different subject in an occupied slot fails.
pub trait IdentityBindingRepository {
    /// Returns a binding by its installation-defined slot.
    ///
    /// # Errors
    ///
    /// Returns [`RepositoryError::Unavailable`] when state cannot be read.
    fn get(&self, id: BindingId) -> Result<Option<IdentityBinding>, RepositoryError>;

    /// Atomically inserts or refreshes a binding.
    ///
    /// # Errors
    ///
    /// Returns [`RepositoryError::SubjectConflict`] for subject substitution,
    /// or [`RepositoryError::Unavailable`] when state cannot be committed.
    fn store(&self, binding: IdentityBinding) -> Result<StoreOutcome, RepositoryError>;
}
