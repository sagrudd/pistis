//! Provider-neutral external identity binding and persistence boundaries.
//!
//! Stable provider subjects are the only identity keys. Human-readable fields
//! are snapshots that may change without changing the bound identity.

#![deny(missing_docs)]

mod file;
mod memory;
mod model;
mod repository;

pub use file::FileIdentityBindingRepository;
pub use memory::InMemoryIdentityBindingRepository;
pub use model::{
    BindingId, ExternalIdentity, GitHubIdentity, GitHubSubject, IdentityBinding, IdentityMetadata,
    InvalidGitHubSubject,
};
pub use repository::{IdentityBindingRepository, RepositoryError, StoreOutcome};
