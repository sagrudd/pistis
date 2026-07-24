use core::{fmt, num::NonZeroU64};
use serde::{Deserialize, Serialize};

/// An installation-defined identifier for one durable binding slot.
///
/// The slot identifies where an external identity is trusted. It is distinct
/// from the provider subject and therefore cannot silently substitute for it.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct BindingId([u8; 16]);

impl BindingId {
    /// Constructs a binding identifier from its opaque bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the opaque identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// A stable numeric GitHub user identifier.
///
/// GitHub login names and email addresses are deliberately excluded from this
/// type because they are mutable metadata, not identity keys.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct GitHubSubject(NonZeroU64);

impl GitHubSubject {
    /// Constructs a stable subject from the numeric `id` returned by GitHub's
    /// authenticated-user endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidGitHubSubject`] when `id` is zero.
    pub const fn new(id: u64) -> Result<Self, InvalidGitHubSubject> {
        match NonZeroU64::new(id) {
            Some(id) => Ok(Self(id)),
            None => Err(InvalidGitHubSubject),
        }
    }

    /// Returns the stable numeric GitHub user identifier.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Error returned for an invalid GitHub stable subject.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidGitHubSubject;

impl fmt::Display for InvalidGitHubSubject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GitHub user id must be non-zero")
    }
}

impl std::error::Error for InvalidGitHubSubject {}

/// Mutable, human-readable provider metadata.
///
/// These values are never used to compare or locate identities.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct IdentityMetadata {
    /// Current provider login snapshot, when available.
    pub login: Option<String>,
    /// Current email snapshot, when available and consented.
    pub email: Option<String>,
    /// Current display-name snapshot, when available.
    pub display_name: Option<String>,
    /// Current provider profile URL snapshot, when appropriate.
    pub profile_url: Option<String>,
}

/// A GitHub identity consisting of a stable subject and mutable metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GitHubIdentity {
    /// Stable numeric user identifier returned by GitHub.
    pub subject: GitHubSubject,
    /// Human-readable snapshots which do not participate in identity equality.
    pub metadata: IdentityMetadata,
}

/// An external provider identity.
///
/// Variants keep provider namespaces separate even if their subject strings or
/// numeric representations happen to match.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub enum ExternalIdentity {
    /// A GitHub identity keyed by its stable numeric user identifier.
    GitHub(GitHubIdentity),
}

impl ExternalIdentity {
    /// Returns whether two values refer to the same stable provider subject.
    #[must_use]
    pub const fn has_same_subject(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::GitHub(left), Self::GitHub(right)) => left.subject.get() == right.subject.get(),
        }
    }
}

/// A durable association between a local binding slot and provider identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IdentityBinding {
    /// Installation-defined binding slot.
    pub id: BindingId,
    /// External identity trusted for the slot.
    pub identity: ExternalIdentity,
    /// Provider authentication time in Unix milliseconds.
    pub authenticated_at_ms: u64,
    /// Time the stored record was last refreshed, in Unix milliseconds.
    pub refreshed_at_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_and_email_do_not_define_subject_identity() {
        let original = ExternalIdentity::GitHub(GitHubIdentity {
            subject: GitHubSubject::new(42).expect("valid subject"),
            metadata: IdentityMetadata {
                login: Some("old-login".into()),
                email: Some("old@example.test".into()),
                ..IdentityMetadata::default()
            },
        });
        let renamed = ExternalIdentity::GitHub(GitHubIdentity {
            subject: GitHubSubject::new(42).expect("valid subject"),
            metadata: IdentityMetadata {
                login: Some("new-login".into()),
                email: Some("new@example.test".into()),
                ..IdentityMetadata::default()
            },
        });

        assert!(original.has_same_subject(&renamed));
    }

    #[test]
    fn zero_is_not_a_github_subject() {
        assert_eq!(GitHubSubject::new(0), Err(InvalidGitHubSubject));
    }
}
