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

/// An exact `OpenID` Connect issuer for a Google identity.
///
/// Issuer normalization and allow-list validation belong to the Google
/// protocol adapter. This type deliberately preserves the validated issuer
/// verbatim because the issuer is part of the stable identity key.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct GoogleIssuer(String);

impl GoogleIssuer {
    /// Constructs an issuer from a non-empty validated `OpenID` Connect issuer.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidGoogleIssuer`] when `issuer` is empty.
    pub fn new(issuer: impl Into<String>) -> Result<Self, InvalidGoogleIssuer> {
        let issuer = issuer.into();
        if issuer.is_empty() {
            Err(InvalidGoogleIssuer)
        } else {
            Ok(Self(issuer))
        }
    }

    /// Returns the exact issuer string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for GoogleIssuer {
    type Error = InvalidGoogleIssuer;

    fn try_from(issuer: String) -> Result<Self, Self::Error> {
        Self::new(issuer)
    }
}

impl From<GoogleIssuer> for String {
    fn from(issuer: GoogleIssuer) -> Self {
        issuer.0
    }
}

/// Error returned for an empty Google `OpenID` Connect issuer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidGoogleIssuer;

impl fmt::Display for InvalidGoogleIssuer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Google `OpenID` Connect issuer must not be empty")
    }
}

impl std::error::Error for InvalidGoogleIssuer {}

/// A stable Google `OpenID` Connect `sub` claim.
///
/// The claim is case-sensitive and is stored without interpretation. Email
/// addresses and hosted-domain claims are deliberately excluded.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct GoogleSubject(String);

impl GoogleSubject {
    /// Constructs a subject satisfying the `OpenID` Connect `sub` size and
    /// character constraints.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidGoogleSubject`] when `subject` is empty, non-ASCII, or
    /// longer than 255 bytes.
    pub fn new(subject: impl Into<String>) -> Result<Self, InvalidGoogleSubject> {
        let subject = subject.into();
        if subject.is_empty() || subject.len() > 255 || !subject.is_ascii() {
            Err(InvalidGoogleSubject)
        } else {
            Ok(Self(subject))
        }
    }

    /// Returns the exact, case-sensitive `sub` claim.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for GoogleSubject {
    type Error = InvalidGoogleSubject;

    fn try_from(subject: String) -> Result<Self, Self::Error> {
        Self::new(subject)
    }
}

impl From<GoogleSubject> for String {
    fn from(subject: GoogleSubject) -> Self {
        subject.0
    }
}

/// Error returned for an invalid Google `OpenID` Connect subject.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidGoogleSubject;

impl fmt::Display for InvalidGoogleSubject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Google `OpenID` Connect subject must be 1 to 255 ASCII bytes")
    }
}

impl std::error::Error for InvalidGoogleSubject {}

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

/// A Google identity keyed by the exact issuer and stable `sub` claim.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GoogleIdentity {
    /// Validated `OpenID` Connect issuer, retained as part of the identity key.
    pub issuer: GoogleIssuer,
    /// Stable, case-sensitive Google `OpenID` Connect `sub` claim.
    pub subject: GoogleSubject,
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
    /// A Google identity keyed by its exact issuer and stable `sub` claim.
    Google(GoogleIdentity),
}

impl ExternalIdentity {
    /// Returns whether two values refer to the same stable provider subject.
    #[must_use]
    pub fn has_same_subject(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::GitHub(left), Self::GitHub(right)) => left.subject.get() == right.subject.get(),
            (Self::Google(left), Self::Google(right)) => {
                left.issuer == right.issuer && left.subject == right.subject
            }
            _ => false,
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

    #[test]
    fn google_metadata_does_not_define_subject_identity() {
        let original = ExternalIdentity::Google(GoogleIdentity {
            issuer: GoogleIssuer::new("https://accounts.google.com").expect("valid issuer"),
            subject: GoogleSubject::new("109876543210987654321").expect("valid subject"),
            metadata: IdentityMetadata {
                email: Some("old@example.test".into()),
                display_name: Some("Old Name".into()),
                ..IdentityMetadata::default()
            },
        });
        let refreshed = ExternalIdentity::Google(GoogleIdentity {
            issuer: GoogleIssuer::new("https://accounts.google.com").expect("valid issuer"),
            subject: GoogleSubject::new("109876543210987654321").expect("valid subject"),
            metadata: IdentityMetadata {
                email: Some("new@example.test".into()),
                display_name: Some("New Name".into()),
                ..IdentityMetadata::default()
            },
        });

        assert!(original.has_same_subject(&refreshed));
    }

    #[test]
    fn google_subject_identity_includes_exact_issuer() {
        let identity = |issuer| {
            ExternalIdentity::Google(GoogleIdentity {
                issuer: GoogleIssuer::new(issuer).expect("valid issuer"),
                subject: GoogleSubject::new("same-subject").expect("valid subject"),
                metadata: IdentityMetadata::default(),
            })
        };

        assert!(
            !identity("accounts.google.com")
                .has_same_subject(&identity("https://accounts.google.com"))
        );
    }

    #[test]
    fn google_subject_validation_preserves_case() {
        assert_eq!(GoogleSubject::new(""), Err(InvalidGoogleSubject));
        assert_eq!(GoogleSubject::new("ü"), Err(InvalidGoogleSubject));
        assert_eq!(
            GoogleSubject::new("a".repeat(256)),
            Err(InvalidGoogleSubject)
        );
        assert_ne!(
            GoogleSubject::new("CaseSensitive").expect("valid subject"),
            GoogleSubject::new("casesensitive").expect("valid subject")
        );
    }
}
