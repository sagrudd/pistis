//! Google `OpenID` Connect enrolment with local ID-token verification.
//!
//! Network access is deliberately outside this crate. Platform code fetches
//! discovery metadata and JWKS documents, then passes their bytes across these
//! parsing boundaries. Unknown signing keys produce an explicit refresh result
//! so callers can refresh JWKS once and retry without weakening validation.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod discovery;
mod flow;
mod token;

pub use discovery::{DiscoveryDocument, DiscoveryError, GOOGLE_DISCOVERY_URI, GOOGLE_ISSUER};
pub use flow::{
    AuthorizationAttempt, AuthorizationCallback, AuthorizationError, AuthorizationRequest,
    ClaimScopes, EntropyError, EntropySource, TokenRequest,
};
pub use token::{
    IdTokenError, JwkSet, JwksError, TokenValidation, ValidatedGoogleIdentity, ValidationError,
};

/// Maximum accepted Google discovery or `JWKS` document size.
///
/// Transport adapters should enforce tighter endpoint-specific limits where
/// practical; the parser boundary enforces this fail-safe ceiling itself.
pub const MAX_PROVIDER_DOCUMENT_BYTES: usize = 64 * 1024;

/// Maximum accepted OAuth authorization-code size.
pub const MAX_AUTHORIZATION_CODE_BYTES: usize = 8 * 1024;
