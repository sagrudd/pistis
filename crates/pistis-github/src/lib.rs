//! GitHub OAuth enrolment with PKCE and stable numeric subjects.
//!
//! This crate deliberately stops at an authenticated provider identity. It
//! neither persists bindings nor retains access tokens. HTTP is represented by
//! narrow transport traits so platform adapters can enforce their own network
//! policy.

#![forbid(unsafe_code)]

mod config;
mod flow;
mod pkce;
mod transport;

pub use config::{ConfigError, OAuthAppConfig};
pub use flow::{
    AUTHORIZE_ENDPOINT, AuthenticatedGitHubIdentity, AuthorizationRequest, Callback, CallbackError,
    GitHubOAuth, OAuthError, ProviderError, TOKEN_ENDPOINT, USER_ENDPOINT,
};
pub use pkce::{EntropyError, EntropySource, Pkce, PkceError, PkceVerifier, State};
pub use transport::{
    AccessToken, TokenExchange, TokenTransport, TransportError, UserPayload, UserTransport,
};

/// Maximum accepted authenticated-user JSON response size.
///
/// HTTP adapters should apply a tighter response limit where practical; the
/// identity parser enforces this fail-safe ceiling itself.
pub const MAX_USER_PAYLOAD_BYTES: usize = 64 * 1024;

/// Maximum accepted OAuth authorization-code or access-token size.
pub const MAX_OAUTH_SECRET_BYTES: usize = 8 * 1024;
