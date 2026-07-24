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
