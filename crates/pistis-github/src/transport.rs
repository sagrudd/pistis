//! Narrow network boundary for GitHub OAuth.

use zeroize::Zeroize;

/// Token exchange request passed to a platform HTTP adapter.
pub struct TokenExchange<'a> {
    /// OAuth application client identifier.
    pub client_id: &'a str,
    /// Exact callback URI used in the authorization request.
    pub redirect_uri: &'a str,
    /// Single-use authorization code.
    pub code: &'a str,
    /// PKCE verifier matching the browser request.
    pub code_verifier: String,
}

impl Drop for TokenExchange<'_> {
    fn drop(&mut self) {
        self.code_verifier.zeroize();
    }
}

/// Opaque, short-lived GitHub access token.
///
/// It is intentionally neither public internally nor `Clone`/`Debug`.
pub struct AccessToken(String);

impl Drop for AccessToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl AccessToken {
    /// Constructs the opaque response from the platform transport.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::MalformedResponse`] for an empty token.
    pub fn new(value: impl Into<String>) -> Result<Self, TransportError> {
        let value = value.into();
        if value.is_empty() {
            Err(TransportError::MalformedResponse)
        } else {
            Ok(Self(value))
        }
    }

    /// Borrows the token for the authenticated-user request.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

/// Raw authenticated-user response and its local receipt time.
///
/// Parsing remains inside this crate so a transport cannot substitute mutable
/// login metadata for GitHub's stable numeric identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserPayload {
    /// Complete response body from the authenticated-user endpoint.
    pub body: Vec<u8>,
    /// Local Unix time in milliseconds at which the response was received.
    pub received_at_ms: u64,
}

/// Explicit failures at the HTTP adapter boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportError {
    /// Network transport failed or timed out.
    Network,
    /// GitHub rejected the request or token.
    Rejected,
    /// GitHub returned an unusable response.
    MalformedResponse,
}

/// Exchanges a GitHub authorization code.
pub trait TokenTransport {
    /// Sends the request through a confidential exchange broker.
    ///
    /// The broker owns the GitHub OAuth App client secret; neither the secret
    /// nor a direct mobile token exchange belongs in this crate.
    ///
    /// # Errors
    ///
    /// Returns a structured transport failure when exchange cannot complete.
    fn exchange(&mut self, request: TokenExchange<'_>) -> Result<AccessToken, TransportError>;
}

/// Fetches GitHub's authenticated user.
pub trait UserTransport {
    /// Calls the authenticated-user endpoint with the short-lived token.
    ///
    /// # Errors
    ///
    /// Returns a structured transport failure when lookup cannot complete.
    fn authenticated_user(&mut self, token: &AccessToken) -> Result<UserPayload, TransportError>;
}
