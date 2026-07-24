//! Authorization request and callback orchestration.

use crate::{
    OAuthAppConfig, Pkce, PkceVerifier, State, TokenExchange, TokenTransport, TransportError,
    UserTransport,
};
use serde_json::Value;
use zeroize::Zeroize;

/// GitHub authorization endpoint.
pub const AUTHORIZE_ENDPOINT: &str = "https://github.com/login/oauth/authorize";
/// GitHub access-token endpoint.
pub const TOKEN_ENDPOINT: &str = "https://github.com/login/oauth/access_token";
/// GitHub authenticated-user endpoint.
pub const USER_ENDPOINT: &str = "https://api.github.com/user";

/// Values to send through the system browser to GitHub.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationRequest {
    /// GitHub OAuth application client identifier.
    pub client_id: String,
    /// Exact registered callback URI.
    pub redirect_uri: String,
    /// Single-use CSRF correlation value.
    pub state: String,
    /// PKCE S256 challenge.
    pub code_challenge: String,
    /// PKCE method; always `S256`.
    pub code_challenge_method: &'static str,
    /// Requested OAuth scopes; empty is GitHub's minimal public identity access.
    pub scopes: Vec<String>,
}

/// Validated browser callback fields.
#[derive(Eq, PartialEq)]
pub struct Callback {
    code: String,
}

impl core::fmt::Debug for Callback {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("Callback").finish_non_exhaustive()
    }
}

impl Drop for Callback {
    fn drop(&mut self) {
        self.code.zeroize();
    }
}

/// Provider-declared authorization failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderError {
    /// OAuth error code returned by GitHub.
    pub code: String,
    /// Optional human-readable description.
    pub description: Option<String>,
}

/// Callback rejection reason.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CallbackError {
    /// State is missing or does not match the initiating request.
    InvalidState,
    /// GitHub returned an OAuth error instead of an authorization code.
    Provider(ProviderError),
    /// Neither a non-empty code nor a provider error was present.
    MissingCode,
}

/// Completed, authenticated GitHub identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedGitHubIdentity {
    /// Stable provider subject; never substitute login or email.
    pub subject: u64,
    /// Mutable login snapshot for display only.
    pub login: String,
    /// Optional provider display-name snapshot.
    pub display_name: Option<String>,
    /// Optional profile URI metadata.
    pub profile_url: Option<String>,
    /// Optional consented email snapshot.
    pub email: Option<String>,
    /// Local response receipt time in Unix milliseconds.
    pub authenticated_at_ms: u64,
}

/// Complete-flow failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OAuthError {
    /// Token exchange failed.
    TokenExchange(TransportError),
    /// Authenticated-user retrieval failed.
    UserLookup(TransportError),
    /// GitHub returned the invalid sentinel user identifier zero.
    InvalidUserId,
    /// GitHub returned no login metadata.
    MissingLogin,
    /// GitHub's authenticated-user response was not valid JSON.
    MalformedUserResponse,
}

/// Stateless GitHub OAuth protocol adapter.
pub struct GitHubOAuth {
    config: OAuthAppConfig,
}

impl GitHubOAuth {
    /// Creates an adapter for one registered OAuth application.
    #[must_use]
    pub fn new(config: OAuthAppConfig) -> Self {
        Self { config }
    }

    /// Returns browser request parameters.
    ///
    /// No `scope` parameter is emitted. GitHub's default, read-only public
    /// identity access is sufficient for stable account identification.
    #[must_use]
    pub fn authorization_request(&self, pkce: &Pkce, state: &State) -> AuthorizationRequest {
        AuthorizationRequest {
            client_id: self.config.client_id().to_owned(),
            redirect_uri: self.config.callback_uri().to_owned(),
            state: state.expose(),
            code_challenge: pkce.challenge().to_owned(),
            code_challenge_method: "S256",
            scopes: Vec::new(),
        }
    }

    /// Validates CSRF correlation before accepting callback content.
    ///
    /// # Errors
    ///
    /// Returns [`CallbackError`] when state, provider response, or code fails
    /// validation.
    pub fn validate_callback(
        &self,
        expected_state: &State,
        state: Option<&str>,
        code: Option<&str>,
        provider_error: Option<ProviderError>,
    ) -> Result<Callback, CallbackError> {
        if !state.is_some_and(|candidate| expected_state.matches(candidate)) {
            return Err(CallbackError::InvalidState);
        }
        if let Some(error) = provider_error {
            return Err(CallbackError::Provider(error));
        }
        let code = code
            .filter(|value| !value.is_empty())
            .ok_or(CallbackError::MissingCode)?;
        Ok(Callback {
            code: code.to_owned(),
        })
    }

    /// Exchanges the code and immediately resolves the authenticated user.
    ///
    /// The token is dropped on return and cannot be included in the result.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthError`] for transport failures or an invalid provider
    /// identity response.
    pub fn complete(
        &self,
        callback: Callback,
        verifier: PkceVerifier,
        token_transport: &mut impl TokenTransport,
        user_transport: &mut impl UserTransport,
    ) -> Result<AuthenticatedGitHubIdentity, OAuthError> {
        let token = token_transport
            .exchange(TokenExchange {
                client_id: self.config.client_id(),
                redirect_uri: self.config.callback_uri(),
                code: &callback.code,
                code_verifier: verifier.into_exposed(),
            })
            .map_err(OAuthError::TokenExchange)?;
        drop(callback);
        let user = user_transport
            .authenticated_user(&token)
            .map_err(OAuthError::UserLookup)?;
        let value: Value =
            serde_json::from_slice(&user.body).map_err(|_| OAuthError::MalformedUserResponse)?;
        let object = value.as_object().ok_or(OAuthError::MalformedUserResponse)?;
        let subject = object
            .get("id")
            .and_then(Value::as_u64)
            .ok_or(OAuthError::InvalidUserId)?;
        if subject == 0 {
            return Err(OAuthError::InvalidUserId);
        }
        let login = object
            .get("login")
            .and_then(Value::as_str)
            .filter(|login| !login.is_empty())
            .ok_or(OAuthError::MissingLogin)?;
        let optional_string = |name| object.get(name).and_then(Value::as_str).map(str::to_owned);
        Ok(AuthenticatedGitHubIdentity {
            subject,
            login: login.to_owned(),
            display_name: optional_string("name"),
            profile_url: optional_string("html_url"),
            email: optional_string("email"),
            authenticated_at_ms: user.received_at_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccessToken, EntropyError, EntropySource, UserPayload};

    struct FixedEntropy;
    impl EntropySource for FixedEntropy {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
            destination.fill(42);
            Ok(())
        }
    }

    struct MockToken {
        saw_s256_verifier: bool,
    }
    impl TokenTransport for MockToken {
        fn exchange(&mut self, request: TokenExchange<'_>) -> Result<AccessToken, TransportError> {
            self.saw_s256_verifier = request.code == "one-use-code"
                && request.code_verifier.len() == 43
                && request.client_id == "client";
            AccessToken::new("short-lived")
        }
    }

    struct MockUser {
        token_seen: bool,
        body: Vec<u8>,
    }
    impl UserTransport for MockUser {
        fn authenticated_user(
            &mut self,
            token: &AccessToken,
        ) -> Result<UserPayload, TransportError> {
            self.token_seen = token.expose() == "short-lived";
            Ok(UserPayload {
                body: self.body.clone(),
                received_at_ms: 1_700_000_000_000,
            })
        }
    }

    fn adapter() -> GitHubOAuth {
        GitHubOAuth::new(OAuthAppConfig::new_brokered("client", "pistis:/github").unwrap())
    }

    #[test]
    fn callback_fails_closed_before_code_acceptance() {
        let state = State::generate(&mut FixedEntropy).unwrap();
        assert_eq!(
            adapter().validate_callback(&state, Some("attacker"), Some("code"), None),
            Err(CallbackError::InvalidState)
        );
        assert_eq!(
            adapter().validate_callback(&state, Some(&state.expose()), None, None),
            Err(CallbackError::MissingCode)
        );
    }

    #[test]
    fn minimal_authorization_request_uses_pkce_and_no_scope() {
        let state = State::generate(&mut FixedEntropy).unwrap();
        let pkce = Pkce::generate(&mut FixedEntropy).unwrap();
        let request = adapter().authorization_request(&pkce, &state);
        assert_eq!(request.code_challenge, pkce.challenge());
        assert_eq!(request.state, state.expose());
        assert_eq!(request.code_challenge_method, "S256");
        assert!(request.scopes.is_empty());
    }

    #[test]
    fn mock_transports_complete_identity_without_returning_token() {
        let state = State::generate(&mut FixedEntropy).unwrap();
        let pkce = Pkce::generate(&mut FixedEntropy).unwrap();
        let callback = adapter()
            .validate_callback(&state, Some(&state.expose()), Some("one-use-code"), None)
            .unwrap();
        let mut tokens = MockToken {
            saw_s256_verifier: false,
        };
        let mut users = MockUser {
            token_seen: false,
            body: br#"{"id":12345678,"login":"renamable-login"}"#.to_vec(),
        };
        let identity = adapter()
            .complete(callback, pkce.into_verifier(), &mut tokens, &mut users)
            .unwrap();
        assert_eq!(identity.subject, 12_345_678);
        assert!(tokens.saw_s256_verifier);
        assert!(users.token_seen);
    }

    #[test]
    fn rejects_zero_stable_user_identifier() {
        let state = State::generate(&mut FixedEntropy).unwrap();
        let pkce = Pkce::generate(&mut FixedEntropy).unwrap();
        let callback = adapter()
            .validate_callback(&state, Some(&state.expose()), Some("code"), None)
            .unwrap();
        let mut tokens = MockToken {
            saw_s256_verifier: false,
        };
        let mut users = MockUser {
            token_seen: false,
            body: br#"{"id":0,"login":"login"}"#.to_vec(),
        };
        assert_eq!(
            adapter().complete(callback, pkce.into_verifier(), &mut tokens, &mut users),
            Err(OAuthError::InvalidUserId)
        );
    }
}
