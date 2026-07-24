//! Authorization-code flow correlation and PKCE secrets.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::DiscoveryDocument;

const SECRET_BYTES: usize = 32;

/// Supplies cryptographically secure random bytes.
pub trait EntropySource {
    /// Fills the destination from an operating-system CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns [`EntropyError`] when secure randomness is unavailable.
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), EntropyError>;
}

/// Secure entropy was unavailable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntropyError;

/// A browser authorization request safe to expose.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationRequest {
    /// Fully encoded system-browser URL.
    pub url: Url,
}

/// Optional identity metadata scopes requested during enrolment.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ClaimScopes {
    /// Request the mutable profile snapshot.
    pub profile: bool,
    /// Request the mutable email snapshot.
    pub email: bool,
}

/// The live secrets for one authorization attempt.
///
/// This type is intentionally neither `Clone` nor `Debug`.
pub struct AuthorizationAttempt {
    state: [u8; SECRET_BYTES],
    nonce: [u8; SECRET_BYTES],
    verifier: [u8; SECRET_BYTES],
    client_id: String,
    redirect_uri: Url,
}

/// Values received from the registered callback.
pub struct AuthorizationCallback {
    /// Single-use authorization code.
    pub code: Zeroizing<String>,
    /// Returned CSRF correlation value.
    pub state: String,
}

/// A secret-bearing token request.
///
/// This type is intentionally neither `Clone` nor `Debug`.
pub struct TokenRequest {
    /// Client ID bound when the browser request was created.
    pub client_id: String,
    /// Single-use authorization code.
    pub code: Zeroizing<String>,
    /// RFC 7636 verifier corresponding to the browser challenge.
    pub code_verifier: Zeroizing<String>,
    /// Exact registered redirect URI.
    pub redirect_uri: Url,
}

/// Failure to start or complete authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationError {
    /// Secure random generation failed.
    EntropyUnavailable,
    /// Callback state did not match the originating attempt.
    StateMismatch,
    /// Client ID must not be empty.
    EmptyClientId,
    /// Callback authorization code must not be empty.
    EmptyAuthorizationCode,
    /// Callback authorization code exceeded the bounded input size.
    OversizedAuthorizationCode,
}

impl Drop for AuthorizationAttempt {
    fn drop(&mut self) {
        self.state.zeroize();
        self.nonce.zeroize();
        self.verifier.zeroize();
    }
}

impl AuthorizationAttempt {
    /// Creates an authorization request with 256-bit state, nonce, and PKCE
    /// verifier values.
    ///
    /// The caller must open the returned URL in a system browser.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorizationError::EntropyUnavailable`] without returning a
    /// partial attempt if secure randomness cannot be obtained.
    pub fn start(
        discovery: &DiscoveryDocument,
        client_id: &str,
        redirect_uri: &Url,
        claim_scopes: ClaimScopes,
        entropy: &mut impl EntropySource,
    ) -> Result<(Self, AuthorizationRequest), AuthorizationError> {
        if client_id.is_empty() {
            return Err(AuthorizationError::EmptyClientId);
        }
        let mut secrets = [[0_u8; SECRET_BYTES]; 3];
        for secret in &mut secrets {
            if entropy.fill(secret).is_err() {
                secrets.zeroize();
                return Err(AuthorizationError::EntropyUnavailable);
            }
        }
        let [state, nonce, verifier] = secrets;
        let state_encoded = encode(&state);
        let nonce_encoded = encode(&nonce);
        let challenge = encode(&Sha256::digest(verifier));
        let mut url = discovery.authorization_endpoint().clone();
        let mut scopes = vec!["openid"];
        if claim_scopes.profile {
            scopes.push("profile");
        }
        if claim_scopes.email {
            scopes.push("email");
        }
        let scope = scopes.join(" ");
        url.query_pairs_mut()
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", redirect_uri.as_str())
            .append_pair("response_type", "code")
            .append_pair("scope", &scope)
            .append_pair("state", &state_encoded)
            .append_pair("nonce", &nonce_encoded)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        Ok((
            Self {
                state,
                nonce,
                verifier,
                client_id: client_id.to_owned(),
                redirect_uri: redirect_uri.clone(),
            },
            AuthorizationRequest { url },
        ))
    }

    /// Validates the callback and consumes the attempt into a token request.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorizationError::StateMismatch`] when the callback cannot
    /// be correlated in constant time.
    pub fn complete(
        self,
        callback: AuthorizationCallback,
    ) -> Result<(TokenRequest, Zeroizing<String>), AuthorizationError> {
        let expected = encode(&self.state);
        if expected.len() != callback.state.len()
            || !bool::from(expected.as_bytes().ct_eq(callback.state.as_bytes()))
        {
            return Err(AuthorizationError::StateMismatch);
        }
        if callback.code.is_empty() {
            return Err(AuthorizationError::EmptyAuthorizationCode);
        }
        if callback.code.len() > crate::MAX_AUTHORIZATION_CODE_BYTES {
            return Err(AuthorizationError::OversizedAuthorizationCode);
        }
        let nonce = Zeroizing::new(encode(&self.nonce));
        let verifier = Zeroizing::new(encode(&self.verifier));
        Ok((
            TokenRequest {
                client_id: self.client_id.clone(),
                code: callback.code,
                code_verifier: verifier,
                redirect_uri: self.redirect_uri.clone(),
            },
            nonce,
        ))
    }
}

fn encode(input: &[u8]) -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Entropy(u8);
    impl EntropySource for Entropy {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
            destination.fill(self.0);
            self.0 += 1;
            Ok(())
        }
    }

    fn discovery() -> DiscoveryDocument {
        DiscoveryDocument::parse(br#"{"issuer":"https://accounts.google.com","authorization_endpoint":"https://accounts.google.com/o/oauth2/v2/auth","token_endpoint":"https://oauth2.googleapis.com/token","jwks_uri":"https://www.googleapis.com/oauth2/v3/certs","response_types_supported":["code"],"grant_types_supported":["authorization_code"],"code_challenge_methods_supported":["S256"],"id_token_signing_alg_values_supported":["RS256"]}"#).unwrap()
    }

    #[test]
    fn request_uses_pkce_nonce_state_and_minimal_scope() {
        let redirect = Url::parse("com.example:/oauth").unwrap();
        let (_, request) = AuthorizationAttempt::start(
            &discovery(),
            "client",
            &redirect,
            ClaimScopes::default(),
            &mut Entropy(1),
        )
        .unwrap();
        let query: std::collections::HashMap<_, _> = request.url.query_pairs().collect();
        assert_eq!(query["scope"], "openid");
        assert_eq!(query["code_challenge_method"], "S256");
        assert_eq!(query["nonce"].len(), 43);
        assert_eq!(query["state"].len(), 43);
    }

    #[test]
    fn explicit_metadata_scopes_do_not_imply_each_other() {
        let redirect = Url::parse("com.example:/oauth").unwrap();
        let (_, email) = AuthorizationAttempt::start(
            &discovery(),
            "client",
            &redirect,
            ClaimScopes {
                profile: false,
                email: true,
            },
            &mut Entropy(1),
        )
        .unwrap();
        assert_eq!(
            email
                .url
                .query_pairs()
                .find(|(key, _)| key == "scope")
                .unwrap()
                .1,
            "openid email"
        );
    }

    #[test]
    fn binds_client_and_redirect_and_rejects_empty_inputs() {
        let redirect = Url::parse("com.example:/oauth").unwrap();
        assert!(matches!(
            AuthorizationAttempt::start(
                &discovery(),
                "",
                &redirect,
                ClaimScopes::default(),
                &mut Entropy(1)
            ),
            Err(AuthorizationError::EmptyClientId)
        ));

        let (attempt, request) = AuthorizationAttempt::start(
            &discovery(),
            "bound-client",
            &redirect,
            ClaimScopes::default(),
            &mut Entropy(1),
        )
        .unwrap();
        let state = request
            .url
            .query_pairs()
            .find(|(key, _)| key == "state")
            .unwrap()
            .1
            .into_owned();
        let (token, nonce) = attempt
            .complete(AuthorizationCallback {
                code: Zeroizing::new("code".into()),
                state,
            })
            .unwrap();
        assert_eq!(token.client_id, "bound-client");
        assert_eq!(token.redirect_uri, redirect);
        assert!(!nonce.is_empty());

        let (attempt, request) = AuthorizationAttempt::start(
            &discovery(),
            "client",
            &redirect,
            ClaimScopes::default(),
            &mut Entropy(4),
        )
        .unwrap();
        let state = request
            .url
            .query_pairs()
            .find(|(key, _)| key == "state")
            .unwrap()
            .1
            .into_owned();
        assert!(matches!(
            attempt.complete(AuthorizationCallback {
                code: Zeroizing::new(String::new()),
                state
            }),
            Err(AuthorizationError::EmptyAuthorizationCode)
        ));

        let (attempt, request) = AuthorizationAttempt::start(
            &discovery(),
            "client",
            &redirect,
            ClaimScopes::default(),
            &mut Entropy(7),
        )
        .unwrap();
        let state = request
            .url
            .query_pairs()
            .find(|(key, _)| key == "state")
            .unwrap()
            .1
            .into_owned();
        assert!(matches!(
            attempt.complete(AuthorizationCallback {
                code: Zeroizing::new("x".repeat(crate::MAX_AUTHORIZATION_CODE_BYTES + 1)),
                state
            }),
            Err(AuthorizationError::OversizedAuthorizationCode)
        ));
    }
}
