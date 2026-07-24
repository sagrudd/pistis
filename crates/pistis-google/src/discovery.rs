//! Validation of Google discovery metadata.

use serde::Deserialize;
use url::Url;

/// Canonical Google identity issuer.
pub const GOOGLE_ISSUER: &str = "https://accounts.google.com";
/// Fixed URL from which transport adapters fetch Google discovery metadata.
pub const GOOGLE_DISCOVERY_URI: &str =
    "https://accounts.google.com/.well-known/openid-configuration";
const AUTHORIZATION_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const JWKS_URI: &str = "https://www.googleapis.com/oauth2/v3/certs";

/// Validated endpoints and capabilities used by enrolment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryDocument {
    authorization_endpoint: Url,
    token_endpoint: Url,
    jwks_uri: Url,
}

/// Rejection reason for untrusted discovery metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiscoveryError {
    /// The document is not valid JSON with required fields.
    InvalidDocument,
    /// The issuer is not either Google-defined spelling.
    UnexpectedIssuer,
    /// An endpoint is not an HTTPS URL.
    InsecureEndpoint(&'static str),
    /// An endpoint differs from the reviewed Google endpoint.
    UnexpectedEndpoint(&'static str),
    /// Authorization-code flow is not advertised.
    AuthorizationCodeUnsupported,
    /// S256 PKCE is not advertised.
    PkceS256Unsupported,
    /// RS256 ID-token signatures are not advertised.
    Rs256Unsupported,
}

#[derive(Deserialize)]
struct WireDocument {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    response_types_supported: Vec<String>,
    grant_types_supported: Option<Vec<String>>,
    code_challenge_methods_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
}

impl DiscoveryDocument {
    /// Parses and validates a Google discovery document.
    ///
    /// # Errors
    ///
    /// Returns an error if the issuer, endpoints, or required capabilities
    /// cannot be trusted by the adapter.
    pub fn parse(input: &[u8]) -> Result<Self, DiscoveryError> {
        let wire: WireDocument =
            serde_json::from_slice(input).map_err(|_| DiscoveryError::InvalidDocument)?;
        if wire.issuer != GOOGLE_ISSUER && wire.issuer != "accounts.google.com" {
            return Err(DiscoveryError::UnexpectedIssuer);
        }
        if !wire.response_types_supported.iter().any(|v| v == "code")
            || wire
                .grant_types_supported
                .as_ref()
                .is_some_and(|values| !values.iter().any(|v| v == "authorization_code"))
        {
            return Err(DiscoveryError::AuthorizationCodeUnsupported);
        }
        if !wire
            .code_challenge_methods_supported
            .iter()
            .any(|v| v == "S256")
        {
            return Err(DiscoveryError::PkceS256Unsupported);
        }
        if !wire
            .id_token_signing_alg_values_supported
            .iter()
            .any(|v| v == "RS256")
        {
            return Err(DiscoveryError::Rs256Unsupported);
        }
        Ok(Self {
            authorization_endpoint: pinned_url(
                &wire.authorization_endpoint,
                AUTHORIZATION_ENDPOINT,
                "authorization_endpoint",
            )?,
            token_endpoint: pinned_url(&wire.token_endpoint, TOKEN_ENDPOINT, "token_endpoint")?,
            jwks_uri: pinned_url(&wire.jwks_uri, JWKS_URI, "jwks_uri")?,
        })
    }

    /// Returns the validated authorization endpoint.
    #[must_use]
    pub fn authorization_endpoint(&self) -> &Url {
        &self.authorization_endpoint
    }

    /// Returns the validated token endpoint.
    #[must_use]
    pub fn token_endpoint(&self) -> &Url {
        &self.token_endpoint
    }

    /// Returns the validated JSON Web Key Set endpoint.
    #[must_use]
    pub fn jwks_uri(&self) -> &Url {
        &self.jwks_uri
    }
}

fn pinned_url(value: &str, expected: &str, field: &'static str) -> Result<Url, DiscoveryError> {
    let parsed = Url::parse(value).map_err(|_| DiscoveryError::InvalidDocument)?;
    if parsed.scheme() != "https" || parsed.host_str().is_none() {
        return Err(DiscoveryError::InsecureEndpoint(field));
    }
    if parsed.as_str() != expected {
        return Err(DiscoveryError::UnexpectedEndpoint(field));
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(issuer: &str) -> Vec<u8> {
        format!(
            r#"{{"issuer":"{issuer}","authorization_endpoint":"https://accounts.google.com/o/oauth2/v2/auth","token_endpoint":"https://oauth2.googleapis.com/token","jwks_uri":"https://www.googleapis.com/oauth2/v3/certs","response_types_supported":["code"],"grant_types_supported":["authorization_code"],"code_challenge_methods_supported":["S256"],"id_token_signing_alg_values_supported":["RS256"]}}"#
        )
        .into_bytes()
    }

    #[test]
    fn accepts_both_google_issuer_spellings() {
        assert!(DiscoveryDocument::parse(&metadata(GOOGLE_ISSUER)).is_ok());
        assert!(DiscoveryDocument::parse(&metadata("accounts.google.com")).is_ok());
    }

    #[test]
    fn rejects_non_google_issuer() {
        assert_eq!(
            DiscoveryDocument::parse(&metadata("https://attacker.invalid")),
            Err(DiscoveryError::UnexpectedIssuer)
        );
    }
}
