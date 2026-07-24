//! OAuth application registration contract.

/// GitHub OAuth application configuration supplied by the platform.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OAuthAppConfig {
    client_id: String,
    callback_uri: String,
}

/// Invalid OAuth application configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    /// The GitHub client identifier is empty.
    EmptyClientId,
    /// The callback is not an absolute URI.
    InvalidCallbackUri,
    /// A URL fragment would make callback matching ambiguous.
    CallbackHasFragment,
}

impl OAuthAppConfig {
    /// Creates a configuration whose token transport is a confidential broker.
    ///
    /// GitHub OAuth Apps require a client secret at token exchange even when
    /// PKCE is used. This adapter therefore requires the supplied
    /// [`crate::TokenTransport`] to cross a trusted broker boundary that holds
    /// the secret. Client secrets are intentionally unsupported here because
    /// an installed application cannot keep them confidential.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when the client ID or callback contract is
    /// incomplete or ambiguous.
    pub fn new_brokered(
        client_id: impl Into<String>,
        callback_uri: impl Into<String>,
    ) -> Result<Self, ConfigError> {
        let client_id = client_id.into();
        let callback_uri = callback_uri.into();
        if client_id.trim().is_empty() {
            return Err(ConfigError::EmptyClientId);
        }
        if callback_uri.contains('#') {
            return Err(ConfigError::CallbackHasFragment);
        }
        let Some((scheme, remainder)) = callback_uri.split_once(':') else {
            return Err(ConfigError::InvalidCallbackUri);
        };
        if scheme.is_empty()
            || !scheme.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_alphabetic()
                    || (index > 0 && (byte.is_ascii_digit() || matches!(byte, b'+' | b'-' | b'.')))
            })
            || remainder.is_empty()
        {
            return Err(ConfigError::InvalidCallbackUri);
        }
        Ok(Self {
            client_id,
            callback_uri,
        })
    }

    /// GitHub OAuth application client identifier.
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Exact registered callback URI.
    #[must_use]
    pub fn callback_uri(&self) -> &str {
        &self.callback_uri
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_https_and_application_callback_schemes() {
        assert!(OAuthAppConfig::new_brokered("client", "https://example.test/callback").is_ok());
        assert!(OAuthAppConfig::new_brokered("client", "pistis:/oauth/github").is_ok());
    }

    #[test]
    fn rejects_ambiguous_or_incomplete_configuration() {
        assert_eq!(
            OAuthAppConfig::new_brokered(" ", "pistis:/callback"),
            Err(ConfigError::EmptyClientId)
        );
        assert_eq!(
            OAuthAppConfig::new_brokered("client", "/callback"),
            Err(ConfigError::InvalidCallbackUri)
        );
        assert_eq!(
            OAuthAppConfig::new_brokered("client", "pistis:/callback#fragment"),
            Err(ConfigError::CallbackHasFragment)
        );
    }
}
