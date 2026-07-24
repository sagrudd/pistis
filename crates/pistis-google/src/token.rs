//! JWKS parsing and signed ID-token validation.

use std::collections::HashSet;

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use pistis_identity::{GoogleIdentity, GoogleIssuer, GoogleSubject, IdentityMetadata};
use serde::Deserialize;
#[cfg(test)]
use serde::Serialize;
use subtle::ConstantTimeEq;

use crate::GOOGLE_ISSUER;

/// A validated local snapshot of Google's public signing keys.
pub struct JwkSet {
    keys: Vec<Jwk>,
}

/// JWKS parsing failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JwksError {
    /// JSON structure is invalid or contains no usable RS256 keys.
    InvalidDocument,
}

/// ID-token structural or cryptographic rejection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdTokenError {
    /// JWT header or compact representation is invalid.
    Malformed,
    /// Only RS256 is accepted by this adapter.
    UnsupportedAlgorithm,
    /// The signing key ID is absent or not present in the current JWKS.
    RefreshSigningKeys,
    /// The signature is invalid.
    InvalidSignature,
    /// A required claim is absent or malformed.
    InvalidClaims,
}

/// Semantic validation failure after signature verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValidationError {
    /// Token/JWKS validation failed.
    Token(IdTokenError),
    /// Issuer is not a Google-defined value.
    Issuer,
    /// Client ID is not in the audience.
    Audience,
    /// Authorized party is absent or incorrect where required.
    AuthorizedParty,
    /// Nonce does not match the originating request.
    Nonce,
    /// Token is expired.
    Expired,
    /// Token was issued implausibly far in the future.
    IssuedInFuture,
    /// Issue time is not before token expiry.
    InvalidTimeRange,
    /// Subject is invalid.
    Subject,
}

/// Evidence retained from local ID-token validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenValidation {
    /// ID of the signing key used.
    pub key_id: String,
    /// Token issue time as Unix seconds.
    pub issued_at: u64,
    /// Token expiry as Unix seconds.
    pub expires_at: u64,
}

/// Provider identity and validation evidence ready for durable binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedGoogleIdentity {
    /// Stable provider-neutral identity value.
    pub identity: GoogleIdentity,
    /// Local cryptographic validation record.
    pub validation: TokenValidation,
    /// Hosted-domain claim snapshot; never part of the identity key.
    pub hosted_domain: Option<String>,
}

#[derive(Deserialize)]
struct WireJwks {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kid: String,
    kty: String,
    n: String,
    e: String,
    #[serde(rename = "use")]
    usage: Option<String>,
    alg: Option<String>,
}

#[derive(Deserialize)]
#[cfg_attr(test, derive(Clone, Serialize))]
struct Claims {
    iss: String,
    sub: String,
    aud: Audience,
    azp: Option<String>,
    exp: u64,
    iat: u64,
    nonce: String,
    name: Option<String>,
    email: Option<String>,
    hd: Option<String>,
}

#[derive(Deserialize)]
#[cfg_attr(test, derive(Clone, Serialize))]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::{EncodingKey, Header, encode};
    use openssl::{pkey::Private, rsa::Rsa};

    use super::*;

    fn test_key() -> Rsa<Private> {
        Rsa::generate(2048).unwrap()
    }

    fn keys(key: &Rsa<Private>, kid: &str) -> JwkSet {
        let modulus = URL_SAFE_NO_PAD.encode(key.n().to_vec());
        let exponent = URL_SAFE_NO_PAD.encode(key.e().to_vec());
        JwkSet::parse(
            format!(
                r#"{{"keys":[{{"kid":"{kid}","kty":"RSA","alg":"RS256","use":"sig","n":"{modulus}","e":"{exponent}"}}]}}"#
            )
            .as_bytes(),
        )
        .unwrap()
    }

    fn claims() -> Claims {
        Claims {
            iss: "accounts.google.com".into(),
            sub: "109876543210987654321".into(),
            aud: Audience::One("mobile-client".into()),
            azp: None,
            exp: 2_000,
            iat: 1_000,
            nonce: "expected-nonce".into(),
            name: Some("Test User".into()),
            email: Some("before@example.test".into()),
            hd: Some("example.test".into()),
        }
    }

    fn sign(key: &Rsa<Private>, claims: &Claims, kid: &str) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.into());
        let pem = key.private_key_to_pem().unwrap();
        encode(&header, claims, &EncodingKey::from_rsa_pem(&pem).unwrap()).unwrap()
    }

    #[test]
    fn validates_rs256_and_canonicalizes_legacy_issuer() {
        let key = test_key();
        let validated = keys(&key, "current")
            .validate(
                &sign(&key, &claims(), "current"),
                "mobile-client",
                "expected-nonce",
                1_100,
                60,
            )
            .unwrap();
        assert_eq!(validated.identity.issuer.as_str(), GOOGLE_ISSUER);
        assert_eq!(validated.identity.subject.as_str(), "109876543210987654321");
        assert_eq!(validated.hosted_domain.as_deref(), Some("example.test"));
    }

    #[test]
    fn rejects_wrong_audience_nonce_expiry_and_future_issue_time() {
        let key = test_key();
        let set = keys(&key, "current");
        let mut changed = claims();
        changed.aud = Audience::One("other-client".into());
        assert_eq!(
            set.validate(
                &sign(&key, &changed, "current"),
                "mobile-client",
                "expected-nonce",
                1_100,
                60
            ),
            Err(ValidationError::Audience)
        );
        assert_eq!(
            set.validate(
                &sign(&key, &claims(), "current"),
                "mobile-client",
                "wrong",
                1_100,
                60
            ),
            Err(ValidationError::Nonce)
        );
        assert_eq!(
            set.validate(
                &sign(&key, &claims(), "current"),
                "mobile-client",
                "expected-nonce",
                2_000,
                60
            ),
            Err(ValidationError::Expired)
        );
        assert_eq!(
            set.validate(
                &sign(&key, &claims(), "current"),
                "mobile-client",
                "expected-nonce",
                900,
                60
            ),
            Err(ValidationError::IssuedInFuture)
        );
    }

    #[test]
    fn enforces_azp_for_multiple_audiences() {
        let key = test_key();
        let mut changed = claims();
        changed.aud = Audience::Many(vec!["mobile-client".into(), "other-client".into()]);
        assert_eq!(
            keys(&key, "current").validate(
                &sign(&key, &changed, "current"),
                "mobile-client",
                "expected-nonce",
                1_100,
                60
            ),
            Err(ValidationError::AuthorizedParty)
        );
        changed.azp = Some("mobile-client".into());
        assert!(
            keys(&key, "current")
                .validate(
                    &sign(&key, &changed, "current"),
                    "mobile-client",
                    "expected-nonce",
                    1_100,
                    60
                )
                .is_ok()
        );
    }

    #[test]
    fn unknown_kid_requests_jwks_refresh() {
        let key = test_key();
        assert_eq!(
            keys(&key, "old").validate(
                &sign(&key, &claims(), "new"),
                "mobile-client",
                "expected-nonce",
                1_100,
                60
            ),
            Err(ValidationError::Token(IdTokenError::RefreshSigningKeys))
        );
        assert!(
            keys(&key, "new")
                .validate(
                    &sign(&key, &claims(), "new"),
                    "mobile-client",
                    "expected-nonce",
                    1_100,
                    60
                )
                .is_ok()
        );
    }

    #[test]
    fn rejects_empty_validation_inputs_and_duplicate_key_ids() {
        let key = test_key();
        let set = keys(&key, "current");
        let token = sign(&key, &claims(), "current");
        assert_eq!(
            set.validate(&token, "", "expected-nonce", 1_100, 60),
            Err(ValidationError::Audience)
        );
        assert_eq!(
            set.validate(&token, "mobile-client", "", 1_100, 60),
            Err(ValidationError::Nonce)
        );
        assert!(matches!(
            JwkSet::parse(
                br#"{"keys":[
                    {"kid":"duplicate","kty":"RSA","alg":"RS256","n":"one","e":"AQAB"},
                    {"kid":"duplicate","kty":"RSA","alg":"RS256","n":"two","e":"AQAB"}
                ]}"#
            ),
            Err(JwksError::InvalidDocument)
        ));
    }

    #[test]
    fn rejects_issue_time_at_or_after_expiry() {
        let key = test_key();
        let set = keys(&key, "current");
        for issued_at in [2_000, 2_001] {
            let mut changed = claims();
            changed.iat = issued_at;
            assert_eq!(
                set.validate(
                    &sign(&key, &changed, "current"),
                    "mobile-client",
                    "expected-nonce",
                    1_100,
                    60
                ),
                Err(ValidationError::InvalidTimeRange)
            );
        }
    }
}

impl JwkSet {
    /// Parses a JWKS document, retaining only structurally valid RS256 keys.
    ///
    /// # Errors
    ///
    /// Returns [`JwksError::InvalidDocument`] for malformed or empty input.
    pub fn parse(input: &[u8]) -> Result<Self, JwksError> {
        if input.len() > crate::MAX_PROVIDER_DOCUMENT_BYTES {
            return Err(JwksError::InvalidDocument);
        }
        let wire: WireJwks =
            serde_json::from_slice(input).map_err(|_| JwksError::InvalidDocument)?;
        let keys: Vec<_> = wire
            .keys
            .into_iter()
            .filter(|key| {
                key.kty == "RSA"
                    && key.alg.as_deref().is_none_or(|alg| alg == "RS256")
                    && key.usage.as_deref().is_none_or(|usage| usage == "sig")
                    && !key.kid.is_empty()
                    && !key.n.is_empty()
                    && !key.e.is_empty()
            })
            .collect();
        let unique_key_ids: HashSet<_> = keys.iter().map(|key| key.kid.as_str()).collect();
        if keys.is_empty() || unique_key_ids.len() != keys.len() {
            return Err(JwksError::InvalidDocument);
        }
        Ok(Self { keys })
    }

    /// Verifies and validates an ID token entirely locally.
    ///
    /// `now` is supplied by trusted caller time for deterministic policy.
    /// `future_iat_tolerance` bounds clock skew; expiry has no grace period.
    ///
    /// # Errors
    ///
    /// Returns a structured failure without producing a partially trusted
    /// identity. An unknown key ID requests one JWKS refresh and retry.
    pub fn validate(
        &self,
        token: &str,
        client_id: &str,
        expected_nonce: &str,
        now: u64,
        future_iat_tolerance: u64,
    ) -> Result<ValidatedGoogleIdentity, ValidationError> {
        if client_id.is_empty() {
            return Err(ValidationError::Audience);
        }
        if expected_nonce.is_empty() {
            return Err(ValidationError::Nonce);
        }
        let header =
            decode_header(token).map_err(|_| ValidationError::Token(IdTokenError::Malformed))?;
        if header.alg != Algorithm::RS256 {
            return Err(ValidationError::Token(IdTokenError::UnsupportedAlgorithm));
        }
        let kid = header
            .kid
            .ok_or(ValidationError::Token(IdTokenError::RefreshSigningKeys))?;
        let key = self
            .keys
            .iter()
            .find(|key| key.kid == kid)
            .ok_or(ValidationError::Token(IdTokenError::RefreshSigningKeys))?;
        let decoding_key = DecodingKey::from_rsa_components(&key.n, &key.e)
            .map_err(|_| ValidationError::Token(IdTokenError::InvalidClaims))?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = false;
        validation.validate_aud = false;
        validation.required_spec_claims =
            HashSet::from_iter(["exp".into(), "iat".into(), "iss".into(), "sub".into()]);
        let claims = decode::<Claims>(token, &decoding_key, &validation)
            .map_err(|_| ValidationError::Token(IdTokenError::InvalidSignature))?
            .claims;

        if claims.iss != GOOGLE_ISSUER && claims.iss != "accounts.google.com" {
            return Err(ValidationError::Issuer);
        }
        let (audience_matches, audience_count) = match &claims.aud {
            Audience::One(value) => (value == client_id, 1),
            Audience::Many(values) => (values.iter().any(|value| value == client_id), values.len()),
        };
        if !audience_matches {
            return Err(ValidationError::Audience);
        }
        if audience_count > 1 && claims.azp.as_deref() != Some(client_id)
            || claims
                .azp
                .as_deref()
                .is_some_and(|party| party != client_id)
        {
            return Err(ValidationError::AuthorizedParty);
        }
        if claims.nonce.len() != expected_nonce.len()
            || !bool::from(claims.nonce.as_bytes().ct_eq(expected_nonce.as_bytes()))
        {
            return Err(ValidationError::Nonce);
        }
        if claims.iat >= claims.exp {
            return Err(ValidationError::InvalidTimeRange);
        }
        if claims.exp <= now {
            return Err(ValidationError::Expired);
        }
        if claims.iat > now.saturating_add(future_iat_tolerance) {
            return Err(ValidationError::IssuedInFuture);
        }

        let issuer = GoogleIssuer::new(GOOGLE_ISSUER).map_err(|_| ValidationError::Issuer)?;
        let subject = GoogleSubject::new(claims.sub).map_err(|_| ValidationError::Subject)?;
        Ok(ValidatedGoogleIdentity {
            identity: GoogleIdentity {
                issuer,
                subject,
                metadata: IdentityMetadata {
                    login: None,
                    display_name: claims.name,
                    email: claims.email,
                    profile_url: None,
                },
            },
            validation: TokenValidation {
                key_id: kid,
                issued_at: claims.iat,
                expires_at: claims.exp,
            },
            hosted_domain: claims.hd,
        })
    }
}
