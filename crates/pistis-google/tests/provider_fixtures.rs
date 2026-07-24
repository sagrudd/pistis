use std::{fs, path::PathBuf};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use openssl::rsa::Rsa;
use pistis_google::{
    DiscoveryDocument, DiscoveryError, GOOGLE_DISCOVERY_URI, GOOGLE_ISSUER, JwkSet,
};
use pistis_identity::{
    BindingId, ExternalIdentity, FileIdentityBindingRepository, IdentityBinding,
    IdentityBindingRepository,
};
use serde::Serialize;

const DISCOVERY: &[u8] = include_bytes!("../../../fixtures/provider/google/discovery.json");
const WRONG_ISSUER: &[u8] =
    include_bytes!("../../../fixtures/provider/google/wrong-issuer-discovery.json");

#[test]
fn accepts_pinned_google_discovery_fixture() {
    let discovery = DiscoveryDocument::parse(DISCOVERY).expect("valid pinned discovery");
    assert_eq!(
        discovery.authorization_endpoint().host_str(),
        Some("accounts.google.com")
    );
    assert_eq!(GOOGLE_ISSUER, "https://accounts.google.com");
    assert_eq!(
        GOOGLE_DISCOVERY_URI,
        "https://accounts.google.com/.well-known/openid-configuration"
    );
}

#[derive(Serialize)]
struct Claims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    exp: u64,
    iat: u64,
    nonce: &'a str,
    email: &'a str,
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("pistis-google-integration-{}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn validated_subject_survives_repository_restart() {
    let key = Rsa::generate(2048).unwrap();
    let modulus = URL_SAFE_NO_PAD.encode(key.n().to_vec());
    let exponent = URL_SAFE_NO_PAD.encode(key.e().to_vec());
    let jwks = JwkSet::parse(
        format!(
            r#"{{"keys":[{{"kid":"integration","kty":"RSA","alg":"RS256","use":"sig","n":"{modulus}","e":"{exponent}"}}]}}"#
        )
        .as_bytes(),
    )
    .unwrap();
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("integration".into());
    let pem = key.private_key_to_pem().unwrap();
    let token = encode(
        &header,
        &Claims {
            iss: "accounts.google.com",
            sub: "109876543210987654321",
            aud: "mobile-client",
            exp: 2_000,
            iat: 1_000,
            nonce: "bound-nonce",
            email: "snapshot@example.test",
        },
        &EncodingKey::from_rsa_pem(&pem).unwrap(),
    )
    .unwrap();
    let validated = jwks
        .validate(&token, "mobile-client", "bound-nonce", 1_100, 60)
        .unwrap();

    let directory = TestDirectory::new();
    let path = directory.0.join("bindings.json");
    let binding = IdentityBinding {
        id: BindingId::from_bytes([44; 16]),
        identity: ExternalIdentity::Google(validated.identity),
        authenticated_at_ms: 1_000_000,
        refreshed_at_ms: 1_100_000,
    };
    FileIdentityBindingRepository::new(&path)
        .store(binding.clone())
        .unwrap();
    let reopened = FileIdentityBindingRepository::new(path);
    assert_eq!(reopened.get(binding.id), Ok(Some(binding)));
}

#[test]
fn rejects_wrong_issuer_fixture() {
    assert_eq!(
        DiscoveryDocument::parse(WRONG_ISSUER),
        Err(DiscoveryError::UnexpectedIssuer)
    );
}
