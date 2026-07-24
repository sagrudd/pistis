use pistis_github::{
    AccessToken, EntropyError, EntropySource, GitHubOAuth, OAuthAppConfig, OAuthError, Pkce, State,
    TokenExchange, TokenTransport, TransportError, UserPayload, UserTransport,
};
use pistis_identity::{
    BindingId, ExternalIdentity, FileIdentityBindingRepository, GitHubIdentity, GitHubSubject,
    IdentityBinding, IdentityBindingRepository, IdentityMetadata, StoreOutcome,
};
use std::{fs, path::PathBuf};

struct FixedEntropy;

impl EntropySource for FixedEntropy {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        destination.fill(19);
        Ok(())
    }
}

struct Token;

impl TokenTransport for Token {
    fn exchange(&mut self, _: TokenExchange<'_>) -> Result<AccessToken, TransportError> {
        AccessToken::new("test-only-token")
    }
}

struct User<'a>(&'a [u8]);

impl UserTransport for User<'_> {
    fn authenticated_user(&mut self, _: &AccessToken) -> Result<UserPayload, TransportError> {
        Ok(UserPayload {
            body: self.0.to_vec(),
            received_at_ms: 123,
        })
    }
}

fn complete(body: &[u8]) -> Result<pistis_github::AuthenticatedGitHubIdentity, OAuthError> {
    let oauth =
        GitHubOAuth::new(OAuthAppConfig::new_brokered("fixture", "pistis:/github").unwrap());
    let state = State::generate(&mut FixedEntropy).unwrap();
    let pkce = Pkce::generate(&mut FixedEntropy).unwrap();
    let callback = oauth
        .validate_callback(&state, Some(&state.expose()), Some("code"), None)
        .unwrap();
    oauth.complete(callback, pkce.into_verifier(), &mut Token, &mut User(body))
}

#[test]
fn accepts_stable_numeric_subject_from_authenticated_user_fixture() {
    let identity = complete(include_bytes!(
        "../../../fixtures/provider/github/authenticated-user.json"
    ))
    .unwrap();
    assert_eq!(identity.subject, 42_424_242);
    assert_eq!(identity.login, "pistis-fixture-user");
    assert_eq!(identity.authenticated_at_ms, 123);
}

#[test]
fn rejects_non_positive_missing_and_non_integer_subjects() {
    for fixture in [
        include_bytes!("../../../fixtures/provider/github/negative-id.json").as_slice(),
        include_bytes!("../../../fixtures/provider/github/missing-id.json").as_slice(),
        include_bytes!("../../../fixtures/provider/github/string-id.json").as_slice(),
        include_bytes!("../../../fixtures/provider/github/fractional-id.json").as_slice(),
        br#"{"id":0,"login":"fixture"}"#,
        br#"{"id":18446744073709551616,"login":"fixture"}"#,
    ] {
        assert_eq!(complete(fixture), Err(OAuthError::InvalidUserId));
    }
}

#[test]
fn rejects_malformed_and_non_object_responses() {
    assert_eq!(
        complete(b"not-json"),
        Err(OAuthError::MalformedUserResponse)
    );
    assert_eq!(complete(b"[]"), Err(OAuthError::MalformedUserResponse));
}

#[test]
fn completed_identity_is_durably_bound_by_stable_subject() {
    let identity = complete(include_bytes!(
        "../../../fixtures/provider/github/authenticated-user.json"
    ))
    .unwrap();
    let directory = TestDirectory::new();
    let path = directory.path.join("bindings.json");
    let binding = IdentityBinding {
        id: BindingId::from_bytes([3; 16]),
        identity: ExternalIdentity::GitHub(GitHubIdentity {
            subject: GitHubSubject::new(identity.subject).unwrap(),
            metadata: IdentityMetadata {
                login: Some(identity.login),
                email: identity.email,
                display_name: identity.display_name,
                profile_url: identity.profile_url,
            },
        }),
        authenticated_at_ms: identity.authenticated_at_ms,
        refreshed_at_ms: identity.authenticated_at_ms,
    };

    assert_eq!(
        FileIdentityBindingRepository::new(&path).store(binding.clone()),
        Ok(StoreOutcome::Inserted)
    );
    assert_eq!(
        FileIdentityBindingRepository::new(path).get(binding.id),
        Ok(Some(binding))
    );
}

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("pistis-github-integration-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).unwrap();
        Self { path }
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).unwrap();
    }
}
