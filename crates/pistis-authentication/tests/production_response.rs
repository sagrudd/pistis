use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use pistis_authentication::{
    AuthenticationResponseCredential, AuthenticationResponseExpectation,
    AuthenticationResponseVerificationError as VerifyError, ChallengeDocument, Decision,
    UnixTimeMillis, encode_challenge, encode_response, verify_authentication_response,
};
use pistis_canonical::{Value, to_vec};
use pistis_cose::{decode, encode, signing_input};
use pistis_crypto::{PublicKey, derive_key_id, sha256};
use pistis_domain::{ChallengeId, DeviceId, ExternalIdentityId, InstallationId, KeyId, UserId};

const SECRET: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
];

struct Fixture {
    signing: SigningKey,
    credential: AuthenticationResponseCredential,
    challenge: ChallengeDocument,
    expected: AuthenticationResponseExpectation,
}

impl Fixture {
    fn new() -> Self {
        let signing = SigningKey::from_bytes((&SECRET).into()).unwrap();
        let encoded = signing.verifying_key().to_encoded_point(false);
        let public_key = PublicKey::from_sec1_bytes(encoded.as_bytes()).unwrap();
        let key_id = derive_key_id(&public_key);
        let challenge = ChallengeDocument {
            issued_at: UnixTimeMillis(1_000),
            expires_at: UnixTimeMillis(2_000),
            installation_id: InstallationId::from_bytes([1; 16]),
            installation_key_id: KeyId::from_bytes([2; 32]),
            challenge_id: ChallengeId::from_bytes([3; 16]),
            nonce: [4; 32],
            user_id: UserId::from_bytes([5; 16]),
            external_identity_id: ExternalIdentityId::from_bytes([6; 16]),
            audience: "jenkins.mnemosyne".into(),
            installation_name: "Jenkins".into(),
            local_username: "admin".into(),
            display_context_digest: [7; 32],
            installation_fingerprint: [8; 32],
            endpoint_hints: Vec::new(),
        };
        let challenge_digest = sha256(&encode_challenge(&challenge).unwrap()).into_bytes();
        let expected = AuthenticationResponseExpectation {
            now: UnixTimeMillis(1_500),
            challenge_issued_at: challenge.issued_at,
            challenge_expires_at: challenge.expires_at,
            installation_id: challenge.installation_id,
            challenge_id: challenge.challenge_id,
            challenge_digest,
            nonce_digest: sha256(&challenge.nonce).into_bytes(),
            user_id: challenge.user_id,
            external_identity_id: challenge.external_identity_id,
            device_id: DeviceId::from_bytes([9; 16]),
            audience: challenge.audience.clone(),
            binding_generation: 10,
            current_binding_generation: 10,
            policy_generation: 11,
            current_policy_generation: 11,
            revocation_generation: 12,
            current_revocation_generation: 12,
            response_consumed: false,
        };
        Self {
            signing,
            credential: AuthenticationResponseCredential {
                key_id,
                public_key,
                active: true,
            },
            challenge,
            expected,
        }
    }

    fn envelope(&self, decision: Decision) -> Vec<u8> {
        let payload = encode_response(
            &self.challenge,
            self.expected.device_id,
            self.credential.key_id,
            decision,
            UnixTimeMillis(1_200),
            UnixTimeMillis(1_250),
        )
        .unwrap();
        self.sign_payload(&payload)
    }

    fn sign_payload(&self, payload: &[u8]) -> Vec<u8> {
        let input = signing_input(payload, self.credential.key_id).unwrap();
        let signature: Signature = self.signing.sign(&input);
        let signature = signature.normalize_s().unwrap_or(signature);
        encode(payload, self.credential.key_id, &signature.to_bytes()).unwrap()
    }
}

#[test]
fn verifies_signed_approval_and_signed_denial_as_terminal_decisions() {
    let fixture = Fixture::new();
    for decision in [Decision::Approve, Decision::Deny] {
        let envelope = fixture.envelope(decision);
        let verified =
            verify_authentication_response(&envelope, &fixture.expected, &fixture.credential)
                .unwrap();
        assert_eq!(verified.decision, decision);
        assert_eq!(verified.user_id, fixture.expected.user_id);
        assert_eq!(verified.device_key_id, fixture.credential.key_id);
        assert_eq!(verified.audience, fixture.expected.audience);
        assert_eq!(verified.response_digest, sha256(&envelope).into_bytes());
    }
}

#[test]
fn rejects_every_authoritative_binding_substitution() {
    let fixture = Fixture::new();
    let envelope = fixture.envelope(Decision::Approve);

    let mutations: [fn(&mut AuthenticationResponseExpectation); 10] = [
        |value| value.installation_id = InstallationId::from_bytes([20; 16]),
        |value| value.challenge_id = ChallengeId::from_bytes([20; 16]),
        |value| value.challenge_digest = [20; 32],
        |value| value.nonce_digest = [20; 32],
        |value| value.user_id = UserId::from_bytes([20; 16]),
        |value| value.external_identity_id = ExternalIdentityId::from_bytes([20; 16]),
        |value| value.device_id = DeviceId::from_bytes([20; 16]),
        |value| value.current_binding_generation += 1,
        |value| value.current_policy_generation += 1,
        |value| value.current_revocation_generation += 1,
    ];
    for mutate in mutations {
        let mut changed = fixture.expected.clone();
        mutate(&mut changed);
        assert_eq!(
            verify_authentication_response(&envelope, &changed, &fixture.credential),
            Err(VerifyError::BindingMismatch)
        );
    }
}

#[test]
fn rejects_replay_expiry_inactive_and_key_substitution() {
    let fixture = Fixture::new();
    let envelope = fixture.envelope(Decision::Approve);

    let mut replayed = fixture.expected.clone();
    replayed.response_consumed = true;
    assert_eq!(
        verify_authentication_response(&envelope, &replayed, &fixture.credential),
        Err(VerifyError::Replayed)
    );

    let mut expired = fixture.expected.clone();
    expired.now = expired.challenge_expires_at;
    assert_eq!(
        verify_authentication_response(&envelope, &expired, &fixture.credential),
        Err(VerifyError::Expired)
    );

    let mut inactive = fixture.credential.clone();
    inactive.active = false;
    assert_eq!(
        verify_authentication_response(&envelope, &fixture.expected, &inactive),
        Err(VerifyError::InactiveCredential)
    );

    let signing = SigningKey::from_bytes((&[2_u8; 32]).into()).unwrap();
    let encoded = signing.verifying_key().to_encoded_point(false);
    let public_key = PublicKey::from_sec1_bytes(encoded.as_bytes()).unwrap();
    let substituted = AuthenticationResponseCredential {
        key_id: derive_key_id(&public_key),
        public_key,
        active: true,
    };
    assert_eq!(
        verify_authentication_response(&envelope, &fixture.expected, &substituted),
        Err(VerifyError::InvalidResponse)
    );
}

#[test]
fn rejects_malformed_unknown_field_invalid_signature_and_oversize() {
    let fixture = Fixture::new();
    let envelope = fixture.envelope(Decision::Approve);
    let sign1 = decode(&envelope).unwrap();

    let Value::Map(mut fields) = pistis_canonical::from_slice(sign1.payload()).unwrap() else {
        unreachable!()
    };
    fields.insert(99, Value::Bool(true));
    let unknown = fixture.sign_payload(&to_vec(&Value::Map(fields)).unwrap());

    let mut invalid_signature = *sign1.signature();
    invalid_signature[0] ^= 1;
    let invalid_signature = encode(sign1.payload(), sign1.key_id(), &invalid_signature).unwrap();

    let low = Signature::from_slice(sign1.signature()).unwrap();
    let high = Signature::from_scalars(low.r().to_bytes(), (-low.s()).to_bytes()).unwrap();
    let high_s = encode(sign1.payload(), sign1.key_id(), &high.to_bytes()).unwrap();

    for malicious in [
        Vec::new(),
        vec![0; 32],
        unknown,
        invalid_signature,
        high_s,
        vec![0; pistis_authentication::MAX_RESPONSE_BYTES + 1],
    ] {
        assert_eq!(
            verify_authentication_response(&malicious, &fixture.expected, &fixture.credential),
            Err(VerifyError::InvalidResponse)
        );
    }
}
