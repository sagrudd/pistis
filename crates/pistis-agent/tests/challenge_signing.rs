use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use pistis_agent::{
    ChallengeSigningError, HostChallengeSigner, InstallationSignature, InstallationSigner,
    SignerError,
};
use pistis_authentication::{ChallengeDocument, UnixTimeMillis};
use pistis_cose::{CoseError, signing_input, verify_sign1};
use pistis_crypto::{PublicKey, derive_key_id, sha256};
use pistis_domain::{ChallengeId, ExternalIdentityId, InstallationId, KeyId, UserId};
use std::sync::{Arc, Mutex};

const SECRET: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
];

struct Provider {
    signing: SigningKey,
    key_id: KeyId,
    captured: Arc<Mutex<Vec<u8>>>,
    substitute_key: bool,
    corrupt_signature: bool,
}

impl InstallationSigner for Provider {
    fn sign(&self, message: &[u8]) -> Result<InstallationSignature, SignerError> {
        *self.captured.lock().unwrap() = message.to_vec();
        let signature: Signature = self.signing.sign(message);
        let signature = signature.normalize_s().unwrap_or(signature);
        let mut signature = signature.to_bytes().to_vec();
        if self.corrupt_signature {
            signature[0] ^= 1;
        }
        Ok(InstallationSignature {
            key_id: if self.substitute_key {
                KeyId::from_bytes([0x44; 32])
            } else {
                self.key_id
            },
            signature,
        })
    }
}

fn fixture() -> (ChallengeDocument, PublicKey, SigningKey) {
    let signing = SigningKey::from_bytes((&SECRET).into()).unwrap();
    let public =
        PublicKey::from_sec1_bytes(signing.verifying_key().to_encoded_point(true).as_bytes())
            .unwrap();
    let challenge = ChallengeDocument {
        issued_at: UnixTimeMillis(1_000),
        expires_at: UnixTimeMillis(61_000),
        challenge_id: ChallengeId::from_bytes([3; 16]),
        installation_id: InstallationId::from_bytes([4; 16]),
        user_id: UserId::from_bytes([5; 16]),
        external_identity_id: ExternalIdentityId::from_bytes([6; 16]),
        installation_key_id: derive_key_id(&public),
        nonce: [7; 32],
        audience: "jenkins.mnemosyne.local".into(),
        installation_name: "Mnemosyne Jenkins".into(),
        local_username: "stephen".into(),
        display_context_digest: [8; 32],
        installation_fingerprint: [9; 32],
        endpoint_hints: vec!["https://pistis.mnemosyne.co.uk/respond".into()],
    };
    (challenge, public, signing)
}

fn provider(signing: SigningKey, key_id: KeyId) -> Provider {
    Provider {
        signing,
        key_id,
        captured: Arc::new(Mutex::new(Vec::new())),
        substitute_key: false,
        corrupt_signature: false,
    }
}

#[test]
fn signs_exact_sig_structure_and_returns_unambiguous_facts() {
    let (challenge, public, signing) = fixture();
    let key_id = derive_key_id(&public);
    let captured = Arc::new(Mutex::new(Vec::new()));
    let test_provider = Provider {
        captured: Arc::clone(&captured),
        ..provider(signing, key_id)
    };
    let signer =
        HostChallengeSigner::new(&public.canonical_bytes(), key_id, test_provider).unwrap();
    let result = signer.sign(&challenge).unwrap();

    assert_eq!(
        *captured.lock().unwrap(),
        signing_input(&result.payload, key_id).unwrap()
    );
    assert_eq!(
        verify_sign1(&result.envelope, &public).unwrap().payload(),
        result.payload
    );
    assert_eq!(
        result.facts.payload_digest.into_bytes(),
        sha256(&result.payload).into_bytes()
    );
    assert_eq!(
        result.facts.envelope_digest.into_bytes(),
        sha256(&result.envelope).into_bytes()
    );
    assert_eq!(
        result.facts.nonce_digest.into_bytes(),
        sha256(&challenge.nonce).into_bytes()
    );
    assert!(!format!("{:?}", result.facts).contains("07070707"));
}

#[test]
fn rejects_malformed_public_key_and_every_key_substitution() {
    let (mut challenge, public, signing) = fixture();
    let key_id = derive_key_id(&public);
    assert!(matches!(
        HostChallengeSigner::new(&[0; 33], key_id, provider(signing.clone(), key_id)),
        Err(ChallengeSigningError::InvalidPublicKey(_))
    ));
    assert!(matches!(
        HostChallengeSigner::new(
            &public.canonical_bytes(),
            KeyId::from_bytes([1; 32]),
            provider(signing.clone(), key_id)
        ),
        Err(ChallengeSigningError::KeyMismatch)
    ));

    let signer = HostChallengeSigner::new(
        &public.canonical_bytes(),
        key_id,
        Provider {
            substitute_key: true,
            ..provider(signing, key_id)
        },
    )
    .unwrap();
    assert!(matches!(
        signer.sign(&challenge),
        Err(ChallengeSigningError::KeyMismatch)
    ));
    challenge.installation_key_id = KeyId::from_bytes([2; 32]);
    assert!(matches!(
        signer.sign(&challenge),
        Err(ChallengeSigningError::KeyMismatch)
    ));
}

#[test]
fn rejects_invalid_challenge_and_provider_signature() {
    let (mut challenge, public, signing) = fixture();
    let key_id = derive_key_id(&public);
    challenge.audience = "wrong\nhost".into();
    let signer = HostChallengeSigner::new(
        &public.canonical_bytes(),
        key_id,
        provider(signing.clone(), key_id),
    )
    .unwrap();
    assert!(matches!(
        signer.sign(&challenge),
        Err(ChallengeSigningError::InvalidChallenge)
    ));

    challenge.audience = "jenkins.mnemosyne.local".into();
    let signer = HostChallengeSigner::new(
        &public.canonical_bytes(),
        key_id,
        Provider {
            corrupt_signature: true,
            ..provider(signing, key_id)
        },
    )
    .unwrap();
    assert!(matches!(
        signer.sign(&challenge),
        Err(ChallengeSigningError::Cose(CoseError::Signature(_)))
    ));
}

#[test]
fn time_audience_and_endpoint_substitution_change_authenticated_bytes() {
    let (challenge, public, signing) = fixture();
    let key_id = derive_key_id(&public);
    let signer =
        HostChallengeSigner::new(&public.canonical_bytes(), key_id, provider(signing, key_id))
            .unwrap();
    let original = signer.sign(&challenge).unwrap();

    let mut changed_time = challenge.clone();
    changed_time.expires_at = UnixTimeMillis(challenge.expires_at.0 + 1);
    let mut changed_audience = challenge.clone();
    changed_audience.audience = "dasobjectstore.mnemosyne.local".into();
    let mut changed_endpoint = challenge;
    changed_endpoint.endpoint_hints = vec!["https://other.mnemosyne.co.uk/respond".into()];

    for substituted in [changed_time, changed_audience, changed_endpoint] {
        let result = signer.sign(&substituted).unwrap();
        assert_ne!(result.payload, original.payload);
        assert_ne!(result.facts.payload_digest, original.facts.payload_digest);
        assert_ne!(result.facts.envelope_digest, original.facts.envelope_digest);
    }

    let mut tampered_envelope = original.envelope;
    let payload_offset = tampered_envelope
        .windows(original.payload.len())
        .position(|candidate| candidate == original.payload)
        .unwrap();
    tampered_envelope[payload_offset + original.payload.len() - 1] ^= 1;
    assert!(verify_sign1(&tampered_envelope, &public).is_err());
}
