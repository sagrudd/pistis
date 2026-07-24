use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use pistis_authentication::{
    AuthenticatedSessionId, AuthenticationService, ChallengeContext, ChallengeDocument, Decision,
    DeviceCredential, DeviceDirectory, LoginStatus, PreAuthSessionId, RandomSource,
    ResponseEnvelope, ServiceError, TransferMode, UnixTimeMillis, encode_response,
};
use pistis_crypto::{PublicKey, derive_key_id};
use pistis_domain::{DeviceId, ExternalIdentityId, InstallationId, UserId};
use pistis_qr::{TransferKind, TransferRef};
use std::{
    sync::{
        Arc, Barrier, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    thread,
};

// TEST-ONLY SYNTHETIC SIGNER. No production private key API is exposed.
const SYNTHETIC_PRIVATE_KEY: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7,
];

struct SequenceRandom(AtomicU8);

impl RandomSource for SequenceRandom {
    fn fill(&self, output: &mut [u8]) -> Result<(), ServiceError> {
        output.fill(self.0.fetch_add(1, Ordering::SeqCst));
        Ok(())
    }
}

struct Directory {
    credential: Mutex<DeviceCredential>,
}

impl DeviceDirectory for Directory {
    fn resolve(&self, device_id: DeviceId) -> Option<DeviceCredential> {
        let value = self.credential.lock().unwrap();
        (value.device_id == device_id).then(|| value.clone())
    }
}

struct Fixture {
    service: Arc<AuthenticationService>,
    signer: SigningKey,
    directory: Arc<Directory>,
    preauth: PreAuthSessionId,
    user: UserId,
    device: DeviceId,
}

fn fixture() -> Fixture {
    let signer = SigningKey::from_bytes((&SYNTHETIC_PRIVATE_KEY).into()).unwrap();
    let encoded = signer.verifying_key().to_encoded_point(true);
    let public_key = PublicKey::from_sec1_bytes(encoded.as_bytes()).unwrap();
    let device = DeviceId::from_bytes([4; 16]);
    let directory = Arc::new(Directory {
        credential: Mutex::new(DeviceCredential {
            device_id: device,
            key_id: derive_key_id(&public_key),
            public_key,
            active: true,
        }),
    });
    let service = Arc::new(AuthenticationService::new(
        InstallationId::from_bytes([1; 16]),
        directory.clone(),
        Arc::new(SequenceRandom(AtomicU8::new(10))),
    ));
    Fixture {
        service,
        signer,
        directory,
        preauth: PreAuthSessionId::from_bytes([2; 32]),
        user: UserId::from_bytes([3; 16]),
        device,
    }
}

fn signed(
    fixture: &Fixture,
    challenge: &ChallengeDocument,
    decision: Decision,
) -> ResponseEnvelope {
    let credential = fixture.directory.credential.lock().unwrap();
    let canonical = encode_response(
        challenge,
        fixture.device,
        credential.key_id,
        decision,
        UnixTimeMillis(150),
        UnixTimeMillis(175),
    )
    .unwrap();
    let signature: Signature = fixture.signer.sign(&canonical);
    let signature = signature.normalize_s().unwrap_or(signature);
    ResponseEnvelope::new(canonical, signature.to_bytes().to_vec()).unwrap()
}

fn begin(fixture: &Fixture) -> (pistis_authentication::LoginHandle, ChallengeDocument) {
    fixture
        .service
        .initiate(
            fixture.preauth,
            ChallengeContext {
                user_id: fixture.user,
                external_identity_id: ExternalIdentityId::from_bytes([5; 16]),
                installation_key_id: pistis_domain::KeyId::from_bytes([6; 32]),
                audience: "local-session".into(),
                installation_name: "Synthetic test installation".into(),
                local_username: "synthetic-user".into(),
                display_context_digest: [7; 32],
                installation_fingerprint: [8; 32],
                endpoint_hints: vec!["https://127.0.0.1:8443/response".into()],
            },
            UnixTimeMillis(100),
            UnixTimeMillis(1_000),
        )
        .unwrap()
}

#[test]
fn offline_direct_flow_creates_no_session_before_completion() {
    let f = fixture();
    let (handle, challenge) = begin(&f);
    let response = signed(&f, &challenge, Decision::Approve);
    f.service
        .submit_direct(handle, response, UnixTimeMillis(200))
        .unwrap();
    assert_eq!(
        f.service.poll(handle, f.preauth, UnixTimeMillis(200)),
        Ok(LoginStatus::ResponseAvailable)
    );
    assert!(
        !f.service
            .is_authenticated(AuthenticatedSessionId::from_bytes([13; 32]))
    );
    let completion = f
        .service
        .complete(handle, f.preauth, UnixTimeMillis(300))
        .unwrap();
    assert!(f.service.is_authenticated(completion.session_id));
    assert_eq!(f.service.audit_events()[0].transfer, TransferMode::Direct);
    assert_eq!(
        f.service.complete(handle, f.preauth, UnixTimeMillis(301)),
        Err(ServiceError::NotFound)
    );
}

#[test]
fn offline_qr_payload_uses_identical_verification_path() {
    let f = fixture();
    let (handle, challenge) = begin(&f);
    let response = signed(&f, &challenge, Decision::Approve);
    let qr_payload = pistis_qr::encode(TransferRef {
        kind: TransferKind::Response,
        payload: &response.canonical,
        signature: &response.signature,
    })
    .unwrap();
    f.service
        .submit_response_qr(handle, &qr_payload, UnixTimeMillis(200))
        .unwrap();
    f.service
        .complete(handle, f.preauth, UnixTimeMillis(300))
        .unwrap();
    assert_eq!(
        f.service.audit_events()[0].transfer,
        TransferMode::ResponseQr
    );
}

#[test]
fn denial_and_inactive_device_fail_terminally_without_session() {
    let f = fixture();
    let (handle, challenge) = begin(&f);
    f.service
        .submit_direct(
            handle,
            signed(&f, &challenge, Decision::Deny),
            UnixTimeMillis(200),
        )
        .unwrap();
    assert_eq!(
        f.service.complete(handle, f.preauth, UnixTimeMillis(300)),
        Err(ServiceError::Conflict)
    );
    assert_eq!(
        f.service.poll(handle, f.preauth, UnixTimeMillis(300)),
        Ok(LoginStatus::Denied)
    );

    let (second, challenge) = begin(&f);
    let response = signed(&f, &challenge, Decision::Approve);
    f.directory.credential.lock().unwrap().active = false;
    f.service
        .submit_direct(second, response, UnixTimeMillis(200))
        .unwrap();
    assert_eq!(
        f.service.complete(second, f.preauth, UnixTimeMillis(300)),
        Err(ServiceError::InvalidResponse)
    );
    assert!(f.service.audit_events().is_empty());
}

#[test]
fn photographed_response_cannot_satisfy_fresh_challenge() {
    let f = fixture();
    let (first, challenge) = begin(&f);
    let old = signed(&f, &challenge, Decision::Approve);
    f.service
        .submit_direct(first, old.clone(), UnixTimeMillis(200))
        .unwrap();
    f.service
        .complete(first, f.preauth, UnixTimeMillis(300))
        .unwrap();

    let (fresh, _) = begin(&f);
    f.service
        .submit_direct(fresh, old, UnixTimeMillis(200))
        .unwrap();
    assert_eq!(
        f.service.complete(fresh, f.preauth, UnixTimeMillis(300)),
        Err(ServiceError::InvalidResponse)
    );
}

#[test]
fn exactly_one_concurrent_completion_wins() {
    let f = fixture();
    let (handle, challenge) = begin(&f);
    f.service
        .submit_direct(
            handle,
            signed(&f, &challenge, Decision::Approve),
            UnixTimeMillis(200),
        )
        .unwrap();
    let barrier = Arc::new(Barrier::new(9));
    let mut workers = Vec::new();
    for _ in 0..8 {
        let service = f.service.clone();
        let barrier = barrier.clone();
        let preauth = f.preauth;
        workers.push(thread::spawn(move || {
            barrier.wait();
            service.complete(handle, preauth, UnixTimeMillis(300))
        }));
    }
    barrier.wait();
    let successes = workers
        .into_iter()
        .flat_map(|worker| worker.join().unwrap())
        .count();
    assert_eq!(successes, 1);
    assert_eq!(f.service.audit_events().len(), 1);
}

#[test]
fn expiry_cancel_and_wrong_session_are_fail_closed() {
    let f = fixture();
    let (handle, _) = begin(&f);
    assert_eq!(
        f.service.poll(
            handle,
            PreAuthSessionId::from_bytes([99; 32]),
            UnixTimeMillis(200)
        ),
        Err(ServiceError::NotFound)
    );
    f.service
        .cancel(handle, f.preauth, UnixTimeMillis(200))
        .unwrap();
    assert_eq!(
        f.service.poll(handle, f.preauth, UnixTimeMillis(300)),
        Ok(LoginStatus::Cancelled)
    );

    let (expired, _) = begin(&f);
    assert_eq!(
        f.service.poll(expired, f.preauth, UnixTimeMillis(1_000)),
        Ok(LoginStatus::Expired)
    );
}
