use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use pistis_canonical::{Value, from_slice, to_vec};
use pistis_cose::{encode, signing_input};
use pistis_crypto::{PublicKey, derive_key_id, sha256};
use pistis_domain::KeyId;
use pistis_protocol::{
    FirstDevicePresentationError, derive_host_trust_words, verify_first_device_presentation,
};
use std::collections::BTreeMap;

const FIXTURE: &str =
    include_str!("../../../fixtures/protocol-v4/first-device/presentation-positive.json");
const APP_DIGEST: [u8; 32] = [
    0xbf, 0x79, 0x68, 0x03, 0x0a, 0xbd, 0xf7, 0xd3, 0xda, 0xbb, 0x38, 0x9f, 0x32, 0xcd, 0x4c, 0x53,
    0x10, 0xc1, 0xec, 0x4c, 0x9c, 0x62, 0x5d, 0x38, 0xd1, 0x3b, 0xe6, 0xef, 0xae, 0x23, 0x06, 0x63,
];
const NOW: u64 = 1_700_000_060_000;
const TLS_SPKI_DIGEST: [u8; 32] = [
    0x9a, 0x72, 0x21, 0x83, 0x6d, 0xf4, 0x42, 0x48, 0x3c, 0x36, 0x4f, 0x2f, 0xa1, 0x2b, 0x83, 0x7f,
    0x7f, 0x36, 0x99, 0x5e, 0x8c, 0x9c, 0xe9, 0x89, 0x83, 0xe3, 0x9a, 0xef, 0xa8, 0x2d, 0x70, 0x68,
];

fn fixture() -> Vec<u8> {
    let signing = signing_key(1);
    let receipt_signing = signing_key(2);
    let (initial_descriptor, key_id) = descriptor(&signing);
    let (receipt_descriptor, _) = descriptor(&receipt_signing);
    let bundle = to_vec(&Value::Map(BTreeMap::from([
        (0, Value::Unsigned(1)),
        (
            1,
            Value::Text("pistis.first-device-authority-bundle.v1".into()),
        ),
        (2, Value::Bytes(initial_descriptor)),
        (3, Value::Bytes(receipt_descriptor)),
    ])))
    .unwrap();
    let descriptor_digest = sha256(&bundle).into_bytes();
    let invitation = to_vec(&Value::Map(BTreeMap::from([
        (0, Value::Unsigned(1)),
        (
            1,
            Value::Text("pistis.mobile-enrolment-invitation.v1".into()),
        ),
        (2, Value::Unsigned(1_700_000_000_000)),
        (3, Value::Unsigned(1_700_000_300_000)),
        (4, Value::Bytes(vec![0x11; 16])),
        (5, Value::Bytes(vec![0x55; 32])),
        (6, Value::Bytes(vec![0x22; 16])),
        (7, Value::Text("prosopikon:pistis:enrolment".into())),
        (8, Value::Bytes(descriptor_digest.to_vec())),
    ])))
    .unwrap();
    let payload = to_vec(&Value::Map(BTreeMap::from([
        (0, Value::Unsigned(2)),
        (1, Value::Text("pistis.first-device-presentation.v2".into())),
        (2, Value::Bytes(vec![0x33; 16])),
        (3, Value::Unsigned(1_700_000_000_000)),
        (4, Value::Unsigned(1_700_000_300_000)),
        (5, Value::Bytes(invitation)),
        (6, Value::Bytes(vec![0x44; 16])),
        (7, Value::Bytes(vec![0x66; 16])),
        (8, Value::Bytes(vec![0x77; 16])),
        (9, Value::Bytes(vec![0x22; 16])),
        (10, Value::Text("Mnemosyne evaluation".into())),
        (11, Value::Text("prosopikon:pistis:enrolment".into())),
        (12, Value::Text("https://pistis.example.test:8443".into())),
        (13, Value::Bytes(APP_DIGEST.to_vec())),
        (14, Value::Bytes(descriptor_digest.to_vec())),
        (15, Value::Bytes(TLS_SPKI_DIGEST.to_vec())),
        (16, Value::Unsigned(1)),
    ])))
    .unwrap();
    let input = signing_input(&payload, key_id).unwrap();
    let signature: Signature = signing.sign(&input);
    let signature = signature.normalize_s().unwrap_or(signature);
    let cose = encode(&payload, key_id, &signature.to_bytes()).unwrap();
    to_vec(&Value::Map(BTreeMap::from([
        (0, Value::Unsigned(4)),
        (1, Value::Unsigned(3)),
        (2, Value::Bytes(cose)),
        (3, Value::Bytes(bundle)),
    ])))
    .unwrap()
}

fn signing_key(scalar: u8) -> SigningKey {
    let mut secret = [0; 32];
    secret[31] = scalar;
    SigningKey::from_bytes((&secret).into()).unwrap()
}

fn descriptor(signing: &SigningKey) -> (Vec<u8>, KeyId) {
    let compressed = signing.verifying_key().to_encoded_point(true);
    let public = PublicKey::from_sec1_bytes(compressed.as_bytes()).unwrap();
    let key_id = derive_key_id(&public);
    let bytes = to_vec(&Value::Map(BTreeMap::from([
        (0, Value::Unsigned(1)),
        (1, Value::Text("pistis.authority-key-descriptor.v1".into())),
        (2, Value::Bytes(key_id.into_bytes().to_vec())),
        (3, Value::Bytes(compressed.as_bytes().to_vec())),
        (4, Value::Negative(-7)),
    ])))
    .unwrap();
    (bytes, key_id)
}

#[test]
fn verifies_the_exact_closed_fixture() {
    let frame = fixture();
    let document: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    assert_eq!(hex(&frame), document["frame_hex"].as_str().unwrap());
    let verified = verify_first_device_presentation(&frame, APP_DIGEST, NOW).unwrap();
    assert_eq!(verified.presentation_id, [0x33; 16]);
    assert_eq!(verified.invitation.invitation_id, [0x11; 16]);
    assert_eq!(verified.invitation.installation_id, [0x22; 16]);
    assert_ne!(
        verified.authority_bundle.initial_invitation.key_id,
        verified.authority_bundle.mobile_receipt.key_id
    );
    assert_eq!(verified.installation_name, "Mnemosyne evaluation");
    assert_eq!(verified.https_origin, "https://pistis.example.test:8443");
    assert_eq!(verified.tls_spki_sha256, TLS_SPKI_DIGEST);
    assert_eq!(
        verified.trust_words,
        derive_host_trust_words(
            [0x44; 16],
            [0x22; 16],
            "https://pistis.example.test:8443",
            TLS_SPKI_DIGEST,
            APP_DIGEST,
        )
        .unwrap()
    );
}

#[test]
fn rejects_version_and_kind_downgrade_configuration_substitution_and_expiry() {
    let frame = fixture();
    let Value::Map(mut outer) = from_slice(&frame).unwrap() else {
        unreachable!()
    };
    outer.insert(0, Value::Unsigned(3));
    assert_eq!(
        verify_first_device_presentation(
            &to_vec(&Value::Map(outer.clone())).unwrap(),
            APP_DIGEST,
            NOW
        ),
        Err(FirstDevicePresentationError::InvalidFrame)
    );
    outer.insert(0, Value::Unsigned(4));
    outer.insert(1, Value::Unsigned(2));
    assert_eq!(
        verify_first_device_presentation(&to_vec(&Value::Map(outer)).unwrap(), APP_DIGEST, NOW),
        Err(FirstDevicePresentationError::InvalidFrame)
    );
    assert_eq!(
        verify_first_device_presentation(&frame, [0; 32], NOW),
        Err(FirstDevicePresentationError::ConfigurationMismatch)
    );
    assert_eq!(
        verify_first_device_presentation(&frame, APP_DIGEST, 1_700_000_300_000),
        Err(FirstDevicePresentationError::Expired)
    );
}

#[test]
fn every_binary_truncation_fails() {
    let frame = fixture();
    for length in 0..frame.len() {
        assert!(
            verify_first_device_presentation(&frame[..length], APP_DIGEST, NOW).is_err(),
            "truncation {length}"
        );
    }
}

#[test]
#[ignore = "fixture exporter"]
fn export_fixture_hex() {
    let frame = fixture();
    let verified = verify_first_device_presentation(&frame, APP_DIGEST, NOW).unwrap();
    eprintln!("{}", hex(&frame));
    eprintln!("{}", verified.trust_words.as_array().join(" "));
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut output, byte| {
            write!(output, "{byte:02x}").expect("writing to a String cannot fail");
            output
        },
    )
}
