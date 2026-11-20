use super::*;
use p256::ecdsa::SigningKey;
use pistis_domain::{DeviceId, InstallationId, KeyId};
use pistis_protocol::UnixTimeMillis;

use crate::{SiteTrustCanonicalPayloadV1, SiteTrustFactCeremonyIdV1, SiteTrustPistisIntentV1};

fn rotation_request(key_id: KeyId) -> CustodyRotationAppAttestRequestV1 {
    let installation = InstallationId::from_bytes([1; 16]);
    let ceremony = SiteTrustFactCeremonyIdV1::from_bytes([3; 16]);
    let mut canonical = Vec::new();
    canonical.extend_from_slice(b"MONASAC2\0");
    canonical.extend_from_slice(installation.as_bytes());
    canonical.extend_from_slice(&9_u16.to_be_bytes());
    canonical.extend_from_slice(b"site-demo");
    canonical.extend_from_slice(ceremony.as_bytes());
    canonical.extend_from_slice(key_id.as_bytes());
    canonical.extend_from_slice(&100_u64.to_be_bytes());
    canonical.extend_from_slice(&200_u64.to_be_bytes());
    canonical.extend_from_slice(&[4; 32]);
    canonical.extend_from_slice(&[5; 32]);
    CustodyRotationAppAttestRequestV1::from_server_owned_challenge(
        installation,
        "site-demo".into(),
        ceremony,
        key_id,
        Sha256::digest(canonical).into(),
        [4; 32],
        [5; 32],
        100,
        200,
    )
    .unwrap()
}

fn durable_key() -> ([u8; 65], KeyId) {
    let signing_key = SigningKey::from_bytes((&[7; 32]).into()).unwrap();
    let encoded = signing_key.verifying_key().to_sec1_point(false);
    let public_key: [u8; 65] = encoded.as_bytes().try_into().unwrap();
    (
        public_key,
        KeyId::from_bytes(Sha256::digest(public_key).into()),
    )
}

fn recovery_request(key_id: KeyId, audience: &str) -> SiteTrustAttestationRequestV1 {
    let fields = [
        "mnemosyne.proxenos.std.v1",
        "1",
        "request-pending",
        "site-demo",
        "tenant-demo",
        "installation-demo",
        "request-demo",
        audience,
        "trust-admission",
        "2026-01-01T00:00:00Z",
        "2026-01-01T01:00:00Z",
        "none",
        "intent-demo",
    ];
    let payload = fields
        .iter()
        .enumerate()
        .fold(Vec::new(), |mut output, (index, field)| {
            output.push(u8::try_from(index + 1).unwrap());
            output.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
            output.extend_from_slice(field.as_bytes());
            output
        });
    SiteTrustAttestationRequestV1 {
        installation_id: InstallationId::from_bytes([1; 16]),
        device_id: DeviceId::from_bytes([2; 16]),
        key_id,
        ceremony_id: SiteTrustFactCeremonyIdV1::from_bytes([3; 16]),
        canonical_payload: SiteTrustCanonicalPayloadV1::parse(payload).unwrap(),
        pistis_intent: SiteTrustPistisIntentV1::parse(
            "mnemosyne.pistis.intent.v1:intent-demo".into(),
        )
        .unwrap(),
        issued_at: UnixTimeMillis::new(42),
    }
}

#[test]
fn package_material_is_pinned_to_the_production_profile() {
    let factory = ProductionAppleAppAttestAcceptanceFactoryV1::from_package().unwrap();
    assert_eq!(
        URL_SAFE_NO_PAD.encode(factory.manifest_digest),
        REGISTRATION_MANIFEST_SHA256_B64URL
    );
}

#[test]
fn pxfp_v2_acceptance_requires_exact_protected_and_durable_registration_identity() {
    let factory = ProductionAppleAppAttestAcceptanceFactoryV1::from_package().unwrap();
    let (public_key, key_id) = durable_key();
    let key_id_b64url = URL_SAFE_NO_PAD.encode(key_id.as_bytes());
    let resume = |expected_key: &str,
                  application: &str,
                  durable_key: &str,
                  key: [u8; 65],
                  manifest: [u8; 32],
                  bundle: &str,
                  counter: u32| {
        factory.resume_durable_registration_for_site_x509_first_provision_offline_v2(
            [0x44; 32],
            expected_key,
            application,
            durable_key,
            key,
            manifest,
            bundle,
            counter,
        )
    };
    assert!(
        resume(
            &key_id_b64url,
            MONAS_PRODUCTION_APP_ATTEST_APP_IDENTIFIER_V1,
            &key_id_b64url,
            public_key,
            factory.manifest_digest,
            "1.0.0",
            8,
        )
        .is_ok()
    );
    let other_key_id = URL_SAFE_NO_PAD.encode([0x99; 32]);
    for denied in [
        resume(
            &other_key_id,
            MONAS_PRODUCTION_APP_ATTEST_APP_IDENTIFIER_V1,
            &key_id_b64url,
            public_key,
            factory.manifest_digest,
            "1.0.0",
            8,
        ),
        resume(
            &key_id_b64url,
            "development.example.pistis",
            &key_id_b64url,
            public_key,
            factory.manifest_digest,
            "1.0.0",
            8,
        ),
        resume(
            &key_id_b64url,
            MONAS_PRODUCTION_APP_ATTEST_APP_IDENTIFIER_V1,
            &key_id_b64url,
            public_key,
            [0x55; 32],
            "1.0.0",
            8,
        ),
        resume(
            &key_id_b64url,
            MONAS_PRODUCTION_APP_ATTEST_APP_IDENTIFIER_V1,
            &key_id_b64url,
            public_key,
            factory.manifest_digest,
            "1/0",
            8,
        ),
        resume(
            &key_id_b64url,
            MONAS_PRODUCTION_APP_ATTEST_APP_IDENTIFIER_V1,
            &key_id_b64url,
            public_key,
            factory.manifest_digest,
            "1.0.0",
            u32::MAX,
        ),
    ] {
        assert!(matches!(
            denied,
            Err(SiteTrustAppAttestRegistrationErrorV1::Denied)
        ));
    }
}

#[test]
fn decoder_rejects_unknown_or_noncanonical_mobile_registration() {
    assert!(decode_site_trust_app_attest_registration_submission_v1(
        br#"{\"protocol\":\"pistis.apple-app-attest-registration.v1\",\"ceremony_id\":\"ceremony\",\"site_trust_domain\":\"site.example\",\"app_identifier\":\"C7A6NQTSY4.org.mnemosynebiosciences.pistis\",\"key_id_b64url\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"client_data_hash_b64url\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"attestation_object_b64url\":\"AA\"}"#
    ).is_err());
    assert!(decode_site_trust_app_attest_registration_submission_v1(
        br#"{\"protocol\":\"pistis.apple-app-attest-registration.v1\",\"ceremony_id\":\"ceremony\",\"site_trust_domain\":\"site.example\",\"app_identifier\":\"C7A6NQTSY4.org.mnemosynebiosciences.pistis\",\"key_id_b64url\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"client_data_hash_b64url\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"attestation_object_b64url\":\"AA\",\"authority\":\"client\"}"#
    ).is_err());
}

#[test]
fn malformed_apple_object_never_creates_an_acceptance() {
    let factory = ProductionAppleAppAttestAcceptanceFactoryV1::from_package().unwrap();
    assert_eq!(
        verify_pinned_apple_registration(b"not-cbor", [0; 32], [0; 32], factory.root_pem),
        Err(SiteTrustAppAttestRegistrationErrorV1::Malformed)
    );
}

#[test]
fn durable_restart_reconstructs_only_the_exact_rotation_acceptance() {
    let factory = ProductionAppleAppAttestAcceptanceFactoryV1::from_package().unwrap();
    let (public_key, key_id) = durable_key();
    let request = rotation_request(key_id);
    factory
        .resume_durable_registration_for_custody_rotation(
            request,
            public_key,
            factory.manifest_digest,
            "1.0.0",
            41,
        )
        .unwrap();
}

#[test]
fn durable_tamper_or_binding_mismatch_never_reconstructs_acceptance() {
    let factory = ProductionAppleAppAttestAcceptanceFactoryV1::from_package().unwrap();
    let (public_key, key_id) = durable_key();
    let request = rotation_request(key_id);
    let attempt = |request, key, manifest, bundle, counter| {
        factory.resume_durable_registration_for_custody_rotation(
            request, key, manifest, bundle, counter,
        )
    };
    assert!(
        attempt(
            request.clone(),
            [0; 65],
            factory.manifest_digest,
            "1.0.0",
            41
        )
        .is_err()
    );
    assert!(attempt(request.clone(), public_key, [0; 32], "1.0.0", 41).is_err());
    assert!(
        attempt(
            request.clone(),
            public_key,
            factory.manifest_digest,
            "bad/version",
            41
        )
        .is_err()
    );
    assert!(
        attempt(
            request,
            public_key,
            factory.manifest_digest,
            "1.0.0",
            u32::MAX
        )
        .is_err()
    );
}

#[test]
fn mtgs_recovery_reconstructs_only_the_exact_durable_audience() {
    let factory = ProductionAppleAppAttestAcceptanceFactoryV1::from_package().unwrap();
    let (public_key, key_id) = durable_key();
    assert!(
        factory
            .resume_durable_registration_for_mtgs_recovery(
                recovery_request(key_id, MONAS_MTGS_RECOVERY_AUDIENCE_V1),
                public_key,
                factory.manifest_digest,
                "1.0.0",
                41
            )
            .is_ok()
    );
    assert!(
        factory
            .resume_durable_registration_for_mtgs_recovery(
                recovery_request(key_id, "monas-local"),
                public_key,
                factory.manifest_digest,
                "1.0.0",
                41
            )
            .is_err()
    );
}
