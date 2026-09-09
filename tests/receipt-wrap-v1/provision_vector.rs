// TEST ONLY: software keys and ciphertext; never production custody material.
use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder, iana};
use p256::{SecretKey, ecdsa::signature::Signer, elliptic_curve::sec1::ToEncodedPoint};
use thesaurophylax_crypto::*;
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
#[test]
fn emit_actual_provision_vector() {
    let site = "site-00000000-0000-0000-0000-000000000001";
    let generation = "site-root-bundle-receipt-1";
    let device_id = "pistis-device-1";
    let now = 1_700_000_000;
    let host = SecretKey::from_slice(&[7; 32]).unwrap();
    let device = p256::ecdsa::SigningKey::from_slice(&[8; 32]).unwrap();
    let host_public = host.public_key().to_encoded_point(true);
    let ceremony = PortableSiteTrustReceiptIssuerCeremonyV1::new_site_root_bundle_receipt(
        site,
        generation,
        device_id,
        host_public.as_bytes(),
    )
    .unwrap();
    let cose = CoseSign1Builder::new()
        .protected(
            HeaderBuilder::new()
                .algorithm(iana::Algorithm::ES256)
                .key_id(device_id.as_bytes().to_vec())
                .build(),
        )
        .create_detached_signature(ceremony.canonical_payload(), &[], |bytes| {
            let signature: p256::ecdsa::Signature = device.sign(bytes);
            signature
                .normalize_s()
                .unwrap_or(signature)
                .to_bytes()
                .to_vec()
        })
        .build()
        .to_vec()
        .unwrap();
    let proof = PistisSecureEnclaveDelegationProof {
        canonical_payload: ceremony.canonical_payload(),
        device_key_id: device_id,
        delegation_serial: "bundle-provision-1",
        site_trust_domain: site,
        purpose: SITE_ROOT_BUNDLE_RECEIPT_PROVISION_PURPOSE_V1,
        cose_sign1: &cose,
    };
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("synthetic-record.bin");
    let file = PortableKeystoreFileV1::new(PortableKeystorePathV1::new(&path).unwrap());
    use new_api::intrinsic_signature_profile_v1::{
        AcceptedIntrinsicSignatureProfileV1, accepted_profile_record_v1,
    };
    let result = PortableSiteTrustReceiptIssuerProvisionerV1::provision_site_root_bundle_receipt(
        AcceptedIntrinsicSignatureProfileV1::from_accepted_record(accepted_profile_record_v1())
            .unwrap(),
        &ceremony,
        device.verifying_key().to_encoded_point(true).as_bytes(),
        "bundle-provision-1",
        now + 100,
        7,
        &proof,
        now,
        &host,
        &file,
    )
    .unwrap();
    let device_secret = SecretKey::from_slice(&[8; 32]).unwrap();
    let shared = derive_portable_shared_secret(&device_secret, host_public.as_bytes()).unwrap();
    let aad = portable_wrap_aad_digest_for_purpose(
        SITE_ROOT_BUNDLE_RECEIPT_PURPOSE_V1,
        site,
        generation,
        device_id,
        host_public.as_bytes(),
    )
    .unwrap();
    let key = derive_portable_wrap_key(shared.expose(), &aad).unwrap();
    let seed = file.read(&key, &aad).unwrap();
    let seed_array: [u8; 32] = seed.as_slice().try_into().unwrap();
    assert_eq!(
        ed25519_dalek::SigningKey::from_bytes(&seed_array)
            .verifying_key()
            .as_bytes(),
        result.ed25519_public_key()
    );
    println!(
        "VECTOR_JSON={{\"site\":\"{site}\",\"generation\":\"{generation}\",\"device_id\":\"{device_id}\",\"device_private_hex\":\"{}\",\"host_public_hex\":\"{}\",\"record_hex\":\"{}\",\"shared_hex\":\"{}\",\"aad_hex\":\"{}\",\"seed_hex\":\"{}\",\"public_hex\":\"{}\"}}",
        hex(&[8; 32]),
        hex(host_public.as_bytes()),
        hex(&std::fs::read(path).unwrap()),
        hex(shared.expose()),
        hex(&aad),
        hex(&seed),
        hex(result.ed25519_public_key())
    );
}
