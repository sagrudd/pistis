use pistis_crypto::{PublicKey, SignatureSuite, derive_key_id, verify};
fn hex(raw: &str) -> Vec<u8> {
    let raw = raw.trim();
    assert!(raw.len().is_multiple_of(2));
    raw.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
#[test]
fn actual_imported_sdk_preserves_retained_bytes_and_denials() {
    let key = hex(include_str!(
        "../../../fixtures/protocol-v1/crypto/public-key-compressed.hex"
    ));
    let challenge = hex(include_str!(
        "../../../fixtures/protocol-v1/crypto/challenge.hex"
    ));
    let signature = hex(include_str!(
        "../../../fixtures/protocol-v1/crypto/signature-cose.hex"
    ));
    let public = PublicKey::from_sec1_bytes(&key).unwrap();
    assert_eq!(public.canonical_bytes().as_slice(), key);
    verify(SignatureSuite::Es256, &public, &challenge, &signature).unwrap();
    assert!(verify(SignatureSuite::Es256, &public, b"substitution", &signature).is_err());
    assert!(verify(SignatureSuite::Es256, &public, &challenge, &signature[..63]).is_err());
    let value = pistis_canonical::from_slice(&challenge).unwrap();
    assert_eq!(pistis_canonical::to_vec(&value).unwrap(), challenge);
    let envelope = pistis_cose::encode(&challenge, derive_key_id(&public), &signature).unwrap();
    let decoded = pistis_cose::decode(&envelope).unwrap();
    assert_eq!(decoded.payload(), challenge);
    assert_eq!(decoded.signature(), signature);
    // This exact fixture signs the plain canonical challenge, not Sig_structure.
    assert!(pistis_cose::verify_sign1(&envelope, &public).is_err());
    let first = pistis_protocol::derive_host_trust_words(
        [1; 16],
        [2; 16],
        "https://fixture.invalid",
        [3; 32],
        [4; 32],
    )
    .unwrap();
    let second = pistis_protocol::derive_host_trust_words(
        [1; 16],
        [2; 16],
        "https://fixture.invalid",
        [3; 32],
        [4; 32],
    )
    .unwrap();
    assert_eq!(first, second);
}
