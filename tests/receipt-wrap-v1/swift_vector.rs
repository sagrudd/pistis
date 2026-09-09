// TEST ONLY: exact output from native Swift CryptoKit synthetic fixture.
use p256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint};
use thesaurophylax_crypto::*;
fn unhex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|s| u8::from_str_radix(std::str::from_utf8(s).unwrap(), 16).unwrap())
        .collect()
}
#[test]
fn native_opens_actual_swift_fresh_record_only_with_short_aad() {
    let record = unhex(
        "a5a5a5a5a5a5a5a5a5a5a5a542834ece8431ebe76963bd6cbeced54d78415e14eb980b7096415e74caa2078651b45a7b90c1563e3131c1af4a964fbf",
    );
    let device = SecretKey::from_slice(&[8; 32]).unwrap();
    let host = SecretKey::from_slice(&[3; 32]).unwrap();
    let host_public = host.public_key().to_encoded_point(true);
    let shared = derive_portable_shared_secret(&device, host_public.as_bytes()).unwrap();
    for (domain, accepts) in [
        ("site-root-bundle-receipt", true),
        ("thesaurophylax.site-root-bundle-receipt-rewrap.v1", false),
    ] {
        let aad = portable_wrap_aad_digest_for_purpose(
            domain,
            "site-00000000-0000-0000-0000-000000000001",
            "site-root-bundle-receipt-1",
            "pistis-device-1",
            host_public.as_bytes(),
        )
        .unwrap();
        let key = derive_portable_wrap_key(shared.expose(), &aad).unwrap();
        let result = open_portable_keystore_record(&key, &aad, &record);
        if accepts {
            assert_eq!(
                result.unwrap(),
                unhex("cb5953c84593c43c527ecb1adc331ab711476094cf8a47a10dcf6c03c2fbdaf6")
            );
        } else {
            assert!(result.is_err());
        }
    }
}
