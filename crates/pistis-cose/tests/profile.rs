use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use pistis_canonical::{Value, to_vec};
use pistis_cose::{CoseError, decode, encode, signing_input, verify_sign1};
use pistis_crypto::{PublicKey, SignatureError, derive_key_id};
use std::collections::BTreeMap;

const SECRET: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
];

fn fixture() -> (SigningKey, PublicKey) {
    let signing = SigningKey::from_bytes((&SECRET).into()).unwrap();
    let encoded = signing.verifying_key().to_encoded_point(false);
    let public = PublicKey::from_sec1_bytes(encoded.as_bytes()).unwrap();
    (signing, public)
}

fn payload() -> Vec<u8> {
    to_vec(&Value::Map(BTreeMap::from([
        (0, Value::Unsigned(1)),
        (1, Value::Text("pistis.authentication-response.v1".into())),
        (2, Value::Bytes(vec![0xa5; 32])),
    ])))
    .unwrap()
}

fn signed_envelope() -> (Vec<u8>, PublicKey) {
    let (signing, public) = fixture();
    let key_id = derive_key_id(&public);
    let input = signing_input(&payload(), key_id).unwrap();
    let signature: Signature = signing.sign(&input);
    let signature = signature.normalize_s().unwrap_or(signature);
    (
        encode(&payload(), key_id, &signature.to_bytes()).unwrap(),
        public,
    )
}

#[test]
fn positive_vector_is_stable_and_verifies() {
    let (bytes, public) = signed_envelope();
    let verified = verify_sign1(&bytes, &public).unwrap();
    assert_eq!(verified.payload(), payload());
    assert_eq!(verified.key_id(), derive_key_id(&public));
    assert_eq!(verified.signature().len(), 64);

    // Exported for independent Swift conformance tests. This is a public,
    // deterministic test key and must never be used outside test fixtures.
    assert_eq!(
        hexadecimal(&bytes),
        "845826a201260458207ad63df38de8c402c7259db7bbc1b97b6890ffaa0a4adf78bc2b873efcabbf8da0584aa300010178217069737469732e61757468656e7469636174696f6e2d726573706f6e73652e7631025820a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5584071296517c3d5fc81a1606e2f6717efa98fa2de073ac3fd68b2155967a55399e7286b77d1e6587da0be79bf0da5aef5e63e9b32bf93f208ae7e87748650582324"
    );
}

#[test]
fn rejects_key_payload_and_signature_substitution() {
    let (bytes, public) = signed_envelope();
    let (_, wrong_public) = {
        let signing = SigningKey::from_bytes((&[2_u8; 32]).into()).unwrap();
        let encoded = signing.verifying_key().to_encoded_point(false);
        (
            signing,
            PublicKey::from_sec1_bytes(encoded.as_bytes()).unwrap(),
        )
    };
    assert_eq!(
        verify_sign1(&bytes, &wrong_public),
        Err(CoseError::KeyMismatch)
    );

    let decoded = decode(&bytes).unwrap();
    let changed_payload = to_vec(&Value::Map(BTreeMap::from([(0, Value::Unsigned(2))]))).unwrap();
    let changed = encode(&changed_payload, decoded.key_id(), decoded.signature()).unwrap();
    assert_eq!(
        verify_sign1(&changed, &public),
        Err(CoseError::Signature(SignatureError::InvalidSignature))
    );

    let mut changed_signature = *decoded.signature();
    changed_signature[0] ^= 1;
    let changed = encode(decoded.payload(), decoded.key_id(), &changed_signature).unwrap();
    assert_eq!(
        verify_sign1(&changed, &public),
        Err(CoseError::Signature(SignatureError::InvalidSignature))
    );
}

#[test]
fn rejects_high_s_signature() {
    let (signing, public) = fixture();
    let key_id = derive_key_id(&public);
    let input = signing_input(&payload(), key_id).unwrap();
    let signature: Signature = signing.sign(&input);
    let low = signature.normalize_s().unwrap_or(signature);
    let high = Signature::from_scalars(low.r().to_bytes(), (-low.s()).to_bytes()).unwrap();
    let bytes = encode(&payload(), key_id, &high.to_bytes()).unwrap();
    assert_eq!(
        verify_sign1(&bytes, &public),
        Err(CoseError::Signature(SignatureError::NonCanonical))
    );
}

#[test]
fn rejects_tagged_detached_unprotected_and_unknown_headers() {
    let (bytes, _) = signed_envelope();
    let mut tagged = vec![0xd2];
    tagged.extend_from_slice(&bytes);
    assert_eq!(decode(&tagged), Err(CoseError::InvalidEnvelope));

    let Value::Array(mut items) = pistis_canonical::from_slice(&bytes).unwrap() else {
        unreachable!()
    };
    items[2] = Value::Null;
    assert_eq!(
        decode(&to_vec(&Value::Array(items.clone())).unwrap()),
        Err(CoseError::InvalidEnvelope)
    );
    items[2] = Value::Bytes(payload());
    items[1] = Value::Map(BTreeMap::from([(4, Value::Bytes(vec![0; 32]))]));
    assert_eq!(
        decode(&to_vec(&Value::Array(items)).unwrap()),
        Err(CoseError::InvalidEnvelope)
    );

    let protected = to_vec(&Value::Map(BTreeMap::from([
        (1, Value::Negative(-7)),
        (2, Value::Array(Vec::new())),
        (4, Value::Bytes(vec![0; 32])),
    ])))
    .unwrap();
    let envelope = Value::Array(vec![
        Value::Bytes(protected),
        Value::Map(BTreeMap::new()),
        Value::Bytes(payload()),
        Value::Bytes(vec![0; 64]),
    ]);
    assert_eq!(
        decode(&to_vec(&envelope).unwrap()),
        Err(CoseError::InvalidEnvelope)
    );
}

#[test]
fn rejects_wrong_algorithm_kid_width_signature_width_and_noncanonical_payload() {
    for protected in [
        BTreeMap::from([(1, Value::Negative(-8)), (4, Value::Bytes(vec![0; 32]))]),
        BTreeMap::from([(1, Value::Negative(-7)), (4, Value::Bytes(vec![0; 31]))]),
    ] {
        let envelope = Value::Array(vec![
            Value::Bytes(to_vec(&Value::Map(protected)).unwrap()),
            Value::Map(BTreeMap::new()),
            Value::Bytes(payload()),
            Value::Bytes(vec![0; 64]),
        ]);
        assert_eq!(
            decode(&to_vec(&envelope).unwrap()),
            Err(CoseError::InvalidEnvelope)
        );
    }

    let (_, public) = fixture();
    assert_eq!(
        encode(&payload(), derive_key_id(&public), &[0; 63]),
        Err(CoseError::InvalidEnvelope)
    );
    assert_eq!(
        encode(&[0x18, 0x00], derive_key_id(&public), &[0; 64]),
        Err(CoseError::InvalidEnvelope)
    );
}

fn hexadecimal(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(output, "{byte:02x}").unwrap();
    }
    output
}
