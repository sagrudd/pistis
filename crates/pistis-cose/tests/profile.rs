use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use pistis_canonical::{Value, to_vec};
use pistis_cose::{CoseError, decode, encode, signing_input, verify_sign1};
use pistis_crypto::{PublicKey, SignatureError, derive_key_id, sha256};
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
    fixture_hex(include_str!(
        "../../../fixtures/protocol-v1/cose/authentication-response-payload.hex"
    ))
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
        bytes,
        fixture_hex(include_str!(
            "../../../fixtures/protocol-v1/cose/positive-envelope.hex"
        ))
    );
    assert_eq!(
        signing_input(&payload(), derive_key_id(&public)).unwrap(),
        fixture_hex(include_str!(
            "../../../fixtures/protocol-v1/cose/signing-input.hex"
        ))
    );
    assert_eq!(
        verified.signature(),
        fixture_hex(include_str!(
            "../../../fixtures/protocol-v1/cose/signature.hex"
        ))
        .as_slice()
    );
    assert_eq!(
        public.canonical_bytes().as_slice(),
        fixture_hex(include_str!(
            "../../../fixtures/protocol-v1/cose/public-key-compressed.hex"
        ))
    );
    assert_eq!(
        derive_key_id(&public).as_bytes().as_slice(),
        fixture_hex(include_str!(
            "../../../fixtures/protocol-v1/cose/key-id.hex"
        ))
    );
}

#[test]
fn schema_payload_fixtures_are_exact_closed_canonical_maps() {
    let cases = [
        (
            include_str!("../../../fixtures/protocol-v1/cose/device-registration-payload.hex"),
            14,
            "pistis.device-registration.v1",
        ),
        (
            include_str!("../../../fixtures/protocol-v1/cose/authentication-challenge-payload.hex"),
            17,
            "pistis.authentication-challenge.v1",
        ),
        (
            include_str!("../../../fixtures/protocol-v1/cose/authentication-response-payload.hex"),
            13,
            "pistis.authentication-response.v1",
        ),
        (
            include_str!(
                "../../../fixtures/protocol-v1/cose/authentication-evidence-receipt-payload.hex"
            ),
            14,
            "pistis.authentication-evidence-receipt.v1",
        ),
    ];
    for (hex, field_count, purpose) in cases {
        let bytes = fixture_hex(hex);
        let Value::Map(fields) = pistis_canonical::from_slice(&bytes).unwrap() else {
            panic!("schema fixture must be a map")
        };
        assert_eq!(fields.len(), field_count);
        assert_eq!(fields.get(&0), Some(&Value::Unsigned(1)));
        assert_eq!(fields.get(&1), Some(&Value::Text(purpose.into())));
        assert_eq!(to_vec(&Value::Map(fields)).unwrap(), bytes);
    }

    let challenge = fixture_hex(include_str!(
        "../../../fixtures/protocol-v1/cose/authentication-challenge-payload.hex"
    ));
    let response = fixture_hex(include_str!(
        "../../../fixtures/protocol-v1/cose/authentication-response-payload.hex"
    ));
    let Value::Map(response_fields) = pistis_canonical::from_slice(&response).unwrap() else {
        unreachable!()
    };
    assert_eq!(
        response_fields.get(&8),
        Some(&Value::Bytes(sha256(&challenge).into_bytes().to_vec()))
    );

    let evidence = fixture_hex(include_str!(
        "../../../fixtures/protocol-v1/cose/authentication-evidence-receipt-payload.hex"
    ));
    let envelope = fixture_hex(include_str!(
        "../../../fixtures/protocol-v1/cose/positive-envelope.hex"
    ));
    let Value::Map(evidence_fields) = pistis_canonical::from_slice(&evidence).unwrap() else {
        unreachable!()
    };
    assert_eq!(
        evidence_fields.get(&7),
        Some(&Value::Bytes(sha256(&envelope).into_bytes().to_vec()))
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

#[test]
fn retained_hostile_corpus_fails_with_classified_outcomes() {
    let (_, public) = fixture();
    for input in [
        include_str!("../../../fixtures/protocol-v1/cose/negative-tagged-envelope.hex"),
        include_str!("../../../fixtures/protocol-v1/cose/negative-detached-payload.hex"),
        include_str!("../../../fixtures/protocol-v1/cose/negative-unprotected-header.hex"),
        include_str!("../../../fixtures/protocol-v1/cose/negative-unknown-protected-header.hex"),
        include_str!("../../../fixtures/protocol-v1/cose/negative-wrong-algorithm.hex"),
    ] {
        assert_eq!(
            verify_sign1(&fixture_hex(input), &public),
            Err(CoseError::InvalidEnvelope)
        );
    }
    assert_eq!(
        verify_sign1(
            &fixture_hex(include_str!(
                "../../../fixtures/protocol-v1/cose/negative-high-s-signature.hex"
            )),
            &public
        ),
        Err(CoseError::Signature(SignatureError::NonCanonical))
    );
    assert_eq!(
        verify_sign1(
            &fixture_hex(include_str!(
                "../../../fixtures/protocol-v1/cose/negative-substituted-payload.hex"
            )),
            &public
        ),
        Err(CoseError::Signature(SignatureError::InvalidSignature))
    );
}

fn fixture_hex(input: &str) -> Vec<u8> {
    let input = input.trim().as_bytes();
    assert!(input.len().is_multiple_of(2));
    input
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}
