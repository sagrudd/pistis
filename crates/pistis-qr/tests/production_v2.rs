//! Accepted ADR 0021 production outer-frame conformance.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use pistis_canonical::{Value, to_vec};
use pistis_cose::{encode, signing_input};
use pistis_crypto::{PublicKey, derive_key_id, sha256};
use pistis_qr::{
    MAX_COSE_ENVELOPE_BYTES, MAX_TRANSFER_TEXT_BYTES, ProductionTransferRef, QrError, TransferKind,
    decode_production, encode_production,
};
use std::collections::BTreeMap;
use std::fmt::Write as _;

const PREFIX: &str = "PISTIS1:";
const FIXTURE_SECRET: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
];

fn fixture_cose() -> Vec<u8> {
    decode_hex(include_str!(
        "../../../fixtures/protocol-v1/cose/positive-envelope.hex"
    ))
}

fn fixture_challenge_cose() -> Vec<u8> {
    let payload = decode_hex(include_str!(
        "../../../fixtures/protocol-v1/cose/authentication-challenge-payload.hex"
    ));
    let signing = SigningKey::from_bytes((&FIXTURE_SECRET).into()).expect("fixture key");
    let encoded = signing.verifying_key().to_encoded_point(false);
    let public = PublicKey::from_sec1_bytes(encoded.as_bytes()).expect("fixture public key");
    let key_id = derive_key_id(&public);
    let input = signing_input(&payload, key_id).expect("fixture signing input");
    let signature: Signature = signing.sign(&input);
    let signature = signature.normalize_s().unwrap_or(signature);
    encode(&payload, key_id, &signature.to_bytes()).expect("fixture challenge envelope")
}

fn checked(frame: &[u8]) -> String {
    let body = URL_SAFE_NO_PAD.encode(frame);
    let digest = sha256(format!("{PREFIX}{body}").as_bytes());
    format!("{PREFIX}{body}.{}", encode_hex(&digest.as_bytes()[..8]))
}

fn frame(version: Value, kind: Value, cose: Value) -> Vec<u8> {
    to_vec(&Value::Map(BTreeMap::from([
        (0, version),
        (1, kind),
        (2, cose),
    ])))
    .expect("test frame")
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut output, byte| {
        write!(output, "{byte:02x}").expect("String write");
        output
    })
}

fn decode_hex(input: &str) -> Vec<u8> {
    input
        .trim()
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII fixture"), 16)
                .expect("hex fixture")
        })
        .collect()
}

#[test]
fn accepted_response_fixture_is_stable_exact_and_round_trips() {
    let expected = include_str!("../../../fixtures/proposed-qr-v2/response-positive.qr.txt").trim();
    let cose = fixture_cose();
    let encoded = encode_production(ProductionTransferRef {
        kind: TransferKind::Response,
        cose: &cose,
    })
    .expect("accepted production transfer");
    assert_eq!(encoded, expected);
    assert_eq!(
        decode_production(&encoded, TransferKind::Response),
        Ok(cose)
    );
}

#[test]
fn accepted_challenge_fixture_is_stable_exact_and_round_trips() {
    let cose = fixture_challenge_cose();
    assert_eq!(
        encode_hex(&cose),
        include_str!("../../../fixtures/proposed-qr-v2/challenge-positive.cose.hex").trim()
    );
    let encoded = encode_production(ProductionTransferRef {
        kind: TransferKind::Challenge,
        cose: &cose,
    })
    .expect("accepted production challenge transfer");
    assert_eq!(
        encoded,
        include_str!("../../../fixtures/proposed-qr-v2/challenge-positive.qr.txt").trim()
    );
    assert_eq!(
        decode_production(&encoded, TransferKind::Challenge),
        Ok(cose)
    );
}

#[test]
fn rejects_downgrade_kind_confusion_and_invalid_cose() {
    let cose = fixture_cose();
    let version_one = checked(&frame(
        Value::Unsigned(1),
        Value::Unsigned(2),
        Value::Bytes(cose.clone()),
    ));
    assert_eq!(
        decode_production(&version_one, TransferKind::Response),
        Err(QrError::UnsupportedVersion)
    );

    let response = encode_production(ProductionTransferRef {
        kind: TransferKind::Response,
        cose: &cose,
    })
    .unwrap();
    assert_eq!(
        decode_production(&response, TransferKind::Challenge),
        Err(QrError::UnsupportedKind)
    );

    let invalid = checked(&frame(
        Value::Unsigned(2),
        Value::Unsigned(2),
        Value::Bytes(vec![0x80]),
    ));
    assert_eq!(
        decode_production(&invalid, TransferKind::Response),
        Err(QrError::InvalidEnvelope)
    );
}

#[test]
fn rejects_wrong_fields_types_unknown_fields_and_noncanonical_order() {
    let cose = fixture_cose();
    let cases = [
        frame(
            Value::Text("2".into()),
            Value::Unsigned(2),
            Value::Bytes(cose.clone()),
        ),
        frame(
            Value::Unsigned(2),
            Value::Text("response".into()),
            Value::Bytes(cose.clone()),
        ),
        frame(
            Value::Unsigned(2),
            Value::Unsigned(2),
            Value::Text("cose".into()),
        ),
        to_vec(&Value::Map(BTreeMap::from([
            (0, Value::Unsigned(2)),
            (1, Value::Unsigned(2)),
            (2, Value::Bytes(cose.clone())),
            (3, Value::Null),
        ])))
        .unwrap(),
    ];
    for malformed in cases {
        assert_eq!(
            decode_production(&checked(&malformed), TransferKind::Response),
            Err(QrError::InvalidFrame)
        );
    }

    let mut reordered = frame(Value::Unsigned(2), Value::Unsigned(2), Value::Bytes(cose));
    assert_eq!(&reordered[..5], &[0xa3, 0x00, 0x02, 0x01, 0x02]);
    reordered[1..5].copy_from_slice(&[0x01, 0x02, 0x00, 0x02]);
    assert_eq!(
        decode_production(&checked(&reordered), TransferKind::Response),
        Err(QrError::InvalidFrame)
    );
}

#[test]
fn rejects_transport_corruption_non_ascii_and_bounds() {
    let cose = fixture_cose();
    let valid = encode_production(ProductionTransferRef {
        kind: TransferKind::Response,
        cose: &cose,
    })
    .unwrap();
    let mut corrupt = valid.clone().into_bytes();
    corrupt[PREFIX.len()] = if corrupt[PREFIX.len()] == b'A' {
        b'B'
    } else {
        b'A'
    };
    assert_eq!(
        decode_production(
            std::str::from_utf8(&corrupt).unwrap(),
            TransferKind::Response
        ),
        Err(QrError::ChecksumMismatch)
    );
    assert_eq!(
        decode_production(
            &valid.replacen(PREFIX, "PISTIS2:", 1),
            TransferKind::Response
        ),
        Err(QrError::InvalidPrefix)
    );
    assert_eq!(
        decode_production("PISTIS1:é.0000000000000000", TransferKind::Response),
        Err(QrError::NonAscii)
    );
    assert_eq!(
        decode_production(
            &"A".repeat(MAX_TRANSFER_TEXT_BYTES + 1),
            TransferKind::Response
        ),
        Err(QrError::TooLarge)
    );
    assert_eq!(
        encode_production(ProductionTransferRef {
            kind: TransferKind::Response,
            cose: &vec![0; MAX_COSE_ENVELOPE_BYTES + 1],
        }),
        Err(QrError::TooLarge)
    );
}

#[test]
fn every_truncation_fails() {
    let cose = fixture_cose();
    let valid = encode_production(ProductionTransferRef {
        kind: TransferKind::Response,
        cose: &cose,
    })
    .unwrap();
    for length in 0..valid.len() {
        assert!(
            decode_production(&valid[..length], TransferKind::Response).is_err(),
            "truncation {length}"
        );
    }
}
