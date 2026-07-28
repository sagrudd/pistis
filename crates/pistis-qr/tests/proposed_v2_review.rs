//! Executable review vector for proposed ADR 0021.
//!
//! This test does not add a v2 production decoder. It independently checks the
//! byte proposal so Rust and Swift reviewers inspect the same candidate.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use pistis_canonical::{Value, from_slice_with_fields};
use pistis_crypto::sha256;
use std::fmt::Write as _;

const PREFIX: &str = "PISTIS1:";
const FIELDS: &[u64] = &[0, 1, 2];

fn parse_review_response(input: &str) -> Result<Vec<u8>, ()> {
    if input.len() > 2_331 || !input.is_ascii() {
        return Err(());
    }
    let rest = input.strip_prefix(PREFIX).ok_or(())?;
    let (body, checksum) = rest.rsplit_once('.').ok_or(())?;
    if body.is_empty()
        || body.contains('=')
        || !body
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        || checksum.len() != 16
        || !checksum
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(());
    }
    let digest = sha256(format!("{PREFIX}{body}").as_bytes());
    if checksum != encode_hex(&digest.as_bytes()[..8]) {
        return Err(());
    }
    let frame = URL_SAFE_NO_PAD.decode(body).map_err(|_| ())?;
    let mut fields = from_slice_with_fields(&frame, FIELDS).map_err(|_| ())?;
    if fields.len() != FIELDS.len()
        || fields.remove(&0) != Some(Value::Unsigned(2))
        || fields.remove(&1) != Some(Value::Unsigned(2))
    {
        return Err(());
    }
    match fields.remove(&2) {
        Some(Value::Bytes(envelope)) => Ok(envelope),
        _ => Err(()),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut output, byte| {
            write!(output, "{byte:02x}").expect("writing to String cannot fail");
            output
        },
    )
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
fn proposed_response_wraps_the_accepted_cose_fixture_exactly() {
    let transfer = include_str!("../../../fixtures/proposed-qr-v2/response-positive.qr.txt").trim();
    let envelope = parse_review_response(transfer).expect("proposed review vector");
    assert_eq!(
        envelope,
        decode_hex(include_str!(
            "../../../fixtures/protocol-v1/cose/positive-envelope.hex"
        ))
    );
}

#[test]
fn proposed_review_parser_rejects_version_kind_checksum_and_alphabet_changes() {
    let transfer = include_str!("../../../fixtures/proposed-qr-v2/response-positive.qr.txt").trim();
    assert!(parse_review_response(&transfer.replacen("PISTIS1:", "PISTIS2:", 1)).is_err());
    assert!(parse_review_response(&format!("{transfer}=")).is_err());

    let mut checksum_changed = transfer.as_bytes().to_vec();
    let last = checksum_changed.last_mut().expect("non-empty fixture");
    *last = if *last == b'0' { b'1' } else { b'0' };
    assert!(parse_review_response(std::str::from_utf8(&checksum_changed).expect("ASCII")).is_err());

    let body = transfer
        .strip_prefix(PREFIX)
        .and_then(|rest| rest.rsplit_once('.').map(|(body, _)| body))
        .expect("fixture shape");
    let mut frame = URL_SAFE_NO_PAD.decode(body).expect("fixture base64");
    frame[2] = 1;
    let changed_body = URL_SAFE_NO_PAD.encode(frame);
    let digest = sha256(format!("{PREFIX}{changed_body}").as_bytes());
    let version_one = format!(
        "{PREFIX}{changed_body}.{}",
        encode_hex(&digest.as_bytes()[..8])
    );
    assert!(parse_review_response(&version_one).is_err());
}
