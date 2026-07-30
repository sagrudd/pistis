use pistis_qr::{
    QrError, TransferKind, decode_enrolment, decode_production, encode_enrolment_frame,
};

const FIXTURE: &str =
    include_str!("../../../fixtures/protocol-v3/first-device/presentation-positive.json");

fn fixture() -> serde_json::Value {
    serde_json::from_str(FIXTURE).unwrap()
}

fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn exact_fixture_round_trips_and_authentication_rejects_it() {
    let document = fixture();
    let frame = hex(document["frame_hex"].as_str().unwrap());
    let transfer = encode_enrolment_frame(&frame).unwrap();
    assert_eq!(transfer, document["qr_text"].as_str().unwrap());
    let decoded = decode_enrolment(&transfer).unwrap();
    assert!(!decoded.presentation_cose.is_empty());
    assert!(!decoded.authority_descriptor.is_empty());
    assert_eq!(
        decode_production(&transfer, TransferKind::Challenge),
        Err(QrError::InvalidFrame)
    );
}

#[test]
fn rejects_wrong_version_kind_corruption_and_every_truncation() {
    let document = fixture();
    let mut frame = hex(document["frame_hex"].as_str().unwrap());
    frame[2] = 2;
    assert_eq!(encode_enrolment_frame(&frame), Err(QrError::InvalidFrame));
    frame[2] = 3;
    frame[4] = 2;
    assert_eq!(encode_enrolment_frame(&frame), Err(QrError::InvalidFrame));

    let transfer = document["qr_text"].as_str().unwrap();
    let mut corrupt = transfer.as_bytes().to_vec();
    corrupt[8] = if corrupt[8] == b'A' { b'B' } else { b'A' };
    assert_eq!(
        decode_enrolment(std::str::from_utf8(&corrupt).unwrap()),
        Err(QrError::ChecksumMismatch)
    );
    for length in 0..transfer.len() {
        assert!(decode_enrolment(&transfer[..length]).is_err());
    }
}
