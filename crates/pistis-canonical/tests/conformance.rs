//! Cross-implementation conformance and negative tests.

use pistis_canonical::{CanonicalError, Value, from_slice, from_slice_with_fields, to_vec};
use std::collections::BTreeMap;
use std::fmt::Write;

const GOLDEN: &[u8] =
    include_bytes!("../../../fixtures/protocol-v1/canonical/minimal-payload.cbor");
const GOLDEN_HEX: &str =
    include_str!("../../../fixtures/protocol-v1/canonical/minimal-payload.hex");

fn golden_value() -> Value {
    Value::Map(BTreeMap::from([
        (0, Value::Unsigned(1)),
        (1, Value::Text("authentication-challenge".into())),
        (2, Value::Bytes(vec![0, 1, 2, 3])),
        (3, Value::Unsigned(1_700_000_000)),
    ]))
}

#[test]
fn independent_golden_bytes_match() {
    assert_eq!(to_vec(&golden_value()).unwrap(), GOLDEN);
    assert_eq!(from_slice(GOLDEN).unwrap(), golden_value());
    let mut rendered_hex = String::with_capacity(GOLDEN.len() * 2);
    for byte in GOLDEN {
        write!(rendered_hex, "{byte:02x}").unwrap();
    }
    assert_eq!(rendered_hex, GOLDEN_HEX.trim());
}

#[test]
fn every_single_byte_truncation_fails() {
    for length in 0..GOLDEN.len() {
        assert!(from_slice(&GOLDEN[..length]).is_err(), "length {length}");
    }
}

#[test]
fn closed_schema_accepts_exact_fixture_fields() {
    assert!(from_slice_with_fields(GOLDEN, &[0, 1, 2, 3]).is_ok());
    assert_eq!(
        from_slice_with_fields(GOLDEN, &[0, 1, 2]),
        Err(CanonicalError::UnknownCriticalField(3))
    );
}
