use pistis_canonical::{Value, from_slice, to_vec};
use pistis_cose::{decode, signing_input, verify_sign1};
use pistis_crypto::{PublicKey, derive_key_id, sha256};
use serde_json::Value as JsonValue;

const FIXTURE: &str = include_str!(
    "../../../fixtures/protocol-v1/enrolment/pistis-enrolment-v1-cross-project-001.json"
);

fn hex(name: &str) -> Vec<u8> {
    let document: JsonValue = serde_json::from_str(FIXTURE).unwrap();
    let text = document[name].as_str().unwrap();
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

fn binding_schema(bytes: &[u8]) -> Result<(), ()> {
    let Value::Map(fields) = from_slice(bytes).map_err(|_| ())? else {
        return Err(());
    };
    if fields.len() != 16
        || fields.keys().copied().collect::<Vec<_>>() != (0..16).collect::<Vec<_>>()
    {
        return Err(());
    }
    matches!(fields.get(&0), Some(Value::Text(profile)) if profile == "pistis.enrolment-binding.v1")
        .then_some(())
        .ok_or(())
}

fn lookup_schema(bytes: &[u8]) -> Result<(), ()> {
    let Value::Map(fields) = from_slice(bytes).map_err(|_| ())? else {
        return Err(());
    };
    (fields.len() == 5 && fields.keys().copied().collect::<Vec<_>>() == (0..5).collect::<Vec<_>>())
        .then_some(())
        .ok_or(())
}

#[test]
fn cross_project_fixture_is_byte_exact_and_strict() {
    let public = PublicKey::from_sec1_bytes(&hex("public_key_compressed_sec1_hex")).unwrap();
    let key_id = derive_key_id(&public);
    assert_eq!(key_id.as_bytes().as_slice(), hex("key_id_hex"));

    let binding = hex("binding_payload_hex");
    assert!(binding_schema(&binding).is_ok());
    let Value::Map(mut changed) = from_slice(&binding).unwrap() else {
        unreachable!()
    };
    changed.insert(16, Value::Unsigned(1));
    assert!(binding_schema(&to_vec(&Value::Map(changed)).unwrap()).is_err());
    assert!(from_slice(&[0x18, 0x00]).is_err());

    let binding_envelope = hex("binding_cose_sign1_hex");
    let lookup_envelope = hex("lookup_cose_sign1_hex");
    let binding_decoded = verify_sign1(&binding_envelope, &public).unwrap();
    let lookup_decoded = verify_sign1(&lookup_envelope, &public).unwrap();
    assert_eq!(binding_decoded.payload(), binding);
    assert_eq!(lookup_decoded.payload(), hex("lookup_payload_hex"));
    assert_eq!(decode(&binding_envelope).unwrap().key_id(), key_id);
    assert_eq!(
        binding_decoded.signature().as_slice(),
        hex("binding_signature_raw_low_s_hex")
    );
    assert_eq!(
        lookup_decoded.signature().as_slice(),
        hex("lookup_signature_raw_low_s_hex")
    );
    let protected = hex("protected_headers_hex");
    let Value::Array(binding_parts) = from_slice(&binding_envelope).unwrap() else {
        unreachable!()
    };
    assert_eq!(binding_parts[0], Value::Bytes(protected.clone()));
    let Value::Array(lookup_parts) = from_slice(&lookup_envelope).unwrap() else {
        unreachable!()
    };
    assert_eq!(lookup_parts[0], Value::Bytes(protected.clone()));
    assert_eq!(
        signing_input(&binding, key_id).unwrap(),
        hex("binding_sig_structure_hex")
    );
    assert_eq!(
        signing_input(lookup_decoded.payload(), key_id).unwrap(),
        hex("lookup_sig_structure_hex")
    );
    assert_eq!(protected, hex("protected_headers_hex"));

    let binding_value: Value = from_slice(&binding).unwrap();
    assert_eq!(to_vec(&binding_value).unwrap(), binding);
    let commit = hex("commit_preimage_hex");
    assert_eq!(
        sha256(&commit).as_bytes().as_slice(),
        hex("commit_digest_sha256_hex")
    );

    let Value::Array(commit_fields) = from_slice(&commit).unwrap() else {
        unreachable!()
    };
    assert_eq!(commit_fields.len(), 11);
    assert_eq!(
        commit_fields[0],
        Value::Text("pistis.commit-enrolment.v1".into())
    );
    assert_eq!(commit_fields[1], Value::Bytes(binding));
    assert_eq!(commit_fields[2], Value::Bytes(vec![0x20; 16]));
    assert_eq!(commit_fields[3], Value::Bytes(vec![0x30; 16]));
    assert_eq!(commit_fields[4], Value::Bytes(vec![0x40; 16]));
    assert_eq!(commit_fields[5], Value::Bytes(vec![0x50; 16]));
    assert_eq!(commit_fields[6], Value::Unsigned(1));
    assert_eq!(commit_fields[7], Value::Unsigned(7));
    assert_eq!(commit_fields[8], Value::Bytes(vec![0x55; 32]));
    assert_eq!(commit_fields[9], Value::Bytes(vec![0x66; 32]));
    assert_eq!(commit_fields[10], Value::Unsigned(1_700_000_000_000));

    let lookup = hex("lookup_payload_hex");
    let Value::Map(mut lookup_fields) = from_slice(&lookup).unwrap() else {
        unreachable!()
    };
    assert_eq!(lookup_fields.len(), 5);
    assert_eq!(
        lookup_fields.keys().copied().collect::<Vec<_>>(),
        (0..5).collect::<Vec<_>>()
    );
    assert_eq!(
        lookup_fields.remove(&0),
        Some(Value::Text("pistis.enrolment-receipt-lookup.v1".into()))
    );
    assert_eq!(lookup_fields.remove(&1), Some(Value::Bytes(vec![0x77; 32])));
    assert_eq!(lookup_fields.remove(&2), Some(Value::Bytes(vec![0x10; 16])));
    assert_eq!(
        lookup_fields.remove(&3),
        Some(Value::Bytes(hex("commit_digest_sha256_hex")))
    );
    assert_eq!(
        lookup_fields.remove(&4),
        Some(Value::Text("prosopikon:pistis:enrolment".into()))
    );
    let Value::Map(mut extra_lookup) = from_slice(&lookup).unwrap() else {
        unreachable!()
    };
    extra_lookup.insert(5, Value::Unsigned(1));
    assert!(lookup_schema(&to_vec(&Value::Map(extra_lookup)).unwrap()).is_err());
}
