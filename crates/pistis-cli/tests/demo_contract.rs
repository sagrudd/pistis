//! Contract checks for the funding-review demonstration manifest.

use pistis_cli::{AuthCommand, parse};
use pistis_qr::{TransferKind, decode};
use sha2::{Digest, Sha256};
use std::{fmt::Write as _, fs, path::PathBuf};

const MANIFEST: &str =
    include_str!("../../../fixtures/demonstration/cli-iphone-kyberneterion-v1.json");
const FIRST_DEVICE: &str =
    include_str!("../../../fixtures/protocol-v4/first-device/presentation-positive.json");
const CHALLENGE_QR: &str =
    include_str!("../../../fixtures/protocol-v1/qr/challenge-minimal.qr.txt");
const MONAS_PRODUCT_AUDIENCE: &str = "propylaion";

fn hex_digest(bytes: &[u8]) -> String {
    let mut digest = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(digest, "{byte:02x}").expect("writing to String cannot fail");
    }
    digest
}

#[test]
fn manifest_is_redacted_and_ordered_for_the_review_demo() {
    let manifest: serde_json::Value = serde_json::from_str(MANIFEST).unwrap();
    assert_eq!(
        manifest["schema"],
        "pistis.cli-iphone-kyberneterion-demonstration.v1"
    );
    assert_eq!(manifest["verdict"], "not_run");
    assert_eq!(manifest["live_claim"], false);
    assert_eq!(manifest["live_credentials_used"], false);

    let steps = manifest["steps"].as_array().unwrap();
    let ids = steps
        .iter()
        .map(|step| step["id"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        ids,
        [
            "cli-user-registration",
            "iphone-host-trust",
            "monas-web-qr-login",
            "kyberneterion-workflow-selection",
            "negative-fail-closed",
        ]
    );

    let serialised = MANIFEST.to_ascii_lowercase();
    for forbidden in [
        "private_key",
        "private-key",
        "provider_token",
        "provider-token",
        "cookie",
        "capability",
        "nonce",
        "signature",
    ] {
        assert!(
            !serialised.contains(forbidden),
            "demo manifest must not contain {forbidden}"
        );
    }
}

#[test]
fn fixture_digests_and_qr_kind_are_stable() {
    let manifest: serde_json::Value = serde_json::from_str(MANIFEST).unwrap();
    let first_device_digest = hex_digest(&Sha256::digest(FIRST_DEVICE.as_bytes()));
    assert_eq!(manifest["steps"][0]["input_sha256"], first_device_digest);
    let challenge_digest = hex_digest(&Sha256::digest(CHALLENGE_QR.as_bytes()));
    assert_eq!(manifest["steps"][2]["challenge_sha256"], challenge_digest);

    let (payload, signature) = decode(CHALLENGE_QR.trim(), TransferKind::Challenge).unwrap();
    assert!(!payload.is_empty());
    assert_eq!(signature.len(), 64);
}

#[test]
fn monas_handoff_uses_an_authority_signed_product_audience() {
    let manifest: serde_json::Value = serde_json::from_str(MANIFEST).unwrap();
    let enrolment: serde_json::Value = serde_json::from_str(FIRST_DEVICE).unwrap();
    let monas = &manifest["steps"][2];

    assert_eq!(monas["id"], "monas-web-qr-login");
    assert_eq!(monas["audience"], MONAS_PRODUCT_AUDIENCE);
    assert!(
        enrolment["authorised_product_audiences"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(serde_json::Value::as_str)
            .any(|audience| audience == MONAS_PRODUCT_AUDIENCE),
        "the Monas demo audience must be authorized by the signed enrolment fixture"
    );
    assert_ne!(
        monas["audience"], enrolment["audience"],
        "the product handoff must not reuse the enrolment ceremony audience"
    );
}

#[test]
fn selected_workflow_is_bound_to_the_exact_cli_argument_vector() {
    let manifest: serde_json::Value = serde_json::from_str(MANIFEST).unwrap();
    let command = manifest["steps"][3]["command"].as_array().unwrap();
    let arguments = command
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    let parsed = parse(arguments.into_iter().skip(1)).unwrap();
    let AuthCommand::Exec {
        command_digest,
        command: exact_command,
        ..
    } = parsed
    else {
        panic!("workflow selection must use exact-action approval");
    };
    assert_eq!(exact_command[0], "/usr/bin/nextflow");
    assert_ne!(command_digest, [0; 32]);

    let mut substituted = exact_command;
    substituted[3] = "das://demo/substituted".into();
    let substituted = std::iter::once("auth".to_owned())
        .chain(std::iter::once("exec".to_owned()))
        .chain(std::iter::once("--".to_owned()))
        .chain(substituted)
        .collect::<Vec<_>>();
    let AuthCommand::Exec {
        command_digest: substituted_digest,
        ..
    } = parse(substituted).unwrap()
    else {
        unreachable!();
    };
    assert_ne!(command_digest, substituted_digest);
}

#[test]
fn referenced_fixtures_exist_in_the_checkout() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    for path in [
        "fixtures/demonstration/cli-iphone-kyberneterion-v1.json",
        "fixtures/protocol-v4/first-device/presentation-positive.json",
        "fixtures/protocol-v1/qr/challenge-minimal.qr.txt",
    ] {
        assert!(
            fs::metadata(root.join(path)).is_ok(),
            "missing fixture {path}"
        );
    }
}
