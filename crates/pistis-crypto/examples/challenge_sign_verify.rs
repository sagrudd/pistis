//! TEST-ONLY signing demonstration for local development.
//!
//! Pistis production crates expose verification only. This example keeps a
//! fixed, publicly disclosed private key in source solely to demonstrate the
//! challenge/sign/verify flow. Never adapt this key handling for production.

use p256::ecdsa::{
    Signature, SigningKey,
    signature::{Signer, Verifier},
};
use pistis_crypto::{PublicKey, SignatureSuite, verify};
use std::fmt::Write as _;

const TEST_ONLY_PRIVATE_KEY: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

// A deterministic, canonical CBOR map representing a demonstration challenge:
// {1: h'000102...1f', 2: 1700000000000}.
const CANONICAL_CHALLENGE: [u8; 46] = [
    0xa2, 0x01, 0x58, 0x20, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    0x1c, 0x1d, 0x1e, 0x1f, 0x02, 0x1b, 0x00, 0x00, 0x01, 0x8b, 0xcf, 0xe5, 0x68, 0x00,
];

fn main() -> Result<(), String> {
    let signing_key = SigningKey::from_bytes((&TEST_ONLY_PRIVATE_KEY).into())
        .map_err(|_| "invalid TEST-ONLY private key")?;
    let signature: Signature = signing_key.sign(&CANONICAL_CHALLENGE);

    // Independently exercise both the reviewed dependency and the Pistis
    // verification boundary over the exact same canonical bytes.
    signing_key
        .verifying_key()
        .verify(&CANONICAL_CHALLENGE, &signature)
        .map_err(|_| "dependency rejected generated signature")?;
    let public_key = PublicKey::from_sec1_bytes(
        signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes(),
    )
    .map_err(|error| error.to_string())?;
    let signature_bytes = signature.to_bytes();
    verify(
        SignatureSuite::Es256,
        &public_key,
        &CANONICAL_CHALLENGE,
        &signature_bytes,
    )
    .map_err(|error| error.to_string())?;

    let mut encoded_signature = String::with_capacity(signature_bytes.len() * 2);
    for byte in signature_bytes {
        write!(encoded_signature, "{byte:02x}").map_err(|error| error.to_string())?;
    }
    if encoded_signature
        != include_str!("../../../fixtures/protocol-v1/crypto/signature-cose.hex").trim()
    {
        return Err("signature differs from retained fixture".to_owned());
    }

    println!("verified TEST-ONLY challenge fixture with ES256");
    println!("signature={encoded_signature}");
    Ok(())
}
