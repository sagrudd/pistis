//! Typed verifier for the one-use iPhone Site Root genesis binding fact.

use core::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use coset::{Algorithm, CborSerializable as _, CoseSign1, iana};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::VerifiedMobileEnrolmentReceiptV2;

/// Exact signed first-device binding schema.
pub const SITE_ROOT_GENESIS_DEVICE_BINDING_PROFILE_V1: &str =
    "pistis.site-root-genesis-device-binding.v1";
const MAXIMUM_WIRE_BYTES: usize = 16 * 1024;
const MAXIMUM_LIFETIME_MILLIS: u64 = 15 * 60 * 1_000;

/// Coarse failure for untrusted first-device binding input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SiteRootGenesisDeviceBindingErrorV1 {
    /// The wire, COSE envelope, or canonical encoding is malformed.
    Malformed,
    /// A well-formed input failed a protected binding or signature check.
    Denied,
}
impl fmt::Display for SiteRootGenesisDeviceBindingErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Site Root genesis device binding was denied")
    }
}
impl std::error::Error for SiteRootGenesisDeviceBindingErrorV1 {}

/// Server-owned, public registration context. Monas creates this only from its
/// durable App Attest registration row before it accepts the binding wire.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SiteRootGenesisBindingContextV1 {
    /// One-use Monas registration reference.
    pub registration_reference: String,
    /// Monas Site Trust domain.
    pub site_trust_domain: String,
    /// Lower-case SHA-256 of the frozen Site Trust payload.
    pub site_trust_payload_sha256: String,
    /// Face-ID Site Root key identifier.
    pub site_root_device_key_id: String,
    /// Face-ID Site Root compressed P-256 public key, base64url.
    pub site_root_public_key_compressed_sec1_base64url: String,
    /// Apple-verified registration key identifier, base64url.
    pub app_attest_registration_key_id_b64url: String,
    /// Server-issued timestamp.
    pub issued_at_unix_millis: u64,
    /// Server-enforced expiry.
    pub expires_at_unix_millis: u64,
}

/// Every expected claim of the strict iPhone binding fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedSiteRootGenesisDeviceBindingV1 {
    /// Stable deterministic replay identifier.
    pub fact_id: String,
    /// Expected one-use Monas registration reference.
    pub registration_reference: String,
    /// Verified Pistis installation identifier.
    pub installation_id: String,
    /// Verified Pistis device identifier.
    pub device_id: String,
    /// Verified Pistis device signing-key identifier.
    pub key_id: String,
    /// Verified Pistis principal identifier.
    pub principal_id: String,
    /// Verified external identity identifier.
    pub external_identity_id: String,
    /// Deterministically derived binding identifier.
    pub binding_id: String,
    /// Expected Site Trust domain.
    pub site_trust_domain: String,
    /// Expected frozen payload digest.
    pub site_trust_payload_sha256: String,
    /// Expected Site Root key identifier.
    pub site_root_device_key_id: String,
    /// Expected Site Root public key.
    pub site_root_public_key_compressed_sec1_base64url: String,
    /// Expected App Attest registration key identifier.
    pub app_attest_registration_key_id_b64url: String,
    /// Expected issue time.
    pub issued_at_unix_millis: u64,
    /// Expected expiry.
    pub expires_at_unix_millis: u64,
}

impl ExpectedSiteRootGenesisDeviceBindingV1 {
    /// Derive all Pistis identity claims only from a verified central receipt.
    ///
    /// # Errors
    ///
    /// Returns a coarse error when the protected Monas context is malformed,
    /// expired, or cannot produce the exact binding profile.
    pub fn from_verified_receipt(
        receipt: &VerifiedMobileEnrolmentReceiptV2,
        context: SiteRootGenesisBindingContextV1,
        now_unix_millis: u64,
    ) -> Result<Self, SiteRootGenesisDeviceBindingErrorV1> {
        if !valid_context(&context, now_unix_millis) {
            return Err(SiteRootGenesisDeviceBindingErrorV1::Denied);
        }
        let installation_id = b64(receipt.installation_id());
        let device_id = b64(receipt.device_id());
        let key_id = b64(receipt.device_key_id());
        let principal_id = b64(receipt.user_id());
        let external_identity_id = b64(receipt.external_identity_id());
        let binding_id = format!(
            "pistis-binding-{}",
            digest(&[
                receipt.installation_id(),
                receipt.device_id(),
                receipt.user_id(),
                receipt.external_identity_id()
            ])
        );
        let fact_id = format!(
            "pistis-genesis-fact-{}",
            digest(&[
                context.registration_reference.as_bytes(),
                installation_id.as_bytes(),
                device_id.as_bytes(),
                key_id.as_bytes(),
                principal_id.as_bytes(),
                external_identity_id.as_bytes(),
                binding_id.as_bytes(),
                context.site_trust_domain.as_bytes(),
                context.site_trust_payload_sha256.as_bytes(),
                context.site_root_device_key_id.as_bytes(),
            ])
        );
        Ok(Self {
            fact_id,
            registration_reference: context.registration_reference,
            installation_id,
            device_id,
            key_id,
            principal_id,
            external_identity_id,
            binding_id,
            site_trust_domain: context.site_trust_domain,
            site_trust_payload_sha256: context.site_trust_payload_sha256,
            site_root_device_key_id: context.site_root_device_key_id,
            site_root_public_key_compressed_sec1_base64url: context
                .site_root_public_key_compressed_sec1_base64url,
            app_attest_registration_key_id_b64url: context.app_attest_registration_key_id_b64url,
            issued_at_unix_millis: context.issued_at_unix_millis,
            expires_at_unix_millis: context.expires_at_unix_millis,
        })
    }
}

/// Signature-verified binding available only after every exact expected value matches.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSiteRootGenesisDeviceBindingV1 {
    expected: ExpectedSiteRootGenesisDeviceBindingV1,
    canonical_digest: [u8; 32],
}
impl VerifiedSiteRootGenesisDeviceBindingV1 {
    /// Return the one-use fact identifier.
    #[must_use]
    pub fn fact_id(&self) -> &str {
        &self.expected.fact_id
    }
    /// Return the matched registration reference.
    #[must_use]
    pub fn registration_reference(&self) -> &str {
        &self.expected.registration_reference
    }
    /// Return SHA-256 of authenticated JCS binding bytes.
    #[must_use]
    pub const fn canonical_digest(&self) -> &[u8; 32] {
        &self.canonical_digest
    }
}

/// Decode and verify one strict iPhone binding against a receipt-derived expectation.
///
/// # Errors
///
/// Returns a coarse error for malformed, non-canonical, substituted, expired
/// or cryptographically invalid input.
pub fn decode_and_verify_site_root_genesis_device_binding_v1(
    encoded: &[u8],
    expected: ExpectedSiteRootGenesisDeviceBindingV1,
    now: u64,
) -> Result<VerifiedSiteRootGenesisDeviceBindingV1, SiteRootGenesisDeviceBindingErrorV1> {
    if !valid_expected(&expected, now) || encoded.is_empty() || encoded.len() > MAXIMUM_WIRE_BYTES {
        return Err(SiteRootGenesisDeviceBindingErrorV1::Denied);
    }
    let wire: BindingWireV1 = serde_json::from_slice(encoded)
        .map_err(|_| SiteRootGenesisDeviceBindingErrorV1::Malformed)?;
    if !wire.one_use
        || wire.schema != SITE_ROOT_GENESIS_DEVICE_BINDING_PROFILE_V1
        || !matches_expected(&wire, &expected)
        || canonical_wire(&wire).as_bytes() != encoded
    {
        return Err(SiteRootGenesisDeviceBindingErrorV1::Denied);
    }
    let payload = canonical_payload(&wire);
    let cose = decode_b64(&wire.cose_sign1_base64url, 1, MAXIMUM_WIRE_BYTES)
        .ok_or(SiteRootGenesisDeviceBindingErrorV1::Malformed)?;
    let public = decode_b64(
        &expected.site_root_public_key_compressed_sec1_base64url,
        33,
        33,
    )
    .ok_or(SiteRootGenesisDeviceBindingErrorV1::Denied)?;
    verify_detached(
        &cose,
        payload.as_bytes(),
        &expected.site_root_device_key_id,
        &public,
    )?;
    Ok(VerifiedSiteRootGenesisDeviceBindingV1 {
        expected,
        canonical_digest: Sha256::digest(payload.as_bytes()).into(),
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingWireV1 {
    schema: String,
    fact_id: String,
    registration_reference: String,
    installation_id: String,
    device_id: String,
    key_id: String,
    principal_id: String,
    external_identity_id: String,
    binding_id: String,
    site_trust_domain: String,
    site_trust_payload_sha256: String,
    site_root_device_key_id: String,
    site_root_public_key_compressed_sec1_base64url: String,
    app_attest_registration_key_id_b64url: String,
    issued_at_unix_millis: u64,
    expires_at_unix_millis: u64,
    one_use: bool,
    cose_sign1_base64url: String,
}
fn matches_expected(w: &BindingWireV1, e: &ExpectedSiteRootGenesisDeviceBindingV1) -> bool {
    w.fact_id == e.fact_id
        && w.registration_reference == e.registration_reference
        && w.installation_id == e.installation_id
        && w.device_id == e.device_id
        && w.key_id == e.key_id
        && w.principal_id == e.principal_id
        && w.external_identity_id == e.external_identity_id
        && w.binding_id == e.binding_id
        && w.site_trust_domain == e.site_trust_domain
        && w.site_trust_payload_sha256 == e.site_trust_payload_sha256
        && w.site_root_device_key_id == e.site_root_device_key_id
        && w.site_root_public_key_compressed_sec1_base64url
            == e.site_root_public_key_compressed_sec1_base64url
        && w.app_attest_registration_key_id_b64url == e.app_attest_registration_key_id_b64url
        && w.issued_at_unix_millis == e.issued_at_unix_millis
        && w.expires_at_unix_millis == e.expires_at_unix_millis
}
fn canonical_payload(w: &BindingWireV1) -> String {
    format!(
        "{{\"app_attest_registration_key_id_b64url\":\"{}\",\"binding_id\":\"{}\",\"device_id\":\"{}\",\"expires_at_unix_millis\":{},\"external_identity_id\":\"{}\",\"fact_id\":\"{}\",\"installation_id\":\"{}\",\"issued_at_unix_millis\":{},\"key_id\":\"{}\",\"one_use\":true,\"principal_id\":\"{}\",\"registration_reference\":\"{}\",\"schema\":\"{}\",\"site_root_device_key_id\":\"{}\",\"site_root_public_key_compressed_sec1_base64url\":\"{}\",\"site_trust_domain\":\"{}\",\"site_trust_payload_sha256\":\"{}\"}}",
        w.app_attest_registration_key_id_b64url,
        w.binding_id,
        w.device_id,
        w.expires_at_unix_millis,
        w.external_identity_id,
        w.fact_id,
        w.installation_id,
        w.issued_at_unix_millis,
        w.key_id,
        w.principal_id,
        w.registration_reference,
        w.schema,
        w.site_root_device_key_id,
        w.site_root_public_key_compressed_sec1_base64url,
        w.site_trust_domain,
        w.site_trust_payload_sha256
    )
}
fn canonical_wire(w: &BindingWireV1) -> String {
    let p = canonical_payload(w);
    let marker = ",\"cose_sign1_base64url\":\"";
    let at = p.find(",\"device_id\"").unwrap();
    format!(
        "{}{}{}\"{}",
        &p[..at],
        marker,
        w.cose_sign1_base64url,
        &p[at..]
    )
}
fn valid_context(c: &SiteRootGenesisBindingContextV1, now: u64) -> bool {
    valid_text(&c.registration_reference)
        && valid_text(&c.site_trust_domain)
        && valid_text(&c.site_root_device_key_id)
        && valid_hex(&c.site_trust_payload_sha256)
        && c.issued_at_unix_millis <= now
        && c.expires_at_unix_millis > now
        && c.expires_at_unix_millis - c.issued_at_unix_millis <= MAXIMUM_LIFETIME_MILLIS
        && valid_site_root_key_binding(
            &c.site_root_device_key_id,
            &c.site_root_public_key_compressed_sec1_base64url,
        )
        && decode_b64(&c.app_attest_registration_key_id_b64url, 32, 32).is_some()
}
fn valid_expected(e: &ExpectedSiteRootGenesisDeviceBindingV1, now: u64) -> bool {
    valid_context(
        &SiteRootGenesisBindingContextV1 {
            registration_reference: e.registration_reference.clone(),
            site_trust_domain: e.site_trust_domain.clone(),
            site_trust_payload_sha256: e.site_trust_payload_sha256.clone(),
            site_root_device_key_id: e.site_root_device_key_id.clone(),
            site_root_public_key_compressed_sec1_base64url: e
                .site_root_public_key_compressed_sec1_base64url
                .clone(),
            app_attest_registration_key_id_b64url: e.app_attest_registration_key_id_b64url.clone(),
            issued_at_unix_millis: e.issued_at_unix_millis,
            expires_at_unix_millis: e.expires_at_unix_millis,
        },
        now,
    ) && [
        &e.fact_id,
        &e.installation_id,
        &e.device_id,
        &e.key_id,
        &e.principal_id,
        &e.external_identity_id,
        &e.binding_id,
    ]
    .iter()
    .all(|x| valid_text(x))
}
fn verify_detached(
    bytes: &[u8],
    payload: &[u8],
    kid: &str,
    public: &[u8],
) -> Result<(), SiteRootGenesisDeviceBindingErrorV1> {
    let sign1 =
        CoseSign1::from_slice(bytes).map_err(|_| SiteRootGenesisDeviceBindingErrorV1::Malformed)?;
    if sign1
        .clone()
        .to_vec()
        .map_err(|_| SiteRootGenesisDeviceBindingErrorV1::Malformed)?
        != bytes
        || sign1.payload.is_some()
        || !sign1.unprotected.is_empty()
        || sign1.protected.header.alg != Some(Algorithm::Assigned(iana::Algorithm::ES256))
        || sign1.protected.header.key_id != kid.as_bytes()
        || !sign1.protected.header.crit.is_empty()
        || sign1.signature.len() != 64
    {
        return Err(SiteRootGenesisDeviceBindingErrorV1::Denied);
    }
    let key = VerifyingKey::from_sec1_bytes(public)
        .map_err(|_| SiteRootGenesisDeviceBindingErrorV1::Denied)?;
    sign1.verify_detached_signature(payload, &[], |signature, tbs| {
        let s = Signature::from_slice(signature)
            .map_err(|_| SiteRootGenesisDeviceBindingErrorV1::Denied)?;
        if s.normalize_s().is_some() {
            return Err(SiteRootGenesisDeviceBindingErrorV1::Denied);
        }
        key.verify(tbs, &s)
            .map_err(|_| SiteRootGenesisDeviceBindingErrorV1::Denied)
    })
}
fn b64(value: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(value)
}
fn digest(values: &[&[u8]]) -> String {
    let mut bytes = b"pistis.site-root-genesis-device-binding.v1\0".to_vec();
    for value in values {
        bytes.extend_from_slice(&(u32::try_from(value.len()).unwrap()).to_be_bytes());
        bytes.extend_from_slice(value);
    }
    b64(&Sha256::digest(bytes))
}
fn decode_b64(value: &str, min: usize, max: usize) -> Option<Vec<u8>> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
    (bytes.len() >= min && bytes.len() <= max && URL_SAFE_NO_PAD.encode(&bytes) == value)
        .then_some(bytes)
}
fn valid_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|b| (0x21..=0x7e).contains(&b) && b != b'"' && b != b'\\')
}
fn valid_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_site_root_key_binding(key_id: &str, public_key: &str) -> bool {
    let Some(public_key) = decode_b64(public_key, 33, 33) else {
        return false;
    };
    let mut derived = String::from("site-root-");
    for byte in Sha256::digest(public_key) {
        use core::fmt::Write as _;
        let _ = write!(derived, "{byte:02x}");
    }
    key_id == derived
}

#[cfg(test)]
mod tests {
    use super::*;
    use coset::{CoseSign1Builder, HeaderBuilder};
    use p256::ecdsa::{SigningKey, signature::Signer as _};

    fn expected() -> ExpectedSiteRootGenesisDeviceBindingV1 {
        let signer = SigningKey::from_bytes((&[7; 32]).into()).unwrap();
        let public = signer.verifying_key().to_encoded_point(true);
        let public_b64 = URL_SAFE_NO_PAD.encode(public.as_bytes());
        let key_id = format!("site-root-{}", hex_digest(public.as_bytes()));
        ExpectedSiteRootGenesisDeviceBindingV1::from_verified_receipt(
            &VerifiedMobileEnrolmentReceiptV2::test_fixture(),
            SiteRootGenesisBindingContextV1 {
                registration_reference: "genesis-registration-01".into(),
                site_trust_domain: "mnemosyne.example.test".into(),
                site_trust_payload_sha256: "a".repeat(64),
                site_root_device_key_id: key_id,
                site_root_public_key_compressed_sec1_base64url: public_b64,
                app_attest_registration_key_id_b64url: URL_SAFE_NO_PAD.encode([1; 32]),
                issued_at_unix_millis: 1_000,
                expires_at_unix_millis: 2_000,
            },
            1_500,
        )
        .unwrap()
    }

    fn hex_digest(value: &[u8]) -> String {
        let mut encoded = String::new();
        for byte in Sha256::digest(value) {
            use core::fmt::Write as _;
            let _ = write!(encoded, "{byte:02x}");
        }
        encoded
    }

    fn signed_wire(expected: &ExpectedSiteRootGenesisDeviceBindingV1) -> Vec<u8> {
        let signer = SigningKey::from_bytes((&[7; 32]).into()).unwrap();
        let unsigned = BindingWireV1 {
            schema: SITE_ROOT_GENESIS_DEVICE_BINDING_PROFILE_V1.into(),
            fact_id: expected.fact_id.clone(),
            registration_reference: expected.registration_reference.clone(),
            installation_id: expected.installation_id.clone(),
            device_id: expected.device_id.clone(),
            key_id: expected.key_id.clone(),
            principal_id: expected.principal_id.clone(),
            external_identity_id: expected.external_identity_id.clone(),
            binding_id: expected.binding_id.clone(),
            site_trust_domain: expected.site_trust_domain.clone(),
            site_trust_payload_sha256: expected.site_trust_payload_sha256.clone(),
            site_root_device_key_id: expected.site_root_device_key_id.clone(),
            site_root_public_key_compressed_sec1_base64url: expected
                .site_root_public_key_compressed_sec1_base64url
                .clone(),
            app_attest_registration_key_id_b64url: expected
                .app_attest_registration_key_id_b64url
                .clone(),
            issued_at_unix_millis: expected.issued_at_unix_millis,
            expires_at_unix_millis: expected.expires_at_unix_millis,
            one_use: true,
            cose_sign1_base64url: String::new(),
        };
        let payload = canonical_payload(&unsigned);
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .key_id(expected.site_root_device_key_id.as_bytes().to_vec())
            .build();
        let cose = CoseSign1Builder::new()
            .protected(protected)
            .create_detached_signature(payload.as_bytes(), &[], |tbs| {
                let signature: Signature = signer.sign(tbs);
                signature
                    .normalize_s()
                    .unwrap_or(signature)
                    .to_bytes()
                    .to_vec()
            })
            .build()
            .to_vec()
            .unwrap();
        let signed = BindingWireV1 {
            cose_sign1_base64url: URL_SAFE_NO_PAD.encode(cose),
            ..unsigned
        };
        canonical_wire(&signed).into_bytes()
    }

    #[test]
    fn receipt_derived_binding_requires_an_exact_canonical_es256_fact() {
        let expected = expected();
        let wire = signed_wire(&expected);
        let decoded: BindingWireV1 = serde_json::from_slice(&wire).unwrap();
        assert_eq!(canonical_wire(&decoded).as_bytes(), wire);
        let cose = URL_SAFE_NO_PAD
            .decode(&decoded.cose_sign1_base64url)
            .unwrap();
        assert!(CoseSign1::from_slice(&cose).is_ok());
        let verified =
            decode_and_verify_site_root_genesis_device_binding_v1(&wire, expected.clone(), 1_500)
                .unwrap();
        assert_eq!(verified.fact_id(), expected.fact_id);
        assert_eq!(
            verified.registration_reference(),
            expected.registration_reference
        );
        assert_ne!(verified.canonical_digest(), &[0; 32]);

        let mut substituted = wire;
        *substituted.last_mut().unwrap() = b'X';
        assert!(
            decode_and_verify_site_root_genesis_device_binding_v1(&substituted, expected, 1_500,)
                .is_err()
        );
    }
}
