//! Apple-root-verified registration factory for assertion acceptance.
//!
//! Monas remains the durable ceremony, session, counter, and registration
//! owner.  This module only verifies bounded iPhone registration evidence under
//! the release-pinned Apple root and produces the opaque acceptance required by
//! the sibling assertion verifier.  It never accepts caller-selected trust
//! material and has no persistence, route, or local-authority fallback.

use core::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ciborium::value::Value;
use coset::{CborSerializable as _, CoseKey, KeyType, Label, iana};
use p256::PublicKey;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use x509_parser::{parse_x509_certificate, pem::parse_x509_pem};

use crate::{
    CustodyRotationAppAttestRequestV1, MONAS_PRODUCTION_APP_ATTEST_APP_IDENTIFIER_V1,
    ServerHeldCustodyRotationAppAttestAcceptanceV1, ServerHeldMonasAppAttestAcceptanceV1,
    SiteTrustAttestationRequestV1,
};

/// Exact iPhone registration wire profile accepted by this factory.
pub const PISTIS_APP_ATTEST_REGISTRATION_PROFILE_V1: &str =
    "pistis.apple-app-attest-registration.v1";
/// Exact reviewed manifest profile shared with the Monas production verifier.
pub const MONAS_APP_ATTEST_REVIEWED_MANIFEST_PROFILE_V1: &str =
    "monas.apple-app-attest-reviewed-manifest.v1";

const MAXIMUM_REGISTRATION_JSON_BYTES: usize = 196_608;
const MAXIMUM_ATTESTATION_OBJECT_BYTES: usize = 131_072;
const MAXIMUM_CERTIFICATE_BYTES: usize = 16_384;
const APPLE_NONCE_EXTENSION_OID: &str = "1.2.840.113635.100.8.2";
const PRODUCTION_AAGUID: &[u8; 16] = b"appattest\0\0\0\0\0\0\0";
const REGISTRATION_MANIFEST_SHA256_B64URL: &str = "68Muj_qAmNAUNJYYV3Vv8gfWb708-mdjUNiYUYGOwaI";

const REVIEWED_MANIFEST: &[u8] =
    include_bytes!("../deploy/app-attest/apple-app-attest-production-manifest-v1.json");
const REVIEWED_ROOT_PEM: &[u8] =
    include_bytes!("../deploy/app-attest/Apple_App_Attestation_Root_CA.pem");

/// Coarse registration-factory failure without Apple object or certificate detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SiteTrustAppAttestRegistrationErrorV1 {
    /// The untrusted envelope or attestation object is malformed or oversized.
    Malformed,
    /// Evidence did not prove the exact production profile and server binding.
    Denied,
    /// Pinned reviewed material or cryptographic verification is unavailable.
    Unavailable,
}

impl fmt::Display for SiteTrustAppAttestRegistrationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Malformed => "Apple App Attest registration is malformed",
            Self::Denied => "Apple App Attest registration was denied",
            Self::Unavailable => "Apple App Attest registration verification is unavailable",
        })
    }
}

impl std::error::Error for SiteTrustAppAttestRegistrationErrorV1 {}

/// Bounded untrusted registration envelope from the iPhone.
///
/// It deliberately contains no server state, bundle expectation, trust bundle,
/// human authority fact, browser session, or counter.  Its Apple object is
/// transient and has no public accessor.
pub struct SiteTrustAppAttestRegistrationSubmissionV1 {
    ceremony_id: String,
    site_trust_domain: String,
    key_id: [u8; 32],
    client_data_hash: [u8; 32],
    attestation_object: Vec<u8>,
}

impl fmt::Debug for SiteTrustAppAttestRegistrationSubmissionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SiteTrustAppAttestRegistrationSubmissionV1")
            .field("profile", &PISTIS_APP_ATTEST_REGISTRATION_PROFILE_V1)
            .field("ceremony_id", &self.ceremony_id)
            .field("site_trust_domain", &self.site_trust_domain)
            .field("key_id", &"[REDACTED]")
            .field("client_data_hash", &"[REDACTED]")
            .field("attestation_object", &"[REDACTED]")
            .finish()
    }
}

/// Decode one strict iPhone registration submission without accepting authority.
///
/// # Errors
///
/// Returns a coarse malformed or denied result without exposing an Apple object
/// or credential in the error.
pub fn decode_site_trust_app_attest_registration_submission_v1(
    encoded: &[u8],
) -> Result<SiteTrustAppAttestRegistrationSubmissionV1, SiteTrustAppAttestRegistrationErrorV1> {
    if encoded.is_empty() || encoded.len() > MAXIMUM_REGISTRATION_JSON_BYTES {
        return Err(SiteTrustAppAttestRegistrationErrorV1::Malformed);
    }
    let envelope = serde_json::from_slice::<RegistrationEnvelopeV1>(encoded)
        .map_err(|_| SiteTrustAppAttestRegistrationErrorV1::Malformed)?;
    if envelope.protocol != PISTIS_APP_ATTEST_REGISTRATION_PROFILE_V1
        || envelope.app_identifier != MONAS_PRODUCTION_APP_ATTEST_APP_IDENTIFIER_V1
        || !valid_server_text(&envelope.ceremony_id, 128)
        || !valid_server_text(&envelope.site_trust_domain, 255)
    {
        return Err(SiteTrustAppAttestRegistrationErrorV1::Denied);
    }
    Ok(SiteTrustAppAttestRegistrationSubmissionV1 {
        ceremony_id: envelope.ceremony_id,
        site_trust_domain: envelope.site_trust_domain,
        key_id: decode_canonical_b64url::<32>(&envelope.key_id_b64url)?,
        client_data_hash: decode_canonical_b64url::<32>(&envelope.client_data_hash_b64url)?,
        attestation_object: decode_canonical_b64url_bytes(
            &envelope.attestation_object_b64url,
            1,
            MAXIMUM_ATTESTATION_OBJECT_BYTES,
        )?,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrationEnvelopeV1 {
    protocol: String,
    ceremony_id: String,
    site_trust_domain: String,
    app_identifier: String,
    key_id_b64url: String,
    client_data_hash_b64url: String,
    attestation_object_b64url: String,
}

/// Production-only Apple-root verifier and opaque acceptance factory.
///
/// Constructing this factory validates the release-pinned manifest and Apple
/// root.  It never reads a root, manifest, development profile, or App ID from
/// a mobile request or runtime configuration.
#[derive(Clone, Debug)]
pub struct ProductionAppleAppAttestAcceptanceFactoryV1 {
    manifest_digest: [u8; 32],
    root_pem: &'static [u8],
}

impl ProductionAppleAppAttestAcceptanceFactoryV1 {
    /// Load the immutable Apple root and reviewed production manifest packaged with Pistis.
    ///
    /// # Errors
    ///
    /// A release packaging, manifest, or root validation failure leaves the
    /// production factory unavailable rather than selecting alternate material.
    pub fn from_package() -> Result<Self, SiteTrustAppAttestRegistrationErrorV1> {
        let manifest_digest: [u8; 32] = Sha256::digest(REVIEWED_MANIFEST).into();
        if URL_SAFE_NO_PAD.encode(manifest_digest) != REGISTRATION_MANIFEST_SHA256_B64URL
            || !valid_reviewed_manifest(REVIEWED_MANIFEST, REVIEWED_ROOT_PEM)
        {
            return Err(SiteTrustAppAttestRegistrationErrorV1::Unavailable);
        }
        let (_, pem) = parse_x509_pem(REVIEWED_ROOT_PEM)
            .map_err(|_| SiteTrustAppAttestRegistrationErrorV1::Unavailable)?;
        let (remaining, root) = parse_x509_certificate(&pem.contents)
            .map_err(|_| SiteTrustAppAttestRegistrationErrorV1::Unavailable)?;
        if !remaining.is_empty()
            || root.as_raw() != pem.contents.as_slice()
            || root.verify_signature(None).is_err()
        {
            return Err(SiteTrustAppAttestRegistrationErrorV1::Unavailable);
        }
        Ok(Self {
            manifest_digest,
            root_pem: REVIEWED_ROOT_PEM,
        })
    }

    /// Verify a bounded iPhone registration and create opaque assertion acceptance.
    ///
    /// Monas supplies its already-created Site Trust request, registration
    /// ceremony/domain, expected client-data hash, and distributed bundle
    /// version.  The factory verifies every untrusted iPhone field and Apple
    /// attestation fact before returning an otherwise unconstructible value.
    /// Monas must durably retain its registration/replay state before using the
    /// acceptance to process a later assertion.
    ///
    /// # Errors
    ///
    /// Any unavailable package material, malformed evidence, failed Apple
    /// verification, or mismatch with Monas' supplied binding is denied.
    pub fn verify_registration_for_site_trust_assertion(
        &self,
        request: SiteTrustAttestationRequestV1,
        expected_registration_ceremony: &str,
        expected_site_trust_domain: &str,
        expected_client_data_hash: [u8; 32],
        expected_bundle_version: &str,
        submission: &SiteTrustAppAttestRegistrationSubmissionV1,
    ) -> Result<ServerHeldMonasAppAttestAcceptanceV1, SiteTrustAppAttestRegistrationErrorV1> {
        request
            .validate()
            .map_err(|_| SiteTrustAppAttestRegistrationErrorV1::Denied)?;
        if !valid_server_text(expected_registration_ceremony, 128)
            || !valid_server_text(expected_site_trust_domain, 255)
            || !valid_bundle_version(expected_bundle_version)
            || submission.ceremony_id != expected_registration_ceremony
            || submission.site_trust_domain != expected_site_trust_domain
            || submission.client_data_hash != expected_client_data_hash
            || submission.key_id != *request.key_id.as_bytes()
        {
            return Err(SiteTrustAppAttestRegistrationErrorV1::Denied);
        }
        let public_key = verify_pinned_apple_registration(
            &submission.attestation_object,
            submission.key_id,
            submission.client_data_hash,
            self.root_pem,
        )?;
        Ok(
            ServerHeldMonasAppAttestAcceptanceV1::from_verified_registration(
                request,
                public_key,
                self.manifest_digest,
                expected_bundle_version.into(),
            ),
        )
    }

    /// Reconstruct narrow custody-rotation acceptance from durable registration.
    ///
    /// This continuation is intentionally narrower than registration verification:
    /// it accepts no attestation object, trust root, application identity, session
    /// identity, or caller-selected verifier. Monas supplies only its server-owned
    /// custody-rotation request and fields read from the already verified durable
    /// genesis registration. The packaged production manifest is revalidated when
    /// the factory is created and its exact digest must match the durable row.
    ///
    /// The request contains no device, principal, human-authority fact, or session.
    /// Its installation, Site Trust domain, ceremony, production key, TLS leaf,
    /// genesis configuration, lifetime, and canonical challenge are already bound.
    ///
    /// # Errors
    ///
    /// Returns [`SiteTrustAppAttestRegistrationErrorV1::Denied`] for any durable
    /// binding mismatch, invalid key, unusable counter, or substituted request.
    /// Package-manifest failure is reported only by [`Self::from_package`] as
    /// unavailable.
    pub fn resume_durable_registration_for_custody_rotation(
        &self,
        request: CustodyRotationAppAttestRequestV1,
        registered_public_key_sec1: [u8; 65],
        durable_manifest_sha256: [u8; 32],
        expected_bundle_version: &str,
        previous_counter: u32,
    ) -> Result<ServerHeldCustodyRotationAppAttestAcceptanceV1, SiteTrustAppAttestRegistrationErrorV1>
    {
        let registered_key_digest: [u8; 32] = Sha256::digest(registered_public_key_sec1).into();
        if !valid_bundle_version(expected_bundle_version)
            || previous_counter == u32::MAX
            || registered_key_digest != *request.key_id().as_bytes()
            || PublicKey::from_sec1_bytes(&registered_public_key_sec1).is_err()
            || durable_manifest_sha256 != self.manifest_digest
        {
            return Err(SiteTrustAppAttestRegistrationErrorV1::Denied);
        }
        Ok(ServerHeldCustodyRotationAppAttestAcceptanceV1::new(
            request,
            registered_public_key_sec1,
            previous_counter,
            expected_bundle_version.into(),
        ))
    }
}

fn valid_reviewed_manifest(manifest: &[u8], root_pem: &[u8]) -> bool {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Manifest<'a> {
        protocol: &'a str,
        profile_id: &'a str,
        app_identifier: &'a str,
        environment: &'a str,
        trust_anchor_set_id: &'a str,
        trust_anchor_bundle_sha256_b64url: &'a str,
    }
    let Ok(manifest) = serde_json::from_slice::<Manifest<'_>>(manifest) else {
        return false;
    };
    manifest.protocol == MONAS_APP_ATTEST_REVIEWED_MANIFEST_PROFILE_V1
        && manifest.profile_id == "apple-app-attestation-root-ca-2020-03-18"
        && manifest.app_identifier == MONAS_PRODUCTION_APP_ATTEST_APP_IDENTIFIER_V1
        && manifest.environment == "Production"
        && manifest.trust_anchor_set_id == "apple-app-attestation-root-ca-2020-03-18"
        && manifest.trust_anchor_bundle_sha256_b64url
            == URL_SAFE_NO_PAD.encode(Sha256::digest(root_pem))
}

fn verify_pinned_apple_registration(
    attestation_object: &[u8],
    key_id: [u8; 32],
    client_data_hash: [u8; 32],
    root_pem: &[u8],
) -> Result<[u8; 65], SiteTrustAppAttestRegistrationErrorV1> {
    let shape = inspect_attestation_object(attestation_object)?;
    let facts = validate_registration_authenticator_data(&shape.authenticator_data, key_id)?;
    let (_, pem) =
        parse_x509_pem(root_pem).map_err(|_| SiteTrustAppAttestRegistrationErrorV1::Unavailable)?;
    let (remaining_root, root) = parse_x509_certificate(&pem.contents)
        .map_err(|_| SiteTrustAppAttestRegistrationErrorV1::Unavailable)?;
    if !remaining_root.is_empty()
        || !root.validity().is_valid()
        || root.verify_signature(None).is_err()
    {
        return Err(SiteTrustAppAttestRegistrationErrorV1::Unavailable);
    }
    let certificates = shape
        .certificate_chain
        .iter()
        .map(|der| {
            parse_x509_certificate(der)
                .ok()
                .and_then(|(remaining, certificate)| remaining.is_empty().then_some(certificate))
                .ok_or(SiteTrustAppAttestRegistrationErrorV1::Denied)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let [leaf, intermediate] = certificates.as_slice() else {
        return Err(SiteTrustAppAttestRegistrationErrorV1::Denied);
    };
    if !leaf.validity().is_valid()
        || !intermediate.validity().is_valid()
        || intermediate.issuer() != root.subject()
        || intermediate
            .verify_signature(Some(root.public_key()))
            .is_err()
        || leaf.issuer() != intermediate.subject()
        || leaf
            .verify_signature(Some(intermediate.public_key()))
            .is_err()
        || !intermediate
            .basic_constraints()
            .ok()
            .flatten()
            .is_some_and(|constraints| constraints.value.ca)
    {
        return Err(SiteTrustAppAttestRegistrationErrorV1::Denied);
    }
    let public_key_digest: [u8; 32] = Sha256::digest(facts.public_key_sec1).into();
    if leaf.public_key().subject_public_key.data.as_ref() != facts.public_key_sec1.as_slice()
        || public_key_digest != key_id
    {
        return Err(SiteTrustAppAttestRegistrationErrorV1::Denied);
    }
    let nonce_extensions = leaf
        .extensions()
        .iter()
        .filter(|extension| extension.oid.to_id_string() == APPLE_NONCE_EXTENSION_OID)
        .collect::<Vec<_>>();
    let [nonce_extension] = nonce_extensions.as_slice() else {
        return Err(SiteTrustAppAttestRegistrationErrorV1::Denied);
    };
    validate_nonce_extension(
        nonce_extension.value,
        &shape.authenticator_data,
        &client_data_hash,
    )?;
    Ok(facts.public_key_sec1)
}

struct RegistrationFactsV1 {
    public_key_sec1: [u8; 65],
}

fn validate_registration_authenticator_data(
    auth_data: &[u8],
    key_id: [u8; 32],
) -> Result<RegistrationFactsV1, SiteTrustAppAttestRegistrationErrorV1> {
    const FLAGS_OFFSET: usize = 32;
    const COUNTER_OFFSET: usize = 33;
    const AAGUID_OFFSET: usize = 37;
    const CREDENTIAL_LENGTH_OFFSET: usize = 53;
    const CREDENTIAL_OFFSET: usize = 55;
    let expected_rp_id_hash: [u8; 32] =
        Sha256::digest(MONAS_PRODUCTION_APP_ATTEST_APP_IDENTIFIER_V1).into();
    if auth_data.len() < CREDENTIAL_OFFSET
        || auth_data[..32] != expected_rp_id_hash
        || auth_data[FLAGS_OFFSET] != 0x41
        || auth_data[COUNTER_OFFSET..AAGUID_OFFSET] != [0; 4]
        || auth_data[AAGUID_OFFSET..CREDENTIAL_LENGTH_OFFSET] != PRODUCTION_AAGUID[..]
    {
        return Err(SiteTrustAppAttestRegistrationErrorV1::Denied);
    }
    let credential_length = usize::from(u16::from_be_bytes(
        auth_data[CREDENTIAL_LENGTH_OFFSET..CREDENTIAL_OFFSET]
            .try_into()
            .map_err(|_| SiteTrustAppAttestRegistrationErrorV1::Denied)?,
    ));
    let credential_end = CREDENTIAL_OFFSET
        .checked_add(credential_length)
        .ok_or(SiteTrustAppAttestRegistrationErrorV1::Denied)?;
    if credential_length != 32
        || credential_end >= auth_data.len()
        || auth_data[CREDENTIAL_OFFSET..credential_end] != key_id
    {
        return Err(SiteTrustAppAttestRegistrationErrorV1::Denied);
    }
    let cose_key = CoseKey::from_slice(&auth_data[credential_end..])
        .map_err(|_| SiteTrustAppAttestRegistrationErrorV1::Denied)?;
    if cose_key.kty != KeyType::Assigned(iana::KeyType::EC2)
        || cose_key.alg != Some(coset::Algorithm::Assigned(iana::Algorithm::ES256))
        || parameter_integer(&cose_key, -1) != Some(1)
    {
        return Err(SiteTrustAppAttestRegistrationErrorV1::Denied);
    }
    let x = parameter_bytes(&cose_key, -2).ok_or(SiteTrustAppAttestRegistrationErrorV1::Denied)?;
    let y = parameter_bytes(&cose_key, -3).ok_or(SiteTrustAppAttestRegistrationErrorV1::Denied)?;
    if x.len() != 32 || y.len() != 32 {
        return Err(SiteTrustAppAttestRegistrationErrorV1::Denied);
    }
    let mut public_key_sec1 = [0_u8; 65];
    public_key_sec1[0] = 0x04;
    public_key_sec1[1..33].copy_from_slice(x);
    public_key_sec1[33..].copy_from_slice(y);
    PublicKey::from_sec1_bytes(&public_key_sec1)
        .map_err(|_| SiteTrustAppAttestRegistrationErrorV1::Denied)?;
    Ok(RegistrationFactsV1 { public_key_sec1 })
}

fn inspect_attestation_object(
    object: &[u8],
) -> Result<AttestationObjectShapeV1, SiteTrustAppAttestRegistrationErrorV1> {
    if object.is_empty() || object.len() > MAXIMUM_ATTESTATION_OBJECT_BYTES {
        return Err(SiteTrustAppAttestRegistrationErrorV1::Malformed);
    }
    let value: Value = ciborium::de::from_reader(object)
        .map_err(|_| SiteTrustAppAttestRegistrationErrorV1::Malformed)?;
    let Value::Map(entries) = value else {
        return Err(SiteTrustAppAttestRegistrationErrorV1::Denied);
    };
    if entries.len() != 3 || map_text(&entries, "fmt") != Some("apple-appattest") {
        return Err(SiteTrustAppAttestRegistrationErrorV1::Denied);
    }
    let authenticator_data = map_bytes(&entries, "authData")
        .filter(|value| (55..=8192).contains(&value.len()))
        .ok_or(SiteTrustAppAttestRegistrationErrorV1::Denied)?;
    let Value::Map(statement) =
        map_value(&entries, "attStmt").ok_or(SiteTrustAppAttestRegistrationErrorV1::Denied)?
    else {
        return Err(SiteTrustAppAttestRegistrationErrorV1::Denied);
    };
    let Value::Array(chain) =
        map_value(statement, "x5c").ok_or(SiteTrustAppAttestRegistrationErrorV1::Denied)?
    else {
        return Err(SiteTrustAppAttestRegistrationErrorV1::Denied);
    };
    if statement.len() != 2 || chain.len() != 2 || map_bytes(statement, "receipt").is_none() {
        return Err(SiteTrustAppAttestRegistrationErrorV1::Denied);
    }
    let certificate_chain = chain
        .iter()
        .map(|value| match value {
            Value::Bytes(value)
                if !value.is_empty() && value.len() <= MAXIMUM_CERTIFICATE_BYTES =>
            {
                Ok(value.clone())
            }
            _ => Err(SiteTrustAppAttestRegistrationErrorV1::Denied),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(AttestationObjectShapeV1 {
        authenticator_data: authenticator_data.clone(),
        certificate_chain,
    })
}

struct AttestationObjectShapeV1 {
    authenticator_data: Vec<u8>,
    certificate_chain: Vec<Vec<u8>>,
}

fn validate_nonce_extension(
    extension: &[u8],
    auth_data: &[u8],
    client_data_hash: &[u8; 32],
) -> Result<(), SiteTrustAppAttestRegistrationErrorV1> {
    if extension.len() != 38 || extension[..6] != [0x30, 0x24, 0xa1, 0x22, 0x04, 0x20] {
        return Err(SiteTrustAppAttestRegistrationErrorV1::Denied);
    }
    let expected = Sha256::digest([auth_data, client_data_hash].concat());
    (extension[6..] == expected[..])
        .then_some(())
        .ok_or(SiteTrustAppAttestRegistrationErrorV1::Denied)
}

fn parameter_bytes(key: &CoseKey, label: i64) -> Option<&[u8]> {
    key.params.iter().find_map(|(candidate, value)| {
        (candidate == &Label::Int(label))
            .then_some(value)
            .and_then(|value| match value {
                Value::Bytes(bytes) => Some(bytes.as_slice()),
                _ => None,
            })
    })
}

fn parameter_integer(key: &CoseKey, label: i64) -> Option<i64> {
    key.params.iter().find_map(|(candidate, value)| {
        (candidate == &Label::Int(label))
            .then_some(value)
            .and_then(|value| match value {
                Value::Integer(value) => i64::try_from(*value).ok(),
                _ => None,
            })
    })
}

fn map_value<'a>(entries: &'a [(Value, Value)], name: &str) -> Option<&'a Value> {
    let mut found = None;
    for (key, value) in entries {
        if matches!(key, Value::Text(text) if text == name) && found.replace(value).is_some() {
            return None;
        }
    }
    found
}

fn map_text<'a>(entries: &'a [(Value, Value)], name: &str) -> Option<&'a str> {
    match map_value(entries, name)? {
        Value::Text(value) => Some(value),
        _ => None,
    }
}

fn map_bytes<'a>(entries: &'a [(Value, Value)], name: &str) -> Option<&'a Vec<u8>> {
    match map_value(entries, name)? {
        Value::Bytes(value) => Some(value),
        _ => None,
    }
}

fn decode_canonical_b64url<const N: usize>(
    encoded: &str,
) -> Result<[u8; N], SiteTrustAppAttestRegistrationErrorV1> {
    decode_canonical_b64url_bytes(encoded, N, N)?
        .try_into()
        .map_err(|_| SiteTrustAppAttestRegistrationErrorV1::Malformed)
}

fn decode_canonical_b64url_bytes(
    encoded: &str,
    minimum: usize,
    maximum: usize,
) -> Result<Vec<u8>, SiteTrustAppAttestRegistrationErrorV1> {
    if encoded.is_empty()
        || encoded.contains('=')
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(SiteTrustAppAttestRegistrationErrorV1::Malformed);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| SiteTrustAppAttestRegistrationErrorV1::Malformed)?;
    if !(minimum..=maximum).contains(&decoded.len()) || URL_SAFE_NO_PAD.encode(&decoded) != encoded
    {
        return Err(SiteTrustAppAttestRegistrationErrorV1::Malformed);
    }
    Ok(decoded)
}

fn valid_server_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn valid_bundle_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use pistis_domain::{InstallationId, KeyId};

    use crate::SiteTrustFactCeremonyIdV1;

    fn rotation_request(key_id: KeyId) -> CustodyRotationAppAttestRequestV1 {
        let installation = InstallationId::from_bytes([1; 16]);
        let ceremony = SiteTrustFactCeremonyIdV1::from_bytes([3; 16]);
        let mut canonical = Vec::new();
        canonical.extend_from_slice(b"MONASAC2\0");
        canonical.extend_from_slice(installation.as_bytes());
        canonical.extend_from_slice(&9_u16.to_be_bytes());
        canonical.extend_from_slice(b"site-demo");
        canonical.extend_from_slice(ceremony.as_bytes());
        canonical.extend_from_slice(key_id.as_bytes());
        canonical.extend_from_slice(&100_u64.to_be_bytes());
        canonical.extend_from_slice(&200_u64.to_be_bytes());
        canonical.extend_from_slice(&[4; 32]);
        canonical.extend_from_slice(&[5; 32]);
        CustodyRotationAppAttestRequestV1::from_server_owned_challenge(
            installation,
            "site-demo".into(),
            ceremony,
            key_id,
            Sha256::digest(canonical).into(),
            [4; 32],
            [5; 32],
            100,
            200,
        )
        .unwrap()
    }

    fn durable_key() -> ([u8; 65], KeyId) {
        let signing_key = SigningKey::from_bytes((&[7; 32]).into()).unwrap();
        let encoded = signing_key.verifying_key().to_encoded_point(false);
        let public_key: [u8; 65] = encoded.as_bytes().try_into().unwrap();
        (
            public_key,
            KeyId::from_bytes(Sha256::digest(public_key).into()),
        )
    }

    #[test]
    fn package_material_is_pinned_to_the_production_profile() {
        let factory = ProductionAppleAppAttestAcceptanceFactoryV1::from_package().unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD.encode(factory.manifest_digest),
            REGISTRATION_MANIFEST_SHA256_B64URL
        );
    }

    #[test]
    fn decoder_rejects_unknown_or_noncanonical_mobile_registration() {
        assert!(decode_site_trust_app_attest_registration_submission_v1(
            br#"{\"protocol\":\"pistis.apple-app-attest-registration.v1\",\"ceremony_id\":\"ceremony\",\"site_trust_domain\":\"site.example\",\"app_identifier\":\"C7A6NQTSY4.org.mnemosynebiosciences.pistis\",\"key_id_b64url\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"client_data_hash_b64url\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"attestation_object_b64url\":\"AA\"}"#
        ).is_err());
        assert!(decode_site_trust_app_attest_registration_submission_v1(
            br#"{\"protocol\":\"pistis.apple-app-attest-registration.v1\",\"ceremony_id\":\"ceremony\",\"site_trust_domain\":\"site.example\",\"app_identifier\":\"C7A6NQTSY4.org.mnemosynebiosciences.pistis\",\"key_id_b64url\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"client_data_hash_b64url\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"attestation_object_b64url\":\"AA\",\"authority\":\"client\"}"#
        ).is_err());
    }

    #[test]
    fn malformed_apple_object_never_creates_an_acceptance() {
        let factory = ProductionAppleAppAttestAcceptanceFactoryV1::from_package().unwrap();
        assert_eq!(
            verify_pinned_apple_registration(b"not-cbor", [0; 32], [0; 32], factory.root_pem),
            Err(SiteTrustAppAttestRegistrationErrorV1::Malformed)
        );
    }

    #[test]
    fn durable_restart_reconstructs_only_the_exact_rotation_acceptance() {
        let factory = ProductionAppleAppAttestAcceptanceFactoryV1::from_package().unwrap();
        let (public_key, key_id) = durable_key();
        let request = rotation_request(key_id);
        factory
            .resume_durable_registration_for_custody_rotation(
                request,
                public_key,
                factory.manifest_digest,
                "1.0.0",
                41,
            )
            .unwrap();
    }

    #[test]
    fn durable_tamper_or_binding_mismatch_never_reconstructs_acceptance() {
        let factory = ProductionAppleAppAttestAcceptanceFactoryV1::from_package().unwrap();
        let (public_key, key_id) = durable_key();
        let request = rotation_request(key_id);
        let attempt = |request, key, manifest, bundle, counter| {
            factory.resume_durable_registration_for_custody_rotation(
                request, key, manifest, bundle, counter,
            )
        };
        assert!(
            attempt(
                request.clone(),
                [0; 65],
                factory.manifest_digest,
                "1.0.0",
                41
            )
            .is_err()
        );
        assert!(attempt(request.clone(), public_key, [0; 32], "1.0.0", 41).is_err());
        assert!(
            attempt(
                request.clone(),
                public_key,
                factory.manifest_digest,
                "bad/version",
                41
            )
            .is_err()
        );
        assert!(
            attempt(
                request,
                public_key,
                factory.manifest_digest,
                "1.0.0",
                u32::MAX
            )
            .is_err()
        );
    }
}
