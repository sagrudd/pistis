//! Verification of the authority-signed iPhone mobile-enrolment receipt.
//!
//! The verifier is deliberately a receipt boundary.  It accepts the exact
//! four-field provider confirmation returned to the iPhone, verifies the
//! pinned authority bundle and both COSE envelopes, and returns typed facts
//! only.  It neither reads local iPhone storage nor creates a session, token,
//! account, or human authority.

use core::fmt;
use std::collections::BTreeMap;

use pistis_canonical::{Value, from_slice_with_fields};
use pistis_cose::verify_sign1;
use pistis_crypto::{PublicKey, derive_key_id, sha256};
use pistis_protocol::UnixTimeMillis;

/// Exact profile carried in an authority-signed mobile-enrolment receipt.
pub const PISTIS_MOBILE_ENROLMENT_RECEIPT_PROFILE_V2: &str = "pistis.mobile-enrolment-receipt.v2";

const AUTHORITY_BUNDLE_FIELDS: &[u64] = &[0, 1, 2, 3];
const AUTHORITY_DESCRIPTOR_FIELDS: &[u64] = &[0, 1, 2, 3, 4];
const REGISTRATION_FIELDS: &[u64] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const RECEIPT_FIELDS: &[u64] = &[
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26,
];
const MAXIMUM_BUNDLE_BYTES: usize = 1_024;
const MAXIMUM_ENVELOPE_BYTES: usize = 16_384;
const PRODUCT_AUDIENCES: &[&str] = &["dasobjectstore", "jenkins", "propylaion"];
const PROVIDER_ENROLMENT_CONFIRMATION_VERSION_V1: u8 = 1;

/// Fail-closed rejection of a provider-enrolment confirmation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MobileEnrolmentReceiptErrorV2 {
    /// The input is malformed, non-canonical, oversized, or uses another profile.
    Malformed,
    /// The signed facts do not match the protected installation context.
    Denied,
    /// The receipt is expired, not yet valid, or internally time-inconsistent.
    Expired,
}

impl fmt::Display for MobileEnrolmentReceiptErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Malformed => "mobile enrolment receipt is malformed",
            Self::Denied => "mobile enrolment receipt was denied",
            Self::Expired => "mobile enrolment receipt is not currently valid",
        })
    }
}

impl std::error::Error for MobileEnrolmentReceiptErrorV2 {}

/// The exact four-field confirmation returned by the authenticated provider.
///
/// Its opaque byte fields deliberately have no public accessors.  Callers must
/// submit them to [`verify_provider_enrolment_confirm_response_v2`] and retain
/// only the returned typed facts and receipt reference.
pub struct ProviderEnrolmentConfirmResponseV2 {
    version: u8,
    authority_bundle: Vec<u8>,
    device_registration_cose: Vec<u8>,
    mobile_enrolment_receipt_cose: Vec<u8>,
}

impl ProviderEnrolmentConfirmResponseV2 {
    /// Construct one bounded response received from the provider transport.
    ///
    /// Version one is the only accepted provider-response version. This constructor performs
    /// bounds checks only; signature and semantic verification remain
    /// mandatory at the explicit verifier boundary.
    ///
    /// # Errors
    ///
    /// Returns a coarse error when the version or any bounded opaque field is
    /// outside the fixed confirmation profile.
    pub fn new(
        version: u8,
        authority_bundle: Vec<u8>,
        device_registration_cose: Vec<u8>,
        mobile_enrolment_receipt_cose: Vec<u8>,
    ) -> Result<Self, MobileEnrolmentReceiptErrorV2> {
        if version != PROVIDER_ENROLMENT_CONFIRMATION_VERSION_V1
            || authority_bundle.is_empty()
            || authority_bundle.len() > MAXIMUM_BUNDLE_BYTES
            || device_registration_cose.is_empty()
            || device_registration_cose.len() > MAXIMUM_ENVELOPE_BYTES
            || mobile_enrolment_receipt_cose.is_empty()
            || mobile_enrolment_receipt_cose.len() > MAXIMUM_ENVELOPE_BYTES
        {
            return Err(MobileEnrolmentReceiptErrorV2::Malformed);
        }
        Ok(Self {
            version,
            authority_bundle,
            device_registration_cose,
            mobile_enrolment_receipt_cose,
        })
    }
}

/// Server-held context which pins a retained provider confirmation to one installation.
pub struct ExpectedProviderEnrolmentConfirmationV2 {
    exact_authority_bundle: Vec<u8>,
    installation_id: [u8; 16],
    https_host: String,
}

impl ExpectedProviderEnrolmentConfirmationV2 {
    /// Construct an expected confirmation from protected Monas configuration.
    ///
    /// `exact_authority_bundle` must be the exact bundle committed by the
    /// already-verified Site Trust presentation.  The host is the canonical
    /// lower-case HTTPS host of that presentation, never a caller-selected URL.
    ///
    /// # Errors
    ///
    /// Returns a coarse error when the protected bundle, installation, or host
    /// cannot satisfy the closed retained-receipt profile.
    pub fn new(
        exact_authority_bundle: Vec<u8>,
        installation_id: [u8; 16],
        https_host: String,
    ) -> Result<Self, MobileEnrolmentReceiptErrorV2> {
        if exact_authority_bundle.is_empty()
            || exact_authority_bundle.len() > MAXIMUM_BUNDLE_BYTES
            || installation_id.iter().all(|byte| *byte == 0)
            || !canonical_host(&https_host)
        {
            return Err(MobileEnrolmentReceiptErrorV2::Malformed);
        }
        decode_authority_bundle(&exact_authority_bundle)?;
        Ok(Self {
            exact_authority_bundle,
            installation_id,
            https_host,
        })
    }
}

/// Authority-verified receipt claims safe for a Monas completion transaction.
///
/// The raw provider response and COSE envelopes are intentionally unavailable:
/// callers may retain [`receipt_sha256`](Self::receipt_sha256) as an evidence
/// reference, not a local substitute for the authority proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedMobileEnrolmentReceiptV2 {
    installation_id: [u8; 16],
    user_id: [u8; 16],
    external_identity_id: [u8; 16],
    device_id: [u8; 16],
    device_key_id: [u8; 32],
    policy_generation: u64,
    revocation_generation: u64,
    receipt_sha256: [u8; 32],
}

impl VerifiedMobileEnrolmentReceiptV2 {
    /// Return the authority-bound installation identifier.
    #[must_use]
    pub const fn installation_id(&self) -> &[u8; 16] {
        &self.installation_id
    }
    /// Return the authority-bound Pistis principal identifier.
    #[must_use]
    pub const fn user_id(&self) -> &[u8; 16] {
        &self.user_id
    }
    /// Return the authority-bound external identity identifier.
    #[must_use]
    pub const fn external_identity_id(&self) -> &[u8; 16] {
        &self.external_identity_id
    }
    /// Return the authority-bound Pistis device identifier.
    #[must_use]
    pub const fn device_id(&self) -> &[u8; 16] {
        &self.device_id
    }
    /// Return the authority-bound P-256 device signing-key identifier.
    #[must_use]
    pub const fn device_key_id(&self) -> &[u8; 32] {
        &self.device_key_id
    }
    /// Return the receipt's accepted policy generation.
    #[must_use]
    pub const fn policy_generation(&self) -> u64 {
        self.policy_generation
    }
    /// Return the receipt's accepted revocation generation.
    #[must_use]
    pub const fn revocation_generation(&self) -> u64 {
        self.revocation_generation
    }
    /// Return a SHA-256 evidence reference for the exact verified receipt.
    #[must_use]
    pub const fn receipt_sha256(&self) -> &[u8; 32] {
        &self.receipt_sha256
    }
}

#[cfg(test)]
impl VerifiedMobileEnrolmentReceiptV2 {
    pub(crate) const fn test_fixture() -> Self {
        Self {
            installation_id: [9; 16],
            user_id: [10; 16],
            external_identity_id: [12; 16],
            device_id: [11; 16],
            device_key_id: [13; 32],
            policy_generation: 2,
            revocation_generation: 1,
            receipt_sha256: [14; 32],
        }
    }
}

/// Verify a retained provider confirmation against protected Site Trust context.
///
/// This is the only retained-receipt verification mode.  It requires an exact
/// pinned authority bundle, validates the device registration COSE under the
/// device key named by its signed payload, validates the authority receipt COSE
/// under the receipt descriptor in the pinned bundle, and binds the receipt to
/// the registration digest, installation, and canonical host.
///
/// # Errors
///
/// Returns a coarse error for every malformed, expired, substituted, or
/// cryptographically invalid input before any caller can retain authority.
pub fn verify_provider_enrolment_confirm_response_v2(
    response: &ProviderEnrolmentConfirmResponseV2,
    expected: &ExpectedProviderEnrolmentConfirmationV2,
    now: UnixTimeMillis,
) -> Result<VerifiedMobileEnrolmentReceiptV2, MobileEnrolmentReceiptErrorV2> {
    if response.version != PROVIDER_ENROLMENT_CONFIRMATION_VERSION_V1
        || response.authority_bundle != expected.exact_authority_bundle
    {
        return Err(MobileEnrolmentReceiptErrorV2::Denied);
    }
    let bundle = decode_authority_bundle(&expected.exact_authority_bundle)?;
    let registration = decode_registration(&response.device_registration_cose)?;
    let device_public = PublicKey::from_sec1_bytes(&registration.device_public_key)
        .map_err(|_| MobileEnrolmentReceiptErrorV2::Denied)?;
    if derive_key_id(&device_public).into_bytes() != registration.device_key_id {
        return Err(MobileEnrolmentReceiptErrorV2::Denied);
    }
    verify_sign1(&response.device_registration_cose, &device_public)
        .map_err(|_| MobileEnrolmentReceiptErrorV2::Denied)?;

    let receipt_public = PublicKey::from_sec1_bytes(&bundle.receipt_public_key)
        .map_err(|_| MobileEnrolmentReceiptErrorV2::Denied)?;
    let receipt_envelope = verify_sign1(&response.mobile_enrolment_receipt_cose, &receipt_public)
        .map_err(|_| MobileEnrolmentReceiptErrorV2::Denied)?;
    decode_receipt(
        receipt_envelope.payload(),
        bundle.receipt_key_id,
        &registration,
        expected,
        now,
        sha256(&response.mobile_enrolment_receipt_cose).into_bytes(),
    )
}

struct AuthorityBundle {
    receipt_key_id: [u8; 32],
    receipt_public_key: [u8; 33],
}

fn decode_authority_bundle(bytes: &[u8]) -> Result<AuthorityBundle, MobileEnrolmentReceiptErrorV2> {
    let mut fields = exact_map(bytes, AUTHORITY_BUNDLE_FIELDS)?;
    require_unsigned(fields.get(&0), 1)?;
    require_text(fields.get(&1), "pistis.first-device-authority-bundle.v1")?;
    let initial = take_bounded_bytes(fields.remove(&2), 256)?;
    let receipt = take_bounded_bytes(fields.remove(&3), 256)?;
    let initial_descriptor = decode_authority_descriptor(&initial)?;
    let receipt_descriptor = decode_authority_descriptor(&receipt)?;
    if initial_descriptor.0 == receipt_descriptor.0 {
        return Err(MobileEnrolmentReceiptErrorV2::Denied);
    }
    Ok(AuthorityBundle {
        receipt_key_id: receipt_descriptor.0,
        receipt_public_key: receipt_descriptor.1,
    })
}

fn decode_authority_descriptor(
    bytes: &[u8],
) -> Result<([u8; 32], [u8; 33]), MobileEnrolmentReceiptErrorV2> {
    let mut fields = exact_map(bytes, AUTHORITY_DESCRIPTOR_FIELDS)?;
    require_unsigned(fields.get(&0), 1)?;
    require_text(fields.get(&1), "pistis.authority-key-descriptor.v1")?;
    let key_id = fixed_bytes(fields.remove(&2))?;
    let public_key = fixed_bytes(fields.remove(&3))?;
    require_negative(fields.get(&4), -7)?;
    let public = PublicKey::from_sec1_bytes(&public_key)
        .map_err(|_| MobileEnrolmentReceiptErrorV2::Malformed)?;
    if derive_key_id(&public).into_bytes() != key_id {
        return Err(MobileEnrolmentReceiptErrorV2::Denied);
    }
    Ok((key_id, public_key))
}

struct Registration {
    installation_id: [u8; 16],
    principal_id: [u8; 16],
    device_key_id: [u8; 32],
    device_public_key: [u8; 33],
    policy_generation: u64,
    exact_sha256: [u8; 32],
}

fn decode_registration(bytes: &[u8]) -> Result<Registration, MobileEnrolmentReceiptErrorV2> {
    let envelope =
        pistis_cose::decode(bytes).map_err(|_| MobileEnrolmentReceiptErrorV2::Malformed)?;
    let mut fields = exact_map(envelope.payload(), REGISTRATION_FIELDS)?;
    require_text(fields.get(&0), "pistis.enrolment-binding.v1")?;
    let _operation_id: [u8; 16] = fixed_bytes(fields.remove(&1))?;
    let _invitation_id: [u8; 16] = fixed_bytes(fields.remove(&2))?;
    let _tenant_id: [u8; 16] = fixed_bytes(fields.remove(&3))?;
    let principal_id = fixed_bytes(fields.remove(&4))?;
    let installation_id = fixed_bytes(fields.remove(&5))?;
    require_text(fields.get(&6), "github.com")?;
    let subject = take_text(fields.remove(&7), 20)?;
    if !numeric_subject(&subject) {
        return Err(MobileEnrolmentReceiptErrorV2::Denied);
    }
    let device_public_key = fixed_bytes(fields.remove(&8))?;
    let device_key_id = fixed_bytes(fields.remove(&9))?;
    require_unsigned(fields.get(&10), 1)?;
    require_unsigned(fields.get(&11), 1)?;
    let policy_generation = take_unsigned(fields.get(&12))?;
    let _app_digest: [u8; 32] = fixed_bytes(fields.remove(&13))?;
    let _challenge: [u8; 32] = fixed_bytes(fields.remove(&14))?;
    let _challenge_expiry = take_unsigned(fields.get(&15))?;
    if policy_generation == 0 {
        return Err(MobileEnrolmentReceiptErrorV2::Denied);
    }
    Ok(Registration {
        installation_id,
        principal_id,
        device_key_id,
        device_public_key,
        policy_generation,
        exact_sha256: sha256(bytes).into_bytes(),
    })
}

fn decode_receipt(
    bytes: &[u8],
    authority_key_id: [u8; 32],
    registration: &Registration,
    expected: &ExpectedProviderEnrolmentConfirmationV2,
    now: UnixTimeMillis,
    receipt_sha256: [u8; 32],
) -> Result<VerifiedMobileEnrolmentReceiptV2, MobileEnrolmentReceiptErrorV2> {
    let mut fields = exact_map(bytes, RECEIPT_FIELDS)?;
    require_unsigned(fields.get(&0), 2)?;
    require_text(fields.get(&1), PISTIS_MOBILE_ENROLMENT_RECEIPT_PROFILE_V2)?;
    let issued = take_unsigned(fields.get(&2))?;
    let expires = take_unsigned(fields.get(&3))?;
    let evidence: [u8; 16] = fixed_bytes(fields.remove(&4))?;
    let installation_id = fixed_bytes(fields.remove(&5))?;
    let _name = take_text(fields.remove(&6), 128)?;
    let _audience = take_text(fields.remove(&7), 128)?;
    let installation_key_id: [u8; 32] = fixed_bytes(fields.remove(&8))?;
    let installation_public_key: [u8; 33] = fixed_bytes(fields.remove(&9))?;
    require_negative(fields.get(&10), -7)?;
    let fingerprint: [u8; 32] = fixed_bytes(fields.remove(&11))?;
    let returned_authority_key_id: [u8; 32] = fixed_bytes(fields.remove(&12))?;
    let user_id = fixed_bytes(fields.remove(&13))?;
    let external_identity_id = fixed_bytes(fields.remove(&14))?;
    let device_id = fixed_bytes(fields.remove(&15))?;
    let device_key_id = fixed_bytes(fields.remove(&16))?;
    let device_public_key: [u8; 33] = fixed_bytes(fields.remove(&17))?;
    require_negative(fields.get(&18), -7)?;
    require_text(fields.get(&19), "secure-enclave-biometry-current-set")?;
    let registration_digest: [u8; 32] = fixed_bytes(fields.remove(&20))?;
    let policy_generation = take_unsigned(fields.get(&21))?;
    let revocation_generation = take_unsigned(fields.get(&22))?;
    require_true(fields.get(&23))?;
    let confirmed = take_unsigned(fields.get(&24))?;
    let hosts = take_text_array(fields.remove(&25), 16, 253)?;
    let audiences = take_text_array(fields.remove(&26), 3, 128)?;

    let installation_public = PublicKey::from_sec1_bytes(&installation_public_key)
        .map_err(|_| MobileEnrolmentReceiptErrorV2::Denied)?;
    let device_public = PublicKey::from_sec1_bytes(&device_public_key)
        .map_err(|_| MobileEnrolmentReceiptErrorV2::Denied)?;
    if issued >= expires
        || now.get() < issued
        || now.get() >= expires
        || confirmed < issued
        || confirmed >= expires
        || confirmed > now.get()
    {
        return Err(MobileEnrolmentReceiptErrorV2::Expired);
    }
    if evidence.iter().all(|byte| *byte == 0)
        || external_identity_id.iter().all(|byte| *byte == 0)
        || device_id.iter().all(|byte| *byte == 0)
        || installation_id != expected.installation_id
        || installation_id != registration.installation_id
        || user_id != registration.principal_id
        || device_key_id != registration.device_key_id
        || device_public_key != registration.device_public_key
        || derive_key_id(&device_public).into_bytes() != device_key_id
        || derive_key_id(&installation_public).into_bytes() != installation_key_id
        || sha256(&installation_public_key).into_bytes() != fingerprint
        || returned_authority_key_id != authority_key_id
        || registration_digest != registration.exact_sha256
        || policy_generation == 0
        || revocation_generation == 0
        || policy_generation != registration.policy_generation
        || !canonical_hosts(&hosts)
        || !hosts.iter().any(|host| host == &expected.https_host)
        || !canonical_product_audiences(&audiences)
    {
        return Err(MobileEnrolmentReceiptErrorV2::Denied);
    }
    Ok(VerifiedMobileEnrolmentReceiptV2 {
        installation_id,
        user_id,
        external_identity_id,
        device_id,
        device_key_id,
        policy_generation,
        revocation_generation,
        receipt_sha256,
    })
}

fn exact_map(
    bytes: &[u8],
    expected: &[u64],
) -> Result<BTreeMap<u64, Value>, MobileEnrolmentReceiptErrorV2> {
    let fields = from_slice_with_fields(bytes, expected)
        .map_err(|_| MobileEnrolmentReceiptErrorV2::Malformed)?;
    (fields.len() == expected.len())
        .then_some(fields)
        .ok_or(MobileEnrolmentReceiptErrorV2::Malformed)
}
fn require_unsigned(
    value: Option<&Value>,
    expected: u64,
) -> Result<(), MobileEnrolmentReceiptErrorV2> {
    if value == Some(&Value::Unsigned(expected)) {
        Ok(())
    } else {
        Err(MobileEnrolmentReceiptErrorV2::Malformed)
    }
}
fn require_negative(
    value: Option<&Value>,
    expected: i64,
) -> Result<(), MobileEnrolmentReceiptErrorV2> {
    if value == Some(&Value::Negative(expected)) {
        Ok(())
    } else {
        Err(MobileEnrolmentReceiptErrorV2::Malformed)
    }
}
fn require_text(
    value: Option<&Value>,
    expected: &str,
) -> Result<(), MobileEnrolmentReceiptErrorV2> {
    if value == Some(&Value::Text(expected.to_owned())) {
        Ok(())
    } else {
        Err(MobileEnrolmentReceiptErrorV2::Malformed)
    }
}
fn require_true(value: Option<&Value>) -> Result<(), MobileEnrolmentReceiptErrorV2> {
    if value == Some(&Value::Bool(true)) {
        Ok(())
    } else {
        Err(MobileEnrolmentReceiptErrorV2::Malformed)
    }
}
fn fixed_bytes<const N: usize>(
    value: Option<Value>,
) -> Result<[u8; N], MobileEnrolmentReceiptErrorV2> {
    match value {
        Some(Value::Bytes(bytes)) => bytes
            .try_into()
            .map_err(|_| MobileEnrolmentReceiptErrorV2::Malformed),
        _ => Err(MobileEnrolmentReceiptErrorV2::Malformed),
    }
}
fn take_bounded_bytes(
    value: Option<Value>,
    maximum: usize,
) -> Result<Vec<u8>, MobileEnrolmentReceiptErrorV2> {
    match value {
        Some(Value::Bytes(bytes)) if !bytes.is_empty() && bytes.len() <= maximum => Ok(bytes),
        _ => Err(MobileEnrolmentReceiptErrorV2::Malformed),
    }
}
fn take_unsigned(value: Option<&Value>) -> Result<u64, MobileEnrolmentReceiptErrorV2> {
    match value {
        Some(Value::Unsigned(value)) => Ok(*value),
        _ => Err(MobileEnrolmentReceiptErrorV2::Malformed),
    }
}
fn take_text(
    value: Option<Value>,
    maximum: usize,
) -> Result<String, MobileEnrolmentReceiptErrorV2> {
    match value {
        Some(Value::Text(value)) if !value.is_empty() && value.len() <= maximum => Ok(value),
        _ => Err(MobileEnrolmentReceiptErrorV2::Malformed),
    }
}
fn take_text_array(
    value: Option<Value>,
    maximum_count: usize,
    maximum_text: usize,
) -> Result<Vec<String>, MobileEnrolmentReceiptErrorV2> {
    match value {
        Some(Value::Array(values)) if !values.is_empty() && values.len() <= maximum_count => values
            .into_iter()
            .map(|value| take_text(Some(value), maximum_text))
            .collect(),
        _ => Err(MobileEnrolmentReceiptErrorV2::Malformed),
    }
}
fn numeric_subject(value: &str) -> bool {
    !value.is_empty() && value.len() <= 20 && value.bytes().all(|byte| byte.is_ascii_digit())
}
fn canonical_host(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.is_ascii()
        && value == value.to_ascii_lowercase()
        && !value.ends_with('.')
        && value.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}
fn canonical_hosts(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
        && values.iter().all(|value| canonical_host(value))
}
fn canonical_product_audiences(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
        && values
            .iter()
            .all(|value| value.is_ascii() && PRODUCT_AUDIENCES.contains(&value.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer as _;
    use p256::ecdsa::{Signature, SigningKey};
    use pistis_canonical::to_vec;

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes((&[seed; 32]).into()).unwrap()
    }

    fn public_key(key: &SigningKey) -> PublicKey {
        PublicKey::from_sec1_bytes(key.verifying_key().to_encoded_point(true).as_bytes()).unwrap()
    }

    fn sign(payload: &[u8], key: &SigningKey) -> Vec<u8> {
        let public = public_key(key);
        let key_id = derive_key_id(&public);
        let input = pistis_cose::signing_input(payload, key_id).unwrap();
        let signature: Signature = key.sign(&input);
        let signature = signature.normalize_s().unwrap_or(signature);
        pistis_cose::encode(payload, key_id, &signature.to_bytes()).unwrap()
    }

    fn descriptor(key: &SigningKey) -> Vec<u8> {
        let public = public_key(key);
        to_vec(&Value::Map(BTreeMap::from([
            (0, Value::Unsigned(1)),
            (1, Value::Text("pistis.authority-key-descriptor.v1".into())),
            (
                2,
                Value::Bytes(derive_key_id(&public).into_bytes().to_vec()),
            ),
            (3, Value::Bytes(public.canonical_bytes().to_vec())),
            (4, Value::Negative(-7)),
        ])))
        .unwrap()
    }

    fn fixture() -> (
        ProviderEnrolmentConfirmResponseV2,
        ExpectedProviderEnrolmentConfirmationV2,
    ) {
        let initial = signing_key(1);
        let receipt_signer = signing_key(2);
        let device_signer = signing_key(3);
        let installation_signer = signing_key(4);
        let installation_id = [9_u8; 16];
        let principal_id = [10_u8; 16];
        let device_id = [11_u8; 16];
        let external_identity_id = [12_u8; 16];
        let device_public = public_key(&device_signer);
        let installation_public = public_key(&installation_signer);
        let registration_payload = to_vec(&Value::Map(BTreeMap::from([
            (0, Value::Text("pistis.enrolment-binding.v1".into())),
            (1, Value::Bytes(vec![1; 16])),
            (2, Value::Bytes(vec![2; 16])),
            (3, Value::Bytes(vec![3; 16])),
            (4, Value::Bytes(principal_id.to_vec())),
            (5, Value::Bytes(installation_id.to_vec())),
            (6, Value::Text("github.com".into())),
            (7, Value::Text("12345".into())),
            (8, Value::Bytes(device_public.canonical_bytes().to_vec())),
            (
                9,
                Value::Bytes(derive_key_id(&device_public).into_bytes().to_vec()),
            ),
            (10, Value::Unsigned(1)),
            (11, Value::Unsigned(1)),
            (12, Value::Unsigned(2)),
            (13, Value::Bytes(vec![4; 32])),
            (14, Value::Bytes(vec![5; 32])),
            (15, Value::Unsigned(999)),
        ])))
        .unwrap();
        let registration = sign(&registration_payload, &device_signer);
        let authority_bundle = to_vec(&Value::Map(BTreeMap::from([
            (0, Value::Unsigned(1)),
            (
                1,
                Value::Text("pistis.first-device-authority-bundle.v1".into()),
            ),
            (2, Value::Bytes(descriptor(&initial))),
            (3, Value::Bytes(descriptor(&receipt_signer))),
        ])))
        .unwrap();
        let receipt_payload = to_vec(&Value::Map(BTreeMap::from([
            (0, Value::Unsigned(2)),
            (
                1,
                Value::Text(PISTIS_MOBILE_ENROLMENT_RECEIPT_PROFILE_V2.into()),
            ),
            (2, Value::Unsigned(100)),
            (3, Value::Unsigned(1_000)),
            (4, Value::Bytes(vec![6; 16])),
            (5, Value::Bytes(installation_id.to_vec())),
            (6, Value::Text("Monas".into())),
            (7, Value::Text("monas-local".into())),
            (
                8,
                Value::Bytes(derive_key_id(&installation_public).into_bytes().to_vec()),
            ),
            (
                9,
                Value::Bytes(installation_public.canonical_bytes().to_vec()),
            ),
            (10, Value::Negative(-7)),
            (
                11,
                Value::Bytes(
                    sha256(&installation_public.canonical_bytes())
                        .into_bytes()
                        .to_vec(),
                ),
            ),
            (
                12,
                Value::Bytes(
                    derive_key_id(&public_key(&receipt_signer))
                        .into_bytes()
                        .to_vec(),
                ),
            ),
            (13, Value::Bytes(principal_id.to_vec())),
            (14, Value::Bytes(external_identity_id.to_vec())),
            (15, Value::Bytes(device_id.to_vec())),
            (
                16,
                Value::Bytes(derive_key_id(&device_public).into_bytes().to_vec()),
            ),
            (17, Value::Bytes(device_public.canonical_bytes().to_vec())),
            (18, Value::Negative(-7)),
            (
                19,
                Value::Text("secure-enclave-biometry-current-set".into()),
            ),
            (
                20,
                Value::Bytes(sha256(&registration).into_bytes().to_vec()),
            ),
            (21, Value::Unsigned(2)),
            (22, Value::Unsigned(1)),
            (23, Value::Bool(true)),
            (24, Value::Unsigned(200)),
            (
                25,
                Value::Array(vec![Value::Text("monas.example.test".into())]),
            ),
            (26, Value::Array(vec![Value::Text("jenkins".into())])),
        ])))
        .unwrap();
        let receipt = sign(&receipt_payload, &receipt_signer);
        (
            ProviderEnrolmentConfirmResponseV2::new(
                1,
                authority_bundle.clone(),
                registration,
                receipt,
            )
            .unwrap(),
            ExpectedProviderEnrolmentConfirmationV2::new(
                authority_bundle,
                installation_id,
                "monas.example.test".into(),
            )
            .unwrap(),
        )
    }

    #[test]
    fn exact_four_field_provider_vector_yields_only_typed_receipt_facts() {
        let (response, expected) = fixture();
        let verified = verify_provider_enrolment_confirm_response_v2(
            &response,
            &expected,
            UnixTimeMillis::new(200),
        )
        .unwrap();
        assert_eq!(verified.installation_id(), &[9; 16]);
        assert_eq!(verified.user_id(), &[10; 16]);
        assert_eq!(verified.external_identity_id(), &[12; 16]);
        assert_eq!(verified.device_id(), &[11; 16]);
        assert_eq!(verified.policy_generation(), 2);
        assert_eq!(verified.revocation_generation(), 1);
        assert_ne!(verified.receipt_sha256(), &[0; 32]);
    }

    #[test]
    fn provider_confirmation_version_and_pinned_bundle_are_not_negotiable() {
        let (response, _expected) = fixture();
        assert!(matches!(
            ProviderEnrolmentConfirmResponseV2::new(2, vec![1], vec![2], vec![3]),
            Err(MobileEnrolmentReceiptErrorV2::Malformed)
        ));
        let wrong_bundle = ExpectedProviderEnrolmentConfirmationV2::new(
            vec![1],
            [9; 16],
            "monas.example.test".into(),
        );
        assert!(matches!(
            wrong_bundle,
            Err(MobileEnrolmentReceiptErrorV2::Malformed)
        ));
        assert!(
            verify_provider_enrolment_confirm_response_v2(
                &response,
                &ExpectedProviderEnrolmentConfirmationV2::new(
                    response.authority_bundle.clone(),
                    [8; 16],
                    "monas.example.test".into(),
                )
                .unwrap(),
                UnixTimeMillis::new(200),
            )
            .is_err()
        );
    }
}
