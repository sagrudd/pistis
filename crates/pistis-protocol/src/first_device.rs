//! Accepted ADR 0028 first-device presentation verification.

use crate::{HOST_TRUST_WORDS_VERSION, HostTrustWords, derive_host_trust_words};
use pistis_canonical::{Value, from_slice_with_fields};
use pistis_cose::verify_sign1;
use pistis_crypto::{PublicKey, derive_key_id, sha256};
use std::{error::Error, fmt};
use url::Url;

const FRAME_FIELDS: &[u64] = &[0, 1, 2, 3];
const BUNDLE_FIELDS: &[u64] = &[0, 1, 2, 3];
const DESCRIPTOR_FIELDS: &[u64] = &[0, 1, 2, 3, 4];
const INVITATION_FIELDS: &[u64] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
const PRESENTATION_FIELDS: &[u64] =
    &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17];
const PRODUCT_AUDIENCES: &[&str] = &["dasobjectstore", "jenkins", "propylaion"];
/// Maximum binary outer-frame bytes accepted from the protected pipe.
pub const MAX_FIRST_DEVICE_FRAME_BYTES: usize = 1_792;
const MAX_INVITATION_BYTES: usize = 512;

/// One authenticated authority-key bootstrap descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityDescriptor {
    /// Domain-separated key identifier derived from the canonical public key.
    pub key_id: [u8; 32],
    /// Canonical compressed SEC1 P-256 public key.
    pub public_key: [u8; 33],
}

/// Purpose-separated trust bootstrap committed by the invitation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FirstDeviceAuthorityBundle {
    /// Key permitted to authenticate the attended presentation.
    pub initial_invitation: AuthorityDescriptor,
    /// Distinct key permitted to authenticate the final enrolment receipt.
    pub mobile_receipt: AuthorityDescriptor,
    /// Exact canonical bundle bytes committed by the invitation.
    pub exact_bytes: Vec<u8>,
}

/// Exact accepted ADR 0023 invitation facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MobileEnrolmentInvitation {
    /// Exclusive start of the invitation lifetime.
    pub issued_at_ms: u64,
    /// Exclusive invitation expiry.
    pub expires_at_ms: u64,
    /// One-use invitation identifier.
    pub invitation_id: [u8; 16],
    /// Installation selected by the administrator.
    pub installation_id: [u8; 16],
    /// Fixed audience of the enrolment ceremony.
    pub audience: String,
    /// Closed authority-signed product audiences permitted after enrolment.
    pub authorised_product_audiences: Vec<String>,
    /// Descriptor commitment supplied through the attended channel.
    pub authority_descriptor_digest: [u8; 32],
}

/// Fully verified facts from one version-4/kind-3 presentation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FirstDevicePresentation {
    /// Correlation identifier; not a second one-use state machine.
    pub presentation_id: [u8; 16],
    /// Inclusive issue time.
    pub issued_at_ms: u64,
    /// Exclusive presentation expiry.
    pub expires_at_ms: u64,
    /// Authority identifier selected by Prosopikon.
    pub authority_id: [u8; 16],
    /// Intended tenant.
    pub tenant_id: [u8; 16],
    /// Intended principal.
    pub principal_id: [u8; 16],
    /// Human-readable installation name.
    pub installation_name: String,
    /// Closed authority-signed product audiences permitted after enrolment.
    pub authorised_product_audiences: Vec<String>,
    /// Exact canonical HTTPS origin for the enrolment-only Monas process.
    pub https_origin: String,
    /// Reviewed GitHub App configuration digest.
    pub app_configuration_digest: [u8; 32],
    /// SHA-256 of the server leaf certificate's exact DER `SubjectPublicKeyInfo`.
    pub tls_spki_sha256: [u8; 32],
    /// Human-comparable checksum derived from the authenticated host binding.
    pub trust_words: HostTrustWords,
    /// Parsed invitation with its secret deliberately omitted from this API.
    pub invitation: MobileEnrolmentInvitation,
    /// Authenticated, purpose-separated authority descriptors.
    pub authority_bundle: FirstDeviceAuthorityBundle,
    /// Exact invitation bytes to submit only to the fixed begin route.
    pub exact_invitation: Vec<u8>,
}

/// Fail-closed first-device presentation rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirstDevicePresentationError {
    /// The input exceeds the accepted binary or nested value bound.
    TooLarge,
    /// The outer frame is malformed, non-canonical, or the wrong kind/version.
    InvalidFrame,
    /// The authority descriptor is malformed or inconsistent with its key.
    InvalidAuthority,
    /// The invitation is malformed, expired, or inconsistent.
    InvalidInvitation,
    /// The signed presentation payload is malformed or inconsistent.
    InvalidPresentation,
    /// The COSE signature is invalid or uses another authority key.
    InvalidSignature,
    /// The reviewed GitHub App configuration does not match.
    ConfigurationMismatch,
    /// The presentation is not currently valid.
    Expired,
}

impl fmt::Display for FirstDevicePresentationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("first-device presentation rejected")
    }
}

impl Error for FirstDevicePresentationError {}

/// Verify one exact binary ADR 0028 outer frame.
///
/// The returned invitation remains sensitive and must be sent only to the
/// fixed begin route on `https_origin`. Callers must not log, persist, or
/// expose the exact frame, invitation, or QR transfer as evidence.
///
/// # Errors
///
/// Rejects wrong-version/kind frames, non-canonical nested CBOR, descriptor or
/// key substitution, invalid signatures, repeated-field mismatch, invalid
/// HTTPS origins, configuration substitution, and expired input.
pub fn verify_first_device_presentation(
    frame: &[u8],
    expected_app_configuration_digest: [u8; 32],
    now_ms: u64,
) -> Result<FirstDevicePresentation, FirstDevicePresentationError> {
    if frame.len() > MAX_FIRST_DEVICE_FRAME_BYTES {
        return Err(FirstDevicePresentationError::TooLarge);
    }
    let mut outer = exact_map(
        frame,
        FRAME_FIELDS,
        FirstDevicePresentationError::InvalidFrame,
    )?;
    require_unsigned(outer.get(&0), 4, FirstDevicePresentationError::InvalidFrame)?;
    require_unsigned(outer.get(&1), 3, FirstDevicePresentationError::InvalidFrame)?;
    let cose = take_bytes(
        outer.remove(&2),
        2_048,
        FirstDevicePresentationError::InvalidFrame,
    )?;
    let bundle_bytes = take_bytes(
        outer.remove(&3),
        512,
        FirstDevicePresentationError::InvalidFrame,
    )?;

    let bundle = decode_bundle(bundle_bytes)?;
    let public_key = PublicKey::from_sec1_bytes(&bundle.initial_invitation.public_key)
        .map_err(|_| FirstDevicePresentationError::InvalidAuthority)?;
    let envelope = verify_sign1(&cose, &public_key)
        .map_err(|_| FirstDevicePresentationError::InvalidSignature)?;
    let presentation = decode_presentation_payload(envelope.payload(), bundle)?;
    validate_presentation(&presentation, expected_app_configuration_digest, now_ms)?;
    Ok(presentation)
}

fn decode_presentation_payload(
    bytes: &[u8],
    authority_bundle: FirstDeviceAuthorityBundle,
) -> Result<FirstDevicePresentation, FirstDevicePresentationError> {
    let mut payload = exact_map(
        bytes,
        PRESENTATION_FIELDS,
        FirstDevicePresentationError::InvalidPresentation,
    )?;
    require_unsigned(
        payload.get(&0),
        3,
        FirstDevicePresentationError::InvalidPresentation,
    )?;
    require_text_exact(
        payload.get(&1),
        "pistis.first-device-presentation.v3",
        FirstDevicePresentationError::InvalidPresentation,
    )?;
    let presentation_id = fixed_bytes(
        payload.remove(&2),
        FirstDevicePresentationError::InvalidPresentation,
    )?;
    let issued_at_ms = unsigned(
        payload.get(&3),
        FirstDevicePresentationError::InvalidPresentation,
    )?;
    let expires_at_ms = unsigned(
        payload.get(&4),
        FirstDevicePresentationError::InvalidPresentation,
    )?;
    let exact_invitation = take_bytes(
        payload.remove(&5),
        MAX_INVITATION_BYTES,
        FirstDevicePresentationError::InvalidPresentation,
    )?;
    let invitation = decode_invitation(&exact_invitation)?;
    let authority_id = fixed_bytes(
        payload.remove(&6),
        FirstDevicePresentationError::InvalidPresentation,
    )?;
    let tenant_id = fixed_bytes(
        payload.remove(&7),
        FirstDevicePresentationError::InvalidPresentation,
    )?;
    let principal_id = fixed_bytes(
        payload.remove(&8),
        FirstDevicePresentationError::InvalidPresentation,
    )?;
    let installation_id = fixed_bytes::<16>(
        payload.remove(&9),
        FirstDevicePresentationError::InvalidPresentation,
    )?;
    let installation_name = bounded_trimmed_text(
        payload.remove(&10),
        128,
        FirstDevicePresentationError::InvalidPresentation,
    )?;
    let audience = bounded_trimmed_text(
        payload.remove(&11),
        128,
        FirstDevicePresentationError::InvalidPresentation,
    )?;
    let host = decode_host_binding(&mut payload)?;
    let authorised_product_audiences = product_audiences(
        payload.remove(&17),
        FirstDevicePresentationError::InvalidPresentation,
    )?;
    let actual_descriptor_digest = sha256(&authority_bundle.exact_bytes).into_bytes();
    if invitation.installation_id != installation_id
        || invitation.audience != audience
        || invitation.authorised_product_audiences != authorised_product_audiences
    {
        return Err(FirstDevicePresentationError::InvalidPresentation);
    }
    if host.descriptor_digest != actual_descriptor_digest {
        return Err(FirstDevicePresentationError::InvalidAuthority);
    }
    let trust_words = derive_host_trust_words(
        authority_id,
        installation_id,
        &host.https_origin,
        host.tls_spki_sha256,
        host.app_configuration_digest,
    )
    .map_err(|_| FirstDevicePresentationError::InvalidPresentation)?;
    Ok(FirstDevicePresentation {
        presentation_id,
        issued_at_ms,
        expires_at_ms,
        authority_id,
        tenant_id,
        principal_id,
        installation_name,
        authorised_product_audiences,
        https_origin: host.https_origin,
        app_configuration_digest: host.app_configuration_digest,
        tls_spki_sha256: host.tls_spki_sha256,
        trust_words,
        invitation,
        authority_bundle,
        exact_invitation,
    })
}

type CanonicalFields = std::collections::BTreeMap<u64, Value>;

struct HostBinding {
    https_origin: String,
    app_configuration_digest: [u8; 32],
    descriptor_digest: [u8; 32],
    tls_spki_sha256: [u8; 32],
}

fn decode_host_binding(
    payload: &mut CanonicalFields,
) -> Result<HostBinding, FirstDevicePresentationError> {
    let https_origin = canonical_https_origin(payload.remove(&12))?;
    let app_configuration_digest = fixed_bytes(
        payload.remove(&13),
        FirstDevicePresentationError::InvalidPresentation,
    )?;
    let descriptor_digest = fixed_bytes(
        payload.remove(&14),
        FirstDevicePresentationError::InvalidPresentation,
    )?;
    let tls_spki_sha256 = fixed_bytes(
        payload.remove(&15),
        FirstDevicePresentationError::InvalidPresentation,
    )?;
    require_unsigned(
        payload.get(&16),
        HOST_TRUST_WORDS_VERSION,
        FirstDevicePresentationError::InvalidPresentation,
    )?;
    Ok(HostBinding {
        https_origin,
        app_configuration_digest,
        descriptor_digest,
        tls_spki_sha256,
    })
}

fn validate_presentation(
    presentation: &FirstDevicePresentation,
    expected_app_configuration_digest: [u8; 32],
    now_ms: u64,
) -> Result<(), FirstDevicePresentationError> {
    if presentation.issued_at_ms >= presentation.expires_at_ms
        || now_ms < presentation.issued_at_ms
        || now_ms >= presentation.expires_at_ms
        || presentation.expires_at_ms > presentation.invitation.expires_at_ms
    {
        return Err(FirstDevicePresentationError::Expired);
    }
    if presentation.invitation.authority_descriptor_digest
        != sha256(&presentation.authority_bundle.exact_bytes).into_bytes()
    {
        return Err(FirstDevicePresentationError::InvalidAuthority);
    }
    if presentation.app_configuration_digest != expected_app_configuration_digest {
        return Err(FirstDevicePresentationError::ConfigurationMismatch);
    }
    Ok(())
}

fn decode_bundle(
    exact_bytes: Vec<u8>,
) -> Result<FirstDeviceAuthorityBundle, FirstDevicePresentationError> {
    let mut fields = exact_map(
        &exact_bytes,
        BUNDLE_FIELDS,
        FirstDevicePresentationError::InvalidAuthority,
    )?;
    require_unsigned(
        fields.get(&0),
        1,
        FirstDevicePresentationError::InvalidAuthority,
    )?;
    require_text_exact(
        fields.get(&1),
        "pistis.first-device-authority-bundle.v1",
        FirstDevicePresentationError::InvalidAuthority,
    )?;
    let initial_bytes = take_bytes(
        fields.remove(&2),
        256,
        FirstDevicePresentationError::InvalidAuthority,
    )?;
    let receipt_bytes = take_bytes(
        fields.remove(&3),
        256,
        FirstDevicePresentationError::InvalidAuthority,
    )?;
    let initial_invitation = decode_descriptor(&initial_bytes)?;
    let mobile_receipt = decode_descriptor(&receipt_bytes)?;
    let initial_key = PublicKey::from_sec1_bytes(&initial_invitation.public_key)
        .map_err(|_| FirstDevicePresentationError::InvalidAuthority)?;
    let receipt_key = PublicKey::from_sec1_bytes(&mobile_receipt.public_key)
        .map_err(|_| FirstDevicePresentationError::InvalidAuthority)?;
    if derive_key_id(&initial_key).into_bytes() != initial_invitation.key_id
        || derive_key_id(&receipt_key).into_bytes() != mobile_receipt.key_id
        || initial_invitation.key_id == mobile_receipt.key_id
    {
        return Err(FirstDevicePresentationError::InvalidAuthority);
    }
    Ok(FirstDeviceAuthorityBundle {
        initial_invitation,
        mobile_receipt,
        exact_bytes,
    })
}

fn decode_descriptor(bytes: &[u8]) -> Result<AuthorityDescriptor, FirstDevicePresentationError> {
    let mut fields = exact_map(
        bytes,
        DESCRIPTOR_FIELDS,
        FirstDevicePresentationError::InvalidAuthority,
    )?;
    require_unsigned(
        fields.get(&0),
        1,
        FirstDevicePresentationError::InvalidAuthority,
    )?;
    require_text_exact(
        fields.get(&1),
        "pistis.authority-key-descriptor.v1",
        FirstDevicePresentationError::InvalidAuthority,
    )?;
    let key_id = fixed_bytes(
        fields.remove(&2),
        FirstDevicePresentationError::InvalidAuthority,
    )?;
    let public_key = fixed_bytes(
        fields.remove(&3),
        FirstDevicePresentationError::InvalidAuthority,
    )?;
    match fields.remove(&4) {
        Some(Value::Negative(-7)) => {}
        _ => return Err(FirstDevicePresentationError::InvalidAuthority),
    }
    Ok(AuthorityDescriptor { key_id, public_key })
}

fn decode_invitation(
    bytes: &[u8],
) -> Result<MobileEnrolmentInvitation, FirstDevicePresentationError> {
    let mut fields = exact_map(
        bytes,
        INVITATION_FIELDS,
        FirstDevicePresentationError::InvalidInvitation,
    )?;
    require_unsigned(
        fields.get(&0),
        2,
        FirstDevicePresentationError::InvalidInvitation,
    )?;
    require_text_exact(
        fields.get(&1),
        "pistis.mobile-enrolment-invitation.v2",
        FirstDevicePresentationError::InvalidInvitation,
    )?;
    let issued_at_ms = unsigned(
        fields.get(&2),
        FirstDevicePresentationError::InvalidInvitation,
    )?;
    let expires_at_ms = unsigned(
        fields.get(&3),
        FirstDevicePresentationError::InvalidInvitation,
    )?;
    let invitation_id = fixed_bytes(
        fields.remove(&4),
        FirstDevicePresentationError::InvalidInvitation,
    )?;
    let _secret: [u8; 32] = fixed_bytes(
        fields.remove(&5),
        FirstDevicePresentationError::InvalidInvitation,
    )?;
    let installation_id = fixed_bytes(
        fields.remove(&6),
        FirstDevicePresentationError::InvalidInvitation,
    )?;
    let audience = bounded_trimmed_text(
        fields.remove(&7),
        128,
        FirstDevicePresentationError::InvalidInvitation,
    )?;
    let authority_descriptor_digest = fixed_bytes(
        fields.remove(&8),
        FirstDevicePresentationError::InvalidInvitation,
    )?;
    let authorised_product_audiences = product_audiences(
        fields.remove(&9),
        FirstDevicePresentationError::InvalidInvitation,
    )?;
    if issued_at_ms >= expires_at_ms {
        return Err(FirstDevicePresentationError::InvalidInvitation);
    }
    Ok(MobileEnrolmentInvitation {
        issued_at_ms,
        expires_at_ms,
        invitation_id,
        installation_id,
        audience,
        authorised_product_audiences,
        authority_descriptor_digest,
    })
}

fn product_audiences(
    value: Option<Value>,
    error: FirstDevicePresentationError,
) -> Result<Vec<String>, FirstDevicePresentationError> {
    let Value::Array(values) = value.ok_or(error)? else {
        return Err(error);
    };
    if values.is_empty() || values.len() > PRODUCT_AUDIENCES.len() {
        return Err(error);
    }
    let audiences: Vec<String> = values
        .into_iter()
        .map(|value| match value {
            Value::Text(text)
                if text.len() <= 128
                    && text.is_ascii()
                    && PRODUCT_AUDIENCES.contains(&text.as_str()) =>
            {
                Ok(text)
            }
            _ => Err(error),
        })
        .collect::<Result<_, _>>()?;
    if audiences.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(error);
    }
    Ok(audiences)
}

fn exact_map(
    bytes: &[u8],
    fields: &[u64],
    error: FirstDevicePresentationError,
) -> Result<CanonicalFields, FirstDevicePresentationError> {
    let values = from_slice_with_fields(bytes, fields).map_err(|_| error)?;
    (values.len() == fields.len())
        .then_some(values)
        .ok_or(error)
}

fn require_unsigned(
    value: Option<&Value>,
    expected: u64,
    error: FirstDevicePresentationError,
) -> Result<(), FirstDevicePresentationError> {
    if value == Some(&Value::Unsigned(expected)) {
        Ok(())
    } else {
        Err(error)
    }
}

fn unsigned(
    value: Option<&Value>,
    error: FirstDevicePresentationError,
) -> Result<u64, FirstDevicePresentationError> {
    match value {
        Some(Value::Unsigned(value)) => Ok(*value),
        _ => Err(error),
    }
}

fn fixed_bytes<const N: usize>(
    value: Option<Value>,
    error: FirstDevicePresentationError,
) -> Result<[u8; N], FirstDevicePresentationError> {
    match value {
        Some(Value::Bytes(bytes)) => bytes.try_into().map_err(|_| error),
        _ => Err(error),
    }
}

fn take_bytes(
    value: Option<Value>,
    maximum: usize,
    error: FirstDevicePresentationError,
) -> Result<Vec<u8>, FirstDevicePresentationError> {
    match value {
        Some(Value::Bytes(bytes)) if !bytes.is_empty() && bytes.len() <= maximum => Ok(bytes),
        _ => Err(error),
    }
}

fn require_text_exact(
    value: Option<&Value>,
    expected: &str,
    error: FirstDevicePresentationError,
) -> Result<(), FirstDevicePresentationError> {
    if value == Some(&Value::Text(expected.into())) {
        Ok(())
    } else {
        Err(error)
    }
}

fn bounded_trimmed_text(
    value: Option<Value>,
    maximum: usize,
    error: FirstDevicePresentationError,
) -> Result<String, FirstDevicePresentationError> {
    match value {
        Some(Value::Text(text))
            if (1..=maximum).contains(&text.len())
                && text.trim() == text
                && !text.chars().any(char::is_control) =>
        {
            Ok(text)
        }
        _ => Err(error),
    }
}

fn canonical_https_origin(value: Option<Value>) -> Result<String, FirstDevicePresentationError> {
    let origin = bounded_trimmed_text(
        value,
        255,
        FirstDevicePresentationError::InvalidPresentation,
    )?;
    if !origin.is_ascii() || origin.contains('%') {
        return Err(FirstDevicePresentationError::InvalidPresentation);
    }
    let parsed =
        Url::parse(&origin).map_err(|_| FirstDevicePresentationError::InvalidPresentation)?;
    let host = parsed
        .host_str()
        .ok_or(FirstDevicePresentationError::InvalidPresentation)?;
    let default_port = parsed.port() == Some(443);
    if parsed.scheme() != "https"
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || host != host.to_ascii_lowercase()
        || host.ends_with('.')
        || host.parse::<std::net::IpAddr>().is_ok()
        || default_port
        || parsed.origin().ascii_serialization() != origin
    {
        return Err(FirstDevicePresentationError::InvalidPresentation);
    }
    Ok(origin)
}
