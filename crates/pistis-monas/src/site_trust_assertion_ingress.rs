//! Production Apple App Attest assertion ingress for one Site Trust ceremony.
//!
//! This module is deliberately transport-neutral.  It accepts a bounded JSON
//! envelope from a mobile client, but it can issue a typed fact only from a
//! server-held acceptance assembled after Monas has verified the original Apple
//! attestation and its pinned Apple trust material.  It has no browser route,
//! cookie, local account, PAM helper, operating-system identity, session, or
//! compatibility fallback.

use core::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::{
    PublicKey,
    ecdsa::{Signature, VerifyingKey, signature::Verifier as _},
};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::site_trust::build_site_trust_human_authority_fact_from_verified_v1;
use crate::{
    AppleAppAttestAssertionV1, SiteTrustAttestationRequestV1, SiteTrustFactCeremonyIdV1,
    SiteTrustFactConsumptionErrorV1, SiteTrustHumanAuthorityFactV1, VerifiedIPhoneAppAttestationV1,
};

/// Exact profile accepted from an iPhone for the Site Trust assertion ceremony.
pub const SITE_TRUST_APP_ATTEST_ASSERTION_INGRESS_PROFILE_V1: &str =
    "mnemosyne.pistis.site-trust-app-attest-assertion-ingress.v1";
/// The only production App ID accepted by this reviewed Monas profile.
pub const MONAS_PRODUCTION_APP_ATTEST_APP_IDENTIFIER_V1: &str =
    "C7A6NQTSY4.org.mnemosynebiosciences.pistis";

const MAXIMUM_MOBILE_SUBMISSION_BYTES: usize = 32 * 1024;
const MAXIMUM_APP_ATTEST_BUNDLE_VERSION_BYTES: usize = 96;
const ASSERTION_CLIENT_DATA_DOMAIN_V1: &[u8] =
    b"mnemosyne.pistis.site-trust-app-attest-client-data.v1\0";
const REDACTED_VECTOR_DOMAIN_V1: &[u8] =
    b"mnemosyne.pistis.site-trust-app-attest-redacted-vector.v1\0";
const AUTHENTICATOR_DATA_MINIMUM_BYTES: usize = 37;
const USER_PRESENT_AND_EXTENSION_FLAGS: u8 = 0x81;

/// A monotonic App Attest assertion counter already structurally verified.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MonotonicAppAttestCounterV1(u32);

impl MonotonicAppAttestCounterV1 {
    /// Returns the verified non-zero counter value.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    fn strictly_after(self, prior: u32) -> bool {
        self.0 > prior
    }
}

/// Coarse failure from the App Attest assertion ingress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SiteTrustAppAttestAssertionIngressErrorV1 {
    /// The mobile envelope or assertion encoding is malformed or oversized.
    Malformed,
    /// A production binding, signature, counter, or verified acceptance check failed.
    Denied,
    /// Required reviewed verifier material or Monas durable state is unavailable.
    Unavailable,
    /// Monas rejected the required atomic counter-and-fact transaction.
    Store(SiteTrustFactConsumptionErrorV1),
}

impl fmt::Display for SiteTrustAppAttestAssertionIngressErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Malformed => "App Attest assertion submission is malformed",
            Self::Denied => "App Attest assertion submission was denied",
            Self::Unavailable => "App Attest assertion verification is unavailable",
            Self::Store(_) => "Monas App Attest fact transaction failed",
        })
    }
}

impl std::error::Error for SiteTrustAppAttestAssertionIngressErrorV1 {}

/// Bounded, untrusted mobile input for exactly one pre-existing ceremony.
///
/// The assertion is transient and intentionally has no public accessor.  The
/// client cannot include an authority fact, a counter, an app identifier, a
/// public key, client data, a browser cookie, or a server acceptance claim.
pub struct SiteTrustAppAttestMobileSubmissionV1 {
    ceremony_id: SiteTrustFactCeremonyIdV1,
    assertion: AppleAppAttestAssertionV1,
}

impl fmt::Debug for SiteTrustAppAttestMobileSubmissionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SiteTrustAppAttestMobileSubmissionV1")
            .field(
                "profile",
                &SITE_TRUST_APP_ATTEST_ASSERTION_INGRESS_PROFILE_V1,
            )
            .field("ceremony_id", &self.ceremony_id)
            .field("assertion", &"[REDACTED]")
            .finish()
    }
}

impl SiteTrustAppAttestMobileSubmissionV1 {
    /// Returns the non-secret ceremony identifier supplied by the client.
    #[must_use]
    pub const fn ceremony_id(&self) -> SiteTrustFactCeremonyIdV1 {
        self.ceremony_id
    }
}

/// Decode one strict, bounded mobile assertion envelope.
///
/// The JSON grammar is exactly `profile`, `ceremony_id_b64url`, and
/// `assertion_b64url`; padded or non-canonical base64url values and unknown
/// fields are denied.  Decoding never treats this input as server authority.
///
/// # Errors
///
/// Returns a coarse malformed or denied result without retaining the raw
/// assertion in an error.
pub fn decode_site_trust_app_attest_mobile_submission_v1(
    encoded: &[u8],
) -> Result<SiteTrustAppAttestMobileSubmissionV1, SiteTrustAppAttestAssertionIngressErrorV1> {
    if encoded.is_empty() || encoded.len() > MAXIMUM_MOBILE_SUBMISSION_BYTES {
        return Err(SiteTrustAppAttestAssertionIngressErrorV1::Malformed);
    }
    let envelope = serde_json::from_slice::<MobileSubmissionEnvelopeV1>(encoded)
        .map_err(|_| SiteTrustAppAttestAssertionIngressErrorV1::Malformed)?;
    if envelope.profile != SITE_TRUST_APP_ATTEST_ASSERTION_INGRESS_PROFILE_V1 {
        return Err(SiteTrustAppAttestAssertionIngressErrorV1::Denied);
    }
    let ceremony_id = decode_canonical_b64url::<16>(&envelope.ceremony_id_b64url)?;
    if ceremony_id == [0; 16] {
        return Err(SiteTrustAppAttestAssertionIngressErrorV1::Denied);
    }
    let assertion = decode_canonical_b64url_bytes(&envelope.assertion_b64url, 1, 16 * 1024)?;
    let assertion = AppleAppAttestAssertionV1::parse(assertion)
        .map_err(|_| SiteTrustAppAttestAssertionIngressErrorV1::Malformed)?;
    Ok(SiteTrustAppAttestMobileSubmissionV1 {
        ceremony_id: SiteTrustFactCeremonyIdV1::from_bytes(ceremony_id),
        assertion,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MobileSubmissionEnvelopeV1 {
    profile: String,
    ceremony_id_b64url: String,
    assertion_b64url: String,
}

/// Server-held proof that Monas accepted the attested App Attest registration.
///
/// This opaque value has no public constructor.  A production runtime may
/// construct it only after its local authenticated Monas bridge has verified a
/// registered Apple key, the exact pinned Apple trust-bundle manifest, and the
/// production application profile.  It is never sent to or accepted from an
/// iPhone, browser, local CLI, operating-system account, PAM path, or cookie.
pub struct ServerHeldMonasAppAttestAcceptanceV1 {
    request: SiteTrustAttestationRequestV1,
    registered_public_key_sec1: [u8; 65],
    previous_counter: u32,
    trust_anchor_manifest_digest: [u8; 32],
    bundle_version: String,
}

impl fmt::Debug for ServerHeldMonasAppAttestAcceptanceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerHeldMonasAppAttestAcceptanceV1")
            .field("ceremony_id", &self.request.ceremony_id)
            .field(
                "trust_anchor_manifest_digest",
                &digest_b64url(&self.trust_anchor_manifest_digest),
            )
            .field("bundle_version", &self.bundle_version)
            .finish_non_exhaustive()
    }
}

impl ServerHeldMonasAppAttestAcceptanceV1 {
    pub(crate) fn from_verified_registration(
        request: SiteTrustAttestationRequestV1,
        registered_public_key_sec1: [u8; 65],
        trust_anchor_manifest_digest: [u8; 32],
        bundle_version: String,
    ) -> Self {
        Self {
            request,
            registered_public_key_sec1,
            previous_counter: 0,
            trust_anchor_manifest_digest,
            bundle_version,
        }
    }

    fn validate(&self) -> Result<(), SiteTrustAppAttestAssertionIngressErrorV1> {
        self.request
            .validate()
            .map_err(|_| SiteTrustAppAttestAssertionIngressErrorV1::Denied)?;
        let registered_key_digest: [u8; 32] =
            Sha256::digest(self.registered_public_key_sec1).into();
        if self.trust_anchor_manifest_digest == [0; 32]
            || !valid_bundle_version(&self.bundle_version)
            || registered_key_digest != *self.request.key_id.as_bytes()
            || PublicKey::from_sec1_bytes(&self.registered_public_key_sec1).is_err()
        {
            return Err(SiteTrustAppAttestAssertionIngressErrorV1::Unavailable);
        }
        Ok(())
    }

    #[cfg(test)]
    fn test_acceptance(
        request: SiteTrustAttestationRequestV1,
        registered_public_key_sec1: [u8; 65],
        previous_counter: u32,
    ) -> Self {
        Self {
            request,
            registered_public_key_sec1,
            previous_counter,
            trust_anchor_manifest_digest: [0x55; 32],
            bundle_version: "1.0.0".into(),
        }
    }
}

/// The atomic Monas-owned persistence boundary for one verified assertion.
///
/// Implementations must compare the current durable counter for the registered
/// key and record both the counter advancement and fact in the same durable,
/// rollback-capable transaction.  A stale acceptance snapshot, duplicate fact,
/// replay, or uncertain write must deny.  Pistis owns neither that state nor a
/// fallback persistence implementation.
pub trait MonasSiteTrustAppAttestAtomicStoreV1 {
    /// Records one verified counter and typed fact atomically.
    ///
    /// # Errors
    ///
    /// The store must leave neither a partial counter update nor a partial fact
    /// when it returns an error.
    fn record_verified_assertion_and_fact(
        &mut self,
        fact: SiteTrustHumanAuthorityFactV1,
        counter: MonotonicAppAttestCounterV1,
    ) -> Result<(), SiteTrustFactConsumptionErrorV1>;
}

/// A complete redacted verifier result suitable only for the atomic store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct VerifiedProductionAssertionV1 {
    assertion_digest: [u8; 32],
    counter: MonotonicAppAttestCounterV1,
}

/// Reviewed production verifier for assertions made by a previously attested iPhone.
///
/// Apple does not include a certificate chain in an assertion.  Therefore this
/// verifier deliberately accepts assertions only under a
/// [`ServerHeldMonasAppAttestAcceptanceV1`] that represents an earlier
/// Apple-root-verified registration.  It has no default-available profile.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProductionAppleAppAttestAssertionVerifierV1;

impl ProductionAppleAppAttestAssertionVerifierV1 {
    fn verify(
        acceptance: &ServerHeldMonasAppAttestAcceptanceV1,
        assertion: &AppleAppAttestAssertionV1,
    ) -> Result<VerifiedProductionAssertionV1, SiteTrustAppAttestAssertionIngressErrorV1> {
        acceptance.validate()?;
        let decoded = decode_assertion_object(assertion.transient_bytes())?;
        let counter = validate_authenticator_data(&decoded.authenticator_data, acceptance)?;
        let challenge = acceptance.request.verification_request().challenge_digest;
        let client_data = assertion_client_data_v1(&challenge);
        let client_data_hash = Sha256::digest(client_data);
        let nonce =
            Sha256::digest([decoded.authenticator_data.as_slice(), &client_data_hash].concat());
        let key = VerifyingKey::from_sec1_bytes(&acceptance.registered_public_key_sec1)
            .map_err(|_| SiteTrustAppAttestAssertionIngressErrorV1::Unavailable)?;
        let signature = Signature::from_der(&decoded.signature)
            .map_err(|_| SiteTrustAppAttestAssertionIngressErrorV1::Denied)?;
        key.verify(&nonce, &signature)
            .map_err(|_| SiteTrustAppAttestAssertionIngressErrorV1::Denied)?;
        Ok(VerifiedProductionAssertionV1 {
            assertion_digest: Sha256::digest(assertion.transient_bytes()).into(),
            counter,
        })
    }
}

/// Verify an assertion and atomically issue the only Monas-consumable fact.
///
/// This is the sole production construction path in this crate for an opaque
/// Site Trust fact from mobile assertion input.  It performs no server session
/// work and returns no raw Apple object.  A caller must already hold the
/// Monas-derived acceptance and use a Monas-owned atomic store.
///
/// # Errors
///
/// Any malformed mobile data, unavailable material, rejected Apple proof, or
/// failed Monas transaction returns a coarse failure and records no fact.
pub fn issue_site_trust_human_authority_fact_from_server_held_app_attest_assertion_v1(
    store: &mut impl MonasSiteTrustAppAttestAtomicStoreV1,
    acceptance: &ServerHeldMonasAppAttestAcceptanceV1,
    submission: &SiteTrustAppAttestMobileSubmissionV1,
) -> Result<SiteTrustAppAttestAssertionIngressOutcomeV1, SiteTrustAppAttestAssertionIngressErrorV1>
{
    if submission.ceremony_id != acceptance.request.ceremony_id {
        return Err(SiteTrustAppAttestAssertionIngressErrorV1::Denied);
    }
    let verified_assertion =
        ProductionAppleAppAttestAssertionVerifierV1::verify(acceptance, &submission.assertion)?;
    let verified_fact = VerifiedIPhoneAppAttestationV1::from_verified_assertion_digest(
        acceptance.request.device_id,
        acceptance.request.key_id,
        verified_assertion.assertion_digest,
    );
    let fact = build_site_trust_human_authority_fact_from_verified_v1(
        acceptance.request.clone(),
        verified_fact,
    )
    .map_err(|error| match error {
        crate::SiteTrustFactIssuanceErrorV1::Store(error) => {
            SiteTrustAppAttestAssertionIngressErrorV1::Store(error)
        }
        crate::SiteTrustFactIssuanceErrorV1::Attestation(_)
        | crate::SiteTrustFactIssuanceErrorV1::InvalidBinding => {
            SiteTrustAppAttestAssertionIngressErrorV1::Denied
        }
    })?;
    store
        .record_verified_assertion_and_fact(fact.clone(), verified_assertion.counter)
        .map_err(SiteTrustAppAttestAssertionIngressErrorV1::Store)?;
    Ok(SiteTrustAppAttestAssertionIngressOutcomeV1 {
        vector: SiteTrustAppAttestAssertionRedactedVectorV1::from_verified(
            &fact,
            acceptance,
            verified_assertion,
        ),
        fact,
    })
}

/// Successful opaque fact and redacted evidence from one atomic issuance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SiteTrustAppAttestAssertionIngressOutcomeV1 {
    fact: SiteTrustHumanAuthorityFactV1,
    vector: SiteTrustAppAttestAssertionRedactedVectorV1,
}

impl SiteTrustAppAttestAssertionIngressOutcomeV1 {
    /// Consumes the outcome and returns the opaque fact for Monas completion.
    #[must_use]
    pub fn into_fact(self) -> SiteTrustHumanAuthorityFactV1 {
        self.fact
    }

    /// Returns deterministic redacted evidence suitable for a retained dossier.
    #[must_use]
    pub fn vector(&self) -> &SiteTrustAppAttestAssertionRedactedVectorV1 {
        &self.vector
    }
}

/// Deterministic, non-secret evidence for a verified production assertion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SiteTrustAppAttestAssertionRedactedVectorV1 {
    fact_digest_b64url: String,
    ceremony_digest_b64url: String,
    challenge_digest_b64url: String,
    canonical_payload_digest_b64url: String,
    assertion_digest_b64url: String,
    trust_anchor_manifest_digest_b64url: String,
    counter: MonotonicAppAttestCounterV1,
}

impl SiteTrustAppAttestAssertionRedactedVectorV1 {
    fn from_verified(
        fact: &SiteTrustHumanAuthorityFactV1,
        acceptance: &ServerHeldMonasAppAttestAcceptanceV1,
        verified: VerifiedProductionAssertionV1,
    ) -> Self {
        let challenge = acceptance.request.verification_request().challenge_digest;
        Self {
            fact_digest_b64url: digest_b64url(fact.id().as_bytes()),
            ceremony_digest_b64url: digest_b64url(fact.ceremony_id().as_bytes()),
            challenge_digest_b64url: digest_b64url(challenge.as_bytes()),
            canonical_payload_digest_b64url: digest_b64url(fact.canonical_payload().digest()),
            assertion_digest_b64url: digest_b64url(&verified.assertion_digest),
            trust_anchor_manifest_digest_b64url: digest_b64url(
                &acceptance.trust_anchor_manifest_digest,
            ),
            counter: verified.counter,
        }
    }

    /// Returns the exact redacted vector profile.
    #[must_use]
    pub const fn profile(&self) -> &'static str {
        SITE_TRUST_APP_ATTEST_ASSERTION_INGRESS_PROFILE_V1
    }

    /// Returns the monotonic counter accepted by the atomic transaction.
    #[must_use]
    pub const fn counter(&self) -> MonotonicAppAttestCounterV1 {
        self.counter
    }

    /// Returns the redacted assertion digest, never the assertion itself.
    #[must_use]
    pub fn assertion_digest_b64url(&self) -> &str {
        &self.assertion_digest_b64url
    }
}

fn validate_authenticator_data(
    authenticator_data: &[u8],
    acceptance: &ServerHeldMonasAppAttestAcceptanceV1,
) -> Result<MonotonicAppAttestCounterV1, SiteTrustAppAttestAssertionIngressErrorV1> {
    let application_rp_id_hash: [u8; 32] =
        Sha256::digest(MONAS_PRODUCTION_APP_ATTEST_APP_IDENTIFIER_V1.as_bytes()).into();
    if authenticator_data.len() <= AUTHENTICATOR_DATA_MINIMUM_BYTES
        || authenticator_data[..32] != application_rp_id_hash
        || authenticator_data[32] != USER_PRESENT_AND_EXTENSION_FLAGS
    {
        return Err(SiteTrustAppAttestAssertionIngressErrorV1::Denied);
    }
    let counter = MonotonicAppAttestCounterV1(u32::from_be_bytes(
        authenticator_data[33..37]
            .try_into()
            .map_err(|_| SiteTrustAppAttestAssertionIngressErrorV1::Denied)?,
    ));
    if !counter.strictly_after(acceptance.previous_counter) {
        return Err(SiteTrustAppAttestAssertionIngressErrorV1::Denied);
    }
    validate_app_attest_extensions(&authenticator_data[37..], &acceptance.bundle_version)?;
    Ok(counter)
}

fn validate_app_attest_extensions(
    encoded: &[u8],
    expected_bundle_version: &str,
) -> Result<(), SiteTrustAppAttestAssertionIngressErrorV1> {
    let mut cursor = CborCursor::new(encoded);
    let entries = cursor.map_len()?;
    if entries != 2 {
        return Err(SiteTrustAppAttestAssertionIngressErrorV1::Denied);
    }
    let mut category = None;
    let mut bundle_version = None;
    for _ in 0..entries {
        match cursor.text()?.as_str() {
            "apple_validation_category_01" if category.is_none() => {
                category = Some(cursor.unsigned()?);
            }
            "apple_bundle_version_01" if bundle_version.is_none() => {
                bundle_version = Some(cursor.text()?);
            }
            _ => return Err(SiteTrustAppAttestAssertionIngressErrorV1::Denied),
        }
    }
    if !cursor.exhausted()
        || !matches!(category, Some(2 | 4 | 5))
        || bundle_version.as_deref() != Some(expected_bundle_version)
    {
        return Err(SiteTrustAppAttestAssertionIngressErrorV1::Denied);
    }
    Ok(())
}

struct DecodedAssertionV1 {
    signature: Vec<u8>,
    authenticator_data: Vec<u8>,
}

fn decode_assertion_object(
    encoded: &[u8],
) -> Result<DecodedAssertionV1, SiteTrustAppAttestAssertionIngressErrorV1> {
    let mut cursor = CborCursor::new(encoded);
    let entries = cursor.map_len()?;
    if entries != 2 {
        return Err(SiteTrustAppAttestAssertionIngressErrorV1::Denied);
    }
    let mut signature = None;
    let mut authenticator_data = None;
    for _ in 0..entries {
        match cursor.text()?.as_str() {
            "signature" if signature.is_none() => signature = Some(cursor.bytes(8, 128)?),
            "authenticatorData" if authenticator_data.is_none() => {
                authenticator_data =
                    Some(cursor.bytes(AUTHENTICATOR_DATA_MINIMUM_BYTES + 1, 1024)?);
            }
            _ => return Err(SiteTrustAppAttestAssertionIngressErrorV1::Denied),
        }
    }
    if !cursor.exhausted() {
        return Err(SiteTrustAppAttestAssertionIngressErrorV1::Denied);
    }
    let (Some(signature), Some(authenticator_data)) = (signature, authenticator_data) else {
        return Err(SiteTrustAppAttestAssertionIngressErrorV1::Denied);
    };
    Ok(DecodedAssertionV1 {
        signature,
        authenticator_data,
    })
}

fn assertion_client_data_v1(challenge: &crate::SiteTrustAttestationChallengeDigestV1) -> Vec<u8> {
    let mut client_data = Vec::with_capacity(ASSERTION_CLIENT_DATA_DOMAIN_V1.len() + 32);
    client_data.extend_from_slice(ASSERTION_CLIENT_DATA_DOMAIN_V1);
    client_data.extend_from_slice(challenge.as_bytes());
    client_data
}

fn decode_canonical_b64url<const N: usize>(
    encoded: &str,
) -> Result<[u8; N], SiteTrustAppAttestAssertionIngressErrorV1> {
    let decoded = decode_canonical_b64url_bytes(encoded, N, N)?;
    decoded
        .try_into()
        .map_err(|_| SiteTrustAppAttestAssertionIngressErrorV1::Malformed)
}

fn decode_canonical_b64url_bytes(
    encoded: &str,
    minimum: usize,
    maximum: usize,
) -> Result<Vec<u8>, SiteTrustAppAttestAssertionIngressErrorV1> {
    if encoded.is_empty()
        || encoded.contains('=')
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(SiteTrustAppAttestAssertionIngressErrorV1::Malformed);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| SiteTrustAppAttestAssertionIngressErrorV1::Malformed)?;
    if !(minimum..=maximum).contains(&decoded.len()) || URL_SAFE_NO_PAD.encode(&decoded) != encoded
    {
        return Err(SiteTrustAppAttestAssertionIngressErrorV1::Malformed);
    }
    Ok(decoded)
}

fn valid_bundle_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAXIMUM_APP_ATTEST_BUNDLE_VERSION_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
}

fn digest_b64url(value: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest([REDACTED_VECTOR_DOMAIN_V1, value].concat()))
}

struct CborCursor<'a> {
    encoded: &'a [u8],
    position: usize,
}

impl<'a> CborCursor<'a> {
    const fn new(encoded: &'a [u8]) -> Self {
        Self {
            encoded,
            position: 0,
        }
    }

    fn map_len(&mut self) -> Result<usize, SiteTrustAppAttestAssertionIngressErrorV1> {
        self.length(5)
    }

    fn text(&mut self) -> Result<String, SiteTrustAppAttestAssertionIngressErrorV1> {
        let length = self.length(3)?;
        let bytes = self.take(length)?;
        if !bytes
            .iter()
            .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
        {
            return Err(SiteTrustAppAttestAssertionIngressErrorV1::Denied);
        }
        String::from_utf8(bytes.to_vec())
            .map_err(|_| SiteTrustAppAttestAssertionIngressErrorV1::Denied)
    }

    fn bytes(
        &mut self,
        minimum: usize,
        maximum: usize,
    ) -> Result<Vec<u8>, SiteTrustAppAttestAssertionIngressErrorV1> {
        let length = self.length(2)?;
        if !(minimum..=maximum).contains(&length) {
            return Err(SiteTrustAppAttestAssertionIngressErrorV1::Denied);
        }
        Ok(self.take(length)?.to_vec())
    }

    fn unsigned(&mut self) -> Result<u64, SiteTrustAppAttestAssertionIngressErrorV1> {
        self.value(0)
    }

    fn length(
        &mut self,
        expected_major: u8,
    ) -> Result<usize, SiteTrustAppAttestAssertionIngressErrorV1> {
        usize::try_from(self.value(expected_major)?)
            .map_err(|_| SiteTrustAppAttestAssertionIngressErrorV1::Denied)
    }

    fn value(
        &mut self,
        expected_major: u8,
    ) -> Result<u64, SiteTrustAppAttestAssertionIngressErrorV1> {
        let initial = *self
            .encoded
            .get(self.position)
            .ok_or(SiteTrustAppAttestAssertionIngressErrorV1::Denied)?;
        self.position += 1;
        if initial >> 5 != expected_major {
            return Err(SiteTrustAppAttestAssertionIngressErrorV1::Denied);
        }
        match initial & 0x1f {
            value @ 0..=23 => Ok(u64::from(value)),
            24 => Ok(u64::from(self.byte()?)),
            25 => Ok(u64::from(u16::from_be_bytes(
                self.take(2)?
                    .try_into()
                    .map_err(|_| SiteTrustAppAttestAssertionIngressErrorV1::Denied)?,
            ))),
            26 => Ok(u64::from(u32::from_be_bytes(
                self.take(4)?
                    .try_into()
                    .map_err(|_| SiteTrustAppAttestAssertionIngressErrorV1::Denied)?,
            ))),
            _ => Err(SiteTrustAppAttestAssertionIngressErrorV1::Denied),
        }
    }

    fn byte(&mut self) -> Result<u8, SiteTrustAppAttestAssertionIngressErrorV1> {
        let value = *self
            .encoded
            .get(self.position)
            .ok_or(SiteTrustAppAttestAssertionIngressErrorV1::Denied)?;
        self.position += 1;
        Ok(value)
    }

    fn take(
        &mut self,
        length: usize,
    ) -> Result<&'a [u8], SiteTrustAppAttestAssertionIngressErrorV1> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(SiteTrustAppAttestAssertionIngressErrorV1::Denied)?;
        let value = self
            .encoded
            .get(self.position..end)
            .ok_or(SiteTrustAppAttestAssertionIngressErrorV1::Denied)?;
        self.position = end;
        Ok(value)
    }

    const fn exhausted(&self) -> bool {
        self.position == self.encoded.len()
    }
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use p256::ecdsa::{SigningKey, signature::Signer as _};
    use pistis_domain::{DeviceId, InstallationId, KeyId};
    use pistis_protocol::UnixTimeMillis;

    use super::*;
    use crate::{SiteTrustCanonicalPayloadV1, SiteTrustPistisIntentV1};

    #[derive(Default)]
    struct AtomicStore {
        calls: usize,
        fact: Option<SiteTrustHumanAuthorityFactV1>,
        counter: Option<MonotonicAppAttestCounterV1>,
    }

    impl MonasSiteTrustAppAttestAtomicStoreV1 for AtomicStore {
        fn record_verified_assertion_and_fact(
            &mut self,
            fact: SiteTrustHumanAuthorityFactV1,
            counter: MonotonicAppAttestCounterV1,
        ) -> Result<(), SiteTrustFactConsumptionErrorV1> {
            self.calls += 1;
            self.fact = Some(fact);
            self.counter = Some(counter);
            Ok(())
        }
    }

    fn request(key_id: KeyId) -> SiteTrustAttestationRequestV1 {
        SiteTrustAttestationRequestV1 {
            installation_id: InstallationId::from_bytes([1; 16]),
            device_id: DeviceId::from_bytes([2; 16]),
            key_id,
            ceremony_id: SiteTrustFactCeremonyIdV1::from_bytes([3; 16]),
            canonical_payload: SiteTrustCanonicalPayloadV1::parse(payload()).unwrap(),
            pistis_intent: SiteTrustPistisIntentV1::parse(
                "mnemosyne.pistis.intent.v1:intent-demo".into(),
            )
            .unwrap(),
            issued_at: UnixTimeMillis::new(42),
        }
    }

    fn payload() -> Vec<u8> {
        let fields = [
            "mnemosyne.proxenos.std.v1",
            "1",
            "request-pending",
            "site-demo",
            "tenant-demo",
            "installation-demo",
            "request-demo",
            "monas-local",
            "trust-admission",
            "2026-01-01T00:00:00Z",
            "2026-01-01T01:00:00Z",
            "none",
            "intent-demo",
        ];
        fields
            .iter()
            .enumerate()
            .fold(Vec::new(), |mut output, (index, field)| {
                output.push(u8::try_from(index + 1).unwrap());
                output.extend_from_slice(&(field.len() as u32).to_be_bytes());
                output.extend_from_slice(field.as_bytes());
                output
            })
    }

    fn mobile_submission(
        ceremony_id: SiteTrustFactCeremonyIdV1,
        assertion: Vec<u8>,
    ) -> SiteTrustAppAttestMobileSubmissionV1 {
        let encoded = serde_json::json!({
            "profile": SITE_TRUST_APP_ATTEST_ASSERTION_INGRESS_PROFILE_V1,
            "ceremony_id_b64url": URL_SAFE_NO_PAD.encode(ceremony_id.as_bytes()),
            "assertion_b64url": URL_SAFE_NO_PAD.encode(assertion),
        });
        decode_site_trust_app_attest_mobile_submission_v1(encoded.to_string().as_bytes()).unwrap()
    }

    fn valid_assertion(
        signing_key: &SigningKey,
        request: &SiteTrustAttestationRequestV1,
        counter: u32,
    ) -> Vec<u8> {
        let auth_data = authenticator_data(request, counter);
        let challenge = request.verification_request().challenge_digest;
        let client_data_hash = Sha256::digest(assertion_client_data_v1(&challenge));
        let nonce = Sha256::digest([auth_data.as_slice(), &client_data_hash].concat());
        let signature: Signature = signing_key.sign(&nonce);
        cbor_map_bytes(&[
            ("signature", signature.to_der().as_bytes()),
            ("authenticatorData", auth_data.as_slice()),
        ])
    }

    fn authenticator_data(_request: &SiteTrustAttestationRequestV1, counter: u32) -> Vec<u8> {
        let mut data =
            Sha256::digest(MONAS_PRODUCTION_APP_ATTEST_APP_IDENTIFIER_V1.as_bytes()).to_vec();
        data.push(USER_PRESENT_AND_EXTENSION_FLAGS);
        data.extend_from_slice(&counter.to_be_bytes());
        data.extend_from_slice(&cbor_extensions("1.0.0", 4));
        data
    }

    fn cbor_extensions(bundle_version: &str, category: u8) -> Vec<u8> {
        let mut value = vec![0xa2];
        cbor_text(&mut value, "apple_validation_category_01");
        cbor_unsigned(&mut value, category);
        cbor_text(&mut value, "apple_bundle_version_01");
        cbor_text(&mut value, bundle_version);
        value
    }

    fn cbor_map_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut value = vec![0xa0 + u8::try_from(entries.len()).unwrap()];
        for (key, bytes) in entries {
            cbor_text(&mut value, key);
            cbor_bytes(&mut value, bytes);
        }
        value
    }

    fn cbor_text(output: &mut Vec<u8>, text: &str) {
        cbor_head(output, 3, text.len());
        output.extend_from_slice(text.as_bytes());
    }

    fn cbor_bytes(output: &mut Vec<u8>, bytes: &[u8]) {
        cbor_head(output, 2, bytes.len());
        output.extend_from_slice(bytes);
    }

    fn cbor_unsigned(output: &mut Vec<u8>, value: u8) {
        output.push(value);
    }

    fn cbor_head(output: &mut Vec<u8>, major: u8, length: usize) {
        if length < 24 {
            output.push((major << 5) | u8::try_from(length).unwrap());
        } else {
            output.push((major << 5) | 24);
            output.push(u8::try_from(length).unwrap());
        }
    }

    fn acceptance(
        signing_key: &SigningKey,
        prior_counter: u32,
    ) -> ServerHeldMonasAppAttestAcceptanceV1 {
        let encoded = signing_key.verifying_key().to_encoded_point(false);
        let public_key: [u8; 65] = encoded.as_bytes().try_into().unwrap();
        let key_id = KeyId::from_bytes(Sha256::digest(public_key).into());
        ServerHeldMonasAppAttestAcceptanceV1::test_acceptance(
            request(key_id),
            public_key,
            prior_counter,
        )
    }

    #[test]
    fn verifies_production_assertion_and_issues_atomically() {
        let signing_key = SigningKey::from_bytes((&[7; 32]).into()).unwrap();
        let acceptance = acceptance(&signing_key, 0);
        let assertion = valid_assertion(&signing_key, &acceptance.request, 1);
        let submission = mobile_submission(acceptance.request.ceremony_id, assertion);
        let mut store = AtomicStore::default();
        let outcome =
            issue_site_trust_human_authority_fact_from_server_held_app_attest_assertion_v1(
                &mut store,
                &acceptance,
                &submission,
            )
            .unwrap();
        assert_eq!(store.calls, 1);
        assert_eq!(store.counter.unwrap().get(), 1);
        assert_eq!(
            outcome.vector().profile(),
            SITE_TRUST_APP_ATTEST_ASSERTION_INGRESS_PROFILE_V1
        );
        assert_eq!(outcome.vector().counter().get(), 1);
        assert_eq!(outcome.into_fact().key_id(), acceptance.request.key_id);
    }

    #[test]
    fn rejects_client_minted_context_bindings_and_stale_counter_before_store() {
        let signing_key = SigningKey::from_bytes((&[8; 32]).into()).unwrap();
        let mut acceptance = acceptance(&signing_key, 1);
        let assertion = valid_assertion(&signing_key, &acceptance.request, 1);
        let mut store = AtomicStore::default();
        let submission = mobile_submission(acceptance.request.ceremony_id, assertion);
        assert_eq!(
            issue_site_trust_human_authority_fact_from_server_held_app_attest_assertion_v1(
                &mut store,
                &acceptance,
                &submission,
            ),
            Err(SiteTrustAppAttestAssertionIngressErrorV1::Denied)
        );
        assert_eq!(store.calls, 0);
        acceptance.trust_anchor_manifest_digest = [0; 32];
        let assertion = valid_assertion(&signing_key, &acceptance.request, 2);
        let submission = mobile_submission(acceptance.request.ceremony_id, assertion);
        assert_eq!(
            issue_site_trust_human_authority_fact_from_server_held_app_attest_assertion_v1(
                &mut store,
                &acceptance,
                &submission,
            ),
            Err(SiteTrustAppAttestAssertionIngressErrorV1::Unavailable)
        );
        assert_eq!(store.calls, 0);
    }

    #[test]
    fn rejects_development_category_wrong_ceremony_and_noncanonical_mobile_input() {
        let signing_key = SigningKey::from_bytes((&[9; 32]).into()).unwrap();
        let acceptance = acceptance(&signing_key, 0);
        let mut store = AtomicStore::default();
        let mut bad_assertion = valid_assertion(&signing_key, &acceptance.request, 1);
        let category = bad_assertion
            .windows(b"apple_validation_category_01".len())
            .position(|value| value == b"apple_validation_category_01")
            .unwrap()
            + b"apple_validation_category_01".len();
        bad_assertion[category] = 3;
        let submission = mobile_submission(acceptance.request.ceremony_id, bad_assertion);
        assert!(
            issue_site_trust_human_authority_fact_from_server_held_app_attest_assertion_v1(
                &mut store,
                &acceptance,
                &submission,
            )
            .is_err()
        );
        assert_eq!(store.calls, 0);
        let assertion = valid_assertion(&signing_key, &acceptance.request, 1);
        let submission =
            mobile_submission(SiteTrustFactCeremonyIdV1::from_bytes([4; 16]), assertion);
        assert_eq!(
            issue_site_trust_human_authority_fact_from_server_held_app_attest_assertion_v1(
                &mut store,
                &acceptance,
                &submission,
            ),
            Err(SiteTrustAppAttestAssertionIngressErrorV1::Denied)
        );
        assert_eq!(store.calls, 0);
        assert!(decode_site_trust_app_attest_mobile_submission_v1(
            br#"{\"profile\":\"mnemosyne.pistis.site-trust-app-attest-assertion-ingress.v1\",\"ceremony_id_b64url\":\"AwMDAwMDAwMDAwMDAwMDAw==\",\"assertion_b64url\":\"AA\"}"#
        ).is_err());
    }

    #[test]
    fn assertion_debug_and_vector_do_not_retain_raw_assertion() {
        let raw = b"private-apple-assertion";
        let assertion = AppleAppAttestAssertionV1::parse(raw.to_vec()).unwrap();
        assert!(!format!("{assertion:?}").contains("private-apple-assertion"));
        let submission =
            mobile_submission(SiteTrustFactCeremonyIdV1::from_bytes([3; 16]), raw.to_vec());
        assert!(!format!("{submission:?}").contains("private-apple-assertion"));
    }
}
