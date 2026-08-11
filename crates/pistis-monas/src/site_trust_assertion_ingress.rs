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

use pistis_domain::{InstallationId, KeyId};

use crate::site_trust::build_site_trust_human_authority_fact_from_verified_v1;
use crate::{
    AppleAppAttestAssertionV1, SiteTrustAttestationRequestV1, SiteTrustFactCeremonyIdV1,
    SiteTrustFactConsumptionErrorV1, SiteTrustHumanAuthorityFactV1, VerifiedIPhoneAppAttestationV1,
};

mod verified_recipient_key;

/// Exact profile accepted from an iPhone for the Site Trust assertion ceremony.
pub const SITE_TRUST_APP_ATTEST_ASSERTION_INGRESS_PROFILE_V1: &str =
    "mnemosyne.pistis.site-trust-app-attest-assertion-ingress.v1";
/// The only production App ID accepted by this reviewed Monas profile.
pub const MONAS_PRODUCTION_APP_ATTEST_APP_IDENTIFIER_V1: &str =
    "C7A6NQTSY4.org.mnemosynebiosciences.pistis";
/// Exact authority audience for a fresh physical-iPhone MTGS recovery assertion.
pub const MONAS_MTGS_RECOVERY_AUDIENCE_V1: &str = "monas:site-trust:mtgs-recovery:v1";

const MAXIMUM_MOBILE_SUBMISSION_BYTES: usize = 32 * 1024;
const MAXIMUM_APP_ATTEST_BUNDLE_VERSION_BYTES: usize = 96;
const ASSERTION_CLIENT_DATA_DOMAIN_V1: &[u8] =
    b"mnemosyne.pistis.site-trust-app-attest-client-data.v1\0";
const REDACTED_VECTOR_DOMAIN_V1: &[u8] =
    b"mnemosyne.pistis.site-trust-app-attest-redacted-vector.v1\0";
const AUTHENTICATOR_DATA_MINIMUM_BYTES: usize = 37;
const USER_PRESENT_FLAG: u8 = 0x01;
const ATTESTED_CREDENTIAL_DATA_FLAG: u8 = 0x40;
const EXTENSION_DATA_FLAG: u8 = 0x80;
const ADVISORY_ASSERTION_FLAGS: u8 = USER_PRESENT_FLAG | ATTESTED_CREDENTIAL_DATA_FLAG;
const ALLOWED_ASSERTION_FLAGS: u8 = ADVISORY_ASSERTION_FLAGS | EXTENSION_DATA_FLAG;
const CUSTODY_ROTATION_CHALLENGE_DOMAIN_V1: &[u8] = b"MONASAC2\0";

/// Narrow server-owned request for one genesis custody-rotation assertion.
///
/// It deliberately has no device, principal, human-authority, or session field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustodyRotationAppAttestRequestV1 {
    installation_id: InstallationId,
    site_trust_domain: String,
    ceremony_id: SiteTrustFactCeremonyIdV1,
    key_id: KeyId,
    client_data_hash: [u8; 32],
    tls_leaf_spki_sha256: [u8; 32],
    genesis_config_sha256: [u8; 32],
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
}

impl CustodyRotationAppAttestRequestV1 {
    /// Constructs and validates the exact server-owned challenge binding.
    ///
    /// # Errors
    ///
    /// Denies malformed, zero, expired, overlong, or digest-substituted input.
    #[allow(clippy::too_many_arguments)]
    pub fn from_server_owned_challenge(
        installation_id: InstallationId,
        site_trust_domain: String,
        ceremony_id: SiteTrustFactCeremonyIdV1,
        key_id: KeyId,
        client_data_hash: [u8; 32],
        tls_leaf_spki_sha256: [u8; 32],
        genesis_config_sha256: [u8; 32],
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
    ) -> Result<Self, SiteTrustAppAttestAssertionIngressErrorV1> {
        let request = Self {
            installation_id,
            site_trust_domain,
            ceremony_id,
            key_id,
            client_data_hash,
            tls_leaf_spki_sha256,
            genesis_config_sha256,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), SiteTrustAppAttestAssertionIngressErrorV1> {
        let lifetime = self
            .expires_at_unix_seconds
            .checked_sub(self.issued_at_unix_seconds)
            .filter(|value| (1..=900).contains(value));
        let expected = custody_rotation_client_data_hash(self);
        if self.installation_id.as_bytes() == &[0; 16]
            || self.ceremony_id.as_bytes() == &[0; 16]
            || self.key_id.as_bytes() == &[0; 32]
            || self.tls_leaf_spki_sha256 == [0; 32]
            || self.genesis_config_sha256 == [0; 32]
            || self.site_trust_domain.is_empty()
            || self.site_trust_domain.len() > 255
            || !self
                .site_trust_domain
                .bytes()
                .all(|b| (0x21..=0x7e).contains(&b))
            || lifetime.is_none()
            || expected != self.client_data_hash
        {
            return Err(SiteTrustAppAttestAssertionIngressErrorV1::Denied);
        }
        Ok(())
    }

    pub(crate) const fn key_id(&self) -> KeyId {
        self.key_id
    }
}

fn custody_rotation_client_data_hash(request: &CustodyRotationAppAttestRequestV1) -> [u8; 32] {
    let mut canonical = Vec::new();
    canonical.extend_from_slice(CUSTODY_ROTATION_CHALLENGE_DOMAIN_V1);
    canonical.extend_from_slice(request.installation_id.as_bytes());
    canonical.extend_from_slice(
        &u16::try_from(request.site_trust_domain.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    canonical.extend_from_slice(request.site_trust_domain.as_bytes());
    canonical.extend_from_slice(request.ceremony_id.as_bytes());
    canonical.extend_from_slice(request.key_id.as_bytes());
    canonical.extend_from_slice(&request.issued_at_unix_seconds.to_be_bytes());
    canonical.extend_from_slice(&request.expires_at_unix_seconds.to_be_bytes());
    canonical.extend_from_slice(&request.tls_leaf_spki_sha256);
    canonical.extend_from_slice(&request.genesis_config_sha256);
    Sha256::digest(canonical).into()
}

/// Opaque durable-registration acceptance for custody rotation only.
pub struct ServerHeldCustodyRotationAppAttestAcceptanceV1 {
    request: CustodyRotationAppAttestRequestV1,
    registered_public_key_sec1: [u8; 65],
    previous_counter: u32,
    bundle_version: String,
}

impl ServerHeldCustodyRotationAppAttestAcceptanceV1 {
    pub(crate) fn new(
        request: CustodyRotationAppAttestRequestV1,
        registered_public_key_sec1: [u8; 65],
        previous_counter: u32,
        bundle_version: String,
    ) -> Self {
        Self {
            request,
            registered_public_key_sec1,
            previous_counter,
            bundle_version,
        }
    }
}

/// Redacted proof that one narrow custody-rotation assertion verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustodyRotationAppAttestOutcomeV1 {
    counter: MonotonicAppAttestCounterV1,
    assertion_sha256: [u8; 32],
}

impl CustodyRotationAppAttestOutcomeV1 {
    /// Returns the counter Monas must atomically persist while consuming the challenge.
    #[must_use]
    pub const fn counter(&self) -> MonotonicAppAttestCounterV1 {
        self.counter
    }

    /// Returns only the assertion digest for retained audit evidence.
    #[must_use]
    pub const fn assertion_sha256(&self) -> [u8; 32] {
        self.assertion_sha256
    }
}

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

    pub(crate) fn from_verified_durable_registration(
        request: SiteTrustAttestationRequestV1,
        registered_public_key_sec1: [u8; 65],
        previous_counter: u32,
        trust_anchor_manifest_digest: [u8; 32],
        bundle_version: String,
    ) -> Self {
        Self {
            request,
            registered_public_key_sec1,
            previous_counter,
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
        let client_data = assertion_client_data_v1(challenge.as_bytes());
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

/// Verifies one assertion only for the narrow genesis custody-rotation gate.
///
/// This returns no human-authority fact, device identity, principal, or session.
/// Monas must atomically advance the counter and consume the exact challenge
/// before arming its separately typed v2 rotation state.
///
/// # Errors
///
/// Denies an expired request, ceremony mismatch, stale counter, wrong production
/// application extension, malformed assertion, or invalid registered-key signature.
pub fn verify_custody_rotation_app_attest_assertion_v1(
    acceptance: &ServerHeldCustodyRotationAppAttestAcceptanceV1,
    submission: &SiteTrustAppAttestMobileSubmissionV1,
    now_unix_seconds: u64,
) -> Result<CustodyRotationAppAttestOutcomeV1, SiteTrustAppAttestAssertionIngressErrorV1> {
    verify_custody_rotation_app_attest_assertion_diagnostic_v1(
        acceptance,
        submission,
        now_unix_seconds,
    )
    .map_err(|_| SiteTrustAppAttestAssertionIngressErrorV1::Denied)
}

/// Redacted, non-secret failure stage for production custody assertion audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodyRotationAppAttestFailureStageV1 {
    /// The server-owned request failed its canonical binding validation.
    RequestBinding,
    /// The ceremony identifier or server-owned validity window did not match.
    CeremonyOrLifetime,
    /// The durable registered key did not match the request key identifier.
    RegisteredKeyBinding,
    /// Apple's assertion object was not structurally canonical.
    AssertionEncoding,
    /// The production application hash or authenticator flags did not match.
    ApplicationBinding,
    /// Apple's authenticator data was shorter than the closed legacy form.
    AuthenticatorDataLength {
        /// Observed authenticator-data byte length.
        actual: usize,
    },
    /// Apple's RP-ID hash did not bind the reviewed application identifier.
    RpIdHash,
    /// The flags did not match a closed legacy or extension-bearing form.
    AuthenticatorFlags {
        /// Observed non-secret authenticator flags byte.
        actual: u8,
        /// Observed authenticator-data byte length.
        length: usize,
    },
    /// Apple's monotonic counter was malformed or stale.
    Counter,
    /// Apple's validation-category or bundle-version extensions did not match.
    AppleExtensions,
    /// Apple's extension bytes were not the exact closed CBOR map.
    AppleExtensionCbor,
    /// Apple's launch-validation category was outside the reviewed policy.
    AppleValidationCategory,
    /// Apple's signed bundle version differed from the reviewed build.
    AppleBundleVersion,
    /// The durable registered public key was unusable.
    RegisteredKey,
    /// Apple's assertion signature was not canonical DER.
    SignatureEncoding,
    /// The assertion signature did not verify against the registered key.
    SignatureVerification,
}

/// Verifies the same fail-closed assertion while preserving only its safe
/// failure stage for a protected service journal. No assertion bytes, keys,
/// identifiers, counters, hashes, or caller text are exposed by the error.
pub fn verify_custody_rotation_app_attest_assertion_diagnostic_v1(
    acceptance: &ServerHeldCustodyRotationAppAttestAcceptanceV1,
    submission: &SiteTrustAppAttestMobileSubmissionV1,
    now_unix_seconds: u64,
) -> Result<CustodyRotationAppAttestOutcomeV1, CustodyRotationAppAttestFailureStageV1> {
    acceptance
        .request
        .validate()
        .map_err(|_| CustodyRotationAppAttestFailureStageV1::RequestBinding)?;
    if submission.ceremony_id != acceptance.request.ceremony_id
        || now_unix_seconds < acceptance.request.issued_at_unix_seconds
        || now_unix_seconds >= acceptance.request.expires_at_unix_seconds
    {
        return Err(CustodyRotationAppAttestFailureStageV1::CeremonyOrLifetime);
    }
    if <[u8; 32]>::from(Sha256::digest(acceptance.registered_public_key_sec1))
        != *acceptance.request.key_id.as_bytes()
    {
        return Err(CustodyRotationAppAttestFailureStageV1::RegisteredKeyBinding);
    }
    let decoded = decode_assertion_object(submission.assertion.transient_bytes())
        .map_err(|_| CustodyRotationAppAttestFailureStageV1::AssertionEncoding)?;
    let application_hash: [u8; 32] =
        Sha256::digest(MONAS_PRODUCTION_APP_ATTEST_APP_IDENTIFIER_V1).into();
    if decoded.authenticator_data.len() < AUTHENTICATOR_DATA_MINIMUM_BYTES {
        return Err(
            CustodyRotationAppAttestFailureStageV1::AuthenticatorDataLength {
                actual: decoded.authenticator_data.len(),
            },
        );
    }
    if decoded.authenticator_data[..32] != application_hash {
        return Err(CustodyRotationAppAttestFailureStageV1::RpIdHash);
    }
    match decoded.authenticator_data.len() {
        AUTHENTICATOR_DATA_MINIMUM_BYTES
            if decoded.authenticator_data[32] & !ADVISORY_ASSERTION_FLAGS == 0 => {}
        length if length > AUTHENTICATOR_DATA_MINIMUM_BYTES => {
            let flags = decoded.authenticator_data[32];
            if flags & !ALLOWED_ASSERTION_FLAGS != 0 || flags & EXTENSION_DATA_FLAG == 0 {
                return Err(CustodyRotationAppAttestFailureStageV1::AuthenticatorFlags {
                    actual: flags,
                    length,
                });
            }
            validate_app_attest_extensions_diagnostic(
                &decoded.authenticator_data[AUTHENTICATOR_DATA_MINIMUM_BYTES..],
                &acceptance.bundle_version,
            )?;
        }
        length => {
            return Err(CustodyRotationAppAttestFailureStageV1::AuthenticatorFlags {
                actual: decoded.authenticator_data[32],
                length,
            });
        }
    }
    let counter = MonotonicAppAttestCounterV1(u32::from_be_bytes(
        decoded.authenticator_data[33..37]
            .try_into()
            .map_err(|_| CustodyRotationAppAttestFailureStageV1::Counter)?,
    ));
    if !counter.strictly_after(acceptance.previous_counter) {
        return Err(CustodyRotationAppAttestFailureStageV1::Counter);
    }
    let nonce = Sha256::digest(
        [
            decoded.authenticator_data.as_slice(),
            acceptance.request.client_data_hash.as_slice(),
        ]
        .concat(),
    );
    let key = VerifyingKey::from_sec1_bytes(&acceptance.registered_public_key_sec1)
        .map_err(|_| CustodyRotationAppAttestFailureStageV1::RegisteredKey)?;
    let signature = Signature::from_der(&decoded.signature)
        .map_err(|_| CustodyRotationAppAttestFailureStageV1::SignatureEncoding)?;
    key.verify(&nonce, &signature)
        .map_err(|_| CustodyRotationAppAttestFailureStageV1::SignatureVerification)?;
    Ok(CustodyRotationAppAttestOutcomeV1 {
        counter,
        assertion_sha256: Sha256::digest(submission.assertion.transient_bytes()).into(),
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
    if authenticator_data.len() < AUTHENTICATOR_DATA_MINIMUM_BYTES
        || authenticator_data[..32] != application_rp_id_hash
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
    if !valid_assertion_flags_and_extensions(authenticator_data, &acceptance.bundle_version) {
        return Err(SiteTrustAppAttestAssertionIngressErrorV1::Denied);
    }
    Ok(counter)
}

/// iOS 26 and earlier emit the closed 37-byte App Attest assertion form with
/// no extensions. iOS 27 adds an extension map and sets the user-present and
/// extension-data bits. Length, flags and extension presence are treated as a
/// single closed shape so a caller cannot downgrade or mix the two profiles.
fn valid_assertion_flags_and_extensions(
    authenticator_data: &[u8],
    expected_bundle_version: &str,
) -> bool {
    match authenticator_data.len() {
        AUTHENTICATOR_DATA_MINIMUM_BYTES => authenticator_data[32] & !ADVISORY_ASSERTION_FLAGS == 0,
        length if length > AUTHENTICATOR_DATA_MINIMUM_BYTES => {
            authenticator_data[32] & !ALLOWED_ASSERTION_FLAGS == 0
                && authenticator_data[32] & EXTENSION_DATA_FLAG != 0
                && validate_app_attest_extensions(
                    &authenticator_data[AUTHENTICATOR_DATA_MINIMUM_BYTES..],
                    expected_bundle_version,
                )
                .is_ok()
        }
        _ => false,
    }
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

fn validate_app_attest_extensions_diagnostic(
    encoded: &[u8],
    expected_bundle_version: &str,
) -> Result<(), CustodyRotationAppAttestFailureStageV1> {
    let mut cursor = CborCursor::new(encoded);
    let entries = cursor
        .map_len()
        .map_err(|_| CustodyRotationAppAttestFailureStageV1::AppleExtensionCbor)?;
    if entries != 2 {
        return Err(CustodyRotationAppAttestFailureStageV1::AppleExtensionCbor);
    }
    let mut category = None;
    let mut bundle_version = None;
    for _ in 0..entries {
        let key = cursor
            .text()
            .map_err(|_| CustodyRotationAppAttestFailureStageV1::AppleExtensionCbor)?;
        match key.as_str() {
            "apple_validation_category_01" if category.is_none() => {
                category = Some(
                    cursor
                        .unsigned()
                        .map_err(|_| CustodyRotationAppAttestFailureStageV1::AppleExtensionCbor)?,
                );
            }
            "apple_bundle_version_01" if bundle_version.is_none() => {
                bundle_version = Some(
                    cursor
                        .text()
                        .map_err(|_| CustodyRotationAppAttestFailureStageV1::AppleExtensionCbor)?,
                );
            }
            _ => return Err(CustodyRotationAppAttestFailureStageV1::AppleExtensionCbor),
        }
    }
    if !cursor.exhausted() {
        return Err(CustodyRotationAppAttestFailureStageV1::AppleExtensionCbor);
    }
    if !matches!(category, Some(2 | 4 | 5)) {
        return Err(CustodyRotationAppAttestFailureStageV1::AppleValidationCategory);
    }
    if bundle_version.as_deref() != Some(expected_bundle_version) {
        return Err(CustodyRotationAppAttestFailureStageV1::AppleBundleVersion);
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
                authenticator_data = Some(cursor.bytes(1, 1024)?);
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

fn assertion_client_data_v1(challenge: &[u8; 32]) -> Vec<u8> {
    let mut client_data = Vec::with_capacity(ASSERTION_CLIENT_DATA_DOMAIN_V1.len() + 32);
    client_data.extend_from_slice(ASSERTION_CLIENT_DATA_DOMAIN_V1);
    client_data.extend_from_slice(challenge);
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
    use serde::Deserialize;

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
        assertion_for_authenticator_data(signing_key, request, auth_data)
    }

    fn legacy_assertion(
        signing_key: &SigningKey,
        request: &SiteTrustAttestationRequestV1,
        counter: u32,
    ) -> Vec<u8> {
        let auth_data = legacy_authenticator_data(counter);
        assertion_for_authenticator_data(signing_key, request, auth_data)
    }

    fn assertion_for_authenticator_data(
        signing_key: &SigningKey,
        request: &SiteTrustAttestationRequestV1,
        auth_data: Vec<u8>,
    ) -> Vec<u8> {
        let challenge = request.verification_request().challenge_digest;
        let client_data_hash = Sha256::digest(assertion_client_data_v1(challenge.as_bytes()));
        let nonce = Sha256::digest([auth_data.as_slice(), &client_data_hash].concat());
        let signature: Signature = signing_key.sign(&nonce);
        cbor_map_bytes(&[
            ("signature", signature.to_der().as_bytes()),
            ("authenticatorData", auth_data.as_slice()),
        ])
    }

    fn legacy_authenticator_data(counter: u32) -> Vec<u8> {
        let mut data =
            Sha256::digest(MONAS_PRODUCTION_APP_ATTEST_APP_IDENTIFIER_V1.as_bytes()).to_vec();
        data.push(0x00);
        data.extend_from_slice(&counter.to_be_bytes());
        data
    }

    fn custody_acceptance(
        signing_key: &SigningKey,
        prior_counter: u32,
    ) -> ServerHeldCustodyRotationAppAttestAcceptanceV1 {
        let public_key: [u8; 65] = signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .unwrap();
        let mut request = CustodyRotationAppAttestRequestV1 {
            installation_id: InstallationId::from_bytes([0x11; 16]),
            site_trust_domain: "site-demo".into(),
            ceremony_id: SiteTrustFactCeremonyIdV1::from_bytes([0x22; 16]),
            key_id: KeyId::from_bytes(Sha256::digest(public_key).into()),
            client_data_hash: [0x33; 32],
            tls_leaf_spki_sha256: [0x44; 32],
            genesis_config_sha256: [0x55; 32],
            issued_at_unix_seconds: 100,
            expires_at_unix_seconds: 200,
        };
        request.client_data_hash = custody_rotation_client_data_hash(&request);
        ServerHeldCustodyRotationAppAttestAcceptanceV1::new(
            request,
            public_key,
            prior_counter,
            "1.0.0".into(),
        )
    }

    fn custody_assertion(
        signing_key: &SigningKey,
        acceptance: &ServerHeldCustodyRotationAppAttestAcceptanceV1,
        auth_data: Vec<u8>,
    ) -> Vec<u8> {
        let nonce = Sha256::digest(
            [
                auth_data.as_slice(),
                acceptance.request.client_data_hash.as_slice(),
            ]
            .concat(),
        );
        let signature: Signature = signing_key.sign(&nonce);
        cbor_map_bytes(&[
            ("signature", signature.to_der().as_bytes()),
            ("authenticatorData", auth_data.as_slice()),
        ])
    }

    fn authenticator_data(_request: &SiteTrustAttestationRequestV1, counter: u32) -> Vec<u8> {
        let mut data =
            Sha256::digest(MONAS_PRODUCTION_APP_ATTEST_APP_IDENTIFIER_V1.as_bytes()).to_vec();
        data.push(EXTENSION_DATA_FLAG);
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

    pub(super) fn acceptance(
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

    #[derive(Deserialize)]
    struct ClientDataKnownAnswerVectorV1 {
        profile: String,
        purpose: String,
        challenge_digest_b64url: String,
        client_data_b64url: String,
        client_data_sha256_b64url: String,
    }

    #[test]
    fn client_data_known_answer_vector_fixes_iphone_hash_input() {
        let vector: ClientDataKnownAnswerVectorV1 = serde_json::from_str(include_str!(
            "../../../fixtures/app-attest/site-trust-assertion-client-data-v1.json"
        ))
        .unwrap();
        assert_eq!(
            vector.profile,
            "mnemosyne.pistis.site-trust-app-attest-client-data-vector.v1"
        );
        assert_eq!(
            vector.purpose,
            "non-production deterministic client-data known-answer vector"
        );
        let challenge: [u8; 32] = URL_SAFE_NO_PAD
            .decode(vector.challenge_digest_b64url)
            .unwrap()
            .try_into()
            .unwrap();
        let client_data = assertion_client_data_v1(&challenge);
        assert_eq!(
            URL_SAFE_NO_PAD.encode(&client_data),
            vector.client_data_b64url
        );
        assert_eq!(
            URL_SAFE_NO_PAD.encode(Sha256::digest(client_data)),
            vector.client_data_sha256_b64url
        );
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
    fn verifies_ios26_legacy_assertion_and_issues_atomically() {
        let signing_key = SigningKey::from_bytes((&[6; 32]).into()).unwrap();
        let acceptance = acceptance(&signing_key, 0);
        let assertion = legacy_assertion(&signing_key, &acceptance.request, 1);
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
        assert_eq!(outcome.vector().counter().get(), 1);
    }

    #[test]
    fn custody_rotation_accepts_exact_ios26_legacy_assertion() {
        let signing_key = SigningKey::from_bytes((&[3; 32]).into()).unwrap();
        let acceptance = custody_acceptance(&signing_key, 0);
        let assertion = custody_assertion(&signing_key, &acceptance, legacy_authenticator_data(1));
        let submission = mobile_submission(acceptance.request.ceremony_id, assertion);

        let outcome = verify_custody_rotation_app_attest_assertion_diagnostic_v1(
            &acceptance,
            &submission,
            150,
        )
        .unwrap();

        assert_eq!(outcome.counter().get(), 1);
    }

    #[test]
    fn custody_rotation_accepts_all_contract_flag_and_shape_vectors() {
        let signing_key = SigningKey::from_bytes((&[7; 32]).into()).unwrap();
        let acceptance = custody_acceptance(&signing_key, 0);
        let rp_hash =
            Sha256::digest(MONAS_PRODUCTION_APP_ATTEST_APP_IDENTIFIER_V1.as_bytes()).to_vec();

        for (flags, extensions) in [
            (0x00, None),
            (USER_PRESENT_FLAG, None),
            (ATTESTED_CREDENTIAL_DATA_FLAG, None),
            (ATTESTED_CREDENTIAL_DATA_FLAG | USER_PRESENT_FLAG, None),
            (EXTENSION_DATA_FLAG, Some(cbor_extensions("1.0.0", 4))),
            (
                EXTENSION_DATA_FLAG | USER_PRESENT_FLAG,
                Some(cbor_extensions("1.0.0", 4)),
            ),
            (
                EXTENSION_DATA_FLAG | ATTESTED_CREDENTIAL_DATA_FLAG,
                Some(cbor_extensions("1.0.0", 4)),
            ),
            (
                EXTENSION_DATA_FLAG | ATTESTED_CREDENTIAL_DATA_FLAG | USER_PRESENT_FLAG,
                Some(cbor_extensions("1.0.0", 4)),
            ),
        ] {
            let mut auth_data = rp_hash.clone();
            auth_data.push(flags);
            auth_data.extend_from_slice(&1_u32.to_be_bytes());
            if let Some(extensions) = extensions {
                auth_data.extend_from_slice(&extensions);
            }
            let assertion = custody_assertion(&signing_key, &acceptance, auth_data);
            let submission = mobile_submission(acceptance.request.ceremony_id, assertion);
            assert!(
                verify_custody_rotation_app_attest_assertion_diagnostic_v1(
                    &acceptance,
                    &submission,
                    150,
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn custody_rotation_reports_redacted_authenticator_failure_stages() {
        let signing_key = SigningKey::from_bytes((&[6; 32]).into()).unwrap();
        let acceptance = custody_acceptance(&signing_key, 0);

        let mut wrong_rp = legacy_authenticator_data(1);
        wrong_rp[0] ^= 1;
        let mut wrong_flags = legacy_authenticator_data(1);
        wrong_flags[32] = 0x02;
        let mut malformed_extensions =
            Sha256::digest(MONAS_PRODUCTION_APP_ATTEST_APP_IDENTIFIER_V1.as_bytes()).to_vec();
        malformed_extensions.push(EXTENSION_DATA_FLAG);
        malformed_extensions.extend_from_slice(&1_u32.to_be_bytes());
        malformed_extensions.extend_from_slice(&cbor_extensions("1.0.0", 4));
        malformed_extensions.push(0x00);
        let mut wrong_category =
            Sha256::digest(MONAS_PRODUCTION_APP_ATTEST_APP_IDENTIFIER_V1.as_bytes()).to_vec();
        wrong_category.push(EXTENSION_DATA_FLAG);
        wrong_category.extend_from_slice(&1_u32.to_be_bytes());
        wrong_category.extend_from_slice(&cbor_extensions("1.0.0", 1));
        let mut wrong_bundle =
            Sha256::digest(MONAS_PRODUCTION_APP_ATTEST_APP_IDENTIFIER_V1.as_bytes()).to_vec();
        wrong_bundle.push(EXTENSION_DATA_FLAG);
        wrong_bundle.extend_from_slice(&1_u32.to_be_bytes());
        wrong_bundle.extend_from_slice(&cbor_extensions("2.0.0", 4));

        for (auth_data, expected) in [
            (
                vec![0; 36],
                CustodyRotationAppAttestFailureStageV1::AuthenticatorDataLength { actual: 36 },
            ),
            (wrong_rp, CustodyRotationAppAttestFailureStageV1::RpIdHash),
            (
                wrong_flags,
                CustodyRotationAppAttestFailureStageV1::AuthenticatorFlags {
                    actual: 0x02,
                    length: 37,
                },
            ),
            (
                malformed_extensions,
                CustodyRotationAppAttestFailureStageV1::AppleExtensionCbor,
            ),
            (
                wrong_category,
                CustodyRotationAppAttestFailureStageV1::AppleValidationCategory,
            ),
            (
                wrong_bundle,
                CustodyRotationAppAttestFailureStageV1::AppleBundleVersion,
            ),
        ] {
            let assertion = custody_assertion(&signing_key, &acceptance, auth_data);
            let submission = mobile_submission(acceptance.request.ceremony_id, assertion);
            assert_eq!(
                verify_custody_rotation_app_attest_assertion_diagnostic_v1(
                    &acceptance,
                    &submission,
                    150,
                ),
                Err(expected)
            );
        }
    }

    #[test]
    fn ios26_legacy_form_rejects_wrong_rp_hash_counter_and_signature() {
        let signing_key = SigningKey::from_bytes((&[5; 32]).into()).unwrap();
        let acceptance = acceptance(&signing_key, 1);
        let mut store = AtomicStore::default();

        let mut wrong_rp = legacy_authenticator_data(2);
        wrong_rp[0] ^= 1;
        let assertion =
            assertion_for_authenticator_data(&signing_key, &acceptance.request, wrong_rp);
        let submission = mobile_submission(acceptance.request.ceremony_id, assertion);
        assert!(
            issue_site_trust_human_authority_fact_from_server_held_app_attest_assertion_v1(
                &mut store,
                &acceptance,
                &submission
            )
            .is_err()
        );

        let assertion = legacy_assertion(&signing_key, &acceptance.request, 1);
        let submission = mobile_submission(acceptance.request.ceremony_id, assertion);
        assert!(
            issue_site_trust_human_authority_fact_from_server_held_app_attest_assertion_v1(
                &mut store,
                &acceptance,
                &submission
            )
            .is_err()
        );

        let assertion = legacy_assertion(&signing_key, &acceptance.request, 2);
        let decoded = decode_assertion_object(&assertion).unwrap();
        let mut signature = decoded.signature;
        let last = signature.len() - 1;
        signature[last] ^= 1;
        let assertion = cbor_map_bytes(&[
            ("signature", signature.as_slice()),
            ("authenticatorData", decoded.authenticator_data.as_slice()),
        ]);
        let submission = mobile_submission(acceptance.request.ceremony_id, assertion);
        assert!(
            issue_site_trust_human_authority_fact_from_server_held_app_attest_assertion_v1(
                &mut store,
                &acceptance,
                &submission
            )
            .is_err()
        );
        assert_eq!(store.calls, 0);
    }

    #[test]
    fn denies_mixed_or_malformed_ios26_and_ios27_authenticator_forms() {
        let signing_key = SigningKey::from_bytes((&[4; 32]).into()).unwrap();
        let acceptance = acceptance(&signing_key, 0);
        let mut store = AtomicStore::default();

        let mut legacy_with_extension_flag = legacy_authenticator_data(1);
        legacy_with_extension_flag[32] = EXTENSION_DATA_FLAG;
        let mut legacy_with_reserved_flag = legacy_authenticator_data(1);
        legacy_with_reserved_flag[32] = 0x02;
        let mut legacy_with_trailing_data = legacy_authenticator_data(1);
        legacy_with_trailing_data.push(0xa0);
        let mut extended_without_extension_flag = authenticator_data(&acceptance.request, 1);
        extended_without_extension_flag[32] = 0x00;
        let mut extended_with_unknown_field = authenticator_data(&acceptance.request, 1);
        extended_with_unknown_field.push(0x00);
        let mut extended_with_reserved_flag = authenticator_data(&acceptance.request, 1);
        extended_with_reserved_flag[32] |= 0x02;
        let mut extended_with_wrong_bundle =
            Sha256::digest(MONAS_PRODUCTION_APP_ATTEST_APP_IDENTIFIER_V1.as_bytes()).to_vec();
        extended_with_wrong_bundle.push(EXTENSION_DATA_FLAG);
        extended_with_wrong_bundle.extend_from_slice(&1_u32.to_be_bytes());
        extended_with_wrong_bundle.extend_from_slice(&cbor_extensions("2.0.0", 4));

        for auth_data in [
            legacy_with_extension_flag,
            legacy_with_reserved_flag,
            legacy_with_trailing_data,
            extended_without_extension_flag,
            extended_with_reserved_flag,
            extended_with_unknown_field,
            extended_with_wrong_bundle,
        ] {
            let assertion =
                assertion_for_authenticator_data(&signing_key, &acceptance.request, auth_data);
            let submission = mobile_submission(acceptance.request.ceremony_id, assertion);
            assert!(
                issue_site_trust_human_authority_fact_from_server_held_app_attest_assertion_v1(
                    &mut store,
                    &acceptance,
                    &submission
                )
                .is_err()
            );
        }
        assert_eq!(store.calls, 0);
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
