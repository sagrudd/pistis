//! Narrow, server-owned first-device status App Attest verification.
//!
//! This module does not supply an endpoint, accept a client-selected key, issue
//! a session or consume a nonce. The authority must source every binding from
//! durable state, verify the other required proofs, and atomically consume the
//! one-use nonce with a counter serialized across every App Attest consumer.

use p256::PublicKey;
use sha2::{Digest as _, Sha256};

use crate::{
    MonotonicAppAttestCounterV1, SiteTrustAppAttestAssertionIngressErrorV1,
    SiteTrustAppAttestMobileSubmissionV1, SiteTrustFactCeremonyIdV1,
    site_trust_assertion_ingress::verify_purpose_bound_app_attest_assertion_v2,
};

const DOMAIN: &[u8] = b"mnemosyne.monas.first-device.status.v2\0";

/// Exact server-owned facts for one purpose-separated status proof.
///
/// Receipt and key fields are already-computed digests of the exact verified
/// authority receipt and keys. Correlation is its server-owned domain-separated
/// digest, never a browser-selected identity or raw bearer capability.
#[derive(Clone, Eq, PartialEq)]
pub struct FirstDeviceStatusAppAttestBindingV2 {
    /// Fresh, unpredictable, nonzero one-use server nonce.
    pub nonce: [u8; 32],
    /// Exact phone operation identifier.
    pub operation_id: [u8; 16],
    /// Digest of the server-owned redeemed broker correlation.
    pub correlation_digest: [u8; 32],
    /// Server-owned genesis registration reference.
    pub reference: String,
    /// Exact current authority installation identifier.
    pub installation_id: [u8; 16],
    /// Exact server-owned Site Trust domain.
    pub site_trust_domain: String,
    /// Digest of the attended V4 presentation.
    pub presentation_digest: [u8; 32],
    /// SHA-256 of the exact signed mobile enrolment receipt.
    pub receipt_digest: [u8; 32],
    /// SHA-256 of the independently pinned native TLS SPKI.
    pub tls_spki_digest: [u8; 32],
    /// SHA-256 identifier of the durable Apple-registered public key.
    pub app_attest_key_id: [u8; 32],
    /// SHA-256 of the compressed Site Root public key.
    pub site_root_key_digest: [u8; 32],
    /// SHA-256 of the compressed enrolled-device public key.
    pub device_key_digest: [u8; 32],
    /// Exclusive expiry, in Unix seconds, included in the transcript.
    pub expires_at_unix_seconds: u64,
}

impl core::fmt::Debug for FirstDeviceStatusAppAttestBindingV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("FirstDeviceStatusAppAttestBindingV2")
            .field("binding", &"[REDACTED]")
            .field("expires_at_unix_seconds", &self.expires_at_unix_seconds)
            .finish_non_exhaustive()
    }
}

/// Request whose facts and nonce must be independently loaded from authority state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FirstDeviceStatusAppAttestRequestV2 {
    binding: FirstDeviceStatusAppAttestBindingV2,
    ceremony_id: SiteTrustFactCeremonyIdV1,
    issued_at_unix_seconds: u64,
}

impl FirstDeviceStatusAppAttestRequestV2 {
    /// Construct a request from a server-owned, one-use status challenge.
    ///
    /// # Errors
    /// Rejects zero bindings, malformed identifiers and lifetimes over 60 seconds.
    pub fn from_server_owned_binding(
        binding: FirstDeviceStatusAppAttestBindingV2,
        ceremony_id: SiteTrustFactCeremonyIdV1,
        issued_at_unix_seconds: u64,
    ) -> Result<Self, SiteTrustAppAttestAssertionIngressErrorV1> {
        let request = Self {
            binding,
            ceremony_id,
            issued_at_unix_seconds,
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), SiteTrustAppAttestAssertionIngressErrorV1> {
        let b = &self.binding;
        let valid_identifier = |text: &str, maximum: usize| {
            !text.is_empty()
                && text.len() <= maximum
                && text.bytes().all(|value| {
                    value.is_ascii_alphanumeric() || matches!(value, b'.' | b'_' | b':' | b'-')
                })
        };
        let valid_lifetime = b
            .expires_at_unix_seconds
            .checked_sub(self.issued_at_unix_seconds)
            .is_some_and(|lifetime| (1..=60).contains(&lifetime));
        if !valid_identifier(&b.reference, 128)
            || !valid_identifier(&b.site_trust_domain, 255)
            || b.nonce == [0; 32]
            || b.operation_id == [0; 16]
            || b.installation_id == [0; 16]
            || self.ceremony_id.as_bytes() == &[0; 16]
            || [
                b.correlation_digest,
                b.presentation_digest,
                b.receipt_digest,
                b.tls_spki_digest,
                b.app_attest_key_id,
                b.site_root_key_digest,
                b.device_key_digest,
            ]
            .contains(&[0; 32])
            || !valid_lifetime
        {
            return Err(SiteTrustAppAttestAssertionIngressErrorV1::Denied);
        }
        Ok(())
    }
}

/// Compute the reviewed 399-byte-preimage status client-data hash.
#[must_use]
pub fn first_device_status_client_data_hash_v2(
    binding: &FirstDeviceStatusAppAttestBindingV2,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(binding.nonce);
    hash.update(binding.operation_id);
    hash.update(binding.correlation_digest);
    hash.update(Sha256::digest(binding.reference.as_bytes()));
    hash.update(binding.installation_id);
    hash.update(Sha256::digest(binding.site_trust_domain.as_bytes()));
    hash.update(binding.presentation_digest);
    hash.update(binding.receipt_digest);
    hash.update(binding.tls_spki_digest);
    hash.update(binding.app_attest_key_id);
    hash.update(binding.site_root_key_digest);
    hash.update(binding.device_key_digest);
    hash.update(binding.expires_at_unix_seconds.to_be_bytes());
    hash.finalize().into()
}

/// Opaque acceptance built only by the reviewed durable-registration factory.
pub struct FirstDeviceStatusAppAttestAcceptanceV2 {
    pub(crate) request: FirstDeviceStatusAppAttestRequestV2,
    pub(crate) registered_public_key_sec1: [u8; 65],
    pub(crate) previous_counter: u32,
    pub(crate) bundle_version: String,
}

impl FirstDeviceStatusAppAttestAcceptanceV2 {
    pub(crate) fn new(
        request: FirstDeviceStatusAppAttestRequestV2,
        key: [u8; 65],
        counter: u32,
        bundle: String,
    ) -> Result<Self, SiteTrustAppAttestAssertionIngressErrorV1> {
        request.validate()?;
        let digest: [u8; 32] = Sha256::digest(key).into();
        if digest != request.binding.app_attest_key_id
            || PublicKey::from_sec1_bytes(&key).is_err()
            || counter == u32::MAX
            || bundle.is_empty()
            || bundle.len() > 96
            || !bundle
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-'))
        {
            return Err(SiteTrustAppAttestAssertionIngressErrorV1::Denied);
        }
        Ok(Self {
            request,
            registered_public_key_sec1: key,
            previous_counter: counter,
            bundle_version: bundle,
        })
    }
}

impl crate::ProductionAppleAppAttestAcceptanceFactoryV1 {
    /// Reconstructs a status-only acceptance from the durable Apple registration.
    ///
    /// The caller must source the request from the exact durable nonce and
    /// authority join. This does not consume that nonce or advance a counter.
    ///
    /// # Errors
    /// Denies a substituted key or manifest, invalid bundle, or exhausted counter.
    pub fn resume_durable_registration_for_first_device_status_v2(
        &self,
        request: FirstDeviceStatusAppAttestRequestV2,
        registered_public_key_sec1: [u8; 65],
        durable_manifest_sha256: [u8; 32],
        expected_bundle_version: &str,
        previous_counter: u32,
    ) -> Result<FirstDeviceStatusAppAttestAcceptanceV2, crate::SiteTrustAppAttestRegistrationErrorV1>
    {
        if durable_manifest_sha256 != self.manifest_digest {
            return Err(crate::SiteTrustAppAttestRegistrationErrorV1::Denied);
        }
        FirstDeviceStatusAppAttestAcceptanceV2::new(
            request,
            registered_public_key_sec1,
            previous_counter,
            expected_bundle_version.to_owned(),
        )
        .map_err(|_| crate::SiteTrustAppAttestRegistrationErrorV1::Denied)
    }
}

/// Redacted assertion result; it does not authorise installation promotion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirstDeviceStatusAppAttestOutcomeV2 {
    counter: MonotonicAppAttestCounterV1,
    assertion_sha256: [u8; 32],
}
impl FirstDeviceStatusAppAttestOutcomeV2 {
    /// Counter that the authority must atomically persist with nonce consumption.
    #[must_use]
    pub const fn counter(&self) -> MonotonicAppAttestCounterV1 {
        self.counter
    }
    /// Digest of the transient assertion, for redacted audit evidence.
    #[must_use]
    pub const fn assertion_sha256(&self) -> [u8; 32] {
        self.assertion_sha256
    }
}

/// Verify only the status-purpose assertion using the existing Apple verifier.
///
/// The caller must verify the other required proofs and atomically consume the
/// nonce and a counter serialized across all consumers; this does not do either.
///
/// # Errors
/// Rejects ceremony/time, key, app, encoding, counter or signature mismatch.
pub fn verify_first_device_status_app_attest_assertion_v2(
    acceptance: &FirstDeviceStatusAppAttestAcceptanceV2,
    submission: &SiteTrustAppAttestMobileSubmissionV1,
    now_unix_seconds: u64,
) -> Result<FirstDeviceStatusAppAttestOutcomeV2, SiteTrustAppAttestAssertionIngressErrorV1> {
    let request = &acceptance.request;
    request.validate()?;
    if submission.ceremony_id() != request.ceremony_id
        || now_unix_seconds < request.issued_at_unix_seconds
        || now_unix_seconds >= request.binding.expires_at_unix_seconds
    {
        return Err(SiteTrustAppAttestAssertionIngressErrorV1::Denied);
    }
    let (counter, assertion_sha256) = verify_purpose_bound_app_attest_assertion_v2(
        submission.assertion_bytes(),
        first_device_status_client_data_hash_v2(&request.binding),
        request.binding.app_attest_key_id,
        acceptance.registered_public_key_sec1,
        acceptance.previous_counter,
        &acceptance.bundle_version,
    )?;
    Ok(FirstDeviceStatusAppAttestOutcomeV2 {
        counter,
        assertion_sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        MONAS_PRODUCTION_APP_ATTEST_APP_IDENTIFIER_V1,
        SITE_TRUST_APP_ATTEST_ASSERTION_INGRESS_PROFILE_V1,
        decode_site_trust_app_attest_mobile_submission_v1,
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};

    fn binding() -> FirstDeviceStatusAppAttestBindingV2 {
        let correlation: Vec<u8> = (32..64).collect();
        let correlation_digest: [u8; 32] = Sha256::digest(
            [
                b"mnemosyne.monas.first-device.correlation.v2\0".as_slice(),
                &correlation,
            ]
            .concat(),
        )
        .into();
        FirstDeviceStatusAppAttestBindingV2 {
            nonce: std::array::from_fn(|i| u8::try_from(i + 96).unwrap()),
            operation_id: std::array::from_fn(|i| u8::try_from(i + 1).unwrap()),
            correlation_digest,
            reference: "genesis-reference-1".into(),
            installation_id: std::array::from_fn(|i| u8::try_from(i + 160).unwrap()),
            site_trust_domain: "site-6073349b-e7f6-420f-ba7c-586b6d9ad78e".into(),
            presentation_digest: std::array::from_fn(|i| u8::try_from(i + 176).unwrap()),
            receipt_digest: std::array::from_fn(|i| u8::try_from(i + 208).unwrap()),
            tls_spki_digest: [0x10; 32],
            app_attest_key_id: [0x11; 32],
            site_root_key_digest: [0x12; 32],
            device_key_digest: [0x13; 32],
            expires_at_unix_seconds: 1_900_000_060,
        }
    }
    fn expected_hash() -> [u8; 32] {
        [
            0xe0, 0x0a, 0xd8, 0x31, 0xca, 0xab, 0x23, 0x41, 0xc8, 0xd2, 0xce, 0xd3, 0x29, 0x15,
            0x57, 0x05, 0x55, 0xbc, 0x33, 0x59, 0xdc, 0x26, 0xf6, 0x03, 0x18, 0x52, 0x7c, 0x58,
            0x8b, 0xef, 0x33, 0x0b,
        ]
    }
    #[test]
    fn matches_shared_status_vector_and_binds_every_fact() {
        let original = binding();
        let expected = first_device_status_client_data_hash_v2(&original);
        assert_eq!(expected, expected_hash());
        let mut changes = Vec::new();
        macro_rules! change {
            ($field:ident, $value:expr) => {{
                let mut b = original.clone();
                b.$field = $value;
                changes.push(b);
            }};
        }
        change!(nonce, [1; 32]);
        change!(operation_id, [2; 16]);
        change!(correlation_digest, [3; 32]);
        change!(reference, "other-reference".into());
        change!(installation_id, [4; 16]);
        change!(site_trust_domain, "other-site".into());
        change!(presentation_digest, [5; 32]);
        change!(receipt_digest, [6; 32]);
        change!(tls_spki_digest, [7; 32]);
        change!(app_attest_key_id, [8; 32]);
        change!(site_root_key_digest, [9; 32]);
        change!(device_key_digest, [10; 32]);
        change!(expires_at_unix_seconds, 1_900_000_059);
        for changed in changes {
            assert_ne!(first_device_status_client_data_hash_v2(&changed), expected);
        }
    }
    #[test]
    fn request_denies_invalid_window_and_redacts_binding() {
        let facts = binding();
        let debug = format!("{facts:?}");
        assert!(!debug.contains("genesis-reference-1"));
        assert!(!debug.contains("site-6073349b"));
        assert!(
            FirstDeviceStatusAppAttestRequestV2::from_server_owned_binding(
                facts.clone(),
                SiteTrustFactCeremonyIdV1::from_bytes([1; 16]),
                1_899_999_999,
            )
            .is_err()
        );
        assert!(
            FirstDeviceStatusAppAttestRequestV2::from_server_owned_binding(
                facts.clone(),
                SiteTrustFactCeremonyIdV1::from_bytes([0; 16]),
                1_900_000_000,
            )
            .is_err()
        );
        let mut zero = facts;
        zero.nonce = [0; 32];
        assert!(
            FirstDeviceStatusAppAttestRequestV2::from_server_owned_binding(
                zero,
                SiteTrustFactCeremonyIdV1::from_bytes([1; 16]),
                1_900_000_000,
            )
            .is_err()
        );
    }

    fn submission(
        key: &SigningKey,
        hash: [u8; 32],
        counter: u32,
        ceremony: [u8; 16],
    ) -> SiteTrustAppAttestMobileSubmissionV1 {
        let mut auth =
            Sha256::digest(MONAS_PRODUCTION_APP_ATTEST_APP_IDENTIFIER_V1.as_bytes()).to_vec();
        auth.push(0);
        auth.extend_from_slice(&counter.to_be_bytes());
        let nonce = Sha256::digest([auth.as_slice(), hash.as_slice()].concat());
        let signature: Signature = key.sign(&nonce);
        let sig = signature.to_der();
        let mut cbor = vec![0xa2, 0x69];
        cbor.extend_from_slice(b"signature");
        cbor.extend_from_slice(&[0x58, u8::try_from(sig.as_bytes().len()).unwrap()]);
        cbor.extend_from_slice(sig.as_bytes());
        cbor.push(0x71);
        cbor.extend_from_slice(b"authenticatorData");
        cbor.extend_from_slice(&[0x58, u8::try_from(auth.len()).unwrap()]);
        cbor.extend_from_slice(&auth);
        let json = serde_json::json!({"profile": SITE_TRUST_APP_ATTEST_ASSERTION_INGRESS_PROFILE_V1,
            "ceremony_id_b64url": URL_SAFE_NO_PAD.encode(ceremony), "assertion_b64url": URL_SAFE_NO_PAD.encode(cbor)});
        decode_site_trust_app_attest_mobile_submission_v1(json.to_string().as_bytes()).unwrap()
    }
    #[test]
    fn verifies_only_exact_status_key_ceremony_time_and_counter() {
        let key = SigningKey::from_bytes((&[0x31; 32]).into()).unwrap();
        let public: [u8; 65] = key
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .try_into()
            .unwrap();
        let mut facts = binding();
        facts.app_attest_key_id = Sha256::digest(public).into();
        let request = FirstDeviceStatusAppAttestRequestV2::from_server_owned_binding(
            facts.clone(),
            SiteTrustFactCeremonyIdV1::from_bytes([0x22; 16]),
            1_900_000_000,
        )
        .unwrap();
        let accepted =
            FirstDeviceStatusAppAttestAcceptanceV2::new(request.clone(), public, 8, "1.0.0".into())
                .unwrap();
        let proof = submission(
            &key,
            first_device_status_client_data_hash_v2(&facts),
            9,
            [0x22; 16],
        );
        assert_eq!(
            verify_first_device_status_app_attest_assertion_v2(&accepted, &proof, 1_900_000_001)
                .unwrap()
                .counter()
                .get(),
            9
        );
        assert!(
            verify_first_device_status_app_attest_assertion_v2(&accepted, &proof, 1_900_000_060)
                .is_err()
        );
        let replay =
            FirstDeviceStatusAppAttestAcceptanceV2::new(request.clone(), public, 9, "1.0.0".into())
                .unwrap();
        assert!(
            verify_first_device_status_app_attest_assertion_v2(&replay, &proof, 1_900_000_001)
                .is_err()
        );
        let wrong = submission(
            &key,
            first_device_status_client_data_hash_v2(&facts),
            9,
            [0x23; 16],
        );
        assert!(
            verify_first_device_status_app_attest_assertion_v2(&accepted, &wrong, 1_900_000_001)
                .is_err()
        );
        let other_key = SigningKey::from_bytes((&[0x32; 32]).into()).unwrap();
        let other_proof = submission(
            &other_key,
            first_device_status_client_data_hash_v2(&facts),
            9,
            [0x22; 16],
        );
        assert!(
            verify_first_device_status_app_attest_assertion_v2(
                &accepted,
                &other_proof,
                1_900_000_001,
            )
            .is_err()
        );
        let other_public: [u8; 65] = other_key
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .try_into()
            .unwrap();
        assert!(
            FirstDeviceStatusAppAttestAcceptanceV2::new(
                request.clone(),
                other_public,
                8,
                "1.0.0".into(),
            )
            .is_err()
        );
        facts.receipt_digest[0] ^= 1;
        let swapped = FirstDeviceStatusAppAttestRequestV2::from_server_owned_binding(
            facts,
            SiteTrustFactCeremonyIdV1::from_bytes([0x22; 16]),
            1_900_000_000,
        )
        .unwrap();
        let swapped =
            FirstDeviceStatusAppAttestAcceptanceV2::new(swapped, public, 8, "1.0.0".into())
                .unwrap();
        assert!(
            verify_first_device_status_app_attest_assertion_v2(&swapped, &proof, 1_900_000_001)
                .is_err()
        );
        assert!(
            FirstDeviceStatusAppAttestAcceptanceV2::new(request, public, u32::MAX, "1.0.0".into())
                .is_err()
        );
    }
}
