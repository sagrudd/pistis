//! Pistis response boundary for the accepted ADR-0014 offline carrier.

use std::fmt;

use thesaurophylax_api::site_x509_first_provision_offline_v2::{
    SiteX509FirstProvisionOfflineErrorV2, SiteX509FirstProvisionOfflineResponseV2,
};

use crate::{
    MonotonicAppAttestCounterV1, SiteTrustAppAttestAssertionIngressErrorV1,
    site_trust_assertion_ingress::verify_purpose_bound_app_attest_assertion_v2,
};

/// Coarse denial at the Pistis offline-approval boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SiteX509FirstProvisionOfflineApprovalErrorV2;

impl fmt::Display for SiteX509FirstProvisionOfflineApprovalErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Site X.509 first-provision offline approval denied")
    }
}

impl std::error::Error for SiteX509FirstProvisionOfflineApprovalErrorV2 {}

impl From<SiteX509FirstProvisionOfflineErrorV2> for SiteX509FirstProvisionOfflineApprovalErrorV2 {
    fn from(_: SiteX509FirstProvisionOfflineErrorV2) -> Self {
        Self
    }
}

/// Opaque server-held acceptance for the PXAT/v2 assertion only.
///
/// This value can be constructed only from the release-pinned registration
/// factory after it has matched the protected carrier identity to the durable,
/// Apple-verified registration. It contains no browser or session authority.
pub struct SiteX509FirstProvisionOfflineAppAttestAcceptanceV2 {
    pub(crate) expected_client_data_hash: [u8; 32],
    pub(crate) registered_key_id: [u8; 32],
    pub(crate) registered_public_key_sec1: [u8; 65],
    pub(crate) previous_counter: u32,
    pub(crate) bundle_version: String,
}

impl fmt::Debug for SiteX509FirstProvisionOfflineAppAttestAcceptanceV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SiteX509FirstProvisionOfflineAppAttestAcceptanceV2")
            .field("expected_client_data_hash", &"[REDACTED]")
            .field("registered_key_id", &"[REDACTED]")
            .field("previous_counter", &self.previous_counter)
            .finish_non_exhaustive()
    }
}

/// Redacted verification result which Monas must atomically consume.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SiteX509FirstProvisionOfflineAppAttestOutcomeV2 {
    counter: MonotonicAppAttestCounterV1,
    assertion_sha256: [u8; 32],
}

impl SiteX509FirstProvisionOfflineAppAttestOutcomeV2 {
    /// Returns the strictly advanced App Attest counter.
    #[must_use]
    pub const fn counter(&self) -> MonotonicAppAttestCounterV1 {
        self.counter
    }

    /// Returns only the assertion digest for durable audit evidence.
    #[must_use]
    pub const fn assertion_sha256(&self) -> [u8; 32] {
        self.assertion_sha256
    }
}

/// Verifies the App Attest assertion inside an exact decoded PXFP response.
///
/// The acceptance binds the protected PXAT/v2 client-data hash, production
/// application, durable registered key and previous counter. The function
/// returns no raw assertion, key, approval, cookie, session, or authority.
/// Monas must atomically persist the returned counter while consuming the exact
/// one-use transaction before relaying the detached approval to Thesaurophylax.
///
/// # Errors
///
/// Denies a response/hash substitution, stale counter, wrong application,
/// malformed assertion, wrong registered key, or invalid signature.
pub fn verify_site_x509_first_provision_offline_app_attest_assertion_v2(
    acceptance: &SiteX509FirstProvisionOfflineAppAttestAcceptanceV2,
    response: &SiteX509FirstProvisionOfflineResponseV2,
) -> Result<
    SiteX509FirstProvisionOfflineAppAttestOutcomeV2,
    SiteTrustAppAttestAssertionIngressErrorV1,
> {
    if response.app_attest_client_data_hash() != &acceptance.expected_client_data_hash {
        return Err(SiteTrustAppAttestAssertionIngressErrorV1::Denied);
    }
    let (counter, assertion_sha256) = verify_purpose_bound_app_attest_assertion_v2(
        response.app_attest_assertion(),
        acceptance.expected_client_data_hash,
        acceptance.registered_key_id,
        acceptance.registered_public_key_sec1,
        acceptance.previous_counter,
        &acceptance.bundle_version,
    )?;
    Ok(SiteX509FirstProvisionOfflineAppAttestOutcomeV2 {
        counter,
        assertion_sha256,
    })
}

/// Encodes the only Pistis response accepted for one exact live presentation.
///
/// The detached COSE approval must already have been released by the enrolled
/// Site-root key after Face ID. The App Attest assertion must have been created
/// over the client-data hash returned by the shared Thesaurophylax API. This
/// function adds no browser grant, session credential or generic authority.
///
/// # Errors
///
/// Denies stale, malformed, substituted, empty, oversized or non-canonical input.
pub fn encode_site_x509_first_provision_offline_approval_v2(
    canonical_presentation: &[u8],
    detached_cose_sign1: Vec<u8>,
    app_attest_assertion: Vec<u8>,
    observed_at_unix_seconds: u64,
) -> Result<Vec<u8>, SiteX509FirstProvisionOfflineApprovalErrorV2> {
    let response = SiteX509FirstProvisionOfflineResponseV2::new(
        canonical_presentation,
        detached_cose_sign1,
        app_attest_assertion,
        observed_at_unix_seconds,
    )?;
    response
        .encode(canonical_presentation, observed_at_unix_seconds)
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
    use serde::Deserialize;
    use sha2::{Digest as _, Sha256};
    use thesaurophylax_api::site_x509_first_provision_offline_v2::{
        SiteX509FirstProvisionOfflinePresentationV2,
        site_x509_first_provision_app_attest_client_data_hash_v2,
    };

    use super::*;
    use crate::MONAS_PRODUCTION_APP_ATTEST_APP_IDENTIFIER_V1;

    #[derive(Deserialize)]
    struct Fixture {
        schema: String,
        observed_at_unix_seconds: u64,
        approval_hex: String,
        presentation_hex: String,
        pxat_client_data_sha256_hex: String,
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert!(value.len().is_multiple_of(2));
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).expect("fixture hex is ASCII");
                u8::from_str_radix(text, 16).expect("fixture hex is valid")
            })
            .collect()
    }

    fn cbor_text(output: &mut Vec<u8>, value: &str) {
        output.push(0x60 + u8::try_from(value.len()).expect("short test text"));
        output.extend_from_slice(value.as_bytes());
    }

    fn cbor_bytes(output: &mut Vec<u8>, value: &[u8]) {
        if value.len() < 24 {
            output.push(0x40 + u8::try_from(value.len()).expect("short bytes"));
        } else {
            output.extend_from_slice(&[0x58, u8::try_from(value.len()).expect("bounded bytes")]);
        }
        output.extend_from_slice(value);
    }

    fn signed_assertion(
        signing_key: &SigningKey,
        client_data_hash: [u8; 32],
        counter: u32,
    ) -> Vec<u8> {
        let mut authenticator_data =
            Sha256::digest(MONAS_PRODUCTION_APP_ATTEST_APP_IDENTIFIER_V1.as_bytes()).to_vec();
        authenticator_data.push(0);
        authenticator_data.extend_from_slice(&counter.to_be_bytes());
        let nonce =
            Sha256::digest([authenticator_data.as_slice(), client_data_hash.as_slice()].concat());
        let signature: Signature = signing_key.sign(&nonce);
        let mut encoded = vec![0xa2];
        cbor_text(&mut encoded, "signature");
        cbor_bytes(&mut encoded, signature.to_der().as_bytes());
        cbor_text(&mut encoded, "authenticatorData");
        cbor_bytes(&mut encoded, &authenticator_data);
        encoded
    }

    fn response_and_acceptance(
        previous_counter: u32,
    ) -> (
        SiteX509FirstProvisionOfflineResponseV2,
        SiteX509FirstProvisionOfflineAppAttestAcceptanceV2,
    ) {
        let fixture: Fixture = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/protocol-v1/site-x509-first-provision/pxfp-offline-v2-customer-appliance.json"
        )))
        .expect("reviewed fixture parses");
        let presentation = decode_hex(&fixture.presentation_hex);
        let approval = decode_hex(&fixture.approval_hex);
        let client_data_hash = site_x509_first_provision_app_attest_client_data_hash_v2(
            &presentation,
            &approval,
            fixture.observed_at_unix_seconds,
        )
        .expect("fixture transcript");
        let signing_key = SigningKey::from_bytes((&[0x31; 32]).into()).expect("test key");
        let public_key: [u8; 65] = signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .expect("uncompressed P-256 key");
        let response = SiteX509FirstProvisionOfflineResponseV2::new(
            &presentation,
            approval,
            signed_assertion(&signing_key, client_data_hash, 9),
            fixture.observed_at_unix_seconds,
        )
        .expect("exact response");
        let acceptance = SiteX509FirstProvisionOfflineAppAttestAcceptanceV2 {
            expected_client_data_hash: client_data_hash,
            registered_key_id: Sha256::digest(public_key).into(),
            registered_public_key_sec1: public_key,
            previous_counter,
            bundle_version: "1.0.0".into(),
        };
        (response, acceptance)
    }

    #[test]
    fn exact_thesaurophylax_v2_fixture_has_pistis_transcript_parity() {
        let fixture: Fixture = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/protocol-v1/site-x509-first-provision/pxfp-offline-v2-customer-appliance.json"
        )))
        .expect("reviewed fixture parses");
        assert_eq!(fixture.schema, "thesaurophylax.pxfp-offline-v2-fixture.v1");
        let presentation_bytes = decode_hex(&fixture.presentation_hex);
        let presentation = SiteX509FirstProvisionOfflinePresentationV2::decode(
            &presentation_bytes,
            fixture.observed_at_unix_seconds,
        )
        .expect("reviewed presentation is canonical");
        assert_eq!(
            presentation.context().registered_target_kind,
            "customer-appliance"
        );
        let hash = site_x509_first_provision_app_attest_client_data_hash_v2(
            &presentation_bytes,
            &decode_hex(&fixture.approval_hex),
            fixture.observed_at_unix_seconds,
        )
        .expect("reviewed App Attest transcript is canonical");
        assert_eq!(
            hash.as_slice(),
            decode_hex(&fixture.pxat_client_data_sha256_hex)
        );
    }

    #[test]
    fn purpose_bound_verifier_returns_only_redacted_counter_and_digest() {
        let (response, acceptance) = response_and_acceptance(8);
        let outcome = verify_site_x509_first_provision_offline_app_attest_assertion_v2(
            &acceptance,
            &response,
        )
        .expect("exact registered assertion verifies");
        assert_eq!(outcome.counter().get(), 9);
        assert_ne!(outcome.assertion_sha256(), [0; 32]);
    }

    #[test]
    fn purpose_bound_verifier_denies_hash_counter_key_and_bundle_substitution() {
        let (response, acceptance) = response_and_acceptance(9);
        assert!(
            verify_site_x509_first_provision_offline_app_attest_assertion_v2(
                &acceptance,
                &response,
            )
            .is_err()
        );

        let (response, mut acceptance) = response_and_acceptance(8);
        acceptance.expected_client_data_hash[0] ^= 1;
        assert!(
            verify_site_x509_first_provision_offline_app_attest_assertion_v2(
                &acceptance,
                &response,
            )
            .is_err()
        );

        let (response, mut acceptance) = response_and_acceptance(8);
        acceptance.registered_key_id[0] ^= 1;
        assert!(
            verify_site_x509_first_provision_offline_app_attest_assertion_v2(
                &acceptance,
                &response,
            )
            .is_err()
        );

        let (response, mut acceptance) = response_and_acceptance(8);
        acceptance.bundle_version.push('/');
        assert!(
            verify_site_x509_first_provision_offline_app_attest_assertion_v2(
                &acceptance,
                &response,
            )
            .is_err()
        );
    }
}
