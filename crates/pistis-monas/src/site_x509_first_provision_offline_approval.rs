//! Pistis response boundary for the accepted ADR-0014 offline carrier.

use std::fmt;

use thesaurophylax_api::site_x509_first_provision_offline_v2::{
    SiteX509FirstProvisionOfflineErrorV2, SiteX509FirstProvisionOfflineResponseV2,
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
    use serde::Deserialize;
    use thesaurophylax_api::site_x509_first_provision_offline_v2::{
        SiteX509FirstProvisionOfflinePresentationV2,
        site_x509_first_provision_app_attest_client_data_hash_v2,
    };

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
}
