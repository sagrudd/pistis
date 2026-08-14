//! Pistis response boundary for the accepted ADR-0014 offline carrier.

use std::fmt;

use thesaurophylax_api::site_x509_first_provision_offline_v1::{
    SiteX509FirstProvisionOfflineErrorV1, SiteX509FirstProvisionOfflineResponseV1,
};

/// Coarse denial at the Pistis offline-approval boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SiteX509FirstProvisionOfflineApprovalErrorV1;

impl fmt::Display for SiteX509FirstProvisionOfflineApprovalErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Site X.509 first-provision offline approval denied")
    }
}

impl std::error::Error for SiteX509FirstProvisionOfflineApprovalErrorV1 {}

impl From<SiteX509FirstProvisionOfflineErrorV1> for SiteX509FirstProvisionOfflineApprovalErrorV1 {
    fn from(_: SiteX509FirstProvisionOfflineErrorV1) -> Self {
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
pub fn encode_site_x509_first_provision_offline_approval_v1(
    canonical_presentation: &[u8],
    detached_cose_sign1: Vec<u8>,
    app_attest_assertion: Vec<u8>,
    observed_at_unix_seconds: u64,
) -> Result<Vec<u8>, SiteX509FirstProvisionOfflineApprovalErrorV1> {
    let response = SiteX509FirstProvisionOfflineResponseV1::new(
        canonical_presentation,
        detached_cose_sign1,
        app_attest_assertion,
        observed_at_unix_seconds,
    )?;
    response
        .encode(canonical_presentation, observed_at_unix_seconds)
        .map_err(Into::into)
}
