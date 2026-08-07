//! Internal construction of Site Trust facts after verifier success.

use super::{
    AttestationVerificationFailureV1, FACT_ID_DOMAIN_V1, SiteTrustAttestationRequestV1,
    SiteTrustFactIdV1, SiteTrustFactIssuanceErrorV1, SiteTrustFactStoreV1,
    SiteTrustHumanAuthorityFactV1, VerifiedIPhoneAppAttestationV1, digest_components,
};

/// Records a fact from an already verified Pistis-owned assertion result.
pub(crate) fn issue_site_trust_human_authority_fact_from_verified_v1(
    store: &mut impl SiteTrustFactStoreV1,
    request: SiteTrustAttestationRequestV1,
    verified_result: VerifiedIPhoneAppAttestationV1,
) -> Result<SiteTrustHumanAuthorityFactV1, SiteTrustFactIssuanceErrorV1> {
    let fact = build_site_trust_human_authority_fact_from_verified_v1(request, verified_result)?;
    store
        .record_verified(fact.clone())
        .map_err(SiteTrustFactIssuanceErrorV1::Store)?;
    Ok(fact)
}

/// Constructs a fact after a sibling Pistis verifier established every binding.
pub(crate) fn build_site_trust_human_authority_fact_from_verified_v1(
    request: SiteTrustAttestationRequestV1,
    verified_result: VerifiedIPhoneAppAttestationV1,
) -> Result<SiteTrustHumanAuthorityFactV1, SiteTrustFactIssuanceErrorV1> {
    if verified_result.device_id != request.device_id || verified_result.key_id != request.key_id {
        return Err(SiteTrustFactIssuanceErrorV1::Attestation(
            AttestationVerificationFailureV1::BindingMismatch,
        ));
    }
    let fact_id = SiteTrustFactIdV1(digest_components(
        FACT_ID_DOMAIN_V1,
        [
            request.installation_id.as_bytes().as_slice(),
            request.device_id.as_bytes().as_slice(),
            request.key_id.as_bytes().as_slice(),
            request.ceremony_id.as_bytes().as_slice(),
            request.canonical_payload.canonical_bytes(),
            request.pistis_intent.as_str().as_bytes(),
            &request.issued_at.get().to_be_bytes(),
            &verified_result.assertion_digest,
        ],
    ));
    Ok(SiteTrustHumanAuthorityFactV1 {
        id: fact_id,
        installation_id: request.installation_id,
        device_id: request.device_id,
        key_id: request.key_id,
        ceremony_id: request.ceremony_id,
        canonical_payload: request.canonical_payload,
        pistis_intent: request.pistis_intent,
        issued_at: request.issued_at,
        attestation_digest: verified_result.assertion_digest,
    })
}
