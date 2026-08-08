//! Test-only Site Trust facts for sibling contract tests.

use super::*;

/// Produces a wholly in-process fact fixture.
///
/// It is not a verifier, cannot be exposed by a package, and must never be
/// treated as a physical-iPhone vector.
pub(crate) fn human_authority_fact_v1() -> SiteTrustHumanAuthorityFactV1 {
    human_authority_fact_with_audience_and_purpose_v1("monas-local", "trust-admission")
}

/// Produces a wholly in-process fact fixture for a valid closed Site Trust
/// audience and purpose pair.
///
/// This is test-only and exists to prove product-audience and purpose fencing.
pub(crate) fn human_authority_fact_with_audience_and_purpose_v1(
    audience: &str,
    purpose: &str,
) -> SiteTrustHumanAuthorityFactV1 {
    let fields = [
        PROXENOS_PAYLOAD_PROFILE_V1,
        "1",
        "request-pending",
        "site-00000001",
        "proxenos-local",
        "rev-00000001",
        "machine-000001",
        audience,
        purpose,
        "op-000000000001",
        "20260802T120000Z",
        "20260802T120500Z",
        "intent-000001",
    ];
    let canonical_bytes =
        fields
            .iter()
            .enumerate()
            .fold(Vec::new(), |mut bytes, (index, value)| {
                bytes.push(u8::try_from(index + 1).expect("fixed test tag"));
                bytes.extend_from_slice(
                    &u32::try_from(value.len())
                        .expect("fixed test length")
                        .to_be_bytes(),
                );
                bytes.extend_from_slice(value.as_bytes());
                bytes
            });
    SiteTrustHumanAuthorityFactV1 {
        id: SiteTrustFactIdV1([1; 32]),
        installation_id: InstallationId::from_bytes([2; 16]),
        device_id: DeviceId::from_bytes([3; 16]),
        key_id: KeyId::from_bytes([4; 32]),
        ceremony_id: SiteTrustFactCeremonyIdV1::from_bytes([5; 16]),
        canonical_payload: SiteTrustCanonicalPayloadV1::parse(canonical_bytes)
            .expect("fixed canonical test payload"),
        pistis_intent: SiteTrustPistisIntentV1::parse(format!(
            "{PISTIS_INTENT_PREFIX_V1}intent-000001"
        ))
        .expect("fixed test intent"),
        issued_at: UnixTimeMillis::new(1),
        attestation_digest: [6; 32],
    }
}
