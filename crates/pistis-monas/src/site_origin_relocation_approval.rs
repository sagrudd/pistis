//! Typed Pistis approval boundary for one attended Site-origin relocation.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use p256::PublicKey;
use pistis_domain::{InstallationId, KeyId};
use sha2::{Digest as _, Sha256};

use crate::{MonotonicAppAttestCounterV1, SiteTrustFactCeremonyIdV1};

/// Exact Proxenos purpose authorised after Face ID.
pub const PROXENOS_SITE_ORIGIN_RELOCATION_PURPOSE_V1: &str = "proxenos.site-origin-relocation.v1";
/// Exact Pistis audience admitted by the relocation verifier.
pub const PISTIS_SITE_ORIGIN_RELOCATION_AUDIENCE_V1: &str = "pistis:site-origin-relocation:v1";

const PROPOSAL_MAGIC: &[u8; 8] = b"PXSR/v1\0";
const CLIENT_DATA_DOMAIN: &[u8] = b"PISTIS-PXSR-APP-ATTEST/v1\0";
const MAX_PROPOSAL_BYTES: usize = 4096;
const MAX_LABEL_BYTES: usize = 128;
const MAX_ORIGIN_BYTES: usize = 96;

/// Strictly parsed canonical PXSR/v1 proposal displayed and approved by Pistis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SiteOriginRelocationProposalV1 {
    canonical: Vec<u8>,
    digest: [u8; 32],
    site_uuid: [u8; 16],
    site_trust_domain: String,
    source_origin: String,
    target_origin: String,
    authority_generation: String,
    custody_generation: String,
    site_root_generation: String,
    ceremony_id: SiteTrustFactCeremonyIdV1,
    challenge_digest: [u8; 32],
    issued_at: u64,
    expires_at: u64,
}

impl SiteOriginRelocationProposalV1 {
    /// Parses one byte-exact Proxenos PXSR/v1 proposal.
    ///
    /// # Errors
    /// Rejects reordered, missing, trailing, oversized, noncanonical or unsafe fields.
    pub fn parse(canonical: Vec<u8>) -> Result<Self, SiteOriginRelocationApprovalErrorV1> {
        if canonical.len() > MAX_PROPOSAL_BYTES || !canonical.starts_with(PROPOSAL_MAGIC) {
            return Err(SiteOriginRelocationApprovalErrorV1);
        }
        let mut cursor = PROPOSAL_MAGIC.len();
        let mut fields = Vec::with_capacity(20);
        for expected in 1..=20_u8 {
            if canonical.get(cursor).copied() != Some(expected) || cursor + 3 > canonical.len() {
                return Err(SiteOriginRelocationApprovalErrorV1);
            }
            let length = usize::from(u16::from_be_bytes([
                canonical[cursor + 1],
                canonical[cursor + 2],
            ]));
            cursor += 3;
            let end = cursor
                .checked_add(length)
                .filter(|end| *end <= canonical.len())
                .ok_or(SiteOriginRelocationApprovalErrorV1)?;
            fields.push(&canonical[cursor..end]);
            cursor = end;
        }
        if cursor != canonical.len()
            || fields[0] != b"proxenos.site-origin-relocation.v1"
            || fields[1] != PROXENOS_SITE_ORIGIN_RELOCATION_PURPOSE_V1.as_bytes()
            || fields[2] != PISTIS_SITE_ORIGIN_RELOCATION_AUDIENCE_V1.as_bytes()
            || fields[3].len() != 16
            || fields[15].len() != 16
            || fields[16].len() != 32
            || fields[19].len() != 32
        {
            return Err(SiteOriginRelocationApprovalErrorV1);
        }
        let source_origin = canonical_origin(fields[5])?;
        let target_origin = canonical_origin(fields[6])?;
        let target_ip_text = text(fields[14])?;
        let target_ip = target_ip_text
            .parse::<IpAddr>()
            .map_err(|_| SiteOriginRelocationApprovalErrorV1)?;
        let (source_ip, source_port) = origin_ip_and_port(&source_origin)?;
        let (target_origin_ip, target_port) = origin_ip_and_port(&target_origin)?;
        if source_origin == target_origin
            || source_ip == target_origin_ip
            || target_origin_ip != target_ip
            || target_ip.to_string() != target_ip_text
            || source_port != target_port
            || fields[13] != b"service-monas-web"
            || u64_field(fields[7])? == 0
            || u64_field(fields[8])?
                != u64_field(fields[7])?
                    .checked_add(1)
                    .ok_or(SiteOriginRelocationApprovalErrorV1)?
        {
            return Err(SiteOriginRelocationApprovalErrorV1);
        }
        let issued_at = u64_field(fields[17])?;
        let expires_at = u64_field(fields[18])?;
        if issued_at == 0 || expires_at <= issued_at || expires_at - issued_at > 300 {
            return Err(SiteOriginRelocationApprovalErrorV1);
        }
        let site_uuid = fixed(fields[3])?;
        let ceremony_bytes: [u8; 16] = fixed(fields[15])?;
        let challenge_digest: [u8; 32] = fixed(fields[16])?;
        if site_uuid == [0; 16]
            || ceremony_bytes == [0; 16]
            || challenge_digest == [0; 32]
            || fields[19] == [0; 32]
        {
            return Err(SiteOriginRelocationApprovalErrorV1);
        }
        let site_trust_domain = label(fields[4])?;
        let authority_generation = label(fields[9])?;
        let custody_generation = label(fields[10])?;
        let site_root_generation = label(fields[11])?;
        let digest = Sha256::digest(&canonical).into();
        Ok(Self {
            canonical,
            digest,
            site_uuid,
            site_trust_domain,
            source_origin,
            target_origin,
            authority_generation,
            custody_generation,
            site_root_generation,
            ceremony_id: SiteTrustFactCeremonyIdV1::from_bytes(ceremony_bytes),
            challenge_digest,
            issued_at,
            expires_at,
        })
    }

    /// Returns the canonical proposal digest bound into Face ID and App Attest.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
    /// Returns the exact canonical bytes signed by the Site authority key.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
    /// Returns the immutable source HTTPS origin.
    #[must_use]
    pub fn source_origin(&self) -> &str {
        &self.source_origin
    }
    /// Returns the proposed target HTTPS origin.
    #[must_use]
    pub fn target_origin(&self) -> &str {
        &self.target_origin
    }
    /// Returns the Site UUID.
    #[must_use]
    pub const fn site_uuid(&self) -> [u8; 16] {
        self.site_uuid
    }
    /// Returns the Site Trust Domain.
    #[must_use]
    pub fn site_trust_domain(&self) -> &str {
        &self.site_trust_domain
    }
    /// Returns the authority generation.
    #[must_use]
    pub fn authority_generation(&self) -> &str {
        &self.authority_generation
    }
    /// Returns the custody generation.
    #[must_use]
    pub fn custody_generation(&self) -> &str {
        &self.custody_generation
    }
    /// Returns the Site-root generation.
    #[must_use]
    pub fn site_root_generation(&self) -> &str {
        &self.site_root_generation
    }
    /// Returns the ceremony identifier.
    #[must_use]
    pub const fn ceremony_id(&self) -> SiteTrustFactCeremonyIdV1 {
        self.ceremony_id
    }
    /// Returns the server challenge digest.
    #[must_use]
    pub const fn challenge_digest(&self) -> [u8; 32] {
        self.challenge_digest
    }
    /// Returns the proposal issuance time.
    #[must_use]
    pub const fn issued_at_unix_seconds(&self) -> u64 {
        self.issued_at
    }
    /// Returns the proposal expiry time.
    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at
    }
}

/// Server-owned App Attest request derived after Face ID signs the exact PXSR bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SiteOriginRelocationAppAttestRequestV1 {
    pub(crate) installation_id: InstallationId,
    pub(crate) key_id: KeyId,
    pub(crate) proposal: SiteOriginRelocationProposalV1,
    pub(crate) detached_cose_sha256: [u8; 32],
    pub(crate) client_data_hash: [u8; 32],
}

impl SiteOriginRelocationAppAttestRequestV1 {
    /// Constructs the only accepted relocation assertion request.
    ///
    /// # Errors
    /// Rejects zero identities/signatures or a substituted client-data hash.
    pub fn new(
        installation_id: InstallationId,
        key_id: KeyId,
        proposal: SiteOriginRelocationProposalV1,
        detached_cose_sha256: [u8; 32],
        client_data_hash: [u8; 32],
    ) -> Result<Self, SiteOriginRelocationApprovalErrorV1> {
        let request = Self {
            installation_id,
            key_id,
            proposal,
            detached_cose_sha256,
            client_data_hash,
        };
        if request.installation_id.as_bytes() == &[0; 16]
            || request.key_id.as_bytes() == &[0; 32]
            || request.detached_cose_sha256 == [0; 32]
            || site_origin_relocation_client_data_hash_v1(&request) != request.client_data_hash
        {
            return Err(SiteOriginRelocationApprovalErrorV1);
        }
        Ok(request)
    }

    /// Returns the exact approved proposal.
    #[must_use]
    pub const fn proposal(&self) -> &SiteOriginRelocationProposalV1 {
        &self.proposal
    }
    /// Returns the App Attest client-data hash.
    #[must_use]
    pub const fn client_data_hash(&self) -> [u8; 32] {
        self.client_data_hash
    }
    /// Returns the registered App Attest key identifier.
    #[must_use]
    pub const fn key_id(&self) -> KeyId {
        self.key_id
    }
}

/// Computes the single domain-separated App Attest input for relocation.
#[must_use]
pub fn site_origin_relocation_client_data_hash_v1(
    request: &SiteOriginRelocationAppAttestRequestV1,
) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(CLIENT_DATA_DOMAIN);
    bytes.extend_from_slice(request.installation_id.as_bytes());
    bytes.extend_from_slice(request.key_id.as_bytes());
    bytes.extend_from_slice(&request.proposal.digest);
    bytes.extend_from_slice(request.proposal.ceremony_id.as_bytes());
    bytes.extend_from_slice(&request.proposal.challenge_digest);
    bytes.extend_from_slice(&request.detached_cose_sha256);
    Sha256::digest(bytes).into()
}

/// Opaque acceptance reconstructed only from a previously Apple-verified registration.
pub struct SiteOriginRelocationAppAttestAcceptanceV1 {
    pub(crate) request: SiteOriginRelocationAppAttestRequestV1,
    pub(crate) registered_public_key_sec1: [u8; 65],
    pub(crate) previous_counter: u32,
    pub(crate) bundle_version: String,
}

impl SiteOriginRelocationAppAttestAcceptanceV1 {
    pub(crate) fn new(
        request: SiteOriginRelocationAppAttestRequestV1,
        registered_public_key_sec1: [u8; 65],
        previous_counter: u32,
        bundle_version: String,
    ) -> Result<Self, SiteOriginRelocationApprovalErrorV1> {
        let key_digest: [u8; 32] = Sha256::digest(registered_public_key_sec1).into();
        if previous_counter == u32::MAX
            || PublicKey::from_sec1_bytes(&registered_public_key_sec1).is_err()
            || key_digest != *request.key_id.as_bytes()
            || bundle_version.is_empty()
            || bundle_version.len() > 96
            || !bundle_version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        {
            return Err(SiteOriginRelocationApprovalErrorV1);
        }
        Ok(Self {
            request,
            registered_public_key_sec1,
            previous_counter,
            bundle_version,
        })
    }
}

/// Redacted verified relocation fact without assertion, signature or credential bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SiteOriginRelocationAppAttestOutcomeV1 {
    pub(crate) proposal_digest: [u8; 32],
    pub(crate) assertion_sha256: [u8; 32],
    pub(crate) detached_cose_sha256: [u8; 32],
    pub(crate) counter: MonotonicAppAttestCounterV1,
}

impl SiteOriginRelocationAppAttestOutcomeV1 {
    /// Returns the approved canonical proposal digest.
    #[must_use]
    pub const fn proposal_digest(&self) -> [u8; 32] {
        self.proposal_digest
    }
    /// Returns the redacted App Attest assertion digest.
    #[must_use]
    pub const fn assertion_sha256(&self) -> [u8; 32] {
        self.assertion_sha256
    }
    /// Returns the Face-ID-authorised detached COSE envelope digest.
    #[must_use]
    pub const fn site_authority_detached_cose_sha256(&self) -> [u8; 32] {
        self.detached_cose_sha256
    }
    /// Returns the monotonic App Attest counter Monas must atomically consume.
    #[must_use]
    pub const fn counter(&self) -> MonotonicAppAttestCounterV1 {
        self.counter
    }
}

/// Coarse fail-closed relocation approval error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SiteOriginRelocationApprovalErrorV1;
impl fmt::Display for SiteOriginRelocationApprovalErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Site origin relocation approval unavailable")
    }
}
impl std::error::Error for SiteOriginRelocationApprovalErrorV1 {}

fn fixed<const N: usize>(value: &[u8]) -> Result<[u8; N], SiteOriginRelocationApprovalErrorV1> {
    value
        .try_into()
        .map_err(|_| SiteOriginRelocationApprovalErrorV1)
}
fn text(value: &[u8]) -> Result<String, SiteOriginRelocationApprovalErrorV1> {
    let value = std::str::from_utf8(value).map_err(|_| SiteOriginRelocationApprovalErrorV1)?;
    if value.is_empty() || value.len() > MAX_LABEL_BYTES {
        return Err(SiteOriginRelocationApprovalErrorV1);
    }
    Ok(value.to_owned())
}
fn label(value: &[u8]) -> Result<String, SiteOriginRelocationApprovalErrorV1> {
    let value = text(value)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b':' | b'_' | b'-'))
    {
        return Err(SiteOriginRelocationApprovalErrorV1);
    }
    Ok(value)
}
fn u64_field(value: &[u8]) -> Result<u64, SiteOriginRelocationApprovalErrorV1> {
    Ok(u64::from_be_bytes(fixed(value)?))
}
fn canonical_origin(value: &[u8]) -> Result<String, SiteOriginRelocationApprovalErrorV1> {
    let value = text(value)?;
    if value.len() > MAX_ORIGIN_BYTES {
        return Err(SiteOriginRelocationApprovalErrorV1);
    }
    let (ip, port) = origin_ip_and_port(&value)?;
    let canonical = match ip {
        IpAddr::V4(ip) => format!("https://{ip}:{port}/"),
        IpAddr::V6(ip) => format!("https://[{ip}]:{port}/"),
    };
    if canonical != value {
        return Err(SiteOriginRelocationApprovalErrorV1);
    }
    Ok(value)
}
fn origin_ip_and_port(value: &str) -> Result<(IpAddr, u16), SiteOriginRelocationApprovalErrorV1> {
    let authority = value
        .strip_prefix("https://")
        .and_then(|v| v.strip_suffix('/'))
        .ok_or(SiteOriginRelocationApprovalErrorV1)?;
    if authority.contains(['@', '/', '?', '#']) {
        return Err(SiteOriginRelocationApprovalErrorV1);
    }
    let (ip, port_text) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, port) = rest
            .split_once("]:")
            .ok_or(SiteOriginRelocationApprovalErrorV1)?;
        let ip = host
            .parse::<Ipv6Addr>()
            .map_err(|_| SiteOriginRelocationApprovalErrorV1)?;
        (IpAddr::V6(ip), port)
    } else {
        let (host, port) = authority
            .rsplit_once(':')
            .ok_or(SiteOriginRelocationApprovalErrorV1)?;
        let ip = host
            .parse::<Ipv4Addr>()
            .map_err(|_| SiteOriginRelocationApprovalErrorV1)?;
        (IpAddr::V4(ip), port)
    };
    let port = port_text
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or(SiteOriginRelocationApprovalErrorV1)?;
    if port.to_string() != port_text {
        return Err(SiteOriginRelocationApprovalErrorV1);
    }
    let eligible = match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_broadcast()
                && !ip.is_unspecified()
                && !ip.is_multicast()
        }
        IpAddr::V6(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && !ip.is_unicast_link_local()
                && (ip.segments()[0] & 0xfe00) == 0xfc00
        }
    };
    if !eligible {
        return Err(SiteOriginRelocationApprovalErrorV1);
    }
    Ok((ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proposal() -> Vec<u8> {
        let fields: Vec<Vec<u8>> = vec![
            b"proxenos.site-origin-relocation.v1".to_vec(),
            PROXENOS_SITE_ORIGIN_RELOCATION_PURPOSE_V1
                .as_bytes()
                .to_vec(),
            PISTIS_SITE_ORIGIN_RELOCATION_AUDIENCE_V1
                .as_bytes()
                .to_vec(),
            vec![1; 16],
            b"site-1".to_vec(),
            b"https://192.168.1.192:8443/".to_vec(),
            b"https://192.168.0.193:8443/".to_vec(),
            1_u64.to_be_bytes().to_vec(),
            2_u64.to_be_bytes().to_vec(),
            b"authority-1".to_vec(),
            b"custody-1".to_vec(),
            b"root-1".to_vec(),
            b"issuer-1".to_vec(),
            b"service-monas-web".to_vec(),
            b"192.168.0.193".to_vec(),
            vec![2; 16],
            vec![3; 32],
            1000_u64.to_be_bytes().to_vec(),
            1300_u64.to_be_bytes().to_vec(),
            vec![4; 32],
        ];
        let mut out = PROPOSAL_MAGIC.to_vec();
        for (index, field) in fields.iter().enumerate() {
            out.push(u8::try_from(index + 1).unwrap());
            out.extend_from_slice(&u16::try_from(field.len()).unwrap().to_be_bytes());
            out.extend_from_slice(field);
        }
        out
    }

    #[test]
    fn exact_pxsr_parser_binds_every_approval_field() {
        let value = SiteOriginRelocationProposalV1::parse(proposal()).unwrap();
        assert_eq!(value.source_origin(), "https://192.168.1.192:8443/");
        assert_eq!(value.target_origin(), "https://192.168.0.193:8443/");
        assert_eq!(value.authority_generation(), "authority-1");
        assert_eq!(value.custody_generation(), "custody-1");
        assert_eq!(value.site_root_generation(), "root-1");
        let expected: [u8; 32] = Sha256::digest(value.canonical_bytes()).into();
        assert_eq!(value.digest(), expected);
    }

    #[test]
    fn parser_rejects_reordered_trailing_and_substituted_contracts() {
        let mut trailing = proposal();
        trailing.push(0);
        assert!(SiteOriginRelocationProposalV1::parse(trailing).is_err());
        let mut reordered = proposal();
        reordered[8] = 2;
        assert!(SiteOriginRelocationProposalV1::parse(reordered).is_err());
        let mut substituted = proposal();
        let position = substituted
            .windows(13)
            .position(|v| v == b"192.168.0.193")
            .unwrap();
        substituted[position..position + 13].copy_from_slice(b"192.168.0.194");
        assert!(SiteOriginRelocationProposalV1::parse(substituted).is_err());
    }
}
