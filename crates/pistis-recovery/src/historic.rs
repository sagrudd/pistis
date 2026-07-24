use pistis_protocol::UnixTimeMillis;

/// Cryptographic verification result, independent of lifecycle policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptographicResult {
    /// Signature verifies over the exact canonical content.
    Valid,
    /// Signature does not verify.
    Invalid,
}

/// Authority supporting the evaluated signing time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningTimeEvidence {
    /// Independently trusted time.
    Trusted(UnixTimeMillis),
    /// Time bounded to an inclusive interval by authoritative system evidence.
    AuthoritativelyBounded {
        /// Earliest possible signing time.
        earliest: UnixTimeMillis,
        /// Latest possible signing time.
        latest: UnixTimeMillis,
    },
    /// Time asserted only by the signer.
    SignerClaimed(UnixTimeMillis),
}

/// Closed terminal revocation facts retained for historic evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationFact {
    /// Credential is not terminally revoked.
    NotRevoked,
    /// Ordinary retirement became effective at the supplied time.
    Retirement(UnixTimeMillis),
    /// Replacement became effective at the supplied time.
    Replacement(UnixTimeMillis),
    /// Loss became effective at the supplied time.
    Loss(UnixTimeMillis),
    /// Compromise became effective at the supplied time.
    Compromise(UnixTimeMillis),
    /// Administrative or policy revocation became effective.
    Administrative(UnixTimeMillis),
}

impl RevocationFact {
    const fn effective_at(self) -> Option<UnixTimeMillis> {
        match self {
            Self::NotRevoked => None,
            Self::Retirement(time)
            | Self::Replacement(time)
            | Self::Loss(time)
            | Self::Compromise(time)
            | Self::Administrative(time) => Some(time),
        }
    }
}

/// Relying-party treatment of apparently pre-compromise evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompromiseTreatment {
    /// Accept independently timed pre-compromise evidence.
    AcceptBeforeEffectiveTime,
    /// Report it as qualified and require review.
    QualifyBeforeEffectiveTime,
    /// Reject all evidence from the compromised key.
    RejectAll,
}

/// Temporal relation between evidence and revocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TemporalResult {
    /// No terminal revocation is recorded.
    NotRevoked,
    /// Authoritative time places signing before revocation.
    BeforeRevocation,
    /// Authoritative time places signing at or after revocation.
    AtOrAfterRevocation,
    /// Signer-controlled time cannot prove signing preceded revocation.
    IndeterminateClaimedTime,
    /// An authoritative interval overlaps revocation or is malformed.
    IndeterminateAuthoritativeRange,
}

/// Historic relying-party policy result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistoricPolicyResult {
    /// Evidence remains acceptable under historic policy.
    Accept,
    /// Evidence is cryptographically valid but requires review.
    Qualified,
    /// Evidence is rejected.
    Reject,
}

/// Structured historic result preserving cryptographic and lifecycle facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoricClassification {
    /// Independent cryptographic result.
    pub cryptographic: CryptographicResult,
    /// Relation between evaluated signing time and revocation.
    pub temporal: TemporalResult,
    /// Current terminal revocation fact.
    pub revocation: RevocationFact,
    /// Explicit relying-party policy result.
    pub policy: HistoricPolicyResult,
}

/// Classifies historic facts without deleting or rewriting key history.
#[must_use]
pub fn classify_historic(
    cryptographic: CryptographicResult,
    signing_time: SigningTimeEvidence,
    revocation: RevocationFact,
    compromise_treatment: CompromiseTreatment,
) -> HistoricClassification {
    let temporal = temporal_result(signing_time, revocation);
    let policy = if cryptographic == CryptographicResult::Invalid {
        HistoricPolicyResult::Reject
    } else {
        policy_for_valid(temporal, revocation, compromise_treatment)
    };
    HistoricClassification {
        cryptographic,
        temporal,
        revocation,
        policy,
    }
}

fn temporal_result(
    signing_time: SigningTimeEvidence,
    revocation: RevocationFact,
) -> TemporalResult {
    let Some(effective_at) = revocation.effective_at() else {
        return TemporalResult::NotRevoked;
    };
    match signing_time {
        SigningTimeEvidence::Trusted(time) if time < effective_at => {
            TemporalResult::BeforeRevocation
        }
        SigningTimeEvidence::Trusted(_) => TemporalResult::AtOrAfterRevocation,
        SigningTimeEvidence::AuthoritativelyBounded { earliest, latest }
            if earliest <= latest && latest < effective_at =>
        {
            TemporalResult::BeforeRevocation
        }
        SigningTimeEvidence::AuthoritativelyBounded { earliest, latest }
            if earliest <= latest && earliest >= effective_at =>
        {
            TemporalResult::AtOrAfterRevocation
        }
        SigningTimeEvidence::AuthoritativelyBounded { .. } => {
            TemporalResult::IndeterminateAuthoritativeRange
        }
        SigningTimeEvidence::SignerClaimed(_) => TemporalResult::IndeterminateClaimedTime,
    }
}

const fn policy_for_valid(
    temporal: TemporalResult,
    revocation: RevocationFact,
    compromise_treatment: CompromiseTreatment,
) -> HistoricPolicyResult {
    match temporal {
        TemporalResult::NotRevoked | TemporalResult::BeforeRevocation => {
            if matches!(revocation, RevocationFact::Compromise(_)) {
                match compromise_treatment {
                    CompromiseTreatment::AcceptBeforeEffectiveTime => HistoricPolicyResult::Accept,
                    CompromiseTreatment::QualifyBeforeEffectiveTime => {
                        HistoricPolicyResult::Qualified
                    }
                    CompromiseTreatment::RejectAll => HistoricPolicyResult::Reject,
                }
            } else {
                HistoricPolicyResult::Accept
            }
        }
        TemporalResult::AtOrAfterRevocation
        | TemporalResult::IndeterminateClaimedTime
        | TemporalResult::IndeterminateAuthoritativeRange => HistoricPolicyResult::Reject,
    }
}
