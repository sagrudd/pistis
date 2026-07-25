use core::fmt;

/// One independently reviewable production-readiness requirement.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ReadinessRequirement {
    /// Ceremonies use durable, rollback-capable transactions.
    DurableCeremonyTransaction,
    /// An accepted COSE profile and shared positive and negative fixtures pass.
    CoseProfileAndFixtures,
    /// The installation signs the exact persisted canonical challenge.
    PersistedChallengeSignature,
    /// The resolver proves every binding and effective revocation state.
    CompleteBindingResolution,
    /// Completion, pre-auth invalidation, session issuance, and audit are atomic.
    AtomicHostCompletion,
    /// The opaque session is delivered only through a protected server cookie.
    ProtectedServerCookie,
    /// Every required session-invalidation path is tested.
    SessionInvalidation,
}

const REQUIREMENTS: [ReadinessRequirement; 7] = [
    ReadinessRequirement::DurableCeremonyTransaction,
    ReadinessRequirement::CoseProfileAndFixtures,
    ReadinessRequirement::PersistedChallengeSignature,
    ReadinessRequirement::CompleteBindingResolution,
    ReadinessRequirement::AtomicHostCompletion,
    ReadinessRequirement::ProtectedServerCookie,
    ReadinessRequirement::SessionInvalidation,
];

/// Evidence observed for one readiness requirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionEvidence {
    /// Reviewed evidence proves the requirement.
    Verified,
    /// The requirement is known not to be implemented.
    Missing,
    /// The caller did not establish whether the requirement is met.
    Unknown,
}

/// Explicit evidence set evaluated before host session issuance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionReadiness {
    evidence: [(ReadinessRequirement, ProductionEvidence); 7],
}

impl ProductionReadiness {
    /// Creates a readiness set with no inferred evidence.
    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            evidence: [
                (REQUIREMENTS[0], ProductionEvidence::Unknown),
                (REQUIREMENTS[1], ProductionEvidence::Unknown),
                (REQUIREMENTS[2], ProductionEvidence::Unknown),
                (REQUIREMENTS[3], ProductionEvidence::Unknown),
                (REQUIREMENTS[4], ProductionEvidence::Unknown),
                (REQUIREMENTS[5], ProductionEvidence::Unknown),
                (REQUIREMENTS[6], ProductionEvidence::Unknown),
            ],
        }
    }

    /// Records evidence for exactly one requirement.
    #[must_use]
    pub fn with(mut self, requirement: ReadinessRequirement, evidence: ProductionEvidence) -> Self {
        if let Some(entry) = self
            .evidence
            .iter_mut()
            .find(|entry| entry.0 == requirement)
        {
            entry.1 = evidence;
        }
        self
    }

    /// Returns all blockers in a deterministic normative order.
    #[must_use]
    pub fn blockers(&self) -> Vec<IntegrationBlocker> {
        self.evidence
            .iter()
            .filter_map(|(requirement, evidence)| {
                (*evidence != ProductionEvidence::Verified).then_some(
                    IntegrationBlocker::Readiness {
                        requirement: *requirement,
                        evidence: *evidence,
                    },
                )
            })
            .collect()
    }

    /// Fails closed unless every requirement has verified evidence.
    ///
    /// # Errors
    ///
    /// Returns the first blocker in normative order.
    pub fn require_ready(&self) -> Result<(), IntegrationBlocker> {
        self.blockers().into_iter().next().map_or(Ok(()), Err)
    }
}

impl Default for ProductionReadiness {
    fn default() -> Self {
        Self::unknown()
    }
}

/// Typed reason that production completion must not issue a session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegrationBlocker {
    /// Required production evidence is absent or unknown.
    Readiness {
        /// Blocked requirement.
        requirement: ReadinessRequirement,
        /// Evidence state observed by the host.
        evidence: ProductionEvidence,
    },
    /// Authoritative binding resolution rejected the completion.
    Binding(crate::BindingFailure),
}

impl fmt::Display for IntegrationBlocker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Readiness {
                requirement,
                evidence,
            } => {
                write!(
                    formatter,
                    "production readiness blocked: {requirement:?} is {evidence:?}"
                )
            }
            Self::Binding(failure) => write!(formatter, "binding rejected: {failure:?}"),
        }
    }
}

impl std::error::Error for IntegrationBlocker {}
