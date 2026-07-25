use core::fmt;

/// Independently enabled Monas delivery profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryProfile {
    /// Typed integration boundary without a host adapter.
    Contract,
    /// Deterministic non-production demonstration.
    Reference,
    /// Durable production service integrated with Monas.
    Standalone,
    /// Network-free verification of detached public evidence.
    OfflineVerifier,
}

/// One independently reviewable standalone-readiness requirement.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ReadinessRequirement {
    /// The accepted COSE profile and shared fixtures pass.
    CoseProfileAndFixtures,
    /// Required `SQLite` repositories and migrations are durable.
    DurableSqliteRepositories,
    /// The installation signs the exact persisted canonical challenge.
    PersistedChallengeSignature,
    /// The resolver proves every binding and effective revocation state.
    CompleteBindingResolution,
    /// Completion, session request, and audit append are one transaction.
    AtomicHostCompletion,
    /// The opaque host session uses only a protected server cookie.
    ProtectedServerCookie,
    /// Every required session-invalidation path is tested.
    SessionInvalidation,
    /// Backup, restore, migration, permission, and corruption evidence passes.
    OperationalStateSafety,
    /// Pinned Jenkins evidence proves tests, docs, packages, and provenance.
    PinnedJenkinsEvidence,
}

const REQUIREMENTS: [ReadinessRequirement; 9] = [
    ReadinessRequirement::CoseProfileAndFixtures,
    ReadinessRequirement::DurableSqliteRepositories,
    ReadinessRequirement::PersistedChallengeSignature,
    ReadinessRequirement::CompleteBindingResolution,
    ReadinessRequirement::AtomicHostCompletion,
    ReadinessRequirement::ProtectedServerCookie,
    ReadinessRequirement::SessionInvalidation,
    ReadinessRequirement::OperationalStateSafety,
    ReadinessRequirement::PinnedJenkinsEvidence,
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

/// Explicit evidence evaluated before a standalone session request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StandaloneReadiness {
    evidence: [(ReadinessRequirement, ProductionEvidence); 9],
}

impl StandaloneReadiness {
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
                (REQUIREMENTS[7], ProductionEvidence::Unknown),
                (REQUIREMENTS[8], ProductionEvidence::Unknown),
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

    /// Returns every blocker in deterministic normative order.
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

impl Default for StandaloneReadiness {
    fn default() -> Self {
        Self::unknown()
    }
}

/// Typed reason that a production session request must not proceed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegrationBlocker {
    /// The selected profile is not the standalone production profile.
    WrongProfile(DeliveryProfile),
    /// Required production evidence is absent or unknown.
    Readiness {
        /// Blocked requirement.
        requirement: ReadinessRequirement,
        /// Evidence state observed by the host.
        evidence: ProductionEvidence,
    },
    /// Authoritative binding resolution rejected completion.
    Binding(crate::BindingFailure),
}

impl fmt::Display for IntegrationBlocker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongProfile(profile) => {
                write!(formatter, "session request blocked for {profile:?} profile")
            }
            Self::Readiness {
                requirement,
                evidence,
            } => write!(
                formatter,
                "standalone readiness blocked: {requirement:?} is {evidence:?}"
            ),
            Self::Binding(failure) => write!(formatter, "binding rejected: {failure:?}"),
        }
    }
}

impl std::error::Error for IntegrationBlocker {}
