/// Exact SHA-256 digest.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Digest([u8; 32]);

impl Digest {
    /// Constructs a digest from already computed bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Reports whether this is the all-zero sentinel, which is never evidence.
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }
}

/// Exact full Git source revision bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Revision([u8; 20]);

impl Revision {
    /// Constructs a full revision from its decoded 40-hex-character value.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    fn is_zero(self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }
}

/// Unique candidate identifier that must not be reused.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CandidateId([u8; 16]);

impl CandidateId {
    /// Constructs an independently allocated candidate identifier.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    fn is_zero(self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }
}

/// Semantic release version.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReleaseVersion {
    /// Major version.
    pub major: u64,
    /// Minor version.
    pub minor: u64,
    /// Patch version.
    pub patch: u64,
}

/// Stable artifact identifier independent of mutable filenames.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ArtifactId([u8; 16]);

impl ArtifactId {
    /// Constructs an artifact identifier.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    fn is_zero(self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }
}

/// Reference to an external protected signing identity, never a credential.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SigningIdentity([u8; 16]);

impl SigningIdentity {
    /// Constructs an opaque signing-identity reference.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    fn is_zero(self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }
}

/// Closed artifact inventory kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactKind {
    /// Rust crate archive.
    RustCrate,
    /// Standalone executable.
    Binary,
    /// Binary RPM.
    Rpm,
    /// Source RPM.
    SourceRpm,
    /// iOS governed archive or store submission.
    IosArchive,
    /// Android governed application bundle.
    AndroidBundle,
    /// Pre-rendered documentation archive.
    Documentation,
    /// Protocol schema or fixture archive.
    ProtocolFixtures,
    /// Release metadata such as checksums or compatibility evidence.
    ReleaseMetadata,
}

/// Publication record for one immutable artifact digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicationState {
    /// Artifact has not been published.
    Unpublished,
    /// Artifact was staged privately.
    Staged {
        /// Immutable repository or store reference.
        reference: String,
        /// Exact artifact digest transferred.
        digest: Digest,
    },
    /// Artifact was published to its final target.
    Published {
        /// Immutable repository or store reference.
        reference: String,
        /// Exact artifact digest transferred.
        digest: Digest,
    },
}

/// One final packaged artifact and its attestations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Artifact {
    /// Stable inventory identifier.
    pub id: ArtifactId,
    /// Closed artifact kind.
    pub kind: ArtifactKind,
    /// Safe basename presented to package consumers.
    pub filename: String,
    /// Exact packaged size in bytes.
    pub size: u64,
    /// SHA-256 of exact packaged bytes.
    pub digest: Digest,
    /// SHA-256 of the reconciled per-artifact SBOM.
    pub sbom_digest: Digest,
    /// SHA-256 of the provenance statement.
    pub provenance_digest: Digest,
    /// Protected signing identity reference.
    pub signing_identity: SigningIdentity,
    /// Current immutable publication state.
    pub publication: PublicationState,
}

/// Reviewable evidence state for one release gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceState {
    /// Reviewed evidence proves the gate for this candidate.
    Verified,
    /// Evidence is known to be absent or failing.
    Missing,
    /// Evidence was not established.
    Unknown,
}

/// Required authenticated approval role.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ApprovalRole {
    /// Product owner.
    Product,
    /// Rust/backend owner.
    Backend,
    /// iOS owner.
    Ios,
    /// Android owner.
    Android,
    /// Synoptikon owner.
    Synoptikon,
    /// Security reviewer.
    Security,
    /// Release manager.
    ReleaseManager,
}

/// Authenticated approval bound to an exact manifest digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Approval {
    /// Required approver role.
    pub role: ApprovalRole,
    /// Exact manifest digest approved.
    pub manifest_digest: Digest,
    /// Authenticated decision time.
    pub approved_at: u64,
    /// Exclusive approval expiry.
    pub expires_at: u64,
}

/// Explicit release workflow phase.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ReleasePhase {
    /// Credential-free candidate assembly.
    Assemble,
    /// Candidate verification.
    Verify,
    /// Protected approval and signing.
    ApproveAndSign,
    /// Least-privileged publication.
    Publish,
}

/// Candidate manifest inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Manifest {
    /// Shared semantic version.
    pub version: ReleaseVersion,
    /// Unique candidate identifier.
    pub candidate_id: CandidateId,
    /// Exact protected-main source revision.
    pub source_revision: Revision,
    /// Digest of exact Jenkins release-pipeline definition.
    pub pipeline_digest: Digest,
    /// Digest of immutable source and dependency inputs.
    pub input_digest: Digest,
    /// Complete artifact inventory.
    pub artifacts: Vec<Artifact>,
    /// Current credential-segregated workflow phase.
    pub phase: ReleasePhase,
}

impl Manifest {
    /// Validates structural integrity without claiming release readiness.
    ///
    /// # Errors
    ///
    /// Rejects sentinel identities, unsafe filenames, empty artifacts,
    /// duplicate identifiers or names, missing attestations, and publication
    /// records that refer to different bytes.
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.version.major == 0 {
            return Err(ManifestError::DevelopmentVersion);
        }
        if self.candidate_id.is_zero() || self.source_revision.is_zero() {
            return Err(ManifestError::SentinelIdentity);
        }
        if self.pipeline_digest.is_zero() || self.input_digest.is_zero() {
            return Err(ManifestError::MissingInputDigest);
        }
        if self.artifacts.is_empty() {
            return Err(ManifestError::EmptyInventory);
        }
        for (index, artifact) in self.artifacts.iter().enumerate() {
            validate_artifact(artifact)?;
            if matches!(artifact.publication, PublicationState::Published { .. })
                && self.phase != ReleasePhase::Publish
            {
                return Err(ManifestError::PrematurePublication);
            }
            if self.artifacts[..index]
                .iter()
                .any(|other| other.id == artifact.id)
            {
                return Err(ManifestError::DuplicateArtifactId);
            }
            if self.artifacts[..index]
                .iter()
                .any(|other| other.filename == artifact.filename)
            {
                return Err(ManifestError::DuplicateFilename);
            }
        }
        Ok(())
    }
}

fn validate_artifact(artifact: &Artifact) -> Result<(), ManifestError> {
    if artifact.id.is_zero() || artifact.signing_identity.is_zero() {
        return Err(ManifestError::SentinelIdentity);
    }
    if artifact.size == 0 {
        return Err(ManifestError::EmptyArtifact);
    }
    if artifact.digest.is_zero()
        || artifact.sbom_digest.is_zero()
        || artifact.provenance_digest.is_zero()
    {
        return Err(ManifestError::MissingAttestation);
    }
    if artifact.filename.is_empty()
        || artifact.filename.len() > 255
        || artifact.filename == "."
        || artifact.filename == ".."
        || artifact
            .filename
            .chars()
            .any(|character| character.is_control() || matches!(character, '/' | '\\'))
    {
        return Err(ManifestError::UnsafeFilename);
    }
    match &artifact.publication {
        PublicationState::Unpublished => {}
        PublicationState::Staged { reference, digest }
        | PublicationState::Published { reference, digest } => {
            if reference.is_empty()
                || reference.len() > 2048
                || reference.chars().any(char::is_control)
                || *digest != artifact.digest
            {
                return Err(ManifestError::InvalidPublication);
            }
        }
    }
    Ok(())
}

/// Structural manifest rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestError {
    /// Version still identifies development output.
    DevelopmentVersion,
    /// Candidate, revision, artifact, or signer uses a sentinel identity.
    SentinelIdentity,
    /// Pipeline or immutable input digest is absent.
    MissingInputDigest,
    /// Artifact inventory is empty.
    EmptyInventory,
    /// Two artifacts share an identifier.
    DuplicateArtifactId,
    /// Two artifacts share a filename.
    DuplicateFilename,
    /// Artifact is empty.
    EmptyArtifact,
    /// Artifact filename can escape or confuse a package boundary.
    UnsafeFilename,
    /// SBOM, provenance, or artifact digest is absent.
    MissingAttestation,
    /// Publication reference is mutable-looking, malformed, or binds other bytes.
    InvalidPublication,
    /// Public release occurred before the publication phase.
    PrematurePublication,
}
