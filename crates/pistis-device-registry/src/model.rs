use pistis_crypto::{PublicKey, SignatureSuite, derive_key_id};
use pistis_domain::{DeviceId, EvidenceId, ExternalIdentityId, InstallationId, KeyId, UserId};
use pistis_protocol::UnixTimeMillis;
use std::{error::Error, fmt};

const MAX_APPLICATION_VERSION_BYTES: usize = 128;
const MAX_REASON_BYTES: usize = 512;

/// A validated, canonical public verification key.
///
/// Only compressed SEC1 P-256 material is retained. Construction validates the
/// curve point and derives the key identifier from its canonical bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct DevicePublicKey {
    key_id: KeyId,
    canonical_sec1: [u8; 33],
}

impl fmt::Debug for DevicePublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DevicePublicKey")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl DevicePublicKey {
    /// Validates SEC1 P-256 material and stores its canonical compressed form.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidDevicePublicKey`] for malformed, unsupported, or
    /// non-curve material.
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, InvalidDevicePublicKey> {
        let public_key = PublicKey::from_sec1_bytes(bytes).map_err(|_| InvalidDevicePublicKey)?;
        Ok(Self {
            key_id: derive_key_id(&public_key),
            canonical_sec1: public_key.canonical_bytes(),
        })
    }

    /// Rehydrates persisted public material and verifies its persisted ID.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidDevicePublicKey`] when either the material is invalid
    /// or `key_id` is not its derived Pistis identifier.
    pub fn from_persisted(
        key_id: KeyId,
        canonical_sec1: &[u8],
    ) -> Result<Self, InvalidDevicePublicKey> {
        let key = Self::from_sec1_bytes(canonical_sec1)?;
        if key.key_id != key_id || key.canonical_sec1.as_slice() != canonical_sec1 {
            return Err(InvalidDevicePublicKey);
        }
        Ok(key)
    }

    /// Returns the identifier derived from the canonical public key.
    #[must_use]
    pub const fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// Returns the only signature suite accepted by this key representation.
    #[must_use]
    pub const fn algorithm(&self) -> SignatureSuite {
        SignatureSuite::Es256
    }

    /// Returns the canonical compressed SEC1 encoding.
    #[must_use]
    pub const fn canonical_sec1(&self) -> &[u8; 33] {
        &self.canonical_sec1
    }
}

/// A malformed or inconsistent persisted device public key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidDevicePublicKey;

impl fmt::Display for InvalidDevicePublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid device public key")
    }
}

impl Error for InvalidDevicePublicKey {}

/// A bounded application version reported during enrolment.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ApplicationVersion(String);

impl ApplicationVersion {
    /// Validates an application version.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidApplicationVersion`] when the value is empty, padded
    /// with whitespace, contains control characters, or exceeds 128 bytes.
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidApplicationVersion> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_APPLICATION_VERSION_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(InvalidApplicationVersion);
        }
        Ok(Self(value))
    }

    /// Returns the validated application version text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An invalid application version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidApplicationVersion;

impl fmt::Display for InvalidApplicationVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid application version")
    }
}

impl Error for InvalidApplicationVersion {}

/// Device platform recorded during enrolment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DevicePlatform {
    /// Apple iOS or iPadOS.
    Ios,
    /// Google Android.
    Android,
}

/// Strength of an assurance claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssuranceState {
    /// Evidence was cryptographically or otherwise independently verified.
    Verified,
    /// The application reported the property without verifiable evidence.
    Reported,
    /// The platform could not provide the signal.
    Unavailable,
    /// The property was not established.
    Unknown,
}

/// State of an optional platform attestation signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttestationState {
    /// The attestation or integrity evidence was verified.
    Verified,
    /// The platform could not provide the evidence.
    Unavailable,
    /// The enrolment did not request this evidence.
    NotRequested,
}

/// User-presence or local-authentication requirement used for the device key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserVerification {
    /// Biometric or device-credential authorization was required.
    Required,
    /// Local user verification was explicitly not required.
    NotRequired,
    /// The requirement was not established.
    Unknown,
}

/// Assurance claims retained from the enrolment ceremony.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssuranceMetadata {
    /// Whether the Pistis application generated the key.
    pub application_generated_key: bool,
    /// Evidence for hardware-backed key storage.
    pub hardware_backing: AssuranceState,
    /// Local authorization required for key use.
    pub user_verification: UserVerification,
    /// Platform attestation result.
    pub platform_attestation: AttestationState,
    /// Device-integrity result.
    pub device_integrity: AttestationState,
    /// Version of the evidence format.
    pub evidence_version: ApplicationVersion,
    /// Version of the verifier policy.
    pub verifier_version: ApplicationVersion,
}

/// A bounded administrative lifecycle reason.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LifecycleReason(String);

impl LifecycleReason {
    /// Validates a lifecycle reason.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidLifecycleReason`] when the reason is empty, padded,
    /// contains control characters, or exceeds 512 bytes.
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidLifecycleReason> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_REASON_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(InvalidLifecycleReason);
        }
        Ok(Self(value))
    }

    /// Returns the validated reason text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An invalid lifecycle reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidLifecycleReason;

impl fmt::Display for InvalidLifecycleReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid device lifecycle reason")
    }
}

impl Error for InvalidLifecycleReason {}

/// Current authoritative device lifecycle state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeviceStatus {
    /// The device may be considered for authentication.
    Active,
    /// The device is temporarily unable to authenticate.
    Suspended {
        /// Time at which suspension became effective.
        at: UnixTimeMillis,
        /// Administrative suspension reason.
        reason: LifecycleReason,
    },
    /// The device is permanently unable to authenticate.
    Revoked {
        /// Time at which revocation became effective.
        at: UnixTimeMillis,
        /// Administrative revocation reason.
        reason: LifecycleReason,
    },
}

/// Optimistic-concurrency revision of a device record.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct DeviceRevision(u64);

impl DeviceRevision {
    /// Constructs a persisted revision.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the persisted integer revision.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    pub(crate) fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }
}

/// Immutable enrolment input for a new device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewDevice {
    /// Stable device identifier.
    pub id: DeviceId,
    /// Installation owning the registry entry.
    pub installation_id: InstallationId,
    /// Local user to which the device is enrolled.
    pub user_id: UserId,
    /// Durable external-identity binding used for enrolment.
    pub external_identity_id: ExternalIdentityId,
    /// Validated public verification key.
    pub public_key: DevicePublicKey,
    /// Device platform.
    pub platform: DevicePlatform,
    /// Enrolled application version.
    pub application_version: ApplicationVersion,
    /// Explicit enrolment assurance claims.
    pub assurance: AssuranceMetadata,
    /// Retained enrolment evidence.
    pub enrolment_evidence_id: EvidenceId,
    /// Time at which enrolment completed.
    pub enrolled_at: UnixTimeMillis,
}

/// Complete current device record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceRecord {
    /// Stable device identifier.
    pub id: DeviceId,
    /// Installation owning the registry entry.
    pub installation_id: InstallationId,
    /// Local user to which the device is enrolled.
    pub user_id: UserId,
    /// Durable external-identity binding used for enrolment.
    pub external_identity_id: ExternalIdentityId,
    /// Validated public verification key.
    pub public_key: DevicePublicKey,
    /// Device platform.
    pub platform: DevicePlatform,
    /// Enrolled application version.
    pub application_version: ApplicationVersion,
    /// Explicit enrolment assurance claims.
    pub assurance: AssuranceMetadata,
    /// Retained enrolment evidence.
    pub enrolment_evidence_id: EvidenceId,
    /// Current authoritative lifecycle state.
    pub status: DeviceStatus,
    /// Time at which enrolment completed.
    pub enrolled_at: UnixTimeMillis,
    /// Time of the most recent successful use.
    pub last_used_at: Option<UnixTimeMillis>,
    /// Optimistic-concurrency revision.
    pub revision: DeviceRevision,
}

impl From<NewDevice> for DeviceRecord {
    fn from(device: NewDevice) -> Self {
        Self {
            id: device.id,
            installation_id: device.installation_id,
            user_id: device.user_id,
            external_identity_id: device.external_identity_id,
            public_key: device.public_key,
            platform: device.platform,
            application_version: device.application_version,
            assurance: device.assurance,
            enrolment_evidence_id: device.enrolment_evidence_id,
            status: DeviceStatus::Active,
            enrolled_at: device.enrolled_at,
            last_used_at: None,
            revision: DeviceRevision::default(),
        }
    }
}

/// Requested constrained lifecycle change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeviceTransition {
    /// Temporarily disable an active device.
    Suspend {
        /// Effective transition time.
        at: UnixTimeMillis,
        /// Administrative reason.
        reason: LifecycleReason,
    },
    /// Restore a suspended device to active use.
    Resume {
        /// Effective transition time.
        at: UnixTimeMillis,
    },
    /// Permanently disable an active or suspended device.
    Revoke {
        /// Effective transition time.
        at: UnixTimeMillis,
        /// Administrative reason.
        reason: LifecycleReason,
    },
}

impl DeviceTransition {
    pub(crate) const fn at(&self) -> UnixTimeMillis {
        match self {
            Self::Suspend { at, .. } | Self::Resume { at } | Self::Revoke { at, .. } => *at,
        }
    }
}

/// Immutable lifecycle event retained for historic interpretation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleEvent {
    /// Device affected by the event.
    pub device_id: DeviceId,
    /// Revision produced by the transition.
    pub revision: DeviceRevision,
    /// Effective transition time.
    pub at: UnixTimeMillis,
    /// Kind and optional reason of the event.
    pub kind: LifecycleEventKind,
}

/// Kind of retained lifecycle event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleEventKind {
    /// Device was suspended.
    Suspended(LifecycleReason),
    /// Device was resumed.
    Resumed,
    /// Device was terminally revoked.
    Revoked(LifecycleReason),
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMPRESSED: [u8; 33] = [
        0x03, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
        0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8,
        0x98, 0xc2, 0x96,
    ];
    const UNCOMPRESSED: [u8; 65] = [
        0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
        0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8,
        0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a,
        0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40,
        0x68, 0x37, 0xbf, 0x51, 0xf5,
    ];

    #[test]
    fn public_key_normalizes_encodings_and_derives_one_identifier() {
        let compressed = DevicePublicKey::from_sec1_bytes(&COMPRESSED).expect("compressed key");
        let uncompressed =
            DevicePublicKey::from_sec1_bytes(&UNCOMPRESSED).expect("uncompressed key");

        assert_eq!(compressed, uncompressed);
        assert_eq!(compressed.canonical_sec1(), &COMPRESSED);
        assert_eq!(compressed.algorithm(), SignatureSuite::Es256);
    }

    #[test]
    fn persisted_public_key_requires_canonical_material_and_matching_identifier() {
        let key = DevicePublicKey::from_sec1_bytes(&COMPRESSED).expect("valid key");
        assert_eq!(
            DevicePublicKey::from_persisted(key.key_id(), &COMPRESSED),
            Ok(key.clone())
        );
        assert_eq!(
            DevicePublicKey::from_persisted(KeyId::from_bytes([9; 32]), &COMPRESSED),
            Err(InvalidDevicePublicKey)
        );
        assert_eq!(
            DevicePublicKey::from_persisted(key.key_id(), &UNCOMPRESSED),
            Err(InvalidDevicePublicKey)
        );
    }

    #[test]
    fn rejects_malformed_public_keys_without_parser_detail() {
        for malformed in [&[][..], &[0; 33][..], &[0x04; 33][..]] {
            assert_eq!(
                DevicePublicKey::from_sec1_bytes(malformed),
                Err(InvalidDevicePublicKey)
            );
        }
        assert_eq!(
            DevicePublicKey::from_sec1_bytes(&[])
                .unwrap_err()
                .to_string(),
            "invalid device public key"
        );
    }

    #[test]
    fn application_version_is_nonempty_bounded_and_log_safe() {
        assert_eq!(
            ApplicationVersion::new("1.2.3").expect("valid").as_str(),
            "1.2.3"
        );
        for invalid in [
            String::new(),
            " padded".into(),
            "padded ".into(),
            "line\nbreak".into(),
            "x".repeat(MAX_APPLICATION_VERSION_BYTES + 1),
        ] {
            assert_eq!(
                ApplicationVersion::new(invalid),
                Err(InvalidApplicationVersion)
            );
        }
    }

    #[test]
    fn lifecycle_reason_is_nonempty_bounded_and_log_safe() {
        assert_eq!(
            LifecycleReason::new("device lost").expect("valid").as_str(),
            "device lost"
        );
        for invalid in [
            String::new(),
            " padded".into(),
            "padded ".into(),
            "line\nbreak".into(),
            "x".repeat(MAX_REASON_BYTES + 1),
        ] {
            assert_eq!(LifecycleReason::new(invalid), Err(InvalidLifecycleReason));
        }
    }
}
