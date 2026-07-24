use pistis_crypto::PublicKey;
use pistis_domain::{ChallengeId, DeviceId, ExternalIdentityId, InstallationId, KeyId, UserId};
use std::{error::Error, fmt};

/// Maximum signed response body accepted by the service.
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024;
/// Fixed width of protocol nonces and opaque browser capabilities.
pub const SECRET_BYTES: usize = 32;

macro_rules! secret_type {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Eq, Hash, PartialEq)]
        pub struct $name([u8; SECRET_BYTES]);

        impl $name {
            /// Constructs the value from trusted random bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; SECRET_BYTES]) -> Self {
                Self(bytes)
            }

            /// Returns the opaque bytes for an adapter that must persist them.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; SECRET_BYTES] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

secret_type!(
    LoginHandle,
    "Opaque capability identifying one login ceremony."
);
secret_type!(
    PreAuthSessionId,
    "Opaque identifier for a browser's unauthenticated session."
);
secret_type!(
    AuthenticatedSessionId,
    "Opaque identifier created only after successful authentication."
);

/// Milliseconds since the Unix epoch.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct UnixTimeMillis(pub u64);

/// How a response reached the installation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferMode {
    /// Submitted through a directly reachable local endpoint.
    Direct,
    /// Decoded from the mobile device's response QR.
    ResponseQr,
}

/// Explicit decision signed by the enrolled device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    /// Approve local authentication.
    Approve,
    /// Deny local authentication.
    Deny,
}

/// Closed, authoritative authentication challenge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChallengeDocument {
    /// Issuer-controlled creation time.
    pub issued_at: UnixTimeMillis,
    /// Exclusive expiry.
    pub expires_at: UnixTimeMillis,
    /// Challenge identifier.
    pub challenge_id: ChallengeId,
    /// Installation receiving the response.
    pub installation_id: InstallationId,
    /// Local user selected before login.
    pub user_id: UserId,
    /// Required enrolled external identity.
    pub external_identity_id: ExternalIdentityId,
    /// Installation signing-key identifier.
    pub installation_key_id: KeyId,
    /// Single-use random value.
    pub nonce: [u8; SECRET_BYTES],
    /// Installation-scoped audience.
    pub audience: String,
    /// Human-readable installation name.
    pub installation_name: String,
    /// Human-readable local username.
    pub local_username: String,
    /// Digest of the complete display context.
    pub display_context_digest: [u8; 32],
    /// Installation identity fingerprint.
    pub installation_fingerprint: [u8; 32],
    /// Zero to two HTTPS local endpoint hints.
    pub endpoint_hints: Vec<String>,
}

/// Caller-supplied authoritative context for a new challenge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChallengeContext {
    /// Local user selected before login.
    pub user_id: UserId,
    /// Required enrolled external identity.
    pub external_identity_id: ExternalIdentityId,
    /// Installation signing-key identifier.
    pub installation_key_id: KeyId,
    /// Installation-scoped audience.
    pub audience: String,
    /// Human-readable installation name.
    pub installation_name: String,
    /// Human-readable local username.
    pub local_username: String,
    /// Digest of the complete display context.
    pub display_context_digest: [u8; 32],
    /// Installation identity fingerprint.
    pub installation_fingerprint: [u8; 32],
    /// Zero to two HTTPS local endpoint hints.
    pub endpoint_hints: Vec<String>,
}

/// Bounded canonical response and detached ES256 signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseEnvelope {
    /// Exact canonical bytes covered by the signature.
    pub canonical: Vec<u8>,
    /// Fixed-width COSE `r || s` signature.
    pub signature: Vec<u8>,
}

impl ResponseEnvelope {
    /// Constructs an envelope while enforcing transport-independent limits.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::InvalidResponse`] for an oversized body or a
    /// signature whose width is not 64 bytes.
    pub fn new(canonical: Vec<u8>, signature: Vec<u8>) -> Result<Self, ServiceError> {
        if canonical.is_empty() || canonical.len() > MAX_RESPONSE_BYTES || signature.len() != 64 {
            return Err(ServiceError::InvalidResponse);
        }
        Ok(Self {
            canonical,
            signature,
        })
    }
}

/// Public verification material resolved for an enrolled device.
#[derive(Clone, Debug)]
pub struct DeviceCredential {
    /// Enrolled device.
    pub device_id: DeviceId,
    /// Derived identifier of `public_key`.
    pub key_id: KeyId,
    /// Reviewed ES256 verification key.
    pub public_key: PublicKey,
    /// Only active devices may authenticate.
    pub active: bool,
}

/// Fail-closed enrolled-device lookup boundary.
pub trait DeviceDirectory: Send + Sync {
    /// Resolves a credential, returning no value for unknown devices.
    fn resolve(&self, device_id: DeviceId) -> Option<DeviceCredential>;
}

/// Injectable cryptographically secure random source.
pub trait RandomSource: Send + Sync {
    /// Fills all bytes, or fails closed.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::Unavailable`] when secure randomness cannot be
    /// obtained.
    fn fill(&self, output: &mut [u8]) -> Result<(), ServiceError>;
}

/// Coarse browser-visible terminal failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicFailure {
    /// The signed response was malformed, invalid, or incorrectly bound.
    Rejected,
    /// The enrolled device is unknown or inactive.
    InactiveDevice,
    /// The ceremony expired.
    Expired,
}

/// Poll-safe ceremony status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoginStatus {
    /// Awaiting a response.
    Pending,
    /// A response is available, but no session exists yet.
    ResponseAvailable,
    /// The device signed an explicit denial.
    Denied,
    /// Verification failed closed.
    Failed(PublicFailure),
    /// The browser cancelled the ceremony.
    Cancelled,
    /// The ceremony expired.
    Expired,
    /// An authenticated session was established.
    Completed,
}

/// Result returned exactly once by successful completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Completion {
    /// Rotated authenticated session identifier.
    pub session_id: AuthenticatedSessionId,
    /// Device that approved authentication.
    pub device_id: DeviceId,
    /// Completion time.
    pub completed_at: UnixTimeMillis,
}

/// Retained non-secret audit event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditEvent {
    /// Ceremony capability (opaque and redacted by `Debug`).
    pub login: LoginHandle,
    /// Authenticated local user.
    pub user_id: UserId,
    /// Device that approved authentication.
    pub device_id: DeviceId,
    /// Response transfer mode.
    pub transfer: TransferMode,
    /// Completion time.
    pub at: UnixTimeMillis,
}

/// Authentication service failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceError {
    /// The handle or pre-authentication session does not identify this ceremony.
    NotFound,
    /// The request is invalid for the ceremony's current state.
    Conflict,
    /// The response is malformed or exceeds a bound.
    InvalidResponse,
    /// Secure randomness or synchronized state is unavailable.
    Unavailable,
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotFound => "authentication ceremony not found",
            Self::Conflict => "authentication ceremony state conflict",
            Self::InvalidResponse => "invalid authentication response",
            Self::Unavailable => "authentication service unavailable",
        })
    }
}

impl Error for ServiceError {}
