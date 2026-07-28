use crate::AgentReference;
use std::{error::Error, fmt};

const MAX_TRANSFER_BYTES: usize = 2_331;
const MAX_DISPLAY_BYTES: usize = 256;

/// Version of the proposed host-owned local-agent authority port.
pub const HOST_AUTHORITY_PORT_VERSION: u16 = 1;

/// Credential-free challenge projection returned by the host authority.
///
/// The reference is opaque to the agent. None of these fields grants a
/// Prosopikon, Monas, Jenkins, or product session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostChallengeProjection {
    reference: AgentReference,
    challenge_transfer: String,
    installation_name: String,
    installation_fingerprint: String,
    purpose: String,
    expires_at_millis: u64,
}

impl HostChallengeProjection {
    /// Constructs a bounded, terminal-safe projection.
    ///
    /// # Errors
    ///
    /// Rejects an empty, non-ASCII, control-bearing or excessive transfer;
    /// unsafe display text; and zero expiry.
    pub fn new(
        reference: AgentReference,
        challenge_transfer: String,
        installation_name: String,
        installation_fingerprint: String,
        purpose: String,
        expires_at_millis: u64,
    ) -> Result<Self, HostPortContractError> {
        validate_transfer(&challenge_transfer)?;
        validate_display(&installation_name)?;
        validate_display(&installation_fingerprint)?;
        validate_display(&purpose)?;
        if expires_at_millis == 0 {
            return Err(HostPortContractError);
        }
        Ok(Self {
            reference,
            challenge_transfer,
            installation_name,
            installation_fingerprint,
            purpose,
            expires_at_millis,
        })
    }

    /// Returns the host-owned opaque ceremony reference.
    #[must_use]
    pub const fn reference(&self) -> AgentReference {
        self.reference
    }

    /// Returns the exact installation-signed QR transfer.
    #[must_use]
    pub fn challenge_transfer(&self) -> &str {
        &self.challenge_transfer
    }

    /// Returns the reviewed installation display name.
    #[must_use]
    pub fn installation_name(&self) -> &str {
        &self.installation_name
    }

    /// Returns the printable installation fingerprint.
    #[must_use]
    pub fn installation_fingerprint(&self) -> &str {
        &self.installation_fingerprint
    }

    /// Returns the signed human-readable purpose.
    #[must_use]
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    /// Returns the authority-clock exclusive expiry.
    #[must_use]
    pub const fn expires_at_millis(&self) -> u64 {
        self.expires_at_millis
    }
}

/// Raw mobile response submitted to the sole host verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostResponseSubmission {
    reference: AgentReference,
    response_transfer: String,
}

impl HostResponseSubmission {
    /// Constructs one bounded response submission.
    ///
    /// This constructor checks transport safety only. Cryptographic, schema,
    /// binding, decision and replay verification remain host responsibilities.
    ///
    /// # Errors
    ///
    /// Rejects empty, non-ASCII, control-bearing or excessive transfers.
    pub fn new(
        reference: AgentReference,
        response_transfer: String,
    ) -> Result<Self, HostPortContractError> {
        validate_transfer(&response_transfer)?;
        Ok(Self {
            reference,
            response_transfer,
        })
    }

    /// Returns the opaque authority reference.
    #[must_use]
    pub const fn reference(&self) -> AgentReference {
        self.reference
    }

    /// Returns the unchanged signed response transfer.
    #[must_use]
    pub fn response_transfer(&self) -> &str {
        &self.response_transfer
    }
}

/// Coarse, credential-free host ceremony projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostCeremonyStatus {
    /// The authority can still accept one bound response.
    Pending,
    /// The single authoritative transaction completed.
    Completed,
    /// The mobile user explicitly denied the ceremony.
    Denied,
    /// The authority-clock expiry is terminal.
    Expired,
    /// The host atomically cancelled the ceremony.
    Cancelled,
}

impl HostCeremonyStatus {
    /// Returns whether no later response may change this projection.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Pending)
    }
}

/// Closed failure from the proposed host authority port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostAuthorityError {
    /// Signed material or a durable binding failed verification.
    Rejected,
    /// The opaque reference is missing, stale, terminal, or conflicts.
    Conflict,
    /// Required signing, storage, verifier, or authority service is unavailable.
    Unavailable,
}

/// Proposed host-owned authority port for an asynchronous phone ceremony.
///
/// Implementations live beside Prosopikon and own the only durable challenge
/// lifecycle. Calls may be exposed through a bounded local IPC adapter, but an
/// IPC spool must never become a second lifecycle authority. This trait is a
/// review contract and does not activate a production daemon.
pub trait HostAgentAuthorityPort {
    /// Durably creates one signed terminal-login challenge.
    ///
    /// # Errors
    ///
    /// Fails closed when signing, randomness, persistence or policy is
    /// unavailable.
    fn begin_login(&self) -> Result<HostChallengeProjection, HostAuthorityError>;

    /// Returns only the current coarse projection for an opaque reference.
    ///
    /// # Errors
    ///
    /// Rejects missing, invalid or non-projectable authority state.
    fn status(&self, reference: AgentReference) -> Result<HostCeremonyStatus, HostAuthorityError>;

    /// Verifies and completes through the one host transaction.
    ///
    /// # Errors
    ///
    /// Rejects malformed, unbound, inactive, replayed or conflicting signed
    /// material and reports durable authority outages without partial success.
    fn submit(
        &self,
        submission: HostResponseSubmission,
    ) -> Result<HostCeremonyStatus, HostAuthorityError>;

    /// Makes a pending challenge terminal in the same authority.
    ///
    /// # Errors
    ///
    /// Rejects missing references and incompatible terminal state, or reports
    /// an authority outage.
    fn cancel(&self, reference: AgentReference) -> Result<HostCeremonyStatus, HostAuthorityError>;
}

/// Invalid proposed-port value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostPortContractError;

impl fmt::Display for HostPortContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("host authority port value rejected")
    }
}

impl Error for HostPortContractError {}

fn validate_transfer(value: &str) -> Result<(), HostPortContractError> {
    if value.is_empty()
        || value.len() > MAX_TRANSFER_BYTES
        || !value.is_ascii()
        || value.chars().any(char::is_control)
    {
        Err(HostPortContractError)
    } else {
        Ok(())
    }
}

fn validate_display(value: &str) -> Result<(), HostPortContractError> {
    if value.is_empty() || value.len() > MAX_DISPLAY_BYTES || value.chars().any(char::is_control) {
        Err(HostPortContractError)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference() -> AgentReference {
        AgentReference::from_bytes([7; 32])
    }

    #[test]
    fn projection_contains_no_session_or_identity_authority() {
        let projection = HostChallengeProjection::new(
            reference(),
            "PISTIS1:challenge.checksum".into(),
            "Mnemosyne".into(),
            "12:34".into(),
            "authenticate terminal".into(),
            42,
        )
        .unwrap();
        assert_eq!(projection.reference(), reference());
        assert_eq!(
            projection.challenge_transfer(),
            "PISTIS1:challenge.checksum"
        );
        assert_eq!(projection.installation_name(), "Mnemosyne");
        assert_eq!(projection.installation_fingerprint(), "12:34");
        assert_eq!(projection.purpose(), "authenticate terminal");
        assert_eq!(projection.expires_at_millis(), 42);
    }

    #[test]
    fn unsafe_projection_and_response_values_fail_before_host_dispatch() {
        for transfer in [
            String::new(),
            "PISTIS1:\u{1b}[31m".into(),
            "π".into(),
            "x".repeat(MAX_TRANSFER_BYTES + 1),
        ] {
            assert!(
                HostResponseSubmission::new(reference(), transfer.clone()).is_err(),
                "{transfer:?}"
            );
            assert!(
                HostChallengeProjection::new(
                    reference(),
                    transfer,
                    "installation".into(),
                    "fingerprint".into(),
                    "purpose".into(),
                    1,
                )
                .is_err()
            );
        }
        assert!(
            HostChallengeProjection::new(
                reference(),
                "PISTIS1:safe".into(),
                "bad\nname".into(),
                "fingerprint".into(),
                "purpose".into(),
                1,
            )
            .is_err()
        );
    }

    #[test]
    fn terminal_projection_is_closed_and_idempotent() {
        assert!(!HostCeremonyStatus::Pending.is_terminal());
        for status in [
            HostCeremonyStatus::Completed,
            HostCeremonyStatus::Denied,
            HostCeremonyStatus::Expired,
            HostCeremonyStatus::Cancelled,
        ] {
            assert!(status.is_terminal());
            assert_eq!(status, status);
        }
    }
}
