use crate::{AuthCommand, OutputProfile};
use std::{error::Error, fmt};

/// Non-secret challenge metadata and exact signed QR transfer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingCeremony {
    /// Opaque adapter-owned reference. It must not be printed.
    pub reference: String,
    /// Exact signed `PISTIS1` challenge transfer.
    pub challenge_transfer: String,
    /// Reviewed installation display name.
    pub installation_name: String,
    /// Printable installation fingerprint.
    pub installation_fingerprint: String,
    /// Human-readable purpose bound into the signed challenge.
    pub purpose: String,
    /// Exclusive expiry in Unix milliseconds.
    pub expires_at_millis: u64,
}

/// Terminal presentation request passed to the QR adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChallengePresentation<'a> {
    /// Exact signed transfer; presentation must not alter it.
    pub transfer: &'a str,
    /// Requested terminal profile.
    pub profile: OutputProfile,
    /// Whether terminal contrast is inverted.
    pub inverted: bool,
}

/// Result of waiting for authenticated direct-local submission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectStatus {
    /// A response has not arrived; offer protected framed input.
    Pending,
    /// The authoritative verifier completed successfully.
    Completed,
    /// The mobile user explicitly denied the request.
    Denied,
    /// The challenge expired.
    Expired,
}

/// Authoritative service boundary used by the CLI.
///
/// Implementations must route direct and framed responses through the same
/// single-use authentication verifier. The CLI never verifies a second time.
pub trait AuthenticationBackend {
    /// Creates and installation-signs a challenge bound to `command`.
    ///
    /// # Errors
    ///
    /// Fails when authoritative challenge creation is unavailable.
    fn begin(&mut self, command: &AuthCommand) -> Result<PendingCeremony, CeremonyError>;
    /// Checks for an already verified direct-local response.
    ///
    /// # Errors
    ///
    /// Fails when status cannot be obtained safely.
    fn direct_status(&mut self, reference: &str) -> Result<DirectStatus, CeremonyError>;
    /// Submits one bounded response frame to the authoritative verifier.
    ///
    /// # Errors
    ///
    /// Fails when ingestion or verification rejects the response.
    fn submit_framed(
        &mut self,
        reference: &str,
        response: &str,
    ) -> Result<DirectStatus, CeremonyError>;
    /// Cancels a pending challenge after interruption or local failure.
    fn cancel(&mut self, reference: &str);
}

/// Protected interaction boundary.
///
/// Implementations must read a response from standard input or a protected
/// descriptor, never argv, an inherited environment variable, or a prompt
/// that enables terminal echo.
pub trait CliIo {
    /// Writes trusted explanatory text.
    ///
    /// # Errors
    ///
    /// Fails when output cannot be written safely.
    fn write_text(&mut self, text: &str) -> Result<(), CeremonyError>;
    /// Renders the exact challenge transfer.
    ///
    /// # Errors
    ///
    /// Fails when a complete scan-ready QR cannot be presented.
    fn write_qr(&mut self, presentation: ChallengePresentation<'_>) -> Result<(), CeremonyError>;
    /// Reads one bounded, non-echoed response frame.
    ///
    /// # Errors
    ///
    /// Fails on interruption, overflow, or protected-input failure.
    fn read_response(&mut self, maximum_bytes: usize) -> Result<String, CeremonyError>;
}

/// Stable process outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum CliExit {
    /// Authentication or approval completed.
    Success = 0,
    /// Command syntax was invalid.
    Usage = 64,
    /// The mobile user denied the request.
    Denied = 77,
    /// The challenge expired.
    Expired = 75,
    /// A response was malformed or failed verification.
    Rejected = 65,
    /// The local adapter or transport was unavailable.
    Unavailable = 69,
    /// The terminal presentation was unsupported.
    Presentation = 78,
    /// The ceremony was interrupted.
    Interrupted = 130,
}

/// A classified ceremony failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CeremonyError {
    /// An adapter is not configured or temporarily unavailable.
    Unavailable,
    /// The terminal cannot safely present the complete QR.
    Presentation,
    /// The response is malformed or rejected by the shared verifier.
    Rejected,
    /// Protected input was interrupted.
    Interrupted,
}

impl fmt::Display for CeremonyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "authentication service unavailable",
            Self::Presentation => "terminal cannot safely present this QR challenge",
            Self::Rejected => "authentication response rejected",
            Self::Interrupted => "authentication interrupted",
        })
    }
}

impl Error for CeremonyError {}

impl CeremonyError {
    fn exit(self) -> CliExit {
        match self {
            Self::Unavailable => CliExit::Unavailable,
            Self::Presentation => CliExit::Presentation,
            Self::Rejected => CliExit::Rejected,
            Self::Interrupted => CliExit::Interrupted,
        }
    }
}

/// Runs one CLI-only authentication or approval ceremony.
///
/// The QR and explanatory metadata are written before direct-local status is
/// checked. If no response is available, exactly one response frame is read
/// from protected input and submitted through the same verifier boundary.
pub fn run(
    command: &AuthCommand,
    backend: &mut impl AuthenticationBackend,
    io: &mut impl CliIo,
) -> CliExit {
    let pending = match backend.begin(command) {
        Ok(pending) => pending,
        Err(error) => return error.exit(),
    };
    let outcome = run_pending(command, backend, io, &pending);
    if outcome != CliExit::Success {
        backend.cancel(&pending.reference);
    }
    outcome
}

fn run_pending(
    command: &AuthCommand,
    backend: &mut impl AuthenticationBackend,
    io: &mut impl CliIo,
    pending: &PendingCeremony,
) -> CliExit {
    let (profile, inverted) = match command {
        AuthCommand::Login { profile, inverted }
        | AuthCommand::Approve {
            profile, inverted, ..
        } => (*profile, *inverted),
    };
    let explanation = format!(
        "Purpose: {}\nInstallation: {}\nFingerprint: {}\nExpires: {}\n",
        printable(&pending.purpose),
        printable(&pending.installation_name),
        printable(&pending.installation_fingerprint),
        pending.expires_at_millis
    );
    if let Err(error) = io.write_text(&explanation).and_then(|()| {
        io.write_qr(ChallengePresentation {
            transfer: &pending.challenge_transfer,
            profile,
            inverted,
        })
    }) {
        return error.exit();
    }
    match backend.direct_status(&pending.reference) {
        Ok(DirectStatus::Completed) => return CliExit::Success,
        Ok(DirectStatus::Denied) => return CliExit::Denied,
        Ok(DirectStatus::Expired) => return CliExit::Expired,
        Ok(DirectStatus::Pending) => {}
        Err(error) => return error.exit(),
    }
    let response = match io.read_response(2_331) {
        Ok(response) => response,
        Err(error) => return error.exit(),
    };
    match backend.submit_framed(&pending.reference, response.trim_end_matches(['\r', '\n'])) {
        Ok(DirectStatus::Completed) => CliExit::Success,
        Ok(DirectStatus::Denied) => CliExit::Denied,
        Ok(DirectStatus::Expired) => CliExit::Expired,
        Ok(DirectStatus::Pending) | Err(CeremonyError::Rejected) => CliExit::Rejected,
        Err(error) => error.exit(),
    }
}

fn printable(input: &str) -> String {
    input
        .chars()
        .map(|value| {
            if value.is_ascii_graphic() || value == ' ' {
                value
            } else {
                '\u{fffd}'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse;

    struct Backend {
        status: DirectStatus,
        submitted: Option<String>,
        cancelled: bool,
    }

    impl AuthenticationBackend for Backend {
        fn begin(&mut self, _: &AuthCommand) -> Result<PendingCeremony, CeremonyError> {
            Ok(PendingCeremony {
                reference: "secret-reference".into(),
                challenge_transfer: "PISTIS1:challenge.checksum".into(),
                installation_name: "cluster\u{1b}]8;;bad".into(),
                installation_fingerprint: "12:34".into(),
                purpose: "login".into(),
                expires_at_millis: 42,
            })
        }

        fn direct_status(&mut self, _: &str) -> Result<DirectStatus, CeremonyError> {
            Ok(self.status)
        }

        fn submit_framed(
            &mut self,
            _: &str,
            response: &str,
        ) -> Result<DirectStatus, CeremonyError> {
            self.submitted = Some(response.into());
            Ok(DirectStatus::Completed)
        }

        fn cancel(&mut self, _: &str) {
            self.cancelled = true;
        }
    }

    #[derive(Default)]
    struct Io {
        text: String,
        qr: String,
        read_maximum: Option<usize>,
    }

    impl CliIo for Io {
        fn write_text(&mut self, text: &str) -> Result<(), CeremonyError> {
            self.text.push_str(text);
            Ok(())
        }

        fn write_qr(
            &mut self,
            presentation: ChallengePresentation<'_>,
        ) -> Result<(), CeremonyError> {
            self.qr = presentation.transfer.into();
            Ok(())
        }

        fn read_response(&mut self, maximum_bytes: usize) -> Result<String, CeremonyError> {
            self.read_maximum = Some(maximum_bytes);
            Ok("PISTIS1:response.checksum\n".into())
        }
    }

    #[test]
    fn framed_fallback_is_bounded_and_metadata_is_control_safe() {
        let command = parse(["auth", "login"]).unwrap();
        let mut backend = Backend {
            status: DirectStatus::Pending,
            submitted: None,
            cancelled: false,
        };
        let mut io = Io::default();
        assert_eq!(run(&command, &mut backend, &mut io), CliExit::Success);
        assert_eq!(io.read_maximum, Some(2_331));
        assert_eq!(
            backend.submitted.as_deref(),
            Some("PISTIS1:response.checksum")
        );
        assert!(!io.text.contains('\u{1b}'));
        assert_eq!(io.qr, "PISTIS1:challenge.checksum");
        assert!(!backend.cancelled);
    }

    #[test]
    fn direct_completion_never_reads_or_echoes_response() {
        let command = parse(["auth", "login"]).unwrap();
        let mut backend = Backend {
            status: DirectStatus::Completed,
            submitted: None,
            cancelled: false,
        };
        let mut io = Io::default();
        assert_eq!(run(&command, &mut backend, &mut io), CliExit::Success);
        assert_eq!(io.read_maximum, None);
        assert_eq!(backend.submitted, None);
    }

    #[test]
    fn denial_and_interruption_fail_closed_and_cancel() {
        let command = parse(["auth", "login"]).unwrap();
        let mut denied = Backend {
            status: DirectStatus::Denied,
            submitted: None,
            cancelled: false,
        };
        assert_eq!(
            run(&command, &mut denied, &mut Io::default()),
            CliExit::Denied
        );
        assert!(denied.cancelled);
    }
}
