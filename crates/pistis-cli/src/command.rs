use pistis_canonical::{Value, to_vec};
use pistis_crypto::sha256;
use std::{collections::BTreeMap, error::Error, fmt};

/// Requested terminal QR presentation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum OutputProfile {
    /// Select the safest profile supported by the terminal.
    #[default]
    Auto,
    /// Use printable seven-bit ASCII.
    Ascii,
    /// Use UTF-8 block characters.
    Unicode,
}

/// One supported authentication command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthCommand {
    /// Authenticate a terminal session.
    Login {
        /// Requested QR presentation.
        profile: OutputProfile,
        /// Prefer light modules on a dark terminal background.
        inverted: bool,
    },
    /// Approve an exact child command.
    Approve {
        /// Requested QR presentation.
        profile: OutputProfile,
        /// Prefer light modules on a dark terminal background.
        inverted: bool,
        /// Human-readable executable and arguments displayed by the phone.
        command: Vec<String>,
        /// Domain-separated digest of the exact argument vector.
        command_digest: [u8; 32],
    },
}

/// A command-line syntax failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    /// The command is absent or unsupported.
    Usage,
    /// An option is unsupported or contradictory.
    InvalidOption,
    /// Action approval did not include a command after `--`.
    MissingAction,
    /// The action exceeds the reviewed canonical display bound.
    ActionTooLarge,
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Usage => "usage: pistis auth <login|approve> [--ascii|--unicode] [--invert]",
            Self::InvalidOption => "invalid or contradictory authentication option",
            Self::MissingAction => "approval requires an exact command after --",
            Self::ActionTooLarge => "approval command exceeds its canonical size bound",
        })
    }
}

impl Error for ParseError {}

/// Parses a complete argument vector excluding the process name.
///
/// Signed responses and session material are intentionally not accepted as
/// arguments.
///
/// # Errors
///
/// Rejects unsupported commands, contradictory profiles, unknown options,
/// missing approval actions, and actions over 4 KiB canonically encoded.
pub fn parse<I, S>(arguments: I) -> Result<AuthCommand, ParseError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let arguments: Vec<String> = arguments.into_iter().map(Into::into).collect();
    if arguments.first().map(String::as_str) != Some("auth") {
        return Err(ParseError::Usage);
    }
    match arguments.get(1).map(String::as_str) {
        Some("login") => {
            let (profile, inverted, consumed) = options(&arguments[2..], false)?;
            if consumed != arguments.len() - 2 {
                return Err(ParseError::InvalidOption);
            }
            Ok(AuthCommand::Login { profile, inverted })
        }
        Some("approve") => {
            let (profile, inverted, consumed) = options(&arguments[2..], true)?;
            let action = &arguments[2 + consumed..];
            if action.first().map(String::as_str) != Some("--") || action.len() == 1 {
                return Err(ParseError::MissingAction);
            }
            let command = action[1..].to_vec();
            let command_digest = digest_command(&command)?;
            Ok(AuthCommand::Approve {
                profile,
                inverted,
                command,
                command_digest,
            })
        }
        _ => Err(ParseError::Usage),
    }
}

fn options(
    arguments: &[String],
    stop_at_separator: bool,
) -> Result<(OutputProfile, bool, usize), ParseError> {
    let mut profile = OutputProfile::Auto;
    let mut inverted = false;
    let mut consumed = 0;
    for argument in arguments {
        if stop_at_separator && argument == "--" {
            break;
        }
        match argument.as_str() {
            "--ascii" if profile != OutputProfile::Unicode => profile = OutputProfile::Ascii,
            "--unicode" if profile != OutputProfile::Ascii => profile = OutputProfile::Unicode,
            "--invert" if !inverted => inverted = true,
            _ => return Err(ParseError::InvalidOption),
        }
        consumed += 1;
    }
    Ok((profile, inverted, consumed))
}

fn digest_command(command: &[String]) -> Result<[u8; 32], ParseError> {
    let arguments = command.iter().cloned().map(Value::Text).collect();
    let canonical = to_vec(&Value::Map(BTreeMap::from([
        (0, Value::Text("pistis.cli-command.v1".into())),
        (1, Value::Array(arguments)),
    ])))
    .map_err(|_| ParseError::ActionTooLarge)?;
    if canonical.len() > 4_096 {
        return Err(ParseError::ActionTooLarge);
    }
    Ok(sha256(&canonical).into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_login_profiles_without_response_arguments() {
        assert_eq!(
            parse(["auth", "login", "--ascii", "--invert"]).unwrap(),
            AuthCommand::Login {
                profile: OutputProfile::Ascii,
                inverted: true
            }
        );
        assert_eq!(
            parse(["auth", "login", "--ascii", "--unicode"]),
            Err(ParseError::InvalidOption)
        );
        assert_eq!(
            parse(["auth", "login", "PISTIS1:response"]),
            Err(ParseError::InvalidOption)
        );
    }

    #[test]
    fn approval_digest_binds_argument_boundaries_and_order() {
        let first = parse(["auth", "approve", "--", "tool", "a", "b"]).unwrap();
        let joined = parse(["auth", "approve", "--", "tool", "a b"]).unwrap();
        let reordered = parse(["auth", "approve", "--", "tool", "b", "a"]).unwrap();
        let digest = |command: &AuthCommand| match command {
            AuthCommand::Approve { command_digest, .. } => *command_digest,
            AuthCommand::Login { .. } => unreachable!(),
        };
        assert_ne!(digest(&first), digest(&joined));
        assert_ne!(digest(&first), digest(&reordered));
    }

    #[test]
    fn approval_requires_separator_and_bounded_action() {
        assert_eq!(
            parse(["auth", "approve", "tool"]),
            Err(ParseError::InvalidOption)
        );
        assert_eq!(
            parse(["auth", "approve", "--"]),
            Err(ParseError::MissingAction)
        );
        let oversized = "x".repeat(4_097);
        assert_eq!(
            parse(vec![
                "auth".into(),
                "approve".into(),
                "--".into(),
                oversized
            ]),
            Err(ParseError::ActionTooLarge)
        );
    }
}
