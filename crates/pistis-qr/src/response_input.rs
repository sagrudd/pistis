use crate::{MAX_TRANSFER_TEXT_BYTES, QrError, TransferKind, decode};
use std::{
    error::Error,
    fmt,
    io::{self, BufRead},
};

/// Failure while acquiring one response from a terminal-safe input stream.
#[derive(Debug)]
pub enum ResponseInputError {
    /// Reading the input stream failed.
    Read(io::Error),
    /// The submitted line exceeds the QR transport bound.
    TooLarge,
    /// The line is empty or contains terminal control characters.
    InvalidLine,
    /// The line is not ASCII.
    NonAscii,
    /// The line is not a valid transfer of the expected kind.
    Transfer(QrError),
}

impl fmt::Display for ResponseInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Read(_) => "could not read terminal response",
            Self::TooLarge => "terminal response exceeds the QR transfer bound",
            Self::InvalidLine => "terminal response must be one control-free line",
            Self::NonAscii => "terminal response must be ASCII",
            Self::Transfer(_) => "terminal response is not a valid QR transfer",
        })
    }
}

impl Error for ResponseInputError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Read(error) => Some(error),
            Self::Transfer(error) => Some(error),
            _ => None,
        }
    }
}

/// Reads and decodes one bounded QR-transfer response line.
///
/// An optional `LF` or `CRLF` terminator is accepted. Every other control byte,
/// including terminal escape sequences, is rejected. CLI adapters should use
/// this standard-input boundary instead of accepting responses through
/// command-line arguments or environment variables.
///
/// This is transport validation only. The returned bytes remain untrusted and
/// require the normal signature and authoritative-binding verifier.
///
/// # Errors
///
/// Fails on read errors, excessive length, non-ASCII or control input, and
/// malformed or incorrectly typed transfers.
pub fn read_response_input<R: BufRead>(
    reader: &mut R,
    expected: TransferKind,
) -> Result<(Vec<u8>, Vec<u8>), ResponseInputError> {
    let transfer = read_response_transfer(reader)?;
    decode(&transfer, expected).map_err(ResponseInputError::Transfer)
}

/// Reads one bounded, validated transfer line without decoding its payload.
///
/// This is useful for a CLI that must forward the exact response frame to the
/// authoritative local agent. The line remains unauthenticated until that
/// agent performs normal framing, signature, binding, expiry, and replay
/// verification.
///
/// # Errors
///
/// Fails on read errors, excessive length, non-ASCII or control input, and
/// malformed transfer framing.
pub fn read_response_transfer<R: BufRead>(reader: &mut R) -> Result<String, ResponseInputError> {
    let limit = (MAX_TRANSFER_TEXT_BYTES + 3) as u64;
    let mut bounded = io::Read::take(reader, limit);
    let mut line = Vec::with_capacity(MAX_TRANSFER_TEXT_BYTES + 2);
    bounded
        .read_until(b'\n', &mut line)
        .map_err(ResponseInputError::Read)?;

    if line.len() > MAX_TRANSFER_TEXT_BYTES + 2 {
        return Err(ResponseInputError::TooLarge);
    }
    if line.last() == Some(&b'\n') {
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
    }
    if line.is_empty() {
        return Err(ResponseInputError::InvalidLine);
    }
    if line.len() > MAX_TRANSFER_TEXT_BYTES {
        return Err(ResponseInputError::TooLarge);
    }
    if !line.is_ascii() {
        return Err(ResponseInputError::NonAscii);
    }
    if line.iter().any(u8::is_ascii_control) {
        return Err(ResponseInputError::InvalidLine);
    }
    let transfer = std::str::from_utf8(&line).map_err(|_| ResponseInputError::NonAscii)?;
    let _ = decode(transfer, TransferKind::Response).map_err(ResponseInputError::Transfer)?;
    Ok(transfer.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SIGNATURE_BYTES, TransferRef, encode};
    use std::io::Cursor;

    fn response() -> String {
        encode(TransferRef {
            kind: TransferKind::Response,
            payload: &[0x01],
            signature: &[7; SIGNATURE_BYTES],
        })
        .unwrap()
    }

    #[test]
    fn accepts_bare_lf_and_crlf_response_lines() {
        let expected = (vec![0x01], vec![7; SIGNATURE_BYTES]);
        for suffix in ["", "\n", "\r\n"] {
            let mut input = Cursor::new(format!("{}{suffix}", response()));
            assert_eq!(
                read_response_input(&mut input, TransferKind::Response).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn rejects_control_non_ascii_oversize_and_wrong_kind() {
        for malicious in [
            format!("{}\u{1b}[2J\n", response()),
            format!("{}\tignored\n", response()),
            format!("{}\rignored\n", response()),
        ] {
            assert!(matches!(
                read_response_input(&mut Cursor::new(malicious), TransferKind::Response),
                Err(ResponseInputError::InvalidLine)
            ));
        }
        assert!(matches!(
            read_response_input(
                &mut Cursor::new("PISTIS1:é.0000000000000000\n"),
                TransferKind::Response
            ),
            Err(ResponseInputError::NonAscii)
        ));
        assert!(matches!(
            read_response_input(
                &mut Cursor::new(vec![b'A'; MAX_TRANSFER_TEXT_BYTES + 3]),
                TransferKind::Response
            ),
            Err(ResponseInputError::TooLarge)
        ));

        let challenge = encode(TransferRef {
            kind: TransferKind::Challenge,
            payload: &[0x01],
            signature: &[3; SIGNATURE_BYTES],
        })
        .unwrap();
        assert!(matches!(
            read_response_input(&mut Cursor::new(challenge), TransferKind::Response),
            Err(ResponseInputError::Transfer(QrError::UnsupportedKind))
        ));
    }

    #[test]
    fn error_never_echoes_attacker_controlled_input() {
        let malicious = format!("{}\u{1b}[31msecret", response());
        let error =
            read_response_input(&mut Cursor::new(&malicious), TransferKind::Response).unwrap_err();
        assert!(!error.to_string().contains(&malicious));
        assert!(!error.to_string().contains('\u{1b}'));
    }
}
