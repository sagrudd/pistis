use pistis_canonical::{Value, from_slice};
use std::{
    error::Error,
    fmt,
    io::{self, Read, Write},
};

/// Maximum canonical request or response accepted on the local socket.
pub const MAX_AGENT_MESSAGE_BYTES: usize = 64 * 1024;

/// Bounded local-socket framing failure.
#[derive(Debug)]
pub enum SocketFrameError {
    /// Socket input or output failed.
    Io(io::Error),
    /// Declared frame length is zero or exceeds the reviewed bound.
    InvalidLength,
    /// Payload is not one complete canonical Pistis value.
    InvalidCanonical,
}

impl fmt::Display for SocketFrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Io(_) => "local agent socket unavailable",
            Self::InvalidLength => "local agent frame length rejected",
            Self::InvalidCanonical => "local agent frame is not canonical",
        })
    }
}

impl Error for SocketFrameError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidLength | Self::InvalidCanonical => None,
        }
    }
}

/// Reads one four-byte big-endian length-prefixed canonical message.
///
/// # Errors
///
/// Rejects empty, oversized, truncated, non-canonical, and I/O-failed frames.
pub fn read_frame(reader: &mut impl Read) -> Result<Vec<u8>, SocketFrameError> {
    let mut header = [0_u8; 4];
    reader
        .read_exact(&mut header)
        .map_err(SocketFrameError::Io)?;
    let length =
        usize::try_from(u32::from_be_bytes(header)).map_err(|_| SocketFrameError::InvalidLength)?;
    if length == 0 || length > MAX_AGENT_MESSAGE_BYTES {
        return Err(SocketFrameError::InvalidLength);
    }
    let mut payload = vec![0; length];
    reader
        .read_exact(&mut payload)
        .map_err(SocketFrameError::Io)?;
    from_slice(&payload).map_err(|_| SocketFrameError::InvalidCanonical)?;
    Ok(payload)
}

/// Writes one bounded canonical message with a four-byte length prefix.
///
/// # Errors
///
/// Rejects empty, oversized, non-canonical payloads and output failures.
pub fn write_frame(writer: &mut impl Write, payload: &[u8]) -> Result<(), SocketFrameError> {
    if payload.is_empty() || payload.len() > MAX_AGENT_MESSAGE_BYTES {
        return Err(SocketFrameError::InvalidLength);
    }
    let _: Value = from_slice(payload).map_err(|_| SocketFrameError::InvalidCanonical)?;
    let length = u32::try_from(payload.len()).map_err(|_| SocketFrameError::InvalidLength)?;
    writer
        .write_all(&length.to_be_bytes())
        .and_then(|()| writer.write_all(payload))
        .and_then(|()| writer.flush())
        .map_err(SocketFrameError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pistis_canonical::{Value, to_vec};
    use std::io::Cursor;

    #[test]
    fn canonical_frame_round_trips() {
        let payload = to_vec(&Value::Map([(0, Value::Unsigned(1))].into())).unwrap();
        let mut wire = Vec::new();
        write_frame(&mut wire, &payload).unwrap();
        assert_eq!(read_frame(&mut Cursor::new(wire)).unwrap(), payload);
    }

    #[test]
    fn empty_oversize_truncated_and_noncanonical_fail_closed() {
        assert!(matches!(
            read_frame(&mut Cursor::new(0_u32.to_be_bytes())),
            Err(SocketFrameError::InvalidLength)
        ));
        assert!(matches!(
            read_frame(&mut Cursor::new(
                u32::try_from(MAX_AGENT_MESSAGE_BYTES + 1)
                    .unwrap()
                    .to_be_bytes()
            )),
            Err(SocketFrameError::InvalidLength)
        ));
        assert!(matches!(
            read_frame(&mut Cursor::new([0, 0, 0, 2, 0xa1])),
            Err(SocketFrameError::Io(_))
        ));
        assert!(matches!(
            read_frame(&mut Cursor::new([0, 0, 0, 2, 0x18, 0x00])),
            Err(SocketFrameError::InvalidCanonical)
        ));
    }
}
