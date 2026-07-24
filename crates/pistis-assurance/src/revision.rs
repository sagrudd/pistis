use core::fmt;

/// Exact 20-byte Git source revision covered by assurance evidence.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SourceRevision([u8; 20]);

impl SourceRevision {
    /// Parses an exact lowercase or uppercase 40-digit hexadecimal revision.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSourceRevision`] for abbreviated, malformed, or
    /// non-ASCII input.
    pub fn from_hex(value: &str) -> Result<Self, InvalidSourceRevision> {
        if value.len() != 40 || !value.is_ascii() {
            return Err(InvalidSourceRevision);
        }
        let mut bytes = [0_u8; 20];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
        }
        Ok(Self(bytes))
    }

    /// Returns the exact revision bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

impl fmt::Debug for SourceRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SourceRevision(")?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str(")")
    }
}

const fn nibble(value: u8) -> Result<u8, InvalidSourceRevision> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(InvalidSourceRevision),
    }
}

/// A source revision that is not an exact 40-digit hexadecimal identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidSourceRevision;

impl fmt::Display for InvalidSourceRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("source revision must be exactly 40 hexadecimal digits")
    }
}

impl std::error::Error for InvalidSourceRevision {}
