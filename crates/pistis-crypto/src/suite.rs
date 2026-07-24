use std::error::Error;
use std::fmt;

/// COSE algorithm number assigned to ES256.
pub const COSE_ES256: i64 = -7;

/// Signature suites accepted by protocol v1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SignatureSuite {
    /// ECDSA over P-256 with SHA-256 (COSE algorithm -7).
    Es256,
}

impl SignatureSuite {
    /// Return the registered COSE algorithm identifier.
    #[must_use]
    pub const fn cose_algorithm(self) -> i64 {
        match self {
            Self::Es256 => COSE_ES256,
        }
    }
}

/// An unrecognized or disallowed signature algorithm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AlgorithmError;

impl fmt::Display for AlgorithmError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("signature algorithm is not allowed")
    }
}

impl Error for AlgorithmError {}

impl TryFrom<i64> for SignatureSuite {
    type Error = AlgorithmError;

    fn try_from(identifier: i64) -> Result<Self, Self::Error> {
        match identifier {
            COSE_ES256 => Ok(Self::Es256),
            _ => Err(AlgorithmError),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_list_contains_only_es256() {
        assert_eq!(SignatureSuite::try_from(-7), Ok(SignatureSuite::Es256));
        for confused in [-8, -37, 0, 7] {
            assert_eq!(SignatureSuite::try_from(confused), Err(AlgorithmError));
        }
    }
}
