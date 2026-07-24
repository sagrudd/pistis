//! Shared domain types for Pistis.
//!
//! Identifier types in this crate are deliberately not interchangeable. Their
//! canonical text form includes a type-specific prefix, so a value crossing a
//! textual boundary cannot silently change identifier classes.

#![deny(missing_docs)]

use core::{fmt, str::FromStr};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

const ENTITY_ID_BYTES: usize = 16;
const KEY_ID_BYTES: usize = 32;

/// An error returned when parsing a typed Pistis identifier.
///
/// The error reports only structural information. It never retains or echoes
/// the input, which makes it safe to include in validation logs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseIdentifierError {
    /// The input does not begin with the identifier type's exact prefix.
    InvalidPrefix,
    /// The hexadecimal payload has the wrong number of bytes.
    InvalidLength {
        /// Required length of the complete canonical identifier.
        expected: usize,
        /// Observed input length in bytes.
        actual: usize,
    },
    /// The payload contains a byte outside lowercase ASCII hexadecimal.
    InvalidCharacter {
        /// Zero-based byte position in the complete identifier.
        index: usize,
    },
}

impl fmt::Display for ParseIdentifierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrefix => formatter.write_str("identifier has an invalid type prefix"),
            Self::InvalidLength { expected, actual } => {
                write!(
                    formatter,
                    "identifier must be {expected} bytes long, but is {actual}"
                )
            }
            Self::InvalidCharacter { index } => {
                write!(
                    formatter,
                    "identifier contains invalid lowercase hexadecimal at byte {index}"
                )
            }
        }
    }
}

impl std::error::Error for ParseIdentifierError {}

fn parse_payload<const N: usize>(
    input: &str,
    prefix: &str,
) -> Result<[u8; N], ParseIdentifierError> {
    let expected = prefix.len() + N * 2;
    if input.len() != expected {
        return Err(ParseIdentifierError::InvalidLength {
            expected,
            actual: input.len(),
        });
    }
    if !input.starts_with(prefix) {
        return Err(ParseIdentifierError::InvalidPrefix);
    }

    let mut payload = [0_u8; N];
    let hexadecimal = input.as_bytes()[prefix.len()..].chunks_exact(2);
    for (byte_index, (output, pair)) in payload.iter_mut().zip(hexadecimal).enumerate() {
        let high = decode_nibble(pair[0]).ok_or(ParseIdentifierError::InvalidCharacter {
            index: prefix.len() + byte_index * 2,
        })?;
        let low = decode_nibble(pair[1]).ok_or(ParseIdentifierError::InvalidCharacter {
            index: prefix.len() + byte_index * 2 + 1,
        })?;
        *output = (high << 4) | low;
    }
    Ok(payload)
}

const fn decode_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn format_identifier<const N: usize>(
    formatter: &mut fmt::Formatter<'_>,
    prefix: &str,
    payload: &[u8; N],
) -> fmt::Result {
    formatter.write_str(prefix)?;
    for byte in payload {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

macro_rules! identifier {
    ($name:ident, $bytes:expr, $bits:literal, $prefix:literal, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; $bytes]);

        impl $name {
            #[doc = concat!("Constructs an identifier from its opaque ", $bits, "-bit payload.")]
            #[must_use]
            pub const fn from_bytes(bytes: [u8; $bytes]) -> Self {
                Self(bytes)
            }

            #[doc = concat!("Returns the identifier's opaque ", $bits, "-bit payload.")]
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $bytes] {
                &self.0
            }

            #[doc = concat!("Consumes the identifier and returns its opaque ", $bits, "-bit payload.")]
            #[must_use]
            pub const fn into_bytes(self) -> [u8; $bytes] {
                self.0
            }
        }

        impl From<[u8; $bytes]> for $name {
            fn from(bytes: [u8; $bytes]) -> Self {
                Self::from_bytes(bytes)
            }
        }

        impl From<$name> for [u8; $bytes] {
            fn from(identifier: $name) -> Self {
                identifier.into_bytes()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                format_identifier(formatter, $prefix, &self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(self, formatter)
            }
        }

        impl FromStr for $name {
            type Err = ParseIdentifierError;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                parse_payload(input, $prefix).map(Self)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct IdentifierVisitor;

                impl de::Visitor<'_> for IdentifierVisitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        formatter.write_str(concat!("a canonical ", stringify!($name), " string"))
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        value.parse().map_err(E::custom)
                    }
                }

                deserializer.deserialize_str(IdentifierVisitor)
            }
        }
    };
}

identifier!(
    InstallationId,
    ENTITY_ID_BYTES,
    "128",
    "installation_",
    "Identifies one independently administered Pistis installation."
);
identifier!(
    UserId,
    ENTITY_ID_BYTES,
    "128",
    "user_",
    "Identifies a user within the Pistis domain model."
);
identifier!(
    DeviceId,
    ENTITY_ID_BYTES,
    "128",
    "device_",
    "Identifies one enrolled physical device."
);
identifier!(
    ChallengeId,
    ENTITY_ID_BYTES,
    "128",
    "challenge_",
    "Identifies one authentication or approval challenge."
);
identifier!(
    EvidenceId,
    ENTITY_ID_BYTES,
    "128",
    "evidence_",
    "Identifies one portable evidence package."
);
identifier!(
    KeyId,
    KEY_ID_BYTES,
    "256",
    "key_",
    "Identifies a cryptographic public key without containing key material."
);
identifier!(
    ExternalIdentityId,
    ENTITY_ID_BYTES,
    "128",
    "external_identity_",
    "Identifies a stable identity asserted by an external provider."
);

#[cfg(test)]
mod tests {
    use super::*;

    const ENTITY_PAYLOAD: [u8; ENTITY_ID_BYTES] = [
        0x00, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde,
        0xff,
    ];

    macro_rules! identifier_tests {
        ($module:ident, $type:ident, $prefix:literal, $payload:expr, $canonical:literal) => {
            mod $module {
                use super::*;

                const CANONICAL: &str = concat!($prefix, $canonical);

                #[test]
                fn formats_and_parses_canonical_form() {
                    let payload = $payload;
                    let identifier = $type::from_bytes(payload);
                    assert_eq!(identifier.to_string(), CANONICAL);
                    assert_eq!(CANONICAL.parse::<$type>(), Ok(identifier));
                    assert_eq!(identifier.as_bytes(), &payload);
                    assert_eq!(identifier.into_bytes(), payload);
                }

                #[test]
                fn serde_uses_canonical_string_form() {
                    let identifier = $type::from_bytes($payload);
                    let json = serde_json::to_string(&identifier).expect("identifier serializes");
                    assert_eq!(json, format!("\"{CANONICAL}\""));
                    assert_eq!(
                        serde_json::from_str::<$type>(&json).expect("identifier deserializes"),
                        identifier
                    );
                }

                #[test]
                fn rejects_wrong_length_without_inspecting_payload() {
                    let short = concat!($prefix, "00");
                    assert!(matches!(
                        short.parse::<$type>(),
                        Err(ParseIdentifierError::InvalidLength { .. })
                    ));
                }

                #[test]
                fn rejects_wrong_identifier_class() {
                    let mut wrong = CANONICAL.to_owned();
                    wrong.replace_range(..1, "x");
                    assert_eq!(
                        wrong.parse::<$type>(),
                        Err(ParseIdentifierError::InvalidPrefix)
                    );
                }

                #[test]
                fn rejects_uppercase_and_non_hexadecimal_payloads() {
                    let mut uppercase = CANONICAL.to_owned();
                    uppercase.replace_range(uppercase.len() - 1.., "F");
                    let mut punctuation = CANONICAL.to_owned();
                    punctuation.replace_range(punctuation.len() - 1.., "!");
                    assert!(matches!(
                        uppercase.parse::<$type>(),
                        Err(ParseIdentifierError::InvalidCharacter { .. })
                    ));
                    assert!(matches!(
                        punctuation.parse::<$type>(),
                        Err(ParseIdentifierError::InvalidCharacter { .. })
                    ));
                }

                #[test]
                fn rejects_non_string_serde_input() {
                    assert!(serde_json::from_str::<$type>("17").is_err());
                }
            }
        };
    }

    identifier_tests!(
        installation_id,
        InstallationId,
        "installation_",
        ENTITY_PAYLOAD,
        "000112233445566778899aabbccddeff"
    );
    identifier_tests!(
        user_id,
        UserId,
        "user_",
        ENTITY_PAYLOAD,
        "000112233445566778899aabbccddeff"
    );
    identifier_tests!(
        device_id,
        DeviceId,
        "device_",
        ENTITY_PAYLOAD,
        "000112233445566778899aabbccddeff"
    );
    identifier_tests!(
        challenge_id,
        ChallengeId,
        "challenge_",
        ENTITY_PAYLOAD,
        "000112233445566778899aabbccddeff"
    );
    identifier_tests!(
        evidence_id,
        EvidenceId,
        "evidence_",
        ENTITY_PAYLOAD,
        "000112233445566778899aabbccddeff"
    );
    identifier_tests!(
        key_id,
        KeyId,
        "key_",
        [0x5a; KEY_ID_BYTES],
        "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
    );
    identifier_tests!(
        external_identity_id,
        ExternalIdentityId,
        "external_identity_",
        ENTITY_PAYLOAD,
        "000112233445566778899aabbccddeff"
    );

    #[test]
    fn parse_errors_do_not_echo_input() {
        let sensitive = "installation_not-a-secret-but-invalid!";
        let rendered = sensitive
            .parse::<InstallationId>()
            .expect_err("invalid identifier must fail")
            .to_string();
        assert!(!rendered.contains(sensitive));
    }
}
