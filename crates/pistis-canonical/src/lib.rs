//! Strict deterministic CBOR for Pistis protocol payloads.
//!
//! This crate implements the deliberately small CBOR profile specified in
//! `docs/encoding.md`. It is an encoding boundary, not a general-purpose CBOR
//! implementation.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

/// Maximum accepted canonical payload size.
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024;
const MAX_DEPTH: usize = 16;

/// A value in the Pistis deterministic CBOR profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Value {
    /// An unsigned integer.
    Unsigned(u64),
    /// A negative integer.
    Negative(i64),
    /// An opaque byte string.
    Bytes(Vec<u8>),
    /// A UTF-8 text string.
    Text(String),
    /// A fixed-length array.
    Array(Vec<Value>),
    /// A map with unsigned integer field identifiers.
    Map(BTreeMap<u64, Value>),
    /// A boolean.
    Bool(bool),
    /// The null value.
    Null,
}

/// A canonical encoding or decoding failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalError {
    /// Input exceeds [`MAX_MESSAGE_SIZE`].
    MessageTooLarge,
    /// Input nesting exceeds the profile limit.
    NestingTooDeep,
    /// The byte stream is incomplete.
    Truncated,
    /// An additional CBOR value follows the payload.
    TrailingData,
    /// An unsupported CBOR major type or additional value was used.
    UnsupportedType,
    /// An integer or length did not use its shortest representation.
    NonMinimalInteger,
    /// A map key was not an unsigned field identifier.
    InvalidMapKey,
    /// Map keys were not in deterministic order.
    MapKeyOrder,
    /// A map contained the same field more than once.
    DuplicateMapKey,
    /// A text string was not valid UTF-8.
    InvalidUtf8,
    /// A negative integer cannot be represented by this profile.
    NegativeOutOfRange,
    /// A field was not declared by the caller's closed schema.
    UnknownCriticalField(u64),
}

impl fmt::Display for CanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MessageTooLarge => formatter.write_str("message exceeds 64 KiB"),
            Self::NestingTooDeep => formatter.write_str("message nesting exceeds 16 levels"),
            Self::Truncated => formatter.write_str("truncated CBOR"),
            Self::TrailingData => formatter.write_str("trailing data after CBOR value"),
            Self::UnsupportedType => formatter.write_str("unsupported CBOR type"),
            Self::NonMinimalInteger => formatter.write_str("non-minimal CBOR integer or length"),
            Self::InvalidMapKey => formatter.write_str("map key is not an unsigned integer"),
            Self::MapKeyOrder => formatter.write_str("map keys are not in deterministic order"),
            Self::DuplicateMapKey => formatter.write_str("duplicate map key"),
            Self::InvalidUtf8 => formatter.write_str("invalid UTF-8 text"),
            Self::NegativeOutOfRange => formatter.write_str("negative integer is out of range"),
            Self::UnknownCriticalField(field) => {
                write!(formatter, "unknown critical field {field}")
            }
        }
    }
}

impl Error for CanonicalError {}

/// Encode a value using the Pistis deterministic CBOR profile.
///
/// # Errors
///
/// Returns an error when a negative value cannot be represented or the result
/// exceeds the profile's message-size limit.
pub fn to_vec(value: &Value) -> Result<Vec<u8>, CanonicalError> {
    let mut output = Vec::new();
    encode(value, &mut output, 0)?;
    if output.len() > MAX_MESSAGE_SIZE {
        return Err(CanonicalError::MessageTooLarge);
    }
    Ok(output)
}

/// Decode and validate one canonical value.
///
/// Validation rejects encodings which could decode to the same data with
/// different bytes.
///
/// # Errors
///
/// Returns an explicit error for malformed, unsupported, oversized, or
/// non-canonical input.
pub fn from_slice(input: &[u8]) -> Result<Value, CanonicalError> {
    if input.len() > MAX_MESSAGE_SIZE {
        return Err(CanonicalError::MessageTooLarge);
    }
    let mut decoder = Decoder { input, offset: 0 };
    let value = decoder.value(0)?;
    if decoder.offset != input.len() {
        return Err(CanonicalError::TrailingData);
    }
    Ok(value)
}

/// Decode a top-level protocol map using a closed set of field identifiers.
///
/// All v1 fields are critical. This helper fails closed if a producer sends a
/// field that the verifier does not understand.
///
/// # Errors
///
/// Returns [`CanonicalError::UnknownCriticalField`] for an undeclared field,
/// in addition to the errors returned by [`from_slice`].
pub fn from_slice_with_fields(
    input: &[u8],
    known_fields: &[u64],
) -> Result<BTreeMap<u64, Value>, CanonicalError> {
    let Value::Map(fields) = from_slice(input)? else {
        return Err(CanonicalError::UnsupportedType);
    };
    for field in fields.keys() {
        if !known_fields.contains(field) {
            return Err(CanonicalError::UnknownCriticalField(*field));
        }
    }
    Ok(fields)
}

fn encode(value: &Value, output: &mut Vec<u8>, depth: usize) -> Result<(), CanonicalError> {
    if depth > MAX_DEPTH {
        return Err(CanonicalError::NestingTooDeep);
    }
    match value {
        Value::Unsigned(number) => encode_head(0, *number, output),
        Value::Negative(number) => {
            let magnitude = number
                .checked_add(1)
                .and_then(i64::checked_neg)
                .ok_or(CanonicalError::NegativeOutOfRange)?;
            encode_head(
                1,
                u64::try_from(magnitude).map_err(|_| CanonicalError::NegativeOutOfRange)?,
                output,
            );
        }
        Value::Bytes(bytes) => {
            encode_head(2, bytes.len() as u64, output);
            output.extend_from_slice(bytes);
        }
        Value::Text(text) => {
            encode_head(3, text.len() as u64, output);
            output.extend_from_slice(text.as_bytes());
        }
        Value::Array(values) => {
            encode_head(4, values.len() as u64, output);
            for item in values {
                encode(item, output, depth + 1)?;
            }
        }
        Value::Map(fields) => {
            encode_head(5, fields.len() as u64, output);
            for (field, item) in fields {
                encode_head(0, *field, output);
                encode(item, output, depth + 1)?;
            }
        }
        Value::Bool(false) => output.push(0xf4),
        Value::Bool(true) => output.push(0xf5),
        Value::Null => output.push(0xf6),
    }
    Ok(())
}

fn encode_head(major: u8, value: u64, output: &mut Vec<u8>) {
    let prefix = major << 5;
    match value {
        0..=23 => output.push(prefix | u8::try_from(value).expect("range checked")),
        24..=0xff => {
            output.extend_from_slice(&[prefix | 24, u8::try_from(value).expect("range checked")]);
        }
        0x100..=0xffff => {
            output.push(prefix | 25);
            output.extend_from_slice(&u16::try_from(value).expect("range checked").to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push(prefix | 26);
            output.extend_from_slice(&u32::try_from(value).expect("range checked").to_be_bytes());
        }
        _ => {
            output.push(prefix | 27);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

struct Decoder<'a> {
    input: &'a [u8],
    offset: usize,
}

impl Decoder<'_> {
    fn value(&mut self, depth: usize) -> Result<Value, CanonicalError> {
        if depth > MAX_DEPTH {
            return Err(CanonicalError::NestingTooDeep);
        }
        let initial = self.byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        match major {
            0 => Ok(Value::Unsigned(self.argument(additional)?)),
            1 => {
                let argument = self.argument(additional)?;
                let number = i64::try_from(-1_i128 - i128::from(argument))
                    .map_err(|_| CanonicalError::NegativeOutOfRange)?;
                Ok(Value::Negative(number))
            }
            2 => {
                let length = self.length(additional)?;
                Ok(Value::Bytes(self.bytes(length)?.to_vec()))
            }
            3 => {
                let length = self.length(additional)?;
                let text = std::str::from_utf8(self.bytes(length)?)
                    .map_err(|_| CanonicalError::InvalidUtf8)?;
                Ok(Value::Text(text.to_owned()))
            }
            4 => {
                let length = self.length(additional)?;
                if length > self.remaining() {
                    return Err(CanonicalError::Truncated);
                }
                let mut values = Vec::with_capacity(length);
                for _ in 0..length {
                    values.push(self.value(depth + 1)?);
                }
                Ok(Value::Array(values))
            }
            5 => self.map(additional, depth),
            7 if additional == 20 => Ok(Value::Bool(false)),
            7 if additional == 21 => Ok(Value::Bool(true)),
            7 if additional == 22 => Ok(Value::Null),
            _ => Err(CanonicalError::UnsupportedType),
        }
    }

    fn map(&mut self, additional: u8, depth: usize) -> Result<Value, CanonicalError> {
        let length = self.length(additional)?;
        if length > self.remaining() / 2 {
            return Err(CanonicalError::Truncated);
        }
        let mut fields = BTreeMap::new();
        let mut previous = None;
        for _ in 0..length {
            let initial = self.byte()?;
            if initial >> 5 != 0 {
                return Err(CanonicalError::InvalidMapKey);
            }
            let field = self.argument(initial & 0x1f)?;
            if let Some(prior) = previous {
                if field == prior {
                    return Err(CanonicalError::DuplicateMapKey);
                }
                if field < prior {
                    return Err(CanonicalError::MapKeyOrder);
                }
            }
            previous = Some(field);
            fields.insert(field, self.value(depth + 1)?);
        }
        Ok(Value::Map(fields))
    }

    fn length(&mut self, additional: u8) -> Result<usize, CanonicalError> {
        usize::try_from(self.argument(additional)?).map_err(|_| CanonicalError::MessageTooLarge)
    }

    fn argument(&mut self, additional: u8) -> Result<u64, CanonicalError> {
        match additional {
            value @ 0..=23 => Ok(u64::from(value)),
            24 => {
                let value = u64::from(self.byte()?);
                (value >= 24)
                    .then_some(value)
                    .ok_or(CanonicalError::NonMinimalInteger)
            }
            25 => {
                let value = u64::from(u16::from_be_bytes(self.array()?));
                (value > 0xff)
                    .then_some(value)
                    .ok_or(CanonicalError::NonMinimalInteger)
            }
            26 => {
                let value = u64::from(u32::from_be_bytes(self.array()?));
                (value > 0xffff)
                    .then_some(value)
                    .ok_or(CanonicalError::NonMinimalInteger)
            }
            27 => {
                let value = u64::from_be_bytes(self.array()?);
                (value > 0xffff_ffff)
                    .then_some(value)
                    .ok_or(CanonicalError::NonMinimalInteger)
            }
            _ => Err(CanonicalError::UnsupportedType),
        }
    }

    fn byte(&mut self) -> Result<u8, CanonicalError> {
        let byte = self
            .input
            .get(self.offset)
            .copied()
            .ok_or(CanonicalError::Truncated)?;
        self.offset += 1;
        Ok(byte)
    }

    fn bytes(&mut self, length: usize) -> Result<&[u8], CanonicalError> {
        let end = self
            .offset
            .checked_add(length)
            .filter(|end| *end <= self.input.len())
            .ok_or(CanonicalError::Truncated)?;
        let bytes = &self.input[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    fn remaining(&self) -> usize {
        self.input.len() - self.offset
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], CanonicalError> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| CanonicalError::Truncated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_supported_value() {
        let value = Value::Map(BTreeMap::from([
            (0, Value::Unsigned(1)),
            (1, Value::Negative(-7)),
            (2, Value::Bytes(vec![0, 1, 255])),
            (3, Value::Text("pistis".into())),
            (4, Value::Array(vec![Value::Bool(true), Value::Null])),
        ]));
        let encoded = to_vec(&value).unwrap();
        assert_eq!(from_slice(&encoded).unwrap(), value);
        let minimum = Value::Negative(i64::MIN);
        assert_eq!(from_slice(&to_vec(&minimum).unwrap()).unwrap(), minimum);
    }

    #[test]
    fn rejects_non_minimal_integer() {
        assert_eq!(
            from_slice(&[0x18, 0x17]),
            Err(CanonicalError::NonMinimalInteger)
        );
    }

    #[test]
    fn rejects_indefinite_length() {
        assert_eq!(
            from_slice(&[0x9f, 0xff]),
            Err(CanonicalError::UnsupportedType)
        );
        assert_eq!(
            from_slice(&[0x9a, 0xff, 0xff, 0xff, 0xff]),
            Err(CanonicalError::Truncated)
        );
        assert_eq!(
            from_slice(&[0xba, 0xff, 0xff, 0xff, 0xff]),
            Err(CanonicalError::Truncated)
        );
    }

    #[test]
    fn rejects_duplicate_and_unsorted_keys() {
        assert_eq!(
            from_slice(&[0xa2, 0x00, 0xf6, 0x00, 0xf6]),
            Err(CanonicalError::DuplicateMapKey)
        );
        assert_eq!(
            from_slice(&[0xa2, 0x01, 0xf6, 0x00, 0xf6]),
            Err(CanonicalError::MapKeyOrder)
        );
    }

    #[test]
    fn rejects_unknown_fields_under_closed_schema() {
        assert_eq!(
            from_slice_with_fields(&[0xa1, 0x02, 0xf6], &[0, 1]),
            Err(CanonicalError::UnknownCriticalField(2))
        );
    }

    #[test]
    fn rejects_float_tag_and_invalid_utf8() {
        assert_eq!(
            from_slice(&[0xf9, 0x00, 0x00]),
            Err(CanonicalError::UnsupportedType)
        );
        assert_eq!(
            from_slice(&[0xc0, 0x00]),
            Err(CanonicalError::UnsupportedType)
        );
        assert_eq!(from_slice(&[0x61, 0xff]), Err(CanonicalError::InvalidUtf8));
    }
}
