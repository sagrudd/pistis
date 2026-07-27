# Canonical encoding

## Normative v1 profile

Pistis canonical payloads use deterministic CBOR as selected by
[ADR 0001](adr/0001-canonical-encoding.md). The following rules are normative:

- one complete CBOR data item, no trailing bytes, at most 65,536 bytes;
- at most 16 nested arrays or maps;
- definite-length byte strings, text strings, arrays, and maps only;
- unsigned and negative integers use the shortest representation;
- map keys are unsigned integer field identifiers in ascending order;
- duplicate, non-integer, or out-of-order map keys are rejected;
- text must be valid UTF-8; its UTF-8 bytes are the signed value;
- byte strings are opaque and are never silently interpreted as text;
- booleans and null are allowed;
- tags, floating point, undefined, other simple values, and break markers are
  rejected.

Protocol schemas are closed in v1. Every field is critical, so a verifier must
reject a field identifier absent from the schema for that object type. This
prevents an older verifier from accepting a payload while ignoring semantics
that a signer considered significant.

Canonical payloads are embedded without re-encoding in the untagged COSE
Sign1 profile specified by
[ADR 0018](adr/0018-production-cose-sign1-profile.md). CBOR tag 18, detached
payloads, non-empty unprotected headers, and alternate envelope encodings are
rejected.

## Text and diagnostic form

No Unicode normalization is performed by the codec. Protocol field definitions
must say whether a textual value is an opaque identifier or requires
normalization before encoding. Verifiers compare the encoded UTF-8 value and
must never apply locale-sensitive case conversion.

Tools may display a diagnostic JSON object whose keys are decimal field
identifiers and whose byte strings use lowercase hexadecimal. Diagnostic JSON
is not canonical, must never be signed, and must never be accepted on a
protocol boundary.

## Conformance fixture

`fixtures/protocol-v1/canonical/minimal-payload.cbor` represents this diagnostic
form:

```json
{
  "0": 1,
  "1": "authentication-challenge",
  "2": "h'00010203'",
  "3": 1700000000
}
```

The adjacent `.hex` file is the authoritative printable byte sequence.
Implementations must produce those exact bytes and must reject the negative
forms covered by the `pistis-canonical` conformance tests.
