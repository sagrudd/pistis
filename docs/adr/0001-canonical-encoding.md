# ADR 0001: Deterministic CBOR for canonical protocol payloads

- Status: Accepted
- Date: 2026-07-24
- Decision owners: Pistis maintainers

## Context

Pistis needs byte-identical signed payloads across Rust, iOS, and Android,
compact offline and QR representations, and a decoder that rejects alternative
representations of the same data. The candidates were deterministic CBOR with
COSE and canonical JSON with JWS.

JSON is easy to inspect, but its number, Unicode, escaping, and object-member
rules require a larger additional profile. CBOR and COSE are IETF standards,
have implementations on all target platforms, preserve byte strings without
base64 expansion, and are compact.

## Decision

Pistis v1 uses deterministic CBOR following RFC 8949 section 4.2.1, narrowed by
the profile in `docs/encoding.md`. COSE structures will carry signatures; the
canonical payload itself remains independently testable CBOR.

The v1 profile uses unsigned integer map keys, definite lengths, shortest-form
integers and lengths, and a closed schema. All declared fields are critical:
an unknown field causes verification to fail. Tags, floating-point values,
undefined, arbitrary simple values, and indefinite-length items are forbidden.
Text is valid UTF-8 and is compared as encoded; producers must not perform
locale-sensitive transformations.

JSON is a non-normative diagnostic view only. It is never signed, hashed, or
accepted as a wire representation.

## Consequences

- Independent implementations can compare exact golden bytes.
- Decoders must validate canonical form rather than merely decode CBOR.
- Adding any v1 field is a protocol change requiring an explicit schema and
  compatibility decision.
- COSE header and signature-suite details remain a separate protocol decision.
