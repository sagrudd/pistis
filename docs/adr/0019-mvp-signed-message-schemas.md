# ADR 0019: MVP signed-message schemas

- Status: Accepted
- Date: 2026-07-27
- Decision owners: Pistis protocol, evidence, and host-integration maintainers
- Security review: required for incompatible schema changes

## Context

The MVP needs byte-identical messages across Rust and iOS. Existing documents
define authentication semantics, but only the EPIC-6 reference challenge and
response have complete integer-key assignments. Enrolment and authentication
evidence also need closed payloads before shared fixtures can be frozen.

This ADR freezes the signed payload layer. ADR 0018 wraps each payload in the
production COSE Sign1 profile. QR, HTTP, and local discovery are transports and
must not alter these bytes.

## Decision

### Common rules

Every payload is a closed deterministic-CBOR map with unsigned integer keys in
ascending order. Every listed field is mandatory. Unknown, missing, duplicate,
mis-typed, non-canonical, or out-of-range fields are rejected. Identifiers are
their raw `pistis-domain` bytes: entity identifiers are 16 bytes and `KeyId`
is 32 bytes. Digests and nonces are 32 bytes. Times are unsigned Unix epoch
milliseconds. Text is non-empty, trimmed UTF-8 without control characters and
is compared byte-for-byte.

The common leading fields are:

| Key | Field | Type |
| --- | --- | --- |
| 0 | `version` | unsigned integer, exactly `1` |
| 1 | `purpose` | exact purpose text |
| 2 | `issued_at_ms` | unsigned integer |

Purpose is domain separation. A valid payload must never be reinterpreted
under another purpose.

### Device enrolment

Purpose: `pistis.device-registration.v1`.

| Key | Field | Type and constraint |
| --- | --- | --- |
| 3 | `installation_id` | 16-byte byte string |
| 4 | `invitation_digest` | 32-byte digest of the complete invitation |
| 5 | `user_id` | 16-byte Prosopikon-bound user identifier |
| 6 | `external_identity_id` | 16-byte stable GitHub binding identifier |
| 7 | `device_id` | 16-byte device identifier |
| 8 | `device_key_id` | 32-byte key identifier |
| 9 | `device_public_key` | canonical 33-byte compressed SEC1 P-256 point |
| 10 | `device_key_algorithm` | integer, exactly `-7` |
| 11 | `key_assurance` | text, exactly `secure-enclave-biometry-current-set` |
| 12 | `provider_evidence_digest` | 32-byte digest |
| 13 | `registered_at_ms` | unsigned integer, not before `issued_at_ms` |

The device signs this payload to prove possession. The host verifies the
single-use invitation, GitHub evidence, principal binding, public-key
derivation, assurance, and policy before atomically recording enrolment. A
host-signed evidence receipt records acceptance; the device signature alone
does not establish enrolment.

### Authentication challenge

Purpose: `pistis.authentication-challenge.v1`.

| Key | Field | Type and constraint |
| --- | --- | --- |
| 3 | `expires_at_ms` | unsigned integer, greater than key 2 |
| 4 | `installation_id` | 16-byte byte string |
| 5 | `installation_key_id` | 32-byte byte string |
| 6 | `challenge_id` | 16-byte byte string |
| 7 | `nonce` | 32-byte byte string |
| 8 | `user_id` | 16-byte byte string |
| 9 | `external_identity_id` | 16-byte byte string |
| 10 | `requested_action` | text, exactly `authenticate-session` |
| 11 | `audience` | text, at most 128 UTF-8 bytes |
| 12 | `installation_name` | display text, at most 128 UTF-8 bytes |
| 13 | `local_username` | display text, at most 128 UTF-8 bytes |
| 14 | `display_context_digest` | 32-byte byte string |
| 15 | `installation_fingerprint` | 32-byte byte string |
| 16 | `endpoint_hints` | array of zero to two unique HTTPS texts |

Endpoint hints are bounded signed transport hints, not authority. The
installation signs the challenge. The host owns time, expiry, audience, and
single-use state.

### Authentication response

Purpose: `pistis.authentication-response.v1`.

| Key | Field | Type and constraint |
| --- | --- | --- |
| 3 | `user_verified_at_ms` | unsigned integer, not before key 2 |
| 4 | `installation_id` | 16-byte byte string |
| 5 | `device_key_id` | 32-byte byte string |
| 6 | `challenge_id` | 16-byte byte string |
| 7 | `nonce` | 32-byte byte string |
| 8 | `challenge_digest` | SHA-256 of exact challenge payload bytes |
| 9 | `user_id` | 16-byte byte string |
| 10 | `device_id` | 16-byte byte string |
| 11 | `external_identity_id` | 16-byte byte string |
| 12 | `decision` | text, exactly `approved` or `denied` |

The device signs the response only after explicit Face ID verification. It
does not assert expiry or session authority. The host verifies the stored
challenge and all bindings and performs the Prosopikon-owned single-use
completion transaction. A denial never creates a session.

### Authentication evidence receipt

Purpose: `pistis.authentication-evidence-receipt.v1`.

| Key | Field | Type and constraint |
| --- | --- | --- |
| 3 | `evidence_id` | 16-byte byte string |
| 4 | `installation_id` | 16-byte byte string |
| 5 | `authority_key_id` | 32-byte byte string |
| 6 | `event_type` | `enrolment`, `authentication`, `cli-approval`, or `revocation` |
| 7 | `subject_digest` | 32-byte digest of the signed subject envelope |
| 8 | `user_id` | 16-byte byte string |
| 9 | `device_id` | 16-byte byte string |
| 10 | `outcome` | `accepted`, `denied`, `revoked`, or `rejected` |
| 11 | `policy_generation` | unsigned integer |
| 12 | `revocation_generation` | unsigned integer |
| 13 | `previous_event_digest` | 32-byte byte string; all-zero for genesis |

The host authority signs the receipt only as part of its durable transaction.
It contains no bearer session, nonce, GitHub token, display snapshot, command
argument, or private material. `subject_digest` binds the exact event input
without copying sensitive contents.

This receipt is the signed event core, not the complete detached evidence
package. EPIC-23 remains responsible for trust bundles, temporal and revocation
proofs, redaction policy, offline verification, and portable packaging.

## Compatibility and verification

These v1 maps cannot gain fields in place because all fields are critical.
Compatible transport or diagnostic changes do not alter payload bytes. A
semantic or field change requires a new purpose/version and accepted ADR.

Shared fixtures must cover every payload and COSE envelope, byte-for-byte
Rust/Swift agreement, and negative cases for wrong purpose, field, type,
width, algorithm, key identifier, signature form, digest, decision, time
ordering, and unknown fields.

Portable Swift tests and Rust tests are necessary but insufficient. Secure
Enclave key production and Face ID gating require a signed physical-device
record, and EPIC-18 remains incomplete until Jenkins retains that
exact-revision interoperability evidence.

## Consequences

- Rust and iOS can implement against stable integer-key assignments.
- The existing authentication challenge and response assignments remain
  compatible with the EPIC-6 reference payloads.
- Enrolment acceptance and evidence authority remain host decisions.
- EPIC-23 can design a detached package around a stable signed receipt without
  reopening these event-core fields.
