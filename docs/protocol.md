# Protocol specification

This document is normative for Pistis protocol state. Concrete canonical
encoding and signature-suite selection require their own accepted ADR before
interoperable signing is implemented.

## Signed-message envelope

Every signed protocol message shall bind, in its canonical bytes:

- `version`, the protocol message version;
- `purpose`, the exact domain-separation label for the structure;
- `issued_at_ms`, the producer-controlled Unix timestamp;
- `installation_id`, the authority namespace;
- `key_id`, the signing or expected verification key;
- the complete purpose-specific payload.

Unknown versions, purposes, fields that affect meaning, algorithms, or critical
extensions must fail closed. A verifier must never reinterpret a byte string
under a different message purpose. Authentication, approval, artefact signing,
enrolment and revocation use distinct domain-separation labels and schemas.

The JSON schemas in `schemas/challenge-v1.schema.json` and
`schemas/authentication-response-v1.schema.json` are diagnostic and validation
representations, not canonical signature encodings. JSON is never accepted at
a signed protocol boundary.

## Normative structures

All fields listed here are required unless explicitly marked optional. An
identifier uses the corresponding canonical `pistis-domain` representation.
Byte strings use the canonical encoding selected by the encoding ADR. A
signature covers the common fields and every purpose-specific field.

### Enrolment intent

Purpose: `pistis.enrolment-intent.v1`.

The intent begins proof of control of an external identity and shall contain
`enrolment_id`, `provider`, `redirect_binding`, `nonce`, `expires_at_ms`, and
the requested local `user_id`. `redirect_binding` binds the exact selected
provider transport and transaction. For ADR 0025 Device Flow it binds the
profile and reviewed App-configuration digest, not a callback URI. An intent
is installation-signed. A provider, transport, user, or nonce from any other
intent must not be substituted.

### External identity binding

Purpose: `pistis.external-identity-binding.v1`.

The binding shall contain `enrolment_id`, `external_identity_id`, `provider`,
the provider's stable `issuer` and `subject`, `verified_at_ms`, and
`provider_evidence_digest`. A mutable login, display name, or email may be
included only as a non-authoritative `display_snapshot`. The binding is
installation-signed after provider evidence verification and shall reference
the exact enrolment intent.

### Device registration

Purpose: `pistis.device-registration.v1`.

The registration shall contain `enrolment_id`, `external_identity_id`,
`user_id`, `device_id`, `device_public_key`, `device_key_algorithm`,
`device_attestation_digest`, and `registered_at_ms`. It shall be signed by the
new device key and countersigned by the installation. The installation must
verify the external identity binding, proof of possession, supported algorithm,
and local policy before countersigning. An unavailable attestation is encoded
explicitly; it must never be silently treated as successful attestation.

### Authentication challenge

Purpose: `pistis.authentication-challenge.v1`.

The challenge shall contain `challenge_id`, `nonce`, `expires_at_ms`, `user_id`,
`requested_action`, `audience`, and a human-readable `display_context_digest`.
It is installation-signed. `audience` names the installation endpoint that may
accept the response. The requested action must unambiguously mean session
authentication and must not authorize an approval or artefact signature.

The EPIC-6 v1 reference schema additionally binds `issued_at_ms`,
`installation_id`, `key_id`, `external_identity_id`, installation name,
installation fingerprint, local username, and a bounded list of HTTPS endpoint
hints. `requested_action` is exactly `authenticate-session`. Names and endpoint
hints aid display and transport only; identifiers, signatures, and local policy
remain authoritative.

### Authentication response

Purpose: `pistis.authentication-response.v1`.

The response shall contain the exact `challenge_id`, `nonce`,
`challenge_digest`, `user_id`, `device_id`, `external_identity_id`, `decision`,
and `user_verified_at_ms`. `decision` is exactly `approved` or `denied`. It is
device-signed after explicit local user verification. An approved response may
be consumed only when its challenge signature, digest, nonce, identifiers,
audience, expiry, device status, and signature all validate. A denial is
evidence of the decision but never authenticates a session.

The EPIC-6 v1 reference schema additionally binds `issued_at_ms`,
`installation_id`, and the device `key_id`. Response expiry is not
claimant-controlled: completion applies the stored challenge's exclusive
expiry. The exact closed canonical-CBOR field assignments and QR framing are
defined by [ADR 0006](adr/0006-qr-authentication-reference-flow.md).

## QR authentication reference flow

QR frames are untrusted transport input. A `PISTIS1:` frame carries one closed
canonical-CBOR transport map, an exact canonical signed payload, a fixed-width
detached ES256 signature, and a truncated SHA-256 scanning checksum. The
checksum detects transcription or scanning errors; it does not authenticate
the installation, device, action, or user. The decoder rejects oversized,
fragmented, padded, non-ASCII, non-canonical, unsupported, trailing, or
wrong-kind input without downgrade.

The detached version-1 signature is an internal reference-harness boundary.
Accepted [ADR 0021](adr/0021-production-qr-envelope-and-installation-trust.md)
defines production frame version 2 as the same prefix and checksum around the
exact complete strict untagged COSE Sign1 bytes. Its decoder rejects version
downgrade and kind confusion and returns those exact bytes without re-encoding.
The COSE profile is accepted by
[ADR 0018](adr/0018-production-cose-sign1-profile.md), and production payload
field assignments are frozen by
[ADR 0019](adr/0019-mvp-signed-message-schemas.md). Approval and denial are
both signed; denial is auditable refusal and never authenticates a session.
External mobile interoperability still requires shared conformance fixtures
and retained physical-device evidence.

The accepted authenticated mobile bootstrap is specified by
[ADR 0023](adr/0023-authenticated-mobile-enrolment-exchange.md). ADR 0025
supersedes its callback, OAuth-state, PKCE, broker, and authorization-code
transport for v0.1 while retaining the invitation-bound authority bootstrap
and atomic Prosopikon transaction. An authority key returned only by an
enrolment response is not trusted: it must match the digest committed by the
administrator-issued, single-use invitation. The authority-signed mobile
receipt binds the exact device-registration COSE envelope and every
installation-trust field that iOS may store.

Direct-local and response-QR submission enter the same verification path.
Polling exposes only a coarse lifecycle state and cannot verify, consume, or
authenticate. Completion verifies the signature and every stored binding
before holding one atomic mutation boundary across challenge consumption,
pre-authentication session invalidation, authenticated-session creation,
immutable audit creation, and terminal state. A denial never creates a
session. A failed atomic mutation leaves the earlier state intact, and exactly
one concurrent completion may succeed.

The EPIC-6 service is framework-neutral and in-memory. Production HTTP, TLS,
durable transaction, installation-identity, local-policy, and operator UI
adapters remain necessary to complete milestone M5.

### Artefact challenge

Purpose: `pistis.artefact-challenge.v1`.

The challenge shall contain `challenge_id`, `nonce`, `expires_at_ms`,
`artefact_digest`, `digest_algorithm`, `media_type`, `requested_statement`,
`audience`, and `display_context_digest`. It is installation-signed.
`requested_statement` describes the precise assertion requested from the user.
The bytes identified by `artefact_digest` must remain available for review and
must not be replaced without creating a new challenge.

### Artefact response

Purpose: `pistis.artefact-response.v1`.

The response shall contain the exact `challenge_id`, `nonce`,
`challenge_digest`, `artefact_digest`, `digest_algorithm`,
`requested_statement`, `device_id`, `external_identity_id`, `decision`, and
`user_verified_at_ms`. It is device-signed after explicit local review and user
verification. Authentication responses and artefact responses are not
interchangeable even when identifiers or keys coincide.

### Revocation statement

Purpose: `pistis.revocation-statement.v1`.

The statement shall contain `revocation_id`, exactly one `revoked_subject`
(`device_id`, `key_id`, or `external_identity_id`), `effective_at_ms`,
`reason_code`, `authority_key_id`, and an optional non-authoritative
`operator_note`. It is installation-authority-signed. Verifiers shall reject
responses whose relevant device, key, or binding was revoked at or before the
response's verification time. Revocation statements are monotonic records and
must not be deleted or reinterpreted as reinstatement.

### Exported trust bundle

Purpose: `pistis.exported-trust-bundle.v1`.

The bundle shall contain `bundle_id`, `exported_at_ms`, `sequence`,
`installation_identity`, active installation verification keys with validity
intervals, external identity bindings, device registrations, revocation
statements, supported protocol versions and algorithms, and a digest over the
ordered bundle contents. It is signed by a currently valid installation export
key. Importers shall verify the signature, internal references, canonical
ordering, sequence monotonicity, and key validity before using any contained
trust. Bundles are detached verification material, not an authority to mutate
local policy.

## Challenge lifecycle

```text
created --present--> presented --claim--> claimed --approve--> approved
   |           |             |                  |                 |
   |           |             |                  +--deny--> denied |
   |           |             |                                    |
   +-----------+-------------+------------------+------------------+
                    cancel ---------------------------> cancelled

created/presented/claimed --expiry reached----------------> expired
approved/denied --atomic record and invalidate------------> consumed
```

Issuance draws an independent 256-bit nonce and 128-bit challenge identifier
from the operating-system cryptographic random generator. Challenge identifiers
use the shared `pistis-domain` `challenge_` representation. Failure to obtain
randomness aborts issuance. Expiry is calculated using checked arithmetic from
the issuer's current Unix time. A zero or unrepresentable lifetime is invalid.

The expiry is an exclusive upper bound: a challenge is valid only while
`now < expires_at`. Verifiers must use issuer-controlled time and must not
accept a claimant-provided clock value.

`created` means issued but not disclosed. `presented` means disclosed through a
transport. `claimed` means one device has begun the ceremony; claiming is not
approval and grants no authority. Explicit user verification moves the
ceremony to `approved` or `denied`. Recording either terminal decision and
invalidating the nonce moves it atomically to `consumed`.

`expired` and `cancelled` are terminal alternatives. Expiry may occur from
`created`, `presented`, or `claimed`. Cancellation may occur from any
unconsumed state under installation policy. No transition leaves `consumed`,
`expired`, or `cancelled`; a retry requires a new identifier and nonce.
Transport retries may repeat presentation but shall not roll state backwards.

Consumption is one atomic transition. The store compares identifier, expiry
and nonce and deletes the active record only after all checks succeed. An
expired record is invalidated and cannot be revived. A mismatched nonce does
not destroy the legitimate active challenge. Once consumed, all replay
attempts fail as unknown/already consumed. Implementations that persist audit
states shall retain a tombstone while still making the active nonce
unavailable.

An in-memory implementation serialises this compare-and-delete transition with
a mutex. Durable implementations must provide equivalent transactional or
compare-and-swap semantics across all verifier processes. Checking and deleting
in separate transactions is non-conformant.

## Versioning

Version numbers describe message semantics and canonical bytes, not application
release numbers. Additive changes are compatible only when old verifiers are
defined to ignore the field and the field cannot affect a security decision.
Otherwise a new protocol version and conformance fixtures are required.

A producer may emit only a version it fully implements. A verifier selects one
explicit supported version before parsing and signature verification. There is
no downgrade fallback after verification failure.

## Failure behavior

Randomness, clock, synchronisation, parsing and state-store failures fail
closed. Logs and user-facing errors must not expose nonce values. Challenge
identifiers are also treated as security-sensitive correlation data even
though they are not authentication secrets.
