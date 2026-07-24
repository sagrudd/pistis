# ADR 0006: QR authentication reference flow

- Status: Accepted
- Date: 2026-07-24
- Owners: Protocol, transport, authentication, and security

## Context

EPIC-6 requires deterministic QR challenge presentation, response decoding,
browser polling and completion boundaries, and an offline acceptance harness.
QR data is attacker-copyable and may be photographed, replaced, replayed, or
submitted concurrently. A checksum can detect scanning errors but cannot
authenticate a device or installation.

The EPIC-6 issue hierarchy covers five transport and reference-flow tasks. It
does not provide the production HTTP server, durable challenge/session/audit
transaction, installation identity, or local-user policy required to complete
all of milestone M5. Those dependencies remain separate M4 and M5 work.

ADR 0001 reserves COSE structures for interoperable signatures. The current
reviewed verifier accepts exact canonical payload bytes and a detached
fixed-width ES256 signature, but the repository does not yet implement a COSE
Sign1 parser or producer. EPIC-6 must exercise the existing verification
boundary without silently declaring its detached test envelope to be the
future mobile interoperability format.

## Decision

### Reference-flow scope

EPIC-6 provides two narrowly responsible crates:

- `pistis-qr` owns bounded QR framing, parsing, checksum validation, and QR
  matrix rendering. It makes no trust decision.
- `pistis-authentication` owns closed challenge/response schemas and a
  framework-neutral, in-memory reference service for initiation, submission,
  polling, completion, cancellation, session rotation, and audit evidence.

The service API represents the semantics of browser endpoints but is not
described as a production HTTP implementation. A later server adapter must add
TLS, content-type and request-size enforcement, cache-control, rate limiting,
cookies, CSRF protection, persistence, and operational metrics without
changing these state semantics.

### QR transport frame

A v1 transfer string is:

```text
PISTIS1:<unpadded-base64url-canonical-frame>.<checksum>
```

The canonical frame is a closed deterministic-CBOR map:

- field `0`: transport version `1`;
- field `1`: kind `1` for challenge or `2` for response;
- field `2`: exact canonical signed payload bytes; and
- field `3`: fixed-width 64-byte ES256 signature used by the reference flow.

The checksum is the lowercase hexadecimal encoding of the first eight bytes of
SHA-256 over the ASCII prefix and encoded frame body. It provides scanning
error detection only. It grants no authority and is never substituted for
signature verification.

The decoder validates ASCII, prefix, total length, alphabet, absence of
padding, checksum, canonical CBOR, exact fields, version, kind, payload bound,
and signature width before returning bytes. Challenge and response kinds are
not interchangeable. The maximum transfer text is 2,331 bytes, matching a
single version-40 QR symbol at error-correction level M. V1 does not fragment,
compress, normalize, or downgrade a transfer.

Rendering uses a reviewed QR implementation in byte mode with error correction
M. The transport crate exposes a deterministic module matrix and text frame;
camera/image acquisition remains a platform adapter responsibility.

### Authentication payloads

The v1 authentication challenge is a closed canonical-CBOR map containing:

- protocol version and exact purpose
  `pistis.authentication-challenge.v1`;
- issuer-controlled issue and expiry times;
- installation identifier and signing-key identifier;
- challenge identifier and 256-bit nonce;
- local user and required external-identity identifiers;
- action `authenticate-session`;
- bounded audience, installation name, local username, and display-context
  digest;
- installation fingerprint; and
- at most two bounded HTTPS endpoint hints.

The v1 authentication response is a closed canonical-CBOR map containing:

- protocol version and exact purpose
  `pistis.authentication-response.v1`;
- issue and user-verification times;
- target installation and device key identifiers;
- challenge identifier, nonce, and SHA-256 digest of the exact challenge
  canonical bytes;
- local user, device, and external-identity identifiers; and
- decision `approved` or `denied`.

All fields are critical. Missing, additional, duplicated, non-canonical,
ill-typed, oversized, unsupported, or out-of-range fields fail closed. The
response does not supply authoritative expiry. Completion uses the stored
challenge expiry and bindings.

The detached signature pair in the reference frame is explicitly an internal
EPIC-6 harness format. It does not supersede ADR 0001 or freeze a production
mobile signing envelope. A separately accepted COSE ADR and conformance
fixtures are required before external mobile interoperability is claimed.

### Browser reference state

Initiation creates independent opaque browser and pre-authentication session
capabilities plus a stored authoritative challenge. Neither capability nor the
QR contents authenticates a session.

The state machine is:

```text
pending -> response-available -> completed
   |              |
   +--------------+-> denied
   +--------------+-> failed
   +--------------+-> cancelled
   +--------------+-> expired
```

Submission through direct-local or response-QR mode enters the same bounded
ingestion path. One response may be staged. An identical retry is idempotent;
a different concurrent response conflicts without replacement.

Polling returns only a redacted lifecycle state. It never returns the nonce,
response, signature, browser capability, session identifier, or audit record,
and it never verifies, consumes, or authenticates.

Completion requires the matching browser and pre-authentication capabilities.
It validates the frame and closed response schema, signature, exact challenge
digest, nonce, installation, user, external identity, audience, expiry, and
active device/key policy before mutation. Denial never establishes a session.

The in-memory reference repository holds one lock while it atomically consumes
the challenge, invalidates the pre-authentication capability, creates a fresh
authenticated-session identifier, records an immutable audit event, and marks
completion. Injected failure leaves the earlier state unchanged. Exactly one
concurrent completion succeeds. Production persistence must provide the same
transactional guarantee before this reference implementation is adapted.

Terminal states reject subsequent submission and completion. A new ceremony
uses a new challenge, nonce, browser capability, and session capability, so a
photographed old response cannot authenticate a new session.

### Failure disclosure and operational behavior

Public outcomes are deliberately coarse: malformed or oversized input,
expiry, wrong binding, unknown or inactive device, verification rejection,
conflict, and unavailable state. Logs do not contain transfer bodies, nonce,
signature, private key, session capability, provider credential, or complete
challenge identifier.

Endpoint hints are signed display/transport metadata, not authority. Even
after signature verification a server or mobile adapter applies its own HTTPS
and local-network policy.

## Consequences

- EPIC-6 obtains deterministic visual transport and an offline, testable
  browser/device reference ceremony without introducing an HTTP framework.
- Challenge and response substitution, corruption, replay, and concurrent
  completion have explicit fail-closed behavior.
- The reference service demonstrates session rotation and audit binding, but
  its in-memory state is not production durability.
- Both direct-local and response-QR paths share verification semantics.
- Production COSE, HTTP, durable storage, installation identity, policy, and
  operator UI remain required before milestone M5 is complete.
- The existing incomplete diagnostic challenge schema must be replaced by
  closed EPIC-6 diagnostic schemas; diagnostic JSON remains non-normative.

## Alternatives considered

- Treat a checksum as authentication: rejected because anyone can recompute
  it after substitution.
- Put a URL-only bearer secret in the QR: rejected because a photograph would
  become sufficient to authenticate.
- Use a generic JSON payload: rejected because signed protocol bytes are
  deterministic CBOR and JSON normalization is ambiguous.
- Permit fragmentation or compression: rejected because they expand parser and
  denial-of-service risk in v1.
- Add Axum now: rejected because endpoint semantics can be tested without
  coupling the protocol to one server runtime.
- Claim detached signatures as final COSE interoperability: rejected because
  that would contradict ADR 0001 without implementing COSE structures.
- Claim milestone M5 complete: rejected because its durable production
  prerequisites are outside issues 74 through 80.

## Review evidence

Independent protocol, browser-flow, and acceptance/security reviews were
completed before implementation. They required strict bounded framing, closed
schemas, authoritative stored challenge bindings, redacted polling, atomic
session rotation and audit creation, replay/concurrency tests, actual QR
rendering, both transfer modes, and an explicit distinction between EPIC-6 and
the broader M5 exit gate.
