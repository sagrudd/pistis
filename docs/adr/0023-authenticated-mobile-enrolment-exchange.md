# ADR 0023: Authenticated mobile enrolment exchange

- Status: Accepted
- Date: 2026-07-28
- Accepted: 2026-07-29
- Decision owners: Pistis protocol and mobile security, Prosopikon authority,
  Monas transport, and security review
- Tracking issue: [#318](https://github.com/sagrudd/pistis/issues/318)
- Implementation: permitted subject to the review and evidence gates below

## Context

ADRs 0003, 0019, 0020, and 0021 define GitHub enrolment, the
device-registration payload, Prosopikon authority ownership, and the iOS
installation-trust record. They do not define the one exchange that turns a
one-use administrator invitation, a validated GitHub result, and a
device-signed registration into authenticated installation trust.

Installing a key returned only by the same HTTPS response would be
trust-on-first-use. Returning fields beside the signed evidence receipt would
also let transport data diverge from authenticated data. The existing
`pistis.authentication-evidence-receipt.v1` deliberately has too few fields to
be an installation trust record and must not be overloaded.

## Decision

### Ownership and route

GitHub returns only to the registered HTTPS callback:

```text
GET /auth/github/callback
```

Monas consumes the authorization code at that callback and retains all GitHub
credentials server-side. It redirects the initiating iOS application to:

```text
pistis://oauth/callback?correlation=<opaque-one-use-value>
```

The correlation is a fresh, unpredictable, single-use value. It is bound in
server-side state to the OAuth state, the pending enrolment transaction, the
invitation digest, and the device key identifier. It is neither a GitHub
authorization code nor a bearer credential for any other operation. The
custom-scheme callback contains no OAuth code, token, PKCE value, provider
subject, invitation, or mutable identity data.

The application completes enrolment through:

```text
POST /auth/pistis/v1/enrolments/exchange
Content-Type: application/json
```

The route requires HTTPS, is never enabled on plain HTTP, and sets
`Cache-Control: no-store`, `Pragma: no-cache`, `Referrer-Policy: no-referrer`,
and a restrictive content-security policy on every response.

Monas owns the exact callback allow-list, OAuth state/correlation, PKCE broker,
the pending-attempt binding, CSRF/origin boundary, request limits, and JSON
transport. Prosopikon owns
invitation consumption, provider/principal binding, policy and revocation
generations, the atomic enrolment transaction, and authority signing. Pistis
owns canonical payloads, COSE verification, shared fixtures, and the iOS
Keychain installation boundary.

No component other than Prosopikon may decide or persist the installation,
user, external identity, or device binding. GitHub access and refresh tokens
never cross the Prosopikon transaction boundary and are destroyed after the
stable numeric GitHub subject has been validated.

### Invitation and authority-key bootstrap

The administrator issues a fresh invitation document as a closed,
deterministic-CBOR map:

| Key | Field | Type and constraint |
| --- | --- | --- |
| 0 | `version` | unsigned integer, exactly `1` |
| 1 | `purpose` | text, exactly `pistis.mobile-enrolment-invitation.v1` |
| 2 | `issued_at_ms` | unsigned integer |
| 3 | `expires_at_ms` | unsigned integer, greater than key 2 |
| 4 | `invitation_id` | 16-byte byte string |
| 5 | `invitation_secret` | 32 random bytes |
| 6 | `installation_id` | 16-byte byte string |
| 7 | `audience` | non-empty text, at most 128 UTF-8 bytes |
| 8 | `authority_descriptor_digest` | 32-byte SHA-256 digest |

The exact invitation bytes are delivered through the administrator-approved
enrolment channel and are sensitive bearer material. They never appear in a
URL, log, audit record, screenshot retained as evidence, or response.
Prosopikon stores `SHA-256(exact invitation bytes)`, not the secret. Expiry is
an exclusive authority-clock bound. The invitation is installation- and
audience-specific and may be consumed only once.

The authority descriptor is a closed deterministic-CBOR map:

| Key | Field | Type and constraint |
| --- | --- | --- |
| 0 | `version` | unsigned integer, exactly `1` |
| 1 | `purpose` | text, exactly `pistis.authority-key-descriptor.v1` |
| 2 | `authority_key_id` | 32-byte byte string |
| 3 | `authority_public_key` | canonical 33-byte compressed SEC1 P-256 point |
| 4 | `algorithm` | integer, exactly `-7` |

`authority_descriptor_digest` is SHA-256 of the exact canonical descriptor
bytes. The response key is authenticated only when its exact descriptor
matches this invitation commitment. HTTPS, DNS, a QR scanned from an
untrusted login page, or a previously unseen key cannot replace that
commitment.

### Strict request transport

The request is one JSON object with exactly these members:

```text
version                         integer, exactly 1
invitation                      base64url without padding, decoded <= 512 bytes
correlation                     base64url without padding, decoded 32 bytes
device_registration_cose        base64url without padding, decoded <= 2,048 bytes
```

Unknown, duplicate, missing, mis-typed, padded-base64, non-canonical
base64url, malformed UTF-8, trailing input, and bodies larger than 8,192 bytes
are rejected before provider exchange. The callback URI, client identifier,
OAuth code, PKCE verifier, OAuth `state`, provider credentials, and local
attempt are server-held state and are never accepted from this body.

The server consumes the correlation only in the atomic enrolment transaction
and only after its pending-attempt bindings match the submitted invitation and
device registration. A failed transaction does not make the correlation
reusable for a different request; an exact retry is governed solely by the
idempotency result described below.

`device_registration_cose` is the exact untagged COSE Sign1 envelope from ADR
0018 containing the ADR 0019 `pistis.device-registration.v1` payload. Its
`invitation_digest` is SHA-256 of the exact decoded invitation bytes. The
device key identifier must equal the ADR 0018 key identifier derived from the
canonical compressed public key. Re-encoding either envelope or payload before
signature or digest verification is prohibited.

### Signed mobile enrolment receipt

Acceptance creates a new closed payload rather than changing the ADR 0019
evidence receipt in place. Purpose is
`pistis.mobile-enrolment-receipt.v1`; all fields are mandatory:

| Key | Field | Type and constraint |
| --- | --- | --- |
| 0 | `version` | unsigned integer, exactly `1` |
| 1 | `purpose` | exact purpose text |
| 2 | `issued_at_ms` | authority-clock Unix epoch milliseconds |
| 3 | `expires_at_ms` | greater than key 2 |
| 4 | `evidence_id` | 16-byte identifier |
| 5 | `installation_id` | 16-byte identifier |
| 6 | `installation_name` | trimmed display text, at most 128 UTF-8 bytes |
| 7 | `audience` | non-empty text, at most 128 UTF-8 bytes |
| 8 | `installation_key_id` | 32-byte identifier |
| 9 | `installation_public_key` | canonical 33-byte compressed SEC1 P-256 point |
| 10 | `installation_key_algorithm` | integer, exactly `-7` |
| 11 | `installation_fingerprint` | 32-byte SHA-256 digest of key 9 |
| 12 | `authority_key_id` | 32-byte identifier |
| 13 | `user_id` | 16-byte identifier |
| 14 | `external_identity_id` | 16-byte identifier |
| 15 | `device_id` | 16-byte identifier |
| 16 | `device_key_id` | 32-byte identifier |
| 17 | `device_public_key` | canonical 33-byte compressed SEC1 P-256 point |
| 18 | `device_key_algorithm` | integer, exactly `-7` |
| 19 | `key_assurance` | exact ADR 0019 assurance text |
| 20 | `registration_envelope_digest` | SHA-256 of exact registration COSE bytes |
| 21 | `policy_generation` | unsigned integer |
| 22 | `revocation_generation` | unsigned integer |
| 23 | `active` | boolean, exactly `true` on issuance |
| 24 | `last_confirmed_at_ms` | authority-clock time, not before key 2 |
| 25 | `allowed_https_hosts` | 1..16 canonical lower-case ASCII DNS names |

The authority signs this exact canonical payload using the strict ADR 0018
COSE profile. Its protected `kid` must equal key 12. Host names contain no
scheme, port, path, wildcard, trailing dot, IP literal, Unicode, or
internationalized spelling; an internationalized name is configured and
signed only in its lower-case ASCII A-label form. Entries are unique and
ascending by encoded byte order.

The receipt expiry is the installation-trust refresh bound, not device
revocation expiry. Current policy and revocation generations still have to be
checked by the authority for every online ceremony.

### Strict success response

Success is one JSON object with exactly:

```text
version                         integer, exactly 1
authority_descriptor            base64url of exact descriptor bytes
device_registration_cose        base64url of exact request envelope bytes
mobile_enrolment_receipt_cose   base64url of exact authority-signed receipt
```

The encoded response body must be at most 16,384 bytes. It contains no OAuth
code or token, correlation, invitation, invitation secret, PKCE value, session
bearer, browser cookie, private key, or mutable provider display value.

iOS must verify, in order and before any Keychain mutation:

1. exact response shape, bounds, and canonical base64url;
2. descriptor digest against the pending invitation commitment;
3. descriptor key identifier against its canonical public key;
4. receipt COSE `kid`, ES256 signature, purpose, canonical payload, and time;
5. installation, audience, authority, user, external-identity, device, key,
   assurance, generation, active-state, and host fields;
6. the receipt registration digest against the exact returned/requested
   registration envelope; and
7. the registration signature and every registration field against the
   locally generated device key and pending invitation.

Only one atomic `installAuthenticated` Keychain operation may follow all
checks. Failure preserves the earlier Keychain state.

### Atomicity, retry, and privacy

Prosopikon computes the idempotency fingerprint as SHA-256 of the exact
deterministic-CBOR encoding of:

```text
{
  0: "pistis.mobile-enrolment-exchange.v1",
  1: bstr .cbor exact-invitation-bytes,
  2: bstr .cbor exact-device-registration-cose-bytes
}
```

The map is closed and its integer keys are encoded in ascending order. An
accepted transaction atomically consumes the
invitation, persists the provider/principal/device binding and exact receipt,
and records the idempotency result. An identical retry returns the byte-exact
same descriptor, registration envelope, and receipt without contacting GitHub
again or creating another row. A different request for a consumed invitation
is rejected. Concurrent requests have exactly one committing transaction.
Provider success followed by transaction failure consumes no invitation and
creates no durable binding.

All pre-commit failures return the same HTTP status and bounded generic error
body. Callers cannot distinguish unknown, expired, consumed, wrong-user,
provider, registration, or policy failures. Rate-limit responses may include
only a coarse retry interval. Logs and audits contain a generated correlation
identifier and coarse outcome, never request bodies, exact envelopes, secrets,
provider tokens, PKCE values, or stable provider subjects.

## Conformance and evidence

One synthetic fixture corpus must contain exact invitation, descriptor,
device-registration payload and COSE, receipt payload and COSE, request JSON,
and response JSON bytes. Rust and Swift must consume the same files.

Negative fixtures cover every unknown/duplicate/missing/type/bound failure;
wrong invitation, descriptor, `kid`, key, signature, purpose, audience, host,
digest, generation, assurance, and time; replay and non-identical retry;
provider substitution; expiry; transaction rollback; restart; concurrency;
and verification failure before Keychain mutation. Fixtures contain only
synthetic keys, identities, codes, and tokens.

Jenkins must retain exact-revision Pistis, Prosopikon, Monas, and iOS-portable
evidence. A separate signed physical-iPhone record proves Secure Enclave key
production, Face ID, system-browser callback, exchange, verification, and
Keychain installation. Neither fixture evidence nor this ADR establishes
production readiness.

## Rotation, revocation, and recovery

Authority-key rotation requires a new administrator-approved invitation whose
descriptor commitment names the new key; no enrolment response may silently
roll the authority key. Installation signing-key rotation and a stale,
expired, inactive, or generation-mismatched trust record require an
authenticated refresh protocol or re-enrolment. That refresh protocol is not
defined here.

Device loss is revoke, invalidate sessions, and issue a fresh invitation.
Backups may retain public receipts and audit records, but never invitation
secrets, OAuth tokens, PKCE verifiers, or device private keys.

## Consequences

- The trust bootstrap is explicit and is not derived from the exchange
  response alone.
- The signed receipt contains every field iOS stores as installation trust.
- Existing ADR 0019 v1 payloads remain byte-compatible.
- Prosopikon PR 16 and Monas PR 14 remain login-ceremony inputs; neither
  implements this enrolment exchange.
- Issues 315 and 318 remain implementation-blocked until specialist review
  accepts this ADR.

## Rejected alternatives

- Trust the authority key returned over HTTPS: trust-on-first-use.
- Add fields to the closed ADR 0019 evidence receipt: incompatible v1 change.
- Store unsigned response fields beside a minimal receipt: substitution risk.
- Put OAuth or invitation secrets in the receipt: credential disclosure.
- Let Monas persist enrolment or let iOS decide the binding: competing
  authority.
