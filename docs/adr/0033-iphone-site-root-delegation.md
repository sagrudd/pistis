# ADR 0033: iPhone Site Root delegation

- Status: Accepted
- Date: 2026-08-04
- Decision owners: project owner, Pistis, Monas, and Thesaurophylax maintainers
- Security review: required before Apple App Attest or live authority activation

## Decision

Pistis uses a distinct, non-exportable P-256 Secure Enclave key for the
attended Site Root delegation profile `pistis-secure-enclave-es256-cose-v1`.
The iPhone signs the exact canonical JSON bytes of Monas
`monas.site-root-delegation.v1` using an untagged detached `COSE_Sign1` with
only protected `alg = ES256` and an exact UTF-8 device-key identifier. The
payload is CBOR `null`, external AAD is empty, and the signature is low-S
64-byte COSE `r || s`.

Monas remains the sole authority for ceremony, policy, expiry, revocation and
replay consumption. Thesaurophylax verifies the public proof only. Pistis
never exports a private key, creates a software fallback, grants authority,
or fabricates an Apple attestation claim.

The initial registration truthfully reports `secure_enclave_attestation` as
`not-asserted`. Apple App Attest is a separately versioned future attachment
requiring Apple/server validation, binding to this public signing key,
anti-replay state, privacy review and specialist acceptance.

## iPhone QR presentation and submission boundary

The iPhone scanner has a distinct, versioned presentation wrapper
`monas.site-root-delegation-presentation.v1`. It contains exactly the schema,
base64url-encoded canonical `monas.site-root-delegation.v1` bytes, a matching
device-key identifier, the exact HTTPS Monas submission path, and a bounded
reference. Unknown, duplicate, malformed, redirected, non-HTTPS, or different
path presentations are rejected. The embedded canonical delegation bytes are
not parsed and re-encoded by Pistis before signing.

After the operator reviews only redacted identifier fragments and the Monas
host, Pistis produces `monas.site-root-delegation-submission.v1` and hands the
typed request to a separately reviewed Monas submission transport. QR text is
not itself transport authority. Until an enrolled-host/session-bound transport
is implemented, the default transport is explicitly unavailable and fails
closed. This scanner is separate from the legacy `PISTIS1` v2 approval flow.

## Consequences

This is a separate profile from ADR 0018's attached 32-byte-key-id Pistis
message profile; neither profile is silently widened. The exact Monas QR and
submission wire contract is documented in Monas' Site Root delegation v1
contract. Physical-device qualification remains required for live evidence.
