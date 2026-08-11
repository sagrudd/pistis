# Formal Site Root QR scanner

Status: approved delivery architecture. The merged iOS proof producer is a
strict client boundary; it is **not** a live scanner, transport client, Apple
attestation claim, or authority. The live result remains `not_run`.

## What Pistis must do

Pistis is the iPhone-only signer in the approved chain. It scans exactly one
`PISTIS1:` payload with schema `pistis.site-root-delegation-qr.v1`, validates
the complete canonical-CBOR envelope, shows the Monas-provided Site Trust
Domain, purpose, origin and absolute expiry, obtains fresh local user
authentication, and signs the exact supplied canonical JSON delegation bytes.
It sends one request only to the exact HTTPS `submit_url` embedded in that QR.
It must not follow redirects, accept another origin, reconstruct an endpoint
from text, or reuse a reference/proof after a terminal result.

The exact Monas v1 route family is:

```text
POST /auth/pistis/site-root-delegations/v1/begin
POST /auth/pistis/site-root-delegations/v1/submit
GET  /auth/pistis/site-root-delegations/v1/status
POST /auth/pistis/site-root-delegations/v1/cancel
```

Only Monas begins, stores, consumes, finalises and cancels a ceremony. The
iPhone calls the QR's `submit` route; it does not call `begin`, `status` or
`cancel` as an authority. An iPad is display/status-only and may not sign,
submit, finalise, cancel, retain or convert QR material into authority.

## Key and proof profile

ADR-0033 defines a distinct Site Root P-256 Secure Enclave key namespace. It
is separate from the ordinary human-approval key, is never exported, has no
software fallback, and uses fresh Face ID/local authentication for each proof.
The proof is an untagged detached `COSE_Sign1` with protected ES256 and exact
UTF-8 `kid`, empty unprotected headers, CBOR-null payload, empty external AAD,
and canonical low-S 64-byte `r || s` signature. The payload is the *exact*
canonical delegation bytes supplied by Monas; the app must not parse and
re-encode it.

The current registration marker is `secure_enclave_attestation: not-asserted`.
This says only that the app makes no App Attest claim. A P-256 public key or a
Secure Enclave client API is not server-verifiable hardware attestation.

## App Attest requirement

Before a live Site Root scanner is enabled, Pistis must implement the reviewed,
separately versioned registration and assertion exchanges:

1. Create an App Attest key and obtain an Apple attestation object using the
   exact fresh Monas registration challenge.
2. Bind the verified registration to the approved app identifier, Site Trust
   Domain and the distinct Site Root signing key.
3. Produce a fresh assertion for each delegation over the SHA-256 of the exact
   canonical delegation bytes.
4. Submit only the documented public evidence; never a private key, biometric
   data, device name/serial, credentials or a long-lived secret.

Monas, not Pistis, validates Apple material and atomically consumes durable
registration/assertion replay state. If the server does not advertise the
reviewed App Attest profile, Pistis must display unavailable and refuse to
produce a live authority proof. It must not fall back to the existing
`not-asserted` v1 proof for a live claim.

## User experience and privacy

The scan surface needs accessible camera permission rationale and an explicit
review screen before Face ID. It displays only non-secret context and a coarse
terminal state: `pending`, `completed`, `denied`, `expired` or `cancelled`.
Never place QR bytes, opaque references, submit URL query, COSE proof, public
key, Apple evidence or device identifier into history, analytics, screenshots,
clipboard, crash reports or support text.

On malformed QR, changed digest/origin/context, expired/cancelled ceremony,
network error, unavailable Secure Enclave, failed local authentication,
server denial or duplicate submission, show a safe failure state and discard
all transient data. A new Monas ceremony is required; no retry, manual repair,
local queue or offline authorisation is permitted.

## Current versus required

| Capability | State |
| --- | --- |
| Separate Secure Enclave Site Root key/proof producer | merged client boundary |
| Exact QR envelope and Monas submission contract | documented |
| Camera scanner, QR decoding and review UI | not implemented for this profile |
| HTTPS submission transport/status display | not implemented for this profile |
| App Attest registration/assertion | contract only |
| Monas durable live ceremony/replay service | not implemented |
| Attended physical-iPhone qualification dossier | not run |

The iOS project deliberately carries no Apple team, credential, profile,
private key or service secret. Deployment uses the operator's normal Xcode/
Apple Developer signing process; none of those materials belongs in source,
configuration logs or a Monas request.
