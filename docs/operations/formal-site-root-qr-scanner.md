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
review screen before Face ID. For first-device registration it also shows the
current non-secret stage (Secure Enclave key, Apple App Attest, Monas
delegation, Face ID signing or proof submission) and elapsed time. The fixed
broker delegation wait is bounded to 30 seconds. Terminal failures identify
the stage and whether registration, delegation, transport or completion was
rejected; they do not collapse into a generic proof message. The remaining
ceremony displays only non-secret context and a coarse terminal state:
`pending`, `completed`, `denied`, `expired` or `cancelled`.
Never place QR bytes, opaque references, submit URL query, COSE proof, public
key, Apple evidence or device identifier into history, analytics, screenshots,
clipboard, crash reports or support text.

On malformed QR, changed digest/origin/context, expired/cancelled ceremony,
network error, unavailable Secure Enclave, failed local authentication,
server denial or duplicate submission, show a safe failure state and discard
all transient data. A new Monas ceremony is required; no retry, manual repair,
local queue or offline authorisation is permitted.

## First-install QR regression gate

The first-install route carries deliberately different QR families in a fixed
host-driven order, including:

* the initial ``monas.site-root-genesis-registration-presentation.v1`` JSON
  presentation, which is routed to the Site Root/App Attest coordinator
  through the fixed ``https://install.mnemosyne.co.uk`` broker. Its opaque
  reference and correlation are relayed unchanged; the QR cannot select a
  customer host; and
* the subsequent ``monas.site-x509-first-provision-broker-presentation.v1``
  JSON presentation, which is submitted only to the fixed install broker and
  creates the reviewed native TLS profile; and
* the direct
  ``monas.site-root-bundle-receipt-provision-presentation.v1`` JSON
  presentation, which provisions the generation-bound Site Root receipt key
  through the pinned native authority. Its embedded Thesaurophylax canonical
  challenge uses one-byte tags and unsigned 32-bit big-endian field lengths;
  a route-only or 16-bit synthetic fixture is not a production-wire test; and
* the final signed ``PISTIS1`` v4/kind-3 first-device presentation, which is
  verified by ``FirstDevicePresentationV4`` before provider enrolment. When
  this presentation is captured by the generic Scan surface, Pistis opens the
  existing first-device flow and begins the bounded GitHub device exchange;
  ordinary authentication ``PISTIS1`` frames remain on the login route.

Every Monas JSON presentation must be scanned from Pistis's multi-family
``Scan`` tab. The deliberately narrow ``Enrol first device`` camera accepts
only a signed ``PISTIS1`` identity presentation. If a Monas authority frame is
shown to that camera, Pistis must identify the scanner-context mismatch and
direct the operator to the ``Scan`` tab; it must not call the structurally
valid authority presentation unsupported.

Run ``scripts/verify-first-device-qr-contract.sh`` and
``scripts/verify-host-agnostic-app-contract.sh`` in every release build.
The iOS platform tests must also pass, including the regression test proving
that the attended scanner accepts every listed family, routes a
production-shaped bundle-receipt presentation to protected review, validates
its exact 337-byte 32-bit-length canonical challenge, reports a
scanner-context mismatch precisely, and rejects a plain URL.
A build that only accepts ``PISTIS1`` is incomplete: it cannot perform the
initial Site Root ceremony on a new iPhone. A fresh-device build may perform
genesis only through the fixed broker; direct Site Root submissions remain
available only after the signed host profile is present. The native Site X.509
phase must complete before the final identity QR can be composed because that
QR is bound to the reviewed native TLS leaf.

During brokered Site X.509 approval, the review screen must distinguish the
fresh Face ID operation from subsequent waits for root unlock, issuer unlock,
acknowledgement setup and initial leaf approval. These labels are a non-secret
projection of the fixed phase enum only. A completed biometric operation must
never remain labelled ``Waiting for Face ID`` while the broker is waiting for
the attended host.

For the brokered genesis phase, the fixed origin is
https://install.mnemosyne.co.uk and the active PHP/Rust route contract is
the plural /api/first-install/v1/site-root-genesis/ family:

* POST /registrations sends exactly schema, purpose, reference,
  correlation_b64url and registration_request_b64url and receives a generic
  accepted response with HTTP 202;
* POST /delegations polls with exactly schema, purpose and
  correlation_b64url until generic ready returns delegation_b64url (or
  returns pending, expired or consumed);
* POST /proofs relays the initial static proof with exactly schema, purpose,
  correlation_b64url and proof_b64url and receives generic accepted with HTTP
  202.

The QR correlation is the sole iPhone queue handle for this contract; there is
no relay_token variant. /completions and /acknowledgements remain the
host-post/iPhone-poll phases and are not used as the initial proof POST.

## Current versus required

| Capability | State |
| --- | --- |
| Separate Secure Enclave Site Root key/proof producer | merged client boundary |
| Exact QR envelope and Monas submission contract | documented |
| Camera scanner, QR decoding and review UI | merged for the attended route |
| HTTPS submission transport/status display | merged for the attended route |
| App Attest registration/assertion | implemented behind reviewed gates |
| Monas durable live ceremony/replay service | implemented behind reviewed gates |
| Attended physical-iPhone qualification dossier | not run |

The iOS project deliberately carries no Apple team, credential, profile,
private key or service secret. Deployment uses the operator's normal Xcode/
Apple Developer signing process; none of those materials belongs in source,
configuration logs or a Monas request.
