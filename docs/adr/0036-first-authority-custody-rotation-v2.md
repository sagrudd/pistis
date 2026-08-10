# ADR 0036: First-authority custody rotation v2

- Status: Accepted
- Date: 2026-08-10
- Decision owners: Programme owner, Pistis, Monas, and Thesaurophylax maintainers

## Context

The legacy first-device authority record is deliberately one-shot and cannot
be reopened after its process restarts. Recovery must create a new authority
custody generation without weakening the enrolled iPhone, Face ID, Secure
Enclave, App Attest, fixed Monas peer, or Thesaurophylax boundaries.

## Decision

Pistis implements only the distinct purposes
`thesaurophylax.pistis-first-device-authority-rotation.v2` and
`thesaurophylax.pistis-first-device-authority-recovery.v2`. V1 schemas,
purposes, canonical bytes and routes are not reused.

After the existing SPKI-pinned Monas App Attest assertion is accepted, the
iPhone generates a fresh random 32-byte seed and derives its Ed25519 public
commitment. The seed is immediately sealed with AES-GCM under a key derived
from an ephemeral P-256 exchange with the enrolled Site Root Secure Enclave
key. Keychain retains only the bounded ciphertext envelope with
`WhenUnlockedThisDeviceOnly`; plaintext is zeroized and is never logged,
projected into UI state, returned by an API, or persisted.

The fixed begin route is
`POST /v1/pistis/site-trust/authority-custody-rotation/v2/begin`. Its exact
body carries only the v2 schema and public recovery commitment because Monas
supplies the retained device, installation, App Attest, Site Root, legacy,
delegation, revocation and expiry bindings. Pistis reconstructs the canonical
Thesaurophylax transcript from every response field and requires a byte-exact
match before Face ID can produce detached ES256 COSE.

Pistis opens the local seed only through Secure Enclave ECDH and Face ID, then
seals it to the presented host key with ECDH, HKDF-SHA256 and AES-GCM. It sends
the opaque proof and ciphertext only to
`POST /v1/pistis/site-trust/authority-custody-rotation/v2/complete`. Success is
only an exact no-store accepted response with the same one-use correlation.
There are no redirects, cookies, bearer tokens, caller-selected URLs, browser,
QR, password, local-authority or software-key fallbacks.

An interrupted exact begin reuses the already sealed commitment; it never
silently creates a replacement seed. Ambiguous, substituted, stale, replayed
or already-consumed state fails closed and requires an attended decision.

## Verification

Simulator unit tests consume the deterministic Thesaurophylax transcript
fixture, enforce exact Monas wire keys and canonical base64url, and cover
purpose/binding tamper, expiry, correlation replay and AES-GCM AAD
substitution. A physical iPhone remains required to accept deployment: it must
prove Face ID, Secure Enclave key retention, pinned TLS, completed Monas/Thes
rotation, restart recovery and the absence of plaintext recovery material.
