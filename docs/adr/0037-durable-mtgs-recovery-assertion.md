# ADR-0037: Durable-registration MTGS recovery assertion

Status: accepted by the Project Owner on 2026-08-11. Bootstrap security/API
reviewer: `@sagrudd`. Independent audit is deferred.

## Decision

Pistis admits the additional closed Site Trust audience
`monas:site-trust:mtgs-recovery:v1` for one fresh physical-iPhone App Attest
assertion. The production acceptance factory may reconstruct an opaque,
process-local assertion acceptance only from an exact server-owned request and
the already verified durable registration's public key, reviewed-manifest
digest, bundle version and monotonic counter.

The continuation accepts no attestation object and does not re-enrol a device.
It serializes neither the acceptance nor private Apple material. Assertion
verification continues through the existing production verifier and atomic
Monas counter/fact store. Monas may use the resulting typed fact, redacted
vector and verified recipient public key only to retain its approved MTGS v2
resume envelope and attempt exactly one fixed-socket dispatch.

## Threat model

- A substituted installation, device, key, manifest, bundle, request audience,
  ceremony or counter denies before an acceptance exists.
- The audience cannot authorize normal login, product access, enrolment,
  custody rotation or generic Site Trust mutation.
- Counter advancement and fact retention remain atomic; replay or an ambiguous
  write fails closed.
- The opaque acceptance remains process-local and non-serializable.
- Monas owns recovery issuance, expiry, write-once dispatch and audit state;
  Pistis provides no retry or synthetic completion.

## Compatibility

This is an additive v1 audience and a new public factory capability. Existing
registration and assertion inputs are unchanged. `pistis-monas` advances to
0.9.0.
