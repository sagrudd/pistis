# Synoptikon integration operations

EPIC-9 is not production-ready while any gate on this page is missing. An
operator must not enable a Pistis authentication choice merely because the UI
or framework-neutral contract is present.

## Enablement gates

Before enabling Pistis in Synoptikon, retain evidence for:

1. merged and accepted EPIC-7 and EPIC-8 dependencies;
2. an accepted COSE profile and shared Rust/iOS/Android conformance fixtures;
3. an installation signing key and exact persisted-challenge signature;
4. durable challenge, binding, device, bootstrap, and policy migrations across
   every supported database;
5. atomic response verification, challenge consumption, normal Synoptikon
   session issuance, and central audit append;
6. a `Secure`, `HttpOnly`, policy-reviewed `SameSite` session cookie that is
   unavailable to JavaScript;
7. immediate new-authentication rejection and affected-session invalidation
   after revocation;
8. authorisation-negative tests proving Pistis grants no Synoptikon role;
9. fresh-install, restart, upgrade, rollback, and audit-redaction tests; and
10. native GB10 package acceptance for exact reviewed revisions.

Configuration defaults to disabled and reports a typed readiness reason. It
never silently falls back to password authentication.

## Bootstrap

Create bootstrap capability material only from the local console. Display it
once, persist only its domain-separated hash, bound its lifetime, and audit its
creation without recording plaintext. Exactly one concurrent completion may
consume it.

Bootstrap does not reopen when all administrators are lost. Do not use it for
recovery. Follow the separately accepted EPIC-13 recovery process when that
process exists.

## Audit and diagnostics

Central audit records non-secret identifiers, coarse outcome/reason, policy and
revocation generations, authoritative timestamps, transfer class, and an
independent correlation identifier. It does not record raw capabilities,
nonces, QR frames, responses, signatures, provider credentials, session
tokens, cookies, private keys, passwords, or full network/client fingerprints.

Grammateus may render a canonical verification bundle into Mnemosyne-branded
HTML or PDF. It is not a second audit database and does not manufacture missing
verification evidence.

Diagnose failures using the typed readiness item and correlation identifier.
Do not enable a bypass, reopen bootstrap, extend an expired challenge, activate
a revoked device, or create a session manually.

## CI and acceptance evidence

Jenkins is authoritative. Retain:

- framework-neutral contract logs and machine-readable results;
- exact source revisions, container digests, dependency locks, schemas, and
  migration inventories;
- targeted server, Yew, database, audit, authorisation, session, revocation,
  and accessibility results; and
- native GB10 host profile, package checksum, installation/upgrade result, and
  redacted service evidence.

An amd64 container build or cross-compilation is not GB10 acceptance. A
reference QR and detached envelope are not production mobile interoperability.
