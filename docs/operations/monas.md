# Monas standalone integration operations

EPIC-10 is not production-ready. The current Monas service provides
Prosopikon-backed password authentication and browser sessions, but no deployed
Pistis service, routes, CLI, or verification-to-session bridge. Operators must
not advertise the current Monas login page as Pistis login.

## Enablement gates

Retain evidence for every gate before enabling Pistis in Monas:

1. accepted EPIC-10 architecture and exact supported Pistis/Monas revisions;
2. accepted COSE profile and shared mobile/Rust conformance fixtures;
3. durable installation, trust-policy, device, challenge, binding, and
   evidence repositories with reviewed SQLite migrations;
4. atomic verification and one-time challenge consumption;
5. explicit mapping from a verified Pistis principal to the immutable
   Prosopikon principal used by Monas;
6. Monas-owned session issuance that grants no role merely because Pistis
   authentication succeeded;
7. immediate revocation enforcement and applicable session invalidation;
8. restart, concurrency, backup, restore, upgrade, rollback, and corruption
   tests;
9. offline CLI-verifier fixtures and negative cases;
10. package, configuration, service-unit, and migration documentation; and
11. Jenkins cross-repository evidence for the exact release revisions.

Configuration defaults to disabled. Readiness reports the specific missing
item and never silently falls back, creates an in-memory production repository,
or substitutes Monas password-login success for Pistis verification.

## CLI safety

Run the future `pistis` CLI as the dedicated service account with private
configuration and database directories. Never pass credentials, raw
capabilities, provider tokens, session cookies, private keys, or complete
authentication responses on the command line, where process listings and shell
history can expose them.

Offline verifier output must distinguish:

- parsed from cryptographically verified;
- signature verified from policy accepted;
- policy accepted from challenge consumed; and
- locally observed evidence from authoritative server audit evidence.

Treat unknown algorithms, unknown schema fields, malformed keys, invalid
signatures, absent trust roots, expired evidence, and unsupported versions as
failures. An `inspect` command is informational and must never return a success
exit code that an operator could confuse with verification.

## Monas and Prosopikon ownership

Monas currently delegates local accounts, password hashing, registration,
session verification, and its device-token registry to Prosopikon. Pistis must
not create a parallel password or browser-session database.

A Pistis device identity, external provider subject, and Prosopikon principal
are different identifiers. Store an explicit reviewed binding; never infer it
from a mutable username or display name. Pistis success does not bypass Monas
authorisation, CSRF checks, product audience checks, or Prosopikon session
revocation.

Keep existing `/api/auth/*` routes classified as Prosopikon compatibility
routes until an accepted migration says otherwise. Product-bootstrap fields
that currently say no device token is required do not establish Pistis
readiness.

## Diagnostics and evidence

Diagnose with a non-secret correlation identifier and typed readiness or
verification reason. Logs and evidence exports exclude:

- challenge capabilities and nonces;
- raw responses and signatures;
- provider authorisation codes, access tokens, and credentials;
- Monas/Prosopikon cookies and session tokens;
- private keys and database encryption material; and
- production personal data used as a test fixture.

An operator may retain public keys, stable non-secret identifiers, coarse
outcomes, policy/revocation generations, authoritative timestamps, and exact
software revisions according to the accepted evidence schema and retention
policy.

## CI and release evidence

Jenkins is authoritative. The cross-repository dossier must name exact Pistis
and Monas commits and retain offline verifier results, server-adapter contract
tests, dependency locks, migration inventory, and redacted logs.

Ordinary Pistis CI alone does not prove Monas integration. Ordinary Monas
password-login tests do not prove Pistis integration. A debug binary, reference
QR demonstration, container-only test, or locally started Axum process does not
prove production packaging, service hardening, appliance behaviour, or mobile
interoperability.

## Demonstration runbook boundary

This runbook covers only the bounded **Pistis → Monas → DASObjectStore →
Oikodome → Jenkins** lane. It is not the complete programme chain
(Pistis → Kyberneterion → Proxenos → Thesaurophylax → Monas → DASObjectStore →
Oikodome → Phoreus Registry → Phoreus Forge → Jenkins), which is defined in the
[programme demonstration plan](https://github.com/sagrudd/mnemosyne-programme/blob/main/DEMONSTRATION_PLAN.md).
The lane assumes the upstream entitlement, Site Trust Domain, and intrinsic
treasury work and does not define Phoreus publication. Monas/Praxis work
admission and Kubernetes Job materialisation are also outside this Pistis
contract; their evidence is required before full programme acceptance.

The run is deliberately constrained to one isolated Monas installation. It
begins with a generated Prosopikon principal and a device-approved Pistis
challenge, then issues one exact-audience Monas session. The session is used to
perform a DASObjectStore operation whose inputs, outputs, and redacted evidence
are retained. Oikodome then admits the operation to the registered private
Kubernetes seed offering, and Jenkins runs one pinned Expedition task against
that admission. Jenkins records references to the DASObjectStore objects and
all exact component revisions in its dossier.

Operators MUST treat these as separate authority transitions: Pistis proves
the device-bound human decision; Prosopikon owns the immutable principal and
Monas session; DASObjectStore owns file/object evidence; Oikodome owns compute
offering and admission; and Jenkins owns task execution evidence. No transition
may copy a browser cookie, bearer token, challenge response, or product role to
another component. A missing or stale offering, revoked device, wrong
audience, replayed challenge, unavailable object store, or failed Jenkins
authority check MUST stop the run before dispatch.

The run is not accepted from console output alone. Retain the correlation
record, machine-readable result, source and package digests, and redacted
failure evidence under the Jenkins dossier policy. A successful local QR
ceremony or Monas password login is useful development evidence but does not
ceremony or Monas password login is useful development evidence but does not
close the lane or the full programme demonstration gate.
