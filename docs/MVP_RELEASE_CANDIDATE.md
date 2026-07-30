# Pistis v0.1 MVP release candidate

**Status:** Approved delivery baseline  
**Candidate:** `v0.1.0-rc.1`  
**Approved:** 27 July 2026

**Deployment profile amended:** 28 July 2026 by ADR 0026

## Purpose

This document defines the shortest production-credible Pistis vertical slice.
It is normative for the `v0.1` MVP programme. `MILESTONE.md` remains the
broader `v1.0` commitment; capabilities deferred here are not cancelled.

## Supported outcome

The candidate shall let one existing Prosopikon principal:

1. accept an administrator-issued, short-lived, single-use enrolment
   invitation;
2. prove one stable GitHub identity through a Mnemosyne Biosciences GitHub App
   using device flow;
3. create one device-protected signing key in the iOS application;
4. scan and explicitly approve a QR authentication challenge using Face ID;
5. authenticate through either the Monas route or the Synoptikon/Mneion route;
6. land on the Propylaion product home after Monas authentication and navigate
   to an authorised Jenkins or DASObjectStore offering without knowing its
   private host or port;
7. run an exact CLI action through a supervised, non-exportable session; and
8. export redacted authentication evidence that an offline verifier can
   validate.

Prosopikon remains the authority for immutable principals, tenants,
entitlements, browser sessions, and host authorisation. Pistis authenticates
and records approval; it does not create a parallel account or session
authority.

## Required scope

- GitHub is the sole production enrolment trust anchor.
- iOS is the sole supported mobile platform.
- QR is the mandatory fallback challenge/response transport. Open-app,
  site-local LAN discovery is also in scope; both complete the same durable
  authority transaction.
- Monas and Synoptikon/Mneion are both required relying routes.
- Propylaion is the required post-authentication home for the Monas standalone
  route. It projects installed, accessible, and ready offerings but never
  authenticates, grants access, supervises products, or proxies their APIs.
- The first required Propylaion profile contains Jenkins and DASObjectStore.
  Navigation is host-relative, reveals no private port or bearer material, and
  each selected product re-authorises the accepted Monas context.
- The Synoptikon route is implemented by the Mneion server and web deployment
  in the `mnemosyne` repository.
- Both routes use one versioned Prosopikon--Pistis authority and transaction
  port.
- Administrator-issued invitations are the sole enrolment route.
- The initial acceptance principal uses one active iOS device. The authority
  follows ADR 0012's policy-bounded multi-device model rather than encoding a
  one-device protocol shortcut.
- Lost-device recovery is revoke, invalidate sessions, and re-enrol. Private
  keys are never migrated or recovered.
- CLI sessions supervise an exact command and never print or export reusable
  bearer tokens.
- Evidence covers enrolment, authentication, exact CLI approval, Prosopikon
  session issuance, revocation, invalidation, and offline verification.
- Linux delivery uses a versioned RPM and systemd units. iOS delivery uses
  TestFlight.

## Explicit deferrals

The first candidate does not qualify:

- Android as a supported client;
- Google enrolment;
- Bluetooth discovery, closed-app notification, and WAN discovery;
- self-service account creation or inferred identity matching;
- multiple active devices or key migration;
- report, dataset, workflow, or multi-party signing;
- public production use before independent review.

Android source and local discovery may remain build-tested previews. They must
be disabled by default and cannot satisfy an MVP acceptance criterion.

## Authority and transaction boundary

Pistis performs deterministic cryptographic and policy verification. The
Prosopikon host adapter owns the final transaction and must re-evaluate the
principal binding, device state, policy generation, and revocation generation.
In one commit it shall:

- consume the single-use challenge;
- create the audience-bound Prosopikon session;
- append authority and Pistis audit records; and
- record the idempotency key.

Monas implements the port over its Prosopikon SQLite authority.
Synoptikon/Mneion implements the same port over its SQL/Hebe authority. A retry
with the same complete envelope is idempotent; no retry may create a second
session.

Browser sessions remain opaque Prosopikon sessions delivered only through
appropriately scoped `Secure`, `HttpOnly` cookies. The CLI receives a
short-lived, audience- and action-bound capability through a protected local
channel controlled by `pistis auth exec -- <command>`.

## Credential boundaries

The GitHub device flow uses only the public GitHub App client identifier and
the minimum permission needed to resolve the stable GitHub user identity.
Pistis discards the user token after enrolment and retains no refresh token.
It never accepts a personal access token, GitHub password, passkey, or
password-manager secret. Keeper or another credential provider may participate
only in GitHub's own browser ceremony.

Each Linux authentication authority selects exactly one reviewed,
non-exporting hardware provider through the provider-neutral boundary in
proposed ADR 0024. TPM2 is the first implementation and PKCS#11 is the second.
The configured provider and enrolled public key are fixed before the service
listens; absence or failure never selects an ordinary-file signer or another
provider. Ordinary Jenkins and DASObjectStore workers remain keyless.
Environment variables and command arguments are forbidden for authorisation
values. Recovery is revoke, invalidate sessions, provision a new
non-exportable key, and re-enrol; Pistis never backs up private-key material.

## Acceptance and release gates

Jenkins is authoritative for Rust, Swift-package, Android-preview,
documentation, packaging, and exact-revision cross-repository tests. The
portfolio expedition pins Pistis, Prosopikon, Monas, Propylaion, Jenkins,
DASObjectStore, and Mnemosyne revisions as applicable to each route and
retains its complete dossier.

One physical Face ID iPhone on the current production iOS major version is the
mandatory security acceptance device. A signed record bound to the exact
candidate covers TestFlight install and upgrade, Secure Enclave key creation,
Face ID approval, QR authentication, both browser routes, CLI approval,
revocation, session invalidation, and offline evidence verification. Jenkins
verifies and retains that record. Any candidate change invalidates it.

An internal release candidate additionally requires threat-model, dependency,
privacy, fuzzing, package, migration, backup/restore, corruption, concurrency,
accessibility, and negative-path acceptance. Public production release remains
blocked until independent cryptographic review and penetration testing are
complete and every critical or high finding is closed.

## Delivery epics

| Epic | Outcome | Depends on |
| --- | --- | --- |
| EPIC 17 | MVP baseline and branch stabilization | Authoritative Jenkins CI |
| EPIC 18 | Rust/iOS COSE interoperability | EPIC 17 |
| EPIC 19 | Prosopikon--Pistis authority bridge | EPIC 18 |
| EPIC 20 | Monas production authentication route | EPIC 19 |
| EPIC 26 | Propylaion standalone product home | EPIC 20 |
| EPIC 21 | Synoptikon/Mneion production route | EPIC 19 |
| EPIC 22 | iOS production qualification | EPICs 18--21 |
| EPIC 23 | Authentication evidence and offline verification | EPIC 19 |
| EPIC 24 | RPM, systemd, and operational lifecycle | EPICs 19--23 |
| EPIC 25 | Security qualification and `v0.1.0-rc.1` | EPICs 20--24 and 26 |

EPIC 16 remains the owner of CLI/local-agent completion and depends on EPICs
18, 19, and 23 for its production path.

## Critical path

```text
stabilize
  -> freeze Rust/iOS interoperability
  -> implement the Prosopikon authority bridge
  -> implement Monas and Synoptikon/Mneion host adapters
  -> land the Monas user on Propylaion and re-authorize Jenkins/DASObjectStore
  -> pass physical iOS end-to-end acceptance
  -> qualify packages and operations
  -> assemble and approve v0.1.0-rc.1
```

CLI/local-agent completion, evidence implementation, and packaging preparation
may proceed in parallel after their shared contracts are accepted.
