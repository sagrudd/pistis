# ADR 0009: Synoptikon integration boundary

- Status: Accepted
- Date: 2026-07-24
- Owners: Pistis protocol, Synoptikon, security, identity, audit, and operations

## Context

Synoptikon must support passwordless administrator bootstrap and ordinary
authentication using Pistis. Synoptikon already owns local users, roles,
authorization, sessions, configuration, database migrations, and central
audit. Pistis owns signed challenge semantics, device and external-identity
bindings, verification policy, and authentication evidence.

The current `pistis-authentication` service is an in-memory reference. It
creates a second reference session map and resolves only a device key plus an
`active` flag. That is insufficient to prove that a device is bound to the
challenged installation, local user, external identity, key, and effective
revocation policy. ADR 0006 also defers the production COSE profile, shared
mobile fixtures, durable ceremony storage, and production transport.

Synoptikon's existing password/session browser flow exposes compatibility
tokens to JavaScript. A Pistis completion must not inherit that boundary.

## Decision

### Dependency direction

Pistis provides a framework-neutral `pistis-synoptikon` contract. It depends
only on inward Pistis domain crates and contains no Axum, Yew, Hebe,
Synoptikon, database, cookie, or central-auditor types. Synoptikon implements
the host ports and owns HTTP, presentation, persistence, migrations, normal
session issuance, authorization, and audit projection.

Any Synoptikon source dependency on Pistis must be pinned to a reviewed remote
revision and recorded in Synoptikon's internal dependency catalogue and branch
policy. Local path dependencies are development aids, not release provenance.

### Production readiness gate

The integration contract evaluates explicit evidence before a host may issue a
session. Production readiness requires all of:

- a durable, rollback-capable ceremony transaction;
- an accepted COSE profile and shared Rust/iOS/Android positive and negative
  fixtures;
- an installation signature over the exact persisted canonical challenge;
- a binding resolver that proves installation, local user, external identity,
  device, key, and effective device/key/binding revocation state;
- atomic challenge consumption, pre-authentication invalidation, normal
  Synoptikon session creation, and audit append;
- a server-side opaque session delivered only in a `Secure`, `HttpOnly`,
  appropriately `SameSite` cookie; and
- tested session invalidation for logout, expiry, relevant revocation,
  recovery, and authorization-version change.

Missing evidence produces a typed blocked or rejected outcome and no session.
The in-memory reference service, detached reference envelope, UI presence,
debug mobile build, or local `KeyInfo` report cannot satisfy this gate.

### Authentication and authorization

A successful Pistis ceremony authenticates exactly one existing local user for
the declared `authenticate-session` purpose. It grants no role, tenant,
project, data, compute, or administrative permission. Synoptikon resolves
current authorization server-side for every request or against an explicitly
invalidatable authorization generation.

Bootstrap role assignment is a separate, audited Synoptikon policy mutation.
Consequential approvals and step-up actions use separate purposes and
challenges.

### Administrator bootstrap

Bootstrap is available only when an immutable installation marker proves that
the installation has never completed bootstrap. A local-console command may
create a short-lived, single-use bootstrap capability. Only its
domain-separated hash is persisted and the plaintext is displayed once.

The capability starts enrolment only. It is not a password, session, recovery
credential, or remotely reusable setup link. Exactly one concurrent completion
may atomically consume it, verify the external identity and device binding,
create the local binding and device, assign the first administrator role, and
append audit evidence. No default password remains.

Bootstrap never reopens because the current administrator count becomes zero.
Lost-device and last-administrator recovery remain EPIC-13 scope and require a
separate accepted recovery decision.

### Challenge, QR, and polling

Initiation is same-origin, CSRF-protected, rate-limited, and bound to a
pre-authentication browser session. The authoritative challenge is durably
persisted before the installation signs its exact canonical bytes. QR is an
untrusted display transport and carries no bearer, session, provider, or
recovery credential.

Browser capability, pre-authentication session, challenge identifier, nonce,
audit correlation identifier, and authenticated session are independent
values. Direct and response-QR inputs use one bounded verification path.
Polling returns only coarse state, never verifies or consumes a response, and
cannot establish a session. Authentication pages disable caching and use
restrictive framing and content policy.

### Completion and sessions

One durable transaction must re-evaluate the exact stored binding and
revocation generation, verify the response, consume the challenge, invalidate
pre-authentication state, issue a normal Synoptikon session, and append audit
evidence. Denial, expiry, cancellation, malformed input, policy mismatch,
revocation, storage failure, audit failure, or signature failure creates no
session.

Sessions use idle and absolute expiry, rotate on authentication and privilege
elevation, and bind the local user, installation, authenticating device/key,
binding, authentication time, assurance result, and policy generation. CSRF
defence applies to every state-changing authenticated endpoint.

### Device administration

Device listing, assurance, suspension, terminal revocation, replacement
enrolment, failures, and verification-bundle export are authorization-protected
Synoptikon administration operations over the Pistis registry contract.
Suspension and revocation remain distinct. Revocation is monotonic, blocks new
authentication at its effective time, and invalidates affected active sessions
without making historic evidence unverifiable.

### Audit minimization

The security mutation and its audit append share one transaction. Audit records
use an independent non-secret correlation identifier and may retain event
type, coarse outcome/reason, installation/user/device/key/binding identifiers,
transfer class, authoritative times, policy/revocation generation, session
identifier digest, source address classification, and bounded user-agent
classification where policy requires them.

Normal audit does not retain raw login capabilities, nonce, QR frame,
canonical response, signature, provider credential, session token, cookie,
private key, bootstrap capability, password, full IP address, or full
user-agent string. Audit read/export has separate authorization, purpose,
retention, and redaction controls.

## Consequences

- Pistis authentication cannot bypass Synoptikon authorization.
- Synoptikon retains one session authority rather than importing the reference
  service's session map.
- UI and transport work can be developed against typed unavailable states
  without implying production interoperability.
- EPIC-9 cannot close until EPIC-8, the COSE/profile gate, durable adapters,
  secure server-cookie boundary, migrations, and end-to-end acceptance exist.
- GB10 verification and canonical Synoptikon documentation are required before
  host code is accepted.

## Alternatives considered

- Reuse the in-memory reference service in production: rejected because it has
  no durable transaction or complete binding/revocation policy.
- Convert the reference session ID directly into a Synoptikon session:
  rejected because it creates competing session authorities.
- Extend the JavaScript-readable compatibility cookies: rejected because
  Pistis session material must be inaccessible to JavaScript.
- Reopen bootstrap when no administrator exists: rejected as an unaudited
  recovery backdoor.
- Close QR work using the detached reference envelope: rejected by ADR 0006.

## Review evidence

Architecture review identified Synoptikon's authentication route, normal
session issuer, central auditor, Hebe configuration and three-backend migration
authorities, Yew login surface, package-version rules, dependency catalogue,
and GB10 gate. Security review supplied the bootstrap, binding, completion,
cookie, authorization, revocation, recovery, audit-minimization, and negative
test requirements captured above.
