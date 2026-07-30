# ADR 0020: Prosopikon--Pistis authority transaction

- Status: Accepted
- Date: 2026-07-27
- Decision owners: Pistis protocol, Prosopikon, Monas, Synoptikon/Mneion,
  DASObjectStore, security, and evidence maintainers
- Related issues: PIS-E19-I229, PIS-E20-I240, PIS-E20-I244; Monas #1;
  Jenkins #32

## Context

ADR 0010 establishes that Monas is the HTTP and product host and Prosopikon is
the sole authority for Monas principals and browser sessions. ADRs 0018 and
0019 establish the signed wire profile and the closed MVP authentication
payloads. Neither decision defines the durable boundary at which a verified
Pistis response becomes a normal host session.

The reference Pistis service has an in-memory session map. Reusing it in Monas
would create a competing authority, make replay protection process-local, and
allow a verified signature to be mistaken for a role or DASObjectStore grant.
Conversely, calling separate Prosopikon operations after a Pistis verifier has
accepted a response can race policy, device revocation, challenge consumption,
session issuance, and audit persistence.

The MVP requires both the Monas and Synoptikon/Mneion relying routes to use one
versioned port. The Monas route must continue to protect DASObjectStore through
its existing live Monas session boundary. Jenkins must be able to prove the
complete composition with deterministic, secret-free fixtures.

## Decision

### Ownership and dependency direction

Pistis owns deterministic parsing, COSE verification, challenge/response
semantic checks, and typed verification outcomes. It has no dependency on
Prosopikon, Monas, Synoptikon, Axum, HTTP cookies, DASObjectStore, SQL, or host
database handles.

Prosopikon owns immutable principals, principal-to-external-identity and
device-key bindings, binding and revocation generations, normal host sessions,
and the durable transaction. Monas and Synoptikon/Mneion implement the port
using their respective Prosopikon authority stores. No adapter may substitute a
username, display name, provider email, browser capability, or device key for
an immutable binding identifier.

Monas owns the versioned HTTP routes, browser presentation, CSRF and
pre-authentication state, transport polling, cookie delivery, product mounts,
and deployment lifecycle. DASObjectStore receives only its existing verified
Monas host context; it never receives a Pistis envelope, provider credential,
or independently minted bearer.

### Versioned host port

The host adapter invokes a versioned `complete_authentication_v1` operation
with:

- the exact persisted challenge record and its canonical signed bytes;
- a bounded verified Pistis response outcome, including immutable installation,
  user, device, device-key, external-identity, challenge, and audience
  identifiers;
- an opaque host-controlled idempotency key derived from the complete envelope;
  and
- non-secret, bounded request metadata needed by the host audit policy.

The operation returns one of these typed outcomes: `accepted`, `denied`,
`rejected`, `expired`, `consumed`, `unavailable`, or `internal_failure`.
`accepted` contains only a host session handle for internal cookie issuance and
a non-secret audit correlation identifier. It is never serialised by Pistis or
delivered to a product adapter. Every other outcome contains no session handle.

The adapter exposes a host-owned, versioned HTTP namespace (initially
`/auth/pistis/v1`). It must not repurpose Monas's existing generic
`/api/auth/*` compatibility routes. QR and direct transport reach the same
bounded completion operation. Browser polling reports a coarse state only and
cannot verify, consume, or issue a session.

### Atomic completion

In one authority-controlled transaction, `complete_authentication_v1` shall:

1. reload the authoritative challenge and reject an absent, expired, cancelled,
   already-consumed, wrong-audience, or substituted record;
2. re-evaluate the immutable principal binding, installation, device, key,
   assurance policy, binding generation, policy generation, and effective
   revocation state;
3. confirm that the verified response binds the exact stored canonical
   challenge digest, nonce, identifiers, purpose, and approved decision;
4. consume the challenge exactly once;
5. invalidate the relevant pre-authentication state and create exactly one
   ordinary host session with audience, authentication time, device/binding,
   and generation attributes;
6. persist the idempotency result; and
7. append minimized authority and Pistis audit records.

Any error, failed audit append, lock timeout, corruption, or unavailable store
rolls back the transaction and creates no host session. Retrying the exact
complete envelope returns its recorded outcome and must not issue another
session. A non-identical response for the same consumed challenge is rejected.

Host session invalidation on logout, expiry, binding/device/key revocation,
recovery, and relevant authorisation or policy-generation change remains a
Prosopikon responsibility. A Pistis approval grants authentication only; it
does not grant a Monas role, DASObjectStore permission, operating-system
privilege, or project capability.

### Browser and product boundary

Only Monas or Synoptikon/Mneion may translate an accepted internal session
handle to a `Secure`, `HttpOnly`, scoped, `SameSite` browser cookie. The cookie,
session token, raw provider token, raw signed payload, QR content, nonce,
signature, key material, and idempotency key are excluded from normal logs,
audit projections, browser storage, URLs, and DASObjectStore contexts.

For the Monas route, `/products/dasobjectstore` continues to require its live
Monas session and CSRF boundary. A failed Pistis operation leaves the caller
unauthenticated and must not create a product context. Existing password
routes may remain compatibility routes, but they must be visibly distinct from
Pistis and cannot be used as Pistis acceptance evidence.

### Readiness and evidence

The adapter starts in an explicit unavailable state unless the authority port,
migrations, private storage permissions, configuration, protocol revision, and
required keys are validated. Readiness endpoints disclose no identifier,
binding, provider, session, or secret.

Jenkins/Expedition is the acceptance authority for this composition. Its
four-repository dossier pins exact Pistis, Prosopikon, Monas, and
DASObjectStore commits and lockfile hashes; records the task/container digest,
commands, tests, results, artefacts, and caveats; and contains no real user,
provider, cookie, private key, or deployment credential. It must prove positive
completion, replay, denial, expiry, malformed input, substitution, revocation,
rollback, idempotency, cookie/CSRF, and DASObjectStore-boundary cases.

### Deployment boundary

Production deployment process management is a Monas concern. A cPanel
Passenger adapter may terminate HTTPS and supervise a minimal Node proxy to a
loopback-only Rust Monas process, but it does not alter this authority port or
become an identity/session authority. It requires a separate Monas deployment
ADR, owner-private state and credentials, a documented backup/restore path,
and a non-sensitive host smoke test before GitHub authentication is enabled.

## Consequences

- The two MVP relying routes share one durable transaction contract while
  retaining their distinct HTTP and database adapters.
- Monas can continue to forward only its verified live session to
  DASObjectStore.
- A verifier success is insufficient by itself to create a browser session.
- EPIC-19 may implement the port against this accepted decision. EPIC-20 host
  routes and the Jenkins dossier remain separately gated by their implementation
  tests and evidence.
- The cPanel deployment proof can proceed only as a non-sensitive operational
  smoke test and cannot be described as production authentication.

## Alternatives considered

- Reuse the Pistis in-memory service session map: rejected; it creates a
  second authority and has no durable atomic completion.
- Issue a Monas cookie directly from a Pistis verifier: rejected; Pistis has no
  host authorisation, session, or cookie authority.
- Let DASObjectStore verify Pistis responses: rejected; it bypasses the Monas
  host context and duplicates identity/session policy at a product boundary.
- Implement distinct Monas and Synoptikon completion semantics: rejected;
  changes could create incompatible security outcomes for identical signed
  messages.
- Put the Rust service directly in a public cPanel document root or CGI:
  rejected; it does not provide a reviewed persistent service lifecycle or
  adequate secret/state boundaries.

## Acceptance and implementation review

The project owner accepted this architecture and the cross-project review rule
on 2026-07-27 after review of the documented authority, transaction, product,
and evidence boundaries. That owner decision accepts the architecture; it does
not assert that any implementation has been reviewed or is production-ready.

Every implementation pull request must name the affected review roles:
Pistis protocol, Prosopikon/Monas authority, Synoptikon/Mneion where the shared
port changes, DASObjectStore product boundary, security, and Jenkins/evidence.
The PR records which roles apply and confirms authority ownership, transaction
atomicity, secret boundaries, negative-path behaviour, and exact-revision
evidence. Repository policy may prohibit author self-approval; in that case the
documented owner acceptance is the ADR decision record and implementation
reviews remain attached to the relevant code pull requests.
