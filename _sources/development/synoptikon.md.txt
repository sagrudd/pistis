# Synoptikon integration development

ADR 0009 is normative. The `pistis-synoptikon` crate is a framework-neutral
contract between Pistis verification and a host application. It is not an HTTP
server, durable authentication service, Synoptikon session issuer, or claim of
mobile interoperability.

## Dependency direction

Pistis owns canonical challenge semantics, signature and binding verification,
device policy, and authentication evidence. Synoptikon owns:

- Axum routes and Yew presentation;
- local users, roles, tenants, projects, and authorization;
- configuration and MySQL, PostgreSQL, and SQLite migrations;
- durable ceremonies and its normal server-side sessions;
- central audit projection; and
- packaging and operational recovery.

Pistis crates never import Hebe, Mneion API, Axum, Yew, SQL-driver, or
Synoptikon session types. A host adapter translates typed Pistis outcomes into
host operations after all readiness and binding gates pass.

## Login presentation contract

Extend Synoptikon's existing authentication panel; do not add a competing
shell or dashboard. Show the Pistis option only when the server reports it
enabled and ready.

The accessible state sequence is:

1. select an existing local username;
2. request a Pistis challenge;
3. present the QR with textual purpose, installation, and expiry;
4. report waiting, approved, denied, expired, cancelled, or unavailable;
5. navigate only after the server issued its normal session cookie.

Polling returns coarse status only. It does not verify, consume, expose a
response, or create a session. Status changes move keyboard focus to the state
heading and use a polite live region except for actionable errors. QR payload
bytes are not exposed as alt text; provide an equivalent nonvisual transfer
route. Password or compatibility-token fallback is visible only when host
policy explicitly permits it.

No login capability, provider token, session token, canonical response,
signature, or QR payload enters the URL, DOM, local storage, JavaScript-readable
cookie, normal logs, or user-facing errors.

## Device administration contract

Use Synoptikon's existing resource-index and task-pane pattern:

- table columns show stable device identity, linked external identity,
  words-first assurance, lifecycle state, and honest last-used state;
- the detail pane separates identity, key and assurance, activity, and
  warnings;
- suspend is reversible, while revoke is terminal and requires an impact
  review and explicit confirmation;
- replacement enrolment and verification-bundle export are separate tasks;
  and
- loading, empty, stale, permission, transport, and unavailable states are
  explicit.

Client-side visibility is never authorization. Every read and mutation is
authorized by Synoptikon on the server.

## Required contract tests

Tests use fixed identifiers and time and cover:

- every missing production-readiness item;
- wrong installation, user, external identity, device, key, binding, purpose,
  policy generation, or revocation generation;
- suspension and revocation effective exactly at verification time;
- denial, expiry, cancellation, collision, replay, and concurrent completion;
- audit correlation identifiers being distinct from bearer capabilities;
- audit failure causing no host session; and
- a successful readiness decision carrying no session token or host role.

Cross-repository tests must pin exact Pistis and Synoptikon revisions.
