# ADR 0022: Host-owned CLI agent authority port

- Status: Proposed
- Date: 2026-07-28
- Decision owners: Pistis, Prosopikon, Monas, CLI and mobile maintainers
- Specialist review: required before production activation
- Related review: mobile/web QR transport ADR 0021

## Context

ADR 0017 places the CLI behind an owner-only local agent and requires one
authority adapter beside Prosopikon. ADR 0020 gives Prosopikon ownership of the
atomic challenge, binding, session and audit transaction.

The integrated code does not connect those boundaries. The Monas durable
adapter under review accepts a private *already verified* completion handoff
and intentionally performs no Pistis signature verification. Its login intent
does not contain the exact installation-signed QR transfer. Merged Prosopikon
has no versioned operation accepting a raw signed mobile response or returning
coarse status and cancellation to the local agent.

Building a file watcher or status spool around those gaps would create a second
ceremony state machine and leave restart, replay and cancellation ownership
ambiguous. Prosopikon PR 10 and Monas PR 5 are review inputs, not merged
production contracts. ADR 0021 must carry the same signed challenge and
response; this port must not define another wire format.

## Decision

Introduce a narrow, versioned, host-owned port with four credential-free
operations:

1. `begin_login` atomically creates and stores a signed authentication
   challenge and returns an opaque reference, exact signed QR transfer, bounded
   trusted display text and authority-clock expiry;
2. `submit` accepts the reference and unchanged bounded signed response, then
   verifies and completes through the one Prosopikon transaction;
3. `status` returns only pending, completed, denied, expired or cancelled; and
4. `cancel` makes a pending challenge terminal in the same authority.

The Rust proposal is `pistis_agent::HostAgentAuthorityPort`. Its types enforce
transport and terminal-safety bounds but do not verify cryptography. The host
implementation reuses the common Pistis verifier and Prosopikon transaction.
It never returns a bearer, cookie, role, username or product identity to the
agent or CLI.

The phone may return the response through ADR 0021's authenticated local
transport or the framed fallback. Both invoke the same `submit`. Discovery and
QR endpoint hints remain metadata, never authority.

## Ownership and restart

Prosopikon owns the reference, signed challenge, expiry, response fingerprint,
terminal state, idempotency, session/action issuance and audit. Monas owns
browser pre-authentication, Origin/CSRF checks, its HttpOnly cookie and product
authorization. The agent owns only its protected listener and presentation.
The CLI owns no durable state.

Restart reopens the same Prosopikon rows. It cannot reconstruct pending state
from IPC files, memory or QR. Repeated `status`, identical `submit`, or
`cancel` projects the durable result under Prosopikon idempotency rules. A
different response for the same reference fails closed.

IPC may queue bounded requests, but queued data has no lifecycle authority.
Loss or corruption returns unavailable and cannot resurrect a terminal row.
Owner-only Unix modes and kernel peer credentials remain mandatory.

## Exact action

This proposal enables login only. `auth exec` remains fail-closed until the
accepted action descriptor is implemented end to end, the phone displays and
signs it, and the host returns a short-lived single-use child capability over
a protected channel. Login completion is never action authority.

## Deployment gate

No production daemon is activated by this Proposed ADR. A package may install
a disabled service template, but startup must fail unless:

- this ADR is Accepted after specialist review;
- the exact Prosopikon implementation passes authority conformance;
- Monas implements the port against that same reviewed revision;
- agent socket and authority service ownership agree;
- installation signer and mobile response verifier are configured;
- ADR 0021's physical iOS path passes; and
- Jenkins retains exact-revision CLI-to-Monas-to-DASObjectStore evidence.

There is no environment bearer, development signer, in-memory fallback,
agent-side password fallback, or partially configured mode.

## Compatibility

This proposal adds no signed field, persistent schema, HTTP route or active
service. `HOST_AUTHORITY_PORT_VERSION` versions implementation review, not the
signed protocol. Signed-message changes still require ADR 0018/0019 fixtures
and specialist approval.

Release pins must use eventual merged Prosopikon, Monas and Pistis revisions,
not the current review heads.

## Required tests

Before acceptance and activation, retain:

- bounds and terminal-injection negatives for every projection;
- real SQLite begin/status/submit/cancel, denial, expiry and restart tests;
- concurrent and substituted-response rejection;
- direct-local and framed input convergence on one durable row;
- absence of bearer, cookie, private key and raw response in CLI output;
- Monas session and DASObjectStore authorization only after completion;
- cancellation and restart without resurrection; and
- physical iOS scan, signing and response-return evidence.

## Consequences

- The missing integration is explicit instead of hidden behind a fixture.
- Prosopikon remains the only lifecycle and session authority.
- CLI polling becomes deployable after a host implements the accepted port.
- Premature systemd/RPM enablement and `auth exec` remain blocked.
- Prosopikon and Monas each require a small reviewed adapter.

## Rejected alternatives

- Use the private handoff spool as ceremony state: competing authority.
- Return a browser bearer through the agent: secret exposure.
- Persist verified state in both agent and Prosopikon: partial-commit risk.
- Poll the public web route from CLI: violates the CLI-only requirement.
- Treat login as exact-action approval: consent and binding failure.

