# ADR 0003: GitHub trust-anchor enrolment

- Status: Accepted
- Date: 2026-07-24
- Owners: Trust, protocol, and mobile security

## Context

Pistis needs a durable GitHub identity binding without making GitHub available
during routine local authentication. A GitHub login is mutable, OAuth bearer
tokens are powerful transient credentials, and a native mobile application
cannot keep a client secret confidential.

GitHub supports authorisation-code PKCE with the `S256` challenge method.
GitHub's published OAuth App token-exchange documentation nevertheless lists a
client secret as required. That provider constraint must not cause Pistis to
embed a shared secret in a public application binary.

## Decision

GitHub enrolment uses the system browser and authorisation-code flow with:

- a fresh, high-entropy PKCE verifier and `S256` challenge;
- a fresh, high-entropy `state` value bound to one local enrolment attempt;
- an exact, pre-registered callback URI;
- an empty OAuth scope request for the authenticated-user endpoint;
- immediate retrieval of `GET https://api.github.com/user`;
- the response's numeric `id` as the stable provider subject; and
- the `login` and other consented profile values only as display snapshots.

Pistis is a public PKCE client. It does not contain, receive, log, or transmit
an OAuth client secret. Because GitHub currently requires that secret at token
exchange, the platform token transport crosses an operator-controlled
confidential broker boundary. The broker holds the environment-specific secret,
accepts only the registered client ID, exact callback, one-use code, and PKCE
verifier, and never decides the resulting subject or persists the access
token. Direct mobile exchange fails closed. Selecting GitHub's device flow or
expanding the broker beyond this exchange requires a separate security review
and ADR.

The callback is accepted only once and only when its scheme, authority, path,
`state`, and local attempt identifier exactly match the pending attempt.
Cancellation, mismatch, expiry, replay, malformed responses, and network
failure produce no trusted binding.

The access token exists only long enough to fetch and validate the
authenticated-user response. It is then removed from memory on every terminal
path and is never written to logs, evidence, backups, analytics, or persistent
storage. The durable binding retains the provider authority, numeric subject,
selected display snapshots, provider response time, authentication time, and
the device-key binding evidence.

## Consequences

- A GitHub username change cannot change or invalidate the stable identity.
- Routine authentication is local and does not depend on GitHub availability.
- Reauthentication is required for initial enrolment, rebinding, replacement
  or recovery devices, administrator-requested revalidation, and any
  policy-required metadata refresh.
- The enrolment ceremony has a temporary online dependency on the confidential
  exchange broker; routine local authentication remains independent.
- Test fixtures use synthetic identities and tokens only; live GitHub accounts
  and public-network calls are excluded from deterministic CI.

## Alternatives considered

- Embed the OAuth App client secret: rejected because a native application is
  a public client and cannot protect a shared secret.
- Use the mutable login as the subject: rejected because account renames would
  cause identity confusion.
- Retain the access token for later refresh: rejected because routine local
  authentication does not need provider access.
- Use an embedded web view: rejected because Pistis must not capture provider
  credentials and should preserve the system browser's security context.
- Attempt secretless direct exchange: rejected because GitHub's current token
  endpoint contract requires the OAuth App client secret even with PKCE.
