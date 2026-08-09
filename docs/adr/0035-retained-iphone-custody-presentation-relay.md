# ADR 0035: Retained iPhone custody-presentation relay

- Status: Accepted
- Date: 2026-08-09
- Decision owners: Programme owner, Pistis, Monas, and Thesaurophylax maintainers
- Security review: independent review deferred during bootstrap; retain exact
  iPhone and cross-repository evidence for that review

## Context

Pistis #400 can use the enrolled Site Root Secure Enclave key to rewrap a
portable custody record. Thesaurophylax #154 deliberately releases only the
authenticated previous ciphertext and public bindings required for that work,
and only to Monas's fixed non-root peer after Monas has accepted a retained
App Attest-backed session. A generic client fetch, QR, cookie, bearer token,
browser page, local account, or local authority would sever that binding.

## Decision

The only mobile delivery is the terminal response of the already SPKI-pinned
Monas App Attest assertion ingress. Monas may return it only after one
assertion has been accepted, the corresponding session has been durably
retained, and the exact fixed Thesaurophylax peer has returned its separate
presentation frame.

The response schema is
`monas.retained-iphone-custody-presentation-relay.v1`. It carries the exact
one-use correlation, canonical challenge, selected public bindings and the
authenticated old ciphertext. It carries no seed, host private key, session
credential, user record, cookie, bearer, fallback endpoint, recovery value or
authority assertion. Pistis strictly rejects unknown fields, non-canonical
base64url, malformed values, expiry outside five minutes, and a canonical
challenge that differs from the Thesaurophylax/Pistis v1 calculation.

Pistis returns the resulting opaque proof/ciphertext only to the fixed
``/v1/pistis/site-trust/custody-rewrap/submit`` endpoint using
`monas.retained-iphone-custody-rewrap-submission.v1`. The correlation is
routing data, not a credential: Monas must bind it to the retained session,
accepted Apple key and live custody attempt before contacting Thesaurophylax.

The normal App Attest assertion result remains `202` with an empty body. A
custody ceremony uses `200` plus the exact no-store response and does not
introduce another path or endpoint. A missing, stale, replayed, non-pinned or
unexpected response fails closed. The iPhone keeps the presentation and the
recovered seed in process memory only, then passes the completed opaque
submission back through Monas's sole fixed custody peer.

## Consequences

- The iPhone cannot retrieve a presentation or submit a rewrap outside an
  existing, pinned Monas ceremony.
- Monas must implement the retained-session terminal-response composition
  before the capability can be activated.
- The physical iPhone test must prove the signed assertion, exact response,
  Face ID rewrap and custody acceptance; simulator tests cover only decoding
  and framing.
- There is no compatibility transport. Manual recovery remains separate and
  fail-closed.

## Alternatives considered

- A separate authenticated `GET`: rejected because a session credential or
  bearer-style selector would be needed.
- A QR or browser presentation: rejected because either adds an unbound human
  presentation channel.
- Returning the ciphertext before App Attest session retention: rejected
  because it permits a release before the intended authority transaction.
