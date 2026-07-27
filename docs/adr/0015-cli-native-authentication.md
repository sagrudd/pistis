# ADR 0015: CLI-native authentication boundary

- Status: Accepted
- Date: 2026-07-26
- Decision owners: Pistis maintainers
- Security review: EPIC-16 security lane

## Context

Scientific users commonly work in local shells, remote shells, schedulers, and
headless bioinformatics environments. Requiring a browser would make the
terminal a secondary surface and would expose authentication material to
clipboard, history, process, and web-origin risks.

Pistis already has a canonical signed authentication challenge, a signed
response, QR transfer framing, and a single-use verifier. EPIC-16 must reuse
those boundaries. It must not introduce a terminal-specific protocol or a
second verifier.

The version 1 authentication schema fixes its action to
`authenticate-session`. It can bind a canonical display-context digest, but it
does not carry the complete action descriptor that a mobile application would
need to show for exact-command approval. Treating that digest alone as an
action approval would create an unsafe consent gap.

## Decision

The `pistis` command line is a primary product surface with two commands:

- `pistis auth login` requests authentication of a terminal session; and
- `pistis auth approve -- <program> [argument ...]` canonicalises the exact
  argument vector and computes a domain-separated SHA-256 digest.

Signed responses and credentials are never accepted through command-line
arguments or environment variables. A response fallback is one bounded,
control-free ASCII `PISTIS1` response line read through a protected input
adapter. Direct-local and framed responses must converge on the same
authoritative single-use verifier.

Terminal QR output is only a deterministic presentation of the existing
transfer frame. The renderer preserves a four-module quiet zone, supports
explicit ASCII and Unicode profiles, has bounded integer scaling and polarity,
emits no terminal escape sequences, and refuses to crop when the declared
terminal width is insufficient.

The CLI crate owns parsing and ceremony orchestration. Challenge signing,
device lookup, response verification, replay state, evidence retention, and
session issuance remain behind an `AuthenticationBackend`. The distributed
binary fails closed until a reviewed local backend adapter is configured; it
must not manufacture a development identity or issue a synthetic session.

Exact-action approval is a reserved command surface, not a completed security
claim. Enabling it against a production backend requires an additive,
versioned protocol document that carries the canonical action descriptor and
digest, mobile rendering and confirmation on both supported platforms, schema
fixtures, downgrade rejection, and specialist approval in a superseding ADR.
Until then the backend must reject action-approval initiation.

Session hand-off to child programs is also deferred. No bearer token is printed
or exported. A later decision must select a bounded inherited descriptor or a
local credential agent and define lifetime, audience, revocation, and child
process semantics.

## Consequences

- Login can use the existing version 1 protocol once the local authentication
  backend and enrolled mobile clients are connected.
- Parser, renderer, protected-input, and orchestration behavior can be tested
  deterministically without keys or a network.
- The CLI cannot honestly claim production login interoperability until the
  backend adapter and real iOS/Android scan-and-sign evidence exist.
- Exact-action approval and child-session hand-off remain fail-closed release
  blockers rather than being approximated with unsafe behavior.
- Jenkins can retain portable contract evidence now and must add native-device,
  dual-architecture, and end-to-end dossiers before EPIC-16 is closed.
