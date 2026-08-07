# ADR 0034: iPhone-attested Site Trust human-authority fact

- Status: Accepted
- Date: 2026-08-07
- Decision owners: project owner, Pistis, Monas, Proxenos, and security maintainers
- Related issue: Pistis #386; Monas #144; Proxenos #169

## Decision

Pistis defines `mnemosyne.pistis.site-trust-human-authority-fact.v1` as the
only portable server-side record that can carry an iPhone-attested human
decision toward the Proxenos Site Trust lifecycle gate. The fact binds all of
the following without copying a browser session, cookie, token, credential,
private key, or raw App Attest assertion:

- the exact frozen `mnemosyne.proxenos.std.v1` canonical payload bytes and
  SHA-256 digest;
- field 13's opaque intent reference and the exact wire value
  `mnemosyne.pistis.intent.v1:<reference>`;
- installation, enrolled iPhone device, registered device key, non-zero
  ceremony identifier, and host-recorded issuance time; and
- a digest of a successfully verified App Attest assertion.

The App Attest challenge digest is domain-separated and length-prefixes the
installation, device, key, ceremony, canonical payload, exact intent, and
issuance time. A later Apple verifier must validate Apple's trust chain,
organisation application identity, registered key, assertion counter, and
this exact digest before Pistis can create a verified result.

The current shipped verifier is deliberately `Unavailable`. It cannot mint a
fact, and unavailable, invalid, or mismatched attestation leaves the Monas
fact store untouched. No mock, browser, cookie, local account, PAM identity,
CLI, operating-system identity, software key, or synthetic assertion is an
authority substitute.

Monas owns durable state. Its implementation of the Pistis fact-store port
must atomically record a verified fact and atomically compare and consume it
with the correlated audit append. Consumption compares the fact identifier,
installation, device, key, ceremony, canonical-payload digest, and exact
Pistis intent, then permanently marks the fact consumed. A read-then-consume
compatibility sequence is prohibited. The only result crossing toward
Proxenos is the exact existing non-secret payload/intent/projection route;
Proxenos still validates its proof, active Site Trust state, peer identity,
and replay record.

## Consequences

- This is an additive `pistis-monas` 0.2.0 contract. It does not issue a
  Monas browser session, activate a service, establish Site Trust, or grant a
  product or operating-system role.
- The fact parser accepts only the frozen Proxenos v1 TLV grammar, pending
  state, closed audience/purpose values, printable ASCII fields, and no
  prohibited credential or secret material. Proxenos retains final runtime
  semantic validation against its protected configuration.
- Apple App Attest acceptance remains a future implementation gate requiring
  reviewed trust-bundle code and physical-iPhone evidence. Until then the
  normal outcome is unavailable and fail closed.
- `pistis-monas` 0.3.0 adds a complementary, evidence-only redacted physical
  vector port. It accepts an opaque result only from a reviewed in-process
  verifier that identifies Monas'
  `monas.apple-app-attest-verifier-profile.v1` production profile, a reviewed
  trust-anchor manifest, organisation App ID, and exact fact bindings. The
  default verifier is unavailable and the Monas-owned retention port must be
  atomic. This port does not mint a fact, activate a route, establish Site
  Trust, issue a session, or provide a substitute for an attended iPhone run.
- The Monas #144 UDS client remains unmounted until its durable fact-store,
  verified Apple path, and protected service configuration are independently
  qualified.

## Alternatives rejected

- Treat a Secure Enclave key or iOS-reported capability as App Attest:
  rejected because it lacks server verification.
- Let Monas or Proxenos synthesize a verified fact: rejected because it would
  collapse the human-authority boundary.
- Forward raw assertion bytes or an Apple receipt to Proxenos: rejected
  because Proxenos needs only the separately verified non-secret lifecycle
  input and must not become an Apple-attestation processor.
- Reuse a browser session, local user, password, PAM helper, CLI, or kernel
  UID: rejected because each is outside Pistis human authority.
