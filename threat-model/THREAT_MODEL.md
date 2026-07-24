# Pistis threat model

## Scope and assets

This model covers enrolment, authentication, approval, revocation, portable
evidence, local discovery, QR transfer, and offline verification. Protected
assets are device private keys, stable identity bindings, single-use
challenges, authorization decisions, signed artefacts, audit evidence, and
installation policy.

## Actors and trust boundaries

Trusted decisions remain inside the Pistis verifier and its durable store.
Mobile secure key stores protect private keys but do not decide local
authorization. GitHub and Google authenticate external subjects; their mutable
display attributes are untrusted metadata. Browsers, QR displays, local
networks, mDNS, and notification transports carry untrusted bytes.

Synoptikon or Monas requests an action but must not forge a Pistis decision.
Administrators manage installation policy and recovery. Offline verifiers and
report recipients trust only exported, cryptographically verifiable bundles.
A compromised browser, installation, phone, rooted device, or local-network
participant is an explicit adversary rather than an implicit trusted actor.

## Threat register

| Threat | Required mitigation | Residual risk or deferral |
| --- | --- | --- |
| Replay of signed login | Atomic single-use challenge consumption; bind response to ID, nonce, user, installation, purpose and expiry | Store availability can deny service |
| Challenge or response substitution | Sign canonical context and compare every verifier-supplied binding | Compromised endpoints can misrepresent UI |
| QR replacement | Display installation, user, purpose and action on the signing device; validate signed bindings | Users may ignore warnings |
| Local-network MITM | Treat discovery as hints; authenticate protocol objects end to end | Traffic analysis remains |
| Malicious mDNS advertisement | Never derive trust from mDNS; require signed challenge bindings | Connection attempts can be diverted or delayed |
| Identity-binding substitution | Bind stable provider issuer and subject during fresh enrolment | Provider compromise is outside Pistis control |
| Mutable GitHub username | Key identities by numeric provider subject, never login name | Historic display names may become stale |
| Google email reuse/domain confusion | Key by issuer and subject; validate issuer, audience, nonce and hosted-domain policy | Provider account recovery remains trusted |
| Installer assigns wrong identity | Require an interactive, freshly authenticated enrolment statement and local confirmation | Malicious local administrator can deny service |
| Stolen unlocked phone | Require per-signature biometric/device authorization and permit rapid revocation | An already-unlocked compromised OS may sign |
| Changed biometric enrolment | Record platform state where available; re-enrol or downgrade on change | Signals vary by platform |
| Device backup/restore | Use non-exportable keys; restoration without the key requires re-enrolment | Platform backup behavior must be tested |
| Key loss or user departure | Recovery and revocation are audited, policy-controlled ceremonies | Availability depends on recovery custodians |
| Revocation after historic signature | Evaluate current authorization separately from historic validity and retain signing-time state | Recipients need current revocation data for current trust |
| Clock manipulation | Use server-issued times, bounded skew and monotonic challenge state | Fully offline freshness has inherent limits |
| Protocol downgrade | Sign version and algorithm; reject unsupported versions and algorithms | Future transitions require explicit policy |
| Canonicalisation ambiguity | Deterministic CBOR; strict decoder re-encodes and byte-compares | Decoder defects remain review targets |
| Cross-installation replay | Sign and verify installation ID | Compromised installations can misuse their own authority |
| Cross-user replay | Sign and verify intended user ID | Incorrect upstream user mapping must fail closed |
| Cross-purpose replay | Domain-separated object type and requested action | New purposes require explicit registration |
| Login reused as report approval | Distinct purpose and message schema; exact action digest for approval | Approval fatigue remains a UX risk |
| Approval fatigue | Clear device display, rate limits, cancellation and denial evidence | Social engineering cannot be eliminated |
| Denial of service | Bounded parsing, expiry, quotas and idempotent denial/cancellation | Availability is not guaranteed against privileged attackers |
| Evidence-store tampering | Signed objects, append-only audit semantics, digests and portable verification | Deletion requires external retention or replication |
| Unknown critical field | Reject unknown critical fields and unsupported object versions | Non-critical extension semantics must stay non-authorizing |
| Revoked or replaced key | Resolve key status for the relevant time and purpose | Offline verifiers may have stale status |

## Security invariants

- Approval and consumption are separate transitions.
- A terminal challenge cannot return to a live state.
- Retrying creates a new challenge identifier and nonce.
- Authentication and artefact approval are cryptographically separated.
- Parser failure, missing context, unknown critical data, and unavailable
  required assurance fail closed.
- Logs and diagnostic JSON never become signature inputs.

## Deferred validation

Independent mobile keystore testing, protocol fuzzing, penetration testing,
attestation policy, recovery ceremonies, and production rate limits are
delivered by their named later milestones. Those deferrals do not weaken the
wire-format and verifier invariants above.
