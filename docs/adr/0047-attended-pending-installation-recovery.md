# ADR 0047: Attended recovery of a pending installation

- Status: Architecture accepted; protocol feasibility and specialist review pending
- Accepted: 2026-11-11 by Stephen, project owner, in the task chat for exact
  [Monas proposal #604](https://github.com/sagrudd/monas/pull/604) revision
  `c5cf15a1a679d872549b2a5356d86d613ed3a80c`
- Decision owners: product owner, Pistis mobile security, Monas authority,
  Thesaurophylax custody and broker authority
- Tracking issue: [#546](https://github.com/sagrudd/pistis/issues/546)

## Decision

When a B first-device operation has a retained accepted owner result but its
broker rendezvous has expired, recovery requires a fresh attended approval
bound to that exact pending operation and owner result. The operator compares
the complete transcript fingerprint, site, attempt and expiry displayed by the
physical Alma terminal and Pistis, confirms both, and approves with the
biometric-gated existing Site Root key. A fresh assertion by the exact pending
B App Attest key proves B-key possession; the shared Site Root key alone does
not. No A key, installation, selection or legacy App Attest reference is
reset, replaced or used as fallback. This supplements ADR 0046.

The fixed host must validate its protected original operation, registration,
Apple key and accepted owner result. A new independent rendezvous and old-route
fence must preserve original authority and phase lineage even if the old hosted
parent has been purged. A missing new receipt after dispatch is unknown and
must be reconciled against the exact durable staged request, never assumed to
have failed. The full design and assumptions are in Monas #604.

## Gates and limits

This is acceptance of the architecture, not of a wire format, implementation,
deployment or live ceremony. The exact paired protocol, authority ownership,
transaction and secret boundaries, counter initialization and migration across
all consumers, old-capability fence and broker authority after purge, and
original-correlation continuity need documented specialist review before
implementation. An unsigned QR or broker hostname is not host authority. The
attended fingerprint assumes the operator compares trusted local displays and
does not defeat an active relay controlling both displays.

Before use, verify the retained key's actual biometric policy on a signed
phone; exercise synthetic and signed-device B proof, wrong operation/site/key,
replay, expiry, crash and lost response, and A→B→A with A unchanged. Missing or
ambiguous evidence fails closed; this ADR does not authorise resetting or
re-enrolling A.
