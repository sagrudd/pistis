# ADR 0040: governed Site Root authority-key replacement

- Status: Proposed
- Date: 2026-08-17
- Issue: [Pistis #461](https://github.com/sagrudd/pistis/issues/461)
- Decision owners: Pistis, Monas, Prosopikon and Thesaurophylax

## Context

Pistis now distinguishes three real failures of the enrolled Site Root
Secure Enclave key: missing, invalidated and mismatched. The existing genesis
registration is intentionally immutable and the current App Attest replacement
route requires a signature from that Site Root key. Reusing either route would
therefore make recovery impossible when the phone no longer has the enrolled
key, while resetting genesis or deleting a Keychain item would orphan the
server's authority history.

The portable-computer deployment also has more than one bounded origin. The
origin is transport configuration, not a new authority: every replacement
transaction must bind the installation, Site Trust domain, current authority
generations and the same signed identity across all configured origins.

## Proposed decision

Add a separate Site Root key-replacement protocol. It is HTTPS-only and
default-unmounted; it is not a QR flow and it does not alter the existing
genesis, first-provision or App Attest routes. The protocol presupposes at
least one already-valid package-pinned HTTPS endpoint; it cannot bootstrap a
missing certificate, origin or TLS trust configuration.

1. A fixed, selector-free operator command verifies the protected registered
   and completed genesis, the active App Attest registration/counter, the
   Prosopikon installation/device projection and a typed, package-owned
   custody/operator authorization artifact. It then records one durable
   `Requested` intent containing the old Site Root generation, candidate
   generation, installation/domain bindings, challenge and expiry.
2. Pistis creates a fresh candidate Secure Enclave key in a distinct pending
   namespace after Face ID. It signs the exact canonical replacement transcript
   and retains the canonical submission before network delivery. The old key
   remains untouched until an authenticated acceptance is received.
3. Monas is the sole system of record for the effective Site Root generation.
   It verifies the candidate proof, the active App Attest assertion and all
   genesis/Pros/custody cross-bindings. One immediate transaction consumes the
   assertion exactly once, records the candidate as staged and marks the intent
   `Accepted`; the old Site Root remains active and the candidate is not yet an
   effective authority. Genesis evidence and prior generations remain
   immutable.
4. Prosopikon and Thesaurophylax are read-only consumers of the authenticated
   Monas generation record; they do not maintain an independently mutable
   current Site Root key. Each must acknowledge the exact generation digest in
   a durable, idempotent publication record. The package-owned publisher moves
   the intent through `Accepted -> Published` only after every required
   consumer has acknowledged the same staged record and has passed its
   restart/read-only validation. A missing, conflicting or stale acknowledgement
   denies and leaves the previous generation authoritative. A final Monas
   transaction then moves `Published -> Activated` and atomically flips the old
   active generation to revoked and the staged candidate to active. Consumers
   resolve only `Activated`; the staged candidate is never served.
5. Pistis promotes the pending key only after a pinned-HTTPS authenticated
   `Activated` response. Ambiguous delivery retries the exact retained bytes or
   observes the durable result; it never regenerates a key or transcript.
6. Every Monas, Prosopikon and Thesaurophylax consumer resolves the effective
   `Activated` generation, rather than reading the genesis key directly, before
   the replacement route can be mounted or production activation can proceed.

The custody/operator authorization artifact is intentionally a required
acceptance input, not a boolean flag or an invented local token. Its exact
producer, verifier, protected path and canonical schema must be named and
accepted in issue #461 before protocol implementation starts. App Attest alone
is not sufficient recovery authority.

## Invariants and negative cases

- No database reset, genesis rewrite, private-key export, key copying, startup
  migration, caller-supplied or unpinned origin, alternate-origin authority,
  trust exception or QR fallback. Retries may use only the package-pinned
  bounded origin set and must carry the identical retained transaction bytes.
- Wrong installation/device/domain, generation, old/candidate key, App Attest
  counter, custody artifact, purpose, expiry, nonce, signature, content type,
  method, canonical encoding or trailing bytes deny without state change.
- Only one live intent exists across `Requested`, `Accepted` and `Published`.
  Expiry, denial, replay and concurrent submissions settle durably. Accepted
  retry and Observe are byte/idempotent.
- Old Site Root signatures deny after activation. The existing App Attest
  generation remains active; its assertion counter advances exactly once for
  the replacement and stale/replayed counters deny. The new effective Site
  Root generation is the only active root and subsequent App Attest replacement
  binds to it.
- Fixture Rust and Swift implementations must exercise crash-before-commit,
  crash-after-commit/lost-response, relaunch, tampering and rollback. Physical
  iPhone qualification is a final gate, not a substitute for fixture tests.
- The route, systemd unit and package remain inactive and unmounted until all
  effective-key consumers and native/package gates are qualified.

## Consequences

This gives the already-installed phone a governed recovery path without
weakening the authority that rejected the mismatched key. It is a new additive
protocol and therefore requires shared canonical vectors, specialist review,
native/package evidence and a follow-up operator guide. Until those gates pass,
the correct user-facing result remains a specific Site Root key-recovery
message and no proof submission.
