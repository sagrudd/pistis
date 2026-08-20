# ADR 0040: governed Site Root authority-key replacement

- Status: Proposed
- Date: 2026-08-17
- Issue: [Pistis #461](https://github.com/sagrudd/pistis/issues/461)
- Decision owners: Pistis, Monas, Prosopikon and Thesaurophylax

## Context

Pistis now distinguishes three real failures of the enrolled Site Root
Secure Enclave key: missing, invalidated and mismatched. The same condition
occurs when an iPhone is lost or stolen. The existing genesis registration is
intentionally immutable and the current App Attest replacement route requires
a signature from that Site Root key. Reusing either route would therefore make
recovery impossible when the phone no longer has the enrolled key, while
resetting genesis or deleting a Keychain item would orphan the server's
authority history.

The retained permitted-user and persona database is still valuable: it records
which human identities and installation relationships may be re-established.
The phone-held Site Root key is an installation authority, not a per-user
credential. The user/persona records and their grants therefore survive device
wipe, destruction or theft. The database is not, by itself, a signing
authority. A replacement flow must first quarantine the lost installation,
preserve those records, and require an independent typed custody/operator
authorization before binding a new phone. Terminal predecessor revocation is
committed with final replacement activation, not as a half-completed
preliminary side effect.

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
   Prosopikon installation/device projection, the retained permitted-user and
   persona records, and a typed, package-owned custody/operator authorization
   artifact. It places the exact lost/stolen installation in durable
   `Quarantined` state, invalidates its sessions and pending ceremonies, and
   records one `Requested` intent containing the old Site Root generation,
   candidate generation, replacement installation binding, exact
   principal/external-identity target, challenge and expiry. The independent
   authorizer record binds its exact device, installation, identity binding,
   policy generation, revocation generation, purpose, artifact type and
   evidence digest. A normal replacement requires a purpose-specific signature
   from an active device for that exact principal/external identity, or an
   explicitly authorised administrator recovery artifact. When every trusted
   installation is lost, the independent recovery-custodian path applies. None
   of these authorizer artifacts may be supplied by, or inferred from, the
   fresh candidate phone's App Attest registration.
2. Pistis creates fresh candidate Secure Enclave and App Attest keys in
   distinct pending namespaces after Face ID, and starts a fresh
   purpose-separated custody/recovery-seed bundle for the replacement phone.
   It signs the exact canonical replacement transcript and retains the
   canonical submission before network delivery. The stolen phone's App Attest
   assertion and custody seed are never required from the candidate and cannot
   be reused. The submission carries the fresh candidate App Attest and custody
   bundle separately from the already-verified authorizer evidence; proving
   possession of either candidate key is not recovery authorization.
   When the retained external-identity provider is available, the candidate
   must also complete fresh authentication that resolves to the exact retained
   provider, issuer and immutable subject binding. Provider authentication is
   corroborating evidence, not sufficient recovery authority. Loss or
   unavailability of that provider is a separate governed recovery policy and
   cannot be silently treated as success by this protocol.
3. Monas is the sole system of record for the effective Site Root generation.
   It verifies the candidate proof, the purpose-specific recovery authorizer,
   fresh candidate App Attest registration/attestation and all genesis/Pros/
   custody cross-bindings. One immediate transaction records the candidate
   Site Root, App Attest and custody generations as staged and marks the intent
   `Accepted`; the candidate is not yet an effective authority. The previously
   activated Site Root remains only the server-side trust anchor and historic
   effective generation needed for validation and rollback-safe convergence;
   quarantine already denies every current-operation proof originating from
   the stolen phone. Genesis evidence and prior generations remain immutable.
4. Prosopikon and Thesaurophylax are read-only consumers of the authenticated
   Monas generation record; they do not maintain an independently mutable
   current Site Root key. Each must acknowledge the exact generation digest in
   a durable, idempotent publication record. The package-owned publisher moves
   the intent through `Accepted -> Published` only after every required
   consumer has acknowledged the same staged record and has passed its
   restart/read-only validation. A missing, conflicting or stale acknowledgement
   denies and leaves the previous generation authoritative. A final Monas
   transaction then moves `Published -> Activated` and atomically flips the old
   active generation to revoked and the staged candidate to active. The same
   transaction terminally revokes the quarantined predecessor's App Attest and
   custody generations, invalidates its remaining sessions, and activates the
   fresh phone's bundles. Consumers resolve only `Activated`; the staged
   candidate is never served.
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
- A quarantined or terminally revoked stolen installation cannot submit,
  observe as active, or be rebound; its permitted-user/persona records remain
  available for the exact replacement binding and are never deleted as part of
  device containment.
- The replacement target is derived from authoritative Pros policy for one
  principal, external identity and installation. Callers cannot select an
  arbitrary retained persona, add grants, or rebind unrelated users.
- Independent authorizer evidence and fresh-phone candidate evidence occupy
  distinct typed fields and verification paths. A candidate App Attest
  registration, Secure Enclave signature, Face ID result or custody bundle
  cannot satisfy, replace or select the recovery authorizer.
- Authorizer verification requires exact equality for authorizer device,
  installation, identity binding, policy generation, revocation generation,
  recovery purpose, artifact type and evidence digest. Missing, stale,
  substituted or cross-principal fields deny without state change.
- When its retained provider remains available, fresh authentication must
  resolve to the exact retained provider, issuer and immutable external subject.
  Provider loss uses a separately accepted policy; this flow neither invents a
  substitute provider nor permits a caller-selected external identity.
- A fresh phone must present its own App Attest registration and custody bundle;
  the stolen phone's old assertion, Site Root key and recovery seed are never
  treated as available evidence.
- The schema is installation- and persona-scoped, not a singleton user row:
  multiple permitted users, personas and active installations may coexist
  according to policy. Wiping one phone never deletes another installation or
  a user's grants.
- Only one live intent exists across `Requested`, `Accepted` and `Published`.
  Expiry, denial, replay and concurrent submissions settle durably. Accepted
  retry and Observe are byte/idempotent.
- Quarantine immediately makes the stolen installation's App Attest and
  custody evidence, Site Root signatures and every other phone-originated
  proof ineligible to authorize current operations, while preserving their
  immutable records for rollback-safe adjudication. Before `Activated` they
  are not terminally revoked; the previously activated Site Root remains only
  the server-side trust anchor and historic effective generation needed to
  validate and converge the governed transition.
- At `Activated`, old Site Root signatures deny, the predecessor App Attest and
  custody generations become terminally revoked, and the fresh candidate App
  Attest counter begins from its independently attested registration state.
  The new Site Root generation is the only effective root and subsequent App
  Attest replacement binds to that new active registration and root.
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
