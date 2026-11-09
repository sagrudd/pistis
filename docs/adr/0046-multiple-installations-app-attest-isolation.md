# ADR 0046: Isolate App Attest and broker setup by installation

- Status: Proposed — implementation and acceptance pending
- Date: 2026-11-09
- Decision owners: product owner, Pistis mobile security, Monas authority and
  Thesaurophylax custody
- Tracking issue: [#546](https://github.com/sagrudd/pistis/issues/546)
- Review: independent mobile security and affected authority owners required

## Context

Pistis retains installation-scoped trust and permits selecting an installation.
ADR 0030, ADR 0031, ADR 0032, ADR 0040 and ADR 0041 govern authority-backed
removal, audience and trust separation, coexistence, and explicit local reset.
The current first-device guard rejects a second installation. The App Attest
key reference is a global `primary` item: accepting a second registration can
replace the reference used by the first installation. Brokered setup records
are also rebound by broker hostname to whichever native authority is selected.
Neither a shared broker hostname nor a QR-supplied origin proves that two
ceremonies refer to the same installed authority.

## Proposed decision

- Keep each existing installation and its device and App Attest references
  independent. Bind each reference to an authenticated, stable installation and
  Site Trust identity; require exact binding for registration, replacement,
  assertion, recovery, and every custody or X.509 continuation. A scanned QR,
  display name or selected host alone is not evidence of that binding.
- Treat a new broker ceremony as pending, non-authorising state keyed by its
  validated opaque correlation and Site Trust identity. Never move all records
  by broker hostname. Promote or associate a single pending ceremony only when
  authenticated authority evidence establishes the same installation and site;
  ambiguity, interruption or substitution fails closed without changing A.
- Preserve A's legacy global reference and its working legacy path without
  migrating or overwriting it. A may use the unscoped path only where the
  retained context unambiguously identifies the one eligible legacy
  installation. B uses a distinct create-once scoped reference and never falls
  back to `primary`. Adding or failing B never overwrites A. Define durable,
  idempotent pending and retry ordering before implementation; a crash at any
  step must preserve A and avoid activating an unverified B.
- A new first-device attempt must reject a conflicting same-installation ID
  before creating or deleting keys. Identical retries remain bounded and
  idempotent; different installation IDs may coexist only after the above
  binding and key separation are implemented. Selection must never change an
  authority or key binding. Use the existing signed authority and endpoint
  constraints, and reject cross-site references and arbitrary QR origins.
- Explicit local reset must enumerate the new per-installation and pending
  references as well as the preserved legacy reference, as required by ADR 0041.
  This decision does not authorise server revocation or deletion.

## Unresolved authority evidence and transaction ordering

The existing pinned-channel `CustodyRotationAppAttestChallengeV2` includes an
installation ID, Site Trust domain, app identifier and Apple key identifier;
the current parser discards the first two after validation. It does not carry
Apple environment or policy and revocation generations. The existing assertion
submission reports transport success rather than a typed acceptance binding all
those facts. Preserve and compare the available challenge fields against the
selected or in-progress authenticated context, and require durable authority
acceptance before associating any scoped reference. The Monas and Pistis owners
must specify the exact authenticated same-ceremony handoff from pending broker
setup to the final installation ID, how environment and relevant generations
are established, and the acceptance/reconciliation evidence. If existing
records do not establish these facts, the coordinated authority contract must
provide them; neither matching hostname nor broker correlation suffices.

Pending reference storage must be durable and create-once for the exact
ceremony. A retry after a timeout or lost response must reuse the same key and
operation identity and reconcile the authenticated authority result; it must
not assume failure or generate a replacement key. A pending correlation is not
an authenticated site identity. Promote a single pending reference only after
verified durable same-ceremony authority acceptance binds every required fact.
Write ordering and recovery must preserve the old usable A path across each
crash boundary; cleanup may occur only after durable verification. A failed,
ambiguous or interrupted B attempt must not mark B enrolled or alter A's
working references or assertions. Concurrent operations must fail closed or be
serialised per installation and pending ceremony.

## Evidence required before acceptance or implementation

The mobile-security, Monas and Thesaurophylax owners must review the exact
identity evidence, custody boundary, atomicity, interruption recovery and
negative cases. Demonstrate isolated A → B → A enrolment and authentication,
wrong-site assertion rejection, same-ID conflicts, retries, restart and lost
responses at each commit boundary, concurrent A/B, legacy ambiguity, swapped
authority, key, environment, generations and correlation, and partial reset
failure with synthetic fixtures.
The actual existing iPhone and its data must not be reset or overwritten. An
accepted decision and specialist implementation review remain prerequisites;
this proposal does not establish that the current source supports multi-host
operation or that any release is qualified.
