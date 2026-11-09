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
- Treat a new broker ceremony as pending, non-authorising state identified by
  its validated opaque correlation and provisional Site Trust claim. Never move all records
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

## Review and qualification sequence

Before accepting this proposed design, the decision owners and mobile-security,
Monas and Thesaurophylax reviewers must establish feasibility and the exact
authoritative same-ceremony provenance, custody boundary, atomicity and
interruption recovery. Monas must affirm that the operation and correlation
are durably bound in authoritative records; a client echo is insufficient.
After acceptance, implementation and independent review must demonstrate
isolated A → B → A enrolment and authentication,
wrong-site assertion rejection, same-ID conflicts, retries, restart and lost
responses at each commit boundary, concurrent A/B, legacy ambiguity, swapped
authority, key, environment, generations and correlation, and partial reset
failure with synthetic fixtures.
These tests and specialist implementation review gate implementation approval
and any live use. The actual existing iPhone and its data must not be reset or
overwritten. This proposal does not establish that the current source supports
multi-host operation or that any release is qualified.

## Concrete bounded decision for owner review

Preserve A's existing `primary` and legacy path. B's pending Keychain item is
create-once under an opaque local operation ID, with its Apple key reference,
validated broker correlation, registration reference, and provisional site,
app and environment claims. These claims are untrusted until authenticated
against the authority record. It is not an active installation and the
correlation does not select an authority. Persist the item before the first registration POST;
a retry reuses its exact key and operation, never regenerates a key or changes
A. Competing attempts for the same operation must serialize.

After genesis and before B is treated as an installation, introduce a
purpose-specific Monas authenticated status operation, over B's separately
verified and pinned native authority transport, with a fixed reviewed path and
strict bounded response. Its request names the pending operation and the
validated ceremony reference; it may not supply an origin. Its authoritative
response must bind, in one durable same-ceremony record: operation ID and
ceremony reference, broker correlation digest, stable 16-byte installation ID,
Site Trust domain, exact registered Apple key ID, app identifier, Apple
attestation environment, relevant policy and revocation generations, and
terminal acceptance state. It must distinguish pending, accepted and rejected;
identical retries return the same accepted facts, and conflicting reuse is a
hard denial. The server derives these values from its committed genesis and
App Attest records, not client claims. Pinned TLS plus strict endpoint and
response binding authenticate this operation; this proposal does not invent a
signature or infer trust from a QR. Exact schema and fixed path require a
coordinated Monas/Pistis protocol change, fixtures and specialist review.

The phone compares every response fact with the pending record and the
independently verified native installation profile, including exact Apple key,
site, app and environment. It writes a create-once B binding and verifies it
is durable before marking B usable or removing pending state. An interruption
before that point leaves A usable and B pending; after it, replay sees the same
binding and completes cleanup idempotently. A mismatch, unavailable or
ambiguous status, changed origin, or conflicting existing B binding preserves
A and pending B and fails closed. B assertions and replacement use only B's
scoped reference; challenges must retain and compare their installation, site,
app and key fields before assertion. Never repair the global `primary` from a
B challenge. Per-installation selection, forget and explicit reset enumerate
exact scoped references, while A's primary and shared Site Root key are never
removed as a side effect of B failure.

Existing evidence for feasibility is Monas's durable genesis registration
context and custody rotation records, which contain installation, site and
App Attest key references, and the existing pinned-channel custody challenge.
Those records are not by themselves the proposed phone-facing same-ceremony
acceptance contract. The decision owners must verify server-side correlation
provenance and environmental/generation availability and approve the exact
status response and crash/replay ordering; if any value is unavailable the
operation remains blocked until Monas can supply it from an authoritative
record. No production operation is authorised by proposing this design.
