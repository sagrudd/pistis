# ADR 0043: proposed enrolled Site Root successor adoption

- Status: Proposed; no implementation authority
- Date: 2026-10-02
- Decision owners: Pistis, Monas and Proxenos; Thesaurophylax review required
- Issue: `PIS-X509-F1` (#448)
- Related decisions: accepted ADR 0038; proposed ADR 0040

## Context

ADR 0038 accepts one attended bootstrap-leaf to Site Root migration through a
replacement signed build. It also says that a later Site Root replacement needs
a new governed transaction and replacement build. The installed-enrolment path
currently restores only the original TLS leaf SPKI pin. It has no accepted
transition that lets an already enrolled installation adopt a successor Site
Root while preserving that installation.

The source confirms the gap. `AuthenticatedEnrollmentOutput` retains the
enrolment receipt, installation and device context, origin, host allow-list,
and TLS leaf SPKI. `ProductionMonasSiteRootTransportFactory.make(verifiedEnrollment:)`
uses that SPKI. A separately verified runtime profile can construct a
Site-Root-generation transport, but the factory only parses its caller-supplied
dictionary; it does not authenticate a signature or bind the profile to an
existing installation or accepted authority. `InstallationTrustKeychain.isAuthorisedReplacement`
permits only a narrowly authority-signed device-key replacement and requires
the origin and TLS SPKI to remain identical. These paths do not establish
successor adoption.

The existing PXRA/v2 acknowledgement is Pistis's post-mutation acknowledgement;
it is not evidence signed by the target that authorises this phone to change
its trust. No accepted Monas/Proxenos contract currently defines that evidence,
its signer, canonical encoding, successor relation, trusted time or anti-replay
rules. This proposal deliberately assigns those fields to the authority owners
instead of inventing a local format.

## Proposed decision

Add a distinct, one-use, target-authorised successor-adoption transaction for
an already enrolled installation. If accepted, this proposal amends ADR 0038's
requirement for a replacement signed build for this defined successor-adoption
case. Until this addendum and its successor contract are accepted, ADR 0038's
replacement-build requirement remains controlling. Before Pistis implements
it, Monas and
Proxenos must define and accept the signed evidence and transaction contract,
and the affected authority owners must review its signer, canonical format,
key purpose, target Site and installation binding, successor-generation rule,
validity/revocation source, trusted time, retry semantics and anti-replay
mechanism. The project owners must record acceptance against the exact contract
revision. ADR 0038 remains authoritative for the initial attended migration and
ordinary bounded leaf renewal; this proposal does not change either.

The accepted evidence must bind at least the Site, existing installation ID,
selected enrolment and authority, configured origin(s), current root identity
and generation, successor root DER and fingerprint, successor generation,
adoption purpose, and a one-use transaction/challenge. Pistis must verify the
target signature, chain, hostname/Site identity, key purpose, validity and
revocation according to the accepted authority contract. It must reject replay,
stale, skipped, conflicting or unrelated generations and evidence for another
installation, authority or origin.

Pistis must stage and validate the successor before committing any persisted
state or foreground transport change. The final persistence and selected
transport switch must be atomic or recover to one unambiguous prior or successor
state. Success preserves installation ID, device key and key namespace,
selected installation, signed trust receipt, and verifiable enrolment and
adoption history. Local verification rejection or cancellation before
submission preserves the prior record. After an ambiguous delivery or
interrupted write, recovery must reconcile the exact transaction with the
authority before selecting a trust profile. The prior profile may be used only
while the authority confirms it remains active; after the authority commits the
successor, recovery must install or observe that exact successor rather than
assume the prior root remains usable. Recovery must never enable both roots,
fall back to an unauthenticated TLS connection, or silently re-enrol the device.

Ordinary leaf renewal remains within its accepted, bounded leaf grant under the
same Site Root generation. It cannot be interpreted as Site Root replacement,
device-key replacement or re-enrolment.

## Required implementation and evidence

After contract acceptance, implementation review must include positive and
negative tests through the production coordinator, persistence and transport
switch boundary, not only parser fakes. Required denials include replay and
stale generation; wrong installation, selected installation, authority or
origin; expired, revoked, unrelated, skipped or conflicting successor; altered
signature/evidence; and interrupted persistence. A success test must prove the
preserved identity and history fields, one active root after restart, and use of
the successor through the production transport. Leaf renewal tests must prove
it cannot cross into root adoption.

This ADR and the accompanying source tests are a reviewable proposal only. They
do not implement the transition or establish installed-phone compatibility.
The tests exercise the existing in-memory replacement predicate and the
production enrolment transport factory/relocation policy; there is no adoption
coordinator or persistence transition to exercise yet. They do not establish
selected-install preservation, persistence atomicity, replay resistance or
successor adoption.
Source review, accepted contract, signed build qualification and physical-phone
evidence are separate states. The live enrolled-phone update remains gated on
those gates and the exact-revision acceptance required by #448.
