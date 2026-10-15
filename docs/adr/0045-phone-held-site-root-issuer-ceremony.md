# ADR 0045: Phone-held Site Root issuer ceremony

- Status: Proposed; human adoption pending
- Date: 2026-10-15
- Scope: Pistis phone protocol and private server handoff contract only

## Context

The existing Site Root P-256 key is nonexportable and phone-held. Existing
registration, delegation consent and continuity approval do not authorise issuer
root-admission or current-status signatures. Exporting or wrapping that key on a
server would contradict its custody. The separate ADR 0026 server-wrap proposal
remains on hold and is not adopted by this proposal.

ROOT allocated 0045 after checking canonical main
`53d6517f0931f2243a05f552e86378bd50a52f29`, its highest ADR 0042, and pending
allocations 0043 and 0044. The [allocation receipt](0045-phone-held-site-root-issuer/ROOT_ADR0045_ALLOCATION_AND_CURRENT_SOURCE.json)
records that the five inspected phone source blobs equal canonical main. This
allocation does not constitute acceptance.

## Proposed decision and normative contract

The normative proposal is the exact reviewed
[R2 contract](0045-phone-held-site-root-issuer/PHONE_SITE_ROOT_ISSUER_PROTOCOL_CANDIDATE_R2.json),
SHA-256 `2bec1a675f5994928b083ab2dfc2f3c5225beeef8a7f28544bc8e0b056bd86f6`.
Its closed field orders, caps, hash preimages, domains, mode-specific authority
requirements, deadlines, endpoints and failure rules are unchanged. The original
unallocated working name inside that immutable artefact is historical; this
proposed ADR supplies its allocated review identity without rewriting its bytes.
This prose does not introduce additional wire fields or signing purposes.

Use only the existing Site Root key: a noninteractive existence check supplies
coarse data, then public-key lookup and fixed-purpose signing use the same fresh,
operation-local Face ID ceremony. Do not call the existing registration flow or
create a key. Initial IADM authorisation comes from the independently verified
existing Site/root-provision owner and original attended act; it cannot depend on
an already signed IADM or ongoing issuer grant. IRCS requires the complete admitted
IADM and current independently verified permission. Readiness, phone possession
and biometric success establish none of that authority.

The attended prephase must finish before the existing Expedition handler starts
its original two-second deadline. The proposed private one-use handoff is new and
unimplemented. It must preserve the closed three-field continuation request and
must not reset or extend that deadline. Current owner, roots, permission and
expiry checks remain required after the original deadline begins. The phone's
separate earlier local deadline also applies. The proposed 30-second prephase,
250-millisecond arm scheduling and two-signature ceremony are subject to actual
platform qualification; they are not measured guarantees.

IADM uses one signature; an IRCS pair uses at most two, with actual protected read,
fresh current checks and strict nonce/serial relations. Exact complete canonical
readiness/task bytes are hashed. The phone's complete PRE IRCS envelope reference
is orchestration correlation only; the adopted POST IRSP must still reference the
complete signed PRE IRSP under its separate accepted domain. Ambiguous completion,
restart, expiry, missing current authority or lost ceremony must fail closed.
Protected attempt fencing and the server one-use journal must exist before use.

## Ownership and implementation gates

Pistis owns the proposed closed parser, presentation, bounded ceremony, transport
and protected attempt ledger. Monas/Pros owns genuine current Site permission,
provision admission, prepared-operation journal and endpoints. Expedition owns
the private pre-handler handoff; Thes retains strict existing proof verification.
The actual JIOQ producer and genuine current-owner ports remain dependencies.
None is replaced by public caller facts, a boolean authority flag or a readiness
response. No server custody owner, generic signing API or root appointment is
introduced.

Pistis policy requires an accepted ADR and specialist review before protocol
implementation. The [independent R2 review](0045-phone-held-site-root-issuer/PHONE_PROTOCOL_INDEPENDENT_REVIEW_R2.json)
is a bounded specialist specification PASS, subject to allocation and owner
acceptance; it is not acceptance itself. No product implementation, signing,
key creation, phone effects, installation or release is authorised by this file.

## Conformance evidence and limits

The [hostile plan](0045-phone-held-site-root-issuer/HOSTILE_CONFORMANCE_PLAN_R2.json),
[executable logical model](0045-phone-held-site-root-issuer/hostile_reference_r2.py)
and [receipt](0045-phone-held-site-root-issuer/HOSTILE_REFERENCE_R2_RECEIPT.json)
record 64 logical assertions over synthetic test data. They cover binding swaps,
metadata digests, initial-mode acyclicity, use counts, deadlines, replay, ambiguity
and distinct envelope-reference domains. Run the model from this package with
Python's standard library; it writes only its logical receipt beside the model.

These are not cryptographic, parser, native-clock, biometric, TLS, current-authority
or crash-durability tests. Real Face ID and two IRCS signatures within the original
two-second operation remain unrun. The [R2 freeze](0045-phone-held-site-root-issuer/PHONE_PROTOCOL_REVIEW_FREEZE_R2.json)
and retained predecessor artefacts preserve the review history. Source paths in
those historical receipts identify inspected evidence, not portable authority or
an installed runtime.
