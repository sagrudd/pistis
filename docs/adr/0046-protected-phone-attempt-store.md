# ADR 0046: Protected phone attempt ledger and prepared cancellation

- Status: Proposed; no adoption or product implementation is claimed
- Date: 2026-10-25
- Deciders: Pistis owner, with Proxenos and Thesaurophylax interface review
- Related issue: [MNE-1481](https://linear.app/mnemosyne-biosciences/issue/MNE-1481/current-phone-attempt-ledger-sqlite-replacement-bypass-and-typed)

## Context

The normally delivered Pistis source at
`aec7d036fe260cab80970b8d3fa52b8fb06f1c02` is iOS 0.28.0 build 75. It has no
`ProtectedPhoneAttemptStore`, `cancelPrepared` or continuity attempt database
implementation. This proposal does not change that source, release coordinate,
installed application, registration, key or enrolment.

The historical R2 profile digest `d55689c237fd1675ec3343b65eb47765db538d5acbcd16ae6df97985832a768c`
is a JSON reference-profile digest, not a product commit. Its 24 SQLite checks
produced receipt `31ed75dce1c3c69b125c49cccf4f2d509e6d25c9b56f2b42f21bcbe79be9c47c`.
They exercise in-memory SQL; prepared cancellation is a direct SQL transaction
and an API-signature assertion. They do not exercise a native typed cancellation
controller, persistence, File Protection, Keychain, current permission or phone
signing. The R1 replacement failures remain failures.

The selected Phone addendum in `JOINT_PRODUCT_SOURCE_INTERFACE_BATCH_R3.json`
supersedes the provisional R1/R2 carriage, path and schema sketches. Its selected
store has `meta`, `attempts`, `history`, five literal states, a private
Application Support/Pistis path, an immutable local anchor and descriptor-held
cross-instance exclusion. The addendum remains a proposal: format adoption
`c2d4d235...` alone does not adopt a local physical store. This ADR supplies one
exact local contract for review, not a second permission or witness profile.

## Proposed decision

Adopt the exact [schema](0046-protected-phone-attempt-store/selected-schema-v1.sql)
and cancellation contract below for the selected store. This adoption alone does
not enable product implementation. Retain the selected R3
`one_delivery_scope.first_implementation_gate`: exact addendum adoption by the
existing Proxenos/Pistis/Thesaurophylax authority owners, canonical ADR 0025 and
complete hostile-conformance/review evidence, and a serialised version/source
lease, followed by the agreed coherent implementation batch. This ADR requires
the repository specialist review and owner acceptance in addition to those
conditions. It neither narrows that architectural gate nor invents a completed
adoption receipt. Do not declare MNE-1481 complete on this proposal or SQL checks.

The gate above is architectural source admission, not an inherited requirement
that the live phone, installed renewal service or Martys runtime must first be
accepted. Any proposed narrower source implementation boundary must be an
explicit, independently reviewed decision by the affected owners; it cannot be
inferred from this ADR or a generic instruction to finish the defect.

### Fixed storage identity and schema

The sole path is the app-private
`Application Support/Pistis/continuity-approvals-v1.sqlite3`, with a sibling lock
and DELETE journal, no caller path or App Group. Retain no-follow parent, lock
and database descriptors; require app ownership, directory 0700, files 0600,
FileProtectionComplete and backup exclusion. Read/write opens use the existing
file only, including SQLite no-follow support; there is no operational CREATE,
WAL, ATTACH, migration, reset or auto-repair path.

The local WhenUnlockedThisDeviceOnly anchor uses the selected existing proposal
service `org.mnemosyne.pistis.continuity-approvals-v1`, account `store-anchor`,
no synchronisation or extra access group. Its exact definite-CBOR array is
`[1, schemaSHA256:bstr32, Site:bstr16, ackKeyID:bstr32,
ackGeneration:bstr8u64BE, filesystemDevice:bstr8u64BE, databaseInode:bstr8u64BE]`.
It is a local replacement detector, not permission or rollback authority.
Provisioning is a separate exact admitted action, adds the anchor without
replacement and quarantines partial states. This ADR authorises no provisioning
or Keychain operation.

Before use and again before fence, invocation and settlement, verify descriptor
identity and the complete exact schema, including intrinsic SQLite autoindices,
all triggers, the sole metadata row and its digest. Unknown objects, stale
schemas, changed identity, missing anchor or protection failure deny operation.
Native checked counters are unsigned, big-endian BLOB8. SQL constraints do not
prove canonical bodies, hashes, signatures or current authority.

`canonical_body` is bounded at 8192 bytes, the adopted PCAP bound. PCUR26
fits within it: its two-byte array header, six-byte tag, twelve 32-byte digests,
five 16-byte UUIDs, six maximum-width unsigned integers, one compressed 33-byte
point and longest closed role (`current-assertion`, 17 bytes) total at most
609 canonical-CBOR bytes, including each encoding header. The proposal checks
construct that maximum-width structural instance. The native exact-family
decoder must still enforce the closed role, exact fields and every adopted bound
before reservation; a structural size bound grants no authority.

### Typed steps for the actual owner-enrolment consumer

The proposed Core ADR 0010 consumer uses fresh dual-key consent because current
ACK point/digest records do not retain a portable AUTHN-to-ACK enrolment original.
This amendment proposes one explicit kind allowlist in the SAME selected store:
`PCAP`, `PCUR`, `CPEI_AUTHN`, `CPEI_ACK`, `CPEC_AUTHN`, `PCPG_ACK`. It adds no
state, second ledger, signature retry or current-authority factory. The kind is
immutable alongside the existing operation/body/challenge identity, and an
operation UUID remains globally unique across all kinds. A different kind cannot
recycle a prior attempt or make a second private invocation under one row.

CPEI28 field 27 is the ordered pair `[AUTHN challenge/attempt UUID16,
ACK proof attempt UUID16]`; both are distinct from the initializer operation and
from each other. CPEC6 contains its distinct commit operation UUID. These are
explicit proposed consumer identities, not reinterpretations of a PCAP/PCUR
operation, a hash-only authority record or one attempt containing two invocations.
The native family decoder/controller verifies the complete exact consumer object
and chooses the sole fixed kind. No caller chooses a generic kind or signer.

For CPEI, each row retains the COMPLETE same canonical control7 as its immutable
body. The exact equality is `CPEI6 == control7[4] nonce32 == action-v2 c7/r7`
for BOTH CPEI_AUTHN and CPEI_ACK. The AUTHN challenge/response
bind that control/session/nonce through the actual action-v2 descriptor and
challenge joins; the ACK detached proof binds the SAME complete control7. The
row UUIDs are respectively CPEI27[0] and CPEI27[1]. The private ACK controller
requires the actual originating retained AUTHN handle AND complete verified
challenge/response, exact CPEI pair, control bytes, Site/actor/device bindings,
nonce, currentness and original expiry. Reading `signed-retained` from SQLite
or accepting a caller result/Boolean is insufficient. Keep cross-step exclusion
while verifying the predecessor and admitting/fencing the ACK attempt.

The literal schema permits a shared nonce ONLY for the exact CPEI_AUTHN and
CPEI_ACK kind pair with byte-identical control body and body digest. The private
controller must additionally verify the exact CPEI27 operation pair. Every other
challenge collision denies, including CPEI_AUTHN/CPEC_AUTHN, PCPG_ACK/CPEI_ACK
and legacy/new-kind pairs. UNIQUE(challenge, attempt_kind) also rejects duplicates
within a kind, and a partial unique index retains the original PCAP/PCUR
cross-kind constraint. Duplicate operation UUID remains rejected across ALL
kinds, including INSERT OR REPLACE. Unknown kinds deny. This narrowly explicit
CPEI-pair exception is part of the reviewed joint profile amendment,
not a silent operational migration. Schema digest/anchor matching remains exact;
no existing database is silently changed.

The four legacy authority slots (`bootstrap`, `permission_revision`,
`delegation_serial`, `captured_revocation`) remain required with their ORIGINAL
meanings for PCAP/PCUR. For the four new consent kinds they MUST be SQL NULL:
there is no existing PCPG grant/permission serial during owner initialisation.
The family CHECK rejects missing legacy values and rejects relabelled values in
new-kind rows. NULL is explicit absence, not a verified zero, sentinel serial,
future grant, Site revision alias or a fabricated permission. Immutable complete
control bytes retain the new family's actual bindings; the consumer independently
verifies all complete native originals/current state. The store cannot infer
permission from these absence slots.

Per-family native request/handle mapping is closed:

| Kind | Operation UUID | Immutable body and challenge | Native origin and required predecessor |
|---|---|---|---|
| PCAP / PCUR | Existing exact operation UUID | Existing canonical payload and challenge | Existing verified live continuity request/immediate permission, unchanged |
| CPEI_AUTHN | CPEI27[0], equal to action-v2 challenge/response UUID | COMPLETE prepare control7; its nonce32 | Private verified native owner-consent request from actual installation challenge and current AUTHN credential; no prior PCPG permission required |
| CPEI_ACK | CPEI27[1], distinct from initializer and AUTHN attempt | IDENTICAL prepare control7 and nonce32 | Actual retained CPEI_AUTHN originating handle and complete verified challenge/response under exclusion, plus current ACK identity proof for the same control |
| CPEC_AUTHN | CPEC6[4], equal to actual action-v2 c6/r6 and distinct from both prepare attempts | COMPLETE commit control7; CPEC6[5] == its nonce32 == action-v2 c7/r7 | Private verified native commit-consent request from the actual action-v2 challenge; complete admitted CPEI Original5 and actual matching generation records |
| PCPG_ACK | PCPG30[5] registration operation UUID | COMPLETE canonical PCPG30 body; PCPG30[6] challenge32 | Private verified native permission-registration request with the complete existing owner-enrolment/registration originals; not a PCAP/PCUR permission handle |

For new controls, row `issued_at`/`expires_at` are the exact control interval,
constrained by original action challenge and ancestor bounds; PCPG uses its exact
registration-request interval PCPG30[26]/[27]. Revalidation never refreshes them. The body and
its digest must match the complete source object, not a copied hash or database
reconstruction. The ordinary `VerifiedLiveContinuityRequest` and
`VerifiedImmediatePermission` types remain PCAP/PCUR-only. New kinds require
separate private native consent/commit/registration request and revalidation
handles with no public, Codable or generic callback constructor. They share the
existing prepared/fenced/retained store mechanics; they do not alias authority.
The shared private controller dispatches only the exact family's fixed primitive
once. The exact new-family mapping follows proposed Core ADR 0010 CPEI28/CPEC6 and
PCPG R2 payload digest
`82248d07c1dd9c672ee34fa34ee8866fb4e8997271485c7356c1b602fb5ba3d0`;
its body/operation/challenge/interval fields are not renamed to legacy authority.
All mappings remain proposed joint-contract decisions before source code.

The partial order is:

1. Persist/fence/retain `CPEI_AUTHN` once, through its existing state machine.
2. Verify that actual retained result under the original control deadline;
   only then may the distinct `CPEI_ACK` row fence and retain its one ACK proof.
3. Assemble complete CPEI Original5 from the retained matching partial results.
   This is pure assembly/retrieval and never signs either result again.
4. Only after the consumer proves actual generation results against the admitted
   prepare may `CPEC_AUTHN` fence its own distinct commit operation and exact
   commit control. It never uses either CPEI row as a second signing allowance.
5. `PCPG_ACK` is its own exact registration operation and retained ACK result;
   it is not an AUTHN substitute or a prerequisite for owner initialisation.
   Actual owner-enrolment/purpose/currentness checks remain with the consumer.
   Retain this phone result FIRST; only then may the separate SiteApproval owner
   fence its own independent second signature. Failure of that second operation
   never permits another phone signature. A phone-only result is not permission;
   the Prox transaction requires both proofs and actual current complete origins.
   No distributed atomicity or single global exactly-once claim is made.

If AUTHN succeeds and ACK is still prepared, local prepared-cancellation proof
can cancel ONLY the ACK row. The AUTHN result remains retained; no assertion that
all workflow steps were unsigned is produced. If either step is fenced without a
result, that step remains unresolved and cannot be replaced by another UUID,
challenge or kind. Exact retry reads the original results; it cannot refresh
expiry, replace consent or repeat a private primitive. A later commit remains
unavailable where its actual predecessor/generation proof is missing. Existing
prepared cancellation, fencing, result settlement and history limits apply to
EACH row; each typed attempt consumes its own quota and settlement credit.

This amendment is proposed under the full joint implementation gate above.
It supplies no new PCAP/PCUR purpose permission, authentication, enrolment,
provisioning or private key operation. The source-only MNE-1481 defect and this
consumer contract review remain separate from live current-origin acceptance.

### Private cancellation and dispatch contract

All store handles and proofs are module-private, non-Codable and non-cloneable;
none has a public/memberwise/deserialisation constructor. The implementation must
provide these operations; these signatures are a contract, not implementation:

```swift
func reserveExact(_ request: VerifiedLiveContinuityRequest) throws -> PreparedPhoneAttempt
func cancelPrepared(_ attempt: PreparedPhoneAttempt,
                    proof: LocalPreparedCancellationEvidence) throws
func fenceExact(_ attempt: PreparedPhoneAttempt,
                revalidated: VerifiedImmediatePermission) throws -> FencedPhoneAttempt
```

A prepared handle binds the originating live store instance, held exclusive
lock/descriptors, operation UUID, exact body digest and current prepared state.
Only the local dispatch controller can mint `LocalPreparedCancellationEvidence`,
after it atomically excludes fence/dispatch and proves that no invocation path
was entered for this exact handle. Task cancellation, a timeout, remote absence,
caller assertions or reconstructing a handle from database bytes cannot mint it.
The controller and store must use one serialised ownership boundary; proving
absence and then releasing exclusion before cancellation is invalid.

`cancelPrepared` keeps that exclusion and performs one `BEGIN IMMEDIATE`:
revalidate the live handle and exact row/body/state; append sequence 1
`prepared-no-key-invocation -> terminal-proven-unsigned` with no result digest;
CAS the same row from prepared to terminal and require exactly one changed row;
commit durably. Any error rolls back the entire transaction and returns failure.
It never creates a fenced handle, calls a private primitive or transports a
submission. A repeated/stale/other-instance/changed-body handle is rejected,
including when the row is already terminal. Exact retry is read-only retrieval.

Fence competes under the same exclusion. If fence wins, prepared cancellation
cannot run. After durable fence, only the existing distinct independently valid
never-invoked evidence may settle an unsigned result. An ambiguous crash,
background failure, lost task or timeout remains fenced/unresolved. No new
attempt or challenge bypasses that retained identity. Restart requires genuine
authenticated exact-attempt reconciliation before any permitted settlement; no
new signing or ECDH is inferred from local absence.

### Replacement and settlement invariants

BEFORE INSERT guards reject an existing metadata singleton, operation,
kind-scoped challenge (plus legacy PCAP/PCUR cross-kind challenge) or history key even with `recursive_triggers=0` and
`INSERT OR REPLACE`. UPDATE/DELETE guards retain immutable identities and history.
The native owner, not SQL alone, verifies sequence contiguity from 1, legal
transitions, exact result digest/signature/ciphertext and current permission.
History insertion and CAS settlement occur in the same transaction.

The selected bounds are 512 attempts, 1536 history rows, 64 MiB database,
64 MiB journal and 262144 bytes per retained result. Reserve maximum bounded
result/history/page/index/journal settlement credit before fence, accounting for
all outstanding attempts. New-admission thresholds cannot consume another
attempt's credit or block its credited settlement. Do not prune unresolved or
terminal history. `max_page_count` bounds the database; `journal_size_limit` does
not bound transient journal writes. A bounded owned I/O mechanism and actual
supported iOS SQLite crash/full/protection tests remain mandatory before product
admission. No unconditional fsync, free-space or atomic SQLite/Keychain guarantee
is claimed. Any post-fence storage failure preserves denial/unresolved state.

## Qualification and delivery

The [proposal checks](0046-protected-phone-attempt-store/check_selected_schema.py)
exercise literal replacement rejection, the direct prepared-cancellation edge,
transaction rollback, a competing fence and retained states against the exact
SQL. Changed-consumer cases cover immutable kinds, shared CPEI nonce scoping,
wrong-kind/body/nonce predecessors, retained AUTHN-before-ACK ordering and the
unchanged legacy PCAP/PCUR challenge constraint. The executable ordering projection
is a contract reference, not a native proof factory or verified-handle producer. They are structural reference evidence only. Native qualification must
exercise private proof construction, wrong-instance/stale/body rejection,
actual exclusion races and zero private invocations on every cancellation,
cross-instance reopen, changed-file/anchor, lock/protection loss, crash after
fence, SQLite FULL/I/O failure and credited settlement. It must preserve old
source/legacy tests and obtain independent exact-source review and normal
publication. No phone, key or native-host operation is authorised here.

## Security and alternatives

Retain the selected R3 single store. A new ledger family, arbitrary provider
callbacks, public current-context factories, caller-selected paths and reuse of
old-purpose approval identities are rejected. Replaying 24 reference cases or
pointing at the accepted 0.28 application cannot substitute for typed native
implementation. Full current permission, carriage and Martys witness delivery
remain their owners' tasks; this ADR neither supplies them nor adds their whole
runtime acceptance as a gate to MNE-1481's own source repair.
