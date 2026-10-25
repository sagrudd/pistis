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

BEFORE INSERT guards reject an existing metadata singleton, operation or
challenge and history key even with `recursive_triggers=0` and
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
SQL. They are structural reference evidence only. Native qualification must
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
