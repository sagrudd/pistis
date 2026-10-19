ADR0022 owner-successor witness supplement
==========================================

Status: candidate for the existing independent specialist review stream. No
phone protocol implementation is authorised by this candidate alone. It
supplements the existing ADR0022 governance and recorded-owner-exception
branch. ADR0022 here means the central Mnemosyne Docs Proxenos ADR,
``architecture/adrs/products/proxenos/0022-exact-source-authority-origin-and-effect-admission.md``,
not the separately numbered Pistis login-port ADR. Pin the central source to
``sagrudd/mnemosyne-docs@1baf590032e9dda113e53e2fcd325439baefd1ff``
(fresh authenticated source connector read on18October2026). Its normative base is
``supporting/0022-exact-source-authority-origin/CURRENT_AUTHORITY_STATE_ORIGIN_CONTRACT_CANDIDATE_V2.md``,
SHA256 ``465828463bb214e78f7ddd7652bbfdcfd592674f43d36679364defdcd99d1c15``.
This supplement defines new kind3/envelope/source-alternative transport; only
the existing governance signed body remains unchanged. It does not change the existing independent-review or post-merge
owner-approval-merge alternatives.

Authority owners and source selection
-------------------------------------

The authenticated original phone Propylaion ReleaseOwner supplies the existing
Core ``governance-exception`` action. The actual current enrolled ACK key
supplies its detached proof. Core supplies the current original action audit;
Root only lends its existing read owner, never the ReleaseOwner principal.
No new Core purpose, key, role assignment or signing capability is introduced.

Jenkins supplies a separate current authenticated source observation through
its existing configured GitHub vault credential and fixed HTTPS origin. The
accepted Role B source is repository ``sagrudd/pistis``, repository ID
1310759408, PR526, ref ``refs/pull/526/head``, selected commit
``bddfb43676a709134d040c84828fcd0ae9c7812d`` and tree
``187fae055997ff845ba7637208271c8c0c666037``. The owner record is comment
6255076636, author ID3848500/login ``sagrudd``, created and last updated
``2026-10-18T20:59:29Z``. Its exact UTF-8 statement digest is
``b969a230f62b722856fa14e4c9319f1386c6cfe27bf7e63ad460cc949d3becd0``.
The adopted policy packet digest is
``b18435a596622b959703bd538a8b32da229996582d88e793ccd9caec61ec99ff``.

The fixed source reader checks repository identity/owner, open and unmerged
PR/head repository, current review ref, immutable commit/tree, comment author,
issue location, timestamps and complete statement. Redirect, retry, changed,
missing, edited, deleted, revoked, oversized, expired or unavailable data deny.
It does not consult hosted checks, statuses or Actions. The synthetic PR
``merge_commit_sha`` is never merge evidence and is not consumed.

Source observation has no serializable authority constructor. The production
caller retains a private non-cloneable read under its original deadline and
freshly checks it before and after the actual authenticated native exchange.
Monas verifies the installed Jenkins peer and its selected native generation;
a public JSON object, protected file, timestamp or matching digest cannot
replace that producer. A retained source original is historical DATA only.
The final consuming Jenkins query must repeat the source checks before and
after the actual operation, including its terminal settlement; no observation
or credential is retained as a permission across a phone display wait. A
current HTTP observation is not an atomic remote revocation lease.

Closed public source original
-----------------------------

The new alternative uses schema
``mnemosyne.proxenos.exact-source-owner-successor.v1``. Its exact fields are:
``schema``, ``repository``, ``repository_id``, ``pull_request``, ``review_ref``,
``reviewed_revision``, ``reviewed_tree``, ``owner_id``, ``owner_login``,
``owner_record_id``, ``owner_record_created_at``, ``owner_record_updated_at``,
``owner_record_body``, ``owner_record_sha256``, ``policy_sha256``, and
``original_independent_technical_review_sha256``. IDs are JSON integers;
remaining values are strings. All selected constants above must match, and
the independent original-review digest must match the full retained verdict.
This closed JCS original is at most8192 bytes. It contains no canonical merge
revision, merge-parent assertion or claim that source acceptance is CI.

Governance phone task and complete witness
------------------------------------------

The existing prepare/task transport admits kind3 for governance only. Kinds1
and2 retain their existing exact definitions. Kind3 uses the existing closed
ADR0022 ``governance-signed-body`` unchanged, with employee_count exactly1,
external_customer_use exactlyfalse and the adopted policy digest above.
The body binds the complete prepared review-subject digest, installation,
Site, actual original owner principal/device/generation, current native role
audit, independent canonical governance source, nonce and exclusive expiry.

Its six complete originals, in order, are: current native ReleaseOwner role
audit, exact governance-exception action, full admission INTENT, full prepared
review subject, full owner-successor source original, independent original
review verdict. Their caps are8192,8192,16384,8192,8192,65536 bytes. The body is
at most8192 bytes. Task and action use the existing exclusive expiry rules:
phone display at most30 seconds, original native action at most60 seconds,
and every ancestor expiry remains binding. The action digest removes only
``role_decision_sha256`` from the governance body; its admission binding hashes
the complete admission INTENT. Parsing or display does not authenticate an
owner or source. Current registration and authenticated session are checked
before and after every awaited operation and signing, using the existing
sticky cancellation and add-only invocation fence. Existing-key Face ID is
explicit and never simulated as a physical acceptance result.

A successfully verified governance proof is retained as a closed JCS envelope
with exactly ``schema``, ``body_b64url``, ``proof_b64url``, ``role_b64url`` and
``action_b64url``. Schema is
``mnemosyne.proxenos.exact-source-native-governance-envelope.v1``; all four
originals use canonical unpadded base64url and the complete envelope is at most
8192 bytes. Hashes in the technical-review body bind this complete envelope
and the complete owner-successor source original. No hash replaces an
original. Verification decodes the exact existing body shape, verifies the
actual current selected ACK COSE proof and freshly borrows the existing Core
ReleaseOwner action audit for ``governance-exception``, exact intent digest
and admission digest. The audit's role/action originals, actor, installation,
Site, device generation, subject, policy/revocation and expiry must all join.
Each borrow is finished under the same native operation deadline.

Only that verified governance witness enables the same-subject technical
review branch. Separate Reviewer and ReleaseOwner operations remain separate;
Root does not impersonate either actor. Preparing/signing these public review
originals grants no initial purpose admission. At final initial admission,
Prox independently repeats current native audit and ACK checks and requires
the current authenticated Jenkins source producer described above. The
independent path still requires actual distinct subjects and both exact
not-used witnesses. No general removal of the independence check is allowed.

Failure, transaction and qualification
--------------------------------------

Only public task bytes and settled audit DATA cross display waits. No native
credential, source-read owner, Root permission or unfinished writer crosses
one. The actual Core child must close its writer, return its bounded result,
receive acknowledgement, send the matching closed receipt and exit0 before
its separate capacity is released. Missing/duplicate/wrong-phase receipts,
process replacement, timeout or uncertain settlement poison that attempt and
cannot be retried into success. No writer is considered closed from a public
receipt alone. Proof retention and task consumption use the existing single
terminal transition; delivery uncertainty stays terminal.

Qualification must exercise actual mounted producer/caller/consumer joins,
not only public shape parsing. Required hostile cases include counterfeit
source JSON/peer, moved ref, wrong repository/owner, changed/deleted statement,
redirect, failed transport, wrong original/digest, stale native audit, wrong
role or purpose, cross-admission/source/subject/device, revoked ACK, duplicate
proof, cancellation, rollback, expiry, missing settlement and child-exit
failure. Source compiler/strict checks and genuine Jenkins qualification do
not substitute for actual phone Face ID or installed acceptance. Preserve
unrun prerequisites and normal protected merge gates.
