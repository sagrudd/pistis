# ADR 0033: Govern infrastructure action approval and consumption

- Status: Proposed
- Date: 2026-07-31
- Decision owners: Pistis protocol; Prosopikon/host authority; Oikodome
  lifecycle; security; evidence
- Related issues: #358; sagrudd/oikodome#5;
  sagrudd/oikodome#53
- Specialist review: protocol/security review required before implementation

## Proposal status

This ADR is review material. It authorises no production endpoint, mobile
presentation, authority adapter, Oikodome readiness transition, or
infrastructure operation. The Project Owner and named protocol/security
specialists must accept it before implementation.

## Context

ADR 0016 and `pistis.action-descriptor.v2` bind one exact local command to one
signed human approval. They do not bind the full authority context required
when Oikodome accepts a governed convergence directive: installation and Site
Trust Domain, Prosopikon authority and tenant, principal and role, immutable
action/target/intent, and the current policy, entitlement, revocation, and
secret generations.

Encoding those facts as generic arguments or resource strings would make the
signed meaning adapter-specific. Treating a verified response as an execution
token would also cross the Pistis authority boundary and would require a
second Pistis decision during later evidence settlement.

The approval must instead establish one durable historical fact: one human
approved one exact directive acceptance while all bound authority generations
were current. Oikodome remains responsible for directive lifecycle and for
revalidating mutable target and execution state.

## Decision

After this ADR is accepted, Pistis will add a distinct governed-action profile.
It will use the accepted deterministic-CBOR and untagged COSE Sign1 profiles
from ADRs 0001 and 0018. It will not reinterpret or extend the bytes of version
1 login or version 2 generic exact-action messages.

One signed human ceremony authorises only acceptance of one immutable
Oikodome convergence directive. The host authority atomically consumes that
ceremony and persists a signed, non-secret receipt. Later evidence creation,
dispatch, or settlement verifies the receipt and accepted directive epoch
without calling Pistis or consuming another human approval.

### Authority ownership

- Pistis owns canonical governed challenge/response parsing, device-signature
  verification, explicit human decision, and the typed completion outcome.
- Prosopikon and the installation host own authoritative principal, tenant,
  role, audience, policy, entitlement, revocation, device, key, and binding
  state and the atomic consumption transaction.
- Oikodome owns the operation intent, directive lifecycle, target revalidation,
  execution, and evidence settlement.
- Thesaurophylax owns secret custody. Only immutable non-secret secret
  references and generation identifiers may enter this profile.

No browser session, Prosopikon session, device response, approval envelope,
receipt, or evidence reference is an execution bearer.

## Canonical governed context

`pistis.governed-action-context.v1` is one closed deterministic-CBOR map. All
fields are mandatory and critical:

| Key | Field | Type and constraint |
| ---: | --- | --- |
| 0 | `version` | unsigned integer `1` |
| 1 | `purpose` | exact text `pistis.governed-action-context.v1` |
| 2 | `installation_id` | 16-byte Pistis installation identifier |
| 3 | `site_trust_domain_id` | bounded opaque text identifier |
| 4 | `authority_id` | bounded opaque text identifier |
| 5 | `authority_generation` | unsigned integer |
| 6 | `tenant_id` | bounded opaque text identifier |
| 7 | `principal_id` | 16-byte immutable Pistis user identifier |
| 8 | `authority_projection_ref` | bounded non-secret opaque text reference |
| 9 | `authority_projection_digest` | 32-byte SHA-256 digest |
| 10 | `role_id` | bounded opaque text identifier |
| 11 | `role_generation` | unsigned integer |
| 12 | `audience` | exact text `oikodome` |
| 13 | `action_class` | unsigned integer `1` |
| 14 | `operation_id` | bounded non-secret opaque text identifier |
| 15 | `operation_intent_digest` | 32-byte SHA-256 digest |
| 16 | `directive_id` | bounded non-secret opaque text identifier |
| 17 | `directive_digest` | 32-byte SHA-256 digest |
| 18 | `target_id` | bounded non-secret opaque text identifier |
| 19 | `target_digest` | 32-byte SHA-256 digest |
| 20 | `plan_digest` | 32-byte SHA-256 digest |
| 21 | `resource_set_digest` | 32-byte SHA-256 digest |
| 22 | `policy_generation` | unsigned integer |
| 23 | `effective_entitlement_generation` | unsigned integer |
| 24 | `revocation_generation` | unsigned integer |
| 25 | `secret_generations` | sorted, unique array defined below |
| 26 | `idempotency_digest` | 32-byte domain-separated SHA-256 digest |
| 27 | `issued_at` | unsigned Unix time in milliseconds |
| 28 | `expires_at` | unsigned Unix time in milliseconds, exclusive |

Action class `1` means only `accept-oikodome-convergence-directive`. Zero and
unknown values deny. This profile does not authorise a shell command, arbitrary
workflow, login, secret access, recovery, destruction, entitlement change, or
future directive. Adding another action class requires a new reviewed
contract decision.

Each `secret_generations` entry is the closed map:

| Key | Field | Type and constraint |
| ---: | --- | --- |
| 0 | `secret_ref` | bounded non-secret opaque text reference |
| 1 | `secret_generation` | bounded immutable non-secret text identifier |

The array is sorted by the exact UTF-8 bytes of `secret_ref`, contains no
duplicate reference, and is bounded to 64 entries. Missing is not equivalent
to empty: an empty array explicitly states that authoritative resolution found
no secret generation relevant to this action. The resolver must be authorised
to make that statement.

Opaque text fields contain 1 through 256 UTF-8 bytes, contain no control or
whitespace characters, and are compared by exact encoded bytes without
normalisation or case folding. Display labels never replace these identifiers.
All digests are the raw 32-byte value of the named canonical object. A caller
cannot substitute an arbitrary digest for an object that the owning authority
can resolve.

`idempotency_digest` binds a host-owned, caller-scoped retry key without
placing the key itself in the challenge or receipt. It is SHA-256 of the exact
canonical CBOR map:

```text
{
  0: 1,
  1: "pistis.governed-action-idempotency.v1",
  2: installation_id,
  3: principal_id,
  4: operation_id,
  5: caller_scoped_idempotency_key
}
```

The final value is a bounded byte string supplied only across the
authenticated host boundary and contains 16 through 64 bytes. It is not a
browser capability or bearer and is never returned to mobile, Oikodome
evidence, logs, or diagnostics.

The canonical governed-context bytes are embedded unchanged in the challenge.
`governed_context_digest` means SHA-256 of exactly those bytes. JSON,
display text, unsigned metadata, or individually re-encoded fields cannot
replace the canonical context.

## Human display document

`pistis.governed-action-display.v1` is this closed canonical map:

| Key | Field | Type and constraint |
| ---: | --- | --- |
| 0 | `version` | unsigned integer `1` |
| 1 | `purpose` | exact text `pistis.governed-action-display.v1` |
| 2 | `installation_name` | text |
| 3 | `site_name` | text |
| 4 | `tenant_name` | text |
| 5 | `principal_name` | text |
| 6 | `role_name` | text |
| 7 | `action_label` | exact text `Accept convergence directive` |
| 8 | `target_name` | text |
| 9 | `intent_summary` | text |
| 10 | `consequence_summary` | text |

Names are 1 through 128 UTF-8 bytes and summaries are 1 through 512 UTF-8
bytes. Control characters are forbidden. Display text is signed and retained
only in the protected ceremony record, but it is not authority: the canonical
identifiers, revisions, and digests remain decisive.

The mobile presentation must show, without truncation or hidden expansion:

- the installation, site, tenant, principal, and role labels alongside stable
  short fingerprints of their canonical identifiers;
- the fixed action, target, intent, and consequence;
- the directive and intent digest fingerprints;
- every authority, role, policy, entitlement, and revocation generation, plus
  the secret-generation set count and fingerprint;
- the exact installation-scoped audience; and
- issue time, exclusive expiry, and an explicit `Approve` or `Deny` choice.

Login and generic exact-action visual treatment cannot be reused without a
prominent governed-infrastructure identity. Unknown fields, action classes,
or display/context disagreement deny before a decision can be signed. iOS and
Android remain disabled for this profile until shared fixtures and specialist
human-factors/security review pass.

## Governed challenge and response

The challenge purpose is
`pistis.governed-action-approval-challenge.v1`. It is this closed canonical
map:

| Key | Field | Type and constraint |
| ---: | --- | --- |
| 0 | `version` | unsigned integer `1` |
| 1 | `purpose` | exact challenge purpose |
| 2 | `issued_at` | unsigned Unix time in milliseconds |
| 3 | `expires_at` | unsigned Unix time in milliseconds, exclusive |
| 4 | `installation_id` | 16-byte identifier |
| 5 | `installation_key_id` | 32-byte identifier |
| 6 | `ceremony_id` | 16-byte single-use identifier |
| 7 | `nonce` | 32-byte random value |
| 8 | `principal_id` | 16-byte identifier |
| 9 | `external_identity_id` | 16-byte identifier |
| 10 | `audience` | exact text `oikodome` |
| 11 | `governed_context` | byte string containing exact canonical context |
| 12 | `human_display` | byte string containing exact canonical display |

The challenge's installation, principal, audience, issue time, and expiry must
equal the corresponding governed context. Any mismatch denies. The
installation signature covers the complete canonical challenge under the
accepted COSE profile.

The response purpose is
`pistis.governed-action-approval-response.v1`. It follows the version 2
exact-action response shape but is this distinct closed map:

| Key | Field | Type and constraint |
| ---: | --- | --- |
| 0 | `version` | unsigned integer `1` |
| 1 | `purpose` | exact response purpose |
| 2 | `issued_at` | unsigned Unix time in milliseconds |
| 3 | `user_verified_at` | unsigned Unix time in milliseconds |
| 4 | `installation_id` | 16-byte identifier |
| 5 | `device_key_id` | 32-byte identifier |
| 6 | `ceremony_id` | 16-byte identifier |
| 7 | `nonce` | exact 32-byte challenge nonce |
| 8 | `challenge_digest` | SHA-256 of exact canonical challenge bytes |
| 9 | `principal_id` | 16-byte identifier |
| 10 | `device_id` | 16-byte identifier |
| 11 | `external_identity_id` | 16-byte identifier |
| 12 | `decision` | exact text `approved` or `denied` |

The response does not assert authority revisions, expiry, role, entitlement,
or secret state. Those facts come only from the stored challenge and the
host's current authoritative re-resolution. A denial is terminal and cannot
produce an accepted consumption receipt.

Issue time must be no later than response time, user-verification time, and
consumption time. Expiry is exclusive at every verification and commit
boundary:

```text
issued_at <= now < expires_at
expires_at - issued_at <= 300,000 milliseconds
```

No clock skew is accepted by this profile. Adapters cannot widen the lifetime
or add local tolerance. Unavailable or backwards-moving trusted time fails
closed.

Every governed context, display, challenge, response, and receipt is one
complete canonical item within the existing 65,536-byte and 16-level nesting
bounds. Unknown, missing, duplicate, out-of-order, ill-typed, excessive, or
trailing data denies before signature or policy evaluation.

## Atomic consumption transaction

The host completion port accepts the exact persisted challenge, exact signed
response, verified device facts, and raw caller-scoped idempotency key. In one
serialisable or equivalent authority transaction it shall:

1. reload the canonical challenge/context and reject absent, malformed,
   cancelled, denied, expired, consumed, or substituted state;
2. verify challenge and response purposes, signatures, exact digest, nonce,
   identifiers, audience, explicit approval, and current trusted time;
3. re-resolve the exact installation, site, authority, tenant, principal,
   role, audience, policy, effective entitlement, revocation, device/key, and
   every secret generation from their owning authorities;
4. compare every resolved value with the canonical governed context;
5. recompute and compare all intent, directive, target, plan, resource-set,
   authority-projection, and idempotency digests;
6. consume the ceremony exactly once;
7. create and sign the exact consumption receipt below;
8. persist that receipt, the idempotent result, and minimised authority/Pistis
   audit events; and
9. commit before returning the receipt.

The receipt signer is an authority-controlled provider using the accepted
untagged COSE profile and a key identifier trusted for the closed receipt
purpose. It has no private-key export path. Signing failure, audit failure,
constraint failure, lock timeout, unavailable authority, drift, concurrency,
or storage ambiguity rolls back the transaction and creates no accepted
outcome.

No mutable action executes inside this transaction. After an accepted receipt
is durably recorded, Oikodome independently revalidates current directive,
target, plan, resource, policy, entitlement, revocation, and secret-generation
state immediately before execution. Drift consumes the approval attempt:
Oikodome records a denied/abandoned lifecycle result and requires a new
operation intent and ceremony. It cannot replay the consumed approval against
changed state.

## Non-secret consumption receipt

`pistis.governed-action-consumption-receipt.v1` is a closed
deterministic-CBOR map signed under the accepted COSE profile:

| Key | Field | Type and constraint |
| ---: | --- | --- |
| 0 | `version` | unsigned integer `1` |
| 1 | `purpose` | exact receipt purpose |
| 2 | `receipt_id` | 16-byte identifier |
| 3 | `installation_id` | 16-byte identifier |
| 4 | `authority_key_id` | 32-byte identifier |
| 5 | `ceremony_id` | 16-byte identifier |
| 6 | `governed_context_digest` | 32-byte SHA-256 digest |
| 7 | `challenge_digest` | 32-byte SHA-256 digest |
| 8 | `principal_id` | 16-byte identifier |
| 9 | `device_id` | 16-byte identifier |
| 10 | `operation_id` | bounded non-secret opaque text identifier |
| 11 | `operation_intent_digest` | 32-byte SHA-256 digest |
| 12 | `directive_id` | bounded non-secret opaque text identifier |
| 13 | `directive_digest` | 32-byte SHA-256 digest |
| 14 | `outcome` | exact text `accepted` |
| 15 | `consumed_at` | unsigned Unix time in milliseconds |
| 16 | `issued_at` | copied governed-context issue time |
| 17 | `expires_at` | copied exclusive expiry |
| 18 | `authority_generation` | unsigned integer |
| 19 | `role_generation` | unsigned integer |
| 20 | `policy_generation` | unsigned integer |
| 21 | `effective_entitlement_generation` | unsigned integer |
| 22 | `revocation_generation` | unsigned integer |
| 23 | `secret_generation_set_digest` | 32-byte SHA-256 digest |
| 24 | `idempotency_digest` | 32-byte digest |
| 25 | `previous_event_digest` | 32-byte authority evidence-chain digest |
| 26 | `audit_ref` | bounded non-secret opaque text reference |
| 27 | `authority_sequence` | unsigned monotonic authority sequence |

`secret_generation_set_digest` is SHA-256 of the exact canonical array from
the governed context. The receipt contains neither the secret references nor
secret values.

The receipt is public verification evidence, not authority to execute. It
contains no browser or Prosopikon session, bearer token, cookie, raw
idempotency key, nonce, signed device response, approval capability, secret
value, secret lease/handle, private key, recovery material, command arguments,
or human-display document. Default debug and operational logs show only
receipt ID, outcome, purpose, and bounded correlation.

Verification requires the exact canonical receipt bytes and COSE envelope,
the trusted authority public key/revision, the accepted governed context, and
the authority's lifecycle/revocation policy. Metadata copied beside a receipt
cannot override signed fields. Unknown purposes, fields, keys, revisions,
algorithms, non-canonical bytes, invalid signatures, chain discontinuity, or
context mismatch deny.

## One ceremony and zero later Pistis calls

The logical Pistis interaction ends when the atomic completion transaction
returns or reconciles the immutable accepted receipt. Transport retries used
only to retrieve that same committed result are part of the original
interaction and cannot create a second ceremony or authority decision.

Oikodome persists the exact canonical context and receipt with its accepted
directive epoch. Every subsequent evidence task or settlement shall:

1. load the accepted epoch, context, and receipt;
2. verify their canonical bytes, digests, receipt signature, receipt purpose,
   installation/site/audience, operation/directive identities, historical
   `issued_at <= consumed_at < expires_at`, and evidence-chain relationship;
3. verify that the settlement refers to that exact accepted epoch; and
4. apply Oikodome's current execution/readiness and supersession policy.

It makes zero Pistis calls, consumes no approval again, and never treats
current Pistis availability as evidence freshness. Missing, corrupt,
unverifiable, superseded, or ambiguous accepted evidence fails closed and
requires manual recovery. This historical verification does not permit a
receipt to approve another directive or prove that current mutable state is
still ready.

## Idempotency, crashes, and recovery

The authority store uniquely binds ceremony ID, operation ID, context digest,
and idempotency digest. An exact retry after commit returns the byte-identical
stored receipt and does not reverify the mobile response, invoke the signer,
append another audit event, consume another ceremony, or create another
authority sequence. A different request under any of those identifiers is a
conflict and denies.

The commit occurs before the response is exposed. A crash before commit leaves
no accepted receipt and the ceremony may be retried only if every original
byte, authoritative generation, decision, and freshness check still passes. A
crash after commit is reconciled through an authenticated exact-receipt lookup
using the original host idempotency material. Lookup returns only the matching
non-secret receipt; neutral not-found, unauthorised, mismatched, and unavailable
outcomes do not reveal another operation.

If commit status, evidence-chain head, receipt signature, authority sequence,
or store integrity cannot be established, the system stops. It preserves all
non-secret diagnostic artefacts and requires a documented, separately
authorised manual recovery. It does not delete ambiguous records, manufacture
a receipt, reset one-use state, reuse the human response, roll back a sequence,
select cached generations, or fall back to generic version 2 approval.

## Compatibility and migration

Version 1 login and version 2 exact-action challenge, response, descriptor,
fixtures, purpose strings, execution grants, and local-agent receipts remain
byte-for-byte unchanged. Neither protocol can satisfy this governed profile.
In particular, an Oikodome intent placed in a generic V2 resource string or
digest does not become governed approval.

Implementation will add parallel request, response, context, display, receipt,
and host-completion types. No existing record is auto-upgraded. Older generic
approvals remain useful only for their original exact-command scope and cannot
be imported as accepted Oikodome directive evidence.

The additive types are expected to be a minor release after acceptance and
implementation. Changing any closed field, integer key, purpose, digest,
ordering, time, atomicity, receipt, or zero-later-call rule requires a new
profile version and migration decision. Removal or incompatible alteration of
existing V1/V2 contracts requires separate major-version agreement.

During migration, Oikodome may use explicitly fixture-only ports for
development. Such fixtures cannot set production readiness, onboard a real
host, accept a real directive, settle production evidence, or be represented
as a permanent Pistis revision.

## Consequences

- Human intent, authority context, mutable generations, and the immutable
  infrastructure target become cryptographically inseparable.
- Pistis participates once at directive acceptance rather than becoming an
  online dependency of every evidence task.
- The host transaction and Oikodome lifecycle have separate, explicit
  revalidation responsibilities.
- Durable exact retry can recover a lost response without another biometric
  ceremony.
- More canonical types, mobile presentation work, authority-store state, and
  cross-product fixtures are required.

## Security and privacy

The profile prevents login, generic-command, purpose, domain, audience, tenant,
role, target, intent, generation, expiry, and replay substitution when all
owners enforce the complete transaction. It does not protect against a
compromised authorised device, host authority, receipt-signing key, trusted
time source, or Oikodome executor.

Canonical challenges and human display may contain user and infrastructure
metadata and must remain inside protected ceremony storage. Receipts minimise
that data and contain no reusable authority. Audit retention, export, legal,
and data-subject policy remain independently governed.

## Alternatives considered

- Add ad hoc V2 arguments/resources: rejected because meaning and display
  would be adapter-specific and authority revisions would remain unsigned.
- Put only one opaque context digest in the challenge: rejected because mobile
  clients could not independently display and validate the complete meaning.
- Return an execution token: rejected because it creates a bearer and moves
  operation authority out of Oikodome.
- Recontact Pistis during each evidence settlement: rejected because approval
  is a historical accepted fact, not recurring online authorisation.
- Delay consumption until execution succeeds: rejected because mutable-state
  drift could permit replay against a changed target.
- Automatically repeat a ceremony after ambiguity: rejected because neither
  the device response nor human intent may be replayed into uncertain state.

## Validation required after acceptance

- Shared Rust, iOS, and Android fixtures must publish exact positive canonical
  context, display, challenge, response, receipt payload, and COSE bytes.
- Negative fixtures must mutate every identifier, digest, generation, action,
  purpose, field, type, width, order, decision, time, nonce, audience, and
  signature independently and require denial.
- Transaction tests must inject failure before and after every re-resolution,
  consume, signature, receipt, idempotency, audit, sequence, and commit stage.
- Restart and concurrency tests must prove exactly one receipt, audit event,
  consumption, and sequence advancement; exact retry returns identical bytes.
- Drift tests must cover authority, tenant, principal, role, device/key,
  policy, entitlement, revocation, every secret generation, directive, target,
  plan, resource set, trusted time, and execution-time state.
- Evidence-settlement tests must assert zero Pistis calls and denial for
  missing, corrupt, superseded, cross-epoch, or context-mismatched evidence.
- Leak-negative tests must reject or redact sessions, cookies, raw
  idempotency keys, nonces, responses, tokens, secret values/references,
  leases, private keys, recovery material, and complete display documents.
- Existing V1 login and V2 exact-action fixtures must remain byte-identical and
  incapable of satisfying the governed completion port.
- Local and GB10 format, Clippy, tests, rustdoc, architecture, language,
  documentation, dependency-policy, and security checks must pass at the exact
  permanent revision before implementation is accepted.
