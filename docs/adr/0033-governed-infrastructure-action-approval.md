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
| 29 | `authoritative_read_set_digest` | 32-byte digest defined below |

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

`authoritative_read_set_digest` is SHA-256 of the exact canonical
`pistis.governed-action-authoritative-read-set.v1` bytes materialised by the
host. That closed internal object contains every context value resolved from
Prosopikon, Oikodome, Thesaurophylax, policy, entitlement, and revocation
owners, plus each owner's stable revision identifier. At completion the owner
conditionally prepares that exact revision and returns a separate opaque
prepare handle. Prepare handles are host-internal, non-bearer material and
never enter the read set, challenge, receipt, browser, mobile client, logs, or
exported evidence.

The read set is this closed canonical map:

| Key | Field | Type and constraint |
| ---: | --- | --- |
| 0 | `version` | unsigned integer `1` |
| 1 | `purpose` | exact text `pistis.governed-action-authoritative-read-set.v1` |
| 2 | `context_bindings_digest` | SHA-256 of canonical context keys 2 through 28 |
| 3 | `installation_revision` | bounded immutable text revision |
| 4 | `prosopikon_revision` | bounded immutable text revision |
| 5 | `oikodome_revision` | bounded immutable text revision |
| 6 | `thesaurophylax_revision` | bounded immutable text revision |
| 7 | `policy_revision` | bounded immutable text revision |
| 8 | `entitlement_revision` | bounded immutable text revision |
| 9 | `revocation_revision` | bounded immutable text revision |
| 10 | `receipt_trust_revision` | bounded immutable text revision |

`context_bindings_digest` hashes one closed canonical map retaining the
original context integer keys 2 through 28 and their exact values; it excludes
version, purpose, and key 29 to avoid self-reference. Each revision identifies
the complete owner projection used to derive those values. Missing,
unresolvable, mutable, or projection-mismatched revision identifiers deny.

Acceptance-relevant mutable facts must use one of these two authority models:

1. the installation host owns an authoritative materialised projection whose
   updates and governed acceptance participate in the same serialisable
   transaction; or
2. the owning authority supplies a conditional prepare fence which reserves
   the exact revision until the host commits or aborts it under a bounded
   two-phase protocol.

A normal remote read followed by an unconditional host write is not an
authority transaction. If any owner cannot provide one of the two models, if
a fence expires, or if prepare, compare, commit, or abort has an ambiguous
outcome, governed acceptance is unavailable and fails closed.

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
| 11 | `target_fingerprint` | exact fingerprint of context key 18 |
| 12 | `target_digest_fingerprint` | exact fingerprint of context key 19 |
| 13 | `plan_digest_fingerprint` | exact fingerprint of context key 20 |
| 14 | `resource_set_digest_fingerprint` | exact fingerprint of context key 21 |
| 15 | `authority_name` | text |
| 16 | `authority_fingerprint` | exact fingerprint of context key 4 |

Names are 1 through 128 UTF-8 bytes and summaries are 1 through 512 UTF-8
bytes. Control characters, Unicode `Bidi_Control`, Unicode
`Default_Ignorable_Code_Point`, and noncharacters are forbidden. Text is not
normalised or case-folded. Renderers add their own directional isolation
outside the signed strings and must not insert, remove, or reorder signed
content. Display text is signed and retained only in the protected ceremony
record, but it is not authority: the canonical identifiers, revisions, and
digests remain decisive.

A display fingerprint is the first 12 lower-case hexadecimal characters of
SHA-256 of the identifier's exact raw byte-string value, exact UTF-8 text
value, or exact 32-byte digest value, rendered as `hhhh-hhhh-hhhh`. CBOR
headers are not part of that input. It is a human comparison aid only; all
machine checks use the complete value. The secret-generation-set fingerprint
applies the same rule to SHA-256 of the exact canonical array.

Every display value has one deterministic source. The installation, site,
tenant, principal, role, and authority labels map respectively to context keys
2, 3, 6, 7, 10, and 4 through authority-owned label projections;
`action_label` maps only from action class `1`; `target_name` maps from the
immutable target projection bound by keys 18 and 19; fields 11 through 14
derive from context keys 18 through 21; and field 16 derives from context key
4. Intent and consequence summaries map from the immutable operation-intent
projection bound by key 15. A missing mapping, a projection digest mismatch,
or two labels for one bound identifier denies.

The mobile presentation must show, without truncation or hidden expansion:

- the installation, site, tenant, principal, role, and authority labels
  alongside stable short fingerprints of their canonical identifiers;
- the fixed action, target, intent, and consequence;
- the directive and intent digest fingerprints;
- every authority, role, policy, entitlement, and revocation generation, plus
  the secret-generation set count and fingerprint;
- the exact audience `oikodome` alongside the installation and Site Trust
  Domain scope; and
- issue time, exclusive expiry, and an explicit `Approve` or `Deny` choice.

Identifier fingerprints use the exact hexadecimal rule above. Generations are
displayed as unsigned base-10 ASCII with no sign, grouping, locale
substitution, or leading zero except the value zero.
Times are displayed both as the complete unsigned Unix-millisecond integer
and as the corresponding fixed UTC form `YYYY-MM-DDTHH:MM:SS.mmmZ`.
Unrepresentable UTC values deny rather than using a locale-dependent fallback.

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

The exact ordering is:

```text
challenge.issued_at == context.issued_at
challenge.expires_at == context.expires_at
challenge.issued_at <= response.user_verified_at
response.user_verified_at <= response.issued_at
response.issued_at <= consumed_at
consumed_at <= committed_at
committed_at < expires_at
expires_at - issued_at <= 300,000 milliseconds
```

Every subtraction and comparison is checked before evaluation and all values
must be representable by the fixed UTC display. `consumed_at` is sampled after
response verification and authoritative prepare; `committed_at` is sampled at
the final commit boundary. No clock skew is accepted by this profile.
Adapters cannot widen the lifetime or add local tolerance. Unavailable,
overflowing, or backwards-moving trusted time fails closed.

For challenge, response, receipt, trust projection, and chain-checkpoint COSE
objects, `alg` and `kid` are protected headers and the unprotected map is
empty. Challenge `kid` equals `installation_key_id`; response `kid` equals
`device_key_id`; receipt and checkpoint `kid` equal their payload
`authority_key_id`. Equality is byte-for-byte and is checked before signature
verification. A missing, duplicate, unprotected, or unequal `kid` denies.

Every governed context, display, challenge, response, and receipt is one
complete canonical item within the existing 65,536-byte and 16-level nesting
bounds. Unknown, missing, duplicate, out-of-order, ill-typed, excessive, or
trailing data denies before signature or policy evaluation.

## Atomic consumption and authority fences

The host completion port accepts the exact persisted challenge, exact signed
response, verified device facts, and raw caller-scoped idempotency key. It
first opens or reloads one durable completion record and then:

1. reloads the canonical challenge/context and rejects absent, malformed,
   cancelled, denied, expired, consumed, or substituted state;
2. verifies challenge and response purposes, signatures, exact digest, nonce,
   identifiers, audience, explicit approval, and current trusted time;
3. materialises the exact installation, site, authority, tenant, principal,
   role, audience, policy, effective entitlement, revocation, device/key,
   Oikodome operation/directive/target/plan/resource, and every secret
   generation from their owning authorities;
4. compares every value and canonical projection digest with the governed
   context and verifies `authoritative_read_set_digest`;
5. prepares every owner revision fence and records the exact prepared fence
   set in the completion record;
6. follows the recoverable receipt-signing protocol below;
7. after the exact receipt signature is durable, rechecks trusted time and
   conditionally compares every prepared fence;
8. in one serialisable host commit durably records coordinator decision
   `COMMIT`, consumes the ceremony, advances the exact evidence-chain head, and
   persists the receipt, idempotent result, minimised audit events, and
   committed read-set digest; and
9. after recovering that durable decision, sends only `COMMIT` to every
   prepared authority participant and obtains a durable successful outcome
   from each before reporting success.

The final compare and host commit are one transaction for host-owned
projections. External owner state may participate only through the bounded
prepare/commit protocol: all owners must be successfully prepared before
signing; an owner commit failure or uncertain outcome makes the completion
ambiguous and requires manual reconciliation. The host never substitutes a
fresh read, cached generation, best-effort validation, or an unconditional
write. These rules include the signing-key/trust projection and Oikodome's
immutable projections, removing a signing-provider or cross-owner
time-of-check/time-of-use gap.

The completion record is the durable two-phase coordinator and has the closed
decision states `PREPARE`, `COMMIT`, and `ABORT`. `PREPARE` binds the exact
participant set, revision, prepare handle, and operation identifier for each
owner. A denial before the serialisable host commit atomically changes
`PREPARE` to `ABORT`; only after that durable decision may the coordinator send
idempotent `ABORT` to every participant. The serialisable host commit
atomically changes `PREPARE` to `COMMIT` with the receipt and chain changes
above. Once `COMMIT` is durable, neither normal processing nor recovery may
write or send `ABORT`; it may only repeat byte-identical, idempotent `COMMIT`
for the recorded handles until every participant proves commit. Once `ABORT`
is durable, neither path may write or send `COMMIT`.

A crash or uncertain host-commit response is not a decision. Recovery first
reads the local serialisable coordinator record and verifies its integrity. It
sends no participant decision while the local outcome is absent, unreadable,
conflicting, or otherwise uncertain. A recovered `COMMIT` drives only commit;
a recovered `ABORT` drives only abort; a recovered `PREPARE` may become
`ABORT` only after the authority store proves that the host transaction never
committed. Mixed participant outcomes, a participant that cannot prove its
decision, or any coordinator fork remains ambiguous and blocks checkpoint
creation and evidence release. Manual reconciliation must preserve the durable
coordinator decision and can never compensate a committed participant by
aborting it.

The receipt signer is an authority-controlled idempotent provider using the
accepted untagged COSE profile and a key identifier trusted for the closed
receipt purpose. It has no private-key export path. A signed but uncommitted
receipt is an orphan, not accepted evidence, and is never returned or exported.
Constraint, lock, authority, drift, concurrency, audit, storage, participant,
or signer ambiguity fails closed under the state machine below.

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
| 28 | `authority_key_generation` | bounded immutable text identifier |
| 29 | `trust_projection_ref` | bounded public immutable reference |
| 30 | `trust_projection_digest` | 32-byte SHA-256 digest |
| 31 | `authoritative_read_set_digest` | exact digest from the context |
| 32 | `evidence_chain_scope_digest` | 32-byte digest defined below |

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
the public trust projection, the accepted governed context, and an
authoritative commit proof defined below. Metadata copied beside a receipt
cannot override signed fields. Unknown purposes, fields, keys, revisions,
algorithms, non-canonical bytes, invalid signatures, chain discontinuity,
missing authoritative inclusion, or context mismatch deny.

The immutable public trust projection is the signed closed profile defined
below. Its exact canonical payload and COSE bytes are retained with exported
evidence. `trust_projection_digest` is SHA-256 of the exact untagged
COSE_Sign1 bytes, not of metadata or a re-encoded payload. The projection
reference and digest in the receipt must resolve to and match those bytes.

### Receipt-signing trust and lifecycle projection

The trust-chain scope is the exact canonical map:

```text
{
  0: 1,
  1: "pistis.governed-action-receipt-trust-scope.v1",
  2: installation_id,
  3: site_trust_domain_id,
  4: authority_id,
  5: "oikodome",
  6: "pistis.governed-action-consumption-receipt.v1",
  7: authority_key_id,
  8: authority_key_generation
}
```

`receipt_trust_scope_digest` is SHA-256 of those exact bytes. The scope fixes
one receipt-signing key generation; a replacement receipt key starts a new
scope and cannot make an older receipt currently ready.

`pistis.governed-action-receipt-trust-projection.v1` is this closed canonical
map:

| Key | Field | Type and constraint |
| ---: | --- | --- |
| 0 | `version` | unsigned integer `1` |
| 1 | `purpose` | exact projection purpose |
| 2 | `receipt_trust_scope_digest` | exact 32-byte scope digest |
| 3 | `revision` | unsigned 64-bit integer beginning at `1` |
| 4 | `previous_projection_digest` | 32-byte digest defined below |
| 5 | `authority_key_id` | exact 32-byte receipt-signing key identifier |
| 6 | `authority_key_generation` | bounded immutable text identifier |
| 7 | `receipt_cose_algorithm` | accepted non-zero signed COSE algorithm integer |
| 8 | `receipt_public_key` | 1 through 4,096 canonical suite-defined public-key bytes |
| 9 | `key_not_before` | unsigned Unix time in milliseconds |
| 10 | `key_not_after` | unsigned Unix time in milliseconds, exclusive |
| 11 | `lifecycle_state` | closed unsigned integer defined below |
| 12 | `lifecycle_effective_at` | unsigned Unix time in milliseconds |
| 13 | `policy_generation` | unsigned integer |
| 14 | `revocation_generation` | unsigned integer |
| 15 | `issued_at` | unsigned Unix time in milliseconds |
| 16 | `expires_at` | unsigned Unix time in milliseconds, exclusive |
| 17 | `projection_signer_key_id` | 32-byte identifier |
| 18 | `projection_signer_key_generation` | bounded immutable text identifier |
| 19 | `projection_signer_cose_algorithm` | accepted non-zero signed COSE algorithm integer |
| 20 | `projection_signer_public_key` | 1 through 4,096 canonical suite-defined public-key bytes |
| 21 | `next_projection_signer` | closed signer map defined below |

The lifecycle registry is `1` `active`, `2` `retiring`, `3`
`revoked-routine`, `4` `revoked-compromise`, and `5` `destroyed`. Zero and
unknown values deny. The signer map is:

| Key | Field | Type and constraint |
| ---: | --- | --- |
| 0 | `key_id` | exact 32-byte identifier authorised for revision plus one |
| 1 | `key_generation` | bounded immutable text identifier |
| 2 | `cose_algorithm` | accepted non-zero signed COSE algorithm integer |
| 3 | `public_key` | 1 through 4,096 canonical suite-defined public-key bytes |
| 4 | `not_before` | unsigned Unix time in milliseconds |

All projection text uses the opaque-text rule above. The receipt algorithm and
public key are immutable within a scope and must verify the receipt COSE
signature. `key_not_before < key_not_after`,
`key_not_before <= lifecycle_effective_at <= issued_at < expires_at`, and
`expires_at - issued_at <= 300,000` milliseconds are checked without
overflow. Projection expiry limits current-readiness proof; it does not erase
a retained historical statement.

Projection revision `1` alone uses 32 zero bytes for
`previous_projection_digest` and its signer tuple must equal one configured
installation trust anchor for this exact scope. Every later revision is exactly
the previous revision plus one, without wrap, and
`previous_projection_digest` is SHA-256 of the exact preceding untagged
COSE_Sign1 projection bytes. Its signer tuple must equal the predecessor's
complete `next_projection_signer` tuple, and its `issued_at` must be at or
after that tuple's `not_before`. The projection's protected COSE `alg` and
`kid` equal `projection_signer_cose_algorithm` and
`projection_signer_key_id` byte for byte; the unprotected map and external AAD
are empty. The signature verifies with the exact
`projection_signer_public_key`. A rotation is therefore authorised only by the
previous signer in the previous signed projection. Repeating the current tuple
retains the signer. No unsigned alias, local key lookup, skipped revision,
second genesis, parallel successor, or out-of-band signer substitution is
accepted.

Installation, scope, receipt-key tuple, key interval, and receipt purpose never
change within a chain. Policy and revocation generations never decrease.
`active` may move to `retiring`, either revocation state, or `destroyed`;
`retiring` may move only to either revocation state or `destroyed`;
`revoked-routine` may move only to `revoked-compromise` or `destroyed`; and
`revoked-compromise` and `destroyed` are terminal. Repeating a state requires
the same effective time. Routine transition effective times cannot move
backwards. A compromise projection may set an earlier, evidence-supported
effective time within the key interval; that earlier time deliberately makes
overlapping historical use indeterminate. Any other state reversal, fork,
generation rollback, time rollback, or changed immutable field denies.

Current readiness also requires an exact signed head statement.
`pistis.governed-action-receipt-trust-head.v1` is this closed canonical map:

| Key | Field | Type and constraint |
| ---: | --- | --- |
| 0 | `version` | unsigned integer `1` |
| 1 | `purpose` | exact head purpose |
| 2 | `receipt_trust_scope_digest` | exact 32-byte scope digest |
| 3 | `latest_revision` | exact unsigned 64-bit revision |
| 4 | `latest_projection_digest` | SHA-256 of exact latest projection COSE bytes |
| 5 | `issued_at` | unsigned Unix time in milliseconds |
| 6 | `expires_at` | unsigned Unix time in milliseconds, exclusive |
| 7 | `projection_signer_key_id` | exact latest-projection signer identifier |
| 8 | `projection_signer_key_generation` | exact latest-projection signer generation |

The head COSE protected `alg` and `kid`, empty unprotected map, empty external
AAD, signer tuple, and signature follow the latest projection. Its exact time
rule is `issued_at <= now < expires_at` and
`expires_at - issued_at <= 300,000` milliseconds, checked without overflow.
The authority store conditionally appends one successor and atomically updates
an anti-rollback tuple of scope, latest revision, and latest projection digest.
The local verifier requires the head payload, its signature, the complete
gap-free projection chain, and that authoritative anti-rollback tuple all to
name the same latest revision and digest. A stale, future, expired, missing,
forked, rolled-back, or merely caller-asserted head blocks current readiness.
Historical analysis may retain an older complete prefix but must label it
non-current and cannot use it as latest-state proof.

Historical verification and current readiness are separate decisions. Routine
retirement or revocation effective strictly after `consumed_at` preserves a
historical accepted result when the retained projection proves that the key
was active and uncompromised at `consumed_at`. Deliberate key destruction
strictly after `consumed_at` has the same historical treatment when its time
and reason are proven and the retained public key remains verifiable. A
compromise or destruction with an unknown or overlapping effective interval,
or any uncertain key history, makes historical validity indeterminate and
fail-closed pending a separately reviewed adjudication. No retired, revoked,
compromised, destroyed, or historically accepted key establishes current
readiness.

The local evidence bundle retains the receipt-bound projection and every
subsequent signed lifecycle projection known to the installation, ordered by
monotonic revision. Historical verification applies all retained projections
to `consumed_at`; it does not let a later routine event rewrite the earlier
cryptographic fact. Current readiness additionally requires the locally
authoritative latest projection and signed head to be present, mutually
consistent, active, uncompromised, within the receipt-key interval, and
unexpired. An unavailable or potentially stale projection, head, or
anti-rollback tuple blocks readiness without causing a Pistis ceremony or
consumption call.

## Evidence-chain definition and committed inclusion

The evidence-chain scope is the exact canonical map:

```text
{
  0: 1,
  1: "pistis.governed-action-evidence-chain-scope.v1",
  2: installation_id,
  3: site_trust_domain_id,
  4: authority_id,
  5: "oikodome"
}
```

`evidence_chain_scope_digest` is SHA-256 of those exact bytes. Each scope has
an independent unsigned 64-bit sequence beginning at `1`. Sequence `1` alone
uses 32 zero bytes as `previous_event_digest`. Every later receipt uses the
current head digest and exactly the previous sequence plus one. A sequence at
`2^64 - 1` is exhausted and denies without wrapping, resetting, or creating a
second genesis.

The event digest is:

```text
SHA-256(
  "pistis.governed-action-evidence-event.v1\0" ||
  exact canonical receipt payload bytes ||
  exact untagged COSE_Sign1 receipt bytes
)
```

The literal domain separator is ASCII including its final NUL byte.
Cross-scope predecessors deny. ADR 0019 and all legacy evidence chains remain
separate domains: they are not imported, linked, renumbered, or used as a
genesis for this profile.

A receipt signature alone is not proof of commit. After the receipt event is
committed, an authority-controlled checkpoint signer must read that exact
committed row and sign
`pistis.governed-action-chain-checkpoint.v1`, this closed canonical map:

| Key | Field | Type and constraint |
| ---: | --- | --- |
| 0 | `version` | unsigned integer `1` |
| 1 | `purpose` | exact checkpoint purpose |
| 2 | `checkpoint_id` | 16-byte identifier |
| 3 | `evidence_chain_scope_digest` | exact 32-byte scope digest |
| 4 | `head_sequence` | unsigned 64-bit integer |
| 5 | `head_event_digest` | 32-byte event digest |
| 6 | `committed_at` | unsigned Unix time in milliseconds |
| 7 | `authority_key_id` | 32-byte identifier |
| 8 | `authority_key_generation` | bounded immutable text identifier |
| 9 | `trust_projection_digest` | 32-byte SHA-256 digest |

The signer interface refuses any event absent from the committed authority
store and verifies the scope, sequence, event digest, committed time, key
generation, and projection digest against that row before signing. Checkpoint
eligibility additionally requires every prepared owner commit to have a
durable successful outcome; pending, failed, or uncertain participants deny
checkpoint signing. Its authority key ID, generation, and trust-projection
digest must equal the committed receipt. Checkpoint signing uses a separately
durable idempotent provider operation under the same unknown-outcome rules as
receipt signing. No accepted evidence is released until the exact checkpoint
signature and checkpoint record are durable. The checkpoint head for this
export must equal the receipt sequence and event digest; later heads cannot
stand in without a separately specified inclusion proof.

## One ceremony and zero later Pistis calls

The logical Pistis interaction ends when the atomic completion transaction
returns or reconciles the immutable committed evidence bundle. Transport
retries used only to retrieve that same committed result are part of the
original interaction and cannot create a second ceremony or authority
decision.

Oikodome gains an additive, receipt-only
`verify_governed_approval_evidence_v1` port. Its input is a closed
`GovernedApprovalEvidenceBundleV1` containing the exact canonical context or
protected context projection defined below, receipt payload and COSE envelope,
the exact receipt-trust scope, receipt-bound and subsequent public trust
projections, current signed trust head and local anti-rollback tuple,
evidence-chain scope, and authoritative checkpoint. The port accepts only
local immutable bytes and configured public trust anchors. It has no Pistis
ceremony, completion, consumption, signing, or network callback and produces a
non-serialisable
`VerifiedGovernedApprovalEvidenceV1` result, never a bearer.

The alternative minimum projection is
`pistis.governed-action-context-projection.v1`, this closed canonical map:

| Key | Field | Type and constraint |
| ---: | --- | --- |
| 0 | `version` | unsigned integer `1` |
| 1 | `purpose` | exact projection purpose |
| 2 | `context_ref` | bounded immutable DASObjectStore reference |
| 3 | `governed_context_digest` | 32-byte SHA-256 digest |
| 4 | `installation_id` | 16-byte identifier |
| 5 | `site_trust_domain_id` | bounded opaque text identifier |
| 6 | `audience` | exact text `oikodome` |
| 7 | `operation_id` | bounded opaque text identifier |
| 8 | `operation_intent_digest` | 32-byte digest |
| 9 | `directive_id` | bounded opaque text identifier |
| 10 | `directive_digest` | 32-byte digest |
| 11 | `target_digest` | 32-byte digest |
| 12 | `plan_digest` | 32-byte digest |
| 13 | `resource_set_digest` | 32-byte digest |
| 14 | `issued_at` | exact context issue time |
| 15 | `expires_at` | exact context exclusive expiry |
| 16 | `consumed_at` | exact receipt consumption time |
| 17 | `receipt_ref` | bounded immutable reference |
| 18 | `receipt_digest` | 32-byte digest of exact COSE receipt bytes |
| 19 | `trust_projection_ref` | exact receipt trust reference |
| 20 | `trust_projection_digest` | exact receipt trust digest |
| 21 | `checkpoint_ref` | bounded immutable reference |
| 22 | `checkpoint_digest` | 32-byte digest of exact COSE checkpoint bytes |
| 23 | `evidence_chain_scope_digest` | exact 32-byte scope digest |
| 24 | `authority_sequence` | exact receipt sequence |
| 25 | `event_digest` | exact 32-byte event digest |

The verifier resolves `context_ref` only through the local owner-restricted
DASObjectStore interface, recomputes every digest, and compares every projected
field with the resolved canonical context and receipt. It does not accept a
projection when the referenced context is unavailable.

Every subsequent evidence task or settlement shall:

1. load the accepted epoch and its exact evidence bundle;
2. verify their canonical bytes, digests, receipt signature, receipt purpose,
   installation/site/audience, operation/directive identities, historical
   time ordering, signing-key generation and lifecycle, exact event digest,
   and checkpoint inclusion;
3. verify that the settlement refers to that exact accepted epoch; and
4. apply Oikodome's current execution/readiness and supersession policy.

It makes zero Pistis calls, consumes no approval again, and never treats
current Pistis availability as evidence freshness. Missing, corrupt,
unverifiable, superseded, or ambiguous accepted evidence fails closed and
requires manual recovery. This historical verification does not permit a
receipt to approve another directive or prove that current mutable state is
still ready.

Oikodome stores the exact context only in owner-restricted encrypted storage.
Where that is unavailable it stores the immutable DASObjectStore reference
and minimum projection above. The reference is not a bearer. Missing, mutable,
unauthorised, digest-mismatched, or unavailable context storage fails closed
and requires manual recovery. Human display, secret references, device
response, session material, and bearer material are excluded.

This port is parallel to existing login and V2 exact-action verifiers.
Existing frozen fixtures and behaviours are not reinterpreted, widened, or
used as fallback.

## Idempotency, crashes, and recovery

The authority store uniquely binds ceremony ID, operation ID, context digest,
and idempotency digest. Before invoking the receipt signer, it durably stores
one `pending_signature` record containing the exact canonical unsigned receipt
payload bytes, receipt ID, reserved sequence, predecessor digest, chain scope,
authority key ID and generation, trust projection, read-set digest, and a
unique provider operation ID. It also stores the exact protected-header bytes,
empty unprotected map, empty external AAD, and Sig_structure bytes supplied to
the provider. Those values are never regenerated after the first durable
write.

`receipt_signing_input_digest` is:

```text
SHA-256(
  "pistis.governed-action-receipt-signing-input.v1\0" ||
  exact persisted canonical Sig_structure bytes
)
```

The Sig_structure already contains the exact protected-header bytes, empty
external AAD, and exact receipt payload bytes. The provider operation is
idempotent for exactly `(provider_operation_id,
receipt_signing_input_digest)` and returns either the byte-identical prior
signature or one new signature. Reuse of the operation identifier with any
different signing-input digest is a terminal provider conflict, including a
change to payload, protected `alg`, protected `kid`, external AAD, framing, or
canonical encoding.

Before constructing or persisting COSE bytes, the host requires the returned
signature to verify with the prepared receipt key over the exact persisted
Sig_structure and requires the provider's result identity and signing-input
digest to equal the pending record. After that verification, the host durably
records the exact COSE bytes as `signed_pending_commit`, then performs the
final time and owner-fence comparison and atomic host commit. A failed final
comparison does not make the orphan signature accepted; the record is retained
for diagnosis, the ceremony cannot authorise changed state, and a new operation
intent and ceremony are required.

Recovery reloads the exact pending bytes and provider operation ID and queries
only that idempotent operation. It accepts only the exact signature already
bound to that signing-input digest and cryptographically verifies it again
against the exact persisted Sig_structure before any state transition.
Provider `not-found` is retryable only when the provider authoritatively proves
that exact `(provider_operation_id, receipt_signing_input_digest)` was never
processed, and even then only through a documented manual recovery which
resubmits the byte-identical operation. There is no automatic resign path.
`unknown`, timeout, lost response, contradictory status, input-digest mismatch,
signature-verification failure, or inability to prove absence transitions the
record to `ambiguous`; the host does not resign, allocate another ID or
sequence, change the predecessor, reuse the response in a new record, or
release evidence. Recovery is manual and fail-closed.

After the receipt commit, checkpoint creation has its own durable pending
payload, provider operation ID, exact-result recovery, and
`unknown => ambiguous` rule. Its provider tuple substitutes the exact
domain-separated `checkpoint_signing_input_digest`, using ASCII
`pistis.governed-action-checkpoint-signing-input.v1` plus NUL and the exact
persisted checkpoint Sig_structure, and applies every input-equality and
signature-verification rule above. An exact retry after both commits returns
the byte-identical stored evidence bundle and does not reverify the mobile
response, invoke either signer, append another audit event, consume another
ceremony, or advance another sequence. If the receipt is committed but its
checkpoint is pending or ambiguous, the acceptance remains internal and
unusable until the exact checkpoint operation is reconciled; no second
ceremony can repair or replace it.

A crash before the receipt commit leaves no accepted receipt. A crash after
that commit is reconciled through authenticated exact-result lookup using the
original host idempotency material. Lookup returns only the matching
non-secret committed bundle; neutral not-found, unauthorised, mismatched, and
unavailable outcomes reveal no other operation.

If participant commit status, evidence-chain head, signature, sequence,
checkpoint inclusion, or store integrity cannot be established, the system
stops. It preserves all non-secret diagnostic artefacts and requires a
documented, separately authorised manual recovery. It does not delete
ambiguous records, manufacture evidence, reset one-use state, reuse the human
response, roll back a sequence, select cached generations, or fall back to
generic version 2 approval.

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
  context, display, challenge, response, receipt, trust projection and
  checkpoint payload and COSE bytes, plus chain scope and event digests.
- Negative fixtures must mutate every identifier, digest, generation, action,
  purpose, field, type, width, order, decision, time, nonce, audience, and
  signature independently and require denial.
- Transaction tests must inject failure before and after every owner prepare,
  durable coordinator decision, fence comparison, re-resolution,
  receipt-signing request/result persistence, consume, receipt, idempotency,
  audit, sequence, participant commit, host commit, checkpoint
  lookup/signing/result persistence, and release stage. Crash tests must prove
  that a durable host `COMMIT` can send only participant `COMMIT`, a durable
  `ABORT` can send only participant `ABORT`, and an uncertain host outcome
  sends neither.
- Restart and concurrency tests must prove exactly one receipt, audit event,
  consumption, sequence advancement, event and checkpoint; exact retry returns
  identical bytes. Signer tests must cover exact-result recovery, proven
  never-signed retry, payload conflict, unknown outcome, orphan signature, and
  the prohibition on resigning or reallocating identity/sequence/predecessor.
- Drift tests must cover authority, tenant, principal, role, device/key,
  policy, entitlement, revocation, every secret generation, directive, target,
  plan, resource set, signing-key trust projection, owner fence, trusted time,
  and execution-time state.
- Evidence-settlement tests must use call-counting ceremony, completion,
  consumption, signer, and network fakes to assert zero calls and denial for
  missing, corrupt, uncommitted, uncheckpointed, superseded, cross-scope,
  cross-epoch, legacy-chain, overflow, or context-mismatched evidence.
- Presentation fixtures must cover exact fingerprints, context/display
  mapping, decimal generations, integer/UTC time pairs, Unicode bidi controls,
  default-ignorable code points, noncharacters, and labels requiring renderer
  isolation.
- Key-lifecycle tests must distinguish active, routine post-consumption
  retirement/revocation, overlapping or unknown compromise, destruction, and
  historical validity from current readiness. Trust fixtures must freeze the
  exact scope, genesis, successor, signer-retention, signer-rotation, lifecycle
  transition, signed-head, expiry, anti-rollback, fork, gap, and overflow
  cases. COSE tests must independently mutate protected and unprotected `kid`,
  `alg`, key generation, trust projection, persisted Sig_structure, external
  AAD, and both domain-separated signing-input digests.
- Leak-negative tests must reject or redact sessions, cookies, raw
  idempotency keys, nonces, responses, tokens, secret values/references,
  leases, private keys, recovery material, and complete display documents.
- Existing V1 login and V2 exact-action fixtures must remain byte-identical and
  incapable of satisfying the governed completion port.
- Local and GB10 format, Clippy, tests, rustdoc, architecture, language,
  documentation, dependency-policy, and security checks must pass at the exact
  permanent revision before implementation is accepted.
