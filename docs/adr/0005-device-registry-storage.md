# ADR 0005: Device registry storage and lifecycle

- Status: Accepted
- Date: 2026-07-24
- Owners: Device, persistence, and security

## Context

Pistis installations must retain device public keys, assurance claims, and
lifecycle state without acquiring a central service dependency. This state is
security-sensitive: treating corrupt data as an empty or active registry,
silently elevating an unknown assurance claim, or reversing a revocation would
permit an untrusted device to authenticate.

EPIC-5 covers the device-registry portion of milestone M4. It does not deliver
installation identity, local-user policy, the challenge store, administration
interfaces, or the future MySQL-compatible or Hebe-backed adapter.

The existing identity-binding repository is a separate persistence boundary.
It uses an opaque `BindingId`, while device, installation, user, key, and
evidence identifiers already have distinct domain types. Combining the stores
now would expand EPIC-5 and obscure their independent responsibilities.

## Decision

The device registry is a narrowly responsible workspace crate. Its domain
model and repository trait do not expose SQL. The first durable adapter uses
SQLite through `rusqlite` with bundled SQLite so local development and Jenkins
use the same database implementation without a system SQLite dependency.

The registry stores:

- typed device, installation, user, external-identity, key, and evidence
  references;
- one canonical compressed P-256 public key and its derived key identifier;
- platform and bounded application-version metadata;
- structured assurance claims which distinguish verified, reported,
  unavailable, and unknown states;
- enrolment and last-used times;
- the current active, suspended, or revoked state; and
- immutable lifecycle events containing effective time and reason.

There is no private-key field in the domain model or schema. A public key is
validated by `pistis-crypto`, canonicalized, and assigned a derived `KeyId`
before insertion and again after hydration. Assurance values never default to
a stronger state when absent or unrecognized.

Suspension is reversible through an explicit resume transition. Revocation is
terminal. Active or suspended devices may be revoked, but a revoked record can
never be resumed, replaced, or deleted through the repository. Historic
records, keys, assurance data, enrolment evidence references, and lifecycle
events remain readable after revocation.

Writes use an integer revision for optimistic concurrency. A transition,
lifecycle event, and revision increment occur in one immediate transaction.
Competing updates from the same revision allow at most one commit. Recording
device use is monotonic and succeeds only for an active device.

SQLite tables are `STRICT` and use length, enumeration, nullability, lifecycle,
uniqueness, and foreign-key constraints where the referenced data is owned by
the registry. Existing external identity bindings remain opaque references;
the enrolment service must confirm their existence before insertion. This
cross-store validation is not atomic in EPIC-5 and must fail without creating a
device if the binding cannot be resolved.

Migrations are embedded, ordered, and checksummed. The runner enables foreign
keys, validates the SQLite application identifier, takes an immediate
transaction, rejects gaps, checksum drift, partial state, and schemas newer
than the binary, then applies each migration and its history record atomically.
Re-running the runner is a no-op.

Production migrations are forward-only. Operators back up the SQLite database
before upgrading; rollback restores that backup with the previous binary.
Automatic down-migrations are forbidden because they could erase lifecycle or
assurance evidence. Later incompatible changes use an
expand-migrate-contract sequence.

Database corruption, invalid public-key material, unknown enum values,
unsupported schema versions, lock failures, and I/O failures are explicit
repository errors. Callers must fail closed and must not convert them into
`None`, an empty registry, or an active device.

## Consequences

- Standalone installations gain deterministic, transactional device storage.
- Public-key and lifecycle invariants are enforced by both domain code and
  database constraints.
- Revocation preserves historic verification material and is resistant to
  stale concurrent updates.
- Bundled SQLite adds a reviewed native dependency and increases compile time,
  but avoids an undeclared host-library dependency.
- External identity and device enrolment span two stores. Their orchestrator
  must validate the binding first and surface partial-system failures; a
  unified transaction would require a separately reviewed migration.
- The future MySQL-compatible or Hebe adapter must preserve the repository
  contract, transition matrix, and fail-closed hydration behaviour.
- Completing EPIC-5 does not complete milestone M4 or its broader exit gate.

## Alternatives considered

- Extend the JSON identity-binding repository: rejected because concurrent
  lifecycle transitions, constrained migrations, and indexed device lookup
  require a transactional store.
- Use SQLx and an asynchronous runtime: rejected because the current
  repository boundaries are synchronous and EPIC-5 does not otherwise need a
  runtime.
- Store provider identity documents in the registry: rejected because it
  duplicates an existing authority and risks divergent identity state.
- Store assurance as opaque JSON: rejected because missing and unknown values
  could be interpreted inconsistently and cannot be constrained by SQLite.
- Permit whole-record replacement: rejected because it could mutate immutable
  ownership or key fields and reverse terminal revocation.
- Automatically down-migrate: rejected because destructive rollback can erase
  evidence required to explain historic trust decisions.

## Review evidence

The decision was reviewed before schema implementation by independent agents
covering schema and migration design, repository and lifecycle security, and
milestone acceptance/documentation scope. Their review required constrained
SQLite storage, public-key-only persistence, optimistic concurrency, terminal
revocation, explicit suspension recovery, retained historic evidence, and
fail-closed handling of corrupt or unavailable state.
