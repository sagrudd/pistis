# Device registry operations

EPIC-5 provides the standalone SQLite device registry used to retain public
device credentials, assurance claims, and lifecycle history. It completes the
device-registry backlog in `docs/TODO.md`; it does not complete all of
milestone M4. Installation identity, local-user trust policy, the challenge
store, administration interfaces, and MySQL-compatible or Hebe-backed storage
remain separate work.

## Security boundary

The registry contains public verification material only. A device record
contains its canonical P-256 public key and derived key identifier, but the
device private key never enters the installation, repository API, schema,
backup, or diagnostic output. Finding private-key material in or beside the
registry is an incident, not a supported configuration.

External identity bindings are opaque references owned by the identity-binding
repository. The enrolment orchestrator must resolve the binding before it
inserts a device. EPIC-5 does not make that cross-store check transactional;
failure to resolve or persist either side must fail the enrolment without
treating the device as trusted.

Registry absence, an unreadable database, migration failure, corrupt rows,
invalid public keys, unknown enumeration values, and lock or I/O failures are
errors. Operators and calling applications must fail closed. They must never
substitute an empty registry, an active device, or weaker assurance.

## Stored device state

Each device record retains typed installation, user, external-identity,
device, key, and enrolment-evidence references together with:

- the canonical public key and its derived key identifier;
- platform and application-version metadata;
- structured assurance claims;
- enrolment and last-used times;
- the current lifecycle state and optimistic-concurrency revision; and
- immutable lifecycle events with their effective time and reason.

The assurance values `verified`, `reported`, `unavailable`, and `unknown` are
different security statements. Missing or unrecognized data cannot become
`verified`. See [the assurance model](../assurance.md) for interpretation.

## Lifecycle

New registrations begin active. An active device may record use, be suspended,
or be revoked.

A suspension blocks current authorisation without destroying the registration
or its history. Only an explicit resume operation may make a suspended device
active again. Resumption is not an enrolment and must not change the device's
key, owner, assurance, or enrolment evidence.

Revocation is terminal. Active and suspended devices may be revoked, but a
revoked device cannot be resumed, replaced in place, deleted through the
repository, or used for a new authentication or approval. Its public key,
assurance, evidence references, timestamps, reason, and lifecycle events remain
available to explain historic decisions. Device replacement creates a new
device registration and does not mutate the revoked one.

Lifecycle writes use the record revision as an optimistic-concurrency token.
The state change, lifecycle event, and revision increment commit in one SQLite
transaction. A stale competing update fails and must be re-read; callers must
not retry it as an unconditional overwrite.

## Database creation and migration

The application opens the configured SQLite path and runs the embedded,
ordered migrations before serving registry-dependent operations. Migration
validates the SQLite application identifier, migration sequence, and stored
checksums. A clean database is initialized, and reopening a current database
is a no-op.

The runner rejects migration gaps, checksum drift, partial migration history,
and a schema newer than the binary. Do not edit an already released migration.
Add a new forward migration and preserve old fields until all supported
readers have moved through an expand-migrate-contract sequence.

The SQLite adapter uses strict tables, constraints, foreign keys for
registry-owned records, and immediate transactions. Do not bypass the
repository with ad hoc SQL: doing so can evade public-key validation,
lifecycle rules, or concurrency checks.

## Backup, upgrade, and rollback

Stop or quiesce registry writers and take a consistent SQLite backup before
upgrading the binary. Retain the backup until the upgraded installation has
opened the registry, completed migration, and passed an operational check.
Copying only the main database file while write-ahead-log or journal state is
active is not a supported backup procedure; use SQLite's backup mechanism or a
documented filesystem snapshot that captures the complete database state.

Production migrations are forward-only. To roll back:

1. stop the upgraded application;
2. restore the pre-upgrade backup;
3. start the previous binary against that restored database; and
4. confirm device counts, lifecycle state, key identifiers, and recent history
   before reopening authentication or approval traffic.

Never run an older binary against a database it reports as newer, and never
attempt a manual down-migration. Destructive schema reversal could erase
revocation or assurance evidence. If no valid backup exists, keep the
installation unavailable and escalate rather than weakening validation.

## Operational checks

After initial creation, migration, restore, or upgrade, verify that:

- the expected database and migration versions are reported;
- active, suspended, and revoked device counts match the operational record;
- a representative record retains the expected key identifier and assurance;
- suspended and revoked devices are rejected for current authorisation;
- historic records and lifecycle events remain readable; and
- no private-key or provider bearer-token material is present.

EPIC-5 supplies the repository boundary, not an operator administration API or
CLI. Until the M4 administration work lands, integrations must expose only
reviewed calls to the repository contract and must not encourage direct
database manipulation.
