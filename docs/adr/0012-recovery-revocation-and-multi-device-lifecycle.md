# ADR 0012: Recovery, revocation, and multi-device lifecycle

- Status: Accepted
- Date: 2026-07-24
- Owners: Pistis device, identity, protocol, evidence, host integration,
  security, privacy, and operations

## Context

Passwordless operation must remain supportable when a device is added, lost,
replaced, retired, or compromised. Recovery is a high-authority operation: a
weak recovery route would become a password substitute capable of silently
replacing the external identity or local administrator.

ADR 0005 already makes device suspension reversible, revocation terminal, and
historic public keys and lifecycle events durable. ADRs 0009 and 0010 prohibit
reopening bootstrap when administrators lose their devices and require
revocation-aware session invalidation. GitHub and Google enrolment decisions
require fresh provider authentication for replacement or recovery bindings.

The current registry supports one distinct public key per device and durable
lifecycle transitions, but it has no recovery transaction, relationship
between predecessor and replacement devices, binding-wide revocation
generation, host-session invalidation port, or temporal historic-verification
policy. The current online verifier uses current key status and correctly
rejects a revoked key for a new operation; it is not a historic evidence
verifier.

EPIC 13 formally depends on EPIC 12. Detached evidence, signed claims, trusted
time semantics, and offline verification must therefore be defined before
historic verification can be completed.

## Decision

### Authority and dependency boundaries

Pistis owns device and binding lifecycle rules, recovery purpose separation,
revocation generations, historic cryptographic classification, and portable
recovery audit evidence. A host owns local users, roles, administrator policy,
normal sessions, console privilege, presentation, and its transactional
adapter.

External providers establish the same stable external subject used at
enrolment. They do not grant local authority, choose an administrator, recover
a session, or authorise a replacement by themselves. Local machine root or
console privilege is a governed emergency authority, not an identity proof.

Recovery, authentication, enrolment, device management, consequential
approval, and artefact signing are distinct protocol purposes. A capability,
response, or signature for one purpose is invalid for every other purpose.

The smallest independently deliverable slice is a framework-neutral lifecycle
contract with closed state transitions, authorisation inputs, recovery plans,
revocation impact sets, temporal verification classifications, and
deterministic negative tests. It cannot issue a session, mutate a host role, or
claim production recovery without durable host adapters.

### Multi-device model

Each enrolled device has a new random `DeviceId`, a newly generated
non-exportable private key, a derived `KeyId`, its own assurance evidence, and
an immutable reference to the exact local-user and external-identity binding.
Private keys, device identifiers, and assurance claims are never copied,
restored, or migrated between devices.

A local policy sets explicit lower and upper device-count bounds and may impose
platform or assurance requirements. Counting is performed against the
authoritative binding inside the enrolment transaction. Suspended devices
remain enrolled for limits and administration; revoked devices remain historic
but cannot authorise or satisfy a required active-device count.

Enrolling an additional device requires fresh provider authentication plus one
of:

- approval by an active device already bound to the exact installation, local
  user, and external identity; or
- a currently authorised administrator using a separate device-management
  ceremony.

Provider authentication alone is insufficient. Concurrent enrolments are
serialized or use an optimistic binding generation so that policy limits
cannot be exceeded by a race.

### Replacement

Replacement creates a new device and key; it never changes the public key,
identity, assurance, or history of an existing device record. A replacement
record may retain non-authoritative predecessor and reason references for audit
and user presentation.

When the old device remains available, its purpose-specific approval and fresh
provider authentication authorise the new enrolment. The transaction activates
the new device, terminally revokes the predecessor with reason `replacement`,
increments the binding revocation generation, invalidates affected sessions
and pending ceremonies, and appends audit evidence.

When the predecessor is unavailable, the operation is a lost-device or
administrator-recovery flow, not a weakened replacement path. Failure after
the new key has been presented but before durable commit leaves neither an
active replacement nor a partially revoked predecessor. Retry uses a
single-use operation identifier and cannot create duplicate devices.

### Suspension, loss, and revocation

Suspension is a reversible containment action. It blocks new authentication,
approval, enrolment authorisation, and signing immediately at its effective
time and invalidates affected active sessions and pending ceremonies. Resume is
an explicit authorised transition; it does not erase the suspension history
and re-evaluates current binding, assurance, external-identity, and policy
state.

Revocation is monotonic and terminal. Closed revocation reasons include at
least loss, compromise, retirement, replacement, administrator action, and
policy action. Free-text operator context is separately bounded and cannot
alter reason semantics.

Every suspension, resume, and revocation:

- re-reads the exact device, key, binding, and policy generation;
- increments a monotonic revocation generation where effective trust changes;
- computes affected sessions and pending ceremonies from authoritative
  references rather than caller-supplied identifiers;
- performs state transition, session and ceremony invalidation, and audit
  append in one rollback-capable transaction; and
- publishes only a post-commit invalidation notification for caches or
  secondary processes.

If a remote session store cannot participate in the transaction, the host must
fail closed for every request whose cached generation is stale or unknown.
Eventual cache notification is not a substitute for authoritative generation
checking.

Lost-device reporting is available only through an already authenticated
session, another active bound device, an authorised administrator, or the
governed console recovery flow. Knowledge of a username, device label,
provider account, QR image, or device identifier is insufficient. A user may
request immediate suspension before a reviewed terminal revocation decision.
Public results do not reveal whether an arbitrary device or account exists.

### Sole-administrator recovery

Bootstrap never reopens. Administrator count, provider outage, loss of all
devices, or deletion of the last role does not restore a bootstrap route.

Sole-administrator recovery is an explicit local-console command requiring
privileged machine access and an initialized installation. The command:

- requires an explicit target local principal and displays the immutable
  installation identity and existing stable external identity;
- records a declared reason and selected recovery policy;
- refuses any request to replace the external identity or grant an additional
  role as part of recovery;
- creates a short-lived, single-use, high-entropy recovery capability;
- persists only a domain-separated hash, purpose, target, issue/expiry,
  attempt limit, policy, and independent audit correlation identifier;
- displays the plaintext exactly once through the local console and never puts
  it in a URL, argument list, environment variable, log, browser storage, or
  configuration file; and
- supports an operator-configured delay and independent second approval for
  institutional deployments.

The capability starts a recovery enrolment ceremony only. It is not a
password, API bearer, session, provider credential, role grant, reusable setup
token, or substitute for device signing.

Completion requires a new device-generated key and installation-bound
ceremony. Fresh authentication to the exact existing external identity is
required when that provider remains available. Provider loss follows a
separately configured governed policy and cannot silently bind a different
provider subject. The host transaction consumes the capability, enrols the new
device, terminally revokes every prior device authorised for the recovered
principal, invalidates sessions and pending ceremonies, increments the
revocation and authorisation generations as required, and appends conspicuous
audit evidence.

Any expiry, attempt exhaustion, mismatch, denial, storage failure, audit
failure, or concurrent completion creates no device or session and performs no
partial revocation. Cancellation and failed capabilities remain auditable and
cannot be resumed.

### External-identity loss

Mutable login names, email addresses, and profile metadata never drive
recovery. A deleted, inaccessible, or policy-forbidden provider identity
prevents fresh provider-based enrolment or rebinding but does not rewrite the
stable subject recorded on existing evidence.

Local policy explicitly selects among:

- continue accepting existing active device signatures without new enrolment;
- require an authorised administrator or governed console recovery;
- suspend the binding pending review; or
- terminally retire the binding.

Changing to another provider subject is a separately authorised rebind with
its own evidence and audit trail. It is never represented as recovery of the
old identity.

### Historic verification

Current-operation verification and historic-evidence verification are separate
APIs. Revoked or suspended devices cannot create a new valid operation,
regardless of claimed signing time.

Historic verification retains and cryptographically validates the immutable
public key, signed bytes, algorithm, identity bindings, lifecycle events,
policy version, and revocation facts. It returns structured facts rather than
a single boolean:

- cryptographic signature validity;
- key and binding state at the evaluated signing time;
- current key and binding state;
- revocation effective time and closed reason;
- whether signing time is independently trusted, bounded by authoritative
  system evidence, or merely signer-claimed; and
- the applicable historic policy result, including compromise treatment.

A signature with independently trusted time before ordinary retirement or
replacement may remain historically valid while reporting current revocation.
A signature at or after effective revocation is invalid. A signer-claimed time
alone cannot prove that signing preceded revocation and produces an
indeterminate temporal result. Compromise policy may reject or qualify evidence
from an earlier interval, but the verifier reports the cryptographic result and
policy classification separately.

Revocation never deletes or rewrites historic keys, evidence, lifecycle events,
or trust material. Verification uses the policy and trust snapshot identified
by the evidence, subject to an explicit relying-party policy; it does not apply
today's status as though it existed at signing time. EPIC 12 defines the
detached evidence schema and trusted-time sources required by this API.

### Audit, privacy, and operation

Recovery and lifecycle audit uses independent non-secret correlation
identifiers and records the actor authority class, target principal, binding,
device/key references, closed reason, effective times, generations, policy,
coarse outcome, invalidation counts, and predecessor/replacement relationship.

Audit never retains recovery capability plaintext or hash, provider credential,
session token, cookie, private key, raw signature, nonce, full evidence
package, or unnecessary personal profile data. Recovery audit read and export
are separately authorised.

Operator documentation includes rehearsal, backup and restore, clock and
trusted-time assumptions, provider-loss policy, two-person mode, aborted
recovery, cache invalidation, replacement rollback, and post-recovery review.
Production acceptance includes full lost-device exercises on iOS and Android
and proof that old devices, sessions, challenges, and capabilities cannot be
reused.

## Consequences

- Loss of one device need not introduce password recovery.
- Multiple devices remain independent credentials rather than key replicas.
- Replacement preserves predecessor history and performs no private-key
  migration.
- Revocation affects new operations immediately and invalidates associated
  host state without destroying historic verification material.
- Sole-administrator recovery is conspicuous, local, bounded, and auditable;
  it cannot silently alter external identity or reopen bootstrap.
- Contract and state-machine work can proceed, but full EPIC 13 remains blocked
  on EPIC 12 evidence semantics, durable host transactions, session
  invalidation, mobile ceremonies, and end-to-end recovery exercises.

## Alternatives considered

- Reopen bootstrap when no active administrator device exists: rejected because
  it creates an unaudited authority reset.
- Restore or migrate a device private key: rejected because device-bound keys
  never leave the device.
- Accept provider authentication alone for replacement: rejected because the
  provider does not grant local authority.
- Mutate the old device record with a new key: rejected because it destroys
  assurance, revocation, and historic identity semantics.
- Leave sessions active until expiry after revocation: rejected because a lost
  or compromised device's authenticated authority would remain usable.
- Delete revoked keys or evidence: rejected because historic verification and
  scientific provenance require immutable public material.
- Treat every pre-revocation signature as valid using its claimed timestamp:
  rejected because the signer controls an untrusted time claim.
- Permit a recovery token to create a browser session: rejected because it
  bypasses new-device proof and purpose separation.

## Review evidence

The architecture review inspected EPIC 13 issues 149–155, M12 acceptance
criteria, ADRs 0003–0011, the device registry's SQLite and in-memory lifecycle
implementations, Synoptikon readiness and session contracts, the authentication
reference session map, and the current verifier. It found durable terminal
device revocation and preserved keys, but no recovery protocol, replacement
relationship, host invalidation transaction, recovery capability, or temporal
historic-verification model.
