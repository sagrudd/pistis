# Recovery, revocation, and multi-device lifecycle development

EPIC-13 governs loss, replacement, compromise, and continued interpretation of
historic evidence. Recovery is an explicit authority-changing ceremony, not an
exception that bypasses identity binding, device policy, revocation, audit, or
host authorization.

The current `pistis-device-registry` supports distinct device records,
optimistic-concurrency lifecycle transitions, terminal revocation, retained
public keys, and immutable lifecycle events in memory and SQLite. It does not
provide multi-device enrolment policy, replacement orchestration, a lost-device
workflow, administrator recovery, host-session invalidation, mobile device
management, or complete historic-evidence verification. Those missing layers
are EPIC-13 blockers.

## Normative boundary

[ADR 0012](../adr/0012-recovery-revocation-and-multi-device-lifecycle.md) is
normative once merged. Development must preserve these invariants:

- every device has a distinct identifier and non-exportable private key;
- replacement creates a new registration and never mutates the old record;
- no private-key migration, backup restore, or device clone is an enrolment
  method;
- suspension is explicit and reversible; revocation is explicit and terminal;
- lifecycle state is re-evaluated at every current authorization boundary;
- recovery cannot silently replace a local user or external identity binding;
- historic public verification material and lifecycle evidence are retained;
  and
- sole-administrator recovery is local, conspicuous, bounded, and audited.

Installation trust in the mobile applications is separate from server-side
device lifecycle. Re-pairing an installation fingerprint does not replace,
resume, or recover a registered phone. Likewise, registering a new phone does
not authorize a changed installation key.

## Aggregate and orchestration boundary

The device registry owns one device's immutable enrolment data, current state,
revision, and lifecycle events. A recovery orchestrator must additionally own
or coordinate:

- per-user and per-purpose multi-device policy;
- authoritative external-identity and installation bindings;
- recovery authority and approval policy;
- session and pending-ceremony invalidation;
- transactional audit;
- replacement/recovery correlation; and
- host authorization after authentication.

Do not add cross-device policy to a broad repository utility or update several
stores with best-effort writes. A transition that changes authorization and
its audit/session consequences needs one reviewed completion boundary or a
fail-closed recovery protocol with explicit reconciliation.

Concurrent lifecycle commands use the device revision. A stale suspend,
resume, revoke, or use-recording command fails and reloads current state; it
must never become an unconditional last-writer-wins update.

## Multi-device enrolment and replacement

Multiple devices for one local user remain separate security principals. Each
record has its own key, platform and assurance claims, external-identity
binding, enrolment evidence, lifecycle state, and last-use evidence. A friendly
device label is mutable display metadata and never an identity key.

Replacement is a new enrolment authorized by fresh authentication to the exact
existing external-provider subject plus one reviewed local-authority route:

- an existing trusted device;
- an authorized administrator using a separate device-management ceremony; or
- governed local-console recovery when the predecessor/provider path is
  unavailable and policy permits it.

The exact route and assurance are retained. Replacement does not inherit the
old device's key, attestation, biometric state, device identifier, enrolment
time, or last-use time. Successful available-predecessor replacement atomically
activates the new device, terminally revokes the predecessor, advances the
binding generation, invalidates affected sessions/ceremonies, and appends
audit. The old record is not deleted or labelled as the new device.

App reinstall, key invalidation, restored application data without its
hardware key, or biometric-security changes produce an unrecognized/new device
state. Mobile code must not silently generate a replacement key under the old
device identifier.

## Host and mobile UX

Device administration is a host-owned structured resource index, not a mobile
installation list or a set of summary cards. Rows identify the stable device,
user, platform, assurance, lifecycle state, honest last use, and replacement
relationship. A detail surface separates:

- identity and key fingerprint;
- enrolment and external-identity evidence;
- assurance at enrolment;
- activity and session impact;
- lifecycle events; and
- warnings or unavailable evidence.

Suspend and revoke are target-scoped consequential actions. The review states
the exact device, user, effect on new approvals and sessions, reason, and
whether the action is reversible. `Suspend` and `Revoke` must not share generic
confirmation text. Resume is available only for a suspended device and cannot
change immutable enrolment fields.

The iOS and Android source applications currently present external identities,
remembered installations, approval, and local informational history. They do
not contain a server device inventory, replacement workflow, or recovery
authority. Do not present those existing lists as multi-device management.

A surviving phone may initiate a replacement ceremony only through a reviewed
host request. A lost phone cannot be expected to participate. Mobile screens
must distinguish:

- `This phone` from another registered device;
- `Suspended`, `Revoked`, `Replacement pending`, and `Unavailable` in words;
- local observation from authoritative host lifecycle state; and
- enrolment success from old-device revocation and session invalidation.

Cancellation, backgrounding, process death, or stale host state produces no
recovery approval. Dynamic Type/font scaling, VoiceOver/TalkBack, keyboard
operation, focus return, and non-colour status remain acceptance requirements.

## Sole-administrator recovery

Sole-administrator recovery is unavailable until the accepted ADR's local
console, authority, delay/two-person, token/ceremony, audit, and old-device
revocation rules are implemented. It must not be exposed through a public HTTP
route, environment variable, database edit, normal password reset, provider
display name, or reusable support credential.

The command runs only with explicit local privileged authority and names the
installation and target immutable principal. It reports a review before
mutation, records an independent audit event, and cannot leave old recovery
material or devices silently active. Operator notes are not authorization
evidence.

## Historic verification

Current authorization and historic interpretation are different questions. A
revoked device cannot create a new valid approval. Normal retirement does not
erase an otherwise valid earlier signature.

Historic verification must report separately:

- cryptographic signature result and canonical payload identity;
- device/key and binding valid at the evaluated event time;
- whether event time is independently trusted or only signer-claimed;
- lifecycle state and effective revocation time/reason;
- current device/key/binding state;
- applicable historic-policy version and compromise treatment; and
- unavailable evidence.

Do not evaluate an old signature solely against today's active-device list, and
do not automatically declare every pre-revocation event trustworthy. Compromise
policy may require a different treatment from routine retirement. EPIC-12's
portable evidence schema and trusted-time semantics must exist before complete
historic verification can be claimed.

## Required tests

Deterministic tests use fixed time and identifiers and cover:

- multiple devices for one user without key or identifier aliasing;
- duplicate key/device rejection within an installation;
- replacement producing a new record while preserving the old record;
- active-to-suspended-to-active and active/suspended-to-revoked transitions;
- every operation rejected after terminal revocation;
- stale and concurrent lifecycle revisions;
- revocation racing verification, challenge completion, and session issuance;
- current-session invalidation according to host policy;
- external-identity outage/loss without silent rebinding;
- app reinstall and invalidated hardware key;
- sole-administrator recovery cancellation, replay, expiry, and audit failure;
- historic verification before, at, and after effective revocation; and
- corruption, migration, backup, restore, and log-redaction failures.

Cross-repository host tests pin exact Pistis and Synoptikon/Monas revisions.
Native acceptance performs the full lost-device and replacement exercise on
physical iOS and Android devices.

## Jenkins contract

Ordinary Pistis Jenkins CI already tests device-registry unit and SQLite
transitions through the workspace gates. That is necessary but not complete
EPIC-13 evidence.

A future lifecycle dossier retains exact source revisions, migration and
lockfile hashes, deterministic concurrency/session/audit results, and redacted
state-machine evidence. Host integration tasks must prove authorization and
session invalidation through real host adapters. Native release tasks retain
physical-device reinstall, key invalidation, replacement, and lost-device
exercise results.

Do not add a Jenkins task that calls repository transitions in isolation and
labels them recovery acceptance. Generic Linux containers cannot prove Secure
Enclave/Android Keystore loss, physical-device lifecycle, local-console
authority, or institutional two-person procedure.
