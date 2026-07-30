# Recovery, revocation, and multi-device lifecycle operations

EPIC-13 recovery is not production-ready. The current SQLite registry can
retain device public keys and enforce suspension/revocation transitions, but
there is no complete replacement orchestrator, administrator recovery command,
host-session invalidation workflow, mobile device-management UI, or historic
portable-evidence verifier.

Never recover access by editing the registry database, deleting a device,
changing a public key in place, reopening bootstrap, copying a private key, or
assigning an external identity based on a display name.

## Readiness gates

Before enabling lifecycle/recovery operations, retain evidence for:

1. accepted ADR 0012 and explicit multi-device/recovery policy;
2. authoritative local-user, external-identity, installation, device, key, and
   recovery-authority bindings;
3. reviewed host administration UI/CLI with target-scoped authorisation;
4. atomic lifecycle change, audit, pending-ceremony cancellation, and required
   session invalidation;
5. replacement enrolment creating a distinct key and device record;
6. external-provider reauthentication and provider-loss behaviour;
7. local-console sole-administrator recovery with bounded, single-use
   authority and reviewed delay/two-person policy;
8. retained historic keys, revocation statements, trusted-time classification,
   and policy-version evidence;
9. backup, restore, migration, corruption, restart, and rollback tests;
10. cross-host and native iOS/Android acceptance evidence; and
11. a complete redacted lost-device exercise.

Missing or unavailable lifecycle/audit/session state fails closed. An empty or
unreadable registry is not an installation with no devices.

## Lost or possibly compromised device

Use the authoritative host inventory, not a phone's local history or remembered
installation list:

1. identify the exact immutable user and device identifier;
2. compare platform, public-key fingerprint, enrolment time, assurance, and
   last-use evidence;
3. record whether the phone is temporarily misplaced, permanently lost,
   retired, or suspected compromised;
4. suspend for a genuinely temporary case or revoke for loss/compromise;
5. review and apply the required pending-ceremony and host-session
   invalidation;
6. confirm the lifecycle event, effective time, reason, revision, and audit
   correlation identifier; and
7. inspect for attempted use after the effective transition.

Suspension is reversible but blocks current authorisation. Do not resume until
the device has been recovered, its integrity reviewed, and current policy
permits it. Revocation is permanent. If the wrong device was revoked, enrol a
new device; never reverse or delete the event.

If compromise is suspected, preserve redacted evidence and evaluate historic
signatures under the compromise policy. Do not indiscriminately invalidate or
erase all earlier evidence.

## Replacement device

Require fresh authentication to the exact existing external-provider subject
plus the authorised local route: surviving trusted-device approval, an
authorised administrator's separate device-management ceremony, or governed
local-console recovery under the configured provider-loss policy. Provider
authentication alone grants no local recovery authority.

The new phone generates its own hardware-bound key and receives a new device
identifier. Confirm its provider subject, local user, installation, key
fingerprint, assurance, and enrolment evidence before activation. App restore
or reinstall does not restore the old private key and must not restore the old
device identity.

Record the relationship to the old device without mutating the old record.
Available-predecessor replacement commits new-device activation, terminal old-
device revocation, generation advance, session/ceremony invalidation, and audit
as one rollback-capable operation. Present these as separate evidence facts,
but do not report replacement complete unless every required fact committed.

## Sole-administrator recovery

Do not attempt sole-administrator recovery until the accepted console procedure
is implemented. It requires local machine privileged access and must remain
unavailable through browser routes, remote support, environment variables, or
direct SQL.

The final runbook must require:

- explicit installation and immutable principal selection;
- review of all existing administrator devices and sessions;
- bounded, single-use recovery authority;
- optional delay/two-person approval according to institutional policy;
- new-device enrolment with a distinct key;
- terminal treatment of lost old devices;
- atomic or explicitly reconciled session and ceremony invalidation; and
- retained, non-secret audit/correlation evidence.

Failure to append audit or invalidate required authority leaves recovery
blocked. Do not issue a session manually as a workaround.

## External identity loss

A deleted GitHub/Google account, provider outage, organisation-policy change,
or changed display metadata does not authorise rebinding.

Existing device signatures may remain interpretable according to local policy.
New enrolment or recovery uses an accepted route and exact immutable provider
subject where available. If the trusted provider identity is permanently
unavailable, follow the governed administrator-recovery policy; do not attach a
similar username, email, or newly created provider account automatically.

## Historic evidence

For an old event, retain and display:

- signature verification result;
- device/key/binding valid at the evaluated time;
- independently trusted versus claimed signing time;
- effective lifecycle/revocation evidence and reason;
- current state;
- historic policy and compromise treatment; and
- missing or unavailable evidence.

Revocation blocks new use from its effective boundary. Routine retirement does
not rewrite earlier facts. A compromise reason may cause policy to distrust a
different interval, but an operator note alone must not rewrite cryptographic
or trusted-time evidence.

Local phone history is informational. Use authoritative server audit and the
accepted portable evidence/trust bundle for historic decisions.

## Backup and incident evidence

Before lifecycle schema upgrades or recovery exercises, take a consistent
SQLite backup using the device-registry procedure. Preserve public keys,
external binding references, lifecycle events, revocation reasons/times,
policy versions, audit references, and migration history.

Logs and tickets exclude private keys, recovery authority, provider tokens,
cookies, session capabilities, complete challenges/responses, raw signatures,
passwords, and production personal data. Use immutable non-secret identifiers
and an independent correlation identifier.

## Acceptance exercise

Run a complete exercise for both physical iOS and Android devices:

1. enrol at least two distinct devices;
2. authenticate with each;
3. lose/suspend one and prove new authorisation is rejected;
4. recover/resume only the temporary-loss case;
5. revoke a device and prove resume and new authorisation remain impossible;
6. enrol a replacement without key/identifier reuse;
7. verify session and pending-ceremony consequences;
8. verify pre-, at-, and post-revocation historic cases;
9. exercise external-provider unavailability; and
10. restore/restart the host and confirm state and audit remain intact.

Retain exact mobile, host, Pistis, dependency, migration, and Jenkins revisions
with redacted results. Emulator/simulator, registry-only unit tests, or a UI
mock does not satisfy the M12 exit gate.

## Current automation boundary

Jenkins is authoritative for deterministic repository and host contract tests.
The current generic tasks do not prove local-console authority, physical key
loss, phone replacement, or institutional two-person recovery. Do not create a
green automation placeholder for those steps. Record them through a reviewed
credential-isolated/native acceptance procedure when the implementation and
workers exist.
