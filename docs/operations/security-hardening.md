# Security hardening and independent review operations

EPIC-14 is not complete. Existing CI provides useful baseline checks, but no
qualified independent penetration test, cryptographic review, privacy
assessment, remediation report, residual-risk register, or security-owner
release approval has been delivered.

Do not describe a passing Jenkins build, advisory scan, mobile simulator test,
or internal code review as an independent security assessment.

## Review readiness

Before commissioning review, freeze and record:

1. exact Pistis, Synoptikon, Monas, broker, mobile, and packaging revisions;
2. Rust binaries, iOS archive/app, Android bundle/APK, container/package, and
   documentation digests;
3. configuration, enabled protocol versions, endpoints, schemas, migrations,
   dependency locks, SBOM/component inventory, and toolchain/container digests;
4. architecture, threat model, data flows, trust boundaries, key/session/
   recovery lifecycles, and known residual risks;
5. isolated test infrastructure, generated accounts/data, devices, network
   topology, logging/monitoring, backup, and restoration plan;
6. penetration-test rules of engagement and system-owner authorisation;
7. secure report/evidence exchange and named incident contacts; and
8. finding severity, remediation, risk-acceptance, retest, and disclosure
   process.

If a production-shaped component is absent or still reference-only, mark the
scope blocked or excluded with impact. Do not replace it with a mock and claim
production coverage.

## Dependency-review operation

For every release candidate:

- verify Cargo/Gradle/Swift/package/documentation graphs and exact lock state;
- validate Gradle verification metadata and wrapper/container/tool hashes
  against expected upstream artefacts;
- run advisory, licence, source, duplicate-version, and prohibited-dependency
  policies;
- inspect build scripts, native/unsafe components, maintainership/provenance,
  privileges, network/data access, and update history;
- compare the graph with the last accepted candidate and explain every change;
- record affected features and exposure for each advisory; and
- retain reviewed output and the reviewer decision.

An unavailable advisory service is not a pass. Preserve the candidate and
rerun with a current, recorded advisory database. Do not automatically update a
dependency across a protocol, cryptographic, persistence, or mobile platform
boundary solely to clear an alert; review compatibility and retest.

## Penetration-test operation

Use only the authorised isolated environment and generated identities/data.
Confirm stop contacts before beginning. Monitor availability and sensitive
logs while testing. Stop on evidence of scope escape, real-user data, third-
party impact, uncontrolled denial of service, credential exposure, or inability
to preserve evidence safely.

Store reports, captures, exploit material, credentials, and detailed findings
in the approved encrypted confidential channel. Do not attach them to public
issues, pull requests, CI logs, chat, support bundles, or normal artefact
storage.

Triage findings with the independent reviewer and affected owner. Record
severity rationale, affected exact build, exploit prerequisites, impact,
remediation, regression test, and disclosure decision. Retest the exact fix and
record whether related attack paths remain.

## Mobile assessment operation

Test release-configured, signed candidates on supported physical iOS and
Android devices. Include first install, upgrade, reinstall, device lock,
biometric change/lockout, backup/restore, screenshots/clipboard/logs, URL and
intent callbacks, background/process death, permissions, network interception,
root/jailbreak policy, key invalidation, recovery, and distribution metadata.

Record device model, OS/build, app digest/version, signing identity reference,
entitlements/manifest/privacy declarations, configuration, and result. Never
export a production private key or weaken a device to manufacture a passing
hardware-assurance result.

Keeper or another system credential provider participates only through the OS
credential UI. Testing must not request vault exports, passkey private keys, or
third-party credentials.

## Finding and risk gate

Maintain a confidential finding register:

| Field | Requirement |
| --- | --- |
| Identity | Stable private finding identifier |
| Scope | Exact revisions, artefacts, configuration, and affected boundary |
| Severity | Method and concrete impact rationale |
| Ownership | Remediation owner and security reviewer |
| State | Open, remediating, ready for retest, verified, or risk accepted |
| Evidence | Reproduction and encrypted artefact references |
| Deadline | Target release/date and escalation |
| Disclosure | Coordinated private/public decision |

Critical or high findings block progression. Medium risk requires a named
owner, deadline, compensating controls, and security-owner acceptance. A
finding is not closed because it is difficult to reproduce, the affected
feature is disabled without enforcement, or a generic test suite passes.

Only the authorised security owner records release progression after verifying
scope, independent reviewer status, reports, retests, unresolved findings,
privacy/cryptographic decisions, artefact traceability, and residual risk.

## Compromised dependency or toolchain

When compromise is suspected:

1. stop affected builds/publication and preserve exact logs, locks, digests,
   artefacts, and advisory intelligence;
2. identify source, build, CI, package, mobile, broker, and deployed exposure;
3. revoke/rotate affected credentials and signing/upload material through
   owner-controlled procedures;
4. rebuild only in a reviewed clean environment from independently verified
   source and dependencies;
5. compare artefacts and investigate unexplained differences;
6. patch or replace the component, run focused regression/security tests, and
   obtain review;
7. notify operators/users through the approved route; and
8. record remediation, residual uncertainty, and disclosure.

Deleting a lockfile, accepting newly generated hashes without provenance
review, or rebuilding on the same suspect worker is not remediation.

## Privacy and evidence handling

Review retention/deletion for provider subject/display metadata, device and
assurance data, events, network metadata, local phone history, diagnostics,
test data, and backups. Test deletion and export behaviour without deleting
public keys, revocation facts, or policy/trusted-time material required to
interpret historic evidence.

Normal security evidence excludes provider credentials, session cookies,
recovery capabilities, private keys, complete challenges/responses, raw
production personal data, and exploit details. Jenkins dossiers may reference
a confidential report identifier and digest; they must not publish the report.

## Current Jenkins boundary

Jenkins is authoritative for reproducible automated evidence at exact
revisions. Current jobs run baseline Rust/Android/Swift tests, Rust advisory and
licence/source checks, fuzz-target compilation, architecture checks, and
documentation rendering. They do not constitute live penetration testing,
independent cryptographic/privacy review, physical mobile assessment, or
security-owner approval.

Add automation only for a concrete reproducible check with reviewed isolation,
permissions, limits, redaction, tools, inputs, outputs, and retention.
Independent human work remains an explicit approval record referencing
confidential evidence. Never automate a checkbox whose only assertion is that a
file or approval label exists.
