# ADR 0013: Security assurance and independent review

- Status: Accepted
- Date: 2026-07-24
- Owners: Pistis security, protocol, cryptography, privacy, mobile, operations,
  release, and independent reviewers

## Context

EPIC 14 is the security hardening and independent-review gate before a release
candidate. Pistis already has safe-Rust policy, denied lints, dependency and
licence configuration, deterministic protocol attack tests, four fuzz targets,
a threat model, explicit assurance states, and security boundaries recorded in
accepted ADRs.

Those controls are useful evidence, but they are not an independent
penetration test, cryptographic review, privacy assessment, or security-owner
approval. Several production surfaces are also incomplete: COSE
interoperability, durable host completion, mobile distribution, local
discovery, detached evidence, recovery, and release packaging. Testing a
reference component cannot close findings against a production surface that
does not yet exist.

Security findings may contain exploit details or personal information and must
not be placed in public issues, logs, CI artefacts, or ordinary documentation.
At the same time, release approval requires traceable evidence that the
reviewed revision and artefacts match the delivered system.

## Decision

### Security assurance is a release gate

EPIC 14 establishes a versioned security-assurance case for one immutable
source revision and its traceable Rust, iOS, Android, host-integration, and
packaging artefacts. Evidence from another revision is reusable only when a
documented impact analysis proves that relevant code, configuration,
dependencies, generated artefacts, and trust boundaries are unchanged.

The assurance case maps every applicable M13 control and threat to:

- assets, actors, entry points, and trust boundaries;
- the responsible component and owner;
- prevention, detection, response, and recovery controls;
- deterministic tests or retained review evidence;
- evidence revision, environment, tool/version, and date;
- finding and remediation status; and
- explicitly accepted residual risk and expiry.

Missing, stale, unverifiable, or out-of-scope evidence is a blocker, not a
passing result.

### Independence and claims

Repository maintainers and autonomous agents may prepare scope, inventories,
attack tests, review checklists, remediation patches, and evidence manifests.
They must not label their own work an independent penetration test or
independent cryptographic review.

An independent reviewer must be organizationally and operationally separate
from the implementation being reviewed, receive the complete scoped material,
declare material conflicts, use a documented method, and sign or otherwise
authenticate the final report. The project security owner—not the implementer
or CI system—accepts residual risk and approves release-candidate progression.

Automated scanners, fuzzers, linters, dependency tools, and AI review are
supporting evidence only. A clean tool result never implies absence of
vulnerabilities.

### Scope and review readiness

The independent review begins only after its target surfaces are
feature-complete, configuration-frozen for review, deployed in an isolated
representative environment, and traceable to the candidate revision.
Out-of-scope or unavailable surfaces remain explicit release blockers.

The review scope includes:

- Rust parsers, canonicalization, signature verification, challenge lifecycle,
  policy, persistence, CLI, and resource limits;
- Synoptikon and Monas authentication, session, authorization, audit, bootstrap,
  recovery, and migration adapters;
- iOS and Android key generation, biometric binding, callback handling, local
  storage, logging, backup, screenshots, deep links, intents, permissions, and
  release configuration;
- QR and direct-local transport, hostile discovery, endpoint binding, fallback,
  and denial-of-service behavior;
- GitHub and Google enrolment, broker boundaries, callback correlation, token
  lifetime, and provider failure;
- detached evidence, trusted-time, revocation, historic policy, and offline
  verification; and
- build, dependency, secret, signing, SBOM, provenance, update, and incident
  response paths.

Testing uses generated identities and isolated data. It does not target public
production systems or access unrelated data.

### Threat model and attack tests

The threat model is a living, version-controlled control register. Before
review it is reconciled against all accepted ADRs, actual routes, schemas,
platform manifests, configuration defaults, dependencies, data stores, logs,
and deployment diagrams. Deferrals name an owning issue and cannot be carried
into a release candidate when their surface is in scope.

Attack tests automate deterministic cases where practical, including replay,
downgrade, cross-purpose/user/installation substitution, concurrent
consumption, parser limits, non-canonical input, signature encoding,
identifier collision handling, expiry and clock boundaries, discovery and TLS
substitution, OAuth/OIDC correlation, CSRF, redirects, token leakage,
revocation, recovery, and session invalidation.

Fuzz evidence records target, corpus digest, candidate revision, engine and
toolchain version, configuration, duration or execution count, sanitizer
settings, crashes, minimization, and remediation. Merely compiling a fuzz
target is not a completed fuzz campaign. Security regressions become permanent
deterministic tests before a finding closes.

### Dependency and code hardening

The candidate dependency review uses the locked Rust, Swift, Gradle, container,
documentation, and CI dependency graphs. It evaluates advisories, yanks,
licences, source provenance, maintainership, release age, native and unsafe
code, build scripts, duplicate versions, features, and necessity.

Exceptions are narrow, owned, time-bounded, justified by impact analysis, and
recorded in the residual-risk register. Suppressing a scanner finding without
this record fails the gate.

Code hardening reviews unsafe code, panic and allocation behavior, secret
zeroization, logging and diagnostics, error redaction, rate and size limits,
timeouts, file permissions, secure configuration defaults, and fail-closed
dependency failure. Tests include logs and crash/error paths, not only success.

### Privacy assessment

The privacy assessment inventories each collected, inferred, transmitted,
displayed, logged, backed-up, exported, and deleted data field. For each field
it records purpose, authority, source, recipients, storage location, retention,
deletion behavior, user visibility, and whether it is required.

Stable provider subjects, device and assurance metadata, authentication and
recovery events, network classifications, mobile history, diagnostic data, and
portable evidence are reviewed explicitly. Data minimization is the default.
Full IP addresses, user-agent strings, provider tokens, session material,
capabilities, nonces, signatures, and raw evidence are not retained merely for
convenience. Platform privacy declarations and store disclosures must match
observed behavior.

### Cryptographic review

The independent cryptographic review covers the exact production profile and
fixtures: algorithms and parameters, key generation and storage, randomness,
canonical encoding, COSE structure, domain separation, nonce and challenge
binding, signature encoding and malleability, key identifiers and collision
handling, protocol versioning, verifier outcome ordering, assurance,
revocation, trusted time, recovery, and detached evidence.

Any protocol, canonicalization, signature, schema, or security-critical fixture
change after review invalidates the affected conclusion until the reviewer or
security owner accepts a documented delta review.

### Findings and release decisions

Findings use a stable private identifier, affected revision and component,
severity, exploitability and impact, reproduction evidence, owner, target,
remediation, regression evidence, reviewer verification, and disclosure state.
Severity uses the reviewer's documented method and is not lowered solely to
meet a release date.

Critical and high findings block release until remediated and independently
verified. Medium findings require an accepted, owned, dated remediation plan
and explicit security-owner residual-risk acceptance. Lower findings remain
tracked. A disputed or untriaged finding is open.

Public release evidence contains only sanitized scope, reviewer identity or
attestation, candidate revision, dates, finding counts by severity, remediation
status, and residual-risk references. Exploit details follow `SECURITY.md` and
remain private until coordinated disclosure.

### Incident readiness

Before approval, exercises cover vulnerability intake, key compromise,
protocol-version disablement, malicious dependency, mobile emergency release,
host rollback, evidence/revocation update, operator and user notification, and
coordinated disclosure. Runbooks name decision authority, secure contact
channels, containment steps, evidence preservation, recovery, validation, and
post-incident review.

No incident path depends solely on a compromised repository, CI controller,
provider account, mobile signing account, or single undocumented individual.

### Smallest honest delivery slice

Before the production surfaces are ready, EPIC 14 may deliver:

- a machine-checkable assurance/control catalogue;
- threat-to-control and control-to-test traceability;
- candidate and evidence-manifest schemas;
- redaction-safe finding and residual-risk templates;
- deterministic security regression tests and fuzz-campaign tooling;
- dependency and privacy inventories; and
- review-readiness checks that report `blocked`, never `passed`, when
  independent evidence is absent.

This slice improves hardening but does not complete penetration testing,
privacy review, cryptographic review, or EPIC 14.

## Consequences

- Security approval is tied to an exact candidate rather than a general claim
  about the repository.
- Independent review cannot be replaced by self-review or automation.
- Sensitive findings remain private while release evidence stays auditable.
- Later security-critical changes trigger scoped re-review.
- EPIC 14 cannot close until prerequisite production surfaces exist, all
  required independent evidence is authenticated, finding gates are satisfied,
  incident exercises pass, and the security owner approves progression.

## Alternatives considered

- Close the epic after scanners and unit tests pass: rejected because automation
  is not independent adversarial review.
- Test only the current reference services: rejected because production host,
  mobile, transport, evidence, and recovery boundaries differ.
- Store complete penetration reports as public CI artefacts: rejected because
  exploit details and personal data require controlled disclosure.
- Accept findings without revision traceability: rejected because conclusions
  cannot be applied reliably to changed code or artefacts.
- Defer all hardening until the end: rejected because control catalogues,
  negative tests, inventories, and remediation can reduce risk earlier.
- Permit high-severity residual risk for schedule reasons: rejected because M13
  explicitly blocks critical and high findings.

## Review evidence

The architecture audit inspected EPIC 14 issues 156–162, M13 criteria,
`SECURITY.md`, all accepted ADRs, the threat model, dependency policy,
architecture guardrails, assurance documentation, fuzz targets, mobile
manifests, and current protocol, registry, transport, and host-contract tests.
It found valuable deterministic controls but no completed independent
penetration report, cryptographic review, privacy assessment, remediation
report, incident exercise, residual-risk register, or release-candidate
approval.
