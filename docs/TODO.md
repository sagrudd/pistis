# TODO.md

> Atomic implementation backlog for Pistis v1.0
>
> This TODO list decomposes the milestones into implementation-sized tasks.
> Each item should generally be completable within 0.5–2 developer days.

## Legend

- [ ] Not started
- [~] In progress
- [x] Complete

---

# EPIC 0 — Repository

## Repository bootstrap

- [x] Create Git repository
- [x] Configure branch protection
- [x] Configure CI
- [x] Configure Rust toolchain
- [x] Configure cargo fmt
- [x] Configure clippy
- [x] Configure cargo deny
- [x] Configure cargo audit
- [x] Add SECURITY.md
- [x] Add CONTRIBUTING.md
- [x] Add CODEOWNERS
- [x] Add issue templates
- [x] Add pull request template
- [x] Create Architecture Decision Record (ADR) directory

---

# EPIC 1 — Protocol

## Domain model

- [x] Define InstallationId
- [x] Define UserId
- [x] Define DeviceId
- [x] Define ChallengeId
- [x] Define EvidenceId
- [x] Define KeyId
- [x] Define ExternalIdentityId

## Canonical encoding

- [x] Choose encoding (CBOR/COSE)
- [x] Implement canonical serializer
- [x] Implement canonical parser
- [x] Produce golden fixtures
- [x] Write round-trip tests

## Challenge lifecycle

- [x] Generate nonce
- [x] Generate expiry
- [x] Generate challenge identifiers
- [x] Validate expiry
- [x] Prevent replay
- [x] Prevent double consumption

---

# EPIC 2 — Crypto

- [x] Select signature suite
- [x] Implement hashing
- [x] Implement signature verification
- [x] Implement key identifier generation
- [x] Implement verifier API
- [x] Fuzz canonical parser
- [x] Fuzz verifier

---

# EPIC 3 — GitHub trust

- [x] Define and validate the OAuth application registration contract
- [x] Implement PKCE flow
- [x] Validate callback
- [x] Retrieve stable GitHub user id
- [x] Persist identity binding
- [x] Add integration tests

---

# EPIC 4 — Google trust

- [x] Implement OIDC discovery
- [x] Validate ID token
- [x] Extract issuer
- [x] Extract subject
- [x] Persist identity binding
- [x] Add integration tests

---

# EPIC 5 — Device registry

- [x] Create database schema
- [x] Create migration
- [x] Implement repositories
- [x] Store public keys
- [x] Store assurance metadata
- [x] Implement revocation
- [x] Implement suspension

---

# EPIC 6 — QR authentication

- [x] Encode challenge QR
- [x] Decode response QR
- [x] Browser polling endpoint
- [x] Browser completion endpoint
- [x] Authentication acceptance tests

EPIC-6 completes the reviewed in-memory QR authentication reference flow.
Production HTTP, durable session/audit persistence, installation policy,
mobile COSE interoperability, and the remaining M5 user experience work stay
open under milestone M5.

---

# EPIC 7 — iOS

Implementation source and portable tests are present on the EPIC-7 delivery
branch. These boxes remain open until the applicable evidence exists: full
Xcode native compilation, simulator and real-device security/accessibility
tests, Apple signing and TestFlight, broker/verifier integration, and the COSE
ADR plus shared mobile conformance fixtures required by ADR 0006. The issue
tracker records signing, TestFlight, and production QR interoperability as
blocked rather than complete.

## Foundation

- [x] Create SwiftUI project
- [ ] Configure signing
- [ ] Configure TestFlight

## Security

- [ ] Generate Secure Enclave key
- [ ] Require Face ID
- [ ] Extract public key

## UX

- [ ] Identity list
- [ ] Installation list
- [ ] QR scanner
- [ ] Approval screen
- [ ] History screen
- [ ] Settings

## Integration

- [ ] GitHub enrolment
- [ ] Google enrolment
- [ ] QR authentication
- [ ] Direct local submission

---

# EPIC 8 — Android

The EPIC-8 source foundation is governed by ADR 0008. A Compose project,
portable ceremony core, platform-policy adapters, and Jenkins build evidence
may close independently when their tests pass. Play Console, physical-device
assurance, production QR/COSE interoperability, and the complete M11 device
matrix remain open until their external evidence exists.

## Foundation

- [ ] Create Compose project
- [ ] Configure Play Console

## Security

- [ ] Generate Android Keystore key
- [ ] Configure BiometricPrompt
- [ ] Report hardware capability

## UX

- [ ] Identity list
- [ ] Installation list
- [ ] QR scanner
- [ ] Approval screen
- [ ] History screen

## Integration

- [ ] GitHub enrolment
- [ ] Google enrolment
- [ ] QR authentication
- [ ] Local discovery

---

# EPIC 9 — Synoptikon

ADR 0009 defines the cross-repository integration boundary. Framework-neutral
host contracts and fail-closed readiness tests may proceed now. Production
bootstrap, QR login, session issuance, device administration, and central
audit remain blocked until EPIC-8, the accepted COSE profile and shared mobile
fixtures, durable binding/ceremony adapters, and Synoptikon's server-only
session-cookie boundary are delivered and accepted.

- [ ] Bootstrap administrator workflow
- [ ] Login page integration
- [ ] QR generation
- [ ] Session creation
- [ ] Device management UI
- [ ] Audit integration

---

# EPIC 10 — Monas

ADR 0010 defines the standalone integration, host-authority, CLI, storage, and
packaging boundaries. A framework-neutral contract and explicitly non-production
reference components may proceed now. Production Monas login, durable SQLite
operation, detached evidence/report signing, local discovery, and release
packaging remain blocked until the EPIC-9 production gates and the applicable
EPIC-11, EPIC-12, EPIC-13, and EPIC-15 decisions and acceptance evidence exist.

- [ ] Standalone server
- [ ] CLI login demo
- [ ] CLI verifier
- [ ] Standalone documentation

---

# EPIC 11 — Local discovery

ADR 0011 defines privacy-minimizing installation advertisement, signed
endpoint binding, TLS pinning, native adapter, bounded fallback, and
host/browser boundaries. Deterministic discovery contracts and hostile-network
tests may proceed now. Production advertisement and direct exchange remain
blocked until EPIC-10, the accepted production signed-message profile, host and
native permission adapters, dependency review, and the IPv4/IPv6,
multiple-interface, multicast-blocked, and physical-device acceptance matrix
are complete.

- [x] Evaluate mDNS implementation
- [x] Advertise installation
- [x] Discover installation
- [ ] Secure local transport
- [ ] Fallback to QR

---

# EPIC 12 — Evidence

- [ ] Define evidence schema
- [ ] Define signing claims
- [ ] Generate detached evidence
- [ ] Implement verifier CLI
- [ ] Implement verifier library

---

# EPIC 13 — Recovery

ADR 0012 defines independent multi-device credentials, replacement without key
migration, monotonic revocation and session invalidation, governed
sole-administrator recovery, external-identity loss policy, and temporal
historic-verification semantics. Framework-neutral lifecycle contracts and
negative state-machine tests may proceed now. Production recovery remains
blocked until EPIC-12 detached evidence and trusted-time semantics, durable
host transactions and session invalidation, native recovery ceremonies, and
complete iOS and Android lost-device exercises are delivered.

- [ ] Multiple devices
- [ ] Replace device
- [ ] Lost device flow
- [ ] Administrator recovery
- [ ] Historic verification after revocation

---

# EPIC 14 — Security

ADR 0013 defines revision-bound security assurance, independent-review
criteria, finding and residual-risk governance, threat/control traceability,
privacy and dependency inventories, fuzz evidence, and incident readiness.
Automated hardening and review-readiness evidence may proceed now, but they
cannot be represented as an independent assessment. EPIC-14 remains blocked
until the production surfaces are complete, independent penetration and
cryptographic reviews and the privacy assessment are authenticated, critical
and high findings are closed, medium risks are explicitly accepted with owned
plans, incident exercises pass, and the security owner approves the exact
release candidate.

- [ ] Threat model review
- [ ] Penetration testing
- [ ] Dependency review
- [ ] Privacy review
- [ ] Cryptographic review

---

# EPIC 15 — Release

ADR 0014 defines immutable candidate identity, separated
assemble/verify/approve/publish phases, credential-isolated Jenkins release
tasks, an artefact/provenance manifest, per-artefact SBOMs, qualified
reproducibility, packaged acceptance, signed approvals, and immutable
publication. Credential-free manifest validation, packaging prototypes, SBOM
reconciliation, and blocked release-task definitions may proceed now. EPIC-15
remains blocked until all prior product and security gates pass for the exact
packaged candidate, external signing/store prerequisites exist, required
approvals bind the final manifest digest, publication succeeds, and the
immutable signed `v1.0.0` tag is created. EPIC-16 is an explicit release gate
despite its later planning identifier.

- [ ] Build SBOM
- [ ] Package RPM
- [ ] Publish Rust crates
- [ ] Publish iOS build
- [ ] Publish Android build
- [ ] Execute acceptance matrix
- [ ] Tag v1.0.0

---

# EPIC 16 — CLI-native authentication

Pistis treats terminal users as a primary product audience. Authentication and
action approval shall complete from a console with the supported iOS
application, without a browser, web application, desktop GUI, or clipboard
ceremony. Android interoperability remains required for v1.0 but does not block
`v0.1.0-rc.1`. EPIC-16 is release-blocking and extends the EPIC-6 transport and
EPIC-10 CLI contracts; it does not introduce a second verifier or weaker
authentication path.

## Terminal QR presentation

- [x] Define terminal capability and rendering profile
- [x] Implement deterministic ASCII and Unicode QR rendering
- [x] Display installation identity, purpose, expiry, and fingerprint
- [x] Support narrow, monochrome, SSH, tmux, and screen terminals
- [ ] Add scanability fixtures for the supported iOS device

## CLI authentication and approval

- [ ] Implement `pistis auth login`
- [ ] Implement `pistis auth exec`
- [x] Bind approvals to the exact action and command digest
- [ ] Support direct-local signed response submission after MVP
- [x] Support bounded terminal-safe framed response input
- [x] Implement cancellation, denial, expiry, and interruption handling

## Security and session handling

- [x] Keep credentials and session material out of argv and shell history
- [x] Prevent terminal escape and control-sequence injection
- [ ] Enforce the shared single-use challenge verifier boundary
- [x] Add replay, substitution, wrong-installation, and wrong-action tests
- [ ] Define secure session hand-off for child CLI processes
- [ ] Retain tamper-evident authentication and approval evidence

## Interoperability and operations

- [ ] Add iOS terminal-QR interoperability tests
- [ ] Add Android terminal-QR interoperability tests for v1.0
- [ ] Add headless and offline end-to-end acceptance tests
- [x] Add CLI user and operator documentation
- [ ] Add dual-architecture Jenkins evidence gates

EPIC-15 release acceptance remains blocked until EPIC-16 passes for the exact
release candidate.

The portable EPIC-16 foundation is implemented: the strict command parser,
canonical argument-vector digest, deterministic terminal renderer, bounded
response reader, orchestration interfaces, fail-closed executable, unit and
regression tests, ADR 0015, and operator documentation. Production completion
remains open because the executable has no running authoritative handler or
secure child-session handoff, mobile exact-action interoperability is absent,
and Jenkins has no retained device/dual-architecture acceptance dossier. ADR
0016 and its tested additive v2 schema remove the v1 action-authority blocker
without changing v1 login. ADR 0017 and `pistis-agent` add owner-only durable
storage, socket framing, non-export signing interfaces, closed semantic
dispatch, and a tested CLI socket client. The native Security-framework signing
operation, native same-user peer authorization, bounded daemon lifecycle, and
single-authority semantic handler are implemented. The agent no longer creates
or stores sessions: its mutation-free coordinator delegates the final
challenge-consumption, Prosopikon-session, and audit transaction to the
host-owned completion port required by the MVP contract. The production
Prosopikon port, protocol-specific login/action adapter, supervised child
command hand-off, and key provisioning remain open. The unchecked MVP items
above are release blockers; a successful library test is not evidence that a
mobile login or action approval completed.

---

# Continuous tasks

- [ ] Keep ADRs current
- [ ] Maintain API documentation
- [ ] Expand protocol fixtures
- [ ] Add regression tests for every bug
- [ ] Maintain benchmark suite
- [ ] Maintain interoperability tests
- [ ] Review dependencies monthly
- [ ] Keep security advisories current

---

# MVP release-candidate programme

`MVP_RELEASE_CANDIDATE.md` is normative for the `v0.1.0-rc.1` programme.
Completion here does not close deferred `v1.0` work above.

## EPIC 17 — MVP baseline and stabilization

- [x] Review and merge EPIC-16 PR 204
- [x] Review and merge EPIC-11 PR 206
- [x] Resolve dependency PR 202 independently
- [x] Reconcile TODO and GitHub delivery states
- [x] Pass authoritative Jenkins CI on the integrated `main`
- [x] Record the clean pre-MVP integration point

The immutable completion record is retained in GitHub issues #207 and #221.
It identifies the exact integrated `main` revision, authoritative Expedition,
stage outcomes, and retained artifact count. EPIC-16 remains open for its
documented production gaps; EPIC-17 landing the reviewed foundation does not
waive those acceptance criteria.

## EPIC 18 — Rust/iOS interoperability

- [x] Accept the production COSE profile
- [x] Freeze canonical enrolment, challenge, response, and evidence schemas
- [x] Publish shared positive and negative Rust/iOS fixtures
- [ ] Prove Secure Enclave public-key encoding interoperability
- [ ] Prove Face ID-gated signing interoperability
- [x] Add downgrade, substitution, replay, and malformed-input cases
- [ ] Retain Jenkins interoperability evidence

ADRs 0018 and 0019 freeze the untagged COSE Sign1 profile and closed MVP
integer-key payloads. This governance completion does not establish
interoperability: shared Rust/iOS fixtures, native Secure Enclave and Face ID
proof, hostile cases, and exact-revision Jenkins evidence remain required.

## EPIC 19 — Prosopikon authority bridge

- [ ] Accept the versioned Prosopikon--Pistis port
- [ ] Persist explicit Pistis-to-Prosopikon principal bindings
- [ ] Implement administrator-issued single-use invitations
- [ ] Implement host-owned atomic completion
- [ ] Bind sessions to product audience and authority revision
- [ ] Implement idempotent retry without duplicate sessions
- [ ] Invalidate sessions on device, binding, and policy revocation
- [ ] Append minimized authority and Pistis audit records atomically
- [ ] Add SQLite and SQL/Hebe adapter conformance suites

## EPIC 20 — Monas MVP route

- [ ] Pin reviewed Pistis and Prosopikon revisions
- [ ] Mount the shared Prosopikon Pistis UI
- [ ] Implement the Monas SQLite authority adapter
- [ ] Deliver enrolment, login, logout, and device-revocation routes
- [ ] Preserve Monas authorization and CSRF boundaries
- [ ] Exercise restart, concurrency, backup, restore, and corruption paths
- [ ] Retain exact-revision cross-repository Jenkins evidence

## EPIC 21 — Synoptikon/Mneion MVP route

- [ ] Pin reviewed Pistis and Prosopikon revisions in Mnemosyne
- [ ] Mount the shared Prosopikon Pistis UI in Mneion
- [ ] Implement the SQL/Hebe authority adapter
- [ ] Deliver enrolment, login, logout, and device-revocation routes
- [ ] Preserve tenant, entitlement, request-context, and audit boundaries
- [ ] Exercise restart, concurrency, migration, and rollback paths
- [ ] Retain exact-revision cross-repository Jenkins evidence

## EPIC 22 — iOS production qualification

- [ ] Register the Mnemosyne Biosciences GitHub App and enable device flow
- [ ] Implement minimum-permission GitHub device-flow enrolment
- [ ] Discard GitHub tokens after stable-identity proof
- [ ] Generate and use the device-protected signing key
- [ ] Require Face ID for every signature
- [ ] Implement enrolment, QR approval, history, and revocation UX
- [ ] Configure Apple signing and TestFlight
- [ ] Pass functional and accessibility simulator suites
- [ ] Pass the signed physical-iPhone acceptance matrix

## EPIC 23 — Authentication evidence

- [ ] Freeze the detached authentication-evidence schema
- [ ] Record enrolment, authentication, CLI approval, and revocation events
- [ ] Minimize and redact retained evidence
- [ ] Implement offline verifier library and CLI
- [ ] Verify trust roots, signatures, policy time, and revocation semantics
- [ ] Add malformed, unsupported, expired, and substituted evidence cases
- [ ] Retain portable evidence in Jenkins dossiers

## EPIC 24 — Packaging and operations

- [ ] Package the service, local agent, CLI, migrations, and systemd units
- [ ] Generate installation keys during privileged bootstrap
- [ ] Load keys through systemd credentials
- [ ] Implement encrypted installation-key backup and explicit restore
- [ ] Document rotation, recovery, upgrade, rollback, and diagnostics
- [ ] Enforce service-account ownership and non-symlink private state
- [ ] Build RPM/SRPM, SBOM, checksums, and provenance
- [ ] Test clean install, upgrade, rollback, backup, and restore

## EPIC 25 — MVP security and release candidate

- [ ] Complete the MVP threat-model review
- [ ] Complete dependency and privacy reviews
- [ ] Pass fuzzing and negative-path acceptance
- [ ] Run the four-repository Jenkins acceptance expedition
- [ ] Verify the signed physical-iPhone record
- [ ] Assemble immutable `v0.1.0-rc.1` artefacts and manifest
- [ ] Record internal release approval against the manifest digest
- [ ] Keep public production release blocked pending independent reviews
