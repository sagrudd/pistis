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

- [ ] Standalone server
- [ ] CLI login demo
- [ ] CLI verifier
- [ ] Standalone documentation

---

# EPIC 11 — Local discovery

- [ ] Evaluate mDNS implementation
- [ ] Advertise installation
- [ ] Discover installation
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

- [ ] Multiple devices
- [ ] Replace device
- [ ] Lost device flow
- [ ] Administrator recovery
- [ ] Historic verification after revocation

---

# EPIC 14 — Security

- [ ] Threat model review
- [ ] Penetration testing
- [ ] Dependency review
- [ ] Privacy review
- [ ] Cryptographic review

---

# EPIC 15 — Release

- [ ] Build SBOM
- [ ] Package RPM
- [ ] Publish Rust crates
- [ ] Publish iOS build
- [ ] Publish Android build
- [ ] Execute acceptance matrix
- [ ] Tag v1.0.0

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
