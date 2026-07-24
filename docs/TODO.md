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

- [ ] Define InstallationId
- [ ] Define UserId
- [ ] Define DeviceId
- [ ] Define ChallengeId
- [ ] Define EvidenceId
- [ ] Define KeyId
- [ ] Define ExternalIdentityId

## Canonical encoding

- [ ] Choose encoding (CBOR/COSE)
- [ ] Implement canonical serializer
- [ ] Implement canonical parser
- [ ] Produce golden fixtures
- [ ] Write round-trip tests

## Challenge lifecycle

- [ ] Generate nonce
- [ ] Generate expiry
- [ ] Generate challenge identifiers
- [ ] Validate expiry
- [ ] Prevent replay
- [ ] Prevent double consumption

---

# EPIC 2 — Crypto

- [ ] Select signature suite
- [ ] Implement hashing
- [ ] Implement signature verification
- [ ] Implement key identifier generation
- [ ] Implement verifier API
- [ ] Fuzz canonical parser
- [ ] Fuzz verifier

---

# EPIC 3 — GitHub trust

- [ ] Register OAuth application
- [ ] Implement PKCE flow
- [ ] Validate callback
- [ ] Retrieve stable GitHub user id
- [ ] Persist identity binding
- [ ] Add integration tests

---

# EPIC 4 — Google trust

- [ ] Implement OIDC discovery
- [ ] Validate ID token
- [ ] Extract issuer
- [ ] Extract subject
- [ ] Persist identity binding
- [ ] Add integration tests

---

# EPIC 5 — Device registry

- [ ] Create database schema
- [ ] Create migration
- [ ] Implement repositories
- [ ] Store public keys
- [ ] Store assurance metadata
- [ ] Implement revocation
- [ ] Implement suspension

---

# EPIC 6 — QR authentication

- [ ] Encode challenge QR
- [ ] Decode response QR
- [ ] Browser polling endpoint
- [ ] Browser completion endpoint
- [ ] Authentication acceptance tests

---

# EPIC 7 — iOS

## Foundation

- [ ] Create SwiftUI project
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
