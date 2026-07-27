# Changelog

All notable changes to Pistis will be documented here. The format follows Keep
a Changelog and releases follow Semantic Versioning.

## [Unreleased]

### Added

- Repository governance, planning, automation, and quality-gate bootstrap.
- Strongly typed protocol identifiers with canonical textual forms.
- Strict deterministic-CBOR serialization, parsing, and golden fixtures.
- Secure, expiring, atomically single-use challenge lifecycle primitives.
- Protocol, encoding, assurance, signature-suite, and threat-model
  specifications.
- Enforced hierarchical Rust source placement and a reviewed 1,000-line
  source-file limit through the repository architecture gate.
- ES256 verification, SHA-256 hashing, full-width key identifiers, structured
  verifier outcomes, conformance fixtures, and bounded fuzz targets.
- GitHub OAuth trust enrolment with PKCE S256, constant-time callback-state
  validation, minimal scopes, stable numeric account identifiers, and
  short-lived secret handling through a narrow confidential broker boundary.
- Provider-neutral durable identity bindings with versioned, atomic,
  fail-closed file persistence and end-to-end provider fixture coverage.
- Google OpenID Connect trust enrolment with pinned discovery, PKCE S256,
  one-use callback correlation, local RS256/JWKS verification, canonical issuer
  handling, stable subject extraction, and durable `(issuer, sub)` bindings.
- A constrained SQLite device registry with embedded checksummed migrations,
  public-key-only records, structured assurance metadata, optimistic
  concurrency, reversible suspension, terminal revocation, and retained
  lifecycle history.
- Bounded deterministic QR challenge and response framing, QR matrix rendering,
  closed authentication schemas, redacted browser polling, verified reference
  completion, atomic in-memory session/audit transitions, and offline
  acceptance coverage for response-QR and direct-local transfer.
- EPIC-11 foreground nearby-request MVP semantics and a reviewed discovery
  implementation selection covering native iOS/Android and the Rust host,
  including bounded host advertisement and strict local candidate discovery.
- EPIC-16 roadmap and acceptance contract for primary CLI-native login and
  exact-action approval through terminal-rendered ASCII/Unicode QR exchange
  with the supported iOS application.
- A fail-closed `pistis` CLI contract, canonical command digests,
  deterministic terminal-safe ASCII/Unicode QR rendering, bounded response
  ingestion, ceremony orchestration interfaces, and EPIC-16 operator guidance.
- A closed additive v2 exact-action descriptor, challenge, and response schema
  with downgrade/substitution rejection and an agent-controlled single-use
  revalidation and direct-execution boundary.
- Owner-only local-agent SQLite and Unix-socket foundations with bounded
  canonical framing, restart-safe single-use ceremony transitions, and a
  non-exportable installation-signing provider contract.
- Native macOS Keychain lookup and Security-framework ES256 signing with
  duplicate-key refusal, low-S conversion, public-key identifier derivation,
  and independent signature verification.
- A closed local-agent request/response protocol, peer-authorization-first
  single-request dispatch, owner-only CLI socket backend, and fail-closed
  terminal executable with protected framed-response input.
- Native same-user socket credential checks, bounded per-client daemon I/O,
  controlled service shutdown, and a single-authority ceremony handler
  contract requiring atomic verification, session, and audit completion.
- A host-owned completion port that binds one verified response to atomic
  challenge consumption, Prosopikon authority/session creation, and audit
  append, with exact-request idempotency and non-secret durable receipts.
- A mutation-free staged-response verifier coordinator with operating-system
  session randomness and fail-closed verification/randomness regression tests.

### Changed

- Replace the incomplete generic challenge diagnostic schema with closed
  authentication challenge and response diagnostic schemas. These JSON views
  remain non-normative and are never signed or accepted on protocol boundaries.

### Security

- Upgrade `jsonwebtoken` to the patched 10.x validation implementation and use
  the reviewed AWS-LC cryptographic backend, resolving CVE-2026-25537.
- Reject malformed, oversized, corrupt, substituted, replayed, and conflicting
  QR authentication transfers while keeping polling redacted and binding
  challenge consumption, session rotation, and audit creation atomically.
