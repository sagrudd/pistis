# Changelog

All notable changes to Pistis will be documented here. The format follows Keep
a Changelog and releases follow Semantic Versioning.

## [Unreleased]

### Added

- Start bounded QR camera capture when the Scan tab appears and stop it when
  the tab disappears. Camera recovery is shown only after an explicit
  permission denial. Add a typed, HTTPS-only Monas Site Root readiness and
  submission transport that remains unavailable for every malformed, redirected
  or unavailable authority response. Release this compatible iOS capability as
  0.3.1.

### Fixed

- Make the CLI demonstration's unavailable-authority preflight deterministic
  and prove that missing or relative local-agent configuration returns a
  redacted exit-69 failure before any QR presentation or authority mutation.

- Bind the funding-review Monas web-QR fixture to the accepted `propylaion`
  product audience and prove that it remains distinct from, and authorised by,
  the signed first-device enrolment profile.

### Added

- Add the accepted `pistis-secure-enclave-es256-cose-v1` iPhone Site Root
  boundary: a distinct Secure Enclave key registration and a closed detached
  ES256 COSE proof producer for Monas `SiteRootDelegationV1`. It has no private
  key export, software fallback, HTTP authority, or Apple attestation claim.
  Release this compatible iOS capability as 0.2.0.

- Add the separate `monas.site-root-delegation-presentation.v1` QR scanner,
  redacted review surface, and fail-closed typed Monas submission boundary for
  an attended Secure Enclave Site Root proof. The legacy Pistis v2 scanner is
  unchanged. Release this compatible iOS capability as 0.3.0.

- Add a redacted, machine-readable funding-review demonstration contract for
  CLI first-device registration, iPhone host trust, Monas web QR login,
  Kyberneterion exact-action workflow selection, and fail-closed negative cases.

- Define the bounded end-to-end Monas demonstration contract linking a
  device-approved Pistis session to DASObjectStore evidence, Oikodome compute
  admission, and a pinned Jenkins Expedition task, including fail-closed
  negative cases and the retained cross-repository dossier.

- Retain the exact first-device operation identifier and Secure Enclave key
  across ambiguous begin-response failures, enabling Prosopikon's
  byte-identical idempotent replay instead of generating a divergent retry.

- Accept and implement QR-bound, app-scoped iOS host trust from ADR 0029,
  withdrawing the manual root-certificate/Settings ceremony from MVP
  acceptance. Version-4 presentations bind the exact origin and DER-SPKI
  SHA-256, derive three cross-language comparison words, and create an
  ephemeral pinned transport only after explicit typed confirmation.
- Retain the version-3 first-device presentation solely as downgrade and
  historical evidence; new enrolment accepts only version 4.
- Reject regular-file standard input at the first-device presenter so the
  sensitive authority frame can arrive only through an actual FIFO.
- Commit distinct initial-invitation and mobile-receipt authority keys in one
  canonical bundle; verify the exact device registration and receipt before a
  create-once iOS Keychain install.
- Require the user to review the immutable GitHub login and numeric subject
  before a separate Face ID confirmation, with fail-closed orphan Secure
  Enclave key cleanup and retry/recovery retention.
- Verify authority receipt time only after the confirmation response arrives,
  and retain the exact randomized device-registration envelope across
  transient in-app retries so a committed response can be replayed
  byte-identically.
- Bind the reviewed GitHub App configuration fixture, Info.plist digest, and
  Swift runtime digest with a deterministic regression test.
- Correct the proposed first-device decisions so pending provider operations
  remain non-terminal and anonymous pipes are not misrepresented as a
  peer-authentication mechanism.
- Require a distinct 32-byte CSPRNG mobile polling capability whose durable
  authority state contains only the digest.
- Keep first-device replay authority singular: presentation IDs are
  correlation-only, while the invitation and durable provider operation own
  one-use state.
- A proposed installation-local GitHub Device Flow verifier that keeps provider
  tokens outside mobile and authority boundaries while preserving Prosopikon
  as the sole durable enrolment state machine.
- A proposed pipe-only, alternate-screen first-device QR presentation that
  binds the canonical invitation, authority descriptor, intended identity,
  and exact Monas HTTPS origin without manual bearer transport.
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
- A development-evaluation iOS GitHub Device Flow screen using the reviewed
  organisation App configuration, explicit foreground resume, stable numeric
  identity display, transient credential clearing, and an honest boundary
  before Prosopikon authority enrolment.
- Owner-only local-agent SQLite and Unix-socket foundations with bounded
  canonical framing, restart-safe single-use ceremony transitions, and a
  non-exportable installation-signing provider contract.
- Native macOS Keychain lookup and Security-framework ES256 signing with
  duplicate-key refusal, low-S conversion, public-key identifier derivation,
  and independent signature verification.
- A closed local-agent request/response protocol, peer-authorisation-first
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
- A strict untagged COSE Sign1 production profile, frozen MVP signed-message
  schemas, and shared Rust/Swift positive and hostile interoperability fixtures.

### Changed

- Replace the incomplete generic challenge diagnostic schema with closed
  authentication challenge and response diagnostic schemas. These JSON views
  remain non-normative and are never signed or accepted on protocol boundaries.

### Fixed

- Bind iOS final first-device confirmation to the exact invitation required by
  the durable Prosopikon transaction.
- Sample the attended first-device clock only after the protected pipe frame is
  complete, and reject terminal heights that would scroll finder patterns away.
- Correct the operator-guide SHA-256 for the retained physical-iPhone
  interoperability record and enforce the documentation-to-fixture binding in
  a deterministic regression test.

### Security

- Upgrade `jsonwebtoken` to the patched 10.x validation implementation and use
  the reviewed AWS-LC cryptographic backend, resolving CVE-2026-25537.
- Reject malformed, oversized, corrupt, substituted, replayed, and conflicting
  QR authentication transfers while keeping polling redacted and binding
  challenge consumption, session rotation, and audit creation atomically.
