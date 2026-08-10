# Changelog

## [0.7.5] - 2026-08-10

### Added

- Record a completed first Site Root ceremony immediately as an explicit,
  non-authorising `Setup in progress` Installation on the iPhone. The record
  contains only a redacted Monas ceremony reference and next action; it cannot
  become an identity, session, custody record, or trusted installation before
  the separately signed provider enrolment completes.

## [0.7.4] - 2026-08-10

### Fixed

- Retain the attended Site Root review surface through every Face ID and
  network transition, so the iPhone explicitly presents the final ceremony
  outcome instead of returning ambiguously to the scanner.
- Record a redacted local History event for each completed or failed Site Root
  ceremony and refresh History immediately. This observation never grants
  authority or substitutes for Monas’s authoritative audit record.

## [0.7.3] - 2026-08-10

### Fixed

- Encode the Site Root detached COSE payload length with explicit truncating
  byte extraction. Valid canonical delegation payloads longer than 255 bytes
  now produce their required CBOR two-byte length rather than trapping the
  iPhone application after a successful App Attest registration.

## [0.7.2] - 2026-08-09

### Added

- Compose the first Site Root device ceremony on iPhone: a strict Monas
  genesis QR can create or reuse the Face-ID protected Site Root key, submit
  its typed public registration with the genuine App Attest evidence only to
  the fixed SPKI-pinned Monas authority, receive the bound one-time delegation,
  and continue through the existing proof, assertion and custody flow.

### Security

- Require a compile-time Monas Site Root SPKI digest before any Site Root or
  first-genesis request is possible. The QR never chooses an authority,
  endpoint, pin, browser, credential, token or local identity.

## Unreleased

### Added

- Add the compatible `pistis-monas` 0.7.0 retained provider-confirmation
  verifier. It accepts only the exact version-one, four-field Prosopikon
  confirmation against a pinned authority bundle, installation and host;
  verifies the canonical registration and authority receipt COSE envelopes;
  returns typed receipt facts and a digest reference only. It creates no
  session, credential, local authority, Keychain substitute or raw-COSE
  retention path.
- Add its receipt-derived, one-use Site Root genesis binding verifier. It
  accepts only strict canonical JSON and detached low-S ES256 signed by the
  registered Site Root key, binds every value to the verified receipt and
  server-owned registration context, and returns a replay-safe digest reference
  only.

- Add the compatible `pistis-monas` 0.6.0 recipient-key accessor required by
  accepted Site Trust custody genesis. It yields only the canonical compressed
  P-256 public key already verified by the production Apple-root registration
  acceptance; it adds no client key input, persistence, secret, session,
  local authority, fallback, or key derivation.

- Compose the iOS 0.7.1 production Site Root path at application startup:
  only a signed build-time Monas authority origin may construct the existing
  Site Root transport; QR text cannot select an authority. After the exact
  proof and App Attest assertion, Pistis now consumes only the pinned terminal
  custody presentation, requires Face ID for the existing Secure Enclave
  rewrap, and submits it only to Monas's fixed custody endpoint. Missing
  application configuration and every network or custody failure remain
  unavailable; no fallback, session credential, local authority, or persisted
  bootstrap is introduced.

- Add the accepted iOS 0.7.0 retained-session custody-presentation relay
  consumer for Pistis #401. It accepts only Monas's exact terminal,
  SPKI-pinned App Attest response and binds its correlation/canonical challenge
  to the existing #400 Face-ID/Secure-Enclave rewrap producer. No browser, QR,
  cookie, bearer token, local authority, persistence, fallback or activation
  path is introduced; Monas must still provide the matching retained-session
  response composition.

- Add the compatible iOS 0.6.0, non-activating iPhone custody-rewrap
  producer foundation. It maps only an authenticated protected presentation to
  Thesaurophylax #148's exact detached Secure Enclave proof and fresh
  ECDH/HKDF/AES-256-GCM ciphertext, holding the seed only in process memory.
  It deliberately has no presentation decoder, UI entry point, HTTP endpoint,
  browser, QR, cookie, token, local identity, persistence, fallback, or live
  submission path until the separately reviewed fixed custody transport can
  prove the retained App Attest-backed Pistis session.

- Add the compatible iOS 0.5.0 Site Root success consumer. It accepts only
  Monas's exact one-use App Attest bootstrap response after the signed proof,
  keeps it in memory, and immediately sends the iPhone assertion through the
  bootstrap's exact HTTPS-origin and SPKI-pinned transport. It accepts no
  receipt, browser state, cookie, token, local identity, QR-derived endpoint,
  fallback, persisted bootstrap, or completed-session claim.

- Add the compatible ``pistis-monas`` 0.5.0 typed App Attest fact-to-session
  handoff. It binds only an opaque production-issued fact to exact Monas
  installation/principal/device/key/binding/generation/session facts and
  canonical bounded bytes. It accepts only the closed ``monas-local`` audience,
  ``trust-admission`` Site Trust purpose, and ``AuthenticateSession`` Monas
  purpose. Monas must still consume the fact, re-resolve authority, issue a
  protected Prosopikon session, and append audit evidence atomically. It
  carries no raw Apple assertion, cookie, session credential, local/OS
  identity, PAM path, token, role, or fallback.

- Add the iPhone-only, pinned Monas App Attest assertion producer for
  `PIS-IOS-APP-ATTEST-ASSERTION-1`: exact purpose-separated client-data hash,
  strict bounded JSON envelope, device-only opaque key-ID storage, and
  redirect/cookie/cache-free 202-only registration and assertion transports.
  This establishes no Site Trust or Monas session without the separate
  server-side ceremony, verifier, and retention gates. Release the compatible
  iOS capability as 0.4.0.

- Add the additive `pistis-monas` 0.3.0 redacted physical-iPhone App Attest
  vector boundary. It derives exact bindings from the accepted Site Trust
  human-authority fact, accepts only an opaque reviewed production-verifier
  result compatible with Monas' Apple verifier profile, and delegates atomic
  retention to Monas. The shipped verifier remains unavailable; it cannot
  retain synthetic, incomplete, unverified, browser, CLI, local-account, PAM,
  kernel-UID, token, cookie, key, or raw Apple evidence, and grants no session
  or Site Trust authority.

- Add the accepted `mnemosyne.pistis.site-trust-human-authority-fact.v1`
  `pistis-monas` contract. It structurally binds a frozen Proxenos Site Trust
  payload, exact Pistis intent, installation, enrolled iPhone, key and
  ceremony to a fail-closed Apple App Attest verification request and
  host-owned atomic one-use fact store. The shipped Apple verifier is
  explicitly unavailable; no unverified or synthetic assertion can issue a
  fact. Release this compatible capability as `pistis-monas` 0.2.0.

- Define and test the credential-free Debian content gate for the
  Monas-owned Pistis provider lifecycle.  The gate requires the fixed
  `mnemosyne-monas` peer boundary and rejects shipped authority sockets and
  package-time activation; it establishes no runtime authority.

### Fixed

- Redact QR transfer `Debug` output to kind and byte lengths. Scanned payload,
  signature, COSE, invitation-presentation, and authority-bundle bytes can no
  longer be formatted accidentally. Framing, parsing, wire bytes, and ceremony
  semantics are unchanged.

All notable changes to Pistis will be documented here. The format follows Keep
a Changelog and releases follow Semantic Versioning.

## [Unreleased]

### Added

- Harden the non-production Pistis-to-Monas host-session contract to reject
  the reserved all-zero audit-correlation sentinel before binding resolution
  or session issuance. This does not add QR, device, broker, signature,
  persistence, or browser-session behaviour.

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
