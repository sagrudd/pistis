# Changelog

- Make the native accessibility gate accept either no SwiftUI navigation-row
  framework contrast findings or the exact reviewed set of three. Partial and
  additional findings remain failures; the gate no longer requires an SDK
  false positive to be present (0.23.7, iOS build 54).

- Preserve an accepted first-device provider handle when the initial status
  projection is temporarily unavailable. Pistis now retries status with that
  handle and cannot begin a second operation for the already-begun invitation.
  A fresh GitHub prompt remains available, while retained already-verified
  recovery never displays its inert server sentinel as an operator code
  (0.23.7, iOS build 54).

- Recheck the live Monas authority-custody state before a retained installation
  advances from locally completed custody to first-device identity enrolment.
  A restarted host signer now enters the existing App Attest and Face ID
  recovery path; provider enrolment opens only after custody is live, and the
  installation action explicitly describes that gate (0.23.6, iOS build 53).

- Stage a freshly attested App Attest registration key until the pinned Monas
  authority accepts its exact envelope, preventing a rejected first-device
  retry from replacing the phone's reference to the immutable registered key.
  An attended custody challenge can restore only that exact server-registered
  reference after Apple proves the original key still exists on this app and
  device; unavailable keys and failed proofs remain non-mutating (0.23.5, iOS
  build 52).

- Restore the complete iPhone Simulator candidate gate by giving the Settings
  navigation and tab surfaces an opaque reviewed canvas, enforcing exactly one
  known Xcode 26.5/26.6 anonymous contrast finding for each of the three native
  navigation rows, and explicitly retaining white text on the destructive
  reset control. Any additional or missing contrast finding fails closed
  (0.23.4, iOS build 51).

- Correct the formal first-login simulator so Site X.509 can never advance
  directly to first-device identity. The candidate now executes the production
  authority-custody v2 status, initial-rotation and recovery wire boundaries,
  explicit App Attest and Face ID outcomes, durable signer checkpoint,
  out-of-order/replay denial and the no-QR operator action before identity
  enrolment (0.23.3, iOS build 50).

- Add a test-target-only iPhone Simulator for the complete formal Monas first
  install, Propylaion home login and exact-audience DASObjectStore login. The
  candidate gate drives production QR parsers and signed challenge
  verification, rejects replay, expiry, substitution, stage skipping,
  biometric/App Attest denial, identity mismatch and audience confusion, and
  explicitly leaves Secure Enclave, Face ID and App Attest as a physical-device
  gate (0.23.2, iOS build 49).

- Report every brokered Site X.509 approval stage after Face ID, including the
  retained root and issuer unlocks, acknowledgement setup and initial leaf
  approval. A host-side continuation wait can no longer remain labelled as a
  biometric prompt, and regression tests pin the complete ordered progress
  projection without exposing ceremony material (0.23.1, iOS build 48).

- Add an explicit Face-ID-gated **Reset Pistis on this iPhone** operation that
  erases the closed set of device-local identities, installation trust,
  Pistis-owned Secure Enclave keys, App Attest references, custody/setup
  projections and diagnostic stores. Cancellation is non-mutating, partial
  erasure is reported truthfully, authority state is never described as
  deleted, and a gate-by-gate first-device/first-Monas-login runbook defines
  the required host reconciliation boundary (0.23.0, iOS build 47).

- Bound the one-use Site Root bundle-receipt provision to its steady custody
  continuation by retrying only the short, explicit authority-unavailable
  window while the NUC finalizes and exposes the attended unlock socket. The
  retry is bounded, preserves the same Face ID ceremony, and fails closed for
  permanent failures (0.22.16, iOS build 46).

- Decode the exact Monas bundle-receipt acceptance field,
  `receipt_key_generation`, after protected proof submission. A closed response
  regression rejects the previously invented `generation` field so the iPhone
  cannot falsely report failure after the NUC has committed the receipt key
  (0.22.15, iOS build 45).

- Decode the Site Root bundle-receipt provision challenge using the exact
  Thesaurophylax 32-bit field lengths. The cross-language regression fixture
  now matches the 337-byte production wire payload, validates the embedded
  challenge beyond QR routing, and rejects the former 16-bit test-only form
  (0.22.14, iOS build 44).

- Route a production-shaped Site Root bundle-receipt QR through acquisition,
  JSON dispatch, and the direct protected-review coordinator in one regression
  test. Structurally valid expired receipt presentations now receive a precise
  reissue instruction instead of the generic unsupported-carrier message
  and the identity-only camera now identifies a valid Monas authority QR as a
  Scan-tab context mismatch rather than claiming it is unsupported (0.22.13,
  iOS build 43).

- Verify live Site authority custody before an already trusted installation
  enters DAS local-authority retirement. A recovery-required host now completes
  retained Site Root custody without incorrectly chaining into DAS on the
  recovery-only listener. Regression tests cover both the preflight and the
  post-recovery boundary (0.22.12, iOS build 42).

- Accept the exact retained first-device custody generation in the ADR-0039
  DAS replacement-receipt presentation. Pistis still validates the closed
  identifier and reconstructs the complete canonical challenge, but no longer
  invents a `das-replacement-*` namespace that the accepted contract does not
  define. A production-shaped regression fixture covers the pre-Face ID
  failure (0.22.11, iOS build 41).

- Bypass the legacy authority-custody status preflight when an already trusted
  installation starts ADR-0039 purpose-four DAS authority retirement. The
  trusted action now enters the pinned receipt route directly and a regression
  asserts that routing decision (0.22.10, iOS build 40).

- Continue ADR-0039 purpose-four DAS authority retirement directly from an
  already trusted installation using its pinned native Monas origin and one
  fresh Face ID evaluation. The action cannot enrol, replace or discard a
  Pistis identity, and a regression prevents trusted installations from being
  routed back into provider enrolment (0.22.9, iOS build 39).

- Restore the accepted post-PXFP NUC replacement-build path without adding
  deployment data to the generic Pistis release. A code-signed exact Site Root
  profile now restores the native Monas transport at launch, rebinds the
  broker-created setup projection to that authority, and requires v2 authority
  custody before GitHub identity enrolment. Regressions cover the skipped
  custody phase and relaunch rebind (0.22.8, iOS build 38).

- Include the fixed
  `proxenos.site-x509-initial-leaf-issuance.v1` purpose in the protected leaf
  submission envelope required by Monas. The encoded-envelope regression now
  asserts the complete nine-field Monas decoder contract, including both
  schema and purpose (0.22.7, iOS build 37).

- Emit the documented Monas
  `monas.site-x509-leaf-approval-submission.v1` schema for the protected leaf
  proof. The exact encoded submission envelope is regression tested so a
  Face ID-approved proof cannot again be rejected at the broker-to-Monas JSON
  boundary (0.22.6, iOS build 36).

- Accept Proxenos's canonical retained Site Root authority generation in the
  combined initial-leaf PXLA payload. Pistis now applies the protocol's strict
  identifier grammar without inventing `x509-root-*` or `x509-issuing-*`
  prefixes, and a retained-authority regression fixture covers the production
  failure before Face ID (0.22.5, iOS build 35).

- Inject the broker continuation capability explicitly into protected recovery
  instead of rediscovering it through a runtime protocol cast immediately
  before Face ID. The recovery route now has a compile-time continuation
  contract and cannot misreport that cast boundary as a Site Root outage
  (0.22.4, iOS build 34).

- Keep the fixed install broker available alongside a retained direct Monas
  authority and route continuation-recovery presentations to it explicitly.
  A retained installation can now resume protected Site X.509 approval instead
  of failing before Face ID with a false Site Root authority outage; the exact
  retained-direct-plus-broker route is regression tested (0.22.3, iOS build 33).

- Route every brokered Site X.509 continuation poll and submission through the
  deployed `/api/first-install/v1` broker prefix. The production-path
  regression gate now rejects the root-relative endpoints that returned an
  Apache 404 and were surfaced as a false Site Root authority outage (0.22.2,
  iOS build 32).

- Route a retained broker-backed Site Root installation to the protected Site
  X.509 scanner instead of an unavailable native authority operation, and
  advance its non-authorising local setup projection only after the brokered
  continuation succeeds. This preserves the retained Site Root, removes the
  deterministic post-proof “authority unavailable” regression, and makes the
  checked GitHub identity presentation the next setup step (0.22.1, iOS build
  31).

## [Unreleased]

### Changed

- Allow a verified host up to 90 seconds to complete the local custody and App
  Attest check after the broker has accepted a first-device registration. The
  UI now says that Monas is verifying the accepted registration, and the
  broker-envelope regression gate checks every App Attest field that Monas
  consumes (0.20.13, iOS build 28).

- Align the Site Root genesis QR parser with Monas's reviewed 15-minute
  post-redemption ceremony lease. A valid attended QR no longer falls through
  as unsupported after five minutes; an actually expired QR receives a bounded
  fresh-ceremony instruction (0.20.12, iOS build 27).

- Distinguish “submitting protected registration” from “registration accepted;
  waiting for Monas delegation” in the first Site Root ceremony. The bounded
  event journal now records the broker's HTTP 202 before it starts the
  delegation poll (0.20.11, iOS build 26).

### Added

- Insert the missing brokered PXAK acknowledgement-key registration between
  issuer custody unlock and initial-leaf approval. The NUC verifies the
  enrolled Site Root proof and registers the key with Proxenos before Pistis
  retains Proxenos's protected leaf generation and signs that leaf, preserving
  one QR and one bounded Face ID context. Ordered orchestration, exact parser,
  digest and forward-wait regressions now fail closed (0.22.0, iOS build 30).

- Continue the accepted pre-native Site X.509 ceremony through the fixed
  broker without another QR. Root custody rewrap, issuer custody rewrap and
  the combined initial-leaf approval retain separate purpose-bound proofs
  while reusing the one bounded Face ID context. Add the purpose-fixed
  accepted-result recovery QR needed only for a proof completed before this
  continuation-capable build existed (0.21.0, iOS build 29).

- Add a bounded iOS onboarding event journal and the reviewed fixed-broker
  upload path. During a protected Site Root ceremony Pistis sends only
  redacted, fixed-vocabulary challenge events through the QR's server-issued
  correlation; the install window projects them live, and unacknowledged local
  rows expire after 48 hours (0.20.10, iOS build 25).

### Fixed

- Bound the fresh-device Site Root broker wait to 30 seconds, preserve precise
  App Attest and broker failure stages, and show staged progress with elapsed
  time instead of collapsing the operation into a generic proof failure
  (0.20.8, iOS build 23).

- Make the approved physical iPhone archive deterministic: Release now uses
  the installed Apple Distribution identity and reviewed Ad Hoc profile
  instead of allowing automatic signing to select a development profile
  (0.20.7, iOS build 22).

- Add a hard gate for the approved physical iPhone artifact: a build used for
  Monas first-device registration must be Apple Distribution-signed, must have
  production App Attest enabled, and must not carry `get-task-allow`. This
  prevents a development-signed `Release` build from reaching a production
  ceremony and being reported as a misleading Site Root authority outage
  (0.20.6, iOS build 21).

- Generate a fresh Apple App Attest key for every new attended Site Root
  registration and retain its identifier only after attestation succeeds.
  Interrupted first-device attempts can no longer reuse a one-use key and
  stop before sending registration to Monas (0.20.5, iOS build 20).

### Changed

- Remove unused demonstration identities and fixed installation data from the
  production iOS target. Customer identity, host origin, trust material and
  installation labels are now exclusively runtime attended-install data
  (0.20.4, iOS build 19).

- Bind later authentication to the exact HTTPS origin and TLS leaf SPKI
  authenticated during first-device enrolment. Current trust records now carry
  those public endpoint facts, pre-binding records fail closed, and changed
  certificates or endpoint origins cannot receive an authentication response
  (0.20.3, iOS build 19).

- Route fresh-device Site Root genesis through the fixed, host-agnostic
  `https://install.mnemosyne.co.uk` broker. Registration, delegation polling
  and initial static proof relay use the PHP/Rust correlation contract; no
  QR-selected customer host is accepted. Align the broker proof envelope with
  the completion schema consumed by the PHP relay (0.20.2, iOS build 19).

- Route a verified first-device `PISTIS1` enrolment presentation scanned from
  the generic Scan surface into the existing first-device flow, automatically
  starting the GitHub device prompt while preserving Site Root JSON and
  ordinary authentication routing (0.19.10, iOS build 16).

- Align the protected pre-native Site X.509 parser with the reviewed server
  contract: the browser code keeps its five-minute redemption window, while
  the post-redemption QR may remain valid for up to 900 seconds. Release
  0.19.9 is iOS build 15.

- Make the Pistis release host-agnostic (0.19.8, iOS build 14). Customer host
  origin, TLS pins, Site Root certificates, generations and installation
  identity are runtime attended-install data, never compiled into
  ``Info.plist``. The generic binary remains capable of onboarding multiple
  hosts through the fixed install broker.

- Enforce the optional `enrolled_site_root_public_key_id_b64url` broker
  presentation binding in Pistis. When present, it must be canonical base64url
  for one 32-byte key ID and must match the SHA-256 digest of the loaded
  compressed Secure Enclave Site Root public key; mismatches fail before proof
  submission.

- Reserve the protected first-install Site X.509 QR before Face ID and App
  Attest. A failed or interrupted approval is terminal for that presentation;
  replay returns a clear reissue instruction and cannot submit a second proof.

- Preserve and surface the exact Site Root authority-key failure during the
  PXFP2 approval path. Missing, Secure-Enclave-invalidated, and server/local
  public-key mismatch are now distinct fail-closed outcomes; none emits a
  proof or silently creates/replaces a key. The release is Pistis 0.19.3
  (iOS build 11).

- Extend the bounded `.192`/`.193` origin policy through readiness, custody,
  installation-status, and App Attest follow-up requests. Alternate-origin
  retry occurs only for a classified connection-unreachable error; reachable
  HTTP denials, malformed responses, and trust failures remain terminal.

- Retry an identical signed ceremony request across the other explicitly
  pinned computer origin when the first address is unreachable. The request
  bytes, Site Root binding, TLS policy, and endpoint path remain unchanged;
  no new QR, host, alias, or attestation is created.

- Pin the same Monas Site Root authority to a bounded pair of HTTPS origins,
  `192.168.1.192:8443` and `192.168.0.193:8443`, so one portable computer can
  move between its two approved network addresses without creating a second
  authority or accepting arbitrary aliases. QR presentations, response
  endpoints, TLS pins, custody continuation, and installation recovery all
  accept only those two build-time origins; the selected installation's
  address chooses which pinned origin is used for follow-up requests.

- Make empty-state action buttons wrap at larger Dynamic Type sizes so their
  accessibility labels and visible text remain fully readable.

- Persist local trust as a bounded installation inventory rather than a
  single `primary` record. Multiple installations and user personas now remain
  visible and independently addressable; selecting or revoking one record
  cannot replace or erase another. The legacy v1 record is migration-only and
  is never silently discarded while a new installation is added. Production
  and passwordless Secure Enclave signing now resolve the selected
  installation's namespace rather than a shared `primary` key namespace.

- Remove the destructive local fresh-install reset. Trusted installation
  records and Secure Enclave keys are retained until an authority-approved
  replacement or revocation is completed; adding another installation or
  persona must never delete an existing one.

### Added

- Add the staged App Attest replacement foundation for an already enrolled
  physical iPhone. Pistis strictly parses the purpose-separated PXAR/v1
  offline carrier, requires the protected Site, installation, device,
  authority, revocation, current App Attest key and Site-root approval key,
  creates and attests one fresh pending key after Face ID, and commits that key
  only through an opaque acceptance capability returned by the fixed pinned
  Monas transport. The admitted key is unchanged while the response is
  pending; exact retries reuse the retained candidate, a server/local old-key
  mismatch may stage recovery without promotion, and alternate transactions
  or acceptance keys fail closed. The production Scan view provides a
  purpose-specific canonical-JSON file importer, review sheet, response-file
  share action, and fixed pinned Monas submission; the generic QR path does not
  accept replacement presentations. Exact submission bytes are retained with
  the pending key for lost-response/relaunch reconciliation without generating
  another key or attestation; verified 4xx denials remain terminal.

- Add the accepted ADR-0014 offline first-Site-X.509 response path. Pistis
  strictly parses the shared Thesaurophylax `PXFP2:P:` presentation from QR or
  raw file bytes, displays the protected Site/device/target/service-IP facts,
  releases the exact existing Site-root approval after Face ID, binds it to
  the registered production App Attest key, and emits only the canonical
  `PXFP2:R:` response. No network origin, trust exception, browser grant,
  replacement enrolment, CA key or generic signing path is introduced. The
  Monas integration API reconstructs a verifier only from exact protected and
  durable App Attest registration identities, verifies the purpose-bound
  PXAT/v2 assertion, and returns only the monotonic counter and assertion
  digest for atomic one-use consumption.

- Add the attended Site-origin relocation approval profile. Pistis parses and
  displays the byte-exact Proxenos PXSR/v1 old/new private-IP origins and all
  authority generations, releases the existing Site-authority key after one
  Face ID evaluation, binds the detached proof into the registered production
  App Attest assertion, and reconciles ambiguous delivery through fixed
  Site-root-trusted Monas status without reapproval or first-device enrolment.
  Trust exceptions, bootstrap-pin copying, DNS, generic URLs and rollback are
  not available.

- Add the one-use attended DAS local-authority replacement receipt ceremony.
  The iPhone accepts only the fixed purpose-four presentation from the pinned
  Monas origin, reconstructs the full Thesaurophylax challenge, rewraps the
  verified P-256 receipt scalar after one existing Face ID ceremony, and
  advances only after the same server-held stream signs and delivers the
  receipt. There is no new QR, route input, password, trust bypass or fallback.
- Add the dedicated THESXIR2 Site X.509 attended-unlock client. Pistis accepts
  only role-fixed root then issuer presentations from the protected Monas
  origin, verifies each exact P-256 transcript and prior record, reuses one
  immediate Face ID context across the distinct root and issuer proofs, and
  submits no generic custody, Ed25519, alternate-route, single-role, password
  or trust fallback.
- Add the single exact post-unlock PXLA approval for the initial DASObjectStore
  and Monas private-IP leaves. The app parses every fixed TLV, service order,
  digest, serial, validity, transaction, nonce and generation, then signs with
  only the enrolled PXRA acknowledgement key using canonical padded Base64.
- Complete THBR provision with its immediate, dedicated Ed25519 receipt
  authority unlock. The second purpose-bound proof reuses only the
  operation-scoped Face ID context, validates the reconstructed receipt public
  key, and has no generic rewrap or alternate endpoint fallback.
- Add the exclusive post-convergence Site-root-generation TLS mode. A migrated
  Release build compiles the exact authenticated root DER, SHA-256 fingerprint
  and positive generation, validates the private-IP hostname and server chain
  to only that root, and contains no bootstrap leaf pin or trust fallback.
- Add the attended Site Root HTTPS convergence sequence for iPhone: strict
  THBR receipt-key provision, purpose-separated Secure Enclave acknowledgement
  registration, canonical low-S PXRA/v2 signing, and atomic two-role Site
  X.509 first provision. Each QR and route is bound to the signed Monas origin;
  unknown fields, stale/replayed input, endpoint drift, prompt loops,
  re-enrolment and password fallback fail closed.
- Share one fresh Face ID `LAContext` only across the acknowledgement key
  registration and exact acknowledgement signature, and separately across the
  atomic Site X.509 root/issuer approval. Receipt provision remains its own
  attended ceremony and all role keys retain distinct namespaces and purposes.

- Add the strict iPhone MTGS-recovery invitation parser and its dedicated,
  fixed pinned Monas assertion transport. Invitations are bound to the exact
  recovery audience, production App Attest key, authority origin, ceremony,
  challenge digest and a maximum 15-minute lifetime; QR-selected endpoints,
  unknown fields and transport fallback are denied.
- Add the owner-approved, purpose-bound
  `monas:site-trust:mtgs-recovery:v1` App Attest continuation. It reconstructs
  only an opaque process-local acceptance from an exact verified durable
  registration; it neither re-enrols a device nor serializes acceptance state.

### Changed

- After App Attest acceptance, dispatch only the exact live Monas custody
  lifecycle instead of assuming initial rotation, and keep already trusted
  installations out of first-device enrolment after successful recovery.

- Expose live Monas authority-custody reconciliation for an installation that
  is already trusted locally, so protected recovery requirements cannot be
  hidden by a stale terminal UI label.

- Fix the MTGS recovery invitation initializer so the production iPhone target
  compiles the parsed reference and binding fields into the presentation.

- Retain authority-signed local-appliance enrolment receipts whose pinned HTTPS
  endpoint is a canonical dotted-decimal IPv4 address. Abbreviated, octal,
  hexadecimal, leading-zero, overflow and other ambiguous address forms remain
  denied.

- Retain an authority-signed, generation-advanced mobile device replacement
  atomically in the iPhone Keychain. Exact receipt replay remains idempotent;
  installation, identity, authority, audience, host, generation and device-key
  substitutions continue to fail closed.

- Continue a server-committed first-device enrolment directly at the explicit
  account-confirmation step when the bound provider identity is already
  verified. Normal pending enrolments still display the one-use GitHub code;
  recovery never repeats provider authentication or weakens Face ID receipt
  signing.

- Replace typed host-verification words in first-device enrolment with an
  explicit confirmation of the already verified, authority-signed
  installation identity, application digest, HTTPS origin and pinned TLS key.
  Report signed-receipt verification separately from secure local persistence
  so a committed server response can be retried without repeating identity
  proof.

- Align the first-authority host envelope with the accepted Thesaurophylax
  portable ECDH key-wrap profile. The previous Swift-only HKDF domain produced
  ciphertext that the fixed custody runtime correctly refused to open.

- Continue directly from an accepted custody App Attest assertion into the
  retained initial-rotation begin/Face ID/complete ceremony; never re-fetch the
  consumed one-use assertion challenge after its empty `202` acceptance.
- Validate App Attest assertion flags by contract shape: treat user-presence
  and attested-credential-data bits as advisory, require extension data only
  for the extension-bearing shape, deny reserved bits and mixed shapes, and
  report redacted length, flag, RP-ID, CBOR, validation-category, and
  bundle-version failure details.
- Accept Apple's closed 37-byte iOS 26 App Attest assertion authenticator data
  only with the exact registered application RP-ID hash, legacy flags, fresh
  counter, and valid signature, while retaining mandatory strict validation of
  the iOS 27 extension-bearing form and denying mixed or unknown encodings.
- Retain and display the exact redacted custody-continuation stage whenever a
  fail-closed physical-device attempt does not complete.
- Treat Monas's empty, no-store `503` custody status as the explicit
  pre-assertion state, then submit fresh App Attest evidence and re-read the
  authoritative rotation/recovery state before continuing.
- Reconcile duplicate Site Root observations into one canonical installation,
  retain bounded ceremony evidence, and preserve monotonic setup progress.
- Continue custody through pinned fresh App Attest and v2 rotation/recovery,
  surface progress and failures, and route completion to identity enrolment.

### Added

- Expose a bounded, non-secret App Attest custody-verification failure stage so
  Monas can diagnose a physical assertion without logging assertion material,
  keys, identifiers, counters, hashes, or caller text.
- Export that diagnostic verifier and stage from the `pistis-monas` public
  boundary consumed by Monas.
- Add a production-only Pistis-to-Monas continuation that reconstructs opaque
  App Attest assertion acceptance after restart solely from the reviewed
  package manifest, an exact durable verified genesis registration, and the
  server-owned custody-rotation request. It revalidates ceremony, Site Trust,
  installation, Site Trust domain, key, P-256 certificate, TLS leaf, genesis
  configuration, expiry, package manifest, and monotonic counter bindings. The
  distinct result cannot carry a device, principal, human-authority fact, session
  identity, replayed Apple registration object, raw acceptance, or fallback.
- Require installation continuation to fetch a fresh, strict custody-rotation
  challenge over the retained SPKI-pinned origin, bind it to the registered App
  Attest key, call Apple's real `generateAssertion` with the exact server hash,
  and receive the assertion ingress's accepted response before v2 begin/complete.

## [0.8.2] - 2026-08-10

### Added

- Add the distinct v2 restart-recovery begin, presentation, complete and
  accepted schemas and fixed pinned routes. Recovery reuses only the existing
  Secure-Enclave-protected seed envelope and validates the separate
  Thesaurophylax recovery transcript before Face ID signing and host rewrap.
- Select rotation, recovery, or ready exactly once from the fixed pinned
  no-store authority-custody status endpoint when the retained Installation
  continuation is selected. Unknown or unavailable state remains blocked;
  Pistis never falls back between rotation and recovery.

## [0.8.1] - 2026-08-10

### Fixed

- Model incomplete Site Root setup as two explicit phases. The existing
  Installation continuation now opens the installation-bound Monas scanner
  for required v2 authority custody first; only a typed accepted completion
  advances the same record to signed identity enrolment. Legacy local records
  safely default to the custody-required phase.

## [0.8.0] - 2026-08-10

### Added

- Add the attended, purpose-separated v2 first-authority custody rotation to
  the existing pinned Monas App Attest workflow. The iPhone generates a fresh
  recovery seed, retains only a Secure-Enclave-protected AES-GCM envelope,
  signs the exact Thesaurophylax transcript after Face ID, and returns the seed
  only as an ECDH/HKDF/AES-GCM envelope to the presented host key.
- Strictly encode and decode the frozen Monas v2 begin, presentation, complete,
  and accepted schemas on their two fixed no-store routes. Unknown fields,
  noncanonical base64url, stale presentations, transcript substitution,
  device/commitment drift, and correlation replay all fail closed.

## [0.7.10] - 2026-08-10

### Fixed

- Implement ADR 0029's local-address endpoint support as the versioned
  `SiteTrustEndpointIdentityV1` contract in both Rust and PistisCore. DNS,
  canonical IPv4, and canonical bracketed IPv6 origins now share the same
  HTTPS, exact-host, certificate-validity and mandatory non-zero TLS SPKI pin
  rules. This adds no unpinned IP, CA bypass, password or local-authority path.

## [0.7.9] - 2026-08-10

### Fixed

- Give a retained incomplete Site Root Installation an explicit route into the
  existing server-driven GitHub first-device enrolment scanner. The local
  record remains redacted and non-authorising: it never supplies a server,
  TLS pin, invitation, provider credential or authority to that flow.

## [0.7.8] - 2026-08-10

### Fixed

- Keep a verified first-device Site Root ceremony on a truthful completion
  screen. It now routes explicitly to its retained `Setup in progress`
  Installation instead of resetting the Scan tab; the later App Attest/custody
  completion retains its distinct, fully-completed evidence.

## [0.7.7] - 2026-08-10

### Fixed

- Treat the empty `204 No Content` response from the attended initial Monas
  Site Root ceremony as its distinct, successful incomplete-installation
  transition. The normal App Attest bootstrap path remains strict and accepts
  only its exact `200` response.

## [0.7.6] - 2026-08-10

### Added

- Recover an already verified, incomplete Site Root installation from the
  fixed SPKI-pinned Monas authority after an app update. The recovery action
  reads only a matching public Site Root key and a redacted lifecycle record;
  it cannot create identity, session, custody, token, or trusted authority.

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
