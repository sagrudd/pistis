# iOS development

The Pistis iOS source is split into a portable domain package and a native
SwiftUI application:

- `ios/PistisCore` contains deterministic models and state transitions. It has
  no UI, camera, keychain, LocalAuthentication, or public-network dependency.
- `ios/PistisApp` contains the native SwiftUI shell, reviewed design tokens,
  Apple-platform adapters, tests, and Xcode project.

The native shell displays the approved Mnemosyne Biosciences lock-up from the
`mnemosyne_design_language` branding contract. On the Mnemosyne provenance
surface, it is reversed non-destructively to white at render time; retain the
unchanged source asset and do not redraw, crop, or use it as a control.

ADR 0007 is normative for the application architecture, evidence hierarchy,
Keeper boundary, visual language, and delivery claims.

## Portable tests

Run the same package tested by the Linux Jenkins stage:

```sh
swift test --package-path ios/PistisCore
```

The portable suite is deterministic and does not contact GitHub, Google,
Keeper, Apple, or a Pistis server.

The app directly links this local package. For production ceremony changes,
also prove that link and the platform adapters compile:

```sh
xcodebuild -project ios/PistisApp/Pistis.xcodeproj \
  -scheme Pistis -sdk iphonesimulator \
  -destination 'generic/platform=iOS Simulator' \
  CODE_SIGNING_ALLOWED=NO build
```

ADR 0021 forbids unauthenticated trust on first scan. ADR 0029 permits the
distinct first-device scan because the authority signature authenticates the
exact HTTPS origin and full TLS SPKI digest before the user confirms the
independently displayed comparison words. Tests may inject an enrolled record,
but the application obtains durable production trust only from the
authenticated Prosopikon enrolment transaction. For ordinary login only, the
verified signed QR scan is the explicit approval and fresh Face ID authorises
the Secure Enclave signature. Governed approval and denial retain separate
review controls and fresh local authentication; cancellation is not a denial.

## Native validation

Native validation requires full Xcode, not the standalone Apple Command Line
Tools. On a reviewed macOS development or Jenkins host, select the pinned Xcode
version and run:

```sh
xcodebuild \
  -project ios/PistisApp/Pistis.xcodeproj \
  -scheme Pistis \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' \
  CODE_SIGNING_ALLOWED=NO \
  test
```

The project commits the Mnemosyne Biosciences development team and production
App Attest entitlement, but never a signing certificate, provisioning profile,
provider client secret, or provider access token. An authorised owner must use
that team with a provisioned physical iPhone before device, archive, or
TestFlight validation.

### Release identity witness

`ios/PistisApp/pistis-ios-release.json` is the first-party, machine-readable
release identity for the native app. It binds the stable Kanon product ID
`pistis-ios`, the Apple bundle identifier, marketing version and build number
to the exact application target, Xcode project and Info.plist. Debug and
Release must both contain the recorded identity; the native test gate verifies
both configurations and the two file digests independently.

The iOS identity is deliberately separate from the historical Linux
`pistis-agent` crate and package. Recording an already merged physical-device
candidate does not rebuild or renumber that candidate. Any later change to an
identity-bearing Xcode setting, project or Info.plist requires a new iOS app
version/build, refreshed witness digests and a coordinated Kanon release.

### Approved physical build gate

The `Release` configuration is reserved for the approved physical build. It
uses the installed Apple Distribution identity and the reviewed `pistis` Ad
Hoc profile. Debug and test configurations remain automatic so simulator
development does not depend on distribution credentials. The archive helper
checks both inputs and does not allow Xcode to replace the reviewed profile
with a development profile. Before installing a build on the iPhone, run:

```sh
scripts/build-approved-iphone-archive.sh \
  /path/to/Pistis.xcarchive
```

Export the verified archive as an Ad Hoc IPA, and repeat the same artifact
gate against the app extracted from the IPA:

```sh
scripts/export-approved-iphone-ipa.sh \
  /path/to/Pistis.xcarchive \
  /path/to/Pistis-adhoc
```

If an archive has already been produced by the reviewed distribution process,
run the artifact gate directly:

```sh
scripts/verify-approved-iphone-build.sh \
  /path/to/Release-iphoneos/Pistis.app
```

The gate rejects development-signed artifacts, `get-task-allow`, a non-production
App Attest entitlement, an unexpected bundle identifier, or an unexpected Apple
team. A build that fails this check must not be used for a Monas first-device
QR; Monas deliberately accepts production App Attest evidence only.

## Apple App Attest registration

The iOS application configures the Apple production App Attest entitlement
and can prepare exactly `pistis.apple-app-attest-registration.v1` plus the
separate `mnemosyne.pistis.site-trust-app-attest-assertion-ingress.v1`
assertion envelope for a server-issued, one-use Monas ceremony. The fixed current App ID is
`C7A6NQTSY4.org.mnemosynebiosciences.pistis`. It sends the ceremony and Site
Trust Domain identifiers, canonical base64url credential ID, SHA-256 challenge
digest, and Apple attestation object directly to Monas. It does not log or
persist the challenge, attestation object, or any private key; the operating
system owns the private App Attest key. Pistis stores only the opaque Apple key
identifier in a device-only Keychain item.

For custody rotation, Pistis first fetches the fresh server-owned challenge
from the fixed `authority-custody-rotation/v2/assertion-challenge` route over
the already retained HTTPS origin and SPKI pin. It strictly validates the
installation, Site Trust, production App ID, registered key, ceremony, issue
time, expiry, and exact 32-byte client-data hash. It passes that hash unchanged
to `DCAppAttestService.generateAssertion`, posts strict JSON only to
`/v1/pistis/site-trust/app-attest/assertion`, and requires an empty `202
no-store` response before invoking v2 begin/complete. Registration uses its
distinct exact endpoint. Both transports
reject redirects, cookies, cache, generic COSE, browser/QR/free-text input,
and local identity. Registration accepts only an empty ``202 no-store``;
assertion accepts only the exact pinned terminal custody-presentation response
and never exposes a Monas session credential.

The ordinary Site Root submission success response is
``monas.pistis.site-trust-app-attest-bootstrap.v1``. Pistis rejects a coarse
receipt, every missing or additional field, an expired response, non-canonical
base64url, zero or incorrectly sized bootstrap material, and an origin other
than the enrolled Monas authority. The bootstrap is retained only on the call
stack long enough to construct the existing SPKI-pinned assertion transport;
it is never saved, displayed, logged, passed through a browser, or used as a
session credential. The assertion result is a custody presentation only after
Monas has retained its protected server-side session; it is never a browser or
session credential.

### Host-agnostic Site Root composition

The released Pistis binary contains only the reviewed Pistis/App Attest
application identity and the global ``install.mnemosyne.co.uk`` broker
identity. It contains no customer hostname, IP address, TLS certificate, Site
Root key, root generation, or installation identity. The old
``PISTIS_MONAS_SITE_ROOT_*`` build settings and ``Info.plist`` fields are not
part of the release contract.

The attended installation service supplies the deployment-specific facts at
runtime. The host registers a one-use transaction with the fixed broker; the
broker relays a signed host-binding presentation containing the installation
identity, Site Trust Domain, canonical HTTPS origin, TLS trust material,
generation, transaction binding, application identity and short expiry. Pistis
verifies the signature and exact binding before contacting the host, displays
the host identity and trust words, and requires Face ID before creating the
Secure Enclave/App Attest identity. A plain HTTPS URL or an unsigned broker
``state=accepted`` response is never sufficient.

The verified runtime profile is retained per installation in protected local
storage only after the host accepts the signed completion receipt. Multiple
hosts therefore use the same binary and remain separate records; selecting a
host selects its verified profile rather than an operator-entered hostname.
Replays, expiry, changed origin, changed TLS material, changed installation or
transaction, cross-host substitution, and downgrade all fail closed.

For the first Site Root device, the brokered QR is the only supported route.
After explicit review, Face ID creates the separate Secure Enclave Site Root
key. Pistis generates a fresh Apple App Attest key for this exact registration
—Apple keys are attested once only—and retains its opaque identifier only after
genuine Apple attestation succeeds. Pistis then submits only the typed public
registration and genuine App Attest registration through the broker. Monas
returns the one-time delegation bound to that same runtime host profile. The
initial proof establishes Site Trust and custody; the later signed first-device
identity receipt establishes the usable Pistis installation. Neither stage is
represented as complete until its own server-side receipt has been accepted.
An interrupted attempt cannot leave a key that a later registration
accidentally re-attests.

That incomplete Installation now has one explicit next action: it switches to
the existing first-device provider-enrolment scanner. The scanner still
requires a new authority-signed presentation before it contacts Monas. The
redacted local Site Root record never chooses the authority, TLS pin,
invitation, provider identity or credential, and cannot turn setup progress
into a session or enrolment.

After a signed Site Root proof receives the short-lived bootstrap, Pistis
constructs the existing SPKI-pinned App Attest transport. The terminal
assertion response is accepted only as the retained-session custody
presentation. Pistis then performs the existing Face-ID-protected Secure
Enclave rewrap and submits it only through the fixed custody endpoint. The
bootstrap, presentation, rewrap seed, session and assertion are never stored,
shown, or logged.

The bootstrap's canonical ceremony identifier is supplied only as the sealed
server bridge's registration correlation. The Site Trust Domain is read only
from the exact signed canonical delegation bytes and must match them exactly.
The 32-byte bootstrap challenge digest is passed directly to Apple App Attest
registration as the server-owned client-data hash; Pistis must never derive,
replace, or double-hash it.

This entitlement neither enables a Monas route nor claims a production
verification result. Before any route is
enabled, obtain a redacted physical-iPhone interoperability record and satisfy
the offline Apple-root verifier, durable replay store, and reviewed
production-profile gates in Monas #74.

The Rust `pistis-monas` 0.3.0 physical-vector boundary is deliberately
evidence-only. A reviewed in-process adapter must verify a production physical
iPhone against Monas'
`monas.apple-app-attest-verifier-profile.v1`, a pinned Apple trust-anchor
manifest, the organisation App ID, the registered key/counter, and the exact
typed Site Trust fact before Monas atomically retains redacted bindings. The
shipped adapter is unavailable. It never retains the raw attestation object,
challenge, credential, private key, cookie, token, or browser material; it
does not establish Site Trust or a Monas session. Unit fixtures exercise only
the refusal boundary and are never physical evidence.

The opt-in physical registration preparation test remains a capability check
only and must never be used as evidence. Formal #393 evidence requires a
fresh Monas-issued bootstrap, real iPhone assertion, 202-only pinned delivery,
and a redacted retained Monas receipt/reference. It must never copy the raw
assertion, key ID, challenge digest, attestation object, cookie, or session to
a terminal, issue, fixture, or commit.

The native UI suite runs Apple's accessibility audit on onboarding and every
primary tab. It exercises the GitHub-enrolment readiness and fail-closed
scanner states without contacting a provider or enabling an approval. Run the
focused audit with:

```sh
xcodebuild \
  -project ios/PistisApp/Pistis.xcodeproj \
  -scheme Pistis \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' \
  CODE_SIGNING_ALLOWED=NO \
  test \
  -only-testing:PistisUITests/PistisUITests/testPrimarySurfacesPassNativeAccessibilityAudit
```

This automated audit does not replace physical VoiceOver, Dynamic Type,
contrast, reduced-motion, camera, or Face ID review.

The scanner is audited at both the top and bottom scroll positions. Xcode 26.6
reports contrast findings for text partly obscured by a viewport edge; the test
handles only the exact labels obscured at one position after auditing them
unobscured at the other. Xcode 26.6 also reports the standard `About Pistis`
`NavigationLink` label for Dynamic Type despite its scalable semantic `body`
font. Every other finding remains test-failing; broaden neither exception
without a documented Xcode regression and review.

## Review gates

Do not merge a native-platform claim without evidence for the affected gate:

- Swift format/lint and portable core tests;
- simulator build and unit/UI tests using the repository's selected Xcode;
- real-device Secure Enclave and biometry tests;
- shared Rust/iOS canonical encoding and signature fixtures;
- bounded Device Flow polling, cancellation, phishing, substitution, and
  negative tests against a non-production GitHub App;
- VoiceOver, Dynamic Type, contrast, and reduced-motion review;
- archive, signing, privacy manifest, export compliance, and TestFlight
  evidence for distribution work.

The Linux Jenkins stage proves only the portable Swift core. It cannot prove
SwiftUI compilation, camera behaviour, Secure Enclave behaviour, signing, or
TestFlight distribution.

## Current native evidence

On 2026-07-28, Xcode 26.6 built and tested the signing-disabled application on
the iOS 26.5 iPhone 17 Pro simulator:

- the application and iOS-only platform-adapter branches compiled and linked;
- all platform policy tests passed; and
- the functional UI tests and native accessibility audit passed across
  onboarding and all five primary tabs.

This closes the SwiftUI project-creation gate. Simulator evidence does not
close real-device Secure Enclave, camera, physical accessibility, signing,
archive, or TestFlight gates.

## Face ID signing boundary

The production device key is a Secure Enclave P-256 key protected with
`biometryCurrentSet`. Key creation and every signature require Apple's
biometric-only policy to be available and require the evaluated biometric type
to be Face ID. Pistis does not request the device-owner policy, so a passcode
cannot satisfy a signature request; Touch ID is also rejected because the MVP
acceptance profile names a Face ID iPhone.

Private-key lookup is constrained to `kSecAttrTokenIDSecureEnclave`; a
software Keychain key with the same application tag is rejected. The signing
operation itself also rejects simulator execution before querying Keychain, so
the invariant does not depend on callers invoking key creation first.

Cancellation, lockout, changed biometric enrolment, missing hardware, a missing
key, and simulator execution fail closed without producing signature bytes.
Simulator policy tests can check the selection logic, but task PIS-E22-I256 is
not physically qualified until a reviewed iPhone run demonstrates one Face ID
prompt for each requested signature and Jenkins retains the resulting
non-secret evidence for the exact revision.

## QR acquisition boundary

The native scanner uses AVFoundation metadata capture and accepts at most one
2,331-byte ASCII `PISTIS1` value. It installs no photo or sample-buffer output,
retains no camera frame, stops after one result, cancels on backgrounding, and
offers accessible permission, unsupported-code, oversize, and retry states.

Acquisition is not verification. The production coordinator loads only an
authenticated enrolment output from the device-only Keychain, verifies the
exact QR-carried COSE challenge against that enrolled installation key, checks
the audience, external identity, fingerprint, semantics, and time window, and
only then presents the signed request facts. Unknown, expired, revoked, or
substituted installations fail before an approval surface or Face ID prompt.

Approve and deny use the same response path: canonical response encoding,
fresh Face ID through the enrolled Secure Enclave key, an untagged COSE Sign1
envelope bounded to 2 KiB, and HTTPS delivery to an enrolled-host allow-list.
The app polls at most ten times and displays only a terminal authority result;
a timeout or malformed/oversized authority response is a failure, not an
implicit acceptance. Hosts are canonical lower-case ASCII DNS names, redirects
are refused by the URL loading delegate before any signed body can be replayed,
and authority status decoders reject unknown fields.

`AuthenticatedEnrollmentOutput` is the internal hand-off from the reviewed
Prosopikon authority transaction. It atomically binds the authority-issued trust record,
device response context, and lower-case endpoint host allow-list. Do not add a
QR, clipboard, fixture, or arbitrary JSON import path to this hand-off.
Persistence decoding is strict: the complete field set must be present with no
unknown fields, and decoded trust and response-context values must pass their
normal validating initializers again before the Keychain record is usable.

`SystemBrowserEnrollmentCoordinator` retains the previously reviewed,
fail-closed authorisation-code scaffold for a possible future broker profile.
ADR 0025 excludes it from v0.1 and it must not be wired into the application.
The v0.1 Device Flow coordinator must perform the same sole Keychain mutation
only after the exact Prosopikon authority receipt verifies.

The concrete Device Flow and authority exchange are blocked on issues 252 and
318. Do not implement the missing cross-project contract ad hoc in the app.

### Passwordless readiness

The scanner screen reports five independent coarse states: camera permission,
Face ID capability, presence of the namespaced device signing key, presence of
enrolled installation-authority trust, and availability of the accepted
production verifier. Approval is available only if all five are ready.

The readiness surface is diagnostic, not evidence. It never displays a key
identifier, public key, QR content, provider identity, endpoint, or scanned
display value. “Key available” means only that the protected keychain item
exists; it does not authenticate the user, verify a request, or prove that the
key remains usable. Operators should resolve the stated missing capability and
rerun the full ceremony rather than interpreting readiness as acceptance.

## GitHub enrolment boundary

The release build may pin more than one HTTPS origin for the same portable
Monas computer. The current profile pins `https://192.168.1.192:8443` and
`https://192.168.0.193:8443` to the same Site Root identity and TLS policy.
This is a bounded address set, not discovery: QR and follow-up requests may
use either listed address, while every unlisted host remains rejected.
If the signed request's listed address is unreachable, the client may retry
the identical bytes at the other listed address; it never rewrites the signed
payload or creates a new ceremony.

The same bounded policy applies to readiness, custody/status reads, and the
subsequent App Attest session. A reachable HTTP denial, malformed response, or
TLS/trust failure is terminal and is never replayed at the other address.

`Trusted` describes the retained Pistis identity; it does not prove that the
current Monas process still holds Site authority custody. Continuing from a
trusted installation therefore checks the live custody status before entering
the separate DAS replacement-receipt route. If the host requires retained
Site Root recovery, Pistis completes that recovery and returns to the
installation screen. It must not immediately send a DAS request to the
recovery-only listener. When custody was already ready, the existing protected
DAS continuation remains available.

The same live check is mandatory for a setup installation whose local phase
already says identity enrolment is required. A host process restart can remove
the live signer without invalidating that retained local phase. The identity
continuation action therefore checks authority custody, completes retained App
Attest and Face ID recovery when required, and opens the signed provider
presentation only after the signer is live. Local phase completion is never
treated as current host readiness.

The Identities screen exposes only the accepted server-driven first-device
surface. It scans and verifies the ADR 0029 version-4 presentation before
network use. The app displays the verified installation and enables **Begin
secure enrolment** only after the authority signature, application digest,
canonical HTTPS origin and complete TLS SPKI pin verify. It does not contact
the host or create the Face-ID-protected Secure Enclave key before that
attended action. The derived words remain optional operator diagnostics, not
authority input.

The resulting ephemeral URL session accepts only the exact signed host and
port, refuses redirects, extracts the leaf certificate's exact DER
SubjectPublicKeyInfo, and compares its complete SHA-256 digest with the signed
pin. It evaluates TLS server policy, hostname, and certificate validity with
the leaf as an app-scoped anchor. A mismatch cancels the authentication
challenge; there is no platform-trust fallback. `NSAllowsLocalNetworking`
enables local HTTPS without enabling arbitrary loads.

The words are a 33-bit human comparison checksum, not authentication
material. The full 256-bit pin and authority signature remain mandatory. The
app does not install a root certificate, configuration profile, global trust
setting, or Safari trust. A different SPKI requires a new attended ceremony;
a renewed certificate with the same SPKI remains valid while its normal TLS
checks pass.

After host confirmation, the app creates the Face-ID-protected Secure Enclave
key and calls only the fixed begin/status/cancel/confirm paths beneath the
signed HTTPS origin.
The phone opens GitHub solely to let the user enter the displayed code. It
never calls GitHub token or user APIs and has no representation for an adapter
handle, provider token, email address, or caller-supplied subject.

Begin returns the public prompt plus a one-use 32-byte polling capability.
Only verified status returns the canonical numeric subject, policy generation,
fresh 32-byte authority challenge and exclusive challenge expiry. iOS binds
those exact values, the invitation/principal/tenant/installation tuple, App
configuration digest, and Secure Enclave key in the canonical ADR 0025 COSE.
Provider success alone is not enrolment.

The accepted bundle commits distinct initial-invitation and mobile-receipt
descriptors. Swift verifies the presentation only with the former and the
receipt only with the latter, re-verifies the exact ADR 0025 device
registration, and then creates the Keychain record once. Exact replay is
idempotent; no code path replaces a different record. Verified GitHub facts
are rendered before a separate explicit Face ID confirmation action.

## Bounded iOS onboarding diagnostics

The iOS target has a client-side diagnostic outbox contract in
`OnboardingEventJournal.swift`. It is deliberately not an analytics SDK or a
Monas authority record. In the protected fresh-device route, the QR supplies
the server-issued 32-byte correlation capability and
`MonasSiteRootGenesisBrokerTransport` sends each event to the fixed
`install.mnemosyne.co.uk` diagnostics path over the existing ephemeral,
no-cookie, no-cache HTTPS session. Upload is best effort and never gates key
creation, Face ID, App Attest, proof submission or installation. The outbox
retains at most 64 closed, redacted events and 32 KiB of JSON, and purges
entries after 48 hours. A duplicate event ID is idempotent only when the
complete event is identical; an attempt to replace an event is rejected.

The active install window displays the broker's redacted projection on every
handoff poll. It is the immediate operator surface: each line identifies the
closed challenge stage, start/response outcome, elapsed time, HTTP status when
known, and a reviewed error code. It never displays QR contents, proof bytes,
email addresses, URLs, App Attest evidence, device keys, cookies or tokens.

Emit events at these exact boundaries:

1. `SiteRootDelegationCoordinator.accept`: after the strict Site Root or
   broker presentation parser accepts the QR, emit `qr_validated`. A parser
   failure emits only a coarse failed event. `QRScannerAdapter` and
   `ScanView.handleScan` must not retain or journal camera frames, QR text, or
   routing substrings.
2. `SiteRootDelegationCoordinator.approve` and its typed completion helpers:
   emit one `stage_entered` event when the Secure Enclave key, App Attest,
   bounded Monas delegation wait, Site Root proof, or later App Attest stage
   begins. Emit a separate response event for each completed transport
   boundary; the fixed broker records its known `202` registration/proof and
   `200` delegation responses. Emit one terminal event beside the existing
   local-history write in `recordCompletion` or `recordFailure`; use a coarse
   failure code, never the `safeUserMessage` text.
3. `FirstDeviceEnrolmentFlow.handleScan`: emit `qr_validated` only after
   `FirstDevicePresentationV4.verify` succeeds. Provider verification and
   device-registration transitions use the same closed stage values, with one
   terminal event after the signed receipt is stored or the operation fails.
4. `LocalHistoryRepository.record` remains a UI projection and is not an upload
   source. Its existing redacted `HistoryEvent` values must not be expanded with
   raw QR, invitation, provider, signature, App Attest, cookie, or token data.
5. `MonasSiteRootDelegationTransport` remains a typed protocol transport. It
   must not receive the journal, log request/response bodies, or emit events
   from polling attempts. The coordinator records only the bounded stage
   surrounding a transport call; the broker transport uploads the resulting
   redacted event after it has been appended locally.

`OnboardingEventUploadClient` remains available for future batch retry and
tests, but the protected Site Root coordinator uses the per-event broker
transport so that the active install window receives progress immediately.
The server-issued correlation is transient request state only: it is not
written to the journal, local history, QR presentation, URL query, crash
metadata or logs. The broker transport uses the already reviewed fixed origin,
ephemeral no-cookie/no-cache `URLSession`, redirect rejection, bounded
request/response sizes and an exact fixed path. A successful response can
acknowledge only the submitted sequence; failed delivery leaves the local
redacted event available until the 48-hour purge boundary.

The event body itself contains only closed enums, a local timestamp, monotonic
elapsed duration, a random event/attempt identifier, an optional HTTP status,
and a SHA-256 digest of an opaque reference. It contains no endpoint, host, QR,
canonical payload, signature, private key, biometric, provider code/token,
cookie or session capability.

## Design maintenance

Changes to tokens or product presentation must be reconciled with
`../mnemosyne_design_language`; evidence semantics must be reconciled with
`../grammateus`. Do not invent missing dark-mode, native mark, App Icon, or
motion rules inside Pistis. Submit those decisions to the design-language
repository first, then update ADR 0007 and this application.
