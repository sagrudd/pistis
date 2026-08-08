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
authenticated Prosopikon enrolment transaction. Approval and denial both
require fresh local authentication and a Secure Enclave signature;
cancellation is not a denial.

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

For an assertion, the only accepted input is the verified, server-issued
Monas ceremony bootstrap: exact HTTPS origin and SPKI SHA-256, a non-zero
16-byte ceremony identifier, and a non-zero 32-byte challenge digest. Pistis
forms `mnemosyne.pistis.site-trust-app-attest-client-data.v1\\0 || digest`,
hashes it with SHA-256, calls `DCAppAttestService.generateAssertion`, then
posts strict JSON only to `/v1/pistis/site-trust/app-attest/assertion` on the
pinned origin. Registration uses its distinct exact endpoint. Both transports
reject redirects, cookies, cache, non-202 responses, response bodies, generic
COSE, browser/QR/free-text input, and local identity; HTTP acceptance does not
claim a completed Monas session.

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

The Identities screen exposes only the accepted server-driven first-device
surface. It scans and verifies the ADR 0029 version-4 presentation before
network use. The app then asks “Do you really trust this host?” and requires
the three words displayed independently beside the CLI QR to be typed into
three separate fields. It does not create a URL session, contact the host, or
create the Face-ID-protected Secure Enclave key until those words match and
the user selects **Trust this host**.

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

## Design maintenance

Changes to tokens or product presentation must be reconciled with
`../mnemosyne_design_language`; evidence semantics must be reconciled with
`../grammateus`. Do not invent missing dark-mode, native mark, App Icon, or
motion rules inside Pistis. Submit those decisions to the design-language
repository first, then update ADR 0007 and this application.
