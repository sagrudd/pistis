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

ADR 0021 forbids trust-on-first-scan. Tests may inject an enrolled record, but
the application obtains production trust only from the authenticated
Prosopikon enrolment transaction. Approval and denial both require fresh local
authentication and a Secure Enclave signature; cancellation is not a denial.

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

The project does not contain a development-team identifier, signing
certificate, provisioning profile, provider client secret, or provider access
token. An authorised owner must select the Mnemosyne Biosciences Apple
Developer team and register the final bundle identifier before device,
archive, or TestFlight validation.

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
SwiftUI compilation, camera behavior, Secure Enclave behavior, signing, or
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
fail-closed authorization-code scaffold for a possible future broker profile.
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
surface. It scans and verifies the ADR 0028 version-3 presentation before
network use, creates the Face-ID-protected Secure Enclave key, and calls only
the fixed begin/status/cancel/confirm paths beneath the signed HTTPS origin.
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
