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

## Review gates

Do not merge a native-platform claim without evidence for the affected gate:

- Swift format/lint and portable core tests;
- simulator build and unit/UI tests using the repository's selected Xcode;
- real-device Secure Enclave and biometry tests;
- shared Rust/iOS canonical encoding and signature fixtures;
- OAuth callback, cancellation, and negative tests against a non-production
  broker;
- VoiceOver, Dynamic Type, contrast, and reduced-motion review;
- archive, signing, privacy manifest, export compliance, and TestFlight
  evidence for distribution work.

The Linux Jenkins stage proves only the portable Swift core. It cannot prove
SwiftUI compilation, camera behavior, Secure Enclave behavior, signing, or
TestFlight distribution.

## Current native evidence

On 2026-07-24, Xcode 26.6 built and tested the signing-disabled application on
the iOS 26.5 iPhone 17 Pro simulator:

- the application and iOS-only platform-adapter branches compiled and linked;
- all eight platform policy tests passed; and
- both UI tests passed, covering primary navigation and the approval evidence
  presentation.

This closes the SwiftUI project-creation gate. Simulator evidence does not
close real-device Secure Enclave, camera, accessibility, signing, archive, or
TestFlight gates.

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

Acquisition is not verification. Until proposed ADR 0021 is reviewed and the
app has an enrolled installation verification key, a captured value is
discarded and the app does not present an approval or invoke Face ID. This is a
deliberate fail-closed state, not a complete authentication ceremony.

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

The Identities screen contains a compiled but disabled GitHub enrolment port.
It validates only non-secret public-client configuration, models a
credential-free broker result containing the numeric GitHub subject and a
bounded display login, and explains which authority ports are absent. It does
not start the browser, contact the broker, persist a token, or create a
binding.

ADR 0003 accepts authorization-code PKCE through a confidential broker and
requires another ADR before GitHub device flow. Until that decision and the
broker/Prosopikon response contracts are reviewed, the disabled state is the
only production-honest behavior.

## Design maintenance

Changes to tokens or product presentation must be reconciled with
`../mnemosyne_design_language`; evidence semantics must be reconciled with
`../grammateus`. Do not invent missing dark-mode, native mark, App Icon, or
motion rules inside Pistis. Submit those decisions to the design-language
repository first, then update ADR 0007 and this application.
