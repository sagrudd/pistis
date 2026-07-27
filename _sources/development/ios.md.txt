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

## Design maintenance

Changes to tokens or product presentation must be reconciled with
`../mnemosyne_design_language`; evidence semantics must be reconciled with
`../grammateus`. Do not invent missing dark-mode, native mark, App Icon, or
motion rules inside Pistis. Submit those decisions to the design-language
repository first, then update ADR 0007 and this application.
