# Pistis for iOS

This directory contains the EPIC-7 iOS source foundation:

- `PistisCore` is a platform-neutral Swift package containing deterministic
  identity, trust, approval, enrolment, and local-history behavior.
- `PistisApp` is the native SwiftUI application, design system, Apple-platform
  adapters, privacy metadata, unit tests, and UI tests.

Read [ADR 0007](../docs/adr/0007-ios-reference-application.md) before changing
security, provider authentication, protocol, or product presentation.

Portable tests:

```sh
swift test --package-path ios/PistisCore
```

Native tests require full Xcode and an iOS simulator. See
`docs/development/ios.md`. The project intentionally contains no development
team, credential, private key, provisioning profile, provider client secret,
or provider access token.

Keeper participation is system-mediated: GitHub asks iOS for its passkey and
iOS may offer Keeper. Pistis never reads Keeper vault contents or passkeys.

The MVP signing key is Secure Enclave-backed and bound to the current Face ID
set. Every signature invokes Apple's biometric-only policy and additionally
rejects non-Face-ID biometric hardware; there is no device-passcode fallback.
