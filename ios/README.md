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

The Scan tab includes a non-secret passwordless-readiness panel. It reports
camera, Face ID, device-key, enrolled-authority, and production-verifier
availability separately. These are coarse diagnostics only; every gate must be
ready before approval can be enabled.

## Production ceremony boundary

The app target links the local `PistisCore` package. Its scanner accepts only
the bounded ADR 0021 `PISTIS1` version-2 challenge frame. The core decodes the
exact COSE envelope and ADR 0019 payload, selects a previously enrolled trust
record, and verifies the enrolled key identifier, P-256 signature,
fingerprint, audience, external identity, and validity window before returning
facts that may be displayed.

Responses for both `approved` and `denied` use the same fresh Face ID and
Secure Enclave signing path. Cancel is the only unsigned dismissal. Direct
HTTPS delivery accepts a signed endpoint hint only when its host also appears
in the enrolled allow-list, and keeps local signing, transfer, and the
server's authoritative result as separate states.

The repository contains no development trust record. Until authenticated host
enrolment installs an authority-verified record and identity binding, a
structurally valid scan reports that enrolment is required and displays no
challenge facts or decision controls. Never add fixture keys,
trust-on-first-scan, or simulator signing fallbacks to bypass this boundary.
