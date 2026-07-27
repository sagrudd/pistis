# iOS application operations

This page describes the intended EPIC-7 reference application and the
prerequisites that remain external to the repository. It is not evidence that
a signed or TestFlight build exists.

## Keeper-assisted GitHub authentication

Pistis opens GitHub in an Apple system authentication session. If Keeper is
enabled under iOS Passwords, AutoFill, and Passkeys and contains the user's
GitHub passkey, iOS may offer Keeper when GitHub requests that passkey. Keeper
and iOS complete the assertion for `github.com`; Pistis receives only the
OAuth callback.

Pistis never asks Keeper for a vault item, passkey, private key, password, or
token. It cannot use a GitHub passkey to sign a Pistis approval. The Pistis
device signing key is separate and non-exportable in the Secure Enclave.

The operator must configure the trusted broker with the provider registration
and exact callback allow-list. Never put a GitHub or Google client secret in
the application bundle. Do not retain provider access tokens on the device.

## Apple distribution prerequisites

An authorised Apple-team owner must provide and review:

1. active Apple Developer Program and App Store Connect access;
2. the final bundle identifier and application record;
3. signing certificate, provisioning profile, and necessary entitlements;
4. privacy declarations, export-compliance answers, and support metadata;
5. an approved App Icon and store presentation from the design-language
   authority;
6. internal tester groups and a non-production end-to-end environment.

The owner must configure these through Xcode and App Store Connect. Secrets,
certificates, private keys, session cookies, and provisioning credentials must
not be committed to Pistis or copied into issue comments.

## Release evidence

Before closing signing or TestFlight work, retain non-secret evidence of:

- the source revision and pinned Xcode version;
- successful clean archive and export;
- selected Apple team, bundle identifier, profile name, and certificate
  fingerprint (never its private key);
- privacy-manifest and entitlement review;
- uploaded build number and processing result;
- internal TestFlight installation and end-to-end acceptance results;
- crash-symbol retention and rollback/revocation procedure.

App reinstall, missing keychain state, or changed enrolled biometrics creates
an explicit unavailable-key state. The app must require new-device enrolment;
it must never silently substitute a new key under the old device identity.

## Current interoperability boundary

Camera capture and the EPIC-6 reference flow can be exercised locally. ADR
0018 and the shared fixtures define the production COSE profile; portable
fixture conformance is not evidence of physical Secure Enclave or Face ID
behavior. No release may describe the detached reference envelope as the
production mobile protocol.

## Physical interoperability record

Use the
[iOS interoperability evidence template](templates/ios-interoperability-evidence.md)
for the physical Secure Enclave and Face ID ceremony. The completed record
must be bound to the exact source revision and independently verified by Rust
before Jenkins retains it. A simulator run, an unverified signature, or a
filled-in template is not physical-device acceptance evidence.
