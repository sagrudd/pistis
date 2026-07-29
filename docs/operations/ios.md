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

## Production ceremony operation

Complete GitHub enrolment in the iOS system browser before scanning. A
successful authenticated broker callback must install one
`AuthenticatedEnrollmentOutput`; operators must not sideload a trust record or
copy a key from a QR code. The record is stored as
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, is not synchronizable, and is
removed on explicit revocation. Replacement enrolment overwrites the complete
record atomically.

Until issue 318 lands across Prosopikon and Monas, the production broker
implementation remains unavailable and enrolment must fail before Keychain
mutation. A development fixture, copied JSON response, bare authority key, or
TLS success is not an acceptable substitute for the signed authority receipt
and its authenticated bootstrap proof.

On the Scan tab, all five readiness rows must be ready. Scan the Monas
`PISTIS1` version-2 QR and compare the displayed audience, installation, local
user, external-identity identifier, installation fingerprint, expiry, and
route with the initiating browser. Choose Approve or Deny; both choices must
produce a fresh Face ID prompt. Success is only the terminal state returned by
the installation authority. A pending timeout, delivery error, unknown host,
or malformed authority response must not be described as acceptance.

For MVP transport, the challenge supplies one HTTPS response endpoint and may
supply a second HTTPS status endpoint. Both hosts must already appear in the
authenticated enrolment allow-list. Request and response bodies are limited to
2 KiB; redirects, credentials in URLs, fragments, non-HTTPS URLs, and unknown
hosts fail closed. Allow-list and challenge hosts use canonical lower-case
ASCII DNS form without an empty label or trailing dot. URLSession is configured
to refuse a redirect before it can replay a signed POST body; observing and
rejecting only the final response URL is not sufficient.

Keychain reads are untrusted persistence input. The app rejects unknown or
missing top-level enrolment fields and reconstructs the trust record and device
response context through their bounded validating initializers before use. A
malformed or stale record disables the ceremony rather than being partially
accepted. Authority status JSON similarly rejects unknown fields.

## Physical interoperability record

Use the
[iOS interoperability evidence template](templates/ios-interoperability-evidence.md)
for the physical Secure Enclave and Face ID ceremony. The completed record
must be bound to the exact source revision and independently verified by Rust
before Jenkins retains it. A simulator run, an unverified signature, or a
filled-in template is not physical-device acceptance evidence.

The Xcode test target includes a deliberately test-only ceremony harness. It
loads the pinned copy of `fixtures/protocol-v1/cose/signing-input.hex`, checks
its SHA-256 digest, and invokes `SecureEnclaveSigner.interoperabilityProbe`.
It attaches only the compressed public key, derived `KeyId`, exact signed
bytes and SHA-256 digest, and raw low-S ES256 signature. It never serializes a
private key, biometric information, device identifier, Apple credential, or
production envelope. The simulator test proves this path fails closed.

On a reviewed, signed **Face ID-capable** physical-device test setup, select
the trusted device identifier and run the ceremony explicitly (normal tests
skip it). The harness rejects Touch ID and unavailable biometry; neither is
Face ID acceptance evidence. The runner passes the opt-in flag through a
generated local `.xctestrun` configuration because app-hosted physical XCTest
processes do not inherit the invoking shell environment:

```sh
PISTIS_INTEROPERABILITY_RESULT_BUNDLE=/absolute/path/to/physical-ceremony.xcresult \
  scripts/run-ios-physical-interoperability <trusted-device-udid>
```

The runner does not change a shared scheme or add a permanent enabled test
configuration. Do not add this environment variable to the normal scheme or
use the physical ceremony in CI.

If an uncommitted local development-team setting is necessary for a personal
Apple account, pass its non-secret team identifier only at invocation time:

```sh
PISTIS_DEVELOPMENT_TEAM=<local-development-team-id> \
  scripts/run-ios-physical-interoperability <trusted-device-udid>
```

This override is intentionally not a substitute for checked, release-team
signing configuration and does not write a team identifier into the project.

Retrieve the XCTest attachment, independently verify it against the Rust
verifier, and complete the evidence template. The test-only Secure Enclave
key namespace must not be registered or used for an authentication session.

Run this command from the repository checkout, replacing the placeholder with
the saved XCTest JSON attachment. It accepts exactly one file, fails closed on
any read, schema, encoding, binding, or signature failure, and prints only the
result and the derived `KeyId`; it does not print the attachment, public key,
signature, or file path:

```sh
cargo run --locked -p pistis-cose \
  --example verify_device_interoperability_record -- \
  /absolute/path/to/device-interoperability-record.json
```

Successful output has this exact form:

```text
verified key_id=key_<lowercase-hex>
```

### EPIC-18 retained physical observation

The redacted physical observation for the EPIC-18 ceremony is retained as
[`ios-physical-interoperability-record.json`](../../fixtures/protocol-v1/cose/ios-physical-interoperability-record.json).
It was produced from source revision
`e58d0a21edb36af85e01d9bfa137136b673456d5` using Xcode 26.6 (17F113) on
an iPhone 14 Pro Max running iOS 26.6. The test-only key reported Secure
Enclave availability, required a fresh Face ID prompt for signing, and emitted
the fixed-width, low-S ES256 record verified by the Rust command above.

The observation is limited to EPIC-18 public-key encoding and Face ID-gated
signature interoperability. It does not assert TestFlight distribution, QR
authentication, a browser route, CLI approval, cancellation behaviour, a
second prompt, or biometry-set invalidation; those are separate MVP gates.
Its SHA-256 digest is
`2c2523a88bc49ce94f0f4aa62235d44684f374f78fd80344ec5a3f95d8509349`.
The authoritative Jenkins Expedition retains the exact observation and
verification result as a dossier artifact; see the PR acceptance record for
the Expedition identifier.
