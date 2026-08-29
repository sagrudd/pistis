# iOS application operations

This page describes the intended EPIC-7 reference application and the
prerequisites that remain external to the repository. It is not evidence that
a signed or TestFlight build exists.

## Keeper-assisted GitHub authentication

Pistis opens the GitHub Device Flow verification URI in an Apple system
authentication session. If Keeper is enabled under iOS Passwords, AutoFill,
and Passkeys and contains the user's GitHub passkey, iOS may offer Keeper when
GitHub requests that passkey. Keeper and iOS complete the assertion for
`github.com`; Pistis receives no passkey or callback credential.

Pistis never asks Keeper for a vault item, passkey, private key, password, or
token. It cannot use a GitHub passkey to sign a Pistis approval. The Pistis
device signing key is separate and non-exportable in the Secure Enclave.

## iPhone-mediated custody rewrap

The iOS 0.7.0 source includes the client-side cryptographic foundation and
strict terminal-response consumer for the accepted Thesaurophylax
iPhone-mediated custody rewrap profile. It is not a live custody transport or
a readiness claim.

After a future fixed authority has verified a retained App Attest-backed
Pistis session, it may construct one typed, protected presentation containing
the exact Site Trust Domain, custody generation, active Site Root device key,
current encrypted-record digest, one-use delegation serial and fresh host
ECDH public key. Pistis then requires Face ID for the detached ES256 proof and
again for each Secure Enclave ECDH operation. It decrypts the current record
only in transient memory and immediately re-encrypts the 32-byte custody seed
to the fresh host key using the selected ECDH/HKDF/AES-256-GCM profile.

ADR 0035 permits one decoder and one transport only: Monas's terminal response
to the already SPKI-pinned App Attest assertion ingress, followed by the exact
fixed Monas custody-submission endpoint. Pistis does not accept QR, browser
state, cookie, bearer token, CLI, local file, local identity, password, PAM,
user input, or an arbitrary HTTPS endpoint as custody authority. Monas must
still mount the retained-session terminal response and bind the submission to
its fixed Thesaurophylax peer before the operation can be activated or an
iPhone interaction requested.

The operator configures the reviewed GitHub App public client identifier and
exact ADR 0025 endpoint profile. Never put a GitHub or Google client secret in
the application bundle. Device codes and provider access tokens are transient
and must be erased on every terminal path.

### Current GitHub enrolment configuration gap

ADR 0025 accepts GitHub App Device Flow and supersedes the callback, PKCE, and
broker transport requirements of ADRs 0003, 0007, 0008, and 0023 for v0.1.

For the accepted v0.1 design, an operator must:

1. use the reviewed organisation-owned GitHub App with Device Flow enabled;
2. request no scopes and retain no provider token;
3. expose only its non-secret public client ID as `PistisGitHubClientID` in
   reviewed iOS build configuration; the v0.1 build accepts only
   `Iv23lievHWZTGyot0BXa`;
4. verify the exact device-code, access-token, and authenticated-user
   endpoints, set the reviewed `PistisGitHubAPIVersion`, and set the 64-digit
   hexadecimal `PistisGitHubAppConfigurationDigest`;
5. keep polling bounded by GitHub's interval, expiry, and error semantics;
6. verify Prosopikon atomically binds the numeric GitHub account ID, invitation,
   device key, and signed receipt; and
7. run synthetic phishing, substitution, expiry, denial, and rate-limit tests
   before a live account ceremony.

The dependency-injected iOS provider client and coordinator implement the
bounded GitHub wire flow through local numeric-subject retrieval. They do not
persist a device code, access token, refresh token, provider response, or
authenticated trust record. The development application contains the three
reviewed public configuration keys and wires the coordinator to the
Identities screen. It labels the successful result as identity verification,
not authority enrolment. The exact canonical public configuration record is
``fixtures/github-app-configuration-v1.json`` and its SHA-256 is compiled as
``PistisGitHubAppConfigurationDigest``.

Local `/user` validation proves what the phone observed over its GitHub TLS
connection. It does not, by itself, give Prosopikon an authority-verifiable
provider assertion: the proposed device key is not trusted before enrolment.
The remaining cross-project design must identify a trusted issuer for ADR
0025's one-use verified capability without sending the GitHub bearer token to
Monas or Prosopikon. Until that issuer, the signed binding, atomic commit, and
receipt verification exist, the app keeps enrolment disabled and performs no
Keychain mutation.

The requested address `stephen@mnemosyne.co.uk` is a Prosopikon principal and
operator acceptance value, not the GitHub stable identity. ADR 0003 binds
GitHub's numeric account ID. An email claim or mutable GitHub login must not be
used to prove or replace that subject.

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
behaviour. No release may describe the detached reference envelope as the
production mobile protocol.

## Production ceremony operation

Complete GitHub enrolment through the foreground Device Flow before scanning.
The verified Prosopikon authority transaction must install one
`AuthenticatedEnrollmentOutput`; operators must not sideload a trust record
or copy a key from a QR code. The record is stored as
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, is not synchronizable, and is
removed on explicit revocation. Replacement enrolment overwrites the complete
record atomically.

Until issues 252 and 318 land across Pistis, Prosopikon, and Monas, the
production Device Flow remains unavailable and enrolment must fail before
Keychain mutation. A development fixture, copied JSON response, bare authority
key, provider poll success, or TLS success is not an acceptable substitute for
the signed authority receipt and its authenticated bootstrap proof.

After initial onboarding, Pistis opens on Scan. For an ordinary Monas
`PISTIS1` login, scanning a challenge that verifies against the selected
enrolled installation is the explicit login decision. Pistis checks live
authority custody in the same task, performs an exact App Attest and
Face-ID-attended continuation when required, and then requests fresh Face ID
for the login signature. There is no separate **Approve** or successful
**Done** control. Authoritative completion returns to Identities; selecting
Scan again starts a fresh camera session without restarting Pistis.

This direct path is restricted to the signed `authenticate-session` action.
Enrolment, Site authority, custody import, destructive, privilege-changing and
other governed requests still display their evidence and require a separate
explicit application-level decision. Success remains only the terminal state
returned by the installation authority. A pending timeout, custody failure,
delivery error, unknown host, or malformed authority response must remain
visible and must not be described as acceptance.

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

## Automated accessibility audit

The signing-disabled simulator suite also runs Apple's native accessibility
audit across onboarding and every primary tab. That repeatable gate requires
no live account or provider network. It supplements rather than replaces
physical VoiceOver, Dynamic Type, contrast, reduced-motion, camera, and Face ID
acceptance.

## Physical interoperability record

Use the
[iOS interoperability evidence template](templates/ios-interoperability-evidence.md)
for the physical Secure Enclave and Face ID ceremony. The completed record
must be bound to the exact source revision and independently verified by Rust
before Jenkins retains it. A simulator run, an unverified signature, or a
filled-in template is not physical-device acceptance evidence.

For the Site Trust App Attest gate, retain the resulting redacted vector only
through Monas' atomic `pistis-monas` 0.3.0 retention port after the reviewed
production Apple verifier has checked the physical iPhone, pinned Apple trust
bundle, organisation App ID, registered key/counter, and exact Site Trust
fact. The current shipped adapter is unavailable and must not be bypassed with
a simulator, fixture, browser, local account, PAM identity, CLI, or operating
system identity. The retained record contains only typed identifiers, digests,
reviewed verifier/trust-manifest identity, application identifier, and time;
it contains no raw Apple object, challenge, credential, token, cookie, key, or
device secret.

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
`b8802b44f02ba0321803b76f3a12fe7d6c684ae696c476f24a418f575f1d9f71`.
The authoritative Jenkins Expedition retains the exact observation and
verification result as a dossier artefact; see the PR acceptance record for
the Expedition identifier.
