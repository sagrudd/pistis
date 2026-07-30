# Android application operations

This page records the intended M11 operational boundary. Source, debug builds,
or emulator results are not evidence of Play distribution or hardware-backed
assurance.

## Future Android Keeper-assisted GitHub authentication

Android is outside the v0.1 release baseline. The broker/PKCE text below
describes an earlier future profile and is not an active v0.1 deployment
procedure. Any Android enrolment implementation must adopt ADR 0025 Device Flow
or receive a separate accepted profile before activation.

Pistis opens GitHub in the external system browser with fresh PKCE and state.
On supported Android versions, GitHub may ask the browser for its
`github.com` passkey and Android may offer Keeper when the user enabled it as a
credential provider.

Keeper and the browser complete the passkey assertion. Pistis receives only
the OAuth callback. Pistis never reads a Keeper vault item, passkey, password,
private key, or provider token and never uses a GitHub credential to sign a
Pistis approval.

Provider code exchange belongs to the trusted Pistis broker. The Android
package contains no GitHub or Google client secret and retains no provider
access token.

## Device security

The signing key is installation-bound and non-exportable through application
functionality. A missing or invalidated key, application reinstall, changed
device-security configuration, or public-key mismatch requires explicit
new-device enrolment.

StrongBox, trusted-environment, software, and unknown are reported as local
capabilities. They are not called remotely verified attestation. A
StrongBox-unavailable result never silently becomes a trusted-environment key
under the same assurance claim.

Every signing operation requires a fresh approved ceremony and
BiometricPrompt-bound cryptographic operation. Cancellation, lockout,
backgrounding, process death, mismatched CryptoObject, or changed request
produces no signature.

## Play prerequisites

An authorised owner must provide:

1. a verified Mnemosyne Biosciences Play developer account;
2. the permanent application ID `org.mnemosynebiosciences.pistis`;
3. Play App Signing and governed upload-key custody;
4. app record, contact details, privacy policy, store assets, content rating,
   app-access and advertising declarations, and Data Safety responses;
5. internal and closed tester groups; and
6. a non-production broker and installation acceptance environment.

Signing keys, service-account credentials, browser sessions, and Play tokens
must not be committed or placed in issue comments. PR jobs must never receive
them.

Before closing distribution work, retain non-secret evidence for the exact
source revision, tool/container versions, application ID and version,
permissions and privacy review, signed AAB checksum, Play processing result,
test track and tester scope, installation result, acceptance results, mapping
files, SBOM/provenance, and upload-key recovery procedure.

## Current interoperability boundary

Camera and detached reference-envelope behaviour may be demonstrated locally.
Production QR authentication remains blocked until a COSE profile and shared
Rust/iOS/Android conformance fixtures are accepted. Local discovery is not
authority; all discovered endpoints still require reviewed transport and
cryptographic verification.
