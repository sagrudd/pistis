# ADR 0008: Android reference application

- Status: Accepted
- Date: 2026-07-24
- Owners: Android, security, protocol, design, and release engineering

## Context

Pistis requires an Android implementation with the same ceremonies, evidence
semantics, and claim discipline as the iOS reference design. Android hardware,
biometric, browser, camera, background-execution, and distribution behaviour
differs materially from iOS and must be represented explicitly.

Milestone M11 requires a Compose application, Android Keystore signing,
BiometricPrompt, provider enrolment, QR and local-network transport, an
assurance policy, a device matrix, and Play distribution. ADR 0006 still
requires a separately accepted COSE profile and shared fixtures before either
mobile platform can claim production QR interoperability.

Three pre-implementation reviews covered Android security, Mnemosyne and
Grammateus design adaptation, and build/release feasibility.

## Decision

### Product and visual language

Android preserves the five primary destinations defined for iOS: Identities,
Installations, Scan, History, and Settings. Compact layouts use a five-item
navigation bar; expanded layouts may use a navigation rail without adding a
dashboard. Approval, pairing, provider enrolment, response QR, diagnostics,
and security status are scoped child tasks.

The application follows Grammateus's evidence hierarchy. Human decision,
local-authentication result, signing result, transfer, and server verification
are independent facts. Local history is this device's observation, not
authoritative server audit evidence.

Compose uses the reviewed Mnemosyne semantic tokens:

- ink `#111111`, canvas `#F6F7F5`, raised `#FFFFFF`;
- provenance green `#1C2B0B`, mark light `#C7BFA8`, mark dark `#4F5C29`;
- action `#0F6B78`, pressed action `#0B5964`;
- border `#D9E0E3`, success `#28622B`, warning `#6F5410`, danger `#8A3C25`;
- on-brand `#FFFFFF`, spacing 4/8/12/16/24/32 dp, and radii 4/8/12 dp.

Material dynamic colour and dark appearance are disabled until reviewed
Mnemosyne palettes exist. Android system typography is used initially. The
partial mark is reserved for restrained onboarding or About provenance and is
not a scanner reticle, spinner, card decoration, or generic status symbol.

Status is words-first; colour and icon are supplementary. Controls provide at
least 48 dp touch targets, scalable text, deliberate TalkBack traversal and
descriptions, selectable grouped fingerprints, nonvisual camera state, and
reduced-motion behaviour.

### Architecture and dependency direction

The source is a hierarchical Gradle project:

- `core:model` owns validated domain values;
- `core:ceremony` owns deterministic state transitions;
- `core:evidence` owns informational local evidence;
- `app` owns Compose presentation and composition;
- platform adapters own Keystore/biometrics, providers, QR, discovery, and
  storage as their implementation slices become reviewable.

Pure modules depend only inward. Compose and ViewModels do not handle private
key bytes, provider tokens, canonical encoding, or trust decisions. Clock,
entropy, persistence, browser, camera, signing, discovery, and transport sit
behind narrow interfaces.

The initial reviewed build baseline is JDK 17, Android Gradle Plugin 9.3.0,
Gradle 9.5.0, Build Tools 36, target API 36, and Compose BOM 2026.06.00. The
minimum API is 31 so security-level reporting and authenticator combinations
have consistent semantics. Versions are exact; dynamic versions and project
repositories are rejected. The Gradle wrapper distribution checksum,
dependency locks, and dependency-verification metadata are retained.

Dependency additions require security/maintenance review. CameraX and bundled
ML Kit barcode scanning are the preferred QR boundary; AppAuth or direct
Custom Tabs support requires a focused provider-adapter review; Room and any
encrypted-storage dependency require a persistence ADR. No crash-reporting or
analytics SDK is introduced by the source foundation.

### Signing key

The device signing key is a non-exportable P-256 key created through
`AndroidKeyStore` using `PURPOSE_SIGN`, `secp256r1`, and SHA-256. Key creation
requires user authentication. The application attempts StrongBox only when
policy requests it. `StrongBoxUnavailableException` becomes an explicit
outcome; a separate TEE attempt requires an explicit policy/user decision and
must not reuse the StrongBox assurance claim.

Every sign operation creates a fresh `SHA256withECDSA` Signature initialized
with the private-key handle and passes it in a BiometricPrompt `CryptoObject`.
Signing occurs only from a successful authentication result containing the
expected CryptoObject and unchanged canonical payload. Cancellation, lockout,
backgrounding, process death, null or changed CryptoObject, missing key,
invalidated key, or changed request produces no signature.

The permitted authenticator set is part of policy and evidence. Device
credential must never be described as biometric authentication.

Public-key extraction is permitted. Private-key encoding is never requested or
exposed. Reinstall, missing alias, invalidation, public-key mismatch, or device
security change requires explicit new-device enrolment; a replacement key is
never silently assigned to the old device identity.

### Capability and attestation

`KeyInfo.securityLevel` is recorded as a locally reported property:
StrongBox, trusted environment, software, or unknown. Key purpose, digest,
curve, origin, authentication requirement, and authenticator type are checked
as well. A local StrongBox/TEE report is not remote attestation.

Full hardware-key attestation is deferred until a server verifier and
operational root/revocation maintenance exist. The first release reports
attestation as not requested or unavailable. Any future verified tier requires
a server-supplied one-use challenge, the complete certificate chain, validation
against versioned accepted roots and revocations, exact package/signing
identity, security level, verified boot/device-locked state, patch policy, and
recorded verifier version. Play Integrity, if later selected, remains a
separate signal.

Milestone tier names remain illustrative until a separate assurance-policy
decision assigns permitted actions to each tier.

### Signature and protocol boundary

Android ECDSA output is strict DER. The protocol adapter must accept exactly
two minimally encoded positive scalars in `1..<n`, reject ambiguity and
trailing data, normalise `s` to low-S, and output fixed 64-byte `r || s`.
Compressed SEC1 public keys, identifiers, signatures, and canonical payloads
must pass shared Rust/iOS/Android fixtures.

Until the COSE profile ADR and those fixtures exist, Android may demonstrate
the EPIC-6 detached reference envelope but must fail closed for production
mobile envelopes. QR authentication and the M11 exit gate remain open.

### Provider authentication and Keeper

GitHub and Google use the external user agent under RFC 8252 with fresh PKCE
S256 and state. A verified HTTPS App Link callback is preferred; any custom
scheme requires exact scheme/host/path validation and intent-hijack review.
WebView is prohibited. Provider code exchange occurs at the trusted Pistis
broker. The application contains no client secret and retains no provider
access token.

Keeper participation is system-mediated. When GitHub requests a
`github.com` passkey in the browser, Android may offer Keeper if the user has
enabled it as a credential provider. Pistis receives only the OAuth callback.
Pistis does not query Keeper, retrieve or export a GitHub passkey, impersonate
the `github.com` relying party, or use that credential to sign Pistis objects.

### QR, discovery, storage, and lifecycle

QR acquisition is QR-only, bounded to the protocol maximum, uses keep-only-
latest backpressure, and never stores or logs frames. Camera permission is
requested only from the scan action. Every image proxy is closed, and camera
work stops on backgrounding.

Prefix, ASCII, size, alphabet, checksum, canonical encoding, closed schema,
expiry, purpose, installation, user, and key bindings are validated before
approval. A response QR being displayed does not imply delivery.

Local discovery is discovery only. Discovered names, addresses, and signed
endpoint hints are not authority. Connection requires reviewed TLS,
hostname/pinning policy, bounds, timeout, cancellation on network change, and
one shared ingestion/verification path with QR.

Local storage retains redacted informational events only. OAuth material,
provider tokens, QR frames, private keys, session capabilities, and complete
challenges are excluded. Installation-bound state is not backed up or
transferred. A storage-encryption key, if introduced, is separate from the
per-signing key.

Backgrounding, process death, network change, or interrupted browser/camera
work cancels a pending ceremony. Saved state contains only opaque local
identifiers and never resumes approval without a fresh challenge.

### Testing and distribution

Pure Kotlin tests use fixed time and entropy and cover state, substitution,
replay, cancellation, invalidation, OAuth, DER, and evidence boundaries.
Compose tests assert semantics and state rather than screenshot appearance.
Emulator tests prove application integration but do not prove hardware-backed
keys or biometric assurance.

Physical acceptance requires a current Pixel, current Samsung flagship or
mid-range device, a lower-cost supported device, StrongBox and non-StrongBox
devices, fingerprint and supported face/device credential paths, reinstall,
and network-change behaviour.

Jenkins runs ordinary Android builds in a digest-pinned SDK/JDK container.
Emulator execution requires a separately reviewed KVM-enabled worker and task;
generic repository jobs never receive `/dev/kvm`. PR jobs receive no Play
signing material.

Play signing and publication use a credential-isolated protected release task
for an exact reviewed `main` or tag. Prefer Play App Signing and keep the upload
key recoverable and isolated. Play Console records, organisation verification,
store declarations, Data Safety, privacy policy, signing, testers, and
internal/closed-track evidence remain owner-controlled gates. An unsigned
bundle or debug APK is not a Play release.

## Consequences

- Android and iOS share evidence truth and ceremony structure without forcing
  pixel-identical UI.
- Hardware and biometric assurance are never inferred from emulator or local
  existence alone.
- Keeper may assist GitHub in the browser without exposing a passkey to Pistis.
- A portable, deterministic source foundation can be reviewed in Linux CI.
- Play distribution, physical-device assurance, attestation, local-network
  interoperability, and production COSE remain explicit gates.

## Alternatives considered

- Material dynamic colour: rejected because it substitutes unreviewed semantic
  colours.
- Silent StrongBox-to-TEE fallback: rejected because it overstates assurance.
- Time-window key authorisation: rejected because each Pistis signature
  requires a fresh explicit ceremony.
- WebView OAuth or embedded client secrets: rejected because native-app OAuth
  requires an external user agent and a public client cannot protect a secret.
- On-device attestation as verified assurance: rejected because the relying
  server must validate chain and policy.
- Treat discovery or response-QR display as delivery: rejected because neither
  establishes authenticated receipt.
- Claim the EPIC-6 detached signature as final COSE: rejected by ADR 0006.

## Review evidence

The design review required exact Mnemosyne tokens, native Compose mechanics,
five-destination parity, accessible words-first states, empty and failure
states, restrained provenance, and Grammateus fact separation. The security
review required per-use CryptoObject signing, explicit StrongBox fallback,
locally reported capability, deferred remote attestation, strict low-S ES256,
external-browser OAuth, system-mediated Keeper participation, bounded camera
and lifecycle behaviour, and extensive negative tests. The release review
required pinned dependencies, modular Gradle structure, Linux and isolated
emulator Jenkins stages, signing separation, retained evidence, device matrix,
and honest Play blockers.
