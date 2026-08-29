# ADR 0007: iOS reference application

- Status: Accepted
- Date: 2026-07-24
- Amended: 2026-08-29 to distinguish ordinary signed-login intent from
  governed-action review
- Owners: iOS, security, protocol, and design

## Context

Pistis needs a production-shaped iOS reference application for identity
enrolment, installation pairing, QR authentication, consequential approval,
and local evidence history. The application may become a public face of
Mnemosyne Biosciences, so it must adapt the existing Mnemosyne design language
and Grammateus evidence hierarchy instead of inventing another visual system.

The application also needs GitHub authentication that works well for people
who store GitHub passkeys in Keeper. Passkeys are scoped to their relying
party. Neither iOS nor Keeper exposes an interface through which Pistis may
retrieve a GitHub passkey or its private key.

ADR 0006 deliberately limits the existing QR reference flow to detached
signatures. It requires a separate accepted COSE design and shared conformance
fixtures before production mobile interoperability is claimed.

## Decision

### Product and evidence model

The application is a native SwiftUI application with five primary
destinations: Identities, Installations, Scan, History, and Settings.
Consequential tasks use a focused review sheet rather than a dashboard card.

Consequential and governed tasks follow the Grammateus information hierarchy:

1. state the requested action and subject;
2. show installation, user, external-identity, expiry, and route evidence;
3. obtain an explicit human approve or deny decision;
4. invoke system local authentication for every signing operation;
5. report human decision, device signature, transfer receipt, and server
   verification as separate facts.

An ordinary authentication QR is the narrow exception. After Pistis verifies
the signed challenge against the selected enrolled installation, scanning that
one-use QR is the operator's explicit request to approve that login. Pistis may
therefore proceed directly to fresh Face ID and Secure Enclave signing without
a second application-level **Approve** control. If retained authority custody
must be restored, the same login task performs the exact pinned App Attest and
Face-ID-attended continuation before resuming the original challenge. No
second challenge or detached recovery navigation is permitted.

This exception does not apply to enrolment, authority replacement or movement,
custody import, destructive action, privilege change, or another governed
approval. Those operations continue to display their complete review evidence
and require an explicit application-level decision before local
authentication. Cancelling Face ID during ordinary login produces no signed
response; it is not converted into a signed denial.

An approval does not imply signature verification or server acceptance.
History is an informational, immutable-looking timeline of locally observed
events; it is not presented as authoritative server audit evidence.

### Visual language

The native adaptation uses the reviewed Mnemosyne tokens:

- ink `#111111`, canvas `#F6F7F5`, raised surface `#FFFFFF`;
- provenance green `#1C2B0B`, mark light `#C7BFA8`, mark dark `#4F5C29`;
- action teal `#0F6B78`, action hover `#0B5964`;
- border `#D9E0E3`, success `#28622B`, warning `#6F5410`, danger `#8A3C25`;
- spacing 4, 8, 12, 16, 24, and 32 points; radii 4, 8, and 12 points.

Source Sans 3 is preferred for body text and Crimson Pro is reserved for rare
provenance or report-display moments. The first implementation uses Dynamic
Type system styles until licensed, bundled native-font assets and rules are
reviewed. Status is always communicated in words and accessibility labels,
never by colour alone. Controls support VoiceOver, Dynamic Type, reduced
motion, sufficient contrast, and a 44-point minimum hit target.

The partial Mnemosyne mark may appear once in onboarding, About, or a restrained
provenance area. It is not used as a scanner reticle, spinner, generic card
decoration, or repeated navigation icon. The web report footer is not copied
into native screens. No dark palette, motion system, App Icon, or native footer
is invented until the design-language repository defines one.

### Architecture

SwiftUI views depend on a small, deterministic domain model and reducer.
Platform behaviour sits behind narrow adapters for:

- secure key storage and public-key extraction;
- local user verification;
- system-browser OAuth and the Pistis broker;
- QR camera acquisition;
- protocol decoding and signing;
- local history storage; and
- time and randomness.

Views do not handle private keys, provider tokens, canonical encoding, or
network policy. The core package is testable without a device, network, camera,
or Apple account. Platform adapters fail closed and expose specific,
non-sensitive error states.

### Device key and local authentication

The signing key is P-256 and generated with
`kSecAttrTokenIDSecureEnclave`. It is non-exportable and stored with
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. Private-key use is protected by
an access control requiring private-key usage and the enrolled biometric set.
Every approval signature uses a fresh `LAContext`; cancellation, lockout,
changed biometrics, backgrounding, or unavailable hardware produces no
signature.

The public P-256 key may be extracted and registered. Private-key bytes never
leave the Secure Enclave. The application does not silently create a software
key when Secure Enclave creation fails. Simulator and test substitutes are
explicitly labelled and cannot claim hardware-backed assurance.

DER-encoded ECDSA signatures must be strictly converted to the protocol's
fixed-width representation and checked against shared Rust fixtures before
mobile interoperability is declared. Cryptographic format conversion is not
implemented inside a view or camera adapter.

### Keeper-assisted GitHub authentication

Pistis opens the GitHub OAuth authorisation endpoint using
`ASWebAuthenticationSession`, with a fresh PKCE verifier, state value, and
exact callback URI. When GitHub requests a passkey, iOS may offer Keeper if the
person enabled Keeper as an iOS Passwords, AutoFill, and Passkeys provider.
Keeper and the operating system perform the WebAuthn assertion for
`github.com`; Pistis receives only its OAuth callback.

Pistis does not query a Keeper vault, request or export a GitHub passkey,
receive the passkey private key, create a credential-provider extension, or
use a GitHub passkey to sign Pistis protocol objects. The user-facing term is
“Keeper-assisted GitHub authentication”, not “Keeper integration”.

OAuth codes are exchanged by a trusted Pistis broker. The iOS bundle contains
no provider client secret and retains no provider access token. State,
callback, and broker responses are validated before an identity is recorded.
Google enrolment uses the same system-browser and broker boundary.

### QR and local transfer

QR acquisition uses AVFoundation metadata capture. Frames are not persisted or
logged. Input bounds, prefix, checksum, closed schema, expiry, purpose, and
installation bindings are checked before any Face ID request. Moving to the
background cancels a pending approval. A successful ordinary login returns to
Identities and retires the transient scanner session; selecting Scan creates a
fresh camera session without restarting the application.

QR response and direct-local submission share one response state machine and
one signing boundary. Until a COSE ADR and cross-language fixtures are
accepted, the app may demonstrate the reviewed EPIC-6 reference envelope but
must label it as reference-only and must not claim production interoperability.

### Distribution and claims

The repository contains source, tests, an Xcode project, and operator guidance.
Jenkins may run portable Swift-core tests in a pinned Swift container. Native
iOS compilation, simulator/UI tests, signing, archiving, and TestFlight require
a reviewed macOS Jenkins worker with full Xcode and owner-controlled Apple
Developer and App Store Connect access.

Absence of Xcode, a signing identity, registered bundle identifier,
provisioning profile, App Store Connect application, export-compliance answers,
or TestFlight test evidence is a blocker, not a successful configuration.
Tasks and milestone gates remain open until their evidence exists.

## Consequences

- The iOS product has a restrained, evidence-led design rooted in the existing
  Mnemosyne and Grammateus work.
- Keeper can participate through Apple's credential UI without weakening
  WebAuthn isolation or exposing credentials to Pistis.
- The Secure Enclave key remains distinct from provider authentication and is
  used only for Pistis signatures.
- Portable domain behaviour can be tested before Apple infrastructure exists.
- Signing, TestFlight, native UI validation, and final QR interoperability
  cannot be marked complete on a Command-Line-Tools-only host.

## Alternatives considered

- Retrieve a GitHub passkey from Keeper: rejected because no supported
  interface exists and it would violate passkey relying-party isolation.
- Embed a GitHub or Google client secret: rejected because an iOS bundle cannot
  protect a client secret.
- Treat an approval as verified evidence: rejected because human intent,
  signature production, transport, and server verification are distinct facts.
- Recreate Grammateus's fixed report page and footer: rejected because a native
  application has different navigation and accessibility requirements.
- Invent unreviewed native brand assets or dark-mode colours: rejected pending
  explicit design-language rules.
- Claim the detached EPIC-6 envelope as final mobile COSE: rejected because it
  contradicts ADR 0006.

## Review evidence

Three independent pre-implementation reviews covered the Mnemosyne design
language, Grammateus reporting/evidence semantics, and iOS/Keeper security
feasibility. The design reviews required exact token reuse, accessible
words-first states, evidence-first task flows, restrained provenance, and
separation of approval from verification. The security review required
system-mediated Keeper participation, non-exportable per-use-authenticated
Secure Enclave keys, brokered OAuth, explicit fallback states, and honest
Apple-distribution and COSE blockers.

On 29 August 2026 the programme owner accepted the ordinary-login amendment:
the verified signed QR scan is the application-level login decision and Face
ID remains mandatory. The accepted boundary retains explicit evidence review
for every enrolment, authority-changing, destructive, privilege-changing, and
otherwise governed operation.
