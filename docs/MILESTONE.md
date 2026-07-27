# Pistis v1.0 — MILESTONE.md

**Document status:** Implementation planning baseline  
**Project:** Pistis  
**Target release:** v1.0  
**Primary implementation language:** Rust  
**Mobile clients:** iOS for MVP; Android for v1.0  
**Primary integrations:** Mnemosyne Synoptikon and Monas standalone deployments  
**Initial external trust anchors:** GitHub and Google OpenID Connect  
**Default operating model:** Local-first, challenge-response authentication without a continuously available Pistis server  
**Last revised:** 24 July 2026

---

## 1. Purpose of this document

This document breaks the work required to deliver Pistis v1.0 into explicit, testable milestones.

It is intended to serve simultaneously as:

- the engineering delivery plan;
- the scope boundary for v1.0;
- the source of milestone acceptance criteria;
- the dependency map for the Rust core, mobile clients and product integrations;
- the baseline for security review and threat modelling;
- the basis for issues, epics and release gates;
- the definition of what “v1.0 complete” means.

This is not a calendar commitment. Estimates are expressed as **developer-weeks of effort**, not elapsed calendar time. Parallel mobile and backend work can shorten elapsed delivery, but it does not reduce total engineering effort.

---

## 2. v1.0 product definition

Pistis v1.0 is a portable cryptographic identity, authentication and approval system.

It allows an administrator to declare that a local application identity—for example, the Synoptikon account `stephen`—must be controlled by a named external identity, initially:

- a stable GitHub user identity; or
- a stable Google OpenID Connect subject.

The user proves control of that external identity during enrolment in the Pistis mobile application. Pistis then creates a device-bound signing key and produces cryptographic evidence linking:

1. the external identity;
2. the Pistis device key;
3. the local application challenge;
4. the requested authentication or approval action;
5. the user’s explicit biometric or device-credential confirmation.

Normal authentication does not require Synoptikon or Monas to contact GitHub or Google after enrolment. GitHub and Google act as **trust anchors for enrolment**, rather than continuously available authentication intermediaries.

The default login ceremony is:

```text
User enters or selects local account
        ↓
Synoptikon or Monas creates a short-lived challenge
        ↓
Application displays challenge as QR code
        ↓
Pistis mobile application scans challenge
        ↓
User reviews installation and action
        ↓
Biometric/device authentication authorises key use
        ↓
Pistis signs the canonical challenge
        ↓
Signed response is returned over the local network or response QR
        ↓
Local installation verifies signature and trust evidence
        ↓
Application session is established
```

Local-network discovery and transfer improve usability but do not alter the trust model. QR exchange remains the universal fallback.

---

## 3. Explicit v1.0 scope

### 3.1 Included

Pistis v1.0 shall include:

- a Rust workspace containing the protocol, cryptographic, evidence, policy and verification components;
- GitHub enrolment as an external trust anchor;
- Google OpenID Connect enrolment as an external trust anchor;
- stable external-identity identifiers rather than mutable usernames or email addresses;
- device-bound signing keys;
- iOS application using Secure Enclave-compatible key storage and LocalAuthentication;
- Android application using Android Keystore and BiometricPrompt;
- QR challenge and response transport;
- local-network discovery and direct exchange where the network permits it;
- deterministic canonical challenge and evidence encodings;
- replay-resistant, short-lived authentication challenges;
- local trust-policy configuration;
- user/device enrolment, listing, suspension and revocation;
- authentication integration with Synoptikon;
- standalone authentication and verification integration for Monas;
- detached evidence generation;
- report/artefact signing primitives;
- a Rust verifier library;
- a verification command-line interface;
- auditable authentication and signing events;
- conformance fixtures shared across Rust, iOS and Android;
- a documented recovery and replacement-device procedure;
- packaging, release automation and operator documentation.

### 3.2 Excluded from v1.0

The following are explicitly outside v1.0:

- a mandatory central Pistis identity service;
- APNs or FCM remote push as a required authentication path;
- a public global identity directory;
- SAML;
- SCIM;
- enterprise lifecycle provisioning;
- password authentication;
- password recovery;
- SMS one-time passwords;
- TOTP;
- custom cryptographic algorithms;
- a public certificate authority;
- a blockchain;
- public transparency logs;
- qualified electronic signatures or formal eIDAS certification;
- legal assertions that a signature is equivalent to a handwritten signature;
- Android devices without an acceptable secure key-storage and screen-lock configuration;
- Huawei or other Android variants without the selected supported platform services, unless separately qualified;
- Apple Watch, Wear OS, NFC and USB transports;
- automatic phone-to-phone credential migration;
- cross-installation global role portability;
- anonymous or pseudonymous account creation;
- general-purpose password-manager functionality.

---

## 4. Architectural invariants

The following constraints apply to every milestone and must not be traded away for convenience.

### 4.1 No central server dependency

A Synoptikon or Monas installation must be capable of:

- enrolling a Pistis device;
- issuing an authentication challenge;
- receiving a response;
- validating the response;
- recording evidence;
- revoking the device;

without depending upon a Mnemosyne-operated cloud service.

External network access may be required during GitHub or Google enrolment, but not for routine challenge signing and verification.

### 4.2 Device private keys never leave the device

Pistis must not export, escrow, synchronise or back up the private signing key.

The server stores:

- a public key;
- public enrolment evidence;
- device metadata;
- revocation state;
- signed responses.

### 4.3 Discovery is not authentication

mDNS, DNS-SD, QR codes, deep links and local HTTP discovery are transports. Discovery results are untrusted until a signed protocol message is verified.

### 4.4 External identity is not local authority

GitHub and Google establish the external subject identity. The local installation decides:

- whether that subject is trusted;
- which local account it controls;
- which roles it receives;
- what it may sign or approve.

### 4.5 Stable identifiers are mandatory

GitHub trust records must use the stable provider user identifier, not only the login name.

Google trust records must use the OIDC issuer and `sub` claim, not only the email address.

Mutable display identifiers may be retained as snapshots for human readability.

### 4.6 Evidence must be portable

A verifier must be able to validate a signed challenge or artefact using a detached evidence package and the local installation’s exported trust material.

### 4.7 Protocol before transport

The canonical message model and signature rules must be frozen and tested before convenience transports are treated as production-ready.

### 4.8 No silent approval

Every signature must be authorised through an explicit local user-verification ceremony appropriate to the device and action class.

---

## 5. Proposed Rust workspace

The exact crate names may change, but v1.0 should preserve these responsibility boundaries.

```text
pistis/
├── Cargo.toml
├── crates/
│   ├── pistis-core/
│   ├── pistis-protocol/
│   ├── pistis-canonical/
│   ├── pistis-crypto/
│   ├── pistis-claims/
│   ├── pistis-evidence/
│   ├── pistis-policy/
│   ├── pistis-verifier/
│   ├── pistis-oidc/
│   ├── pistis-github/
│   ├── pistis-google/
│   ├── pistis-qr/
│   ├── pistis-discovery/
│   ├── pistis-store/
│   ├── pistis-audit/
│   ├── pistis-server/
│   ├── pistis-cli/
│   ├── pistis-synoptikon/
│   └── pistis-monas/
├── apps/
│   ├── ios/
│   └── android/
├── fixtures/
├── schemas/
├── docs/
├── threat-model/
└── xtask/
```

### Crate responsibilities

#### `pistis-core`

Shared identifiers, timestamps, errors, state enumerations and domain types. It must contain no transport-specific logic.

#### `pistis-protocol`

Request and response state machines, challenge types, protocol version negotiation and validation rules.

#### `pistis-canonical`

Deterministic canonical byte encoding for signed objects. It must expose test vectors and reject non-canonical or ambiguous inputs.

#### `pistis-crypto`

Signature-suite abstraction, hashing, signature verification and safe key-identifier derivation. It must not implement novel cryptography.

#### `pistis-claims`

External identity claims and local binding statements.

#### `pistis-evidence`

Detached evidence envelopes, artefact-digest records, signature chains and export/import formats.

#### `pistis-policy`

Local trust and approval policy parsing and evaluation.

#### `pistis-verifier`

High-level verification API returning structured verdicts, warnings and failure reasons.

#### `pistis-oidc`

OIDC discovery, authorization-code flow support, ID-token validation and subject extraction.

#### `pistis-github`

GitHub-specific enrolment adapter and stable-user-ID retrieval.

#### `pistis-google`

Google OIDC enrolment adapter.

#### `pistis-qr`

Compact QR payload framing, fragmentation where required, checksums and visual-transfer error handling.

#### `pistis-discovery`

mDNS/DNS-SD advertisement and discovery, local endpoint resolution and transport negotiation.

#### `pistis-store`

Storage interfaces and implementations. Initial implementations should support SQLite and the Mnemosyne database abstraction where appropriate.

#### `pistis-audit`

Structured immutable audit-event definitions and sinks.

#### `pistis-server`

Axum endpoints for enrolment, challenges, response submission, device administration and evidence retrieval.

#### `pistis-cli`

Operator, developer and standalone verification commands.

#### `pistis-synoptikon`

Synoptikon-specific integration layer.

#### `pistis-monas`

Standalone Monas integration layer and embedding examples.

---

## 6. Delivery summary

The `v1.0` plan below remains the complete product commitment.
`MVP_RELEASE_CANDIDATE.md` defines the approved narrower `v0.1.0-rc.1`
vertical slice and its delivery epics. MVP completion must not be represented
as completion of deferred `v1.0` capabilities.

| Milestone | Outcome | Estimated effort |
| --- | --- | ---: |
| M0 | Charter reconciliation and delivery baseline | 1 developer-week |
| M1 | Threat model and protocol specification | 3 developer-weeks |
| M2 | Rust workspace and cryptographic foundation | 4 developer-weeks |
| M3 | External trust-anchor enrolment | 4 developer-weeks |
| M4 | Local installation identity and device registry | 3 developer-weeks |
| M5 | QR authentication end-to-end | 4 developer-weeks |
| M6 | iOS MVP application | 6 developer-weeks |
| M7 | Synoptikon integration | 3 developer-weeks |
| M8 | Monas standalone integration and CLI | 3 developer-weeks |
| M9 | Local-network discovery and direct exchange | 4 developer-weeks |
| M10 | Artefact/report signing and portable evidence | 4 developer-weeks |
| M11 | Android application | 7 developer-weeks |
| M12 | Recovery, revocation and multi-device lifecycle | 3 developer-weeks |
| M13 | Security hardening and independent review | 5 developer-weeks |
| M14 | Packaging, operations and documentation | 3 developer-weeks |
| M15 | Release candidate and v1.0 acceptance | 2 developer-weeks |
| **Total** | | **59 developer-weeks** |

The estimate is deliberately broader than the earlier concept estimate because this plan defines a complete, supportable v1.0 rather than a demonstration prototype. A focused team can execute workstreams in parallel. A plausible staffing model is:

- one Rust/backend engineer;
- one iOS engineer;
- one Android engineer joining before M11;
- part-time product/security/QA support.

Under that model, an elapsed programme of approximately **24–32 weeks** is plausible, while retaining the total effort above.

---

# Milestone M0 — Charter reconciliation and delivery baseline

**Objective:** Convert the product concept into a controlled engineering baseline before implementation begins.

**Estimated effort:** 1 developer-week

## Work items

### M0.1 Resolve terminology

Define and freeze the meanings of:

- local user;
- external identity;
- trust anchor;
- device;
- device key;
- enrolment;
- binding;
- challenge;
- approval;
- authentication;
- signature;
- evidence envelope;
- installation;
- realm, if the term is retained;
- verifier;
- transport;
- recovery;
- revocation.

### M0.2 Confirm v1.0 platform interpretation

Record explicitly that:

- iOS is the MVP mobile platform;
- Android is the second platform required for v1.0;
- “Google app” in the original charter is interpreted as the Android application;
- Google is also an external OIDC trust anchor;
- Synoptikon and Monas are independent relying applications sharing the same Pistis core.

### M0.3 Freeze initial protocol assumptions

Confirm:

- no central Pistis server;
- QR as mandatory fallback;
- local-network transfer as convenience;
- direct signed challenge response;
- local application retains user and authorization state;
- GitHub/Google are used at enrolment;
- device key is subsequently sufficient for routine login until revoked.

### M0.4 Establish repository and governance

Create:

- repository;
- issue labels;
- milestones;
- contribution policy;
- security reporting policy;
- branch protection;
- required CI checks;
- architecture-decision-record directory;
- release versioning policy;
- licence decision.

### M0.5 Define supported platform baseline

Propose and record:

- minimum supported iOS major versions;
- minimum supported Android API level;
- supported desktop/browser matrix for QR and local discovery;
- supported Linux distributions for server and CLI;
- supported database backends;
- FIPS requirements, if any;
- offline and air-gapped expectations.

## Deliverables

- `PROJECT_CHARTER.md`
- `MILESTONE.md`
- `GLOSSARY.md`
- `CONTRIBUTING.md`
- `SECURITY.md`
- initial ADRs
- v1.0 product requirements baseline

## Acceptance criteria

- No unresolved contradiction remains between local-first operation and any proposed mandatory central component.
- iOS MVP and Android v1.0 boundaries are explicit.
- All product terms used in later milestones have normative definitions.
- Repository protections and CI skeleton are operational.
- All subsequent milestones have named owners or workstream placeholders.

## Exit gate

Engineering may begin only after the protocol owner and Synoptikon integration owner approve the baseline.

---

# Milestone M1 — Threat model and protocol specification

**Objective:** Specify what is signed, what is trusted and how attacks are rejected before production code fixes accidental behaviour into the protocol.

**Estimated effort:** 3 developer-weeks

## Work items

### M1.1 Define actors and trust boundaries

Model:

- local user;
- local administrator;
- browser;
- Synoptikon/Monas server;
- Pistis mobile application;
- GitHub;
- Google;
- local network;
- malicious local-network participant;
- compromised browser;
- compromised installation;
- stolen phone;
- malicious or rooted/jailbroken device;
- offline verifier;
- report recipient.

### M1.2 Define threat scenarios

At minimum:

- replay of a valid signed login;
- challenge substitution;
- QR-code replacement;
- response substitution;
- local-network man-in-the-middle;
- malicious mDNS advertisements;
- identity-binding substitution;
- mutable GitHub username confusion;
- Google email reuse or account-domain confusion;
- malicious installer assigning the wrong external identity;
- stolen unlocked phone;
- changed biometric enrolment;
- device backup/restore;
- key loss;
- user departure;
- device revocation after historic signatures;
- clock manipulation;
- protocol downgrade;
- canonicalisation ambiguity;
- cross-installation replay;
- cross-purpose replay;
- login signature reused as report approval;
- approval fatigue;
- denial of service;
- local evidence-store tampering.

### M1.3 Define canonical signed messages

Specify normative structures for:

- enrolment intent;
- external-identity binding statement;
- device registration;
- authentication challenge;
- authentication response;
- artefact-signing challenge;
- artefact-signing response;
- revocation statement;
- exported trust bundle.

Each signed object must include:

- protocol version;
- object type/purpose;
- unique identifier;
- random nonce where applicable;
- issuing installation identifier;
- intended local user;
- requested external identity;
- requesting application;
- issued time;
- expiry;
- requested action;
- key identifier;
- signature suite;
- canonical payload digest.

### M1.4 Select canonical encoding

Evaluate deterministic CBOR/COSE and tightly specified canonical JSON/JWS.

The decision must consider:

- native iOS and Android implementation;
- Rust ecosystem maturity;
- QR size;
- deterministic encoding;
- debugging and audit readability;
- offline verification;
- future extensibility.

Record the decision in an ADR. If CBOR/COSE is selected, provide JSON diagnostic forms for debugging.

### M1.5 Select signature suites

The mobile platform capabilities must drive the decision.

The design should prefer a signature suite available through:

- Apple Secure Enclave-compatible APIs;
- Android Keystore;
- stable Rust verification libraries.

A likely common denominator is P-256 ECDSA with SHA-256. Ed25519 may remain available for software or non-mobile keys but must not be assumed to be Secure Enclave-backed on all target devices.

### M1.6 Define protocol state machines

Authentication request states:

```text
created → presented → claimed → approved → consumed
                     ↘ denied
                     ↘ expired
                     ↘ cancelled
```

Rules:

- approval is not equivalent to consumption;
- consumption is atomic and single-use;
- an expired or cancelled challenge cannot be revived;
- a response must be bound to the exact challenge;
- retries create new challenge identifiers and nonces.

### M1.7 Define assurance model

At minimum record:

- external identity was freshly authenticated at enrolment;
- device key was generated by the application;
- hardware-backed status known/unknown;
- biometric or device credential required for each signature;
- platform attestation available/not available;
- device integrity signal available/not available.

Do not collapse all enrolled devices into one indistinguishable assurance level.

### M1.8 Produce conformance fixtures

Create language-neutral test vectors:

- valid challenge;
- valid response;
- invalid signature;
- wrong installation;
- wrong purpose;
- expired challenge;
- replayed challenge;
- non-canonical encoding;
- unknown critical field;
- revoked key;
- provider-identity mismatch.

## Deliverables

- `docs/protocol.md`
- `docs/encoding.md`
- `docs/assurance.md`
- `threat-model/THREAT_MODEL.md`
- `schemas/`
- `fixtures/protocol-v1/`
- protocol ADRs

## Acceptance criteria

- Independent implementations can produce byte-identical canonical payloads from the test fixtures.
- Every threat has a mitigation, accepted residual risk or explicit deferral.
- Login and artefact-signing messages are cryptographically separated by purpose.
- Cross-installation and cross-user replay are impossible under the specified verifier rules.
- The selected signature suite is implementable on both iOS and Android secure key stores.
- Protocol versioning and unknown-field behaviour are explicit.

## Exit gate

No external mobile or Synoptikon integration begins against an undocumented wire format.

---

# Milestone M2 — Rust workspace and cryptographic foundation

**Objective:** Deliver the protocol-independent Rust core with deterministic encoding, verification and conformance tests.

**Estimated effort:** 4 developer-weeks

## Work items

### M2.1 Create workspace and dependency policy

- pin minimum supported Rust version;
- configure `cargo-deny`;
- configure licence allow-list;
- configure vulnerability scanning;
- disallow unsafe code by default;
- document justified exceptions;
- configure reproducible release builds;
- establish feature-flag policy.

### M2.2 Implement domain identifiers

Introduce typed identifiers for:

- installation;
- local user;
- external identity;
- device;
- key;
- challenge;
- evidence;
- artefact;
- policy;
- session.

Avoid free-form string substitution between identifier classes.

### M2.3 Implement canonical encoding

- deterministic field ordering;
- integer and timestamp rules;
- byte-string handling;
- Unicode normalisation decision;
- unknown-field handling;
- maximum message sizes;
- canonical decoder validation;
- differential fixture tests.

### M2.4 Implement cryptographic abstraction

Provide:

- SHA-256 digest;
- supported public-key parsing;
- key identifier derivation;
- signature verification;
- constant-time comparisons where applicable;
- algorithm allow-list;
- rejection of algorithm confusion;
- structured cryptographic errors.

### M2.5 Implement challenge generation

- cryptographically secure random nonce;
- monotonic challenge identifiers;
- configurable expiry within safe bounds;
- installation and purpose binding;
- state persistence interface;
- no predictable challenge material.

### M2.6 Implement verification pipeline

Return a structured result:

```text
Valid
InvalidSignature
Expired
AlreadyConsumed
WrongInstallation
WrongUser
WrongPurpose
UnknownKey
RevokedKey
PolicyRejected
Malformed
UnsupportedVersion
UnsupportedAlgorithm
NonCanonical
```

Avoid a single boolean verdict.

### M2.7 Implement protocol fixtures and fuzzing

- property tests;
- parser fuzz targets;
- canonicalisation fuzz targets;
- signature-verification negative tests;
- malformed length and allocation limits;
- corpus retained in repository.

## Deliverables

- initial Rust crates;
- public API documentation;
- fixture runner;
- fuzz harness;
- CI matrix;
- example challenge/verifier program.

## Acceptance criteria

- All normative fixtures pass.
- Fuzz targets run continuously in scheduled CI.
- No private-key handling exists in the server-side Rust core.
- Unsupported algorithms are rejected rather than dynamically accepted.
- A challenge cannot be consumed twice under concurrent verification.
- Public Rust APIs have documentation and examples.
- `cargo audit`/equivalent and licence checks pass.

## Exit gate

A command-line demonstration must create a challenge, sign it with a test key and verify it using only the Rust libraries.

---

# Milestone M3 — GitHub and Google trust-anchor enrolment

**Objective:** Allow Pistis to establish a durable external identity binding using GitHub and Google.

**Estimated effort:** 4 developer-weeks

## Work items

### M3.1 Provider abstraction

Define a provider adapter interface that yields:

- provider type;
- issuer/authority;
- stable subject identifier;
- current display name;
- current email snapshot where available and consented;
- profile URL where appropriate;
- authentication time;
- token-validation evidence;
- provider-specific metadata.

### M3.2 GitHub enrolment

Implement a standards-compliant GitHub authorization flow suitable for the mobile app.

Requirements:

- authorization code with PKCE where supported/appropriate;
- CSRF `state` validation;
- system browser rather than embedded credential capture;
- access-token confidentiality;
- minimal scopes;
- call authenticated-user endpoint;
- capture stable numeric GitHub user ID;
- capture login as display metadata only;
- discard or securely remove provider access token once binding evidence is complete unless refresh is explicitly required;
- record provider response time and selected identity fields.

### M3.3 Google enrolment

Implement Google OpenID Connect:

- discovery metadata;
- authorization code with PKCE;
- nonce;
- ID-token signature validation;
- issuer validation;
- audience validation;
- `azp` handling where applicable;
- expiry and issued-at validation;
- stable `sub` extraction;
- email retained only as display metadata;
- hosted-domain information treated as a claim, not identity key;
- minimal scopes (`openid`, profile as needed, email only if needed).

### M3.4 Bind provider identity to device key

The mobile app generates its device key before completing enrolment evidence.

The binding statement must include:

- external identity;
- device public key;
- provider authentication event metadata;
- app instance identifier;
- protocol version;
- creation time;
- optional installation enrolment intent.

### M3.5 Installation trust matching

Support administrator policy such as:

```yaml
users:
  stephen:
    trust:
      any_of:
        - provider: github
          subject: "12345678"
        - provider: google
          issuer: "https://accounts.google.com"
          subject: "109876543210987654321"
```

Display names must never satisfy the match.

### M3.6 Reauthentication policy

Document when provider reauthentication is required:

- initial enrolment;
- identity rebinding;
- recovery/replacement device;
- administrator-requested revalidation;
- provider metadata refresh where policy requires it.

Routine local login does not require provider access.

## Deliverables

- `pistis-oidc`
- `pistis-github`
- `pistis-google`
- provider conformance tests;
- example binding statements;
- privacy/data-retention documentation.

## Acceptance criteria

- Changing a GitHub login name does not invalidate a binding to the same stable GitHub user ID.
- Changing a Google email address does not alter the identity key.
- ID tokens with incorrect issuer, audience, nonce or expiry are rejected.
- GitHub/Google access tokens are not retained without a documented reason.
- The application cannot substitute one provider subject for another in a signed binding statement.
- Provider cancellation and network failure leave no partially trusted enrolment.

## Exit gate

A test device can produce independently verifiable GitHub and Google binding evidence using non-production test accounts.

---

# Milestone M4 — Local installation identity and device registry

**Objective:** Give each Synoptikon or Monas installation the local state required to trust, manage and revoke Pistis devices.

**Estimated effort:** 3 developer-weeks

## Work items

### M4.1 Installation identity

Generate and persist an installation identity containing:

- installation identifier;
- human-readable name;
- canonical base URL where available;
- local signing/sealing public key where required;
- protocol capabilities;
- creation time;
- key-rotation metadata.

The installation identity is not a global Pistis account.

### M4.2 Local user trust policy

Support:

- one or more accepted trust anchors per local user;
- `any_of` and `all_of` rules;
- disabled user;
- expiry;
- administrative comments;
- source/configuration provenance;
- validation at startup;
- no ambiguous duplicate local usernames.

### M4.3 Device registry

Persist:

- device ID;
- local user;
- external identity;
- public key;
- key algorithm;
- platform;
- app version;
- assurance metadata;
- enrolment evidence;
- status;
- enrolled time;
- last-used time;
- revoked time and reason.

### M4.4 Challenge store

Persist:

- challenge;
- state;
- expiry;
- intended user;
- installation;
- purpose;
- response metadata;
- consumption transaction;
- audit correlation identifier.

### M4.5 Storage implementations

Provide:

- SQLite implementation for standalone/development;
- MySQL-compatible or Hebe-backed implementation for Synoptikon;
- migration framework;
- backup/restore documentation;
- integrity constraints;
- transactional single-use consumption.

### M4.6 Administration API

Implement endpoints/commands to:

- list users and trusted identities;
- list enrolled devices;
- inspect device assurance;
- suspend device;
- revoke device;
- view recent authentication events;
- export public verification material.

## Deliverables

- persistence schema;
- migrations;
- repository/store traits;
- administration endpoints;
- operator CLI commands.

## Acceptance criteria

- Concurrent response submissions cannot consume the same challenge twice.
- Revoked devices cannot authenticate.
- Historic evidence remains readable after revocation.
- Installation state survives backup/restore without changing installation identity unintentionally.
- Trust-policy configuration errors prevent unsafe startup rather than silently weakening policy.
- Device records contain no private key.

## Exit gate

A local installation can be fully operated with no central Pistis database or account.

---

# Milestone M5 — QR authentication end-to-end

**Objective:** Deliver a complete serverless/local authentication flow using visual challenge and response exchange.

**Estimated effort:** 4 developer-weeks

## Work items

### M5.1 Login initiation

- user enters/selects local account;
- installation resolves required trust policy;
- challenge generated;
- browser displays installation identity, expiry and QR;
- browser polls or listens for completion;
- no authenticated session is created yet.

### M5.2 QR challenge format

Include:

- protocol magic/version;
- challenge URL or embedded challenge;
- challenge identifier;
- installation fingerprint;
- expiry;
- checksum;
- optional local endpoint hints.

No secret embedded in the QR may be sufficient to authenticate without the device signature.

### M5.3 Mobile challenge validation

Before prompting for approval, display:

- installation name;
- installation fingerprint or previously trusted status;
- local username;
- action;
- expiry;
- whether the installation is new;
- whether the request arrived via QR or local transfer.

Reject:

- expired challenge;
- malformed challenge;
- unsupported version;
- wrong external identity;
- unknown critical fields;
- implausible payload sizes.

### M5.4 Response transfer

Support two v1.0 baseline modes:

1. direct HTTPS/local submission where reachable;
2. response QR displayed by the phone and captured by the browser/workstation.

If browser camera access is unavailable, provide a manual compact transfer fallback only if it can be implemented safely; otherwise document camera requirements.

### M5.5 Session establishment

After verification:

- atomically consume challenge;
- rotate pre-authentication session;
- establish local authenticated session;
- bind audit event;
- show successful device and identity;
- reject further responses.

### M5.6 Failure and cancellation UX

Handle:

- user denial;
- timeout;
- mobile app missing;
- camera denial;
- wrong Pistis identity;
- revoked device;
- installation key changed;
- response too large;
- local network unreachable.

## Deliverables

- QR encoder/decoder;
- browser login component;
- response ingestion API;
- end-to-end test harness;
- accessibility review for QR fallback instructions.

## Acceptance criteria

- Authentication succeeds without APNs, FCM or Mnemosyne cloud services.
- Authentication can succeed with both devices offline from the public internet.
- A photographed or replayed old response cannot establish a new session.
- The phone never signs a challenge for an external identity it does not hold.
- The browser does not establish a session before successful response verification.
- Installation fingerprint changes are prominently surfaced.
- End-to-end median interaction is practical for routine use.

## Exit gate

A Synoptikon-independent demo application authenticates using QR challenge and response with a test mobile signer.

---

# Milestone M6 — iOS MVP application

**Objective:** Deliver the first production-shaped Pistis mobile client.

**Estimated effort:** 6 developer-weeks

## Work items

### M6.1 Application shell

Implement in Swift/SwiftUI:

- onboarding;
- identities;
- installations;
- scan;
- pending action;
- approval result;
- history;
- device security/settings;
- diagnostics;
- legal/privacy information.

### M6.2 Secure key generation

Use Apple-supported key storage compatible with the Secure Enclave where available.

Requirements:

- non-exportable device key;
- explicit user authentication requirement for signature;
- key tag namespacing;
- key lifecycle errors handled;
- key invalidation detected;
- key regeneration never silently reuses the old device identity;
- public-key extraction;
- algorithm aligned with M1 decision.

### M6.3 Local authentication

Use LocalAuthentication to require Face ID, Touch ID or the documented fallback policy.

The app must distinguish:

- biometry available;
- biometry enrolled;
- lockout;
- device passcode fallback;
- cancellation;
- system error.

The chosen fallback policy must be visible in evidence assurance metadata.

### M6.4 External identity enrolment

Implement:

- GitHub browser flow;
- Google browser/OIDC flow;
- callback handling;
- cancellation;
- provider error reporting;
- identity display;
- removal/re-enrolment;
- binding evidence generation.

### M6.5 QR scanning and response

- camera permission;
- QR scanning;
- payload parsing;
- installation trust display;
- biometric-gated signing;
- direct response submission;
- response QR fallback;
- screen brightness and size optimisation;
- protection against accidental screenshots where practical;
- no sensitive provider token in QR.

### M6.6 Installation pairing

Allow an installation to be remembered after first successful pairing:

- installation ID;
- display name;
- public fingerprint;
- endpoint hints;
- last-used time;
- local aliases.

Changing installation trust material must trigger a warning and re-pairing.

### M6.7 Local history

Store a local summary of:

- successful approvals;
- denials;
- installation;
- action type;
- time;
- local user;
- key used.

History is informational and not the authoritative evidence store.

### M6.8 App lifecycle and recovery

Handle:

- device restore;
- app reinstall;
- missing keychain entry;
- changed biometric set according to chosen policy;
- backgrounding during approval;
- interrupted OAuth;
- phone clock changes;
- app version migration.

### M6.9 Distribution

- Apple Developer organisation setup;
- bundle ID;
- entitlements;
- privacy manifest;
- TestFlight;
- crash-symbol handling;
- release signing;
- App Store submission preparation.

## Deliverables

- iOS application;
- TestFlight build;
- iOS security design note;
- UI test suite;
- protocol conformance test execution against Rust fixtures.

## Acceptance criteria

- Private signing key cannot be exported through application functionality.
- Each signing operation invokes the configured local user-verification policy.
- GitHub and Google enrolment produce evidence accepted by the Rust verifier.
- iOS signatures match Rust conformance fixtures.
- App reinstall without recovery requires explicit new-device enrolment.
- No provider access token is exposed in logs, QR payloads or crash reports.
- Accessibility labels and Dynamic Type support cover the core ceremony.
- TestFlight build passes end-to-end tests with Synoptikon-independent server.

## Exit gate

The iOS application is the reference mobile implementation for the protocol.

---

# Milestone M7 — Synoptikon integration

**Objective:** Make Pistis a supported authentication and approval mechanism within Synoptikon.

**Estimated effort:** 3 developer-weeks

## Work items

### M7.1 Configuration

Provide installation configuration for:

- enabling Pistis;
- declaring local users;
- selecting trusted provider identities;
- requiring one or multiple trust anchors;
- challenge expiry;
- allowed device assurance;
- recovery administrators;
- audit retention;
- fallback policy.

### M7.2 Bootstrap administrator

Implement a safe first-install flow:

- installer declares initial administrator;
- installer declares expected GitHub and/or Google stable identity;
- installation creates bootstrap pairing challenge;
- Pistis enrols first administrator device;
- bootstrap credential is invalidated after completion;
- no default password remains.

Support a controlled console-based recovery path for initial installation failure.

### M7.3 Web authentication

Integrate:

- login page;
- challenge generation;
- QR display;
- local-discovery status;
- timeout;
- denial;
- session creation;
- logout;
- session listing;
- fresh-approval/step-up hooks.

### M7.4 Authorization separation

Ensure Pistis controls authentication only. Synoptikon continues to own:

- tenant membership;
- project roles;
- data access;
- compute permissions;
- administrative authorization.

### M7.5 Audit integration

Record:

- local username;
- external identity;
- device;
- challenge;
- verification result;
- source IP;
- user agent;
- installation;
- policy version;
- session ID.

### M7.6 Administrative UI

Provide:

- trusted identities;
- enrolled devices;
- device assurance;
- suspend/revoke;
- last used;
- enrol replacement device;
- export verification bundle;
- authentication failures.

## Deliverables

- `pistis-synoptikon`;
- Synoptikon migrations;
- authentication UI;
- bootstrap workflow;
- administrator documentation;
- integration tests.

## Acceptance criteria

- A fresh Synoptikon installation can bootstrap an administrator without creating a password.
- A valid Pistis response creates a normal Synoptikon session.
- Pistis identity does not bypass Synoptikon authorization.
- Revocation takes effect for new authentication immediately.
- Login events appear in the central auditor with correlation identifiers.
- Disabling Pistis cannot accidentally expose an unauthenticated administrator route.
- Existing deployments have a documented migration path.

## Exit gate

Pistis can be selected as the supported authentication method in a Synoptikon development release.

---

# Milestone M8 — Monas standalone integration and CLI

**Objective:** Ensure Pistis is an independent product capability rather than a Synoptikon-only feature.

**Estimated effort:** 3 developer-weeks

## Work items

### M8.1 Standalone service profile

Provide a minimal deployable service containing:

- local users;
- trust policies;
- device registry;
- challenge API;
- verifier;
- evidence store;
- administration API;
- SQLite support.

### M8.2 Embedding API

Expose Rust APIs for Monas applications to:

- create challenge;
- render challenge payload;
- submit response;
- verify response;
- consume challenge;
- retrieve authentication principal;
- create artefact-signing request;
- verify detached evidence.

### M8.3 CLI

Commands should include:

```text
pistis init
pistis user add
pistis trust add-github
pistis trust add-google
pistis device list
pistis device revoke
pistis challenge create
pistis response verify
pistis evidence inspect
pistis evidence verify
pistis trust export
pistis doctor
```

### M8.4 Reference application

Build a small Monas-style reference web application demonstrating:

- bootstrap;
- local user login;
- QR exchange;
- local discovery;
- report signing;
- detached verification.

### M8.5 Packaging

- standalone binary;
- configuration file;
- systemd unit;
- container image where compatible with project policy;
- RPM/SRPM integration path through Phoreus;
- database migration commands.

## Deliverables

- `pistis-monas`;
- `pistis-cli`;
- reference app;
- deployment guide;
- RPM packaging specification.

## Acceptance criteria

- A non-Synoptikon application can integrate Pistis without importing Synoptikon types.
- CLI verification works offline.
- Standalone deployment runs with SQLite and no cloud services.
- The reference application passes the same protocol fixtures as Synoptikon.
- Upgrade and backup procedures are documented.

## Exit gate

Pistis has an independent release artefact and integration surface.

---

# Milestone M9 — Local-network discovery and direct exchange

**Objective:** Remove routine QR response scanning when the phone and installation can communicate on the same local network.

**Estimated effort:** 4 developer-weeks

## Work items

### M9.1 Discovery design

Decide which endpoint advertises:

- the installation advertises a temporary approval service; or
- the phone advertises availability; or
- both.

The preferred privacy-preserving model is for the installation to advertise a short-lived, non-user-specific service. The phone discovers it only after scanning an initial pairing/login QR or selecting the installation.

Do not broadcast:

- username;
- external identity;
- public profile;
- report title;
- project name;
- persistent device identifier.

### M9.2 DNS-SD/mDNS implementation

Rust service:

- advertise `_pistis._tcp.local` or approved service name;
- include protocol version and opaque endpoint identifier;
- handle multiple interfaces;
- handle interface changes;
- handle sleep/wake;
- apply TTL;
- unregister cleanly;
- tolerate multicast being blocked.

Mobile:

- local network permission on iOS;
- network service discovery on Android;
- scoped browsing;
- endpoint resolution;
- UX explaining permission;
- fallback when permission denied.

### M9.3 Pairwise secure channel

Discovery must lead to an authenticated channel.

Options include:

- installation HTTPS certificate pinned from QR/pairing;
- ephemeral key agreement authenticated by installation identity;
- signed challenge submission over untrusted HTTP with confidentiality limitations documented.

The selected design must prevent endpoint substitution and must not trust the local CA environment by default.

### M9.4 Direct challenge retrieval

After discovery:

- phone retrieves pending challenge;
- phone checks exact installation identity;
- phone signs;
- phone posts response;
- browser receives completion event.

### M9.5 Fallback hierarchy

```text
paired local endpoint reachable
        ↓ no
QR direct endpoint reachable
        ↓ no
response QR
```

No indefinite “searching” state.

### M9.6 Browser limitations

A normal browser cannot directly perform arbitrary mDNS discovery. Synoptikon’s backend therefore performs discovery advertisement and receives the phone response; browser state is updated by polling, SSE or WebSocket.

Document this explicitly to prevent an impossible browser-only design.

## Deliverables

- `pistis-discovery`;
- discovery protocol;
- iOS local-network implementation;
- Android discovery implementation;
- secure channel design;
- network test suite.

## Acceptance criteria

- Local login can complete without scanning a response QR where multicast and direct connectivity are available.
- Authentication remains secure when an attacker publishes a conflicting mDNS service.
- Blocking multicast causes clean fallback to QR.
- Discovery advertisements disclose no user identity.
- Multiple Pistis installations on one LAN are distinguishable.
- IPv4, IPv6 and multiple-interface behaviour are tested.
- Guest Wi-Fi client isolation is handled as an expected fallback condition.

## Exit gate

Local-network direct exchange is a convenience layer with no change to verifier semantics.

---

# Milestone M10 — Artefact/report signing and portable evidence

**Objective:** Extend the authentication primitive into durable scientific artefact approval.

**Estimated effort:** 4 developer-weeks

## Work items

### M10.1 Artefact digest model

Support:

- SHA-256;
- file size;
- media type;
- artefact identifier;
- version;
- generation time;
- workflow/provenance references;
- digest computed after finalisation.

### M10.2 Signing claims

Define initial claim types:

- `auth.login`;
- `report.reviewed`;
- `report.approved`;
- `dataset.released`;
- `workflow.approved`;
- `software.release-approved`;
- generic `artefact.attested`.

Each claim must state its semantics. “Signed” alone is insufficient.

### M10.3 Mobile signing UX

Display:

- action;
- artefact title;
- artefact ID;
- digest abbreviation;
- installation;
- local role/capacity;
- requested declaration;
- expiry.

The app must not display metadata that is not included in, or cryptographically bound to, the signed payload.

### M10.4 Evidence envelope

Include:

- canonical claim;
- artefact digest;
- signer external identity;
- local user;
- local signing capacity;
- device key;
- installation;
- policy;
- signature;
- signing time claim;
- verification metadata;
- revocation/status references;
- protocol version.

### M10.5 Verification CLI and library

Verifier output:

- content digest match;
- cryptographic signature valid/invalid;
- device key trusted/untrusted;
- device status at signing;
- external identity binding valid/invalid;
- local capacity evidence;
- policy status;
- warnings;
- inability to establish trusted time.

### M10.6 PDF integration boundary

Pistis should generate detached evidence by default. Grammateus may embed:

- document ID;
- signature ID;
- QR verification reference;
- visible approval summary.

The authoritative cryptographic evidence remains detached or embedded as a clearly specified attachment, avoiding accidental PDF mutation after signing.

### M10.7 Multi-signature primitives

Implement evidence structures capable of carrying multiple independent signatures, even if sophisticated workflow policy remains limited.

## Deliverables

- artefact claim schemas;
- evidence envelope;
- signer UI;
- verifier CLI;
- Grammateus integration example;
- signed fixture corpus.

## Acceptance criteria

- Any byte change to a signed artefact is detected.
- Evidence can be verified offline.
- The verifier differentiates cryptographic validity from scientific correctness and organizational authorization.
- Login signatures cannot satisfy report-approval claims.
- Visible metadata shown to the signer is cryptographically bound to the signature.
- Historic evidence remains verifiable after normal device retirement.
- Multi-signature envelopes do not require signatures to be merged into a mutable structure that invalidates prior signatures.

## Exit gate

A sample scientific report can be signed on iOS and verified using only the report, detached evidence and exported installation trust material.

---

# Milestone M11 — Android application

**Objective:** Deliver functional parity for the Pistis v1.0 ceremonies on supported Android devices.

**Estimated effort:** 7 developer-weeks

## Work items

### M11.1 Application shell

Implement in Kotlin/Jetpack Compose:

- onboarding;
- identities;
- installations;
- scanner;
- pending action;
- approval;
- response QR;
- history;
- device/security status;
- diagnostics.

### M11.2 Android Keystore key generation

- non-exportable signing key;
- require user authentication;
- prefer hardware-backed storage;
- detect security level;
- capture StrongBox/TEE/software status;
- handle devices without required capabilities;
- public-key extraction;
- key invalidation;
- app reinstall behaviour;
- no silent downgrade.

### M11.3 BiometricPrompt

- biometric/device credential policy;
- `CryptoObject`-bound signing where appropriate;
- cancellation;
- lockout;
- fallback;
- evidence assurance metadata;
- explicit failure messaging.

### M11.4 External provider enrolment

Implement GitHub and Google system-browser flows with the same protocol and evidence semantics as iOS.

### M11.5 QR and local-network support

- camera scanning;
- Android app links where used;
- response QR;
- local network discovery;
- network changes;
- battery/background constraints;
- notification permissions not required for v1.0 core.

### M11.6 Device capability policy

Define support tiers, for example:

```text
PST-A3: hardware-backed key, strong biometric, validated attestation
PST-A2: hardware-backed key, device credential or biometric
PST-A1: software-backed or unverified key
```

v1.0 must state which tiers can:

- authenticate;
- sign reports;
- perform administrator approval.

### M11.7 Key attestation decision

Implement or explicitly defer full Android hardware-key attestation.

If included:

- validate attestation chain server-side;
- pin/maintain accepted roots;
- bind challenge to key generation;
- handle revocation and known device anomalies.

If deferred:

- record hardware-backed status as locally reported and avoid overstating assurance.

### M11.8 Device test matrix

At minimum:

- current Google Pixel;
- current Samsung flagship/mid-range;
- one lower-cost supported device;
- minimum supported API level;
- device with StrongBox;
- device without StrongBox;
- fingerprint;
- supported face biometric where available;
- work-profile behaviour if in scope.

### M11.9 Distribution

- Play Console;
- application signing;
- internal testing;
- closed testing;
- data safety declaration;
- release track;
- crash reporting;
- reproducible build documentation.

## Deliverables

- Android application;
- Play internal/closed testing release;
- Android security design;
- device capability matrix;
- conformance-test report.

## Acceptance criteria

- Android-generated signatures verify identically through the Rust verifier.
- No private key export path exists.
- Unsupported or insecure device configurations receive an explicit result, not silent fallback.
- GitHub and Google enrolment semantics match iOS.
- QR response and local-network direct exchange work on the supported test matrix.
- Evidence truthfully reports key assurance.
- App reinstall produces a new device identity and requires re-enrolment.
- Android v1.0 feature parity covers all mandatory ceremonies, though UI need not be pixel-identical.

## Exit gate

Both mobile platforms pass the shared protocol conformance suite.

---

# Milestone M12 — Recovery, revocation and multi-device lifecycle

**Objective:** Ensure passwordless operation remains supportable when devices are lost, replaced or compromised.

**Estimated effort:** 3 developer-weeks

## Work items

### M12.1 Multi-device enrolment

Allow a local user to enrol multiple devices subject to local policy.

Record each as a distinct key and device identity.

### M12.2 Device replacement

Supported route:

- authenticate with an existing trusted device; or
- reauthenticate against the required external trust anchor and complete installation-controlled recovery approval; or
- perform governed local administrator recovery.

No automatic private-key migration.

### M12.3 Revocation

Support:

- user-requested lost device;
- administrator revocation;
- compromise;
- retirement;
- replacement;
- temporary suspension.

### M12.4 Historic evidence semantics

Verification must distinguish:

- key valid at signing;
- key currently revoked;
- revocation reason;
- signing time independently trusted or merely claimed;
- policy treatment of compromise.

### M12.5 Bootstrap recovery

Document a controlled server-console recovery process for a sole administrator who loses all Pistis devices.

Requirements:

- local machine privileged access;
- explicit recovery command;
- audit event;
- recovery token or ceremony;
- old devices revoked;
- no unaudited database edit;
- optional delay/two-person procedure for institutional deployments.

### M12.6 External identity loss

Handle:

- deleted GitHub account;
- inaccessible Google account;
- organization policy change;
- provider outage;
- changed display metadata.

Existing device signatures may continue according to local policy, but new recovery/rebinding must follow explicit rules.

## Deliverables

- recovery protocol;
- revocation schema;
- admin commands/UI;
- support runbook;
- historic-verification rules.

## Acceptance criteria

- Loss of one phone does not force a password reset mechanism.
- A revoked device cannot create new valid approvals.
- Existing valid evidence is not indiscriminately destroyed by normal retirement.
- Sole-administrator recovery is possible but conspicuous and auditable.
- Recovery cannot silently replace the external identity trusted for a local account.
- All lifecycle transitions are covered by integration tests.

## Exit gate

A full lost-device exercise is completed for both iOS and Android.

---

# Milestone M13 — Security hardening and independent review

**Objective:** Validate that Pistis can safely protect scientific-computing installations and signed artefacts.

**Estimated effort:** 5 developer-weeks

## Work items

### M13.1 Code hardening

- dependency review;
- unsafe-code review;
- secret-zeroisation where relevant;
- logging review;
- panic handling;
- resource limits;
- rate limiting;
- input size limits;
- secure default configuration;
- production error redaction.

### M13.2 Protocol attack tests

Test:

- replay;
- downgrade;
- cross-purpose signatures;
- cross-installation signatures;
- race consumption;
- malformed QR;
- malicious CBOR/JSON;
- signature malleability handling;
- key-ID collision handling;
- expired challenge;
- clock skew;
- mDNS spoofing;
- local endpoint substitution;
- OAuth/OIDC callback attacks;
- CSRF;
- open redirect;
- token leakage.

### M13.3 Mobile security review

iOS:

- Keychain/Secure Enclave configuration;
- LocalAuthentication policy;
- URL callback handling;
- clipboard;
- screenshots;
- logs;
- backups;
- app groups;
- jailbreak response policy.

Android:

- Keystore policy;
- BiometricPrompt binding;
- exported activities;
- deep links;
- backup configuration;
- rooted-device response policy;
- logs;
- intent spoofing;
- WebView avoidance.

### M13.4 Privacy review

Document data collected:

- provider subject;
- display metadata;
- device metadata;
- authentication events;
- IP/user agent on server;
- local phone history.

Provide retention and deletion behaviour.

### M13.5 Independent penetration test

Scope:

- Rust service;
- Synoptikon integration;
- iOS app;
- Android app;
- QR protocol;
- local discovery;
- provider enrolment.

Classify and remediate findings.

### M13.6 Cryptographic review

Independent review must confirm:

- selected algorithms;
- canonicalisation;
- domain separation;
- nonce generation;
- signature encoding;
- key identifiers;
- verifier status rules;
- evidence semantics.

### M13.7 Security incident readiness

- vulnerability disclosure;
- key compromise response;
- mobile app emergency release;
- compromised dependency response;
- protocol version revocation;
- operator notification route.

## Deliverables

- hardened release branch;
- penetration-test report;
- remediation report;
- cryptographic review;
- privacy assessment;
- incident runbook;
- residual-risk register.

## Acceptance criteria

- No open critical or high-severity security findings.
- Medium findings have accepted remediation plans and owners.
- Secrets and provider tokens do not appear in normal logs.
- All protocol attack tests are automated where practical.
- Security defaults do not require operator opt-in.
- Rust, iOS and Android release artefacts are traceable to reviewed source commits.
- Threat model is updated to reflect implementation reality.

## Exit gate

Security owner approves progression to release candidate.

---

# Milestone M14 — Packaging, operations and documentation

**Objective:** Make Pistis installable, diagnosable, upgradeable and supportable.

**Estimated effort:** 3 developer-weeks

## Work items

### M14.1 Release packaging

- Rust binaries;
- Rust library crates;
- RPM/SRPM;
- container image only where required;
- iOS archive;
- Android bundle;
- SBOM;
- checksums;
- signatures;
- provenance.

### M14.2 Configuration reference

Document:

- installation identity;
- trust policies;
- database;
- challenge lifetime;
- clock-skew policy;
- local discovery;
- TLS;
- device assurance;
- audit;
- recovery;
- feature flags.

### M14.3 Operations

Provide:

- health endpoint;
- readiness endpoint;
- metrics;
- structured logs;
- database migration;
- backup;
- restore;
- key rotation;
- device-revocation procedure;
- discovery diagnostics;
- OIDC diagnostics.

### M14.4 `pistis doctor`

Check:

- clock;
- installation identity;
- database;
- migrations;
- TLS;
- mDNS interfaces;
- provider discovery;
- callback URLs;
- trust policies;
- unsupported algorithms;
- audit sink;
- mobile reachability hints.

### M14.5 User documentation

- enrol GitHub;
- enrol Google;
- pair installation;
- login by QR;
- login on local network;
- sign report;
- replace phone;
- revoke lost phone;
- understand warnings.

### M14.6 Developer documentation

- embedding API;
- challenge lifecycle;
- verifier API;
- provider adapter;
- transport adapter;
- test fixtures;
- version negotiation;
- sample integration.

## Deliverables

- operator guide;
- user guide;
- API reference;
- architecture guide;
- troubleshooting guide;
- release packages;
- SBOM and provenance.

## Acceptance criteria

- A clean supported host can install and bootstrap Pistis from released packages.
- Upgrade from the previous release candidate preserves devices and evidence.
- Backup/restore exercise succeeds.
- `pistis doctor` diagnoses common discovery and provider failures.
- Synoptikon and Monas integration examples are reproducible from documentation.
- Mobile-store submission material is complete.

## Exit gate

Release candidate can be deployed by someone outside the core engineering team using only the documentation.

---

# Milestone M15 — Release candidate and v1.0 acceptance

**Objective:** Demonstrate that the complete v1.0 meets product, interoperability, security and operational requirements.

**Estimated effort:** 2 developer-weeks

## Work items

### M15.1 Freeze protocol v1

- freeze schemas;
- freeze signature suites;
- freeze canonical encoding;
- assign protocol version;
- publish compatibility policy;
- prohibit unreviewed changes.

### M15.2 End-to-end acceptance matrix

Run each scenario on iOS and Android:

1. GitHub enrolment.
2. Google enrolment.
3. Synoptikon administrator bootstrap.
4. Synoptikon login by QR.
5. Synoptikon login by local direct exchange.
6. Monas standalone login.
7. Report signing.
8. Offline evidence verification.
9. Multi-device enrolment.
10. Device suspension.
11. Device revocation.
12. Lost-device recovery.
13. Provider display-name change.
14. Installation backup/restore.
15. Upgrade from release candidate.
16. Multicast blocked fallback.
17. Wrong identity rejection.
18. Replay rejection.
19. Expired challenge rejection.
20. Installation fingerprint-change warning.

### M15.3 Performance and usability targets

Suggested targets:

- challenge creation: under 100 ms excluding storage contention;
- signature verification: under 100 ms on supported server hardware;
- QR scan to approval screen: under 2 seconds under normal conditions;
- local direct response after approval: under 2 seconds on normal LAN;
- authentication flow: normally under 20 seconds for an enrolled user;
- no unbounded challenge-store growth;
- no material battery drain from passive discovery.

These are acceptance targets, not protocol guarantees.

### M15.4 Compatibility declaration

Publish:

- supported iOS versions/devices;
- supported Android versions/security tiers;
- supported browsers;
- supported Synoptikon version;
- supported Monas embedding API;
- supported database versions;
- unsupported environments.

### M15.5 Release approval

Require signed approvals from:

- product owner;
- Rust/backend owner;
- iOS owner;
- Android owner;
- Synoptikon owner;
- security reviewer;
- release manager.

Pistis should use its own artefact-signing capability to sign the v1.0 release evidence where practical.

## Deliverables

- v1.0 release notes;
- protocol v1 specification;
- compatibility matrix;
- acceptance report;
- signed release artefacts;
- known limitations;
- migration guide;
- public security contact.

## Acceptance criteria

Pistis v1.0 is complete only when all of the following are true:

- Synoptikon supports passwordless Pistis administrator bootstrap and login.
- Monas can consume Pistis independently.
- GitHub and Google external identities can be enrolled.
- iOS and Android clients pass the same protocol conformance suite.
- Routine authentication requires no central Pistis service.
- QR authentication functions without public internet after enrolment.
- Local-network direct exchange has a reliable QR fallback.
- Device revocation is immediate for new approvals.
- Signed report evidence can be verified offline.
- No open critical/high security defects remain.
- Operator, recovery and user documentation is complete.
- Reproducible release artefacts, SBOMs and checksums are published.
- Protocol v1 is frozen and versioned.

## Exit gate

Tag and publish `v1.0.0`.

---

# 7. Cross-cutting engineering requirements

These requirements apply to every milestone.

## 7.1 Testing

Required test layers:

- Rust unit tests;
- property tests;
- protocol fixtures;
- fuzzing;
- database integration tests;
- browser integration tests;
- iOS unit/UI tests;
- Android unit/instrumentation tests;
- cross-language conformance tests;
- end-to-end tests;
- recovery exercises;
- upgrade tests;
- negative security tests.

Every bug in protocol validation should produce a permanent regression fixture.

## 7.2 Observability

Structured events must include correlation identifiers but must not leak:

- provider tokens;
- full ID tokens;
- private keys;
- raw biometric information;
- sensitive report contents;
- complete response QR payloads at normal log levels.

## 7.3 Versioning

Maintain distinct versions for:

- protocol;
- evidence schema;
- Rust crate APIs;
- server application;
- mobile applications;
- database schema.

A mobile app and server must negotiate protocol support explicitly.

## 7.4 Clock handling

Challenges use server-issued times and bounded expiry. The phone may display time based on its local clock but must not establish authoritative validity from that clock alone.

Allow configurable small skew; never accept unbounded expiry.

## 7.5 Accessibility

QR is not the only explanation of the task. Provide text and assistive-technology descriptions.

Core approval buttons and identity details must be accessible.

## 7.6 Internationalisation

v1.0 may ship English-only, but strings must not be hard-coded into protocol payloads or domain logic. Human-readable display fields should be separable from canonical machine semantics.

## 7.7 Privacy

Collect the minimum provider data needed to establish identity. Avoid retaining GitHub/Google access tokens after enrolment.

## 7.8 Supply-chain integrity

- dependency allow-list;
- locked dependencies;
- SBOM;
- signed build artefacts;
- CI provenance;
- mobile signing-key governance;
- reproducible Rust builds where practical.

---

# 8. Dependency graph

```text
M0
└── M1
    └── M2
        ├── M3
        │   └── M6
        ├── M4
        │   ├── M5
        │   │   ├── M7
        │   │   ├── M8
        │   │   └── M9
        │   └── M12
        └── M10
            └── M6 / M11 UI support

M6 + M7 + M8 + M9 + M10
└── M11
    └── M12
        └── M13
            └── M14
                └── M15
```

Parallelisation notes:

- iOS UI shell can begin during M2, but signing integration waits for M1/M2.
- Synoptikon UI preparation can begin during M4.
- Android application shell may begin before M10, but protocol parity depends on frozen fixtures.
- Documentation should be written continuously rather than deferred entirely to M14.
- Security review should begin during M1 and M2; M13 is the final hardening gate, not the first security activity.

---

# 9. Recommended implementation sequence by release

## Prototype 0.1

- Rust challenge and verifier;
- software test key;
- QR round trip;
- no external provider;
- no production mobile app.

## Developer Preview 0.2

- GitHub and Google enrolment;
- iOS test app;
- local registry;
- QR login;
- standalone reference server.

## Synoptikon Alpha 0.3

- administrator bootstrap;
- Synoptikon session integration;
- device administration;
- audit.

## iOS MVP 0.5

- production-shaped iOS app;
- GitHub/Google;
- QR login;
- basic report signing;
- Monas CLI;
- recovery documentation.

## Cross-platform Beta 0.8

- Android app;
- local-network discovery;
- direct response;
- multi-device lifecycle;
- detached evidence.

## Release Candidate 1.0.0-rc.1

- security hardening;
- penetration-test remediation;
- packaging;
- compatibility freeze;
- documentation.

## v1.0.0

- acceptance matrix passed;
- protocol frozen;
- mobile releases approved;
- signed release artefacts.

---

# 10. Principal risks and mitigations

| Risk | Consequence | Mitigation |
| --- | --- | --- |
| Treating mutable usernames/emails as identity | Account misbinding | Store stable provider subjects |
| Divergent iOS/Android canonical encoding | Cross-platform verification failure | Shared normative fixtures and byte-level tests |
| Secure Enclave/Keystore capability mismatch | Inconsistent assurance | Select common signature suite and report capability truthfully |
| mDNS blocked by enterprise networks | Poor convenience | QR fallback is mandatory |
| Browser expected to discover mDNS directly | Unimplementable UX | Backend advertises/receives; browser observes state |
| Lost sole-admin phone | Installation lockout | Audited console recovery and second-device recommendation |
| Provider outage | New enrolment unavailable | Routine login remains local |
| Compromised external account after enrolment | Recovery risk | Local device remains separate; rebinding requires explicit policy |
| Stolen unlocked phone | Unauthorized signing | Per-signature biometric/device authentication |
| Key invalidation after biometric changes | User lockout | Clear re-enrolment and recovery flow |
| Local database tampering | Trust substitution | audit sealing, OS controls, exported verification material, future transparency option |
| QR phishing/substitution | Approval of wrong installation | display installation identity/fingerprint and sign exact installation ID |
| Protocol scope expansion | Project becomes IAM platform | enforce v1.0 non-goals |
| App-store delays | Release slip | TestFlight/Play internal tracks early |
| Android device fragmentation | Unsupported assurance | explicit device tiers and test matrix |
| Legal overstatement of signatures | Compliance exposure | describe cryptographic attestation accurately; no legal equivalence claim |

---

# 11. Definition of done for every milestone

A milestone is not complete until:

- code is merged;
- tests are automated;
- user/operator behaviour is documented;
- security implications are reviewed;
- errors and failure states are implemented;
- metrics/logging are present where operationally relevant;
- database migration and rollback implications are known;
- compatibility fixtures are updated;
- acceptance criteria have recorded evidence;
- no critical TODO remains hidden in code comments.

---

# 12. Deferred post-v1.0 backlog

Likely post-v1.0 work includes:

- APNs and FCM remote push relay;
- ORCID;
- Microsoft Entra ID;
- Apple identity;
- institutional generic OIDC configuration;
- hardware attestation strengthening;
- trusted timestamp service;
- transparency anchoring;
- formal delegated authority;
- richer multi-person policy engine;
- Apple Watch/Wear OS approval;
- NFC;
- SSH-agent integration;
- Kubernetes admission approval;
- software-release signing;
- public verification portal;
- encrypted phone-to-phone recovery transfer;
- regulated-signature profiles;
- organisation-managed mobile deployment;
- global Pistis identity continuity, only if a clear requirement emerges.

None of these should be allowed to delay v1.0 unless a security review establishes that omission would make the baseline unsafe.

---

# 13. Reference implementation technologies

The following are current implementation candidates rather than mandatory dependencies:

## Rust

- `axum`
- `tokio`
- `serde`
- `openidconnect`
- `sha2`
- `p256`
- `coset`
- `ciborium`
- `qrcode`
- `mdns-sd`, `simple-mdns`, or an OS-native DNS-SD abstraction
- `rustls`
- `sqlx`
- `tracing`
- `thiserror`
- `zeroize`
- `proptest`
- `cargo-fuzz`

## iOS

- Swift
- SwiftUI
- Security framework
- CryptoKit where suitable
- LocalAuthentication
- AuthenticationServices
- AVFoundation for QR scanning
- Network framework / Bonjour APIs

## Android

- Kotlin
- Jetpack Compose
- Android Keystore
- BiometricPrompt
- AppAuth or platform-compatible OAuth/OIDC flow
- CameraX / ML Kit or a selected QR library
- Network service discovery APIs

Dependency selection must occur through an ADR and security/maintenance review. Crate or platform availability alone is not sufficient justification.

---

# 14. Source notes

The implementation plan assumes established platform capabilities:

- Apple’s LocalAuthentication framework provides the system interface for Face ID and Touch ID-gated operations.
- Apple’s Security/CryptoKit APIs provide device-protected cryptographic-key operations, subject to the selected key type and platform capabilities.
- Android Keystore supports application-scoped cryptographic keys and reports hardware-backed characteristics.
- Android BiometricPrompt provides a system biometric authentication dialog and can bind authentication to cryptographic operations.
- OpenID Connect supplies a verifiable identity layer over OAuth 2.0; Google provides an OpenID Connect implementation.
- Rust’s `openidconnect` crate provides strongly typed OpenID Connect interfaces.
- Rust mDNS/DNS-SD crates exist, but the project must evaluate pure-Rust versus operating-system-native discovery stacks.

Authoritative/current references consulted during planning:

- Apple LocalAuthentication: https://developer.apple.com/documentation/localauthentication
- Apple Keychain access with Face ID/Touch ID: https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id
- Android Keystore: https://developer.android.com/privacy-and-security/keystore
- Android biometric authentication: https://developer.android.com/identity/sign-in/biometric-auth
- Google OpenID Connect: https://developers.google.com/identity/openid-connect/openid-connect
- OpenID Connect Core: https://openid.net/specs/openid-connect-core-1_0.html
- Rust `openidconnect`: https://docs.rs/openidconnect
- Rust `mdns-sd`: https://docs.rs/mdns-sd
- Rust `simple-mdns`: https://docs.rs/simple-mdns

---

# 15. Final v1.0 boundary

Pistis v1.0 is successful when it provides a small, auditable and independently reusable trust layer—not when it reproduces Okta, Auth0 or Keycloak.

The final v1.0 architecture must preserve this division:

```text
GitHub or Google
    proves control of an external identity during enrolment

Pistis mobile application
    protects a device key and signs explicit challenges

Synoptikon or Monas
    defines the local account, permissions and requested action

Rust Pistis verifier
    validates the cryptographic evidence

QR/local network
    transports the challenge and response

Local installation
    remains sovereign and operable without a central Pistis service
```

This boundary is the primary mechanism for controlling development scope and retaining the conceptual simplicity that makes Pistis distinctive.
