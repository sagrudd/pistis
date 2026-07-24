# Project Charter --- Pistis

**Status:** Draft Charter v0.1\
**Project:** Pistis\
**Language:** Rust (core services and libraries)

------------------------------------------------------------------------

# 1. Vision

Pistis is a **portable cryptographic trust and attestation system**
designed for scientific computing.

Unlike conventional identity providers, Pistis does **not** own user
identities. Instead, it binds trusted external identities (initially
GitHub and Google) to hardware-backed device credentials and produces
durable, verifiable evidence of human approval.

Pistis is intended to become the trust layer underpinning
authentication, report signing, workflow approval and governance
throughout the Mnemosyne ecosystem while remaining usable as a
standalone open system.

------------------------------------------------------------------------

# 2. Scope

Pistis shall:

-   prove control of trusted external identities;
-   authenticate users through cryptographic challenge/response;
-   generate durable approval evidence;
-   support offline and air-gapped operation;
-   operate without requiring a central identity server;
-   expose clean Rust APIs and CLI tooling.

Pistis shall **not**:

-   become a general enterprise IAM platform;
-   replace GitHub, Google or institutional identity providers;
-   maintain user passwords;
-   require cloud infrastructure for normal operation.

------------------------------------------------------------------------

# 3. Guiding Principles

1.  Local-first.
2.  Cryptography over shared secrets.
3.  Evidence over sessions.
4.  Portable and verifiable artefacts.
5.  Minimal infrastructure.
6.  Human-readable audit trails.
7.  Open standards wherever practical.

------------------------------------------------------------------------

# 4. Primary Use Cases

-   Browser login approval.
-   Scientific report signing.
-   Dataset publication approval.
-   Workflow release.
-   Software release approval.
-   Administrative approval.
-   Multi-person governance approval.

------------------------------------------------------------------------

# 5. Architecture

## Trust Anchors

Initial MVP:

-   GitHub
-   Google

Future:

-   ORCID
-   Microsoft Entra ID
-   Apple
-   Institutional OIDC providers

Trust anchors establish identity **once**. Pistis subsequently proves
possession of the enrolled device credential.

## Device

MVP:

-   iOS
-   Secure Enclave
-   Face ID / Touch ID

Version 1.0:

-   Android
-   Android Keystore
-   BiometricPrompt

## Communication

Priority order:

1.  Local discovery (mDNS)
2.  QR code
3.  Optional remote notification (future)

Authentication is always challenge/response using signed nonces.

------------------------------------------------------------------------

# 6. Deployment Modes

## Embedded

Integrated into Mnemosyne Synoptikon.

Responsibilities:

-   login approval
-   report signing
-   workflow approval

## Standalone (Monas)

Monas deployments may consume Pistis as an independent trust service
without requiring Synoptikon.

------------------------------------------------------------------------

# 7. Technology

Core implementation:

-   Rust
-   Axum
-   Rustls
-   Serde
-   CBOR
-   Ed25519
-   SHA-256

Expected ecosystem:

-   openidconnect
-   ed25519-dalek
-   coset
-   ciborium
-   qrcode
-   mdns-sd

Native applications:

-   Swift / SwiftUI (MVP)
-   Kotlin / Jetpack Compose (v1.0)

------------------------------------------------------------------------

# 8. MVP Deliverables

## Backend

-   Device enrolment
-   GitHub authentication
-   Google authentication
-   Challenge generation
-   Challenge verification
-   Signature verification
-   Local evidence store
-   Audit trail
-   REST API

## iOS

-   Identity enrolment
-   Secure Enclave key generation
-   Face ID approval
-   QR scanning
-   Approval history
-   Device management

## Synoptikon Integration

-   Login approval
-   User enrolment
-   Local trust policy

## Monas Integration

-   Standalone authentication
-   CLI verification
-   Detached evidence generation

------------------------------------------------------------------------

# 9. Version 1.0

-   Android application
-   Local network discovery (mDNS)
-   Multiple identities per device
-   Multi-device support
-   Report signing
-   Workflow approval
-   Multi-signature approval
-   Verification CLI
-   Rust verification library

------------------------------------------------------------------------

# 10. Future Roadmap

-   ORCID
-   Microsoft Entra
-   Apple Sign In
-   NFC transport
-   APNs / FCM convenience notifications
-   Transparency log
-   Trusted timestamping
-   Delegated authority
-   Professional identity assertions

------------------------------------------------------------------------

# 11. Deliverables

-   Rust workspace
-   REST API
-   CLI
-   iOS application (MVP)
-   Android application (v1.0)
-   Verification library
-   Documentation
-   Architecture diagrams
-   Security review
-   Threat model

------------------------------------------------------------------------

# 12. Success Criteria

Pistis shall demonstrate that:

-   no passwords are required;
-   no central identity server is required;
-   authentication succeeds using GitHub and Google trust anchors;
-   login approval works through QR challenge/response;
-   report signatures produce portable evidence;
-   evidence can be verified independently of the originating
    installation;
-   the same protocol supports Synoptikon and standalone Monas
    deployments.

------------------------------------------------------------------------

# 13. Non-Goals

-   Enterprise directory replacement.
-   Password management.
-   SAML implementation in MVP.
-   Cloud-hosted identity platform.
-   Custom cryptographic algorithms.

------------------------------------------------------------------------

# 14. Long-Term Vision

Pistis will become the trust foundation for the Mnemosyne ecosystem.

Rather than acting solely as an authentication component, it will
provide a reusable cryptographic evidence layer capable of supporting
authentication, approval, report signing, software release, scientific
governance and durable provenance across both integrated Mnemosyne
products and independent third-party applications.
