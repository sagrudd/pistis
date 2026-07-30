---
orphan: true
---

# iOS interoperability evidence record

This template records a physical-device EPIC-18 ceremony. A completed copy is
evidence only after independent Rust verification, review, and retention by
the authoritative Jenkins Expedition. Simulator output cannot complete this
record.

Do not record private-key material, biometric data, device serial numbers,
Apple credentials, provisioning secrets, complete challenge nonces, or
production personal data.

## Immutable build identity

- Pistis source revision:
- COSE fixture-set digest:
- Jenkins Expedition identifier:
- Xcode version and build:
- iOS version:
- application bundle identifier:
- signing certificate fingerprint:

## Device and key observation

- Device model class (no serial number):
- Secure Enclave reported available: yes / no
- Face ID enrolled before key creation: yes / no
- Compressed SEC1 public-key fixture path:
- Derived Pistis key identifier:
- COSE `Sig_structure` fixture path:
- Raw low-S ES256 signature fixture path:

## Ceremony observations

- Fresh Face ID prompt appeared for signing: pass / fail
- Cancellation produced no signature: pass / fail
- A second operation required a fresh prompt: pass / fail
- Biometry-set change invalidated the prior key: pass / fail / not exercised
- Missing or invalidated key required explicit re-enrolment: pass / fail
- No software-key fallback was observed: pass / fail

## Independent verification

- Rust verifier revision:
- Exact fixture verified: pass / fail
- Wrong key rejected: pass / fail
- Changed payload rejected: pass / fail
- High-S or DER representation rejected: pass / fail
- Reviewer and review date:

## Retention

- Redacted evidence archive digest:
- Jenkins dossier artefact:
- Owner acceptance reference:
- Deviations or follow-up issues:
