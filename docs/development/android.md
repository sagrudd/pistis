# Android development

The Android source is a hierarchical Gradle project under `android/`.
ADR 0008 is normative for architecture, platform security, evidence claims,
dependencies, design adaptation, and release boundaries.

The Compose shell displays the unmodified approved Mnemosyne Biosciences
light-surface lock-up from the `mnemosyne_design_language` branding contract.
Keep it on a light surface; do not recolour, redraw, crop, or use it as a
control.

## Module direction

- `core:model` contains validated domain values.
- `core:ceremony` contains deterministic approval state transitions.
- `core:evidence` contains informational local evidence.
- `platform:security` contains Android Keystore and biometric adapters.
- `app` contains the Compose shell and composition root.

Core modules do not depend on Android, Compose, cameras, browsers, networks, or
public services. Platform and presentation code depend inward. Do not add
generic utility modules or move cryptographic/protocol decisions into a
ViewModel or composable.

## Toolchain

The reviewed baseline is:

- JDK 17;
- Gradle 9.5.0 through the checked-in wrapper;
- Android Gradle Plugin 9.3.0;
- compile and target API 36;
- minimum API 31; and
- Compose BOM 2026.06.00.

Use the wrapper and an Android SDK containing platform and Build Tools 36:

```sh
cd android
./gradlew --no-daemon check lintDebug testDebugUnitTest assembleDebug
```

Do not accept dynamic dependency versions, project-local repositories,
unverified wrapper distributions, or undocumented SDK upgrades.

## Test boundaries

Pure JVM tests use fixed time and entropy and make no public-network request.
They cover identity substitution, trust changes, approval fact separation,
background cancellation, OAuth callbacks, local history, DER conversion, and
hardware-capability policy.

Compose tests assert semantics and claim honesty. Emulator tests demonstrate
Android integration but do not prove StrongBox, trusted-environment storage,
biometric strength, or attestation.

Real-device acceptance requires the M11 matrix: Pixel, Samsung, a supported
lower-cost device, StrongBox and non-StrongBox paths, fingerprint and supported
face/device-credential paths, reinstall, key invalidation, network change, and
camera behavior. Record device model, OS and patch level, security level,
authentication type, source revision, and result without collecting personal
device data.

## Jenkins

Ordinary builds run in a digest-pinned Android SDK/JDK container and receive no
Play credentials or `/dev/kvm`. Instrumented emulator work requires a separate
reviewed KVM-enabled Jenkins worker and approved task. Physical-device
acceptance is retained separately.

PR jobs build debug or unsigned release artifacts only. A future protected
release task must bind an exact reviewed `main` or tag to isolated upload-key
and Play credentials.

## Claims

Do not describe a key as hardware-backed merely because Android Keystore
contains it. `KeyInfo` is a locally reported capability. Remote attestation
requires server-side chain and policy verification. A displayed response QR is
not delivered, a human approval is not a signature, and a signature is not
server acceptance.
