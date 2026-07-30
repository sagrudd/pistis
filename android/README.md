# Pistis for Android

This directory contains the EPIC-8 Android source foundation:

- pure Kotlin model, ceremony, and evidence modules;
- a native Jetpack Compose application shell;
- Android Keystore and BiometricPrompt security adapters; and
- deterministic JVM and Android test sources.

Read [ADR 0008](../docs/adr/0008-android-reference-application.md) before
changing security, dependencies, provider authentication, protocol behaviour,
or product presentation.

Run repository checks with the pinned wrapper:

```sh
cd android
./gradlew --no-daemon check lintDebug testDebugUnitTest assembleDebug
```

The package intentionally contains no Play credential, upload key, provider
client secret, provider token, analytics SDK, or production personal data.
Debug/emulator evidence does not prove StrongBox, hardware-backed security,
biometric assurance, attestation, signing, or Play distribution.

Keeper participation is system-mediated: GitHub asks the external browser for
its passkey and Android may offer Keeper. Pistis never reads Keeper vault
contents or passkeys.
