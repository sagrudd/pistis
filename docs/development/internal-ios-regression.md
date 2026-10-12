# Internal Pistis iOS regression harness

This is a developer-only source test of first-device onboarding and ordinary
login. It is embedded in the existing Pistis checkout; it has no separately
distributed package, registered identity, trust authority or production route.
`pistis-qr` 0.1.2 owns the **dev-only** PNG decoder and fixture examples. Its
existing encoder remains `qrcode 0.14.1` with default features disabled.
`PistisCore` supplies the actual Swift presentation, binding, COSE and receipt
verification. No product verifier, native coordinator or iOS release build is
modified.

Run `ios/RegressionHarness/run-source-regressions.sh` in a clean checkout at
the committed candidate head. The companion `ios/RegressionHarness/recipe.json` pins the
selected parent and records the old manifest/catalogue digests as **references
only**: their files were not supplied to this environment, and the old recipe
does not cover this harness. The runner prints the actual candidate commit,
tree, lock blob/SHA-256 and new recipe SHA-256. Its checks use Rust 1.94,
Swift 6 on Linux, Node 24 with markdownlint-cli2 0.18.1 and a **separate**
Rust 1.90 check for the affected QR package. It runs workspace tests, strict
lint, rustdoc, audit and the unmodified deny policy on the final lockfile.
For development before commit, run the individual commands in the script;
the runner intentionally rejects dirty source as a qualification input.

The image example scans real PNG pixels and rejects corrupt, empty, multiple,
oversized and non-UTF-8 QR data. It emits only redacted metadata by default;
`--emit-payload` requires a pipe and must be used only with disposable test QR
images. Tests render synthetic v2/v4 fixtures, decode their PNGs, then invoke
the unmodified production Swift core. All six simulated biometric outcomes,
failure effects, first enrolment, receipt validation, interruption, retained
checkpoint, expiry and retry are checked. Reports label Face ID, provider,
authority, keychain and trust effects as modelled; they do not claim actual
Secure Enclave, App Attest, sessions, service receipts or physical-device proof.

Canonical checkpoint encoding does **not** protect history: removal of a valid
receipt can restore pending state and repeat a modelled submission. Native
pending retry reuses its envelope; this model requests a simulated biometric
again. Neither this model nor its passing results prove protected storage,
issuer-side idempotence, genuine first-install authority, certificate renewal,
live custody, protected merge, installation or INT-07 acceptance.

The selected source input is Pistis #526 at
`ef00ff34efbb9cfeac9298c9c77f1dc9694162cd`, tree
`13857903766fc230de7b6f87f6f38122cd6945d6`, lock blob
`ca9e7b9adcb9e6640a0c63c9ce39f2bc111fd432`. Review the **new** commit,
tree and lock independently. The exact existing `deny.toml` governs the
updated graph; no licence allowance, advisory ignore or Git source exception
is added. Kanon #750 remains pending, and REG-09 retains the registry writer
lease. No shared registry or `.mnemosyne/expedition.json` update occurs here.

The updated lock keeps all original crate revisions, checksums and resolved
dependency edges; it adds only `pistis-qr` 0.1.2 and its test/image route.
`hashlink` and `rsqlite-vfs` now spell out their existing `hashbrown 0.16.1`
dependency because the new test-only `lru 0.18.5` adds `hashbrown 0.17.1`.
The unchanged deny policy allows duplicate-version warnings, so a policy
result with those warnings is not an all-warnings-denied result. Strict
`cargo audit --deny warnings` remains a separate required command.

On a separately authorised macOS/Xcode host, rerun the existing iPhone
simulator coordinator tests, including native cancellation and unavailable
biometry. On a real device, separately qualify App Attest, Secure Enclave and
keychain retention. Only the existing owner can admit an exact-source Jenkins
task, publish an authentic Expedition status and coordinate any forward Kanon
binding. No customer test-QR scan is required for these developer tests.
