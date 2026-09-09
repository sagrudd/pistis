# Synthetic receipt wrapping interoperability

All key material in this directory is disposable **test-only software material**.
It is not a production record, enrolled device or approval. Never install it.

`provisioned.json` was emitted on native Linux by the actual
`PortableSiteTrustReceiptIssuerProvisionerV1::provision_site_root_bundle_receipt`
at Thesaurophylax canonical
`b013f62bcc0d04dc0b4fe748d89092063f6ab35d` (0.78.3). The emitter constructs
the real provision ceremony and detached ES256 proof with synthetic device
scalar `[8; 32]`, host scalar `[7; 32]`, and the accepted signature profile.
The actual provisioner creates the random receipt seed and encrypts the record;
the emitter then authenticates `PortableKeystoreFileV1::read` using its derived
short-domain AAD and checks the recovered seed's Ed25519 public key against the
actual provision result. It does not handcraft the retained ciphertext.

The native Swift test derives ECDH and wrapping AAD/key independently, opens
that exact retained record, checks seed/public-key equality and rewraps to a
fresh synthetic host scalar `[3; 32]` using the production wrapping helpers.
The full external proof purpose is deliberately rejected as wrapping AAD for
both old and fresh records. A fixed test nonce is used only for a separate
reproducible fresh-ciphertext cross-check; production sealing remains random.

This demonstrates software record interoperability, not physical Secure
Enclave, Face ID, live retained-key recovery or an installed app. The fixed
external proof purpose and the short authenticated wrapping domain remain
distinct, as recorded in ADR 0038 and coordinated Thesaurophylax #298.

## Generation receipt

`tests/receipt-wrap-v1/provision_vector.rs` retains the actual emitter source (formatting only after
generation). It ran as a test module in the isolated native joined fixture
`receipt-joined-source-fixture` using Rust 1.97.0, with exact Thesaurophylax
crypto and `new_api` dependencies pinned to the canonical revision above.
The test-only manifest also contained the Monas fixture's unchanged old API
pin `0bfb16857d135d2830de2cf53d245b68ed2d051f`. Its locked dependency graph
SHA-256 was
`4e91b34e2c0bd57e275d22f5aafff58f92e29f26e482701ae56524fcf108ffe3`.

The native command, within the existing network-disabled, unprivileged,
mount-free builder and its public toolchain/cache, was:

```sh
cargo test --offline emit_actual_provision_vector -- --nocapture
```

An outer 180-second deadline and five-second kill grace bounded it. The actual
provision/open test passed in 0.06 seconds. The original emitted JSON SHA-256
was `c44ae9fedda34043aafe58a18187c7f6025cfda3b406e86d23c41d9d6f8ae20b`;
the checked-in JSON is reformatted and adds the separately emitted Swift fresh
record. Regeneration creates a new random test seed/nonce, so it is not a
byte-identical regeneration claim. The retained vector makes regression tests
deterministic. The device identifier follows the actual provisioner's test
template, not the production iOS key-ID derivation, so this is not a full
production producer or device-binding test.

`tests/receipt-wrap-v1/swift_vector.rs` retains the reverse native check: actual
Thesaurophylax opens the exact Swift fresh ciphertext to the same synthetic
seed only with the short wrapping AAD; using the full proof purpose denies.
The final locked, offline native harness ran three tests in 0.08 seconds:
the joined four proof/AAD combinations, actual provision/open, and Swift-record
opening. These retained Rust modules belong to that external integration
harness, not the production iOS dependency graph or a new Pistis crate.
