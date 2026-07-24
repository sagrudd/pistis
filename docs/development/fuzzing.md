# Fuzz testing

Pistis uses `cargo-fuzz` for security-sensitive parsing and verification
boundaries. The harness package is deliberately separate from the release
workspace and must never be published.

Install the runner on a Rust nightly toolchain:

```console
cargo install cargo-fuzz --locked
```

Run the canonical-CBOR parser target:

```console
cargo +nightly fuzz run canonical_parser -- -max_len=65536
```

Run the signed-message verifier target:

```console
cargo +nightly fuzz run verifier -- -max_len=65536
```

Run the reviewed public-key and ES256 verification boundary:

```console
cargo +nightly fuzz run crypto_verifier -- -max_len=65536
```

Run the bounded QR transport decoder against challenge and response kinds:

```console
cargo +nightly fuzz run qr_decoder -- -max_len=2331
```

The checked-in seed corpora under `fuzz/corpus/` contain representative valid
and invalid inputs. New regression-provoking inputs should be minimized before
being retained:

```console
cargo +nightly fuzz cmin canonical_parser
cargo +nightly fuzz cmin verifier
cargo +nightly fuzz cmin crypto_verifier
cargo +nightly fuzz cmin qr_decoder
```

Fuzzing is a bounded developer and review activity. The ordinary Jenkins gate
compiles every locked fuzz target under strict Clippy and runs the deterministic
unit, negative, fixture, and demonstration suites. It does not claim that a
live fuzz campaign ran. Live campaigns should record the target, revision,
duration, corpus, and sanitizer in the associated issue or review evidence.

Fuzz findings may be security vulnerabilities. Follow `SECURITY.md`; do not
attach a sensitive crashing input to a public issue.
