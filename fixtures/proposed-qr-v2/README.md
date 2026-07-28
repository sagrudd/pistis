# Proposed production QR v2 review vectors

These vectors are **not an accepted production protocol**. They make proposed
ADR 0021 byte-exact so Rust, Swift, protocol, and security reviewers can review
one concrete representation before implementation.

`response-positive.qr.txt` wraps the already accepted ADR 0018
`positive-envelope.hex` as response kind `2` in deterministic CBOR:

```text
{0: 2, 1: 2, 2: bstr .cbor COSE_Sign1}
```

The source COSE fixture contains an authentication response. The outer
`PISTIS1` checksum detects scanning corruption only. Neither this synthetic
fixture nor successful parsing grants authority.

Production code must not consume this directory until ADR 0021 is Accepted.
Test-only review parsers reject version 1, challenge/response kind confusion,
padding, non-ASCII or alternate alphabets, checksum changes, structural
changes, and invalid COSE.

Review commands:

```sh
cargo test --locked -p pistis-qr --test proposed_v2_review
swift test --package-path ios/PistisCore
```
