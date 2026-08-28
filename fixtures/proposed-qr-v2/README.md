# Production QR v2 conformance vectors

These vectors make accepted ADR 0021 byte-exact so Rust, Swift, protocol, and
security implementations consume one concrete representation.

`response-positive.qr.txt` wraps the already accepted ADR 0018
`positive-envelope.hex` as response kind `2` in deterministic CBOR:

```text
{0: 2, 1: 2, 2: bstr .cbor COSE_Sign1}
```

The source COSE fixture contains an authentication response. The outer
`PISTIS1` checksum detects scanning corruption only. Neither this synthetic
fixture nor successful parsing grants authority.

`challenge-positive.cose.hex` and `challenge-positive.qr.txt` are the matching
Rust-generated challenge-kind conformance vectors consumed by the production
Swift decoder. They use the deliberately compromised P-256 scalar `1` and the
public protocol challenge payload, so they are test material only. Rust proves
the exact COSE and outer-frame bytes are stable; Swift proves that the released
decoder accepts the same prefix-separated checksum contract.

Production parsers reject version 1, challenge/response kind confusion,
padding, non-ASCII or alternate alphabets, checksum changes, structural
changes, and invalid COSE.

Review commands:

```sh
cargo test --locked -p pistis-qr --test production_v2
swift test --package-path ios/PistisCore
```
