# Protocol v1 cryptographic fixtures

These fixtures use the P-256 private scalar `1`. It is public, compromised,
and reserved exclusively for deterministic tests and documentation. Production
code must never load private keys from this directory.

The canonical challenge is signed directly with ES256. The signature encoding
is fixed-width COSE `r || s`, not ASN.1 DER. Run the crate-local example to
exercise the complete test-only signing and production verification boundary:

```console
cargo run --locked -p pistis-crypto --example challenge_sign_verify
```
