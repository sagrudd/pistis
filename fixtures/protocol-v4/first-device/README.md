# First-device presentation v4 fixtures

These fixtures close ADR 0029 across Rust and the mobile implementations. The
positive fixture carries an authority-signed HTTPS origin, the SHA-256 digest
of the leaf certificate's exact DER SubjectPublicKeyInfo, and trust-word
derivation version 1. Version 3 remains under `protocol-v3` solely for
downgrade-rejection and historical evidence.

Trust words use the 2,048-word English list defined by BIP 39. The committed
list was retrieved from the Bitcoin BIPs repository and has SHA-256 digest
`2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`.
The BIPs repository is distributed under the MIT licence.

The words are a human comparison checksum, not authentication material. Every
implementation must enforce the full 256-bit SPKI digest and the authority
signature.
