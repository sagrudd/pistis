# Cryptographic primitives

Pistis protocol v1 has one signature allow-list entry: COSE algorithm `-7`,
ES256 (ECDSA over NIST P-256 with SHA-256). A verifier rejects every other
algorithm identifier before interpreting a key or signature. Signatures use
the fixed-width 64-byte COSE `r || s` representation; DER and high-S signatures
are rejected.

Public keys are validated P-256 SEC1 points. Pistis accepts the standard
compressed and uncompressed encodings at an input boundary, then immediately
canonicalizes a key to its 33-byte compressed SEC1 representation.

`KeyId` is the complete 32-byte result of:

```text
SHA-256("pistis:key-id:v1\0" || compressed-sec1-public-key)
```

The domain prefix prevents cross-protocol reuse of the digest. Retaining the
complete digest provides SHA-256's 128-bit generic collision-security target.
Both SEC1 representations of one public key therefore produce the same
identifier.

The `pistis-crypto` crate deliberately has no signing or private-key production
API. Mobile and service implementations keep private operations in their
platform key stores; the Rust foundation parses public material, hashes, and
verifies.
