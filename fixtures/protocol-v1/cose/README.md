# Pistis v1 COSE interoperability fixtures

These language-neutral fixtures define the exact Pistis `COSE_Sign1` profile
used by Rust and Swift conformance tests. Every `.hex` file contains one
lowercase hexadecimal byte sequence followed by a newline.

The positive vector uses the public, compromised P-256 private scalar `1`.
It exists only to make the ES256 signature deterministic and reproducible.
It must never be used for an installation or device key.

The production profile is an untagged four-element `COSE_Sign1` array:

1. protected headers `{1: -7, 4: kid}`;
2. an empty unprotected-header map;
3. the embedded, exact canonical payload; and
4. a fixed-width, low-S ES256 signature.

The `Sig_structure` uses context `Signature1`, the exact protected-header
bytes, empty external AAD, and the exact payload. Tags, detached payloads,
unprotected headers, unknown protected headers, other algorithms, malformed
key identifiers, noncanonical values, high-S signatures, and substitutions
fail closed.

`manifest.json` classifies each retained vector. A conforming implementation
must verify `positive-envelope.hex`, reproduce the other positive components,
and reject every entry whose outcome is not `valid`.

The four `*-payload.hex` schema fixtures use conspicuous repeated bytes and
the fixed time `1700000000000` milliseconds. They are non-secret examples of
the exact device-registration, authentication-challenge,
authentication-response, and authentication-evidence-receipt maps accepted in
ADR 0019. The authentication response contains the SHA-256 digest of the
retained challenge payload.
