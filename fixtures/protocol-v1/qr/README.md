# QR transport fixtures

These are deterministic EPIC-6 transport fixtures for independent decoders.
They exercise the `PISTIS1:` framing, canonical-CBOR frame, response-kind
separation, and scanning checksum defined by ADR 0006.

`challenge-minimal.qr.txt` contains a synthetic challenge transfer whose
canonical payload is the closed map `{0: 1, 1:
"pistis.authentication-challenge.v1"}` and whose 64-byte detached test
signature is entirely `0x5a`. It is a framing fixture, not a valid production
installation assertion and contains no private key.

The iOS simulator test `QRImageRoundTripTests` encodes the exact 179 UTF-8
bytes of that frame as an error-correction-level-M QR image, decodes the image,
and requires byte equality plus SHA-256
`2e2a88f27b4692db5a1e76e0fac6f31dc1fc3aa3a7367dedd43cfd5f43dfaa78`.
This is a fixture transport witness only. It is not a live authority QR,
camera scan, physical-device, Face ID, Secure Enclave, or App Attest result.
