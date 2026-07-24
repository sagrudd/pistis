# QR transport fixtures

These are deterministic EPIC-6 transport fixtures for independent decoders.
They exercise the `PISTIS1:` framing, canonical-CBOR frame, response-kind
separation, and scanning checksum defined by ADR 0006.

`challenge-minimal.qr.txt` contains a synthetic challenge transfer whose
canonical payload is the closed map `{0: 1, 1:
"pistis.authentication-challenge.v1"}` and whose 64-byte detached test
signature is entirely `0x5a`. It is a framing fixture, not a valid production
installation assertion and contains no private key.
