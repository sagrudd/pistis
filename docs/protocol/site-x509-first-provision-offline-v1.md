# Site X.509 first-provision offline response v1

This additive Pistis capability implements accepted Proxenos ADR-0014 using
the canonical carrier owned by Thesaurophylax 0.67.0 at exact merge revision
`547fa11acd657b862e0f42cbf477843e7cbfffb3`. Pistis does not define a parallel
wire format.

The Scan view admits only the strict `PXFP1:P:` unpadded-Base64url text form;
the file entry point accepts the byte-identical raw presentation. Both reach
the same closed parser. The review shows the Site UUID and Trust Domain,
authority/custody/revocation/root/issuer generations, enrolled installation,
device and App Attest application, protected target kind and identifier, every
ordered service/private-IP set, and exclusive expiry.

One Face ID evaluation releases the existing enrolled Site-root key only after
its compressed public key exactly matches the challenge. Pistis creates the
existing detached ES256 `application/vnd.mnemosyne.pxfp.v1` approval, computes
the shared `PXAT/v1` client-data hash, and asks only the already registered
production App Attest key for an assertion. It emits the strict `PXFP1:R:` QR
text or the same canonical response bytes as a file. The response contains no
private key, custody handle, authority token, origin override, certificate,
browser grant or session credential.

Expiry, alternate Base64, unknown/reordered/trailing TLV, wrong purpose or
audience, Site/device/generation/target/service/IP substitution, mismatched
Site-root key and replaced App Attest key all fail closed. A response remains
byte-identical and retryable after Thesaurophylax restart; Monas and
Thesaurophylax, not Pistis, own durable replay and ambiguous-relay settlement.
