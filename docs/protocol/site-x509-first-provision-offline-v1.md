# Site X.509 first-provision offline response v2

This additive Pistis capability implements accepted Proxenos ADR-0014 using
the canonical V2 carrier owned by Thesaurophylax 0.79.9 at exact source revision
`eb2f180ee7b8cb8673fa325a9235a5ba2709adb9`. Its contract sets a maximum
900-second (15-minute) lifetime from the trusted preparation time to the
exclusive challenge expiry. This bound was introduced in Thesaurophylax
0.68.9 and retained by the current source contract; see the [provider contract
at the pinned revision](https://github.com/sagrudd/thesaurophylax/blob/eb2f180ee7b8cb8673fa325a9235a5ba2709adb9/docs/SITE_X509_FIRST_PROVISION_OFFLINE_V2.md).
Pistis does not define a parallel wire format or extend the challenge lifetime.

The Scan view admits only the strict `PXFP2:P:` unpadded-Base64url text form;
the file entry point accepts the byte-identical raw presentation. Both reach
the same closed parser. The review shows the Site UUID and Trust Domain,
authority/custody/revocation/root/issuer generations, enrolled installation,
device and App Attest application, protected target kind and identifier, every
ordered service/private-IP set, and exclusive expiry.

One Face ID evaluation releases the existing enrolled Site-root approval key
only after its identifier and compressed public key exactly match the protected
registration projected in the carrier context. The newly prepared X.509 root
and issuer keys in the challenge are distinct certificate outputs; neither is
an iPhone approval key. Pistis creates the existing detached ES256
`application/vnd.mnemosyne.pxfp.v1` approval, computes
the shared `PXAT/v2` client-data hash, and asks only the already registered
production App Attest key for an assertion. It emits the strict `PXFP2:R:` QR
text or the same canonical response bytes as a file. The response contains no
private key, custody handle, authority token, origin override, certificate,
browser grant or session credential.

Expiry, alternate Base64, unknown/reordered/trailing TLV, wrong purpose or
audience, Site/device/generation/target/service/IP substitution, mismatched
Site-root key and replaced App Attest key all fail closed. A response remains
byte-identical and retryable after Thesaurophylax restart; Monas and
Thesaurophylax, not Pistis, own durable replay and ambiguous-relay settlement.
