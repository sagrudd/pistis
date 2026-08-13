# Site-origin relocation approval v1

This is the Pistis implementation profile for accepted Proxenos ADR-0013. It
adds one attended capability; it does not alter authentication, enrolment or
ordinary Site-root delegation wires.

Pistis accepts a bounded `monas.site-origin-relocation-presentation.v1` JSON
object only when it has exactly these fields: `schema`, canonical PXSR bytes in
canonical padded Base64, the PXSR SHA-256 in canonical unpadded Base64url,
16-byte installation ID, 32-byte registered App Attest key ID, `prepared`
state, and the exact forward-only warning. No route, hostname, fingerprint,
certificate pin, DNS name or fallback is carried by the wrapper.

The app parses the 20 ordered PXSR/v1 fields and displays the exact Site UUID,
Site Trust Domain, old and new private-IP HTTPS origins, origin generations,
authority, custody, root and issuer generations, and forward-only warning.
Purpose is `proxenos.site-origin-relocation.v1`; audience is
`pistis:site-origin-relocation:v1`; service is `service-monas-web`. The target
transport is derived only from the parsed PXSR and validates through the
already authenticated Site-root generation. Bootstrap leaf pins cannot be
relocated.

One Face ID evaluation releases the existing Site-authority Secure Enclave key
to sign the byte-exact PXSR in detached ES256 COSE. The existing registered App
Attest key then asserts this client-data hash:

```text
SHA256(
  "PISTIS-PXSR-APP-ATTEST/v1\0" ||
  installation_id[16] || app_attest_key_id[32] || pxsr_sha256[32] ||
  ceremony_id[16] || challenge_sha256[32] || detached_cose_sha256[32]
)
```

The fixed Monas routes are:

- `GET /v1/pistis/site-origin-relocation/v1/presentation`;
- `POST /v1/pistis/site-origin-relocation/v1/submission`;
- `GET /v1/pistis/site-origin-relocation/v1/status`; and
- `POST /v1/pistis/site-origin-relocation/v1/cancel`.

Submission repeats byte-identical canonical PXSR bytes and their digest and
carries only the detached COSE plus the existing opaque App Attest envelope.
After an ambiguous submission, Pistis reads status for the same ceremony and
PXSR digest. It never repeats Face ID, creates an App Attest key or enters first
device enrolment. Cancellation is accepted only as the exact authoritative
`cancelled` state; committed and converged states are forward-only.

Wrong purpose, audience, Site, origin, generation, ceremony, challenge,
authority, root, custody, app, key, counter, encoding, expiry, replay or
cancellation fails closed. Raw assertion and signature bytes are transient and
must not enter logs, retained history or browser state.
