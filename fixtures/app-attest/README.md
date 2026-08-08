# App Attest contract fixtures

These fixtures are deterministic, non-secret contract inputs. They are not
Apple evidence and cannot register a key, prove a physical iPhone, mint a
Pistis fact, establish a Monas session, or activate a route.

`site-trust-assertion-client-data-v1.json` is the shared known-answer vector
for the iPhone client and Rust verifier. It fixes the exact bytes passed to
`SHA-256` before `DCAppAttestService.generateAssertion`:

```text
UTF-8("mnemosyne.pistis.site-trust-app-attest-client-data.v1\\0") ||
the 32 decoded challenge-digest bytes
```

The JSON values are canonical unpadded base64url. The client must use the
server-issued challenge digest only; this fixture's deterministic challenge is
test data and is never valid for a live Monas ceremony. The expected SHA-256
is the value passed to Apple's API. The actual assertion is intentionally not
recorded here because it is transient and must not be retained in source,
logs, fixtures, or a dossier.
