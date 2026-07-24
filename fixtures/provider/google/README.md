# Google OpenID Connect provider fixtures

These files are TEST-ONLY synthetic inputs for the Google discovery boundary.
They contain no real account identifier, credential, token, or captured
provider response.

| Fixture | Expected result |
| --- | --- |
| `discovery.json` | Accept as the supported Google metadata shape after applying the fixed-authority policy. |
| `wrong-issuer-discovery.json` | Reject before using any endpoint or key URI. |

The valid fixture intentionally contains only fields needed to establish the
current security contract: canonical issuer, HTTPS authorization/token/JWKS
endpoints, authorization-code support, public subjects, `RS256`, and PKCE
`S256`. Tests must not assume that optional provider metadata is exhaustive or
that cached endpoint values never rotate.

ID-token signatures and JWKS inputs are generated deterministically in tests
from conspicuous test-only keys. Claim mutation tests cover both documented
issuer spellings, issuer canonicalization, subject stability, audience,
authorized presenter, expiry, issued-at, nonce, key selection, signature
corruption, and mutable metadata. Do not add a live ID token or a discovery
response copied from the public service.
