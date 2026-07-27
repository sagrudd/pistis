# Provider conformance testing

Provider adapters are tested without public-network access. GitHub fixtures in
`fixtures/provider/github/` are synthetic authenticated-user responses; they
contain no live account, credential, authorization code, or bearer token.

## GitHub fixture contract

The adapter must:

- accept `authenticated-user.json`;
- preserve the numeric `id` as a decimal stable subject;
- treat `login`, `name`, `email`, and `html_url` only as display metadata;
- reject a missing `id`;
- reject string, fractional, negative, zero, or out-of-range IDs;
- reject malformed JSON and incompatible top-level values; and
- ignore unrelated response members without copying the full response into
  durable evidence.

Tests must also exercise callback cancellation, wrong or absent `state`,
callback replay, expired attempts, token-exchange failure, provider timeouts,
and persistence failure. Every failure must assert that no binding was
committed and transient secrets were cleared.

Tests that simulate two responses with the same numeric `id` and different
`login` values must produce the same provider identity. Responses with the
same login and different numeric IDs must produce different identities.

## Fixture maintenance

Fixtures are conformance inputs, not example production data. Use conspicuous
synthetic values, keep the minimum fields needed by the case, and describe the
expected outcome in `fixtures/provider/github/README.md`. Never record traffic
from a real GitHub session.

Provider response changes may extend the accepted input, but must not change
the stable-subject rule. A change to identity semantics, callback validation,
token retention, or durable evidence requires security review and an ADR.

## Google fixture contract

Google fixtures in `fixtures/provider/google/` are synthetic. The discovery
fixture records the security-relevant shape of Google's published metadata; it
is not fetched during tests and its endpoint values are not a general
allow-list for arbitrary issuers.

The adapter must:

- begin discovery at the fixed Google well-known URI;
- reject an unexpected metadata issuer, insecure endpoint, missing JWKS URI,
  or signing algorithm outside the reviewed policy;
- require authorization code flow, PKCE `S256`, exact callback and `state`,
  and a fresh one-use `nonce`;
- verify the ID-token signature against the selected JWK before exposing
  claims;
- accept Google's documented modern and legacy token-issuer spellings while
  canonicalizing both to `https://accounts.google.com`;
- require the configured client ID in `aud`, enforce the authorized presenter
  rules for `azp`, and reject unrelated audiences or presenters;
- reject expired tokens, implausible future `iat` values, nonce mismatch,
  nonce replay, missing or empty subjects, and unsupported claim types;
- use the exact, case-sensitive `sub` as the stable subject; and
- treat email, verification state, name, picture, locale, and `hd` only as
  metadata or separate policy inputs.

Tests must cover signature corruption, algorithm substitution, unknown and
ambiguous `kid` values, malformed discovery/JWKS/JWT input, bounded JWKS
refresh, cache expiry, provider timeout, cancellation, persistence failure,
and the clock-tolerance boundaries. Every negative case asserts that no
identity claims escape validation, no durable binding is committed, and all
transient credentials are cleared.

Two valid tokens with the same `sub` and different email or profile claims
must produce the same provider identity. Tokens using the two accepted Google
issuer spellings must also produce the same canonical identity. A different
`sub` must produce a different identity even when email and `hd` match.

Signed test tokens and keys must be generated deterministically from test-only
key material. Never copy a real ID token, authorization response, discovery
capture, account identifier, or production signing key into the repository.
Production tests must not call Google, including the debugging `tokeninfo`
endpoint.
