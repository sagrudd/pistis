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
