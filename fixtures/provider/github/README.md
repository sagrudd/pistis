# GitHub provider fixtures

These JSON files are TEST-ONLY synthetic responses for the GitHub
authenticated-user boundary. They are not captured from real accounts and do
not contain tokens or other credentials.

| Fixture | Expected result |
| --- | --- |
| `authenticated-user.json` | Accept subject `42424242`; retain selected display snapshots only. |
| `missing-id.json` | Reject because the stable subject is absent. |
| `string-id.json` | Reject because the subject is not a JSON integer. |
| `negative-id.json` | Reject because GitHub user IDs must be positive. |
| `fractional-id.json` | Reject because the subject is not an integer. |

Tests should additionally mutate the valid fixture to cover zero, numeric
overflow, malformed JSON, and incompatible top-level values. Tokens,
authorization codes, PKCE material, and full live provider responses must
never be added here.
