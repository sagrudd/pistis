# ADR 0004: Google OpenID Connect trust-anchor enrolment

- Status: Accepted
- Date: 2026-07-24
- Owners: Trust, protocol, and mobile security

## Context

Pistis needs a durable Google identity binding without making Google available
during routine local authentication. Email addresses and hosted domains can
change and are not account identifiers. An OpenID Connect ID token is a
time-limited assertion whose trust depends on its signature, issuer, intended
client, freshness, and binding to the initiating browser ceremony.

Google publishes OpenID Connect discovery metadata and rotating signing keys.
Its current documentation identifies `https://accounts.google.com` as the
modern issuer, while requiring validators to accept the legacy
`accounts.google.com` issuer spelling. Allowing those spellings to become
different durable authorities would split one Google account into two Pistis
identities.

## Decision

Google enrolment uses the system browser and authorisation-code flow with:

- a platform-specific installed-application OAuth client registration;
- a fresh PKCE verifier and the `S256` challenge method;
- fresh, independent, high-entropy `state` and `nonce` values bound to one
  local enrolment attempt;
- an exact registered redirect URI;
- the minimum scopes, beginning with `openid` and adding `profile` or `email`
  only when the deployment needs those display snapshots; and
- no request for offline access or refresh token.

The adapter is Google-specific. It starts discovery only at the hard-coded
`https://accounts.google.com/.well-known/openid-configuration` URI, respects
HTTP cache controls, and accepts metadata only when the issuer and security
endpoints match the configured Google authority policy. It does not accept an
operator-supplied discovery URL, downgrade to HTTP, or dynamically enable an
unreviewed signing algorithm.

Before using any claim, the adapter:

1. verifies the compact token structure and a supported asymmetric signature
   with the key selected from the discovered `jwks_uri`;
2. accepts only Google's documented modern or legacy `iss` spelling;
3. requires the configured client ID in `aud`;
4. validates `azp` when present and requires it when multiple audiences make
   the authorised presenter significant;
5. validates `exp` and `iat` against the captured verification time and a
   small, explicitly configured clock tolerance;
6. requires an exact, one-use match for the request's `nonce`; and
7. extracts a non-empty, bounded, case-sensitive `sub`.

An unknown signing-key identifier may trigger one bounded JWKS refresh before
failure. Production validation never calls Google's debugging `tokeninfo`
endpoint. Network, discovery, key-refresh, token, callback, or persistence
failure creates no trusted binding.

Both documented issuer spellings canonicalize to the durable authority
`https://accounts.google.com`. The identity key is that canonical authority
plus the exact `sub`. Email, `email_verified`, name, picture, locale, and `hd`
are optional metadata. The `hd` claim may satisfy a separate administrator
policy only after token validation; the authorisation request's `hd` parameter
is merely a user-interface hint.

The authorisation code, ID token, access token, PKCE verifier, `state`,
`nonce`, and complete provider response are transient. They are redacted from
diagnostics, cleared on every terminal path, and never stored in the durable
binding.

## Consequences

- Changing a Google email address cannot change the stable identity.
- The two Google issuer spellings cannot create duplicate local identities.
- Signing-key rotation is supported through bounded, cache-aware JWKS refresh.
- Initial enrolment temporarily requires Google and the system browser;
  routine authentication remains local.
- Reauthentication is required for initial enrolment, rebinding, replacement
  or recovery devices, administrator-requested revalidation, and any
  policy-required metadata refresh.
- Deterministic CI uses synthetic discovery, JWKS, token, and claim fixtures;
  it never contacts Google or uses a real account.

## Alternatives considered

- Use email as the identity key: rejected because email is mutable and may be
  reassigned.
- Use `hd` as the identity key: rejected because it describes organisation
  membership rather than a Google account.
- Trust decoded JWT claims without signature validation: rejected because an
  attacker could substitute every identity claim.
- Use `tokeninfo` for production validation: rejected because it creates an
  unnecessary online validation dependency and Google documents it as a
  debugging facility.
- Accept arbitrary discovery issuers or algorithms: rejected because EPIC 4
  establishes Google trust, not a general federation boundary.
- Persist ID or refresh tokens: rejected because routine local authentication
  needs neither and retention would expand credential exposure.

## References

- [Google OpenID Connect guide](https://developers.google.com/identity/openid-connect/openid-connect)
- [Google OpenID Connect API reference](https://developers.google.com/identity/openid-connect/reference)
- [OAuth 2.0 for iOS and desktop applications](https://developers.google.com/identity/protocols/oauth2/native-app)
