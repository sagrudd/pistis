# Operate Google trust enrolment

Google is a trust anchor for enrolment, not an online dependency for routine
Pistis authentication. This guide covers OAuth client registration, consent,
privacy, key rotation, and recovery from interrupted enrolment.

## Register the Google OAuth clients

Create a dedicated Google Cloud project, consent configuration, and OAuth
client for each deployment environment. Do not reuse production registrations
for development or conformance tests.

In Google Auth Platform:

1. configure user-facing branding, an operator-controlled homepage and privacy
   policy, support contacts, and the intended audience;
2. add only the users or organisation audience needed for that environment;
3. request only `openid`, plus `profile` or `email` when the deployment has a
   documented need for those display snapshots; and
4. create a separate installed-application client for every supported platform
   and application identity.

Use the platform client type and redirect mechanism required by Google.
Desktop clients may use a loopback IP redirect on an ephemeral port. Do not use
the loopback flow for iOS or Android client types. Mobile registrations must
bind the application identity using their platform-specific bundle/package and
signing-certificate configuration. Redirect URIs, client IDs, and application
identities are environment configuration; validate them before enabling
enrolment.

Installed applications are public clients. Do not package a client secret in a
Pistis application or treat a distributed secret as confidential. Disable
enrolment if registration preflight, redirect ownership, or application
identity validation fails.

## Enrolment request

Open Google's authorisation endpoint in the system browser, never an embedded
credential-capture view. Use authorisation code flow, PKCE `S256`, and fresh
independent `state` and `nonce` values. The redirect URI must exactly match the
platform registration.

The scope starts with `openid`. Add:

- `profile` only to display consented name or picture snapshots; and
- `email` only to display a consented email snapshot.

Do not request other Google API scopes, offline access, or a refresh token.
The `hd` request parameter may help account selection but cannot enforce an
organisation boundary. If organisation policy matters, validate the signed
ID-token `hd` claim separately after authentication.

Before confirmation, show the user the validated account metadata and the
device key that will be bound. The user must be able to cancel or restart with
a different account.

## Discovery and signing-key operation

The application obtains metadata only from:

`https://accounts.google.com/.well-known/openid-configuration`

Honor the discovery and JWKS HTTP cache directives. Retain only public signing
keys and cache metadata, never tokens. If an ID token refers to an unknown
`kid`, refresh JWKS once within a bounded timeout and retry validation. Repeated
unknown keys, malformed key sets, unsupported algorithms, insecure endpoints,
or issuer mismatch fail closed.

Google's `tokeninfo` endpoint may assist isolated operator diagnosis with
synthetic or already-revoked material, but is not part of production
validation. Never paste a live ID token into tickets, chat, shell history, or
shared diagnostics.

## Identity and retention

Persist only:

- provider type and canonical authority `https://accounts.google.com`;
- the exact, case-sensitive `sub`;
- consented email, verification state, name, picture, locale, or hosted-domain
  snapshots needed by local policy;
- provider authentication and validation timestamps;
- the local installation, application instance, and device public-key
  binding; and
- protocol and verifier versions needed to assess the evidence.

Email and `hd` are metadata, not the identity key. Never persist the
authorisation code, ID token, access token, refresh token, PKCE verifier,
`state`, `nonce`, browser data, or complete discovery/token response. Redact
tokens and callback query strings from logs. Clear transient material after
success, cancellation, timeout, or error.

## Failure and recovery

An enrolment attempt remains untrusted until callback correlation, token
signature and claims, provider identity, and device-key binding have all
validated and the binding commits atomically.

| Event | Required outcome |
| --- | --- |
| User cancels or Google returns an error | Clear the attempt and create no binding. |
| Redirect, `state`, or local attempt differs | Reject as a security error and require a fresh flow. |
| `nonce` differs or is replayed | Reject the token, clear the attempt, and create no binding. |
| Discovery, JWKS, or token exchange is unavailable | Preserve no partial trust; retry only with a fresh ceremony. |
| Signature, issuer, audience, `azp`, time, or subject validation fails | Reject the token and create no binding. |
| An unknown `kid` remains after one refresh | Fail closed; investigate key-cache health without logging the token. |
| Returned account is unexpected | Let the user cancel or explicitly restart account selection. |
| Durable commit fails | Create no visible binding and clear all transient credentials. |

Retries never reuse an authorisation code, PKCE material, `state`, or `nonce`.

## Reauthentication and incidents

Require a complete new Google ceremony for initial enrolment, identity
rebinding, replacement or recovery devices, administrator-requested
revalidation, and policy-required metadata refresh. Do not contact Google for
routine local challenge signing or verification.

If transient credentials may have leaked, revoke the application's Google
authorisation where applicable, clear pending attempts, inspect redacted audit
events, and start a fresh enrolment. Unexpected issuer, subject substitution,
nonce replay, signing-key anomalies, or redirect interception are
security-sensitive and follow `SECURITY.md`.
