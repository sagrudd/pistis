# Operate GitHub trust enrolment

GitHub is a trust anchor for enrolment, not an online dependency for routine
Pistis authentication. This guide covers OAuth App registration, privacy, and
recovery from interrupted enrolment.

## Register the OAuth application

Create a dedicated GitHub OAuth App for each deployment environment. Do not
reuse production registration for development or conformance tests.

Configure:

- **Application name:** an environment-specific, user-recognizable name;
- **Homepage URL:** the operator-controlled Pistis information page;
- **Authorization callback URL:** the exact callback URI compiled or
  configured for that environment; and
- **Device flow:** disabled unless a later accepted ADR selects it.

Record the public client ID in application configuration. Generate the client
secret only in the operator-controlled confidential exchange broker; never
distribute or package it with a native Pistis client. Configure the broker to
accept only the registered client ID and exact callback, pass the one-use code
and PKCE verifier to GitHub, and return the short-lived token only to the
initiating enrolment attempt over an authenticated confidential channel.
Disable enrolment when that broker is unavailable or its registration
preflight fails. The broker must not persist tokens, select identity fields, or
create a trusted binding.

The callback must use an application-claimed HTTPS link where the platform can
verify ownership, or a uniquely assigned private-use scheme. Register only the
single exact callback. Wildcards, open redirects, fragments, and runtime
callback overrides are prohibited.

## Minimum access

Request an empty OAuth scope. The authenticated-user endpoint exposes the
stable numeric account ID and public profile data without a broader scope.
Do not request `repo`, `gist`, organization, write, or email scope. If a future
policy needs non-public email, that data expansion requires privacy review and
must not change the identity key.

The application must show the account returned by the authenticated-user
endpoint before the user confirms the device binding. The numeric `id` is the
subject. The login, display name, profile URL, and public email are optional
snapshots and never authorize a user.

## Privacy and retention

Persist only:

- provider type and authority;
- decimal GitHub numeric user ID;
- consented display snapshots;
- provider-response and authentication timestamps;
- the local installation, application instance, and device public-key
  binding; and
- protocol and verifier versions needed to assess the evidence.

Never persist the authorization code, access token, PKCE verifier, `state`,
cookies, browser history, or complete provider response. Redact bearer tokens,
authorization codes, and callback query strings from logs and diagnostics.
Clear transient material after success, cancellation, timeout, or error.

Binding records follow the installation's identity-record retention policy.
Display snapshots may be refreshed or erased independently without changing
the stable subject. Revocation prevents future authorization but does not
rewrite retained historical evidence.

## Failure and recovery

An enrolment attempt is untrusted until provider identity, callback state, and
device-key binding have all validated and the binding commits atomically.

| Event | Required outcome |
| --- | --- |
| User cancels or GitHub denies access | Clear the attempt and show a neutral cancellation; create no binding. |
| Callback state, URI, or attempt differs | Reject as a security error, clear the attempt, and require a new browser flow. |
| Callback is replayed | Reject it; an attempt can complete at most once. |
| Authorization code expires or exchange fails | Clear secrets and restart from a new authorization request. |
| Network fails or GitHub is unavailable | Preserve no partial trust; allow an explicit retry with fresh state and PKCE material. |
| Authenticated-user response is malformed | Reject it and create no binding. |
| Returned account is not the expected account | Let the user cancel or explicitly restart with account selection. |

Retries never reuse `state`, authorization codes, or PKCE material.

## Reauthentication

Require a complete new provider ceremony for:

- initial enrolment;
- changing the provider identity bound to a local user;
- replacement or recovery device enrolment;
- administrator-requested identity revalidation; and
- metadata refresh when local policy requires fresh provider authentication.

Do not contact GitHub for routine challenge signing or verification. A login
rename alone does not require rebinding because the numeric subject remains
stable.

## Incident response

If transient credentials may have leaked, revoke the OAuth authorization in
GitHub, clear pending local attempts, inspect redacted audit events, and begin
a fresh enrolment. If the OAuth client ID or callback registration changes,
disable enrolment until compatibility and redirect validation have passed
again. A suspected subject-substitution or callback attack is security
sensitive and follows `SECURITY.md`.
