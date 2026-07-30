# Operate GitHub trust enrolment

GitHub is a trust anchor for enrolment, not an online dependency for routine
Pistis authentication. ADR 0025 defines the v0.1 GitHub App Device Flow
profile. It supersedes callback, OAuth-state, PKCE, confidential-broker, and
authorisation-code transport requirements from earlier ADRs for v0.1.

## Register the GitHub App

Use the reviewed organisation-owned GitHub App for each environment. The v0.1
profile requires:

- Device Flow enabled;
- user authorisation-token expiration enabled;
- no installation-time user authorisation;
- no active webhook or subscribed events;
- no explicit repository, organisation, or account permissions;
- GitHub's unavoidable implicit Metadata read only; and
- availability to any GitHub account, with Pistis enrolment still
  invitation-only.

Record only the public client ID in reviewed application configuration. Do not
create or distribute a client secret, App private key, webhook secret, personal
access token, or callback URL for this profile. The public client ID is not an
authority credential.

Before enabling an implementation, compare the exact App configuration digest
required by ADR 0025. A changed owner, slug, client-ID fingerprint, endpoint,
permission, event, webhook, installation, or token-expiration setting disables
enrolment until review passes again.

The development iOS build commits the exact public registration fields in
``fixtures/github-app-configuration-v1.json`` and embeds that file's SHA-256.
Recompute the digest from the exact bytes and review the registration before
changing either value. This digest is a configuration commitment, not a
credential.

## Exact provider boundary

The implementation may contact only the exact endpoints in ADR 0025:

- `https://github.com/login/device/code`;
- `https://github.com/login/oauth/access_token`; and
- `https://api.github.com/user`.

Honor GitHub's returned polling interval, expiry, `slow_down`,
`authorization_pending`, `access_denied`, and `expired_token` semantics within
the stricter local bounds. Do not poll while the app is backgrounded. Resume
only after an explicit foreground action and fresh platform authentication.

The app must show the account returned by the authenticated-user endpoint
before the user confirms the invitation, installation, and device binding.
The non-zero numeric `id` is the provider subject. Login, display name, profile
URL, and public email are mutable snapshots and never authorise a user.

## Authority commit

A successful provider poll is not enrolment. The device must bind the numeric
subject, invitation, public key, assurance, installation, policy generation,
App configuration digest, and fresh authority challenge into the exact signed
binding defined by ADR 0025. Prosopikon then performs the ADR 0023 invitation,
principal, device, receipt, reconciliation, and audit transaction atomically.

Persist only the minimized authority receipt and permitted display snapshots.
Never persist the device code, user code, access or refresh token, complete
provider response, browser history, or private key. Clear transient material
on success, denial, cancellation, backgrounding, timeout, malformed response,
rate-limit termination, or network failure.

## Failure and recovery

| Event | Required outcome |
| --- | --- |
| User cancels or GitHub denies access | Clear the attempt and create no binding. |
| User code or provider subject is substituted | Fail closed, audit coarsely, and require a fresh invitation and Device Flow. |
| Poll interval or expiry is violated | Stop polling, clear transient material, and create no binding. |
| GitHub or the network is unavailable | Preserve no partial trust; retry explicitly with a fresh device code. |
| Authenticated-user response is malformed | Reject it and create no binding. |
| Authority commit is uncertain | Use only ADR 0025's signed receipt lookup and bounded reconciliation. |

Do not contact GitHub for routine challenge signing or verification. A login
rename alone does not require rebinding because the numeric subject remains
stable.

## Incident response

If transient credentials may have leaked, revoke the GitHub App user
authorisation, clear pending attempts, inspect redacted audit events, and begin
a fresh invitation and Device Flow. A suspected subject, user-code, invitation,
device-key, or App-configuration substitution is security sensitive and
follows `SECURITY.md`.

A future authorisation-code or confidential-broker profile requires a distinct
accepted ADR and profile identifier. It must not silently replace or fall back
from the v0.1 Device Flow profile.
