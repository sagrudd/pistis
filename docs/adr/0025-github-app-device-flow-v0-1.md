# ADR 0025: GitHub App device flow for v0.1 enrolment

- Status: Accepted
- Date: 2026-07-28
- Decision owners: Trust, mobile, Prosopikon authority, security, and evidence
- Related issue: PIS-E22-I252
- Supersedes: the GitHub enrolment **transport sections only**
  of ADRs 0003, 0007, 0008, and 0023 for the v0.1 profile

This decision was reviewed as ADR 0023 on its source branch. Integration
renumbered it mechanically to ADR 0025 because accepted mobile-enrolment and
proposed Linux-signer decisions now occupy ADRs 0023 and 0024.

## Context

The approved v0.1 MVP requires a Mnemosyne Biosciences GitHub App device-flow
ceremony. ADR 0003 accepts GitHub authorisation-code PKCE through a
confidential broker; ADRs 0007 and 0008 consequently specify a brokered
system-browser transport. That is incompatible with the approved no-broker
v0.1 deployment shape and cannot be changed by implication.

ADR 0023 later accepted the authority-owned invitation, binding, receipt, and
audit transaction together with an authorisation-code callback transport.
The project owner's subsequent GitHub App decision selected Device Flow and no
broker for v0.1. This ADR therefore preserves ADR 0023's authority transaction
and signed enrolment-result invariants while superseding only its callback,
OAuth-state, PKCE, broker, and authorisation-code transport requirements.

GitHub Apps support the OAuth 2.0 Device Authorization Grant using their public
client ID. It removes the client-secret exchange broker, but provides neither
OAuth callback correlation, PKCE nor `state`. A `device_code` is a transient
polling capability and a displayed `user_code` can be phished or used to mix
the browser account with the wrong local invitation.

This decision preserves the non-transport invariants of ADRs 0003, 0007 and
0008: GitHub's non-zero numeric `id` is the provider subject; login, email and
profile fields are mutable display/policy data; provider tokens are transient;
routine authentication is local; device keys are platform protected; and
Prosopikon alone owns principals, device generations, invitations, sessions,
durable audit and authority transactions. It defines one platform-neutral
transport profile for iOS and Android. The MVP release baseline still supports
iOS only; Android may implement and test this same profile but cannot claim
v0.1 release support until its separate MVP gate changes.

## Decision

ADR 0025 supersedes only the cited GitHub transport sections of ADRs 0003,
0007, 0008, and 0023 for v0.1. ADR 0023's invitation-bound authority-key
bootstrap, signed device binding, atomic Prosopikon commit, receipt,
reconciliation, and audit requirements remain normative. Google, a future
GitHub authorisation-code PKCE/broker profile, stable-subject semantics,
authority ownership, and device-assurance policies are not superseded.

Official GitHub contracts used by this profile are [GitHub App user access
tokens via device flow](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app),
[GitHub App registration](https://docs.github.com/en/apps/maintaining-github-apps/modifying-a-github-app-registration),
and [the authenticated-user REST endpoint](https://docs.github.com/en/rest/users/users#get-the-authenticated-user).
Their exact version is captured in the reviewed App configuration digest.

### Registration and configuration commitment

The operator shall create one dedicated Mnemosyne Biosciences GitHub App per
environment, enable Device Flow, and configure its public **client ID** (not
App ID) in a reviewed release configuration. A client ID is not a secret and
must never authenticate a caller. No client secret, private key, webhook
secret, access token, refresh token or client-ID value is committed by this
ADR or embedded in an unreviewed build.

The exact registration manifest is: all repository, organisation and account
permissions **No access**; no subscribed events; no webhook URL or active
webhook; installation neither required nor requested; Device Flow enabled; and
GitHub's mandatory implicit Metadata read permission only. User access-token
expiration is enabled as the fixed profile policy; any access/refresh token is
discarded rather than refreshed. A registration that cannot express this exact
manifest is not eligible for this profile.

Before an implementation is enabled, an owner-reviewed preflight creates a
versioned canonical configuration record and SHA-256 `app_configuration_digest`
covering exactly: GitHub App owner and slug, public client-ID fingerprint,
`github.com` and API origins, Device Flow enabled state, every permission/event
value, webhook-disabled state, installation-not-required/not-requested state,
mandatory Metadata-read status, fixed user-token-expiration setting, permitted
installation profile (no installation or repository access), SDK/API-header
revision and profile version. The configuration record has no secret values.
Changing any committed field disables new enrolment until a new review,
physical evidence and Jenkins dossier bind the replacement digest.

The profile requests no OAuth scope expansion, no repository, organisation,
write or email access, and calls only `/user`. GitHub App user-token expiry
**is enabled** for this profile; Pistis never refreshes or retains either token
shape.

### Closed attempt and lifecycle state machine

One foreground enrolment owns one opaque CSPRNG local `attempt_id`, one
invitation and one device-flow capability. At most one non-terminal attempt
exists per local installation and invitation. `attempt_id` is never sent to
GitHub or used as an identity.

```text
idle -- explicit foreground start --> requesting_code
requesting_code -- validated device-code response --> awaiting_browser
awaiting_browser -- explicit trusted system-browser presentation --> browser_suspended
browser_suspended -- owned browser returns + explicit resume --> polling
polling -- authorization_pending / permitted transient retry --> polling
polling -- token --> identifying
identifying -- valid numeric /user subject + key proof --> awaiting_confirmation
awaiting_confirmation -- explicit confirm --> committing
committing -- durable receipt --> committed
committing -- uncertain delivery/result --> reconciling
reconciling -- matching durable receipt --> committed | terminal_failed
any active state -- cancel, expiry, invalid response, denial --> terminal
```

`browser_suspended` is a narrow trusted presentation state, not generic
background execution. It is entered only after the platform reports that the
application's owned external system-browser authentication presentation opened
the exact `https://github.com/login/device` origin. While suspended it does no
polling, networking or commitment; the transient capability remains only in
protected process memory and its monotonic expiry timer continues. Returning
from that owned presentation requires an explicit foreground **Resume
verification** action before polling begins.

Any unrelated backgrounding, scene loss, process death, replacement app,
untrusted browser return, memory warning that prevents protected retention,
user cancellation or monotonic-clock failure cancels the attempt. It clears
transient credentials and requires a fresh attempt. The one exception is the
owned, tracked `browser_suspended` presentation above. No capability is stored
to disk merely to survive process death.

Every terminal transition stops polling, clears secrets, leaves no partial
binding and rejects late, duplicate or replayed results. `expires_in` bounds
the attempt and a local policy may shorten it but never extend it. The client
may persist only redacted state needed for user-visible throttle/audit and,
after a completed commit request, non-secret reconciliation data defined
below.

### Exact GitHub wire profile and bounds

The adapter has fixed HTTPS origins, a disabled cookie jar, no redirect
following, no caller-controlled URL, and JSON-only responses. It sends a
bounded release User-Agent, `Accept: application/json`, and `Cache-Control:
no-store`; it never logs request bodies, authorization headers, response
bodies or redirect locations.

1. `POST https://github.com/login/device/code` uses no query string and has
   HTTP `Content-Type` exactly `application/x-www-form-urlencoded; charset=utf-8`.
   Its UTF-8 body contains exactly one ASCII `client_id`; no `scope` parameter
   is sent. The
   response `Content-Type` must be `application/json` with no charset or an
   explicit UTF-8 charset. The response
   body is at most 4 KiB and has exactly `device_code`, `user_code`,
   `verification_uri`, `expires_in`, and `interval`. `device_code` is ASCII
   40 bytes, `user_code` matches ASCII `^[A-Z0-9]{4}-[A-Z0-9]{4}$`, and
   `verification_uri` is byte-for-byte `https://github.com/login/device`.
   `expires_in` is an integer 1..900 and `interval` is an integer 1..60.
   Any missing, duplicate, unknown, malformed or out-of-bound member fails
   closed.
2. The app displays the literal `github.com` origin and user code in a
   foreground confirmation screen, then opens only the exact verification URI
   through its external system browser. It does not use a WebView, browser
   callback, provider-provided alternate URL or code-prefilled URL.
3. `POST https://github.com/login/oauth/access_token` uses no query string and
   has HTTP `Content-Type` exactly `application/x-www-form-urlencoded;
   charset=utf-8`. Its UTF-8 body contains exactly `client_id`, `device_code`
   and `grant_type=urn:ietf:params:oauth:grant-type:device_code`; duplicate
   keys are rejected before transmission. Its response `Content-Type` must be
   `application/json` with no charset or an explicit UTF-8 charset. A 4 KiB JSON
   success object has exactly `access_token`, `token_type`, `scope` and, when
   GitHub token expiration is enabled, `expires_in`, `refresh_token`, and
   `refresh_token_expires_in`. `token_type` must be `bearer`; scope must be
   empty; token strings are bounded printable ASCII (1..4096). Refresh-token
   fields are accepted only to discard them immediately. Any other success
   shape is terminal.
4. A JSON error object is at most 1 KiB and has exactly non-empty bounded
   `error` and optional bounded `error_description`/`error_uri`; unknown,
   duplicate or malformed members are terminal. `authorization_pending` is
   non-terminal. `slow_down` increases the current minimum polling interval by
   **exactly five seconds**. GitHub documents the expired-code wire value as
   `expired_token`; it is accepted as a terminal expiry. `token_expired` is
   not an accepted wire value and therefore fails closed as an unknown terminal
   error. `access_denied`, `incorrect_device_code`,
   `incorrect_client_credentials`, `unsupported_grant_type`,
   `device_flow_disabled`, any unrecognised error, and all malformed responses
   are terminal.
5. Exactly one successful token is used once for
   `GET https://api.github.com/user`, with `Authorization: Bearer` only on
   that request, `Accept: application/vnd.github+json`, and the reviewed
   `X-GitHub-Api-Version`. Redirects, cookies, non-200 responses and bodies
   over 64 KiB fail closed. The accepted object has an `id` whose original JSON
   numeric lexeme is `^[1-9][0-9]{0,19}$` and lexicographically no greater than
   `18446744073709551615`; floats, exponent notation, strings, signs, leading
   zeroes and parser-rounded values are rejected. Its canonical subject is that
   exact shortest decimal ASCII lexeme. Rust, iOS and Android share these
   `u64` boundary fixtures. `login`, `name`, `email` and `html_url` are optional,
   bounded display values and cannot affect identity or authorisation.

The implementation must parse duplicate JSON members as an error, bound every
string before allocation, reject control characters in display values, and
never copy the full provider response to evidence. It never calls token refresh,
installation-token, repository, email or arbitrary GitHub endpoints and never
accepts a personal access token, password, passkey, QR value or endpoint URL
as a substitute.

### Monotonic polling and rate control

All expiry and poll scheduling uses a monotonic clock. The first poll is no
earlier than the received interval; each later poll is no earlier than the
current interval after the prior request completed. On `slow_down`, precisely
five seconds are added for all remaining polls. A valid numeric `Retry-After`
on HTTP 429/503 may only increase the next delay; invalid or date-form
`Retry-After` is terminal because it cannot be interpreted with a wall clock.

Connection and response timeouts are bounded by ten seconds and never cross
the monotonic expiry. Before expiry, at most three transient transport or 5xx
retries are permitted, using in order `max(current interval, 5 seconds)`, then
`max(current interval, 10 seconds)`, then `max(current interval, 20 seconds)`;
each may be increased by valid `Retry-After`. No attempt makes more than 90
polls. A timeout, retry exhaustion, wall-clock jump, clock failure or expiry is
terminal. There is no automatic retry after app restart.

Persistent, non-secret installation-local throttle state records only bounded
failure category, cooldown class, configuration digest and counter. On a fresh
process it conservatively reapplies that class's reviewed elapsed-duration
cooldown rather than deriving authority from a wall-clock deadline. It limits
repeated phishing prompts and provider abuse but cannot prove that the browser
account belongs to the intended person; that residual risk is explicit and is
addressed by invitation constraints and final confirmation.

### User intent and session-misbinding controls

An attempt starts only after an explicit foreground action displays the exact
administrator invitation, target tenant/principal, proposed installation and
device key, operation purpose and configuration digest. A successful browser
login or token poll is never enrolment. After `/user` and key proof validate,
the app displays the bounded account snapshot together with that exact context
and requires a separate explicit **Confirm enrolment** action.

The confirmation rejects any numeric subject inconsistent with the invitation
constraint or tenant policy. It never infers a match from login, email,
browser session, passkey or a user code. Fixed origins, no redirects, one
attempt, trusted-browser suspension, explicit resume and confirmation reduce
device-flow phishing/session-misbinding risk but do not eliminate it. The
remaining risk is recorded in redacted audit and canary evidence.

### Platform-backed device-key proof

Before confirmation, the device signs one canonical CBOR
`enrolment_binding_v1` message with the proposed Pistis key. It contains
exactly: profile version, operation identifier, canonical invitation ID,
tenant ID, immutable Prosopikon principal ID, installation ID, provider
authority `github.com`, canonical numeric GitHub subject, compressed SEC1
device public key and derived key ID, key-assurance claim, operation purpose,
policy generation, `app_configuration_digest`, fresh authority challenge and
challenge expiry. The signature uses the accepted COSE/ES256 profile and its
exact canonical bytes, public-key encoding and low-S representation are shared
Rust/iOS/Android fixtures. Any changed field, malformed encoding, wrong key,
expired/replayed challenge or wrong profile is rejected before authority
mutation.

The fresh authority challenge is issued for the exact invitation/principal/
installation/configuration tuple, bounded to one operation and consumed only
by the authority transaction. iOS produces this proof through Secure Enclave
private-key use gated by Face ID. Android produces it through the expected
Android Keystore `CryptoObject` gated by `BiometricPrompt`; device credential
must not be relabelled as biometric proof. Existing-device continuation and
administrator authentication use their own reviewed key/session ceremonies,
not a GitHub token.

### Shared canonical byte contract

The following is the complete cross-project `enrolment_binding_v1` CBOR map.
It uses deterministic CBOR, unsigned integer keys in ascending order, definite
lengths, NFC UTF-8 text, byte strings for UUIDs/digests/keys, and a Unix
millisecond unsigned expiry. No field is optional and no additional field is
accepted:

| Key | Value | Fixture value |
| --- | --- | --- |
| 0 | profile text | `pistis.enrolment-binding.v1` |
| 1 | operation UUID bytes | `10` repeated 16 times |
| 2 | invitation UUID bytes | `20` repeated 16 times |
| 3 | tenant UUID bytes | `30` repeated 16 times |
| 4 | principal UUID bytes | `40` repeated 16 times |
| 5 | installation UUID bytes | `50` repeated 16 times |
| 6 | provider authority text | `github.com` |
| 7 | canonical provider-subject text | `18446744073709551615` |
| 8 | compressed SEC1 P-256 public key | fixture test key |
| 9 | derived 32-byte Pistis key ID | fixture-derived |
| 10 | key-assurance ordinal | `1` = Secure Enclave Face ID; `2` = Android Keystore biometric |
| 11 | purpose ordinal | `1` = enrolment; `2` add-device; `3` replacement; `4` governed-rebind |
| 12 | policy generation | unsigned `u64` |
| 13 | 32-byte App configuration digest | SHA-256 bytes |
| 14 | 32-byte fresh authority challenge | opaque bytes |
| 15 | exclusive authority-challenge expiry | Unix milliseconds, unsigned `u64` |

The fixture uses the map above with `operation=10`, `invitation=20`,
`tenant=30`, `principal=40`, `installation=50`, policy generation `7`, App
digest `55` repeated 32 times, challenge `66` repeated 32 times, and expiry
`1700000000000`. It is deliberately public and has no production identifier.

The binding is an untagged COSE_Sign1 with protected header bytes exactly
`{1: -7, 4: kid}`, empty unprotected headers, embedded payload and empty
external AAD. Its signature input is exactly canonical CBOR
`["Signature1", protected, h'', payload]`; it uses fixed-width low-S ES256.
The commit preimage is exactly canonical CBOR array
`["pistis.commit-enrolment.v1", binding_payload, invitation_id, tenant_id,
principal_id, installation_id, purpose_ordinal, policy_generation,
app_configuration_digest, authority_challenge, challenge_expiry_unix_ms]`.
`commit_digest` is SHA-256 of that complete preimage.

The receipt-lookup payload is exactly canonical CBOR map `{0: profile text
"pistis.enrolment-receipt-lookup.v1", 1: nonce bytes, 2: operation UUID
bytes, 3: commit digest bytes, 4: audience text}` and uses the same strict
untagged COSE Sign1 protected-header and `Sig_structure` rules. Its fixture
nonce is `77` repeated 32 times and audience is `prosopikon:pistis:enrolment`.

[`pistis-enrolment-v1-cross-project-001`](../../fixtures/protocol-v1/enrolment/pistis-enrolment-v1-cross-project-001.json)
is normative. It retains every payload, protected-header byte string,
`Sig_structure`, low-S signature, COSE envelope, complete commit preimage and
digest for Rust, Swift, Kotlin and Prosopikon. Its scalar-1 signing key is
public, compromised and fixture-only. Implementations must consume the same
file and reject byte changes; they must not regenerate a semantically similar
encoding.

Prosopikon-only `device_id`, storage challenge digest, binding/revocation/
installation/device generations, receipt fields, authorisation variants and
row projections are intentionally absent from these shared signed bytes. The
authority derives `device_id` and every post-state generation only after its
transactional reread. Expected pre-state generations, policy and revocation
snapshots come only from the authority-issued invitation/challenge capability;
they are never caller commit fields. Adding one to a shared byte preimage
requires a new coordinated profile and fixture.

### Canonical authority data and transaction

`github.com` plus the canonical numeric subject is unique within `(tenant_id,
provider_authority, provider_subject)`. A device key ID is unique within its
installation generation. An invitation canonically constrains tenant,
principal, permitted provider authority, optional exact numeric subject,
installation/device policy, expiry and single use; it cannot constrain a
login or email as an identity. These uniqueness rules, generation indexes and
foreign-key/migration semantics require an accepted versioned Prosopikon schema
decision and migration before this transport can be enabled.

Prosopikon alone performs `commit_enrolment_v1` in one transaction. It reloads
and consumes the invitation; verifies the exact authority challenge and key
proof; derives device identity and post-state generations; re-evaluates
principal, tenant, policy, revocation and device-generation state; applies the
policy-bounded multi-device rule in ADR 0012 (rather than a one-device
shortcut); binds provider subject and device/key generation; appends minimized
authority and Pistis audit; and stores an idempotent receipt. No GitHub token
creates or extends a Pistis, Monas, Synoptikon or Prosopikon session. Pistis
retains only a redacted local projection of the outcome.

The commit has a CSPRNG 128-bit `operation_id` and a `commit_digest` equal to
SHA-256 of the exact canonical `enrolment_binding_v1` plus profile and
invitation-commit fields. Both omit provider secrets. The separate one-use
verified authority capability is cryptographically bound to exactly
`operation_id`, `commit_digest`, purpose, audience, invitation and authority
snapshot; it is not a caller-supplied digest assertion. An exact replay of an
already committed operation/digest returns its immutable receipt. A divergent
pre-commit operation, capability or digest fails closed and receives only a
coarse authority audit. If delivery of a commit result is uncertain, the
client enters `reconciling`; it may obtain only the
matching minimized receipt through a device-key-authenticated receipt lookup.
The authority first issues a fresh, one-use, expiring lookup nonce without
revealing receipt existence. The device signs a canonical COSE
`enrolment_receipt_lookup_v1` envelope over exactly that nonce, `operation_id`,
`commit_digest`, authority audience and profile version. The authority accepts
the proof only from the bound device key, consumes the nonce, and returns a
receipt only for the exact matching pair. Not-found, unauthorized, wrong-key,
used/expired nonce and mismatched receipt cases use the same bounded neutral
status/body and indistinguishable redacted audit outcome. A mismatch, absent
receipt after the bounded reconciliation period, replay or second result is
terminal. The receipt has no bearer, browser session, token, code or full
provider data.

Every caller-controlled mutation fact is either a field of the signed binding
and complete commit preimage (operation, invitation, tenant, principal,
installation, provider subject, public key, assurance, purpose, policy,
configuration and authority challenge) or is rejected as non-authoritative.
Device identity, pre-state snapshots, storage generations, authorisation
decision and receipt values are exclusively authority-derived. A production
platform may produce a nondeterministic ECDSA signature; it must verify the
exact shared `Sig_structure` and enforce the same low-S ES256 representation,
not reproduce this fixture's deterministic scalar-1 signature.

### Token handling and Keeper boundary

Mobile runtimes cannot make a universal, compiler-proof promise to zeroize a
managed string or network buffer. The implementation must therefore minimise
secret copies; keep capabilities in bounded mutable buffers where the platform
permits; overwrite and release those buffers on every terminal path; disable
URL/cache/cookie persistence; and treat this as best-effort memory hygiene,
not a durable erasure claim. The security guarantee is stronger and testable:
these values are never intentionally persisted, logged, emitted to analytics,
crash reporting, evidence, Keychain, backup, Monas, Prosopikon or retry queue.

Pistis has no Keeper integration. Keeper may be selected only as the user's
operating-system credential provider inside GitHub's own `github.com`
system-browser/WebAuthn UI. Pistis cannot request, enumerate, import, export
or receive a GitHub passkey or Keeper vault secret.

### Acceptance, canary and rollback

Acceptance of this ADR activates nothing. Before implementation is enabled,
review requires deterministic synthetic tests for every state/field/error/bound,
interval/slow-down/retry/expiry path, secret-redaction path, authority
substitution/replay/rollback/idempotency case and fixture conformance; physical
iOS and Android lifecycle/browser/biometric/key-proof tests; and exact-revision
Jenkins/Expedition evidence with no live provider traffic or credentials.

In addition, an owner-controlled, consented, redacted live GitHub canary is
required after approved registration and before production enablement. It uses
a dedicated non-production App/profile and test principal, stores only config
and event digests plus minimized receipt/audit correlations, confirms no
token/capability appears in retained diagnostics, and is disabled after review.
It is evidence of the provider contract, not authorisation to enrol production
users.

Production enablement additionally requires an owner-attested record outside
source control of the real App owner/slug, public client-ID fingerprint and
`app_configuration_digest`, plus one consented production-identity `/user`
check bound to a non-production invitation and then revoked/expired. The
record contains no token, code, login, email or full provider response. The
owner and security reviewers must explicitly accept the residual public-client
impersonation and user-code phishing risk after reviewing a controlled
look-alike-client/user-code attack exercise; a public client ID cannot prevent
an attacker from initiating a convincing GitHub flow, only the invitation,
key-proof and confirmation/authority controls from committing it here.

Rollback disables local enrolment and Device Flow for the reviewed App/profile
and cancels pending local attempts. Revoking a GitHub authorisation prevents
future provider use but **does not revoke an existing local device, principal
binding or session**. Those require the explicit Prosopikon/ADR-0012 device,
binding and session-revocation transactions. Suspected capability exposure
requires both GitHub-side authorisation revocation and the separate local
authority decision.

A future confidential-broker plus PKCE profile must be separately proposed
with a distinct profile identifier and migration rules. It must not silently
fall back from this profile or weaken its numeric-subject, proof, transaction,
confirmation or token-retention invariants.

## Decision record

The project owner accepted this decision on 2026-07-28 after the recorded
mobile, security, protocol, and authority review. That acceptance explicitly
includes the residual public-client impersonation and user-code phishing risk
described above; the platform-key proof, fresh biometric confirmation, bounded
polling, token non-retention, and single Prosopikon authority transaction are
mandatory compensating controls.

This decision record does not activate a client ID or authorise an
implementation or production deployment. Issue PIS-E22-I252 remains the
implementation and enablement gate, including the configuration commitment,
physical-device evidence, canary, attack exercise, and production attestation
required by this ADR.

## Consequences

- v0.1 gains a precise no-secret-broker GitHub App transport profile without
  turning a public client ID into an authority credential.
- Device flow has weaker provider-side correlation than PKCE, so trusted
  browser lifecycle, explicit confirmation, platform-key proof and authority
  transaction rules are mandatory release gates.
- The shared iOS/Android profile preserves one security contract while leaving
  Android's separate MVP-support decision unchanged.

## Alternatives considered

- Retain ADR 0003's confidential broker and PKCE transport: stronger callback
  correlation, but incompatible with the v0.1 no-broker deployment decision.
- Embed a client secret, private key or personal token: rejected because a
  public mobile client cannot protect them.
- Treat a user code or successful poll as enrolment: rejected because either
  can be phished, substituted or detached from invitation and key proof.
- Revoke a local device when GitHub authorisation is revoked: rejected because
  it bypasses Prosopikon's durable device/binding/session authority.
