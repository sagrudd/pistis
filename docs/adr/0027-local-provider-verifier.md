# ADR 0027: Installation-local GitHub provider verifier

- Status: Proposed
- Date: 2026-07-29
- Decision owners: Pistis security and mobile, Prosopikon authority, Monas
  transport, and deployment
- Related issue: PIS-E22-I318
- Would supersede: the direct-mobile GitHub request, polling, token, and
  `/user` transport sections of ADR 0025 only

## Context

Accepted ADR 0025 places the GitHub App Device Flow and `/user` request on the
phone. That lets Pistis display GitHub's immutable numeric account subject, but
it does not let Prosopikon verify the observation. GitHub's `/user` JSON is not
a signed identity assertion, the proposed device key is not trusted before
enrolment, and the public GitHub App client ID authenticates no caller.

Forwarding the phone's bearer or copied JSON to Monas or Prosopikon would only
move an untrusted assertion across the boundary. Asking the user or an
administrator to copy the numeric subject would be weaker still. A GitHub App
JWT or installation token authenticates the App or installation, not the
human user. None can complete ADR 0023's authority transaction.

GitHub Device Flow is available to headless and CLI software. The installation
can therefore own the provider exchange while the user still opens GitHub on
the phone and authorizes there. This requires no Mnemosyne-hosted broker,
callback URL, client secret, webhook, App installation, repository permission,
or push service. It does require a narrow local provider-verifier boundary and
changes ADR 0025's token location.

## Proposed decision

For enrolment, one installation-local Pistis provider-verifier adapter shall
own the exact GitHub Device Flow request, polling, token handling, and `/user`
request. The iOS or Android application shall display the returned user code,
open the fixed GitHub verification URI in the system browser, present the
verified account result, collect explicit confirmation, and sign the existing
canonical device-binding payload. It shall not receive a GitHub token or a
copy of GitHub's raw response.

The adapter shall run inside the reviewed Monas process for the MVP. It is a
narrow provider port, not an enrolment authority or a second durable state
machine. Prosopikon remains the sole owner of invitations, principals,
provider bindings, devices, generations, one-use state, receipts, and audit.
The adapter may call only authority methods that create, complete, deny, or
expire one provider-verification operation.

This proposal activates nothing. ADR 0025 remains normative until this ADR is
accepted, its shared contract and fixtures are reviewed, and the affected
implementation gates pass.

### One authority-owned operation

Prosopikon creates a CSPRNG `provider_verification_id` and one durable
`provider_verification` row before any GitHub request. It is distinct from the
client-generated enrolment `operation_id`. The row is bound to:

- exact enrolment `operation_id`;
- exact invitation, tenant, principal, provider authority, purpose, and
  product audience;
- proposed device public-key and key-ID digest;
- installation identifier and generation;
- ADR 0025 App-configuration digest;
- authority revision, policy generation, and revocation generation;
- issue time, lifetime, and terminal expiry; and
- a fresh operation nonce and canonical digest of those initial fields.

The public mobile transport receives a distinct fresh 32-byte CSPRNG polling
capability for the exact `provider_verification_id`; Prosopikon stores only its
digest.
That capability permits only status, cancellation, and final confirmation for
the exact operation. It is not provider proof, cannot mark an operation
verified, and is never accepted by `commit_enrolment_v1`.

Denied, expired, cancelled, and consumed states are terminal. Pending may
transition only to verified, denied, cancelled, or expired; verified may
transition only to consumed, cancelled, or expired. Concurrent completion uses
one compare-and-set transition. A verified row is consumed in the same SQLite
transaction as the invitation, provider binding, trusted device credential,
generations, receipt, and audit. Exact committed replay returns the immutable
receipt; divergent replay fails closed.
The authority derives the final `commit_digest` only after the verified subject
is present and the phone supplies the complete signed binding. It accepts that
digest only when the binding's initial fields match the durable operation and
its provider subject matches the adapter-authenticated observation, then stores
the digest with the consumed operation and immutable receipt.

### Exact provider-verifier boundary

The adapter receives a Prosopikon-created provider-verification handle through an
in-process, non-public Rust port. Only that port can submit a bounded verified
observation. No public HTTP request, browser field, mobile JSON, email, login,
user code, or caller-supplied digest can construct the authority input.

The adapter reuses ADR 0025's fixed origins, disabled redirects and cookies,
closed JSON shapes, numeric-subject parsing, response limits, API revision,
scope prohibition, polling interval, `slow_down`, retry, and timeout rules.
The public client ID and reviewed App-configuration digest are deployment
configuration, never caller input.

The adapter:

1. asks GitHub for one device code using the exact reviewed public client ID;
2. retains `device_code` only in bounded process memory;
3. returns only the bounded `user_code`, exact fixed verification URI, expiry,
   and redacted operation status through Monas;
4. polls GitHub no faster than the returned interval and ADR 0025 limits;
5. uses one successful bearer exactly once for the fixed `/user` endpoint;
6. validates the exact unsigned 64-bit numeric subject and bounded display
   projection;
7. discards access and refresh tokens and the raw response on every terminal
   path; and
8. asks Prosopikon to mark the exact operation verified with only the numeric
   subject, minimized display projection, configuration digest, and outcome
   time.

The token never crosses the adapter port into Monas routing, mobile transport,
Prosopikon, logs, evidence, SQLite, crash reporting, or retry storage. Managed
runtime erasure remains best effort; non-persistence and boundary exclusion
are testable guarantees.

### Mobile flow and user intent

The phone starts only from an authority invitation and a fresh proposed
platform key. Monas returns a bounded enrolment-attempt response containing the
fixed GitHub verification URI, user code, expiry, and non-authoritative polling
capability. The phone opens only that URI in the system browser. Keeper may
participate only inside GitHub's own WebAuthn UI.

The phone polls Monas, not GitHub. After the local verifier succeeds,
Prosopikon supplies the exact numeric subject and bounded display projection
for the pending operation. The phone shows that account together with the
invitation, tenant, installation, proposed key, purpose, and configuration
digest. A successful provider check is not enrolment. The user must explicitly
confirm with the required local biometric or device-key policy and sign the
unchanged ADR 0025 `enrolment_binding_v1` bytes.

Prosopikon compares the signed subject and every bound field with its verified
operation and current authority state inside `commit_enrolment_v1`. Any
substitution, expiry, cancellation, replay, changed key, changed invitation,
changed configuration, rollback, or generation change fails before mutation.

### Restart and deployment

No token or device code survives process death. A restart makes every polling
operation terminal and requires a fresh Device Flow. A verified but unconsumed
operation may survive only for its original short expiry because Prosopikon
durably recorded the adapter-authenticated outcome; it can be consumed only by
the exact signed binding and invitation transaction.

The verifier is disabled unless the complete reviewed GitHub profile and
Prosopikon authority are configured. Customer-hosted installations use their
own reviewed GitHub App registration or an explicitly accepted shared-App
policy; no Mnemosyne server is required. Egress is restricted to the exact
GitHub origins. The verifier exposes no general OAuth, proxy, token
introspection, repository, email, or arbitrary-URL function.

The development software installation signer is orthogonal. It may support an
isolated evaluation of Monas challenge signing but does not authenticate the
provider verifier and does not make the deployment production eligible.

### Fresh-authority startup lifecycle

A fresh authority has no provider binding or trusted device, while the normal
Monas Pistis runtime correctly refuses to listen until
`pistis_login_target` resolves both. The verifier cannot be reached through
that normal runtime. Implementations shall not solve this circular dependency
by inserting a device manually, weakening normal startup, or running a second
authority.

Monas shall therefore define one explicit, attended `provider_enrolment`
startup mode. It is a deployment setting, not a browser, mobile, invitation,
or query parameter. In that mode Monas:

- opens the exact fresh authority and verifies its configured active
  principal, tenant, authority revision, installation identity and signer;
- requires no active or suspended provider binding or device for that
  principal and requires one still-valid first-device invitation;
- deliberately does not call the normal login-target readiness check;
- mounts only the versioned first-device enrolment begin, status, cancel,
  confirmation and bounded mobile transport plus coarse health/support;
- does not mount product, Propylaion, login, session, compatibility-password,
  EasyConnect, Jenkins, general Prosopikon, or ordinary Pistis ceremony routes;
- retains no provider token or device code across restart and creates no
  session; and
- becomes terminal for new enrolment work when the exact invitation commits,
  is denied, expires, or is cancelled.

Successful commit does not hot-upgrade the process into an authenticated
product host. The attended operator stops it, removes the enrolment-only
setting and invitation material, and starts normal Monas. Normal startup then
performs the unchanged `pistis_login_target` check against the newly committed
binding and trusted credential. A process configured for enrolment mode after
an active or suspended device exists fails before listening.

The compatibility password registry must be absent and non-writable in both
modes. The first invitation is issued by the attended Prosopikon CLI while
Monas is stopped; its bearer is delivered only through the reviewed enrolment
bootstrap input and is never written to the environment file, command line,
logs, or evidence. Exact packaging, socket activation, restart, and cleanup
behavior require Monas and Prosopikon review before implementation.

### Audit and privacy

Durable authority audit records only the provider-verification and enrolment
operation identifiers, invitation and commit digests, provider authority,
canonical numeric subject where policy permits, configuration digest, coarse
result, timestamps, and resulting authority receipt correlation. It records no
token, device code, user code, refresh token, raw provider response, login,
email, browser cookie, polling capability, or private key.

Operator diagnostics expose bounded counts and coarse states only. Rate-limit,
transport, malformed-response, denial, expiry, cancellation, and substitution
events are indistinguishable at the public polling boundary where disclosure
would create an oracle.

## Required acceptance before implementation

- specialist security, Prosopikon, Monas, mobile, and privacy approval of this
  decision and its threat analysis;
- a versioned Prosopikon schema decision for the one durable operation and its
  restart, uniqueness, expiry, consumption, and migration behavior;
- exact Rust/Swift/Kotlin request, response, binding, and negative fixtures;
- deterministic tests for every GitHub response, bound, interval, retry,
  timeout, cancellation, restart, concurrency, replay, rollback, and
  substitution path;
- startup tests proving normal mode rejects an unenrolled principal,
  enrolment-only mode exposes only its closed route set, a pre-existing device
  rejects enrolment mode, and successful commit requires an attended restart
  into normal mode;
- tests proving provider credentials never enter Monas transport, Prosopikon,
  SQLite, logs, evidence, crash reports, or mobile storage;
- an attended consented GitHub canary using the reviewed development App and a
  fresh authority, followed by authorization and installation revocation;
- retained exact-revision Jenkins evidence and physical-iPhone enrolment; and
- a documented kill switch that disables new provider verification without
  revoking already-enrolled local devices by implication.

## Consequences

- Prosopikon can verify the GitHub subject without trusting mobile data or
  receiving a bearer.
- The user still completes GitHub Device Flow on the phone, but the
  installation rather than the phone owns the provider exchange.
- No dedicated Mnemosyne broker or customer callback registration is needed.
- Fresh installation gains a deliberately separate, temporary enrolment-only
  process profile; normal Monas startup remains fail-closed and unchanged.
- ADR 0025's current direct-mobile client remains useful only as a visibly
  non-authoritative diagnostic until replaced in the enrolment flow.
- The local installation gains outbound GitHub dependency during enrolment;
  routine Pistis authentication remains local and provider-independent.
- Public-client impersonation and user-code phishing remain residual risks,
  bounded by the invitation, fixed origins, explicit account confirmation,
  platform-key proof, authority transaction, rate controls, and audit.

## Alternatives considered

- Trust the phone's numeric subject or copied `/user` JSON: rejected because
  neither is an authority-verifiable assertion.
- Forward the phone's bearer to the host: rejected because it expands token
  exposure and makes mobile transport a credential channel.
- Run two Device Flows, one on the phone and one on the host: rejected because
  they can resolve different accounts and create an avoidable misbinding risk.
- Use a GitHub App JWT or installation token: rejected because those identify
  the App or installation, not the authorizing human.
- Ask an administrator to enter the subject: rejected because manual entry is
  forgeable and substitution-prone.
- Operate a shared Mnemosyne confidential broker: deferred because the MVP and
  customer-hosted profile require a local deployment with no dedicated
  authentication server.
- Issue a new signed provider-capability wire token: rejected for the MVP
  because the authority-owned verified row is not caller-supplied, is consumed
  atomically, and avoids a second signing-key lifecycle and canonical protocol.
