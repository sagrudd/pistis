# ADR 0030: Authority-backed account and installation removal

- Status: Accepted
- Date: 2026-07-30
- Accepted: 2026-07-30
- Decision owners: Pistis mobile security, Prosopikon authority, Monas
  transport, and product owner
- Tracking issue: [#344](https://github.com/sagrudd/pistis/issues/344)
- Implementation: permitted in dependency-ordered slices with the required
  cross-project review and evidence

## Context

A person may use several accounts from the same identity provider, hold
different roles on different installations, or temporarily join a customer
installation as a field applications support scientist. The person must be
able to leave those relationships from Pistis.

Deleting only the phone's projection would be unsafe: the authority could
continue to recognize the device, account, or roles while Pistis falsely
reported their removal. Conversely, deleting durable authority audit evidence
would prevent investigation and accountability. Mutable provider login or
email is not a safe deletion key.

## Decision

### Exact targets

Every destructive request identifies an exact authority, installation,
external binding, provider authority, immutable provider subject, device, and
expected generation. Roles are installation-and-binding scoped. Login, email,
display name, and local username are presentation fields and never identify a
destructive target.

Pistis exposes two different authority operations:

1. **Leave this installation** revokes the caller's exact account,
   installation, device, and role binding on one authority. It does not delete
   the installation, another account, another device, or another person's
   roles.
2. **Remove this provider account** enumerates every exact installation
   binding known to the phone and requests the first operation separately from
   each owning authority. It is not represented as globally atomic across
   independent customer systems. Pistis displays each success, refusal,
   unreachable authority, and remaining binding.

A support user's departure therefore removes only that support relationship.
Customer data, the customer installation, and other operators remain intact.

### Destructive interaction

The provider-account detail and installation detail screens show the provider
login, authority, installation, local username, and roles that will be
affected. A destructive slide-to-confirm control is required. VoiceOver,
Switch Control, keyboard, and other users receive an equally deliberate
non-gesture confirmation action; accessibility must not weaken confirmation.

Immediately before submission Pistis requires local user presence under the
enrolled device-key policy. The signed request commits the exact target,
expected generation, action, fresh authority challenge, issued time, expiry,
and idempotency identifier. A generic session cookie, provider login, or local
screen unlock cannot substitute for that proof.

### Authority transaction and replay

Prosopikon owns one durable transaction that validates current device,
identity, installation, role, policy, and revocation state; enforces the
expected generation; records a minimized audit event; advances the revocation
generation; and returns an authority-signed removal receipt. Exact replay
returns the byte-identical result. A changed replay fails closed.

An authority refuses a removal that would violate its accepted minimum
administrator policy. The UI explains that another administrator must be
appointed first; it never silently transfers or broadens authority.

Monas transports the bounded request and response without making an
authorization decision. Provider credentials do not participate and never
cross this boundary.

### Local completion, failure, and forgetting

Pistis deletes the affected local authorization material only after verifying
the authority receipt under the already trusted authority key. If local
cleanup then fails, the item is shown as **revoked — cleanup required** and
cannot authorize. It is never shown as active.

An offline, timed-out, refused, or malformed authority response leaves local
material intact and shows the exact binding as **removal not completed**.
Retry uses the same idempotency identifier when safe. Pistis never reports
authority removal merely because a local record disappeared.

An already expired, inactive, or authority-revoked installation may instead
offer **Forget local record**. This action clearly states that it removes only
this phone's cached record and cannot change server state. It requires the
same deliberate local confirmation. It is never available as a shortcut for
an active binding.

Immutable, minimized history remains after credential cleanup: action,
authority and installation identifiers, account class, outcome, receipt
digest, and time. Provider subject plaintext, email, credentials, invitation
material, private keys, and unrelated roles are not retained in local history.
Authority audit evidence is never deleted by either operation.

## Consequences

- Multi-account projection from issue 340 is a prerequisite for active account
  removal; no implementation may infer account identity from the current
  version-one generic display.
- The expired evaluation-v5 installation may use the local-forget path, because
  it cannot authorize, without pretending that its authority history was
  erased.
- Removing one account from several independent customer authorities may be
  partially complete and must remain visibly reconcilable.
- Account removal is not provider-account deletion at GitHub or another
  provider.

## Required evidence

- Two GitHub accounts, GitHub plus Google, reused display login, multiple roles,
  and two installations never cross-target.
- Support departure preserves the customer installation and other users.
- Last-administrator removal is refused without mutation.
- Wrong generation, target, device, challenge, signature, authority, and
  replay variants fail closed.
- Offline retry, exact replay, authority success followed by local cleanup
  failure, expired local forget, and restart recovery are deterministic.
- UI and accessibility tests prove the destructive slider, affected-scope
  summary, non-gesture alternative, and truthful partial-failure states.
- Audit and logs pass redaction tests.
