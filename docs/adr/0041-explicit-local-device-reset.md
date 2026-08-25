# ADR 0041: Explicit local-device reset

- Status: Accepted
- Date: 2026-08-24
- Accepted: 2026-08-24 by explicit product-owner direction
- Decision owners: product owner, Pistis mobile security, Monas authority and
  Thesaurophylax custody
- Tracking issue: [#474](https://github.com/sagrudd/pistis/issues/474)
- Implementation: permitted as a local erasure capability; merge and release
  remain subject to specialist security review and physical-iPhone evidence

## Context

Pistis intentionally retains installation trust, identity bindings, App Attest
references, recovery material and Secure Enclave keys outside ordinary view
lifecycle. Deleting and reinstalling an iOS application is not a dependable
reset because Keychain material can survive. During controlled development and
device retirement an operator needs a truthful way to make one iPhone locally
incapable of using any retained Pistis identity or installation.

ADR 0030 correctly prohibits presenting disappearance of an active local record
as authority-backed account or installation removal. A local cryptographic
erasure has a different meaning: it intentionally destroys this phone's ability
to use its old credentials, while server sessions, authority recognition,
revocation state and audit evidence remain until their own governed lifecycle
completes.

The distinction is operationally important. If a phone holding the only Site
Root or recovery key is reset before authority recovery or a bounded
development teardown completes, the retained host authority can become
unrecoverable through the normal flow.

## Decision

### User interaction

Settings exposes **Reset Pistis on this iPhone** in a visibly destructive
section. Selecting it opens a native confirmation dialogue titled **Are you
really sure?**. The dialogue states that the operation:

- permanently deletes all Pistis identities and installations stored on this
  iPhone;
- leaves server sessions, authority records and audit evidence unchanged;
- requires Face ID; and
- cannot be undone.

Cancellation performs no authentication and no mutation. Confirmation requires
one fresh Face ID evaluation before the first store changes. The reset is not
available through a URL, QR payload, notification, background task or remote
request.

### Closed local scope

The reset attempts every item in this closed list:

1. current and legacy installation-trust Keychain records, including the local
   provider-identity projection;
2. every Secure Enclave key whose application tag begins with the exact Pistis
   prefix `org.mnemosyne.pistis.device-key.`;
3. the primary and pending App Attest key-ID references;
4. the first-authority recovery envelope;
5. the Site Root convergence acknowledgement record;
6. non-authorising Site Root installation/setup projections;
7. local diagnostic history; and
8. the bounded onboarding event journal.

The Secure Enclave deletion enumerates attributes and deletes only exact tags
selected under the closed prefix. It must not issue a broad Keychain deletion
or select another application's key.

Apple owns the opaque App Attest private key and supplies no application API to
delete it. Pistis deletes its local key-ID references so the old credential is
no longer addressable by the app. This is not Apple-side destruction or
authority-side revocation.

Browser cookies, GitHub accounts, provider credentials, NUC state, Prosopikon
records, Proxenos Site Trust, Thesaurophylax custody, product data and authority
audit evidence are outside the local reset.

### Ordering and partial failure

Face ID is a precondition. If it fails or is cancelled, no store is touched.

After authorisation, installation trust is erased first so an orphaned key
cannot remain locally authorising. Every remaining closed store is attempted
even if another erasure fails. This is intentionally best-effort across stores
that cannot participate in one atomic transaction.

Pistis returns to initial onboarding only after every closed target succeeds.
If any target fails, Settings remains visible and reports **Pistis reset is
incomplete**. It must not claim that nothing changed, claim complete rollback,
or present the device as fresh. Repeating the idempotent operation attempts the
remaining material.

### Relationship to authority lifecycle

This decision adds local cryptographic erasure; it does not supersede ADR 0030
authority-backed departure or ADR 0040 Site Root replacement.

Before resetting the only enrolled phone, an operator must first choose and
complete one of these authority outcomes:

- revoke/replace the exact device through an accepted authority recovery flow;
- complete a bounded development teardown of every retained authority and
  custody generation; or
- accept that the old authority remains and cannot be treated as a fresh first
  install.

`monas-first-install teardown --confirm` is not automatically sufficient. Its
documented boundary preserves Proxenos and Thesaurophylax state and refuses when
protected Site Root custody is retained. Operators must not bypass that refusal
with manual file or database deletion.

## Consequences

- A controlled iPhone can be returned to an honest local pre-enrolment state.
- A reset phone never implies that the corresponding authority identity,
  installation, role, session or audit record disappeared.
- Fresh onboarding after reset is gated by server-side reconciliation or a
  separately accepted complete development teardown.
- A partial reset may remove some local diagnostic context while retaining an
  item that needs another attempt; the UI reports this truthfully.
- The operation is intentionally unsuitable as ordinary account removal.

## Required evidence

- UI tests prove the destructive label, exact warning, confirmation and
  cancellation path.
- Unit tests prove Face ID failure causes no mutation, every closed target is
  attempted in order, partial failures do not mark onboarding incomplete, and
  successful completion survives relaunch.
- Prefix-selection tests prove foreign and near-miss Secure Enclave tags are
  excluded.
- Repository tests prove local projections are empty after reset.
- A physical-iPhone test records the pre-reset inventory, cancels once, resets
  once, relaunches, verifies empty identities/installations/history, and proves
  the old device keys can no longer sign.
- An end-to-end qualification follows the gate-by-gate Monas first-login
  runbook and records exact source, build and host revisions.
