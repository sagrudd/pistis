# Pistis first-device onboarding and first Monas web login

This runbook is the attended, gate-by-gate procedure for onboarding one Pistis
iPhone and using it to create the first formal Monas web session. Complete one
gate at a time. Record its evidence and stop on any mismatch; do not improvise
a second QR route, edit authority databases, copy private keys or repeatedly
restart services.

The procedure distinguishes three different events:

1. **Local Pistis reset** erases this iPhone's Pistis state only.
2. **Formal first install** creates the installation, Site Trust, custody,
   GitHub identity and initial administrator evidence.
3. **Normal Monas login** creates a short-lived, exact-audience web session.

None is evidence that another one completed.

## Run record

Create one run record before starting:

| Field | Recorded value |
|---|---|
| Date and operator | |
| NUC hostname and address | |
| Monas package version and source revision | |
| Kanon lockset ID and digest | |
| Terraform source revision | |
| Pistis version, build and source revision | |
| iPhone model and iOS version | |
| Native Monas HTTPS origin | |
| Outcome of each gate | |

Do not record QR payloads, bootstrap codes, browser capabilities, cookies,
provider tokens, private keys or complete signed proofs.

## Gate 0 — Choose retained recovery or genuine fresh development state

**Purpose:** prevent a local phone reset from destroying the only key capable
of recovering a retained Site Root.

On the NUC, run only the read-only checks:

```bash
sudo monas-first-install --status
sudo monas-first-install teardown
```

The second command prints the bounded teardown plan and makes no change because
`--confirm` is absent.

Choose exactly one route:

- **Retained authority recovery:** do not press the Pistis reset button. Follow
  the separately accepted recovery or Site Root replacement procedure.
- **Genuine fresh development install:** while the old phone keys still exist,
  complete the reviewed authority/custody teardown and verify that no retained
  Site Root, App Attest registration, provider binding or installation owner
  remains eligible.

### Pass condition

For a genuine fresh run, the NUC has authoritative evidence that every prior
development installation/device generation is retired and that a new Site Root
may be issued. Proxenos and Thesaurophylax agree with that state.

### Stop conditions

Stop if status says that the Site Root is retained, the signed first-device
identity receipt is retained, or the installation is committed. The current
`monas-first-install teardown --confirm` deliberately preserves Proxenos and
Thesaurophylax and refuses protected retained custody; do not bypass that
refusal manually.

## Gate 1 — Install and identify the qualified Pistis build

**Purpose:** ensure the phone contains the build whose reset and QR contracts
were tested.

Install the reviewed, distribution-signed Pistis build. In **Settings → About
Pistis**, record the application version and build. Match its source revision
and archive digest to the run record.

### Pass condition

- The bundle identifier is `org.mnemosynebiosciences.pistis`.
- Production App Attest entitlement and distribution signing are present.
- The build contains **Settings → Reset this iPhone → Reset Pistis on this
  iPhone**.

### Stop conditions

Stop for a development signer, a different bundle identifier, an unknown
archive digest or a build without the reset regression evidence.

## Gate 2 — Reset Pistis locally

**Purpose:** erase the old Pistis identities, installations and app-owned local
cryptographic state only after Gate 0 has made that safe.

1. Open **Pistis → Settings**.
2. Scroll to **Reset this iPhone**.
3. Tap **Reset Pistis on this iPhone**.
4. Read the **Are you really sure?** dialogue.
5. First tap **Cancel**. Verify that the existing Pistis screens remain. This
   witnesses the non-mutating cancellation path.
6. Open the dialogue again.
7. Tap **Reset identities and installations**.
8. Complete the fresh Face ID prompt once.
9. Wait for Pistis to return to its initial onboarding screen.
10. Force-quit and relaunch Pistis.

### Pass condition

- The initial onboarding screen remains after relaunch.
- After entering the app, **Identities**, **Installations** and **History** are
  empty.
- No **Pistis reset is incomplete** alert appeared.

The reset does not log out GitHub in Safari, revoke Monas sessions, delete
authority audit evidence or remove Apple's opaque App Attest private key. It
removes Pistis's reference to that App Attest credential.

### Stop conditions

Stop if the app reports an incomplete reset, relaunch skips onboarding, or any
identity/installation remains. Do not begin first install from a partially
reset phone.

## Gate 3 — Verify the NUC package and dependency baseline

**Purpose:** prove that a new ceremony starts from one supported host build.

Run:

```bash
sudo dpkg --audit
sudo monas-first-install --status
```

Also verify the installed Monas, Thesaurophylax, Proxenos and DASObjectStore
packages against the exact Kanon lockset and Terraform projection recorded for
this run.

### Pass condition

- `dpkg --audit` prints nothing.
- DAS and Proxenos prerequisites are active.
- Thesaurophylax reports the accepted pre-enrolment custody profile.
- Site X.509 first-provision configuration is present.
- No retained installation or identity causes reconciliation mode.
- No first-install, protected-custody or broker lease is already active.

### Stop conditions

Stop on `identity-receipt-retained`, `committed`,
`reconciliation-required`, a retained Site Root, a stale active lease, a
source/lockset mismatch or an unexpected failed package.

## Gate 4 — Start the single supported first-install command

**Purpose:** create one attached host rendezvous.

In one SSH terminal on the NUC run:

```bash
sudo monas-first-install
```

Keep that terminal open. Do not run another copy of the command and do not
start individual Monas or Thesaurophylax units manually.

### Pass condition

The terminal prints:

- the ordered route state;
- `https://install.mnemosyne.co.uk`;
- one short-lived code and its expiry; and
- an instruction to keep the terminal attached.

### Stop conditions

Stop if the command selects reconciliation without a new code, reports an
inactive or incompatible protected route, or cannot start its broker
rendezvous. If the code expires unused, let the command settle and then start
one new run; never reuse or transcribe an expired code.

## Gate 5 — Redeem the code and verify GitHub

**Purpose:** bind the browser ceremony to the attended host and the verified
GitHub identity.

1. Open `https://install.mnemosyne.co.uk` in one browser window.
2. Enter the exact code printed by the attached NUC terminal.
3. Authenticate with GitHub when redirected.
4. Review the GitHub account and submit once.
5. Return to the same install window.

### Pass condition

The browser says the code was accepted and advances to the first protected
Pistis event. The terminal independently reports broker acceptance. GitHub
display text is not treated as the immutable identity; the authority binds the
numeric GitHub subject.

### Stop conditions

Stop on an unknown/expired code, a second browser attempting the same code, a
different GitHub account, a page outside the fixed install origin, or a browser
that offers only discard/cancel after provider approval.

## Gate 6 — Approve the protected Site Root genesis QR

**Purpose:** create the first iPhone Site Root key and App Attest binding.

The install browser must display exactly one protected **Site Root genesis** QR
for a genuinely fresh installation.

1. In Pistis, open **Scan**.
2. Scan the QR directly from the install browser.
3. Review the installation, destination, expiry and first-device purpose.
4. Approve once with Face ID.
5. Leave both browser and NUC terminal open.

### Pass condition

Pistis reports accepted proof submission, the browser advances, and the NUC
records the exact Site Root/App Attest fact. The phone shows one setup-in-
progress installation and does not yet show an authenticated GitHub identity.

### Stop conditions

Stop for **unsupported Pistis QR code**, **Site Root authority unavailable**,
an expired QR, an unexpected retained-authority recovery presentation, a
second Site Root QR, or endless Face ID waiting. Do not rescan the same QR after
an ambiguous submission; first inspect the host's durable state.

## Gate 7 — Approve the protected Site X.509 QR

**Purpose:** authorise the initial native HTTPS root, issuer and exact service
leaf set without reissuing Site Root.

The same install browser must next show one protected **Site X.509 first
provision** QR.

1. Scan it from the Pistis **Scan** tab.
2. Verify the displayed Monas/DAS services, addresses and generation.
3. Approve once with Face ID.
4. Keep the browser and terminal attached while custody continuation,
   acknowledgement registration and paired-leaf activation complete.

### Pass condition

- Pistis accepts the protected Site X.509 result.
- The browser does not request a second Site Root QR.
- Root custody, issuer custody, acknowledgement registration and initial leaf
  approval complete in their documented order.
- The NUC accepts the native TLS manifest for the Monas and DAS pair.

### Stop conditions

Stop for an unprotected/root QR, **custody ceremony unavailable**, **waiting
for Face ID** after Face ID already completed, an unsupported QR, an authority
generation mismatch or a host-side partial transaction. Do not start custody
units manually.

## Gate 8 — Commit the GitHub identity and initial administrator

**Purpose:** turn verified provider identity and signed iPhone registration
into the formal installation evidence.

Follow the browser and Pistis instructions for the provider-enrolment review.
Approve only the GitHub numeric subject and installation shown for this run.

### Pass condition

- Prosopikon durably commits one signed first-device enrolment receipt.
- Pistis shows one trusted installation and one GitHub identity.
- The authority projects exactly one `dasobjectstore/Administer` owner grant.
- The NUC profile commit is idempotently complete.

### Stop conditions

Stop if the phone says an identity already occupies the device, if the
provider subject differs, if identity trust appears before the signed receipt,
or if Monas reports success from files/systemd state without revalidating the
receipt.

## Gate 9 — Activate the protected authority and web surface

**Purpose:** expose normal Monas only after formal enrolment.

The original `sudo monas-first-install` process performs this automatically.
Do not run another command while it is progressing.

### Pass condition

- The terminal reports formal installation complete.
- `monas-pistis-authority.service` is active and owns the fixed Jenkins
  authority socket.
- `monas-pistis.service` is active on the native HTTPS origin.
- Oikodome reaches its package-owned readiness gate if it is part of the
  recorded release graph.
- No bootstrap/genesis listener remains active.

### Stop conditions

Stop on **production authority profile is invalid**, a stale authority socket,
bootstrap/authority overlap, activation from an unverified profile, or a
listener on an unapproved origin. A socket inode without a listener is stale
state, not an authority.

## Gate 10 — Perform the first normal Monas web login

**Purpose:** prove that onboarding produced credentials usable for a distinct,
normal authentication ceremony.

1. In a new browser tab, open the recorded native Monas HTTPS origin at
   `/login`.
2. Select **Continue with Pistis** if the login page offers multiple methods.
3. Confirm that the browser reaches `/auth/pistis/v3/login` and displays
   **Approve sign-in with Pistis**, one QR, **Cancel**, and **Waiting for your
   phone…**.
4. In Pistis, open **Scan** and scan that browser QR.
5. Verify the Monas installation, GitHub identity, exact audience and expiry.
6. Approve once with Face ID.
7. Leave the browser open while it polls and finalises the ceremony.

### Pass condition

- The browser redirects to `/home` over the same native HTTPS origin.
- The page shows the authorised product cards for the committed principal.
- The same-origin session projection is available and contains the expected
  principal, authority revision and `dasobjectstore/Administer` entitlement.
- Refresh preserves the session; logout revokes it.

The browser's ceremony capability remains HttpOnly and is not encoded in the
QR. The QR contains only the one-use signed Pistis challenge.

### Stop conditions

Stop if no QR is rendered, Pistis classifies it as onboarding or Site Root,
the audience is wrong, the browser says authentication unavailable, the phone
approves but the browser never finalises, or `/home` appears without a verified
Pistis session.

## Gate 11 — Prove exact-audience product entry

**Purpose:** demonstrate that a Monas home session does not silently grant a
product session.

Select DASObjectStore from `/home`. A fresh product-specific Pistis QR must be
issued. Scan, review the `dasobjectstore` audience, approve with Face ID and
verify that the resulting product session cannot be replayed for Jenkins,
Oikodome or another audience.

### Pass condition

The DASObjectStore web application opens with the exact authorised role, and a
different product still requires its own ceremony.

### Stop conditions

Stop if a home cookie directly opens DASObjectStore, if one product QR grants
another audience, or if product access is inferred from a username, email,
local Unix account or legacy password.

## Completion record

The run is complete only when every gate has a recorded pass. Retain:

- exact build/source/lockset identifiers;
- coarse timestamps and unit states;
- redacted receipt/evidence digests;
- the GitHub numeric-subject confirmation;
- the authority revision and exact product entitlement; and
- test results for reset, first install, normal login and audience separation.

Do not retain codes, QR payloads, browser capabilities, session cookies,
provider tokens, private keys or raw App Attest objects.
